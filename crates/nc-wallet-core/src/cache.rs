//! Sealing what the device keeps about a wallet (its history), at rest.
//!
//! The history lists every address the wallet ever dealt with. Neither Chrome's
//! storage nor an app's private files are encrypted in a way that protects them from
//! someone holding the profile or a rooted phone, so each piece is sealed under a key
//! that only the wallet's own phrase can make, and only while it is unlocked.
//!
//! * **Master:** `HMAC-SHA256(key = the BIP-39 seed, "nowcoin-wallet/cache/master/v1")`.
//!   The seed is never used as a key itself; the master is made once per unlock.
//! * **Key of a label:** `HMAC-SHA256(master, "key" 0x00 label)`; the **id** of a label
//!   (a name safe to store: it reveals neither the address nor the network in it) is the
//!   first 12 bytes of `HMAC-SHA256(master, "id" 0x00 label)`, in hex.
//! * **Seal:** AES-256-GCM, a random 96-bit nonce, and the header and the label as the
//!   associated data, so a blob cannot be opened under another label.
//!
//! Blob: `NCWC` | version `1` | nonce (12) | ciphertext and tag.
//!
//! Opening a blob that was sealed by another wallet, under another label, or that was
//! changed, gives `None` and nothing else: the caller starts that history afresh.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload, generic_array::GenericArray};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::mnemonic::Seed;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"NCWC";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN;
const TAG_LEN: usize = 16;
/// The longest label accepted, in bytes.
pub const MAX_LABEL_LEN: usize = 256;

/// What a wallet's cache keys are made from. Wiped when dropped; prints nothing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CacheMaster([u8; 32]);

impl std::fmt::Debug for CacheMaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CacheMaster(<redacted>)")
    }
}

fn mac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    // HMAC takes a key of any length.
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

impl CacheMaster {
    /// The master of the wallet whose BIP-39 seed this is.
    #[must_use]
    pub fn from_seed(seed: &Seed) -> Self {
        Self(*mac(seed.expose_secret(), &[b"nowcoin-wallet/cache/master/v1"]))
    }

    /// The master of a wallet that is one imported private key: made from the key under a
    /// label of its own, so it is never the master of a phrase.
    #[must_use]
    pub fn from_imported(key: &crate::imported::ImportedKey) -> Self {
        Self(*mac(key.expose_secret(), &[b"nowcoin-wallet/cache/master/imported-key/v1"]))
    }

    /// The name to store `label`'s blob under: 24 hex characters.
    #[must_use]
    pub fn id(&self, label: &str) -> String {
        use std::fmt::Write as _;
        mac(&self.0, &[b"id\0", label.as_bytes()])[..12].iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn key(&self, label: &str) -> Zeroizing<[u8; 32]> {
        mac(&self.0, &[b"key\0", label.as_bytes()])
    }

    /// Seals `plaintext` for `label`. `None` only if the system has no randomness or the
    /// label is too long.
    #[must_use]
    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
        if label.len() > MAX_LABEL_LEN {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).ok()?;
        if nonce.iter().all(|b| *b == 0) {
            return None;
        }
        self.seal_with(label, plaintext, nonce)
    }

    fn seal_with(&self, label: &str, plaintext: &[u8], nonce: [u8; NONCE_LEN]) -> Option<Vec<u8>> {
        let mut blob = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.extend_from_slice(&nonce);
        let key = self.key(label);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*key));
        let aad = [&blob[..5], label.as_bytes()].concat();
        let sealed = cipher
            .encrypt(GenericArray::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .ok()?;
        blob.extend_from_slice(&sealed);
        Some(blob)
    }

    /// What `blob` holds, if it was sealed for `label` by this wallet and is whole.
    #[must_use]
    pub fn open(&self, label: &str, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if label.len() > MAX_LABEL_LEN
            || blob.len() < HEADER_LEN + TAG_LEN
            || &blob[..4] != MAGIC
            || blob[4] != VERSION
        {
            return None;
        }
        let key = self.key(label);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*key));
        let aad = [&blob[..5], label.as_bytes()].concat();
        cipher
            .decrypt(
                GenericArray::from_slice(&blob[5..HEADER_LEN]),
                Payload { msg: &blob[HEADER_LEN..], aad: &aad },
            )
            .ok()
            .map(Zeroizing::new)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mnemonic::Mnemonic;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const OTHER: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn master_of(phrase: &str, passphrase: &str) -> CacheMaster {
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        CacheMaster::from_seed(&mnemonic.to_seed(passphrase))
    }

    #[test]
    fn what_is_sealed_opens_under_the_same_label_and_wallet() {
        let master = master_of(ABANDON, "");
        let blob = master.seal("history/ethereum/0xabc", b"{\"v\":1}").unwrap();
        assert_eq!(&blob[..5], b"NCWC\x01");
        assert_eq!(blob.len(), 5 + 12 + 7 + 16);
        assert_eq!(&*master.open("history/ethereum/0xabc", &blob).unwrap(), b"{\"v\":1}");
        // Not the same blob twice (a fresh nonce), and an empty text is fine.
        assert_ne!(blob, master.seal("history/ethereum/0xabc", b"{\"v\":1}").unwrap());
        let empty = master.seal("x", b"").unwrap();
        assert_eq!(master.open("x", &empty).unwrap().len(), 0);
    }

    #[test]
    fn another_label_another_wallet_another_passphrase_or_a_change_opens_nothing() {
        let master = master_of(ABANDON, "");
        let blob = master.seal("history/a", b"secret").unwrap();
        assert!(master.open("history/b", &blob).is_none());
        assert!(master_of(OTHER, "").open("history/a", &blob).is_none());
        assert!(master_of(ABANDON, "p").open("history/a", &blob).is_none());
        for i in 0..blob.len() {
            let mut changed = blob.clone();
            changed[i] ^= 1;
            assert!(master.open("history/a", &changed).is_none(), "byte {i}");
        }
        assert!(master.open("history/a", &blob[..blob.len() - 1]).is_none());
        assert!(master.open("history/a", &[]).is_none());
        assert!(master.open("history/a", b"NCWC\x01").is_none());
    }

    #[test]
    fn the_plaintext_is_not_in_the_blob() {
        let master = master_of(ABANDON, "");
        let text = b"0x28C6c06298d514Db089934071355E5743bf21d60";
        let blob = master.seal("l", text).unwrap();
        assert!(!blob.windows(text.len()).any(|w| w == text));
    }

    #[test]
    fn ids_are_stable_hex_and_reveal_nothing_of_the_label() {
        let master = master_of(ABANDON, "");
        let id = master.id("history/ethereum/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        assert_eq!(id.len(), 24);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, master.id("history/ethereum/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        assert_ne!(id, master.id("history/bsc/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        assert_ne!(
            id,
            master_of(OTHER, "").id("history/ethereum/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        );
    }

    #[test]
    fn the_keys_are_what_the_text_above_says() {
        // HMAC-SHA256 computed outside this crate (Python's hmac module) over the seed of the
        // "abandon ... about" phrase (BIP-39 test vector, empty passphrase).
        let master = master_of(ABANDON, "");
        assert_eq!(master.id("a"), EXPECTED_ID_OF_A);
    }

    #[test]
    fn a_label_that_is_too_long_is_refused() {
        let master = master_of(ABANDON, "");
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(master.seal(&long, b"x").is_none());
        assert!(master.open(&long, &[0; 64]).is_none());
    }

    const EXPECTED_ID_OF_A: &str = "f45f135d6d3b1ecf2748ab15";
}
