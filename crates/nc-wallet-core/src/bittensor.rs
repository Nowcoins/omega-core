//! Bittensor: sr25519 by Substrate's derivation, SS58 prefix 42.
//!
//! This is how `btcli`, Polkadot.js and Talisman read a recovery phrase:
//!
//! * The root key (account 0) is made from the phrase's **entropy**, not from
//!   the BIP-39 seed: `mini secret = PBKDF2-HMAC-SHA512(entropy, "mnemonic" ||
//!   passphrase, 2048 rounds)[..32]` (`substrate-bip39`), then expanded in
//!   Ed25519 mode. There is no derivation path.
//! * Account `i >= 1` is the hard junction `//i` below the root key: the
//!   chain code is `i` as a little-endian `u64`, zero-padded to 32 bytes, and
//!   schnorrkel's hard derivation gives the new mini secret.
//! * The address is SS58: `base58(prefix || public key || checksum)`, where
//!   the checksum is the first 2 bytes of Blake2b-512 over `"SS58PRE" ||
//!   prefix || public key`, and the prefix is 42 (the generic Substrate
//!   format, as Bittensor uses).
//!
//! The passphrase is Substrate's "password" (`<phrase>///<password>`): it is
//! used as written, without the Unicode normalisation BIP-39 applies.
//!
//! # Transactions
//!
//! [`extrinsic`] builds and signs a `Balances.transfer_keep_alive` in a signed
//! extrinsic of format 4, with sr25519. The call index, the runtime versions,
//! the genesis hash, the hash of the block the mortal era begins at, the nonce
//! and the tip are inputs. The tests pin the encoder to Substrate's own tests
//! and to transfers on Finney.

pub mod extrinsic;

#[cfg(test)]
mod transfer_tests;

pub use extrinsic::{
    CallIndex, Era, FINNEY_GENESIS, SignedExtrinsic, Transfer, TransferError, sign_transfer,
};

use blake2::{Blake2b512, Digest as _};
use schnorrkel::ExpansionMode;
use schnorrkel::derive::ChainCode;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::key::{Account, SigningKey};
use crate::mnemonic::Mnemonic;

/// Bittensor's SS58 address format.
pub const SS58_PREFIX: u8 = 42;

/// The private key of account `index`: the root key for 0, the hard junction
/// `//index` below it otherwise.
pub fn signing_key(mnemonic: &Mnemonic, passphrase: &str, index: u32) -> Result<SigningKey, Error> {
    let junction = (index != 0).then(|| chain_code(u64::from(index)));
    derive(mnemonic, passphrase, junction.as_ref()).ok_or(Error::InvalidKey(index))
}

/// The root key (`junction` is `None`) or the hard junction with the given
/// chain code below it.
pub(crate) fn derive(
    mnemonic: &Mnemonic,
    passphrase: &str,
    junction: Option<&[u8; 32]>,
) -> Option<SigningKey> {
    let entropy = mnemonic.entropy();
    let root = substrate_bip39::mini_secret_from_entropy(&entropy, passphrase).ok()?;
    let secret = if let Some(chain_code) = junction {
        let (child, _) = root.hard_derive_mini_secret_key(
            Some(ChainCode(*chain_code)),
            b"",
            ExpansionMode::Ed25519,
        );
        Zeroizing::new(child.to_bytes())
    } else {
        Zeroizing::new(root.to_bytes())
    };
    SigningKey::sr25519(&secret)
}

/// The address and public key of account `index`.
pub fn account(mnemonic: &Mnemonic, passphrase: &str, index: u32) -> Result<Account, Error> {
    let key = signing_key(mnemonic, passphrase, index)?;
    account_of(&key, index)
}

pub(crate) fn account_of(key: &SigningKey, index: u32) -> Result<Account, Error> {
    let address = address_from_public_key(key.public_key()).ok_or(Error::InvalidKey(index))?;
    Ok(Account { address, public_key: key.public_key().to_vec() })
}

/// The SS58 address, format 42, of an sr25519 public key; `None` unless it is
/// 32 bytes.
pub fn address_from_public_key(public_key: &[u8]) -> Option<String> {
    ss58(SS58_PREFIX, public_key)
}

/// Reads a Bittensor address (SS58, prefix 42, `5…`) into its 32-byte account.
/// `None` for a wrong checksum, another prefix or another length: an address
/// written for another Substrate chain is a different address even where the
/// key under it is the same.
#[must_use]
pub fn parse_address(text: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(text).into_vec().ok()?;
    let (body, checksum) = bytes.split_at_checked(33)?;
    let (&prefix, key) = body.split_first()?;
    let key: [u8; 32] = key.try_into().ok()?;
    if prefix != SS58_PREFIX || ss58(prefix, &key)?.as_str() != text {
        return None;
    }
    // `ss58` rebuilt the same text, so the two checksum bytes are right too.
    (checksum.len() == 2).then_some(key)
}

/// A numeric Substrate junction: the number as 8 little-endian bytes, padded
/// with zeros to the 32 bytes of a chain code.
pub(crate) fn chain_code(number: u64) -> [u8; 32] {
    let mut chain_code = [0u8; 32];
    chain_code[..8].copy_from_slice(&number.to_le_bytes());
    chain_code
}

/// A 32-byte account id in SS58 with a one-byte `prefix` (0 to 63); `None`
/// for anything else.
pub(crate) fn ss58(prefix: u8, public_key: &[u8]) -> Option<String> {
    if prefix >= 64 || public_key.len() != 32 {
        return None;
    }
    let mut body = Vec::with_capacity(35);
    body.push(prefix);
    body.extend_from_slice(public_key);
    let checksum = Blake2b512::new().chain_update(b"SS58PRE").chain_update(&body).finalize();
    body.extend_from_slice(&checksum[..2]);
    Some(bs58::encode(body).into_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Substrate's public development phrase and the SS58 address of its root
    /// key. From `sp-core`'s `crypto.rs` (`DEV_PHRASE`, `DEV_ADDRESS`) at
    /// <https://github.com/paritytech/polkadot-sdk/blob/f20de3de1c5f9624a33209466968e35c1228c0f4/substrate/primitives/core/src/crypto.rs>.
    const DEV_PHRASE: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const DEV_ADDRESS: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

    fn dev() -> Mnemonic {
        Mnemonic::parse(DEV_PHRASE).unwrap()
    }

    /// The chain code Substrate gives a string junction such as `//Alice`: the
    /// string SCALE-encoded (a compact length, then the bytes), padded with
    /// zeros to 32 bytes.
    fn string_junction(name: &str) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        chain_code[0] = u8::try_from(name.len()).unwrap() << 2;
        chain_code[1..=name.len()].copy_from_slice(name.as_bytes());
        chain_code
    }

    #[test]
    fn root_key_of_the_dev_phrase() {
        // sp-core: DEV_ADDRESS is the address of DEV_PHRASE's root key.
        let key = derive(&dev(), "", None).unwrap();
        assert_eq!(address_from_public_key(key.public_key()).unwrap(), DEV_ADDRESS);
    }

    #[test]
    fn hard_junction_alice_of_the_dev_phrase() {
        // sp-core `derive_hard_known_pair_should_work`: `DEV_PHRASE//Alice` has
        // this public key. sr25519.rs at the commit above, lines 623 to 631.
        let key = derive(&dev(), "", Some(&string_junction("Alice"))).unwrap();
        assert_eq!(
            hex::encode(key.public_key()),
            "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
        // Polkadot.js `createFromUri('//Alice')` (keyring/src/index.spec.ts at
        // commit 9281daa14c2c2a41708c3489de8770a064525577, "creates with dev
        // phrase when only path specified") shows that key as this address.
        assert_eq!(
            address_from_public_key(key.public_key()).unwrap(),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
    }

    #[test]
    fn numeric_hard_junction_matches_polkadot_js() {
        // Polkadot.js keyring "creates with integer derivations": the dev
        // phrase with `//9007199254740991` (the largest safe JS integer, which
        // needs more than 4 bytes of the chain code).
        let key = derive(&dev(), "", Some(&chain_code(9_007_199_254_740_991))).unwrap();
        assert_eq!(
            address_from_public_key(key.public_key()).unwrap(),
            "5CDsyNZyqxLpHnTvknr68anUcYoBFjZbFKiEJJf4prB75Uog"
        );
    }

    #[test]
    fn junction_is_the_number_little_endian_in_32_bytes() {
        let cc = chain_code(1);
        assert_eq!(cc[0], 1);
        assert!(cc[1..].iter().all(|b| *b == 0));
        let cc = chain_code(0x0102_0304_0506_0708);
        assert_eq!(cc[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert!(cc[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn index_one_is_the_junction_one() {
        let phrase = dev();
        let by_index = signing_key(&phrase, "", 1).unwrap();
        let by_junction = derive(&phrase, "", Some(&chain_code(1))).unwrap();
        assert_eq!(by_index.expose_secret(), by_junction.expose_secret());
        let root = signing_key(&phrase, "", 0).unwrap();
        assert_ne!(root.expose_secret(), by_index.expose_secret());
        assert_ne!(signing_key(&phrase, "", 2).unwrap().expose_secret(), by_index.expose_secret());
    }

    #[test]
    fn ss58_with_prefix_zero_matches_py_substrate_interface() {
        // py-substrate-interface `test_create_sr25519_keypair`: this phrase
        // with `ss58_format=0` has this address (test/test_keypair.py at
        // commit 65b2ccaa3adea558313f1620d360ec803811f8b9 of
        // JAMdotTech/py-polkadot-sdk, formerly polkascan/py-substrate-interface).
        let phrase = Mnemonic::parse(
            "old leopard transfer rib spatial phone calm indicate online fire caution review",
        )
        .unwrap();
        let key = derive(&phrase, "", None).unwrap();
        assert_eq!(
            ss58(0, key.public_key()).unwrap(),
            "16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2"
        );
    }

    #[test]
    fn ss58_refuses_what_it_cannot_encode() {
        assert!(ss58(64, &[1u8; 32]).is_none());
        assert!(ss58(42, &[1u8; 31]).is_none());
        assert!(ss58(42, &[1u8; 33]).is_none());
        assert!(ss58(42, &[1u8; 32]).is_some());
    }
}
