//! Hierarchical derivation from a seed: BIP-32 over secp256k1 (the `bip32`
//! crate) and SLIP-10 over ed25519 (HMAC-SHA512, from the specification, with
//! the HMAC and SHA-2 from `RustCrypto`).

use bip32::{DerivationPath, XPrv};
use hmac::{Hmac, Mac as _};
use k256::elliptic_curve::sec1::ToSec1Point as _;
use sha2::Sha512;
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::Error;
use crate::key::SigningKey;

type HmacSha512 = Hmac<Sha512>;

/// The first hardened index: BIP-32 elements below it are normal, from it up
/// hardened.
const HARDENED: u32 = 0x8000_0000;

/// Refuses an account index that no BIP-32 element can hold (`>= 2^31`).
pub(crate) fn check_index(index: u32) -> Result<u32, Error> {
    if index >= HARDENED { Err(Error::IndexOutOfRange(index)) } else { Ok(index) }
}

/// The BIP-32 node at `path` (`m/44'/60'/0'/0/0`) under `seed`.
pub(crate) fn secp256k1_node(seed: &[u8], path: &str) -> Option<XPrv> {
    let path: DerivationPath = path.parse().ok()?;
    XPrv::derive_from_path(seed, &path).ok()
}

/// The secp256k1 key at `path` under `seed`.
pub(crate) fn secp256k1_key(seed: &[u8], path: &str) -> Option<SigningKey> {
    let node = secp256k1_node(seed, path)?;
    let secret = Zeroizing::new(node.to_bytes());
    SigningKey::secp256k1(&secret)
}

/// The ed25519 key at `path` under `seed`, by SLIP-10. Every element of the
/// path must be hardened: ed25519 has no normal derivation.
pub(crate) fn ed25519_key(seed: &[u8], path: &str) -> Option<SigningKey> {
    let secret = slip10_ed25519(seed, path)?;
    Some(SigningKey::ed25519(&secret))
}

/// SLIP-10 for ed25519: the 32-byte private key at `path` under `seed`.
///
/// Master: `I = HMAC-SHA512(key = "ed25519 seed", data = seed)`, key = `I[..32]`,
/// chain code = `I[32..]`. Child: `I = HMAC-SHA512(key = chain code,
/// data = 0x00 || key || ser32(index))`, hardened indexes only.
pub(crate) fn slip10_ed25519(seed: &[u8], path: &str) -> Option<Zeroizing<[u8; 32]>> {
    let path: DerivationPath = path.parse().ok()?;
    let mut node = hmac_sha512(b"ed25519 seed", &[seed])?;
    for child in path.iter() {
        if !child.is_hardened() {
            return None;
        }
        let next = hmac_sha512(&node[32..], &[&[0u8], &node[..32], &child.0.to_be_bytes()])?;
        node = next;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&node[..32]);
    Some(key)
}

/// HMAC-SHA512 over the concatenation of `parts`, in a buffer that wipes
/// itself.
fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Option<Zeroizing<[u8; 64]>> {
    let mut mac = HmacSha512::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(part);
    }
    let mut digest = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Some(out)
}

/// The 64 bytes X || Y of a compressed secp256k1 public key (33 bytes), as
/// Keccak-256 hashes them for EVM and TRON; `None` if it is not on the curve.
pub(crate) fn secp256k1_uncompressed_xy(compressed: &[u8]) -> Option<[u8; 64]> {
    let point = k256::PublicKey::from_sec1_bytes(compressed).ok()?.to_sec1_point(false);
    <[u8; 64]>::try_from(point.as_bytes().get(1..)?).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use bip32::Prefix;

    use super::*;
    use crate::mnemonic::Mnemonic;

    /// BIP-32, "Test Vectors" 1 to 4 (vector 5 is about invalid serialised
    /// keys, which this crate never parses), copied verbatim from
    /// <https://github.com/bitcoin/bips/blob/100ba872c808946155b1eeb8c4568058f2eea0a7/bip-0032.mediawiki>
    /// (the BIP text at that commit).
    const BIP32: &str = include_str!("../tests/vectors/bip-0032-test-vectors-1-4.txt");

    /// SLIP-0010, "Test vector 1 for ed25519" and "Test vector 2 for ed25519",
    /// copied verbatim from
    /// <https://github.com/satoshilabs/slips/blob/570ed55b7fde158f1116be34fc2faa35dada5912/slip-0010.md>.
    const SLIP10: &str = include_str!("../tests/vectors/slip-0010-ed25519.md");

    /// BIP-84, "Test vectors", copied verbatim from
    /// <https://github.com/bitcoin/bips/blob/100ba872c808946155b1eeb8c4568058f2eea0a7/bip-0084.mediawiki>.
    const BIP84: &str = include_str!("../tests/vectors/bip-0084-test-vectors.txt");

    /// Trezor firmware's Solana address fixtures (mnemonic `all all … all`),
    /// copied verbatim from
    /// <https://github.com/trezor/trezor-firmware/blob/2ad1fd4df6b35fde2cd83109d1406d97a2de31af/common/tests/fixtures/solana/get_address.json>.
    const TREZOR_SOLANA: &str = include_str!("../tests/vectors/trezor-solana-get_address.json");

    /// One chain of a published vector: its path and the expected values.
    struct Chain {
        path: String,
        fields: Vec<(String, String)>,
    }

    impl Chain {
        fn get(&self, name: &str) -> &str {
            &self.fields.iter().find(|(k, _)| k == name).unwrap().1
        }
    }

    fn path_of(text: &str) -> String {
        text.replace("<sub>H</sub>", "'")
    }

    /// Reads the vectors of BIP-32 and SLIP-10, which both list a seed and then
    /// `Chain <path>` entries with `name: value` lines below.
    fn parse_chains(text: &str, seed_marker: &str) -> Vec<(Vec<u8>, Vec<Chain>)> {
        let mut out: Vec<(Vec<u8>, Vec<Chain>)> = Vec::new();
        for line in text.lines() {
            let line = line.trim().trim_start_matches('*').trim();
            if let Some(seed) = line.strip_prefix(seed_marker) {
                out.push((hex::decode(seed.trim()).unwrap(), Vec::new()));
            } else if let Some(path) = line.strip_prefix("Chain ") {
                out.last_mut().unwrap().1.push(Chain { path: path_of(path), fields: Vec::new() });
            } else if let Some((name, value)) = line.split_once(": ")
                && let Some((_, chains)) = out.last_mut()
                && let Some(chain) = chains.last_mut()
            {
                chain.fields.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        out
    }

    #[test]
    fn bip32_vectors() {
        let vectors = parse_chains(BIP32, "Seed (hex):");
        assert_eq!(vectors.len(), 4);
        let mut checked = 0;
        for (seed, chains) in &vectors {
            for chain in chains {
                let node = secp256k1_node(seed, &chain.path).unwrap();
                assert_eq!(*node.to_string(Prefix::XPRV), chain.get("ext prv"), "{}", chain.path);
                assert_eq!(
                    node.public_key().to_string(Prefix::XPUB),
                    chain.get("ext pub"),
                    "{}",
                    chain.path
                );
                checked += 1;
            }
        }
        // 6 + 6 + 2 + 3 chains in vectors 1 to 4.
        assert_eq!(checked, 17);
    }

    #[test]
    fn slip10_ed25519_vectors() {
        let vectors = parse_chains(SLIP10, "Seed (hex):");
        assert_eq!(vectors.len(), 2);
        let mut checked = 0;
        for (seed, chains) in &vectors {
            for chain in chains {
                let private = slip10_ed25519(seed, &chain.path).unwrap();
                assert_eq!(hex::encode(*private), chain.get("private"), "{}", chain.path);
                // SLIP-10 lists ed25519 public keys behind a 0x00 marker byte.
                let public = SigningKey::ed25519(&private);
                assert_eq!(
                    format!("00{}", hex::encode(public.public_key())),
                    chain.get("public"),
                    "{}",
                    chain.path
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 12);
    }

    #[test]
    fn slip10_refuses_normal_children() {
        // ed25519 has no normal derivation.
        assert!(slip10_ed25519(&[7u8; 64], "m/44'/501'/0'/0").is_none());
        assert!(slip10_ed25519(&[7u8; 64], "m/44'/501'/0'/0'").is_some());
        assert!(slip10_ed25519(&[7u8; 64], "not a path").is_none());
    }

    #[test]
    fn bip84_root_and_account_extended_keys() {
        // Lines look like `rootpriv = zprv…`; the mnemonic is the BIP-39
        // phrase `abandon … about`, with no passphrase.
        let value = |name: &str| -> String {
            let line = BIP84.lines().find(|l| l.trim_start().starts_with(name)).unwrap();
            line.split_once('=').unwrap().1.trim().to_owned()
        };
        let phrase = value("mnemonic");
        let seed = Mnemonic::parse(&phrase).unwrap().to_seed("");
        let root = secp256k1_node(seed.expose_secret(), "m").unwrap();
        assert_eq!(*root.to_string(Prefix::ZPRV), value("rootpriv"));
        assert_eq!(root.public_key().to_string(Prefix::ZPUB), value("rootpub"));
        let account = secp256k1_node(seed.expose_secret(), "m/84'/0'/0'").unwrap();
        assert_eq!(*account.to_string(Prefix::ZPRV), value("xpriv"));
        assert_eq!(account.public_key().to_string(Prefix::ZPUB), value("xpub"));
    }

    #[test]
    fn trezor_solana_paths() {
        let fixture: serde_json::Value = serde_json::from_str(TREZOR_SOLANA).unwrap();
        let setup = &fixture["setup"];
        let seed = Mnemonic::parse(setup["mnemonic"].as_str().unwrap())
            .unwrap()
            .to_seed(setup["passphrase"].as_str().unwrap());
        let tests = fixture["tests"].as_array().unwrap();
        assert_eq!(tests.len(), 3);
        for test in tests {
            let path = test["parameters"]["path"].as_str().unwrap();
            let key = ed25519_key(seed.expose_secret(), path).unwrap();
            assert_eq!(
                crate::solana::address_from_public_key(key.public_key()).unwrap(),
                test["result"]["expected_address"].as_str().unwrap(),
                "{path}"
            );
        }
    }

    /// Trezor's BIP-39 vectors (the `english` list of `vectors.json`): each
    /// phrase with the passphrase `TREZOR` gives the listed seed, and the seed
    /// the listed BIP-32 master key. Copied from
    /// <https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json>.
    const BIP39: &str = include_str!("../tests/vectors/bip39-trezor-english.json");

    #[test]
    fn bip39_trezor_vectors_give_the_listed_master_keys() {
        let vectors: Vec<[String; 4]> = serde_json::from_str(BIP39).unwrap();
        assert_eq!(vectors.len(), 24);
        for [_entropy, phrase, seed, xprv] in &vectors {
            let seed_bytes = Mnemonic::parse(phrase).unwrap().to_seed("TREZOR");
            assert_eq!(hex::encode(seed_bytes.expose_secret()), *seed);
            let master = secp256k1_node(seed_bytes.expose_secret(), "m").unwrap();
            assert_eq!(*master.to_string(Prefix::XPRV), *xprv);
        }
    }

    #[test]
    fn index_limit() {
        assert_eq!(check_index(0), Ok(0));
        assert_eq!(check_index(0x7fff_ffff), Ok(0x7fff_ffff));
        assert_eq!(check_index(0x8000_0000), Err(Error::IndexOutOfRange(0x8000_0000)));
        assert_eq!(check_index(u32::MAX), Err(Error::IndexOutOfRange(u32::MAX)));
    }
}
