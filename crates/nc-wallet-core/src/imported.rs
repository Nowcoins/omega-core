//! A wallet that is one private key, typed in by the person who holds it.
//!
//! A recovery phrase reaches every network; a private key reaches the networks
//! of its own kind and no other. Two kinds are read:
//!
//! * **secp256k1**, as 64 hexadecimal digits with or without `0x` (what MetaMask,
//!   Trust Wallet and `TronLink` export): the one key is the account on Ethereum, BNB
//!   Chain, Polygon and Base, and on TRON, where the same public key is written as a
//!   `T…` address.
//! * **ed25519 for Solana**, as the base58 of the 64-byte secret key (what Phantom and
//!   Solflare export) or as the list of 64 numbers the Solana tools write
//!   (`[12,34,…]`): the 32-byte seed and the public key after it. The public half is
//!   checked against the seed, so a mistyped key is refused, never opened as another
//!   account.
//!
//! A 32-byte base58 text is **not** read as a key: that is what a Solana *address*
//! looks like, and taking it for a seed would open a wallet nobody asked for.
//!
//! There is no Bitcoin here (a key in WIF may hold coins at address types this wallet
//! does not read), no Stellar and no Bittensor: those are reached with a phrase.
//!
//! The key is wiped from memory when the value is dropped, `Debug` prints nothing of
//! it, and it is not `Clone`.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;
use crate::key::{Account, SigningKey};
use crate::network::Network;
use crate::{evm, hexutil, solana, tron};

/// What kind of key was imported, which decides the networks it reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportedKeyKind {
    /// secp256k1: Ethereum, BNB Chain, Polygon, Base and TRON.
    Secp256k1,
    /// ed25519: Solana.
    Ed25519,
}

impl ImportedKeyKind {
    /// The byte the vault writes for the kind.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Secp256k1 => 1,
            Self::Ed25519 => 2,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Secp256k1),
            2 => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// The families of networks a key of this kind is an account on.
    #[must_use]
    pub const fn networks(self) -> &'static [Network] {
        match self {
            Self::Secp256k1 => &[Network::Evm, Network::Tron],
            Self::Ed25519 => &[Network::Solana],
        }
    }
}

/// Why a text is not a private key this wallet can open. None of the values carries
/// any of the text: it is safe to log and to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImportedKeyError {
    /// Nothing was typed.
    #[error("the private key is empty")]
    Empty,

    /// Neither 64 hexadecimal digits nor a Solana secret key.
    #[error("this is not a private key the wallet can read")]
    Unrecognised,

    /// An address, not a key: the commonest slip is to copy the address where the key belongs.
    /// 40 hexadecimal digits (Ethereum's kind), 25 bytes in base58 (TRON's, and Bitcoin's older
    /// kind), `bc1...` (Bitcoin's newer kind) or 32 bytes in base58 (Solana's).
    #[error("this looks like an address, not a private key")]
    LooksLikeAnAddress,

    /// 64 hexadecimal digits that are not a key of the curve (zero, or too large).
    #[error("these digits are not a valid private key")]
    NotOnCurve,

    /// A Solana secret key whose second half is not the public key of its first.
    #[error("the private key is damaged: its two halves do not belong together")]
    HalvesDisagree,
}

/// One private key, imported. See the module.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ImportedKey {
    #[zeroize(skip)]
    kind: ImportedKeyKind,
    secret: [u8; 32],
}

impl fmt::Debug for ImportedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedKey")
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The longest text looked at: a list of 64 numbers with spaces is under 400 bytes.
const MAX_TEXT: usize = 1024;

impl ImportedKey {
    /// Reads a private key as a person pastes it: spaces and line ends around it are
    /// ignored, nothing else is forgiven.
    pub fn parse(text: &str) -> Result<Self, ImportedKeyError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(ImportedKeyError::Empty);
        }
        if text.len() > MAX_TEXT {
            return Err(ImportedKeyError::Unrecognised);
        }
        let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
        if digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes =
                Zeroizing::new(hexutil::decode(digits).ok_or(ImportedKeyError::Unrecognised)?);
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&bytes);
            return Self::from_parts(ImportedKeyKind::Secp256k1, &secret);
        }
        if text.starts_with('[') {
            let bytes = Zeroizing::new(number_list(text).ok_or(ImportedKeyError::Unrecognised)?);
            return Self::solana_secret(&bytes);
        }
        // An address where the key belongs is said to be one, so that the person looks for the
        // key and not for a typing mistake: 40 hexadecimal digits, or Bitcoin's `bc1...`.
        if digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ImportedKeyError::LooksLikeAnAddress);
        }
        let lower = text.as_bytes();
        if (14..=90).contains(&lower.len())
            && lower[..3].eq_ignore_ascii_case(b"bc1")
            && lower.iter().all(u8::is_ascii_alphanumeric)
        {
            return Err(ImportedKeyError::LooksLikeAnAddress);
        }
        // Base58 has no 0, O, I or l: hexadecimal of another length, or anything else, ends here.
        // 25 bytes are an address with its check (TRON's `T...`, Bitcoin's `1...` and `3...`),
        // 32 bytes one of Solana's.
        let mut decoded = Zeroizing::new([0u8; 64]);
        match bs58::decode(text).onto(&mut decoded[..]) {
            Ok(64) => Self::solana_secret(&decoded[..]),
            Ok(32 | 25) => Err(ImportedKeyError::LooksLikeAnAddress),
            _ => Err(ImportedKeyError::Unrecognised),
        }
    }

    /// The 64 bytes of a Solana secret key: the seed, then the public key it makes.
    fn solana_secret(bytes: &[u8]) -> Result<Self, ImportedKeyError> {
        if bytes.len() != 64 {
            return Err(ImportedKeyError::Unrecognised);
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[..32]);
        let key = SigningKey::ed25519(&secret);
        if key.public_key() != &bytes[32..] {
            return Err(ImportedKeyError::HalvesDisagree);
        }
        Self::from_parts(ImportedKeyKind::Ed25519, &secret)
    }

    /// A key from its kind and its 32 bytes (how the vault gives one back).
    pub fn from_parts(kind: ImportedKeyKind, secret: &[u8; 32]) -> Result<Self, ImportedKeyError> {
        if kind == ImportedKeyKind::Secp256k1 && SigningKey::secp256k1(secret).is_none() {
            return Err(ImportedKeyError::NotOnCurve);
        }
        Ok(Self { kind, secret: *secret })
    }

    /// What kind of key it is.
    #[must_use]
    pub const fn kind(&self) -> ImportedKeyKind {
        self.kind
    }

    /// Whether the key is an account on `network`.
    #[must_use]
    pub fn reaches(&self, network: Network) -> bool {
        self.kind.networks().contains(&network)
    }

    /// The signing key for `network`: the key itself, in that network's scheme.
    /// [`Error::KeyDoesNotReach`] for a network of another kind.
    pub fn signing_key(&self, network: Network) -> Result<SigningKey, Error> {
        if !self.reaches(network) {
            return Err(Error::KeyDoesNotReach);
        }
        match self.kind {
            ImportedKeyKind::Secp256k1 => {
                SigningKey::secp256k1(&self.secret).ok_or(Error::InvalidKey(0))
            }
            ImportedKeyKind::Ed25519 => Ok(SigningKey::ed25519(&self.secret)),
        }
    }

    /// The address and public key on `network`.
    pub fn account(&self, network: Network) -> Result<Account, Error> {
        let key = self.signing_key(network)?;
        let address = match network {
            Network::Evm => evm::address_from_public_key(key.public_key()),
            Network::Tron => tron::address_from_public_key(key.public_key()),
            Network::Solana => solana::address_from_public_key(key.public_key()),
            Network::Bitcoin | Network::Stellar | Network::Bittensor => None,
        }
        .ok_or(Error::InvalidKey(0))?;
        Ok(Account { address, public_key: key.public_key().to_vec() })
    }

    /// The key as its owner would export it again: 64 hexadecimal digits, or the base58
    /// of Solana's 64 bytes. Named like this on purpose: grep for it to find every place
    /// the key is written out.
    #[must_use]
    pub fn expose_text(&self) -> Zeroizing<String> {
        match self.kind {
            ImportedKeyKind::Secp256k1 => Zeroizing::new(hexutil::encode(&self.secret)),
            ImportedKeyKind::Ed25519 => {
                let mut both = Zeroizing::new([0u8; 64]);
                both[..32].copy_from_slice(&self.secret);
                both[32..].copy_from_slice(SigningKey::ed25519(&self.secret).public_key());
                Zeroizing::new(bs58::encode(&both[..]).into_string())
            }
        }
    }

    /// The 32 secret bytes, for the vault and the cache key. Named like this on purpose.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// `[1, 2, …]`: decimal numbers below 256 between brackets, separated by commas, with
/// any spaces. `None` for anything else.
fn number_list(text: &str) -> Option<Vec<u8>> {
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::with_capacity(64);
    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            out.zeroize();
            return None;
        }
        let Ok(byte) = part.parse::<u8>() else {
            out.zeroize();
            return None;
        };
        out.push(byte);
        if out.len() > 64 {
            out.zeroize();
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Mnemonic, signing_key};

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn phrase_key(network: Network) -> SigningKey {
        signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", network, 0).unwrap()
    }

    #[test]
    fn hex_with_and_without_the_prefix_is_the_same_key() {
        // The reference phrase's first Ethereum key, which every wallet documents.
        let hex = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
        let a = ImportedKey::parse(hex).unwrap();
        let b = ImportedKey::parse(&format!("  0x{}\n", hex.to_uppercase())).unwrap();
        assert_eq!(a.kind(), ImportedKeyKind::Secp256k1);
        assert_eq!(a.expose_secret(), b.expose_secret());
        assert_eq!(
            a.account(Network::Evm).unwrap().address,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(*a.expose_text(), hex);
    }

    #[test]
    fn a_key_is_the_phrases_account_on_evm_and_on_tron() {
        let mnemonic = Mnemonic::parse(ABANDON).unwrap();
        let evm_key = phrase_key(Network::Evm);
        let imported = ImportedKey::parse(&hexutil::encode(evm_key.expose_secret())).unwrap();
        assert_eq!(
            imported.account(Network::Evm).unwrap(),
            crate::derive(&mnemonic, "", Network::Evm, 0).unwrap()
        );
        // The same key on TRON is the T… address of the same public key (not the phrase's TRON account,
        // which is derived at another path).
        let tron = imported.account(Network::Tron).unwrap();
        assert!(tron.address.starts_with('T') && tron.address.len() == 34);
        assert_eq!(tron.public_key, evm_key.public_key());
        // And a TRON key exported from the phrase opens the phrase's TRON account.
        let tron_key = phrase_key(Network::Tron);
        let from_tron = ImportedKey::parse(&hexutil::encode(tron_key.expose_secret())).unwrap();
        assert_eq!(
            from_tron.account(Network::Tron).unwrap(),
            crate::derive(&mnemonic, "", Network::Tron, 0).unwrap()
        );
    }

    #[test]
    fn a_solana_secret_key_in_base58_and_as_a_list() {
        let mnemonic = Mnemonic::parse(ABANDON).unwrap();
        let key = phrase_key(Network::Solana);
        let mut both = [0u8; 64];
        both[..32].copy_from_slice(key.expose_secret());
        both[32..].copy_from_slice(key.public_key());
        let base58 = bs58::encode(&both[..]).into_string();
        let list = format!("[{}]", both.iter().map(u8::to_string).collect::<Vec<_>>().join(", "));
        for text in [base58.clone(), list] {
            let imported = ImportedKey::parse(&text).unwrap();
            assert_eq!(imported.kind(), ImportedKeyKind::Ed25519);
            assert_eq!(
                imported.account(Network::Solana).unwrap(),
                crate::derive(&mnemonic, "", Network::Solana, 0).unwrap()
            );
            assert_eq!(*imported.expose_text(), base58);
        }
    }

    #[test]
    fn a_key_reaches_only_its_own_networks() {
        let secp = ImportedKey::parse(&"11".repeat(32)).unwrap();
        for network in [Network::Bitcoin, Network::Solana, Network::Stellar, Network::Bittensor] {
            assert_eq!(secp.account(network).unwrap_err(), Error::KeyDoesNotReach);
            assert!(matches!(secp.signing_key(network), Err(Error::KeyDoesNotReach)));
        }
        let key = phrase_key(Network::Solana);
        let ed = ImportedKey::from_parts(ImportedKeyKind::Ed25519, key.expose_secret()).unwrap();
        for network in
            [Network::Evm, Network::Tron, Network::Bitcoin, Network::Stellar, Network::Bittensor]
        {
            assert_eq!(ed.account(network).unwrap_err(), Error::KeyDoesNotReach);
        }
    }

    #[test]
    fn what_is_not_a_key_is_refused_and_says_why() {
        assert_eq!(ImportedKey::parse("  \n").unwrap_err(), ImportedKeyError::Empty);
        // Zero, and the curve's order itself: 64 digits that are no key.
        assert_eq!(ImportedKey::parse(&"00".repeat(32)).unwrap_err(), ImportedKeyError::NotOnCurve);
        assert_eq!(
            ImportedKey::parse("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap_err(),
            ImportedKeyError::NotOnCurve
        );
        // An address is not a key, and is said to be an address, whichever network's it is: Solana's
        // (32 bytes), Ethereum's with and without its prefix, TRON's, and Bitcoin's three kinds.
        for text in [
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "0X9858effd232b4033e47d90003d41ec34ecaeda94",
            "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU",
            "  0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n",
        ] {
            assert_eq!(
                ImportedKey::parse(text).unwrap_err(),
                ImportedKeyError::LooksLikeAnAddress,
                "{text}"
            );
        }
        // A recovery phrase, 39 and 41 and 63 digits, a list too short, `bc1` and little else.
        for text in [
            ABANDON,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda9",
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda944",
            &"1".repeat(63),
            "[1, 2, 3]",
            "[1,2,x]",
            "bc1",
            "bc1 q",
        ] {
            assert_eq!(
                ImportedKey::parse(text).unwrap_err(),
                ImportedKeyError::Unrecognised,
                "{text}"
            );
        }
        // A secret key whose public half was changed.
        let key = phrase_key(Network::Solana);
        let mut both = [0u8; 64];
        both[..32].copy_from_slice(key.expose_secret());
        both[32..].copy_from_slice(key.public_key());
        both[40] ^= 1;
        assert_eq!(
            ImportedKey::parse(&bs58::encode(&both[..]).into_string()).unwrap_err(),
            ImportedKeyError::HalvesDisagree
        );
    }

    #[test]
    fn nothing_of_the_key_is_printed() {
        let key = ImportedKey::parse(&"22".repeat(32)).unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains("redacted") && !shown.contains("2222"), "{shown}");
        for error in
            [ImportedKeyError::Empty, ImportedKeyError::Unrecognised, ImportedKeyError::NotOnCurve]
        {
            assert!(!error.to_string().contains("22"));
        }
    }
}
