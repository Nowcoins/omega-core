//! What derivation hands out: a public [`Account`], and, through one explicit
//! accessor, a [`SigningKey`].

use std::fmt;

use ed25519_dalek::SigningKey as DalekKey;
use k256::elliptic_curve::sec1::ToSec1Point as _;
use schnorrkel::{ExpansionMode, MiniSecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The curve and signature scheme a key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyScheme {
    /// secp256k1 (EVM, TRON, Bitcoin). Public keys are 33-byte compressed
    /// SEC1 points.
    Secp256k1,
    /// Ed25519 (Solana, Stellar). Public keys are 32 bytes.
    Ed25519,
    /// sr25519, Schnorr over Ristretto (Bittensor). Public keys are 32 bytes.
    Sr25519,
}

/// What a person can be shown and what the chain sees: the address and the
/// public key behind it. Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The address in the network's own format (EIP-55 `0x…`, TRON `T…`,
    /// Bitcoin `bc1q…`, Solana base58, Stellar `G…`, SS58 `5…`).
    pub address: String,
    /// The public key: 33 bytes (compressed SEC1) for secp256k1, 32 bytes for
    /// ed25519 and sr25519.
    pub public_key: Vec<u8>,
}

/// A private signing key, for the signing code and nothing else.
///
/// The key is wiped from memory when the value is dropped. `Debug` shows the
/// scheme and the public key, never the secret, and the type is not `Clone`,
/// so there is one copy to account for. The secret leaves only through
/// [`SigningKey::expose_secret`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    #[zeroize(skip)]
    scheme: KeyScheme,
    secret: [u8; 32],
    #[zeroize(skip)]
    public: Vec<u8>,
}

impl SigningKey {
    /// A secp256k1 key from its 32-byte big-endian scalar; `None` if the
    /// scalar is zero or not below the curve order.
    pub(crate) fn secp256k1(secret: &[u8; 32]) -> Option<Self> {
        let key = k256::SecretKey::from_slice(secret).ok()?;
        let public = key.public_key().to_sec1_point(true).as_bytes().to_vec();
        Some(Self { scheme: KeyScheme::Secp256k1, secret: *secret, public })
    }

    /// An ed25519 key from its 32-byte seed.
    pub(crate) fn ed25519(secret: &[u8; 32]) -> Self {
        let public = DalekKey::from_bytes(secret).verifying_key().to_bytes().to_vec();
        Self { scheme: KeyScheme::Ed25519, secret: *secret, public }
    }

    /// An sr25519 key from its 32-byte mini secret.
    pub(crate) fn sr25519(mini_secret: &[u8; 32]) -> Option<Self> {
        let mini = MiniSecretKey::from_bytes(mini_secret).ok()?;
        let public = mini.expand_to_public(ExpansionMode::Ed25519).to_bytes().to_vec();
        Some(Self { scheme: KeyScheme::Sr25519, secret: *mini_secret, public })
    }

    /// Which scheme the key belongs to.
    pub fn scheme(&self) -> KeyScheme {
        self.scheme
    }

    /// The public key: 33 bytes (compressed SEC1) for secp256k1, 32 bytes
    /// for ed25519 and sr25519.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The 32 secret bytes. Named like this on purpose: grep for it to find
    /// every place a private key is read. What the bytes are depends on the
    /// scheme:
    ///
    /// * `Secp256k1`: the private scalar, big-endian.
    /// * `Ed25519`: the seed of RFC 8032 (the key SLIP-10 derives).
    /// * `Sr25519`: the Substrate mini secret key. Expand it with
    ///   `schnorrkel::MiniSecretKey::from_bytes(..)` and
    ///   `expand_to_keypair(ExpansionMode::Ed25519)`, as Substrate does.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("scheme", &self.scheme)
            .field("public_key_len", &self.public.len())
            .field("secret", &"<redacted>")
            .finish()
    }
}
