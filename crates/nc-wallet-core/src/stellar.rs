//! Stellar: ed25519 by SLIP-10 at `m/44'/148'/{index}'`, as SEP-0005
//! specifies (Lobstr and Freighter read the same). The address is the strkey
//! of the public key: version byte, 32 bytes, CRC-16 checksum, base32, which
//! gives `G…`.
//!
//! The matching secret is also a strkey (`S…`). It is not part of
//! [`Account`]; [`export_secret_seed`] is the one function that writes it.
//!
//! # Transactions
//!
//! The wallet builds a version-1 transaction with one operation ([`xdr`]): a
//! payment of XLM or of an issued asset such as USDC, a trustline for one, or
//! the creation of an account, with a text, id or no memo. The account's
//! sequence number, the fee and the time bounds are inputs. [`sign_transaction`]
//! signs it for a network, named by its passphrase, over the SHA-256 of the
//! network id, the envelope type and the transaction's XDR, and returns the
//! envelope to submit. The tests pin the encoders to the Go SDK's signed
//! envelopes and to payments on the public network.

pub mod xdr;

#[cfg(test)]
mod tests;

pub use xdr::{
    Asset, AssetCode, Memo, MemoText, Operation, PUBLIC_NETWORK_PASSPHRASE,
    TEST_NETWORK_PASSPHRASE, TimeBounds, Transaction, XdrError,
};

use ed25519_dalek::Signer as _;

use stellar_strkey::ed25519::{PrivateKey, PublicKey};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::Error;
use crate::hd;
use crate::key::{Account, KeyScheme, SigningKey};
use crate::mnemonic::Seed;
use crate::network::Network;

/// The private key of account `index`.
pub fn signing_key(seed: &Seed, index: u32) -> Result<SigningKey, Error> {
    let index = hd::check_index(index)?;
    hd::ed25519_key(seed.expose_secret(), &Network::Stellar.derivation_path(index))
        .ok_or(Error::InvalidKey(index))
}

/// The address and public key of account `index`.
pub fn account(seed: &Seed, index: u32) -> Result<Account, Error> {
    let key = signing_key(seed, index)?;
    account_of(&key, index)
}

pub(crate) fn account_of(key: &SigningKey, index: u32) -> Result<Account, Error> {
    let address = address_from_public_key(key.public_key()).ok_or(Error::InvalidKey(index))?;
    Ok(Account { address, public_key: key.public_key().to_vec() })
}

/// The `G…` address of an ed25519 public key; `None` unless it is 32 bytes.
pub fn address_from_public_key(public_key: &[u8]) -> Option<String> {
    let bytes: [u8; 32] = public_key.try_into().ok()?;
    Some(PublicKey(bytes).to_string().as_str().to_owned())
}

/// The `S…` secret seed of account `index`, the form Lobstr, Freighter and
/// the Stellar SDKs import. This is the account's private key in text: show it
/// only on an explicit request, never log it. The returned string wipes itself
/// when dropped.
pub fn export_secret_seed(seed: &Seed, index: u32) -> Result<Zeroizing<String>, Error> {
    let key = signing_key(seed, index)?;
    let secret = PrivateKey(*key.expose_secret());
    let mut text = secret.as_unredacted().to_string();
    let out = Zeroizing::new(text.as_str().to_owned());
    text.zeroize();
    Ok(out)
}

/// Circle's USDC on the public network: the issuer of the `USDC` asset
/// (7 decimals). Horizon lists the asset under this issuer, whose home domain
/// is `circle.com`, and Centre's `stellar.toml` names it among its accounts.
pub const USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Reads a `G…` address into its 32-byte key. A muxed address (`M…`), a secret
/// (`S…`) or anything else is `None`: this is the account of a key (an issuer, a
/// signer), and a payment's destination is read by [`parse_destination`].
#[must_use]
pub fn parse_address(text: &str) -> Option<[u8; 32]> {
    PublicKey::from_string(text).ok().map(|key| key.0)
}

/// Who a payment is paid, as the address it was given says: an account (`G…`), or a muxed account
/// (`M…`, SEP-23), which is an account and the 64-bit id its owner gave this address, so that
/// one account (an exchange's) can tell its customers apart without a memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    /// The account.
    pub key: [u8; 32],
    /// The id of a muxed address; `None` for a plain one.
    pub id: Option<u64>,
}

/// Reads the address a payment is sent to: `G…`, or `M…`. A secret (`S…`), a contract (`C…`), a
/// checksum that does not hold, a padded or cut one, or anything else is `None`.
#[must_use]
pub fn parse_destination(text: &str) -> Option<Destination> {
    if let Some(key) = parse_address(text) {
        return Some(Destination { key, id: None });
    }
    stellar_strkey::ed25519::MuxedAccount::from_string(text)
        .ok()
        .map(|muxed| Destination { key: muxed.ed25519, id: Some(muxed.id) })
}

/// The `M…` address of `key` with `id`, as SEP-23 writes it.
#[must_use]
pub fn muxed_address(key: &[u8; 32], id: u64) -> String {
    stellar_strkey::ed25519::MuxedAccount { ed25519: *key, id }.to_string().as_str().to_owned()
}

/// Why a transaction could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StellarError {
    /// The transaction is not one the network would accept.
    #[error(transparent)]
    Transaction(#[from] XdrError),
    /// The key is not an ed25519 key.
    #[error("a Stellar transaction is signed with an ed25519 key")]
    WrongKeyScheme,
    /// The transaction's source is another account than the key's.
    #[error("the key is not the transaction's source account")]
    NotTheSource,
}

/// A signed transaction, ready to submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The transaction envelope's XDR.
    pub envelope: Vec<u8>,
    /// The transaction's hash: its id on the network.
    pub hash: [u8; 32],
    /// The signature, over the hash.
    pub signature: [u8; 64],
}

impl SignedTransaction {
    /// The envelope in base64, the form Horizon's submit endpoint takes.
    #[must_use]
    pub fn envelope_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.envelope)
    }

    /// The hash in lowercase hex, as explorers show it.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        use std::fmt::Write as _;
        self.hash.iter().fold(String::with_capacity(64), |mut out, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
    }
}

/// Signs `transaction` for the network named by `network_passphrase`
/// ([`PUBLIC_NETWORK_PASSPHRASE`] for the public one): ed25519 over the
/// SHA-256 of the network id, the envelope type and the transaction's XDR.
///
/// # Errors
/// [`StellarError`] if the transaction is invalid, the key is not ed25519 or
/// the key is not the transaction's source.
pub fn sign_transaction(
    key: &SigningKey,
    network_passphrase: &str,
    transaction: &Transaction,
) -> Result<SignedTransaction, StellarError> {
    if key.scheme() != KeyScheme::Ed25519 {
        return Err(StellarError::WrongKeyScheme);
    }
    if key.public_key() != transaction.source.as_slice() {
        return Err(StellarError::NotTheSource);
    }
    let body = transaction.encode()?;
    let hash = xdr::transaction_hash(&xdr::network_id(network_passphrase), &body);
    // The dalek key wipes itself when dropped.
    let signature =
        ed25519_dalek::SigningKey::from_bytes(key.expose_secret()).sign(&hash).to_bytes();
    let hint = xdr::signature_hint(&transaction.source);
    Ok(SignedTransaction { envelope: xdr::envelope(&body, &[(hint, signature)]), hash, signature })
}
