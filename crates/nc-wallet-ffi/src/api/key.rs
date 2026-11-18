//! A wallet that is one private key, typed in by the person who holds it.
//!
//! A recovery phrase reaches every network; a private key reaches the networks
//! of its own kind and no other ([`WalletKind`]). The key crosses to Rust once,
//! as the text the person pasted ([`start_import_key`]), is sealed under the
//! password like a phrase ([`crate::api::vault::seal_pending`]), and comes back
//! to Dart in one place only: Settings, after the password is typed again
//! ([`reveal_key`]). [`check_key`] says what pasted text is without keeping it.

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

use super::error::WalletError;
use crate::engine;

/// What a wallet is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
    /// A recovery phrase: every network, any number of accounts.
    Phrase,
    /// One imported secp256k1 private key: Ethereum, BNB Chain, Polygon, Base and TRON.
    KeySecp256K1,
    /// One imported ed25519 private key: Solana.
    KeyEd25519,
}

/// What [`check_key`] found in the text a person pasted as a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProblem {
    /// Nothing typed yet.
    Empty,
    /// A private key the wallet can open.
    Valid,
    /// Not a private key in any form the wallet reads.
    Unrecognised,
    /// An address (of any of the networks), not a key.
    LooksLikeAnAddress,
    /// 64 hexadecimal digits that are not a key of the curve.
    NotOnCurve,
    /// A Solana secret key whose two halves do not belong together.
    HalvesDisagree,
}

/// The result of reading pasted text as a private key. Nothing of the key is in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCheck {
    /// What was found.
    pub problem: KeyProblem,
    /// For `Valid`: which kind of key it is, and so which networks it opens.
    pub kind: Option<WalletKind>,
}

/// Reads pasted text as a private key and says what it is: a key of which kind,
/// or what is wrong with it. The text is not kept.
#[frb(sync)]
pub fn check_key(text: String) -> KeyCheck {
    let text = Zeroizing::new(text);
    nc_wallet_session::check_key(&text).into()
}

/// Starts an imported wallet from one private key. Replaces any wallet being
/// made. `InvalidKey` for anything [`check_key`] does not call `Valid`.
pub fn start_import_key(text: String) -> Result<(), WalletError> {
    let text = Zeroizing::new(text);
    Ok(engine::engine().start_import_key(&text)?)
}

/// What the unlocked wallet (or, with none, the one being made) is.
/// `NotUnlocked` when there is neither.
#[frb(sync)]
pub fn wallet_kind() -> Result<WalletKind, WalletError> {
    Ok(engine::engine().wallet_kind()?.into())
}

/// The private key of a wallet that is one, as its owner would export it again,
/// for Settings, after the password is typed again. Nothing is unlocked or
/// locked by this. `HoldsAPhrase` for a wallet made of a recovery phrase.
pub fn reveal_key(vault: Vec<u8>, password: String) -> Result<String, WalletError> {
    engine::reveal_key(&vault, &Zeroizing::new(password))
}
