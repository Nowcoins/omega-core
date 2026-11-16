//! Signing for the unlocked wallet: the same small surface the Chrome extension
//! gets from `nc-wallet-wasm`, over the same `nc-wallet-session`.
//!
//! A transfer is one JSON request. [`decode_request`] reads it, checks it
//! against the account that would sign and says what it would do (the summary
//! the review screen shows) with an **approval hash**. [`sign_request`] reads
//! the same request again, recomputes the hash and signs only if it is the one
//! that was approved, so a request that changed after the screen was drawn, or
//! that would sign something other than the summary says, cannot be signed.
//!
//! **The private key never leaves Rust.** It is derived inside
//! [`sign_request`] from the unlocked wallet, used once and wiped; what crosses
//! to Dart is the summary, the approval hash and the signed transaction (public
//! bytes to broadcast). No error value carries an address, an amount or a key.

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use flutter_rust_bridge::frb;

use super::accounts::NetworkId;
use crate::engine::engine;

/// Why a request could not be decoded or signed. The app puts each in its own
/// words; none carries a value or a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// The wallet is locked.
    NotUnlocked,
    /// The account number is out of range.
    AccountIndexOutOfRange,
    /// The request is malformed, or its numbers disagree (a field that is
    /// missing, of the wrong type, out of range; an address that is not the
    /// network's; inputs for another chain).
    BadRequest,
    /// The request is of a kind this wallet does not sign.
    Unsupported,
    /// The inputs are not paid to this account.
    NotASigner,
    /// The request is not the one the approval was made for: it changed
    /// after it was decoded.
    ApprovalMismatch,
    /// The coins on hand do not cover the amount and the fee.
    InsufficientFunds,
    /// The amount is below what the network relays.
    Dust,
    /// The recipient has no trustline for the asset (Stellar).
    NoTrustline,
    /// The recipient asks for a memo (Stellar).
    MemoRequired,
    /// The recipient is a token account, not a wallet (Solana).
    RecipientIsTokenAccount,
    /// The message to sign looks like a transaction.
    LooksLikeTransaction,
    /// The network fee is above the most this wallet will pay, whatever an
    /// endpoint said (`nc_wallet_core::limits`).
    FeeTooHigh,
    /// The network fee is one the person has to accept first, and the request did not say they
    /// had (`fee_ok`).
    FeeNotAccepted,
    /// The signature could not be made.
    Unavailable,
}

/// A request read and checked: what the review screen shows, and the hash that
/// must be handed back to [`sign_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    /// The summary as JSON: `request`, `network`, `signer`, `action`,
    /// `details`, `fee`, `warnings` (and `tx` for an EVM transaction). Amounts
    /// are decimal strings.
    pub summary_json: String,
    /// The approval hash: 64 lower-case hex digits.
    pub approval: String,
}

/// Why text is not an address on a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressProblem {
    /// Nothing was typed.
    Empty,
    /// The wrong shape for the network.
    Format,
    /// An EVM address in mixed case that is not its EIP-55 checksum.
    Checksum,
    /// The all-zero address.
    ZeroAddress,
    /// The network is not one the wallet serves.
    UnsupportedNetwork,
}

/// Whether text is an address on a network, as the core checks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCheck {
    /// Whether the text is an address on that network.
    pub valid: bool,
    /// The canonical form: the EIP-55 checksum form for the EVM networks, the
    /// text itself for the others. `None` when not valid.
    pub normalized: Option<String>,
    /// Why not, when not valid.
    pub problem: Option<AddressProblem>,
}

/// Reads a signing request (JSON, see `nc-wallet-session`'s `signing` module)
/// and says what it would do for account number `index`. Nothing is signed.
/// The wallet must be unlocked: the summary names the signer.
pub fn decode_request(index: u32, request: String) -> Result<DecodedRequest, SigningError> {
    let decoded = engine().decode_request(index, &request)?;
    Ok(DecodedRequest {
        summary_json: decoded.summary.to_string(),
        approval: crate::engine::hex(&decoded.approval),
    })
}

/// Signs `request` if `approval` (64 hex digits, from [`decode_request`]) is
/// the one it was decoded to. Returns the answer as JSON: for a `send`,
/// `{ network, raw, encoding, hash }`, which is what the broadcast route
/// takes. The key is derived, used and wiped inside.
pub fn sign_request(index: u32, request: String, approval: String) -> Result<String, SigningError> {
    let approval = crate::engine::parse_approval(&approval).ok_or(SigningError::BadRequest)?;
    Ok(engine().sign_request(index, &request, &approval)?.to_string())
}

/// The extended public key (`zpub…`) of Bitcoin account `index` (BIP-84 `m/84'/0'/index'`).
/// It finds every receive and change address of the account without any private key. It is for
/// the chain client alone, which asks public endpoints about addresses derived from it: whoever
/// holds it sees all the account's addresses, so it is never shown, logged or sent to a server.
pub fn bitcoin_zpub(index: u32) -> Result<String, SigningError> {
    Ok(engine().bitcoin_zpub(index)?)
}

/// Whether `text` is an address on `network`, checked by the core (checksums
/// included). Needs no wallet. The text is checked as it is: trim it first.
#[frb(sync)]
pub fn validate_address(network: NetworkId, text: String) -> AddressCheck {
    crate::engine::validate_address(network, &text)
}

/// The address lookup tables a Solana transaction loads accounts through, as base58 addresses: the app
/// fetches these (from two operators that must agree) and hands them to a `solana_transaction` request's
/// `lookup_tables`. A transaction with none needs none. Needs no wallet: it only reads the transaction.
#[frb(sync)]
pub fn solana_lookup_tables(transaction_base64: String) -> Result<Vec<String>, SigningError> {
    crate::engine::solana_lookup_tables(&transaction_base64)
}
