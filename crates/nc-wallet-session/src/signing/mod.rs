//! Signing for the unlocked wallet: what a dApp asks for, and the wallet's own
//! transfers, as one JSON request in and one JSON answer out.
//!
//! # Two calls on one parsed request
//!
//! [`Engine::decode_request`] reads a request, checks it against the account
//! that would sign, and returns the **summary** the approval screen shows and
//! an **approval hash**. [`Engine::sign_request`] reads the *same request*
//! again through the *same function*, recomputes the hash and refuses
//! ([`SigningError`] `ApprovalMismatch`) unless it equals the one the person
//! approved. The hash covers the kind, the network, the signer, **the exact
//! bytes that are signed** and the summary text, so a request that changed
//! after the screen was drawn, or that would sign something other than what the
//! summary says, cannot be signed. The private key is derived inside
//! [`Engine::sign_request`], used once and wiped; no summary, answer or error
//! contains it.
//!
//! # Requests
//!
//! A request is a JSON object with a `kind`:
//!
//! | `kind` | What | Module |
//! |---|---|---|
//! | `evm_transaction` | a dApp's `eth_sendTransaction`, filled in by the wallet | [`evm`] |
//! | `evm_personal_sign` | `personal_sign` (EIP-191) | [`evm`] |
//! | `evm_typed_data` | `eth_signTypedData_v4` (EIP-712) | [`evm`] |
//! | `solana_transaction` | `signTransaction` / `signAndSendTransaction` | [`solana`] |
//! | `solana_message` | `signMessage` | [`solana`] |
//! | `tron_transaction` | a TRON transaction a page built (`TronWeb`'s `trx.sign`), read from its `raw_data_hex` | [`tron`] |
//! | `tron_message` | `signMessageV2` | [`tron`] |
//! | `send` | the wallet's own transfer on any of the nine networks, built from the wallet API's `inputs` and `estimate` | [`send`] |
//!
//! Our own numbers are decimal strings. The wallet API's `inputs` and
//! `estimate` bodies are passed through as they came: where they hold integers,
//! a JSON number or a decimal string is read. Fields a request does not define
//! are refused, except inside those two API bodies and the token entry of
//! `asset` (all three may grow fields).
//!
//! # Decisions where the contract left a choice
//!
//! * A field that is missing, of the wrong type, out of range, or a request
//!   larger than 256 KiB is `BadRequest`. Its `detail` names the field and
//!   never repeats a value (an address, an amount) or anything secret.
//! * A dApp transaction may be addressed to the all-zero address (the approval
//!   screen shows it); a transfer sent from the wallet may not.
//! * Typed data whose domain names another chain than the request's network is decoded, with the
//!   warning `chain_mismatch` so that it can be shown, and is signed only if the request carries
//!   `allow_chain_mismatch: true` (`ChainMismatch` otherwise), as `fee_ok` is for a high fee: not
//!   part of what is approved, and set by an app only after the person has been told.
//! * A Solana transaction whose signature slots are not ours is left as it
//!   was; only our own slot is filled. A transaction of more than 1232 bytes is
//!   `BadRequest` (the network takes no more).
//! * `send_max` is read by Bitcoin only (`Amount::All`); every other network's
//!   maximum is worked out by the app from balance, fee and reserve, and sent
//!   as `amount`.
//! * Amounts above 2^128 are `BadRequest` (every coin and token the wallet
//!   lists fits 128 bits many times over).
//! * Bitcoin spends confirmed outputs, and unconfirmed outputs only on the
//!   change chain (the wallet's own change). Change goes to the change address
//!   of the same account index.
//! * Solana: a token source other than the associated account is used only
//!   when the associated one cannot cover the amount. The fee shown is
//!   `estimate.fee` (base plus priority); the rent for a new token account is
//!   `details.account_creation`.

mod address;
mod evm;
mod hexs;
mod json;
mod send;
mod solana;
mod text;
mod tron;
mod warning;

#[cfg(test)]
mod tests;

use std::fmt;

use nc_wallet_core::bitcoin::Plan;
use nc_wallet_core::evm::{EvmTransaction, TypedData};
use nc_wallet_core::tron::TronTransaction;
use nc_wallet_core::{Error as CoreError, Network, SigningKey, TxError, bittensor, stellar};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::engine::{Engine, Secrets};
use crate::types::NetworkId;

pub use address::{AddressCheck, MAX_ADDRESS_LEN, validate_address};
pub use solana::lookup_tables_needed as solana_lookup_tables;

/// The most bytes a request may have.
const MAX_REQUEST: usize = 262_144;

/// Why a request could not be decoded or signed. `code` is stable (the
/// extension matches on it); `detail` is a safe sentence for a log or a
/// message: it names a field or a rule and carries no value and no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningError {
    code: &'static str,
    detail: String,
}

impl SigningError {
    pub(crate) fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }

    /// `NotUnlocked`, `AccountIndexOutOfRange`, `BadRequest`, `Unsupported`,
    /// `NotASigner`, `ApprovalMismatch`, `InsufficientFunds`, `Dust`,
    /// `NoTrustline`, `MemoRequired`, `RecipientIsTokenAccount`,
    /// `LooksLikeTransaction`, `FeeTooHigh`, `FeeNotAccepted`, `ChainMismatch` or `Unavailable`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// A safe sentence saying what is wrong.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for SigningError {}

impl From<TxError> for SigningError {
    fn from(error: TxError) -> Self {
        match error {
            TxError::Invalid { field, reason } => {
                Self::new("BadRequest", format!("{field}: {reason}"))
            }
            TxError::Address(_) => {
                Self::new("BadRequest", "an address is not valid for this network")
            }
            TxError::InsufficientFunds { .. } => Self::new(
                "InsufficientFunds",
                "the coins on hand do not cover the amount and the fee",
            ),
            TxError::Dust { .. } => {
                Self::new("Dust", "the amount is below what the network relays")
            }
            TxError::KeyMismatch { .. } => {
                Self::new("NotASigner", "an input is not paid to this account")
            }
            TxError::TypedData(reason) => Self::new("BadRequest", format!("typed data: {reason}")),
            TxError::Key(error) => error.into(),
            TxError::WrongKeyScheme | TxError::Signing | _ => {
                Self::new("Unavailable", "the signature could not be made")
            }
        }
    }
}

impl From<CoreError> for SigningError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::IndexOutOfRange(_) => {
                Self::new("AccountIndexOutOfRange", "the account number is out of range")
            }
            // A wallet that is one imported private key, asked for a network (or an account
            // number) its key is not an account on.
            CoreError::KeyDoesNotReach => Self::new(
                "Unsupported",
                "this wallet's private key is not an account on that network",
            ),
            _ => Self::new("Unavailable", "the account's key could not be made"),
        }
    }
}

/// What [`Engine::decode_request`] returns.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// What the approval screen shows: `request`, `network`, `signer`,
    /// `action`, `details`, `fee`, `warnings` (and `tx` for an EVM
    /// transaction).
    pub summary: Value,
    /// The approval hash, to be handed back to [`Engine::sign_request`].
    pub approval: [u8; 32],
}

/// One request, read and checked, with everything needed to sign it.
pub(crate) struct Prepared {
    /// The request's `kind`.
    pub(crate) kind: &'static str,
    /// The network id the summary names.
    pub(crate) network: String,
    /// The signing account's address on that network.
    pub(crate) signer: String,
    pub(crate) summary: Value,
    /// The exact bytes that are signed (or hashed to be signed).
    pub(crate) payload: Vec<u8>,
    pub(crate) action: Action,
    /// Whether the answer is a transaction to broadcast (`send`).
    pub(crate) send: bool,
    /// The fee is above what a lone operator may quote, or the engine warned of it: the person must
    /// accept it before anything is signed. Set centrally by [`fee_is_high`].
    pub(crate) fee_high: bool,
    /// The request carried the person's explicit acceptance of a high fee (`fee_ok`).
    pub(crate) fee_ok: bool,
    /// The request carried the person's explicit word that typed data for another chain may be signed
    /// (`allow_chain_mismatch`).
    pub(crate) chain_mismatch_ok: bool,
}

/// What is signed, built and checked.
pub(crate) enum Action {
    EvmTransaction(EvmTransaction),
    PersonalSign(Vec<u8>),
    TypedData(TypedData),
    SolanaTransaction(Vec<u8>),
    SolanaMessage(Vec<u8>),
    Tron(TronTransaction),
    TronMessage(Vec<u8>),
    Bitcoin(Plan),
    Stellar(stellar::Transaction),
    Bittensor(bittensor::Transfer),
}

/// The summary under construction.
pub(crate) struct Summary {
    pub(crate) request: &'static str,
    pub(crate) network: String,
    pub(crate) signer: String,
    pub(crate) action: &'static str,
    pub(crate) details: Value,
    pub(crate) tx: Option<Value>,
    pub(crate) fee: Option<Value>,
    pub(crate) warnings: Vec<warning::Code>,
}

impl Summary {
    pub(crate) fn into_value(self) -> Value {
        let mut map = Map::new();
        map.insert("request".into(), Value::from(self.request));
        map.insert("network".into(), Value::from(self.network));
        map.insert("signer".into(), Value::from(self.signer));
        map.insert("action".into(), Value::from(self.action));
        map.insert("details".into(), self.details);
        if let Some(tx) = self.tx {
            map.insert("tx".into(), tx);
        }
        map.insert("fee".into(), self.fee.unwrap_or(Value::Null));
        map.insert("warnings".into(), self.warnings.into_iter().map(Value::from).collect());
        Value::Object(map)
    }
}

/// The network's own coin and its decimals.
pub(crate) const fn native(network: NetworkId) -> (&'static str, u8) {
    match network {
        NetworkId::Ethereum | NetworkId::Base => ("ETH", 18),
        NetworkId::BnbChain => ("BNB", 18),
        NetworkId::Polygon => ("POL", 18),
        NetworkId::Tron => ("TRX", 6),
        NetworkId::Bitcoin => ("BTC", 8),
        NetworkId::Solana => ("SOL", 9),
        NetworkId::Stellar => ("XLM", 7),
        NetworkId::Bittensor => ("TAO", 9),
    }
}

/// A fee in the network's native coin.
pub(crate) fn fee_json(network: NetworkId, amount: u128) -> Value {
    let (asset, decimals) = native(network);
    json!({ "asset": asset, "amount": amount.to_string(), "decimals": decimals })
}

/// The address of account `index` on `family`.
pub(crate) fn signer_address(
    secrets: &Secrets,
    family: Network,
    index: u32,
) -> Result<String, SigningError> {
    Ok(secrets.account(family, index)?.address)
}

/// The public key of account `index` on `family`.
pub(crate) fn signer_public_key(
    secrets: &Secrets,
    family: Network,
    index: u32,
) -> Result<Vec<u8>, SigningError> {
    Ok(secrets.account(family, index)?.public_key)
}

/// The private key of account `index` on `family`, for one signature.
pub(crate) fn derive_key(
    secrets: &Secrets,
    family: Network,
    index: u32,
) -> Result<SigningKey, SigningError> {
    Ok(secrets.signing_key(family, index)?)
}

/// Reads a request and builds everything needed to show it and to sign it.
fn prepare(secrets: &Secrets, index: u32, request: &str) -> Result<Prepared, SigningError> {
    if request.len() > MAX_REQUEST {
        return Err(json::bad("the request is larger than the wallet takes"));
    }
    let value: Value =
        serde_json::from_str(request).map_err(|_| json::bad("the request is not valid JSON"))?;
    let map = json::as_object(&value, "the request")?;
    // `fee_ok` is the person's acceptance of a high fee; it is not part of what is signed or
    // approved, so a request is decoded without it and signed with it.
    let mut map = map.clone();
    let fee_ok = match map.remove("fee_ok") {
        None => false,
        Some(Value::Bool(flag)) => flag,
        Some(_) => return Err(json::bad("fee_ok is true or false")),
    };
    // So is `allow_chain_mismatch`, the person's word that typed data for another chain than the one asked
    // may be signed (see [`Engine::sign_request`]).
    let chain_mismatch_ok = match map.remove("allow_chain_mismatch") {
        None => false,
        Some(Value::Bool(flag)) => flag,
        Some(_) => return Err(json::bad("allow_chain_mismatch is true or false")),
    };
    let map = &map;
    let mut prepared = match json::string(map, "kind")? {
        "evm_transaction" => evm::prepare_transaction(secrets, index, map),
        "evm_personal_sign" => evm::prepare_personal_sign(secrets, index, map),
        "evm_typed_data" => evm::prepare_typed_data(secrets, index, map),
        "solana_transaction" => solana::prepare_transaction(secrets, index, map),
        "solana_message" => solana::prepare_message(secrets, index, map),
        "tron_transaction" => tron::prepare_transaction(secrets, index, map),
        "tron_message" => tron::prepare_message(secrets, index, map),
        "send" => send::prepare(secrets, index, map),
        _ => Err(json::bad("kind is not one this wallet signs")),
    }?;
    prepared.fee_ok = fee_ok;
    prepared.chain_mismatch_ok = chain_mismatch_ok;
    if fee_is_high(&prepared) {
        prepared.fee_high = true;
        if let Some(list) = prepared.summary.get_mut("warnings").and_then(Value::as_array_mut)
            && !list
                .iter()
                .any(|w| w == warning::FEE_HIGH.as_str() || w == warning::HIGH_FEE.as_str())
        {
            list.push(Value::from(warning::FEE_HIGH));
        }
    }
    #[cfg(test)]
    warning::assert_listed(&prepared.summary);
    Ok(prepared)
}

/// Whether the fee of what is prepared is above the wallet's own "high" line, in the network's coin, whatever
/// any price says: the most a lone operator may quote (`nc_wallet_core::limits`), or the engine's own
/// `high_fee` warning (a fee that is a large part of the amount). The person must then accept it:
/// the apps show a tick, and the engine refuses to sign without the request's `fee_ok`.
fn fee_is_high(prepared: &Prepared) -> bool {
    use nc_wallet_core::evm::{EvmChain, Fees};
    use nc_wallet_core::limits as lim;
    if warning::has(&prepared.summary, warning::HIGH_FEE) {
        return true;
    }
    let fee_amount = || -> u128 {
        prepared
            .summary
            .pointer("/fee/amount")
            .and_then(Value::as_str)
            .and_then(|a| a.parse().ok())
            .unwrap_or(0)
    };
    match &prepared.action {
        Action::EvmTransaction(tx) => {
            let Some(chain) = EvmChain::from_chain_id(tx.chain_id) else { return false };
            let (max_fee, tip) = match tx.fees {
                Fees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
                    (max_fee_per_gas, max_priority_fee_per_gas)
                }
                Fees::Legacy { gas_price } => (gas_price, 0),
            };
            let total = u128::from(tx.gas_limit).saturating_mul(max_fee);
            let bound = if prepared.send {
                lim::evm_total_fee(chain)
            } else {
                lim::evm_dapp_total_fee(chain)
            };
            bound.above_alone(total)
                || lim::evm_max_fee_per_gas(chain).above_alone(max_fee)
                || lim::evm_priority_fee(chain).above_alone(tip)
        }
        Action::SolanaTransaction(_) => lim::SOLANA_TOTAL_FEE.above_alone(fee_amount()),
        Action::Bitcoin(plan) => lim::BITCOIN_TOTAL.above_alone(u128::from(plan.fee)),
        Action::Tron(tx) => {
            // A site's contract call may name a higher cap than the wallet's own sends do.
            let bound = if prepared.send { lim::TRON_FEE_LIMIT } else { lim::TRON_DAPP_FEE_LIMIT };
            tx.fee_limit.is_some_and(|limit| bound.above_alone(u128::from(limit)))
        }
        Action::Stellar(tx) => lim::STELLAR_BASE_FEE.above_alone(u128::from(tx.fee)),
        Action::Bittensor(_) => lim::BITTENSOR_FEE.above_alone(fee_amount()),
        Action::PersonalSign(_)
        | Action::TypedData(_)
        | Action::SolanaMessage(_)
        | Action::TronMessage(_) => false,
    }
}

/// Whether what is prepared is typed data that the engine warned is for another chain.
fn is_for_another_chain(prepared: &Prepared) -> bool {
    matches!(prepared.action, Action::TypedData(_))
        && warning::has(&prepared.summary, warning::CHAIN_MISMATCH)
}

fn length_prefixed(hasher: &mut Sha256, part: &[u8]) {
    // Every part is far below 4 GiB (requests are capped at 256 KiB).
    hasher.update(u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(part);
}

/// The hash the approval keeps: the kind, the network, the signer, the bytes
/// that are signed and the summary that was shown.
fn approval_hash(prepared: &Prepared) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NCW-approval-v1");
    length_prefixed(&mut hasher, prepared.kind.as_bytes());
    length_prefixed(&mut hasher, prepared.network.as_bytes());
    length_prefixed(&mut hasher, prepared.signer.as_bytes());
    length_prefixed(&mut hasher, &prepared.payload);
    length_prefixed(&mut hasher, prepared.summary.to_string().as_bytes());
    hasher.finalize().into()
}

/// The answer to a `send` request: what `POST …/broadcast` takes, and the id
/// the API will return.
pub(crate) fn send_output(network: &str, raw: &str, encoding: &str, hash: &str) -> Value {
    json!({ "network": network, "raw": raw, "encoding": encoding, "hash": hash })
}

fn sign(secrets: &Secrets, index: u32, prepared: &Prepared) -> Result<Value, SigningError> {
    match &prepared.action {
        Action::EvmTransaction(tx) => evm::sign_transaction(secrets, index, prepared, tx),
        Action::PersonalSign(message) => evm::sign_personal(secrets, index, message),
        Action::TypedData(data) => evm::sign_typed_data(secrets, index, data),
        Action::SolanaTransaction(bytes) => {
            solana::sign_transaction(secrets, index, prepared, bytes)
        }
        Action::SolanaMessage(bytes) => solana::sign_message(secrets, index, bytes),
        Action::Tron(tx) if prepared.send => send::sign_tron(secrets, index, prepared, tx),
        Action::Tron(tx) => tron::sign_transaction(secrets, index, tx),
        Action::TronMessage(message) => tron::sign_message(secrets, index, message),
        Action::Bitcoin(plan) => send::sign_bitcoin(secrets, index, prepared, plan),
        Action::Stellar(tx) => send::sign_stellar(secrets, index, prepared, tx),
        Action::Bittensor(transfer) => send::sign_bittensor(secrets, index, prepared, transfer),
    }
}

impl Engine {
    fn signing_secrets(&self) -> Result<&Secrets, SigningError> {
        self.unlocked_secrets()
            .ok_or_else(|| SigningError::new("NotUnlocked", "the wallet is locked"))
    }

    /// Reads `request` (see the module docs) and says what it would do.
    ///
    /// `index` is the account that would sign. Nothing is signed; the wallet
    /// must be unlocked, because the summary names the signer.
    pub fn decode_request(&self, index: u32, request: &str) -> Result<Decoded, SigningError> {
        let secrets = self.signing_secrets()?;
        let prepared = prepare(secrets, index, request)?;
        let approval = approval_hash(&prepared);
        Ok(Decoded { summary: prepared.summary, approval })
    }

    /// Signs `request`, if it is the one `approval` was made for.
    ///
    /// The request is read again from its text, so what is signed is what
    /// [`Engine::decode_request`] described: any change to the request, the
    /// account or the bytes that would be signed is `ApprovalMismatch`.
    pub fn sign_request(
        &self,
        index: u32,
        request: &str,
        approval: &[u8; 32],
    ) -> Result<Value, SigningError> {
        let secrets = self.signing_secrets()?;
        let prepared = prepare(secrets, index, request)?;
        if approval_hash(&prepared) != *approval {
            return Err(SigningError::new(
                "ApprovalMismatch",
                "the request is not the one that was approved",
            ));
        }
        // A fee the engine calls high is signed only on the person's explicit acceptance.
        if prepared.fee_high && !prepared.fee_ok {
            return Err(SigningError::new(
                "FeeNotAccepted",
                "the network fee is high: the person has to accept it first",
            ));
        }
        // Typed data whose domain names another chain than the one asked for is the usual shape of a
        // cross-chain phishing permit, and MetaMask refuses it: it is signed only on the person's word.
        if is_for_another_chain(&prepared) && !prepared.chain_mismatch_ok {
            return Err(SigningError::new(
                "ChainMismatch",
                "the typed data is for another chain than the one asked: the person has to allow it first",
            ));
        }
        sign(secrets, index, &prepared)
    }

    /// The extended public key of Bitcoin account `index` (BIP-84 `m/84'/0'/index'`), a `zpub`
    /// that finds every receive and change address of the account without any private key.
    /// It is public data for reading, but it reveals every address of the account to whoever
    /// holds it: the apps pass it only to the chain client, which asks public endpoints about
    /// addresses it derives (see `docs/direct-chain.md`).
    pub fn bitcoin_zpub(&self, index: u32) -> Result<String, SigningError> {
        let secrets = self.signing_secrets()?;
        let seed = secrets.seed()?;
        Ok(nc_wallet_core::bitcoin::account_zpub(&seed, index)?)
    }
}
