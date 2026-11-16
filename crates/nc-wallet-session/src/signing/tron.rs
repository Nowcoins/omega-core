//! TRON requests from a web page: a transaction it built (`tron_transaction`) and a message
//! (`tron_message`, `signMessageV2`). The wallet's own TRON transfers are `send` requests
//! ([`super::send`]).
//!
//! # A page's transaction
//!
//! `TronWeb` builds a transaction through a node and the page hands the wallet its `raw_data_hex`.
//! The wallet reads those bytes itself ([`nc_wallet_core::tron::TronTransaction::from_raw_data`],
//! which is strict and canonical) and shows what they say, never what the page's JSON says; the
//! bytes the person approved are the bytes signed, and the approval hash covers them.
//!
//! What is read: a TRX transfer and a smart-contract call. Every other kind of transaction is
//! `Unsupported`, and the ones that take an account away (a permission update, which can hand its
//! control to someone else) are named in the refusal. The summary uses the EVM request's words for
//! the same things (`native_transfer`, `token_transfer`, `token_approve`, `token_transfer_from`,
//! `set_approval_for_all`, `contract_call`) so that the approval screen reads them in one place.
//!
//! The request is `{ kind, raw_data_hex, estimate }`. `estimate` is the chain client's
//! `tron_estimate` for these bytes (the energy the call would use as two operators say it, the
//! bandwidth, the prices, the fee the account would burn for them); the fee shown is its fee.
//! What the transaction may burn at most is its own `fee_limit`, which the wallet bounds
//! ([`nc_wallet_core::limits::TRON_DAPP_FEE_LIMIT`]): above the first line the person has to accept
//! it, above the second the transaction is refused.

use nc_wallet_core::Network;
use nc_wallet_core::limits;
use nc_wallet_core::text;
use nc_wallet_core::tron::{self, Call, RawDataError, TronTransaction};
use serde_json::{Value, json};

use super::json::{self, Obj, bad};
use super::signer_address;
use super::text::{map_origin, message_details, message_warnings};
use super::warning;
use super::{Action, Prepared, Secrets, SigningError, Summary, derive_key, fee_json, hexs};
use crate::types::NetworkId;

/// The most bytes of `raw_data` a request may carry (a contract creation is the largest transaction; this
/// wallet signs none, and a call is a few hundred bytes).
const MAX_RAW: usize = 32_768;
/// The most bytes of a message a request may carry.
const MAX_MESSAGE: usize = 131_072;
/// How much call data a summary repeats.
const SHOWN_DATA: usize = 4096;

fn address(bytes: &tron::AddressBytes) -> String {
    tron::format_address(bytes)
}

/// Says why a page's bytes were not read.
fn unreadable(error: RawDataError) -> SigningError {
    match error {
        RawDataError::Unsupported(what) => {
            SigningError::new("Unsupported", format!("Nowcoin Omega does not sign {what}"))
        }
        RawDataError::Malformed(what) => bad(format!("raw_data_hex: {what}")),
    }
}

// ---- a transaction ----

pub(super) fn prepare_transaction(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "raw_data_hex", "estimate"], "the request")?;
    let raw = hexs::decode(json::string(map, "raw_data_hex")?)
        .filter(|raw| !raw.is_empty() && raw.len() <= MAX_RAW)
        .ok_or_else(|| bad("raw_data_hex is not hex digits, or is empty or too long"))?;
    let tx = TronTransaction::from_raw_data(&raw).map_err(unreadable)?;
    // The network's own rules (an amount, a time, a fee limit on a call), before anything is shown.
    tx.validate()?;
    let signer = signer_address(secrets, Network::Tron, index)?;
    if address(tx.owner()) != signer {
        return Err(SigningError::new(
            "NotASigner",
            "the transaction is not from the account that would sign",
        ));
    }
    if let Some(limit) = tx.fee_limit
        && !limits::TRON_DAPP_FEE_LIMIT.allows(u128::from(limit))
    {
        return Err(SigningError::new(
            "FeeTooHigh",
            "the transaction may burn more for energy than the most this wallet allows a site to ask for",
        ));
    }

    let estimate = json::object(map, "estimate")?;
    if let Some(echoed) = json::opt_string(estimate, "network")?
        && echoed != "tron"
    {
        return Err(bad("estimate is for another network"));
    }
    let fee = json::object(estimate, "fee")?;
    let fee_sun = json::api_u128(fee, "amount")?;
    let energy = json::api_u64(estimate, "energy")?;
    let bandwidth = json::api_u64(estimate, "bandwidth")?;
    let energy_price = json::api_u64(estimate, "energy_price_sun")?;
    let bandwidth_price = json::api_u64(estimate, "bandwidth_price_sun")?;
    let energy_fee = json::opt_api_u128(estimate, "energy_fee")?;

    let mut warnings = Vec::new();
    let (action, details) = match tx.describe() {
        Call::TrxTransfer { to, amount } => {
            ("native_transfer", json!({ "recipient": address(&to), "amount": amount.to_string() }))
        }
        Call::Trc20Transfer { token, to, amount } => (
            "token_transfer",
            json!({
                "token": address(&token),
                "recipient": address(&to),
                "amount": amount.to_string(),
            }),
        ),
        Call::Trc20Approve { token, spender, amount, unlimited } => {
            if unlimited {
                warnings.push(warning::UNLIMITED_APPROVAL);
            }
            (
                "token_approve",
                json!({
                    "token": address(&token),
                    "spender": address(&spender),
                    "amount": amount.to_string(),
                    "unlimited": unlimited,
                }),
            )
        }
        Call::Trc20TransferFrom { token, from, to, amount } => (
            "token_transfer_from",
            json!({
                "token": address(&token),
                "from": address(&from),
                "recipient": address(&to),
                "amount": amount.to_string(),
            }),
        ),
        Call::SetApprovalForAll { contract, operator, approved } => {
            if approved {
                warnings.push(warning::APPROVAL_FOR_ALL);
            }
            (
                "set_approval_for_all",
                json!({
                    "contract": address(&contract),
                    "operator": address(&operator),
                    "approved": approved,
                }),
            )
        }
        Call::UnknownContractCall { contract, call_value, selector, data_len } => {
            warnings.push(warning::UNKNOWN_CONTRACT_CALL);
            let data = match &tx.contract {
                tron::Contract::TriggerSmartContract { data, .. } => data.as_slice(),
                tron::Contract::Transfer { .. } => &[],
            };
            let shown = &data[..data.len().min(SHOWN_DATA)];
            (
                "contract_call",
                json!({
                    "contract": address(&contract),
                    "selector": selector.map(|s| hexs::encode_0x(&s)),
                    "data_len": data_len,
                    "data": hexs::encode_0x(shown),
                    "data_truncated": data.len() > SHOWN_DATA,
                    "value": call_value.to_string(),
                }),
            )
        }
    };
    // A call whose energy, at the price now, costs more than it is allowed to burn will run out and still
    // burn the whole limit: the person is told before it is sent.
    let is_call = matches!(tx.contract, tron::Contract::TriggerSmartContract { .. });
    if is_call && energy_fee.is_some_and(|burn| u128::from(tx.fee_limit.unwrap_or(0)) < burn) {
        warnings.push(warning::FEE_LIMIT_LOW);
    }

    // A memo is the site's text, read as the Solana memo is (`nc_wallet_core::text`): `memo` is the text only where
    // nothing is hidden in it; `memo_escaped` is always safe to show (each hidden or control character written as
    // `<U+202E>`, or the bytes as hex where they are not UTF-8); `memo_hidden` counts what was written out.
    let memo = tx.memo.as_deref().map(|bytes| {
        let found = text::inspect(bytes);
        let escaped = found.escaped.clone().unwrap_or_else(|| hexs::encode_0x(bytes));
        (found, escaped)
    });
    let memo_hidden = memo.as_ref().map(|(found, _)| found.hidden + found.control);
    if memo_hidden.is_some_and(|hidden| hidden > 0) {
        warnings.push(warning::HIDDEN_CHARACTERS);
    }
    let summary = Summary {
        request: "tron_transaction",
        network: "tron".to_owned(),
        signer: signer.clone(),
        action,
        details,
        tx: Some(json!({
            "txid": hexs::encode(&tx.txid()),
            "energy": energy.to_string(),
            "bandwidth": bandwidth.to_string(),
            "energy_price_sun": energy_price.to_string(),
            "bandwidth_price_sun": bandwidth_price.to_string(),
            "fee_limit": tx.fee_limit.map(|limit| limit.to_string()),
            "timestamp_ms": tx.timestamp_ms,
            "expiration_ms": tx.expiration_ms,
            "memo": memo.as_ref().and_then(|(found, _)| found.text.clone()),
            "memo_escaped": memo.as_ref().map(|(_, escaped)| escaped),
            "memo_hidden": memo_hidden,
        })),
        fee: Some(fee_json(NetworkId::Tron, fee_sun)),
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "tron_transaction",
        network: "tron".to_owned(),
        signer,
        summary,
        payload: tx.raw_data(),
        action: Action::Tron(tx),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

pub(super) fn sign_transaction(
    secrets: &Secrets,
    index: u32,
    tx: &TronTransaction,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Tron, index)?;
    let signed = tx.sign(&key)?;
    // `signature` is what `TronWeb` puts in `signature: [..]` (`r ‖ s ‖ recovery id`, 0 or 1); `transaction`
    // is the signed message `/wallet/broadcasthex` takes.
    Ok(json!({
        "txid": signed.txid_hex(),
        "signature": hexs::encode(&signed.signature),
        "transaction": signed.transaction_hex(),
        "raw_data_hex": hexs::encode(&signed.raw_data),
    }))
}

// ---- a message ----

pub(super) fn prepare_message(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "message_hex", "origin"], "the request")?;
    let message = hexs::decode_0x(json::string(map, "message_hex")?)
        .ok_or_else(|| bad("message_hex is not 0x and hex digits"))?;
    if message.len() > MAX_MESSAGE {
        return Err(bad("message_hex is larger than the wallet takes"));
    }
    let signer = signer_address(secrets, Network::Tron, index)?;
    let mut details = message_details(&message, "Tron", &signer, map_origin(map)?);
    details["message_hex"] = json!(hexs::encode_0x(&message));
    let mut warnings = message_warnings(&details);
    // 32 bytes, or a 32-byte hash written out in hex, with `0x` or without (a transaction id is written without).
    let hash_like = message.len() == 32
        || details["text"].as_str().is_some_and(|t| {
            let digits = t.strip_prefix("0x").unwrap_or(t);
            digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit())
        });
    if hash_like {
        warnings.push(warning::HASH_LIKE_MESSAGE);
    }
    let summary = Summary {
        request: "tron_message",
        network: "tron".to_owned(),
        signer: signer.clone(),
        action: "sign_message",
        details,
        tx: None,
        fee: None,
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "tron_message",
        network: "tron".to_owned(),
        signer,
        summary,
        payload: message.clone(),
        action: Action::TronMessage(message),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

pub(super) fn sign_message(
    secrets: &Secrets,
    index: u32,
    message: &[u8],
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Tron, index)?;
    let signature = tron::sign_message(&key, message)?;
    // `TronWeb`'s `signMessageV2` answers `0x` and `r ‖ s ‖ v` with `v` 27 or 28.
    Ok(json!({ "signature": hexs::encode_0x(&signature.to_rsv(27)) }))
}
