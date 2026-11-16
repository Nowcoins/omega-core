//! EVM requests: a transaction, `personal_sign` and EIP-712 typed data. The
//! `send` request for the four EVM networks builds an [`EvmTransaction`] and
//! comes through [`transaction_summary`] too, so a dApp's transaction and the
//! wallet's own transfer are described by the same code.

use nc_wallet_core::Network;
use nc_wallet_core::evm::{
    self, Call, EvmChain, EvmTransaction, Fees, Permit2Allowance, Permit2Token, TypedData,
    TypedDataKind, U256, checksum_address, known_contract_name,
};
use serde_json::{Map, Value, json};

use super::json::{self, Obj, bad};
use super::text::{map_origin, message_details, message_warnings};
use super::warning;
use super::{
    Action, Prepared, Secrets, SigningError, Summary, derive_key, fee_json, hexs, signer_address,
};
use nc_wallet_core::limits;

use crate::types::NetworkId;

/// The most bytes of a message or of call data a request may carry.
const MAX_BYTES: usize = 131_072;
/// How much call data a summary repeats.
const SHOWN_DATA: usize = 4096;

/// The `network` field of an EVM request.
pub(super) fn evm_network(map: &Obj) -> Result<(NetworkId, EvmChain), SigningError> {
    let id = json::string(map, "network")?;
    let network =
        NetworkId::from_api_id(id).ok_or_else(|| bad("network is not one this wallet serves"))?;
    let chain = match network {
        NetworkId::Ethereum => EvmChain::Ethereum,
        NetworkId::BnbChain => EvmChain::BnbChain,
        NetworkId::Polygon => EvmChain::Polygon,
        NetworkId::Base => EvmChain::Base,
        _ => return Err(bad("network is not an EVM network")),
    };
    Ok((network, chain))
}

fn address(bytes: &[u8; 20]) -> String {
    checksum_address(bytes)
}

fn parse_any(text: &str, field: &str) -> Result<[u8; 20], SigningError> {
    evm::parse_address_any(text).map_err(|error| match error {
        evm::AddressError::Checksum => bad(format!("{field} fails its address checksum")),
        _ => bad(format!("{field} is not an address")),
    })
}

fn signer(secrets: &Secrets, index: u32) -> Result<(String, [u8; 20]), SigningError> {
    let text = signer_address(secrets, Network::Evm, index)?;
    let bytes = evm::parse_address_any(&text)
        .map_err(|_| SigningError::new("Unavailable", "the account's address could not be made"))?;
    Ok((text, bytes))
}

// ---- kind 1: a transaction ----

const TRANSACTION_FIELDS: &[&str] =
    &["kind", "network", "from", "to", "value", "data", "nonce", "gas_limit", "fees"];

pub(super) fn prepare_transaction(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, TRANSACTION_FIELDS, "the request")?;
    let (network, chain) = evm_network(map)?;
    let (signer_text, signer_bytes) = signer(secrets, index)?;
    if let Some(from) = json::opt_string(map, "from")?
        && parse_any(from, "from")? != signer_bytes
    {
        return Err(SigningError::new("NotASigner", "from is not the account that would sign"));
    }
    let to = match map.get("to") {
        None | Some(Value::Null) => {
            return Err(SigningError::new("Unsupported", "creating a contract is not supported"));
        }
        Some(_) => parse_any(json::string(map, "to")?, "to")?,
    };
    let data = hexs::decode_0x(json::string(map, "data")?)
        .ok_or_else(|| bad("data is not 0x and hex digits"))?;
    if data.len() > MAX_BYTES {
        return Err(bad("data is larger than the wallet takes"));
    }
    let fees = object_fees(json::object(map, "fees")?)?;
    let tx = EvmTransaction {
        chain_id: chain.chain_id(),
        nonce: json::decimal_u64(map, "nonce")?,
        to,
        value: json::decimal_u128(map, "value")?,
        data,
        gas_limit: json::decimal_u64(map, "gas_limit")?,
        fees,
    };
    tx.validate()?;
    super::send::check_evm_rates(chain, &tx)?;
    // A site names the work its transaction may use; the wallet bounds it, and what it may cost in all.
    if tx.gas_limit > limits::EVM_DAPP_GAS_LIMIT {
        return Err(SigningError::new(
            "FeeTooHigh",
            "the transaction reserves more work than the most this wallet allows a site to ask for",
        ));
    }
    let max_fee = match tx.fees {
        Fees::Eip1559 { max_fee_per_gas, .. } => max_fee_per_gas,
        Fees::Legacy { gas_price } => gas_price,
    };
    if !limits::evm_dapp_total_fee(chain).allows(u128::from(tx.gas_limit).saturating_mul(max_fee)) {
        return Err(SigningError::new(
            "FeeTooHigh",
            "the network fee for this transaction is above the most this wallet will pay",
        ));
    }
    let summary = transaction_summary("evm_transaction", network, &signer_text, &tx)?;
    Ok(prepared_transaction("evm_transaction", network, signer_text, summary, tx, false))
}

fn object_fees(fees: &Obj) -> Result<Fees, SigningError> {
    match json::string(fees, "type")? {
        "eip1559" => {
            json::only(fees, &["type", "max_fee_per_gas", "max_priority_fee_per_gas"], "fees")?;
            Ok(Fees::Eip1559 {
                max_fee_per_gas: json::decimal_u128(fees, "max_fee_per_gas")?,
                max_priority_fee_per_gas: json::decimal_u128(fees, "max_priority_fee_per_gas")?,
            })
        }
        "legacy" => {
            json::only(fees, &["type", "gas_price"], "fees")?;
            Ok(Fees::Legacy { gas_price: json::decimal_u128(fees, "gas_price")? })
        }
        _ => Err(bad("fees.type is neither eip1559 nor legacy")),
    }
}

/// A transaction as a [`Prepared`] (also the end of an EVM `send`).
pub(super) fn prepared_transaction(
    kind: &'static str,
    network: NetworkId,
    signer: String,
    summary: Value,
    tx: EvmTransaction,
    send: bool,
) -> Prepared {
    Prepared {
        kind,
        network: network.api_id().to_owned(),
        signer,
        summary,
        payload: tx.signing_payload(),
        action: Action::EvmTransaction(tx),
        send,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    }
}

/// What a transaction does, as the approval screen says it.
pub(super) fn transaction_summary(
    request: &'static str,
    network: NetworkId,
    signer: &str,
    tx: &EvmTransaction,
) -> Result<Value, SigningError> {
    let mut warnings = Vec::new();
    let (action, details) = match tx.describe() {
        Call::NativeTransfer { to, value } => {
            ("native_transfer", json!({ "recipient": address(&to), "amount": value.to_string() }))
        }
        Call::Erc20Transfer { token, to, amount } => (
            "token_transfer",
            json!({ "token": address(&token), "recipient": address(&to), "amount": amount.to_string() }),
        ),
        Call::Erc20Approve { token, spender, amount, unlimited } => {
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
        Call::Erc20TransferFrom { token, from, to, amount } => (
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
        Call::UnknownContractCall { to, value, selector, data_len } => {
            warnings.push(warning::UNKNOWN_CONTRACT_CALL);
            let shown = &tx.data[..tx.data.len().min(SHOWN_DATA)];
            (
                "contract_call",
                json!({
                    "contract": address(&to),
                    "selector": selector.map(|s| hexs::encode_0x(&s)),
                    "data_len": data_len,
                    "data": hexs::encode_0x(shown),
                    "data_truncated": tx.data.len() > SHOWN_DATA,
                    "value": value.to_string(),
                }),
            )
        }
    };

    let mut fields = Map::new();
    fields.insert("chain_id".into(), Value::from(tx.chain_id));
    fields.insert("to".into(), Value::from(address(&tx.to)));
    fields.insert("value".into(), Value::from(tx.value.to_string()));
    fields.insert("nonce".into(), Value::from(tx.nonce.to_string()));
    fields.insert("gas_limit".into(), Value::from(tx.gas_limit.to_string()));
    let price = match tx.fees {
        Fees::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
            fields.insert("type".into(), Value::from("eip1559"));
            fields.insert("max_fee_per_gas".into(), Value::from(max_fee_per_gas.to_string()));
            fields.insert(
                "max_priority_fee_per_gas".into(),
                Value::from(max_priority_fee_per_gas.to_string()),
            );
            max_fee_per_gas
        }
        Fees::Legacy { gas_price } => {
            fields.insert("type".into(), Value::from("legacy"));
            fields.insert("gas_price".into(), Value::from(gas_price.to_string()));
            gas_price
        }
    };
    let fee = u128::from(tx.gas_limit)
        .checked_mul(price)
        .ok_or_else(|| bad("gas_limit times the gas price does not fit"))?;

    Ok(Summary {
        request,
        network: network.api_id().to_owned(),
        signer: signer.to_owned(),
        action,
        details,
        tx: Some(Value::Object(fields)),
        fee: Some(fee_json(network, fee)),
        warnings,
    }
    .into_value())
}

pub(super) fn sign_transaction(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    tx: &EvmTransaction,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Evm, index)?;
    let signed = tx.sign(&key)?;
    if prepared.send {
        Ok(super::send_output(&prepared.network, &signed.raw_hex(), "hex", &signed.hash_hex()))
    } else {
        Ok(json!({ "raw": signed.raw_hex(), "hash": signed.hash_hex() }))
    }
}

// ---- kind 2: personal_sign ----

pub(super) fn prepare_personal_sign(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "message_hex", "origin"], "the request")?;
    let message = hexs::decode_0x(json::string(map, "message_hex")?)
        .ok_or_else(|| bad("message_hex is not 0x and hex digits"))?;
    if message.len() > MAX_BYTES {
        return Err(bad("message_hex is larger than the wallet takes"));
    }
    let (signer_text, _) = signer(secrets, index)?;
    let mut details = message_details(&message, "Ethereum", &signer_text, map_origin(map)?);
    details["message_hex"] = Value::from(hexs::encode_0x(&message));
    let mut warnings = message_warnings(&details);
    let hash_like = message.len() == 32
        || details["text"].as_str().is_some_and(|t| {
            t.len() == 66 && t.starts_with("0x") && t[2..].bytes().all(|b| b.is_ascii_hexdigit())
        });
    if hash_like {
        warnings.push(warning::HASH_LIKE_MESSAGE);
    }
    let summary = Summary {
        request: "evm_personal_sign",
        network: "evm".to_owned(),
        signer: signer_text.clone(),
        action: "personal_sign",
        details,
        tx: None,
        fee: None,
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "evm_personal_sign",
        network: "evm".to_owned(),
        signer: signer_text,
        summary,
        payload: message.clone(),
        action: Action::PersonalSign(message),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

pub(super) fn sign_personal(
    secrets: &Secrets,
    index: u32,
    message: &[u8],
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Evm, index)?;
    let signature = evm::sign_personal_message(&key, message)?;
    Ok(json!({ "signature": hexs::encode_0x(&signature.to_rsv(27)) }))
}

// ---- kind 3: typed data ----

pub(super) fn prepare_typed_data(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "network", "typed_data"], "the request")?;
    let (network, chain) = evm_network(map)?;
    let text = json::string(map, "typed_data")?;
    let document: Value =
        serde_json::from_str(text).map_err(|_| bad("typed_data is not valid JSON"))?;
    let data = TypedData::from_value(&document)?;
    let parsed = data.summary()?;
    let signing_hash = data.signing_hash()?;
    let (signer_text, _) = signer(secrets, index)?;

    let domain = &parsed.domain;
    let mut warnings = Vec::new();
    let mut details = Map::new();
    details.insert("primary_type".into(), Value::from(parsed.primary_type.clone()));
    details.insert(
        "domain".into(),
        json!({
            "name": domain.name,
            "version": domain.version,
            "chain_id": domain.chain_id.map(|id| id.to_string()),
            "verifying_contract": domain.verifying_contract.as_ref().map(address),
            "salt": domain.salt.as_ref().map(|s| hexs::encode_0x(s)),
            // The site wrote `name` and `version`: any contract and any site can
            // claim any name. `known_contract` is what the wallet itself knows the
            // verifying contract to be.
            "claimed_by_site": ["name", "version"],
            "known_contract": domain
                .verifying_contract
                .as_ref()
                .and_then(known_contract_name),
        }),
    );
    // Whether the wallet recognised the message, and whether signing it may let
    // someone spend the signer's tokens: a screen never says "nothing is sent"
    // unless it is recognised and this is false. Typed data it does not recognise
    // (orders, listings, votes, meta-transactions) can authorise spending.
    let mut understood = true;
    let mut may_authorise_spending = true;
    match &parsed.kind {
        TypedDataKind::Permit { owner, spender, value, unlimited, nonce, deadline } => {
            details.insert("kind".into(), Value::from("permit"));
            let never_expires = *deadline >= U256::from_u128(u128::from(u32::MAX));
            details.insert(
                "permit".into(),
                json!({
                    "owner": address(owner),
                    "spender": address(spender),
                    "value": value.to_string(),
                    "unlimited": unlimited,
                    "nonce": nonce.to_string(),
                    "deadline": deadline.to_string(),
                    "never_expires": never_expires,
                }),
            );
            warnings.push(warning::PERMIT_SIGNATURE);
            if *unlimited {
                warnings.push(warning::UNLIMITED_APPROVAL);
            }
        }
        TypedDataKind::DaiPermit { holder, spender, nonce, expiry, allowed } => {
            details.insert("kind".into(), Value::from("dai_permit"));
            details.insert(
                "dai_permit".into(),
                json!({
                    "holder": address(holder),
                    "spender": address(spender),
                    "nonce": nonce.to_string(),
                    "expiry": expiry.to_string(),
                    "allowed": allowed,
                }),
            );
            may_authorise_spending = *allowed;
            if *allowed {
                warnings.push(warning::PERMIT_SIGNATURE);
            }
        }
        TypedDataKind::Permit2Allowance { details: allowances, spender, sig_deadline, batch } => {
            details.insert("kind".into(), Value::from("permit2_allowance"));
            details.insert(
                "permit2".into(),
                json!({
                    "batch": batch,
                    "spender": address(spender),
                    "sig_deadline": sig_deadline.to_string(),
                    "allowances": allowances.iter().map(allowance_json).collect::<Vec<_>>(),
                }),
            );
            warnings.push(warning::PERMIT_SIGNATURE);
            if allowances.iter().any(|a| a.unlimited) {
                warnings.push(warning::UNLIMITED_APPROVAL);
            }
        }
        TypedDataKind::Permit2Transfer {
            permitted,
            spender,
            nonce,
            deadline,
            witness_type,
            batch,
        } => {
            details.insert("kind".into(), Value::from("permit2_transfer"));
            details.insert(
                "permit2".into(),
                json!({
                    "batch": batch,
                    "spender": address(spender),
                    "nonce": nonce.to_string(),
                    "deadline": deadline.to_string(),
                    "witness_type": witness_type,
                    "permitted": permitted.iter().map(token_json).collect::<Vec<_>>(),
                }),
            );
            warnings.push(warning::PERMIT_SIGNATURE);
            if permitted.iter().any(|t| t.unlimited) {
                warnings.push(warning::UNLIMITED_APPROVAL);
            }
        }
        TypedDataKind::Other => {
            details.insert("kind".into(), Value::from("other"));
            understood = false;
            warnings.push(warning::UNRECOGNISED_TYPED_DATA);
        }
    }
    if domain.chain_id.is_some_and(|id| id != U256::from(chain.chain_id())) {
        warnings.push(warning::CHAIN_MISMATCH);
    }
    details.insert("understood".into(), Value::from(understood));
    details.insert("may_authorise_spending".into(), Value::from(may_authorise_spending));
    details.insert("typed_data".into(), Value::from(document.to_string()));

    let summary = Summary {
        request: "evm_typed_data",
        network: network.api_id().to_owned(),
        signer: signer_text.clone(),
        action: "typed_data",
        details: Value::Object(details),
        tx: None,
        fee: None,
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "evm_typed_data",
        network: network.api_id().to_owned(),
        signer: signer_text,
        summary,
        payload: signing_hash.to_vec(),
        action: Action::TypedData(data),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

fn allowance_json(a: &Permit2Allowance) -> Value {
    json!({
        "token": address(&a.token),
        "amount": a.amount.to_string(),
        "unlimited": a.unlimited,
        "expiration": a.expiration.to_string(),
        "never_expires": a.never_expires,
        "nonce": a.nonce.to_string(),
    })
}

fn token_json(t: &Permit2Token) -> Value {
    json!({ "token": address(&t.token), "amount": t.amount.to_string(), "unlimited": t.unlimited })
}

pub(super) fn sign_typed_data(
    secrets: &Secrets,
    index: u32,
    data: &TypedData,
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Evm, index)?;
    let signature = data.sign(&key)?;
    Ok(json!({ "signature": hexs::encode_0x(&signature.to_rsv(27)) }))
}
