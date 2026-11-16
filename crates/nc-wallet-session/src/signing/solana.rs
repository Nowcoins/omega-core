//! Solana requests: a transaction a site hands over (`signTransaction`,
//! `signAndSendTransaction`) and a message (`signMessage`). The wallet's own
//! SOL and SPL transfers are built in `send.rs` and read back through
//! [`summarize`] here, so the summary of a transfer is a reading of the bytes
//! that are signed.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nc_wallet_core::Network;
use nc_wallet_core::solana::{
    self, InstructionReview, InstructionSummary, LookupTable, MessageError, TransactionSummary,
    message,
};
use serde_json::{Value, json};

use super::json::{self, Obj, bad};
use super::text::{map_origin, message_details, message_warnings};
use super::warning::{self, Code};
use super::{
    Action, Prepared, Secrets, SigningError, Summary, derive_key, fee_json, hexs, signer_address,
};
use nc_wallet_core::limits;

use crate::types::NetworkId;

const MAX_MESSAGE: usize = 131_072;
/// How much of an unknown instruction's data a summary repeats.
const SHOWN_DATA: usize = 1024;
/// The base fee of a signature, in lamports.
const LAMPORTS_PER_SIGNATURE: u128 = 5_000;
/// What the runtime reserves per instruction when no limit is set.
const DEFAULT_UNITS_PER_INSTRUCTION: u128 = 200_000;
const MAX_UNITS: u128 = 1_400_000;

pub(super) fn message_error(error: &MessageError) -> SigningError {
    match error {
        MessageError::UnsupportedVersion(_) => {
            SigningError::new("Unsupported", "this Solana transaction version is not supported")
        }
        MessageError::MissingLookupTable(_) => {
            bad("an address lookup table the transaction uses was not supplied")
        }
        MessageError::Malformed(reason) => bad(format!("the transaction is malformed: {reason}")),
        MessageError::TooManyAccounts | MessageError::TooMuchData => {
            bad("the transaction is larger than the network takes")
        }
    }
}

fn decode_base64(text: &str, field: &str) -> Result<Vec<u8>, SigningError> {
    STANDARD.decode(text).map_err(|_| bad(format!("{field} is not base64")))
}

/// The address lookup tables a transaction loads accounts through, as base58:
/// fetch these, and hand them to a `solana_transaction` request.
pub fn lookup_tables_needed(transaction_base64: &str) -> Result<Vec<String>, SigningError> {
    let bytes = decode_base64(transaction_base64, "transaction_base64")?;
    let keys = solana::lookup_tables_needed(&bytes).map_err(|e| message_error(&e))?;
    Ok(keys.iter().map(solana::address).collect())
}

/// Reads a transaction and its tables into the summary.
///
/// `user` is the wallet account that would sign: it is what "your accounts" means in
/// the answer.
pub(super) fn summarize(
    bytes: &[u8],
    tables: &[LookupTable],
    user: &message::Pubkey,
) -> Result<TransactionSummary, SigningError> {
    solana::summarize_transaction_for(bytes, tables, user).map_err(|e| message_error(&e))
}

fn b58(key: &message::Pubkey) -> String {
    solana::address(key)
}

/// One instruction as the screen reads it: what it is (`type`), the fields of that kind, and
/// for every instruction (known or not) `program_name`, `danger`, `moves_user_funds` and
/// `user` (whether the user's accounts are a signer or writable in it).
fn instruction_json(instruction: &InstructionSummary, review: &InstructionReview) -> Value {
    let mut value = instruction_fields(instruction);
    if let Value::Object(map) = &mut value {
        map.insert("program_name".into(), json!(review.program_name));
        map.insert("danger".into(), json!(review.danger.map(solana::Danger::code)));
        map.insert("moves_user_funds".into(), json!(review.moves_user_funds));
        map.insert(
            "user".into(),
            json!({
                "signer": review.user_signer,
                "writable": review.user_writable,
                "accounts": review.user_accounts.iter().map(b58).collect::<Vec<_>>(),
            }),
        );
        if !map.contains_key("program") {
            map.insert("program".into(), json!(b58(&review.program)));
        }
    }
    value
}

fn instruction_fields(instruction: &InstructionSummary) -> Value {
    match instruction {
        InstructionSummary::SystemCreateAccount {
            from,
            new_account,
            lamports,
            space,
            owner,
            seed,
            base,
        } => json!({
            "type": "system_create_account", "from": b58(from), "new_account": b58(new_account),
            "lamports": lamports.to_string(), "space": space.to_string(), "owner": b58(owner),
            "seed": seed, "base": base.as_ref().map(b58),
        }),
        InstructionSummary::SystemAssign { account, owner, base } => json!({
            "type": "system_assign", "account": b58(account), "owner": b58(owner),
            "base": base.as_ref().map(b58),
        }),
        InstructionSummary::SystemAllocate { account, space } => json!({
            "type": "system_allocate", "account": b58(account), "space": space.to_string(),
        }),
        InstructionSummary::SystemTransferWithSeed {
            from,
            base,
            to,
            lamports,
            from_seed,
            from_owner,
        } => json!({
            "type": "system_transfer_with_seed", "from": b58(from), "base": b58(base),
            "to": b58(to), "lamports": lamports.to_string(), "from_seed": from_seed,
            "from_owner": b58(from_owner),
        }),
        InstructionSummary::SystemAdvanceNonce { nonce_account, authority } => json!({
            "type": "system_advance_nonce", "nonce_account": b58(nonce_account),
            "authority": b58(authority),
        }),
        InstructionSummary::SystemWithdrawNonce { nonce_account, to, authority, lamports } => {
            json!({
                "type": "system_withdraw_nonce", "nonce_account": b58(nonce_account), "to": b58(to),
                "authority": b58(authority), "lamports": lamports.to_string(),
            })
        }
        InstructionSummary::SystemInitializeNonce { nonce_account, authority } => json!({
            "type": "system_initialize_nonce", "nonce_account": b58(nonce_account),
            "authority": b58(authority),
        }),
        InstructionSummary::SystemAuthorizeNonce { nonce_account, authority, new_authority } => {
            json!({
                "type": "system_authorize_nonce", "nonce_account": b58(nonce_account),
                "authority": b58(authority), "new_authority": b58(new_authority),
            })
        }
        InstructionSummary::SplSetAuthority {
            program,
            account,
            current_authority,
            authority_type,
            new_authority,
        } => json!({
            "type": "spl_set_authority", "program": b58(program), "account": b58(account),
            "current_authority": b58(current_authority), "authority_type": authority_type,
            "new_authority": new_authority.as_ref().map(b58),
        }),
        InstructionSummary::SplCloseAccount { program, account, destination, owner } => json!({
            "type": "spl_close_account", "program": b58(program), "account": b58(account),
            "destination": b58(destination), "owner": b58(owner),
        }),
        InstructionSummary::SplBurn { program, account, mint, authority, amount, decimals } => {
            json!({
                "type": "spl_burn", "program": b58(program), "account": b58(account),
                "mint": b58(mint), "authority": b58(authority), "amount": amount.to_string(),
                "decimals": decimals,
            })
        }
        InstructionSummary::SplRevoke { program, source, owner } => json!({
            "type": "spl_revoke", "program": b58(program), "source": b58(source),
            "owner": b58(owner),
        }),
        InstructionSummary::Memo { program, text, escaped, len, signers } => json!({
            "type": "memo", "program": b58(program), "text": text, "text_escaped": escaped,
            "len": len, "signers": signers.iter().map(b58).collect::<Vec<_>>(),
        }),
        InstructionSummary::SystemTransfer { from, to, lamports } => json!({
            "type": "system_transfer", "from": b58(from), "to": b58(to), "lamports": lamports.to_string(),
        }),
        InstructionSummary::SplTransfer {
            program,
            source,
            destination,
            authority,
            mint,
            amount,
            decimals,
        } => json!({
            "type": "spl_transfer",
            "program": b58(program),
            "source": b58(source),
            "destination": b58(destination),
            "authority": b58(authority),
            "mint": mint.as_ref().map(b58),
            "amount": amount.to_string(),
            "decimals": decimals,
        }),
        InstructionSummary::SplApprove {
            program,
            source,
            delegate,
            owner,
            mint,
            amount,
            decimals,
            unlimited,
        } => json!({
            "type": "spl_approve",
            "program": b58(program),
            "source": b58(source),
            "delegate": b58(delegate),
            "owner": b58(owner),
            "mint": mint.as_ref().map(b58),
            "amount": amount.to_string(),
            "decimals": decimals,
            "unlimited": unlimited,
        }),
        InstructionSummary::CreateAssociatedTokenAccount {
            payer,
            account,
            owner,
            mint,
            idempotent,
        } => json!({
            "type": "create_token_account",
            "payer": b58(payer),
            "account": b58(account),
            "owner": b58(owner),
            "mint": b58(mint),
            "idempotent": idempotent,
        }),
        InstructionSummary::SetComputeUnitLimit { units } => {
            json!({ "type": "set_compute_unit_limit", "units": units })
        }
        InstructionSummary::SetComputeUnitPrice { micro_lamports } => {
            json!({ "type": "set_compute_unit_price", "micro_lamports": micro_lamports.to_string() })
        }
        InstructionSummary::Unknown { program, accounts, data } => json!({
            "type": "unknown",
            "program": b58(program),
            "accounts": accounts.iter().map(|meta| b58(&meta.key)).collect::<Vec<_>>(),
            "data_len": data.len(),
            "data": hexs::encode(&data[..data.len().min(SHOWN_DATA)]),
        }),
    }
}

/// The network fee in lamports, as far as the transaction says it: 5000 per
/// signature, and the priority fee its compute-budget instructions set.
fn fee_estimate(summary: &TransactionSummary) -> u128 {
    let mut limit = None;
    let mut price = 0_u128;
    let mut others: u128 = 0;
    for instruction in &summary.instructions {
        match instruction {
            InstructionSummary::SetComputeUnitLimit { units } => {
                limit.get_or_insert(u128::from(*units));
            }
            InstructionSummary::SetComputeUnitPrice { micro_lamports } => {
                price = u128::from(*micro_lamports);
            }
            _ => others += 1,
        }
    }
    let units = limit.unwrap_or_else(|| (DEFAULT_UNITS_PER_INSTRUCTION * others).min(MAX_UNITS));
    let priority = (units * price).div_ceil(1_000_000);
    LAMPORTS_PER_SIGNATURE * summary.required_signers.len() as u128 + priority
}

/// The summary of a transaction (a site's, or one of the wallet's own).
pub(super) fn transaction_details(summary: &TransactionSummary) -> (Value, u128, Vec<Code>) {
    let mut warnings = Vec::new();
    if !summary.fully_understood {
        warnings.push(warning::UNKNOWN_PROGRAMS);
    }
    if summary.reviews.iter().any(|r| r.danger.is_some_and(|d| d != solana::Danger::Approve)) {
        warnings.push(warning::DANGEROUS_INSTRUCTION);
    }
    if summary.durable_nonce {
        warnings.push(warning::DURABLE_NONCE);
    }
    for instruction in &summary.instructions {
        if let InstructionSummary::SplApprove { unlimited, .. } = instruction {
            if !warnings.contains(&warning::DELEGATE_APPROVAL) {
                warnings.push(warning::DELEGATE_APPROVAL);
            }
            if *unlimited && !warnings.contains(&warning::UNLIMITED_APPROVAL) {
                warnings.push(warning::UNLIMITED_APPROVAL);
            }
        }
    }
    let details = json!({
        "fee_payer": b58(&summary.fee_payer),
        "required_signers": summary.required_signers.iter().map(b58).collect::<Vec<_>>(),
        "recent_blockhash": b58(&summary.recent_blockhash),
        "instructions": summary
            .instructions
            .iter()
            .zip(&summary.reviews)
            .map(|(instruction, review)| instruction_json(instruction, review))
            .collect::<Vec<_>>(),
        // The two answers a screen must ask before it says "no coins of yours are sent":
        // that is only true of a transaction that is `fully_understood` and
        // does not `may_move_user_funds`.
        "fully_understood": summary.fully_understood,
        "may_move_user_funds": summary.may_move_user_funds,
        "durable_nonce": summary.durable_nonce,
        "user_token_accounts": summary.user_token_accounts.iter().map(b58).collect::<Vec<_>>(),
    });
    (details, fee_estimate(summary), warnings)
}

// ---- kind 4: a transaction ----

pub(super) fn prepare_transaction(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "transaction_base64", "lookup_tables"], "the request")?;
    let bytes = decode_base64(json::string(map, "transaction_base64")?, "transaction_base64")?;
    if bytes.len() > message::MAX_TRANSACTION_SIZE {
        return Err(bad("the transaction is larger than the network takes"));
    }
    let mut tables = Vec::new();
    if map.contains_key("lookup_tables") {
        for entry in json::array(map, "lookup_tables")? {
            let entry = json::as_object(entry, "a lookup table")?;
            json::only(entry, &["address", "data_base64"], "a lookup table")?;
            let key = solana::parse_address(json::string(entry, "address")?)
                .ok_or_else(|| bad("a lookup table's address is not an address"))?;
            let data = decode_base64(json::string(entry, "data_base64")?, "data_base64")?;
            tables.push(LookupTable::parse(key, &data).map_err(|e| message_error(&e))?);
        }
    }
    let signer_text = signer_address(secrets, Network::Solana, index)?;
    let signer_key = solana::parse_address(&signer_text).ok_or_else(|| {
        SigningError::new("Unavailable", "the account's address could not be made")
    })?;
    let summary = summarize(&bytes, &tables, &signer_key)?;
    if !summary.required_signers.contains(&signer_key) {
        return Err(SigningError::new(
            "NotASigner",
            "this account is not one of the transaction's signers",
        ));
    }
    let (details, fee, warnings) = transaction_details(&summary);
    // A site sets the priority fee in its own compute-budget instructions: the wallet bounds what it can cost.
    if !limits::SOLANA_TOTAL_FEE.allows(fee) {
        return Err(SigningError::new(
            "FeeTooHigh",
            "the network fee for this transaction is above the most this wallet will pay",
        ));
    }
    let shown = Summary {
        request: "solana_transaction",
        network: "solana".to_owned(),
        signer: signer_text.clone(),
        action: "solana_transaction",
        details,
        tx: None,
        fee: Some(fee_json(NetworkId::Solana, fee)),
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "solana_transaction",
        network: "solana".to_owned(),
        signer: signer_text,
        summary: shown,
        payload: bytes.clone(),
        action: Action::SolanaTransaction(bytes),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

pub(super) fn sign_transaction(
    secrets: &Secrets,
    index: u32,
    prepared: &Prepared,
    bytes: &[u8],
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Solana, index)?;
    let signed = solana::sign_transaction(&key, bytes).map_err(|e| solana_error(&e))?;
    if prepared.send {
        return Ok(super::send_output(
            &prepared.network,
            &STANDARD.encode(&signed.transaction),
            "base64",
            &signed.id(),
        ));
    }
    Ok(json!({
        "transaction_base64": STANDARD.encode(&signed.transaction),
        "signature_base64": STANDARD.encode(signed.signature),
        "id_base58": signed.id(),
    }))
}

pub(super) fn solana_error(error: &solana::SolanaError) -> SigningError {
    use solana::SolanaError as E;
    match error {
        E::Message(inner) => message_error(inner),
        E::NotASigner => {
            SigningError::new("NotASigner", "this account is not one of the transaction's signers")
        }
        E::NotText => {
            SigningError::new("NotText", "a message to sign must be text; these bytes are not")
        }
        E::LooksLikeTransaction => SigningError::new(
            "LooksLikeTransaction",
            "these bytes are a transaction; sign them as a transaction, not a message",
        ),
        E::ZeroAmount => bad("the amount must be more than zero"),
        E::TooLarge => bad("the transaction is larger than the network takes"),
        E::NoTokenAccount => bad("no token account address could be derived"),
        E::WrongKeyScheme => SigningError::new("Unavailable", "the signature could not be made"),
    }
}

// ---- kind 5: a message ----

pub(super) fn prepare_message(
    secrets: &Secrets,
    index: u32,
    map: &Obj,
) -> Result<Prepared, SigningError> {
    json::only(map, &["kind", "message_base64", "origin"], "the request")?;
    let bytes = decode_base64(json::string(map, "message_base64")?, "message_base64")?;
    if bytes.len() > MAX_MESSAGE {
        return Err(bad("message_base64 is larger than the wallet takes"));
    }
    // A site's message is text and not a transaction: `solana::check_message` refuses the
    // bytes of a transaction in any format this wallet reads, and any bytes that are not
    // UTF-8 (which no transaction message in any format can be, as it lists its signers'
    // public keys). The same refusal is made again at signing, which prepares again.
    solana::check_message(&bytes).map_err(|e| solana_error(&e))?;
    let signer_text = signer_address(secrets, Network::Solana, index)?;
    let mut details = message_details(&bytes, "Solana", &signer_text, map_origin(map)?);
    details["message_hex"] = json!(hexs::encode(&bytes));
    let warnings = message_warnings(&details);
    let summary = Summary {
        request: "solana_message",
        network: "solana".to_owned(),
        signer: signer_text.clone(),
        action: "sign_message",
        details,
        tx: None,
        fee: None,
        warnings,
    }
    .into_value();
    Ok(Prepared {
        kind: "solana_message",
        network: "solana".to_owned(),
        signer: signer_text,
        summary,
        payload: bytes.clone(),
        action: Action::SolanaMessage(bytes),
        send: false,
        fee_high: false,
        fee_ok: false,
        chain_mismatch_ok: false,
    })
}

pub(super) fn sign_message(
    secrets: &Secrets,
    index: u32,
    bytes: &[u8],
) -> Result<Value, SigningError> {
    let key = derive_key(secrets, Network::Solana, index)?;
    let signature = solana::sign_message(&key, bytes).map_err(|e| solana_error(&e))?;
    Ok(json!({
        "signature_base64": STANDARD.encode(signature),
        "signature_base58": bs58::encode(signature).into_string(),
    }))
}
