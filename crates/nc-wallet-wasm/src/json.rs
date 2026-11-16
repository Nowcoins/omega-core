//! The records that go to JavaScript as JSON text, built by hand so no
//! serialisation library is needed. Public data only: addresses, counts, the
//! quiz's choices. The shapes are declared for TypeScript in `lib.rs`.

use nc_wallet_session::{
    AddressCheck, BackupQuestion, Decoded, NetworkAccount, PhraseCheck, VaultFacts,
};
use serde_json::{Value, json};

pub(crate) fn account(account: &NetworkAccount) -> Value {
    json!({
        "network": account.network.api_id(),
        "address": account.address,
        "publicKeyHex": account.public_key_hex,
        "path": account.path,
    })
}

pub(crate) fn accounts(accounts: &[NetworkAccount]) -> Value {
    Value::Array(accounts.iter().map(account).collect())
}

pub(crate) fn questions(questions: &[BackupQuestion]) -> Value {
    Value::Array(
        questions.iter().map(|q| json!({ "position": q.position, "choices": q.choices })).collect(),
    )
}

pub(crate) fn phrase_check(check: &PhraseCheck) -> Value {
    json!({
        "problem": check.problem.code(),
        "wordCount": check.word_count,
        "position": check.position,
        "suggestions": check.suggestions,
    })
}

pub(crate) fn vault_facts(facts: &VaultFacts) -> Value {
    json!({
        "version": facts.version,
        "memoryKib": facts.memory_kib,
        "iterations": facts.iterations,
        "lanes": facts.lanes,
    })
}

/// A decoded signing request: the summary the approval screen shows and the
/// approval hash (64 hex digits) to hand back to `sign_request`.
pub(crate) fn decoded(decoded: &Decoded) -> Value {
    json!({ "summary": decoded.summary, "approval": hex(&decoded.approval) })
}

pub(crate) fn address_check(check: &AddressCheck) -> Value {
    json!({ "valid": check.valid, "normalized": check.normalized, "reason": check.reason })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The approval hash as the page sends it: exactly 64 hex digits.
pub(crate) fn parse_approval(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(out)
}
