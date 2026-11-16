//! The approval: what was decoded is what is signed, and nothing else is.

use serde_json::{Value, json};

use nc_wallet_core::Mnemonic;

use super::evm::MAIL;
use super::*;

const BOB: &str = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB";

fn tx() -> Value {
    json!({
        "kind": "evm_transaction", "network": "ethereum", "to": BOB, "value": "1000", "data": "0x",
        "nonce": "7", "gas_limit": "21000",
        "fees": { "type": "eip1559", "max_fee_per_gas": "30000000000", "max_priority_fee_per_gas": "1500000000" },
    })
}

fn personal() -> Value {
    json!({ "kind": "evm_personal_sign", "message_hex": "0x68656c6c6f" })
}

fn typed() -> Value {
    json!({ "kind": "evm_typed_data", "network": "ethereum", "typed_data": MAIL })
}

fn solana_message() -> Value {
    json!({ "kind": "solana_message", "message_base64": "aGVsbG8=" })
}

fn solana_transaction(lamports: u64) -> Value {
    let bytes = nc_wallet_core::solana::build_sol_transfer(&nc_wallet_core::solana::SolTransfer {
        from: nc_wallet_core::solana::parse_address("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")
            .unwrap(),
        to: [9; 32],
        lamports,
        recent_blockhash: [7; 32],
        priority: None,
    })
    .unwrap();
    use base64::Engine as _;
    json!({ "kind": "solana_transaction", "transaction_base64": base64::engine::general_purpose::STANDARD.encode(bytes) })
}

fn mutate(request: &Value, path: &[&str], new: Value) -> Value {
    let mut changed = request.clone();
    let mut at = &mut changed;
    for key in &path[..path.len() - 1] {
        at = &mut at[*key];
    }
    at[path[path.len() - 1]] = new;
    changed
}

#[test]
fn decoding_twice_gives_the_same_approval_and_the_same_summary() {
    let engine = engine();
    for request in [tx(), personal(), typed(), solana_message(), solana_transaction(5)] {
        let a = decode(&engine, 0, &request).unwrap();
        let b = decode(&engine, 0, &request).unwrap();
        assert_eq!(a, b, "{request}");
    }
}

#[test]
fn a_request_that_changed_after_it_was_decoded_cannot_be_signed() {
    let engine = engine();
    let cases = [
        (tx(), mutate(&tx(), &["value"], json!("1001"))),
        (tx(), mutate(&tx(), &["to"], json!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))),
        (tx(), mutate(&tx(), &["nonce"], json!("8"))),
        (tx(), mutate(&tx(), &["network"], json!("polygon"))),
        (tx(), mutate(&tx(), &["data"], json!("0x00"))),
        (tx(), mutate(&tx(), &["fees", "max_fee_per_gas"], json!("30000000001"))),
        (personal(), mutate(&personal(), &["message_hex"], json!("0x68656c6c6f21"))),
        (
            typed(),
            mutate(&typed(), &["typed_data"], json!(MAIL.replace("Hello, Bob!", "Hello, Eve!"))),
        ),
        (solana_message(), mutate(&solana_message(), &["message_base64"], json!("aGVsbG8h"))),
        (solana_transaction(5), solana_transaction(6)),
    ];
    for (original, changed) in cases {
        let approval = decode(&engine, 0, &original).unwrap().approval;
        let result = engine.sign_request(0, &changed.to_string(), &approval);
        assert_eq!(result.unwrap_err().code(), "ApprovalMismatch", "{changed}");
        // And the request that was approved still signs.
        assert!(engine.sign_request(0, &original.to_string(), &approval).is_ok(), "{original}");
    }
}

#[test]
fn the_account_is_part_of_the_approval() {
    let engine = engine();
    for request in [personal(), solana_message(), typed()] {
        let approval = decode(&engine, 0, &request).unwrap().approval;
        let result = engine.sign_request(1, &request.to_string(), &approval);
        assert_eq!(result.unwrap_err().code(), "ApprovalMismatch", "{request}");
    }
}

#[test]
fn bytes_the_summary_does_not_show_still_change_the_approval() {
    // Another signer's signature slot is not in the summary, but it is in what
    // is handed back and sent on, so it is covered.
    let engine = engine();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let original = solana_transaction(5);
    let mut bytes = b64.decode(original["transaction_base64"].as_str().unwrap()).unwrap();
    let a = decode(&engine, 0, &original).unwrap();
    // Our own slot (the only one) holds a stray non-zero byte: same summary.
    bytes[1] = 1;
    let changed = json!({ "kind": "solana_transaction", "transaction_base64": b64.encode(&bytes) });
    let b = decode(&engine, 0, &changed).unwrap();
    assert_eq!(a.summary, b.summary);
    assert_ne!(a.approval, b.approval);
}

#[test]
fn a_wrong_approval_signs_nothing() {
    let engine = engine();
    let request = personal().to_string();
    let good = engine.decode_request(0, &request).unwrap().approval;
    let mut flipped = good;
    flipped[31] ^= 1;
    assert_eq!(engine.sign_request(0, &request, &flipped).unwrap_err().code(), "ApprovalMismatch");
    assert_eq!(engine.sign_request(0, &request, &[0; 32]).unwrap_err().code(), "ApprovalMismatch");
    // A request that does not parse is refused before the approval is looked at.
    assert_eq!(engine.sign_request(0, "{", &good).unwrap_err().code(), "BadRequest");
}

#[test]
fn a_locked_wallet_decodes_and_signs_nothing() {
    let mut engine = engine();
    let request = personal().to_string();
    let approval = engine.decode_request(0, &request).unwrap().approval;
    engine.lock();
    assert_eq!(engine.decode_request(0, &request).unwrap_err().code(), "NotUnlocked");
    assert_eq!(engine.sign_request(0, &request, &approval).unwrap_err().code(), "NotUnlocked");
    assert_eq!(engine.bitcoin_zpub(0).unwrap_err().code(), "NotUnlocked");
    // The engine that never held a wallet likewise.
    let fresh = Engine::new();
    assert_eq!(fresh.decode_request(0, &request).unwrap_err().code(), "NotUnlocked");
}

#[test]
fn the_zpub_is_the_bip_84_accounts_and_finds_its_addresses() {
    let engine = engine();
    // m/84'/0'/0' of the reference phrase (BIP-84's test vector).
    assert_eq!(
        engine.bitcoin_zpub(0).unwrap(),
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
    // Another account is another key, and it finds that account's addresses.
    assert_ne!(engine.bitcoin_zpub(0).unwrap(), engine.bitcoin_zpub(1).unwrap());
    let first = nc_wallet_core::bitcoin::addresses_from_zpub(
        &engine.bitcoin_zpub(1).unwrap(),
        nc_wallet_core::bitcoin::Chain::Receive,
        0,
        1,
    )
    .unwrap();
    assert_eq!(
        first[0],
        engine
            .accounts(1)
            .unwrap()
            .into_iter()
            .find(|a| a.network == crate::NetworkId::Bitcoin)
            .unwrap()
            .address
    );
    assert_eq!(engine.bitcoin_zpub(1 << 31).unwrap_err().code(), "AccountIndexOutOfRange");
}

#[test]
fn no_secret_is_in_any_summary_answer_or_error() {
    let engine = engine();
    let mnemonic = Mnemonic::parse(ABANDON).unwrap();
    // Every private key the signing code can hold, in every spelling an answer might use.
    let mut secrets: Vec<String> = Vec::new();
    for network in [
        nc_wallet_core::Network::Evm,
        nc_wallet_core::Network::Solana,
        nc_wallet_core::Network::Bittensor,
    ] {
        let key = nc_wallet_core::signing_key(&mnemonic, "", network, 0).unwrap();
        let bytes = *key.expose_secret();
        secrets.push(hex::encode(bytes));
        secrets.push(hex::encode(bytes).to_uppercase());
        secrets.push(bs58::encode(bytes).into_string());
        use base64::Engine as _;
        secrets.push(base64::engine::general_purpose::STANDARD.encode(bytes));
        secrets.push(format!("{bytes:?}"));
    }
    let seed = mnemonic.to_seed("");
    secrets.push(hex::encode(seed.expose_secret()));

    let mut texts: Vec<String> = Vec::new();
    for request in [tx(), personal(), typed(), solana_message(), solana_transaction(5)] {
        let decoded = decode(&engine, 0, &request).unwrap();
        texts.push(decoded.summary.to_string());
        texts.push(format!("{decoded:?}"));
        texts.push(sign(&engine, 0, &request).to_string());
    }
    for bad in [
        json!({ "kind": "nope" }),
        tx().as_object()
            .map(|m| Value::Object(m.clone()))
            .map(|v| mutate(&v, &["to"], json!("x")))
            .unwrap(),
    ] {
        let error = decode(&engine, 0, &bad).unwrap_err();
        texts.push(format!("{error:?} {error}"));
    }
    texts.push(format!("{engine:?}"));
    for text in &texts {
        for secret in &secrets {
            assert!(
                !text.contains(secret.as_str()),
                "a secret is in: {}",
                &text[..text.len().min(80)]
            );
        }
        for word in ["abandon", "about"] {
            assert!(
                !text.to_lowercase().contains(word),
                "the phrase is in: {}",
                &text[..text.len().min(80)]
            );
        }
    }
}
