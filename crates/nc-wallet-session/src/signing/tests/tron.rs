//! Kinds 7 and 8: a TRON transaction a web page built (`TronWeb`'s `trx.sign`) and `signMessageV2`.
//! The transactions are built with the core's own encoder for the reference account, so the owner is
//! the signer; the page's bytes are read back by the strict reader, shown, and signed unchanged.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use nc_wallet_core::evm::U256;
use nc_wallet_core::tron::{self, AddressBytes, ReferenceBlock, TronTransaction};
use nc_wallet_core::{Mnemonic, Network, derive};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::super::hexs;
use super::*;

const TRON_USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const NOW: i64 = 1_793_058_193_685;

fn address(index: u32) -> String {
    derive(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Tron, index).unwrap().address
}

fn parsed(text: &str) -> AddressBytes {
    tron::parse_address(text).unwrap()
}

fn reference() -> ReferenceBlock {
    ReferenceBlock::from_block(
        87_461_647,
        &hexs::decode_array::<32>(
            "0000000005368f0fa1555acb3c6f9bc45b368bc2b683314e933f51fa5f1bc229",
        )
        .unwrap(),
    )
}

/// What the chain client's `tron_estimate` says for a call that needs 64,285 energy.
fn estimate() -> Value {
    json!({
        "network": "tron", "energy": "64285", "bandwidth": "345",
        "energy_price_sun": "420", "bandwidth_price_sun": "1000",
        "fee": { "asset": "TRX", "amount": "27299700", "decimals": 6 },
        "energy_fee": "26999700", "activation_fee": "0",
    })
}

fn request(tx: &TronTransaction) -> Value {
    json!({ "kind": "tron_transaction", "raw_data_hex": hexs::encode(&tx.raw_data()), "estimate": estimate() })
}

fn transfer(amount: u64) -> TronTransaction {
    TronTransaction::trx_transfer(
        parsed(&address(0)),
        parsed(&address(1)),
        amount,
        reference(),
        NOW,
        NOW + 60_000,
    )
    .unwrap()
}

fn approve(amount: &U256, fee_limit: u64) -> TronTransaction {
    TronTransaction::trc20_approve(
        parsed(&address(0)),
        parsed(TRON_USDT),
        &parsed(&address(1)),
        amount,
        fee_limit,
        reference(),
        NOW,
        NOW + 60_000,
    )
    .unwrap()
}

fn signer_of(digest: &[u8; 32], rs: &[u8], parity: u8) -> String {
    let key = VerifyingKey::recover_from_prehash(
        digest,
        &Signature::from_slice(&rs[..64]).unwrap(),
        RecoveryId::from_byte(parity).unwrap(),
    )
    .unwrap();
    tron::address_from_public_key(key.to_encoded_point(true).as_bytes()).unwrap()
}

#[test]
fn a_trx_transfer_a_page_built_is_shown_as_the_bytes_say_and_signed_unchanged() {
    let engine = engine();
    let tx = transfer(1_500_000);
    let request = request(&tx);
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["request"], "tron_transaction");
    assert_eq!(s["network"], "tron");
    assert_eq!(s["signer"], address(0));
    assert_eq!(s["action"], "native_transfer");
    assert_eq!(s["details"], json!({ "recipient": address(1), "amount": "1500000" }));
    assert_eq!(s["fee"], json!({ "asset": "TRX", "amount": "27299700", "decimals": 6 }));
    assert_eq!(s["warnings"], json!([]));
    assert_eq!(s["tx"]["txid"], hexs::encode(&tx.txid()));
    assert_eq!(s["tx"]["energy"], "64285");
    assert_eq!(s["tx"]["bandwidth"], "345");
    assert_eq!(s["tx"]["fee_limit"], Value::Null);
    assert_eq!(s["tx"]["expiration_ms"], NOW + 60_000);

    let signed = sign(&engine, 0, &request);
    assert_eq!(signed["txid"], hexs::encode(&tx.txid()));
    assert_eq!(signed["raw_data_hex"], hexs::encode(&tx.raw_data()));
    // The same bytes and the same signature as the core makes for the same key.
    let key = nc_wallet_core::signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Tron, 0)
        .unwrap();
    let direct = tx.sign(&key).unwrap();
    assert_eq!(signed["signature"], hexs::encode(&direct.signature));
    assert_eq!(signed["transaction"], direct.transaction_hex());
    // The signature is what TronWeb carries: r, s and a recovery id of 0 or 1, and it recovers to the account.
    let signature = hex(signed["signature"].as_str().unwrap());
    assert_eq!(signature.len(), 65);
    assert!(signature[64] <= 1);
    let txid: [u8; 32] = Sha256::digest(tx.raw_data()).into();
    assert_eq!(signer_of(&txid, &signature, signature[64]), address(0));
}

#[test]
fn an_unlimited_token_approval_is_flagged_and_a_fee_limit_over_the_line_needs_the_persons_word() {
    let engine = engine();
    let tx = approve(&U256::MAX, 200_000_000);
    let mut request = request(&tx);
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["action"], "token_approve");
    assert_eq!(s["details"]["token"], TRON_USDT);
    assert_eq!(s["details"]["spender"], address(1));
    assert_eq!(s["details"]["unlimited"], true);
    assert_eq!(s["tx"]["fee_limit"], "200000000");
    // 200 TRX is above the 150 TRX a site may name without the person's word.
    assert_eq!(s["warnings"], json!(["unlimited_approval", "fee_high"]));
    let text = request.to_string();
    assert_eq!(
        engine.sign_request(0, &text, &decoded.approval).unwrap_err().code(),
        "FeeNotAccepted"
    );
    request["fee_ok"] = json!(true);
    let signed = engine.sign_request(0, &request.to_string(), &decoded.approval).unwrap();
    assert_eq!(signed["txid"], hexs::encode(&tx.txid()));

    // A limited approval at TronWeb's own default cap is plain.
    let limited = request_for(&approve(&U256::from_u128(5_000_000), 150_000_000));
    let s = decode(&engine, 0, &limited).unwrap().summary;
    assert_eq!(s["details"]["unlimited"], false);
    assert_eq!(s["warnings"], json!([]));
}

fn request_for(tx: &TronTransaction) -> Value {
    request(tx)
}

#[test]
fn a_cap_past_the_most_a_site_may_name_is_refused_and_a_cap_below_the_energy_is_warned_of() {
    let engine = engine();
    let too_much = approve(&U256::from_u128(1), 1_000_000_001);
    assert_eq!(code(decode(&engine, 0, &request(&too_much))), "FeeTooHigh");
    // The line is the cap itself: 1,000 TRX goes to the person, 1,000.000001 does not.
    let top = approve(&U256::from_u128(1), 1_000_000_000);
    let s = decode(&engine, 0, &request(&top)).unwrap().summary;
    assert!(s["warnings"].as_array().unwrap().contains(&json!("fee_high")));

    // The energy at today's price costs 27 TRX; a cap of 10 TRX will run out and burn all of it.
    let low = approve(&U256::from_u128(1), 10_000_000);
    let s = decode(&engine, 0, &request(&low)).unwrap().summary;
    assert!(s["warnings"].as_array().unwrap().contains(&json!("fee_limit_low")));
    let enough = approve(&U256::from_u128(1), 30_000_000);
    let s = decode(&engine, 0, &request(&enough)).unwrap().summary;
    assert_eq!(s["warnings"], json!([]));
}

#[test]
fn a_call_to_an_unknown_contract_is_shown_with_its_data_and_the_trx_sent_along() {
    let engine = engine();
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbc];
    data.extend([0u8; 12]);
    data.extend([0x11; 20]);
    let tx = TronTransaction {
        reference_block: reference(),
        timestamp_ms: NOW,
        expiration_ms: NOW + 60_000,
        memo: None,
        contract: tron::Contract::TriggerSmartContract {
            owner: parsed(&address(0)),
            contract: parsed(TRON_USDT),
            call_value: 7_000_000,
            data: data.clone(),
        },
        fee_limit: Some(100_000_000),
    };
    // TRX sent with a call makes it a call of the contract's own, however it looks.
    let s = decode(&engine, 0, &request(&tx)).unwrap().summary;
    assert_eq!(s["action"], "contract_call");
    assert_eq!(s["details"]["contract"], TRON_USDT);
    assert_eq!(s["details"]["selector"], "0xa9059cbc");
    assert_eq!(s["details"]["value"], "7000000");
    assert_eq!(s["details"]["data_len"], data.len());
    assert_eq!(s["details"]["data"], hexs::encode_0x(&data));
    assert_eq!(s["warnings"], json!(["unknown_contract_call"]));
}

#[test]
fn a_memo_is_shown() {
    let engine = engine();
    for text in ["order 17", "line 1\nline 2\tend", "日本語 ✓"] {
        let tx = transfer(5).with_memo(text.as_bytes());
        let s = decode(&engine, 0, &request(&tx)).unwrap().summary;
        assert_eq!(s["tx"]["memo"], text);
        assert_eq!(s["tx"]["memo_escaped"], text);
        assert_eq!(s["tx"]["memo_hidden"], 0);
        assert_eq!(s["warnings"], json!([]));
    }
    // Bytes that are not text: no text, and the bytes in hex to show.
    let tx = transfer(5).with_memo(&[0xff, 0x00]);
    let s = decode(&engine, 0, &request(&tx)).unwrap().summary;
    assert_eq!(s["tx"]["memo"], Value::Null);
    assert_eq!(s["tx"]["memo_escaped"], "0xff00");
    assert_eq!(s["tx"]["memo_hidden"], 0);
    assert_eq!(s["warnings"], json!([]));
    // No memo: nothing of one.
    let s = decode(&engine, 0, &request(&transfer(5))).unwrap().summary;
    assert_eq!(
        (&s["tx"]["memo"], &s["tx"]["memo_escaped"], &s["tx"]["memo_hidden"]),
        (&Value::Null, &Value::Null, &Value::Null)
    );
}

#[test]
fn a_memo_with_hidden_characters_is_written_out_and_warned_of() {
    let engine = engine();
    // A right-to-left override that turns what follows around, a zero-width space, a control character.
    for (memo, escaped, hidden) in [
        ("pay \u{202E}0.1 TRX\u{202C}", "pay <U+202E>0.1 TRX<U+202C>", 2),
        ("TMuA6\u{200B}YqfCe", "TMuA6<U+200B>YqfCe", 1),
        ("a\u{0}b\u{7}", "a<U+0000>b<U+0007>", 2),
    ] {
        let tx = transfer(5).with_memo(memo.as_bytes());
        let s = decode(&engine, 0, &request(&tx)).unwrap().summary;
        assert_eq!(s["tx"]["memo"], Value::Null, "{escaped}");
        assert_eq!(s["tx"]["memo_escaped"], escaped);
        assert_eq!(s["tx"]["memo_hidden"], hidden);
        assert_eq!(s["warnings"], json!(["hidden_characters"]));
    }
    // On a call, after the call's own warnings.
    let tx = approve(&U256::MAX, 150_000_000).with_memo("\u{2066}x".as_bytes());
    let s = decode(&engine, 0, &request(&tx)).unwrap().summary;
    assert_eq!(s["warnings"], json!(["unlimited_approval", "hidden_characters"]));
}

#[test]
fn the_approval_covers_the_bytes_the_account_and_the_estimate() {
    let engine = engine();
    let request = request(&transfer(1_500_000));
    let decoded = decode(&engine, 0, &request).unwrap();
    // Other bytes, another account, and another fee on the screen are not the request that was approved.
    let other = super::tron::request(&transfer(1_500_001));
    assert_eq!(
        engine.sign_request(0, &other.to_string(), &decoded.approval).unwrap_err().code(),
        "ApprovalMismatch"
    );
    let mut dearer = request.clone();
    dearer["estimate"]["fee"]["amount"] = json!("90000000");
    assert_eq!(
        engine.sign_request(0, &dearer.to_string(), &decoded.approval).unwrap_err().code(),
        "ApprovalMismatch"
    );
    // The transaction is account 0's: account 1 is not its signer.
    assert_eq!(code(decode(&engine, 1, &request)), "NotASigner");
}

#[test]
fn what_is_not_a_transfer_or_a_call_is_refused_by_name() {
    let engine = engine();
    // Cut, padded, empty, odd: not bytes the network writes.
    let tx = transfer(1);
    let hex_ = hexs::encode(&tx.raw_data());
    for bad in [&hex_[..hex_.len() - 2], "", "0a", "zz"] {
        let mut request = request(&tx);
        request["raw_data_hex"] = json!(bad);
        assert_eq!(code(decode(&engine, 0, &request)), "BadRequest", "{bad}");
    }
    // An unexpected field of the request, and an estimate for another network.
    let mut extra = request(&tx);
    extra["to"] = json!("T");
    assert_eq!(code(decode(&engine, 0, &extra)), "BadRequest");
    let mut other = request(&tx);
    other["estimate"]["network"] = json!("ethereum");
    assert_eq!(code(decode(&engine, 0, &other)), "BadRequest");
    // A transfer to oneself and a transfer of nothing are not transactions the network takes.
    let own = TronTransaction {
        contract: tron::Contract::Transfer {
            owner: parsed(&address(0)),
            to: parsed(&address(0)),
            amount: 5,
        },
        ..transfer(5)
    };
    assert_eq!(code(decode(&engine, 0, &request(&own))), "BadRequest");
    // An account permission update: named, and not a bad request but a kind this wallet does not sign.
    let owner = parsed(&address(0));
    let mut update = vec![0x0a, 21];
    update.extend(owner);
    let mut any = vec![0x0a, 60];
    any.extend(b"type.googleapis.com/protocol.AccountPermissionUpdateContract");
    any.extend([0x12, update.len() as u8]);
    any.extend(&update);
    let mut contract = vec![0x08, 46, 0x12, any.len() as u8];
    contract.extend(&any);
    let mut raw = vec![
        0x0a, 2, 0x8f, 0x0f, 0x22, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x40, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x30,
    ];
    raw.push(0x5a);
    raw.push(contract.len() as u8);
    raw.extend(&contract);
    raw.extend([0x70, 0x80, 0x80, 0x80, 0x80, 0x80, 0x30]);
    let mut theft = request(&tx);
    theft["raw_data_hex"] = json!(hexs::encode(&raw));
    let error = decode(&engine, 0, &theft).unwrap_err();
    assert_eq!(error.code(), "Unsupported");
    assert!(error.detail().contains("permission update"), "{}", error.detail());
}

#[test]
fn a_locked_wallet_signs_nothing() {
    let locked = Engine::new();
    assert_eq!(code(locked.decode_request(0, &request(&transfer(1)).to_string())), "NotUnlocked");
}

// ---- signMessageV2 ----

fn message(text: &[u8]) -> Value {
    json!({ "kind": "tron_message", "message_hex": hexs::encode_0x(text) })
}

#[test]
fn a_message_is_shown_and_signed_the_way_tronweb_signs_it() {
    let engine = engine();
    let text = b"Sign in to SunSwap\nnonce 7";
    let request = message(text);
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["request"], "tron_message");
    assert_eq!(s["network"], "tron");
    assert_eq!(s["signer"], address(0));
    assert_eq!(s["action"], "sign_message");
    assert_eq!(s["details"]["text"], "Sign in to SunSwap\nnonce 7");
    assert_eq!(s["details"]["message_len"], text.len());
    assert_eq!(s["fee"], Value::Null);
    assert_eq!(s["warnings"], json!([]));

    let signed = sign(&engine, 0, &request);
    let signature = hex(signed["signature"].as_str().unwrap());
    assert!(signed["signature"].as_str().unwrap().starts_with("0x"));
    assert_eq!(signature.len(), 65);
    assert!(signature[64] == 27 || signature[64] == 28);
    // Keccak of the TRON prefix, the length and the message recovers to the account.
    let digest = tron::message_hash(text);
    assert_eq!(signer_of(&digest, &signature, signature[64] - 27), address(0));
    // And it is the core's own signature.
    let key = nc_wallet_core::signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Tron, 0)
        .unwrap();
    assert_eq!(signature, tron::sign_message(&key, text).unwrap().to_rsv(27).to_vec());
}

#[test]
fn a_message_that_cannot_be_read_or_looks_like_a_hash_is_warned_of() {
    let engine = engine();
    let hash = Sha256::digest(b"x");
    let s = decode(&engine, 0, &message(&hash)).unwrap().summary;
    assert!(s["warnings"].as_array().unwrap().contains(&json!("hash_like_message")));
    assert!(s["warnings"].as_array().unwrap().contains(&json!("unreadable_message")));
    let s = decode(&engine, 0, &message(&[0xff, 0xfe, 0x00])).unwrap().summary;
    assert_eq!(s["warnings"], json!(["unreadable_message"]));
    // Not hex, not 0x, a field that is not ours.
    let mut broken = message(b"x");
    broken["message_hex"] = json!("78");
    assert_eq!(code(decode(&engine, 0, &broken)), "BadRequest");
    let mut extra = message(b"x");
    extra["network"] = json!("tron");
    assert_eq!(code(decode(&engine, 0, &extra)), "BadRequest");
}

#[test]
fn a_hash_written_out_in_hex_with_or_without_0x_is_hash_like() {
    let engine = engine();
    let id = hexs::encode(&Sha256::digest(b"x"));
    // A transaction id as TronWeb writes it (no 0x), in either case, and with 0x: readable text, still a hash.
    for text in [id.clone(), id.to_uppercase(), format!("0x{id}")] {
        let s = decode(&engine, 0, &message(text.as_bytes())).unwrap().summary;
        assert_eq!(s["details"]["text"], text.as_str());
        assert_eq!(s["warnings"], json!(["hash_like_message"]), "{text}");
    }
    // One digit short or long, or a letter that is not hex: an ordinary message.
    for text in
        [id[1..].to_owned(), format!("{id}0"), format!("{}g", &id[1..]), format!("0x{}", &id[1..])]
    {
        let s = decode(&engine, 0, &message(text.as_bytes())).unwrap().summary;
        assert_eq!(s["warnings"], json!([]), "{text}");
    }
}

// ---- a wallet that is one imported private key ----

#[test]
fn an_imported_tron_key_signs_exactly_what_the_phrase_signs() {
    let phrase = engine();
    let imported = key_engine(&exported_key(Network::Tron));
    for tx in [transfer(1_500_000), approve(&U256::from_u128(25_000_000), 30_000_000)] {
        let request = request(&tx);
        let theirs = decode(&phrase, 0, &request).unwrap();
        let ours = decode(&imported, 0, &request).unwrap();
        assert_eq!(ours.summary, theirs.summary);
        assert_eq!(ours.summary["signer"], address(0));
        assert_eq!(sign(&imported, 0, &request), sign(&phrase, 0, &request));
    }
    // The same key imported from an Ethereum wallet is another TRON account than the phrase's:
    // a transaction the phrase's account owns is not its to sign.
    let from_evm = key_engine(&exported_key(Network::Evm));
    assert!(decode(&from_evm, 0, &request(&transfer(1))).is_err());
}
