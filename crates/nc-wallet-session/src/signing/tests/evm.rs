//! Kinds 1 to 3: the EVM requests.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use nc_wallet_core::evm::{
    self, EvmTransaction, Fees, TypedData, U256, abi, personal_message_hash,
};
use nc_wallet_core::{Mnemonic, Network, signing_key};
use serde_json::{Value, json};

use super::super::{evm as module, prepare};
use super::*;

const REAL: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/real-evm-transactions.json");
const TYPED_V4: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/eth-sig-util-sign-typed-data-v4.json");

/// The EVM address the signature recovers to over `digest`.
pub(super) fn recover(digest: &[u8; 32], r: &[u8], s: &[u8], parity: u8) -> String {
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let signature = Signature::from_slice(&rs).unwrap();
    let key = VerifyingKey::recover_from_prehash(
        digest,
        &signature,
        RecoveryId::from_byte(parity).unwrap(),
    )
    .unwrap();
    let compressed = key.to_encoded_point(true);
    evm::address_from_public_key(compressed.as_bytes()).unwrap()
}

/// The items of an RLP list: strings without their length prefix, nested
/// lists as their raw encoding.
pub(super) fn rlp_list(data: &[u8]) -> Vec<Vec<u8>> {
    fn length(data: &[u8], at: usize, short: u8, long: u8) -> (usize, usize) {
        let first = data[at];
        if first <= short + 55 {
            (usize::from(first - short), 1)
        } else {
            let n = usize::from(first - long);
            let mut len = 0usize;
            for b in &data[at + 1..at + 1 + n] {
                len = len << 8 | usize::from(*b);
            }
            (len, 1 + n)
        }
    }
    let (len, skip) = length(data, 0, 0xc0, 0xf7);
    let body = &data[skip..skip + len];
    let mut items = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let first = body[at];
        let (start, end) = if first < 0x80 {
            (at, at + 1)
        } else if first <= 0xb7 || (0xb8..=0xbf).contains(&first) {
            let (len, skip) = length(body, at, 0x80, 0xb7);
            (at + skip, at + skip + len)
        } else {
            let (len, skip) = length(body, at, 0xc0, 0xf7);
            (at, at + skip + len)
        };
        items.push(body[start..end].to_vec());
        at = end;
    }
    items
}

pub(super) fn pad32(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32 - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

fn tx_request(network: &str, to: &str, value: &str, data: &str) -> Value {
    json!({
        "kind": "evm_transaction",
        "network": network,
        "to": to,
        "value": value,
        "data": data,
        "nonce": "7",
        "gas_limit": "60000",
        "fees": { "type": "eip1559", "max_fee_per_gas": "30000000000", "max_priority_fee_per_gas": "1500000000" },
    })
}

const BOB: &str = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB";
const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

fn bob() -> [u8; 20] {
    [0xbb; 20]
}

#[test]
fn a_native_transfer_is_decoded_and_signed_by_the_account() {
    let engine = engine();
    let request = tx_request("ethereum", BOB, "1000000000000000", "0x");
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["request"], "evm_transaction");
    assert_eq!(s["network"], "ethereum");
    assert_eq!(s["signer"], EVM_0);
    assert_eq!(s["action"], "native_transfer");
    assert_eq!(s["details"], json!({ "recipient": BOB, "amount": "1000000000000000" }));
    assert_eq!(s["fee"], json!({ "asset": "ETH", "amount": "1800000000000000", "decimals": 18 }));
    assert_eq!(s["warnings"], json!([]));
    assert_eq!(s["tx"]["chain_id"], 1);
    assert_eq!(s["tx"]["type"], "eip1559");
    assert_eq!(s["tx"]["nonce"], "7");

    // The bytes equal the core's own for the same inputs and the same key.
    let signed = sign(&engine, 0, &request);
    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 7,
        to: bob(),
        value: 1_000_000_000_000_000,
        data: Vec::new(),
        gas_limit: 60_000,
        fees: Fees::Eip1559 {
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
        },
    };
    let key = signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Evm, 0).unwrap();
    let direct = tx.sign(&key).unwrap();
    assert_eq!(signed["raw"], direct.raw_hex());
    assert_eq!(signed["hash"], direct.hash_hex());

    // And the signature in it recovers to the account.
    let raw = hex(signed["raw"].as_str().unwrap());
    assert_eq!(raw[0], 2);
    let items = rlp_list(&raw[1..]);
    assert_eq!(items.len(), 12);
    // The parity is 0 (written as the empty string) or 1.
    let parity = items[9].first().copied().unwrap_or(0);
    let signer = recover(&tx.signing_hash(), &pad32(&items[10]), &pad32(&items[11]), parity);
    assert_eq!(signer, EVM_0);
}

#[test]
fn a_legacy_transaction_signs_with_eip_155_and_recovers() {
    let engine = engine();
    let mut request = tx_request("bsc", BOB, "5", "0x");
    request["fees"] = json!({ "type": "legacy", "gas_price": "3000000000" });
    let decoded = decode(&engine, 0, &request).unwrap();
    assert_eq!(decoded.summary["tx"]["type"], "legacy");
    assert_eq!(decoded.summary["tx"]["gas_price"], "3000000000");
    assert_eq!(decoded.summary["tx"]["chain_id"], 56);
    assert_eq!(
        decoded.summary["fee"],
        json!({ "asset": "BNB", "amount": "180000000000000", "decimals": 18 })
    );
    let signed = sign(&engine, 0, &request);
    let raw = hex(signed["raw"].as_str().unwrap());
    let items = rlp_list(&raw);
    assert_eq!(items.len(), 9);
    // v = parity + 2 * 56 + 35.
    let v = u16::from(*items[6].last().unwrap());
    assert!(v == 147 || v == 148, "{v}");
    let tx = EvmTransaction {
        chain_id: 56,
        nonce: 7,
        to: bob(),
        value: 5,
        data: Vec::new(),
        gas_limit: 60_000,
        fees: Fees::Legacy { gas_price: 3_000_000_000 },
    };
    let signer = recover(
        &tx.signing_hash(),
        &pad32(&items[7]),
        &pad32(&items[8]),
        u8::try_from(v - 147).unwrap(),
    );
    assert_eq!(signer, EVM_0);
}

#[test]
fn token_calls_are_decoded_for_the_approval_screen() {
    let engine = engine();
    let usdt = evm::parse_address(USDT).unwrap();
    let amount = U256::from(250_000_000_u64);
    let hex_of = |bytes: &[u8]| format!("0x{}", super::super::hexs::encode(bytes));

    // transfer
    let data = hex_of(&abi::erc20_transfer(&bob(), &amount));
    let s = decode(&engine, 0, &tx_request("ethereum", USDT, "0", &data)).unwrap().summary;
    assert_eq!(s["action"], "token_transfer");
    assert_eq!(s["details"], json!({ "token": USDT, "recipient": BOB, "amount": "250000000" }));
    assert_eq!(s["warnings"], json!([]));

    // a limited approve
    let data = hex_of(&abi::erc20_approve(&bob(), &amount));
    let s = decode(&engine, 0, &tx_request("ethereum", USDT, "0", &data)).unwrap().summary;
    assert_eq!(s["action"], "token_approve");
    assert_eq!(s["details"]["unlimited"], false);
    assert_eq!(s["details"]["spender"], BOB);
    assert_eq!(s["warnings"], json!([]));

    // an unlimited approve
    let data = hex_of(&abi::erc20_approve(&bob(), &U256::MAX));
    let s = decode(&engine, 0, &tx_request("ethereum", USDT, "0", &data)).unwrap().summary;
    assert_eq!(s["details"]["unlimited"], true);
    assert_eq!(s["warnings"], json!(["unlimited_approval"]));

    // transferFrom
    let mut data = abi::TRANSFER_FROM.to_vec();
    data.extend_from_slice(&abi::pad_address(&bob()));
    data.extend_from_slice(&abi::pad_address(&usdt));
    data.extend_from_slice(&amount.to_be_bytes());
    let s = decode(&engine, 0, &tx_request("ethereum", USDT, "0", &hex_of(&data))).unwrap().summary;
    assert_eq!(s["action"], "token_transfer_from");
    assert_eq!(s["details"]["from"], BOB);
    assert_eq!(s["details"]["recipient"], USDT);

    // setApprovalForAll: granting warns, revoking does not
    for (approved, warns) in [(1_u8, true), (0, false)] {
        let mut data = abi::SET_APPROVAL_FOR_ALL.to_vec();
        data.extend_from_slice(&abi::pad_address(&bob()));
        data.extend_from_slice(&pad32(&[approved]));
        let s =
            decode(&engine, 0, &tx_request("polygon", USDT, "0", &hex_of(&data))).unwrap().summary;
        assert_eq!(s["action"], "set_approval_for_all");
        assert_eq!(s["details"]["approved"], approved == 1);
        assert_eq!(s["warnings"], if warns { json!(["approval_for_all"]) } else { json!([]) });
    }

    // anything else is an unknown call, with its selector and data
    let s = decode(&engine, 0, &tx_request("base", USDT, "5", "0x38ed1739aabb")).unwrap().summary;
    assert_eq!(s["action"], "contract_call");
    // (The test transaction's fee is also past what a lone operator may quote on Base: it asks for the person's OK.)
    assert_eq!(s["warnings"], json!(["unknown_contract_call", "fee_high"]));
    assert_eq!(s["details"]["selector"], "0x38ed1739");
    assert_eq!(s["details"]["data_len"], 6);
    assert_eq!(s["details"]["data"], "0x38ed1739aabb");
    assert_eq!(s["details"]["data_truncated"], false);
    assert_eq!(s["details"]["value"], "5");
    // A token call that also sends coin is not a token call.
    let data = hex_of(&abi::erc20_transfer(&bob(), &amount));
    let s = decode(&engine, 0, &tx_request("ethereum", USDT, "1", &data)).unwrap().summary;
    assert_eq!(s["action"], "contract_call");
}

#[test]
fn long_call_data_is_cut_in_the_summary_and_covered_by_the_hash() {
    let engine = engine();
    let long = format!("0x38ed1739{}", "ab".repeat(6000));
    let request = tx_request("ethereum", USDT, "0", &long);
    let decoded = decode(&engine, 0, &request).unwrap();
    assert_eq!(decoded.summary["details"]["data_truncated"], true);
    assert_eq!(decoded.summary["details"]["data_len"], 6004);
    assert_eq!(decoded.summary["details"]["data"].as_str().unwrap().len(), 2 + 2 * 4096);
    // One byte past what the summary shows still changes the approval.
    let other = format!("0x38ed1739{}ac", "ab".repeat(5999));
    let changed = decode(&engine, 0, &tx_request("ethereum", USDT, "0", &other)).unwrap();
    assert_ne!(decoded.approval, changed.approval);
}

#[test]
fn a_transaction_that_is_not_ours_or_not_supported_is_refused() {
    let engine = engine();
    let mut request = tx_request("ethereum", BOB, "1", "0x");
    request["from"] = json!(BOB);
    assert_eq!(code(decode(&engine, 0, &request)), "NotASigner");
    // The signer's own address, in any case, is fine.
    request["from"] = json!(EVM_0.to_lowercase());
    assert!(decode(&engine, 0, &request).is_ok());
    // Another account index is another signer.
    request["from"] = json!(EVM_0);
    assert_eq!(code(decode(&engine, 1, &request)), "NotASigner");

    let mut creation = tx_request("ethereum", BOB, "1", "0x6080");
    creation.as_object_mut().unwrap().remove("to");
    assert_eq!(code(decode(&engine, 0, &creation)), "Unsupported");
    // Not an EVM network.
    assert_eq!(code(decode(&engine, 0, &tx_request("tron", BOB, "1", "0x"))), "BadRequest");
    assert_eq!(code(decode(&engine, 0, &tx_request("nowhere", BOB, "1", "0x"))), "BadRequest");
    // A mixed-case address that fails its checksum.
    let wrong = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBBb";
    assert_eq!(code(decode(&engine, 0, &tx_request("ethereum", wrong, "1", "0x"))), "BadRequest");
    // Numbers are decimal strings.
    let mut number = tx_request("ethereum", BOB, "1", "0x");
    number["value"] = json!(1);
    assert_eq!(code(decode(&engine, 0, &number)), "BadRequest");
    // Zero gas, a tip above the cap, odd hex.
    let mut zero_gas = tx_request("ethereum", BOB, "1", "0x");
    zero_gas["gas_limit"] = json!("0");
    assert_eq!(code(decode(&engine, 0, &zero_gas)), "BadRequest");
    let mut tip = tx_request("ethereum", BOB, "1", "0x");
    tip["fees"]["max_priority_fee_per_gas"] = json!("40000000000");
    assert_eq!(code(decode(&engine, 0, &tip)), "BadRequest");
    assert_eq!(code(decode(&engine, 0, &tx_request("ethereum", BOB, "1", "0xabc"))), "BadRequest");
    assert_eq!(code(decode(&engine, 0, &tx_request("ethereum", BOB, "1", "abcd"))), "BadRequest");
    // Fields the request does not define.
    let mut extra = tx_request("ethereum", BOB, "1", "0x");
    extra["chain_id"] = json!(1);
    assert_eq!(code(decode(&engine, 0, &extra)), "BadRequest");
    // The zero address is shown, not refused, for a dApp.
    let zero = format!("0x{}", "0".repeat(40));
    assert!(decode(&engine, 0, &tx_request("ethereum", &zero, "1", "0x")).is_ok());
    // An account index no path takes.
    assert_eq!(
        code(decode(&engine, 1 << 31, &tx_request("ethereum", BOB, "1", "0x"))),
        "AccountIndexOutOfRange"
    );
    // Unknown kind and non-JSON.
    assert_eq!(code(decode(&engine, 0, &json!({ "kind": "evm_sign" }))), "BadRequest");
    assert_eq!(code(engine.decode_request(0, "{")), "BadRequest");
    assert_eq!(code(engine.decode_request(0, &" ".repeat(262_145))), "BadRequest");
}

#[test]
fn real_transactions_hash_to_the_digest_their_senders_signed() {
    // 24 mainnet transactions on four chains, in both forms: the bytes this
    // module would sign are the bytes the sender signed, so the vector's own
    // signature recovers to the vector's sender.
    let secrets = secrets();
    let vectors: Value = serde_json::from_str(REAL).unwrap();
    let mut checked = 0;
    let mut actions = std::collections::BTreeSet::new();
    for tx in vectors["transactions"].as_array().unwrap() {
        let chain = tx["chainId"].as_u64().unwrap();
        let network = match chain {
            1 => "ethereum",
            56 => "bsc",
            137 => "polygon",
            8453 => "base",
            other => panic!("{other}"),
        };
        let quantity = |name: &str| -> u128 {
            u128::from_str_radix(tx[name].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let fees = if tx["type"] == 2 {
            json!({ "type": "eip1559",
                "max_fee_per_gas": quantity("maxFeePerGas").to_string(),
                "max_priority_fee_per_gas": quantity("maxPriorityFeePerGas").to_string() })
        } else {
            json!({ "type": "legacy", "gas_price": quantity("gasPrice").to_string() })
        };
        let request = json!({
            "kind": "evm_transaction", "network": network,
            "to": tx["to"], "value": quantity("value").to_string(), "data": tx["input"],
            "nonce": quantity("nonce").to_string(), "gas_limit": quantity("gas").to_string(),
            "fees": fees,
        });
        let map = request.as_object().unwrap();
        let prepared = module::prepare_transaction(&secrets, 0, map).unwrap();
        let digest = evm::tx::keccak(&prepared.payload);
        let even = |text: &str| {
            let digits = text.trim_start_matches("0x");
            hex(&if digits.len() % 2 == 1 { format!("0{digits}") } else { digits.to_owned() })
        };
        let r = even(tx["r"].as_str().unwrap());
        let s = even(tx["s"].as_str().unwrap());
        let v = quantity("v");
        let parity = if tx["type"] == 2 {
            u8::try_from(if tx["yParity"].is_null() { v } else { quantity("yParity") }).unwrap()
        } else {
            u8::try_from(v - (2 * u128::from(chain) + 35)).unwrap()
        };
        let sender = recover(&digest, &pad32(&r), &pad32(&s), parity);
        assert_eq!(
            sender.to_lowercase(),
            tx["from"].as_str().unwrap().to_lowercase(),
            "{}",
            tx["hash"]
        );
        // And the summary names what the call is, from its call data.
        let input = tx["input"].as_str().unwrap();
        let expected = match input.get(..10).unwrap_or(input) {
            "0x" => "native_transfer",
            "0xa9059cbb" if input.len() == 138 => "token_transfer",
            "0x095ea7b3" if input.len() == 138 => "token_approve",
            _ => "contract_call",
        };
        assert_eq!(prepared.summary["action"], expected, "{}", tx["hash"]);
        if expected == "token_approve" {
            let unlimited = input.ends_with(&"f".repeat(64));
            assert_eq!(prepared.summary["details"]["unlimited"], unlimited, "{}", tx["hash"]);
            assert_eq!(prepared.summary["warnings"] == json!(["unlimited_approval"]), unlimited);
        }
        actions.insert(expected);
        checked += 1;
    }
    assert_eq!(checked, 24);
    // The vectors cover coin transfers, token transfers and approvals.
    assert!(
        actions.contains("native_transfer")
            && actions.contains("token_transfer")
            && actions.contains("token_approve"),
        "{actions:?}"
    );
}

#[test]
fn personal_sign_signs_the_eip_191_digest_for_the_account() {
    let engine = engine();
    let message = b"Sign in to example.org\nNonce: 12345".to_vec();
    let request = json!({ "kind": "evm_personal_sign", "message_hex": format!("0x{}", super::super::hexs::encode(&message)) });
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["action"], "personal_sign");
    assert_eq!(s["network"], "evm");
    assert_eq!(s["signer"], EVM_0);
    assert_eq!(s["details"]["text"], "Sign in to example.org\nNonce: 12345");
    assert_eq!(s["details"]["message_len"], message.len());
    assert_eq!(s["warnings"], json!([]));
    assert_eq!(s["fee"], Value::Null);

    let signed = sign(&engine, 0, &request);
    let signature = hex(signed["signature"].as_str().unwrap());
    assert_eq!(signature.len(), 65);
    assert!(signature[64] == 27 || signature[64] == 28);
    let signer = recover(
        &personal_message_hash(&message),
        &signature[..32],
        &signature[32..64],
        signature[64] - 27,
    );
    assert_eq!(signer, EVM_0);
    // The core's digest for it, once more, from its own vectors' rule.
    let key = signing_key(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Evm, 0).unwrap();
    let direct = evm::sign_personal_message(&key, &message).unwrap();
    assert_eq!(signature, direct.to_rsv(27));
}

#[test]
fn personal_sign_warns_about_hashes_and_unreadable_bytes() {
    let engine = engine();
    let warnings = |message_hex: &str| {
        decode(&engine, 0, &json!({ "kind": "evm_personal_sign", "message_hex": message_hex }))
            .unwrap()
            .summary["warnings"]
            .clone()
    };
    // Exactly 32 bytes: may be a transaction hash.
    let thirty_two = format!("0x{}", "11".repeat(32));
    assert_eq!(
        warnings(&thirty_two),
        json!(["unreadable_message", "hidden_characters", "hash_like_message"])
    );
    // The text of a hash (66 characters), which a site may send as plain text.
    let text_hash =
        format!("0x{}", super::super::hexs::encode(format!("0x{}", "ab".repeat(32)).as_bytes()));
    assert_eq!(warnings(&text_hash), json!(["hash_like_message"]));
    // Bytes that are not text.
    assert_eq!(warnings("0xff00fe"), json!(["unreadable_message"]));
    // Text with a control character is unreadable and says there is something hidden.
    assert_eq!(warnings("0x61006200"), json!(["unreadable_message", "hidden_characters"]));
    // Empty is the empty message.
    assert_eq!(warnings("0x"), json!([]));
    // Not hex.
    let bad = decode(&engine, 0, &json!({ "kind": "evm_personal_sign", "message_hex": "hello" }));
    assert_eq!(code(bad), "BadRequest");
}

pub(super) const MAIL: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
    "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}]
  },
  "primaryType": "Mail",
  "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
  "message": {
    "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!"
  }
}"#;

fn typed_request(network: &str, document: &str) -> Value {
    json!({ "kind": "evm_typed_data", "network": network, "typed_data": document })
}

#[test]
fn typed_data_is_summarised_hashed_and_signed() {
    let engine = engine();
    let request = typed_request("ethereum", MAIL);
    let decoded = decode(&engine, 0, &request).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["action"], "typed_data");
    assert_eq!(s["details"]["primary_type"], "Mail");
    assert_eq!(s["details"]["kind"], "other");
    assert_eq!(s["details"]["domain"]["name"], "Ether Mail");
    assert_eq!(s["details"]["domain"]["chain_id"], "1");
    assert_eq!(
        s["details"]["domain"]["verifying_contract"],
        "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    );
    assert_eq!(s["warnings"], json!(["unrecognised_typed_data"]));
    // The document shown is the one parsed.
    let shown: Value = serde_json::from_str(s["details"]["typed_data"].as_str().unwrap()).unwrap();
    assert_eq!(shown, serde_json::from_str::<Value>(MAIL).unwrap());

    // EIP-712's own digest for the Mail example.
    let data = TypedData::parse(MAIL).unwrap();
    assert_eq!(
        super::super::hexs::encode(&data.signing_hash().unwrap()),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
    let signed = sign(&engine, 0, &request);
    let signature = hex(signed["signature"].as_str().unwrap());
    let signer = recover(
        &data.signing_hash().unwrap(),
        &signature[..32],
        &signature[32..64],
        signature[64] - 27,
    );
    assert_eq!(signer, EVM_0);
}

#[test]
fn permits_warn_and_a_chain_mismatch_is_flagged() {
    let engine = engine();
    let permit = |value: &str, chain: u64| {
        json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                "Permit": [
                    {"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}]
            },
            "primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": chain, "verifyingContract": USDT},
            "message": {"owner": EVM_0, "spender": BOB, "value": value, "nonce": 0, "deadline": "1893456000"}
        })
        .to_string()
    };
    let s = decode(&engine, 0, &typed_request("ethereum", &permit("5000000", 1))).unwrap().summary;
    assert_eq!(s["details"]["kind"], "permit");
    assert_eq!(s["details"]["permit"]["owner"], EVM_0);
    assert_eq!(s["details"]["permit"]["spender"], BOB);
    assert_eq!(s["details"]["permit"]["value"], "5000000");
    assert_eq!(s["details"]["permit"]["unlimited"], false);
    assert_eq!(s["details"]["permit"]["deadline"], "1893456000");
    assert_eq!(s["warnings"], json!(["permit_signature"]));

    let max = U256::MAX.to_string();
    let s = decode(&engine, 0, &typed_request("ethereum", &permit(&max, 1))).unwrap().summary;
    assert_eq!(s["details"]["permit"]["unlimited"], true);
    assert_eq!(s["warnings"], json!(["permit_signature", "unlimited_approval"]));

    // The domain names another chain than the site's.
    let s = decode(&engine, 0, &typed_request("polygon", &permit("5", 1))).unwrap().summary;
    assert_eq!(s["warnings"], json!(["permit_signature", "chain_mismatch"]));
    let s = decode(&engine, 0, &typed_request("polygon", &permit("5", 137))).unwrap().summary;
    assert_eq!(s["warnings"], json!(["permit_signature"]));

    // DAI's permit warns only when it grants.
    let dai = |allowed: bool| {
        json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}],
                "Permit": [
                    {"name": "holder", "type": "address"}, {"name": "spender", "type": "address"},
                    {"name": "nonce", "type": "uint256"}, {"name": "expiry", "type": "uint256"},
                    {"name": "allowed", "type": "bool"}]
            },
            "primaryType": "Permit",
            "domain": {"name": "Dai Stablecoin", "chainId": 1},
            "message": {"holder": EVM_0, "spender": BOB, "nonce": 3, "expiry": 0, "allowed": allowed}
        })
        .to_string()
    };
    let s = decode(&engine, 0, &typed_request("ethereum", &dai(true))).unwrap().summary;
    assert_eq!(s["details"]["kind"], "dai_permit");
    assert_eq!(s["details"]["dai_permit"]["allowed"], true);
    assert_eq!(s["details"]["dai_permit"]["nonce"], "3");
    assert_eq!(s["warnings"], json!(["permit_signature"]));
    let s = decode(&engine, 0, &typed_request("ethereum", &dai(false))).unwrap().summary;
    assert_eq!(s["warnings"], json!([]));
}

#[test]
fn bad_typed_data_is_refused() {
    let engine = engine();
    for document in ["", "[]", "{}", r#"{"types":{},"primaryType":"X","domain":{},"message":{}}"#] {
        assert_eq!(
            code(decode(&engine, 0, &typed_request("ethereum", document))),
            "BadRequest",
            "{document}"
        );
    }
    assert_eq!(code(decode(&engine, 0, &typed_request("solana", MAIL))), "BadRequest");
}

#[test]
fn every_typed_data_case_of_the_eth_sig_util_suite_hashes_as_its_signer_signed() {
    // MetaMask's `eth-sig-util` snapshots: the digest this module signs
    // recovers, from the snapshot's signature, to the snapshot key's address.
    let secrets = secrets();
    let vectors: Value = serde_json::from_str(TYPED_V4).unwrap();
    let key_bytes: [u8; 32] = hex(vectors["private_key"].as_str().unwrap()).try_into().unwrap();
    let secret = k256::SecretKey::from_slice(&key_bytes).unwrap();
    let public =
        k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&secret.public_key(), true);
    let owner = evm::address_from_public_key(public.as_bytes()).unwrap();

    let check = |document: &Value, signature: &str, label: &str| -> bool {
        let request = typed_request("ethereum", &document.to_string());
        let Ok(prepared) = prepare(&secrets, 0, &request.to_string()) else { return false };
        let digest: [u8; 32] = prepared.payload.clone().try_into().unwrap();
        let signature = hex(signature);
        let signer = recover(&digest, &signature[..32], &signature[32..64], signature[64] - 27);
        assert_eq!(signer, owner, "{label}");
        true
    };
    let mut checked = 0;
    for case in vectors["cases"].as_array().unwrap() {
        assert!(
            check(
                &case["data"],
                case["signature"].as_str().unwrap(),
                case["name"].as_str().unwrap()
            ),
            "{}",
            case["name"]
        );
        checked += 1;
    }
    // 74 single values: the wallet is stricter than MetaMask on some (they
    // are refused, as in the core's own test), and agrees on the rest.
    let mut agreed = 0;
    for atom in vectors["atoms"].as_array().unwrap() {
        let document = json!({
            "types": {"EIP712Domain": [], "Message": [{"name": "data", "type": atom["type"]}]},
            "primaryType": "Message", "domain": {}, "message": {"data": atom["value"]},
        });
        if check(&document, atom["signature"].as_str().unwrap(), atom["type"].as_str().unwrap()) {
            agreed += 1;
        }
    }
    assert_eq!(checked, 5);
    assert!(agreed >= 30, "{agreed}");
}

// ---- a site's transaction: the work and the fee it may reserve ----

fn dapp_tx(network: &str, gas: &str, max_fee_gwei: u128, tip_gwei: u128) -> Value {
    let mut request = tx_request(network, BOB, "0", "0x");
    request["gas_limit"] = json!(gas);
    request["fees"] = json!({
        "type": "eip1559",
        "max_fee_per_gas": (max_fee_gwei * 1_000_000_000).to_string(),
        "max_priority_fee_per_gas": (tip_gwei * 1_000_000_000).to_string(),
    });
    request
}

#[test]
fn a_site_cannot_reserve_more_work_or_more_fee_than_the_wallets_own_bounds() {
    let engine = engine();
    // Three million units is the most a site may reserve; one more is refused, whatever the price.
    assert!(decode(&engine, 0, &dapp_tx("ethereum", "3000000", 1, 1)).is_ok());
    assert_eq!(code(decode(&engine, 0, &dapp_tx("ethereum", "3000001", 1, 1))), "FeeTooHigh");
    // The thirty million of a block (a contract that burns all it is given) at 40 gwei is 1.2 ETH.
    assert_eq!(code(decode(&engine, 0, &dapp_tx("ethereum", "30000000", 40, 1))), "FeeTooHigh");
    // Inside the work bound, the fee in all is bounded too: 3M units at 200 gwei is 0.6 ETH, past 0.5.
    assert_eq!(code(decode(&engine, 0, &dapp_tx("ethereum", "3000000", 200, 1))), "FeeTooHigh");
    // A real contract call in a busy hour: 400,000 units at 120 gwei is 0.048 ETH, under the line a person
    // is asked about (0.05 ETH).
    let s = decode(&engine, 0, &dapp_tx("ethereum", "400000", 120, 2)).unwrap().summary;
    assert!(s["warnings"].as_array().unwrap().iter().all(|w| w != "fee_high"), "{s}");
}

#[test]
fn typed_data_for_another_chain_is_signed_only_when_the_person_has_said_so() {
    let engine = engine();
    // A permit whose domain names `chain`, asked for on `network`: the usual shape of a cross-chain phishing permit.
    let permit = |network: &str, chain: u64| {
        let document = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                "Permit": [
                    {"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}]
            },
            "primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": chain, "verifyingContract": USDT},
            "message": {"owner": EVM_0, "spender": BOB, "value": "5", "nonce": 0, "deadline": "1893456000"}
        });
        typed_request(network, &document.to_string())
    };
    // On the network the domain names, nothing more is asked.
    let same = permit("polygon", 137);
    assert!(
        engine
            .sign_request(0, &same.to_string(), &decode(&engine, 0, &same).unwrap().approval)
            .is_ok()
    );

    // Another chain: the review still shows it, with its warning, so that it can be told...
    let other = permit("polygon", 1);
    let text = other.to_string();
    let decoded = engine.decode_request(0, &text).unwrap();
    assert!(decoded.summary["warnings"].as_array().unwrap().iter().any(|w| w == "chain_mismatch"));
    // ...and is not signed. A site's request is refused, as MetaMask refuses it.
    let refused = engine.sign_request(0, &text, &decoded.approval).unwrap_err();
    assert_eq!(refused.code(), "ChainMismatch");
    assert!(!refused.detail().contains("0x"), "{}", refused.detail());
    // The person's word, set after a warning of its own, signs it, and the approval did not change.
    let mut said = other.clone();
    said["allow_chain_mismatch"] = json!(true);
    let again = engine.decode_request(0, &said.to_string()).unwrap();
    assert_eq!(again.approval, decoded.approval);
    let signed = engine.sign_request(0, &said.to_string(), &decoded.approval).unwrap();
    assert!(signed["signature"].is_string());
    // `false` is no word; nothing but true or false is read.
    let mut no = other.clone();
    no["allow_chain_mismatch"] = json!(false);
    let text = no.to_string();
    let refused = engine.sign_request(0, &text, &decoded.approval).unwrap_err();
    assert_eq!(refused.code(), "ChainMismatch");
    let mut odd = other;
    odd["allow_chain_mismatch"] = json!("yes");
    assert_eq!(code(decode(&engine, 0, &odd)), "BadRequest");
    // The word does not make another request's approval work.
    let wrong = permit("polygon", 56);
    let mut wrong_said = wrong.clone();
    wrong_said["allow_chain_mismatch"] = json!(true);
    let refused = engine.sign_request(0, &wrong_said.to_string(), &decoded.approval).unwrap_err();
    assert_eq!(refused.code(), "ApprovalMismatch");
}

#[test]
fn a_high_fee_is_signed_only_when_the_person_has_accepted_it() {
    let engine = engine();
    // 1.5M units at 100 gwei is 0.15 ETH: allowed for a site, but past 0.05 ETH, where the person is asked.
    let request = dapp_tx("ethereum", "1500000", 100, 2);
    let text = request.to_string();
    let decoded = engine.decode_request(0, &text).unwrap();
    assert!(decoded.summary["warnings"].as_array().unwrap().iter().any(|w| w == "fee_high"));
    let refused = engine.sign_request(0, &text, &decoded.approval).unwrap_err();
    assert_eq!(refused.code(), "FeeNotAccepted");
    // With the person's OK the same request signs, and the approval did not change.
    let mut accepted = request.clone();
    accepted["fee_ok"] = json!(true);
    let again = engine.decode_request(0, &accepted.to_string()).unwrap();
    assert_eq!(again.approval, decoded.approval);
    assert!(engine.sign_request(0, &accepted.to_string(), &decoded.approval).is_ok());
    // fee_ok is true or false, nothing else.
    let mut odd = request;
    odd["fee_ok"] = json!("yes");
    assert_eq!(code(decode(&engine, 0, &odd)), "BadRequest");
    // An ordinary fee needs no OK.
    let ordinary = dapp_tx("ethereum", "60000", 30, 1);
    assert!(
        decode(&engine, 0, &ordinary).unwrap().summary["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|w| w != "fee_high")
    );
    sign(&engine, 0, &ordinary);
}

// ---- MINOR 6: text that hides ----

fn personal(message: &str, origin: Option<&str>) -> Value {
    let mut request = json!({ "kind": "evm_personal_sign", "message_hex": format!("0x{}", super::super::hexs::encode(message.as_bytes())) });
    if let Some(origin) = origin {
        request["origin"] = json!(origin);
    }
    decode(&engine(), 0, &request).unwrap().summary
}

#[test]
fn a_right_to_left_override_makes_a_message_unreadable_and_is_shown_escaped() {
    for hidden in
        ['\u{202E}', '\u{200B}', '\u{2028}', '\u{2029}', '\u{FEFF}', '\u{2066}', '\u{E0041}']
    {
        let s = personal(&format!("Send 1 ETH{hidden} to Bob"), None);
        assert_eq!(s["details"]["text"], Value::Null, "{:X}", u32::from(hidden));
        assert_eq!(s["details"]["hidden_characters"], 1);
        assert!(s["details"]["text_escaped"].as_str().unwrap().contains("<U+"));
        assert_eq!(s["warnings"], json!(["unreadable_message", "hidden_characters"]));
    }
    // The full length is always given: 17 characters, more bytes.
    let s = personal("héllo wörld ✓ ok!!", None);
    assert_eq!(s["details"]["text_chars"], 18);
    assert_eq!(s["details"]["message_len"], "héllo wörld ✓ ok!!".len());
    assert_eq!(s["warnings"], json!([]));
}

#[test]
fn a_sign_in_message_names_its_claimed_domain_and_is_compared_with_the_origin() {
    let signer = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    let text = format!(
        "bank.example wants you to sign in with your Ethereum account:\n{signer}\n\nSign in.\n\nURI: https://bank.example\nVersion: 1\nChain ID: 1\nNonce: abc12345\nIssued At: 2026-10-28T12:00:00Z"
    );
    let honest = personal(&text, Some("https://bank.example"));
    assert_eq!(honest["details"]["siwe"]["claimed_domain"], "bank.example");
    assert_eq!(honest["details"]["siwe"]["chain_id"], "1");
    assert_eq!(honest["details"]["siwe"]["nonce"], "abc12345");
    assert_eq!(honest["details"]["siwe"]["domain_matches_origin"], true);
    assert_eq!(honest["details"]["siwe"]["address_matches_signer"], true);
    assert_eq!(honest["warnings"], json!([]));
    let phish = personal(&text, Some("https://bank-login.example"));
    assert_eq!(phish["warnings"], json!(["siwe_domain_mismatch"]));
    // The origin is part of what is approved: a request with another one is another approval.
    assert_ne!(
        decode(&engine(), 0, &json!({ "kind": "evm_personal_sign", "message_hex": format!("0x{}", super::super::hexs::encode(text.as_bytes())), "origin": "https://bank.example" })).unwrap().approval,
        decode(&engine(), 0, &json!({ "kind": "evm_personal_sign", "message_hex": format!("0x{}", super::super::hexs::encode(text.as_bytes())), "origin": "https://bank-login.example" })).unwrap().approval,
    );
}

// ---- MAJOR 1: Permit2 and unrecognised typed data ----

#[test]
fn permit2_is_decoded_as_a_spending_permission_and_other_typed_data_is_not_called_harmless() {
    let permit2 = json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" },
            ],
            "PermitSingle": [
                { "name": "details", "type": "PermitDetails" },
                { "name": "spender", "type": "address" },
                { "name": "sigDeadline", "type": "uint256" },
            ],
            "PermitDetails": [
                { "name": "token", "type": "address" },
                { "name": "amount", "type": "uint160" },
                { "name": "expiration", "type": "uint48" },
                { "name": "nonce", "type": "uint48" },
            ],
        },
        "primaryType": "PermitSingle",
        "domain": { "name": "Uniswap Permit", "chainId": 1, "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
        "message": {
            "details": {
                "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "amount": "1461501637330902918203684832716283019655932542975",
                "expiration": "281474976710655",
                "nonce": "0",
            },
            "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "sigDeadline": "1893456000",
        },
    });
    let s = decode(&engine(), 0, &typed_request("ethereum", &permit2.to_string())).unwrap().summary;
    assert_eq!(s["details"]["kind"], "permit2_allowance");
    assert_eq!(s["details"]["understood"], true);
    assert_eq!(s["details"]["may_authorise_spending"], true);
    assert_eq!(s["details"]["domain"]["known_contract"], "Permit2");
    assert_eq!(s["details"]["domain"]["claimed_by_site"], json!(["name", "version"]));
    let allowance = &s["details"]["permit2"]["allowances"][0];
    assert_eq!(allowance["token"], "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    assert_eq!(allowance["unlimited"], true);
    assert_eq!(allowance["never_expires"], true);
    assert_eq!(s["details"]["permit2"]["spender"], "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD");
    assert_eq!(s["warnings"], json!(["permit_signature", "unlimited_approval"]));

    // Unrecognised typed data is never "nothing is sent".
    let other = decode(&engine(), 0, &typed_request("ethereum", MAIL)).unwrap().summary;
    assert_eq!(other["details"]["understood"], false);
    assert_eq!(other["details"]["may_authorise_spending"], true);
    assert_eq!(other["details"]["domain"]["known_contract"], Value::Null);
}
