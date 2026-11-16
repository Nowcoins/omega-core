//! TRON encoding, signing and decoding against vectors from outside this
//! crate: real mainnet transactions, Trust Wallet Core's and `TronWeb`'s.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::Value;

use super::RawDataError;
use super::decode::{Call, classify_contract_call};
use super::message::{message_hash, sign_message};
use super::tx::{
    AddressBytes, Contract, ReferenceBlock, TronTransaction, address_from_hash, format_address,
    parse_address, sha256,
};
use crate::evm::U256;
use crate::evm::abi;
use crate::hexutil;
use crate::key::SigningKey;
use crate::tx_error::TxError;

const REAL: &str = include_str!("../../tests/vectors/real-tron-transactions.json");
const MESSAGES: &str = include_str!("../../tests/vectors/tron-sign-message-v2.json");

fn key(hex: &str) -> SigningKey {
    let bytes: [u8; 32] = hexutil::decode(hex).unwrap().try_into().unwrap();
    SigningKey::secp256k1(&bytes).unwrap()
}

fn addr(hex: &str) -> AddressBytes {
    hexutil::decode(hex).unwrap().try_into().unwrap()
}

/// The `T…` address that signed `digest` with `signature` (`r ‖ s ‖ v`, v 0
/// or 1).
fn signer_of(digest: &[u8; 32], signature: &[u8], v_offset: u8) -> String {
    let sig = Signature::from_slice(&signature[..64]).unwrap();
    let id = RecoveryId::from_byte(signature[64] - v_offset).unwrap();
    let key = VerifyingKey::recover_from_prehash(digest, &sig, id).unwrap();
    let compressed = key.to_sec1_point(true);
    super::address_from_public_key(compressed.as_bytes()).unwrap()
}

/// A transaction as the node's JSON describes it, rebuilt.
fn rebuild(tx: &Value) -> TronTransaction {
    let raw = &tx["raw_data"];
    let reference_block = ReferenceBlock {
        bytes: hexutil::decode(raw["ref_block_bytes"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        hash: hexutil::decode(raw["ref_block_hash"].as_str().unwrap()).unwrap().try_into().unwrap(),
    };
    let contract = &raw["contract"][0]["parameter"]["value"];
    let owner = addr(contract["owner_address"].as_str().unwrap());
    let contract = match raw["contract"][0]["type"].as_str().unwrap() {
        "TransferContract" => Contract::Transfer {
            owner,
            to: addr(contract["to_address"].as_str().unwrap()),
            amount: contract["amount"].as_u64().unwrap(),
        },
        "TriggerSmartContract" => Contract::TriggerSmartContract {
            owner,
            contract: addr(contract["contract_address"].as_str().unwrap()),
            call_value: contract["call_value"].as_u64().unwrap_or(0),
            data: hexutil::decode(contract["data"].as_str().unwrap()).unwrap(),
        },
        other => panic!("{other}"),
    };
    TronTransaction {
        reference_block,
        timestamp_ms: raw["timestamp"].as_i64().unwrap(),
        expiration_ms: raw["expiration"].as_i64().unwrap(),
        memo: raw.get("data").map(|d| hexutil::decode(d.as_str().unwrap()).unwrap()),
        contract,
        fee_limit: raw.get("fee_limit").map(|l| l.as_u64().unwrap()),
    }
}

#[test]
fn real_mainnet_transactions_are_reproduced_byte_for_byte() {
    let file: Value = serde_json::from_str(REAL).unwrap();
    let txs = file["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 5);
    let mut kinds = std::collections::BTreeSet::new();
    for tx in txs {
        let name = tx["txID"].as_str().unwrap();
        let built = rebuild(tx);
        built.validate().unwrap();
        // The protobuf body is the node's, byte for byte, and so is its id.
        assert_eq!(
            hexutil::encode(&built.raw_data()),
            tx["raw_data_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(hexutil::encode(&built.txid()), name);
        // The signature on the chain recovers to the owner.
        let signature = hexutil::decode(tx["signature"].as_str().unwrap()).unwrap();
        assert_eq!(
            signer_of(&built.txid(), &signature, 0),
            format_address(built.owner()),
            "{name}: signer"
        );
        let data = match &built.contract {
            Contract::TriggerSmartContract { data, .. } => data.clone(),
            Contract::Transfer { .. } => Vec::new(),
        };
        kinds.insert(match built.describe() {
            Call::TrxTransfer { .. } => "trx",
            // The real calls write their address words with the 0x41 prefix.
            Call::Trc20Transfer { to, amount, .. } => {
                assert_eq!(to[1..], data[16..36], "{name}");
                assert_eq!(amount.to_be_bytes(), data[36..68], "{name}");
                "transfer"
            }
            Call::Trc20Approve { spender, amount, unlimited, .. } => {
                assert_eq!(spender[1..], data[16..36], "{name}");
                assert_eq!(amount.to_be_bytes(), data[36..68], "{name}");
                assert!(!unlimited);
                "approve"
            }
            other => panic!("{name}: {other:?}"),
        });
    }
    assert_eq!(kinds.len(), 3);
}

#[test]
fn reference_blocks_are_made_as_java_tron_makes_them() {
    let file: Value = serde_json::from_str(REAL).unwrap();
    for tx in file["transactions"].as_array().unwrap() {
        let built = rebuild(tx);
        let reference = &tx["reference_block"];
        let id: [u8; 32] =
            hexutil::decode(reference["block_id"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(
            ReferenceBlock::from_block(reference["number"].as_u64().unwrap(), &id),
            built.reference_block,
            "{}",
            tx["txID"]
        );
    }
}

#[test]
fn trust_wallet_core_memo_transaction_is_signed_identically() {
    // tests/chains/Tron/SignerTests.cpp @ adf80f8b, SignTransferWithMemo: the
    // key, the addresses, the amount, the memo, the id and the signature.
    let file: Value = serde_json::from_str(REAL).unwrap();
    let tx = file["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["txID"] == "20321755964d6ec5bcfc9ebfb15faeb043787ae599fff44442962e12e1c357f1")
        .unwrap();
    let built = rebuild(tx);
    let signer = key("7c2108a30f6f69f8dce72a7df897eabadfe9810eee6976b43bdf8c0b0d35337d");
    let signed = built.sign(&signer).unwrap();
    assert_eq!(
        signed.txid_hex(),
        "20321755964d6ec5bcfc9ebfb15faeb043787ae599fff44442962e12e1c357f1"
    );
    assert_eq!(
        hexutil::encode(&signed.signature),
        "6fcee79c61f660ec689299f77924f32b5020b4c41593056052ef07d640cc799325103fab130c8691e8a224c96cd0704a698ac356ff789a543c284605668bf38000"
    );
    assert_eq!(hexutil::encode(&signed.signature), tx["signature"].as_str().unwrap());
    assert_eq!(format_address(built.owner()), "TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp");
    match &built.contract {
        Contract::Transfer { to, amount, .. } => {
            assert_eq!(format_address(to), "TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX");
            assert_eq!(*amount, 100_000);
        }
        other @ Contract::TriggerSmartContract { .. } => panic!("{other:?}"),
    }
    assert_eq!(built.memo.as_deref(), Some(b"Test memo".as_slice()));
    // The message `broadcasthex` takes: the body, then the signature.
    // The body is 144 bytes, a varint of two bytes (0x90 0x01).
    assert_eq!(signed.raw_data.len(), 144);
    assert_eq!(
        signed.transaction,
        [&[0x0a, 0x90, 0x01][..], &signed.raw_data, &[0x12, 0x41], &signed.signature].concat()
    );
}

#[test]
fn a_transaction_signed_by_another_key_is_refused() {
    let file: Value = serde_json::from_str(REAL).unwrap();
    let built = rebuild(&file["transactions"][0]);
    let other = key("0000000000000000000000000000000000000000000000000000000000000001");
    assert_eq!(
        built.sign(&other).unwrap_err(),
        TxError::invalid("owner", "is not the address of the signing key")
    );
    assert_eq!(built.sign(&SigningKey::ed25519(&[1; 32])).unwrap_err(), TxError::WrongKeyScheme);
}

#[test]
fn sign_message_v2_matches_tronweb_and_trust_wallet_core() {
    let file: Value = serde_json::from_str(MESSAGES).unwrap();
    for case in file["cases"].as_array().unwrap() {
        let message = match case.get("message_utf8") {
            Some(text) => text.as_str().unwrap().as_bytes().to_vec(),
            None => hexutil::decode_prefixed(case["message_hex"].as_str().unwrap()).unwrap(),
        };
        let signer = key(case["private_key"].as_str().unwrap());
        assert_eq!(
            hexutil::encode_prefixed(&message_hash(&message)),
            case["message_hash"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        let signature = sign_message(&signer, &message).unwrap();
        assert_eq!(
            hexutil::encode_prefixed(&signature.to_rsv(27)),
            case["signature"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            signer_of(&message_hash(&message), &signature.to_rsv(27), 27),
            case["address"].as_str().unwrap()
        );
    }
    // Trust Wallet Core's two (bare hex, v 27 or 28), key 75065f10….
    let signer = key("75065f100e38d3f3b4c5c4235834ba8216de62272a4f03532c44b31a5734360a");
    for (message, expected) in [
        (
            "Hello World",
            "bc0753c070cc55693097df11bc11e1a7c4bd5e1a40b9dc94c75568e59bcc9d6b50a7873ef25b469e494490a54de37327b4bc7fc825c81a377b555e34fb7261ba1c",
        ),
        (
            "A much longer message to test the signing and verification process",
            "93aee5f753cf889e0749c74dd0c5996cce889883ae079e09ede462e16d65d06a4f43d1ed2745e9f3c1690695628269bd58f057a4a93953cc50e66b4a05bc0f451b",
        ),
    ] {
        let signature = sign_message(&signer, message.as_bytes()).unwrap();
        assert_eq!(hexutil::encode(&signature.to_rsv(27)), expected);
    }
}

#[test]
fn addresses_round_trip_and_wrong_ones_are_refused() {
    let owner = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    assert_eq!(owner[0], 0x41);
    assert_eq!(format_address(&owner), "TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp");
    assert_eq!(address_from_hash(&owner[1..].try_into().unwrap()), owner);
    for bad in [
        "",
        "TFnYQCt892UNjn67pjAULTSTkB7YvqsnPq",
        "0x3fcc5f66a381694b6f6656eb08b535c3587e8ed1",
        // An EVM address's base58 is not a TRON one.
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    ] {
        assert!(parse_address(bad).is_err(), "{bad}");
    }
}

fn block() -> ReferenceBlock {
    ReferenceBlock { bytes: [0x27, 0xdc], hash: [1, 2, 3, 4, 5, 6, 7, 8] }
}

#[test]
fn a_transaction_the_network_would_refuse_is_refused_before_signing() {
    let a = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    let b = parse_address("TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX").unwrap();
    let now = 1_730_827_017_000_i64;
    assert!(TronTransaction::trx_transfer(a, b, 1, block(), now, now + 60_000).is_ok());
    assert!(TronTransaction::trx_transfer(a, b, 0, block(), now, now + 60_000).is_err());
    assert!(TronTransaction::trx_transfer(a, b, u64::MAX, block(), now, now + 60_000).is_err());
    assert!(TronTransaction::trx_transfer(a, a, 1, block(), now, now + 60_000).is_err());
    assert!(TronTransaction::trx_transfer(a, b, 1, block(), now, now).is_err());
    assert!(TronTransaction::trx_transfer(a, b, 1, block(), 0, 5).is_err());
    let token = parse_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();
    let amount = U256::from_u128(5);
    assert!(
        TronTransaction::trc20_transfer(a, token, &b, &amount, 1_000, block(), now, now + 1)
            .is_ok()
    );
    // A call needs a fee limit; a transfer has none.
    assert!(
        TronTransaction::trc20_transfer(a, token, &b, &amount, 0, block(), now, now + 1).is_err()
    );
    let mut call =
        TronTransaction::trc20_transfer(a, token, &b, &amount, 1_000, block(), now, now + 1)
            .unwrap();
    call.fee_limit = None;
    assert!(call.validate().is_err());
    let mut transfer = TronTransaction::trx_transfer(a, b, 1, block(), now, now + 1).unwrap();
    transfer.fee_limit = Some(1);
    assert!(transfer.validate().is_err());
}

#[test]
fn trc20_calls_are_encoded_and_classified() {
    let a = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    let b = parse_address("TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX").unwrap();
    // USDT on TRON.
    let token = parse_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();
    let amount = U256::from_u128(25_000_000);
    let now = 1_730_827_017_000_i64;
    let transfer = TronTransaction::trc20_transfer(
        a,
        token,
        &b,
        &amount,
        30_000_000,
        block(),
        now,
        now + 60_000,
    )
    .unwrap();
    let Contract::TriggerSmartContract { data, call_value, .. } = &transfer.contract else {
        panic!()
    };
    assert_eq!(*call_value, 0);
    assert_eq!(*data, abi::erc20_transfer(&b[1..].try_into().unwrap(), &amount));
    assert_eq!(transfer.describe(), Call::Trc20Transfer { token, to: b, amount });

    let approve = TronTransaction::trc20_approve(
        a,
        token,
        &b,
        &U256::MAX,
        30_000_000,
        block(),
        now,
        now + 60_000,
    )
    .unwrap();
    assert_eq!(
        approve.describe(),
        Call::Trc20Approve { token, spender: b, amount: U256::MAX, unlimited: true }
    );
    // TRX sent with a token call, or a call that is not canonical, is unknown.
    let Contract::TriggerSmartContract { data, .. } = &approve.contract else { panic!() };
    assert!(matches!(
        classify_contract_call(&token, 1, data),
        Call::UnknownContractCall { call_value: 1, .. }
    ));
    assert!(matches!(
        classify_contract_call(&token, 0, &data[..data.len() - 1]),
        Call::UnknownContractCall { data_len: 67, .. }
    ));
    // transferFrom and setApprovalForAll.
    let mut from = abi::TRANSFER_FROM.to_vec();
    from.extend_from_slice(&abi::pad_address(&a[1..].try_into().unwrap()));
    from.extend_from_slice(&abi::pad_address(&b[1..].try_into().unwrap()));
    from.extend_from_slice(&U256::from_u128(7).to_be_bytes());
    assert_eq!(
        classify_contract_call(&token, 0, &from),
        Call::Trc20TransferFrom { token, from: a, to: b, amount: U256::from_u128(7) }
    );
    let mut all = abi::SET_APPROVAL_FOR_ALL.to_vec();
    all.extend_from_slice(&abi::pad_address(&b[1..].try_into().unwrap()));
    all.extend_from_slice(&U256::from_u128(1).to_be_bytes());
    assert_eq!(
        classify_contract_call(&token, 0, &all),
        Call::SetApprovalForAll { contract: token, operator: b, approved: true }
    );
}

#[test]
fn the_protobuf_leaves_out_what_holds_its_default() {
    // A memo of nothing is no field; a zero call value is no field.
    let a = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    let b = parse_address("TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX").unwrap();
    let now = 1_730_827_017_000_i64;
    let plain = TronTransaction::trx_transfer(a, b, 1, block(), now, now + 1).unwrap();
    let empty_memo = plain.clone().with_memo(&[]);
    assert_eq!(plain.raw_data(), empty_memo.raw_data());
    assert_ne!(plain.raw_data(), plain.clone().with_memo(b"x").raw_data());
    assert_eq!(sha256(&plain.raw_data()), plain.txid());
}

// ---- reading a page's transaction back ----

fn real_raw() -> Vec<(String, Vec<u8>, TronTransaction)> {
    let file: Value = serde_json::from_str(REAL).unwrap();
    file["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tx| {
            let raw = hexutil::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap();
            (tx["txID"].as_str().unwrap().to_owned(), raw, rebuild(tx))
        })
        .collect()
}

fn varint_bytes(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn bytes_field(number: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint_bytes(number << 3 | 2);
    out.extend(varint_bytes(bytes.len() as u64));
    out.extend_from_slice(bytes);
    out
}

fn varint_field(number: u64, value: u64) -> Vec<u8> {
    let mut out = varint_bytes(number << 3);
    out.extend(varint_bytes(value));
    out
}

/// A `raw_data` of the real shape around a contract message built here.
fn raw_with_contract(contract: &[u8]) -> Vec<u8> {
    let mut raw = bytes_field(1, &[0x7a, 0xf0]);
    raw.extend(bytes_field(4, &[1, 2, 3, 4, 5, 6, 7, 8]));
    raw.extend(varint_field(8, 1_793_042_850_000));
    raw.extend(bytes_field(11, contract));
    raw.extend(varint_field(14, 1_793_042_790_000));
    raw
}

fn contract_of(kind: u64, url: &str, value: &[u8]) -> Vec<u8> {
    let mut any = bytes_field(1, url.as_bytes());
    any.extend(bytes_field(2, value));
    let mut out = varint_field(1, kind);
    out.extend(bytes_field(2, &any));
    out
}

#[test]
fn a_page_built_transaction_is_read_back_exactly() {
    let all = real_raw();
    assert_eq!(all.len(), 5);
    for (name, raw, expected) in all {
        let read = TronTransaction::from_raw_data(&raw).unwrap();
        assert_eq!(read, expected, "{name}");
        read.validate().unwrap();
        // The bytes are the same bytes, so the id and the signature are the node's.
        assert_eq!(read.raw_data(), raw, "{name}");
        assert_eq!(hexutil::encode(&read.txid()), name);
    }
}

#[test]
fn a_transaction_that_is_not_exactly_the_networks_writing_is_refused() {
    let (_, raw, _) = real_raw().remove(0);
    let malformed = |bytes: &[u8]| {
        assert!(
            matches!(TronTransaction::from_raw_data(bytes), Err(RawDataError::Malformed(_))),
            "{}",
            hexutil::encode(bytes)
        );
    };
    // Cut short, with something after it, and nothing.
    malformed(&raw[..raw.len() - 1]);
    malformed(&[&raw[..], &[0x00]].concat());
    malformed(&[&raw[..], &[0x70, 0x01]].concat());
    malformed(&[]);
    // The first field moved to the end: the same fields, not the same bytes.
    let moved = [&raw[4..], &raw[..4]].concat();
    malformed(&moved);
    // A number written longer than it needs to be (the timestamp's last byte, padded).
    let at = raw.len() - 1;
    let padded = [&raw[..at], &[raw[at] | 0x80, 0x00]].concat();
    malformed(&padded);
    // A field written twice.
    malformed(&[&raw[..], &raw[..4]].concat());
    // A fee limit of zero is no field: written out, it is not canonical.
    malformed(&[&raw[..], &[0x90, 0x01, 0x00]].concat());
    // A fixed-width field, which the network does not use here.
    malformed(&[&raw[..], &[0x75, 0, 0, 0, 0]].concat());
}

#[test]
fn the_kinds_of_transaction_that_take_an_account_away_are_named_and_refused() {
    let a = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    // An account permission update: the classic theft.
    let mut update = bytes_field(1, &a);
    update.extend(bytes_field(2, &[1, 2, 3]));
    let raw = raw_with_contract(&contract_of(
        46,
        "type.googleapis.com/protocol.AccountPermissionUpdateContract",
        &update,
    ));
    let error = TronTransaction::from_raw_data(&raw).unwrap_err();
    assert!(
        matches!(error, RawDataError::Unsupported(words) if words.contains("permission update")),
        "{error:?}"
    );
    // Staking, a vote, a TRC-10 transfer, a contract creation, anything unknown.
    for kind in [54, 57, 4, 2, 30, 99] {
        let raw = raw_with_contract(&contract_of(kind, "type.googleapis.com/protocol.Other", &[]));
        assert!(
            matches!(TronTransaction::from_raw_data(&raw), Err(RawDataError::Unsupported(_))),
            "{kind}"
        );
    }
    // Two contracts, a permission other than the owner's, authorities.
    let b = parse_address("TBUCzgc29vykkvFaEG2mgRtxKvaKe6skwX").unwrap();
    let mut transfer = bytes_field(1, &a);
    transfer.extend(bytes_field(2, &b));
    transfer.extend(varint_field(3, 1));
    let one = contract_of(1, "type.googleapis.com/protocol.TransferContract", &transfer);
    let single = raw_with_contract(&one);
    assert!(TronTransaction::from_raw_data(&single).is_ok());
    let mut twice = single.clone();
    twice.extend(bytes_field(11, &one));
    assert!(matches!(TronTransaction::from_raw_data(&twice), Err(RawDataError::Unsupported(_))));
    let mut permissioned = one.clone();
    permissioned.extend(varint_field(5, 2));
    assert!(matches!(
        TronTransaction::from_raw_data(&raw_with_contract(&permissioned)),
        Err(RawDataError::Unsupported(_))
    ));
    let mut authorities = single.clone();
    authorities.extend(bytes_field(9, &[1]));
    assert!(matches!(
        TronTransaction::from_raw_data(&authorities),
        Err(RawDataError::Unsupported(_))
    ));
    // A parameter whose type does not match its contract is not read.
    let confused = contract_of(1, "type.googleapis.com/protocol.TriggerSmartContract", &transfer);
    assert!(matches!(
        TronTransaction::from_raw_data(&raw_with_contract(&confused)),
        Err(RawDataError::Malformed(_))
    ));
    // TRC-10 tokens sent along with a call.
    let mut token_call = bytes_field(1, &a);
    token_call.extend(bytes_field(2, &b));
    token_call.extend(varint_field(5, 1));
    let call = contract_of(31, "type.googleapis.com/protocol.TriggerSmartContract", &token_call);
    assert!(matches!(
        TronTransaction::from_raw_data(&raw_with_contract(&call)),
        Err(RawDataError::Unsupported(_))
    ));
}

#[test]
fn a_page_transaction_the_network_would_refuse_reads_but_does_not_validate() {
    let a = parse_address("TFnYQCt892UNjn67pjAULTSTkB7YvqsnPp").unwrap();
    // A transfer to oneself reads (the bytes are canonical) and is then refused as the network refuses it.
    let mut transfer = bytes_field(1, &a);
    transfer.extend(bytes_field(2, &a));
    transfer.extend(varint_field(3, 5));
    let raw = raw_with_contract(&contract_of(
        1,
        "type.googleapis.com/protocol.TransferContract",
        &transfer,
    ));
    let read = TronTransaction::from_raw_data(&raw).unwrap();
    assert!(read.validate().is_err());
    // A contract call with no fee limit also reads, and does not validate (a wallet sets one).
    let token = parse_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();
    let mut call = bytes_field(1, &a);
    call.extend(bytes_field(2, &token));
    call.extend(bytes_field(4, &[0xde, 0xad]));
    let raw = raw_with_contract(&contract_of(
        31,
        "type.googleapis.com/protocol.TriggerSmartContract",
        &call,
    ));
    let read = TronTransaction::from_raw_data(&raw).unwrap();
    assert_eq!(read.fee_limit, None);
    assert!(read.validate().is_err());
}
