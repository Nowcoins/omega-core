//! Permit2 typed data is read as the spending permission it is.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use serde_json::{Value, json};

use super::{PERMIT2, TypedData, TypedDataKind, U256, known_contract_name};

const TOKEN: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const SPENDER: &str = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD";
const PERMIT2_HEX: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

fn domain() -> Value {
    json!({ "name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2_HEX })
}

fn domain_type() -> Value {
    json!([
        { "name": "name", "type": "string" },
        { "name": "chainId", "type": "uint256" },
        { "name": "verifyingContract", "type": "address" },
    ])
}

fn details_type() -> Value {
    json!([
        { "name": "token", "type": "address" },
        { "name": "amount", "type": "uint160" },
        { "name": "expiration", "type": "uint48" },
        { "name": "nonce", "type": "uint48" },
    ])
}

fn permissions_type() -> Value {
    json!([{ "name": "token", "type": "address" }, { "name": "amount", "type": "uint256" }])
}

fn kind(document: &Value) -> TypedDataKind {
    TypedData::from_value(document).unwrap().summary().unwrap().kind
}

const UINT160_MAX: &str = "1461501637330902918203684832716283019655932542975";

fn single(amount: &str, expiration: &str) -> Value {
    json!({
        "types": {
            "EIP712Domain": domain_type(),
            "PermitSingle": [
                { "name": "details", "type": "PermitDetails" },
                { "name": "spender", "type": "address" },
                { "name": "sigDeadline", "type": "uint256" },
            ],
            "PermitDetails": details_type(),
        },
        "primaryType": "PermitSingle",
        "domain": domain(),
        "message": {
            "details": { "token": TOKEN, "amount": amount, "expiration": expiration, "nonce": "0" },
            "spender": SPENDER,
            "sigDeadline": "1893456000",
        },
    })
}

#[test]
fn a_permit_single_is_a_spending_permission() {
    let TypedDataKind::Permit2Allowance { details, spender, batch, sig_deadline } =
        kind(&single("1000000", "1893456000"))
    else {
        panic!("not read as Permit2");
    };
    assert!(!batch);
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].amount, U256::from_u128(1_000_000));
    assert!(!details[0].unlimited && !details[0].never_expires);
    assert_eq!(spender.to_vec(), hex::decode(&SPENDER[2..]).unwrap());
    assert_eq!(sig_deadline, U256::from_u128(1_893_456_000));
}

#[test]
fn the_uint160_maximum_and_an_endless_expiry_are_flagged() {
    let TypedDataKind::Permit2Allowance { details, .. } =
        kind(&single(UINT160_MAX, "281474976710655"))
    else {
        panic!("not read as Permit2");
    };
    assert!(details[0].unlimited, "uint160 max is unlimited");
    assert!(details[0].never_expires, "uint48 max never expires");
}

#[test]
fn a_permit_batch_lists_every_token() {
    let document = json!({
        "types": {
            "EIP712Domain": domain_type(),
            "PermitBatch": [
                { "name": "details", "type": "PermitDetails[]" },
                { "name": "spender", "type": "address" },
                { "name": "sigDeadline", "type": "uint256" },
            ],
            "PermitDetails": details_type(),
        },
        "primaryType": "PermitBatch",
        "domain": domain(),
        "message": {
            "details": [
                { "token": TOKEN, "amount": "5", "expiration": "1893456000", "nonce": "0" },
                { "token": SPENDER, "amount": UINT160_MAX, "expiration": "1893456000", "nonce": "1" },
            ],
            "spender": SPENDER,
            "sigDeadline": "1893456000",
        },
    });
    let TypedDataKind::Permit2Allowance { details, batch, .. } = kind(&document) else {
        panic!("not read as Permit2");
    };
    assert!(batch);
    assert_eq!(details.iter().map(|d| d.unlimited).collect::<Vec<_>>(), [false, true]);
}

fn transfer(primary: &str, batch: bool, witness: bool) -> Value {
    let mut members = vec![
        json!({ "name": "permitted", "type": if batch { "TokenPermissions[]" } else { "TokenPermissions" } }),
        json!({ "name": "spender", "type": "address" }),
        json!({ "name": "nonce", "type": "uint256" }),
        json!({ "name": "deadline", "type": "uint256" }),
    ];
    let mut types =
        json!({ "EIP712Domain": domain_type(), "TokenPermissions": permissions_type() });
    let one = json!({ "token": TOKEN, "amount": "250" });
    let mut message = json!({
        "permitted": if batch { json!([one]) } else { one },
        "spender": SPENDER, "nonce": "7", "deadline": "1893456000",
    });
    if witness {
        members.push(json!({ "name": "witness", "type": "Order" }));
        types["Order"] = json!([{ "name": "id", "type": "uint256" }]);
        message["witness"] = json!({ "id": "9" });
    }
    types[primary] = Value::Array(members);
    json!({ "types": types, "primaryType": primary, "domain": domain(), "message": message })
}

#[test]
fn the_transfer_variants_are_one_time_permissions() {
    for (primary, batch, witness) in [
        ("PermitTransferFrom", false, false),
        ("PermitBatchTransferFrom", true, false),
        ("PermitWitnessTransferFrom", false, true),
        ("PermitBatchWitnessTransferFrom", true, true),
    ] {
        let TypedDataKind::Permit2Transfer {
            permitted, nonce, witness_type, batch: is_batch, ..
        } = kind(&transfer(primary, batch, witness))
        else {
            panic!("{primary} not read as Permit2");
        };
        assert_eq!((is_batch, witness_type.is_some()), (batch, witness), "{primary}");
        assert_eq!(permitted.len(), 1);
        assert_eq!(permitted[0].amount, U256::from_u128(250));
        assert_eq!(nonce, U256::from_u128(7));
    }
}

#[test]
fn look_alikes_are_not_permit2() {
    // A wrong member type, or the right name with other members: unrecognised, not guessed at.
    let mut wrong = single("1", "1");
    wrong["types"]["PermitDetails"][1]["type"] = json!("uint256");
    assert_eq!(kind(&wrong), TypedDataKind::Other);
    let mut extra = transfer("PermitTransferFrom", false, false);
    extra["types"]["PermitTransferFrom"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "to", "type": "address" }));
    extra["message"]["to"] = json!(SPENDER);
    assert_eq!(kind(&extra), TypedDataKind::Other);
}

#[test]
fn only_the_canonical_address_is_named_permit2() {
    assert_eq!(known_contract_name(&PERMIT2), Some("Permit2"));
    assert_eq!(known_contract_name(&[1; 20]), None);
    assert_eq!(hex::encode(PERMIT2), PERMIT2_HEX[2..].to_lowercase());
}
