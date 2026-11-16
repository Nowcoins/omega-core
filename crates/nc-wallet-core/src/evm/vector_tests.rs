//! EVM encoding, signing and decoding against vectors from outside this
//! crate. Every constant says where it comes from (the files in
//! `tests/vectors` carry their source and commit); none was produced by
//! running this code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::Value;

use super::abi;
use super::decode::{Call, classify_call};
use super::message::{personal_message_hash, sign_personal_message};
use super::rlp;
use super::tx::{EvmChain, EvmTransaction, Fees, keccak};
use super::typed_data::{TypedData, TypedDataKind};
use super::u256::U256;
use crate::ecdsa::RecoverableSignature;
use crate::hexutil;
use crate::key::SigningKey;

const RLP_TESTS: &str = include_str!("../../tests/vectors/rlp-ethereum-tests-rlptest.json");
const EIP155: &str = include_str!("../../tests/vectors/eip-155-replay-protection.md");
const EIP712_TEXT: &str = include_str!("../../tests/vectors/eip-712-typed-structured-data.md");
const EIP712_EXAMPLE_JS: &str = include_str!("../../tests/vectors/eip-712-example.js");
const ERC2612: &str = include_str!("../../tests/vectors/erc-2612-permit.md");
const TW_SIGNER: &str = include_str!("../../tests/vectors/trustwallet-evm-signer.json");
const TW_MESSAGES: &str = include_str!("../../tests/vectors/trustwallet-evm-messages.json");
const REAL: &str = include_str!("../../tests/vectors/real-evm-transactions.json");
const PERSONAL: &str = include_str!("../../tests/vectors/eth-sig-util-personal-sign.json");
const TYPED_V4: &str = include_str!("../../tests/vectors/eth-sig-util-sign-typed-data-v4.json");

fn key(hex: &str) -> SigningKey {
    let bytes: [u8; 32] =
        hexutil::decode(hex.trim_start_matches("0x")).unwrap().try_into().unwrap();
    SigningKey::secp256k1(&bytes).unwrap()
}

fn h(text: &str) -> Vec<u8> {
    hexutil::decode(text.trim_start_matches("0x")).unwrap()
}

fn address(text: &str) -> [u8; 20] {
    h(text).try_into().unwrap()
}

fn word(text: &str) -> [u8; 32] {
    // A quantity as the nodes write it (no leading zeros) or a full word.
    let bytes = h(&if text.trim_start_matches("0x").len() % 2 == 1 {
        format!("0{}", text.trim_start_matches("0x"))
    } else {
        text.to_owned()
    });
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn quantity(text: &str) -> u128 {
    u128::from_str_radix(text.trim_start_matches("0x"), 16).unwrap()
}

/// The EVM address the signature recovers to over `digest`.
fn recover_address(digest: &[u8; 32], signature: &RecoverableSignature) -> [u8; 20] {
    let sig = Signature::from_scalars(signature.r, signature.s).unwrap();
    let id = RecoveryId::from_byte(signature.recovery_id).unwrap();
    let key = VerifyingKey::recover_from_prehash(digest, &sig, id).unwrap();
    let point = key.to_sec1_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    hash[12..].try_into().unwrap()
}

fn address_of(key: &SigningKey) -> [u8; 20] {
    super::address_from_public_key(key.public_key()).map(|a| address(&a)).unwrap()
}

// ---- RLP --------------------------------------------------------------------

/// `RLPTests/rlptest.json` of `ethereum/tests` @ c67e485ff8b5be9abc8ad15345ec21aa22e290d9: each
/// entry has an input (a string, an integer, a `#`-prefixed big integer or a
/// nested list) and the expected encoding.
fn rlp_of(value: &Value) -> Vec<u8> {
    match value {
        Value::String(s) => match s.strip_prefix('#') {
            // A big integer: its minimal big-endian bytes (it may be wider
            // than 256 bits, as the file's `bigint` is).
            Some(digits) => {
                let mut be: Vec<u8> = Vec::new();
                for digit in digits.bytes() {
                    let mut carry = u32::from(digit - b'0');
                    for byte in be.iter_mut().rev() {
                        let value = u32::from(*byte) * 10 + carry;
                        *byte = (value & 0xff) as u8;
                        carry = value >> 8;
                    }
                    while carry > 0 {
                        be.insert(0, (carry & 0xff) as u8);
                        carry >>= 8;
                    }
                }
                rlp::bytes(&be)
            }
            None => rlp::bytes(s.as_bytes()),
        },
        Value::Number(n) => rlp::uint(u128::from(n.as_u64().unwrap())),
        Value::Array(items) => rlp::list(&items.iter().map(rlp_of).collect::<Vec<_>>()),
        other => panic!("unexpected RLP test input {other:?}"),
    }
}

#[test]
fn rlp_matches_the_ethereum_tests() {
    let cases: Value = serde_json::from_str(RLP_TESTS).unwrap();
    let cases = cases.as_object().unwrap();
    assert_eq!(cases.len(), 28, "the file has 28 cases at the pinned commit");
    for (name, case) in cases {
        let out = case["out"].as_str().unwrap();
        assert_eq!(hexutil::encode_prefixed(&rlp_of(&case["in"])), out, "{name}");
    }
}

// ---- EIP-155 ----------------------------------------------------------------

/// The code-block line after the line that starts with `marker`.
fn line_after<'a>(text: &'a str, marker: &str) -> &'a str {
    let mut lines = text.lines();
    lines.find(|l| l.starts_with(marker)).unwrap_or_else(|| panic!("no line {marker}"));
    lines.find(|l| l.starts_with("0x") || l.starts_with('(')).unwrap()
}

#[test]
fn the_eip155_worked_example_is_reproduced_exactly() {
    let signing_data = line_after(EIP155, "The \"signing data\" becomes");
    let signing_hash = line_after(EIP155, "The \"signing hash\" becomes");
    let vrs = line_after(EIP155, "If the transaction is signed with the private key");
    let signed = line_after(EIP155, "Notice the use of 37");
    let key_hex =
        EIP155.split("private key `").nth(1).and_then(|rest| rest.split('`').next()).unwrap();

    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 9,
        to: address("0x3535353535353535353535353535353535353535"),
        value: 1_000_000_000_000_000_000,
        data: Vec::new(),
        gas_limit: 21_000,
        fees: Fees::Legacy { gas_price: 20 * 10u128.pow(9) },
    };
    assert_eq!(hexutil::encode_prefixed(&tx.signing_payload()), signing_data);
    assert_eq!(hexutil::encode_prefixed(&tx.signing_hash()), signing_hash);

    let signed_tx = tx.sign(&key(key_hex)).unwrap();
    assert_eq!(signed_tx.raw_hex(), signed);
    assert_eq!(signed_tx.hash, keccak(&h(signed)));

    // `(37, r, s)` in decimal.
    let numbers: Vec<&str> = vrs.trim_matches(|c| c == '(' || c == ')').split(", ").collect();
    assert_eq!(numbers[0], "37");
    assert_eq!(U256::from_be_bytes(signed_tx.signature.r).to_string(), numbers[1], "r");
    assert_eq!(U256::from_be_bytes(signed_tx.signature.s).to_string(), numbers[2], "s");
}

// ---- Trust Wallet Core's signer vectors -------------------------------------

fn tw_transaction(case: &Value) -> EvmTransaction {
    let data = match case.get("token_call") {
        None => Vec::new(),
        Some(call) => {
            let to = address(call["to"].as_str().unwrap());
            let amount = U256::from_decimal_str(call["amount"].as_str().unwrap()).unwrap();
            match call["kind"].as_str().unwrap() {
                "transfer" => abi::erc20_transfer(&to, &amount),
                "approve" => abi::erc20_approve(&to, &amount),
                other => panic!("{other}"),
            }
        }
    };
    let u = |name: &str| u128::from(case[name].as_u64().unwrap());
    let fees = if case.get("gas_price").is_some() {
        Fees::Legacy { gas_price: u("gas_price") }
    } else {
        Fees::Eip1559 {
            max_fee_per_gas: u("max_fee_per_gas"),
            max_priority_fee_per_gas: u("max_priority_fee_per_gas"),
        }
    };
    EvmTransaction {
        chain_id: case["chain_id"].as_u64().unwrap(),
        nonce: case["nonce"].as_u64().unwrap(),
        to: address(case["to"].as_str().unwrap()),
        value: case["value"].as_u64().map_or(0, u128::from),
        data,
        gas_limit: case["gas_limit"].as_u64().unwrap(),
        fees,
    }
}

#[test]
fn trust_wallet_core_signed_transactions_are_reproduced_exactly() {
    let cases: Value = serde_json::from_str(TW_SIGNER).unwrap();
    let cases = cases["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let tx = tw_transaction(case);
        assert_eq!(
            hexutil::encode(&tx.signing_hash()),
            case["expected_signing_hash"].as_str().unwrap(),
            "{label}: signing hash"
        );
        let signed = tx.sign(&key(case["private_key"].as_str().unwrap())).unwrap();
        assert_eq!(hexutil::encode(&signed.raw), case["expected_raw"].as_str().unwrap(), "{label}");
        // The transaction recovers to the key that signed it.
        assert_eq!(
            recover_address(&tx.signing_hash(), &signed.signature),
            address_of(&key(case["private_key"].as_str().unwrap())),
            "{label}: signer"
        );
    }
}

// ---- Real transactions of the four chains ------------------------------------

#[test]
fn real_transactions_of_all_four_chains_re_encode_and_recover_their_senders() {
    let file: Value = serde_json::from_str(REAL).unwrap();
    let txs = file["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 24, "six per chain");
    let (mut legacy, mut typed) = (0, 0);
    let mut chains = std::collections::BTreeSet::new();
    for t in txs {
        let name = t["hash"].as_str().unwrap();
        let chain_id = t["chainId"].as_u64().unwrap();
        chains.insert(chain_id);
        assert!(EvmChain::from_chain_id(chain_id).is_some());
        let r = word(t["r"].as_str().unwrap());
        let s = word(t["s"].as_str().unwrap());
        let (fees, parity) = if t["type"].as_u64().unwrap() == 2 {
            typed += 1;
            (
                Fees::Eip1559 {
                    max_fee_per_gas: quantity(t["maxFeePerGas"].as_str().unwrap()),
                    max_priority_fee_per_gas: quantity(t["maxPriorityFeePerGas"].as_str().unwrap()),
                },
                u8::try_from(quantity(t["v"].as_str().unwrap())).unwrap(),
            )
        } else {
            legacy += 1;
            let v = quantity(t["v"].as_str().unwrap());
            // EIP-155: v = parity + 2 * chain id + 35.
            let parity = v - 35 - 2 * u128::from(chain_id);
            (
                Fees::Legacy { gas_price: quantity(t["gasPrice"].as_str().unwrap()) },
                u8::try_from(parity).unwrap(),
            )
        };
        assert!(parity <= 1, "{name}");
        let tx = EvmTransaction {
            chain_id,
            nonce: u64::try_from(quantity(t["nonce"].as_str().unwrap())).unwrap(),
            to: address(t["to"].as_str().unwrap()),
            value: quantity(t["value"].as_str().unwrap()),
            data: h(t["input"].as_str().unwrap()),
            gas_limit: u64::try_from(quantity(t["gas"].as_str().unwrap())).unwrap(),
            fees,
        };
        let signature = RecoverableSignature { r, s, recovery_id: parity };
        // The node's hash covers every byte of the signed transaction.
        let (_, hash) = tx.encode_signed(&signature);
        assert_eq!(hexutil::encode_prefixed(&hash), name, "{name}: hash");
        // The signing hash is what the sender signed.
        assert_eq!(
            hexutil::encode_prefixed(&recover_address(&tx.signing_hash(), &signature)),
            t["from"].as_str().unwrap().to_lowercase(),
            "{name}: sender"
        );
        // The call data reads as what it is.
        let call = tx.describe();
        let input = t["input"].as_str().unwrap();
        match (&call, input) {
            (Call::NativeTransfer { .. }, "0x") => {}
            (Call::Erc20Transfer { amount, to, token }, i) if i.starts_with("0xa9059cbb") => {
                assert_eq!(*token, tx.to);
                assert_eq!(&hexutil::encode_prefixed(to), &format!("0x{}", &i[34..74]));
                assert_eq!(&hexutil::encode(&amount.to_be_bytes()), &i[74..]);
            }
            (Call::Erc20Approve { amount, spender, unlimited, .. }, i)
                if i.starts_with("0x095ea7b3") =>
            {
                assert_eq!(&hexutil::encode_prefixed(spender), &format!("0x{}", &i[34..74]));
                assert_eq!(&hexutil::encode(&amount.to_be_bytes()), &i[74..]);
                assert_eq!(*unlimited, amount.is_unlimited());
            }
            (call, i) => panic!("{name}: {call:?} for {i}"),
        }
    }
    assert_eq!(chains.len(), 4);
    assert_eq!((legacy, typed), (12, 12));
}

// ---- ABI and call classification ---------------------------------------------

#[test]
fn selectors_are_the_keccak_of_the_signatures() {
    // 4byte.directory lists these: 0xa9059cbb transfer(address,uint256),
    // 0x095ea7b3 approve(address,uint256), 0x23b872dd
    // transferFrom(address,address,uint256), 0xa22cb465
    // setApprovalForAll(address,bool).
    assert_eq!(abi::selector("transfer(address,uint256)"), abi::TRANSFER);
    assert_eq!(abi::selector("approve(address,uint256)"), abi::APPROVE);
    assert_eq!(abi::selector("transferFrom(address,address,uint256)"), abi::TRANSFER_FROM);
    assert_eq!(abi::selector("setApprovalForAll(address,bool)"), abi::SET_APPROVAL_FOR_ALL);
    assert_eq!(hexutil::encode(&abi::TRANSFER), "a9059cbb");
    assert_eq!(hexutil::encode(&abi::APPROVE), "095ea7b3");
    assert_eq!(hexutil::encode(&abi::TRANSFER_FROM), "23b872dd");
    assert_eq!(hexutil::encode(&abi::SET_APPROVAL_FOR_ALL), "a22cb465");
}

fn call_data(selector: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
    let mut data = selector.to_vec();
    for w in words {
        data.extend_from_slice(w);
    }
    data
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    abi::pad_address(a)
}

const TOKEN: &str = "0x6b175474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "0x5322b34c88ed0691971bf52a7047448f0f4efc84";
const BOB: &str = "0x718046867b5b1782379a14ea4fc0c9b724da94fc";

#[test]
fn calls_are_classified() {
    let (token, alice, bob) = (address(TOKEN), address(ALICE), address(BOB));
    let amount = U256::from_u128(2_000_000_000_000_000_000);

    // A plain transfer.
    assert_eq!(classify_call(&alice, 5, &[]), Call::NativeTransfer { to: alice, value: 5 });
    // Trust Wallet Core's ERC-20 transfer call data.
    let data = h(
        "a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000",
    );
    assert_eq!(data, abi::erc20_transfer(&alice, &amount));
    assert_eq!(classify_call(&token, 0, &data), Call::Erc20Transfer { token, to: alice, amount });
    // ... and approve.
    let data = h(
        "095ea7b30000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000",
    );
    assert_eq!(data, abi::erc20_approve(&alice, &amount));
    assert_eq!(
        classify_call(&token, 0, &data),
        Call::Erc20Approve { token, spender: alice, amount, unlimited: false }
    );
    // An unlimited approve: everything from the 128-bit maximum up (2^256 - 1, 2^255,
    // the 160-bit maximum Permit2 uses), and 2^255 - 1 with them; a trillion
    // 18-decimal tokens is a number, not "everything".
    for (amount, unlimited) in [
        (U256::MAX, true),
        (U256::TWO_POW_255, true),
        (
            U256::from_decimal_str(
                "57896044618658097711785492504343953926634992332820282019728792003956564819967",
            )
            .unwrap(),
            true,
        ),
        (U256::from_u128(10_u128.pow(30)), false),
    ] {
        let data = abi::erc20_approve(&alice, &amount);
        assert_eq!(
            classify_call(&token, 0, &data),
            Call::Erc20Approve { token, spender: alice, amount, unlimited }
        );
    }
    // transferFrom (the ERC-721 call data of Trust Wallet Core's vector, whose
    // third argument is a token id read here as an amount).
    let data = h(
        "23b872dd000000000000000000000000718046867b5b1782379a14ea4fc0c9b724da94fc0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000000000023c47ee5",
    );
    assert_eq!(
        classify_call(&token, 0, &data),
        Call::Erc20TransferFrom {
            token,
            from: bob,
            to: alice,
            amount: U256::from_u128(0x23c4_7ee5)
        }
    );
    // setApprovalForAll, granted and revoked.
    for approved in [true, false] {
        let mut flag = [0u8; 32];
        flag[31] = u8::from(approved);
        let data = call_data(abi::SET_APPROVAL_FOR_ALL, &[addr_word(&bob), flag]);
        assert_eq!(
            classify_call(&token, 0, &data),
            Call::SetApprovalForAll { contract: token, operator: bob, approved }
        );
    }
}

#[test]
fn anything_not_canonical_is_an_unknown_call() {
    let (token, alice) = (address(TOKEN), address(ALICE));
    let good = abi::erc20_transfer(&alice, &U256::from_u128(1));
    let unknown = |value: u128, data: &[u8]| Call::UnknownContractCall {
        to: token,
        value,
        selector: data.first_chunk::<4>().copied(),
        data_len: data.len(),
    };
    // Native coin sent along with a token call.
    assert_eq!(classify_call(&token, 1, &good), unknown(1, &good));
    // A byte too many, a byte too few.
    let mut long = good.clone();
    long.push(0);
    assert_eq!(classify_call(&token, 0, &long), unknown(0, &long));
    assert_eq!(classify_call(&token, 0, &good[..67]), unknown(0, &good[..67]));
    // Garbage above the 20 bytes of an address word.
    let mut dirty = good.clone();
    dirty[4] = 1;
    assert_eq!(classify_call(&token, 0, &dirty), unknown(0, &dirty));
    // A boolean that is neither 0 nor 1.
    let mut flag = [0u8; 32];
    flag[31] = 2;
    let data = call_data(abi::SET_APPROVAL_FOR_ALL, &[addr_word(&alice), flag]);
    assert_eq!(classify_call(&token, 0, &data), unknown(0, &data));
    flag[31] = 0;
    flag[0] = 1;
    let data = call_data(abi::SET_APPROVAL_FOR_ALL, &[addr_word(&alice), flag]);
    assert_eq!(classify_call(&token, 0, &data), unknown(0, &data));
    // Another function, a selector alone, and fewer than four bytes.
    let other = call_data([0xde, 0xad, 0xbe, 0xef], &[addr_word(&alice)]);
    assert_eq!(classify_call(&token, 0, &other), unknown(0, &other));
    assert_eq!(classify_call(&token, 0, &abi::TRANSFER), unknown(0, &abi::TRANSFER));
    assert_eq!(
        classify_call(&token, 7, &[1, 2]),
        Call::UnknownContractCall { to: token, value: 7, selector: None, data_len: 2 }
    );
}

#[test]
fn a_transaction_describes_itself() {
    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 0,
        to: address(TOKEN),
        value: 0,
        data: abi::erc20_approve(&address(ALICE), &U256::MAX),
        gas_limit: 60_000,
        fees: Fees::Legacy { gas_price: 1 },
    };
    assert!(matches!(tx.describe(), Call::Erc20Approve { unlimited: true, .. }));
}

// ---- validation ---------------------------------------------------------------

#[test]
fn a_transaction_no_node_would_take_is_refused_before_signing() {
    let base = EvmTransaction {
        chain_id: 1,
        nonce: 0,
        to: [1; 20],
        value: 1,
        data: Vec::new(),
        gas_limit: 21_000,
        fees: Fees::Eip1559 { max_fee_per_gas: 10, max_priority_fee_per_gas: 2 },
    };
    let signer = key("0x4646464646464646464646464646464646464646464646464646464646464646");
    assert!(base.sign(&signer).is_ok());
    for bad in [
        EvmTransaction { chain_id: 0, ..base.clone() },
        EvmTransaction { gas_limit: 0, ..base.clone() },
        EvmTransaction {
            fees: Fees::Eip1559 { max_fee_per_gas: 1, max_priority_fee_per_gas: 2 },
            ..base.clone()
        },
    ] {
        assert!(bad.sign(&signer).is_err());
    }
    assert_eq!(base.max_cost(), Some(21_000 * 10 + 1));
    assert_eq!(
        EvmTransaction { fees: Fees::Legacy { gas_price: u128::MAX }, ..base.clone() }.max_cost(),
        None
    );
}

#[test]
fn a_key_of_another_curve_cannot_sign() {
    let ed = SigningKey::ed25519(&[7u8; 32]);
    let tx = EvmTransaction {
        chain_id: 1,
        nonce: 0,
        to: [1; 20],
        value: 1,
        data: Vec::new(),
        gas_limit: 21_000,
        fees: Fees::Legacy { gas_price: 1 },
    };
    assert_eq!(tx.sign(&ed).unwrap_err(), crate::TxError::WrongKeyScheme);
    assert!(sign_personal_message(&ed, b"x").is_err());
}

#[test]
fn signing_is_deterministic_and_low_s() {
    let signer = key("0x4646464646464646464646464646464646464646464646464646464646464646");
    let tx = EvmTransaction {
        chain_id: 8453,
        nonce: 3,
        to: [2; 20],
        value: 10,
        data: vec![1, 2, 3],
        gas_limit: 50_000,
        fees: Fees::Eip1559 { max_fee_per_gas: 100, max_priority_fee_per_gas: 1 },
    };
    let a = tx.sign(&signer).unwrap();
    let b = tx.sign(&signer).unwrap();
    assert_eq!(a, b);
    // s is at most half the order.
    let half = h("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    assert!(a.signature.s.as_slice() <= half.as_slice());
}

// ---- personal_sign -------------------------------------------------------------

#[test]
fn personal_sign_matches_eth_sig_util_and_geth() {
    let file: Value = serde_json::from_str(PERSONAL).unwrap();
    for case in file["cases"].as_array().unwrap() {
        let message = match case.get("message_utf8") {
            Some(text) => text.as_str().unwrap().as_bytes().to_vec(),
            None => h(case["message_hex"].as_str().unwrap()),
        };
        let signer = key(case["key"].as_str().unwrap());
        let signature = sign_personal_message(&signer, &message).unwrap();
        assert_eq!(
            hexutil::encode_prefixed(&signature.to_rsv(27)),
            case["signature"].as_str().unwrap(),
            "{}",
            case["label"]
        );
        if let Some(expected) = case.get("address") {
            assert_eq!(hexutil::encode_prefixed(&address_of(&signer)), expected.as_str().unwrap());
        }
        assert_eq!(
            recover_address(&personal_message_hash(&message), &signature),
            address_of(&signer)
        );
    }
}

#[test]
fn personal_sign_matches_trust_wallet_core() {
    let file: Value = serde_json::from_str(TW_MESSAGES).unwrap();
    let legacy = file["legacy"].as_array().unwrap();
    assert_eq!(legacy.len(), 2);
    for case in legacy {
        let text = case["message"].as_str().unwrap();
        // Trust Wallet Core reads a message of 0x and hex as bytes.
        let message = if text.starts_with("0x") { h(text) } else { text.as_bytes().to_vec() };
        let signature =
            sign_personal_message(&key(case["private_key"].as_str().unwrap()), &message).unwrap();
        assert_eq!(hexutil::encode(&signature.to_rsv(27)), case["signature"].as_str().unwrap());
    }
}

#[test]
fn the_personal_message_prefix_counts_bytes_in_decimal() {
    // keccak256("\x19Ethereum Signed Message:\n" + len + message), spelt out.
    let mut preimage = b"\x19Ethereum Signed Message:\n11hello world".to_vec();
    assert_eq!(personal_message_hash(b"hello world"), keccak(&preimage));
    // Eleven bytes of two characters each: the length is of bytes, not letters.
    preimage = "\u{e9}\u{e9}\u{e9}".as_bytes().to_vec();
    let mut expected = b"\x19Ethereum Signed Message:\n6".to_vec();
    expected.extend_from_slice(&preimage);
    assert_eq!(personal_message_hash(&preimage), keccak(&expected));
    // The empty message and a message of ten bytes use "0" and "10".
    assert_eq!(personal_message_hash(b""), keccak(b"\x19Ethereum Signed Message:\n0"));
    assert_eq!(
        personal_message_hash(&[0u8; 10]),
        keccak(&[b"\x19Ethereum Signed Message:\n10".as_slice(), &[0u8; 10]].concat())
    );
}

// ---- EIP-712 ---------------------------------------------------------------------

/// The value an `expect(...).to.equal('0x…')` line of the EIP's `Example.js`
/// states for the expression that starts with `expression`.
fn example_js(expression: &str) -> String {
    let at = EIP712_EXAMPLE_JS.find(expression).unwrap_or_else(|| panic!("{expression}"));
    let rest = &EIP712_EXAMPLE_JS[at..];
    let equal = rest.find("to.equal(").unwrap();
    let rest = &rest[equal + "to.equal(".len()..];
    rest.trim_start().trim_start_matches('\'').split('\'').next().unwrap().to_owned()
}

/// The `curl` request of the EIP's `eth_signTypedData` example: its typed
/// data, and the result it states.
fn eip712_text_example() -> (String, String, String) {
    let request = EIP712_TEXT.lines().find(|l| l.starts_with("curl -X POST")).unwrap();
    let body: Value = {
        let start = request.find("--data '").unwrap() + "--data '".len();
        let end = request.rfind('\'').unwrap();
        serde_json::from_str(&request[start..end]).unwrap()
    };
    let params = body["params"].as_array().unwrap();
    let result =
        EIP712_TEXT.lines().find(|l| l.trim_start().starts_with("\"result\": \"0x4355")).unwrap();
    let signature = result.split('"').nth(3).unwrap().to_owned();
    (params[0].as_str().unwrap().to_owned(), params[1].to_string(), signature)
}

#[test]
fn the_eip712_example_is_reproduced_exactly() {
    let (signer_address, typed_json, signature) = eip712_text_example();
    let data = TypedData::parse(&typed_json).unwrap();
    // encodeType, typeHash, hashStruct of the message and of the domain, and
    // the digest: the values of the EIP's own Example.js.
    assert_eq!(
        data.encode_type("Mail").unwrap(),
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    );
    assert_eq!(data.encode_type("Mail").unwrap(), example_js("expect(encodeType('Mail'))"));
    assert_eq!(
        hexutil::encode_prefixed(&keccak(data.encode_type("Mail").unwrap().as_bytes())),
        example_js("expect(ethUtil.bufferToHex(typeHash('Mail')))")
    );
    assert_eq!(
        hexutil::encode_prefixed(&data.message_hash().unwrap()),
        example_js(
            "expect(ethUtil.bufferToHex(structHash(typedData.primaryType, typedData.message)))"
        )
    );
    assert_eq!(
        hexutil::encode_prefixed(&data.domain_separator().unwrap()),
        example_js("expect(ethUtil.bufferToHex(structHash('EIP712Domain', typedData.domain)))")
    );
    assert_eq!(
        hexutil::encode_prefixed(&data.signing_hash().unwrap()),
        example_js("expect(ethUtil.bufferToHex(signHash()))")
    );
    // The key of the example is keccak256("cow"); its address, v, r and s.
    let cow = key(&hexutil::encode(&keccak(b"cow")));
    assert_eq!(
        hexutil::encode_prefixed(&address_of(&cow)),
        example_js("expect(ethUtil.bufferToHex(address))")
    );
    assert_eq!(hexutil::encode_prefixed(&address_of(&cow)), signer_address.to_lowercase());
    let sig = data.sign(&cow).unwrap();
    assert_eq!(hexutil::encode_prefixed(&sig.to_rsv(27)), signature);
    assert_eq!(hexutil::encode_prefixed(&sig.r), example_js("expect(ethUtil.bufferToHex(sig.r))"));
    assert_eq!(hexutil::encode_prefixed(&sig.s), example_js("expect(ethUtil.bufferToHex(sig.s))"));
    assert_eq!(sig.recovery_id + 27, 28);
}

fn typed_hash_matches(file: &Value, name: &str) {
    let case = file["typed"].as_array().unwrap().iter().find(|c| c["data_file"] == name).unwrap();
    let data = TypedData::from_value(&case["typed_data"]).unwrap();
    assert_eq!(
        hexutil::encode(&data.signing_hash().unwrap()),
        case["signing_hash"].as_str().unwrap(),
        "{name}"
    );
}

#[test]
fn trust_wallet_core_typed_data_hashes_match() {
    let file: Value = serde_json::from_str(TW_MESSAGES).unwrap();
    // The Mail example again, then a struct with nested arrays, then a custom
    // array.
    typed_hash_matches(&file, "eip712_case_1");
    typed_hash_matches(&file, "eip712_case_2");
    typed_hash_matches(&file, "eip712_with_custom_array");
}

#[test]
fn trust_wallet_core_typed_data_signatures_match() {
    let file: Value = serde_json::from_str(TW_MESSAGES).unwrap();
    let mut checked = 0;
    for case in file["typed"].as_array().unwrap() {
        let Some(expected) = case.get("signature") else { continue };
        let expected = h(expected.as_str().unwrap());
        let data = TypedData::from_value(&case["typed_data"]).unwrap();
        let signature = data.sign(&key(case["private_key"].as_str().unwrap())).unwrap();
        let name = case["data_file"].as_str().unwrap();
        if name == "eip712_with_chain_id_string" {
            // Signed in Trust Wallet Core's EIP-155 style: v carries the chain
            // id there. r and s are the same.
            assert_eq!(&signature.to_rsv(27)[..64], &expected[..64], "{name}");
        } else {
            assert_eq!(signature.to_rsv(27).to_vec(), expected, "{name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 5);
}

#[test]
fn what_trust_wallet_core_accepts_and_this_wallet_does_not() {
    let file: Value = serde_json::from_str(TW_MESSAGES).unwrap();
    let refused = file["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 2);
    for case in refused {
        let name = case["data_file"].as_str().unwrap();
        let error = TypedData::from_value(&case["typed_data"])
            .and_then(|d| d.signing_hash())
            .unwrap_err()
            .to_string();
        let expected = match name {
            // A fixed array of two holding one.
            "eip712_unequal_array_lengths" => "an array of 2 was expected",
            // An address written without its 0x.
            "eip712_case_3" => "not 0x and 40 hex digits",
            other => panic!("{other}"),
        };
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn eth_sig_util_typed_data_signatures_match() {
    let file: Value = serde_json::from_str(TYPED_V4).unwrap();
    let signer = key(file["private_key"].as_str().unwrap());
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let data = TypedData::from_value(&case["data"]).unwrap();
        let signature = data.sign(&signer).unwrap();
        assert_eq!(
            hexutil::encode_prefixed(&signature.to_rsv(27)),
            case["signature"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(recover_address(&data.signing_hash().unwrap(), &signature), address_of(&signer));
    }
}

/// `eth-sig-util` signs one value of one type in a struct `Message{data}`.
/// Where this wallet takes the value, the signature must be the library's;
/// the values it refuses are listed, each for a reason that is the wallet's
/// being stricter.
#[test]
fn eth_sig_util_atomic_values_match_where_they_are_accepted() {
    let file: Value = serde_json::from_str(TYPED_V4).unwrap();
    let signer = key(file["private_key"].as_str().unwrap());
    let atoms = file["atoms"].as_array().unwrap();
    let (mut agreed, mut refused) = (0, Vec::new());
    for atom in atoms {
        let ty = atom["type"].as_str().unwrap();
        let data = serde_json::json!({
            "types": {"EIP712Domain": [], "Message": [{"name": "data", "type": ty}]},
            "primaryType": "Message",
            "domain": {},
            "message": {"data": atom["value"]},
        });
        let label = format!("{ty} {} ({})", atom["value"], atom["js_type"]);
        match TypedData::from_value(&data).and_then(|d| d.sign(&signer)) {
            Ok(signature) => {
                assert_eq!(
                    hexutil::encode_prefixed(&signature.to_rsv(27)),
                    atom["signature"].as_str().unwrap(),
                    "{label}"
                );
                agreed += 1;
            }
            Err(_) => refused.push((ty.to_owned(), atom["value"].clone(), label)),
        }
    }
    // Every refusal is one of these kinds, each a convenience of JavaScript
    // that is not typed data, or a value outside its type.
    for (ty, value, label) in &refused {
        let text = value.as_str().unwrap_or("");
        let ok = match ty.as_str() {
            // `uint` and `int` are not EIP-712 types (the specification says
            // so in as many words); and a value outside int8.
            "int" | "uint" | "int8" => true,
            // A number where a hex string is wanted.
            "address" | "bytes" | "bytes1" | "bytes32" | "string" if value.is_number() => true,
            // An address that is not 0x and 40 hex digits.
            "address" => text.len() != 42 || !text.starts_with("0x"),
            // Bytes without the 0x of hex, or more than the type holds.
            "bytes" => !text.starts_with("0x"),
            "bytes1" => text.trim_start_matches("0x").len() > 2,
            // A boolean written as text.
            "bool" => value.is_string(),
            _ => false,
        };
        assert!(ok, "an unexpected refusal: {label}\nall: {refused:?}");
    }
    assert!(agreed >= 30, "agreed on only {agreed} of {}", atoms.len());
    assert_eq!(agreed + refused.len(), atoms.len());
}

#[test]
fn typed_data_that_is_malformed_is_refused() {
    let mail = |message: Value| {
        serde_json::json!({
            "types": {
                "EIP712Domain": [],
                "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
                "Mail": [{"name": "from", "type": "Person"}, {"name": "n", "type": "uint8"}]
            },
            "primaryType": "Mail",
            "domain": {},
            "message": message,
        })
    };
    let person =
        serde_json::json!({"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"});
    let ok = mail(serde_json::json!({"from": person, "n": 255}));
    assert!(TypedData::from_value(&ok).unwrap().signing_hash().is_ok());
    for (message, why) in [
        (serde_json::json!({"from": person}), "message.n: missing"),
        (serde_json::json!({"from": person, "n": null}), "message.n: missing"),
        (serde_json::json!({"from": person, "n": 256}), "does not fit 8 bits"),
        (serde_json::json!({"from": person, "n": -1}), "negative"),
        (serde_json::json!({"from": person, "n": 1.5}), "not an integer"),
        (serde_json::json!({"from": person, "n": true}), "not a number"),
        (serde_json::json!({"from": {"name": "Cow"}, "n": 1}), "message.from.wallet: missing"),
        (serde_json::json!({"from": "Cow", "n": 1}), "message.from: not an object"),
        (
            serde_json::json!({"from": {"name": 5, "wallet": person["wallet"]}, "n": 1}),
            "not a string",
        ),
    ] {
        let error = TypedData::from_value(&mail(message))
            .and_then(|d| d.signing_hash())
            .unwrap_err()
            .to_string();
        assert!(error.contains(why), "{error} should say {why}");
    }
    // Definitions that are wrong.
    for (types, primary, why) in [
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "uint"}]}),
            "A",
            "needs a width",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "uint7"}]}),
            "A",
            "needs a width",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "uint264"}]}),
            "A",
            "needs a width",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "bytes33"}]}),
            "A",
            "not a type",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "B"}]}),
            "A",
            "not defined",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x(", "type": "bool"}]}),
            "A",
            "no valid name",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "bool"}, {"name": "x", "type": "bool"}]}),
            "A",
            "twice",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "address": [{"name": "x", "type": "bool"}]}),
            "address",
            "built-in",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "uint8[0]"}]}),
            "A",
            "array length",
        ),
        (
            serde_json::json!({"A": [{"name": "x", "type": "bool"}]}),
            "A",
            "EIP712Domain is not defined",
        ),
        (
            serde_json::json!({"EIP712Domain": [], "A": [{"name": "x", "type": "bool"}]}),
            "B",
            "is not one of the types",
        ),
    ] {
        let data = serde_json::json!({"types": types, "primaryType": primary, "domain": {}, "message": {"x": true}});
        let error =
            TypedData::from_value(&data).and_then(|d| d.signing_hash()).unwrap_err().to_string();
        assert!(error.contains(why), "{error} should say {why}");
    }
    assert!(TypedData::parse("not json").is_err());
    assert!(TypedData::parse("[]").is_err());
    assert!(TypedData::parse("{}").is_err());
}

#[test]
fn integers_are_checked_against_their_width_and_signed_correctly() {
    let hash_of = |ty: &str, value: Value| {
        let data = serde_json::json!({
            "types": {"EIP712Domain": [], "M": [{"name": "v", "type": ty}]},
            "primaryType": "M", "domain": {}, "message": {"v": value},
        });
        TypedData::from_value(&data).and_then(|d| d.message_hash())
    };
    // int8 ranges from -128 to 127; uint8 from 0 to 255.
    assert!(hash_of("int8", serde_json::json!(127)).is_ok());
    assert!(hash_of("int8", serde_json::json!(128)).is_err());
    assert!(hash_of("int8", serde_json::json!(-128)).is_ok());
    assert!(hash_of("int8", serde_json::json!(-129)).is_err());
    assert!(hash_of("uint8", serde_json::json!(255)).is_ok());
    assert!(hash_of("uint8", serde_json::json!(256)).is_err());
    assert!(hash_of("uint8", serde_json::json!("0x100")).is_err());
    // -1 as an int256 is all ones, the same word as 2^256 - 1 as a uint256 up
    // to the type hash; compare the word under one struct hash each by
    // checking int8 -1 equals int256 -1 only if the type strings were equal,
    // so check the encoding through a bytes32 of ones instead.
    assert!(
        hash_of(
            "int256",
            serde_json::json!(
                "-57896044618658097711785492504343953926634992332820282019728792003956564819968"
            )
        )
        .is_ok()
    );
    assert!(
        hash_of(
            "int256",
            serde_json::json!(
                "-57896044618658097711785492504343953926634992332820282019728792003956564819969"
            )
        )
        .is_err()
    );
    assert!(
        hash_of(
            "int256",
            serde_json::json!(
                "57896044618658097711785492504343953926634992332820282019728792003956564819967"
            )
        )
        .is_ok()
    );
    assert!(
        hash_of(
            "int256",
            serde_json::json!(
                "57896044618658097711785492504343953926634992332820282019728792003956564819968"
            )
        )
        .is_err()
    );
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    assert!(hash_of("uint256", serde_json::json!(max)).is_ok());
    assert!(hash_of("uint256", serde_json::json!(format!("{max}0"))).is_err());
    // Decimal, hex and number spellings of one value hash alike.
    let a = hash_of("uint256", serde_json::json!(4096)).unwrap();
    assert_eq!(a, hash_of("uint256", serde_json::json!("4096")).unwrap());
    assert_eq!(a, hash_of("uint256", serde_json::json!("0x1000")).unwrap());
    // A negative int8 and the same int256 differ only by their type hashes,
    // but their encoded words are both ff…ff: pin it through a hand-built
    // struct hash of one member.
    let minus_one = keccak(&[keccak(b"M(int8 v)").as_slice(), &[0xff; 32]].concat());
    assert_eq!(hash_of("int8", serde_json::json!(-1)).unwrap(), minus_one);
}

#[test]
fn arrays_nest_and_fixed_arrays_are_counted() {
    let hash_of = |ty: &str, value: Value| {
        let data = serde_json::json!({
            "types": {"EIP712Domain": [], "M": [{"name": "v", "type": ty}]},
            "primaryType": "M", "domain": {}, "message": {"v": value},
        });
        TypedData::from_value(&data).and_then(|d| d.message_hash())
    };
    // hashStruct(M{uint8[2][] v}) by hand: the array hashes the concatenated
    // hashes of its elements, each of which hashes its own words.
    let word = |n: u8| {
        let mut w = [0u8; 32];
        w[31] = n;
        w
    };
    let pair = |a: u8, b: u8| keccak(&[word(a), word(b)].concat());
    let expected = keccak(
        &[keccak(b"M(uint8[2][] v)").as_slice(), &keccak(&[pair(1, 2), pair(3, 4)].concat())]
            .concat(),
    );
    assert_eq!(hash_of("uint8[2][]", serde_json::json!([[1, 2], [3, 4]])).unwrap(), expected);
    assert!(hash_of("uint8[2][]", serde_json::json!([[1, 2], [3]])).is_err());
    assert!(hash_of("uint8[2][]", serde_json::json!([[1, 2], [3, null]])).is_err());
    // An empty dynamic array hashes the empty string.
    let empty = keccak(&[keccak(b"M(uint8[] v)").as_slice(), &keccak(b"")].concat());
    assert_eq!(hash_of("uint8[]", serde_json::json!([])).unwrap(), empty);
}

#[test]
fn a_permit_is_recognised_in_typed_data() {
    // EIP-2612's own type string, as the ERC states PERMIT_TYPEHASH.
    let permit_type = ERC2612
        .lines()
        .find_map(|l| {
            l.split("keccak256(\"").nth(1)?.split("\")").next().filter(|s| s.starts_with("Permit("))
        })
        .unwrap();
    assert_eq!(
        permit_type,
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    let typed = |value: &str| {
        serde_json::json!({
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
            "domain": {"name": "USD Coin", "version": "2", "chainId": 1, "verifyingContract": TOKEN},
            "message": {"owner": BOB, "spender": ALICE, "value": value, "nonce": "0", "deadline": "1700000000"},
        })
    };
    let data = TypedData::from_value(&typed("1000000")).unwrap();
    assert_eq!(data.encode_type("Permit").unwrap(), permit_type);
    let summary = data.summary().unwrap();
    assert_eq!(summary.primary_type, "Permit");
    assert_eq!(summary.domain.name.as_deref(), Some("USD Coin"));
    assert_eq!(summary.domain.chain_id, Some(U256::from_u128(1)));
    assert_eq!(summary.domain.verifying_contract, Some(address(TOKEN)));
    assert_eq!(
        summary.kind,
        TypedDataKind::Permit {
            owner: address(BOB),
            spender: address(ALICE),
            value: U256::from_u128(1_000_000),
            unlimited: false,
            nonce: U256::ZERO,
            deadline: U256::from_u128(1_700_000_000),
        }
    );
    // An unlimited one.
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let summary = TypedData::from_value(&typed(max)).unwrap().summary().unwrap();
    assert!(matches!(summary.kind, TypedDataKind::Permit { unlimited: true, .. }));
    // DAI's permit.
    let dai = serde_json::json!({
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}],
            "Permit": [
                {"name": "holder", "type": "address"}, {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"}, {"name": "expiry", "type": "uint256"},
                {"name": "allowed", "type": "bool"}]
        },
        "primaryType": "Permit",
        "domain": {"name": "Dai", "chainId": 1},
        "message": {"holder": BOB, "spender": ALICE, "nonce": 3, "expiry": 0, "allowed": true},
    });
    assert_eq!(
        TypedData::from_value(&dai).unwrap().summary().unwrap().kind,
        TypedDataKind::DaiPermit {
            holder: address(BOB),
            spender: address(ALICE),
            nonce: U256::from_u128(3),
            expiry: U256::ZERO,
            allowed: true,
        }
    );
    // The Mail example is not a permit.
    let (_, mail, _) = eip712_text_example();
    let summary = TypedData::parse(&mail).unwrap().summary().unwrap();
    assert_eq!(summary.kind, TypedDataKind::Other);
    assert_eq!(summary.domain.name.as_deref(), Some("Ether Mail"));
    // A struct named Permit with other members is not one either.
    let other = serde_json::json!({
        "types": {"EIP712Domain": [], "Permit": [{"name": "owner", "type": "address"}]},
        "primaryType": "Permit", "domain": {}, "message": {"owner": BOB},
    });
    assert_eq!(
        TypedData::from_value(&other).unwrap().summary().unwrap().kind,
        TypedDataKind::Other
    );
}

#[test]
fn chain_ids_are_the_four() {
    assert_eq!(EvmChain::ALL.map(EvmChain::chain_id), [1, 56, 137, 8453]);
    for chain in EvmChain::ALL {
        assert_eq!(EvmChain::from_chain_id(chain.chain_id()), Some(chain));
    }
    assert_eq!(EvmChain::from_chain_id(10), None);
}
