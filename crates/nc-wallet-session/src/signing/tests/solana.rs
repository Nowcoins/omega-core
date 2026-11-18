//! Kinds 4 and 5: Solana transactions and messages.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use nc_wallet_core::solana::{
    self, ParsedTransaction, Priority, SolTransfer, SplTransfer, message, parse_address,
};
use nc_wallet_core::{Mnemonic, Network, derive};
use serde_json::{Value, json};

use super::*;

const MAINNET: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/solana-mainnet-transactions.json");

/// Account 0 of the reference phrase on Solana (Phantom's address for it).
const SOLANA_0: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn public_key(index: u32) -> [u8; 32] {
    let account = derive(&Mnemonic::parse(ABANDON).unwrap(), "", Network::Solana, index).unwrap();
    account.public_key.try_into().unwrap()
}

fn verifies(index: u32, signed_message: &[u8], signature: &[u8]) -> bool {
    let key = VerifyingKey::from_bytes(&public_key(index)).unwrap();
    let signature = Signature::from_slice(signature).unwrap();
    key.verify(signed_message, &signature).is_ok()
}

fn sol_transfer(lamports: u64, priority: Option<Priority>) -> Vec<u8> {
    solana::build_sol_transfer(&SolTransfer {
        from: public_key(0),
        to: [9; 32],
        lamports,
        recent_blockhash: [7; 32],
        priority,
    })
    .unwrap()
}

fn request(transaction: &[u8]) -> Value {
    json!({ "kind": "solana_transaction", "transaction_base64": b64(transaction) })
}

#[test]
fn a_transfer_is_decoded_signed_and_the_signature_verifies() {
    let engine = engine();
    let priority =
        Priority { compute_unit_limit: 1000, compute_unit_price_micro_lamports: 200_000 };
    let bytes = sol_transfer(1_500_000_000, Some(priority));
    let decoded = decode(&engine, 0, &request(&bytes)).unwrap();
    let s = &decoded.summary;
    assert_eq!(s["request"], "solana_transaction");
    assert_eq!(s["network"], "solana");
    assert_eq!(s["signer"], SOLANA_0);
    assert_eq!(s["details"]["fee_payer"], SOLANA_0);
    assert_eq!(s["details"]["required_signers"], json!([SOLANA_0]));
    let instructions = s["details"]["instructions"].as_array().unwrap();
    assert_eq!(instructions[0]["type"], "set_compute_unit_limit");
    assert_eq!(instructions[0]["units"], 1000);
    assert_eq!(instructions[0]["program_name"], "Compute Budget");
    assert_eq!(instructions[1]["type"], "set_compute_unit_price");
    assert_eq!(instructions[1]["micro_lamports"], "200000");
    assert_eq!(instructions[2]["type"], "system_transfer");
    assert_eq!(instructions[2]["lamports"], "1500000000");
    assert_eq!(instructions[2]["from"], SOLANA_0);
    assert_eq!(s["warnings"], json!([]));
    // 5000 for the signature and 1000 units at 200000 micro-lamports each.
    assert_eq!(s["fee"], json!({ "asset": "SOL", "amount": "5200", "decimals": 9 }));

    let signed = sign(&engine, 0, &request(&bytes));
    let wire = STANDARD.decode(signed["transaction_base64"].as_str().unwrap()).unwrap();
    let parsed = ParsedTransaction::parse(&wire).unwrap();
    let signature = STANDARD.decode(signed["signature_base64"].as_str().unwrap()).unwrap();
    assert_eq!(parsed.signatures[0].as_slice(), signature.as_slice());
    assert!(verifies(0, &parsed.message_bytes, &signature));
    assert_eq!(signed["id_base58"], bs58::encode(&signature).into_string());
    // The message is the one that was handed in.
    assert_eq!(parsed.message_bytes, ParsedTransaction::parse(&bytes).unwrap().message_bytes);
}

#[test]
fn token_programs_and_unknown_ones_are_told_apart() {
    let engine = engine();
    // A token transfer that creates the recipient's account.
    let transfer = solana::build_spl_transfer(&SplTransfer {
        owner: public_key(0),
        mint: [3; 32],
        decimals: 6,
        amount: 250_000_000,
        recipient: [9; 32],
        source: None,
        recipient_token_account_exists: false,
        recent_blockhash: [7; 32],
        priority: None,
    })
    .unwrap();
    let s = decode(&engine, 0, &request(&transfer)).unwrap().summary;
    let kinds: Vec<&str> = s["details"]["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["create_token_account", "spl_transfer"]);
    assert_eq!(s["details"]["instructions"][1]["amount"], "250000000");
    assert_eq!(s["details"]["instructions"][1]["decimals"], 6);
    assert_eq!(s["warnings"], json!([]));

    // An unknown program: any instruction the reader does not know.
    let unknown = message::Instruction {
        program: [5; 32],
        accounts: vec![message::AccountMeta::writable(public_key(0), true)],
        data: vec![1, 2, 3],
    };
    let compiled = message::compile(&public_key(0), &[unknown], &[7; 32]).unwrap();
    let bytes = message::transaction(&[[0; 64]], &compiled);
    let s = decode(&engine, 0, &request(&bytes)).unwrap().summary;
    assert_eq!(s["warnings"], json!(["unknown_programs"]));
    let instruction = &s["details"]["instructions"][0];
    assert_eq!(instruction["type"], "unknown");
    assert_eq!(instruction["data"], "010203");
    assert_eq!(instruction["data_len"], 3);
    assert_eq!(instruction["program"], bs58::encode([5u8; 32]).into_string());
    assert_eq!(instruction["accounts"], json!([SOLANA_0]));

    // A token approval, limited and unlimited.
    for (amount, warnings) in [
        (500_u64, json!(["delegate_approval"])),
        (u64::MAX, json!(["delegate_approval", "unlimited_approval"])),
    ] {
        let mut data = vec![4];
        data.extend_from_slice(&amount.to_le_bytes());
        let approve = message::Instruction {
            program: message::TOKEN_PROGRAM,
            accounts: vec![
                message::AccountMeta::writable([1; 32], false),
                message::AccountMeta::readonly([2; 32], false),
                message::AccountMeta::readonly(public_key(0), true),
            ],
            data,
        };
        let compiled = message::compile(&public_key(0), &[approve], &[7; 32]).unwrap();
        let bytes = message::transaction(&[[0; 64]], &compiled);
        let s = decode(&engine, 0, &request(&bytes)).unwrap().summary;
        assert_eq!(s["warnings"], warnings);
        assert_eq!(s["details"]["instructions"][0]["type"], "spl_approve");
        assert_eq!(s["details"]["instructions"][0]["unlimited"], amount == u64::MAX);
    }
}

#[test]
fn every_mainnet_transaction_is_read_as_the_node_reads_it() {
    let all: Value = serde_json::from_str(MAINNET).unwrap();
    let mut seen = 0;
    for (name, entry) in all["transactions"].as_object().unwrap() {
        let bytes = STANDARD.decode(entry["transaction_base64"].as_str().unwrap()).unwrap();
        let tables: Vec<solana::LookupTable> = entry["lookup_tables"]
            .as_object()
            .map(|tables| {
                tables
                    .iter()
                    .map(|(address, table)| {
                        let data = STANDARD.decode(table["data_base64"].as_str().unwrap()).unwrap();
                        solana::LookupTable::parse(parse_address(address).unwrap(), &data).unwrap()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let summary = super::super::solana::summarize(&bytes, &tables, &[0; 32]).unwrap();
        let (details, fee, _) = super::super::solana::transaction_details(&summary);
        let ours: Vec<&str> = details["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["type"].as_str().unwrap())
            .collect();
        let node: Vec<&str> = entry["parsed_message"]["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                let program = i["programId"].as_str().unwrap();
                if program == "ComputeBudget111111111111111111111111111111" {
                    let data = bs58::decode(i["data"].as_str().unwrap()).into_vec().unwrap();
                    return if data[0] == 2 {
                        "set_compute_unit_limit"
                    } else {
                        "set_compute_unit_price"
                    };
                }
                match i["parsed"]["type"].as_str().unwrap_or("") {
                    "transfer" if program == "11111111111111111111111111111111" => {
                        "system_transfer"
                    }
                    "transfer" | "transferChecked" => "spl_transfer",
                    "create" | "createIdempotent" => "create_token_account",
                    _ => "unknown",
                }
            })
            .collect();
        assert_eq!(ours, node, "{name}");
        assert_eq!(
            details["fee_payer"], entry["parsed_message"]["accountKeys"][0]["pubkey"],
            "{name}"
        );
        // Where the transaction sets its own compute limit, the estimate is what the node charged.
        let sets_limit = ours.contains(&"set_compute_unit_limit");
        if sets_limit {
            assert_eq!(fee, u128::from(entry["fee"].as_u64().unwrap()), "{name}");
        } else {
            assert!(fee >= 5000, "{name}");
        }
        // These are other people's transactions: not ours to sign.
        let engine = engine();
        let mut with_tables = request(&bytes);
        if let Some(tables) = entry["lookup_tables"].as_object() {
            with_tables["lookup_tables"] = tables
                .iter()
                .map(|(address, table)| json!({ "address": address, "data_base64": table["data_base64"] }))
                .collect();
        }
        assert_eq!(code(decode(&engine, 0, &with_tables)), "NotASigner", "{name}");
        seen += 1;
    }
    assert_eq!(seen, 8);
}

#[test]
fn a_version_0_transaction_needs_its_tables_and_signs_once_it_has_them() {
    let engine = engine();
    let all: Value = serde_json::from_str(MAINNET).unwrap();
    let entry = &all["transactions"]["v0_with_lookup_tables"];
    let original = STANDARD.decode(entry["transaction_base64"].as_str().unwrap()).unwrap();
    // The same transaction with this wallet as its fee payer: swap the first
    // account key in the message, and leave the signature slot empty.
    let parsed = ParsedTransaction::parse(&original).unwrap();
    let mut message_bytes = parsed.message_bytes.clone();
    assert_eq!(message_bytes[0], 0x80);
    let first_key = 1 + 3 + 1;
    assert_eq!(&message_bytes[first_key..first_key + 32], parsed.message.fee_payer().as_slice());
    message_bytes[first_key..first_key + 32].copy_from_slice(&public_key(0));
    let bytes = message::transaction(&vec![[0; 64]; parsed.signatures.len()], &message_bytes);

    let tables: Vec<Value> = entry["lookup_tables"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, table)| json!({ "address": address, "data_base64": table["data_base64"] }))
        .collect();
    let mut with_tables = request(&bytes);
    with_tables["lookup_tables"] = Value::Array(tables.clone());

    // Without the tables the request cannot be read.
    assert_eq!(code(decode(&engine, 0, &request(&bytes))), "BadRequest");
    // The tables a caller must fetch are named.
    let needed = crate::solana_lookup_tables(&b64(&bytes)).unwrap();
    assert_eq!(needed.len(), 3);
    for table in &tables {
        assert!(needed.contains(&table["address"].as_str().unwrap().to_owned()));
    }
    // A table that is not one.
    let mut broken = with_tables.clone();
    broken["lookup_tables"][0]["data_base64"] = json!(b64(&[1, 2, 3]));
    assert_eq!(code(decode(&engine, 0, &broken)), "BadRequest");

    let decoded = decode(&engine, 0, &with_tables).unwrap();
    assert_eq!(decoded.summary["signer"], SOLANA_0);
    let signed = sign(&engine, 0, &with_tables);
    let wire = STANDARD.decode(signed["transaction_base64"].as_str().unwrap()).unwrap();
    let signed_parsed = ParsedTransaction::parse(&wire).unwrap();
    assert_eq!(signed_parsed.message_bytes, message_bytes);
    assert!(verifies(0, &message_bytes, &signed_parsed.signatures[0]));
}

#[test]
fn another_signers_slot_is_left_as_it_was() {
    let engine = engine();
    // A transfer from a second account that this wallet co-signs: two
    // required signers, the other's slot already filled.
    let instruction = message::system_transfer([42; 32], [9; 32], 5);
    let mut accounts = instruction.accounts.clone();
    accounts.push(message::AccountMeta::readonly(public_key(0), true));
    let two_signers = message::Instruction { accounts, ..instruction };
    let compiled = message::compile(&[42; 32], &[two_signers], &[7; 32]).unwrap();
    let parsed = ParsedMessage::parse(&compiled).unwrap();
    let ours = parsed.signers().iter().position(|k| *k == public_key(0)).unwrap();
    let mut signatures = vec![[0u8; 64]; parsed.signers().len()];
    let other = 1 - ours;
    signatures[other] = [0xab; 64];
    let bytes = message::transaction(&signatures, &compiled);

    let signed = sign(&engine, 0, &request(&bytes));
    let wire = STANDARD.decode(signed["transaction_base64"].as_str().unwrap()).unwrap();
    let after = ParsedTransaction::parse(&wire).unwrap();
    assert_eq!(after.signatures[other], [0xab; 64]);
    assert!(verifies(0, &compiled, &after.signatures[ours]));
    // The id is the first signature, whichever slot it is.
    assert_eq!(signed["id_base58"], bs58::encode(after.signatures[0]).into_string());
}

use nc_wallet_core::solana::ParsedMessage;

#[test]
fn refused_transactions() {
    let engine = engine();
    let bytes = sol_transfer(5, None);
    // Not ours: signer index 1 is another account.
    assert_eq!(code(decode(&engine, 1, &request(&bytes))), "NotASigner");
    // A version this wallet does not read.
    let mut v1 = bytes.clone();
    v1[65] = 0x81;
    assert_eq!(code(decode(&engine, 0, &request(&v1))), "Unsupported");
    // Not a transaction, not base64, too large, extra fields.
    assert_eq!(code(decode(&engine, 0, &request(&[1, 2, 3]))), "BadRequest");
    assert_eq!(
        code(decode(
            &engine,
            0,
            &json!({ "kind": "solana_transaction", "transaction_base64": "!!" })
        )),
        "BadRequest"
    );
    assert_eq!(code(decode(&engine, 0, &request(&vec![0u8; 1233]))), "BadRequest");
    let mut extra = request(&bytes);
    extra["chain"] = json!("solana:mainnet");
    assert_eq!(code(decode(&engine, 0, &extra)), "BadRequest");
}

#[test]
fn a_message_is_signed_as_it_is_and_never_as_a_transaction() {
    let engine = engine();
    let text = b"Sign in to example.org\nNonce: 8a41".to_vec();
    let request = json!({ "kind": "solana_message", "message_base64": b64(&text) });
    let decoded = decode(&engine, 0, &request).unwrap();
    assert_eq!(decoded.summary["action"], "sign_message");
    assert_eq!(decoded.summary["signer"], SOLANA_0);
    assert_eq!(decoded.summary["details"]["text"], "Sign in to example.org\nNonce: 8a41");
    assert_eq!(decoded.summary["details"]["message_len"], text.len());
    assert_eq!(decoded.summary["warnings"], json!([]));

    let signed = sign(&engine, 0, &request);
    let signature = STANDARD.decode(signed["signature_base64"].as_str().unwrap()).unwrap();
    assert!(verifies(0, &text, &signature));
    assert_eq!(signed["signature_base58"], bs58::encode(&signature).into_string());
    // Another account signs differently.
    let other = sign(&engine, 1, &request);
    let other_signature = STANDARD.decode(other["signature_base64"].as_str().unwrap()).unwrap();
    assert!(!verifies(0, &text, &other_signature));
    assert!(verifies(1, &text, &other_signature));

    // Bytes that are not text are refused: they could be a transaction in a format this
    // wallet cannot read, and a first byte of 0x80 or more is how a versioned message starts.
    for first in [0x80_u8, 0x81, 0xC0, 0xFF] {
        let binary =
            json!({ "kind": "solana_message", "message_base64": b64(&[first, 0x00, 0xfe]) });
        assert_eq!(code(decode(&engine, 0, &binary)), "NotText", "{first:x}");
    }
    // Text that begins with a non-ASCII letter is still text.
    let japanese =
        json!({ "kind": "solana_message", "message_base64": b64("ログイン".as_bytes()) });
    assert_eq!(decode(&engine, 0, &japanese).unwrap().summary["warnings"], json!([]));
    // A message with a right-to-left override is signed only on sight of the warning.
    let hidden =
        json!({ "kind": "solana_message", "message_base64": b64("pay \u{202E}1 SOL".as_bytes()) });
    let s = decode(&engine, 0, &hidden).unwrap().summary;
    assert_eq!(s["warnings"], json!(["unreadable_message", "hidden_characters"]));
    assert_eq!(s["details"]["text_escaped"], "pay <U+202E>1 SOL");

    // A transaction, or the message of one, is not a message.
    let transaction = sol_transfer(5, None);
    let parsed = ParsedTransaction::parse(&transaction).unwrap();
    for bytes in [transaction.as_slice(), parsed.message_bytes.as_slice()] {
        let request = json!({ "kind": "solana_message", "message_base64": b64(bytes) });
        assert_eq!(code(decode(&engine, 0, &request)), "LooksLikeTransaction");
    }
    let with_extra = json!({ "kind": "solana_message", "message_base64": b64(&text), "x": 1 });
    assert_eq!(code(decode(&engine, 0, &with_extra)), "BadRequest");
}

#[test]
fn a_sites_priority_fee_is_bounded_and_a_high_one_needs_the_persons_ok() {
    let engine = engine();
    // 200,000 units at 100,000,000,000 micro-lamports is 20,000,000,000 lamports (20 SOL): refused.
    let huge = Priority {
        compute_unit_limit: 200_000,
        compute_unit_price_micro_lamports: 100_000_000_000,
    };
    let bytes = sol_transfer(1_000, Some(huge));
    assert_eq!(code(decode(&engine, 0, &request(&bytes))), "FeeTooHigh");
    // 200,000 units at 20,000,000 micro-lamports is 4,000,000 lamports (0.004 SOL): allowed, but past
    // 0.001 SOL, where the person is asked.
    let dear =
        Priority { compute_unit_limit: 200_000, compute_unit_price_micro_lamports: 20_000_000 };
    let req = request(&sol_transfer(1_000, Some(dear)));
    let text = req.to_string();
    let decoded = engine.decode_request(0, &text).unwrap();
    assert!(decoded.summary["warnings"].as_array().unwrap().iter().any(|w| w == "fee_high"));
    assert_eq!(
        engine.sign_request(0, &text, &decoded.approval).unwrap_err().code(),
        "FeeNotAccepted"
    );
    let mut accepted = req;
    accepted["fee_ok"] = json!(true);
    assert!(engine.sign_request(0, &accepted.to_string(), &decoded.approval).is_ok());
}

// ---- MAJOR 1: what the approval may say about a transaction ----

fn raw(instructions: &[message::Instruction]) -> Value {
    let compiled = message::compile(&public_key(0), instructions, &[7; 32]).unwrap();
    request(&message::transaction(&[[0; 64]], &compiled))
}

#[test]
fn assigning_the_users_account_is_dangerous_and_the_summary_will_not_say_nothing_is_sent() {
    let engine = engine();
    let assign = message::Instruction {
        program: message::SYSTEM_PROGRAM,
        accounts: vec![message::AccountMeta::writable(public_key(0), true)],
        data: [1_u32.to_le_bytes().to_vec(), vec![5; 32]].concat(),
    };
    let s = decode(&engine, 0, &raw(&[assign])).unwrap().summary;
    let details = &s["details"];
    let instruction = &details["instructions"][0];
    assert_eq!(instruction["type"], "system_assign");
    assert_eq!(instruction["danger"], "assign_owner");
    assert_eq!(instruction["program_name"], "System");
    assert_eq!(instruction["user"]["signer"], true);
    assert_eq!(instruction["user"]["writable"], true);
    assert_eq!(details["may_move_user_funds"], true);
    assert_eq!(s["warnings"], json!(["dangerous_instruction"]));
}

#[test]
fn an_unknown_instruction_reports_the_users_accounts_and_is_never_fully_understood() {
    let engine = engine();
    let unknown = |accounts: Vec<message::AccountMeta>| message::Instruction {
        program: [5; 32],
        accounts,
        data: vec![9],
    };
    let touches = decode(
        &engine,
        0,
        &raw(&[unknown(vec![message::AccountMeta::readonly(public_key(0), true)])]),
    )
    .unwrap()
    .summary;
    assert_eq!(touches["details"]["fully_understood"], false);
    assert_eq!(touches["details"]["may_move_user_funds"], true);
    assert_eq!(touches["details"]["instructions"][0]["user"]["signer"], true);
    // The user only pays the fee: nothing of theirs is in the instruction, still not understood.
    let apart =
        decode(&engine, 0, &raw(&[unknown(vec![message::AccountMeta::writable([6; 32], false)])]))
            .unwrap()
            .summary;
    assert_eq!(apart["details"]["fully_understood"], false);
    assert_eq!(apart["details"]["may_move_user_funds"], false);
    assert_eq!(apart["details"]["instructions"][0]["user"]["accounts"], json!([]));
    // A plain transfer is understood, and moves the user's coins.
    let plain = decode(&engine, 0, &request(&sol_transfer(5, None))).unwrap().summary;
    assert_eq!(plain["details"]["fully_understood"], true);
    assert_eq!(plain["details"]["may_move_user_funds"], true);
}

// ---- a wallet that is one imported private key ----

#[test]
fn an_imported_solana_key_signs_exactly_what_the_phrase_signs() {
    let phrase = engine();
    let imported = key_engine(&exported_key(Network::Solana));
    let bytes = sol_transfer(1_500_000_000, None);
    let request = request(&bytes);
    let theirs = decode(&phrase, 0, &request).unwrap();
    let ours = decode(&imported, 0, &request).unwrap();
    assert_eq!(ours.summary, theirs.summary);
    assert_eq!(ours.summary["signer"], SOLANA_0);
    assert_eq!(sign(&imported, 0, &request), sign(&phrase, 0, &request));
    // No second account, and no EVM network, behind a Solana key.
    assert_eq!(code(decode(&imported, 1, &request)), "Unsupported");
}
