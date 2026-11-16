//! Solana: vectors from Solana's own libraries and from mainnet, and the
//! behaviour of the builders, the reader and the signers.
//!
//! Every expected value below is copied from the source named beside it, at
//! the commit named, or read from mainnet (see `tests/vectors/`). None is
//! worked out by the code under test.
//!
//! "The SDK" is <https://github.com/anza-xyz/solana-sdk> at commit
//! `d43dc05eaf2ffc60e5a7a576fe04396eb3e9b804`; file paths are in it.

#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]

use ed25519_dalek::Verifier as _;

use super::message::*;
use super::summary::*;
use super::*;

fn key(text: &str) -> Pubkey {
    decode(text).unwrap()
}

fn verifies(public: &Pubkey, message: &[u8], signature: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(public)
        .unwrap()
        .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

// ---- the programs' addresses ------------------------------------------------

#[test]
fn program_ids_are_the_published_addresses() {
    // The strings are the ones these declarations carry (fetched 2026-10-26):
    //  * system: `solana_sdk_ids::system_program` and compute budget:
    //    `solana_sdk_ids::compute_budget`, sdk-ids/src/lib.rs at the SDK commit;
    //  * Token: solana-program/token, interface/src/lib.rs at
    //    57bd873fdec3f6c7585068b190f6122e998cd4df;
    //  * Token-2022: solana-program/token-2022, interface/src/lib.rs at
    //    aa9b2ad96de25d214e9af3a960d2b59cd2f29e98;
    //  * associated token account: solana-program/associated-token-account,
    //    interface/src/lib.rs at 8efacd63d491e91d8c2a5b6fac9b74fdb9ba2d1e.
    assert_eq!(encode(&SYSTEM_PROGRAM), "11111111111111111111111111111111");
    assert_eq!(encode(&TOKEN_PROGRAM), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    assert_eq!(encode(&TOKEN_2022_PROGRAM), "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    assert_eq!(encode(&ASSOCIATED_TOKEN_PROGRAM), "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    assert_eq!(encode(&COMPUTE_BUDGET_PROGRAM), "ComputeBudget111111111111111111111111111111");
}

// ---- compact-u16 --------------------------------------------------------------

#[test]
fn shortvec_matches_the_sdk() {
    // solana-short-vec, `test_short_vec_encode_len` and `test_deserialize`
    // (short-vec/src/lib.rs at the SDK commit).
    for (len, bytes) in [
        (0x0_usize, vec![0x0_u8]),
        (0x7f, vec![0x7f]),
        (0x80, vec![0x80, 0x01]),
        (0xff, vec![0xff, 0x01]),
        (0x100, vec![0x80, 0x02]),
        (0x7fff, vec![0xff, 0xff, 0x01]),
        (0xffff, vec![0xff, 0xff, 0x03]),
        (0x07ff, vec![0xff, 0x0f]),
        (0x3fff, vec![0xff, 0x7f]),
        (0x4000, vec![0x80, 0x80, 0x01]),
    ] {
        let mut out = Vec::new();
        shortvec(len, &mut out);
        assert_eq!(out, bytes, "write {len:#x}");
        let mut offset = 0;
        assert_eq!(read_shortvec(&bytes, &mut offset), Some(len), "read {len:#x}");
        assert_eq!(offset, bytes.len());
    }
    // The SDK's refusals: aliases (a number written longer than it needs),
    // too short, too long, too large.
    for bad in [
        &[0x80_u8, 0x00][..],
        &[0x80, 0x80, 0x00],
        &[0xff, 0x00],
        &[0xff, 0x80, 0x00],
        &[0x80, 0x81, 0x00],
        &[0xff, 0x81, 0x00],
        &[0x80, 0x82, 0x00],
        &[0xff, 0x8f, 0x00],
        &[0xff, 0xff, 0x00],
        &[],
        &[0x80],
        &[0x80, 0x80, 0x80, 0x00],
        &[0x80, 0x80, 0x04],
        &[0x80, 0x80, 0x06],
    ] {
        assert_eq!(read_shortvec(bad, &mut 0), None, "{bad:02x?}");
    }
}

// ---- program-derived addresses ------------------------------------------------

#[test]
fn program_derived_addresses_match_the_sdk() {
    // solana-address `test_create_program_address` (address/src/lib.rs at the
    // SDK commit): these seeds under the upgradeable BPF loader.
    let program = key("BPFLoaderUpgradeab1e11111111111111111111111");
    let seed_key = key("SeedPubey1111111111111111111111111111111111");
    for (seeds, expected) in [
        (vec![&b""[..], &[1]], "BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe"),
        (vec!["☉".as_bytes(), &[0]], "13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19"),
        (vec![&b"Talking"[..], b"Squirrels"], "2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk"),
        (vec![&seed_key[..], &[1]], "976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL"),
    ] {
        assert_eq!(encode(&create_program_address(&seeds, &program).unwrap()), expected);
    }
    // The same test: a seed of 33 bytes, or 17 seeds, are refused; 32 and 16 are fine.
    assert!(create_program_address(&[&[127; 33]], &program).is_none());
    assert!(create_program_address(&[b"short_seed", &[127; 33]], &program).is_none());
    assert!(create_program_address(&[&[0; 32]], &program).is_some());
    let seventeen: Vec<[u8; 1]> = (1..=17).map(|n| [n]).collect();
    let seventeen: Vec<&[u8]> = seventeen.iter().map(<[u8; 1]>::as_slice).collect();
    assert!(create_program_address(&seventeen, &program).is_none());
    assert!(create_program_address(&seventeen[..16], &program).is_some());

    // `test_find_program_address`: the address found is the one made with its bump.
    let (found, bump) = find_program_address(&[b"Lil'", b"Bits"], &program).unwrap();
    assert_eq!(create_program_address(&[b"Lil'", b"Bits", &[bump]], &program), Some(found));
    assert!(!on_curve(&found));
}

// ---- Solana SDK: a whole transaction, byte for byte -----------------------------

#[test]
fn the_sdks_sample_transaction_is_reproduced_byte_for_byte() {
    // anza-xyz/solana-sdk, transaction/src/lib.rs at the SDK commit:
    // `create_sample_transaction` (lines 1347-1377) and `test_sdk_serialize`
    // (lines 1440-1456, "Detect binary changes in the serialized transaction
    // data, which could have a downstream affect on SDKs and applications").
    // The keypair is 64 bytes: the secret, then the public key.
    let keypair: [u8; 64] = [
        255, 101, 36, 24, 124, 23, 167, 21, 132, 204, 155, 5, 185, 58, 121, 75, 156, 227, 116, 193,
        215, 38, 142, 22, 8, 14, 229, 239, 119, 93, 5, 218, 36, 100, 158, 252, 33, 161, 97, 185,
        62, 89, 99, 195, 250, 249, 187, 189, 171, 118, 241, 90, 248, 14, 68, 219, 231, 62, 157, 5,
        142, 27, 210, 117,
    ];
    let to: Pubkey = [
        1, 1, 1, 4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 7, 6, 5, 4, 1,
        1, 1,
    ];
    let program: Pubkey = [
        2, 2, 2, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 8, 7, 6, 5, 4, 2,
        2, 2,
    ];
    let expected: Vec<u8> = vec![
        1, 120, 138, 162, 185, 59, 209, 241, 157, 71, 157, 74, 131, 4, 87, 54, 28, 38, 180, 222,
        82, 64, 62, 61, 62, 22, 46, 17, 203, 187, 136, 62, 43, 11, 38, 235, 17, 239, 82, 240, 139,
        130, 217, 227, 214, 9, 242, 141, 223, 94, 29, 184, 110, 62, 32, 87, 137, 63, 139, 100, 221,
        20, 137, 4, 5, 1, 0, 1, 3, 36, 100, 158, 252, 33, 161, 97, 185, 62, 89, 99, 195, 250, 249,
        187, 189, 171, 118, 241, 90, 248, 14, 68, 219, 231, 62, 157, 5, 142, 27, 210, 117, 1, 1, 1,
        4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 7, 6, 5, 4, 1, 1, 1, 2,
        2, 2, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 8, 7, 6, 5, 4, 2, 2,
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 2, 2, 0, 1, 3, 1, 2, 3,
    ];

    let secret: [u8; 32] = keypair[..32].try_into().unwrap();
    let signer = SigningKey::ed25519(&secret);
    assert_eq!(signer.public_key(), &keypair[32..], "the keypair's own public half");
    let payer: Pubkey = keypair[32..].try_into().unwrap();

    // `Instruction::new_with_bincode(program_id, &(1u8, 2u8, 3u8), metas)`: the
    // data is bincode of three bytes, which is the three bytes.
    let instruction = Instruction {
        program,
        accounts: vec![AccountMeta::writable(payer, true), AccountMeta::writable(to, false)],
        data: vec![1, 2, 3],
    };
    let message = compile(&payer, &[instruction], &[0; 32]).unwrap();
    // Signed, by the same function that signs a wallet's own transfers.
    let signed = sign_transaction(&signer, &transaction(&[[0; 64]], &message)).unwrap();
    assert_eq!(signed.transaction, expected);
    assert_eq!(&expected[1..65], &signed.signature);
    assert!(verifies(&payer, &message, &signed.signature));
}

#[test]
fn the_sdks_message_hash_pins_the_account_order() {
    // anza-xyz/solana-sdk, message/src/legacy.rs at the SDK commit, `test_message_hash`
    // (lines 774-803): four instructions over six accounts, with BLAKE3 of
    // "solana-tx-message-v1" and the message as the expected value. Each
    // instruction's data is bincode of `0` (an i32), so four zero bytes.
    let program_0 = key("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM");
    let program_1 = key("8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh");
    let id_0 = key("CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3");
    let id_1 = key("GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP");
    let id_2 = key("LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj");
    let id_3 = key("QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5");
    let zero = vec![0, 0, 0, 0];
    let instructions = vec![
        Instruction {
            program: program_0,
            accounts: vec![AccountMeta::writable(id_0, false)],
            data: zero.clone(),
        },
        Instruction {
            program: program_0,
            accounts: vec![AccountMeta::writable(id_1, true)],
            data: zero.clone(),
        },
        Instruction {
            program: program_1,
            accounts: vec![AccountMeta::readonly(id_2, false)],
            data: zero.clone(),
        },
        Instruction {
            program: program_1,
            accounts: vec![AccountMeta::readonly(id_3, true)],
            data: zero,
        },
    ];
    let message = compile(&id_1, &instructions, &[0; 32]).unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"solana-tx-message-v1");
    hasher.update(&message);
    let hash = hasher.finalize();
    assert_eq!(
        bs58::encode(hash.as_bytes()).into_string(),
        "7VWCF4quo2CcWQFNUayZiorxpiR5ix8YzLebrXKf3fMF"
    );
}

// ---- instruction data, from the programs' own packing tests --------------------

#[test]
fn token_instructions_pack_as_the_token_program_packs_them() {
    // solana-program/token, interface/src/instruction.rs at
    // 57bd873fdec3f6c7585068b190f6122e998cd4df, `test_instruction_packing`
    // (line 1671 on): `Transfer { amount: 1 }`, `Approve { amount: 1 }`,
    // `TransferChecked { amount: 1, decimals: 2 }` and `ApproveChecked` pack to
    // these bytes.
    let (a, b, c, d) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    assert_eq!(transfer_checked(a, b, c, d, 1, 2).data, [12u8, 1, 0, 0, 0, 0, 0, 0, 0, 2]);

    let as_instruction = |data: Vec<u8>, accounts: usize| Instruction {
        program: TOKEN_PROGRAM,
        accounts: [a, b, c, d]
            .iter()
            .take(accounts)
            .map(|k| AccountMeta::readonly(*k, false))
            .collect(),
        data,
    };
    assert_eq!(
        classify(&as_instruction(vec![3u8, 1, 0, 0, 0, 0, 0, 0, 0], 3)),
        InstructionSummary::SplTransfer {
            program: TOKEN_PROGRAM,
            source: a,
            destination: b,
            authority: c,
            mint: None,
            amount: 1,
            decimals: None
        }
    );
    assert_eq!(
        classify(&as_instruction(vec![12u8, 1, 0, 0, 0, 0, 0, 0, 0, 2], 4)),
        InstructionSummary::SplTransfer {
            program: TOKEN_PROGRAM,
            source: a,
            destination: c,
            authority: d,
            mint: Some(b),
            amount: 1,
            decimals: Some(2)
        }
    );
    assert_eq!(
        classify(&as_instruction(vec![4u8, 1, 0, 0, 0, 0, 0, 0, 0], 3)),
        InstructionSummary::SplApprove {
            program: TOKEN_PROGRAM,
            source: a,
            delegate: b,
            owner: c,
            mint: None,
            amount: 1,
            decimals: None,
            unlimited: false
        }
    );
    assert_eq!(
        classify(&as_instruction(vec![13u8, 1, 0, 0, 0, 0, 0, 0, 0, 2], 4)),
        InstructionSummary::SplApprove {
            program: TOKEN_PROGRAM,
            source: a,
            delegate: c,
            owner: d,
            mint: Some(b),
            amount: 1,
            decimals: Some(2),
            unlimited: false
        }
    );
    // The largest amount is flagged as an allowance with no practical limit.
    let mut unlimited = vec![4u8];
    unlimited.extend_from_slice(&u64::MAX.to_le_bytes());
    let InstructionSummary::SplApprove { unlimited, .. } = classify(&as_instruction(unlimited, 3))
    else {
        panic!("an approval");
    };
    assert!(unlimited);
    // Token-2022 shares these instructions' layouts.
    let mut token_2022 = as_instruction(vec![12u8, 1, 0, 0, 0, 0, 0, 0, 0, 2], 4);
    token_2022.program = TOKEN_2022_PROGRAM;
    assert!(
        matches!(classify(&token_2022), InstructionSummary::SplTransfer { program, .. } if program == TOKEN_2022_PROGRAM)
    );
    // Anything with the wrong length, too few accounts, or another opcode
    // (MintTo is opcode 7; SetAuthority 6 and CloseAccount 9 are read, in their one form) is unknown, never
    // misread as a transfer.
    for (data, accounts) in [
        (vec![12u8, 1, 0, 0, 0, 0, 0, 0, 0], 4),       // a byte short
        (vec![12u8, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0], 4), // a byte long
        (vec![12u8, 1, 0, 0, 0, 0, 0, 0, 0, 2], 3),    // an account short
        (vec![6u8, 1, 1, 4, 4, 4, 4, 4, 4, 4], 3),     // too short for the key it announces
        (vec![7u8, 1, 0, 0, 0, 0, 0, 0, 0], 3),
        (vec![9u8, 0], 3),    // CloseAccount takes no data
        (vec![6u8, 2, 1], 2), // SetAuthority's option tag says a key follows, none does
        (vec![], 3),
    ] {
        assert!(
            matches!(
                classify(&as_instruction(data.clone(), accounts)),
                InstructionSummary::Unknown { .. }
            ),
            "{data:?}"
        );
    }
}

#[test]
fn compute_budget_instructions_pack_as_the_sdk_packs_them() {
    // solana-compute-budget-interface, src/lib.rs at the SDK commit,
    // `test_to_instruction`: the limit 257 and the largest price.
    assert_eq!(set_compute_unit_limit(257).data, [2, 1, 1, 0, 0]);
    assert_eq!(set_compute_unit_price(u64::MAX).data, [3, 255, 255, 255, 255, 255, 255, 255, 255]);
    assert_eq!(
        classify(&set_compute_unit_limit(257)),
        InstructionSummary::SetComputeUnitLimit { units: 257 }
    );
    assert_eq!(
        classify(&set_compute_unit_price(u64::MAX)),
        InstructionSummary::SetComputeUnitPrice { micro_lamports: u64::MAX }
    );
}

// ---- mainnet --------------------------------------------------------------------
//
// `tests/vectors/solana-mainnet-transactions.json`: transactions as the network
// finalized them, each with the node's own reading of it (`jsonParsed`). A
// builder is right if it writes the bytes the network accepted; a reader is
// right if it reads what the node reads.

const MAINNET: &str = include_str!("../../tests/vectors/solana-mainnet-transactions.json");

fn fixtures() -> serde_json::Value {
    serde_json::from_str(MAINNET).unwrap()
}

fn wire(entry: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(entry["transaction_base64"].as_str().unwrap())
        .unwrap()
}

fn text<'a>(value: &'a serde_json::Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_else(|| panic!("no {name} in {value}"))
}

fn pubkey_of(value: &serde_json::Value, name: &str) -> Pubkey {
    key(text(value, name))
}

/// The base58 `data` of an instruction the node leaves unparsed.
fn data_of(instruction: &serde_json::Value) -> Vec<u8> {
    bs58::decode(text(instruction, "data")).into_vec().unwrap()
}

/// What the node says each instruction is, in the terms of
/// [`InstructionSummary`].
fn nodes_reading(entry: &serde_json::Value) -> Vec<InstructionSummary> {
    entry["parsed_message"]["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|instruction| {
            let program = text(instruction, "programId");
            if program == "ComputeBudget111111111111111111111111111111" {
                let data = data_of(instruction);
                return match data[0] {
                    2 => InstructionSummary::SetComputeUnitLimit {
                        units: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    },
                    3 => InstructionSummary::SetComputeUnitPrice {
                        micro_lamports: u64::from_le_bytes(data[1..9].try_into().unwrap()),
                    },
                    other => panic!("compute budget instruction {other}"),
                };
            }
            if instruction["parsed"].is_null() {
                // A program the node does not read: its accounts, as the node
                // lists them with their privileges, and its data.
                let keys = entry["parsed_message"]["accountKeys"].as_array().unwrap();
                let privileges = |address: &str| {
                    let account = keys.iter().find(|a| a["pubkey"] == address).unwrap();
                    (account["signer"].as_bool().unwrap(), account["writable"].as_bool().unwrap())
                };
                return InstructionSummary::Unknown {
                    program: key(program),
                    accounts: instruction["accounts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| {
                            let (signer, writable) = privileges(a.as_str().unwrap());
                            AccountMeta { key: key(a.as_str().unwrap()), signer, writable }
                        })
                        .collect(),
                    data: data_of(instruction),
                };
            }
            let info = &instruction["parsed"]["info"];
            match (program, text(&instruction["parsed"], "type")) {
                ("11111111111111111111111111111111", "transfer") => {
                    InstructionSummary::SystemTransfer {
                        from: pubkey_of(info, "source"),
                        to: pubkey_of(info, "destination"),
                        lamports: info["lamports"].as_u64().unwrap(),
                    }
                }
                (_, "transferChecked") => InstructionSummary::SplTransfer {
                    program: key(program),
                    source: pubkey_of(info, "source"),
                    destination: pubkey_of(info, "destination"),
                    authority: pubkey_of(info, "authority"),
                    mint: Some(pubkey_of(info, "mint")),
                    amount: text(&info["tokenAmount"], "amount").parse().unwrap(),
                    decimals: Some(
                        u8::try_from(info["tokenAmount"]["decimals"].as_u64().unwrap()).unwrap(),
                    ),
                },
                (_, "transfer") => InstructionSummary::SplTransfer {
                    program: key(program),
                    source: pubkey_of(info, "source"),
                    destination: pubkey_of(info, "destination"),
                    authority: pubkey_of(info, "authority"),
                    mint: None,
                    amount: text(info, "amount").parse().unwrap(),
                    decimals: None,
                },
                (_, kind @ ("create" | "createIdempotent")) => {
                    InstructionSummary::CreateAssociatedTokenAccount {
                        payer: pubkey_of(info, "source"),
                        account: pubkey_of(info, "account"),
                        owner: pubkey_of(info, "wallet"),
                        mint: pubkey_of(info, "mint"),
                        idempotent: kind == "createIdempotent",
                    }
                }
                other => panic!("an instruction the fixtures do not use: {other:?}"),
            }
        })
        .collect()
}

/// An unknown instruction without its accounts' privileges, which the node
/// reports with programs demoted to read-only (see the account check below).
fn without_privileges(summary: &InstructionSummary) -> InstructionSummary {
    match summary {
        InstructionSummary::Unknown { program, accounts, data } => InstructionSummary::Unknown {
            program: *program,
            accounts: accounts
                .iter()
                .map(|a| AccountMeta { key: a.key, signer: false, writable: false })
                .collect(),
            data: data.clone(),
        },
        other => other.clone(),
    }
}

fn tables_of(entry: &serde_json::Value) -> Vec<LookupTable> {
    use base64::Engine as _;
    let Some(tables) = entry["lookup_tables"].as_object() else { return Vec::new() };
    tables
        .iter()
        .map(|(address, table)| {
            let data = base64::engine::general_purpose::STANDARD
                .decode(text(table, "data_base64"))
                .unwrap();
            LookupTable::parse(key(address), &data).unwrap()
        })
        .collect()
}

#[test]
fn the_networks_transactions_verify_and_read_as_the_node_reads_them() {
    let all = fixtures();
    let transactions = all["transactions"].as_object().unwrap();
    assert_eq!(transactions.len(), 8);
    for (name, entry) in transactions {
        let bytes = wire(entry);
        let parsed = ParsedTransaction::parse(&bytes).unwrap();
        // Re-serialised, it is the same bytes.
        assert_eq!(transaction(&parsed.signatures, &parsed.message_bytes), bytes, "{name}");
        // The first signature, which is also the id the network knows it by,
        // verifies over the message with the fee payer's key.
        assert_eq!(
            bs58::encode(parsed.signatures[0]).into_string(),
            text(entry, "signature"),
            "{name}"
        );
        assert!(
            verifies(parsed.message.fee_payer(), &parsed.message_bytes, &parsed.signatures[0]),
            "{name}"
        );
        // The node's account list: keys, and who signs and writes.
        let tables = tables_of(entry);
        let metas = parsed.message.resolve(&tables).unwrap();
        let node_keys = entry["parsed_message"]["accountKeys"].as_array().unwrap();
        assert_eq!(metas.len(), node_keys.len(), "{name}");
        for (ours, theirs) in metas.iter().zip(node_keys) {
            assert_eq!(encode(&ours.key), text(theirs, "pubkey"), "{name}");
            assert_eq!(ours.signer, theirs["signer"].as_bool().unwrap(), "{name} signer");
            // The node reports an invoked program as read-only whatever the
            // message's header says (the runtime takes its write lock away).
            let theirs_writable = theirs["writable"].as_bool().unwrap();
            let invoked = parsed.message.instructions.iter().any(|instruction| {
                parsed.message.account_keys[usize::from(instruction.program_index)] == ours.key
            });
            assert!(
                ours.writable == theirs_writable || (ours.writable && !theirs_writable && invoked),
                "{name} writable"
            );
        }
        assert_eq!(
            encode(&parsed.message.recent_blockhash),
            text(&entry["parsed_message"], "recentBlockhash")
        );
        // The summary is the node's reading of the instructions.
        let summary = summarize_transaction(&bytes, &tables).unwrap();
        assert_eq!(
            summary.instructions.iter().map(without_privileges).collect::<Vec<_>>(),
            nodes_reading(entry).iter().map(without_privileges).collect::<Vec<_>>(),
            "{name}"
        );
        assert_eq!(encode(&summary.fee_payer), text(&node_keys[0], "pubkey"));
        // Without its lookup tables a version-0 transaction names them and is not read.
        if parsed.message.version == Version::V0 {
            assert_eq!(lookup_tables_needed(&bytes).unwrap().len(), 3);
            assert!(matches!(
                summarize_transaction(&bytes, &[]),
                Err(MessageError::MissingLookupTable(_))
            ));
        } else {
            assert!(lookup_tables_needed(&bytes).unwrap().is_empty());
        }
    }
}

/// The instructions of a legacy fixture, rebuilt with this crate's own
/// constructors from what the node says each is.
fn rebuilt(entry: &serde_json::Value) -> Option<Vec<Instruction>> {
    nodes_reading(entry)
        .iter()
        .map(|summary| {
            Some(match summary {
                InstructionSummary::SystemTransfer { from, to, lamports } => {
                    system_transfer(*from, *to, *lamports)
                }
                InstructionSummary::SplTransfer {
                    source,
                    destination,
                    authority,
                    mint: Some(mint),
                    amount,
                    decimals: Some(decimals),
                    ..
                } => transfer_checked(*source, *mint, *destination, *authority, *amount, *decimals),
                InstructionSummary::CreateAssociatedTokenAccount {
                    payer,
                    account,
                    owner,
                    mint,
                    idempotent: true,
                } => create_associated_token_account_idempotent(*payer, *account, *owner, *mint),
                InstructionSummary::SetComputeUnitLimit { units } => set_compute_unit_limit(*units),
                InstructionSummary::SetComputeUnitPrice { micro_lamports } => {
                    set_compute_unit_price(*micro_lamports)
                }
                _ => return None,
            })
        })
        .collect()
}

/// Whether two messages are the same transaction: the same fee payer,
/// blockhash and header, the same accounts with the same privileges, and the
/// same instructions (program, accounts in order with their privileges, data).
/// Only the order of accounts within a group may differ, which no library
/// agrees on and the runtime does not look at (see [`compile`]).
fn same_transaction(ours: &[u8], theirs: &[u8]) -> bool {
    let (ours, theirs) =
        (ParsedMessage::parse(ours).unwrap(), ParsedMessage::parse(theirs).unwrap());
    let sorted = |message: &ParsedMessage| {
        let mut metas: Vec<(Pubkey, bool, bool)> = message
            .resolve(&[])
            .unwrap()
            .iter()
            .map(|meta| (meta.key, meta.signer, meta.writable))
            .collect();
        metas.sort_unstable();
        metas
    };
    ours.version == theirs.version
        && ours.header == theirs.header
        && ours.fee_payer() == theirs.fee_payer()
        && ours.recent_blockhash == theirs.recent_blockhash
        && sorted(&ours) == sorted(&theirs)
        && ours.resolved_instructions(&[]).unwrap() == theirs.resolved_instructions(&[]).unwrap()
}

#[test]
fn the_encoders_write_the_transactions_the_network_accepted() {
    let all = fixtures();
    let mut checked = Vec::new();
    let mut identical = Vec::new();
    for (name, entry) in all["transactions"].as_object().unwrap() {
        let Some(instructions) = rebuilt(entry) else { continue };
        let bytes = wire(entry);
        let parsed = ParsedTransaction::parse(&bytes).unwrap();
        let message =
            compile(parsed.message.fee_payer(), &instructions, &parsed.message.recent_blockhash)
                .unwrap();
        assert!(same_transaction(&message, &parsed.message_bytes), "{name}");
        checked.push(name.as_str());
        if message == parsed.message_bytes {
            identical.push(name.as_str());
            // And with the network's signature in, the whole transaction.
            assert_eq!(transaction(&parsed.signatures, &message), bytes, "{name}");
        }
    }
    // Every legacy transaction but the two this crate has no encoder for (a
    // non-idempotent `Create`, and a plain `Transfer`).
    checked.sort_unstable();
    assert_eq!(
        checked,
        [
            "sol_transfer",
            "sol_transfer_with_unit_limit",
            "spl_transfer_creating_account",
            "spl_transfer_creating_account_with_priority",
            "spl_transfer_with_priority",
        ]
    );
    // Those with so few accounts that every ordering agrees are the same bytes.
    assert!(identical.contains(&"sol_transfer"), "{identical:?}");
}

fn priority_of(entry: &serde_json::Value) -> Option<Priority> {
    let reading = nodes_reading(entry);
    let limit = reading.iter().find_map(|i| match i {
        InstructionSummary::SetComputeUnitLimit { units } => Some(*units),
        _ => None,
    })?;
    let price = reading.iter().find_map(|i| match i {
        InstructionSummary::SetComputeUnitPrice { micro_lamports } => Some(*micro_lamports),
        _ => None,
    })?;
    Some(Priority { compute_unit_limit: limit, compute_unit_price_micro_lamports: price })
}

#[test]
fn the_builders_write_the_transactions_mainnet_wallets_sent() {
    let all = fixtures();
    let get = |name: &str| all["transactions"][name].clone();
    let message_of = |entry: &serde_json::Value| ParsedTransaction::parse(&wire(entry)).unwrap();

    // A plain SOL transfer.
    let entry = get("sol_transfer");
    let parsed = message_of(&entry);
    let InstructionSummary::SystemTransfer { from, to, lamports } =
        nodes_reading(&entry)[0].clone()
    else {
        panic!("a transfer");
    };
    let built = build_sol_transfer(&SolTransfer {
        from,
        to,
        lamports,
        recent_blockhash: parsed.message.recent_blockhash,
        priority: None,
    })
    .unwrap();
    // The same transaction with the signature slot zeroed.
    assert_eq!(built, transaction(&[[0; 64]], &parsed.message_bytes));
    assert_eq!(built.len(), 1 + 64 + parsed.message_bytes.len());

    // An SPL transfer, to an owner who has no token account yet, with a
    // priority fee: [limit, price, create idempotent, transferChecked].
    let entry = get("spl_transfer_creating_account_with_priority");
    let parsed = message_of(&entry);
    let reading = nodes_reading(&entry);
    let InstructionSummary::SplTransfer {
        source,
        authority,
        mint: Some(mint),
        amount,
        decimals: Some(decimals),
        ..
    } = reading[3].clone()
    else {
        panic!("a transfer");
    };
    let InstructionSummary::CreateAssociatedTokenAccount { owner: recipient, .. } =
        reading[2].clone()
    else {
        panic!("an account creation");
    };
    let spl = SplTransfer {
        owner: authority,
        mint,
        decimals,
        amount,
        recipient,
        source: None,
        recipient_token_account_exists: false,
        recent_blockhash: parsed.message.recent_blockhash,
        priority: priority_of(&entry),
    };
    assert!(spl.priority.is_some());
    // The node's own token balances say whose accounts these are: the source
    // is the sender's associated account, the destination the recipient's.
    let balances = entry["postTokenBalances"].as_array().unwrap();
    for balance in balances {
        let account =
            all_keys(&entry)[usize::try_from(balance["accountIndex"].as_u64().unwrap()).unwrap()];
        assert_eq!(
            associated_token_account(&pubkey_of(balance, "owner"), &pubkey_of(balance, "mint")),
            Some(account)
        );
    }
    assert_built(&build_spl_transfer(&spl).unwrap(), &parsed.message_bytes);
    assert_eq!(associated_token_account(&authority, &mint), Some(source));
    // The same sender naming the source account explicitly.
    let named = SplTransfer { source: Some(source), ..spl.clone() };
    assert_eq!(build_spl_transfer(&named).unwrap(), build_spl_transfer(&spl).unwrap());

    // To an owner who has one: no creation.
    let entry = get("spl_transfer_with_priority");
    let parsed = message_of(&entry);
    let reading = nodes_reading(&entry);
    let InstructionSummary::SplTransfer {
        authority,
        mint: Some(mint),
        amount,
        decimals: Some(decimals),
        destination,
        ..
    } = reading[2].clone()
    else {
        panic!("a transfer");
    };
    // The recipient's wallet is not in the transaction, only its token
    // account; the node's token balances name that account's owner.
    let destination_index = all_keys(&entry).iter().position(|k| *k == destination).unwrap();
    let recipient = entry["postTokenBalances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["accountIndex"].as_u64().unwrap() == destination_index as u64)
        .map(|b| pubkey_of(b, "owner"))
        .unwrap();
    let spl = SplTransfer {
        owner: authority,
        mint,
        decimals,
        amount,
        recipient,
        source: None,
        recipient_token_account_exists: true,
        recent_blockhash: parsed.message.recent_blockhash,
        priority: priority_of(&entry),
    };
    assert_built(&build_spl_transfer(&spl).unwrap(), &parsed.message_bytes);

    // Creating the account, no priority fee.
    let entry = get("spl_transfer_creating_account");
    let parsed = message_of(&entry);
    let reading = nodes_reading(&entry);
    let InstructionSummary::SplTransfer {
        authority,
        mint: Some(mint),
        amount,
        decimals: Some(decimals),
        ..
    } = reading[1].clone()
    else {
        panic!("a transfer");
    };
    let InstructionSummary::CreateAssociatedTokenAccount { owner: recipient, .. } =
        reading[0].clone()
    else {
        panic!("an account creation");
    };
    let spl = SplTransfer {
        owner: authority,
        mint,
        decimals,
        amount,
        recipient,
        source: None,
        recipient_token_account_exists: false,
        recent_blockhash: parsed.message.recent_blockhash,
        priority: None,
    };
    assert_built(&build_spl_transfer(&spl).unwrap(), &parsed.message_bytes);
}

/// A built transaction is unsigned, with one zeroed signature slot, and its
/// message is the same transaction as the network's.
fn assert_built(built: &[u8], network_message: &[u8]) {
    assert_eq!(built[..65], [[1u8].as_slice(), &[0u8; 64]].concat(), "one empty signature slot");
    assert!(same_transaction(&built[65..], network_message));
}

/// Every account key of a transaction, as the node lists them.
fn all_keys(entry: &serde_json::Value) -> Vec<Pubkey> {
    entry["parsed_message"]["accountKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| pubkey_of(account, "pubkey"))
        .collect()
}

#[test]
fn a_site_transaction_with_two_signers_is_signed_in_its_own_slot_only() {
    // A real transaction that two keys sign (`two_signers_token_transfer`): the
    // fee payer and the owner of the token account. A key that is neither is
    // refused; the wallet's signature goes in the slot of its own key and the
    // other signature stays as it was. The wallet's key is made up: this
    // checks the slot logic on a real message, not a real account.
    let all = fixtures();
    let entry = &all["transactions"]["two_signers_token_transfer"];
    let bytes = wire(entry);
    let parsed = ParsedTransaction::parse(&bytes).unwrap();
    assert_eq!(parsed.message.signers().len(), 2);

    let stranger = SigningKey::ed25519(&[42; 32]);
    assert_eq!(sign_transaction(&stranger, &bytes), Err(SolanaError::NotASigner));

    // Put a key of ours in the second slot of an otherwise identical message.
    let ours = SigningKey::ed25519(&[43; 32]);
    let mut message = parsed.message_bytes.clone();
    let our_public: Pubkey = ours.public_key().try_into().unwrap();
    let second_key_at = 1 + 3 + 32; // header (3), key count (1), then the first key
    message[second_key_at..second_key_at + 32].copy_from_slice(&our_public);
    let rewritten = transaction(&parsed.signatures, &message);
    let signed = sign_transaction(&ours, &rewritten).unwrap();
    let after = ParsedTransaction::parse(&signed.transaction).unwrap();
    assert_eq!(after.signatures[0], parsed.signatures[0], "the first signer's slot is untouched");
    assert_eq!(after.signatures[1], signed.signature);
    assert!(verifies(&our_public, &message, &signed.signature));
    assert_eq!(after.message_bytes, message);
}

// ---- reading what a site hands over ----------------------------------------------------

fn wallet_key() -> SigningKey {
    SigningKey::ed25519(&[7; 32])
}

fn wallet_pubkey() -> Pubkey {
    wallet_key().public_key().try_into().unwrap()
}

/// A transaction as a site would send it: a swap-like call into a program the
/// wallet does not know, after a transfer and an approval.
fn site_transaction(payer: Pubkey) -> Vec<u8> {
    let (token_account, delegate, mint, program) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    let mut approve = vec![13u8];
    approve.extend_from_slice(&u64::MAX.to_le_bytes());
    approve.push(6);
    let instructions = vec![
        set_compute_unit_limit(200_000),
        system_transfer(payer, [9; 32], 1_000),
        Instruction {
            program: TOKEN_PROGRAM,
            accounts: vec![
                AccountMeta::writable(token_account, false),
                AccountMeta::readonly(mint, false),
                AccountMeta::readonly(delegate, false),
                AccountMeta::readonly(payer, true),
            ],
            data: approve,
        },
        Instruction {
            program,
            accounts: vec![AccountMeta::writable(payer, true), AccountMeta::readonly(mint, false)],
            data: vec![0xde, 0xad],
        },
    ];
    let message = compile(&payer, &instructions, &[5; 32]).unwrap();
    transaction(&[[0; 64]], &message)
}

#[test]
fn a_site_transaction_is_summarised_instruction_by_instruction() {
    let payer = wallet_pubkey();
    let bytes = site_transaction(payer);
    let summary = summarize_transaction(&bytes, &[]).unwrap();
    assert_eq!(summary.fee_payer, payer);
    assert_eq!(summary.required_signers, vec![payer]);
    assert_eq!(summary.recent_blockhash, [5; 32]);
    assert_eq!(summary.instructions.len(), 4);
    assert_eq!(summary.instructions[0], InstructionSummary::SetComputeUnitLimit { units: 200_000 });
    assert_eq!(
        summary.instructions[1],
        InstructionSummary::SystemTransfer { from: payer, to: [9; 32], lamports: 1_000 }
    );
    // An approval with no practical limit is flagged as one.
    assert_eq!(
        summary.instructions[2],
        InstructionSummary::SplApprove {
            program: TOKEN_PROGRAM,
            source: [1; 32],
            delegate: [2; 32],
            owner: payer,
            mint: Some([3; 32]),
            amount: u64::MAX,
            decimals: Some(6),
            unlimited: true,
        }
    );
    // A program the wallet does not know is reported with everything it is
    // given, never skipped.
    let InstructionSummary::Unknown { program, accounts, data } = &summary.instructions[3] else {
        panic!("an unknown program");
    };
    assert_eq!(*program, [4; 32]);
    assert_eq!(data, &[0xde, 0xad]);
    assert_eq!(
        accounts,
        &[AccountMeta::writable(payer, true), AccountMeta::readonly([3; 32], false)]
    );
}

#[test]
fn what_the_wallet_builds_it_summarises_the_same_way() {
    let (from, to, mint) = (wallet_pubkey(), [9; 32], [8; 32]);
    let sol = build_sol_transfer(&SolTransfer {
        from,
        to,
        lamports: 5,
        recent_blockhash: [1; 32],
        priority: Some(Priority { compute_unit_limit: 7, compute_unit_price_micro_lamports: 9 }),
    })
    .unwrap();
    assert_eq!(
        summarize_transaction(&sol, &[]).unwrap().instructions,
        [
            InstructionSummary::SetComputeUnitLimit { units: 7 },
            InstructionSummary::SetComputeUnitPrice { micro_lamports: 9 },
            InstructionSummary::SystemTransfer { from, to, lamports: 5 },
        ]
    );
    let spl = build_spl_transfer(&SplTransfer {
        owner: from,
        mint,
        decimals: 6,
        amount: 123,
        recipient: to,
        source: None,
        recipient_token_account_exists: false,
        recent_blockhash: [1; 32],
        priority: None,
    })
    .unwrap();
    let source = associated_token_account(&from, &mint).unwrap();
    let destination = associated_token_account(&to, &mint).unwrap();
    assert_eq!(
        summarize_transaction(&spl, &[]).unwrap().instructions,
        [
            InstructionSummary::CreateAssociatedTokenAccount {
                payer: from,
                account: destination,
                owner: to,
                mint,
                idempotent: true,
            },
            InstructionSummary::SplTransfer {
                program: TOKEN_PROGRAM,
                source,
                destination,
                authority: from,
                mint: Some(mint),
                amount: 123,
                decimals: Some(6),
            },
        ]
    );
}

#[test]
fn bytes_that_are_not_a_transaction_are_refused_never_guessed_at() {
    let bytes = site_transaction(wallet_pubkey());
    // Cut anywhere, or with anything after: refused.
    for cut in 0..bytes.len() {
        assert!(summarize_transaction(&bytes[..cut], &[]).is_err(), "cut at {cut}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(summarize_transaction(&longer, &[]).is_err());
    // Every other single-byte change either is refused or still reads as a
    // transaction; none panics.
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 0xff;
        let _ = summarize_transaction(&changed, &[]);
    }
    // Arbitrary bytes never panic either.
    let mut state = 1u64;
    for length in 0..300 {
        let junk: Vec<u8> = (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 56) as u8
            })
            .collect();
        let _ = summarize_transaction(&junk, &[]);
        let _ = ParsedMessage::parse(&junk);
    }
    assert!(summarize_transaction(&[], &[]).is_err());
}

#[test]
fn a_message_that_breaks_the_runtimes_rules_is_refused() {
    let payer = wallet_pubkey();
    let good = compile(&payer, &[system_transfer(payer, [9; 32], 1)], &[5; 32]).unwrap();
    assert!(ParsedMessage::parse(&good).is_ok());

    let change = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut message = good.clone();
        edit(&mut message);
        ParsedMessage::parse(&message)
    };
    // Header: no signer; the fee payer read-only; more read-only accounts than there are.
    assert!(change(&|m| m[0] = 0).is_err());
    assert!(change(&|m| m[1] = 1).is_err());
    assert!(change(&|m| m[2] = 3).is_err());
    // A program that is the fee payer (index 0), or past the keys.
    let program_index_at = 3 + 1 + 3 * 32 + 32 + 1;
    assert_eq!(good[program_index_at], 2, "the system program");
    assert!(change(&|m| m[program_index_at] = 0).is_err());
    assert!(change(&|m| m[program_index_at] = 3).is_err());
    // An account index past the keys.
    assert!(change(&|m| m[program_index_at + 2] = 3).is_err());
    // The same key twice.
    assert!(
        change(&|m| {
            let (first, second) = (4, 4 + 32);
            let copy = m[first..first + 32].to_vec();
            m[second..second + 32].copy_from_slice(&copy);
        })
        .is_err()
    );
    // A version this wallet does not read.
    assert_eq!(change(&|m| m[0] = 0x81), Err(MessageError::UnsupportedVersion(1)));
    assert_eq!(change(&|m| m[0] = 0xff), Err(MessageError::UnsupportedVersion(127)));
    // A transaction whose signature slots do not match its header.
    let mut two_slots = transaction(&[[0; 64], [0; 64]], &good);
    assert!(ParsedTransaction::parse(&two_slots).is_err());
    two_slots = transaction(&[], &good);
    assert!(ParsedTransaction::parse(&two_slots).is_err());
}

// ---- signing ---------------------------------------------------------------------------

#[test]
fn a_transaction_is_signed_in_the_slot_of_its_key() {
    let key = wallet_key();
    let payer = wallet_pubkey();
    let unsigned = site_transaction(payer);
    let signed = sign_transaction(&key, &unsigned).unwrap();
    let parsed = ParsedTransaction::parse(&signed.transaction).unwrap();
    assert_eq!(parsed.signatures, vec![signed.signature]);
    assert_eq!(parsed.message_bytes, ParsedTransaction::parse(&unsigned).unwrap().message_bytes);
    assert!(verifies(&payer, &parsed.message_bytes, &signed.signature));
    assert_eq!(signed.id(), bs58::encode(signed.signature).into_string());
    // Signing is deterministic (RFC 8032), and signing a signed transaction
    // again changes nothing.
    assert_eq!(sign_transaction(&key, &unsigned).unwrap(), signed);
    assert_eq!(sign_transaction(&key, &signed.transaction).unwrap(), signed);
    // Another key is not a signer; neither is a key of another scheme.
    assert_eq!(
        sign_transaction(&SigningKey::ed25519(&[8; 32]), &unsigned),
        Err(SolanaError::NotASigner)
    );
    assert_eq!(
        sign_transaction(&SigningKey::sr25519(&[7; 32]).unwrap(), &unsigned),
        Err(SolanaError::WrongKeyScheme)
    );
    assert_eq!(
        sign_transaction(&SigningKey::secp256k1(&[7; 32]).unwrap(), &unsigned),
        Err(SolanaError::WrongKeyScheme)
    );
    // Bytes that are not a transaction are not signed.
    assert!(matches!(sign_transaction(&key, &unsigned[..70]), Err(SolanaError::Message(_))));
}

#[test]
fn sign_message_signs_raw_bytes_and_refuses_a_transaction() {
    let key = wallet_key();
    let payer = wallet_pubkey();
    // ed25519 over exactly the bytes, no prefix: RFC 8032 section 7.1, "TEST 1"
    // (the empty message) and "TEST 3" (the two bytes af82), keys and
    // signatures as the RFC prints them.
    for (secret, public, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ] {
        let signer = SigningKey::ed25519(&hex::decode(secret).unwrap().try_into().unwrap());
        assert_eq!(hex::encode(signer.public_key()), public);
        let bytes = hex::decode(message).unwrap();
        // The first is neither a transaction nor a message the wallet refuses.
        assert_eq!(hex::encode(sign_message(&signer, &bytes).unwrap()), signature);
    }
    let signature = sign_message(&key, b"Sign in to nowcoin.xyz").unwrap();
    assert!(verifies(&payer, b"Sign in to nowcoin.xyz", &signature));

    // A transaction's message, a whole transaction, a version-0 message: refused.
    let unsigned = site_transaction(payer);
    let message = ParsedTransaction::parse(&unsigned).unwrap().message_bytes;
    assert_eq!(sign_message(&key, &message), Err(SolanaError::LooksLikeTransaction));
    assert_eq!(sign_message(&key, &unsigned), Err(SolanaError::LooksLikeTransaction));
    let mut v0 = vec![VERSION_0];
    v0.extend_from_slice(&message);
    v0.push(0); // no lookup tables
    assert!(ParsedMessage::parse(&v0).is_ok());
    assert_eq!(sign_message(&key, &v0), Err(SolanaError::LooksLikeTransaction));
    assert_eq!(
        sign_message(&SigningKey::sr25519(&[7; 32]).unwrap(), b"hello"),
        Err(SolanaError::WrongKeyScheme)
    );
}

// ---- building --------------------------------------------------------------------------

#[test]
fn the_builders_refuse_nothing_and_the_zero_amounts() {
    let (from, to, mint) = (wallet_pubkey(), [9; 32], [8; 32]);
    assert_eq!(
        build_sol_transfer(&SolTransfer {
            from,
            to,
            lamports: 0,
            recent_blockhash: [1; 32],
            priority: None
        }),
        Err(SolanaError::ZeroAmount)
    );
    let spl = SplTransfer {
        owner: from,
        mint,
        decimals: 6,
        amount: 0,
        recipient: to,
        source: None,
        recipient_token_account_exists: true,
        recent_blockhash: [1; 32],
        priority: None,
    };
    assert_eq!(build_spl_transfer(&spl), Err(SolanaError::ZeroAmount));
    // The amounts at the edges are fine.
    assert!(
        build_sol_transfer(&SolTransfer {
            from,
            to,
            lamports: u64::MAX,
            recent_blockhash: [1; 32],
            priority: None
        })
        .is_ok()
    );
    assert!(build_spl_transfer(&SplTransfer { amount: u64::MAX, ..spl.clone() }).is_ok());
    // The built transaction is small, unsigned, and fits the network's limit.
    let built = build_spl_transfer(&SplTransfer {
        amount: 1,
        recipient_token_account_exists: false,
        ..spl
    })
    .unwrap();
    assert!(built.len() < MAX_TRANSACTION_SIZE);
    assert_eq!(&built[..65], &[[1u8].as_slice(), &[0u8; 64]].concat()[..]);
}

#[test]
fn addresses_read_and_write_as_base58() {
    // Phantom's and the SDK's examples are 32 bytes in base58; anything else is not.
    let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let parsed = parse_address(usdc).unwrap();
    assert_eq!(address(&parsed), usdc);
    // (Base58 has no checksum, so one wrong letter is another address; only a
    // wrong length is caught.)
    for bad in [
        "",
        "0",
        "O",
        usdc.get(..40).unwrap(),
        &format!("{usdc}1111"),
        "11111111111111111111111111111111111111111111111111",
    ] {
        assert_eq!(parse_address(bad), None, "{bad:?}");
    }
    assert_eq!(parse_address("11111111111111111111111111111111"), Some(SYSTEM_PROGRAM));
}

#[test]
fn a_sites_message_must_be_text_and_not_a_transaction() {
    use super::check_message;
    let payer = wallet_pubkey();
    assert_eq!(check_message(b"Sign in to nowcoin.xyz"), Ok(()));
    assert_eq!(
        check_message("日本語のメッセージ".as_bytes()),
        Ok(()),
        "a non-ASCII first byte is fine in text"
    );
    assert_eq!(check_message(&[]), Ok(()));
    // Not UTF-8: refused, including every first byte a versioned message could start with.
    for first in [0x80_u8, 0x81, 0x90, 0xBF, 0xC0, 0xFF] {
        assert_eq!(check_message(&[first, 1, 2, 3]), Err(SolanaError::NotText), "{first:x}");
    }
    assert_eq!(check_message(&[0xaf, 0x82]), Err(SolanaError::NotText));
    // A transaction, its message, a version-0 message: still a transaction.
    let unsigned = site_transaction(payer);
    let message = ParsedTransaction::parse(&unsigned).unwrap().message_bytes;
    assert_eq!(check_message(&unsigned), Err(SolanaError::LooksLikeTransaction));
    assert_eq!(check_message(&message), Err(SolanaError::LooksLikeTransaction));
}
