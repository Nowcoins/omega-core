//! Tests. The host ones check the JSON the JavaScript side parses; the
//! `wasm_bindgen_test` ones (run in Node by `wasm-bindgen-test-runner`, see
//! `scripts/test-wasm.sh`) drive the whole engine as the service worker does,
//! with the browser's own randomness and the real Argon2id cost.
//!
//! The recovery phrase is the BIP-39 reference vector (entropy all zero).

#![allow(clippy::unwrap_used)]

use super::*;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The reference phrase sealed by the native build under
/// [`FIXTURE_PASSWORD`]: the WebAssembly build must open it.
const NATIVE_VAULT: &[u8] = include_bytes!("../tests/fixtures/native.vault");
/// The same phrase sealed by the WebAssembly build: the native build must open
/// it (`tests/cross_format.rs`).
#[allow(dead_code)]
const WASM_VAULT: &[u8] = include_bytes!("../tests/fixtures/wasm.vault");
const FIXTURE_PASSWORD: &str = "cross-format fixture password";

/// A `personal_sign` of "hello" by the reference phrase's first EVM account, and the signature it makes.
/// The signature was worked out apart from this code: RFC 6979 over secp256k1 with HMAC-SHA256, and a
/// Keccak-256 of the prefixed message, in plain Python integers (whose key gave the address
/// `0x9858...da94`). ECDSA here is deterministic, so the native build (64-bit arithmetic) and
/// WebAssembly (32-bit arithmetic) must both make exactly these bytes.
const PERSONAL_SIGN_HELLO: &str = r#"{"kind":"evm_personal_sign","message_hex":"0x68656c6c6f"}"#;
const PERSONAL_SIGN_HELLO_SIGNATURE: &str = "0x22f6b9cd7ff4f321e11181c4fe64adeea9469908fb514fbb6001fe022002dfda1f4ec9ea436bad14a7823806487d3aeb39b22e2556590922d6a8308971a17e991c";

#[cfg(not(target_arch = "wasm32"))]
mod host {
    use super::*;
    use nc_wallet_session::{NetworkAccount, NetworkId};

    #[test]
    fn accounts_are_json_with_the_api_ids() {
        let accounts = vec![
            NetworkAccount {
                network: NetworkId::BnbChain,
                address: "0xabc".to_owned(),
                public_key_hex: "02ff".to_owned(),
                path: "m/44'/60'/0'/0/0".to_owned(),
            },
            NetworkAccount {
                network: NetworkId::Bittensor,
                address: "5Grw".to_owned(),
                public_key_hex: "d435".to_owned(),
                path: String::new(),
            },
        ];
        assert_eq!(
            json::accounts(&accounts).to_string(),
            r#"[{"network":"bsc","address":"0xabc","publicKeyHex":"02ff","path":"m/44'/60'/0'/0/0"},{"network":"bittensor","address":"5Grw","publicKeyHex":"d435","path":""}]"#
        );
    }

    #[test]
    fn one_account_is_the_same_json_as_one_of_the_list() {
        let account = NetworkAccount {
            network: NetworkId::Solana,
            address: "2bUB".to_owned(),
            public_key_hex: "ab".to_owned(),
            path: "m/44'/501'/0'".to_owned(),
        };
        assert_eq!(
            json::account(&account).to_string(),
            r#"{"network":"solana","address":"2bUB","publicKeyHex":"ab","path":"m/44'/501'/0'"}"#
        );
        assert_eq!(json::accounts(std::slice::from_ref(&account))[0], json::account(&account));
    }

    #[test]
    fn a_phrase_check_names_its_problem_in_camel_case() {
        let check = session::check_phrase("abandon abandn");
        assert_eq!(
            json::phrase_check(&check).to_string(),
            r#"{"problem":"unknownWord","wordCount":2,"position":2,"suggestions":["abandon"]}"#
        );
        let valid = session::check_phrase(ABANDON);
        assert_eq!(json::phrase_check(&valid)["problem"], "valid");
        assert_eq!(json::phrase_check(&valid)["wordCount"], 12);
    }

    #[test]
    fn the_quiz_and_the_vault_header_are_json() {
        let questions = vec![session::BackupQuestion {
            position: 7,
            choices: vec!["a".to_owned(), "b".to_owned()],
        }];
        assert_eq!(
            json::questions(&questions).to_string(),
            r#"[{"position":7,"choices":["a","b"]}]"#
        );
        let facts = session::vault_facts(NATIVE_VAULT).unwrap();
        assert_eq!(
            json::vault_facts(&facts).to_string(),
            r#"{"version":1,"memoryKib":65536,"iterations":3,"lanes":1}"#
        );
    }

    #[test]
    fn signing_answers_are_json_with_the_hash_in_hex() {
        let decoded = nc_wallet_session::Decoded {
            summary: serde_json::json!({ "request": "evm_personal_sign", "warnings": [] }),
            approval: [0xab; 32],
        };
        let value = json::decoded(&decoded);
        assert_eq!(value["approval"], "ab".repeat(32));
        assert_eq!(value["summary"]["request"], "evm_personal_sign");

        let found =
            session::validate_address("ethereum", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert_eq!(
            json::address_check(&found).to_string(),
            r#"{"valid":true,"normalized":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","reason":null}"#
        );
        let bad = session::validate_address("tron", "nope");
        assert_eq!(
            json::address_check(&bad).to_string(),
            r#"{"valid":false,"normalized":null,"reason":"format"}"#
        );
    }

    #[test]
    fn the_approval_is_exactly_64_hex_digits() {
        let text = "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD";
        assert_eq!(text.len(), 64);
        let parsed = json::parse_approval(text).unwrap();
        assert_eq!(parsed[0], 0x01);
        assert_eq!(parsed[31], 0xcd);
        assert_eq!(json::hex(&parsed), text.to_lowercase());
        for bad in [
            "",
            "ab",
            &text[..63],
            &format!("{text}0"),
            &text.replace('0', "g"),
            &format!(" {}", &text[1..]),
        ] {
            assert!(json::parse_approval(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn signing_runs_on_the_host_build_too() {
        // The same calls the service worker makes, natively: the reference
        // phrase, a personal_sign, then a request that is not the approved one.
        let mut engine = WalletEngine::new();
        engine
            .inner
            .unlock_with_password(NATIVE_VAULT, &Zeroizing::new(FIXTURE_PASSWORD.to_owned()))
            .unwrap();
        let request = PERSONAL_SIGN_HELLO;
        let decoded = engine.inner.decode_request(0, request).unwrap();
        assert_eq!(decoded.summary["signer"], "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        let signed = engine.inner.sign_request(0, request, &decoded.approval).unwrap();
        assert_eq!(signed["signature"], PERSONAL_SIGN_HELLO_SIGNATURE);
        let other = r#"{"kind":"evm_personal_sign","message_hex":"0x68656c6c6f21"}"#;
        assert_eq!(
            engine.inner.sign_request(0, other, &decoded.approval).unwrap_err().code(),
            "ApprovalMismatch"
        );
        engine.lock();
        assert_eq!(engine.inner.decode_request(0, request).unwrap_err().code(), "NotUnlocked");
    }

    #[test]
    fn the_fixtures_are_vaults_of_the_reference_phrase_in_both_directions() {
        // Natively: both the vault the native build sealed and the one the
        // WebAssembly build sealed open to the reference phrase.
        for blob in [NATIVE_VAULT, WASM_VAULT] {
            let password = Zeroizing::new(FIXTURE_PASSWORD.to_owned());
            let words = session::reveal_phrase(blob, &password).unwrap();
            assert_eq!(words.join(" "), ABANDON);
            let facts = session::vault_facts(blob).unwrap();
            assert_eq!((facts.version, facts.memory_kib, facts.iterations), (1, 65_536, 3));
        }
        assert_ne!(NATIVE_VAULT, WASM_VAULT);
    }

    #[test]
    fn the_extension_seals_heavier_and_still_opens_a_vault_of_the_phone_parameters() {
        assert_eq!(SEAL_PARAMS, VaultParams::EXTENSION);
        let password = Zeroizing::new(FIXTURE_PASSWORD.to_owned());
        // The native fixture is a 64 MiB vault, as every extension vault was
        // before: the engine opens it with the parameters in its header.
        let mut engine = WalletEngine::new();
        engine.inner.unlock_with_password(NATIVE_VAULT, &password).unwrap();
        let accounts = engine.inner.accounts(0).unwrap();
        engine.lock();

        // Re-sealed under the same password, as the worker does after an unlock.
        let (renewed, key) =
            session::change_password_keeping_key(NATIVE_VAULT, &password, &password, SEAL_PARAMS)
                .unwrap();
        let facts = session::vault_facts(&renewed).unwrap();
        assert_eq!(
            (facts.memory_kib, facts.iterations, facts.lanes),
            (SEAL_PARAMS.memory_kib(), SEAL_PARAMS.iterations(), SEAL_PARAMS.lanes())
        );
        // The check the worker makes before it stores the new vault: no wallet is touched.
        check_unlock_key(&renewed, key.clone()).unwrap();
        assert!(!engine.is_unlocked());
        engine.unlock_with_key(&renewed, key).unwrap();
        assert_eq!(engine.inner.accounts(0).unwrap(), accounts);
        engine.lock();

        // A new wallet is sealed with the extension's parameters.
        engine.start_import(ABANDON.to_owned(), String::new()).unwrap();
        let blob = engine.inner.seal_pending(FIXTURE_PASSWORD).unwrap();
        assert_eq!(session::vault_facts(&blob).unwrap().memory_kib, SEAL_PARAMS.memory_kib());
        let thrown = session::vault_facts(&throwaway_vault().unwrap()).unwrap();
        assert_eq!(thrown.memory_kib, SEAL_PARAMS.memory_kib());
    }

    #[test]
    fn the_extension_opens_no_vault_that_asks_for_more_than_its_limits() {
        assert_eq!(OPEN_LIMITS, VaultLimits::EXTENSION);
        assert_eq!(
            (OPEN_LIMITS.max_memory_kib(), OPEN_LIMITS.max_iterations(), OPEN_LIMITS.max_lanes()),
            (512 * 1024, 10, 1)
        );
        // What it seals, and the native fixture (the phone's 64 MiB), are within.
        assert!(OPEN_LIMITS.admits(&SEAL_PARAMS));
        assert!(OPEN_LIMITS.admits(&VaultParams::PHONE));
        let engine = WalletEngine::new();
        assert_eq!(engine.inner.open_limits(), OPEN_LIMITS);

        // The native fixture with a header raised past them, one field at a time.
        let password = Zeroizing::new(FIXTURE_PASSWORD.to_owned());
        let started = std::time::Instant::now();
        for (range, value) in [(6..10, 512 * 1024 + 1), (10..14, 11), (14..18, 2)] {
            let mut hostile = NATIVE_VAULT.to_vec();
            hostile[range].copy_from_slice(&u32::to_be_bytes(value));
            let refused = Some(SessionError::NotAVault);
            assert_eq!(session::vault_facts_within(&hostile, OPEN_LIMITS).err(), refused);
            assert_eq!(
                session::open_with_password_keeping_key_within(&hostile, &password, OPEN_LIMITS)
                    .err(),
                refused
            );
            assert_eq!(
                session::reveal_phrase_within(&hostile, &password, OPEN_LIMITS).err(),
                refused
            );
            // The phone's ceiling would read it.
            assert!(session::vault_facts(&hostile).is_ok());
        }
        assert!(started.elapsed().as_millis() < 1000, "refusing took {:?}", started.elapsed());
    }
}

#[cfg(target_arch = "wasm32")]
mod in_wasm {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn code_of(error: &JsValue) -> String {
        Reflect::get(error, &JsValue::from_str("code")).unwrap().as_string().unwrap()
    }

    fn name_of(error: &JsValue) -> String {
        Reflect::get(error, &JsValue::from_str("name")).unwrap().as_string().unwrap()
    }

    fn field(value: &JsValue, name: &str) -> JsValue {
        Reflect::get(value, &JsValue::from_str(name)).unwrap()
    }

    fn list(value: &JsValue) -> Vec<JsValue> {
        js_sys::Array::from(value).iter().collect()
    }

    fn account<'a>(accounts: &'a [JsValue], network: &str) -> &'a JsValue {
        accounts
            .iter()
            .find(|a| field(a, "network").as_string().as_deref() == Some(network))
            .unwrap()
    }

    /// Passes the quiz of the wallet being made, the way the UI does: it is
    /// shown choices and picks; the engine checks. (Here the test knows the
    /// words, as the backup screen does.)
    fn pass_the_quiz(engine: &mut WalletEngine) -> Vec<String> {
        let words = engine.pending_words().unwrap();
        let count = list(&engine.backup_questions().unwrap()).len();
        for slot in 0..count {
            let read = |engine: &mut WalletEngine| {
                let question = list(&engine.backup_questions().unwrap())[slot].clone();
                let position = field(&question, "position")
                    .as_f64()
                    .unwrap()
                    .to_string()
                    .parse::<u32>()
                    .unwrap();
                let choices: Vec<String> = list(&field(&question, "choices"))
                    .iter()
                    .map(|c| c.as_string().unwrap())
                    .collect();
                assert_eq!(choices.len(), 6);
                (position, choices)
            };
            let (position, choices) = read(engine);
            let right = &words[position as usize - 1];
            let wrong = choices.iter().find(|c| *c != right).unwrap();
            assert!(!engine.check_backup_answer(position, wrong.clone()).unwrap());
            // A wrong answer draws the question again (another word, new choices): ask again.
            let (position, _) = read(engine);
            let right = &words[position as usize - 1];
            assert!(engine.check_backup_answer(position, right.clone()).unwrap());
        }
        words
    }

    #[wasm_bindgen_test]
    fn a_vault_that_asks_for_more_than_the_extension_runs_is_not_a_vault() {
        // The native fixture, its header asking for 1 GiB: every way in refuses it before Argon2id.
        let mut hostile = NATIVE_VAULT.to_vec();
        hostile[6..10].copy_from_slice(&u32::to_be_bytes(1024 * 1024));
        let password = || FIXTURE_PASSWORD.to_owned();
        let mut engine = WalletEngine::new();
        assert_eq!(code_of(&vault_facts(&hostile).unwrap_err()), "NotAVault");
        assert_eq!(
            code_of(&engine.unlock_with_password(&hostile, password()).unwrap_err()),
            "NotAVault"
        );
        assert_eq!(
            code_of(&engine.unlock_with_key(&hostile, vec![1; 32]).unwrap_err()),
            "NotAVault"
        );
        assert_eq!(code_of(&reveal_phrase(&hostile, password()).unwrap_err()), "NotAVault");
        assert_eq!(code_of(&export_unlock_key(&hostile, password()).unwrap_err()), "NotAVault");
        assert_eq!(
            code_of(&change_password(&hostile, password(), password()).unwrap_err()),
            "NotAVault"
        );
        assert_eq!(code_of(&check_unlock_key(&hostile, vec![1; 32]).unwrap_err()), "NotAVault");
        assert_eq!(code_of(&open_throwaway_vault(&hostile).unwrap_err()), "NotAVault");
        assert!(!engine.is_unlocked());
    }

    #[wasm_bindgen_test]
    fn a_vault_the_native_build_sealed_opens_in_wasm() {
        let mut engine = WalletEngine::new();
        let key = engine.unlock_with_password(NATIVE_VAULT, FIXTURE_PASSWORD.to_owned()).unwrap();
        assert_eq!(key.len(), 32);
        assert!(engine.is_unlocked());
        // The vault key opens it too, with no Argon2id.
        engine.lock();
        engine.unlock_with_key(NATIVE_VAULT, key).unwrap();
        let words = reveal_phrase(NATIVE_VAULT, FIXTURE_PASSWORD.to_owned()).unwrap();
        assert_eq!(words.join(" "), ABANDON);
    }

    #[wasm_bindgen_test]
    fn a_cache_is_sealed_and_opened_only_by_the_unlocked_wallet() {
        let mut engine = WalletEngine::new();
        assert_eq!(
            code_of(&engine.seal_cache("history/a".to_owned(), b"x").unwrap_err()),
            "NotUnlocked"
        );
        engine.unlock_with_password(NATIVE_VAULT, FIXTURE_PASSWORD.to_owned()).unwrap();

        let blob = engine.seal_cache("history/a".to_owned(), b"{\"v\":1}").unwrap();
        assert_eq!(&blob[..5], b"NCWC\x01");
        assert_eq!(
            engine.open_cache("history/a".to_owned(), &blob).unwrap().unwrap(),
            b"{\"v\":1}"
        );
        // Another label opens nothing; a damaged blob opens nothing.
        assert!(engine.open_cache("history/b".to_owned(), &blob).unwrap().is_none());
        assert!(engine.open_cache("history/a".to_owned(), &blob[1..]).unwrap().is_none());
        // The name to store it under is 24 hex characters and the same every time.
        let id = engine.cache_id("history/a".to_owned()).unwrap();
        assert_eq!(id.len(), 24);
        assert_eq!(id, engine.cache_id("history/a".to_owned()).unwrap());
        // Locked: nothing opens.
        engine.lock();
        assert_eq!(
            code_of(&engine.open_cache("history/a".to_owned(), &blob).unwrap_err()),
            "NotUnlocked"
        );
    }

    #[wasm_bindgen_test]
    fn a_vault_sealed_in_wasm_has_the_same_format() {
        let mut engine = WalletEngine::new();
        engine.start_import(ABANDON.to_owned(), String::new()).unwrap();
        let blob = engine.seal_pending(FIXTURE_PASSWORD.to_owned()).unwrap();
        let facts = vault_facts(&blob).unwrap();
        assert_eq!(field(&facts, "version").as_f64(), Some(1.0));
        // The extension's parameters (`SEAL_PARAMS`), heavier than the native fixture's.
        assert_eq!(field(&facts, "memoryKib").as_f64(), Some(262_144.0));
        assert_eq!(field(&facts, "iterations").as_f64(), Some(3.0));
        assert_eq!(field(&facts, "lanes").as_f64(), Some(1.0));
        // Same length as the native build's (padding hides the phrase length).
        assert_eq!(blob.len(), NATIVE_VAULT.len());
        assert_eq!(&blob[..5], &NATIVE_VAULT[..5]);
        // And the wasm vault committed as a fixture is of this format.
        assert_eq!(WASM_VAULT.len(), NATIVE_VAULT.len());
    }

    #[wasm_bindgen_test]
    fn make_back_up_seal_lock_and_unlock() {
        let mut engine = WalletEngine::new();
        assert!(!engine.has_pending());
        assert_eq!(code_of(&engine.pending_words().unwrap_err()), "NoPendingWallet");

        engine.start_new(12).unwrap();
        assert!(engine.has_pending());
        assert_eq!(engine.pending_word_count().unwrap(), 12);
        // Not sealed before the backup check.
        assert_eq!(
            code_of(&engine.seal_pending("a good password".to_owned()).unwrap_err()),
            "BackupNotConfirmed"
        );
        let words = pass_the_quiz(&mut engine);
        assert_eq!(words.len(), 12);
        // An empty password is refused and keeps the wallet.
        assert_eq!(code_of(&engine.seal_pending(String::new()).unwrap_err()), "EmptyPassword");
        assert!(engine.has_pending());

        let blob = engine.seal_pending("a good password".to_owned()).unwrap();
        // Sealed, not stored: locked, still pending. Commit after storing.
        assert!(!engine.is_unlocked());
        assert!(engine.has_pending());
        engine.commit_pending().unwrap();
        assert!(engine.is_unlocked());
        assert!(!engine.has_pending());
        let key = engine.take_new_unlock_key().unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(code_of(&engine.take_new_unlock_key().unwrap_err()), "NoNewKey");
        assert_eq!(key, export_unlock_key(&blob, "a good password".to_owned()).unwrap());

        let accounts = list(&engine.derive_accounts(0).unwrap());
        assert_eq!(accounts.len(), 9);
        engine.lock();
        assert_eq!(code_of(&engine.derive_accounts(0).unwrap_err()), "NotUnlocked");

        // The key reopens it without the password; a wrong one does not.
        engine.unlock_with_key(&blob, key.clone()).unwrap();
        assert_eq!(list(&engine.derive_accounts(0).unwrap()).len(), 9);
        engine.lock();
        assert_eq!(
            code_of(&engine.unlock_with_key(&blob, vec![0; 32]).unwrap_err()),
            "WrongPassword"
        );
        assert_eq!(
            code_of(&engine.unlock_with_key(&blob, vec![0; 3]).unwrap_err()),
            "WrongPassword"
        );
        assert_eq!(
            code_of(&engine.unlock_with_password(&blob, "nope".to_owned()).unwrap_err()),
            "WrongPassword"
        );
        assert!(!engine.is_unlocked());
        let again = engine.unlock_with_password(&blob, "a good password".to_owned()).unwrap();
        assert_eq!(again, key);

        // Settings: the phrase after the password, a new password.
        assert_eq!(reveal_phrase(&blob, "a good password".to_owned()).unwrap(), words);
        assert_eq!(code_of(&reveal_phrase(&blob, "nope".to_owned()).unwrap_err()), "WrongPassword");
        let changed =
            change_password(&blob, "a good password".to_owned(), "another password".to_owned())
                .unwrap();
        let renewed = js_sys::Uint8Array::from(field(&changed, "vault")).to_vec();
        let new_key = js_sys::Uint8Array::from(field(&changed, "key")).to_vec();
        assert_eq!(new_key, export_unlock_key(&renewed, "another password".to_owned()).unwrap());
        assert_ne!(new_key, key);
        engine.lock();
        assert_eq!(
            code_of(
                &engine.unlock_with_password(&renewed, "a good password".to_owned()).unwrap_err()
            ),
            "WrongPassword"
        );
        engine.unlock_with_password(&renewed, "another password".to_owned()).unwrap();
        // Garbage is not a vault.
        assert_eq!(code_of(&vault_facts(b"nonsense").unwrap_err()), "NotAVault");
    }

    #[wasm_bindgen_test]
    fn the_reference_phrase_gives_the_reference_addresses() {
        let mut engine = WalletEngine::new();
        engine.start_import(ABANDON.to_owned(), String::new()).unwrap();
        engine.seal_pending("a good password".to_owned()).unwrap();
        engine.commit_pending().unwrap();
        let accounts = list(&engine.derive_accounts(0).unwrap());
        let networks: Vec<String> =
            accounts.iter().map(|a| field(a, "network").as_string().unwrap()).collect();
        assert_eq!(
            networks,
            [
                "ethereum",
                "bsc",
                "polygon",
                "base",
                "tron",
                "bitcoin",
                "solana",
                "stellar",
                "bittensor"
            ]
        );
        // MetaMask and Trust Wallet show this address for this phrase.
        assert_eq!(
            field(account(&accounts, "ethereum"), "address").as_string().unwrap(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(
            field(account(&accounts, "base"), "address").as_string().unwrap(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        // BIP-84's first receive address.
        assert_eq!(
            field(account(&accounts, "bitcoin"), "address").as_string().unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(field(account(&accounts, "bittensor"), "path").as_string().unwrap(), "");
        assert_eq!(
            code_of(&engine.derive_accounts(1 << 31).unwrap_err()),
            "AccountIndexOutOfRange"
        );
    }

    #[wasm_bindgen_test]
    fn trust_wallets_solana_account_is_found_while_importing_and_when_unlocked() {
        // Trust Wallet Core's own phrase and the address it shows for Solana.
        let phrase =
            "shoot island position soft burden budget tooth cruel issue economy destroy above";
        let mut engine = WalletEngine::new();
        assert_eq!(
            code_of(&engine.derive_trust_wallet_solana_account().unwrap_err()),
            "NotUnlocked"
        );
        engine.start_import(phrase.to_owned(), String::new()).unwrap();
        let found = engine.derive_trust_wallet_solana_account().unwrap();
        assert_eq!(field(&found, "network").as_string().unwrap(), "solana");
        assert_eq!(
            field(&found, "address").as_string().unwrap(),
            "2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m"
        );
        assert_eq!(field(&found, "path").as_string().unwrap(), "m/44'/501'/0'");
        // The wallet's own Solana account is at Phantom's path and is not this one.
        engine.seal_pending("a good password".to_owned()).unwrap();
        engine.commit_pending().unwrap();
        let own = list(&engine.derive_accounts(0).unwrap());
        let own = account(&own, "solana");
        assert_eq!(field(own, "path").as_string().unwrap(), "m/44'/501'/0'/0'");
        assert_ne!(field(own, "address").as_string(), field(&found, "address").as_string());
    }

    #[wasm_bindgen_test]
    fn typed_phrases_are_checked_and_words_complete() {
        let found = check_phrase("abandon abandn".to_owned()).unwrap();
        assert_eq!(field(&found, "problem").as_string().unwrap(), "unknownWord");
        assert_eq!(field(&found, "position").as_f64(), Some(2.0));
        let suggestions: Vec<String> =
            list(&field(&found, "suggestions")).iter().map(|s| s.as_string().unwrap()).collect();
        assert_eq!(suggestions, ["abandon"]);
        assert_eq!(
            field(&check_phrase(ABANDON.to_owned()).unwrap(), "problem").as_string().unwrap(),
            "valid"
        );
        assert_eq!(
            field(&check_phrase(["abandon"; 12].join(" ")).unwrap(), "problem")
                .as_string()
                .unwrap(),
            "badChecksum"
        );
        assert_eq!(complete_word("aba".to_owned(), 5), ["abandon"]);
        // Importing a bad phrase is refused with a code, and keeps nothing.
        let mut engine = WalletEngine::new();
        assert_eq!(
            code_of(&engine.start_import("abandon abandon".to_owned(), String::new()).unwrap_err()),
            "InvalidPhrase"
        );
        assert!(!engine.has_pending());
    }

    #[wasm_bindgen_test]
    fn bad_arguments_and_errors_are_named() {
        let mut engine = WalletEngine::new();
        let error = engine.start_new(13).unwrap_err();
        assert_eq!(code_of(&error), "BadArgument");
        assert_eq!(name_of(&error), "WalletError");
        engine.start_new(24).unwrap();
        assert_eq!(engine.pending_word_count().unwrap(), 24);
        assert_eq!(engine.pending_words().unwrap().len(), 24);
        engine.discard_pending();
        assert!(!engine.has_pending());
        // No error message carries a word.
        let error = engine.pending_words().unwrap_err();
        let message = field(&error, "message").as_string().unwrap();
        assert!(!message.contains("abandon"));
    }

    #[wasm_bindgen_test]
    fn new_phrases_use_the_browsers_randomness() {
        let mut engine = WalletEngine::new();
        engine.start_new(12).unwrap();
        let a = engine.pending_words().unwrap();
        engine.start_new(12).unwrap();
        let b = engine.pending_words().unwrap();
        assert_ne!(a, b);
        // A real phrase: every word is in the list, so the checker accepts it.
        let check = check_phrase(b.join(" ")).unwrap();
        assert_eq!(field(&check, "problem").as_string().unwrap(), "valid");
    }

    fn unlocked_reference_engine() -> WalletEngine {
        let mut engine = WalletEngine::new();
        engine.start_import(ABANDON.to_owned(), String::new()).unwrap();
        engine.seal_pending("a good password".to_owned()).unwrap();
        engine.commit_pending().unwrap();
        engine
    }

    #[wasm_bindgen_test]
    fn a_request_is_decoded_and_signed_in_wasm() {
        let engine = unlocked_reference_engine();
        let request = r#"{"kind":"evm_transaction","network":"base","to":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","value":"1000","data":"0x","nonce":"3","gas_limit":"21000","fees":{"type":"eip1559","max_fee_per_gas":"2000000","max_priority_fee_per_gas":"1000000"}}"#;
        let decoded = engine.decode_request(0, request.to_owned()).unwrap();
        let summary = field(&decoded, "summary");
        assert_eq!(field(&summary, "action").as_string().unwrap(), "native_transfer");
        assert_eq!(
            field(&summary, "signer").as_string().unwrap(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(field(&summary, "network").as_string().unwrap(), "base");
        let approval = field(&decoded, "approval").as_string().unwrap();
        assert_eq!(approval.len(), 64);

        let signed = engine.sign_request(0, request.to_owned(), approval.clone()).unwrap();
        let raw = field(&signed, "raw").as_string().unwrap();
        assert!(raw.starts_with("0x02"));
        assert_eq!(field(&signed, "hash").as_string().unwrap().len(), 66);

        // Another request, another account, a bad hash and a locked wallet.
        let other = request.replace("\"1000\"", "\"1001\"");
        assert_eq!(
            code_of(&engine.sign_request(0, other, approval.clone()).unwrap_err()),
            "ApprovalMismatch"
        );
        assert_eq!(
            code_of(&engine.sign_request(1, request.to_owned(), approval.clone()).unwrap_err()),
            "ApprovalMismatch"
        );
        assert_eq!(
            code_of(&engine.sign_request(0, request.to_owned(), "xyz".to_owned()).unwrap_err()),
            "BadRequest"
        );
        let error = engine.decode_request(0, "{".to_owned()).unwrap_err();
        assert_eq!(code_of(&error), "BadRequest");
        assert_eq!(name_of(&error), "WalletError");
        let mut locked = engine;
        locked.lock();
        assert_eq!(
            code_of(&locked.decode_request(0, request.to_owned()).unwrap_err()),
            "NotUnlocked"
        );
    }

    #[wasm_bindgen_test]
    fn the_signature_made_in_wasm_is_the_one_worked_out_apart_from_the_code() {
        // WebAssembly does its big-integer arithmetic in 32-bit words, the native build in 64-bit ones.
        let engine = unlocked_reference_engine();
        let decoded = engine.decode_request(0, PERSONAL_SIGN_HELLO.to_owned()).unwrap();
        let approval = field(&decoded, "approval").as_string().unwrap();
        let signed = engine.sign_request(0, PERSONAL_SIGN_HELLO.to_owned(), approval).unwrap();
        assert_eq!(field(&signed, "signature").as_string().unwrap(), PERSONAL_SIGN_HELLO_SIGNATURE);
    }

    #[wasm_bindgen_test]
    fn solana_messages_sign_and_tables_are_named_in_wasm() {
        let engine = unlocked_reference_engine();
        let request = r#"{"kind":"solana_message","message_base64":"aGVsbG8="}"#;
        let decoded = engine.decode_request(0, request.to_owned()).unwrap();
        let approval = field(&decoded, "approval").as_string().unwrap();
        let signed = engine.sign_request(0, request.to_owned(), approval).unwrap();
        assert!(!field(&signed, "signature_base58").as_string().unwrap().is_empty());
        assert_eq!(
            field(&field(&decoded, "summary"), "signer").as_string().unwrap(),
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
        assert_eq!(code_of(&solana_lookup_tables("!".to_owned()).unwrap_err()), "BadRequest");
        assert_eq!(code_of(&solana_lookup_tables("AAAA".to_owned()).unwrap_err()), "BadRequest");
    }

    #[wasm_bindgen_test]
    fn addresses_are_validated_and_bitcoin_has_a_change_address_in_wasm() {
        let ok = validate_address(
            "ethereum".to_owned(),
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".to_owned(),
        )
        .unwrap();
        assert_eq!(field(&ok, "valid").as_bool(), Some(true));
        assert_eq!(
            field(&ok, "normalized").as_string().unwrap(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert!(field(&ok, "reason").is_null());
        let bad = validate_address(
            "ethereum".to_owned(),
            "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_owned(),
        )
        .unwrap();
        assert_eq!(field(&bad, "valid").as_bool(), Some(false));
        assert_eq!(field(&bad, "reason").as_string().unwrap(), "checksum");
        assert!(field(&bad, "normalized").is_null());
        let engine = unlocked_reference_engine();
        assert_eq!(
            engine.bitcoin_zpub(0).unwrap(),
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        );
    }

    #[wasm_bindgen_test]
    fn one_unlock_time_in_wasm() {
        // WebAssembly has no clock: the host measures. This test only proves
        // the throwaway vault round-trips; the e2e run reports the browser's
        // own timing.
        let blob = throwaway_vault().unwrap();
        open_throwaway_vault(&blob).unwrap();
        assert_eq!(code_of(&open_throwaway_vault(b"nope").unwrap_err()), "NotAVault");
    }
}
