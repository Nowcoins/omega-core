//! The session's tests. The recovery phrase is the BIP-39 reference vector
//! (entropy all zero), whose addresses every wallet documents.

#![allow(clippy::unwrap_used)]

use nc_wallet_core::{Mnemonic, wordlist};
use zeroize::Zeroizing;

use crate::accounts::accounts_of;
use crate::engine::Secrets;
use crate::phrase::distance;
use crate::quiz::{random_below, shuffle};
use crate::*;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn pw(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn account(accounts: &[NetworkAccount], network: NetworkId) -> &NetworkAccount {
    accounts.iter().find(|a| a.network == network).unwrap()
}

// ---- typed phrases ----

fn problem(text: &str) -> PhraseProblem {
    check_phrase(text).problem
}

#[test]
fn a_valid_phrase_is_valid_however_it_was_typed() {
    let found = check_phrase(ABANDON);
    assert_eq!((found.problem, found.word_count), (PhraseProblem::Valid, 12));
    let messy = format!("  {}\n", ABANDON.to_uppercase().replace(' ', "  "));
    assert_eq!(problem(&messy), PhraseProblem::Valid);
    let twenty_four = format!("{} art", ["abandon"; 23].join(" "));
    let found = check_phrase(&twenty_four);
    assert_eq!((found.problem, found.word_count), (PhraseProblem::Valid, 24));
    // 15, 18 and 21 words are phrases too.
    let fifteen = format!("{} address", ["abandon"; 14].join(" "));
    let found = check_phrase(&fifteen);
    assert_eq!((found.problem, found.word_count), (PhraseProblem::Valid, 15));
}

#[test]
fn nothing_typed_is_empty() {
    assert_eq!(problem(""), PhraseProblem::Empty);
    assert_eq!(problem(" \n\t "), PhraseProblem::Empty);
}

#[test]
fn a_wrong_word_is_named_with_what_it_could_be() {
    // A missing letter, a changed letter, a swap and a half-typed word.
    for text in ["abandon abandn", "abandon abandin", "abandon abnadon", "abandon abando"] {
        let found = check_phrase(text);
        assert_eq!(found.problem, PhraseProblem::UnknownWord, "{text}");
        assert_eq!((found.position, found.word_count), (2, 2), "{text}");
        assert!(
            found.suggestions.iter().any(|s| s == "abandon"),
            "{text}: {:?}",
            found.suggestions
        );
        assert!(found.suggestions.len() <= 3);
    }
    // A word nothing is near gets no suggestion.
    let found = check_phrase("abandon qqqqqqqq");
    assert_eq!(found.problem, PhraseProblem::UnknownWord);
    assert_eq!(found.position, 2);
    assert!(found.suggestions.is_empty());
}

#[test]
fn the_first_wrong_word_wins_even_in_an_unfinished_phrase() {
    let found = check_phrase("abandon ability zzzzz able");
    assert_eq!((found.problem, found.position), (PhraseProblem::UnknownWord, 3));
    // And a typo late in a full-length phrase is still found by position.
    let found = check_phrase(&ABANDON.replace("about", "abot"));
    assert_eq!((found.problem, found.position), (PhraseProblem::UnknownWord, 12));
    assert!(found.suggestions.iter().any(|s| s == "about"), "{:?}", found.suggestions);
}

#[test]
fn the_word_count_and_the_checksum_are_told_apart() {
    for count in [1usize, 5, 11, 13, 23, 25] {
        let found = check_phrase(&vec!["abandon"; count].join(" "));
        assert_eq!(found.problem, PhraseProblem::WrongWordCount, "{count}");
        assert_eq!(found.word_count as usize, count);
    }
    // Twelve valid words with a bad checksum.
    assert_eq!(problem(&["abandon"; 12].join(" ")), PhraseProblem::BadChecksum);
    // The right words in the wrong order.
    let swapped = format!("about {}", ["abandon"; 11].join(" "));
    assert_eq!(problem(&swapped), PhraseProblem::BadChecksum);
}

#[test]
fn words_complete_from_their_start() {
    assert_eq!(complete_word("aba", 5), ["abandon"]);
    assert_eq!(complete_word("  ABA ", 5), ["abandon"]);
    assert_eq!(complete_word("ab", 3).len(), 3);
    assert!(complete_word("", 5).is_empty());
    assert!(complete_word("xyzzy", 5).is_empty());
}

#[test]
fn edit_distance_counts_a_swap_as_one() {
    let d = |a: &str, b: &str| distance(&a.chars().collect::<Vec<_>>(), b);
    assert_eq!(d("abandon", "abandon"), 0);
    assert_eq!(d("abandn", "abandon"), 1);
    assert_eq!(d("abnadon", "abandon"), 1);
    assert_eq!(d("abandin", "abandon"), 1);
    assert_eq!(d("abandonn", "abandon"), 1);
    assert_eq!(d("", "abc"), 3);
    assert_eq!(d("kitten", "sitting"), 3);
}

// ---- the quiz ----

#[test]
fn the_quiz_asks_three_positions_in_order_with_six_choices() {
    let mut engine = Engine::new();
    assert_eq!(engine.quiz().unwrap_err(), SessionError::NoPendingWallet);
    engine.start_new(PhraseLength::Twelve).unwrap();
    let words = engine.pending_words().unwrap();
    assert_eq!(words.len(), 12);
    assert_eq!(engine.pending_word_count().unwrap(), 12);

    let quiz = engine.quiz().unwrap();
    assert_eq!(quiz.len(), 3);
    assert!(quiz.windows(2).all(|pair| pair[0].position < pair[1].position));
    for question in &quiz {
        assert!((1..=12).contains(&question.position));
        assert_eq!(question.choices.len(), 6);
        let answer = &words[question.position as usize - 1];
        assert_eq!(question.choices.iter().filter(|c| *c == answer).count(), 1);
        // The five others are in no position of the phrase, and all differ.
        let mut distinct = question.choices.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 6);
        for choice in question.choices.iter().filter(|c| *c != answer) {
            assert!(!words.contains(choice));
            assert!(wordlist::contains(choice));
        }
    }
    // Asked once: the same questions come back.
    assert_eq!(engine.quiz().unwrap(), quiz);
}

#[test]
fn the_quiz_works_for_a_24_word_phrase() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::TwentyFour).unwrap();
    assert_eq!(engine.pending_words().unwrap().len(), 24);
    assert!(engine.quiz().unwrap().iter().all(|q| (1..=24).contains(&q.position)));
}

#[test]
fn answers_are_checked_against_the_phrase() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    let words = engine.pending_words().unwrap();
    assert_eq!(engine.check_answer(1, "abandon").unwrap_err(), SessionError::NoQuiz);
    let quiz = engine.quiz().unwrap();
    let first = &quiz[0];
    let wrong = first.choices.iter().find(|c| **c != words[first.position as usize - 1]).unwrap();
    assert!(!engine.check_answer(first.position, wrong).unwrap());
    // A wrong answer draws that question again: the quiz is read again.
    let quiz = engine.quiz().unwrap();
    let first = &quiz[0];
    assert!(engine.check_answer(first.position, &words[first.position as usize - 1]).unwrap());
    // A position the quiz did not ask cannot be probed.
    let outside = (1..=12).find(|p| quiz.iter().all(|q| q.position != *p)).unwrap();
    assert_eq!(
        engine.check_answer(outside, &words[outside as usize - 1]).unwrap_err(),
        SessionError::NoQuiz
    );
    assert_eq!(engine.check_answer(0, "x").unwrap_err(), SessionError::NoQuiz);
}

#[test]
fn a_wrong_answer_draws_the_question_again_so_elimination_does_not_work() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    let words = engine.pending_words().unwrap();
    let before = engine.quiz().unwrap();
    // The second question is answered rightly, and stays so across the others' redraws.
    let second = &before[1];
    assert!(engine.check_answer(second.position, &words[second.position as usize - 1]).unwrap());
    let mut positions_seen = std::collections::BTreeSet::new();
    let mut last = before.clone();
    for _ in 0..20 {
        let target = last.iter().find(|q| q.position != second.position).unwrap().clone();
        let wrong =
            target.choices.iter().find(|c| **c != words[target.position as usize - 1]).unwrap();
        assert!(!engine.check_answer(target.position, wrong).unwrap());
        let now = engine.quiz().unwrap();
        assert_eq!(now.len(), 3);
        assert_eq!(now[1].position, second.position, "the other questions keep their places");
        assert_eq!(now[1].choices, second.choices);
        assert!(
            !now.iter().any(|q| q.position == target.position),
            "the position that was answered wrongly is not asked again at once"
        );
        positions_seen.insert(target.position);
        last = now;
    }
    assert!(positions_seen.len() > 3, "the questions move around the phrase");
    // The answered state of the second question holds: two more rights finish the quiz.
    for question in engine.quiz().unwrap() {
        if question.position != second.position {
            assert!(
                engine
                    .check_answer(question.position, &words[question.position as usize - 1])
                    .unwrap()
            );
        }
    }
    assert!(engine.begin_seal().is_ok());
}

#[test]
fn a_new_wallet_is_not_sealed_before_its_backup_is_checked() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    assert_eq!(engine.begin_seal().err(), Some(SessionError::BackupNotConfirmed));
    let words = engine.pending_words().unwrap();
    let quiz = engine.quiz().unwrap();
    assert_eq!(engine.begin_seal().err(), Some(SessionError::BackupNotConfirmed));
    for question in &quiz[..2] {
        assert!(
            engine.check_answer(question.position, &words[question.position as usize - 1]).unwrap()
        );
    }
    assert_eq!(engine.begin_seal().err(), Some(SessionError::BackupNotConfirmed));
    let last = &quiz[2];
    assert!(engine.check_answer(last.position, &words[last.position as usize - 1]).unwrap());
    assert!(engine.begin_seal().is_ok());
    // Taken: nothing is pending now.
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::NoPendingWallet);
}

#[test]
fn an_imported_wallet_needs_no_quiz() {
    let mut engine = Engine::new();
    assert_eq!(
        engine.start_import("abandon abandon", "").unwrap_err(),
        SessionError::InvalidPhrase
    );
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::NoPendingWallet);
    engine.start_import(ABANDON, "").unwrap();
    assert!(engine.begin_seal().is_ok());
}

#[test]
fn discarding_forgets_the_wallet_being_made() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    engine.discard_pending();
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::NoPendingWallet);
}

#[test]
fn two_new_wallets_differ() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    let a = engine.pending_words().unwrap();
    engine.start_new(PhraseLength::Twelve).unwrap();
    assert_ne!(a, engine.pending_words().unwrap());
}

#[test]
fn random_numbers_stay_below_their_bound_and_shuffles_keep_every_item() {
    for bound in [1usize, 2, 3, 7, 100, 2048] {
        for _ in 0..200 {
            assert!(random_below(bound).unwrap() < bound);
        }
    }
    let mut items: Vec<u32> = (0..50).collect();
    shuffle(&mut items).unwrap();
    assert_ne!(items, (0..50).collect::<Vec<_>>(), "50 items stayed in order");
    items.sort_unstable();
    assert_eq!(items, (0..50).collect::<Vec<_>>());
}

// ---- accounts ----

#[test]
fn the_nine_accounts_of_the_reference_phrase() {
    let mut engine = Engine::new();
    assert_eq!(engine.accounts(0).unwrap_err(), SessionError::NotUnlocked);
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    engine.set_session_for_tests(Secrets::Phrase {
        mnemonic: phrase,
        passphrase: Zeroizing::new(String::new()),
    });

    let accounts = engine.accounts(0).unwrap();
    let networks: Vec<NetworkId> = accounts.iter().map(|a| a.network).collect();
    assert_eq!(
        networks,
        [
            NetworkId::Ethereum,
            NetworkId::BnbChain,
            NetworkId::Polygon,
            NetworkId::Base,
            NetworkId::Tron,
            NetworkId::Bitcoin,
            NetworkId::Solana,
            NetworkId::Stellar,
            NetworkId::Bittensor
        ]
    );
    // The four EVM networks share one account.
    let ethereum = account(&accounts, NetworkId::Ethereum);
    for same in [NetworkId::BnbChain, NetworkId::Polygon, NetworkId::Base] {
        assert_eq!(account(&accounts, same).address, ethereum.address);
    }
    // MetaMask and Trust Wallet show this address for this phrase at m/44'/60'/0'/0/0.
    assert_eq!(ethereum.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    assert_eq!(ethereum.path, "m/44'/60'/0'/0/0");
    assert_eq!(ethereum.public_key_hex.len(), 66);
    // BIP-84's first receive address for this phrase.
    assert_eq!(
        account(&accounts, NetworkId::Bitcoin).address,
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert!(account(&accounts, NetworkId::Tron).address.starts_with('T'));
    assert!(account(&accounts, NetworkId::Stellar).address.starts_with('G'));
    assert!(account(&accounts, NetworkId::Bittensor).address.starts_with('5'));
    assert_eq!(account(&accounts, NetworkId::Bittensor).path, "");
    assert_eq!(account(&accounts, NetworkId::Solana).path, "m/44'/501'/0'/0'");

    // Account 1 is a different account on every network.
    let next = engine.accounts(1).unwrap();
    for (a, b) in accounts.iter().zip(&next) {
        if a.network == NetworkId::Ethereum
            || a.network == NetworkId::Tron
            || a.network == NetworkId::Bitcoin
            || a.network == NetworkId::Solana
            || a.network == NetworkId::Stellar
            || a.network == NetworkId::Bittensor
        {
            assert_ne!(a.address, b.address, "{:?}", a.network);
        }
    }
    assert_eq!(account(&next, NetworkId::Bittensor).path, "//1");
    assert_eq!(engine.accounts(1 << 31).unwrap_err(), SessionError::AccountIndexOutOfRange);
}

#[test]
fn the_passphrase_makes_another_wallet() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    let plain = accounts_of(&phrase, "", 0).unwrap();
    let with = accounts_of(&phrase, "TREZOR", 0).unwrap();
    assert_ne!(
        account(&plain, NetworkId::Ethereum).address,
        account(&with, NetworkId::Ethereum).address
    );
}

// ---- the vault, through an engine ----

fn pass_the_quiz(engine: &mut Engine) -> Vec<String> {
    let words = engine.pending_words().unwrap();
    for question in engine.quiz().unwrap() {
        assert!(
            engine.check_answer(question.position, &words[question.position as usize - 1]).unwrap()
        );
    }
    words
}

#[test]
fn make_seal_lock_and_unlock() {
    let mut engine = Engine::new();

    // Make a wallet and pass the backup check.
    engine.start_new(PhraseLength::Twelve).unwrap();
    assert_eq!(
        engine.seal_pending("a good password").unwrap_err(),
        SessionError::BackupNotConfirmed
    );
    // The failed attempt did not lose the wallet.
    let words = pass_the_quiz(&mut engine);
    // An empty password is refused and keeps the wallet being made.
    assert_eq!(engine.seal_pending("").unwrap_err(), SessionError::EmptyPassword);
    assert!(engine.pending_words().is_ok());

    let blob = engine.seal_pending("a good password").unwrap();
    // Sealed but not stored: still pending, not unlocked, and it can be sealed again.
    assert!(!engine.is_unlocked());
    assert!(engine.has_pending());
    let again = engine.seal_pending("a good password").unwrap();
    assert_ne!(again, blob, "a new salt each time");
    engine.commit_pending().unwrap();
    assert_eq!(engine.commit_pending().unwrap_err(), SessionError::NoPendingWallet);
    assert!(engine.is_unlocked());
    let blob = again;
    // The key it was sealed with is available once, and opens the vault.
    let new_key = engine.take_new_key().unwrap();
    assert_eq!(engine.take_new_key().unwrap_err(), SessionError::NoNewKey);
    assert_eq!(new_key, export_unlock_key(&blob, &pw("a good password")).unwrap());
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::NoPendingWallet);
    let before = engine.accounts(0).unwrap();
    assert_eq!(before.len(), 9);

    let facts = vault_facts(&blob).unwrap();
    assert_eq!((facts.version, facts.memory_kib, facts.iterations, facts.lanes), (1, 65_536, 3, 1));

    // Lock: nothing to derive from.
    engine.lock();
    assert!(!engine.is_unlocked());
    assert_eq!(engine.accounts(0).unwrap_err(), SessionError::NotUnlocked);

    // A wrong password, then the right one.
    assert_eq!(
        engine.unlock_with_password(&blob, &pw("not the password")).unwrap_err(),
        SessionError::WrongPassword
    );
    assert!(!engine.is_unlocked());
    engine.unlock_with_password(&blob, &pw("a good password")).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), before);

    // Re-authentication shows the phrase the wallet was made with.
    assert_eq!(reveal_phrase(&blob, &pw("a good password")).unwrap(), words);
    assert_eq!(reveal_phrase(&blob, &pw("nope")).unwrap_err(), SessionError::WrongPassword);

    // The vault key opens the vault without the password, only this vault.
    let key = export_unlock_key(&blob, &pw("a good password")).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(export_unlock_key(&blob, &pw("nope")).unwrap_err(), SessionError::WrongPassword);
    engine.lock();
    engine.unlock_with_key(&blob, &Zeroizing::new(key.clone())).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), before);
    engine.lock();
    assert_eq!(
        engine.unlock_with_key(&blob, &Zeroizing::new(vec![0; 32])).unwrap_err(),
        SessionError::WrongPassword
    );
    assert_eq!(
        engine.unlock_with_key(&blob, &Zeroizing::new(vec![0; 5])).unwrap_err(),
        SessionError::WrongPassword
    );

    // A new password: the old one stops working, the key is replaced.
    let renewed = change_password(&blob, &pw("a good password"), &pw("another password")).unwrap();
    assert_ne!(renewed, blob);
    assert_eq!(
        engine.unlock_with_password(&renewed, &pw("a good password")).unwrap_err(),
        SessionError::WrongPassword
    );
    engine.unlock_with_password(&renewed, &pw("another password")).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), before);
    assert_eq!(
        engine.unlock_with_key(&renewed, &Zeroizing::new(key)).unwrap_err(),
        SessionError::WrongPassword
    );
    assert_eq!(
        change_password(&blob, &pw("wrong"), &pw("another password")).unwrap_err(),
        SessionError::WrongPassword
    );

    // Garbage is not a vault.
    assert_eq!(
        engine.unlock_with_password(b"nonsense", &pw("x")).unwrap_err(),
        SessionError::NotAVault
    );
    assert_eq!(vault_facts(b"nonsense").unwrap_err(), SessionError::NotAVault);
    engine.lock();
}

#[test]
fn trust_wallets_solana_account_is_found_for_an_import_and_for_the_unlocked_wallet_and_is_another_account()
 {
    // Trust Wallet Core's own phrase for its Solana address (`TWSolanaAddress.HDWallet`).
    const SHOOT: &str =
        "shoot island position soft burden budget tooth cruel issue economy destroy above";
    let mut engine = Engine::new();
    assert_eq!(engine.solana_trust_wallet_account().unwrap_err(), SessionError::NotUnlocked);
    // While the phrase is being imported, before it is sealed: where its funds may be.
    engine.start_import(SHOOT, "").unwrap();
    let found = engine.solana_trust_wallet_account().unwrap();
    assert_eq!(found.network, NetworkId::Solana);
    assert_eq!(found.address, "2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m");
    assert_eq!(found.path, "m/44'/501'/0'");
    assert_eq!(found.public_key_hex.len(), 64);
    // It is not the wallet's own Solana account, whose path is Phantom's, and that one is as it was.
    let blob = engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    let own = account(&engine.accounts(0).unwrap(), NetworkId::Solana).clone();
    assert_ne!(own.address, found.address);
    assert_eq!(own.path, "m/44'/501'/0'/0'");
    // Unlocked later, the same address; locked, none.
    assert_eq!(engine.solana_trust_wallet_account().unwrap(), found);
    engine.lock();
    assert_eq!(engine.solana_trust_wallet_account().unwrap_err(), SessionError::NotUnlocked);
    engine.unlock_with_password(&blob, &pw("a good password")).unwrap();
    assert_eq!(engine.solana_trust_wallet_account().unwrap(), found);
    // The passphrase belongs to the phrase: another passphrase, another account.
    let mut with_passphrase = Engine::new();
    with_passphrase.start_import(SHOOT, "TREZOR").unwrap();
    assert_ne!(with_passphrase.solana_trust_wallet_account().unwrap().address, found.address);
}

#[test]
fn a_password_unlock_can_hand_back_the_key_it_made() {
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "").unwrap();
    let blob = engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    let accounts = engine.accounts(0).unwrap();
    engine.lock();

    let (unlocked, key) = open_with_password_keeping_key(&blob, &pw("a good password")).unwrap();
    engine.install(unlocked);
    assert_eq!(engine.accounts(0).unwrap(), accounts);
    // It is the key `export_unlock_key` gives, and it opens the vault alone.
    assert_eq!(key, export_unlock_key(&blob, &pw("a good password")).unwrap());
    engine.lock();
    engine.install(open_with_key(&blob, &Zeroizing::new(key)).unwrap());
    assert_eq!(engine.accounts(0).unwrap(), accounts);

    assert_eq!(
        open_with_password_keeping_key(&blob, &pw("nope")).unwrap_err(),
        SessionError::WrongPassword
    );
    assert_eq!(
        open_with_password_keeping_key(b"nonsense", &pw("x")).unwrap_err(),
        SessionError::NotAVault
    );
}

#[test]
fn a_new_password_can_hand_back_the_new_key() {
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "TREZOR").unwrap();
    let blob = engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    let accounts = engine.accounts(0).unwrap();
    engine.lock();

    let (renewed, key) = change_password_keeping_key(
        &blob,
        &pw("a good password"),
        &pw("another password"),
        VaultParams::PHONE,
    )
    .unwrap();
    assert_ne!(renewed, blob);
    // The key is the new vault's, made by the same run: it opens the new
    // vault and not the old one, and is what `export_unlock_key` would give.
    assert_eq!(key, export_unlock_key(&renewed, &pw("another password")).unwrap());
    engine.unlock_with_key(&renewed, &Zeroizing::new(key.clone())).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), accounts, "the passphrase came along");
    engine.lock();
    assert_eq!(
        engine.unlock_with_key(&blob, &Zeroizing::new(key)).unwrap_err(),
        SessionError::WrongPassword
    );
    assert_eq!(
        change_password_keeping_key(
            &blob,
            &pw("wrong"),
            &pw("another password"),
            VaultParams::PHONE
        )
        .unwrap_err(),
        SessionError::WrongPassword
    );
    assert_eq!(
        change_password_keeping_key(&blob, &pw("a good password"), &pw(""), VaultParams::PHONE)
            .unwrap_err(),
        SessionError::EmptyPassword
    );
}

#[test]
fn an_extension_engine_seals_heavier_and_still_opens_an_old_vault() {
    // A vault of the phone's parameters (64 MiB), as every extension vault was
    // before the extension's own.
    let mut phone = Engine::new();
    phone.start_import(ABANDON, "TREZOR").unwrap();
    let old = phone.seal_pending("a good password").unwrap();
    assert_eq!(vault_facts(&old).unwrap().memory_kib, 65_536);

    let mut engine = Engine::with_vault_params(VaultParams::EXTENSION);
    engine.unlock_with_password(&old, &pw("a good password")).unwrap();
    let accounts = engine.accounts(0).unwrap();
    engine.lock();

    // Re-sealed under the same password with the extension's parameters: the
    // header says so, the new key opens it, the old vault still opens.
    let (renewed, key) = change_password_keeping_key(
        &old,
        &pw("a good password"),
        &pw("a good password"),
        VaultParams::EXTENSION,
    )
    .unwrap();
    let facts = vault_facts(&renewed).unwrap();
    let extension = VaultParams::EXTENSION;
    assert_eq!(
        (facts.memory_kib, facts.iterations, facts.lanes),
        (extension.memory_kib(), extension.iterations(), extension.lanes())
    );
    engine.unlock_with_key(&renewed, &Zeroizing::new(key)).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), accounts, "the same wallet, passphrase and all");
    engine.lock();
    engine.unlock_with_password(&old, &pw("a good password")).unwrap();

    // A new wallet from this engine is sealed with its parameters.
    engine.start_import(ABANDON, "").unwrap();
    let blob = engine.seal_pending("a good password").unwrap();
    assert_eq!(vault_facts(&blob).unwrap().memory_kib, extension.memory_kib());
    engine.commit_pending().unwrap();
    assert_eq!(
        engine.take_new_key().unwrap(),
        export_unlock_key(&blob, &pw("a good password")).unwrap()
    );
}

#[test]
fn an_engine_opens_only_vaults_within_its_limits() {
    // A vault of the phone's parameters (64 MiB), which the extension still
    // opens, and the same vault with a header that asks for 1 GiB: within the
    // crate's own ceiling (the phone's), above the extension's.
    let mut phone = Engine::new();
    phone.start_import(ABANDON, "").unwrap();
    let blob = phone.seal_pending("a good password").unwrap();
    phone.commit_pending().unwrap();
    let key = phone.take_new_key().unwrap();
    let mut hostile = blob.clone();
    hostile[6..10].copy_from_slice(&(1024u32 * 1024).to_be_bytes());

    // The phone keeps its ceiling; the extension's engine says its own.
    assert_eq!(Engine::new().open_limits(), VaultLimits::PHONE);
    assert_eq!(Engine::with_vault_params(VaultParams::EXTENSION).open_limits(), VaultLimits::PHONE);
    assert_eq!(vault_facts(&hostile).unwrap().memory_kib, 1024 * 1024);
    let limits = VaultLimits::EXTENSION;
    let mut engine = Engine::with_vault_params_and_limits(VaultParams::EXTENSION, limits);
    assert_eq!(engine.open_limits(), limits);
    assert!(limits.admits(&VaultParams::EXTENSION) && limits.admits(&VaultParams::PHONE));

    // Every way the extension opens a vault refuses it as not a vault, at once:
    // no Argon2id run at 1 GiB (which would take seconds, or fail for memory).
    let password = pw("a good password");
    let started = std::time::Instant::now();
    let refused = Some(SessionError::NotAVault);
    assert_eq!(engine.unlock_with_password(&hostile, &password).err(), refused);
    assert_eq!(engine.unlock_with_key(&hostile, &Zeroizing::new(key.clone())).err(), refused);
    assert_eq!(open_with_password_within(&hostile, &password, limits).err(), refused);
    assert_eq!(open_with_password_keeping_key_within(&hostile, &password, limits).err(), refused);
    assert_eq!(open_with_key_within(&hostile, &Zeroizing::new(key.clone()), limits).err(), refused);
    assert_eq!(export_unlock_key_within(&hostile, &password, limits).err(), refused);
    assert_eq!(reveal_phrase_within(&hostile, &password, limits).err(), refused);
    assert_eq!(
        change_password_keeping_key_within(
            &hostile,
            &password,
            &password,
            VaultParams::EXTENSION,
            limits
        )
        .err(),
        refused
    );
    assert_eq!(vault_facts_within(&hostile, limits).err(), refused);
    assert_eq!(open_throwaway_within(&hostile, limits).err(), refused);
    assert!(started.elapsed().as_millis() < 1000, "refusing took {:?}", started.elapsed());
    assert!(!engine.is_unlocked());

    // The vault itself opens within them, by password and by key.
    engine.unlock_with_password(&blob, &password).unwrap();
    let accounts = engine.accounts(0).unwrap();
    engine.lock();
    engine.unlock_with_key(&blob, &Zeroizing::new(key)).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), accounts);
    assert_eq!(reveal_phrase_within(&blob, &password, limits).unwrap().join(" "), ABANDON);
    assert_eq!(vault_facts_within(&blob, limits).unwrap().memory_kib, 65_536);
}

#[test]
fn sealing_in_two_steps_keeps_the_wallet_while_the_lock_is_free() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    assert_eq!(engine.begin_seal().err(), Some(SessionError::BackupNotConfirmed));
    pass_the_quiz(&mut engine);

    let job = engine.begin_seal().unwrap();
    // While the job runs, the engine holds no wallet.
    assert!(!engine.has_pending());
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::NoPendingWallet);
    let done = job.seal("a good password");
    let blob = engine.finish_seal(done).unwrap();
    assert!(engine.has_pending());
    assert!(!engine.is_unlocked());
    engine.commit_pending().unwrap();
    assert!(engine.is_unlocked());
    assert_eq!(vault_facts(&blob).unwrap().version, 1);

    // A failed seal puts the wallet back.
    engine.start_import(ABANDON, "").unwrap();
    let done = engine.begin_seal().unwrap().seal("");
    assert_eq!(engine.finish_seal(done).unwrap_err(), SessionError::EmptyPassword);
    assert!(engine.has_pending());
}

#[test]
fn the_new_key_is_dropped_on_request_and_on_lock() {
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "").unwrap();
    engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    engine.drop_new_key();
    assert_eq!(engine.take_new_key().unwrap_err(), SessionError::NoNewKey);

    engine.start_import(ABANDON, "").unwrap();
    engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    engine.lock();
    assert_eq!(engine.take_new_key().unwrap_err(), SessionError::NoNewKey);
}

#[test]
fn an_imported_wallet_with_a_passphrase_keeps_it_through_the_vault() {
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "TREZOR").unwrap();
    let blob = engine.seal_pending("a good password").unwrap();
    engine.commit_pending().unwrap();
    let sealed_accounts = engine.accounts(0).unwrap();
    // The reference wallet "abandon ... about" + passphrase TREZOR is not the
    // plain one.
    let plain = accounts_of(&Mnemonic::parse(ABANDON).unwrap(), "", 0).unwrap();
    assert_ne!(sealed_accounts, plain);
    engine.lock();
    engine.unlock_with_password(&blob, &pw("a good password")).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), sealed_accounts);
    engine.lock();
}

#[test]
fn a_sealed_wallet_that_is_replaced_or_discarded_cannot_be_committed() {
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "").unwrap();
    engine.seal_pending("a good password").unwrap();
    engine.discard_pending();
    assert_eq!(engine.commit_pending().unwrap_err(), SessionError::NoPendingWallet);

    engine.start_import(ABANDON, "").unwrap();
    engine.seal_pending("a good password").unwrap();
    // Starting another wallet forgets the sealing of the first.
    engine.start_import(ABANDON, "").unwrap();
    assert_eq!(engine.commit_pending().unwrap_err(), SessionError::NoPendingWallet);
    engine.discard_pending();
    assert!(!engine.is_unlocked());
}

#[test]
fn locking_leaves_a_wallet_being_made_alone() {
    let mut engine = Engine::new();
    engine.start_new(PhraseLength::Twelve).unwrap();
    engine.lock();
    assert!(engine.has_pending());
    engine.discard_pending();
    assert!(!engine.has_pending());
}

#[test]
fn the_throwaway_vault_is_for_timing_an_unlock() {
    let blob = throwaway_vault().unwrap();
    let facts = vault_facts(&blob).unwrap();
    assert_eq!((facts.memory_kib, facts.iterations, facts.lanes), (65_536, 3, 1));
    open_throwaway(&blob).unwrap();
    // Two are never the same.
    assert_ne!(throwaway_vault().unwrap(), blob);
    let heavier = throwaway_vault_with_params(VaultParams::EXTENSION).unwrap();
    assert_eq!(vault_facts(&heavier).unwrap().memory_kib, VaultParams::EXTENSION.memory_kib());
    open_throwaway(&heavier).unwrap();
}

#[test]
fn errors_say_nothing_secret() {
    for error in [
        SessionError::WrongPassword,
        SessionError::InvalidPhrase,
        SessionError::NotUnlocked,
        SessionError::Unavailable,
    ] {
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("abandon"));
    }
    // Nor do the engine and the values that hold a phrase.
    let mut engine = Engine::new();
    engine.start_import(ABANDON, "TREZOR").unwrap();
    let job = engine.begin_seal().unwrap();
    let done = job.seal("a good password");
    let shown = format!("{engine:?} {done:?}");
    assert!(!shown.contains("abandon") && !shown.contains("TREZOR"));
    let blob = engine.finish_seal(done).unwrap();
    let unlocked = open_with_password(&blob, &pw("a good password")).unwrap();
    assert!(!format!("{unlocked:?} {engine:?}").contains("abandon"));
}

#[test]
fn error_codes_are_stable_names() {
    let all = [
        (SessionError::WrongPassword, "WrongPassword"),
        (SessionError::EmptyPassword, "EmptyPassword"),
        (SessionError::NotAVault, "NotAVault"),
        (SessionError::UnsupportedVault, "UnsupportedVault"),
        (SessionError::PassphraseTooLong, "PassphraseTooLong"),
        (SessionError::InvalidPhrase, "InvalidPhrase"),
        (SessionError::NoPendingWallet, "NoPendingWallet"),
        (SessionError::NotUnlocked, "NotUnlocked"),
        (SessionError::NoQuiz, "NoQuiz"),
        (SessionError::BackupNotConfirmed, "BackupNotConfirmed"),
        (SessionError::NoNewKey, "NoNewKey"),
        (SessionError::AccountIndexOutOfRange, "AccountIndexOutOfRange"),
        (SessionError::Unavailable, "Unavailable"),
    ];
    for (error, code) in all {
        assert_eq!(error.code(), code);
        // The code is the variant's own name.
        assert_eq!(format!("{error:?}"), code);
    }
}

#[test]
fn problem_codes_and_api_ids_are_stable_names() {
    assert_eq!(
        [
            PhraseProblem::Empty,
            PhraseProblem::Valid,
            PhraseProblem::UnknownWord,
            PhraseProblem::WrongWordCount,
            PhraseProblem::BadChecksum
        ]
        .map(PhraseProblem::code),
        ["empty", "valid", "unknownWord", "wrongWordCount", "badChecksum"]
    );
    // The ids the wallet API names the networks by.
    let ids = [
        (NetworkId::Ethereum, "ethereum"),
        (NetworkId::BnbChain, "bsc"),
        (NetworkId::Polygon, "polygon"),
        (NetworkId::Base, "base"),
        (NetworkId::Tron, "tron"),
        (NetworkId::Bitcoin, "bitcoin"),
        (NetworkId::Solana, "solana"),
        (NetworkId::Stellar, "stellar"),
        (NetworkId::Bittensor, "bittensor"),
    ];
    for (network, id) in ids {
        assert_eq!(network.api_id(), id);
    }
}

#[test]
fn core_errors_map_to_the_session_errors_the_apps_show() {
    use nc_wallet_core::vault::VaultError;
    let cases = [
        (VaultError::EmptyPassword, SessionError::EmptyPassword),
        (VaultError::PassphraseTooLong, SessionError::PassphraseTooLong),
        (VaultError::UnsupportedVersion(9), SessionError::UnsupportedVault),
        (VaultError::UnsupportedAlgorithm, SessionError::UnsupportedVault),
        (VaultError::Authentication, SessionError::WrongPassword),
        (VaultError::Corrupt, SessionError::WrongPassword),
        (VaultError::BadKey, SessionError::WrongPassword),
        (VaultError::NotAVault, SessionError::NotAVault),
        (VaultError::BadParams, SessionError::NotAVault),
        (VaultError::Kdf, SessionError::Unavailable),
        (VaultError::Randomness, SessionError::Unavailable),
    ];
    for (from, to) in cases {
        assert_eq!(SessionError::from(from), to);
    }
}

// ---- the sealed caches (history at rest) ----

fn unlocked(phrase: &str, passphrase: &str) -> Engine {
    let mut engine = Engine::new();
    engine.set_session_for_tests(Secrets::Phrase {
        mnemonic: Mnemonic::parse(phrase).unwrap(),
        passphrase: Zeroizing::new(passphrase.to_owned()),
    });
    engine
}

#[test]
fn a_cache_is_sealed_for_a_label_and_opens_only_while_unlocked_by_the_same_wallet() {
    let mut engine = Engine::new();
    assert_eq!(engine.seal_cache("history/a", b"x").unwrap_err(), SessionError::NotUnlocked);
    assert_eq!(engine.open_cache("history/a", b"x").unwrap_err(), SessionError::NotUnlocked);
    assert_eq!(engine.cache_id("history/a").unwrap_err(), SessionError::NotUnlocked);

    let mut engine = unlocked(ABANDON, "");
    let blob = engine.seal_cache("history/a", b"{\"v\":1}").unwrap();
    assert_eq!(engine.open_cache("history/a", &blob).unwrap().as_deref(), Some(&b"{\"v\":1}"[..]));
    // Not under another label, not by another wallet or passphrase, not damaged.
    assert_eq!(engine.open_cache("history/b", &blob).unwrap(), None);
    let mut other =
        unlocked("legal winner thank year wave sausage worth useful legal winner thank yellow", "");
    assert_eq!(other.open_cache("history/a", &blob).unwrap(), None);
    assert_eq!(unlocked(ABANDON, "p").open_cache("history/a", &blob).unwrap(), None);
    assert_eq!(engine.open_cache("history/a", &blob[..blob.len() - 1]).unwrap(), None);

    // Locking wipes the key: nothing opens until the wallet is unlocked again, and then the same blob does.
    engine.lock();
    assert_eq!(engine.open_cache("history/a", &blob).unwrap_err(), SessionError::NotUnlocked);
    engine.set_session_for_tests(Secrets::Phrase {
        mnemonic: Mnemonic::parse(ABANDON).unwrap(),
        passphrase: Zeroizing::new(String::new()),
    });
    assert_eq!(engine.open_cache("history/a", &blob).unwrap().as_deref(), Some(&b"{\"v\":1}"[..]));
}

#[test]
fn a_cache_id_is_the_same_every_time_and_differs_by_label_and_wallet() {
    let mut engine = unlocked(ABANDON, "");
    let id = engine.cache_id("history/ethereum/0x1").unwrap();
    assert_eq!(id.len(), 24);
    assert_eq!(id, engine.cache_id("history/ethereum/0x1").unwrap());
    assert_ne!(id, engine.cache_id("history/ethereum/0x2").unwrap());
    assert_ne!(id, unlocked(ABANDON, "p").cache_id("history/ethereum/0x1").unwrap());
}

// ---- a wallet that is one imported private key ----

/// The reference phrase's first Ethereum key, which every wallet documents.
const ABANDON_EVM_KEY: &str = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727";
const ABANDON_EVM_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

#[test]
fn a_private_key_is_imported_sealed_unlocked_and_shown_again() {
    let password = Zeroizing::new("correct horse battery staple".to_owned());
    let mut engine = Engine::with_vault_params(VaultParams::EXTENSION);
    assert_eq!(engine.start_import_key("not a key").unwrap_err(), SessionError::InvalidKey);
    assert!(!engine.has_pending());
    engine.start_import_key(&format!("0x{ABANDON_EVM_KEY}")).unwrap();
    assert_eq!(engine.wallet_kind().unwrap(), WalletKind::KeySecp256k1);
    // A key has no words to write down and no backup check to pass.
    assert_eq!(engine.pending_words().unwrap_err(), SessionError::HoldsAKey);
    assert_eq!(engine.pending_word_count().unwrap_err(), SessionError::HoldsAKey);
    assert_eq!(engine.quiz().unwrap_err(), SessionError::HoldsAKey);
    assert_eq!(engine.solana_trust_wallet_account().unwrap_err(), SessionError::HoldsAKey);

    let blob = engine.seal_pending(&password).unwrap();
    engine.commit_pending().unwrap();
    assert!(engine.is_unlocked());
    let new_key = Zeroizing::new(engine.take_new_key().unwrap());

    // Account 0 on the four EVM networks and on TRON, the same key on each; no other account.
    let accounts = engine.accounts(0).unwrap();
    let networks: Vec<NetworkId> = accounts.iter().map(|a| a.network).collect();
    assert_eq!(
        networks,
        [
            NetworkId::Ethereum,
            NetworkId::BnbChain,
            NetworkId::Polygon,
            NetworkId::Base,
            NetworkId::Tron
        ]
    );
    for account in &accounts[..4] {
        assert_eq!(account.address, ABANDON_EVM_ADDRESS);
        assert_eq!(account.path, "");
    }
    assert!(accounts[4].address.starts_with('T'));
    assert_eq!(accounts[4].public_key_hex, accounts[0].public_key_hex);
    assert_eq!(engine.accounts(1).unwrap_err(), SessionError::AccountIndexOutOfRange);

    // Locked and opened again, by the password and by the vault key, it is the same wallet.
    engine.lock();
    assert_eq!(engine.accounts(0).unwrap_err(), SessionError::NotUnlocked);
    engine.unlock_with_key(&blob, &new_key).unwrap();
    assert_eq!(engine.wallet_kind().unwrap(), WalletKind::KeySecp256k1);
    assert_eq!(engine.accounts(0).unwrap(), accounts);
    engine.lock();
    let wrong = Zeroizing::new("another password".to_owned());
    assert_eq!(
        engine.unlock_with_password(&blob, &wrong).unwrap_err(),
        SessionError::WrongPassword
    );

    // The key is shown again for the password alone; a phrase is not what this vault holds.
    assert_eq!(
        *reveal_key_within(&blob, &password, VaultLimits::EXTENSION).unwrap(),
        ABANDON_EVM_KEY
    );
    assert_eq!(
        reveal_phrase_within(&blob, &password, VaultLimits::EXTENSION).unwrap_err(),
        SessionError::HoldsAKey
    );
    assert_eq!(
        reveal_key_within(&blob, &wrong, VaultLimits::EXTENSION).unwrap_err(),
        SessionError::WrongPassword
    );

    // A new password seals the same key.
    let (renewed, key) = change_password_keeping_key_within(
        &blob,
        &password,
        &wrong,
        VaultParams::EXTENSION,
        VaultLimits::EXTENSION,
    )
    .unwrap();
    assert_eq!(
        *reveal_key_within(&renewed, &wrong, VaultLimits::EXTENSION).unwrap(),
        ABANDON_EVM_KEY
    );
    engine.unlock_with_key(&renewed, &Zeroizing::new(key)).unwrap();
    assert_eq!(engine.accounts(0).unwrap(), accounts);
}

#[test]
fn a_phrase_vault_has_no_single_key_to_show() {
    let password = Zeroizing::new("correct horse battery staple".to_owned());
    let mut engine = Engine::with_vault_params(VaultParams::EXTENSION);
    engine.start_import(ABANDON, "").unwrap();
    assert_eq!(engine.wallet_kind().unwrap(), WalletKind::Phrase);
    let blob = engine.seal_pending(&password).unwrap();
    assert_eq!(
        reveal_key_within(&blob, &password, VaultLimits::EXTENSION).unwrap_err(),
        SessionError::HoldsAPhrase
    );
    assert_eq!(Engine::new().wallet_kind().unwrap_err(), SessionError::NotUnlocked);
}

#[test]
fn a_key_wallets_cache_is_its_own() {
    let mut key_wallet = Engine::new();
    key_wallet.set_session_for_tests(Secrets::Key(
        nc_wallet_core::ImportedKey::parse(ABANDON_EVM_KEY).unwrap(),
    ));
    let blob = key_wallet.seal_cache("history/a", b"{}").unwrap();
    assert_eq!(key_wallet.open_cache("history/a", &blob).unwrap().as_deref(), Some(&b"{}"[..]));
    // Not the phrase wallet's, though its first key is this very key.
    assert_eq!(unlocked(ABANDON, "").open_cache("history/a", &blob).unwrap(), None);
    assert_ne!(
        key_wallet.cache_id("history/a").unwrap(),
        unlocked(ABANDON, "").cache_id("history/a").unwrap()
    );
}

#[test]
fn check_key_says_what_was_pasted() {
    let found = |text: &str| check_key(text);
    assert_eq!(found("").problem.code(), "empty");
    assert_eq!(found(ABANDON_EVM_KEY).problem.code(), "valid");
    assert_eq!(found(ABANDON_EVM_KEY).kind.map(WalletKind::code), Some("keySecp256k1"));
    assert_eq!(found(ABANDON).problem.code(), "unrecognised");
    assert_eq!(found(ABANDON).kind, None);
    assert_eq!(
        found("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").problem.code(),
        "looksLikeAnAddress"
    );
    assert_eq!(found(&"00".repeat(32)).problem.code(), "notOnCurve");
}
