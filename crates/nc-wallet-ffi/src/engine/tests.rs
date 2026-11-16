//! The bridge layer's tests: the process-wide engine behind the `api`
//! functions, and the conversions. The logic itself (phrase checks, the quiz,
//! sealing, the vault round trips) is tested in `nc-wallet-session`, where it
//! lives; these tests go through the same entry points Dart calls, so they fail
//! if the layer drops, reorders or mislabels anything on the way.
//! The recovery phrase is the BIP-39 reference vector (entropy all zero).

#![allow(clippy::unwrap_used)]

use std::sync::Mutex;

use super::*;
use crate::api::{accounts, phrase, vault};

pub(super) const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The tests that use the process-wide engine run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

pub(super) fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn pw(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn account(accounts: &[NetworkAccount], network: NetworkId) -> &NetworkAccount {
    accounts.iter().find(|a| a.network == network).unwrap()
}

// ---- the vault, through the process-wide engine ----

#[test]
fn make_seal_lock_and_unlock() {
    let _one_at_a_time = serial();
    engine().lock();
    engine().discard_pending();

    // Make a wallet and pass the backup check.
    engine().start_new(session::PhraseLength::Twelve).unwrap();
    assert_eq!(seal_pending("a good password").unwrap_err(), WalletError::BackupNotConfirmed);
    // The failed attempt did not lose the wallet.
    let words = engine().pending_words().unwrap();
    let quiz = engine().quiz().unwrap();
    for question in quiz {
        assert!(
            engine()
                .check_answer(question.position, &words[question.position as usize - 1])
                .unwrap()
        );
    }
    // An empty password is refused and keeps the wallet being made.
    assert_eq!(seal_pending("").unwrap_err(), WalletError::EmptyPassword);
    assert!(engine().pending_words().is_ok());

    let blob = seal_pending("a good password").unwrap();
    // Sealed but not stored: still pending, not unlocked, and it can be sealed again.
    assert!(!engine().is_unlocked());
    assert!(engine().pending_words().is_ok());
    let again = seal_pending("a good password").unwrap();
    assert_ne!(again, blob, "a new salt each time");
    engine().commit_pending().unwrap();
    assert_eq!(
        WalletError::from(engine().commit_pending().unwrap_err()),
        WalletError::NoPendingWallet
    );
    assert!(engine().is_unlocked());
    let blob = again;
    // The key it was sealed with is available once, and opens the vault.
    let new_key = engine().take_new_key().unwrap();
    assert!(engine().take_new_key().is_err());
    assert_eq!(new_key, export_unlock_key(&blob, &pw("a good password")).unwrap());
    let before = accounts::derive_accounts(0).unwrap();
    assert_eq!(before.len(), 9);

    let facts = vault_facts(&blob).unwrap();
    assert_eq!((facts.version, facts.memory_kib, facts.iterations, facts.lanes), (1, 65_536, 3, 1));

    // Lock: nothing to derive from.
    engine().lock();
    assert!(!engine().is_unlocked());
    assert_eq!(accounts::derive_accounts(0).unwrap_err(), WalletError::NotUnlocked);

    // A wrong password, then the right one.
    assert_eq!(
        unlock_with_password(&blob, &pw("not the password")).unwrap_err(),
        WalletError::WrongPassword
    );
    assert!(!engine().is_unlocked());
    unlock_with_password(&blob, &pw("a good password")).unwrap();
    assert_eq!(accounts::derive_accounts(0).unwrap(), before);

    // Re-authentication shows the phrase the wallet was made with.
    assert_eq!(reveal_phrase(&blob, &pw("a good password")).unwrap(), words);
    assert_eq!(reveal_phrase(&blob, &pw("nope")).unwrap_err(), WalletError::WrongPassword);

    // The biometric key opens the vault without the password, only this vault.
    let key = export_unlock_key(&blob, &pw("a good password")).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(export_unlock_key(&blob, &pw("nope")).unwrap_err(), WalletError::WrongPassword);
    engine().lock();
    unlock_with_key(&blob, &Zeroizing::new(key.clone())).unwrap();
    assert_eq!(accounts::derive_accounts(0).unwrap(), before);
    engine().lock();
    assert_eq!(
        unlock_with_key(&blob, &Zeroizing::new(vec![0; 32])).unwrap_err(),
        WalletError::WrongPassword
    );
    assert_eq!(
        unlock_with_key(&blob, &Zeroizing::new(vec![0; 5])).unwrap_err(),
        WalletError::WrongPassword
    );

    // A new password: the old one stops working, the key is replaced.
    let renewed = change_password(&blob, &pw("a good password"), &pw("another password")).unwrap();
    assert_ne!(renewed, blob);
    assert_eq!(
        unlock_with_password(&renewed, &pw("a good password")).unwrap_err(),
        WalletError::WrongPassword
    );
    unlock_with_password(&renewed, &pw("another password")).unwrap();
    assert_eq!(accounts::derive_accounts(0).unwrap(), before);
    assert_eq!(
        unlock_with_key(&renewed, &Zeroizing::new(key)).unwrap_err(),
        WalletError::WrongPassword
    );
    assert_eq!(
        change_password(&blob, &pw("wrong"), &pw("another password")).unwrap_err(),
        WalletError::WrongPassword
    );

    // Garbage is not a vault.
    assert_eq!(unlock_with_password(b"nonsense", &pw("x")).unwrap_err(), WalletError::NotAVault);
    assert_eq!(vault_facts(b"nonsense").unwrap_err(), WalletError::NotAVault);
    engine().lock();
}

#[test]
fn the_api_functions_drive_the_same_engine() {
    let _one_at_a_time = serial();
    vault::lock();
    phrase::discard_pending();

    phrase::start_new_wallet(PhraseLength::TwentyFour).unwrap();
    assert_eq!(phrase::pending_word_count().unwrap(), 24);
    let words = phrase::pending_phrase().unwrap();
    assert_eq!(words.len(), 24);
    let questions = phrase::backup_questions().unwrap();
    assert_eq!(questions.len(), 3);
    // A wrong choice is refused; the right one is accepted.
    let first = &questions[0];
    let right = &words[first.position as usize - 1];
    let wrong = first.choices.iter().find(|c| *c != right).unwrap();
    assert!(!phrase::check_backup_answer(first.position, wrong.clone()).unwrap());
    // A wrong answer draws that question again: the app reads the questions again.
    let questions = phrase::backup_questions().unwrap();
    assert_eq!(questions.len(), 3);
    for question in &questions {
        assert!(
            phrase::check_backup_answer(
                question.position,
                words[question.position as usize - 1].clone()
            )
            .unwrap()
        );
    }
    let blob = vault::seal_pending("a good password".to_owned()).unwrap();
    vault::commit_pending().unwrap();
    assert!(vault::is_unlocked());
    let key = vault::take_new_unlock_key().unwrap();
    assert_eq!(vault::take_new_unlock_key().unwrap_err(), WalletError::NoNewKey);
    assert_eq!(key.len(), 32);
    vault::lock();
    vault::unlock_with_key(blob.clone(), key).unwrap();
    assert_eq!(accounts::derive_accounts(0).unwrap().len(), 9);
    vault::lock();
    assert_eq!(
        vault::reveal_phrase(blob, "a good password".to_owned()).unwrap(),
        words,
        "the phrase made is the phrase sealed"
    );
    phrase::discard_pending();
}

#[test]
fn typed_phrases_are_checked_by_the_session() {
    let found = phrase::check_phrase(ABANDON.to_owned());
    assert_eq!((found.problem, found.word_count), (PhraseProblem::Valid, 12));
    let found = phrase::check_phrase("abandon abandn".to_owned());
    assert_eq!(found.problem, PhraseProblem::UnknownWord);
    assert_eq!(found.position, 2);
    assert!(found.suggestions.iter().any(|s| s == "abandon"));
    assert_eq!(phrase::check_phrase(["abandon"; 12].join(" ")).problem, PhraseProblem::BadChecksum);
    assert_eq!(
        phrase::check_phrase(["abandon"; 5].join(" ")).problem,
        PhraseProblem::WrongWordCount
    );
    assert_eq!(phrase::check_phrase(String::new()).problem, PhraseProblem::Empty);
    assert_eq!(phrase::complete_word("aba".to_owned(), 5), ["abandon"]);
}

#[test]
fn the_nine_accounts_come_through_in_order() {
    let _one_at_a_time = serial();
    engine().lock();
    engine().start_import(ABANDON, "").unwrap();
    seal_pending("a good password").unwrap();
    engine().commit_pending().unwrap();

    let accounts = accounts::derive_accounts(0).unwrap();
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
    // MetaMask and Trust Wallet show this address for this phrase at m/44'/60'/0'/0/0.
    let ethereum = account(&accounts, NetworkId::Ethereum);
    assert_eq!(ethereum.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    assert_eq!(ethereum.path, "m/44'/60'/0'/0/0");
    assert_eq!(
        account(&accounts, NetworkId::Bitcoin).address,
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(account(&accounts, NetworkId::Bittensor).path, "");
    assert_eq!(
        accounts::derive_accounts(1 << 31).unwrap_err(),
        WalletError::AccountIndexOutOfRange
    );
    engine().lock();
}

#[test]
fn the_solana_account_trust_wallet_shows_comes_through_for_an_import_and_for_the_unlocked_wallet() {
    // Trust Wallet Core's own phrase for its Solana address (`TWSolanaAddress.HDWallet`).
    const SHOOT: &str =
        "shoot island position soft burden budget tooth cruel issue economy destroy above";
    let _one_at_a_time = serial();
    engine().lock();
    engine().discard_pending();
    assert_eq!(
        accounts::derive_trust_wallet_solana_account().unwrap_err(),
        WalletError::NotUnlocked
    );
    // While the phrase is being imported, before it is sealed: where its funds may be.
    engine().start_import(SHOOT, "").unwrap();
    let found = accounts::derive_trust_wallet_solana_account().unwrap();
    assert_eq!(found.network, NetworkId::Solana);
    assert_eq!(found.address, "2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m");
    assert_eq!(found.path, "m/44'/501'/0'");
    assert_eq!(found.public_key_hex.len(), 64);
    // The wallet's own Solana account is another, at Phantom's path, and as it was.
    seal_pending("a good password").unwrap();
    engine().commit_pending().unwrap();
    let own = accounts::derive_accounts(0).unwrap();
    let own = account(&own, NetworkId::Solana);
    assert_ne!(own.address, found.address);
    assert_eq!(own.path, "m/44'/501'/0'/0'");
    assert_eq!(accounts::derive_trust_wallet_solana_account().unwrap(), found);
    // Locked, none.
    engine().lock();
    assert_eq!(
        accounts::derive_trust_wallet_solana_account().unwrap_err(),
        WalletError::NotUnlocked
    );
}

#[test]
fn unlock_time_can_be_measured() {
    let _one_at_a_time = serial();
    let ms = measure_unlock_ms().unwrap();
    assert!(ms < 60_000);
}

// ---- the conversions: Dart reads these enums by position ----

#[test]
fn every_error_keeps_its_name_and_its_place() {
    use session::SessionError as E;
    let pairs = [
        (E::WrongPassword, WalletError::WrongPassword),
        (E::EmptyPassword, WalletError::EmptyPassword),
        (E::NotAVault, WalletError::NotAVault),
        (E::UnsupportedVault, WalletError::UnsupportedVault),
        (E::PassphraseTooLong, WalletError::PassphraseTooLong),
        (E::InvalidPhrase, WalletError::InvalidPhrase),
        (E::NoPendingWallet, WalletError::NoPendingWallet),
        (E::NotUnlocked, WalletError::NotUnlocked),
        (E::NoQuiz, WalletError::NoQuiz),
        (E::BackupNotConfirmed, WalletError::BackupNotConfirmed),
        (E::NoNewKey, WalletError::NoNewKey),
        (E::AccountIndexOutOfRange, WalletError::AccountIndexOutOfRange),
        (E::Unavailable, WalletError::Unavailable),
    ];
    // The bridge writes Dart enums in declaration order: the two enums must
    // list the same variants in the same order.
    let order: Vec<String> = pairs.iter().map(|(_, w)| format!("{w:?}")).collect();
    assert_eq!(order.len(), 13);
    for (index, (from, to)) in pairs.into_iter().enumerate() {
        assert_eq!(format!("{from:?}"), format!("{to:?}"));
        assert_eq!(WalletError::from(from), to);
        assert_eq!(order[index], format!("{to:?}"));
        // And the app's own display text still says nothing secret.
        assert!(!to.to_string().contains("abandon"));
    }
}

#[test]
fn every_problem_and_network_keeps_its_name() {
    use session::NetworkId as N;
    use session::PhraseProblem as P;
    for (from, to) in [
        (P::Empty, PhraseProblem::Empty),
        (P::Valid, PhraseProblem::Valid),
        (P::UnknownWord, PhraseProblem::UnknownWord),
        (P::WrongWordCount, PhraseProblem::WrongWordCount),
        (P::BadChecksum, PhraseProblem::BadChecksum),
    ] {
        assert_eq!(format!("{from:?}"), format!("{to:?}"));
        assert_eq!(PhraseProblem::from(from), to);
    }
    for (from, to) in [
        (N::Ethereum, NetworkId::Ethereum),
        (N::BnbChain, NetworkId::BnbChain),
        (N::Polygon, NetworkId::Polygon),
        (N::Base, NetworkId::Base),
        (N::Tron, NetworkId::Tron),
        (N::Bitcoin, NetworkId::Bitcoin),
        (N::Solana, NetworkId::Solana),
        (N::Stellar, NetworkId::Stellar),
        (N::Bittensor, NetworkId::Bittensor),
    ] {
        assert_eq!(format!("{from:?}"), format!("{to:?}"));
        assert_eq!(NetworkId::from(from), to);
    }
    assert_eq!(session::PhraseLength::from(PhraseLength::Twelve), session::PhraseLength::Twelve);
    assert_eq!(
        session::PhraseLength::from(PhraseLength::TwentyFour),
        session::PhraseLength::TwentyFour
    );
}
