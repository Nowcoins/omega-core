//! Making and importing a recovery phrase.
//!
//! A new wallet is made in three steps, with the phrase held in Rust all along:
//! [`start_new_wallet`], the backup screen ([`pending_phrase`]), the quiz
//! ([`backup_questions`] and [`check_backup_answer`]); then
//! [`crate::api::vault::seal_pending`] seals it under a password. An imported
//! wallet skips the quiz: [`check_phrase`] says whether the typed text is a
//! phrase, [`start_import`] takes it.

// The bridge hands each argument over by value; there is no borrowing across it.
#![allow(clippy::needless_pass_by_value)]

use flutter_rust_bridge::frb;

use super::error::WalletError;
use crate::engine::engine;

/// How many words a new recovery phrase has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseLength {
    /// 12 words (128 bits).
    Twelve,
    /// 24 words (256 bits).
    TwentyFour,
}

/// What `check_phrase` found in the text a person typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseProblem {
    /// Nothing typed yet.
    Empty,
    /// A valid recovery phrase (12, 15, 18, 21 or 24 words).
    Valid,
    /// The first word that is not in the BIP-39 English list.
    UnknownWord,
    /// Every word is in the list but there are not 12, 15, 18, 21 or 24.
    WrongWordCount,
    /// The right number of words, all in the list, but the checksum fails:
    /// a word is wrong, missing or out of order.
    BadChecksum,
}

/// The result of reading typed text as a recovery phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhraseCheck {
    /// What was found.
    pub problem: PhraseProblem,
    /// How many words were typed.
    pub word_count: u32,
    /// For `UnknownWord`: where the word stands, counting from 1. Otherwise 0.
    pub position: u32,
    /// For `UnknownWord`: up to three words from the list that it starts like
    /// or differs from by a letter. Otherwise empty.
    pub suggestions: Vec<String>,
}

/// One question of the backup check: which word stands at `position`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupQuestion {
    /// The word's place in the phrase, from 1.
    pub position: u32,
    /// Six words, one of them the answer, in random order.
    pub choices: Vec<String>,
}

/// Starts a new wallet: makes a phrase from the system's secure randomness and
/// holds it in Rust until it is sealed or discarded. Replaces any wallet being
/// made.
pub fn start_new_wallet(length: PhraseLength) -> Result<(), WalletError> {
    Ok(engine().start_new(length.into())?)
}

/// The words of the phrase being made, for the backup screen. This is the one
/// place a new phrase reaches Dart; the app keeps it only while it is shown.
#[frb(sync)]
pub fn pending_phrase() -> Result<Vec<String>, WalletError> {
    Ok(engine().pending_words()?)
}

/// How many words the phrase being made has (12 or 24), for laying out the
/// backup screen while the words are hidden.
#[frb(sync)]
pub fn pending_word_count() -> Result<u32, WalletError> {
    Ok(engine().pending_word_count()?)
}

/// Three questions about the phrase being made, in the order of their
/// positions. Asked once: calling again gives the same questions.
#[frb(sync)]
pub fn backup_questions() -> Result<Vec<BackupQuestion>, WalletError> {
    Ok(engine().quiz()?.into_iter().map(Into::into).collect())
}

/// Whether `word` is the word at `position` in the phrase being made. The
/// position must be one of the quiz's.
#[frb(sync)]
pub fn check_backup_answer(position: u32, word: String) -> Result<bool, WalletError> {
    Ok(engine().check_answer(position, &word)?)
}

/// Forgets the wallet being made or imported, wiping its phrase.
#[frb(sync)]
pub fn discard_pending() {
    engine().discard_pending();
}

/// Reads typed text as a recovery phrase and says what is wrong with it, if
/// anything. The text is not kept.
#[frb(sync)]
pub fn check_phrase(text: String) -> PhraseCheck {
    nc_wallet_session::check_phrase(&text).into()
}

/// Up to `limit` words of the BIP-39 list that start with `prefix`, for
/// completing a word as it is typed.
#[frb(sync)]
pub fn complete_word(prefix: String, limit: u32) -> Vec<String> {
    nc_wallet_session::complete_word(&prefix, limit as usize)
}

/// Starts an imported wallet from the typed phrase and the optional BIP-39
/// passphrase (`""` for none). Replaces any wallet being made.
pub fn start_import(text: String, passphrase: String) -> Result<(), WalletError> {
    Ok(engine().start_import(&text, &passphrase)?)
}
