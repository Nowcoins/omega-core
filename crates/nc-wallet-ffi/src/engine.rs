//! The process-wide engine, and the glue between the bridge's types and the
//! session's.
//!
//! The logic (the wallet being made, the quiz, sealing, the unlocked session,
//! typed-phrase checks) lives in `nc-wallet-session`, which the Chrome
//! extension's WebAssembly shares. What is left here is what only the Android
//! bridge needs: one engine per process behind a lock, Argon2id run with that
//! lock released, and the conversions to the types `flutter_rust_bridge` writes
//! Dart for (their names and variant order are the Dart side's contract, so
//! they stay defined in `api`).

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use nc_wallet_session::{self as session, Engine};
use zeroize::Zeroizing;

use crate::api::accounts::{NetworkAccount, NetworkId};
use crate::api::error::WalletError;
use crate::api::key::{KeyCheck, KeyProblem, WalletKind};
use crate::api::phrase::{BackupQuestion, PhraseCheck, PhraseLength, PhraseProblem};
use crate::api::signing::{AddressCheck, AddressProblem, SigningError};
use crate::api::vault::VaultFacts;

static ENGINE: Mutex<Engine> = Mutex::new(Engine::new());

/// The process-wide engine. A panic while it was held does not lock the wallet
/// out: the state is plain data.
pub(crate) fn engine() -> MutexGuard<'static, Engine> {
    ENGINE.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- the vault ----

/// Seals the wallet being made; the wallet is unlocked by `commit_pending`.
/// The lock is not held while Argon2id runs.
pub(crate) fn seal_pending(password: &str) -> Result<Vec<u8>, WalletError> {
    let job = engine().begin_seal()?;
    let done = job.seal(password);
    Ok(engine().finish_seal(done)?)
}

pub(crate) fn unlock_with_password(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<(), WalletError> {
    let unlocked = session::open_with_password(blob, password)?;
    engine().install(unlocked);
    Ok(())
}

pub(crate) fn unlock_with_key(blob: &[u8], key: &Zeroizing<Vec<u8>>) -> Result<(), WalletError> {
    let unlocked = session::open_with_key(blob, key)?;
    engine().install(unlocked);
    Ok(())
}

pub(crate) fn export_unlock_key(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<Vec<u8>, WalletError> {
    Ok(session::export_unlock_key(blob, password)?)
}

pub(crate) fn reveal_phrase(
    blob: &[u8],
    password: &Zeroizing<String>,
) -> Result<Vec<String>, WalletError> {
    Ok(session::reveal_phrase(blob, password)?)
}

/// The private key of a key wallet, as text. The copy the session hands over is
/// wiped here; the `String` that crosses to Dart is the one the app shows.
pub(crate) fn reveal_key(blob: &[u8], password: &Zeroizing<String>) -> Result<String, WalletError> {
    let text = session::reveal_key(blob, password)?;
    Ok(text.as_str().to_owned())
}

pub(crate) fn change_password(
    blob: &[u8],
    old: &Zeroizing<String>,
    new: &Zeroizing<String>,
) -> Result<Vec<u8>, WalletError> {
    Ok(session::change_password(blob, old, new)?)
}

pub(crate) fn vault_facts(blob: &[u8]) -> Result<VaultFacts, WalletError> {
    Ok(session::vault_facts(blob)?.into())
}

pub(crate) fn measure_unlock_ms() -> Result<u32, WalletError> {
    let blob = session::throwaway_vault()?;
    let started = Instant::now();
    session::open_throwaway(&blob)?;
    Ok(u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX))
}

// ---- signing ----

/// Whether `text` is an address on `network`.
pub(crate) fn validate_address(network: NetworkId, text: &str) -> AddressCheck {
    let network = session::NetworkId::from(network);
    session::validate_address(network.api_id(), text).into()
}

/// The address lookup tables a Solana transaction (base64) needs.
pub(crate) fn solana_lookup_tables(transaction_base64: &str) -> Result<Vec<String>, SigningError> {
    Ok(session::solana_lookup_tables(transaction_base64)?)
}

/// Bytes as lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The approval hash as the app hands it back: exactly 64 hex digits.
pub(crate) fn parse_approval(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

// ---- conversions ----

impl From<session::SigningError> for SigningError {
    fn from(error: session::SigningError) -> Self {
        // The session's codes are stable strings (the extension matches on them).
        match error.code() {
            "NotUnlocked" => Self::NotUnlocked,
            "AccountIndexOutOfRange" => Self::AccountIndexOutOfRange,
            "BadRequest" => Self::BadRequest,
            "Unsupported" => Self::Unsupported,
            "NotASigner" => Self::NotASigner,
            "ApprovalMismatch" => Self::ApprovalMismatch,
            "InsufficientFunds" => Self::InsufficientFunds,
            "Dust" => Self::Dust,
            "NoTrustline" => Self::NoTrustline,
            "MemoRequired" => Self::MemoRequired,
            "RecipientIsTokenAccount" => Self::RecipientIsTokenAccount,
            "LooksLikeTransaction" => Self::LooksLikeTransaction,
            "FeeTooHigh" => Self::FeeTooHigh,
            "FeeNotAccepted" => Self::FeeNotAccepted,
            // Anything else, `ChainMismatch` (typed data for another chain, not allowed by the request)
            // included: the app blocks that before it asks for a signature, and one that gets this far is
            // not signed. It has no variant of its own until the bindings are regenerated.
            _ => Self::Unavailable,
        }
    }
}

impl From<session::AddressCheck> for AddressCheck {
    fn from(check: session::AddressCheck) -> Self {
        Self {
            valid: check.valid,
            normalized: check.normalized,
            problem: check.reason.map(|reason| match reason {
                "empty" => AddressProblem::Empty,
                "checksum" => AddressProblem::Checksum,
                "zero_address" => AddressProblem::ZeroAddress,
                "unsupported_network" => AddressProblem::UnsupportedNetwork,
                _ => AddressProblem::Format,
            }),
        }
    }
}

impl From<NetworkId> for session::NetworkId {
    fn from(network: NetworkId) -> Self {
        match network {
            NetworkId::Ethereum => Self::Ethereum,
            NetworkId::BnbChain => Self::BnbChain,
            NetworkId::Polygon => Self::Polygon,
            NetworkId::Base => Self::Base,
            NetworkId::Tron => Self::Tron,
            NetworkId::Bitcoin => Self::Bitcoin,
            NetworkId::Solana => Self::Solana,
            NetworkId::Stellar => Self::Stellar,
            NetworkId::Bittensor => Self::Bittensor,
        }
    }
}

impl From<session::SessionError> for WalletError {
    fn from(error: session::SessionError) -> Self {
        use session::SessionError as E;
        match error {
            E::WrongPassword => Self::WrongPassword,
            E::EmptyPassword => Self::EmptyPassword,
            E::NotAVault => Self::NotAVault,
            E::UnsupportedVault => Self::UnsupportedVault,
            E::PassphraseTooLong => Self::PassphraseTooLong,
            E::InvalidPhrase => Self::InvalidPhrase,
            E::NoPendingWallet => Self::NoPendingWallet,
            E::NotUnlocked => Self::NotUnlocked,
            E::NoQuiz => Self::NoQuiz,
            E::BackupNotConfirmed => Self::BackupNotConfirmed,
            E::NoNewKey => Self::NoNewKey,
            E::AccountIndexOutOfRange => Self::AccountIndexOutOfRange,
            E::Unavailable => Self::Unavailable,
            E::InvalidKey => Self::InvalidKey,
            E::HoldsAKey => Self::HoldsAKey,
            E::HoldsAPhrase => Self::HoldsAPhrase,
        }
    }
}

impl From<session::WalletKind> for WalletKind {
    fn from(kind: session::WalletKind) -> Self {
        use session::WalletKind as K;
        match kind {
            K::Phrase => Self::Phrase,
            K::KeySecp256k1 => Self::KeySecp256K1,
            K::KeyEd25519 => Self::KeyEd25519,
        }
    }
}

impl From<session::KeyProblem> for KeyProblem {
    fn from(problem: session::KeyProblem) -> Self {
        use session::KeyProblem as P;
        match problem {
            P::Empty => Self::Empty,
            P::Valid => Self::Valid,
            P::Unrecognised => Self::Unrecognised,
            P::LooksLikeAnAddress => Self::LooksLikeAnAddress,
            P::NotOnCurve => Self::NotOnCurve,
            P::HalvesDisagree => Self::HalvesDisagree,
        }
    }
}

impl From<session::KeyCheck> for KeyCheck {
    fn from(check: session::KeyCheck) -> Self {
        Self { problem: check.problem.into(), kind: check.kind.map(Into::into) }
    }
}

impl From<PhraseLength> for session::PhraseLength {
    fn from(length: PhraseLength) -> Self {
        match length {
            PhraseLength::Twelve => Self::Twelve,
            PhraseLength::TwentyFour => Self::TwentyFour,
        }
    }
}

impl From<session::PhraseProblem> for PhraseProblem {
    fn from(problem: session::PhraseProblem) -> Self {
        use session::PhraseProblem as P;
        match problem {
            P::Empty => Self::Empty,
            P::Valid => Self::Valid,
            P::UnknownWord => Self::UnknownWord,
            P::WrongWordCount => Self::WrongWordCount,
            P::BadChecksum => Self::BadChecksum,
        }
    }
}

impl From<session::PhraseCheck> for PhraseCheck {
    fn from(check: session::PhraseCheck) -> Self {
        Self {
            problem: check.problem.into(),
            word_count: check.word_count,
            position: check.position,
            suggestions: check.suggestions,
        }
    }
}

impl From<session::BackupQuestion> for BackupQuestion {
    fn from(question: session::BackupQuestion) -> Self {
        Self { position: question.position, choices: question.choices }
    }
}

impl From<session::NetworkId> for NetworkId {
    fn from(network: session::NetworkId) -> Self {
        use session::NetworkId as N;
        match network {
            N::Ethereum => Self::Ethereum,
            N::BnbChain => Self::BnbChain,
            N::Polygon => Self::Polygon,
            N::Base => Self::Base,
            N::Tron => Self::Tron,
            N::Bitcoin => Self::Bitcoin,
            N::Solana => Self::Solana,
            N::Stellar => Self::Stellar,
            N::Bittensor => Self::Bittensor,
        }
    }
}

impl From<session::NetworkAccount> for NetworkAccount {
    fn from(account: session::NetworkAccount) -> Self {
        Self {
            network: account.network.into(),
            address: account.address,
            public_key_hex: account.public_key_hex,
            path: account.path,
        }
    }
}

impl From<session::VaultFacts> for VaultFacts {
    fn from(facts: session::VaultFacts) -> Self {
        Self {
            version: facts.version,
            memory_kib: facts.memory_kib,
            iterations: facts.iterations,
            lanes: facts.lanes,
        }
    }
}

#[cfg(test)]
mod signing_tests;
#[cfg(test)]
mod tests;
