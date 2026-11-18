//! The one error type Dart sees. No value carries a word, a password or a key.

use std::fmt;

/// Why a call failed. The app shows its own words for each; none of these
/// carries anything secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    /// The password does not open the vault, or the stored vault is damaged.
    /// The two cannot be told apart.
    WrongPassword,
    /// The password is empty.
    EmptyPassword,
    /// The stored bytes are not a Nowcoin Omega vault.
    NotAVault,
    /// The vault was written by a newer version of the app.
    UnsupportedVault,
    /// The passphrase is longer than the vault keeps.
    PassphraseTooLong,
    /// The typed recovery phrase is not valid. `check_phrase` says why.
    InvalidPhrase,
    /// There is no wallet being made or imported.
    NoPendingWallet,
    /// The wallet is locked.
    NotUnlocked,
    /// The backup quiz was not asked, or that position is not in it.
    NoQuiz,
    /// A new wallet cannot be sealed before its backup was checked.
    BackupNotConfirmed,
    /// There is no new vault key to take: it was taken, dropped, or the wallet
    /// was locked since.
    NoNewKey,
    /// The account index is not one a derivation path can take (below 2^31).
    AccountIndexOutOfRange,
    /// The system's secure random source failed, or the phone has no memory
    /// to spare for the key derivation. Nothing was changed.
    Unavailable,
    /// The pasted private key is not one the wallet reads. `check_key` says why.
    InvalidKey,
    /// The wallet is one private key and has no recovery phrase to show.
    HoldsAKey,
    /// The wallet is a recovery phrase and has no single private key to show.
    HoldsAPhrase,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "wrong password, or the vault is damaged",
            Self::EmptyPassword => "the password is empty",
            Self::NotAVault => "this is not a Nowcoin Omega vault",
            Self::UnsupportedVault => "this vault was made by a newer version of the app",
            Self::PassphraseTooLong => "the passphrase is too long",
            Self::InvalidPhrase => "the recovery phrase is not valid",
            Self::NoPendingWallet => "no wallet is being made",
            Self::NotUnlocked => "the wallet is locked",
            Self::NoQuiz => "the backup check was not asked",
            Self::BackupNotConfirmed => "the recovery phrase was not checked yet",
            Self::NoNewKey => "there is no new unlock key",
            Self::AccountIndexOutOfRange => "the account number is out of range",
            Self::Unavailable => "the secure random source or memory is unavailable",
            Self::InvalidKey => "the private key is not valid",
            Self::HoldsAKey => "this wallet is one private key and has no recovery phrase",
            Self::HoldsAPhrase => "this wallet is a recovery phrase and has no single private key",
        })
    }
}

impl std::error::Error for WalletError {}
