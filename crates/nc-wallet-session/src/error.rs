//! The one error type the apps see. No value carries a word, a password or a key.

use std::fmt;

use nc_wallet_core::vault::VaultError;
use nc_wallet_core::{Error as CoreError, MnemonicError};

/// Why a call failed. The apps show their own words for each; none of these
/// carries anything secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
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
    /// The system's secure random source failed, or the device has no memory
    /// to spare for the key derivation. Nothing was changed.
    Unavailable,
}

impl SessionError {
    /// A stable name for the variant, for apps that cannot share the enum
    /// itself (the extension's TypeScript matches on these).
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongPassword => "WrongPassword",
            Self::EmptyPassword => "EmptyPassword",
            Self::NotAVault => "NotAVault",
            Self::UnsupportedVault => "UnsupportedVault",
            Self::PassphraseTooLong => "PassphraseTooLong",
            Self::InvalidPhrase => "InvalidPhrase",
            Self::NoPendingWallet => "NoPendingWallet",
            Self::NotUnlocked => "NotUnlocked",
            Self::NoQuiz => "NoQuiz",
            Self::BackupNotConfirmed => "BackupNotConfirmed",
            Self::NoNewKey => "NoNewKey",
            Self::AccountIndexOutOfRange => "AccountIndexOutOfRange",
            Self::Unavailable => "Unavailable",
        }
    }
}

impl fmt::Display for SessionError {
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
        })
    }
}

impl std::error::Error for SessionError {}

impl From<VaultError> for SessionError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::EmptyPassword => Self::EmptyPassword,
            VaultError::PassphraseTooLong => Self::PassphraseTooLong,
            VaultError::UnsupportedVersion(_) | VaultError::UnsupportedAlgorithm => {
                Self::UnsupportedVault
            }
            // A damaged vault and a wrong password look the same; so does a
            // key that does not fit. `Corrupt` means the cipher opened it and
            // the contents were wrong, which only a bug or an attacker with
            // the password could make.
            VaultError::Authentication | VaultError::Corrupt | VaultError::BadKey => {
                Self::WrongPassword
            }
            // Parameters outside what a vault may ask for: not one of ours.
            VaultError::NotAVault | VaultError::BadParams => Self::NotAVault,
            VaultError::Kdf | VaultError::Randomness => Self::Unavailable,
        }
    }
}

impl From<MnemonicError> for SessionError {
    fn from(_: MnemonicError) -> Self {
        Self::InvalidPhrase
    }
}

impl From<CoreError> for SessionError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Mnemonic(_) => Self::InvalidPhrase,
            CoreError::IndexOutOfRange(_) => Self::AccountIndexOutOfRange,
            _ => Self::Unavailable,
        }
    }
}
