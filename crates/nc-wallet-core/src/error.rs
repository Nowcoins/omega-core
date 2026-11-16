//! Errors. None of them carries a word, a passphrase or a key: an error value
//! is safe to log and to show.

/// Why a recovery phrase was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MnemonicError {
    /// The phrase has no words.
    #[error("the recovery phrase is empty")]
    Empty,

    /// The number of words is not one BIP-39 allows.
    #[error("a recovery phrase has 12, 15, 18, 21 or 24 words, this one has {0}")]
    WordCount(usize),

    /// A word is not in the English BIP-39 wordlist. `position` counts from 1.
    #[error("word {position} is not in the English BIP-39 wordlist")]
    UnknownWord {
        /// Where the word stands in the phrase, counting from 1.
        position: usize,
    },

    /// Every word is valid but together they do not pass BIP-39's checksum:
    /// a word is wrong, missing or out of order.
    #[error("the recovery phrase's checksum does not match: a word is wrong or out of order")]
    Checksum,

    /// Entropy of a length BIP-39 has no phrase for (16, 20, 24, 28 or 32
    /// bytes only).
    #[error("entropy of {0} bytes does not make a recovery phrase (16, 20, 24, 28 or 32 bytes)")]
    EntropyLength(usize),
}

/// Why a key or an address could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The recovery phrase was refused.
    #[error(transparent)]
    Mnemonic(#[from] MnemonicError),

    /// The operating system's random source failed or returned nothing but
    /// zeros. No phrase is made from a source that cannot be trusted.
    #[error("the system's secure random source is unavailable")]
    Randomness,

    /// The account index does not fit the derivation path: a BIP-32 element
    /// is below 2^31.
    #[error("account index {0} is out of range, it must be below 2147483648")]
    IndexOutOfRange(u32),

    /// Derivation hit a key that is not valid (probability about 2^-127). The
    /// standard answer is to move to the next index.
    #[error("account index {0} gives an invalid key, use the next index")]
    InvalidKey(u32),

    /// The phrase's entropy could not be turned into a Substrate key.
    #[error("the recovery phrase cannot be turned into a Bittensor key")]
    Substrate,

    /// The network is derived from the recovery phrase itself, not from the
    /// BIP-39 seed, so a seed alone is not enough (Bittensor).
    #[error("this network needs the recovery phrase itself, not only its seed")]
    NeedsPhrase,
}
