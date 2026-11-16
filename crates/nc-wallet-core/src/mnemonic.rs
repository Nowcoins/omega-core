//! Recovery phrases (BIP-39, English) and the seed they stand for.

use std::fmt;
use std::str::FromStr;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, MnemonicError};

/// How many words a new recovery phrase has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordCount {
    /// 12 words: 128 bits of entropy.
    Twelve,
    /// 24 words: 256 bits of entropy.
    TwentyFour,
}

impl WordCount {
    /// Bytes of entropy behind a phrase this long.
    const fn entropy_len(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::TwentyFour => 32,
        }
    }
}

/// A BIP-39 recovery phrase in the English wordlist.
///
/// The words are wiped from memory when the value is dropped. `Debug` shows
/// the word count and nothing else, and there is no `Display`: the only way
/// to read the words is [`Mnemonic::expose_phrase`].
///
/// Phrases of 12, 15, 18, 21 and 24 words are accepted, as other wallets make
/// them; new ones are 12 or 24 ([`WordCount`]).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    inner: bip39::Mnemonic,
}

impl Mnemonic {
    /// A new phrase from the operating system's secure random source (the
    /// browser's `crypto.getRandomValues` on WebAssembly).
    ///
    /// Fails, rather than falling back to anything weaker, if that source is
    /// unavailable.
    pub fn generate(words: WordCount) -> Result<Self, Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        let bytes = &mut entropy[..words.entropy_len()];
        getrandom::getrandom(bytes).map_err(|_| Error::Randomness)?;
        Ok(Self::from_entropy(checked_entropy(bytes)?)?)
    }

    /// The phrase that encodes `entropy` (16, 20, 24, 28 or 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, MnemonicError> {
        bip39::Mnemonic::from_entropy(entropy).map(|inner| Self { inner }).map_err(map_error)
    }

    /// Reads a phrase typed or pasted by a person and checks it, checksum
    /// included.
    ///
    /// Any run of whitespace between words is one space, ends are trimmed,
    /// and capitals are lowercased; nothing else is forgiven.
    pub fn parse(phrase: &str) -> Result<Self, MnemonicError> {
        let mut clean = Zeroizing::new(String::with_capacity(phrase.len()));
        for (i, word) in phrase.split_whitespace().enumerate() {
            if i > 0 {
                clean.push(' ');
            }
            clean.push_str(word);
        }
        if clean.is_empty() {
            return Err(MnemonicError::Empty);
        }
        clean.make_ascii_lowercase();
        bip39::Mnemonic::parse_in(bip39::Language::English, clean.as_str())
            .map(|inner| Self { inner })
            .map_err(map_error)
    }

    /// How many words the phrase has.
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// The words, separated by single spaces. This is the one way to read a
    /// phrase back (the backup screen, an export); the copy wipes itself when
    /// dropped.
    pub fn expose_phrase(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(8 * self.word_count()));
        for (i, word) in self.inner.words().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(word);
        }
        out
    }

    /// The BIP-39 seed: 2048 rounds of PBKDF2-HMAC-SHA512 over the phrase,
    /// salted with `"mnemonic"` and the optional `passphrase` (NFKD
    /// normalised). Pass `""` for no passphrase. A different passphrase gives
    /// a different, equally valid wallet; there is no way to tell that it is
    /// the "wrong" one.
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        let seed = Zeroizing::new(self.inner.to_seed(passphrase));
        Seed(*seed)
    }

    /// The entropy the phrase encodes (16 to 32 bytes). Substrate keys are
    /// made from this, not from the BIP-39 seed.
    pub(crate) fn entropy(&self) -> Zeroizing<Vec<u8>> {
        let (bytes, len) = self.inner.to_entropy_array();
        let bytes = Zeroizing::new(bytes);
        Zeroizing::new(bytes[..len].to_vec())
    }
}

impl FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(phrase: &str) -> Result<Self, Self::Err> {
        Self::parse(phrase)
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic({} words, <redacted>)", self.word_count())
    }
}

/// The 64-byte BIP-39 seed that BIP-32 and SLIP-10 start from. Wiped when
/// dropped; `Debug` prints nothing of it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// The seed's bytes. Named like this on purpose: grep for it to find
    /// every place a seed is read.
    pub fn expose_secret(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// Refuses a buffer the random source left all zero (it either failed
/// silently or is not random). 128 random bits are all zero with probability
/// 2^-128, so this never turns a good source away.
fn checked_entropy(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.iter().all(|b| *b == 0) { Err(Error::Randomness) } else { Ok(bytes) }
}

fn map_error(error: bip39::Error) -> MnemonicError {
    match error {
        bip39::Error::BadWordCount(count) => {
            if count == 0 {
                MnemonicError::Empty
            } else {
                MnemonicError::WordCount(count)
            }
        }
        bip39::Error::UnknownWord(index) => MnemonicError::UnknownWord { position: index + 1 },
        bip39::Error::BadEntropyBitCount(bits) => MnemonicError::EntropyLength(bits / 8),
        bip39::Error::InvalidChecksum => MnemonicError::Checksum,
        // Only the English list is compiled in, so a phrase can never be
        // ambiguous between languages; if it somehow were, it is not valid.
        bip39::Error::AmbiguousLanguages(_) => MnemonicError::UnknownWord { position: 1 },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_randomness_is_refused() {
        assert_eq!(checked_entropy(&[0u8; 16]), Err(Error::Randomness));
        assert_eq!(checked_entropy(&[0u8; 32]), Err(Error::Randomness));
        assert!(checked_entropy(&[0, 0, 0, 1]).is_ok());
    }

    #[test]
    fn generated_phrases_are_valid_and_different() {
        let a = Mnemonic::generate(WordCount::Twelve).unwrap();
        let b = Mnemonic::generate(WordCount::Twelve).unwrap();
        let c = Mnemonic::generate(WordCount::TwentyFour).unwrap();
        assert_eq!(a.word_count(), 12);
        assert_eq!(c.word_count(), 24);
        assert_ne!(*a.expose_phrase(), *b.expose_phrase());
        // What was shown parses back to the same phrase.
        let again = Mnemonic::parse(&a.expose_phrase()).unwrap();
        assert_eq!(*again.expose_phrase(), *a.expose_phrase());
        let again = Mnemonic::parse(&c.expose_phrase()).unwrap();
        assert_eq!(*again.expose_phrase(), *c.expose_phrase());
    }
}
