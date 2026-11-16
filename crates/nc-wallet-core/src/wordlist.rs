//! The BIP-39 English wordlist, for screens that take a recovery phrase as
//! typed input: is this a word, and which words start like it.
//!
//! This is the same list [`crate::Mnemonic::parse`] checks against. It is
//! public information, not a secret.

use bip39::Language;

/// All 2048 words, in BIP-39's order (sorted; the first four letters of a
/// word identify it).
pub fn all() -> &'static [&'static str; 2048] {
    Language::English.word_list()
}

/// Whether `word` is in the list (lowercase, exact).
pub fn contains(word: &str) -> bool {
    Language::English.find_word(word).is_some()
}

/// The words that start with `prefix` (lowercase), in list order. An empty
/// prefix gives every word.
pub fn with_prefix(prefix: &str) -> &'static [&'static str] {
    // The list is sorted, so the words with a prefix are one run of it.
    let list = all();
    let start = list.partition_point(|word| *word < prefix);
    let len = list[start..].iter().take_while(|word| word.starts_with(prefix)).count();
    &list[start..start + len]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[test]
    fn the_list_is_the_bip_39_english_list() {
        // SHA-256 of bitcoin/bips bip-0039/english.txt: the 2048 words, one
        // per line, with a newline after the last.
        let mut text = String::new();
        for word in all() {
            text.push_str(word);
            text.push('\n');
        }
        let digest = Sha256::digest(text.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn the_list_is_sorted() {
        assert!(all().windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn words_and_prefixes() {
        assert!(contains("abandon") && contains("zoo"));
        assert!(!contains("Abandon") && !contains("abandonn") && !contains(""));
        assert_eq!(with_prefix("aba"), ["abandon"]);
        assert_eq!(with_prefix("zoo"), ["zoo"]);
        assert!(with_prefix("xyz").is_empty());
        assert_eq!(with_prefix("").len(), 2048);
        assert_eq!(with_prefix("ab").first(), Some(&"abandon"));
        assert!(with_prefix("ab").len() > 5);
        // The first four letters identify a word.
        for word in all() {
            let four = &word[..word.len().min(4)];
            assert!(with_prefix(four).iter().all(|w| w.starts_with(four)));
        }
    }
}
