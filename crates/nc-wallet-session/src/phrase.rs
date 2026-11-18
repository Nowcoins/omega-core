//! Typed recovery phrases: what is wrong with them, and what a word could be.

use nc_wallet_core::{Mnemonic, MnemonicError, wordlist};
use zeroize::Zeroizing;

use crate::engine::to_u32;
use crate::types::{PhraseCheck, PhraseProblem};

/// What is wrong with typed text, if anything. The text is not kept.
pub fn check_phrase(text: &str) -> PhraseCheck {
    let lowered = Zeroizing::new(text.to_lowercase());
    let words: Vec<&str> = lowered.split_whitespace().collect();
    let found = |problem| PhraseCheck {
        problem,
        word_count: to_u32(words.len()),
        position: 0,
        suggestions: Vec::new(),
    };
    if words.is_empty() {
        return found(PhraseProblem::Empty);
    }
    // Unknown words first, even in an unfinished phrase, so a typo shows up
    // as it is typed rather than when the last word is.
    if let Some(index) = words.iter().position(|word| !wordlist::contains(word)) {
        return PhraseCheck {
            position: to_u32(index + 1),
            suggestions: suggest(words[index], 3),
            ..found(PhraseProblem::UnknownWord)
        };
    }
    match Mnemonic::parse(&lowered) {
        Ok(_) => found(PhraseProblem::Valid),
        Err(MnemonicError::Checksum) => found(PhraseProblem::BadChecksum),
        Err(MnemonicError::UnknownWord { position }) => {
            PhraseCheck { position: to_u32(position), ..found(PhraseProblem::UnknownWord) }
        }
        Err(MnemonicError::Empty) => found(PhraseProblem::Empty),
        Err(MnemonicError::WordCount(_) | MnemonicError::EntropyLength(_)) => {
            found(PhraseProblem::WrongWordCount)
        }
    }
}

/// Up to `limit` words of the BIP-39 list that start with `prefix`, for
/// completing a word as it is typed.
pub fn complete_word(prefix: &str, limit: usize) -> Vec<String> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        return Vec::new();
    }
    wordlist::with_prefix(&prefix).iter().take(limit).map(|w| (*w).to_owned()).collect()
}

/// Up to `limit` words a mistyped word could be: those that start with it,
/// else those a letter away (one inserted, dropped, changed or swapped), else,
/// for a long word, two letters away. Nearest first, then list order.
pub fn suggest(word: &str, limit: usize) -> Vec<String> {
    let by_prefix = complete_word(word, limit);
    if !by_prefix.is_empty() {
        return by_prefix;
    }
    let typed: Vec<char> = word.chars().collect();
    for allowed in 1..=if typed.len() >= 4 { 2 } else { 1 } {
        let near: Vec<String> = wordlist::all()
            .iter()
            .filter(|candidate| distance(&typed, candidate) <= allowed)
            .take(limit)
            .map(|candidate| (*candidate).to_owned())
            .collect();
        if !near.is_empty() {
            return near;
        }
    }
    Vec::new()
}

/// Edit distance counting a swap of two neighbours as one edit (optimal
/// string alignment).
pub(crate) fn distance(a: &[char], b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut rows = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let same = usize::from(a[i - 1] != b[j - 1]);
            let mut best =
                (rows[i - 1][j] + 1).min(rows[i][j - 1] + 1).min(rows[i - 1][j - 1] + same);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

/// Reads pasted text as a private key, without keeping anything: what is wrong with it, or
/// which kind of key it is (see [`nc_wallet_core::imported`] for the forms that are read).
#[must_use]
pub fn check_key(text: &str) -> crate::types::KeyCheck {
    use nc_wallet_core::{ImportedKey, ImportedKeyError, ImportedKeyKind};

    use crate::types::{KeyCheck, KeyProblem, WalletKind};
    match ImportedKey::parse(text) {
        Ok(key) => KeyCheck {
            problem: KeyProblem::Valid,
            kind: Some(match key.kind() {
                ImportedKeyKind::Secp256k1 => WalletKind::KeySecp256k1,
                ImportedKeyKind::Ed25519 => WalletKind::KeyEd25519,
            }),
        },
        Err(error) => KeyCheck {
            problem: match error {
                ImportedKeyError::Empty => KeyProblem::Empty,
                ImportedKeyError::Unrecognised => KeyProblem::Unrecognised,
                ImportedKeyError::LooksLikeAnAddress => KeyProblem::LooksLikeAnAddress,
                ImportedKeyError::NotOnCurve => KeyProblem::NotOnCurve,
                ImportedKeyError::HalvesDisagree => KeyProblem::HalvesDisagree,
            },
            kind: None,
        },
    }
}
