//! Recovery phrases through the public API: BIP-39's published vectors,
//! validation and its errors.

#![allow(clippy::unwrap_used)]

use nc_wallet_core::{Mnemonic, MnemonicError, WordCount};

/// BIP-39's test vectors as Trezor publishes them: `[entropy, phrase, seed,
/// master xprv]`, the seed made with the passphrase `TREZOR`. This is the
/// `english` list of `vectors.json` in
/// <https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json>,
/// reformatted, nothing else changed. (`hd.rs` checks the master keys.)
const TREZOR: &str = include_str!("vectors/bip39-trezor-english.json");

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn trezor_vectors_entropy_phrase_seed() {
    let vectors: Vec<[String; 4]> = serde_json::from_str(TREZOR).unwrap();
    assert_eq!(vectors.len(), 24);
    let mut lengths = std::collections::BTreeSet::new();
    for [entropy, phrase, seed, _xprv] in &vectors {
        let entropy = hex::decode(entropy).unwrap();
        // entropy -> phrase
        let made = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(*made.expose_phrase(), *phrase);
        // phrase -> same phrase, with its checksum accepted
        let read = Mnemonic::parse(phrase).unwrap();
        assert_eq!(*read.expose_phrase(), *phrase);
        assert_eq!(read.word_count(), phrase.split(' ').count());
        // phrase + "TREZOR" -> seed
        assert_eq!(hex::encode(read.to_seed("TREZOR").expose_secret()), *seed);
        lengths.insert(read.word_count());
    }
    assert_eq!(lengths.into_iter().collect::<Vec<_>>(), [12, 18, 24]);
}

#[test]
fn seed_without_passphrase_and_with_one_differ() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    let plain = phrase.to_seed("");
    assert_ne!(plain.expose_secret(), phrase.to_seed("TREZOR").expose_secret());
    assert_ne!(plain.expose_secret(), phrase.to_seed(" ").expose_secret());
}

#[test]
fn passphrase_is_unicode_normalised() {
    // BIP-39: the passphrase is NFKD. A composed "é" and "e" + combining acute
    // are the same passphrase.
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    assert_eq!(
        phrase.to_seed("caf\u{e9}").expose_secret(),
        phrase.to_seed("cafe\u{301}").expose_secret()
    );
}

#[test]
fn people_type_phrases_loosely() {
    let want = Mnemonic::parse(ABANDON).unwrap();
    for typed in [
        "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ",
        "ABANDON abandon Abandon abandon abandon abandon abandon abandon abandon abandon abandon About",
        "abandon\tabandon\nabandon  abandon abandon abandon abandon abandon abandon abandon abandon about",
        // ideographic spaces, as some phone keyboards insert
        "abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}abandon\u{3000}about",
    ] {
        let got: Mnemonic = typed.parse().unwrap();
        assert_eq!(*got.expose_phrase(), *want.expose_phrase());
    }
}

#[test]
fn errors_say_what_is_wrong() {
    assert_eq!(Mnemonic::parse("").unwrap_err(), MnemonicError::Empty);
    assert_eq!(Mnemonic::parse("  \n\t ").unwrap_err(), MnemonicError::Empty);

    // Word count: 11 and 13 words are not a phrase.
    let eleven = ["abandon"; 11].join(" ");
    let thirteen = ["abandon"; 13].join(" ");
    assert_eq!(Mnemonic::parse(&eleven).unwrap_err(), MnemonicError::WordCount(11));
    assert_eq!(Mnemonic::parse(&thirteen).unwrap_err(), MnemonicError::WordCount(13));

    // A word that is not in the list: its position, counted from 1.
    let typo = ABANDON.replace("about", "abouts");
    assert_eq!(Mnemonic::parse(&typo).unwrap_err(), MnemonicError::UnknownWord { position: 12 });
    let typo = ABANDON.replacen("abandon", "zzzz", 1);
    assert_eq!(Mnemonic::parse(&typo).unwrap_err(), MnemonicError::UnknownWord { position: 1 });

    // All words valid, checksum wrong: the last word must be "about".
    let wrong_last = ABANDON.replace("about", "abandon");
    assert_eq!(Mnemonic::parse(&wrong_last).unwrap_err(), MnemonicError::Checksum);
    // The same words in another order.
    let vector = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    assert!(Mnemonic::parse(vector).is_ok());
    let swapped = "winner legal thank year wave sausage worth useful legal winner thank yellow";
    assert_eq!(Mnemonic::parse(swapped).unwrap_err(), MnemonicError::Checksum);

    // Not a word list at all.
    assert!(matches!(Mnemonic::parse("12345 67890 ...").unwrap_err(), MnemonicError::WordCount(3)));
}

#[test]
fn error_messages_are_clear_and_never_echo_a_word() {
    let typo = ABANDON.replace("about", "secretwordtypo");
    let message = Mnemonic::parse(&typo).unwrap_err().to_string();
    assert_eq!(message, "word 12 is not in the English BIP-39 wordlist");
    assert!(!message.contains("secretwordtypo"));

    assert_eq!(
        Mnemonic::parse("abandon abandon").unwrap_err().to_string(),
        "a recovery phrase has 12, 15, 18, 21 or 24 words, this one has 2"
    );
    assert_eq!(
        Mnemonic::parse(&ABANDON.replace("about", "abandon")).unwrap_err().to_string(),
        "the recovery phrase's checksum does not match: a word is wrong or out of order"
    );
    assert_eq!(MnemonicError::Empty.to_string(), "the recovery phrase is empty");
}

#[test]
fn entropy_must_have_a_length_bip39_knows() {
    for length in [16, 20, 24, 28, 32] {
        assert!(Mnemonic::from_entropy(&vec![7u8; length]).is_ok(), "{length}");
    }
    for length in [0, 8, 15, 17, 33, 64] {
        assert_eq!(
            Mnemonic::from_entropy(&vec![7u8; length]).unwrap_err(),
            MnemonicError::EntropyLength(length),
            "{length}"
        );
    }
}

#[test]
fn fifteen_and_twenty_one_word_phrases_are_accepted() {
    // 15 and 21 words come from 20 and 28 bytes of entropy.
    for (length, words) in [(20, 15), (28, 21)] {
        let made = Mnemonic::from_entropy(&vec![0x42u8; length]).unwrap();
        assert_eq!(made.word_count(), words);
        let again = Mnemonic::parse(&made.expose_phrase()).unwrap();
        assert_eq!(again.word_count(), words);
    }
}

#[test]
fn generated_phrases_come_from_the_system_source() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let twelve = Mnemonic::generate(WordCount::Twelve).unwrap();
        let long = Mnemonic::generate(WordCount::TwentyFour).unwrap();
        assert_eq!(twelve.word_count(), 12);
        assert_eq!(long.word_count(), 24);
        // Valid by construction: they parse back.
        Mnemonic::parse(&twelve.expose_phrase()).unwrap();
        Mnemonic::parse(&long.expose_phrase()).unwrap();
        assert!(seen.insert(twelve.expose_phrase().to_string()), "repeated phrase");
        assert!(seen.insert(long.expose_phrase().to_string()), "repeated phrase");
    }
}
