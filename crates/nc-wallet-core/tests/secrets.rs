//! Secret hygiene: no secret type prints its bytes, and every one wipes
//! itself.

#![allow(clippy::unwrap_used)]

use nc_wallet_core::{Mnemonic, Network, Seed, SigningKey, WordCount, derive, signing_key};
use zeroize::{Zeroize as _, ZeroizeOnDrop};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Every way a derived `Debug` or a careless one would write `bytes`: hex in
/// either case, and decimal lists such as `[171, 205, 12]` or `171, 205, 12`.
/// Windows of 6 bytes are searched, so a partial leak is caught as well.
fn renderings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for window in bytes.windows(6) {
        out.push(hex::encode(window));
        out.push(hex::encode_upper(window));
        out.push(window.iter().map(u8::to_string).collect::<Vec<_>>().join(", "));
        out.push(window.iter().map(u8::to_string).collect::<Vec<_>>().join(","));
    }
    out
}

fn assert_no_secret(shown: &str, secret: &[u8], what: &str) {
    for needle in renderings(secret) {
        assert!(!shown.contains(&needle), "{what}: {shown:?} contains {needle:?}");
    }
}

/// Both `{:?}` and `{:#?}`, bare and inside the containers a caller would
/// put a value in.
fn debug_forms<T: std::fmt::Debug>(value: &T) -> Vec<String> {
    vec![
        format!("{value:?}"),
        format!("{value:#?}"),
        format!("{:?}", Some(value)),
        format!("{:#?}", vec![value]),
        format!("{:?}", Ok::<&T, ()>(value)),
    ]
}

#[test]
fn the_check_itself_catches_a_leak() {
    // Guards against a vacuous test: a plain byte array does leak.
    let secret = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let leaky = format!("{secret:?}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaky, &secret, "plain array"));
    assert!(caught.is_err());
    let hexed = hex::encode(secret);
    let caught = std::panic::catch_unwind(|| assert_no_secret(&hexed, &secret, "hex"));
    assert!(caught.is_err());
}

#[test]
fn debug_of_a_mnemonic_shows_no_word() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    for shown in debug_forms(&phrase) {
        assert!(!shown.contains("abandon"), "{shown}");
        assert!(!shown.contains("about"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }
    // A generated phrase: none of its words appears either.
    let generated = Mnemonic::generate(WordCount::TwentyFour).unwrap();
    let words = generated.expose_phrase();
    for shown in debug_forms(&generated) {
        for word in words.split(' ') {
            // Words that are also part of the fixed text of the redaction are
            // not a leak of the phrase ("words").
            if !["redacted", "words", "mnemonic"].contains(&word) {
                assert!(!shown.contains(&format!(" {word}")), "{shown}");
            }
        }
    }
}

#[test]
fn debug_of_a_seed_shows_no_byte() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    let seed = phrase.to_seed("");
    for shown in debug_forms(&seed) {
        assert_no_secret(&shown, seed.expose_secret(), "Seed");
        assert!(shown.contains("redacted"));
    }
}

#[test]
fn debug_of_a_signing_key_shows_no_secret_byte() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    for network in Network::ALL {
        let key = signing_key(&phrase, "", network, 0).unwrap();
        for shown in debug_forms(&key) {
            assert_no_secret(&shown, key.expose_secret(), &format!("{network:?} SigningKey"));
            assert!(shown.contains("redacted"));
        }
    }
}

#[test]
fn errors_and_accounts_carry_no_secret() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    for network in Network::ALL {
        let key = signing_key(&phrase, "", network, 0).unwrap();
        let account = derive(&phrase, "", network, 0).unwrap();
        assert_no_secret(&format!("{account:?}"), key.expose_secret(), "Account");
    }
    let error = Mnemonic::parse(&ABANDON.replace("about", "abandon")).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("abandon"));
}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn every_secret_type_wipes_itself_on_drop() {
    // Compile-time: the types implement `ZeroizeOnDrop`.
    assert_zeroize_on_drop::<Mnemonic>();
    assert_zeroize_on_drop::<Seed>();
    assert_zeroize_on_drop::<SigningKey>();
}

#[test]
fn zeroize_clears_the_secret_bytes() {
    let phrase = Mnemonic::parse(ABANDON).unwrap();

    let mut seed = phrase.to_seed("");
    assert!(seed.expose_secret().iter().any(|b| *b != 0));
    seed.zeroize();
    assert!(seed.expose_secret().iter().all(|b| *b == 0));

    for network in Network::ALL {
        let mut key = signing_key(&phrase, "", network, 0).unwrap();
        assert!(key.expose_secret().iter().any(|b| *b != 0));
        key.zeroize();
        assert!(key.expose_secret().iter().all(|b| *b == 0), "{network:?}");
    }

    let mut phrase = phrase;
    phrase.zeroize();
    // A wiped phrase no longer reads back as the original.
    assert_ne!(*phrase.expose_phrase(), ABANDON);
}

#[test]
fn exposed_copies_wipe_themselves() {
    // `expose_phrase` hands out a `Zeroizing<String>`; `export_secret_seed`
    // does too. The types say it; this keeps them from regressing to `String`.
    fn is_zeroizing<T: ZeroizeOnDrop>(_: &T) {}
    let phrase = Mnemonic::parse(ABANDON).unwrap();
    is_zeroizing(&phrase.expose_phrase());
    let seed = phrase.to_seed("");
    is_zeroizing(&nc_wallet_core::stellar::export_secret_seed(&seed, 0).unwrap());
}
