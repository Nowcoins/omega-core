//! The vault's tests: the primitives against published vectors, then the
//! container (round trips, a pinned blob, wrong passwords, tampering).
//!
//! The recovery phrases are the BIP-39 reference vectors (Trezor's
//! `python-mnemonic` `vectors.json`: entropy of all `00` and of all `7f`).

#![allow(clippy::unwrap_used)]

use std::time::Instant;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

use super::*;
use crate::mnemonic::WordCount;

/// 12 words, entropy `00 * 16`.
const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// 24 words, entropy `00 * 32`.
const ABANDON_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/// 12 words, entropy `7f * 16`.
const LEGAL_12: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

const PASSWORD: &str = "correct horse battery staple";

/// Small and quick, for the loops that open a vault hundreds of times.
fn cheap() -> VaultParams {
    VaultParams::for_tests(64, 1, 1)
}

fn phrase(text: &str) -> Mnemonic {
    Mnemonic::parse(text).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

fn cheap_blob(text: &str, passphrase: &str, password: &str) -> Vec<u8> {
    seal_unchecked(&phrase(text), passphrase, password, cheap(), [7; SALT_LEN], [9; NONCE_LEN])
        .unwrap()
}

// ---- Argon2id ----

/// RFC 9106, section 5.3: the Argon2id test vector (with a secret and
/// associated data, which the vault does not use). It pins the `argon2`
/// crate as built here.
#[test]
fn rfc_9106_argon2id_vector() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4u8; 12]).unwrap())
        .build()
        .unwrap();
    let argon2 =
        Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut tag = [0u8; 32];
    argon2.hash_password_into(&[1u8; 32], &[2u8; 16], &mut tag).unwrap();
    assert_eq!(to_hex(&tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

/// The reference implementation's test suite (phc-winner-argon2 `src/test.c`,
/// commit f57e61e, the Argon2id block): password `password`, salt `somesalt`,
/// 32-byte output. Each row is (passes, memory in KiB, lanes, password, salt,
/// key). The vault's own derivation (zeroed memory, no secret, no associated
/// data) must give these bytes.
#[test]
fn reference_argon2id_vectors_through_the_vault_derivation() {
    const ROWS: &[(u32, u32, u32, &str, &str, &str)] = &[
        (
            2,
            1 << 16,
            1,
            "password",
            "somesalt",
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
        ),
        (
            2,
            1 << 8,
            1,
            "password",
            "somesalt",
            "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
        ),
        (
            2,
            1 << 8,
            2,
            "password",
            "somesalt",
            "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
        ),
        (
            1,
            1 << 16,
            1,
            "password",
            "somesalt",
            "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
        ),
        (
            4,
            1 << 16,
            1,
            "password",
            "somesalt",
            "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
        ),
        (
            2,
            1 << 16,
            1,
            "differentpassword",
            "somesalt",
            "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
        ),
        (
            2,
            1 << 16,
            1,
            "password",
            "diffsalt",
            "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
        ),
    ];
    for (passes, memory_kib, lanes, password, salt, expected) in ROWS {
        let params = VaultParams::for_tests(*memory_kib, *passes, *lanes);
        let key = argon2id(password.as_bytes(), salt.as_bytes(), &params).unwrap();
        assert_eq!(to_hex(key.expose_secret()), *expected, "t={passes} m={memory_kib} p={lanes}");
    }
}

// ---- AES-256-GCM ----

/// (key, nonce, plaintext, aad, ciphertext, tag), hex.
type GcmVector =
    (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

const GCM_VECTORS: &[GcmVector] = &[
    // McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)", the
    // 2004 submission to NIST, appendix B, Test Case 16 (AES-256, 60 bytes of
    // plaintext, 20 bytes of associated data); also in NIST SP 800-38D's test
    // suite. Checked against OpenSSL.
    (
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72 1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
    // NIST CAVP gcmEncryptExtIV256.rsp, as copied into RustCrypto/AEADs
    // aes-gcm/tests/aes256gcm.rs at tag aes-gcm-v0.10.3 (first vector with
    // both plaintext and associated data). Checked against OpenSSL.
    (
        "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
        "ac93a1a6145299bde902f21a",
        "2d71bcfa914e4ac045b2aa60955fad24",
        "1e0889016f67601c8ebea4943bc23ad6",
        "8995ae2e6df3dbf96fac7b7137bae67f",
        "eca5aa77d51d4a0a14d9c51e1da474ab",
    ),
    // gcmEncryptExtIV256.rsp, no plaintext and no associated data: a tag only.
    (
        "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        "516c33929df5a3284ff463d7",
        "",
        "",
        "",
        "bdc1ac884d332457a1d2664f168c76f0",
    ),
];

#[test]
fn aes_256_gcm_vectors() {
    for (key, nonce, plaintext, aad, ciphertext, tag) in GCM_VECTORS {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&hex(key)));
        let nonce = hex(nonce);
        let (plaintext, aad) = (hex(plaintext), hex(aad));
        let expected = [hex(ciphertext), hex(tag)].concat();
        let sealed = cipher
            .encrypt(GenericArray::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
            .unwrap();
        assert_eq!(sealed, expected);
        let opened = cipher
            .decrypt(GenericArray::from_slice(&nonce), Payload { msg: &expected, aad: &aad })
            .unwrap();
        assert_eq!(opened, plaintext);
        // One changed byte of the associated data refuses.
        let mut other = aad.clone();
        other.push(0);
        assert!(
            cipher
                .decrypt(GenericArray::from_slice(&nonce), Payload { msg: &expected, aad: &other })
                .is_err()
        );
    }
}

// ---- the container ----

#[test]
fn round_trip_for_every_shape_of_phrase() {
    for text in [ABANDON_12, ABANDON_24, LEGAL_12] {
        for passphrase in ["", "TREZOR", "pässphräse 🔑 with spaces"] {
            let blob = cheap_blob(text, passphrase, PASSWORD);
            let opened = open(&blob, PASSWORD).unwrap();
            assert_eq!(*opened.mnemonic().expose_phrase(), text);
            assert_eq!(opened.expose_passphrase(), passphrase);
        }
    }
}

#[test]
fn round_trip_at_the_phone_setting() {
    let blob = seal(&phrase(ABANDON_12), "", PASSWORD).unwrap();
    assert_eq!(info(&blob).unwrap().params, VaultParams::PHONE);
    let opened = open(&blob, PASSWORD).unwrap();
    assert_eq!(*opened.mnemonic().expose_phrase(), ABANDON_12);
    assert_eq!(open(&blob, "correct horse battery stapl").unwrap_err(), VaultError::Authentication);
}

#[test]
fn round_trip_at_the_extension_setting_and_the_key_it_keeps() {
    let (blob, key) =
        seal_keeping_key_with_params(&phrase(LEGAL_12), "TREZOR", PASSWORD, VaultParams::EXTENSION)
            .unwrap();
    assert_eq!(info(&blob).unwrap().params, VaultParams::EXTENSION);
    assert_eq!(
        (VaultParams::EXTENSION.memory_kib(), VaultParams::EXTENSION.iterations()),
        (256 * 1024, 3)
    );
    // The same shape as any vault: the parameters are in the header.
    let floor =
        VaultParams::new(VaultParams::MIN_MEMORY_KIB, VaultParams::MIN_ITERATIONS, 1).unwrap();
    assert_eq!(blob.len(), seal_with_params(&phrase(LEGAL_12), "", PASSWORD, floor).unwrap().len());
    let opened = open_with_key(&blob, &key).unwrap();
    assert_eq!(*opened.mnemonic().expose_phrase(), LEGAL_12);
    assert_eq!(opened.expose_passphrase(), "TREZOR");
    assert_eq!(open(&blob, PASSWORD).unwrap().expose_passphrase(), "TREZOR");
}

#[test]
fn the_blob_is_pinned_byte_for_byte() {
    // Fixed salt (0x07 * 16) and nonce (0x09 * 12), cheap parameters. If this
    // changes, the format changed and every stored vault stops opening.
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    assert_eq!(blob.len(), HEADER_LEN + 256 + TAG_LEN);
    assert_eq!(
        to_hex(&blob[..HEADER_LEN]),
        "4e43575601\
         01\
         00000040\
         00000001\
         00000001\
         07070707070707070707070707070707\
         01\
         090909090909090909090909"
    );
    assert_eq!(to_hex(&blob[HEADER_LEN..]), GOLDEN_SEALED);
}

/// The ciphertext and tag of the pinned blob. Made by this code, then
/// confirmed with OpenSSL's AES-GCM (Python `cryptography`) from the
/// Argon2id key, the header as associated data and the documented plaintext.
const GOLDEN_SEALED: &str = "383f5c85addc79ca500de725cbb69a8c9b4306c518d866a4c2b38f20f4fb43d6ad74e0bcff1af00e69bf2aa3889d0c727cbd9333ad9dbcc85caac9147da9c1ea55eaec49c400655e4e37537f8db5806d8399641a8cf6d1366d5cc682f1404aa2324910a7f34a205ca818b80e5f418c373b7d821f88c550562f3a9e6434bdda9eced2d772e8ccd38579f97e052e0ad1f56b32203365db3691bd375cb653a9a4b8e52109c12526e1a7fdc7959d30a7e4d50c10d1d206d9c3a099232616e10426a9d58f559071e33e48a6e766b0771e183bdafe96cfc4573f6536a4fdff72698123ab9c9b3b82f19b8cd412112703327775354b51373eee4ccfc342479bb8f00b99bfadc3836ef93daed0a710ebdfa193dc";

#[test]
fn two_seals_of_the_same_phrase_differ() {
    let a = seal_with_params(
        &phrase(ABANDON_12),
        "",
        PASSWORD,
        VaultParams::new(16 * 1024, 2, 1).unwrap(),
    )
    .unwrap();
    let b = seal_with_params(
        &phrase(ABANDON_12),
        "",
        PASSWORD,
        VaultParams::new(16 * 1024, 2, 1).unwrap(),
    )
    .unwrap();
    assert_ne!(a[18..34], b[18..34], "salts differ");
    assert_ne!(a[35..47], b[35..47], "nonces differ");
    assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
}

#[test]
fn an_opened_vault_gives_up_its_parts() {
    let blob = cheap_blob(LEGAL_12, "TREZOR", PASSWORD);
    let (mnemonic, passphrase) = open(&blob, PASSWORD).unwrap().into_parts();
    assert_eq!(*mnemonic.expose_phrase(), LEGAL_12);
    assert_eq!(passphrase.as_str(), "TREZOR");
}

#[test]
fn a_generated_phrase_survives_the_vault() {
    let generated = Mnemonic::generate(WordCount::TwentyFour).unwrap();
    let blob =
        seal_unchecked(&generated, "", PASSWORD, cheap(), [1; SALT_LEN], [2; NONCE_LEN]).unwrap();
    assert_eq!(
        *open(&blob, PASSWORD).unwrap().mnemonic().expose_phrase(),
        *generated.expose_phrase()
    );
}

#[test]
fn the_blob_has_one_length_whatever_the_phrase() {
    let twelve = cheap_blob(ABANDON_12, "", PASSWORD);
    let twenty_four = cheap_blob(ABANDON_24, "", PASSWORD);
    let with_passphrase = cheap_blob(ABANDON_24, "a passphrase of some length", PASSWORD);
    assert_eq!(twelve.len(), twenty_four.len());
    assert_eq!(twelve.len(), with_passphrase.len());
    // A long passphrase takes the next multiple of 256.
    let long = cheap_blob(ABANDON_24, &"x".repeat(600), PASSWORD);
    assert_eq!(long.len() % 256, (HEADER_LEN + TAG_LEN) % 256);
    assert!(long.len() > twelve.len());
}

#[test]
fn the_parameters_are_stored_in_the_blob() {
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    let facts = info(&blob).unwrap();
    assert_eq!(facts.version, 1);
    assert_eq!(facts.params, cheap());

    let params = VaultParams::new(20 * 1024, 2, 2).unwrap();
    let blob = seal_with_params(&phrase(ABANDON_12), "", PASSWORD, params).unwrap();
    assert_eq!(info(&blob).unwrap().params, params);
    assert_eq!(*open(&blob, PASSWORD).unwrap().mnemonic().expose_phrase(), ABANDON_12);
}

#[test]
fn a_wrong_password_is_refused() {
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    for wrong in ["wrong", "Correct horse battery staple", "correct horse battery staple ", "x"] {
        assert_eq!(open(&blob, wrong).unwrap_err(), VaultError::Authentication, "{wrong}");
    }
    assert_eq!(open(&blob, "").unwrap_err(), VaultError::EmptyPassword);
}

#[test]
fn the_password_is_normalised_before_it_is_used() {
    // "é" as one code point and as "e" plus a combining accent.
    let blob = cheap_blob(ABANDON_12, "", "caf\u{e9} password");
    assert!(open(&blob, "cafe\u{301} password").is_ok());
    // The compatibility form of a full-width letter is the plain one.
    let blob = cheap_blob(ABANDON_12, "", "ＡＢＣ-password");
    assert!(open(&blob, "ABC-password").is_ok());
}

#[test]
fn every_changed_bit_of_the_blob_is_refused() {
    let blob = cheap_blob(LEGAL_12, "TREZOR", PASSWORD);
    for index in 0..blob.len() {
        for bit in [0x01u8, 0x80] {
            let mut tampered = blob.clone();
            tampered[index] ^= bit;
            assert!(open(&tampered, PASSWORD).is_err(), "byte {index} bit {bit:#x} was accepted");
        }
    }
}

#[test]
fn a_cut_or_extended_blob_is_refused() {
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    for len in 0..blob.len() {
        assert!(open(&blob[..len], PASSWORD).is_err(), "cut to {len} bytes was accepted");
    }
    let mut longer = blob.clone();
    longer.push(0);
    assert_eq!(open(&longer, PASSWORD).unwrap_err(), VaultError::Authentication);
    assert_eq!(open(&[], PASSWORD).unwrap_err(), VaultError::NotAVault);
}

#[test]
fn a_header_that_asks_too_much_is_refused_before_any_work() {
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    let started = Instant::now();
    // Memory field (bytes 6..10), passes (10..14), lanes (14..18).
    for (range, value) in [
        (6..10, u32::MAX),
        (6..10, 2 * 1024 * 1024),
        (10..14, 1000),
        (14..18, 100),
        (14..18, 0),
        (10..14, 0),
        (6..10, 4),
    ] {
        let mut hostile = blob.clone();
        hostile[range].copy_from_slice(&u32::to_be_bytes(value));
        assert_eq!(open(&hostile, PASSWORD).unwrap_err(), VaultError::BadParams, "{value}");
        assert!(derive_key(&hostile, PASSWORD).is_err());
        assert!(info(&hostile).is_err());
    }
    assert!(started.elapsed().as_secs() < 5, "refusing took {:?}", started.elapsed());
}

/// `blob` with its header's Argon2 parameters replaced (memory, passes, lanes).
fn with_params(blob: &[u8], memory_kib: u32, iterations: u32, lanes: u32) -> Vec<u8> {
    let mut out = blob.to_vec();
    out[6..10].copy_from_slice(&memory_kib.to_be_bytes());
    out[10..14].copy_from_slice(&iterations.to_be_bytes());
    out[14..18].copy_from_slice(&lanes.to_be_bytes());
    out
}

#[test]
fn the_extension_limits_and_the_crates_own() {
    let extension = VaultLimits::EXTENSION;
    assert_eq!(
        (extension.max_memory_kib(), extension.max_iterations(), extension.max_lanes()),
        (512 * 1024, 10, 1)
    );
    // What the extension seals, and what it sealed before, are within.
    assert!(extension.admits(&VaultParams::EXTENSION));
    assert!(extension.admits(&VaultParams::PHONE));
    assert!(extension.admits(&VaultParams::for_tests(512 * 1024, 10, 1)));
    assert!(!extension.admits(&VaultParams::for_tests(512 * 1024 + 1, 10, 1)));
    assert!(!extension.admits(&VaultParams::for_tests(512 * 1024, 11, 1)));
    assert!(!extension.admits(&VaultParams::for_tests(512 * 1024, 10, 2)));
    // The crate's own ceiling, which the phone keeps, is not lowered.
    let phone = VaultLimits::PHONE;
    assert_eq!(
        (phone.max_memory_kib(), phone.max_iterations(), phone.max_lanes()),
        (VaultParams::MAX_MEMORY_KIB, VaultParams::MAX_ITERATIONS, VaultParams::MAX_LANES)
    );
    assert_eq!(
        (phone.max_memory_kib(), phone.max_iterations(), phone.max_lanes()),
        (1024 * 1024, 32, 8)
    );
    assert!(phone.admits(&VaultParams::for_tests(1024 * 1024, 32, 8)));
    assert_eq!(VaultLimits::default(), phone);
}

#[test]
fn a_vault_at_the_limits_opens_and_one_above_them_does_not() {
    // Sealing at 512 MiB takes seconds: the cheap vault (64 KiB, 1 pass, 1
    // lane) and limits lowered to exactly that stand in for it. The check is
    // the same comparison.
    let blob = cheap_blob(LEGAL_12, "TREZOR", PASSWORD);
    let at = VaultLimits::new(64, 1, 1);
    assert!(at.admits(&cheap()));
    assert_eq!(*open_within(&blob, PASSWORD, at).unwrap().mnemonic().expose_phrase(), LEGAL_12);
    let key = derive_key_within(&blob, PASSWORD, at).unwrap();
    assert_eq!(open_with_key_within(&blob, &key, at).unwrap().expose_passphrase(), "TREZOR");
    assert_eq!(info_within(&blob, at).unwrap().params, cheap());
    for below in
        [VaultLimits::new(63, 1, 1), VaultLimits::new(64, 0, 1), VaultLimits::new(64, 1, 0)]
    {
        assert_eq!(open_within(&blob, PASSWORD, below).unwrap_err(), VaultError::BadParams);
        assert_eq!(derive_key_within(&blob, PASSWORD, below).unwrap_err(), VaultError::BadParams);
        // Not even the right key gets past them.
        assert_eq!(open_with_key_within(&blob, &key, below).unwrap_err(), VaultError::BadParams);
        assert_eq!(info_within(&blob, below).unwrap_err(), VaultError::BadParams);
    }
    // The functions without limits are the crate's ceiling.
    assert!(open(&blob, PASSWORD).is_ok());
}

#[test]
fn a_header_above_the_extension_limits_is_refused_before_any_work() {
    // Headers within the crate's ceiling (the phone reads them) but above the
    // extension's. Argon2 at any of these would reserve 256 MiB to 1 GiB and
    // run for a second or far more, and a header it had run on would end in
    // `Authentication` (the header is the associated data): `BadParams`, at
    // once, means the parameters were refused when the header was read, before
    // the key derivation and its memory.
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    let started = Instant::now();
    for (memory_kib, iterations, lanes) in [
        (512 * 1024 + 1, 3, 1),
        (1024 * 1024, 3, 1),
        (256 * 1024, 11, 1),
        (256 * 1024, 32, 1),
        (256 * 1024, 3, 2),
        (256 * 1024, 3, 8),
    ] {
        let hostile = with_params(&blob, memory_kib, iterations, lanes);
        let asked = (memory_kib, iterations, lanes);
        assert_eq!(
            info(&hostile).unwrap().params,
            VaultParams::for_tests(memory_kib, iterations, lanes)
        );
        let limits = VaultLimits::EXTENSION;
        assert_eq!(info_within(&hostile, limits).unwrap_err(), VaultError::BadParams, "{asked:?}");
        assert_eq!(
            open_within(&hostile, PASSWORD, limits).unwrap_err(),
            VaultError::BadParams,
            "{asked:?}"
        );
        assert_eq!(
            derive_key_within(&hostile, PASSWORD, limits).unwrap_err(),
            VaultError::BadParams,
            "{asked:?}"
        );
        let key = VaultKey::from_bytes(&[1; KEY_LEN]).unwrap();
        assert_eq!(
            open_with_key_within(&hostile, &key, limits).unwrap_err(),
            VaultError::BadParams
        );
    }
    assert!(started.elapsed().as_millis() < 1000, "refusing took {:?}", started.elapsed());
}

#[test]
fn an_unknown_format_or_algorithm_is_named() {
    let blob = cheap_blob(ABANDON_12, "", PASSWORD);
    let mut other = blob.clone();
    other[4] = 2;
    assert_eq!(open(&other, PASSWORD).unwrap_err(), VaultError::UnsupportedVersion(2));
    let mut other = blob.clone();
    other[5] = 2;
    assert_eq!(open(&other, PASSWORD).unwrap_err(), VaultError::UnsupportedAlgorithm);
    let mut other = blob.clone();
    other[34] = 2;
    assert_eq!(open(&other, PASSWORD).unwrap_err(), VaultError::UnsupportedAlgorithm);
    let mut other = blob;
    other[0] = b'X';
    assert_eq!(open(&other, PASSWORD).unwrap_err(), VaultError::NotAVault);
}

#[test]
fn parameters_below_the_floor_are_not_written() {
    assert_eq!(VaultParams::new(1024, 3, 1).unwrap_err(), VaultError::BadParams);
    assert_eq!(VaultParams::new(65_536, 1, 1).unwrap_err(), VaultError::BadParams);
    assert_eq!(VaultParams::new(65_536, 3, 0).unwrap_err(), VaultError::BadParams);
    assert_eq!(VaultParams::new(u32::MAX, 3, 1).unwrap_err(), VaultError::BadParams);
    assert_eq!(VaultParams::new(65_536, 3, 1).unwrap(), VaultParams::PHONE);
    assert_eq!(VaultParams::default(), VaultParams::PHONE);
    assert_eq!(VaultParams::new(262_144, 3, 1).unwrap(), VaultParams::EXTENSION);
    assert_eq!(
        seal_with_params(&phrase(ABANDON_12), "", PASSWORD, cheap()).unwrap_err(),
        VaultError::BadParams
    );
    assert_eq!(
        seal_keeping_key_with_params(&phrase(ABANDON_12), "", PASSWORD, cheap()).unwrap_err(),
        VaultError::BadParams
    );
}

#[test]
fn passphrase_and_password_limits() {
    let long = "x".repeat(MAX_PASSPHRASE_LEN + 1);
    assert_eq!(
        seal_unchecked(&phrase(ABANDON_12), &long, PASSWORD, cheap(), [1; 16], [1; 12])
            .unwrap_err(),
        VaultError::PassphraseTooLong
    );
    let longest = "x".repeat(MAX_PASSPHRASE_LEN);
    let blob = cheap_blob(ABANDON_24, &longest, PASSWORD);
    assert_eq!(open(&blob, PASSWORD).unwrap().expose_passphrase(), longest);
    assert_eq!(
        seal_unchecked(&phrase(ABANDON_12), "", "", cheap(), [1; 16], [1; 12]).unwrap_err(),
        VaultError::EmptyPassword
    );
}

#[test]
fn a_key_opens_its_own_vault_and_no_other() {
    let blob = cheap_blob(ABANDON_12, "TREZOR", PASSWORD);
    let key = derive_key(&blob, PASSWORD).unwrap();
    let opened = open_with_key(&blob, &key).unwrap();
    assert_eq!(*opened.mnemonic().expose_phrase(), ABANDON_12);
    assert_eq!(opened.expose_passphrase(), "TREZOR");

    // The key as the app keeps it (32 bytes) comes back the same.
    let restored = VaultKey::from_bytes(key.expose_secret()).unwrap();
    assert!(open_with_key(&blob, &restored).is_ok());
    assert_eq!(VaultKey::from_bytes(&[0; 31]).unwrap_err(), VaultError::BadKey);
    assert_eq!(VaultKey::from_bytes(&[0; 33]).unwrap_err(), VaultError::BadKey);

    // A key made from a wrong password does not open it.
    let wrong = derive_key(&blob, "wrong password").unwrap();
    assert_eq!(open_with_key(&blob, &wrong).unwrap_err(), VaultError::Authentication);

    // A new password is a new salt, so the old key opens nothing new.
    let other =
        seal_unchecked(&phrase(ABANDON_12), "TREZOR", "new password", cheap(), [8; 16], [9; 12])
            .unwrap();
    assert_eq!(open_with_key(&other, &key).unwrap_err(), VaultError::Authentication);
}

#[test]
fn the_key_kept_while_sealing_is_the_key_that_opens() {
    let (blob, key) = seal_keeping_key(&phrase(LEGAL_12), "TREZOR", PASSWORD).unwrap();
    let opened = open_with_key(&blob, &key).unwrap();
    assert_eq!(*opened.mnemonic().expose_phrase(), LEGAL_12);
    assert_eq!(opened.expose_passphrase(), "TREZOR");
    assert_eq!(key.expose_secret(), derive_key(&blob, PASSWORD).unwrap().expose_secret());
}

#[test]
fn contents_that_are_not_a_phrase_are_refused() {
    // A vault sealed by hand with a payload that is not a phrase: the cipher
    // opens it and the contents check refuses it.
    let key = argon2id(PASSWORD.as_bytes(), &[7; 16], &cheap()).unwrap();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key.expose_secret()));
    let sealed_with = |payload: &[u8]| {
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&[FORMAT_VERSION, KDF_ARGON2ID_V13]);
        header.extend_from_slice(&64u32.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&[7; 16]);
        header.push(CIPHER_AES_256_GCM);
        header.extend_from_slice(&[9; 12]);
        let sealed = cipher
            .encrypt(GenericArray::from_slice(&[9; 12]), Payload { msg: payload, aad: &header })
            .unwrap();
        [header, sealed].concat()
    };
    let mut good = vec![PAYLOAD_VERSION, 0, 11];
    good.extend_from_slice(b"not a phras");
    good.extend_from_slice(&[0, 0]);
    good.resize(256, 0);
    assert_eq!(open(&sealed_with(&good), PASSWORD).unwrap_err(), VaultError::Corrupt);

    let mut wrong_version = good.clone();
    wrong_version[0] = 9;
    assert_eq!(open(&sealed_with(&wrong_version), PASSWORD).unwrap_err(), VaultError::Corrupt);

    // A real phrase with the padding not zero.
    let mut payload = vec![PAYLOAD_VERSION, 0, u8::try_from(ABANDON_12.len()).unwrap()];
    payload.extend_from_slice(ABANDON_12.as_bytes());
    payload.extend_from_slice(&[0, 0]);
    payload.resize(256, 0);
    assert!(open(&sealed_with(&payload), PASSWORD).is_ok());
    payload[255] = 1;
    assert_eq!(open(&sealed_with(&payload), PASSWORD).unwrap_err(), VaultError::Corrupt);

    // A length that runs past the end.
    let overrun = vec![PAYLOAD_VERSION, 0xff, 0xff, 1, 2, 3];
    assert_eq!(open(&sealed_with(&overrun), PASSWORD).unwrap_err(), VaultError::Corrupt);
    assert_eq!(open(&sealed_with(&[]), PASSWORD).unwrap_err(), VaultError::Corrupt);
}

#[test]
fn nothing_secret_is_printed() {
    let blob = cheap_blob(ABANDON_12, "TREZOR", PASSWORD);
    let key = derive_key(&blob, PASSWORD).unwrap();
    let opened = open(&blob, PASSWORD).unwrap();
    let key_hex = to_hex(key.expose_secret());
    for shown in
        [format!("{key:?}"), format!("{key:#?}"), format!("{opened:?}"), format!("{opened:#?}")]
    {
        assert!(!shown.contains("abandon") && !shown.contains("TREZOR"), "{shown}");
        assert!(!shown.contains(&key_hex[..12]), "{shown}");
    }
    // Errors name no secret either.
    for error in [VaultError::Authentication, VaultError::Corrupt, VaultError::EmptyPassword] {
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains(PASSWORD));
    }
}

/// `cargo test -p nc-wallet-core --release vault::tests::unlock_time -- --ignored --nocapture`
/// prints how long one unlock takes at the phone setting on this machine.
#[test]
#[ignore = "a measurement, not a check"]
fn unlock_time() {
    let blob = seal(&phrase(ABANDON_12), "", PASSWORD).unwrap();
    open(&blob, PASSWORD).unwrap();
    let started = Instant::now();
    for _ in 0..5 {
        open(&blob, PASSWORD).unwrap();
    }
    println!("unlock at {:?}: {:?} each", VaultParams::PHONE, started.elapsed() / 5);
}
