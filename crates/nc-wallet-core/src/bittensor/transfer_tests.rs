//! Bittensor transfers: vectors from Substrate's own libraries and from
//! transfers on Finney, and the behaviour of the encoder and the signer.
//!
//! Every expected value below is copied from the source named beside it, or
//! read from the chain (see `tests/vectors/`). None is worked out by the code
//! under test.

#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]

use schnorrkel::{PublicKey, Signature};

use super::extrinsic::*;
use super::*;
use crate::key::SigningKey;

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).unwrap().try_into().unwrap()
}

// ---- SCALE compact integers ----------------------------------------------------

#[test]
fn compact_integers_are_what_parity_scale_codec_writes() {
    // parity-scale-codec 3.7.5 (crates.io), src/compact.rs, test
    // `compact_integers_encoded_as_expected` (line 815 on).
    for (value, expected) in [
        (0_u128, "00"),
        (63, "fc"),
        (64, "01 01"),
        (16383, "fd ff"),
        (16384, "02 00 01 00"),
        (1_073_741_823, "fe ff ff ff"),
        (1_073_741_824, "03 00 00 00 40"),
        ((1 << 32) - 1, "03 ff ff ff ff"),
        (1 << 32, "07 00 00 00 00 01"),
        (1 << 40, "0b 00 00 00 00 00 01"),
        (1 << 48, "0f 00 00 00 00 00 00 01"),
        ((1 << 56) - 1, "0f ff ff ff ff ff ff ff"),
        (1 << 56, "13 00 00 00 00 00 00 00 01"),
        (u128::from(u64::MAX), "13 ff ff ff ff ff ff ff ff"),
    ] {
        let expected: String = expected.split(' ').collect();
        assert_eq!(hex::encode(compact(value)), expected, "{value}");
    }
}

// ---- eras ------------------------------------------------------------------------

#[test]
fn eras_are_what_substrate_makes() {
    // polkadot-sdk at f20de3de1c5f9624a33209466968e35c1228c0f4,
    // substrate/primitives/runtime/src/generic/era.rs, tests `mortal_codec_works`,
    // `long_period_mortal_codec_works`, `era_initialization_works`,
    // `quantized_clamped_era_initialization_works`, `mortal_birth_death_works`
    // and `current_less_than_phase`.
    let e = Era::mortal(64, 42);
    let expected = [5 + 42 % 16 * 16, 42 / 16];
    assert_eq!(e.encode(), expected);
    assert_eq!(Era::decode(expected), Some(e));

    let e = Era::mortal(32768, 20000);
    let expected = [u8::try_from(14 + 2500 % 16 * 16).unwrap(), u8::try_from(2500 / 16).unwrap()];
    assert_eq!(e.encode(), expected);
    assert_eq!(Era::decode(expected), Some(e));

    // `Era::Mortal(period, phase)` in Substrate's tests.
    let mortal = |period, current| {
        let e = Era::mortal(period, current);
        (e.period(), e.phase())
    };
    assert_eq!(mortal(64, 42), (64, 42));
    assert_eq!(mortal(32768, 20000), (32768, 20000));
    assert_eq!(mortal(200, 513), (256, 1));
    assert_eq!(mortal(2, 1), (4, 1));
    assert_eq!(mortal(4, 5), (4, 1));
    // Clamp 1000000 to 65536, quantize 1000001 % 65536 to the nearest 4.
    assert_eq!(mortal(1_000_000, 1_000_001), (65536, 1_000_001 % 65536 / 4 * 4));

    let e = Era::mortal(4, 6);
    for i in 6..10 {
        assert_eq!(e.birth(i), 6);
        assert_eq!(e.death(i), 10);
    }
    // Outside of the (current...current + period) range.
    assert_ne!(e.birth(10), 6);
    assert_ne!(e.birth(5), 6);
    // Should not panic.
    let _ = Era::mortal(4, 3).birth(1);

    // An immortal era is a single zero byte and is never read here.
    assert_eq!(Era::decode([0, 0]), None);
    // `Decode for Era` (same file, line 118 on) refuses a phase that is not
    // below the period: period 4 (exponent 1) with phase 3 is read, with phase
    // 4 is not.
    assert!(Era::decode([1 | (3 << 4), 0]).is_some());
    assert_eq!(Era::decode([1 | (4 << 4), 0]), None);
}

// ---- transfers on Finney ---------------------------------------------------------

const FINNEY: &str = include_str!("../../tests/vectors/finney-transfer-keep-alive-extrinsics.json");

/// Reads a SCALE compact integer at the front of `bytes`.
fn read_compact(bytes: &mut &[u8]) -> u128 {
    let first = bytes[0];
    let (value, used) = match first & 0b11 {
        0 => (u128::from(first >> 2), 1),
        1 => (u128::from(u16::from_le_bytes([bytes[0], bytes[1]]) >> 2), 2),
        2 => (u128::from(u32::from_le_bytes(bytes[..4].try_into().unwrap()) >> 2), 4),
        _ => {
            let length = usize::from(first >> 2) + 4;
            let mut le = [0u8; 16];
            le[..length].copy_from_slice(&bytes[1..=length]);
            (u128::from_le_bytes(le), length + 1)
        }
    };
    *bytes = &bytes[used..];
    value
}

/// An extrinsic read the way the chain reads it, apart from this crate: every
/// field out of the bytes, and the call, kept as raw bytes.
struct Read {
    sender: [u8; 32],
    signature: [u8; 64],
    era: [u8; 2],
    nonce: u32,
    tip: u64,
    call: Vec<u8>,
}

fn read_extrinsic(extrinsic: &[u8]) -> Read {
    let mut rest = extrinsic;
    let length = read_compact(&mut rest);
    assert_eq!(usize::try_from(length).unwrap(), rest.len(), "the length prefix");
    // 0x84: signed, extrinsic format 4. 0x00: MultiAddress::Id.
    assert_eq!(rest[..2], [0x84, 0x00]);
    let sender: [u8; 32] = rest[2..34].try_into().unwrap();
    assert_eq!(rest[34], 1, "MultiSignature::Sr25519");
    let signature: [u8; 64] = rest[35..99].try_into().unwrap();
    let era: [u8; 2] = rest[99..101].try_into().unwrap();
    let mut rest = &rest[101..];
    let nonce = u32::try_from(read_compact(&mut rest)).unwrap();
    let tip = u64::try_from(read_compact(&mut rest)).unwrap();
    assert_eq!(rest[0], 0, "CheckMetadataHash mode: disabled");
    Read { sender, signature, era, nonce, tip, call: rest[1..].to_vec() }
}

#[test]
fn transfers_on_finney_are_reproduced_and_their_signatures_verify() {
    let data: serde_json::Value = serde_json::from_str(FINNEY).unwrap();
    let genesis = hex32(data["genesis_hash"].as_str().unwrap());
    let extrinsics = data["extrinsics"].as_array().unwrap();
    assert!(extrinsics.len() >= 4);
    for entry in extrinsics {
        let text = |name: &str| entry[name].as_str().unwrap();
        let number = |name: &str| entry[name].as_u64().unwrap();
        let bytes = hex::decode(text("extrinsic").strip_prefix("0x").unwrap()).unwrap();
        let read = read_extrinsic(&bytes);

        // The call is Balances.transfer_keep_alive (5, 3), to a MultiAddress::Id
        // (0), then a compact amount.
        assert_eq!(read.call[..3], [5, 3, 0]);
        let dest: [u8; 32] = read.call[3..35].try_into().unwrap();
        let mut amount = &read.call[35..];
        let value = u64::try_from(read_compact(&mut amount)).unwrap();
        assert!(amount.is_empty());

        // The era's birth block, from the era and the block it was included in.
        let era = Era::decode(read.era).unwrap();
        assert_eq!(era.birth(number("block_number")), number("birth_block"));

        let transfer = Transfer {
            sender: read.sender,
            dest,
            value,
            call_index: CallIndex::BALANCES_TRANSFER_KEEP_ALIVE,
            nonce: read.nonce,
            tip: read.tip,
            period: era.period(),
            birth: number("birth_block"),
            birth_hash: hex32(text("birth_hash")),
            spec_version: u32::try_from(number("spec_version")).unwrap(),
            transaction_version: u32::try_from(number("transaction_version")).unwrap(),
            genesis_hash: genesis,
        };
        // Our extrinsic, around the chain's signature, is the chain's bytes...
        assert_eq!(
            transfer.encode_signed(&read.signature).unwrap(),
            bytes,
            "{}",
            text("block_hash")
        );
        assert_eq!(transfer.era().encode(), read.era);
        // ...and the signature the chain accepted verifies over our payload.
        let payload = transfer.signing_payload().unwrap();
        let public = PublicKey::from_bytes(&read.sender).unwrap();
        let signature = Signature::from_bytes(&read.signature).unwrap();
        assert!(
            public.verify_simple(SR25519_CONTEXT, &payload, &signature).is_ok(),
            "block {}",
            number("block_number")
        );
        // A change to any field the signature covers breaks it.
        for change in [
            |t: &mut Transfer| t.spec_version += 1,
            |t: &mut Transfer| t.transaction_version += 1,
            |t: &mut Transfer| t.genesis_hash[0] ^= 1,
            |t: &mut Transfer| t.birth_hash[0] ^= 1,
            |t: &mut Transfer| t.nonce += 1,
            |t: &mut Transfer| t.tip += 1,
            |t: &mut Transfer| t.value += 1,
            |t: &mut Transfer| t.dest[0] ^= 1,
            |t: &mut Transfer| t.period *= 2,
        ] {
            let mut changed = transfer.clone();
            change(&mut changed);
            let payload = changed.signing_payload().unwrap();
            assert!(public.verify_simple(SR25519_CONTEXT, &payload, &signature).is_err());
        }
    }
}

// ---- the signer -------------------------------------------------------------------

fn transfer_of(sender: &[u8]) -> Transfer {
    Transfer {
        sender: sender.try_into().unwrap(),
        dest: [9; 32],
        value: 1_500_000_000,
        call_index: CallIndex::BALANCES_TRANSFER_KEEP_ALIVE,
        nonce: 70_000,
        tip: 0,
        period: 64,
        birth: 9_141_862,
        birth_hash: [0xa1; 32],
        spec_version: 486,
        transaction_version: 1,
        genesis_hash: hex32("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
    }
}

#[test]
fn a_signed_transfer_verifies_and_signatures_are_randomised() {
    let key = SigningKey::sr25519(&[7; 32]).unwrap();
    let transfer = transfer_of(key.public_key());
    let first = sign_transfer(&key, &transfer).unwrap();
    let second = sign_transfer(&key, &transfer).unwrap();
    let payload = transfer.signing_payload().unwrap();
    let public = PublicKey::from_bytes(key.public_key()).unwrap();
    for signed in [&first, &second] {
        let signature = Signature::from_bytes(&signed.signature).unwrap();
        assert!(public.verify_simple(SR25519_CONTEXT, &payload, &signature).is_ok());
        assert!(public.verify_simple(b"polkadot", &payload, &signature).is_err(), "context");
        assert_eq!(signed.extrinsic, transfer.encode_signed(&signed.signature).unwrap());
        assert_eq!(signed.hash, blake2_256(&signed.extrinsic));
    }
    // schnorrkel mixes fresh randomness into the nonce.
    assert_ne!(first.signature, second.signature);
}

#[test]
fn a_failing_random_source_makes_no_signature() {
    let key = SigningKey::sr25519(&[7; 32]).unwrap();
    let transfer = transfer_of(key.public_key());
    let mut failing = |_: &mut [u8]| false;
    assert_eq!(sign_with_source(&key, &transfer, &mut failing), Err(TransferError::Randomness));
    // A source that works once and then fails: still none.
    let mut calls = 0;
    let mut flaky = |dest: &mut [u8]| {
        calls += 1;
        dest.fill(0x5a);
        calls == 1
    };
    let result = sign_with_source(&key, &transfer, &mut flaky);
    assert!(matches!(result, Ok(_) | Err(TransferError::Randomness)));
    // A source that works signs, whatever the bytes are.
    let mut fixed = |dest: &mut [u8]| {
        dest.fill(0x5a);
        true
    };
    assert!(sign_with_source(&key, &transfer, &mut fixed).is_ok());
}

#[test]
fn the_sender_the_scheme_and_the_fields_are_checked() {
    let key = SigningKey::sr25519(&[7; 32]).unwrap();
    let transfer = transfer_of(key.public_key());
    let other = SigningKey::sr25519(&[8; 32]).unwrap();
    assert_eq!(sign_transfer(&other, &transfer), Err(TransferError::NotTheSender));
    let ed25519 = SigningKey::ed25519(&[7; 32]);
    assert_eq!(sign_transfer(&ed25519, &transfer), Err(TransferError::WrongKeyScheme));
    let zero = Transfer { value: 0, ..transfer.clone() };
    assert_eq!(sign_transfer(&key, &zero), Err(TransferError::ZeroValue));
    for period in [0, 3, 5, 100, 8192, 1 << 16] {
        let bad = Transfer { period, ..transfer.clone() };
        assert_eq!(sign_transfer(&key, &bad), Err(TransferError::EraPeriod), "{period}");
    }
    for period in [4, 64, 128, 4096] {
        let good = Transfer { period, ..transfer.clone() };
        assert!(sign_transfer(&key, &good).is_ok(), "{period}");
    }
}

#[test]
fn the_last_valid_block_is_one_before_the_era_dies() {
    let key = SigningKey::sr25519(&[7; 32]).unwrap();
    let transfer = transfer_of(key.public_key());
    assert_eq!(transfer.last_valid_block(), 9_141_862 + 63);
}

#[test]
fn a_long_payload_is_signed_as_its_hash() {
    assert_eq!(reduce_payload(vec![1; 256]), vec![1; 256]);
    assert_eq!(reduce_payload(vec![1; 257]), blake2_256(&[1; 257]).to_vec());
}

#[test]
fn blake2_256_is_the_hash_a_finney_block_is_named_by() {
    // A block's hash is the BLAKE2-256 of its SCALE-encoded header: the parent
    // hash, the compact block number, the state root, the extrinsics root and
    // the digest (a compact count, then each item as the node returns it).
    // The header and the hash are what `chain_getHeader` and the block list
    // return for block 9369961 (`tests/vectors/finney-transfer-keep-alive-extrinsics.json`).
    let data: serde_json::Value = serde_json::from_str(FINNEY).unwrap();
    let header = &data["header_of_first_block"];
    let text = |name: &str| header[name].as_str().unwrap();
    let number = u128::from_str_radix(text("number").strip_prefix("0x").unwrap(), 16).unwrap();
    let mut encoded = hex32(text("parentHash")).to_vec();
    encoded.extend_from_slice(&compact(number));
    encoded.extend_from_slice(&hex32(text("stateRoot")));
    encoded.extend_from_slice(&hex32(text("extrinsicsRoot")));
    let logs = header["digest"]["logs"].as_array().unwrap();
    encoded.extend_from_slice(&compact(logs.len() as u128));
    for log in logs {
        encoded.extend_from_slice(
            &hex::decode(log.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap(),
        );
    }
    assert_eq!(hex::encode(blake2_256(&encoded)), text("block_hash").strip_prefix("0x").unwrap());
    assert_eq!(number, 9_369_961);
}

// ---- addresses ---------------------------------------------------------------------

#[test]
fn addresses_are_read_back_to_the_key_they_were_made_from() {
    // sp-core's `DEV_ADDRESS` (see the derivation tests), and the Polkadot.js
    // address of `//Alice`, with that key's public bytes from sp-core.
    let dev = parse_address("5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV").unwrap();
    assert_eq!(
        address_from_public_key(&dev).unwrap(),
        "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"
    );
    let alice = parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
    assert_eq!(
        hex::encode(alice),
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
    );
    // Not an address: wrong checksum, another prefix (py-substrate-interface's
    // prefix-0 address of a key), wrong length, nonsense.
    assert!(parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQz").is_none());
    assert!(parse_address("16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2").is_none());
    assert!(parse_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQ").is_none());
    assert!(parse_address("").is_none());
    assert!(
        parse_address("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
            .is_none()
    );
}
