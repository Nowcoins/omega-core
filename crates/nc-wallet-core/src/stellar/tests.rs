//! Stellar: vectors from the Go SDK and from the public network, and the
//! behaviour of the builder and the signer.
//!
//! Every expected value below is copied from the source named beside it, at
//! the commit named, or read from the public network (see `tests/vectors/`).
//! None is worked out by the code under test.

#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]

use base64::Engine as _;
use ed25519_dalek::Verifier as _;
use stellar_strkey::ed25519::PrivateKey;

use super::xdr::*;
use super::*;

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

/// The key of a `G…` address.
fn account(text: &str) -> [u8; 32] {
    parse_address(text).unwrap()
}

/// A signing key from an `S…` secret seed.
fn key_of(secret: &str) -> SigningKey {
    SigningKey::ed25519(&PrivateKey::from_string(secret).unwrap().0)
}

// ---- the Go SDK: signed envelopes, byte for byte --------------------------------
//
// stellar/go, txnbuild/transaction_test.go at commit
// aab2ea4aca889ebebb11148a542e2165a0778f9a. Each test there builds a
// transaction from `newKeypair0()` (helpers_test.go), with `MinBaseFee` (100)
// and an infinite timeout (time bounds 0 to 0), signs it for the test network
// and compares the envelope's base64 with a string written in the test. The
// SDK's `IncrementSequenceNum` makes the transaction's sequence number the
// account's plus one, as `Transaction::account_sequence` does here.

/// `newKeypair0()`: `helpers_test.go`.
const GO_KEYPAIR_0: &str = "SBPQUZ6G4FZNWFHKUWC5BEYWF6R52E3SEP7R3GWYSM2XTKGF5LNTWW4R";
/// `newKeypair1()`: `helpers_test.go`.
const GO_KEYPAIR_1: &str = "SBMSVD4KKELKGZXHBUQTIROWUAPQASDX7KEJITARP4VMZ6KLUHOGPTYW";

fn go_transaction(account_sequence: i64, operation: Operation) -> Transaction {
    Transaction {
        source: key_of(GO_KEYPAIR_0).public_key().try_into().unwrap(),
        fee: 100,
        account_sequence,
        time_bounds: TimeBounds { min_time: 0, max_time: 0 },
        memo: Memo::None,
        operation,
    }
}

fn go_signed(transaction: &Transaction) -> String {
    sign_transaction(&key_of(GO_KEYPAIR_0), TEST_NETWORK_PASSPHRASE, transaction)
        .unwrap()
        .envelope_base64()
}

#[test]
fn go_sdk_create_account() {
    // `TestCreateAccount` (line 168): 10 XLM to this account, source sequence
    // 9605939170639897.
    let transaction = go_transaction(
        9_605_939_170_639_897,
        Operation::CreateAccount {
            destination: account("GCCOBXW2XQNUSL467IEILE6MMCNRR66SSVL4YQADUNYYNUVREF3FIV2Z"),
            starting_balance: 10 * 10_000_000,
        },
    );
    assert_eq!(
        go_signed(&transaction),
        "AAAAAgAAAADg3G3hclysZlFitS+s5zWyiiJD5B0STWy5LXCj6i5yxQAAAGQAIiCNAAAAGgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAACE4N7avBtJL576CIWTzGCbGPvSlVfMQAOjcYbSsSF2VAAAAAAF9eEAAAAAAAAAAAHqLnLFAAAAQB7MjKIwNEOTIjbEeV+QIjaQp/ZpV5qpbkbDaU54gkfdTOFOUxZq66lTS5FOfP5fmPIVD8InQ00Usy2SmzFC/wc="
    );
}

#[test]
fn go_sdk_payment() {
    // `TestPayment` (line 205): 10 XLM to this account, source sequence
    // 9605939170639898.
    let transaction = go_transaction(
        9_605_939_170_639_898,
        Operation::Payment {
            destination: account("GB7BDSZU2Y27LYNLALKKALB52WS2IZWYBDGY6EQBLEED3TJOCVMZRH7H"),
            destination_id: None,
            asset: Asset::Native,
            amount: 10 * 10_000_000,
        },
    );
    assert_eq!(
        go_signed(&transaction),
        "AAAAAgAAAADg3G3hclysZlFitS+s5zWyiiJD5B0STWy5LXCj6i5yxQAAAGQAIiCNAAAAGwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAB+Ecs01jX14asC1KAsPdWlpGbYCM2PEgFZCD3NLhVZmAAAAAAAAAAABfXhAAAAAAAAAAAB6i5yxQAAAEDXBkKYzThQi3/XhJqGzfh/EjaAx/4zK3xBT1/JDNtdkk/kxn4qxHVx++xiV72lqZXxiphNwflA8C7mC8Dvim0E"
    );
}

#[test]
fn go_sdk_change_trust_and_its_removal() {
    // `TestChangeTrust` (line 621): trust ABCD issued by `newKeypair1()`, up to
    // 10, source sequence 40385577484348; `TestChangeTrustDeleteTrustline`
    // (line 668): the same asset with a limit of 0, source sequence
    // 40385577484354.
    let issuer: [u8; 32] = key_of(GO_KEYPAIR_1).public_key().try_into().unwrap();
    let asset = Asset::Credit { code: AssetCode::new("ABCD").unwrap(), issuer };
    assert_eq!(
        go_signed(&go_transaction(
            40_385_577_484_348,
            Operation::ChangeTrust { asset: asset.clone(), limit: 10 * 10_000_000 }
        )),
        "AAAAAgAAAADg3G3hclysZlFitS+s5zWyiiJD5B0STWy5LXCj6i5yxQAAAGQAACS7AAAAPQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAABgAAAAFBQkNEAAAAACXK8doPx27P6IReQlRRuweSSUiUfjqgyswxiu3Sh2R+AAAAAAX14QAAAAAAAAAAAeoucsUAAABA+2EndVXXsBHbRFEQGLsgsvHVm8wCxH9byZ/PP4AhEeAjXSL6IzhGnyRIWIc2SYXRu6GvveVI3yPbzCTvKnVjCg=="
    );
    assert_eq!(
        go_signed(&go_transaction(40_385_577_484_354, Operation::ChangeTrust { asset, limit: 0 })),
        "AAAAAgAAAADg3G3hclysZlFitS+s5zWyiiJD5B0STWy5LXCj6i5yxQAAAGQAACS7AAAAQwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAABgAAAAFBQkNEAAAAACXK8doPx27P6IReQlRRuweSSUiUfjqgyswxiu3Sh2R+AAAAAAAAAAAAAAAAAAAAAeoucsUAAABAoHdsJCt+XIr73+jSqbEhQ8iqXcqP3LO8C/kWH2dgQj+3hq1FKbthn0BbX/x5umgcE+pyfnTjU0j158qew6tfCw=="
    );
}

#[test]
fn go_sdk_memos_are_encoded_as_the_sdk_encodes_them() {
    // `TestMemoText` (line 896) and `TestMemoID` (line 918) sign a transaction
    // with a memo and a `BumpSequence`, an operation this wallet does not
    // build; the memo is the same bytes wherever it sits. In the envelope an
    // XDR envelope type (4 bytes), the source (36), the fee (4), the sequence
    // number (8) and the preconditions (4 + 16 for infinite time bounds)
    // come first: the memo starts at byte 72.
    let text = b64(
        "AAAAAgAAAAB+Ecs01jX14asC1KAsPdWlpGbYCM2PEgFZCD3NLhVZmAAAAGQADKJBAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAxUd2FzIGJyaWxsaWcAAAABAAAAAAAAAAsAAAAAAAAAAQAAAAAAAAABLhVZmAAAAECC0/P+zBk5lpH4zIumNt59nFVrPiDGOu8TrJE4r0mXoae8Fmg1yyHQm3Yo5huuPjc/nzwU/R2DKkkQ3C4mWA0N",
    );
    let mut ours = Vec::new();
    Memo::text("Twas brillig").unwrap().encode(&mut ours);
    assert_eq!(&text[72..72 + ours.len()], ours.as_slice());
    assert_eq!(ours.len(), 20, "a type, a length and twelve bytes");

    let id = b64(
        "AAAAAgAAAAB+Ecs01jX14asC1KAsPdWlpGbYCM2PEgFZCD3NLhVZmAAAAGQADC4KAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAABMsvAAAAAQAAAAAAAAALAAAAAAAAAAEAAAAAAAAAAS4VWZgAAABAOT/1f1XoeqY14+wp6rVgwE4fCCPnItc9/85jZN++Fy7lS88e40b3ufQCpzzMCD8AyfHF8BCs/Pn2DiJHxCPQCQ==",
    );
    let mut ours = Vec::new();
    Memo::Id(314_159).encode(&mut ours);
    assert_eq!(&id[72..72 + ours.len()], ours.as_slice());

    // `TestMemoHash` with no memo at all: the SDK's `Transaction` with no memo
    // writes `MEMO_NONE`, the four zero bytes the first vector's envelope has
    // at the same place.
    let none = b64(
        "AAAAAgAAAADg3G3hclysZlFitS+s5zWyiiJD5B0STWy5LXCj6i5yxQAAAGQAIiCNAAAAGwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAB+Ecs01jX14asC1KAsPdWlpGbYCM2PEgFZCD3NLhVZmAAAAAAAAAAABfXhAAAAAAAAAAAB6i5yxQAAAEDXBkKYzThQi3/XhJqGzfh/EjaAx/4zK3xBT1/JDNtdkk/kxn4qxHVx++xiV72lqZXxiphNwflA8C7mC8Dvim0E",
    );
    let mut ours = Vec::new();
    Memo::None.encode(&mut ours);
    assert_eq!(&none[72..76], ours.as_slice());
}

// ---- network ids and the signature base ------------------------------------------

#[test]
fn network_ids_are_the_hashes_of_the_passphrases() {
    // The passphrases are the constants `PublicNetworkPassphrase` and
    // `TestNetworkPassphrase` in stellar/go, network/main.go at commit
    // aab2ea4aca889ebebb11148a542e2165a0778f9a. The network's id is the SHA-256
    // of its passphrase; for the test network the Go SDK envelopes above, and
    // for the public network the hashes of the transactions in the public
    // network test below, only come out right with the right id.
    assert_eq!(PUBLIC_NETWORK_PASSPHRASE, "Public Global Stellar Network ; September 2015");
    assert_eq!(TEST_NETWORK_PASSPHRASE, "Test SDF Network ; September 2015");
    assert_ne!(network_id(PUBLIC_NETWORK_PASSPHRASE), network_id(TEST_NETWORK_PASSPHRASE));
}

// ---- memo and asset rules ------------------------------------------------------

#[test]
fn a_number_written_as_one_is_an_id_memo() {
    assert_eq!(Memo::parse("350940740").unwrap(), Memo::Id(350_940_740));
    assert_eq!(Memo::parse("18446744073709551615").unwrap(), Memo::Id(u64::MAX));
    assert_eq!(Memo::parse("0").unwrap(), Memo::Id(0));
    for text in ["007", "+5", "18446744073709551616", "12 34", "ref-42", "-1"] {
        assert_eq!(Memo::parse(text).unwrap(), Memo::text(text).unwrap(), "{text}");
    }
    assert_eq!(Memo::parse("").unwrap(), Memo::None);
}

#[test]
fn a_memo_is_measured_in_bytes() {
    assert!(Memo::text(&"a".repeat(28)).is_ok());
    assert_eq!(Memo::text(&"a".repeat(29)), Err(XdrError::MemoTooLong(29)));
    // Ten two-byte characters are twenty bytes; fifteen are thirty.
    assert!(Memo::text(&"é".repeat(10)).is_ok());
    assert_eq!(Memo::text(&"é".repeat(15)), Err(XdrError::MemoTooLong(30)));
}

#[test]
fn asset_codes_are_checked() {
    assert!(AssetCode::new("USDC").is_ok());
    assert!(AssetCode::new("USDCTWELVE12").is_ok());
    for bad in ["", "USDCTWELVE123", "US-D", "USDÇ"] {
        assert!(AssetCode::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn text_is_padded_to_four_bytes() {
    // XDR: a memo type, then the text as a length, the bytes and zeros to a
    // multiple of four.
    for (text, expected) in [("", 8), ("a", 12), ("abcd", 12), ("abcde", 16)] {
        let mut out = Vec::new();
        Memo::text(text).unwrap().encode(&mut out);
        assert_eq!(out.len(), expected, "{text:?}");
        assert!(out[8 + text.len()..].iter().all(|b| *b == 0));
    }
}

#[test]
fn credit_assets_use_the_short_form_up_to_four_characters() {
    let issuer = account(USDC_ISSUER);
    let mut short = Vec::new();
    let usdc = Asset::credit("USDC", USDC_ISSUER).unwrap();
    let mut transaction =
        go_transaction(1, Operation::ChangeTrust { asset: usdc, limit: i64::MAX });
    transaction.source = issuer;
    short.extend_from_slice(&transaction.encode().unwrap());
    // alphanum4 is type 1 followed by the four letters.
    assert!(short.windows(8).any(|w| w == [0, 0, 0, 1, b'U', b'S', b'D', b'C']));
    let long = Asset::credit("USDCLONGER", USDC_ISSUER).unwrap();
    transaction.operation = Operation::ChangeTrust { asset: long, limit: i64::MAX };
    let encoded = transaction.encode().unwrap();
    // alphanum12 is type 2 followed by twelve bytes, zero padded.
    assert!(encoded.windows(16).any(
        |w| w == [0, 0, 0, 2, b'U', b'S', b'D', b'C', b'L', b'O', b'N', b'G', b'E', b'R', 0, 0]
    ));
}

// ---- the public network ------------------------------------------------------------
//
// `tests/vectors/stellar-public-network-transactions.json`: transactions as
// the network recorded them, with Horizon's reading of each. A builder is right
// if it writes the bytes the network accepted and the hash the network names
// the transaction by.

const PUBLIC: &str = include_str!("../../tests/vectors/stellar-public-network-transactions.json");

fn text<'a>(value: &'a serde_json::Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_else(|| panic!("no {name} in {value}"))
}

/// Horizon's decimal amounts ("5.1800000": seven places) in stroops.
fn stroops(amount: &str) -> i64 {
    let (whole, fraction) = amount.split_once('.').unwrap();
    assert_eq!(fraction.len(), 7, "{amount}");
    whole.parse::<i64>().unwrap() * 10_000_000 + fraction.parse::<i64>().unwrap()
}

/// The transaction Horizon describes, in this crate's terms.
fn as_described(entry: &serde_json::Value) -> Transaction {
    let tx = &entry["transaction"];
    let operations = entry["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 1);
    let op = &operations[0];
    let operation = match text(op, "type") {
        "payment" => Operation::Payment {
            destination: account(text(op, "to")),
            destination_id: None,
            asset: match text(op, "asset_type") {
                "native" => Asset::Native,
                "credit_alphanum4" => {
                    Asset::credit(text(op, "asset_code"), text(op, "asset_issuer")).unwrap()
                }
                other => panic!("{other}"),
            },
            amount: stroops(text(op, "amount")),
        },
        "change_trust" => Operation::ChangeTrust {
            asset: Asset::credit(text(op, "asset_code"), text(op, "asset_issuer")).unwrap(),
            limit: stroops(text(op, "limit")),
        },
        "create_account" => Operation::CreateAccount {
            destination: account(text(op, "account")),
            starting_balance: stroops(text(op, "starting_balance")),
        },
        other => panic!("{other}"),
    };
    let bounds = &tx["preconditions"]["timebounds"];
    Transaction {
        source: account(text(tx, "source_account")),
        fee: text(tx, "max_fee").parse().unwrap(),
        // Horizon's `source_account_sequence` is the number the transaction
        // carried; the account's was one less.
        account_sequence: text(tx, "source_account_sequence").parse::<i64>().unwrap() - 1,
        time_bounds: TimeBounds {
            min_time: text(bounds, "min_time").parse().unwrap(),
            max_time: text(bounds, "max_time").parse().unwrap(),
        },
        memo: match text(tx, "memo_type") {
            "none" => Memo::None,
            "text" => Memo::text(text(tx, "memo")).unwrap(),
            "id" => Memo::Id(text(tx, "memo").parse().unwrap()),
            other => panic!("{other}"),
        },
        operation,
    }
}

#[test]
fn the_builder_writes_what_the_public_network_accepted() {
    let data: serde_json::Value = serde_json::from_str(PUBLIC).unwrap();
    let entries = data["transactions"].as_object().unwrap();
    // XLM and USDC payments, with no memo, a text memo and an id memo, an
    // account creation and a USDC trustline.
    assert_eq!(entries.len(), 7);
    for (name, entry) in entries {
        let tx = &entry["transaction"];
        let envelope_bytes = b64(text(tx, "envelope_xdr"));
        // One signature at the end: a count, a hint, the signature (a 4-byte
        // length, then 64 bytes).
        let body = &envelope_bytes[4..envelope_bytes.len() - 4 - 4 - 4 - 64];
        let signature: [u8; 64] = envelope_bytes[envelope_bytes.len() - 64..].try_into().unwrap();
        assert_eq!(b64(tx["signatures"][0].as_str().unwrap()), signature, "{name}");

        let ours = as_described(entry);
        assert_eq!(ours.encode().unwrap(), body, "{name}");

        // The network's name for the transaction is the hash of those bytes
        // under the public network's id.
        let hash =
            transaction_hash(&network_id(PUBLIC_NETWORK_PASSPHRASE), &ours.encode().unwrap());
        assert_eq!(hex::encode(hash), text(tx, "hash"), "{name}");
        // The network's signature is over that hash, by the source account.
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&ours.source).unwrap();
        assert!(
            verifying.verify(&hash, &ed25519_dalek::Signature::from_bytes(&signature)).is_ok(),
            "{name}"
        );
        // And the envelope, around that signature, is the network's.
        assert_eq!(
            envelope(&ours.encode().unwrap(), &[(signature_hint(&ours.source), signature)]),
            envelope_bytes,
            "{name}"
        );
    }
}

// ---- what the builder and the signer refuse ----------------------------------------------

fn payment(amount: i64) -> Transaction {
    Transaction {
        source: key_of(GO_KEYPAIR_0).public_key().try_into().unwrap(),
        fee: 100,
        account_sequence: 7,
        time_bounds: TimeBounds { min_time: 0, max_time: 1_000 },
        memo: Memo::None,
        operation: Operation::Payment {
            destination: account("GB7BDSZU2Y27LYNLALKKALB52WS2IZWYBDGY6EQBLEED3TJOCVMZRH7H"),
            destination_id: None,
            asset: Asset::Native,
            amount,
        },
    }
}

#[test]
fn a_transaction_the_network_would_refuse_is_not_built() {
    assert!(payment(1).encode().is_ok());
    assert!(payment(i64::MAX).encode().is_ok());
    assert_eq!(payment(0).encode(), Err(XdrError::Amount));
    assert_eq!(payment(-1).encode(), Err(XdrError::Amount));

    let mut tx = payment(1);
    tx.fee = 0;
    assert_eq!(tx.encode(), Err(XdrError::OutOfRange("the fee")));
    let mut tx = payment(1);
    tx.account_sequence = -1;
    assert_eq!(tx.encode(), Err(XdrError::OutOfRange("the sequence number")));
    // The next sequence number does not fit.
    tx.account_sequence = i64::MAX;
    assert_eq!(tx.encode(), Err(XdrError::OutOfRange("the sequence number")));
    let mut tx = payment(1);
    tx.time_bounds = TimeBounds { min_time: 10, max_time: 5 };
    assert_eq!(tx.encode(), Err(XdrError::TimeBounds));
    // No limit is a maximum of zero.
    tx.time_bounds = TimeBounds { min_time: 10, max_time: 0 };
    assert!(tx.encode().is_ok());

    let mut tx = payment(1);
    tx.operation = Operation::ChangeTrust { asset: Asset::Native, limit: 1 };
    assert_eq!(tx.encode(), Err(XdrError::NativeTrustline));
    tx.operation =
        Operation::ChangeTrust { asset: Asset::credit("USDC", USDC_ISSUER).unwrap(), limit: -1 };
    assert_eq!(tx.encode(), Err(XdrError::OutOfRange("the trustline limit")));
    tx.operation = Operation::CreateAccount { destination: [1; 32], starting_balance: -1 };
    assert_eq!(tx.encode(), Err(XdrError::OutOfRange("the starting balance")));
    // Not an issuer.
    assert!(Asset::credit("USDC", "not an address").is_err());
    assert!(
        Asset::credit("USDC", "GB7BDSZU2Y27LYNLALKKALB52WS2IZWYBDGY6EQBLEED3TJOCVMZRH7").is_err()
    );
}

#[test]
fn a_key_signs_only_its_own_transactions_and_only_as_ed25519() {
    let key = key_of(GO_KEYPAIR_0);
    let signed = sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, &payment(1)).unwrap();
    // Signing is deterministic (RFC 8032), the signature is over the hash, by the source.
    assert_eq!(signed, sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, &payment(1)).unwrap());
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&payment(1).source).unwrap();
    assert!(
        verifying
            .verify_strict(&signed.hash, &ed25519_dalek::Signature::from_bytes(&signed.signature))
            .is_ok()
    );
    assert_eq!(signed.hash_hex().len(), 64);
    assert_eq!(b64(&signed.envelope_base64()), signed.envelope);
    // Another network, another hash and another signature.
    let elsewhere = sign_transaction(&key, TEST_NETWORK_PASSPHRASE, &payment(1)).unwrap();
    assert_ne!(elsewhere.hash, signed.hash);
    assert_ne!(elsewhere.signature, signed.signature);
    assert_eq!(
        elsewhere.envelope[..elsewhere.envelope.len() - 76],
        signed.envelope[..signed.envelope.len() - 76]
    );

    assert_eq!(
        sign_transaction(&key_of(GO_KEYPAIR_1), PUBLIC_NETWORK_PASSPHRASE, &payment(1)),
        Err(StellarError::NotTheSource)
    );
    assert_eq!(
        sign_transaction(
            &SigningKey::sr25519(&[1; 32]).unwrap(),
            PUBLIC_NETWORK_PASSPHRASE,
            &payment(1)
        ),
        Err(StellarError::WrongKeyScheme)
    );
    assert_eq!(
        sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, &payment(0)),
        Err(StellarError::Transaction(XdrError::Amount))
    );
}

#[test]
fn only_plain_g_addresses_are_read() {
    // SEP-0005's first account (`tests/vectors/sep-0005-test-cases.md`).
    let address = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    assert!(parse_address(address).is_some());
    // A muxed address (`M…`, from the Go SDK's `TestPaymentMuxedAccounts`,
    // transaction_test.go line 248), a secret seed (`S…`), a wrong checksum,
    // nonsense.
    assert!(
        parse_address("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK")
            .is_none()
    );
    assert!(parse_address(GO_KEYPAIR_0).is_none());
    assert!(parse_address("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ7").is_none());
    assert!(parse_address("").is_none());
    assert_eq!(parse_address(USDC_ISSUER).map(|k| k.len()), Some(32));
}

// ---- muxed destinations (SEP-23) -----------------------------------------------------------

/// SEP-23's account, and its muxed addresses with the ids 0 and 2^63.
const MUXED_BASE: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
const MUXED_0: &str = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ";
const MUXED_2_63: &str = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

#[test]
fn a_destination_is_a_g_address_or_a_muxed_one_and_nothing_else() {
    let key = account(MUXED_BASE);
    assert_eq!(parse_destination(MUXED_BASE), Some(Destination { key, id: None }));
    assert_eq!(parse_destination(MUXED_0), Some(Destination { key, id: Some(0) }));
    assert_eq!(
        parse_destination(MUXED_2_63),
        Some(Destination { key, id: Some(9_223_372_036_854_775_808) })
    );
    assert_eq!(muxed_address(&key, 9_223_372_036_854_775_808), MUXED_2_63);
    assert_eq!(muxed_address(&key, u64::MAX).len(), 69);
    assert_eq!(
        parse_destination(&muxed_address(&key, u64::MAX)),
        Some(Destination { key, id: Some(u64::MAX) })
    );
    // A G address is still the only account of a key: an issuer is not a muxed account.
    assert_eq!(parse_address(MUXED_BASE), Some(key));
    assert_eq!(parse_address(MUXED_0), None);
    // A secret, a contract, a changed letter, a cut or a padded one, lower case, nothing.
    let mut changed = MUXED_0.to_owned().into_bytes();
    changed[10] = if changed[10] == b'A' { b'B' } else { b'A' };
    for not in [
        "SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7",
        "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        &String::from_utf8(changed).unwrap(),
        &MUXED_0[..MUXED_0.len() - 1],
        &format!("{MUXED_0}A"),
        &format!("{MUXED_0}==="),
        &MUXED_0.to_lowercase(),
        "",
        "M",
    ] {
        assert_eq!(parse_destination(not), None, "{not}");
    }
}

#[test]
fn a_payment_to_a_muxed_address_is_the_same_payment_with_the_muxed_arm_in_the_destination() {
    let plain = payment(5_000_000);
    let Operation::Payment { destination, .. } = plain.operation.clone() else { panic!() };
    for id in [0, 1, 9_223_372_036_854_775_808, u64::MAX] {
        let mut muxed = plain.clone();
        let Operation::Payment { destination_id, .. } = &mut muxed.operation else { panic!() };
        *destination_id = Some(id);
        let (plain_xdr, muxed_xdr) = (plain.encode().unwrap(), muxed.encode().unwrap());
        // KEY_TYPE_MUXED_ED25519 (0x100) and the id come before the key: eight bytes more, nothing else.
        let at = plain_xdr.windows(32).position(|w| w == destination).unwrap() - 4;
        assert_eq!(&plain_xdr[at..at + 4], &[0, 0, 0, 0]);
        let mut want = plain_xdr[..at].to_vec();
        want.extend_from_slice(&[0, 0, 1, 0]);
        want.extend_from_slice(&id.to_be_bytes());
        want.extend_from_slice(&plain_xdr[at + 4..]);
        assert_eq!(muxed_xdr, want, "{id}");
        assert_eq!(muxed_xdr.len(), plain_xdr.len() + 8);
        // So the payment is signed for, and has the hash of, another transaction.
        let key = key_of(GO_KEYPAIR_0);
        let a = sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, &plain).unwrap();
        let b = sign_transaction(&key, PUBLIC_NETWORK_PASSPHRASE, &muxed).unwrap();
        assert_ne!(a.hash, b.hash);
        assert_eq!(b.hash, transaction_hash(&network_id(PUBLIC_NETWORK_PASSPHRASE), &muxed_xdr));
    }
}
