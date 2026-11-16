//! Accounts through the public API, against vectors published by other
//! wallets, wallet libraries and the BIPs. Every constant says where it comes
//! from; none was produced by running this crate.
//!
//! Sources (each pinned to the commit the values were read at):
//!
//! * BIP-84: `bitcoin/bips` @ 100ba872c808946155b1eeb8c4568058f2eea0a7,
//!   `bip-0084.mediawiki`, "Test vectors".
//! * SEP-0005: `stellar/stellar-protocol` @ 1ae39233055a0fb94bb737650a39ede8d77d924c,
//!   `ecosystem/sep-0005.md`, "Test Cases".
//! * Trezor firmware: `trezor/trezor-firmware` @ 2ad1fd4df6b35fde2cd83109d1406d97a2de31af,
//!   `common/tests/fixtures/{ethereum/getaddress,tron/get_address,solana/get_address,stellar/get_address}.json`.
//! * Trust Wallet Core: `trustwallet/wallet-core` @ adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9,
//!   `swift/Tests/HDWalletTests.swift` and `registry.json` (for the default paths).
//! * Polkadot.js: `polkadot-js/common` @ 9281daa14c2c2a41708c3489de8770a064525577,
//!   `packages/keyring/src/index.spec.ts`, `packages/util-crypto/src/mnemonic/toMiniSecret.spec.ts`.
//! * py-substrate-interface: `JAMdotTech/py-polkadot-sdk` (formerly
//!   `polkascan/py-substrate-interface`) @ 65b2ccaa3adea558313f1620d360ec803811f8b9,
//!   `test/test_keypair.py`.
//! * Substrate: `paritytech/polkadot-sdk` @ f20de3de1c5f9624a33209466968e35c1228c0f4,
//!   `substrate/primitives/core/src/crypto.rs` and
//!   `substrate/utils/substrate-bip39/src/lib.rs`.

#![allow(clippy::unwrap_used)]

use blake2::{Blake2b512, Digest as _};
use nc_wallet_core::{
    Account, Error, KeyScheme, Mnemonic, Network, bitcoin, bittensor, derive, evm, signing_key,
    solana, stellar, tron,
};

/// The phrase most vectors use: BIP-39 entropy of all zeros.
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Trezor's test phrase.
const ALL: &str = "all all all all all all all all all all all all";

/// Trust Wallet Core's test phrase (`HDWallet.test`), always used with the
/// passphrase `TREZOR`.
const TRUST: &str =
    "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";

fn phrase(words: &str) -> Mnemonic {
    Mnemonic::parse(words).unwrap()
}

fn hex32(secret: &[u8; 32]) -> String {
    hex::encode(secret)
}

// ---- Trezor firmware fixtures ----------------------------------------------

/// `[{ "parameters": { "path": … }, "result": { <key>: address } }]` of a
/// Trezor fixture, as `(path, address)`.
fn trezor(fixture: &str, address_key: &str) -> (String, String, Vec<(String, String)>) {
    let json: serde_json::Value = serde_json::from_str(fixture).unwrap();
    let mnemonic = json["setup"]["mnemonic"].as_str().unwrap().to_owned();
    let passphrase = json["setup"]["passphrase"].as_str().unwrap().to_owned();
    let tests = json["tests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["parameters"]["path"].as_str().unwrap().to_owned(),
                t["result"][address_key].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    (mnemonic, passphrase, tests)
}

/// Checks every fixture entry whose path is `{prefix}{index}{suffix}` for a
/// plain number `index`; returns how many it checked.
fn check_trezor(
    fixture: &str,
    address_key: &str,
    network: Network,
    prefix: &str,
    suffix: &str,
) -> usize {
    let (mnemonic, passphrase, tests) = trezor(fixture, address_key);
    assert_eq!(passphrase, "");
    let phrase = phrase(&mnemonic);
    let mut checked = 0;
    for (path, address) in tests {
        let Some(rest) = path.strip_prefix(prefix).and_then(|r| r.strip_suffix(suffix)) else {
            continue;
        };
        let Ok(index) = rest.parse::<u32>() else { continue };
        assert_eq!(network.derivation_path(index), path);
        assert_eq!(derive(&phrase, "", network, index).unwrap().address, address, "{path}");
        checked += 1;
    }
    checked
}

// ---- EVM -------------------------------------------------------------------

#[test]
fn evm_trezor_firmware() {
    // m/44'/60'/0'/0/0 and m/44'/60'/0'/0/100; the other entries of the
    // fixture are other paths (account level, ETC, Ledger Live).
    let checked = check_trezor(
        include_str!("vectors/trezor-ethereum-getaddress.json"),
        "address",
        Network::Evm,
        "m/44'/60'/0'/0/",
        "",
    );
    assert_eq!(checked, 2);
}

#[test]
fn evm_trust_wallet_core() {
    // swift/Tests/HDWalletTests.swift: `testDeriveEthereum` (address 0) and
    // `testDerive` (addresses 0 and 1); the default Ethereum path in
    // registry.json is m/44'/60'/0'/0/0.
    let phrase = phrase(TRUST);
    let at = |i| derive(&phrase, "TREZOR", Network::Evm, i).unwrap().address;
    assert_eq!(at(0), "0x27Ef5cDBe01777D62438AfFeb695e33fC2335979");
    assert_eq!(at(1), "0x98f5438cDE3F0Ff6E11aE47236e93481899d1C47");
}

#[test]
fn evm_polkadot_js_keyring_private_key_and_address() {
    // keyring/src/index.spec.ts, `describe('ethereum')`: the phrase with the
    // path `/m/44'/60'/0'/0/0` has PRIV_KEY_ONE and ETH_ADDRESS_ONE.
    let phrase = phrase("seed sock milk update focus rotate barely fade car face mechanic mercy");
    let key = signing_key(&phrase, "", Network::Evm, 0).unwrap();
    assert_eq!(key.scheme(), KeyScheme::Secp256k1);
    assert_eq!(
        hex32(key.expose_secret()),
        "070dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46"
    );
    assert_eq!(
        derive(&phrase, "", Network::Evm, 0).unwrap().address,
        "0x31ea8795EE32D782C8ff41a5C68Dcbf0F5B27f6d"
    );
}

#[test]
fn evm_py_substrate_interface_ecdsa() {
    // test/test_keypair.py, `test_create_ecdsa_keypair_uri`: this phrase at
    // `/m/44'/60'/0'/0/0` and `/m/44'/60'/0'/0/1`.
    let phrase =
        phrase("old leopard transfer rib spatial phone calm indicate online fire caution review");
    let at = |i| derive(&phrase, "", Network::Evm, i).unwrap().address;
    assert_eq!(at(0), "0xc6A0d8799D596BDd5C30E9ACbe2c63F37c142e35");
    assert_eq!(at(1), "0x571DCd75Cd50852db08951e3A173aC23e44F05c9");
}

// ---- TRON ------------------------------------------------------------------

#[test]
fn tron_trezor_firmware() {
    // m/44'/195'/0'/0/{0,1,2}; the other entries change the account level.
    let checked = check_trezor(
        include_str!("vectors/trezor-tron-get_address.json"),
        "address",
        Network::Tron,
        "m/44'/195'/0'/0/",
        "",
    );
    assert_eq!(checked, 3);
}

#[test]
fn tron_trust_wallet_core() {
    // `testDeriveTron`; default path m/44'/195'/0'/0/0 in registry.json.
    let phrase = phrase(TRUST);
    assert_eq!(
        derive(&phrase, "TREZOR", Network::Tron, 0).unwrap().address,
        "THJrqfbBhoB1vX97da6S6nXWkafCxpyCNB"
    );
}

#[test]
fn tron_and_evm_share_the_key_but_not_the_path() {
    // The same 20 bytes behind a 0x41 byte would be the same account; they
    // are not, because the paths differ (60' against 195').
    let phrase = phrase(ABANDON);
    let evm = signing_key(&phrase, "", Network::Evm, 0).unwrap();
    let tron = signing_key(&phrase, "", Network::Tron, 0).unwrap();
    assert_ne!(evm.expose_secret(), tron.expose_secret());
}

// ---- Bitcoin ---------------------------------------------------------------

/// BIP-84 "Test vectors", copied verbatim.
const BIP84: &str = include_str!("vectors/bip-0084-test-vectors.txt");

fn bip84_values(name: &str) -> Vec<String> {
    BIP84
        .lines()
        .filter_map(|l| l.trim().strip_prefix(name))
        .filter_map(|l| l.trim_start().strip_prefix('='))
        .map(|v| v.trim().to_owned())
        .collect()
}

/// A compressed-key WIF (`Base58Check` of 0x80, the key, 0x01) to the key.
fn wif_secret(wif: &str) -> Vec<u8> {
    let bytes = bs58::decode(wif).with_check(None).into_vec().unwrap();
    assert_eq!((bytes.len(), bytes[0], bytes[33]), (34, 0x80, 0x01));
    bytes[1..33].to_vec()
}

#[test]
fn bitcoin_bip84_vector() {
    assert_eq!(bip84_values("mnemonic"), [ABANDON]);
    let seed = phrase(ABANDON).to_seed("");
    let privkeys = bip84_values("privkey");
    let pubkeys = bip84_values("pubkey");
    let addresses = bip84_values("address");
    assert_eq!((privkeys.len(), pubkeys.len(), addresses.len()), (3, 3, 3));

    // Account 0: first receiving address m/84'/0'/0'/0/0, second receiving
    // address m/84'/0'/0'/0/1, first change address m/84'/0'/0'/1/0.
    let wanted =
        [(bitcoin::Chain::Receive, 0), (bitcoin::Chain::Receive, 1), (bitcoin::Chain::Change, 0)];
    for (i, (chain, index)) in wanted.into_iter().enumerate() {
        let account = bitcoin::account(&seed, 0, chain, index).unwrap();
        assert_eq!(account.address, addresses[i]);
        assert_eq!(hex::encode(&account.public_key), pubkeys[i]);
        let key = bitcoin::signing_key(&seed, 0, chain, index).unwrap();
        assert_eq!(key.expose_secret().to_vec(), wif_secret(&privkeys[i]));
        assert_eq!(key.public_key(), account.public_key);
    }
    // The generic entry point gives the first receiving address.
    assert_eq!(derive(&phrase(ABANDON), "", Network::Bitcoin, 0).unwrap().address, addresses[0]);
    assert_eq!(Network::Bitcoin.derivation_path(0), "m/84'/0'/0'/0/0");
    // The wallet's account number is the BIP-84 account.
    assert_eq!(Network::Bitcoin.derivation_path(2), "m/84'/0'/2'/0/0");
}

#[test]
fn bitcoin_account_zpub_is_bip84s() {
    let zpub = bip84_values("xpub");
    assert_eq!(zpub.len(), 1);
    let seed = phrase(ABANDON).to_seed("");
    assert_eq!(bitcoin::account_zpub(&seed, 0).unwrap(), zpub[0]);
    assert!(zpub[0].starts_with("zpub"));
}

#[test]
fn bitcoin_trust_wallet_core() {
    // `testGetKeyDerivationBitcoin` (the segwit key, default path
    // m/84'/0'/0'/0/0 in registry.json) and `testDeriveBitcoin`.
    let phrase = phrase(TRUST);
    let key = signing_key(&phrase, "TREZOR", Network::Bitcoin, 0).unwrap();
    assert_eq!(
        hex32(key.expose_secret()),
        "1901b5994f075af71397f65bd68a9fff8d3025d65f5a2c731cf90f5e259d6aac"
    );
    assert_eq!(
        derive(&phrase, "TREZOR", Network::Bitcoin, 0).unwrap().address,
        "bc1qumwjg8danv2vm29lp5swdux4r60ezptzz7ce85"
    );
}

// ---- Solana ----------------------------------------------------------------

#[test]
fn solana_trezor_firmware() {
    // m/44'/501'/0'/0' is account 0 here; the fixture's other entries are the
    // shorter paths m/44'/501' and m/44'/501'/0' (checked against the SLIP-10
    // code directly, in hd.rs).
    let (mnemonic, passphrase, tests) =
        trezor(include_str!("vectors/trezor-solana-get_address.json"), "expected_address");
    assert_eq!(passphrase, "");
    let phrase = phrase(&mnemonic);
    let account = derive(&phrase, "", Network::Solana, 0).unwrap();
    let (path, address) = tests.iter().find(|(p, _)| p == "m/44'/501'/0'/0'").unwrap();
    assert_eq!(*path, Network::Solana.derivation_path(0));
    assert_eq!(account.address, *address);
    assert_eq!(account.address, "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS");
    let key = signing_key(&phrase, "", Network::Solana, 0).unwrap();
    assert_eq!(key.scheme(), KeyScheme::Ed25519);
    assert_eq!(key.public_key(), account.public_key);
    assert_eq!(bs58::encode(&account.public_key).into_string(), account.address);
}

#[test]
fn solana_trust_wallets_default_path_is_not_phantoms() {
    // `trustwallet/wallet-core` @ 992b248dfa94202019b718f714918e431ec4c305 (the last commit to the
    // file), `tests/chains/Solana/TWSolanaAddressTests.cpp`, `TWSolanaAddress.HDWallet`: this phrase, no
    // passphrase, at `TWCoinTypeDerivationPath(TWCoinTypeSolana)`, which `registry.json` gives as the
    // first of Solana's two derivations (`m/44'/501'/0'`; the second, `m/44'/501'/0'/0'`, is
    // Phantom's and Omega's account 0). The address is what Trust Wallet shows.
    let phrase =
        phrase("shoot island position soft burden budget tooth cruel issue economy destroy above");
    let trust = solana::trust_wallet_account(&phrase.to_seed("")).unwrap();
    assert_eq!(trust.address, "2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m");
    assert_eq!(bs58::encode(&trust.public_key).into_string(), trust.address);
    assert_eq!(solana::TRUST_WALLET_PATH, "m/44'/501'/0'");
    // So a phrase moved from Trust Wallet shows another Solana address in Omega, whose account 0 is
    // the other path's: the two are not the same account, and neither is a copy of the other.
    let omega = derive(&phrase, "", Network::Solana, 0).unwrap();
    assert_ne!(omega.address, trust.address);
}

#[test]
fn solana_trust_wallets_path_is_the_one_trezors_fixture_lists_as_the_shorter_one() {
    // The Trezor firmware fixture lists `m/44'/501'/0'` beside Omega's `m/44'/501'/0'/0'` (its other
    // entries are checked against the SLIP-10 code in hd.rs): the same derivation, by another author.
    let (mnemonic, passphrase, tests) =
        trezor(include_str!("vectors/trezor-solana-get_address.json"), "expected_address");
    assert_eq!(passphrase, "");
    let phrase = phrase(&mnemonic);
    let (_, address) = tests.iter().find(|(p, _)| p == "m/44'/501'/0'").unwrap();
    let trust = solana::trust_wallet_account(&phrase.to_seed("")).unwrap();
    assert_eq!(trust.address, *address);
    // And Omega's account 0 of the same phrase is the fixture's other entry.
    let (_, omega) = tests.iter().find(|(p, _)| p == "m/44'/501'/0'/0'").unwrap();
    assert_eq!(derive(&phrase, "", Network::Solana, 0).unwrap().address, *omega);
    assert_ne!(address, omega);
}

#[test]
fn solana_account_index_moves_the_hardened_account_level() {
    // The account index is the third element, hardened: i = 1 is
    // m/44'/501'/1'/0', as Phantom's second account. SLIP-10's own vectors
    // pin the derivation at every depth (hd.rs); here the indexes must differ.
    let phrase = phrase(ALL);
    let a = derive(&phrase, "", Network::Solana, 0).unwrap();
    let b = derive(&phrase, "", Network::Solana, 1).unwrap();
    assert_ne!(a.address, b.address);
    assert_eq!(Network::Solana.derivation_path(1), "m/44'/501'/1'/0'");
}

// ---- Stellar ---------------------------------------------------------------

/// SEP-0005 "Test Cases", copied verbatim.
const SEP5: &str = include_str!("vectors/sep-0005-test-cases.md");

#[test]
fn stellar_sep0005_vectors() {
    let mut accounts_checked = 0;
    let mut cases = 0;
    for section in SEP5.split("### Test ").skip(1) {
        // The fenced blocks of a case: [phrase (+ blank line + passphrase)],
        // [BIP-39 seed], [the m/44'/148' key], [the `path G… S…` lines].
        let blocks: Vec<Vec<&str>> = section
            .split("```")
            .skip(1)
            .step_by(2)
            .map(|b| b.lines().filter(|l| !l.is_empty()).collect())
            .collect();
        assert_eq!(blocks.len(), 4);
        let words = blocks[0][0];
        let passphrase = blocks[0].get(1).copied().unwrap_or("");
        let phrase = phrase(words);
        let seed = phrase.to_seed(passphrase);
        assert_eq!(hex::encode(seed.expose_secret()), blocks[1][0]);

        for (i, line) in blocks[3].iter().enumerate() {
            let mut parts = line.split(' ');
            let (path, address, secret) =
                (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
            assert_eq!(path, Network::Stellar.derivation_path(u32::try_from(i).unwrap()));
            let index = u32::try_from(i).unwrap();
            let account = stellar::account(&seed, index).unwrap();
            assert_eq!(account.address, address, "{path}");
            assert_eq!(*stellar::export_secret_seed(&seed, index).unwrap(), secret, "{path}");
            // Through the one entry point too.
            assert_eq!(derive(&phrase, passphrase, Network::Stellar, index).unwrap(), account);
            accounts_checked += 1;
        }
        cases += 1;
    }
    assert_eq!((cases, accounts_checked), (5, 50));
}

#[test]
fn stellar_trezor_firmware() {
    // Trezor's own fixture for SEP-0005's first phrase (its `data_source_url`
    // says so), accounts 0 to 9.
    let checked = check_trezor(
        include_str!("vectors/trezor-stellar-get_address.json"),
        "address",
        Network::Stellar,
        "m/44'/148'/",
        "'",
    );
    assert_eq!(checked, 10);
}

#[test]
fn stellar_trust_wallet_core() {
    // `testDevieStellar` (sic): the key behind the first account, and its
    // address; default path m/44'/148'/0' in registry.json.
    let phrase = phrase(TRUST);
    let key = signing_key(&phrase, "TREZOR", Network::Stellar, 0).unwrap();
    assert_eq!(
        hex32(key.expose_secret()),
        "4fd1cb3c9c15c171b7b90dc3fefc7b2fc54de09b869cc9d6708d26b114e8d9a5"
    );
    assert_eq!(
        derive(&phrase, "TREZOR", Network::Stellar, 0).unwrap().address,
        "GCRWFRVQP5XS7I4SFCL374VKV6OHJ3L3H3SDVGH7FW73N7LSNYJXOLDK"
    );
}

#[test]
fn stellar_secret_is_not_in_the_account() {
    let seed = phrase(ABANDON).to_seed("");
    let account = stellar::account(&seed, 0).unwrap();
    assert!(account.address.starts_with('G'));
    assert!(!format!("{account:?}").contains("SBUV3MRWKNS6AYKZ6E6M"));
    let secret = stellar::export_secret_seed(&seed, 0).unwrap();
    assert!(secret.starts_with('S'));
    assert_eq!(secret.len(), 56);
}

// ---- Bittensor -------------------------------------------------------------

/// Substrate's public development phrase and the SS58 address of its root key
/// (`DEV_PHRASE`, `DEV_ADDRESS` in sp-core's `crypto.rs`).
const DEV_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const DEV_ADDRESS: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

/// The 32-byte public key inside an SS58 address, after checking its prefix
/// byte and its checksum (Blake2b-512 of `SS58PRE`, prefix and key).
fn ss58_decode(address: &str, prefix: u8) -> Vec<u8> {
    let bytes = bs58::decode(address).into_vec().unwrap();
    assert_eq!(bytes.len(), 35);
    assert_eq!(bytes[0], prefix);
    let digest = Blake2b512::new().chain_update(b"SS58PRE").chain_update(&bytes[..33]).finalize();
    assert_eq!(bytes[33..], digest[..2]);
    bytes[1..33].to_vec()
}

#[test]
fn bittensor_root_key_is_account_zero() {
    let phrase = phrase(DEV_PHRASE);
    let account = derive(&phrase, "", Network::Bittensor, 0).unwrap();
    assert_eq!(account.address, DEV_ADDRESS);
    assert_eq!(account.public_key.len(), 32);
    assert_eq!(ss58_decode(&account.address, 42), account.public_key);
    let key = signing_key(&phrase, "", Network::Bittensor, 0).unwrap();
    assert_eq!(key.scheme(), KeyScheme::Sr25519);
    assert_eq!(key.public_key(), account.public_key);
}

#[test]
fn bittensor_matches_py_substrate_interface_and_so_btcli() {
    // `test_create_sr25519_keypair`: the phrase with `ss58_format=0` is
    // 16ADqp…; the same public key in format 42 is what this crate shows.
    let phrase =
        phrase("old leopard transfer rib spatial phone calm indicate online fire caution review");
    let account = derive(&phrase, "", Network::Bittensor, 0).unwrap();
    assert_eq!(
        ss58_decode("16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2", 0),
        account.public_key
    );
    assert_eq!(ss58_decode(&account.address, 42), account.public_key);
    assert!(account.address.starts_with('5'));
}

#[test]
fn bittensor_mini_secret_matches_polkadot_js() {
    // toMiniSecret.spec.ts: `mnemonicToMiniSecret(MNEMONIC)` with no password.
    let phrase = phrase("seed sock milk update focus rotate barely fade car face mechanic mercy");
    let key = signing_key(&phrase, "", Network::Bittensor, 0).unwrap();
    assert_eq!(
        hex32(key.expose_secret()),
        "4d1ab2a57929edfd018aaa974e62ed557e3f54b4104acabedf73c8f5a1dbb029"
    );
}

/// `static VECTORS` of `substrate-bip39`'s tests, copied verbatim: `[phrase,
/// entropy, seed]`, all made with the password `Substrate`. The mini secret is
/// the first 32 bytes of the seed.
const SUBSTRATE_BIP39: &str = include_str!("vectors/substrate-bip39-vectors.txt");

#[test]
fn bittensor_mini_secret_matches_substrate_bip39_vectors() {
    // The file starts with comments, one of which quotes "Substrate".
    let table = SUBSTRATE_BIP39.split_once("static VECTORS").unwrap().1;
    let quoted: Vec<&str> = table.split('"').skip(1).step_by(2).collect();
    assert_eq!(quoted.len() % 3, 0);
    let mut checked = 0;
    for vector in quoted.chunks(3) {
        let (words, _entropy, seed) = (vector[0], vector[1], vector[2]);
        let phrase = phrase(words);
        let key = signing_key(&phrase, "Substrate", Network::Bittensor, 0).unwrap();
        assert_eq!(hex32(key.expose_secret()), seed[..64], "{words}");
        checked += 1;
    }
    assert_eq!(checked, 24);
}

#[test]
fn bittensor_password_changes_the_wallet() {
    let phrase = phrase(DEV_PHRASE);
    let plain = derive(&phrase, "", Network::Bittensor, 0).unwrap();
    let with = derive(&phrase, "password", Network::Bittensor, 0).unwrap();
    assert_ne!(plain, with);
    assert_ne!(
        derive(&phrase, "password", Network::Bittensor, 1).unwrap(),
        derive(&phrase, "", Network::Bittensor, 1).unwrap()
    );
}

#[test]
fn bittensor_accounts_beyond_zero_are_hard_junctions() {
    let phrase = phrase(DEV_PHRASE);
    let mut seen = std::collections::BTreeSet::new();
    for index in [0, 1, 2, 3, 100, u32::MAX] {
        let account = derive(&phrase, "", Network::Bittensor, index).unwrap();
        assert!(seen.insert(account.address), "index {index} repeated an address");
    }
    assert_eq!(Network::Bittensor.derivation_path(1), "//1");
}

// ---- All networks ----------------------------------------------------------

#[test]
fn key_schemes_and_public_key_sizes() {
    let phrase = phrase(ABANDON);
    for network in Network::ALL {
        let account = derive(&phrase, "", network, 0).unwrap();
        let key = signing_key(&phrase, "", network, 0).unwrap();
        let (scheme, len) = match network {
            Network::Evm | Network::Tron | Network::Bitcoin => (KeyScheme::Secp256k1, 33),
            Network::Solana | Network::Stellar => (KeyScheme::Ed25519, 32),
            Network::Bittensor => (KeyScheme::Sr25519, 32),
        };
        assert_eq!(key.scheme(), scheme, "{network:?}");
        assert_eq!(account.public_key.len(), len, "{network:?}");
        assert_eq!(key.public_key(), account.public_key, "{network:?}");
    }
}

#[test]
fn address_formats() {
    let phrase = phrase(ABANDON);
    let at = |n| derive(&phrase, "", n, 0).unwrap().address;
    let evm = at(Network::Evm);
    assert!(evm.starts_with("0x") && evm.len() == 42);
    let tron = at(Network::Tron);
    assert!(tron.starts_with('T') && tron.len() == 34);
    assert!(at(Network::Bitcoin).starts_with("bc1q"));
    assert!(at(Network::Stellar).starts_with('G') && at(Network::Stellar).len() == 56);
    assert!(at(Network::Bittensor).starts_with('5'));
    let solana = at(Network::Solana);
    assert_eq!(bs58::decode(&solana).into_vec().unwrap().len(), 32);
}

#[test]
fn different_passphrases_are_different_wallets_on_every_network() {
    let phrase = phrase(ABANDON);
    for network in Network::ALL {
        let none = derive(&phrase, "", network, 0).unwrap();
        let some = derive(&phrase, "hunter2", network, 0).unwrap();
        assert_ne!(none.address, some.address, "{network:?}");
    }
}

#[test]
fn indexes_beyond_what_a_path_can_hold_are_refused() {
    let phrase = phrase(ABANDON);
    for network in
        [Network::Evm, Network::Tron, Network::Bitcoin, Network::Solana, Network::Stellar]
    {
        assert!(derive(&phrase, "", network, 0x7fff_ffff).is_ok(), "{network:?}");
        for index in [0x8000_0000, u32::MAX] {
            assert_eq!(
                derive(&phrase, "", network, index).unwrap_err(),
                Error::IndexOutOfRange(index),
                "{network:?} {index}"
            );
            assert_eq!(
                signing_key(&phrase, "", network, index).unwrap_err(),
                Error::IndexOutOfRange(index),
                "{network:?} {index}"
            );
        }
    }
    let seed = phrase.to_seed("");
    assert_eq!(
        bitcoin::account(&seed, 0, bitcoin::Chain::Change, 0x8000_0000).unwrap_err(),
        Error::IndexOutOfRange(0x8000_0000)
    );
    assert_eq!(
        Error::IndexOutOfRange(5).to_string(),
        "account index 5 is out of range, it must be below 2147483648"
    );
}

#[test]
fn entry_points_agree_with_the_per_network_functions() {
    let phrase = phrase(TRUST);
    let seed = phrase.to_seed("TREZOR");
    let same = |a: &Account, b: &Account| assert_eq!(a, b);
    for index in [0, 1, 7] {
        same(
            &derive(&phrase, "TREZOR", Network::Evm, index).unwrap(),
            &evm::account(&seed, index).unwrap(),
        );
        same(
            &derive(&phrase, "TREZOR", Network::Tron, index).unwrap(),
            &tron::account(&seed, index).unwrap(),
        );
        same(
            &derive(&phrase, "TREZOR", Network::Bitcoin, index).unwrap(),
            &bitcoin::account(&seed, index, bitcoin::Chain::Receive, 0).unwrap(),
        );
        same(
            &derive(&phrase, "TREZOR", Network::Solana, index).unwrap(),
            &solana::account(&seed, index).unwrap(),
        );
        same(
            &derive(&phrase, "TREZOR", Network::Stellar, index).unwrap(),
            &stellar::account(&seed, index).unwrap(),
        );
        same(
            &derive(&phrase, "TREZOR", Network::Bittensor, index).unwrap(),
            &bittensor::account(&phrase, "TREZOR", index).unwrap(),
        );
        // `account_from_seed` is the same thing for the seed-based networks,
        // and refuses the one that is not seed-based.
        same(
            &nc_wallet_core::account_from_seed(&seed, Network::Evm, index).unwrap(),
            &evm::account(&seed, index).unwrap(),
        );
    }
    assert_eq!(
        nc_wallet_core::account_from_seed(&seed, Network::Bittensor, 0).unwrap_err(),
        Error::NeedsPhrase
    );
    assert_eq!(
        nc_wallet_core::signing_key_from_seed(&seed, Network::Bittensor, 0).unwrap_err(),
        Error::NeedsPhrase
    );
}

// ---- Public key to address, without a phrase -------------------------------

#[test]
fn addresses_from_public_keys_alone() {
    // Polkadot.js keyring/src/index.spec.ts, `describe('ethereum')`, "allows
    // adding from JSON": this compressed public key is ETH_ADDRESS_TWO.
    let key =
        hex::decode("03b9dc646dd71118e5f7fda681ad9eca36eb3ee96f344f582fbe7b5bcdebb13077").unwrap();
    assert_eq!(
        evm::address_from_public_key(&key).unwrap(),
        "0x4119b2e6c3Cb618F4f0B93ac77f9BeeC7FF02887"
    );

    // BIP-84: the public key of m/84'/0'/0'/0/0 and its address.
    let key =
        hex::decode("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c").unwrap();
    assert_eq!(
        bitcoin::address_from_public_key(&key).unwrap(),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
}

#[test]
fn address_functions_refuse_keys_of_the_wrong_kind() {
    // Not a point on secp256k1 (bad SEC1 prefix), too short, empty.
    for bad in [&[0u8; 33][..], &[5u8; 33], &[2u8; 5], &[]] {
        assert!(evm::address_from_public_key(bad).is_none());
        assert!(tron::address_from_public_key(bad).is_none());
        assert!(bitcoin::address_from_public_key(bad).is_none());
    }
    // A 65-byte uncompressed key is not what Bitcoin's P2WPKH hashes.
    let compressed =
        hex::decode("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c").unwrap();
    assert!(bitcoin::address_from_public_key(&compressed).is_some());
    assert!(bitcoin::address_from_public_key(&[&[4u8][..], &[1u8; 64]].concat()).is_none());
    // ed25519 and sr25519 public keys are exactly 32 bytes.
    for bad in [&[1u8; 31][..], &[1u8; 33], &[]] {
        assert!(solana::address_from_public_key(bad).is_none());
        assert!(stellar::address_from_public_key(bad).is_none());
        assert!(bittensor::address_from_public_key(bad).is_none());
    }
    assert!(solana::address_from_public_key(&[1u8; 32]).is_some());
    assert!(stellar::address_from_public_key(&[1u8; 32]).is_some());
    assert!(bittensor::address_from_public_key(&[1u8; 32]).is_some());
}

#[test]
fn a_bitcoin_account_is_a_bip84_account_with_two_chains_and_its_zpub_finds_them_all() {
    let seed = phrase(ABANDON).to_seed("");
    // Account 0 is the one every other wallet shows; account 1 is another, with its own zpub.
    let zero = bitcoin::account_zpub(&seed, 0).unwrap();
    let one = bitcoin::account_zpub(&seed, 1).unwrap();
    assert_ne!(zero, one);
    assert_eq!(
        derive(&phrase(ABANDON), "", Network::Bitcoin, 1).unwrap(),
        bitcoin::account(&seed, 1, bitcoin::Chain::Receive, 0).unwrap()
    );
    assert_ne!(
        derive(&phrase(ABANDON), "", Network::Bitcoin, 1).unwrap().address,
        derive(&phrase(ABANDON), "", Network::Bitcoin, 0).unwrap().address
    );
    // The zpub of an account gives, with no private key, the address the seed derives, on both chains.
    for account in [0, 1, 5] {
        let zpub = bitcoin::account_zpub(&seed, account).unwrap();
        for (chain, index) in [
            (bitcoin::Chain::Receive, 0),
            (bitcoin::Chain::Receive, 7),
            (bitcoin::Chain::Change, 0),
            (bitcoin::Chain::Change, 3),
            (bitcoin::Chain::Receive, 19),
        ] {
            let from_seed = bitcoin::account(&seed, account, chain, index).unwrap().address;
            let from_zpub = bitcoin::addresses_from_zpub(&zpub, chain, index, 1).unwrap().remove(0);
            assert_eq!(from_seed, from_zpub, "account {account} {chain:?} {index}");
        }
    }
    assert_eq!(
        bitcoin::account_zpub(&seed, 0x8000_0000).unwrap_err(),
        Error::IndexOutOfRange(0x8000_0000)
    );
}
