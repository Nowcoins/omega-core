//! `validate_address`, against the core's address vectors.

use serde_json::Value;

use super::super::{MAX_ADDRESS_LEN, validate_address};
use crate::types::NetworkId;

const KEY_IO_VALID: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/key_io_valid.json");
const KEY_IO_INVALID: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/key_io_invalid.json");
const ERC55: &str = include_str!("../../../../nc-wallet-core/tests/vectors/erc-55-test-cases.md");
const TREZOR_ETH: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/trezor-ethereum-getaddress.json");
const TREZOR_TRON: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/trezor-tron-get_address.json");
const TREZOR_SOLANA: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/trezor-solana-get_address.json");
const TREZOR_STELLAR: &str =
    include_str!("../../../../nc-wallet-core/tests/vectors/trezor-stellar-get_address.json");

const EVM_NETWORKS: [&str; 4] = ["ethereum", "bsc", "polygon", "base"];

fn ok(network: &str, text: &str) -> bool {
    validate_address(network, text).valid
}

fn reason(network: &str, text: &str) -> &'static str {
    let check = validate_address(network, text);
    assert!(!check.valid && check.normalized.is_none(), "{network} {text}");
    check.reason.unwrap()
}

/// The addresses a Trezor fixture lists, under `result.<field>`.
fn trezor(json: &str, field: &str) -> Vec<String> {
    let file: Value = serde_json::from_str(json).unwrap();
    file["tests"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["result"][field].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn evm_addresses_need_their_checksum_when_they_mix_case() {
    for line in ERC55.lines().filter(|l| l.starts_with("0x")) {
        for network in EVM_NETWORKS {
            let check = validate_address(network, line);
            assert!(check.valid, "{line}");
            // Normalised to the checksum form, whatever case came in.
            let lower = validate_address(network, &line.to_lowercase());
            assert_eq!(lower.normalized, check.normalized);
            assert_eq!(check.reason, None);
        }
    }
    let normalized = validate_address("ethereum", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    assert_eq!(
        normalized.normalized.as_deref(),
        Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
    );
    for address in trezor(TREZOR_ETH, "address") {
        assert!(ok("ethereum", &address), "{address}");
    }
    // One letter's case wrong.
    assert_eq!(reason("ethereum", "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), "checksum");
    assert_eq!(reason("base", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAEd"), "checksum");
    // Not an address.
    for bad in [
        "0x",
        "0x1234",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "0xzzaeb6053f3e94c9b9a09f33669435e7ef1beaed",
    ] {
        assert_eq!(reason("polygon", bad), "format", "{bad}");
    }
    assert_eq!(reason("bsc", &format!("0x{}", "0".repeat(40))), "zero_address");
    assert_eq!(reason("ethereum", ""), "empty");
    assert_eq!(reason("ethereum", "   "), "empty");
}

#[test]
fn bitcoin_accepts_mainnet_payment_addresses_and_nothing_else() {
    let valid: Value = serde_json::from_str(KEY_IO_VALID).unwrap();
    let (mut accepted, mut refused) = (0, 0);
    for entry in valid.as_array().unwrap() {
        let address = entry[0].as_str().unwrap();
        let script = entry[1].as_str().unwrap();
        let info = &entry[2];
        if info["isPrivkey"] == true {
            assert!(!ok("bitcoin", address));
            continue;
        }
        let supported = script.starts_with("76a914") // P2PKH
            || script.starts_with("a914") // P2SH
            || script.starts_with("0014") // P2WPKH
            || script.starts_with("0020") // P2WSH
            || script.starts_with("5120"); // P2TR
        let expected = info["chain"] == "main" && supported;
        assert_eq!(ok("bitcoin", address), expected, "{address} {info}");
        if expected {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(accepted >= 8 && refused >= 8, "{accepted} {refused}");
    let invalid: Value = serde_json::from_str(KEY_IO_INVALID).unwrap();
    for entry in invalid.as_array().unwrap() {
        assert!(!ok("bitcoin", entry[0].as_str().unwrap()), "{entry}");
    }
    // The reference account's address, and another network's.
    assert!(ok("bitcoin", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
    assert!(!ok("bitcoin", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"));
    assert!(!ok("ethereum", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
}

#[test]
fn tron_solana_stellar_and_bittensor_addresses() {
    let tron = trezor(TREZOR_TRON, "address");
    assert!(tron.len() >= 5);
    for address in &tron {
        assert!(ok("tron", address), "{address}");
        // The checksum catches a changed character.
        let mut changed = address.clone().into_bytes();
        let at = changed.len() - 3;
        changed[at] = if changed[at] == b'2' { b'3' } else { b'2' };
        assert!(!ok("tron", &String::from_utf8(changed).unwrap()));
        assert!(!ok("solana", address) || address.len() >= 43);
    }
    assert!(!ok("tron", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"));
    assert!(!ok("tron", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));

    let solana = trezor(TREZOR_SOLANA, "expected_address");
    assert!(solana.len() >= 3);
    for address in &solana {
        assert!(ok("solana", address), "{address}");
        assert!(!ok("stellar", address));
    }
    assert_eq!(reason("solana", "11111111111111111111111111111111"), "zero_address");
    assert_eq!(reason("solana", "not base58 0OIl"), "format");
    // 31 bytes of base58.
    assert_eq!(reason("solana", "2NEpo7TZRRrLZSi2U"), "format");

    let stellar = trezor(TREZOR_STELLAR, "address");
    assert!(stellar.len() >= 5);
    for address in &stellar {
        assert!(ok("stellar", address), "{address}");
    }
    // A secret seed is not a payment destination.
    assert_eq!(
        reason("stellar", "SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7"),
        "format"
    );
    // A muxed address (SEP-23's, ids 0 and 2^63) is: an account and the id its owner gave this address.
    for muxed in [
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
    ] {
        assert!(ok("stellar", muxed), "{muxed}");
        assert!(!ok("solana", muxed) && !ok("tron", muxed) && !ok("bittensor", muxed));
        // A changed letter breaks the checksum, as for a G address; so does a cut or an added one.
        let mut changed = muxed.to_owned().into_bytes();
        changed[20] = if changed[20] == b'A' { b'B' } else { b'A' };
        assert_eq!(reason("stellar", &String::from_utf8(changed).unwrap()), "format");
        assert_eq!(reason("stellar", &muxed[..muxed.len() - 1]), "format");
        assert_eq!(reason("stellar", &format!("{muxed}A")), "format");
        assert_eq!(reason("stellar", &muxed.to_lowercase()), "format");
    }
    // A muxed address of the zero key is the zero address.
    assert_eq!(reason("stellar", &muxed_of(&[0; 32], 7)), "zero_address");

    // Substrate's development address, SS58 prefix 42.
    assert!(ok("bittensor", "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"));
    // The same key under Polkadot's prefix 0 and Kusama's 2 is not Bittensor's address.
    assert_eq!(reason("bittensor", "16ADqpMa4yzfmWs3nuTSMhfZ2ckeGtvqhPWCNqECEGDcGgU2"), "format");
    assert_eq!(reason("bittensor", "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzW"), "format");
}

#[test]
fn an_unknown_network_has_no_addresses() {
    let check = validate_address("dogecoin", "D8vFz4p1L37jdg47HXKtNYYvgJPiWgAz2d");
    assert_eq!((check.valid, check.reason), (false, Some("unsupported_network")));
    assert_eq!(
        validate_address("Ethereum", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").reason,
        Some("unsupported_network")
    );
}

/// The `M…` address of `key` and `id`, as SEP-23 writes it.
fn muxed_of(key: &[u8; 32], id: u64) -> String {
    nc_wallet_core::stellar::muxed_address(key, id)
}

// ---- the longest text that is read ----

/// The length of the longest address each network takes. A `match` on every network: a network the wallet
/// learns must be entered here, and the bound looked at, before this compiles.
fn longest_address(network: NetworkId) -> usize {
    match network {
        NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => 42,
        NetworkId::Tron => 34,
        NetworkId::Bitcoin => 62,
        NetworkId::Solana => 44,
        NetworkId::Stellar => 69,
        NetworkId::Bittensor => 48,
    }
}

const NETWORKS: [NetworkId; 9] = [
    NetworkId::Ethereum,
    NetworkId::BnbChain,
    NetworkId::Polygon,
    NetworkId::Base,
    NetworkId::Tron,
    NetworkId::Bitcoin,
    NetworkId::Solana,
    NetworkId::Stellar,
    NetworkId::Bittensor,
];

/// Addresses that are valid on `network`, from the vectors and the forms the wallet is known to take.
fn valid_addresses(network: NetworkId) -> Vec<String> {
    let mut found: Vec<String> = match network {
        NetworkId::Ethereum | NetworkId::BnbChain | NetworkId::Polygon | NetworkId::Base => ERC55
            .lines()
            .filter(|l| l.starts_with("0x"))
            .map(str::to_owned)
            .chain(trezor(TREZOR_ETH, "address"))
            .collect(),
        NetworkId::Tron => trezor(TREZOR_TRON, "address"),
        NetworkId::Bitcoin => {
            let valid: Value = serde_json::from_str(KEY_IO_VALID).unwrap();
            valid
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry[0].as_str().unwrap().to_owned())
                .filter(|address| ok("bitcoin", address))
                .collect()
        }
        NetworkId::Solana => trezor(TREZOR_SOLANA, "expected_address")
            .into_iter()
            .chain(["HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk".to_owned()])
            .collect(),
        NetworkId::Stellar => trezor(TREZOR_STELLAR, "address")
            .into_iter()
            .chain([
                "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ".to_owned(),
                "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK".to_owned(),
            ])
            .collect(),
        NetworkId::Bittensor => {
            vec!["5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV".to_owned()]
        }
    };
    found.retain(|address| ok(network.api_id(), address));
    found
}

#[test]
fn the_bound_is_above_the_longest_valid_address_of_every_network() {
    // BIP-173 limits a bech32 string to 90 characters: the longest text any of the formats could take.
    const LONGEST_FORMAT: usize = 90;
    const { assert!(MAX_ADDRESS_LEN >= LONGEST_FORMAT) };
    for network in NETWORKS {
        let known = valid_addresses(network);
        let longest = longest_address(network);
        assert!(longest <= LONGEST_FORMAT, "{network:?} takes {longest} characters");
        assert!(!known.is_empty(), "{network:?} has valid addresses to check");
        // The table is what the vectors show: no valid address is longer than it says, and one is that long.
        assert!(known.iter().all(|a| a.len() <= longest), "{network:?}: {known:?}");
        assert!(known.iter().any(|a| a.len() == longest), "{network:?} has none of {longest}");
        // And every valid address is read whole: the same answer as with no bound.
        for address in &known {
            let check = validate_address(network.api_id(), address);
            assert!(check.valid && check.reason.is_none(), "{network:?} {address}");
        }
    }
}

#[test]
fn text_is_read_up_to_the_bound_and_refused_beyond_it() {
    for network in NETWORKS {
        let id = network.api_id();
        // Spaces say what was done: at the bound the text is read (and found to be nothing), one more and it is
        // refused as it stands.
        assert_eq!(reason(id, &" ".repeat(MAX_ADDRESS_LEN)), "empty", "{id}");
        assert_eq!(reason(id, &" ".repeat(MAX_ADDRESS_LEN + 1)), "format", "{id}");
        // An address with something after it is no address, however little: and with a lot, no longer read.
        let known = valid_addresses(network).remove(0);
        assert_eq!(reason(id, &format!("{known}1")), "format", "{id}");
        assert_eq!(
            reason(id, &format!("{known}{}", "1".repeat(MAX_ADDRESS_LEN))),
            "format",
            "{id}"
        );
        // Bytes are what is counted, so text of wider characters stops sooner.
        assert_eq!(reason(id, &"é".repeat(MAX_ADDRESS_LEN / 2 + 1)), "format", "{id}");
    }
}

#[test]
fn a_huge_paste_is_refused_at_once() {
    // Decoding base58 takes time that grows with the square of the length: 60,000 characters took 0.8 s on
    // each of Solana, TRON, Bitcoin and Bittensor. Past the bound nothing is decoded.
    let started = std::time::Instant::now();
    for network in NETWORKS {
        for text in [
            "1".repeat(60_000),
            "z".repeat(60_000),
            format!("0x{}", "a".repeat(60_000)),
            format!("bc1q{}", "q".repeat(60_000)),
            "G".repeat(100_000),
        ] {
            assert_eq!(reason(network.api_id(), &text), "format", "{network:?}");
        }
    }
    // Each of those cost seconds on the four base58 networks before the bound, and costs nothing now.
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
}
