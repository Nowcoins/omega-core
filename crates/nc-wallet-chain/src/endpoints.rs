//! The public endpoints the wallet reads each network from: free, keyless,
//! listed here and nowhere else.
//!
//! Each endpoint was checked from a server, with the rates it published (or
//! less, where none is published) and what it refuses. A device keeps under
//! each rate on its own clock; there are many devices and each has its own
//! address, so a pace a whole server could keep is already a conservative one.
//!
//! * **No key of any kind.** An endpoint that wants one is not on the list.
//! * **No indexer or explorer API.** Only the networks' own nodes and their
//!   reference REST services: Esplora (Bitcoin), TronGrid (TRON) and Horizon
//!   (Stellar).
//! * **More than one operator** per network wherever one exists, so a figure
//!   that moves money can be read from two.
//!
//! `host_permissions` of the Chrome extension is generated from this list
//! (`origins()`), so the extension can reach exactly these origins and no
//! other.

use crate::networks::Network;
use crate::pool::{EndpointSpec, refuses};

// Log limits ("log_span", "log_reach") are what the endpoints answered from this machine on
// 2026-10-28; the history scan also learns them as it
// goes, so a limit that moves costs a halved window, not a failure.
const ETHEREUM: &[EndpointSpec] = &[
    // Logs only for the last 10,000 blocks (about 33 hours): "archive requests need a token".
    EndpointSpec::new("publicnode", "https://ethereum-rpc.publicnode.com", "publicnode", 10, 100)
        .log_span(10_000)
        .log_reach(10_000),
    EndpointSpec::new("publicnode-2", "https://ethereum.publicnode.com", "publicnode", 10, 50)
        .log_span(10_000)
        .log_reach(10_000),
    // Free plan: log queries of about a hundred blocks, no more.
    EndpointSpec::new("drpc", "https://eth.drpc.org", "drpc", 5, 10).log_span(100),
    EndpointSpec::new("meowrpc", "https://eth.meowrpc.com", "meowrpc", 1, 10)
        .refusing(refuses::LOGS),
    // Tenderly's public gateway is an archive that answers log queries of any width up to
    // 20,000 results (22 million blocks in one query, 6 s): what makes the whole history of
    // USDT and USDC a few requests. Its other answers agree with the others'.
    EndpointSpec::new("tenderly", "https://gateway.tenderly.co/public/mainnet", "tenderly", 2, 20),
    // MEV Blocker: an archive for logs up to 100,000 blocks a query. It is a private relay,
    // so it is never asked anything but logs.
    EndpointSpec::new("mevblocker", "https://rpc.mevblocker.io", "mevblocker", 2, 10)
        .log_span(100_000)
        .logs_only(),
];

const BSC: &[EndpointSpec] = &[
    // Logs 50,000 blocks a query, and back about 325,000 blocks (41 hours).
    EndpointSpec::new("publicnode", "https://bsc-rpc.publicnode.com", "publicnode", 10, 100)
        .log_span(50_000)
        .log_reach(300_000),
    // Answers eth_getLogs for 25 blocks at most.
    EndpointSpec::new("blockrazor", "https://bsc.blockrazor.xyz", "blockrazor", 5, 50).log_span(25),
    // BNB Chain's own dataseeds: one organisation under three domains. They
    // answer eth_getLogs "limit exceeded" even for one block.
    EndpointSpec::new("bnbchain", "https://bsc-dataseed.bnbchain.org", "bnbchain.org", 5, 10)
        .refusing(refuses::LOGS),
    EndpointSpec::new("defibit", "https://bsc-dataseed1.defibit.io", "bnbchain.org", 5, 10)
        .refusing(refuses::LOGS),
    EndpointSpec::new("ninicoin", "https://bsc-dataseed1.ninicoin.io", "bnbchain.org", 5, 10)
        .refusing(refuses::LOGS),
    // 48 Club and bloXroute: logs 5,000 blocks a query, back at least 190,000 blocks. Their
    // fee quotes differ from the others' (docs/followups.md), so logs and nothing else.
    EndpointSpec::new("48club", "https://rpc-bsc.48.club", "48club", 3, 10)
        .log_span(5_000)
        .log_reach(190_000)
        .logs_only(),
    EndpointSpec::new("bloxroute", "https://bsc.rpc.blxrbdn.com", "bloxroute", 3, 10)
        .log_span(5_000)
        .log_reach(190_000)
        .logs_only(),
];

const POLYGON: &[EndpointSpec] = &[
    // Logs 10,000 blocks a query, back about 2.2 million blocks (four weeks).
    EndpointSpec::new(
        "publicnode",
        "https://polygon-bor-rpc.publicnode.com",
        "publicnode",
        10,
        100,
    )
    .log_span(10_000)
    .log_reach(2_200_000),
    EndpointSpec::new("drpc", "https://polygon.drpc.org", "drpc", 10, 50).log_span(100),
    // Tenderly publishes no limit, only that it is limited: three a second.
    EndpointSpec::new("tenderly", "https://polygon.gateway.tenderly.co", "tenderly", 3, 30),
];

const BASE: &[EndpointSpec] = &[
    // Refuses every receipt without a token. Logs: it allows 50,000 blocks a query, but Base's
    // USDC makes that take six to ten seconds, past the request timeout; 20,000 take about two.
    // Back about 2.1 million blocks (seven weeks).
    EndpointSpec::new("publicnode", "https://base-rpc.publicnode.com", "publicnode", 10, 100)
        .refusing(refuses::RECEIPTS)
        .log_span(20_000)
        .log_reach(2_100_000),
    // Answers "request limit reached" to every `eth_getLogs`, whatever the span.
    EndpointSpec::new("coinbase", "https://mainnet.base.org", "coinbase", 10, 50)
        .refusing(refuses::LOGS),
    EndpointSpec::new("drpc", "https://base.drpc.org", "drpc", 5, 10).log_span(100),
    // "The method eth_getLogs is not supported."
    EndpointSpec::new("meowrpc", "https://base.meowrpc.com", "meowrpc", 1, 10)
        .refusing(refuses::LOGS),
    // An archive, but its public access answers log queries of a thousand blocks at most.
    EndpointSpec::new("tenderly", "https://base.gateway.tenderly.co", "tenderly", 2, 10)
        .log_span(1_000),
];

const TRON: &[EndpointSpec] = &[
    EndpointSpec::new("publicnode", "https://tron-rpc.publicnode.com", "publicnode", 10, 100)
        .refusing(refuses::V1),
    // TronGrid keyless: about three requests a second to an address, past
    // which it answers 429 and suspends the address for five seconds.
    EndpointSpec::new("trongrid", "https://api.trongrid.io", "trongrid", 2, 30),
    // Answers every constant call with a 200 that says "this node does not support constant" (checked on
    // 2026-11-01), so it is not asked to size a token transfer.
    EndpointSpec::new("pocket", "https://tron.api.pocket.network", "pocket", 2, 10)
        .refusing(refuses::V1 | refuses::CONSTANT),
];

const BITCOIN: &[EndpointSpec] = &[
    // Esplora. Neither publishes a number; both ask for fair use.
    EndpointSpec::new("mempool", "https://mempool.space/api", "mempool.space", 2, 100),
    EndpointSpec::new("blockstream", "https://blockstream.info/api", "blockstream", 2, 50),
];

// Checked on 2026-10-28 with a browser's `Origin` header (`scripts/endpoint_check.py`):
// * PublicNode answers every call a wallet makes except the *indexed* ones
//   (`getTokenAccountsByOwner` with a mint: "Indexed requests require a personal token"), so
//   token balances are read from the owner's associated accounts when that is refused.
// * Pocket Network's gateway answers all of them, keyless, and publishes a limit of 1,200
//   requests a minute per address (`x-ratelimit-limit`).
// * The Solana Foundation's node answers 403 "Access forbidden" to any request that carries an
//   `Origin` header, which a browser extension always does, so it is on the Android app's
//   list only (the app sends none) and not on the extension's, whose `host_permissions` are
//   made from the browser list. It is not gone round: the extension simply does not ask it.
const SOLANA_PUBLICNODE: EndpointSpec =
    EndpointSpec::new("publicnode", "https://solana-rpc.publicnode.com", "publicnode", 10, 100);
const SOLANA_POCKET: EndpointSpec =
    EndpointSpec::new("pocket", "https://solana.api.pocket.network", "pocket", 5, 50);
// About 100 requests per 10 seconds per address, and fewer for history calls.
const SOLANA_FOUNDATION: EndpointSpec =
    EndpointSpec::new("foundation", "https://api.mainnet-beta.solana.com", "solana.com", 5, 50);
const SOLANA: &[EndpointSpec] = &[SOLANA_PUBLICNODE, SOLANA_POCKET, SOLANA_FOUNDATION];
const SOLANA_IN_A_BROWSER: &[EndpointSpec] = &[SOLANA_PUBLICNODE, SOLANA_POCKET];

const STELLAR: &[EndpointSpec] = &[
    EndpointSpec::new("sdf", "https://horizon.stellar.org", "sdf", 2, 100),
    EndpointSpec::new("lobstr", "https://horizon.stellar.lobstr.co", "lobstr", 2, 100),
    EndpointSpec::new("ankr", "https://rpc.ankr.com/http/stellar_horizon", "ankr", 2, 10),
];

const BITTENSOR: &[EndpointSpec] = &[
    EndpointSpec::new(
        "opentensor",
        "https://entrypoint-finney.opentensor.ai:443",
        "opentensor",
        10,
        100,
    ),
    EndpointSpec::new(
        "opentensor-lite",
        "https://lite.chain.opentensor.ai:443",
        "opentensor",
        10,
        100,
    ),
    EndpointSpec::new(
        "opentensor-archive",
        "https://archive.chain.opentensor.ai:443",
        "opentensor",
        5,
        10,
    ),
    // Published limit: 5 requests a second per address.
    EndpointSpec::new(
        "onfinality",
        "https://bittensor-finney.api.onfinality.io/public",
        "onfinality",
        2,
        10,
    ),
];

/// A network's endpoints, for the device this is built for: in a browser (the extension) the ones
/// that answer a request carrying an `Origin` header, on Android all of them.
#[must_use]
pub fn specs(network: Network) -> &'static [EndpointSpec] {
    endpoints_for(network, cfg!(target_arch = "wasm32"))
}

/// A network's endpoints as a browser can use them.
fn endpoints_for(network: Network, in_a_browser: bool) -> &'static [EndpointSpec] {
    match network {
        Network::Ethereum => ETHEREUM,
        Network::Bsc => BSC,
        Network::Polygon => POLYGON,
        Network::Base => BASE,
        Network::Tron => TRON,
        Network::Bitcoin => BITCOIN,
        Network::Solana if in_a_browser => SOLANA_IN_A_BROWSER,
        Network::Solana => SOLANA,
        Network::Stellar => STELLAR,
        Network::Bittensor => BITTENSOR,
    }
}

/// The origins of every endpoint, once each, as `https://host/*` match
/// patterns: the extension's `host_permissions`. The port of a URL is left out
/// (a match pattern has none).
#[must_use]
pub fn origins() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for network in crate::networks::ALL {
        for spec in endpoints_for(network, true) {
            let host = spec
                .url
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .map(|authority| authority.split(':').next().unwrap_or(authority));
            if let Some(host) = host {
                let pattern = format!("https://{host}/*");
                if !out.contains(&pattern) {
                    out.push(pattern);
                }
            }
        }
    }
    out
}

/// The extension's `src/data/chain-origins.json`: the origins (`host_permissions`) and, for the tests,
/// each network's hosts.
#[must_use]
pub fn origins_json() -> String {
    let mut hosts = serde_json::Map::new();
    for network in crate::networks::ALL {
        let mut list: Vec<String> = Vec::new();
        for spec in endpoints_for(network, true) {
            let host = spec
                .url
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .map(|authority| authority.split(':').next().unwrap_or(authority).to_owned());
            if let Some(host) = host
                && !list.contains(&host)
            {
                list.push(host);
            }
        }
        hosts.insert(network.id().to_owned(), serde_json::json!(list));
    }
    let mut text =
        serde_json::to_string_pretty(&serde_json::json!({ "origins": origins(), "hosts": hosts }))
            .unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::ALL;

    #[test]
    fn every_endpoint_is_https_without_a_key_or_a_trailing_slash() {
        for network in ALL {
            for spec in specs(network) {
                assert!(spec.url.starts_with("https://"), "{}", spec.name);
                assert!(!spec.url.ends_with('/'), "{}", spec.name);
                let lower = spec.url.to_ascii_lowercase();
                for word in ["key", "token", "apikey", "secret", "?"] {
                    assert!(!lower.contains(word), "{} has `{word}` in its address", spec.name);
                }
                assert!(spec.per_second >= 1 && spec.weight >= 1, "{}", spec.name);
            }
        }
    }

    #[test]
    fn every_network_has_two_operators_so_a_figure_can_have_a_second_opinion() {
        for network in ALL {
            for in_a_browser in [false, true] {
                let mut operators: Vec<&str> =
                    endpoints_for(network, in_a_browser).iter().map(|s| s.operator).collect();
                operators.sort_unstable();
                operators.dedup();
                // Bittensor's Foundation runs three of its four; OnFinality is the other.
                assert!(operators.len() >= 2, "{network:?} (in a browser: {in_a_browser})");
            }
        }
    }

    #[test]
    fn the_solana_foundation_node_is_the_apps_and_not_the_extensions() {
        // It answers 403 to any request that carries an `Origin` header, as the extension's do.
        let foundation = |browser: bool| {
            endpoints_for(Network::Solana, browser)
                .iter()
                .any(|s| s.url.contains("api.mainnet-beta"))
        };
        assert!(foundation(false));
        assert!(!foundation(true));
        assert!(!origins().iter().any(|o| o.contains("api.mainnet-beta")));
    }

    #[test]
    fn no_indexer_or_price_api_is_on_the_list() {
        for network in ALL {
            for spec in specs(network) {
                for banned in [
                    "etherscan",
                    "bscscan",
                    "polygonscan",
                    "basescan",
                    "blockscout",
                    "taostats",
                    "covalent",
                    "moralis",
                    "alchemy",
                    "infura",
                    "coingecko",
                    "coinmarketcap",
                    "tronscan",
                    "solscan",
                    "ankr.com/multichain",
                ] {
                    assert!(!spec.url.contains(banned), "{} is {banned}", spec.name);
                }
            }
        }
    }

    #[test]
    fn no_endpoint_host_is_a_nowcoin_host() {
        // Nowcoin Omega never talks to a Nowcoin server: not on Android, not in a browser, not as a
        // backup, and not under another name for the same thing. The check reads the host, so a
        // path or a query that merely mentions the name (there are none) would not hide one.
        let nowcoin = |host: &str| {
            let host = host.to_ascii_lowercase();
            host.contains("nowcoin") || host.contains("nc-wallet") || host.contains("nowcoin-omega")
        };
        for in_a_browser in [false, true] {
            for network in ALL {
                for spec in endpoints_for(network, in_a_browser) {
                    let authority = spec
                        .url
                        .strip_prefix("https://")
                        .and_then(|rest| rest.split('/').next())
                        .unwrap_or(spec.url);
                    let host = authority.split(':').next().unwrap_or(authority);
                    assert!(!nowcoin(host), "{} ({}) is a Nowcoin host", spec.name, spec.url);
                    assert!(!nowcoin(spec.operator), "{} has a Nowcoin operator", spec.name);
                }
            }
        }
        // The extension's host permissions are the same list: no Nowcoin origin among them.
        assert!(origins().iter().all(|o| !nowcoin(o)));
        assert!(!origins_json().to_ascii_lowercase().contains("nowcoin"));
    }

    #[test]
    fn the_extensions_origins_are_the_endpoints_and_each_appears_once() {
        let origins = origins();
        let mut unique = origins.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(origins.len(), unique.len());
        assert!(origins.contains(&"https://mempool.space/*".to_owned()));
        assert!(origins.contains(&"https://entrypoint-finney.opentensor.ai/*".to_owned()));
        assert!(origins.iter().all(|o| o.starts_with("https://") && o.ends_with("/*")));
    }

    /// The registrable domain of an endpoint's host: its last two labels.
    fn domain(url: &str) -> String {
        let host =
            url.strip_prefix("https://").unwrap_or(url).split(['/', ':']).next().unwrap_or("");
        let labels: Vec<&str> = host.split('.').collect();
        labels[labels.len().saturating_sub(2)..].join(".")
    }

    /// Hosts whose organisation is not the name of their domain: the operator they are, and why.
    const OPERATOR_EXCEPTIONS: &[(&str, &str, &str)] = &[
        ("bnbchain.org", "bnbchain.org", "BNB Chain's own dataseeds"),
        ("defibit.io", "bnbchain.org", "one of BNB Chain's dataseeds, under another domain"),
        ("ninicoin.io", "bnbchain.org", "one of BNB Chain's dataseeds, under another domain"),
        ("base.org", "coinbase", "Base's node is run by Coinbase"),
        ("48.club", "48club", "48 Club"),
        ("blxrbdn.com", "bloxroute", "bloXroute's gateway"),
        ("stellar.org", "sdf", "the Stellar Development Foundation"),
        ("solana.com", "solana.com", "the Solana Foundation"),
        ("mempool.space", "mempool.space", "mempool.space"),
        ("blockstream.info", "blockstream", "Blockstream"),
    ];

    #[test]
    fn every_hosts_operator_is_the_organisation_behind_its_domain() {
        // An operator is an organisation, and two hosts of one organisation are one opinion. So a host's
        // operator is the name of its domain, unless this list says whose it is and why; and two hosts
        // under one domain are never two operators.
        let mut by_domain: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for in_a_browser in [false, true] {
            for network in ALL {
                for spec in endpoints_for(network, in_a_browser) {
                    let domain = domain(spec.url);
                    let label = domain.split('.').next().unwrap_or("");
                    let expected = OPERATOR_EXCEPTIONS
                        .iter()
                        .find(|(d, _, _)| *d == domain)
                        .map_or(label, |(_, operator, _)| *operator);
                    assert_eq!(
                        spec.operator, expected,
                        "{} ({}): the operator of {domain} is {expected}",
                        spec.name, spec.url
                    );
                    let known =
                        by_domain.entry(domain.clone()).or_insert_with(|| spec.operator.to_owned());
                    assert_eq!(known, spec.operator, "{domain} has two operators");
                }
            }
        }
        // The exceptions are all in use (a stale one is a mistake waiting).
        for (domain, _, _) in OPERATOR_EXCEPTIONS {
            assert!(by_domain.contains_key(*domain), "{domain} is not an endpoint's domain");
        }
    }
}
