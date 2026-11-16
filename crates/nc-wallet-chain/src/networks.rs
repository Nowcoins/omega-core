//! The nine networks the wallet lists, what each lists on it, and the links to
//! open a transaction or an address in a block explorer.
//!
//! This is the list the apps used to fetch from the wallet API; it is bundled
//! now, because there is no server to ask. The contracts are the issuers' own
//! (Tether, Circle, USDT0), each confirmed on chain.
//! The explorer links are **links a person opens**; no explorer's API is ever
//! called.

use serde_json::{Value, json};

/// The nine networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    /// Ethereum (chain id 1).
    Ethereum,
    /// BNB Smart Chain (56). Its id in the apps is `bsc`.
    Bsc,
    /// Polygon PoS (137).
    Polygon,
    /// Base (8453), an OP-stack rollup.
    Base,
    /// TRON.
    Tron,
    /// Bitcoin, native segwit.
    Bitcoin,
    /// Solana.
    Solana,
    /// Stellar.
    Stellar,
    /// Bittensor (Finney), SS58 prefix 42.
    Bittensor,
}

/// How a network is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// EVM JSON-RPC.
    Evm,
    /// TRON's HTTP API.
    Tron,
    /// Bitcoin through Esplora.
    Bitcoin,
    /// Solana JSON-RPC.
    Solana,
    /// Stellar's Horizon.
    Stellar,
    /// Substrate JSON-RPC.
    Substrate,
}

/// Every network, in the order the apps list them.
pub const ALL: [Network; 9] = [
    Network::Ethereum,
    Network::Bsc,
    Network::Polygon,
    Network::Base,
    Network::Tron,
    Network::Bitcoin,
    Network::Solana,
    Network::Stellar,
    Network::Bittensor,
];

/// A coin or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// The ticker: a ticker means one asset on one network.
    pub symbol: &'static str,
    /// "Tether USD".
    pub name: &'static str,
    /// The contract's own decimals.
    pub decimals: u8,
    /// The contract address, the Solana mint, or the Stellar issuer.
    pub contract: &'static str,
    /// What the network calls this token where it is not simply the asset.
    pub label: Option<&'static str>,
}

/// A network's native coin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Native {
    /// The ticker.
    pub symbol: &'static str,
    /// Its name.
    pub name: &'static str,
    /// Its decimals.
    pub decimals: u8,
}

const fn token(
    symbol: &'static str,
    name: &'static str,
    decimals: u8,
    contract: &'static str,
    label: Option<&'static str>,
) -> Token {
    Token { symbol, name, decimals, contract, label }
}

const ETHEREUM_TOKENS: &[Token] = &[
    token("USDT", "Tether USD", 6, "0xdAC17F958D2ee523a2206206994597C13D831ec7", None),
    token("USDC", "USD Coin", 6, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", None),
];
const BSC_TOKENS: &[Token] = &[
    token(
        "USDT",
        "Tether USD",
        18,
        "0x55d398326f99059fF775485246999027B3197955",
        Some("Binance-Peg"),
    ),
    token(
        "USDC",
        "USD Coin",
        18,
        "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
        Some("Binance-Peg"),
    ),
];
const POLYGON_TOKENS: &[Token] = &[
    token("USDT", "Tether USD", 6, "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", Some("USDT0")),
    token("USDC", "USD Coin", 6, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", None),
];
const BASE_TOKENS: &[Token] =
    &[token("USDC", "USD Coin", 6, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", None)];
const TRON_TOKENS: &[Token] =
    &[token("USDT", "Tether USD", 6, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", None)];
const SOLANA_TOKENS: &[Token] = &[
    token("USDT", "Tether USD", 6, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", None),
    token("USDC", "USD Coin", 6, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", None),
];
const STELLAR_TOKENS: &[Token] = &[token(
    "USDC",
    "USD Coin",
    7,
    "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
    None,
)];

impl Network {
    /// The id the apps use in their paths and records.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Bsc => "bsc",
            Self::Polygon => "polygon",
            Self::Base => "base",
            Self::Tron => "tron",
            Self::Bitcoin => "bitcoin",
            Self::Solana => "solana",
            Self::Stellar => "stellar",
            Self::Bittensor => "bittensor",
        }
    }

    /// The network with this id.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        ALL.into_iter().find(|network| network.id() == id)
    }

    /// "BNB Chain".
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::Bsc => "BNB Chain",
            Self::Polygon => "Polygon",
            Self::Base => "Base",
            Self::Tron => "TRON",
            Self::Bitcoin => "Bitcoin",
            Self::Solana => "Solana",
            Self::Stellar => "Stellar",
            Self::Bittensor => "Bittensor",
        }
    }

    /// How the network is spoken to.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Self::Ethereum | Self::Bsc | Self::Polygon | Self::Base => Family::Evm,
            Self::Tron => Family::Tron,
            Self::Bitcoin => Family::Bitcoin,
            Self::Solana => Family::Solana,
            Self::Stellar => Family::Stellar,
            Self::Bittensor => Family::Substrate,
        }
    }

    /// The EVM chain id.
    #[must_use]
    pub const fn chain_id(self) -> Option<u64> {
        match self {
            Self::Ethereum => Some(1),
            Self::Bsc => Some(56),
            Self::Polygon => Some(137),
            Self::Base => Some(8453),
            _ => None,
        }
    }

    /// The CAIP-2 chain id.
    #[must_use]
    pub const fn caip2(self) -> &'static str {
        match self {
            Self::Ethereum => "eip155:1",
            Self::Bsc => "eip155:56",
            Self::Polygon => "eip155:137",
            Self::Base => "eip155:8453",
            Self::Tron => "tron:0x2b6653dc",
            Self::Bitcoin => "bip122:000000000019d6689c085ae165831e93",
            Self::Solana => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            Self::Stellar => "stellar:pubnet",
            Self::Bittensor => "polkadot:2f0555cc76fc2840a25a6ea3b9637146",
        }
    }

    /// The native coin.
    #[must_use]
    pub const fn native(self) -> Native {
        match self {
            Self::Ethereum | Self::Base => Native { symbol: "ETH", name: "Ethereum", decimals: 18 },
            Self::Bsc => Native { symbol: "BNB", name: "BNB", decimals: 18 },
            Self::Polygon => Native { symbol: "POL", name: "Polygon", decimals: 18 },
            Self::Tron => Native { symbol: "TRX", name: "TRON", decimals: 6 },
            Self::Bitcoin => Native { symbol: "BTC", name: "Bitcoin", decimals: 8 },
            Self::Solana => Native { symbol: "SOL", name: "Solana", decimals: 9 },
            Self::Stellar => Native { symbol: "XLM", name: "Stellar Lumens", decimals: 7 },
            Self::Bittensor => Native { symbol: "TAO", name: "Bittensor", decimals: 9 },
        }
    }

    /// The listed tokens, USDT then USDC.
    #[must_use]
    pub const fn tokens(self) -> &'static [Token] {
        match self {
            Self::Ethereum => ETHEREUM_TOKENS,
            Self::Bsc => BSC_TOKENS,
            Self::Polygon => POLYGON_TOKENS,
            Self::Base => BASE_TOKENS,
            Self::Tron => TRON_TOKENS,
            Self::Solana => SOLANA_TOKENS,
            Self::Stellar => STELLAR_TOKENS,
            Self::Bitcoin | Self::Bittensor => &[],
        }
    }

    /// The token listed under this ticker (any case).
    #[must_use]
    pub fn token(self, ticker: &str) -> Option<&'static Token> {
        self.tokens().iter().find(|token| token.symbol.eq_ignore_ascii_case(ticker))
    }

    /// The token with this contract: EVM compares without regard to case, the
    /// others exactly.
    #[must_use]
    pub fn token_by_contract(self, contract: &str) -> Option<&'static Token> {
        let evm = self.family() == Family::Evm;
        self.tokens().iter().find(|token| {
            if evm {
                token.contract.eq_ignore_ascii_case(contract)
            } else {
                token.contract == contract
            }
        })
    }

    /// Whether the ticker names the native coin.
    #[must_use]
    pub fn is_native(self, ticker: &str) -> bool {
        self.native().symbol.eq_ignore_ascii_case(ticker)
    }

    /// How deep a transfer must be before it is final: a conservative depth
    /// for each network.
    #[must_use]
    pub const fn confirmations(self) -> u32 {
        match self {
            Self::Ethereum => 24,
            Self::Bsc => 30,
            Self::Polygon => 64,
            Self::Base => 20,
            Self::Tron => 19,
            Self::Bitcoin => 2,
            Self::Solana => 32,
            Self::Stellar | Self::Bittensor => 1,
        }
    }

    /// A link to a transaction in the network's block explorer (`{hash}`).
    #[must_use]
    pub const fn explorer_transaction(self) -> &'static str {
        match self {
            Self::Ethereum => "https://etherscan.io/tx/{hash}",
            Self::Bsc => "https://bscscan.com/tx/{hash}",
            Self::Polygon => "https://polygonscan.com/tx/{hash}",
            Self::Base => "https://basescan.org/tx/{hash}",
            Self::Tron => "https://tronscan.org/#/transaction/{hash}",
            Self::Bitcoin => "https://mempool.space/tx/{hash}",
            Self::Solana => "https://solscan.io/tx/{hash}",
            Self::Stellar => "https://stellar.expert/explorer/public/tx/{hash}",
            Self::Bittensor => "https://taostats.io/extrinsic/{hash}",
        }
    }

    /// A link to an address in the network's block explorer (`{address}`).
    #[must_use]
    pub const fn explorer_address(self) -> &'static str {
        match self {
            Self::Ethereum => "https://etherscan.io/address/{address}",
            Self::Bsc => "https://bscscan.com/address/{address}",
            Self::Polygon => "https://polygonscan.com/address/{address}",
            Self::Base => "https://basescan.org/address/{address}",
            Self::Tron => "https://tronscan.org/#/address/{address}",
            Self::Bitcoin => "https://mempool.space/address/{address}",
            Self::Solana => "https://solscan.io/account/{address}",
            Self::Stellar => "https://stellar.expert/explorer/public/account/{address}",
            Self::Bittensor => "https://taostats.io/account/{address}",
        }
    }

    /// Whether a site may read the network through the wallet's provider.
    #[must_use]
    pub const fn rpc_available(self) -> bool {
        matches!(self.family(), Family::Evm | Family::Solana)
    }

    /// The network as the apps' list has it.
    #[must_use]
    pub fn to_value(self) -> Value {
        let native = self.native();
        let family = match self.family() {
            Family::Evm => "evm",
            Family::Tron => "tron",
            Family::Bitcoin => "bitcoin",
            Family::Solana => "solana",
            Family::Stellar => "stellar",
            Family::Substrate => "substrate",
        };
        let kind = match self.family() {
            Family::Evm => "erc20",
            Family::Tron => "trc20",
            Family::Solana => "spl",
            Family::Stellar => "stellar_asset",
            Family::Bitcoin | Family::Substrate => "none",
        };
        let tokens: Vec<Value> = self
            .tokens()
            .iter()
            .map(|token| {
                let mut entry = json!({
                    "symbol": token.symbol,
                    "name": token.name,
                    "decimals": token.decimals,
                    "kind": kind,
                    "contract": token.contract,
                });
                match self.family() {
                    Family::Solana => entry["mint"] = json!(token.contract),
                    Family::Stellar => {
                        entry["issuer"] = json!(token.contract);
                        entry["code"] = json!(token.symbol);
                    }
                    _ => {}
                }
                if let Some(label) = token.label {
                    entry["label"] = json!(label);
                }
                entry
            })
            .collect();
        let mut network = json!({
            "id": self.id(),
            "name": self.name(),
            "family": family,
            "caip2": self.caip2(),
            "native": { "symbol": native.symbol, "name": native.name, "decimals": native.decimals },
            "tokens": tokens,
            "explorer": {
                "transaction": self.explorer_transaction(),
                "address": self.explorer_address(),
            },
            "confirmations": self.confirmations(),
            // Every network has a history now: all of it where the public
            // endpoints keep it, and from the day the app first saw the
            // wallet where they do not (see `history`).
            "history_available": true,
            "rpc_available": self.rpc_available(),
        });
        if let Some(chain_id) = self.chain_id() {
            network["chain_id"] = json!(chain_id);
        }
        if self == Self::Bittensor {
            network["ss58"] = json!(42);
        }
        network
    }
}

/// The apps' network list.
#[must_use]
pub fn networks_value() -> Value {
    json!({ "networks": ALL.iter().map(|network| network.to_value()).collect::<Vec<_>>() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_has_an_id_that_finds_it_again() {
        for network in ALL {
            assert_eq!(Network::from_id(network.id()), Some(network));
        }
        assert_eq!(Network::from_id("BSC"), None, "ids are lower case, no aliases");
        assert_eq!(Network::from_id("bnb"), None);
    }

    #[test]
    fn the_same_ticker_is_another_token_with_other_decimals_on_bnb_chain() {
        assert_eq!(Network::Ethereum.token("usdt").map(|t| t.decimals), Some(6));
        let peg = Network::Bsc.token("USDT").unwrap();
        assert_eq!(peg.decimals, 18);
        assert_eq!(peg.label, Some("Binance-Peg"));
    }

    #[test]
    fn a_contract_is_found_by_its_address_without_regard_to_case_on_evm_only() {
        let lower = "0xc2132d05d31c914a87c6611c10748aeb04b58e8f";
        assert_eq!(Network::Polygon.token_by_contract(lower).map(|t| t.symbol), Some("USDT"));
        let mint = Network::Solana.token("USDC").unwrap().contract;
        assert!(Network::Solana.token_by_contract(mint).is_some());
        assert!(Network::Solana.token_by_contract(&mint.to_ascii_lowercase()).is_none());
    }

    #[test]
    fn the_list_has_what_the_apps_read() {
        let list = networks_value();
        let networks = list["networks"].as_array().unwrap();
        assert_eq!(networks.len(), 9);
        let stellar = &networks[7];
        assert_eq!(stellar["id"], "stellar");
        assert_eq!(stellar["tokens"][0]["issuer"], stellar["tokens"][0]["contract"]);
        assert_eq!(stellar["tokens"][0]["code"], "USDC");
        assert_eq!(networks[0]["chain_id"], 1);
        assert_eq!(networks[8]["ss58"], 42);
        assert_eq!(networks[8]["rpc_available"], false);
        assert_eq!(networks[3]["rpc_available"], true);
    }
}
