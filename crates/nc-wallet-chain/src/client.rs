//! The chain client: one object per app, one JSON door.
//!
//! `call(op, request)` takes an operation and its request as JSON and answers
//! JSON in the shapes the apps read; a failure is `{ code, message, retryable,
//! details? }`. The apps' data layers (`WalletData` in Dart and TypeScript) are
//! thin translations of that, and `nc-wallet-session`'s `send` request takes the
//! `inputs` and `estimate` bodies unchanged.
//!
//! | Operation | Request | Answer |
//! |---|---|---|
//! | `networks` | `{}` | the nine networks, their tokens, explorer links |
//! | `balances` | `{ network, address, addresses?, fresh? }` | the coin and every listed token |
//! | `inputs` | `{ network, address, addresses? }` | what a send is built from |
//! | `estimate` | `{ network, from, to, asset, amount, addresses? }` | the fee, and facts on the recipient |
//! | `broadcast` | `{ network, raw, encoding }` | `{ network, hash }` |
//! | `status` | `{ network, hash }` | `{ status, block?, confirmations? }` |
//! | `prices` | `{ assets?, fresh? }` | dollars per coin, from Chainlink |
//! | `rpc` | `{ network, request }` | a site's read, as the node answered (the strict allowlist of `dapp`) |
//! | `health` | `{}` | what is known of each endpoint |
//!
//! `addresses` is Bitcoin's other addresses (receive and change).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::{Value, json};

use crate::address::{self, Address};
use crate::bitcoin::{self, Bitcoin};
use crate::bittensor::{self, Bittensor};
use crate::common::EstimateArgs;
use crate::dapp;
use crate::endpoints;
use crate::error::{ChainError, ChainResult};
use crate::evm::Evm;
use crate::freshness::Freshness;
use crate::net::Net;
use crate::networks::{ALL, Family, Network, networks_value};
use crate::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Platform};
use crate::prices;
use crate::sent::Sent;
use crate::solana::Solana;
use crate::stellar::Stellar;
use crate::tron::Tron;
use crate::txid;
use crate::util::{bytes_from_hex, parse_amount, rfc3339};
use nc_wallet_core::bitcoin::{Chain as BitcoinChain, addresses_from_zpub};

/// The most a signed transaction may be, as the networks take it.
const MAX_RAW: usize = 125_000;

/// The platform, counting what goes through it: how many requests and how many
/// bytes came back. For a diagnostics screen and for the tests that bound what
/// an open panel costs the endpoints.
#[derive(Debug)]
struct Counted {
    inner: Arc<dyn Platform>,
    requests: AtomicU64,
    received: AtomicU64,
}

impl Platform for Counted {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            self.requests.fetch_add(1, Ordering::Relaxed);
            let answer = self.inner.send(request).await;
            if let Ok(answer) = &answer {
                self.received.fetch_add(answer.body.len() as u64, Ordering::Relaxed);
            }
            answer
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        self.inner.sleep(millis)
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
}

/// How long prices are answered from the last reading.
const PRICES_FOR_MS: u64 = 120_000;

/// The device's access to the nine networks.
#[derive(Debug)]
pub struct ChainClient {
    platform: Arc<Counted>,
    nets: Vec<Net>,
    bittensor: bittensor::State,
    prices: prices::State,
    /// The last balances, so that asking again soon, and again, costs nothing.
    kept: Freshness,
    /// The last prices.
    kept_prices: Freshness,
    /// What this device has just sent (its nonces and hashes), in memory only.
    sent: Sent,
    /// What the last reading of each Bitcoin account (by its first receive address) found, in memory
    /// only: the apps keep the same thing sealed and hand it back at the start.
    hints: Mutex<HashMap<String, bitcoin::Hint>>,
}

fn text<'a>(request: &'a Value, key: &str) -> ChainResult<&'a str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ChainError::invalid(format!("{key} is missing")))
}

fn texts(request: &Value, key: &str) -> ChainResult<Vec<String>> {
    match request.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ChainError::invalid(format!("{key} are strings")))
            })
            .collect(),
        Some(_) => Err(ChainError::invalid(format!("{key} is a list"))),
    }
}

fn network_of(request: &Value) -> ChainResult<Network> {
    Network::from_id(text(request, "network")?).ok_or(ChainError::UnknownNetwork)
}

impl ChainClient {
    /// A client over the device's platform.
    #[must_use]
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        // Under WebAssembly the platform is the browser's, on one thread.
        #[allow(clippy::arc_with_non_send_sync)]
        let platform = Arc::new(Counted {
            inner: platform,
            requests: AtomicU64::new(0),
            received: AtomicU64::new(0),
        });
        let nets = ALL
            .iter()
            .map(|&network| {
                let shared: Arc<dyn Platform> = platform.clone();
                let net = Net::new(shared, endpoints::specs(network));
                // TRON's nodes speak Ethereum's JSON-RPC beside their own HTTP API.
                if network == Network::Tron { net.with_rpc_path("/jsonrpc") } else { net }
            })
            .collect();
        Self {
            platform,
            nets,
            bittensor: bittensor::State::default(),
            prices: prices::State::default(),
            kept: Freshness::default(),
            kept_prices: Freshness::new(PRICES_FOR_MS, PRICES_FOR_MS),
            sent: Sent::default(),
            hints: Mutex::new(HashMap::new()),
        }
    }

    /// How many requests the client has made to endpoints, and how many bytes
    /// of answers came back, since it was made.
    #[must_use]
    pub fn traffic(&self) -> (u64, u64) {
        (
            self.platform.requests.load(Ordering::Relaxed),
            self.platform.received.load(Ordering::Relaxed),
        )
    }

    /// What this device sent lately (nonces and hashes), for the app to keep for a few minutes across a
    /// restart, as JSON text. It names the wallet's addresses: keep it sealed, or in memory that goes
    /// with the session, and remove it with the wallet.
    #[must_use]
    pub fn export_sent(&self) -> String {
        self.sent.export(self.platform.now_ms()).to_string()
    }

    /// The nonce the send of `hash` used, if this device sent it lately and the app said which (with
    /// its broadcast).
    pub(crate) fn sent_nonce(&self, hash: &str) -> Option<u128> {
        self.sent.nonce_of(hash, self.platform.now_ms())
    }

    /// Takes back what [`Self::export_sent`] wrote. Anything else, or anything stale, is ignored.
    pub fn import_sent(&self, text: &str) {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            self.sent.import(&value, self.platform.now_ms());
        }
    }

    /// Forgets the balances and prices it is holding (the wallet was removed).
    pub fn forget_everything(&self) {
        self.kept.clear();
        self.kept_prices.clear();
        self.sent.clear();
        if let Ok(mut hints) = self.hints.lock() {
            hints.clear();
        }
    }

    /// A network's endpoints.
    ///
    /// # Panics
    /// Never: the table is built from [`ALL`].
    #[must_use]
    pub fn net(&self, network: Network) -> &Net {
        let index = ALL.iter().position(|n| *n == network).unwrap_or(0);
        &self.nets[index]
    }

    /// What is worth keeping between launches, as JSON text for the app to store:
    /// the price feeds already checked, the prices a day ago, and the Bittensor
    /// runtimes already read. Nothing in it is about a person or an address.
    #[must_use]
    pub fn export_state(&self) -> String {
        json!({ "v": 1, "prices": self.prices.export(), "bittensor": self.bittensor.export() })
            .to_string()
    }

    /// Takes back what [`Self::export_state`] wrote; anything else is ignored.
    pub fn import_state(&self, state: &str) {
        let Ok(parsed) = serde_json::from_str::<Value>(state) else { return };
        if parsed.get("v").and_then(Value::as_u64) != Some(1) {
            return;
        }
        if let Some(prices) = parsed.get("prices") {
            self.prices.import(prices);
        }
        if let Some(bittensor) = parsed.get("bittensor") {
            self.bittensor.import(bittensor);
        }
    }

    fn as_of(&self) -> String {
        rfc3339(self.platform.now_ms() / 1000)
    }

    /// Runs one operation: `request` is JSON text, the answer is JSON text, and
    /// an error is the error's JSON text.
    pub async fn call(&self, op: &str, request: &str) -> Result<String, String> {
        let parsed: Value = if request.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(request)
                .map_err(|_| ChainError::invalid("the request is not JSON").to_json())?
        };
        self.dispatch(op, &parsed).await.map(|value| value.to_string()).map_err(|e| e.to_json())
    }

    /// Runs one operation on a parsed request.
    pub async fn dispatch(&self, op: &str, request: &Value) -> ChainResult<Value> {
        match op {
            "networks" => Ok(networks_value()),
            "balances" => self.balances(request).await,
            "inputs" => self.inputs(request).await,
            "estimate" => self.estimate(request).await,
            "broadcast" => self.broadcast(request).await,
            "status" => self.status(request).await,
            "prices" => self.prices(request).await,
            "rpc" => self.rpc(request).await,
            // What a web page's transaction needs, asked of two operators: the work it would use, as the nodes
            // say it. The page's own figure is checked against it.
            "gas" => {
                let network = network_of(request)?;
                if network.family() != Family::Evm {
                    return Err(ChainError::invalid("gas is for the EVM networks"));
                }
                let mut call = serde_json::Map::new();
                for key in ["from", "to", "data"] {
                    if let Some(v) = request.get(key).and_then(Value::as_str) {
                        call.insert(key.to_owned(), json!(v));
                    }
                }
                if let Some(v) = request.get("value").and_then(Value::as_str) {
                    let n = parse_amount(v)?;
                    call.insert("value".to_owned(), json!(format!("0x{n:x}")));
                }
                let (gas, sources) =
                    Evm::new(self.net(network), network).gas_raw(&Value::Object(call)).await?;
                Ok(json!({ "gas": gas.to_string(), "sources": sources }))
            }
            // What a site's TRON transaction would cost the account, from the bytes the site built.
            "tron_estimate" => {
                let from = address::parse(Network::Tron, text(request, "address")?)?;
                let raw = bytes_from_hex(text(request, "raw_data_hex")?)
                    .ok_or_else(|| ChainError::invalid("raw_data_hex is not hex digits"))?;
                Tron::new(self.net(Network::Tron)).dapp_estimate(&from, &raw).await
            }
            "solana_tables" => {
                let tables = texts(request, "addresses")?;
                Solana::new(self.net(Network::Solana)).lookup_tables(&tables).await
            }
            op if op.starts_with("history") => crate::history::call(self, op, request).await,
            "health" => Ok(self.health()),
            _ => Err(ChainError::invalid("that operation is not one this wallet has")),
        }
    }

    /// What is known of every network's endpoints, and what the client has cost
    /// them so far.
    #[must_use]
    pub fn health(&self) -> Value {
        let mut networks = serde_json::Map::new();
        for network in ALL {
            networks.insert(network.id().to_owned(), json!(self.net(network).health()));
        }
        let (requests, received) = self.traffic();
        json!({ "requests": requests, "bytes_received": received, "networks": networks })
    }

    fn account(request: &Value) -> ChainResult<(Network, Address)> {
        let network = network_of(request)?;
        let primary = address::parse(network, text(request, "address")?)?;
        if request.get("addresses").is_some_and(|a| !a.is_null()) {
            return Err(ChainError::invalid(if network == Network::Bitcoin {
                "a Bitcoin account is named by its zpub: the addresses are found from it"
            } else {
                "addresses is for Bitcoin only"
            }));
        }
        Ok((network, primary))
    }

    /// A Bitcoin account as a request names it: its `zpub`, and (if the app has it) what an earlier
    /// reading left. The address given must be the account's first receive address, the one the
    /// app shows; the hint this client already holds for it wins over a stale one the app sends.
    fn bitcoin_account(&self, request: &Value) -> ChainResult<bitcoin::Account> {
        let zpub = text(request, "zpub")?;
        let shown = addresses_from_zpub(zpub, BitcoinChain::Receive, 0, 1)
            .and_then(|mut list| list.pop())
            .ok_or_else(|| ChainError::invalid("zpub is not a Bitcoin account key"))?;
        if let Some(given) = request.get("address").and_then(Value::as_str)
            && given != shown
        {
            return Err(ChainError::invalid(
                "address is not the first receive address of the zpub",
            ));
        }
        let sent = request.get("hint").and_then(bitcoin::Hint::from_json);
        let held = self.hints.lock().ok().and_then(|hints| hints.get(&shown).cloned());
        Ok(bitcoin::Account {
            zpub: zpub.to_owned(),
            shown,
            hint: held.or(sent),
            now_s: self.platform.now_ms() / 1000,
        })
    }

    /// Keeps the hint a Bitcoin reading left, for the next one.
    fn remember_hint(&self, shown: &str, body: &Value) {
        if let Some(hint) = body.pointer("/bitcoin/hint").and_then(bitcoin::Hint::from_json)
            && let Ok(mut hints) = self.hints.lock()
        {
            hints.insert(shown.to_owned(), hint);
        }
    }

    async fn balances(&self, request: &Value) -> ChainResult<Value> {
        let (network, address) = Self::account(request)?;
        let key = format!("balances|{}|{}", network.id(), address.text);
        let now = self.platform.now_ms();
        if !wants_fresh(request)
            && let Some(kept) = self.kept.get(&key, now)
        {
            return Ok(kept);
        }
        let body = self.read_balances(network, &address, request).await?;
        // A reading that is not finished (a Bitcoin account being found, piece by piece) is not kept:
        // asking again is how it goes on.
        if body.pointer("/bitcoin/scanning").and_then(Value::as_bool) != Some(true) {
            self.kept.put(&key, network.id(), now, &body);
        }
        Ok(body)
    }

    async fn read_balances(
        &self,
        network: Network,
        address: &Address,
        request: &Value,
    ) -> ChainResult<Value> {
        let address = address.clone();
        let net = self.net(network);
        let as_of = self.as_of();
        match network.family() {
            Family::Evm => Evm::new(net, network).balances(&address, &as_of).await,
            Family::Tron => Tron::new(net).balances(&address, &as_of).await,
            Family::Bitcoin => {
                let account = self.bitcoin_account(request)?;
                let body = Bitcoin::new(net).balances(&account, &as_of).await?;
                self.remember_hint(&account.shown, &body);
                Ok(body)
            }
            Family::Solana => Solana::new(net).balances(&address, &as_of).await,
            Family::Stellar => Stellar::new(net).balances(&address, &as_of).await,
            Family::Substrate => {
                Bittensor::new(net, &self.bittensor).balances(&address, &as_of).await
            }
        }
    }

    async fn inputs(&self, request: &Value) -> ChainResult<Value> {
        let (network, address) = Self::account(request)?;
        let net = self.net(network);
        match network.family() {
            Family::Evm => {
                // Never below one past what this device sent a moment ago (see `sent`).
                let floor =
                    self.sent.next_nonce(network.id(), &address.text, 0, self.platform.now_ms());
                Evm::new(net, network).inputs(&address, floor).await
            }
            Family::Tron => Tron::new(net).inputs(&address).await,
            Family::Bitcoin => {
                let account = self.bitcoin_account(request)?;
                let own = self.sent.recent_hashes(self.platform.now_ms());
                let body = Bitcoin::new(net).inputs(&account, &own).await?;
                self.remember_hint(&account.shown, &body);
                Ok(body)
            }
            Family::Solana => Solana::new(net).inputs(&address).await,
            Family::Stellar => Stellar::new(net).inputs(&address).await,
            Family::Substrate => {
                let floor =
                    self.sent.next_nonce(network.id(), &address.text, 0, self.platform.now_ms());
                Bittensor::new(net, &self.bittensor).inputs(&address, floor).await
            }
        }
    }

    async fn estimate(&self, request: &Value) -> ChainResult<Value> {
        let network = network_of(request)?;
        let args = EstimateArgs::parse(network, request)?;
        let net = self.net(network);
        match network.family() {
            Family::Evm => Evm::new(net, network).estimate(&args).await,
            Family::Tron => Tron::new(net).estimate(&args).await,
            Family::Bitcoin => {
                let account = self.bitcoin_account(request)?;
                let own = self.sent.recent_hashes(self.platform.now_ms());
                let body = Bitcoin::new(net).estimate(&account, &args, &own).await?;
                self.remember_hint(&account.shown, &body);
                Ok(body)
            }
            Family::Solana => Solana::new(net).estimate(&args).await,
            Family::Stellar => Stellar::new(net).estimate(&args).await,
            Family::Substrate => {
                let floor =
                    self.sent.next_nonce(network.id(), &args.from, 0, self.platform.now_ms());
                Bittensor::new(net, &self.bittensor).estimate(&args, floor).await
            }
        }
    }

    async fn broadcast(&self, request: &Value) -> ChainResult<Value> {
        let network = network_of(request)?;
        let raw =
            raw_bytes(text(request, "raw")?, request.get("encoding").and_then(Value::as_str))?;
        // The id is worked out from the bytes, which also says they are a signed
        // transaction of this network.
        let hash = txid::of(network, &raw)?;
        let net = self.net(network);
        // Whatever was kept of this network's balances is about to be out of date.
        self.kept.forget(network.id());
        let now = self.platform.now_ms();
        let sent_before = self.sent.knows(&hash, now);
        let hash = match network.family() {
            Family::Evm => Evm::new(net, network).broadcast(&raw, &hash, sent_before).await?,
            Family::Tron => Tron::new(net).broadcast(&raw, &hash).await?,
            Family::Bitcoin => Bitcoin::new(net).broadcast(&raw, &hash).await?,
            Family::Solana => Solana::new(net).broadcast(&raw, &hash).await?,
            Family::Stellar => Stellar::new(net).broadcast(&raw, &hash).await?,
            Family::Substrate => {
                Bittensor::new(net, &self.bittensor).broadcast(&raw, &hash, sent_before).await?
            }
        };
        // The app says who sent it and with which nonce, so that the next send is not put on
        // the same one while the endpoints are still catching up.
        let from = request.get("from").and_then(Value::as_str);
        let nonce = request.get("nonce").and_then(|n| match n {
            Value::Number(n) => n.as_u64().map(u128::from),
            Value::String(text) => text.parse().ok(),
            _ => None,
        });
        self.sent.record(network.id(), from, nonce, &hash, now);
        Ok(json!({ "network": network.id(), "hash": hash }))
    }

    async fn status(&self, request: &Value) -> ChainResult<Value> {
        let network = network_of(request)?;
        let hash = text(request, "hash")?;
        let net = self.net(network);
        match network.family() {
            Family::Evm => Evm::new(net, network).status(hash).await,
            Family::Tron => Tron::new(net).status(hash).await,
            Family::Bitcoin => Bitcoin::new(net).status(hash).await,
            Family::Solana => Solana::new(net).status(hash).await,
            Family::Stellar => Stellar::new(net).status(hash).await,
            Family::Substrate => Ok(Bittensor::new(net, &self.bittensor).status(hash)),
        }
    }

    async fn rpc(&self, request: &Value) -> ChainResult<Value> {
        let network = network_of(request)?;
        let call =
            request.get("request").ok_or_else(|| ChainError::invalid("request is missing"))?;
        dapp::answer(self.net(network), network, call).await
    }

    async fn prices(&self, request: &Value) -> ChainResult<Value> {
        let assets: Vec<String> = texts(request, "assets")?;
        if assets.len() > 40 {
            return Err(ChainError::invalid("at most 40 assets"));
        }
        let mut key_assets = assets.clone();
        key_assets.sort();
        let key = format!("prices|{}", key_assets.join(","));
        let now = self.platform.now_ms();
        if !wants_fresh(request)
            && let Some(kept) = self.kept_prices.get(&key, now)
        {
            return Ok(kept);
        }
        let body = prices::prices(
            self.net(Network::Bsc),
            self.net(Network::Ethereum),
            &self.prices,
            &assets,
        )
        .await?;
        self.kept_prices.put(&key, "prices", now, &body);
        Ok(body)
    }
}

/// Whether the request asks to be read afresh: the person came back to the
/// window, pulled to refresh, or has just sent something.
fn wants_fresh(request: &Value) -> bool {
    request.get("fresh").and_then(Value::as_bool).unwrap_or(false)
}

/// Decodes the bytes of a broadcast: hex (with or without `0x`) or base64.
fn raw_bytes(raw: &str, encoding: Option<&str>) -> ChainResult<Vec<u8>> {
    let bad = |what: &str| ChainError::invalid(format!("raw is not {what}"));
    let bytes = match encoding.unwrap_or("hex") {
        "hex" => bytes_from_hex(raw).ok_or_else(|| bad("hexadecimal"))?,
        "base64" => {
            base64::engine::general_purpose::STANDARD.decode(raw).map_err(|_| bad("base64"))?
        }
        _ => return Err(ChainError::invalid("encoding is hex or base64")),
    };
    if bytes.is_empty() || bytes.len() > MAX_RAW {
        return Err(ChainError::invalid("raw is empty or too large"));
    }
    Ok(bytes)
}

/// Digits only: re-exported for the request parsers of the apps' layers.
#[doc(hidden)]
pub fn amount(text: &str) -> ChainResult<u128> {
    parse_amount(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_bytes_are_hex_with_or_without_the_prefix_or_base64() {
        assert_eq!(raw_bytes("0x0a0b", Some("hex")).unwrap(), [0x0a, 0x0b]);
        assert_eq!(raw_bytes("0a0b", None).unwrap(), [0x0a, 0x0b]);
        assert_eq!(raw_bytes("Cgs=", Some("base64")).unwrap(), [0x0a, 0x0b]);
        assert!(raw_bytes("zz", Some("hex")).is_err());
        assert!(raw_bytes("", Some("hex")).is_err());
        assert!(raw_bytes("0a0b", Some("rot13")).is_err());
        assert!(raw_bytes(&"00".repeat(MAX_RAW + 1), Some("hex")).is_err());
    }
}
