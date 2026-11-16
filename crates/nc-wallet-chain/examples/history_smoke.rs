//! A read-only look at the live history sources, from this machine: keyless, at
//! the endpoints' pace, never a broadcast. Run by hand, never by a test.
//!
//!     cargo run -p nc-wallet-chain --example history_smoke -- \
//!         [--only ethereum,tron] [--rounds 4] [--address ADDRESS] [--no-zpub] [--record out.json]
//!
//! For each network it asks for the history of a public address the way the app
//! does (newest first, then "show earlier" until the scan is finished or the
//! rounds are spent; `--address` takes the place of the built-in one when a single
//! network is asked for), carrying the state from one call to the next, and prints
//! what each call cost (requests, bytes), what it found, and where the coverage
//! stands. `--record` writes every exchange to a file `testing::Replay` can play.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nc_wallet_chain::ChainClient;
use nc_wallet_chain::native::ReqwestPlatform;
use nc_wallet_chain::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Platform};
use nc_wallet_chain::testing::Recorder;
use serde_json::{Value, json};

#[derive(Debug)]
struct Counting<P> {
    inner: P,
    calls: AtomicU64,
    received: AtomicU64,
}

impl<P: Platform> Platform for Counting<P> {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
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

/// Public addresses with something in their history.
const WALLETS: &[(&str, &str)] = &[
    ("ethereum", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
    ("bsc", "0x5BC24606e389465DF34068fCC3357465e7A473C2"),
    ("polygon", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
    ("base", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
    ("tron", "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb"),
    ("bitcoin", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    ("solana", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
    ("stellar", "GAFK7XFZHMLSNV7OJTBO7BAIZA66X6QIBV5RMZZYXK4Q7ZSO52J5C3WQ"),
    ("bittensor", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"),
];

/// BIP-84's test wallet ("abandon … about"): the zpub of the Bitcoin account.
const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let value = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
    let only: Option<Vec<String>> =
        value("--only").map(|v| v.split(',').map(str::to_owned).collect());
    let rounds: usize = value("--rounds").and_then(|r| r.parse().ok()).unwrap_or(4);
    let recorder = Arc::new(Recorder::new(ReqwestPlatform::new()));
    let counter = Arc::new(Counting {
        inner: Arc::clone(&recorder),
        calls: AtomicU64::new(0),
        received: AtomicU64::new(0),
    });
    let client = ChainClient::new(Arc::<Counting<Arc<Recorder<ReqwestPlatform>>>>::clone(&counter));

    for (network, address) in WALLETS {
        if only.as_ref().is_some_and(|o| !o.iter().any(|n| n == network)) {
            continue;
        }
        let address = match (&only, value("--address")) {
            (Some(only), Some(given)) if only.len() == 1 => given,
            _ => (*address).to_owned(),
        };
        println!("== {network} {address}");
        let mut state: Option<String> = None;
        let mut cursor: Option<String> = None;
        for round in 0..rounds {
            let mut request = json!({ "network": network, "address": address, "limit": 50 });
            if *network == "bitcoin" && !args.iter().any(|a| a == "--no-zpub") {
                request["zpub"] = json!(ZPUB);
            }
            if matches!(*network, "ethereum" | "bsc" | "polygon" | "base" | "bittensor") {
                request["balance"] = json!("1000000000");
            }
            if let Some(s) = &state {
                request["state"] = json!(s);
            }
            if round > 0 {
                request["mode"] = json!("page");
                if let Some(c) = &cursor {
                    request["cursor"] = json!(c);
                }
            }
            let (calls, bytes) =
                (counter.calls.load(Ordering::Relaxed), counter.received.load(Ordering::Relaxed));
            let started = std::time::Instant::now();
            match client.call("history", &request.to_string()).await {
                Ok(text) => {
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let items = v["items"].as_array().cloned().unwrap_or_default();
                    println!(
                        "  round {round}: {:>2} requests {:>8} bytes {:>5} ms | {:>3} items | next {} | state {} bytes | coverage {} stale {}",
                        counter.calls.load(Ordering::Relaxed) - calls,
                        counter.received.load(Ordering::Relaxed) - bytes,
                        started.elapsed().as_millis(),
                        items.len(),
                        if v["next_cursor"].is_null() { "no" } else { "yes" },
                        v["state"].as_str().map_or(0, str::len),
                        v["coverage"],
                        v["stale"],
                    );
                    for item in items.iter().take(3) {
                        println!(
                            "     {} {} {} {} {} {}{}",
                            item["time"],
                            item["direction"],
                            item["amount"],
                            item["asset"],
                            item["counterparty"].as_str().unwrap_or("-"),
                            item["hash"]
                                .as_str()
                                .unwrap_or("")
                                .chars()
                                .take(12)
                                .collect::<String>(),
                            if item["poisoned"] == true { " POISONED" } else { "" },
                        );
                    }
                    state = v["state"].as_str().map(str::to_owned);
                    cursor = v["next_cursor"].as_str().map(str::to_owned);
                    if v["coverage"]["scanning"] != true && cursor.is_none() {
                        break;
                    }
                }
                Err(e) => {
                    println!("  round {round}: ERR {e}");
                    println!("  health {}", client.health()["networks"][*network]);
                    break;
                }
            }
        }
    }
    if std::env::var("HEALTH").is_ok() {
        println!("health {}", client.health());
    }
    if let Some(path) = value("--record") {
        std::fs::write(&path, recorder.to_json()).expect("write the recording");
        println!("recorded to {path}");
    }
}
