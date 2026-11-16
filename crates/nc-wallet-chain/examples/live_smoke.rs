//! A read-only look at the live endpoints, from this machine: keyless, a few
//! requests to each, never a broadcast. Run by hand, never by a test.
//!
//!     cargo run -p nc-wallet-chain --example live_smoke -- [--record out.json] [--only ethereum,bitcoin]
//!
//! For each network it asks what the apps ask when they open (balances and
//! prices) and what a send asks (inputs and an estimate), prints whether each
//! answered, how many requests it took and how many bytes came back, and with
//! `--record` writes every exchange to a file `testing::Replay` can play back
//! (the fixtures of `tests/fixtures/`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nc_wallet_chain::native::ReqwestPlatform;
use nc_wallet_chain::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Platform};
use nc_wallet_chain::testing::Recorder;
use nc_wallet_chain::{ChainClient, Network};
use serde_json::{Value, json};

#[derive(Debug)]
struct Counting<P> {
    inner: P,
    calls: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}

impl<P: Platform> Platform for Counting<P> {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.sent.fetch_add(
                (request.url.len() + request.body.as_ref().map_or(0, Vec::len)) as u64,
                Ordering::Relaxed,
            );
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

/// The Bitcoin account the recording was made for: BIP-84 account 0 of the "abandon ... about" test
/// phrase, whose receive and change addresses are public (and have seen real transactions).
const BITCOIN_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

/// Well-known public addresses with something on them.
const WALLETS: &[(&str, &str, &str, &str)] = &[
    // network, an address, a recipient, the asset to estimate
    (
        "ethereum",
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "0x5BC24606e389465DF34068fCC3357465e7A473C2",
        "USDT",
    ),
    (
        "bsc",
        "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3",
        "0x5BC24606e389465DF34068fCC3357465e7A473C2",
        "BNB",
    ),
    (
        "polygon",
        "0xe7804c37c13166fF0b37F5aE0BB07A3aEbb6e245",
        "0x5BC24606e389465DF34068fCC3357465e7A473C2",
        "POL",
    ),
    (
        "base",
        "0x4200000000000000000000000000000000000016",
        "0x5BC24606e389465DF34068fCC3357465e7A473C2",
        "ETH",
    ),
    ("tron", "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9", "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb", "USDT"),
    (
        "bitcoin",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "bc1qg3f7exyzcgpw48ysh58rgpuu7vyh9wnu64mae8",
        "BTC",
    ),
    (
        "solana",
        "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9",
        "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        "USDC",
    ),
    (
        "stellar",
        "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        "GBDEVU63Y6NTHJQQZIKVTC23NWLQVP3WJ2RI2OTSJTNYOIGICST6DUXR",
        "XLM",
    ),
    (
        "bittensor",
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        "TAO",
    ),
];

async fn run(
    client: &ChainClient,
    counter: &Counting<Arc<Recorder<ReqwestPlatform>>>,
    label: &str,
    op: &str,
    request: Value,
) {
    let (calls, received) =
        (counter.calls.load(Ordering::Relaxed), counter.received.load(Ordering::Relaxed));
    let started = std::time::Instant::now();
    let mut request = request;
    let mut answer = client.call(op, &request.to_string()).await;
    // A Bitcoin account used on many addresses is read in pieces: ask again with the hint, as the apps do.
    for _ in 0..12 {
        let Ok(body) = &answer else { break };
        let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        if value["bitcoin"]["scanning"] != true {
            break;
        }
        request["hint"] = value["bitcoin"]["hint"].clone();
        answer = client.call(op, &request.to_string()).await;
    }
    let took = started.elapsed().as_millis();
    let calls = counter.calls.load(Ordering::Relaxed) - calls;
    let bytes = counter.received.load(Ordering::Relaxed) - received;
    match answer {
        Ok(body) => {
            let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let brief = brief(op, &value);
            println!(
                "ok    {label:<22} {calls:>2} requests {bytes:>8} bytes {took:>5} ms  {brief}"
            );
        }
        Err(error) => {
            let value: Value = serde_json::from_str(&error).unwrap_or(Value::Null);
            println!(
                "ERR   {label:<22} {calls:>2} requests {bytes:>8} bytes {took:>5} ms  {} {}",
                value["code"], value["message"]
            );
        }
    }
}

fn brief(op: &str, value: &Value) -> String {
    match op {
        "balances" => value["balances"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|b| {
                        format!(
                            "{} {}",
                            b["asset"].as_str().unwrap_or("?"),
                            b["amount"].as_str().unwrap_or("-")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        "prices" => value["prices"]
            .as_object()
            .map(|p| {
                p.iter()
                    .map(|(k, v)| {
                        format!(
                            "{k} {} ({}{})",
                            v["usd"].as_str().unwrap_or("?"),
                            v["change_24h"].as_str().unwrap_or("-"),
                            if v["stale"] == true { " stale" } else { "" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        "estimate" => value["fee"].to_string(),
        "inputs" => {
            let keys: Vec<&str> = value
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            keys.join(" ")
        }
        _ => String::new(),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let record = args.windows(2).find(|w| w[0] == "--record").map(|w| w[1].clone());
    let only: Option<Vec<String>> = args
        .windows(2)
        .find(|w| w[0] == "--only")
        .map(|w| w[1].split(',').map(str::to_owned).collect());
    let recorder = Arc::new(Recorder::new(ReqwestPlatform::new()));
    let counter = Arc::new(Counting {
        inner: Arc::clone(&recorder),
        calls: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
    });
    // Recording sits under counting; the client talks to the counting layer.
    let client = ChainClient::new(Arc::<Counting<Arc<Recorder<ReqwestPlatform>>>>::clone(&counter));
    let started = (counter.calls.load(Ordering::Relaxed), counter.received.load(Ordering::Relaxed));

    println!("-- what opening the app asks (balances of one wallet on each network, and prices)");
    run(&client, &counter, "prices (all)", "prices", json!({})).await;
    // The second reading, once the feeds are checked: one small call a network.
    run(&client, &counter, "prices (again)", "prices", json!({ "fresh": true })).await;
    for (id, address, _, _) in WALLETS {
        if only.as_ref().is_some_and(|only| !only.iter().any(|o| o == id)) {
            continue;
        }
        let mut request = json!({ "network": id, "address": address });
        if *id == "bitcoin" {
            request["zpub"] = json!(BITCOIN_ZPUB);
        }
        run(&client, &counter, &format!("{id} balances"), "balances", request).await;
    }
    println!(
        "== opening: {} requests, {} bytes received",
        counter.calls.load(Ordering::Relaxed) - started.0,
        counter.received.load(Ordering::Relaxed) - started.1
    );

    println!("-- what a send asks (inputs, then an estimate)");
    for (id, address, to, asset) in WALLETS {
        if only.as_ref().is_some_and(|only| !only.iter().any(|o| o == id)) {
            continue;
        }
        let mut request = json!({ "network": id, "address": address });
        let mut estimate =
            json!({ "network": id, "from": address, "to": to, "asset": asset, "amount": "1000" });
        if *id == "bitcoin" {
            request["zpub"] = json!(BITCOIN_ZPUB);
            estimate["zpub"] = json!(BITCOIN_ZPUB);
            estimate["amount"] = json!("10000");
        }
        run(&client, &counter, &format!("{id} inputs"), "inputs", request).await;
        run(&client, &counter, &format!("{id} estimate"), "estimate", estimate).await;
    }
    println!("-- a transaction's status");
    for (id, hash) in [
        ("ethereum", "0x316a268da99f8a8e28c851548d3f20080e8f030e8c15811bf161dd32fc43db5f"),
        ("bitcoin", "122a9a81385679aa4bbddddfcba64e24ffb5438c5013467d34e2ff5da2c098d5"),
        ("tron", "6150b2bb0a8871c7607d63e5cfdee96887bdd90cb49789cf5f790fc07c1c5ba5"),
        ("stellar", "a2854a78247bd08a425cf79254654488f7f56be4136f274494cf82f515bd0544"),
        (
            "solana",
            "2LPEaTFDLJPQ8KtwwEZotJS5deGmtc5Wif4Rc3ymowd78KmLpQ9rDiJ1xkYZ9AyXxjnWhz6UEUqAS4BV7E8UYrJd",
        ),
    ] {
        if only.as_ref().is_some_and(|only| !only.iter().any(|o| o == id)) {
            continue;
        }
        run(
            &client,
            &counter,
            &format!("{id} status"),
            "status",
            json!({ "network": id, "hash": hash }),
        )
        .await;
    }
    println!("-- endpoints seen");
    for network in nc_wallet_chain::networks::ALL {
        let health = client.net(network).health();
        let line: Vec<String> = health
            .iter()
            .map(|h| {
                format!(
                    "{} ok={} err={} {}ms",
                    h["endpoint"].as_str().unwrap_or("?"),
                    h["ok"],
                    h["errors"],
                    h["latency_ms"]
                )
            })
            .collect();
        println!("{:<10} {}", network.id(), line.join(" | "));
    }
    let _ = Network::Ethereum;
    if let Some(path) = record {
        std::fs::write(&path, recorder.to_json()).expect("write the recording");
        println!("recorded to {path}");
    }
}
