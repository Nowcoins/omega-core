//! The operations the apps make when they open and when they send, played back
//! from answers recorded from the live endpoints on 2026-10-28
//! (`tests/fixtures/live-ops.json`, made by `examples/live_smoke.rs`). No network.
//!
//! Three things are checked: that every answer has the shape the apps and the
//! signing engine read (the shapes of the former wallet API, kept in the apps'
//! own fixtures), that the money in them is what the recorded nodes said, and
//! what an open panel costs the endpoints over an hour.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use nc_wallet_chain::ChainClient;
use nc_wallet_chain::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Platform};
use nc_wallet_chain::testing::Replay;
use serde_json::{Value, json};

const RECORDING: &str = include_str!("fixtures/live-ops.json");
/// Finney's runtime 470, whose metadata is too large to repeat in the recording.
const METADATA: &[u8] = include_bytes!("fixtures/finney-470.metadata");
/// 2026-10-28 06:31 UTC, about: the moment of the recording.
const RECORDED_AT_MS: u64 = 1_793_171_700_000;

/// A replay that also answers the runtime metadata from the file beside it, and says
/// that the runtime is that one (the live one has moved on since the file was made).
#[derive(Debug)]
struct Recorded {
    replay: Replay,
}

impl Platform for Recorded {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        let wants_metadata = request
            .body
            .as_deref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("\"state_getMetadata\""));
        let wants_version = request
            .body
            .as_deref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("\"state_getRuntimeVersion\""));
        if wants_version {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "result": { "specVersion": 470, "transactionVersion": 1, "specName": "node-subtensor" } });
            return Box::pin(async move {
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: body.to_string().into_bytes(),
                })
            });
        }
        if wants_metadata {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{}", hex::encode(METADATA)) });
            return Box::pin(async move {
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: body.to_string().into_bytes(),
                })
            });
        }
        self.replay.send(request)
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        self.replay.sleep(millis)
    }

    fn now_ms(&self) -> u64 {
        self.replay.now_ms()
    }
}

/// The Bitcoin account the recording was made for: BIP-84 account 0 of the "abandon ... about" test
/// phrase, whose receive and change addresses are public (and have seen real transactions).
const BITCOIN_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

fn client() -> (ChainClient, Arc<Recorded>) {
    let platform = Arc::new(Recorded { replay: Replay::new(RECORDING, RECORDED_AT_MS) });
    (ChainClient::new(platform.clone()), platform)
}

async fn run(client: &ChainClient, op: &str, request: Value) -> Value {
    let mut request = request;
    // A Bitcoin account used on many addresses is read in pieces: ask again with the hint, as the apps do.
    for _ in 0..12 {
        let body = match client.call(op, &request.to_string()).await {
            Ok(body) => serde_json::from_str::<Value>(&body).unwrap(),
            Err(error) => panic!("{op} {request}: {error}"),
        };
        if body["bitcoin"]["scanning"] != true {
            return body;
        }
        request["hint"] = body["bitcoin"]["hint"].clone();
    }
    panic!("{op}: still scanning after twelve readings");
}

/// Every wallet the recording was made for: network, address, a recipient, the asset estimated.
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

/// What the app already knows of the recorded Bitcoin account (it has been read before): its
/// receive chain used up to index 41, its change chain up to 0, nothing on any of them now.
fn bitcoin_hint() -> Value {
    json!({
        "v": 1, "at": RECORDED_AT_MS / 1000,
        "r": { "last": 41, "live": [], "resume": null },
        "c": { "last": 0, "live": [], "resume": null },
    })
}

fn request_for(id: &str, address: &str) -> Value {
    let mut request = json!({ "network": id, "address": address });
    if id == "bitcoin" {
        request["zpub"] = json!(BITCOIN_ZPUB);
        request["hint"] = bitcoin_hint();
    }
    request
}

fn app_fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/wallet-api/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Every key of `want` is in `got` with the same kind of value (a null is taken
/// for what an optional field is), except the `optional` ones, which may be absent.
fn same_shape(want: &Value, got: &Value, path: &str, optional: &[&str]) {
    match (want, got) {
        (Value::Object(want), Value::Object(got)) => {
            for (key, expected) in want {
                let here = format!("{path}.{key}");
                match got.get(key) {
                    Some(found) => same_shape(expected, found, &here, optional),
                    None if optional.contains(&key.as_str()) => {}
                    None => panic!("{here} is missing"),
                }
            }
        }
        (Value::Array(want), Value::Array(got)) => {
            if let (Some(expected), Some(found)) = (want.first(), got.first()) {
                same_shape(expected, found, &format!("{path}[]"), optional);
            }
        }
        (_, Value::Null) => {}
        (expected, found) => assert_eq!(kind(expected), kind(found), "{path}"),
    }
}

#[tokio::test]
async fn balances_have_the_coin_then_each_listed_token_in_base_units() {
    let (client, platform) = client();
    let shape = app_fixture("balances");
    for (id, address, _, _) in WALLETS {
        let body = run(&client, "balances", request_for(id, address)).await;
        same_shape(&shape, &body, id, &[]);
        let list = body["balances"].as_array().unwrap();
        let network = nc_wallet_chain::Network::from_id(id).unwrap();
        assert_eq!(list.len(), 1 + network.tokens().len(), "{id}");
        assert_eq!(list[0]["asset"], network.native().symbol, "{id}");
        for (entry, token) in list[1..].iter().zip(network.tokens()) {
            assert_eq!(entry["asset"], token.symbol);
            assert_eq!(entry["contract"], token.contract);
            assert_eq!(entry["decimals"], token.decimals);
        }
        assert!(
            list.iter().all(|b| b["amount"]
                .as_str()
                .is_some_and(|a| a.bytes().all(|c| c.is_ascii_digit()))),
            "{id}: {body}"
        );
    }
    assert!(platform.replay.misses().is_empty(), "{:?}", platform.replay.misses());
}

#[tokio::test]
async fn the_bitcoin_balance_is_found_by_looking_at_the_whole_account() {
    let (client, platform) = client();
    // An account no one has told the client of is walked from the start on both chains, in pieces
    // the client hands back to be continued (as the apps do), until twenty unused addresses in a row.
    let mut request =
        json!({ "network": "bitcoin", "address": WALLETS[5].1, "zpub": BITCOIN_ZPUB });
    let mut readings = 0;
    let body = loop {
        readings += 1;
        let body = match client.call("balances", &request.to_string()).await {
            Ok(text) => serde_json::from_str::<Value>(&text).unwrap(),
            Err(error) => panic!("{error}"),
        };
        if body["bitcoin"]["scanning"] != true {
            break body;
        }
        request["hint"] = body["bitcoin"]["hint"].clone();
        assert!(readings < 12, "it never finishes");
    };
    let entry = &body["balances"][0];
    let total: i128 = entry["amount"].as_str().unwrap().parse().unwrap();
    let confirmed: i128 = entry["confirmed"].as_str().unwrap().parse().unwrap();
    let unconfirmed: i128 = entry["unconfirmed"].as_str().unwrap().parse().unwrap();
    assert_eq!(total, confirmed + unconfirmed);
    // The BIP-84 test phrase's receive chain was used up to index 41 and its change chain up to 0.
    assert_eq!(body["bitcoin"]["hint"]["r"]["last"], 41);
    assert_eq!(body["bitcoin"]["hint"]["c"]["last"], 0);
    assert_eq!(body["bitcoin"]["next_change"], 1);
    assert!(
        readings >= 2,
        "an account used on 42 addresses takes more than one reading: {readings}"
    );
    let (walk, _) = client.traffic();
    // The next reading, with the hint the walk left, asks only about the live addresses, receive 0 and
    // the few past the highest used on each chain.
    request["hint"] = body["bitcoin"]["hint"].clone();
    request["fresh"] = json!(true);
    let again = run(&client, "balances", request.clone()).await;
    assert_eq!(again["bitcoin"]["scanning"], false);
    assert_eq!(again["balances"][0]["amount"], body["balances"][0]["amount"]);
    let (after, _) = client.traffic();
    println!(
        "bitcoin, an imported account of 42 receive addresses: the walk is {readings} readings and \
         {walk} requests; a reading with its hint is {} requests",
        after - walk
    );
    assert!(platform.replay.misses().is_empty(), "{:?}", platform.replay.misses());
}

#[tokio::test]
async fn inputs_and_estimates_have_the_shapes_the_signing_engine_reads() {
    let (client, platform) = client();
    let families = [
        ("ethereum", "evm", &["block"][..]),
        ("bsc", "evm", &["block"]),
        ("polygon", "evm", &["block", "l1_fee"]),
        ("base", "evm", &["block"]),
        ("tron", "tron", &[]),
        ("bitcoin", "bitcoin", &["block"]),
        ("solana", "solana", &[]),
        ("stellar", "stellar", &[]),
        ("bittensor", "bittensor", &[]),
    ];
    for ((id, address, to, asset), (_, family, optional)) in WALLETS.iter().zip(families) {
        let inputs = run(&client, "inputs", request_for(id, address)).await;
        // Whatever the recorded chain had (a token transfer, a coin transfer), the keys the
        // engine reads are the fixture's.
        let mut optional = optional.to_vec();
        optional.extend(["base_fee", "max_priority_fee", "max_fee"]);
        same_shape(
            &app_fixture(&format!("inputs-{family}")),
            &inputs,
            &format!("inputs {id}"),
            &optional,
        );
        assert_eq!(inputs["network"], *id);

        let mut request =
            json!({ "network": id, "from": address, "to": to, "asset": asset, "amount": "1000" });
        if *id == "bitcoin" {
            request["amount"] = json!("10000");
            request["zpub"] = json!(BITCOIN_ZPUB);
        }
        if family == "evm" {
            request["tiers"] = json!(true);
        }
        if *id == "bitcoin" {
            // The recorded account holds nothing: the estimate says so, in the words of the contract.
            request["hint"] = bitcoin_hint();
            let error = client.call("estimate", &request.to_string()).await.unwrap_err();
            assert!(error.contains("insufficient_funds"), "{error}");
            continue;
        }
        let estimate = run(&client, "estimate", request).await;
        // A token transfer has other recipient facts than a coin transfer; the fee is the same shape.
        optional.extend([
            "recipient",
            "exists",
            "trustline",
            "memo_required",
            "activated",
            "is_contract",
            "l1_fee",
            "base_fee",
            "priority_fee",
            "compute_unit_limit",
            "account_creation",
            "compute_unit_price_micro_lamports",
        ]);
        same_shape(
            &app_fixture(&format!("estimate-{family}")),
            &estimate,
            &format!("estimate {id}"),
            &optional,
        );
        assert!(estimate["fee"]["amount"].as_str().unwrap().parse::<u128>().unwrap() > 0, "{id}");
        if family == "evm" {
            // Standard is the top of the answer; slow and fast, where there are any, are on either side.
            let fees = &estimate["fees"];
            assert_eq!(fees["normal"]["max_fee_per_gas"], estimate["max_fee_per_gas"], "{id}");
            assert_eq!(fees["normal"]["fee"], estimate["fee"], "{id}");
            let max = |speed: &str| {
                fees[speed]["max_fee_per_gas"].as_str().map(|m| m.parse::<u128>().unwrap())
            };
            let standard = max("normal").unwrap();
            assert!(max("slow").is_none_or(|slow| slow <= standard), "{id}: {fees}");
            assert!(max("fast").is_none_or(|fast| fast >= standard), "{id}: {fees}");
        }
    }
    assert!(platform.replay.misses().is_empty(), "{:?}", platform.replay.misses());
}

#[tokio::test]
async fn the_evm_fee_is_a_cap_of_twice_the_base_fee_and_a_tip() {
    let (client, _) = client();
    let body = run(&client, "inputs", request_for("ethereum", WALLETS[0].1)).await;
    assert_eq!(body["eip1559"], true);
    assert_eq!(body["chain_id"], 1);
    let base: u128 = body["base_fee"].as_str().unwrap().parse().unwrap();
    let tip: u128 = body["max_priority_fee"].as_str().unwrap().parse().unwrap();
    let cap: u128 = body["max_fee"].as_str().unwrap().parse().unwrap();
    assert_eq!(cap, 2 * base + tip);
    assert!(tip >= 10_000_000, "never below the network's floor");
}

#[tokio::test]
async fn prices_come_from_chainlink_for_every_listed_coin_and_are_not_stale() {
    let (client, _) = client();
    let body = run(&client, "prices", json!({})).await;
    let prices = body["prices"].as_object().unwrap();
    for coin in ["BTC", "ETH", "BNB", "POL", "TRX", "SOL", "XLM", "TAO", "USDT", "USDC"] {
        let price = &prices[coin];
        let usd = price["usd"].as_str().unwrap();
        assert!(usd.contains('.') && usd.split('.').nth(1).unwrap().len() == 8, "{coin}: {usd}");
        assert_eq!(price["stale"], false, "{coin}");
        assert!(price["updated_at"].as_str().unwrap().ends_with('Z'));
    }
    // A stablecoin is about a dollar (between 0.90 and 1.10), a coin is not: in cents.
    let cents = |coin: &str| -> u128 {
        let usd = prices[coin]["usd"].as_str().unwrap();
        let (whole, fraction) = usd.split_once('.').unwrap();
        whole.parse::<u128>().unwrap() * 100 + fraction[..2].parse::<u128>().unwrap()
    };
    assert!((90..=110).contains(&cents("USDT")));
    assert!(cents("BTC") > 100_000);
    // A ticker nothing lists is left out and named, not guessed at and not an error.
    let only = run(&client, "prices", json!({ "assets": ["DOGE"] })).await;
    assert!(only["prices"].as_object().unwrap().is_empty());
    assert_eq!(only["unknown"], json!(["DOGE"]));
}

#[tokio::test]
async fn an_open_panel_costs_the_endpoints_a_fraction_of_what_it_asks() {
    // A panel that re-reads every network's balances and the prices once a minute
    // for an hour, on a wallet that does not change: what the endpoints are asked.
    let (client, platform) = client();
    let asked = |id: &str, address: &str| {
        let mut request = request_for(id, address);
        request["fresh"] = json!(false);
        request
    };
    let mut opening = 0;
    for minute in 0..60_u64 {
        for (id, address, _, _) in WALLETS {
            let _ = run(&client, "balances", asked(id, address)).await;
        }
        let _ = run(&client, "prices", json!({})).await;
        if minute == 0 {
            opening = client.traffic().0;
        }
        platform.sleep(60_000).await;
    }
    let (requests, bytes) = client.traffic();
    assert!(platform.replay.misses().is_empty(), "{:?}", platform.replay.misses());
    println!(
        "opening: {opening} requests; an hour of an open panel: {requests} requests, {bytes} bytes"
    );
    // Nine networks cost 17 requests a round (Bitcoin's account: its shown address and a short window
    // past the last used), and prices two, every two minutes: asked every
    // minute for an hour that would be 1,100; the cache brings it under a third. Opening adds the
    // first look for the prices of a day ago: a ladder of rounds and a few narrower questions on each
    // of the two chains (seven requests), which is looked for again once an hour.
    assert!(opening <= 28, "{opening}");
    assert!(requests < 330, "{requests}");
    // And a fresh read is a read.
    let before = client.traffic().0;
    let mut request = request_for("ethereum", WALLETS[0].1);
    request["fresh"] = json!(true);
    let _ = run(&client, "balances", request).await;
    assert_eq!(client.traffic().0, before + 1);
}
