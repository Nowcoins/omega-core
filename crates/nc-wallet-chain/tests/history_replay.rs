//! The history operation over answers recorded from the live, keyless endpoints
//! (2026-10-28), replayed with no network. They are the answers as the endpoints
//! gave them; what is checked is that what the parsers make of them is what the
//! chain says. To make one again: `cargo run -p nc-wallet-chain --example
//! history_smoke -- --only <network> --address <address> --record <file>`.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use nc_wallet_chain::ChainClient;
use nc_wallet_chain::testing::Replay;
use serde_json::{Value, json};

/// 2026-10-28 07:50 UTC, when they were recorded.
const RECORDED_AT: u64 = 1_793_173_800_000;

async fn replayed(recording: &str, request: Value) -> (Value, Arc<Replay>) {
    replayed_except(recording, request, "").await
}

/// As [`replayed`], allowing requests whose text holds `allowed` to be unrecorded: the
/// second operators' receipts, which the recordings (made before a second opinion was asked
/// for) do not have.
async fn replayed_except(recording: &str, request: Value, allowed: &str) -> (Value, Arc<Replay>) {
    let replay = Arc::new(Replay::new(recording, RECORDED_AT));
    let client = ChainClient::new(replay.clone());
    let answer = client.dispatch("history", &request).await.unwrap();
    let missed: Vec<String> = replay
        .misses()
        .into_iter()
        .filter(|m| allowed.is_empty() || !m.contains(allowed))
        .collect();
    assert!(missed.is_empty(), "asked for what was not recorded: {missed:?}");
    (answer, replay)
}

fn items(answer: &Value) -> &Vec<Value> {
    answer["items"].as_array().unwrap()
}

fn item<'a>(answer: &'a Value, hash_starts: &str) -> &'a Value {
    items(answer)
        .iter()
        .find(|i| i["hash"].as_str().unwrap().starts_with(hash_starts))
        .unwrap_or_else(|| panic!("no item {hash_starts}"))
}

#[tokio::test]
async fn ethereum_tokens_from_logs_with_the_fees_from_receipts() {
    let (answer, _) = replayed_except(
        include_str!("fixtures/history/ethereum.json"),
        json!({ "network": "ethereum", "address": "0xdee6a6d5f1e0af9364fc247f034b5508080a268a",
                "limit": 50, "balance": "1000000000" }),
        "eth_getTransactionReceipt",
    )
    .await;
    assert_eq!(items(&answer).len(), 5);
    let sent = item(&answer, "0xcbd20037e9");
    assert_eq!(
        (sent["direction"].as_str(), sent["asset"].as_str(), sent["amount"].as_str()),
        (Some("out"), Some("USDT"), Some("7231635496"))
    );
    assert_eq!(sent["counterparty"], "0x28C6c06298d514Db089934071355E5743bf21d60");
    assert_eq!(sent["contract"], "0xdAC17F958D2ee523a2206206994597C13D831ec7");
    assert_eq!(sent["fee"]["amount"], "10354892702221", "the units used at the price paid");
    let got = item(&answer, "0xc13a23c2c9");
    assert_eq!((got["direction"].as_str(), got["fee"].clone()), (Some("in"), Value::Null));
    assert_eq!(item(&answer, "0x2b3abc1e67")["asset"], "USDC");
    // Newest first.
    let times: Vec<&str> = items(&answer).iter().map(|i| i["time"].as_str().unwrap()).collect();
    assert!(times.windows(2).all(|w| w[0] >= w[1]), "{times:?}");
    // The whole chain was read: the tokens are complete, the coin is from first sight.
    assert_eq!(answer["coverage"]["parts"][1]["kind"], "full");
    assert_eq!(answer["coverage"]["complete"], true);
}

#[tokio::test]
async fn solana_reads_what_a_transaction_did_to_the_account_from_its_balances() {
    let (answer, _) = replayed(
        include_str!("fixtures/history/solana.json"),
        json!({ "network": "solana", "address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }),
    )
    .await;
    assert_eq!(items(&answer).len(), 1);
    let call = &items(&answer)[0];
    // It moved no coin of this account's; it cost the fee.
    assert_eq!(
        (call["kind"].as_str(), call["direction"].as_str(), call["amount"].as_str()),
        (Some("call"), Some("out"), Some("0"))
    );
    assert_eq!(call["fee"], json!({ "asset": "SOL", "amount": "5333", "decimals": 9 }));
    assert_eq!(answer["coverage"]["complete"], true);
}

#[tokio::test]
async fn stellar_payments_with_their_memos_and_fees() {
    let (answer, _) = replayed(
        include_str!("fixtures/history/stellar.json"),
        json!({ "network": "stellar", "address": "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H" }),
    )
    .await;
    assert_eq!(items(&answer).len(), 4);
    let sent = item(&answer, "cd6b1eef5d");
    assert_eq!(
        (sent["direction"].as_str(), sent["amount"].as_str()),
        (Some("out"), Some("5999900"))
    );
    assert_eq!(sent["fee"], json!({ "asset": "XLM", "amount": "100", "decimals": 7 }));
    let funded = item(&answer, "0fd0a8e7a5");
    assert_eq!(
        (funded["memo"].as_str(), funded["fee"].clone()),
        (Some("SYNC GENESIS NODE"), Value::Null)
    );
    assert_eq!(answer["coverage"]["kind"], "full");
    assert_eq!(answer["coverage"]["complete"], true);
}

#[tokio::test]
async fn tron_two_lists_one_history_with_a_page_to_come() {
    let (answer, _) = replayed(
        include_str!("fixtures/history/tron.json"),
        json!({ "network": "tron", "address": "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9" }),
    )
    .await;
    assert_eq!(items(&answer).len(), 50);
    let usdt = item(&answer, "8b5e5f9a99");
    assert_eq!(
        (usdt["asset"].as_str(), usdt["contract"].as_str(), usdt["amount"].as_str()),
        (Some("USDT"), Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), Some("2000000"))
    );
    let trx = item(&answer, "3b6fd4d794");
    assert_eq!(
        (trx["direction"].as_str(), trx["fee"]["amount"].as_str()),
        (Some("out"), Some("270000"))
    );
    let times: Vec<&str> = items(&answer).iter().map(|i| i["time"].as_str().unwrap()).collect();
    assert!(times.windows(2).all(|w| w[0] >= w[1]), "{times:?}");
    // More is on the lists: the app is told to come back.
    assert_eq!(answer["coverage"]["complete"], false);
    assert!(answer["next_cursor"].is_string());
}

#[tokio::test]
async fn bitcoin_nets_each_transaction_at_the_account_level() {
    let (answer, _) = replayed(
        include_str!("fixtures/history/bitcoin.json"),
        json!({ "network": "bitcoin", "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" }),
    )
    .await;
    assert_eq!(items(&answer).len(), 8);
    let payment = item(&answer, "1a30e9e11d");
    assert_eq!(
        (
            payment["direction"].as_str(),
            payment["amount"].as_str(),
            payment["fee"]["amount"].as_str()
        ),
        (Some("out"), Some("322"), Some("8178"))
    );
    assert_eq!(payment["counterparty"], "bc1qme580gd42sa3qn3um3hghhd6ggmd6u3l5kakek");
    // A spend of the account's coin back to itself is the fee and nothing else.
    let own = item(&answer, "9fe5136fd7");
    assert_eq!((own["direction"].as_str(), own["amount"].as_str()), (Some("self"), Some("0")));
    assert_eq!(answer["coverage"]["complete"], true);
}
