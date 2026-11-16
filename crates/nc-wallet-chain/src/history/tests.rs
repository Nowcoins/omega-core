//! The history operations end to end: a request in, an answer out, over the
//! scripted platform. Every answer an endpoint gives here is made up in the
//! shape the live ones were seen to have (see `docs/history.md`); the
//! recorded ones are in `tests/history_replay.rs`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::client::ChainClient;
use crate::error::ChainResult;
use crate::testing::{Reply, Script};

const ME: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const USDT: &str = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TAO: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
const TAO_FRIEND: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
const FRIEND: &str = "0x1111111111111111111111111111111111112222";

struct Rig {
    script: Arc<Script>,
    client: ChainClient,
}

fn rig() -> Rig {
    let script = Arc::new(Script::new());
    let client = ChainClient::new(script.clone());
    Rig { script, client }
}

impl Rig {
    async fn op(&self, op: &str, request: Value) -> ChainResult<Value> {
        self.client.dispatch(op, &request).await
    }

    async fn history(&self, request: Value) -> Value {
        self.op("history", request).await.unwrap()
    }
}

fn hash(n: u64) -> String {
    format!("0x{n:064x}")
}

fn topic(address: &str) -> String {
    format!("0x{:0>64}", address.trim_start_matches("0x").to_lowercase())
}

/// An ERC-20 `Transfer` log as a node gives it.
fn log(
    contract: &str,
    from: &str,
    to: &str,
    amount: u128,
    block: u64,
    tx: u64,
    time: u64,
) -> Value {
    json!({
        "address": contract,
        "topics": [TRANSFER, topic(from), topic(to)],
        "data": format!("0x{amount:064x}"),
        "blockNumber": format!("0x{block:x}"),
        "logIndex": "0x1",
        "transactionHash": hash(tx),
        "blockTimestamp": format!("0x{time:x}"),
    })
}

/// What the EVM endpoints say: a head, and the same logs for every window.
fn chain(rig: &Rig, received: &[Value], sent: &[Value]) {
    let s = &rig.script;
    s.rpc("eth_blockNumber", &json!("0x1312d00"));
    // The sent query has the address in the second topic, the received one in the third.
    s.on("", Some("b3ef\",\"0x00"), vec![Reply::result(&json!(sent))]);
    s.on("", Some(",null,\"0x00"), vec![Reply::result(&json!(received))]);
    s.rpc(
        "eth_getTransactionReceipt",
        &json!({ "status": "0x1", "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00" }),
    );
}

fn items(answer: &Value) -> &Vec<Value> {
    answer["items"].as_array().unwrap()
}

fn hashes(answer: &Value) -> Vec<String> {
    items(answer).iter().map(|i| i["hash"].as_str().unwrap().to_owned()).collect()
}

// ---- tokens on an EVM network --------------------------------------------------

#[tokio::test]
async fn token_transfers_are_read_from_logs_newest_first_and_the_page_resumes() {
    let rig = rig();
    chain(
        &rig,
        &[
            log(USDT, FRIEND, ME, 5_000_000, 19_999_000, 1, 1_792_900_000),
            log(USDC, FRIEND, ME, 1_000_000, 19_990_000, 3, 1_792_800_000),
        ],
        &[log(USDT, ME, FRIEND, 2_500_000, 19_995_000, 2, 1_792_850_000)],
    );

    let first = rig.history(json!({ "network": "ethereum", "address": ME, "limit": 1 })).await;
    assert_eq!(hashes(&first), [hash(1)]);
    let top = &items(&first)[0];
    assert_eq!(
        (top["direction"].as_str(), top["asset"].as_str(), top["amount"].as_str()),
        (Some("in"), Some("USDT"), Some("5000000"))
    );
    assert_eq!(top["decimals"], 6);
    // One source's word is not enough: confirmed only once two operators agree (below).
    assert_eq!(
        (top["status"].as_str(), top["unverified"].as_bool()),
        (Some("pending"), Some(true))
    );
    assert!(top["counterparty"].as_str().unwrap().eq_ignore_ascii_case(FRIEND));
    assert!(first["next_cursor"].is_string(), "there is more");
    assert!(first["explorer_address"].as_str().unwrap().contains(ME));
    // The coin has no source but what this wallet sees; an archive gateway reads the
    // tokens back to the beginning in one query.
    let coverage = &first["coverage"];
    assert_eq!(coverage["kind"], "from_first_sight");
    assert_eq!(coverage["complete"], true);
    assert_eq!(coverage["parts"][0]["scope"], "coin");
    assert_eq!(coverage["parts"][0]["kind"], "from_first_sight");
    assert_eq!(coverage["parts"][1]["scope"], "tokens");
    assert_eq!(coverage["parts"][1]["kind"], "full");

    // The next page comes from the state and the cursor, and a send has its fee.
    let second = rig
        .history(json!({
            "network": "ethereum", "address": ME, "limit": 2, "mode": "page",
            "state": first["state"], "cursor": first["next_cursor"],
        }))
        .await;
    assert_eq!(hashes(&second), [hash(2), hash(3)]);
    let sent = &items(&second)[0];
    assert_eq!(sent["direction"], "out");
    assert_eq!(sent["fee"], json!({ "asset": "ETH", "amount": "21000000000000", "decimals": 18 }));
    assert_eq!(items(&second)[1]["asset"], "USDC");
}

#[tokio::test]
async fn a_scan_is_bounded_resumable_and_within_what_the_endpoints_serve() {
    let rig = rig();
    // Base: the only endpoint that serves logs that far back answers 20,000 blocks a query.
    rig.script.rpc("eth_blockNumber", &json!("0x32b9c60"));
    rig.script.rpc("eth_getLogs", &json!([]));
    let request = |state: &Value| json!({ "network": "base", "address": ME, "state": state });

    let first = rig.history(request(&Value::Null)).await;
    let spans = || -> Vec<u64> {
        let number = |v: &Value, key: &str| {
            u64::from_str_radix(v[0][key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        rig.script
            .seen()
            .iter()
            .filter(|s| s.body.contains("eth_getLogs"))
            .map(|s| {
                let body: Value = serde_json::from_str(&s.body).unwrap();
                number(&body["params"], "toBlock") - number(&body["params"], "fromBlock") + 1
            })
            .collect()
    };
    assert!(!spans().is_empty());
    assert!(spans().iter().all(|s| (1_000..=20_000).contains(s)), "{:?}", spans());
    assert!(rig.script.seen().len() <= 10, "a call is bounded: {}", rig.script.seen().len());
    let tokens = &first["coverage"]["parts"][1];
    assert_eq!(tokens["kind"], "partial");
    assert_eq!(first["coverage"]["complete"], false);
    assert_eq!(first["coverage"]["scanning"], true, "the app is told to come back");

    // The next call goes on from where it stopped.
    let before = rig.script.seen().len();
    let second = rig.history(request(&first["state"])).await;
    assert!(rig.script.seen().len() - before <= 10);
    let (a, b) =
        (tokens["from"].as_str().unwrap(), second["coverage"]["parts"][1]["from"].as_str());
    assert!(b.unwrap() < a, "it went further back: {a} then {b:?}");
}

#[tokio::test]
async fn a_look_alike_of_an_address_paid_is_flagged_on_the_device() {
    let rig = rig();
    let paid = "0xabcd5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e1234";
    let fake = "0xabcd9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f1234";
    chain(
        &rig,
        &[
            // A millionth of a token, from an address that begins and ends like the one paid.
            log(USDT, fake, ME, 1, 19_999_500, 7, 1_792_950_000),
            log(USDT, paid, ME, 40_000_000, 19_980_000, 5, 1_792_700_000),
        ],
        &[log(USDT, ME, paid, 10_000_000, 19_990_000, 6, 1_792_800_000)],
    );
    let answer = rig.history(json!({ "network": "ethereum", "address": ME, "limit": 10 })).await;
    let by = |n: u64| items(&answer).iter().find(|i| i["hash"] == hash(n).as_str()).unwrap();
    assert_eq!(by(7)["poisoned"], true);
    assert!(by(7)["look_alike_of"].as_str().unwrap().eq_ignore_ascii_case(paid));
    assert!(by(5).get("poisoned").is_none(), "the real one is not flagged");
    assert!(by(6).get("poisoned").is_none());
}

#[tokio::test]
async fn with_the_endpoints_down_what_is_stored_is_shown_and_said_to_be_stale() {
    let up = rig();
    chain(&up, &[log(USDT, FRIEND, ME, 5_000_000, 19_999_000, 1, 1_792_900_000)], &[]);
    let fresh = up.history(json!({ "network": "ethereum", "address": ME })).await;
    assert!(fresh.get("stale").is_none());
    assert_eq!(hashes(&fresh), [hash(1)]);

    // A new session, no endpoint answering.
    let down = rig();
    let later = down
        .history(json!({ "network": "ethereum", "address": ME, "state": fresh["state"] }))
        .await;
    assert_eq!(hashes(&later), [hash(1)]);
    assert!(later["stale"].is_string(), "{later}");
    assert_eq!(later["coverage"]["scanning"], false);

    // With nothing stored, it is an error the app can retry.
    let error = down.op("history", json!({ "network": "ethereum", "address": ME })).await;
    assert_eq!(error.unwrap_err().code(), "upstream_unavailable");
}

#[tokio::test]
async fn a_head_a_node_makes_up_is_not_believed_and_never_panics_the_scan() {
    // A node that says the chain is at block 2^64 - 1: the windows are counted back from it, and that
    // arithmetic must never be reached (in the extension's WebAssembly a panic would stop the whole worker).
    for head in ["0xffffffffffffffff", "0x1000000000001", "0xffffffffffffffffffffffffffffffff"] {
        let rig = rig();
        rig.script.rpc("eth_blockNumber", &json!(head));
        let error = rig.op("history", json!({ "network": "ethereum", "address": ME })).await;
        assert_eq!(error.unwrap_err().code(), "upstream_unavailable", "{head}");
    }
    // With something stored, it is shown as it was and said to be stale, not replaced by nonsense.
    let up = rig();
    chain(&up, &[log(USDT, FRIEND, ME, 5_000_000, 19_999_000, 1, 1_792_900_000)], &[]);
    let fresh = up.history(json!({ "network": "ethereum", "address": ME })).await;
    let lying = rig();
    lying.script.rpc("eth_blockNumber", &json!("0xffffffffffffffff"));
    let later = lying
        .history(json!({ "network": "ethereum", "address": ME, "state": fresh["state"] }))
        .await;
    assert_eq!(hashes(&later), [hash(1)]);
    assert!(later["stale"].is_string(), "{later}");
}

// ---- a state, a cursor, a note ----------------------------------------------------

#[tokio::test]
async fn a_state_kept_for_another_wallet_is_not_used() {
    let rig = rig();
    let noted = rig
        .op(
            "history_note",
            json!({ "network": "bittensor", "address": TAO, "sent": {
                "hash": hash(9), "asset": "TAO", "amount": "1000000000", "decimals": 9,
                "to": TAO_FRIEND,
            } }),
        )
        .await
        .unwrap();
    let mine = rig
        .history(json!({ "network": "bittensor", "address": TAO, "state": noted["state"] }))
        .await;
    assert_eq!(items(&mine).len(), 1);
    let theirs = rig
        .history(json!({ "network": "bittensor", "address": TAO_FRIEND, "state": noted["state"] }))
        .await;
    assert!(items(&theirs).is_empty(), "another wallet's state is not read");
}

#[tokio::test]
async fn requests_that_are_not_ours_are_refused() {
    let rig = rig();
    let cases = [
        ("history", json!({ "network": "bittensor", "address": TAO, "cursor": "not a cursor" })),
        ("history", json!({ "network": "bittensor", "address": TAO, "mode": "oldest" })),
        ("history", json!({ "network": "bittensor", "address": TAO, "zpub": "zpub6x" })),
        ("history", json!({ "network": "bittensor", "address": TAO, "addresses": [TAO_FRIEND] })),
        ("history", json!({ "network": "dogecoin", "address": TAO })),
        ("history", json!({ "network": "bittensor", "address": "5nope" })),
        (
            "history_note",
            json!({ "network": "bittensor", "address": TAO, "sent": {
                "hash": hash(1), "asset": "DOGE", "amount": "1", "decimals": 9, "to": TAO_FRIEND,
            } }),
        ),
        ("history_note", json!({ "network": "bittensor", "address": TAO })),
        ("history_nothing", json!({})),
    ];
    for (op, request) in cases {
        let error = rig.op(op, request.clone()).await.unwrap_err();
        assert!(
            ["invalid_request", "invalid_address", "unknown_network"].contains(&error.code()),
            "{op} {request}: {}",
            error.code()
        );
    }
    // A state that is not one is not trusted, and not an error: the history starts again.
    let again = rig
        .history(json!({ "network": "bittensor", "address": TAO, "state": "eyJ2IjoyMDB9" }))
        .await;
    assert!(items(&again).is_empty());
}

#[tokio::test]
async fn a_send_the_app_noted_shows_pending_then_in_and_an_arrival_is_seen_as_a_rise() {
    let rig = rig();
    let request = |state: &Value, balance: &str| json!({ "network": "bittensor", "address": TAO, "state": state, "balance": balance });
    // First sight: what is there is the past.
    let first = rig.history(request(&Value::Null, "5000000000")).await;
    assert!(items(&first).is_empty());
    assert_eq!(first["coverage"]["kind"], "from_first_sight");
    assert_eq!(first["coverage"]["complete"], true);
    assert!(first["coverage"]["from"].is_string());

    // The app sends one TAO and a fee of 125,000 rao and tells the history.
    let noted = rig
        .op(
            "history_note",
            json!({ "network": "bittensor", "address": TAO, "state": first["state"], "sent": {
                "hash": hash(9), "asset": "TAO", "amount": "1000000000", "decimals": 9,
                "to": TAO_FRIEND, "fee": { "asset": "TAO", "amount": "125000", "decimals": 9 },
                "nonce": 7,
            } }),
        )
        .await
        .unwrap();
    chain_nonce(&rig, 7);
    let pending = rig.history(request(&noted["state"], "3999875000")).await;
    assert_eq!(items(&pending).len(), 1, "a send is not an arrival: {pending}");
    let note = &items(&pending)[0];
    assert_eq!(
        (note["direction"].as_str(), note["status"].as_str(), note["amount"].as_str()),
        (Some("out"), Some("pending"), Some("1000000000"))
    );
    assert_eq!(note["fee"]["amount"], "125000");

    // Two minutes on, the account's nonce has moved past the one the send used (the app told it by the
    // broadcast): it counts as in, and the balance moving by what was sent is no arrival.
    rig.script.advance(121_000);
    chain_nonce(&rig, 8);
    let settled = rig.history(request(&pending["state"], "3999875000")).await;
    assert_eq!(items(&settled).len(), 1);
    assert_eq!(items(&settled)[0]["status"], "confirmed");

    // Two TAO arrive. Just after the wallet's own send a rise is not taken for an arrival (the reading may be
    // older than the send), and later it must be seen twice, apart.
    let soon = rig.history(request(&settled["state"], "5999875000")).await;
    assert_eq!(items(&soon).len(), 1);
    rig.script.advance(601_000);
    let once = rig.history(request(&soon["state"], "5999875000")).await;
    assert_eq!(items(&once).len(), 1, "one reading of a rise is not an arrival: {once}");
    rig.script.advance(30_000);
    // The rise is shown as seen, not as read from the chain.
    let rise = rig.history(request(&once["state"], "5999875000")).await;
    assert_eq!(items(&rise).len(), 2);
    let arrival = &items(&rise)[0];
    assert_eq!(
        (arrival["direction"].as_str(), arrival["amount"].as_str(), arrival["observed"].as_bool()),
        (Some("in"), Some("2000000000"), Some(true))
    );
    assert!(arrival["counterparty"].is_null());
}

/// What `System.Account` holds for an account that has had `nonce` extrinsics in: four `u32`s, three
/// `u64`s and a `u128`.
fn account_entry(nonce: u32) -> String {
    let mut bytes = vec![0_u8; 56];
    bytes[..4].copy_from_slice(&nonce.to_le_bytes());
    bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&5_000_000_000_u64.to_le_bytes());
    format!("0x{}", hex::encode(bytes))
}

/// Every Finney endpoint says the account has had `nonce` extrinsics in.
fn chain_nonce(rig: &Rig, nonce: u32) {
    rig.script.on_first(
        "",
        Some("\"method\":\"state_getStorage\""),
        vec![Reply::result(&json!(account_entry(nonce)))],
    );
}

/// A Bittensor wallet that has seen its balance, then sent one TAO (and a fee of 125,000 rao) with
/// `nonce`, as the app tells the history. Returns the state after the note.
async fn sent_tao(rig: &Rig, nonce: Option<u32>) -> Value {
    let first = rig
        .history(json!({ "network": "bittensor", "address": TAO, "balance": "5000000000" }))
        .await;
    let mut sent = json!({
        "hash": hash(9), "asset": "TAO", "amount": "1000000000", "decimals": 9, "to": TAO_FRIEND,
        "fee": { "asset": "TAO", "amount": "125000", "decimals": 9 },
    });
    if let Some(nonce) = nonce {
        sent["nonce"] = json!(nonce);
    }
    rig.op(
        "history_note",
        json!({ "network": "bittensor", "address": TAO, "state": first["state"], "sent": sent }),
    )
    .await
    .unwrap()["state"]
        .clone()
}

fn tao_history(state: &Value, balance: &str) -> Value {
    json!({ "network": "bittensor", "address": TAO, "state": state, "balance": balance })
}

#[tokio::test]
async fn a_bittensor_send_waits_for_the_accounts_nonce_and_not_for_a_timer() {
    let rig = rig();
    let state = sent_tao(&rig, Some(7)).await;
    // Past the two minutes the old timer waited, and well inside the transaction's life: the chain's
    // nonce is still 7, so nothing says it came in.
    rig.script.advance(300_000);
    chain_nonce(&rig, 7);
    let waiting = rig.history(tao_history(&state, "5000000000")).await;
    assert_eq!(items(&waiting)[0]["status"], "pending", "{waiting}");
    // The nonce passes the send's: it came in, and it is no arrival that the balance fell by it.
    chain_nonce(&rig, 8);
    let settled = rig.history(tao_history(&waiting["state"], "3999875000")).await;
    assert_eq!(items(&settled).len(), 1, "{settled}");
    assert_eq!(
        (items(&settled)[0]["status"].as_str(), items(&settled)[0]["direction"].as_str()),
        (Some("confirmed"), Some("out"))
    );
}

#[tokio::test]
async fn a_bittensor_send_that_was_dropped_is_failed_when_its_era_is_over_and_comes_back_as_no_arrival()
 {
    // The extrinsic was rejected or dropped from the pool: the nonce never moves and the money never
    // leaves. It used to be shown confirmed after two minutes, and when the balance did not fall, the
    // amount and the fee were then "seen" arriving.
    let rig = rig();
    let state = sent_tao(&rig, Some(7)).await;
    chain_nonce(&rig, 7);
    let mut state = state;
    // Two minutes, five, ten: still pending, the era is not over.
    for minutes in [2, 3, 5] {
        rig.script.advance(minutes * 60_000);
        let said = rig.history(tao_history(&state, "5000000000")).await;
        assert_eq!(items(&said)[0]["status"], "pending", "{minutes}: {said}");
        state = said["state"].clone();
    }
    // Fifteen minutes on, the nonce unmoved: it never came in.
    rig.script.advance(10 * 60_000);
    let dropped = rig.history(tao_history(&state, "5000000000")).await;
    assert_eq!(items(&dropped).len(), 1, "{dropped}");
    assert_eq!(items(&dropped)[0]["status"], "failed", "{dropped}");
    assert!(items(&dropped)[0]["fee"].is_null(), "no fee was paid: {dropped}");
    // The balance is what it was: not an arrival of the amount and the fee, then or later.
    let mut state = dropped["state"].clone();
    for _ in 0..4 {
        rig.script.advance(700_000);
        let later = rig.history(tao_history(&state, "5000000000")).await;
        assert_eq!(items(&later).len(), 1, "a phantom arrival: {later}");
        state = later["state"].clone();
    }
}

#[tokio::test]
async fn a_bittensor_send_is_settled_only_on_the_word_of_two_operators() {
    let rig = rig();
    let state = sent_tao(&rig, Some(7)).await;
    rig.script.advance(1_000_000);
    // One endpoint answers (and says the nonce moved); everything else is down: no verdict, either way.
    rig.script.on(
        "entrypoint-finney.opentensor.ai",
        Some("\"method\":\"state_getStorage\""),
        vec![Reply::result(&json!(account_entry(8)))],
    );
    let alone = rig.history(tao_history(&state, "3999875000")).await;
    assert_eq!(items(&alone)[0]["status"], "pending", "{alone}");
    // A second operator says it did not: two operators that differ settle nothing either (a third
    // outvotes one liar, and here there is none).
    rig.script.on(
        "onfinality.io",
        Some("\"method\":\"state_getStorage\""),
        vec![Reply::result(&json!(account_entry(7)))],
    );
    let split = rig.history(tao_history(&alone["state"], "3999875000")).await;
    assert_eq!(items(&split)[0]["status"], "pending", "{split}");
}

#[tokio::test]
async fn a_send_without_a_nonce_in_the_note_takes_the_one_the_broadcast_recorded() {
    // The apps tell the client the sender and the nonce with a broadcast, and the note comes right after:
    // the note finds it by the hash. (Here the record is handed in, as a restarted app does.)
    let rig = rig();
    let at = rig.script.seen().len();
    assert_eq!(at, 0);
    rig.client.import_sent(&format!(r#"{{"v":1,"n":[],"h":[["{}",1793145600000,"7"]]}}"#, hash(9)));
    let state = sent_tao(&rig, None).await;
    rig.script.advance(300_000);
    chain_nonce(&rig, 7);
    let waiting = rig.history(tao_history(&state, "5000000000")).await;
    assert_eq!(items(&waiting)[0]["status"], "pending", "{waiting}");
    chain_nonce(&rig, 8);
    let settled = rig.history(tao_history(&waiting["state"], "3999875000")).await;
    assert_eq!(items(&settled)[0]["status"], "confirmed", "{settled}");
}

#[tokio::test]
async fn a_bittensor_note_nobody_gave_a_nonce_stays_pending_and_is_forgotten_after_three_days() {
    let rig = rig();
    let state = sent_tao(&rig, None).await;
    // Nothing can say whether it came in: it is neither confirmed nor failed by a timer.
    rig.script.advance(3_600_000);
    chain_nonce(&rig, 9);
    let hour = rig.history(tao_history(&state, "3999875000")).await;
    assert_eq!(items(&hour)[0]["status"], "pending", "{hour}");
    rig.script.advance(3 * 86_400_000);
    let days = rig.history(tao_history(&hour["state"], "3999875000")).await;
    assert!(items(&days).is_empty(), "{days}");
}

#[tokio::test]
async fn a_nonce_a_note_or_a_node_makes_up_is_no_nonce() {
    let rig = rig();
    let first = rig
        .history(json!({ "network": "bittensor", "address": TAO, "balance": "5000000000" }))
        .await;
    for nonce in [json!(-1), json!(4_294_967_296_u64), json!("1e30"), json!(u64::MAX), json!([1])] {
        let error = rig
            .op(
                "history_note",
                json!({ "network": "bittensor", "address": TAO, "state": first["state"], "sent": {
                    "hash": hash(9), "asset": "TAO", "amount": "1", "decimals": 9,
                    "to": TAO_FRIEND, "nonce": nonce,
                } }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "invalid_request", "{nonce}");
    }
    // A node that writes the largest number for the account's nonce settles a send that used a small
    // one (it says it came in), and one that used the largest is not passed (nothing is past it).
    let state = sent_tao(&rig, Some(u32::MAX)).await;
    rig.script.advance(1_000_000);
    chain_nonce(&rig, u32::MAX);
    let said = rig.history(tao_history(&state, "5000000000")).await;
    assert_eq!(items(&said)[0]["status"], "failed", "{said}");
}

// ---- TRON ---------------------------------------------------------------------------

const TRON_ME: &str = "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb";
const TRON_YOU: &str = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9";
const TRON_USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

fn tron_hex(address: &str) -> String {
    hex::encode(nc_wallet_core::tron::parse_address(address).unwrap())
}

#[tokio::test]
async fn tron_is_read_from_two_lists_and_a_calls_fee_goes_to_its_transfer() {
    let rig = rig();
    let transaction = |id: &str, ms: u64, kind: &str, value: &Value, fee: u64| {
        json!({
            "txID": id, "block_timestamp": ms, "blockNumber": 100,
            "ret": [{ "contractRet": "SUCCESS", "fee": fee }],
            "raw_data": { "contract": [{ "type": kind, "parameter": { "value": value } }] },
        })
    };
    let trx_in = json!({
        "owner_address": tron_hex(TRON_YOU), "to_address": tron_hex(TRON_ME), "amount": 5_000_000,
    });
    let call =
        json!({ "owner_address": tron_hex(TRON_ME), "contract_address": tron_hex(TRON_USDT) });
    rig.script.on(
        "/transactions/trc20",
        None,
        vec![Reply::json(&json!({ "success": true, "data": [{
            "transaction_id": "t2", "block_timestamp": 1_792_900_000_000_u64,
            "from": TRON_ME, "to": TRON_YOU, "value": "7000000",
            "token_info": { "address": TRON_USDT, "decimals": 6, "symbol": "USDT" },
        }] }))],
    );
    rig.script.on(
        "/transactions?",
        None,
        vec![Reply::json(&json!({ "success": true, "data": [
            transaction("t2", 1_792_900_000_000, "TriggerSmartContract", &call, 6_000_000),
            transaction("t1", 1_792_800_000_000, "TransferContract", &trx_in, 0),
        ] }))],
    );

    let answer = rig.history(json!({ "network": "tron", "address": TRON_ME })).await;
    assert_eq!(hashes(&answer), ["t2", "t1"], "the call and its transfer are one item");
    let usdt = &items(&answer)[0];
    assert_eq!(
        (usdt["asset"].as_str(), usdt["direction"].as_str(), usdt["amount"].as_str()),
        (Some("USDT"), Some("out"), Some("7000000"))
    );
    assert_eq!(usdt["fee"], json!({ "asset": "TRX", "amount": "6000000", "decimals": 6 }));
    let trx = &items(&answer)[1];
    assert_eq!((trx["asset"].as_str(), trx["direction"].as_str()), (Some("TRX"), Some("in")));
    assert!(trx["fee"].is_null(), "someone else paid");
    // Both lists came back short: nothing older exists.
    assert_eq!(answer["coverage"]["kind"], "full");
    assert_eq!(answer["coverage"]["complete"], true);
    assert!(answer["next_cursor"].is_null());
    // Only the history endpoint was asked.
    assert!(rig.script.seen().iter().all(|s| s.url.contains("/v1/accounts/")));
}

#[tokio::test]
async fn a_bot_challenge_is_told_and_not_gone_round() {
    let rig = rig();
    rig.script.on(
        "",
        None,
        vec![Reply::Http {
            status: 403,
            headers: vec![("cf-mitigated".into(), "challenge".into())],
            body: b"<html><title>Just a moment...</title></html>".to_vec(),
        }],
    );
    let answer = rig.history(json!({ "network": "tron", "address": TRON_ME })).await;
    assert_eq!(answer["unavailable"], "history_source_blocked");
    assert!(items(&answer).is_empty());
    let asked = rig.script.seen().len();
    // Asking again does not knock on the same door.
    let again = rig.history(json!({ "network": "tron", "address": TRON_ME })).await;
    assert_eq!(again["unavailable"], "history_source_blocked");
    assert_eq!(rig.script.seen().len(), asked, "a challenged endpoint is left alone");
}

// ---- Bitcoin ------------------------------------------------------------------------

// BIP-84's "abandon … about" wallet.
const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
const R0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const R1: &str = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
const C0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";
const EXT: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

fn txid(n: u64) -> String {
    format!("{n:064x}")
}

fn btc_tx(n: u64, ins: &[(&str, u64)], outs: &[(&str, u64)], fee: u64, when: Option<u64>) -> Value {
    json!({
        "txid": txid(n), "fee": fee,
        "status": when.map_or_else(
            || json!({ "confirmed": false }),
            |t| json!({ "confirmed": true, "block_height": 900_000 + n, "block_time": t }),
        ),
        "vin": ins.iter().map(|(a, v)| json!({ "prevout": { "scriptpubkey_address": a, "value": v } })).collect::<Vec<_>>(),
        "vout": outs.iter().map(|(a, v)| json!({ "scriptpubkey_address": a, "value": v })).collect::<Vec<_>>(),
    })
}

fn stats(count: u64) -> Value {
    json!({ "chain_stats": { "tx_count": count }, "mempool_stats": { "tx_count": 0 } })
}

/// Esplora, for a wallet whose first two receive addresses and first change address are used.
fn esplora(rig: &Rig, mempool: &[Value]) {
    let s = &rig.script;
    s.get("/blocks/tip/height", &json!(900_050));
    // 1: paid in. 2: spent, a payment and change. 3: paid in to the second address.
    let paid_in = btc_tx(1, &[(EXT, 120_000)], &[(R0, 100_000)], 500, Some(1_790_000_000));
    let spent =
        btc_tx(2, &[(R0, 100_000)], &[(EXT, 30_000), (C0, 69_000)], 1_000, Some(1_791_000_000));
    let second = btc_tx(3, &[(EXT, 60_000)], &[(R1, 50_000)], 500, Some(1_792_000_000));
    s.get(&format!("/address/{R0}/txs"), &json!([spent, paid_in]));
    s.get(&format!("/address/{C0}/txs"), &json!([spent]));
    let mut at_r1 = mempool.to_vec();
    at_r1.push(second);
    s.get(&format!("/address/{R1}/txs"), &json!(at_r1));
    s.get("/txs", &json!([]));
    s.get(&format!("/address/{R0}"), &stats(2));
    s.get(&format!("/address/{R1}"), &stats(1));
    s.get(&format!("/address/{C0}"), &stats(1));
    s.get("/address/", &stats(0));
}

#[tokio::test]
async fn bitcoin_is_one_history_for_the_account_found_from_its_zpub() {
    let rig = rig();
    esplora(&rig, &[]);
    let answer = rig
        .history(json!({ "network": "bitcoin", "address": R0, "zpub": ZPUB, "limit": 50 }))
        .await;
    // Newest first. The payment out is what left the account, its change is not counted, and
    // the fee is shown since the account paid it. Each transaction is one item although two
    // of the account's addresses saw it.
    assert_eq!(hashes(&answer), [txid(3), txid(2), txid(1)]);
    let get = |n: usize, key: &str| items(&answer)[n][key].clone();
    assert_eq!((get(0, "direction"), get(0, "amount")), (json!("in"), json!("50000")));
    assert_eq!(get(0, "counterparty"), json!(EXT));
    assert_eq!((get(1, "direction"), get(1, "amount")), (json!("out"), json!("30000")));
    assert_eq!(get(1, "fee"), json!({ "asset": "BTC", "amount": "1000", "decimals": 8 }));
    assert_eq!(get(1, "counterparty"), json!(EXT));
    assert_eq!(
        (get(2, "direction"), get(2, "amount"), get(2, "fee")),
        (json!("in"), json!("100000"), Value::Null)
    );
    assert_eq!(get(1, "confirmations"), json!(49), "900,050 is the tip, 900,002 the block");
    assert_eq!(answer["coverage"]["kind"], "full");
    assert_eq!(answer["coverage"]["complete"], true);
    assert!(answer["next_cursor"].is_null());
    // The walk stopped at the gap limit: it looked at 20 unused addresses of each chain
    // after the last used one, no more.
    let looked_at = rig
        .script
        .seen()
        .iter()
        .filter(|s| s.url.contains("/address/bc1q") && !s.url.contains("/txs"))
        .count();
    assert!((40..=50).contains(&looked_at), "{looked_at}");
}

#[tokio::test]
async fn without_a_zpub_only_the_addresses_named_are_the_account() {
    let rig = rig();
    esplora(&rig, &[]);
    let answer = rig
        .history(json!({ "network": "bitcoin", "address": R0, "addresses": [C0], "limit": 50 }))
        .await;
    assert_eq!(hashes(&answer), [txid(2), txid(1)], "the second receive address is not known");
    assert_eq!(answer["coverage"]["complete"], true);
}

#[tokio::test]
async fn a_pending_payment_keeps_its_time_and_goes_when_the_mempool_drops_it() {
    let up = rig();
    let waiting = btc_tx(4, &[(EXT, 30_000)], &[(R1, 20_000)], 400, None);
    esplora(&up, &[waiting]);
    let request = |state: &Value| json!({ "network": "bitcoin", "address": R0, "zpub": ZPUB, "state": state });
    let first = up.history(request(&Value::Null)).await;
    let pending = items(&first).iter().find(|i| i["hash"] == txid(4).as_str()).unwrap();
    assert_eq!(
        (pending["status"].as_str(), pending["confirmations"].as_u64()),
        (Some("pending"), Some(0))
    );
    let first_seen = pending["time"].clone();

    // Ten minutes on it is still there, and still dated by when it was first seen.
    up.script.advance(600_000);
    let later = up.history(request(&first["state"])).await;
    let still = items(&later).iter().find(|i| i["hash"] == txid(4).as_str()).unwrap();
    assert_eq!(still["time"], first_seen);

    // A day on, another session: the mempool no longer has it.
    let after = rig();
    esplora(&after, &[]);
    after.script.advance(86_400_000);
    let dropped = after.history(request(&later["state"])).await;
    assert!(!hashes(&dropped).contains(&txid(4)), "{:?}", hashes(&dropped));
    assert_eq!(items(&dropped).len(), 3);
}

// ---- Stellar ------------------------------------------------------------------------

const XLM_ME: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7";
const XLM_YOU: &str = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H";

fn payment(n: u64) -> Value {
    let (from, to) = if n.is_multiple_of(2) { (XLM_ME, XLM_YOU) } else { (XLM_YOU, XLM_ME) };
    json!({
        "type": "payment", "paging_token": format!("{}", n * 100), "transaction_successful": true,
        "created_at": format!("2026-10-26T14:{n:02}:00Z"), "transaction_hash": format!("h{n}"),
        "source_account": from, "from": from, "to": to, "amount": "5.0000000", "asset_type": "native",
        "transaction": { "ledger": 7000 + n, "fee_account": from, "fee_charged": "100" },
    })
}

const HORIZON: &str = "limit=40&join=transactions&include_failed=true";

/// Horizon answering `query` with payments `numbers`, newest first when read backwards.
fn horizon(rig: &Rig, query: &str, numbers: std::ops::RangeInclusive<u64>, backwards: bool) {
    let mut records: Vec<Value> = numbers.map(payment).collect();
    if backwards {
        records.reverse();
    }
    rig.script.on(
        &format!("/accounts/{XLM_ME}/payments?{query}"),
        None,
        vec![Reply::json(&json!({ "_embedded": { "records": records } }))],
    );
}

#[tokio::test]
async fn stellar_is_read_a_page_at_a_time_back_and_then_forward() {
    let rig = rig();
    // 45 payments: the newest 40 are the first page, the other five the page before it.
    horizon(&rig, &format!("order=desc&{HORIZON}&cursor=600"), 1..=5, true);
    horizon(&rig, &format!("order=desc&{HORIZON}"), 6..=45, true);
    let request = |state: &Value, cursor: &Value, limit: u64| {
        json!({ "network": "stellar", "address": XLM_ME, "state": state, "cursor": cursor,
                "limit": limit, "mode": if cursor.is_null() { "newest" } else { "page" } })
    };

    let first = rig.history(request(&Value::Null, &Value::Null, 10)).await;
    assert_eq!(items(&first).len(), 10);
    assert_eq!(items(&first)[0]["hash"], "h45");
    let top = &items(&first)[0];
    assert_eq!((top["direction"].as_str(), top["fee"].clone()), (Some("in"), Value::Null));
    assert_eq!(items(&first)[1]["fee"], json!({ "asset": "XLM", "amount": "100", "decimals": 7 }));
    assert_eq!(first["coverage"]["kind"], "full");
    assert_eq!(first["coverage"]["complete"], false, "the oldest page is not read yet");
    assert_eq!(first["coverage"]["scanning"], true);
    assert!(first["next_cursor"].is_string());
    assert_eq!(rig.script.count("/payments?"), 1, "only the page that was wanted");

    // Showing more than it has reads the page before.
    let rest = rig.history(request(&first["state"], &first["next_cursor"], 40)).await;
    assert_eq!(items(&rest).len(), 35);
    assert_eq!(items(&rest)[0]["hash"], "h35");
    assert_eq!(items(&rest)[34]["hash"], "h1");
    assert_eq!(rest["coverage"]["complete"], true);
    assert!(rest["next_cursor"].is_null());

    // A payment that comes later is read from the newest token on.
    horizon(&rig, &format!("order=asc&{HORIZON}&cursor=4500"), 46..=46, false);
    let newer = rig.history(request(&rest["state"], &Value::Null, 5)).await;
    assert_eq!(hashes(&newer), ["h46", "h45", "h44", "h43", "h42"]);
}

// ---- Solana -------------------------------------------------------------------------

const SOL_ME: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
const SOL_YOU: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

fn sol_tx(keys: &[&str], pre: &[u64], post: &[u64], fee: u64, time: u64) -> Value {
    json!({
        "slot": 77, "blockTime": time,
        "transaction": { "message": { "accountKeys": keys.iter().map(|k| json!({ "pubkey": k })).collect::<Vec<_>>() } },
        "meta": { "err": null, "fee": fee, "preBalances": pre, "postBalances": post,
                  "preTokenBalances": [], "postTokenBalances": [] },
    })
}

#[tokio::test]
async fn solana_lists_signatures_then_reads_what_each_did_to_the_account() {
    let rig = rig();
    let s = &rig.script;
    s.rpc(
        "getSignaturesForAddress",
        &json!([
            { "signature": "sigC", "slot": 79, "err": null, "blockTime": 1_792_900_000 },
            { "signature": "sigB", "slot": 78, "err": null, "blockTime": 1_792_800_000 },
            { "signature": "sigA", "slot": 77, "err": null, "blockTime": 1_792_700_000 },
        ]),
    );
    // A: 2 SOL in. B: 0.5 SOL out and 5,000 of fee. C: a transaction that moved nothing of ours.
    s.on(
        "",
        Some("\"sigA\""),
        vec![Reply::result(&sol_tx(
            &[SOL_YOU, SOL_ME],
            &[9_000_000_000, 0],
            &[6_999_995_000, 2_000_000_000],
            5_000,
            1_792_700_000,
        ))],
    );
    s.on(
        "",
        Some("\"sigB\""),
        vec![Reply::result(&sol_tx(
            &[SOL_ME, SOL_YOU],
            &[2_000_000_000, 0],
            &[1_499_995_000, 500_000_000],
            5_000,
            1_792_800_000,
        ))],
    );
    s.on(
        "",
        Some("\"sigC\""),
        vec![Reply::result(&sol_tx(
            &[SOL_YOU, "Vote111111111111111111111111111111111111111"],
            &[5_000_000_000, 1],
            &[4_999_995_000, 1],
            5_000,
            1_792_900_000,
        ))],
    );

    let answer = rig.history(json!({ "network": "solana", "address": SOL_ME })).await;
    assert_eq!(hashes(&answer), ["sigB", "sigA"], "what moved nothing of ours is not shown");
    let out = &items(&answer)[0];
    assert_eq!(
        (out["direction"].as_str(), out["amount"].as_str(), out["asset"].as_str()),
        (Some("out"), Some("500000000"), Some("SOL"))
    );
    assert_eq!(out["fee"], json!({ "asset": "SOL", "amount": "5000", "decimals": 9 }));
    assert_eq!(out["counterparty"], SOL_YOU);
    assert_eq!(items(&answer)[1]["direction"], "in");
    assert_eq!(answer["coverage"]["kind"], "full");
    assert_eq!(answer["coverage"]["complete"], true);
    assert_eq!(s.count("getSignaturesForAddress"), 1);

    // Asked again with the state: only what is newer than its newest signature.
    let again = rig
        .history(json!({ "network": "solana", "address": SOL_ME, "state": answer["state"] }))
        .await;
    assert_eq!(hashes(&again), ["sigB", "sigA"]);
    assert!(s.seen().iter().any(|r| r.body.contains("\"until\":\"sigC\"")));
}

// ---- a second operator's agreement ----

fn fresh() -> Rig {
    rig()
}

/// The receipt a node gives for the transfer of `log(USDT, FRIEND, ME, 5_000_000, 19_999_000, 1, ..)`.
fn receipt_of_the_usdt_payment(amount: u128, block: u64) -> Value {
    json!({
        "status": "0x1", "blockNumber": format!("0x{block:x}"),
        "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00",
        "logs": [{
            "address": USDT, "topics": [TRANSFER, topic(FRIEND), topic(ME)],
            "data": format!("0x{amount:064x}"),
        }],
    })
}

#[tokio::test]
async fn a_payment_received_is_confirmed_only_when_two_operators_have_it() {
    let request = |state: &Value| json!({ "network": "ethereum", "address": ME, "state": state });
    let received = [log(USDT, FRIEND, ME, 5_000_000, 19_999_000, 1, 1_792_900_000)];

    // Every operator gives the receipt of that payment: confirmed, and kept so.
    let rig = fresh();
    chain(&rig, &received, &[]);
    rig.script.on_first(
        "",
        Some("\"method\":\"eth_getTransactionReceipt\""),
        vec![Reply::result(&receipt_of_the_usdt_payment(5_000_000, 19_999_000))],
    );
    let first = rig.history(json!({ "network": "ethereum", "address": ME })).await;
    let top = &items(&first)[0];
    assert_eq!(top["status"], "confirmed", "{top}");
    assert_eq!(top.get("unverified"), None);
    // Asked again with the state, it is not asked a second time.
    let before = rig.script.count("eth_getTransactionReceipt");
    let again = rig.history(request(&first["state"])).await;
    assert_eq!(items(&again)[0]["status"], "confirmed");
    assert_eq!(rig.script.count("eth_getTransactionReceipt"), before, "checked once");

    // The receipt says another amount (or another block): not the payment the source described.
    for receipt in [
        receipt_of_the_usdt_payment(4_000_000, 19_999_000),
        receipt_of_the_usdt_payment(5_000_000, 19_999_001),
    ] {
        let rig = fresh();
        chain(&rig, &received, &[]);
        rig.script.on_first("", Some("eth_getTransactionReceipt"), vec![Reply::result(&receipt)]);
        let answer = rig.history(json!({ "network": "ethereum", "address": ME })).await;
        let top = &items(&answer)[0];
        assert_eq!(
            (top["status"].as_str(), top["unverified"].as_bool()),
            (Some("pending"), Some(true))
        );
        assert_eq!(top["reported"], "confirmed");
    }

    // No operator has a receipt for it (the listing alone claims it): unverified.
    let rig = fresh();
    chain(&rig, &received, &[]);
    rig.script.on_first("", Some("eth_getTransactionReceipt"), vec![Reply::result(&Value::Null)]);
    let answer = rig.history(json!({ "network": "ethereum", "address": ME })).await;
    assert_eq!(items(&answer)[0]["unverified"], true);
}
