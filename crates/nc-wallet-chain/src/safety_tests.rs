//! The bounds that hold when endpoints lie or break: figures that move money come from
//! independent operators or stay within the wallet's own limits, a contract's words never
//! switch an endpoint's method off, and a site's calls cannot teach the pool anything about
//! the wallet's own reads. Every answer here is scripted; no network.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::client::ChainClient;
use crate::testing::{Reply, Script};

const ME: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const GWEI: u128 = 1_000_000_000;

struct Rig {
    script: Arc<Script>,
    client: ChainClient,
}

fn rig() -> Rig {
    let script = Arc::new(Script::new());
    let client = ChainClient::new(script.clone());
    Rig { script, client }
}

fn hex(n: u128) -> Value {
    json!(format!("0x{n:x}"))
}

/// The hosts of Ethereum's endpoints, by operator.
const PUBLICNODE: [&str; 2] = ["ethereum-rpc.publicnode.com", "ethereum.publicnode.com"];
const DRPC: &str = "eth.drpc.org";
const TENDERLY: &str = "gateway.tenderly.co";

impl Rig {
    /// Makes `host` answer the fee market and the nonce: a next base fee, a tip, a pending count.
    fn eth_host(&self, host: &str, base_gwei: u128, tip_gwei: u128, nonce: u64) -> &Self {
        let s = &self.script;
        let on = |method: &str, result: Value| {
            s.on(host, Some(&format!("\"method\":\"{method}\"")), vec![Reply::result(&result)]);
        };
        on(
            "eth_feeHistory",
            json!({ "baseFeePerGas": [hex(base_gwei * GWEI), hex(base_gwei * GWEI)], "gasUsedRatio": [0.5], "oldestBlock": "0x1" }),
        );
        on("eth_maxPriorityFeePerGas", hex(tip_gwei * GWEI));
        on("eth_getTransactionCount", hex(u128::from(nonce)));
        self
    }

    async fn inputs(&self) -> Result<Value, Value> {
        self.client
            .dispatch("inputs", &json!({ "network": "ethereum", "address": ME }))
            .await
            .map_err(|e| e.to_value())
    }
}

fn message(error: &Value) -> String {
    error["message"].as_str().unwrap_or_default().to_owned()
}

// ---- #2: independent operators ----

#[tokio::test]
async fn two_hosts_of_one_operator_are_not_two_opinions() {
    let r = rig();
    for host in PUBLICNODE {
        r.eth_host(host, 20, 1, 7);
    }
    // Nobody else answers: a nonce vouched for by PublicNode alone is not confirmed.
    let error = r.inputs().await.unwrap_err();
    assert_eq!(error["code"], "estimate_failed");
    assert!(message(&error).contains("could not be confirmed"), "{error}");
    assert_eq!(error["retryable"], true);
    assert!(!message(&error).to_lowercase().contains("gas"));
}

#[tokio::test]
async fn two_operators_that_agree_give_a_confirmed_nonce_and_fee() {
    let r = rig();
    r.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 21, 1, 7);
    let inputs = r.inputs().await.unwrap();
    assert_eq!(inputs["nonce"], 7);
    // Twice the higher base fee, and the tip.
    assert_eq!(inputs["max_fee"], json!((2 * 21 * GWEI + GWEI).to_string()));
}

#[tokio::test]
async fn nonces_that_disagree_are_never_settled_by_taking_the_lower() {
    let r = rig();
    // 7 and 8, and nobody to break the tie: not 7 (which would replace the person's own pending
    // transaction), not 8 (a gap if the lagging one is right): ask again.
    r.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 20, 1, 8);
    let error = r.inputs().await.unwrap_err();
    assert!(message(&error).contains("could not be confirmed"), "{error}");
    // A third operator that sides with the higher settles it.
    r.eth_host(TENDERLY, 20, 1, 8);
    let r2 = rig();
    r2.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 20, 1, 8).eth_host(TENDERLY, 20, 1, 8);
    assert_eq!(r2.inputs().await.unwrap()["nonce"], 8);
}

#[tokio::test]
async fn a_fee_above_the_wallets_ceiling_is_refused_whoever_agrees() {
    let r = rig();
    // 3,000 gwei: far past Ethereum's 1,000. Two operators agree and it is refused, not clamped.
    r.eth_host(PUBLICNODE[0], 3_000, 1, 7).eth_host(DRPC, 3_000, 1, 7);
    let error = r.inputs().await.unwrap_err();
    assert_eq!(error["code"], "estimate_failed");
    assert!(message(&error).contains("above the most this wallet will pay"), "{error}");
    assert_eq!(error["retryable"], false);
}

#[tokio::test]
async fn one_operators_high_fee_cannot_stand_alone() {
    // Past the 150 gwei a lone operator may quote, inside the 1,000 ceiling: a second must agree.
    let r = rig();
    r.eth_host(PUBLICNODE[0], 400, 1, 7).eth_host(DRPC, 20, 1, 7);
    // The two fee readings (400 and 20 gwei) are not within a quarter: unconfirmed, not 400.
    let error = r.inputs().await.unwrap_err();
    assert!(message(&error).contains("could not be confirmed"), "{error}");
    // Both at 400: confirmed, used.
    let r = rig();
    r.eth_host(PUBLICNODE[0], 400, 1, 7).eth_host(DRPC, 400, 1, 7);
    assert!(r.inputs().await.is_ok());
}

#[tokio::test]
async fn a_liar_among_three_is_outvoted() {
    let r = rig();
    r.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 20_000, 1, 7).eth_host(TENDERLY, 21, 1, 7);
    let inputs = r.inputs().await.unwrap();
    assert_eq!(inputs["max_fee"], json!((2 * 21 * GWEI + GWEI).to_string()));
}

// ---- #4: the wallet's own record of what it sent ----

#[tokio::test]
async fn the_next_nonce_is_never_below_one_past_the_last_sent_while_endpoints_catch_up() {
    let r = rig();
    // Endpoints still say 7 after nonce 7 was sent a moment ago.
    r.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 20, 1, 7);
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(host, Some("eth_sendRawTransaction"), vec![Reply::result(&json!("0xabc"))]);
    }
    r.client
        .dispatch(
            "broadcast",
            &json!({ "network": "ethereum", "raw": "02c0", "encoding": "hex", "from": ME, "nonce": 7 }),
        )
        .await
        .unwrap();
    assert_eq!(r.inputs().await.unwrap()["nonce"], 8);
    // Ten minutes on, the record is forgotten: a dropped transaction frees its number.
    r.script.advance(crate::sent::FOR_MS + 1);
    r.script.on(PUBLICNODE[0], Some("eth_getTransactionCount"), vec![Reply::result(&hex(7))]);
    assert_eq!(r.inputs().await.unwrap()["nonce"], 7);
}

#[tokio::test]
async fn removing_the_wallet_forgets_what_it_sent() {
    let r = rig();
    r.eth_host(PUBLICNODE[0], 20, 1, 7).eth_host(DRPC, 20, 1, 7);
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(host, Some("eth_sendRawTransaction"), vec![Reply::result(&json!("0xabc"))]);
    }
    r.client
        .dispatch(
            "broadcast",
            &json!({ "network": "ethereum", "raw": "02c0", "from": ME, "nonce": "7" }),
        )
        .await
        .unwrap();
    r.client.forget_everything();
    assert_eq!(r.inputs().await.unwrap()["nonce"], 7);
}

// ---- #1: a contract's words, and a site's, teach the pool nothing ----

const POLYGON_HOSTS: [&str; 3] =
    ["polygon-bor-rpc.publicnode.com", "polygon.drpc.org", "polygon.gateway.tenderly.co"];
const WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

fn site_call(data: &str) -> Value {
    json!({ "network": "polygon", "request": {
        "jsonrpc": "2.0", "id": 9, "method": "eth_call",
        "params": [{ "to": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "data": data }, "latest"],
    } })
}

fn polygon_balances_work(r: &Rig) {
    for host in POLYGON_HOSTS {
        r.script.on(host, Some("eth_getBalance"), vec![Reply::result(&json!("0x10"))]);
        // Whatever else is called (the multicall, a token's balance) answers a single word.
        r.script.on(host, Some("\"method\":\"eth_call\""), vec![Reply::result(&json!(WORD))]);
    }
}

async fn wallet_reads_polygon(r: &Rig) -> Value {
    r.client
        .dispatch("balances", &json!({ "network": "polygon", "address": ME, "fresh": true }))
        .await
        .unwrap_or_else(|e| panic!("the wallet's own balances failed: {}", e.to_value()))
}

#[tokio::test]
async fn a_revert_with_alarming_words_is_handed_back_and_switches_nothing_off() {
    let r = rig();
    for host in POLYGON_HOSTS {
        // The site's call reverts with words that look like an endpoint's problem.
        r.script.on(
            host,
            Some("0xdeadbeef"),
            vec![Reply::error(3, "execution reverted: transfers not allowed")],
        );
    }
    polygon_balances_work(&r);
    for _ in 0..6 {
        let answer = r.client.dispatch("rpc", &site_call("0xdeadbeef")).await.unwrap();
        // The reason reaches the site as the node wrote it.
        assert_eq!(answer["error"]["code"], 3);
        assert_eq!(answer["error"]["message"], "execution reverted: transfers not allowed");
    }
    // The wallet's own reads still work: eth_call is on, on all three.
    let balances = wallet_reads_polygon(&r).await;
    assert_eq!(balances["balances"][0]["asset"], "POL");
}

#[tokio::test]
async fn the_words_a_site_can_make_a_node_echo_do_not_switch_methods_off() {
    let r = rig();
    for host in POLYGON_HOSTS {
        r.script.on(
            host,
            Some("0xbad0"),
            vec![Reply::error(
                -32602,
                "invalid argument 1: rate limit; method not found; disabled; forbidden",
            )],
        );
    }
    polygon_balances_work(&r);
    for _ in 0..6 {
        r.client.dispatch("rpc", &site_call("0xbad0")).await.unwrap();
    }
    wallet_reads_polygon(&r).await;
}

#[tokio::test]
async fn a_revert_in_the_wallets_own_estimate_is_the_contracts_verdict_not_the_endpoints() {
    // A send to a contract whose revert says "disabled" must not take eth_estimateGas off, and the
    // person is told the reason.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC, TENDERLY] {
        r.eth_host(host, 20, 1, 7);
        r.script.on(host, Some("eth_getCode"), vec![Reply::result(&json!("0x6001"))]);
        r.script.on(
            host,
            Some("eth_estimateGas"),
            vec![Reply::error(3, "execution reverted: disabled")],
        );
    }
    let request = json!({
        "network": "ethereum", "from": ME, "to": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
        "asset": "ETH", "amount": "1000",
    });
    for _ in 0..4 {
        let error = r.client.dispatch("estimate", &request).await.unwrap_err().to_value();
        assert_eq!(error["code"], "estimate_failed");
        assert!(message(&error).contains("disabled"), "{error}");
    }
    // Every attempt reached an endpoint: none was switched off.
    assert!(r.script.count("eth_estimateGas") >= 4);
}

// ---- #13: Solana tokens ----

const SOL_OWNER: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";

fn solana_amount(body: &Value, symbol: &str) -> Option<String> {
    body["balances"]
        .as_array()?
        .iter()
        .find(|e| e["asset"] == symbol)?
        .get("amount")?
        .as_str()
        .map(str::to_owned)
}

#[tokio::test]
async fn the_indexed_path_counts_only_an_account_of_the_mint_held_by_the_owner() {
    let r = rig();
    // An answer that lists two accounts the owner does not hold, or of another mint.
    let account = |mint: &str, owner: &str, amount: &str| {
        json!({ "pubkey": "11111111111111111111111111111112", "account": { "data": { "parsed": { "info": {
            "mint": mint, "owner": owner, "tokenAmount": { "amount": amount }
        } } } } })
    };
    r.script.rpc("getBalance", &json!({ "value": 5 }));
    r.script.rpc(
        "getTokenAccountsByOwner",
        &json!({ "value": [
            account("So11111111111111111111111111111111111111112", SOL_OWNER, "9"),
            account("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", "SomeoneElse1111111111111111111111111111111", "7"),
        ] }),
    );
    let body = r
        .client
        .dispatch("balances", &json!({ "network": "solana", "address": SOL_OWNER }))
        .await
        .unwrap();
    assert_eq!(solana_amount(&body, "USDT").as_deref(), Some("0"));
    assert_eq!(solana_amount(&body, "USDC").as_deref(), Some("0"));
}

#[tokio::test]
async fn a_token_that_cannot_be_read_does_not_stop_a_coin_send_being_prepared() {
    let r = rig();
    r.script.rpc(
        "getLatestBlockhash",
        &json!({ "value": { "blockhash": "F9YDb7X2fNnvX4x7U8RXLF3eLJfBwMVgcbnfVdZ4Sn9G", "lastValidBlockHeight": 5 } }),
    );
    r.script.rpc("getRecentPrioritizationFees", &json!([]));
    r.script.rpc("getMinimumBalanceForRentExemption", &json!(2_039_280));
    r.script.rpc_error(
        "getTokenAccountsByOwner",
        -32602,
        "Indexed requests require a personal token",
    );
    r.script.rpc_error("getMultipleAccounts", -32000, "node is having a moment");
    let inputs = r
        .client
        .dispatch("inputs", &json!({ "network": "solana", "address": SOL_OWNER }))
        .await
        .unwrap();
    assert!(inputs["blockhash"].is_string());
    assert_eq!(inputs["token_accounts"], json!([]));
    assert_eq!(inputs["token_accounts_unread"], json!(["USDT", "USDC"]));
}

// ---- #3: Bitcoin's rates ----

mod bitcoin_rates {
    use super::*;
    use crate::bitcoin::Bitcoin;
    use crate::networks::Network;

    const MEMPOOL: &str = "mempool.space/api/fee-estimates";
    const BLOCKSTREAM: &str = "blockstream.info/api/fee-estimates";
    const RECEIVE: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const TO: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    /// Esplora's `/fee-estimates`, as text (satoshis a virtual byte, by block target).
    fn estimates(sat_per_vb: &str) -> Reply {
        Reply::text(
            200,
            &format!(r#"{{"1": {sat_per_vb}, "3": {sat_per_vb}, "12": {sat_per_vb}}}"#),
        )
    }

    async fn rates(r: &Rig) -> Result<[u64; 3], Value> {
        Bitcoin::new(r.client.net(Network::Bitcoin))
            .rates()
            .await
            .map(|rates| rates.kvb)
            .map_err(|e| e.to_value())
    }

    #[tokio::test]
    async fn extreme_congestion_loses_the_speeds_past_the_ceiling_and_keeps_the_rest() {
        // Fast is past 1,000 sat/vB at both services; slow and normal are not: the reading is not
        // discarded, the fast speed is simply not offered.
        let body = |slow: &str, normal: &str, fast: &str| {
            Reply::text(200, &format!(r#"{{"1": {fast}, "3": {normal}, "12": {slow}}}"#))
        };
        let r = rig();
        r.script.on(MEMPOOL, None, vec![body("200", "400", "1500")]);
        r.script.on(BLOCKSTREAM, None, vec![body("220", "380", "1600")]);
        let rates = Bitcoin::new(r.client.net(Network::Bitcoin)).rates().await.unwrap();
        assert_eq!(rates.ok, [true, true, false]);
        assert_eq!(rates.kvb[..2], [220_000, 400_000]);
        // The inputs offer two speeds and the estimate gives the third no fee.
        r.script.on("/blocks/tip/height", None, vec![Reply::text(200, "1000")]);
        account_with(&r, &[]);
        let inputs = r
            .client
            .dispatch("inputs", &json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB }))
            .await
            .unwrap();
        let speeds: Vec<&str> =
            inputs["fee_rates"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(speeds, ["slow", "normal"]);
        // If the normal one is past it too, there is nothing to offer, and the answer says why.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![body("900", "1500", "2000")]);
        r.script.on(BLOCKSTREAM, None, vec![body("950", "1400", "2100")]);
        let error = Bitcoin::new(r.client.net(Network::Bitcoin)).rates().await.unwrap_err();
        assert!(matches!(error, crate::error::ChainError::OverCeiling(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_lie_of_fifty_thousand_satoshis_a_byte_is_not_believed() {
        // `{"1": 50000}` made a 0.07 BTC fee on a 0.5 BTC payment. A service quoting past the
        // wallet's ceiling is set aside as if it had not answered; the honest one stands alone.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("50000")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("12")]);
        assert_eq!(rates(&r).await.unwrap(), [12_000, 12_000, 12_000]);
    }

    #[tokio::test]
    async fn a_lie_inside_the_ceiling_but_far_from_the_other_service_is_not_reconciled() {
        // 800 sat/vB against 10: neither is believed over the other, and neither is used.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("800")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("10")]);
        let error = rates(&r).await.unwrap_err();
        assert!(message(&error).contains("could not be confirmed"), "{error}");
    }

    #[tokio::test]
    async fn two_services_that_roughly_agree_give_the_higher_and_one_alone_is_bounded() {
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("10")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("25")]);
        assert_eq!(rates(&r).await.unwrap(), [25_000, 25_000, 25_000]);
        // One alone, at 300 sat/vB: past the 100 a lone service may quote.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("300")]);
        let error = rates(&r).await.unwrap_err();
        assert!(message(&error).contains("could not be confirmed"), "{error}");
        // One alone, at 40: used.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("40")]);
        assert_eq!(rates(&r).await.unwrap(), [40_000, 40_000, 40_000]);
        // Both services agree on 1,500 sat/vB: refused, never clamped.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("1500")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("1500")]);
        assert!(rates(&r).await.is_err());
    }

    /// Esplora's statistics of an address: `received` satoshis confirmed and `waiting` in the mempool.
    fn stats(received: u64, waiting: u64) -> Reply {
        Reply::json(&json!({
            "chain_stats": { "funded_txo_sum": received, "spent_txo_sum": 0, "tx_count": u64::from(received > 0) },
            "mempool_stats": { "funded_txo_sum": waiting, "spent_txo_sum": 0, "tx_count": u64::from(waiting > 0) },
        }))
    }

    fn at(chain: nc_wallet_core::bitcoin::Chain, index: u32) -> String {
        nc_wallet_core::bitcoin::addresses_from_zpub(ZPUB, chain, index, 1).unwrap().remove(0)
    }

    /// An account whose addresses are looked up: `known` are (chain, index, confirmed, waiting); every
    /// other address is unused.
    fn account_with(r: &Rig, known: &[(nc_wallet_core::bitcoin::Chain, u32, u64, u64)]) {
        for &(chain, index, received, waiting) in known {
            r.script.on(
                &format!("/address/{}", at(chain, index)),
                None,
                vec![stats(received, waiting)],
            );
        }
        r.script.on("/address/", None, vec![stats(0, 0)]);
    }

    fn utxo_list(r: &Rig, chain: nc_wallet_core::bitcoin::Chain, index: u32, list: &Value) {
        // Before the general rule above: the first rule that fits answers.
        r.script.on_first(
            &format!("/address/{}/utxo", at(chain, index)),
            None,
            vec![Reply::json(list)],
        );
    }

    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[tokio::test]
    async fn an_estimate_spends_what_the_signer_spends() {
        use nc_wallet_core::bitcoin::Chain::{Change, Receive};
        // Money paid to the receive chain from outside is not spent until it is confirmed (the
        // signer skips it); the wallet's own unconfirmed change is. The estimate must say the same,
        // or compose succeeds and review fails.
        let utxo = |txid: &str, value: u64, confirmed: bool| json!({ "txid": txid, "vout": 0, "value": value, "status": { "confirmed": confirmed, "block_height": 1 } });
        let ask = || {
            json!({ "network": "bitcoin", "from": RECEIVE, "to": TO, "asset": "BTC",
                    "amount": "50000", "zpub": ZPUB })
        };
        // 5,000 confirmed and 100,000 unconfirmed from outside, both on receive 0: not enough to pay 50,000.
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("5")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
        utxo_list(&r, Receive, 0, &json!([utxo("aa", 5_000, true), utxo("bb", 100_000, false)]));
        account_with(&r, &[(Receive, 0, 5_000, 100_000)]);
        let error = r.client.dispatch("estimate", &ask()).await.unwrap_err().to_value();
        assert_eq!(error["code"], "insufficient_funds");
        // The same unconfirmed 100,000 as change (change 0) of a transaction this device did not send:
        // not spent either (it can be replaced before it is mined).
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("5")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
        utxo_list(&r, Receive, 0, &json!([utxo("aa", 5_000, true)]));
        utxo_list(&r, Change, 0, &json!([utxo("bb", 100_000, false)]));
        account_with(&r, &[(Receive, 0, 5_000, 0), (Change, 0, 0, 100_000)]);
        let error = r.client.dispatch("estimate", &ask()).await.unwrap_err().to_value();
        assert_eq!(error["code"], "insufficient_funds");
        // The same, as the wallet's own change (this device sent transaction `bb`): spendable.
        let r = rig();
        r.client.import_sent(r#"{"v":1,"n":[],"h":[["bb",1793145600000]]}"#);
        r.script.on(MEMPOOL, None, vec![estimates("5")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
        utxo_list(&r, Receive, 0, &json!([utxo("aa", 5_000, true)]));
        utxo_list(&r, Change, 0, &json!([utxo("bb", 100_000, false)]));
        account_with(&r, &[(Receive, 0, 5_000, 0), (Change, 0, 0, 100_000)]);
        let estimate = r.client.dispatch("estimate", &ask()).await.unwrap();
        assert_eq!(estimate["fee"]["asset"], "BTC");
    }

    #[tokio::test]
    async fn an_imported_wallet_is_found_whole_and_the_next_reading_is_cheap() {
        use nc_wallet_core::bitcoin::Chain::{Change, Receive};
        // Money at receive 0, 3 and 7 and at change 1 and 3: found by looking, summed, with the change
        // going to the next unused change address.
        let r = rig();
        account_with(
            &r,
            &[
                (Receive, 0, 10_000, 0),
                (Receive, 3, 20_000, 0),
                (Receive, 7, 30_000, 0),
                (Change, 1, 5_000, 0),
                (Change, 3, 7_000, 2_000),
            ],
        );
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let before = r.script.seen().len();
        let first = r.client.dispatch("balances", &ask).await.unwrap();
        let first_cost = r.script.seen().len() - before;
        let entry = &first["balances"][0];
        assert_eq!(entry["amount"], "74000");
        assert_eq!(entry["confirmed"], "72000");
        assert_eq!(entry["unconfirmed"], "2000");
        // 28 lookups for the receive chain (0 to 7 and twenty past it), 24 for the change chain, and one
        // more: the highest change address found used (3) is confirmed by a second service.
        assert_eq!(first_cost, 28 + 24 + 1);
        let bitcoin = &first["bitcoin"];
        assert_eq!(bitcoin["next_change"], 4);
        assert_eq!(bitcoin["hint"]["r"]["last"], 7);
        assert_eq!(
            bitcoin["hint"]["r"]["live"],
            json!([[0, 10_000, 0], [3, 20_000, 0], [7, 30_000, 0]])
        );
        assert_eq!(bitcoin["hint"]["c"]["last"], 3);
        assert_eq!(bitcoin["scanning"], false);

        // A new client (the app restarted) is handed the hint it kept: it asks about the five live addresses,
        // the shown one, and the window past the highest used: a few lookups, not fifty.
        let r2 = rig();
        account_with(
            &r2,
            &[
                (Receive, 0, 10_000, 0),
                (Receive, 3, 20_000, 0),
                (Receive, 7, 30_000, 0),
                (Change, 1, 5_000, 0),
                (Change, 3, 7_000, 2_000),
            ],
        );
        let mut with_hint = ask.clone();
        with_hint["hint"] = bitcoin["hint"].clone();
        let before = r2.script.seen().len();
        let again = r2.client.dispatch("balances", &with_hint).await.unwrap();
        let cost = r2.script.seen().len() - before;
        assert_eq!(again["balances"][0]["amount"], "74000");
        // Receive: 0, 3, 7 and the window 8 to 10; change: 1, 3 and the window 4 and 5.
        assert_eq!(cost, 6 + 4);
    }

    /// Esplora's statistics of an address that was funded and has been spent again.
    fn spent(received: u64) -> Reply {
        Reply::json(&json!({
            "chain_stats": { "funded_txo_sum": received, "spent_txo_sum": received, "tx_count": 2 },
            "mempool_stats": { "funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 0 },
        }))
    }

    #[tokio::test]
    async fn a_service_that_says_a_funded_address_is_empty_does_not_hide_its_coins() {
        use nc_wallet_core::bitcoin::Chain::Receive;
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let r = rig();
        account_with(&r, &[(Receive, 0, 10_000, 0), (Receive, 3, 20_000, 0)]);
        let first = r.client.dispatch("balances", &ask).await.unwrap();
        assert_eq!(first["balances"][0]["amount"], "30000");
        let mut again = ask.clone();
        again["hint"] = first["bitcoin"]["hint"].clone();
        let live3 = |body: &Value| {
            body["bitcoin"]["hint"]["r"]["live"].as_array().unwrap().iter().any(|l| l[0] == 3)
        };

        // The first service asked about receive 3 says it is empty (lagging, or lying); the second has the
        // coins: they stay, in the balance and in the hint.
        let r2 = rig();
        account_with(&r2, &[(Receive, 0, 10_000, 0)]);
        r2.script.on_first(
            &format!("/address/{}", at(Receive, 3)),
            None,
            vec![stats(0, 0), stats(20_000, 0)],
        );
        let body = r2.client.dispatch("balances", &again).await.unwrap();
        assert_eq!(body["balances"][0]["amount"], "30000");
        assert!(live3(&body));

        // Both say it was funded and spent: it is forgotten, as it should be.
        let r3 = rig();
        account_with(&r3, &[(Receive, 0, 10_000, 0)]);
        r3.script.on_first(&format!("/address/{}", at(Receive, 3)), None, vec![spent(20_000)]);
        let body = r3.client.dispatch("balances", &again).await.unwrap();
        assert_eq!(body["balances"][0]["amount"], "10000");
        assert!(!live3(&body));

        // The second service cannot be asked: the address is kept as it was, and asked again next time.
        let r4 = rig();
        account_with(&r4, &[(Receive, 0, 10_000, 0)]);
        r4.script.on_first(
            &format!("/address/{}", at(Receive, 3)),
            None,
            vec![stats(0, 0), Reply::text(500, "")],
        );
        let body = r4.client.dispatch("balances", &again).await.unwrap();
        assert_eq!(body["balances"][0]["amount"], "30000");
        assert!(live3(&body));
    }

    #[tokio::test]
    async fn a_hint_dated_in_the_future_is_checked_in_full() {
        use nc_wallet_core::bitcoin::Chain::Receive;
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let r = rig();
        account_with(&r, &[(Receive, 0, 10_000, 0), (Receive, 3, 20_000, 0)]);
        let first = r.client.dispatch("balances", &ask).await.unwrap();
        let hint = first["bitcoin"]["hint"].clone();
        let cost_of = |hint: Value| {
            let ask = ask.clone();
            async move {
                let r = rig();
                account_with(&r, &[(Receive, 0, 10_000, 0), (Receive, 3, 20_000, 0)]);
                let mut with = ask;
                with["hint"] = hint;
                let before = r.script.seen().len();
                r.client.dispatch("balances", &with).await.unwrap();
                r.script.seen().len() - before
            }
        };
        let now = 1_793_145_600_u64;
        // Made a moment ago: the few lookups of a refresh (0, 3, and the window past 3).
        let mut recent = hint.clone();
        recent["at"] = json!(now - 60);
        let cheap = cost_of(recent).await;
        assert!(cheap <= 8, "{cheap}");
        // Made ten days from now: it would never come due. It is read in full: every used address and the gap.
        let mut future = hint.clone();
        future["at"] = json!(now + 10 * 86_400);
        let full = cost_of(future).await;
        assert!(full >= 24, "{full}");
        // And a day old is the same.
        let mut old = hint;
        old["at"] = json!(now - 2 * 86_400);
        assert!(cost_of(old).await >= 24);
    }

    #[tokio::test]
    async fn a_service_that_says_a_far_change_address_is_used_does_not_push_the_change_ahead() {
        use nc_wallet_core::bitcoin::Chain::{Change, Receive};
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        // The first service asked says change 8 is used (with coins in it); the second says it is not. Where
        // the change goes is the address after the highest one *two* services agree is used.
        for second in [stats(0, 0), Reply::text(500, "")] {
            let r = rig();
            account_with(&r, &[(Receive, 0, 10_000, 0), (Change, 0, 5_000, 0)]);
            r.script.on_first(
                &format!("/address/{}", at(Change, 8)),
                None,
                vec![stats(1_000, 0), second],
            );
            let body = r.client.dispatch("balances", &ask).await.unwrap();
            assert_eq!(body["bitcoin"]["next_change"], 1, "not 9");
            assert_eq!(body["bitcoin"]["hint"]["c"]["last"], 0);
        }
        // Two services that agree move it.
        let r = rig();
        account_with(&r, &[(Receive, 0, 10_000, 0), (Change, 0, 5_000, 0), (Change, 2, 1_000, 0)]);
        let body = r.client.dispatch("balances", &ask).await.unwrap();
        assert_eq!(body["bitcoin"]["next_change"], 3);
    }

    #[tokio::test]
    async fn a_wallet_used_on_many_addresses_is_read_in_pieces_the_app_asks_again_for() {
        use nc_wallet_core::bitcoin::Chain::Receive;
        // Thirty-one receive addresses, all funded: more than one reading's time allows at the
        // pace the services are asked at. The first reading hands back what it found and says it
        // is still scanning; the next goes on from there with the hint, and the sum is whole.
        let r = rig();
        let known: Vec<_> = (0..31).map(|i| (Receive, i, 1_000, 0)).collect();
        account_with(&r, &known);
        let mut ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let mut calls = 0;
        let mut seen = r.script.seen().len();
        let last_body = loop {
            calls += 1;
            // (Not `fresh`: an unfinished reading is not kept, so asking again goes on.)
            let body = r.client.dispatch("balances", &ask).await.unwrap();
            // Each reading is bounded.
            assert!(r.script.seen().len() - seen <= 200, "call {calls}");
            seen = r.script.seen().len();
            ask["hint"] = body["bitcoin"]["hint"].clone();
            if body["bitcoin"]["scanning"] != true {
                break body;
            }
            assert!(calls < 10, "it never finishes");
        };
        assert!(calls >= 2, "it should have taken more than one reading, took {calls}");
        assert_eq!(last_body["balances"][0]["amount"], "31000");
        assert_eq!(last_body["bitcoin"]["hint"]["r"]["last"], 30);
    }

    #[tokio::test]
    async fn the_inputs_carry_where_each_output_is_and_the_next_unused_change_address() {
        use nc_wallet_core::bitcoin::Chain::{Change, Receive};
        let r = rig();
        r.script.on(MEMPOOL, None, vec![estimates("5")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
        r.script.on("/blocks/tip/height", None, vec![Reply::text(200, "1000")]);
        let utxo = |txid: &str, value: u64| json!({ "txid": txid, "vout": 0, "value": value, "status": { "confirmed": true, "block_height": 900 } });
        utxo_list(&r, Receive, 7, &json!([utxo("d1", 30_000)]));
        utxo_list(&r, Change, 3, &json!([utxo("d2", 40_000)]));
        account_with(&r, &[(Receive, 7, 30_000, 0), (Change, 3, 40_000, 0)]);
        let inputs = r
            .client
            .dispatch("inputs", &json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB }))
            .await
            .unwrap();
        let utxos = inputs["utxos"].as_array().unwrap();
        assert_eq!(utxos.len(), 2);
        // Largest first, each with its place and its address.
        assert_eq!(utxos[0]["value"], "40000");
        assert_eq!((utxos[0]["chain"].clone(), utxos[0]["index"].clone()), (json!(1), json!(3)));
        assert_eq!(utxos[0]["address"], at(Change, 3));
        assert_eq!((utxos[1]["chain"].clone(), utxos[1]["index"].clone()), (json!(0), json!(7)));
        assert_eq!(utxos[1]["address"], at(Receive, 7));
        // The change goes to change 4: the first change address nothing has used.
        assert_eq!(inputs["change"], json!({ "chain": 1, "index": 4, "address": at(Change, 4) }));
    }

    #[tokio::test]
    async fn the_account_is_named_by_its_zpub_and_by_nothing_else() {
        let r = rig();
        // An address that is not the zpub's first receive address; addresses given; no zpub.
        for ask in [
            json!({ "network": "bitcoin", "address": TO, "zpub": ZPUB }),
            json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB, "addresses": [TO] }),
            json!({ "network": "bitcoin", "address": RECEIVE }),
            json!({ "network": "bitcoin", "address": RECEIVE, "zpub": "zpub-not-a-key" }),
        ] {
            let error = r.client.dispatch("balances", &ask).await.unwrap_err().to_value();
            assert_eq!(error["code"], "invalid_request", "{ask}");
        }
    }

    #[tokio::test]
    async fn a_wallet_made_here_is_not_walked_and_one_used_a_day_ago_is_checked_again() {
        use nc_wallet_core::bitcoin::Chain::Receive;
        let r = rig();
        account_with(&r, &[(Receive, 0, 0, 0)]);
        let mut ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let now_s = crate::platform::Platform::now_ms(&*r.script) / 1000;
        ask["hint"] = crate::bitcoin::Hint::unused(now_s).to_json();
        let before = r.script.seen().len();
        r.client.dispatch("balances", &ask).await.unwrap();
        // The shown address and the window past nothing used: 3 receive and 2 change.
        assert_eq!(r.script.seen().len() - before, 5);
        // A hint a day old is read in full: the gap of twenty on each chain.
        let r = rig();
        account_with(&r, &[(Receive, 0, 0, 0)]);
        let mut old = ask.clone();
        old["hint"] = crate::bitcoin::Hint::unused(now_s - 86_401).to_json();
        let before = r.script.seen().len();
        r.client.dispatch("balances", &old).await.unwrap();
        assert_eq!(r.script.seen().len() - before, 40);
    }

    // ---- a service that writes the largest numbers there are ----

    /// What the estimate shows for each speed (`None`: no fee) and what the signing engine's planner
    /// makes of the same coins at the same rates, as (fee, inputs, change kept).
    #[allow(clippy::type_complexity)]
    async fn compose_and_sign(
        kvb: [u64; 3],
        utxos: &[u64],
        amount: u64,
    ) -> Vec<(Option<(u64, u64, u64)>, Option<(u64, u64, bool)>)> {
        use nc_wallet_core::bitcoin::{
            Amount,
            Chain::{Change, Receive},
            FeeRate, Request, Utxo, plan,
        };
        let r = rig();
        // Esplora writes satoshis a virtual byte: 1,640 a thousand is 1.64.
        let body = |kvb: [u64; 3]| {
            let text = |k: u64| format!("{}.{:03}", k / 1000, k % 1000);
            Reply::text(
                200,
                &format!(
                    r#"{{"1": {}, "3": {}, "12": {}}}"#,
                    text(kvb[2]),
                    text(kvb[1]),
                    text(kvb[0])
                ),
            )
        };
        r.script.on(MEMPOOL, None, vec![body(kvb)]);
        r.script.on(BLOCKSTREAM, None, vec![body(kvb)]);
        // All the coins are separate outputs of receive 0.
        let txid = |i: usize| format!("{:064x}", i + 1);
        let list: Vec<Value> = utxos
            .iter()
            .enumerate()
            .map(|(i, v)| {
                json!({ "txid": txid(i), "vout": 0, "value": v,
                                   "status": { "confirmed": true, "block_height": 1 } })
            })
            .collect();
        utxo_list(&r, Receive, 0, &json!(list));
        account_with(&r, &[(Receive, 0, utxos.iter().sum(), 0)]);
        let ask = json!({ "network": "bitcoin", "from": RECEIVE, "to": TO, "asset": "BTC",
                          "amount": amount.to_string(), "zpub": ZPUB });
        let shown = r.client.dispatch("estimate", &ask).await;
        let owned: Vec<Utxo> = utxos
            .iter()
            .enumerate()
            .map(|(i, v)| Utxo::new(&txid(i), 0, *v, RECEIVE, Receive, 0).unwrap())
            .collect();
        let change = at(Change, 0);
        ["slow", "normal", "fast"]
            .iter()
            .enumerate()
            .map(|(speed, name)| {
                let line = shown.as_ref().ok().map(|e| &e["fees"][*name]);
                let fee = line.and_then(|l| {
                    let number = |key: &str| l[key].as_str()?.parse::<u64>().ok();
                    Some((number("fee")?, l["inputs"].as_u64()?, number("vsize")?))
                });
                let planned = plan(&Request {
                    to: TO,
                    amount: Amount::Exact(amount),
                    utxos: &owned,
                    change_address: &change,
                    fee_rate: FeeRate::from_sat_per_kvb(kvb[speed]),
                })
                .ok()
                .map(|p| (p.fee, p.inputs.len() as u64, p.change.is_some()));
                (fee, planned)
            })
            .collect()
    }

    #[tokio::test]
    async fn the_fee_shown_when_composing_is_the_fee_signed() {
        // The audit's three cases: the estimate kept change above the dust limit (294) and stopped at the
        // first input count that worked, the planner keeps change only above `min_change` and prefers any
        // input count that leaves it.
        for (rate, utxos, amount) in [
            (10_000, vec![100_000], 98_000),
            (50_000, vec![100_000], 90_000),
            (1_000, vec![100_000, 100_000], 99_700),
        ] {
            let said = compose_and_sign([rate; 3], &utxos, amount).await;
            for (shown, planned) in said {
                let (fee, inputs, _) = planned.expect("the planner builds it");
                let (shown_fee, shown_inputs, _) = shown.expect("the estimate has a fee");
                assert_eq!((shown_fee, shown_inputs), (fee, inputs), "{rate} {utxos:?} {amount}");
            }
        }
        // And across the thresholds: several rates, sets of coins and amounts (`quote` itself is swept
        // against the planner in the core). Where the planner builds the payment the fee and the inputs
        // agree; where it cannot there is no fee.
        let mut checked = 0;
        for rate in [1_000, 12_300, 50_000] {
            for utxos in [vec![100_000], vec![40_000, 30_000, 20_000, 10_000]] {
                let total: u64 = utxos.iter().sum();
                for amount in (1_000..=total + 2_000).step_by(9_973) {
                    let said = compose_and_sign([rate, rate, rate], &utxos, amount).await;
                    for (shown, planned) in said {
                        match (shown, planned) {
                            (Some((fee, inputs, _)), Some((planned_fee, planned_inputs, _))) => {
                                assert_eq!(
                                    (fee, inputs),
                                    (planned_fee, planned_inputs),
                                    "{rate} {utxos:?} {amount}"
                                );
                            }
                            (None, None) => {}
                            (shown, planned) => {
                                panic!("{rate} {utxos:?} {amount}: {shown:?} against {planned:?}")
                            }
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 100, "{checked}");
    }

    #[tokio::test]
    async fn coins_a_service_makes_up_are_not_coins() {
        use nc_wallet_core::bitcoin::Chain::Receive;
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let listed = |values: &[u64]| {
            let r = rig();
            r.script.on(MEMPOOL, None, vec![estimates("5")]);
            r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
            r.script.on("/blocks/tip/height", None, vec![Reply::text(200, "1000")]);
            let list: Vec<Value> = values
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    json!({ "txid": format!("{:064x}", i + 1), "vout": 0, "value": v,
                                       "status": { "confirmed": true, "block_height": 1 } })
                })
                .collect();
            utxo_list(&r, Receive, 0, &json!(list));
            account_with(&r, &[(Receive, 0, 100_000, 0)]);
            r
        };
        // More than there is bitcoin: no answer of Esplora's, and nothing is spent from it.
        for lie in [u64::MAX, 2_100_000_000_000_001] {
            let r = listed(&[100_000, lie]);
            let error = r.client.dispatch("inputs", &ask).await.unwrap_err();
            assert_eq!(error.code(), "upstream_unavailable", "{lie}");
        }
        // The estimate used to subtract the payment and its fee from a sum that a coin of 2^64-1 had
        // saturated, with an amount just under it: an unchecked subtraction, found by reading.
        let r = listed(&[u64::MAX]);
        let estimate = json!({ "network": "bitcoin", "from": RECEIVE, "to": TO, "asset": "BTC",
                               "amount": (u64::MAX - 10).to_string(), "zpub": ZPUB });
        let error = r.client.dispatch("estimate", &estimate).await.unwrap_err();
        assert_eq!(error.code(), "upstream_unavailable");
        // An output that holds nothing cannot be spent (the planner refuses a send that lists one), so
        // it is not listed.
        let r = listed(&[100_000, 0]);
        let inputs = r.client.dispatch("inputs", &ask).await.unwrap();
        assert_eq!(inputs["utxos"].as_array().unwrap().len(), 1, "{inputs}");
    }

    #[tokio::test]
    async fn an_address_with_the_largest_transaction_counts_is_read_and_does_not_panic() {
        // 2^64-1 transactions confirmed and one in the mempool: the two counts were added unchecked,
        // which aborts the extension's whole worker.
        let r = rig();
        r.script.on(
            "/address/",
            None,
            vec![Reply::json(&json!({
                "chain_stats": { "funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": u64::MAX },
                "mempool_stats": { "funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 1 },
            }))],
        );
        let ask = json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB });
        let balances = r.client.dispatch("balances", &ask).await.unwrap();
        // Every address says it is used, so the walk goes on until its lookups run out.
        assert_eq!(balances["bitcoin"]["scanning"], true, "{balances}");
    }

    /// Esplora's rates and an account with one output, at block `height`, under a tip of `tip`.
    fn one_output_at(r: &Rig, height: u64, tip: &str) {
        use nc_wallet_core::bitcoin::Chain::Receive;
        r.script.on(MEMPOOL, None, vec![estimates("5")]);
        r.script.on(BLOCKSTREAM, None, vec![estimates("5")]);
        utxo_list(
            r,
            Receive,
            0,
            &json!([{ "txid": "aa", "vout": 0, "value": 100_000,
                      "status": { "confirmed": true, "block_height": height } }]),
        );
        account_with(r, &[(Receive, 0, 100_000, 0)]);
        r.script.on("/blocks/tip/height", None, vec![Reply::text(200, tip)]);
    }

    #[tokio::test]
    async fn an_output_at_block_zero_under_the_largest_tip_has_confirmations_not_a_panic() {
        // A service that gives block 0 for an output and 2^64-1 for the tip: `tip - height + 1` was
        // not saturating.
        let r = rig();
        one_output_at(&r, 0, "18446744073709551615");
        let inputs = r
            .client
            .dispatch("inputs", &json!({ "network": "bitcoin", "address": RECEIVE, "zpub": ZPUB }))
            .await
            .unwrap();
        assert_eq!(inputs["utxos"][0]["confirmations"], u64::MAX, "{inputs}");
    }

    #[tokio::test]
    async fn a_transaction_at_block_zero_under_the_largest_tip_has_confirmations_not_a_panic() {
        let txid = "12".repeat(32);
        let r = rig();
        r.script.on(
            &format!("/tx/{txid}/status"),
            None,
            vec![Reply::json(&json!({ "confirmed": true, "block_height": 0 }))],
        );
        r.script.on("/blocks/tip/height", None, vec![Reply::text(200, "18446744073709551615")]);
        let said = r
            .client
            .dispatch("status", &json!({ "network": "bitcoin", "hash": txid }))
            .await
            .unwrap();
        assert_eq!(said["status"], "confirmed");
        assert_eq!(said["confirmations"], u64::MAX);
    }
}

// ---- #9: Stellar's clock ----

#[tokio::test]
async fn a_stellar_send_is_not_built_where_the_ledger_does_not_say_when_it_closed() {
    let r = rig();
    r.script.on(
        "/ledgers?order=desc&limit=1",
        None,
        vec![Reply::json(
            &json!({ "_embedded": { "records": [{ "base_reserve_in_stroops": 5_000_000 }] } }),
        )],
    );
    r.script.on(
        "/fee_stats",
        None,
        vec![Reply::json(&json!({ "last_ledger_base_fee": "100", "ledger_capacity_usage": "0.5",
                                   "fee_charged": { "mode": "100", "p70": "100" } }))],
    );
    r.script.on("/accounts/", None, vec![Reply::text(404, "{}")]);
    let error = r
        .client
        .dispatch(
            "inputs",
            &json!({ "network": "stellar", "address": "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ" }),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("time could not be read"), "{error:?}");
}

#[tokio::test]
async fn a_send_on_stellar_is_timed_by_the_networks_clock_not_the_devices() {
    let r = rig();
    // The device thinks it is 2026-10-28 00:00 UTC; the ledger closed at 10:00. A device clock five
    // minutes (or ten hours) behind would otherwise make every send "too late".
    r.script.on(
        "/ledgers?order=desc&limit=1",
        None,
        vec![Reply::json(&json!({ "_embedded": { "records": [{
            "base_reserve_in_stroops": 5_000_000, "closed_at": "2026-10-28T10:00:00Z"
        }] } }))],
    );
    r.script.on(
        "/fee_stats",
        None,
        vec![Reply::json(&json!({ "last_ledger_base_fee": "100", "ledger_capacity_usage": "0.5",
                                   "fee_charged": { "mode": "100", "p70": "100" } }))],
    );
    r.script.on("/accounts/", None, vec![Reply::text(404, "{}")]);
    let inputs = r
        .client
        .dispatch(
            "inputs",
            &json!({ "network": "stellar", "address": "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ" }),
        )
        .await
        .unwrap();
    assert_eq!(inputs["server_time"], 1_793_181_600_u64);
}

// ---- #5: a site's Solana transaction: its lookup tables ----

mod lookup_tables {
    use super::*;

    const TABLE: &str = "9X5M6u1m6Jr1VPj8mFH6Y7h6vX3d5qtDq1TAVh4eN3Xg";
    const PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
    const PUBLICNODE: &str = "solana-rpc.publicnode.com";
    const POCKET: &str = "solana.api.pocket.network";
    const FOUNDATION: &str = "api.mainnet-beta.solana.com";

    fn table(data: &str) -> Value {
        json!({ "value": [{ "owner": PROGRAM, "data": [data, "base64"] }] })
    }

    fn says(r: &Rig, host: &str, answer: &Value) {
        r.script.on(host, Some("getMultipleAccounts"), vec![Reply::result(answer)]);
    }

    async fn tables(r: &Rig) -> Result<Value, Value> {
        r.client
            .dispatch("solana_tables", &json!({ "addresses": [TABLE] }))
            .await
            .map_err(|e| e.to_value())
    }

    #[tokio::test]
    async fn two_operators_that_agree_give_the_tables() {
        let r = rig();
        says(&r, PUBLICNODE, &table("AAAA"));
        says(&r, POCKET, &table("AAAA"));
        let answer = tables(&r).await.unwrap();
        assert_eq!(answer["tables"][0], json!({ "address": TABLE, "data_base64": "AAAA" }));
    }

    #[tokio::test]
    async fn a_node_that_lies_about_a_table_is_not_believed_alone() {
        // One says another destination is in the table. Two operators, no tie-break: the
        // destination could not be verified, and no table is given.
        let r = rig();
        says(&r, PUBLICNODE, &table("AAAA"));
        says(&r, POCKET, &table("EVIL"));
        let error = tables(&r).await.unwrap_err();
        assert!(message(&error).contains("could not be confirmed"), "{error}");
        // A third operator settles it, against the liar.
        says(&r, FOUNDATION, &table("AAAA"));
        let answer = tables(&r).await.unwrap();
        assert_eq!(answer["tables"][0]["data_base64"], "AAAA");
    }

    #[tokio::test]
    async fn one_operator_alone_is_not_enough_and_a_table_must_be_the_programs() {
        let r = rig();
        says(&r, PUBLICNODE, &table("AAAA"));
        assert!(tables(&r).await.is_err());
        // An account that is not owned by the lookup-table program is not a table.
        let r = rig();
        let fake = json!({ "value": [{ "owner": "11111111111111111111111111111111", "data": ["AAAA", "base64"] }] });
        says(&r, PUBLICNODE, &fake);
        says(&r, POCKET, &fake);
        assert!(tables(&r).await.is_err());
    }
}

// ---- a site's transaction: its work, asked of two operators ----

#[tokio::test]
async fn the_work_of_a_sites_transaction_is_asked_of_two_operators_and_the_higher_is_given() {
    let r = rig();
    // 270,000 and 300,000: within a quarter of each other.
    for (host, gas) in [(PUBLICNODE[0], "0x41eb0"), (DRPC, "0x493e0")] {
        r.script.on(host, Some("eth_estimateGas"), vec![Reply::result(&json!(gas))]);
    }
    let answer = r
        .client
        .dispatch(
            "gas",
            &json!({ "network": "ethereum", "from": ME, "to": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                     "value": "0", "data": "0xdeadbeef" }),
        )
        .await
        .unwrap();
    // The higher, as said (the caller adds its own headroom and bound), with two standing behind it.
    assert_eq!(answer, json!({ "gas": "300000", "sources": 2 }));
    // Two that do not agree (100,000 and 300,000): the higher is still given, but as one node's word.
    let r = rig();
    for (host, gas) in [(PUBLICNODE[0], "0x186a0"), (DRPC, "0x493e0")] {
        r.script.on(host, Some("eth_estimateGas"), vec![Reply::result(&json!(gas))]);
    }
    let apart = r
        .client
        .dispatch("gas", &json!({ "network": "ethereum", "from": ME, "to": ME, "data": "0x" }))
        .await
        .unwrap();
    assert_eq!(apart, json!({ "gas": "300000", "sources": 1 }));
    // Only one operator answers: one source, whatever it says.
    let r = rig();
    r.script.on(PUBLICNODE[0], Some("eth_estimateGas"), vec![Reply::result(&json!("0x493e0"))]);
    let alone = r
        .client
        .dispatch("gas", &json!({ "network": "ethereum", "from": ME, "to": ME, "data": "0x" }))
        .await
        .unwrap();
    assert_eq!(alone, json!({ "gas": "300000", "sources": 1 }));
    // A node that says the call fails is believed, with its reason.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(
            host,
            Some("eth_estimateGas"),
            vec![Reply::error(3, "execution reverted: nope")],
        );
    }
    let error = r
        .client
        .dispatch("gas", &json!({ "network": "ethereum", "from": ME, "to": ME, "data": "0x" }))
        .await
        .unwrap_err();
    assert!(error.message().contains("nope"), "{error:?}");
    // Not for a network without gas.
    let error = r.client.dispatch("gas", &json!({ "network": "bitcoin" })).await.unwrap_err();
    assert_eq!(error.code(), "invalid_request");
}

// ---- a lone operator cannot make a transaction look sent or confirmed ----

const TX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

fn receipt(status: &str, block: &str) -> Value {
    json!({ "status": status, "blockNumber": block, "blockHash": "0xbb", "gasUsed": "0x5208" })
}

async fn status_of(r: &Rig) -> Value {
    r.client.dispatch("status", &json!({ "network": "ethereum", "hash": TX })).await.unwrap()
}

#[tokio::test]
async fn one_operators_receipt_is_unverified_two_that_agree_confirm() {
    // Only PublicNode has a receipt; DRPC (another operator) has none: pending, unverified.
    let r = rig();
    r.script.on(
        PUBLICNODE[0],
        Some("eth_getTransactionReceipt"),
        vec![Reply::result(&receipt("0x1", "0x10"))],
    );
    r.script.on(DRPC, Some("eth_getTransactionReceipt"), vec![Reply::result(&Value::Null)]);
    let said = status_of(&r).await;
    assert_eq!(said["status"], "pending", "{said}");
    assert_eq!(said["unverified"], true);
    assert_eq!(said["reported"], "confirmed");

    // Another operator is asked and has a different outcome in that block: still unverified.
    let r = rig();
    r.script.on(
        PUBLICNODE[0],
        Some("eth_getTransactionReceipt"),
        vec![Reply::result(&receipt("0x1", "0x10"))],
    );
    r.script.on(
        DRPC,
        Some("eth_getTransactionReceipt"),
        vec![Reply::result(&receipt("0x0", "0x10"))],
    );
    assert_eq!(status_of(&r).await["unverified"], true);

    // Two operators, the same receipt: confirmed, and not marked unverified.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(
            host,
            Some("eth_getTransactionReceipt"),
            vec![Reply::result(&receipt("0x1", "0x10"))],
        );
        r.script.on(host, Some("eth_blockNumber"), vec![Reply::result(&hex(0x20))]);
    }
    let said = status_of(&r).await;
    assert_eq!(said["status"], "confirmed", "{said}");
    assert_eq!(said.get("unverified"), None);
    assert_eq!(said["confirmations"], 17);
    // Cost: a receipt from each of two operators (a failed try on an endpoint the rig does not
    // script may add one); not a third operator's.
    assert!(r.script.count("eth_getTransactionReceipt") <= 4);
}

async fn send_raw(r: &Rig) -> Result<Value, crate::error::ChainError> {
    r.client
        .dispatch(
            "broadcast",
            &json!({ "network": "ethereum", "raw": "02c0", "from": ME, "nonce": 7 }),
        )
        .await
}

#[tokio::test]
async fn a_lone_already_known_is_not_a_sent_transaction() {
    // One node says "already known", the others refuse otherwise, and nobody else has it.
    let r = rig();
    r.script.on(
        PUBLICNODE[0],
        Some("eth_sendRawTransaction"),
        vec![Reply::error(-32000, "already known")],
    );
    r.script.on(DRPC, Some("eth_sendRawTransaction"), vec![Reply::error(-32000, "internal error")]);
    r.script.on(
        PUBLICNODE[0],
        Some("eth_getTransactionByHash"),
        vec![Reply::result(&json!({ "hash": "0x1" }))],
    );
    r.script.on(DRPC, Some("eth_getTransactionByHash"), vec![Reply::result(&Value::Null)]);
    let error = send_raw(&r).await.unwrap_err().to_value();
    assert_eq!(error["code"], "estimate_failed", "{error}");
    assert_eq!(error["details"]["reason"], "unconfirmed");
    // A second operator that has the transaction settles it.
    let r = rig();
    r.script.on(
        PUBLICNODE[0],
        Some("eth_sendRawTransaction"),
        vec![Reply::error(-32000, "already known")],
    );
    r.script.on(DRPC, Some("eth_sendRawTransaction"), vec![Reply::error(-32000, "internal error")]);
    r.script.on(
        DRPC,
        Some("eth_getTransactionByHash"),
        vec![Reply::result(&json!({ "hash": "0x1" }))],
    );
    r.script.on(
        PUBLICNODE[0],
        Some("eth_getTransactionByHash"),
        vec![Reply::result(&json!({ "hash": "0x1" }))],
    );
    assert!(send_raw(&r).await.is_ok());
}

#[tokio::test]
async fn a_nodes_own_words_for_a_refusal_are_not_passed_on() {
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(
            host,
            Some("eth_sendRawTransaction"),
            vec![Reply::error(-32000, "transaction rejected: send 1 ETH to 0xabc to unlock")],
        );
    }
    let error = r
        .client
        .dispatch(
            "broadcast",
            &json!({ "network": "ethereum", "raw": "02c0", "from": ME, "nonce": 7 }),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "rejected");
    assert!(!error.message().contains("unlock") && !error.message().contains("0xabc"), "{error:?}");
}

// ---- hints that guard against losing a payment come from two operators ----

const STELLAR_FROM: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
const STELLAR_TO: &str = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H";

#[tokio::test]
async fn a_memo_required_by_either_operator_is_required() {
    // The first operator leaves the flag out; the second says the destination needs a memo.
    let r = rig();
    r.script.on(
        "/ledgers?order=desc&limit=1",
        None,
        vec![Reply::json(&json!({ "_embedded": { "records": [{
            "base_reserve_in_stroops": 5_000_000, "closed_at": "2026-10-28T10:00:00Z" }] } }))],
    );
    r.script.on(
        "/fee_stats",
        None,
        vec![Reply::json(&json!({ "last_ledger_base_fee": "100", "ledger_capacity_usage": "0.5",
                                   "fee_charged": { "mode": "100", "p70": "100" } }))],
    );
    let account = |data: Value| {
        Reply::json(&json!({ "id": STELLAR_TO, "sequence": "5", "subentry_count": 0,
                              "balances": [{ "asset_type": "native", "balance": "100.0" }], "data": data }))
    };
    r.script.on(
        &format!("/accounts/{STELLAR_TO}"),
        None,
        vec![account(json!({})), account(json!({ "config.memo_required": "MQ==" }))],
    );
    let estimate = r
        .client
        .dispatch(
            "estimate",
            &json!({ "network": "stellar", "from": STELLAR_FROM, "to": STELLAR_TO, "asset": "XLM", "amount": "10000000" }),
        )
        .await
        .unwrap();
    assert_eq!(estimate["recipient"]["memo_required"], true, "{estimate}");
}

#[tokio::test]
async fn a_token_account_is_seen_if_either_operator_sees_one() {
    // An address that is a token account: one operator says it is owned by the wallet's system
    // program (a lie), the other that the token program owns it. Sending to it would strand the tokens.
    let r = rig();
    let token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let info = |owner: &str| {
        Reply::result(
            &json!({ "context": { "slot": 1 }, "value": { "owner": owner, "lamports": 2_039_280 } }),
        )
    };
    r.script.on(
        "",
        Some("\"method\":\"getAccountInfo\""),
        vec![info("11111111111111111111111111111111"), info(token_program)],
    );
    r.script.rpc("getMinimumBalanceForRentExemption", &json!(2_039_280));
    r.script.rpc("getRecentPrioritizationFees", &json!([]));
    let estimate = r
        .client
        .dispatch(
            "estimate",
            &json!({ "network": "solana", "from": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
                     "to": "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk", "asset": "USDC", "amount": "1000000" }),
        )
        .await
        .unwrap();
    assert_eq!(estimate["recipient"]["is_token_account"], true, "{estimate}");
}

// ---- a node that writes the largest numbers there are ----

#[tokio::test]
async fn a_tron_transaction_at_block_zero_under_the_largest_head_has_confirmations_not_a_panic() {
    let r = rig();
    r.script.on(
        "/wallet/gettransactioninfobyid",
        None,
        vec![Reply::json(&json!({ "blockNumber": 0, "receipt": { "result": "SUCCESS" } }))],
    );
    r.script.on(
        "/wallet/getblock",
        None,
        vec![Reply::json(&json!({ "block_header": { "raw_data": { "number": u64::MAX } } }))],
    );
    let said = r
        .client
        .dispatch("status", &json!({ "network": "tron", "hash": "12".repeat(32) }))
        .await
        .unwrap();
    assert_eq!(said["status"], "confirmed");
    assert_eq!(said["confirmations"], u64::MAX);
}

#[tokio::test]
async fn a_receipt_in_block_zero_under_the_largest_head_has_confirmations_not_a_panic() {
    // Two operators agree on the receipt; the head is read from one, which may say anything.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.script.on(
            host,
            Some("eth_getTransactionReceipt"),
            vec![Reply::result(&receipt("0x1", "0x0"))],
        );
        r.script.on(
            host,
            Some("eth_blockNumber"),
            vec![Reply::result(&json!("0xffffffffffffffff"))],
        );
    }
    let said = status_of(&r).await;
    assert_eq!(said["status"], "confirmed", "{said}");
    assert_eq!(said["confirmations"], u64::MAX);
}

/// A Horizon that gives `sub` subentries and `sponsoring` sponsored-for entries to the account, and
/// `reserve` stroops as each entry's reserve.
async fn stellar_inputs(sub: u64, sponsoring: u64, reserve: u64) -> Result<Value, Value> {
    let r = rig();
    r.script
        .on(
            "/accounts/",
            None,
            vec![Reply::json(&json!({
                "sequence": "123",
                "balances": [{ "asset_type": "native", "balance": "100.0000000" }],
                "subentry_count": sub, "num_sponsoring": sponsoring, "num_sponsored": 0
            }))],
        )
        .on(
            "/fee_stats",
            None,
            vec![Reply::json(&json!({ "last_ledger_base_fee": "100", "ledger_capacity_usage": "0.5",
                                       "fee_charged": { "mode": "100", "p70": "100" } }))],
        )
        .on(
            "/ledgers",
            None,
            vec![Reply::json(&json!({ "_embedded": { "records": [
                { "base_reserve_in_stroops": reserve, "closed_at": "2026-10-28T10:00:00Z" } ] } }))],
        );
    r.client
        .dispatch(
            "inputs",
            &json!({ "network": "stellar", "address": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" }),
        )
        .await
        .map_err(|e| e.to_value())
}

#[tokio::test]
async fn a_horizon_that_writes_the_largest_reserve_and_entry_counts_does_not_panic() {
    // The control: ordinary numbers are read, and the minimum is (2 + 3) x 0.5 XLM.
    let sane = stellar_inputs(3, 0, 5_000_000).await.unwrap();
    assert_eq!(sane["min_balance"], "25000000");
    // (2 + 2^64-1 + 2^64-1) x 2^64-1 does not fit 128 bits.
    let hostile = stellar_inputs(u64::MAX, u64::MAX, u64::MAX).await;
    // Whatever it answers, it answers: a reserve of that size is not the network's.
    assert!(hostile.is_err(), "{hostile:?}");
}

// ---- a coin sent to an account a program owns ----

#[tokio::test]
async fn a_sol_transfer_to_an_account_a_program_owns_is_told_so_if_either_operator_says_it() {
    const SYSTEM: &str = "11111111111111111111111111111111";
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    // The USDC mint: a program's account. Lamports sent to it can never be taken out again.
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let info = |owner: &str| {
        Reply::result(
            &json!({ "context": { "slot": 1 }, "value": { "owner": owner, "lamports": 1_461_600 } }),
        )
    };
    let ask = |to: &str| {
        json!({ "network": "solana", "from": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
                "to": to, "asset": "SOL", "amount": "1000000" })
    };
    let rig_with = |replies: Vec<Reply>| {
        let r = rig();
        r.script.on("", Some("\"method\":\"getAccountInfo\""), replies);
        r.script.rpc("getMinimumBalanceForRentExemption", &json!(890_880));
        r.script.rpc("getRecentPrioritizationFees", &json!([]));
        r
    };
    // The operator asked first says so.
    let r = rig_with(vec![info(TOKEN_PROGRAM)]);
    let estimate = r.client.dispatch("estimate", &ask(MINT)).await.unwrap();
    assert_eq!(estimate["recipient"]["program_owned"], true, "{estimate}");
    assert_eq!(estimate["recipient"]["owner"], TOKEN_PROGRAM);
    // The first says an ordinary account and the second says a program owns it: either one's yes counts.
    let r = rig_with(vec![info(SYSTEM), info(SYSTEM), info(TOKEN_PROGRAM)]);
    let estimate = r.client.dispatch("estimate", &ask(MINT)).await.unwrap();
    assert_eq!(estimate["recipient"]["program_owned"], true, "{estimate}");
    // An ordinary account: nothing to say. It costs five requests (docs/direct-chain.md): two for the
    // priority fee and three for the recipient, whose second opinion is asked of two other operators because
    // the pool cannot keep a single one from being the operator that answered the first.
    let r = rig_with(vec![info(SYSTEM)]);
    let estimate = r.client.dispatch("estimate", &ask(MINT)).await.unwrap();
    assert_eq!(estimate["recipient"]["program_owned"], false, "{estimate}");
    assert_eq!(estimate["recipient"]["exists"], true);
    assert_eq!(r.script.seen().len(), 5);
    assert_eq!(r.script.count("\"method\":\"getAccountInfo\""), 3);
    // An account nothing has been sent to yet is nobody's program, and a second opinion is not asked.
    let r = rig_with(vec![Reply::result(&json!({ "context": { "slot": 1 }, "value": null }))]);
    let estimate = r.client.dispatch("estimate", &ask(MINT)).await.unwrap();
    assert_eq!(estimate["recipient"]["program_owned"], false, "{estimate}");
    assert_eq!(estimate["recipient"]["exists"], false);
    assert_eq!(r.script.count("\"method\":\"getAccountInfo\""), 1);
}

// ---- a payment to a muxed Stellar address ----

#[tokio::test]
async fn a_stellar_payment_to_a_muxed_address_is_asked_about_by_the_account_behind_it() {
    // SEP-23's account and its muxed address with the id 2^63.
    const BASE: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
    const MUXED: &str = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
    const ME: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let rig_with = |account: Reply| {
        let r = rig();
        r.script.on(&format!("/accounts/{BASE}"), None, vec![account]);
        r.script.on(
            "/fee_stats",
            None,
            vec![Reply::json(
                &json!({ "last_ledger_base_fee": "100", "ledger_capacity_usage": "0.5",
                                       "fee_charged": { "mode": "100", "p70": "100" } }),
            )],
        );
        r.script.on(
            "/ledgers",
            None,
            vec![Reply::json(&json!({ "_embedded": { "records": [
                { "base_reserve_in_stroops": 5_000_000, "closed_at": "2026-10-28T10:00:00Z" } ] } }))],
        );
        r
    };
    let ask = |to: &str| json!({ "network": "stellar", "from": ME, "to": to, "asset": "XLM", "amount": "10000000" });
    // An exchange's account that asks for a memo: the address carries the id, so none is asked for.
    let wants_a_memo = Reply::json(&json!({
        "sequence": "1", "balances": [{ "asset_type": "native", "balance": "5.0000000" }],
        "data": { "config.memo_required": "MQ==" }
    }));
    let r = rig_with(wants_a_memo.clone());
    let estimate = r.client.dispatch("estimate", &ask(MUXED)).await.unwrap();
    assert_eq!(estimate["recipient"]["exists"], true, "{estimate}");
    assert_eq!(estimate["recipient"]["muxed_id"], "9223372036854775808");
    assert_eq!(estimate["recipient"]["memo_required"], false);
    // Horizon is asked about the account, never about the muxed text.
    assert!(r.script.count(&format!("/accounts/{BASE}")) >= 1);
    assert_eq!(r.script.count(MUXED), 0);
    // The same account by its plain address is still owed a memo, and has no id.
    let r = rig_with(wants_a_memo);
    let plain = r.client.dispatch("estimate", &ask(BASE)).await.unwrap();
    assert_eq!(plain["recipient"]["memo_required"], true, "{plain}");
    assert!(plain["recipient"].get("muxed_id").is_none());
    // An account that does not exist: said so, with the minimum a first payment to it must carry.
    let r = rig_with(Reply::text(404, "{}"));
    let missing = r.client.dispatch("estimate", &ask(MUXED)).await.unwrap();
    assert_eq!(missing["recipient"]["exists"], false, "{missing}");
    assert_eq!(missing["recipient"]["minimum_new_account"], "10000000");
    // Not an address: a secret seed, a muxed one with a changed letter.
    for bad in [
        "SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLL",
    ] {
        let error = rig_with(Reply::text(404, "{}")).client.dispatch("estimate", &ask(bad)).await;
        assert_eq!(error.unwrap_err().code(), "invalid_address", "{bad}");
    }
}

// ---- fee speeds on the EVM networks ----

const OTHER_EVM: &str = "0x5BC24606e389465DF34068fCC3357465e7A473C2";

impl Rig {
    /// Makes `host` answer a coin transfer's estimate: no code at the recipient, a base fee and a tip
    /// (the node's), and the fee history of the last ten blocks, whose tips at the 10th and the 90th
    /// percentile are `p10` and `p90` wei.
    fn eth_tiers(&self, host: &str, base_gwei: u128, tip_gwei: u128, p10: u128, p90: u128) {
        self.eth_host(host, base_gwei, tip_gwei, 7);
        self.script.on(host, Some("eth_getCode"), vec![Reply::result(&json!("0x"))]);
        let reward: Vec<Value> = (0..10).map(|_| json!([hex(p10), hex(p90)])).collect();
        self.script.on_first(
            host,
            Some("[10,90]"),
            vec![Reply::result(&json!({
                "baseFeePerGas": [hex(base_gwei * GWEI), hex(base_gwei * GWEI)],
                "gasUsedRatio": [0.5], "oldestBlock": "0x1", "reward": reward,
            }))],
        );
    }

    /// A coin transfer's estimate on Ethereum, with the speeds asked for.
    async fn eth_estimate(&self) -> Result<Value, Value> {
        self.eth_estimate_of(json!({ "tiers": true })).await
    }

    async fn eth_estimate_of(&self, extra: Value) -> Result<Value, Value> {
        let mut request = json!({ "network": "ethereum", "from": ME, "to": OTHER_EVM, "asset": "ETH",
                                  "amount": "1000000000000000" });
        request.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        self.client.dispatch("estimate", &request).await.map_err(|e| e.to_value())
    }
}

#[tokio::test]
async fn an_evm_estimate_offers_no_speeds_and_asks_for_none_unless_the_app_asks() {
    // An app that does not know of speeds (the apps of 1.0.0) is answered as it always was, and the
    // node is not asked for the fee history of the last blocks on its behalf.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_tiers(host, 20, 1, GWEI / 5, 4 * GWEI);
    }
    let plain = r.eth_estimate_of(json!({})).await.unwrap();
    assert_eq!(plain["max_fee_per_gas"], (41 * GWEI).to_string());
    assert!(plain.get("fees").is_none(), "{plain}");
    assert_eq!(r.script.count("[10,90]"), 0);
    // Asked for, they are there, and the standard figures are the same as without.
    let asked = r.eth_estimate().await.unwrap();
    assert!(asked["fees"].is_object(), "{asked}");
    assert!(r.script.count("[10,90]") > 0);
    for key in ["max_fee_per_gas", "max_priority_fee_per_gas", "gas_limit", "fee"] {
        assert_eq!(asked[key], plain[key], "{key}");
    }
    // `tiers: false` and `null` are no ask; anything else is not a request.
    for no in [json!(false), Value::Null] {
        let answer = r.eth_estimate_of(json!({ "tiers": no })).await.unwrap();
        assert!(answer.get("fees").is_none(), "{answer}");
    }
    let refused = r.eth_estimate_of(json!({ "tiers": "yes" })).await.unwrap_err();
    assert_eq!(refused["code"], "invalid_request", "{refused}");
}

#[tokio::test]
async fn an_evm_estimate_offers_a_slow_a_standard_and_a_fast_fee_for_the_same_work() {
    let r = rig();
    // A base fee of 20 gwei, the nodes' tip 1 gwei, and the last blocks' tips from 0.2 to 4 gwei.
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_tiers(host, 20, 1, GWEI / 5, 4 * GWEI);
    }
    let estimate = r.eth_estimate().await.unwrap();
    // Standard is what it always was, and what the top of the answer says: twice the base fee and the tip.
    assert_eq!(estimate["max_fee_per_gas"], (41 * GWEI).to_string());
    assert_eq!(estimate["max_priority_fee_per_gas"], GWEI.to_string());
    let fees = &estimate["fees"];
    let tier = |name: &str, max_fee: u128, tip: u128| {
        let entry = &fees[name];
        assert_eq!(entry["max_fee_per_gas"], max_fee.to_string(), "{name}");
        assert_eq!(entry["max_priority_fee_per_gas"], tip.to_string(), "{name}");
        // 21,000 units of work at the most the tier bids.
        assert_eq!(entry["fee"]["amount"], (21_000 * max_fee).to_string(), "{name}");
        assert_eq!(entry["fee"]["asset"], "ETH");
    };
    tier("normal", 41 * GWEI, GWEI);
    assert_eq!(estimate["fee"], fees["normal"]["fee"]);
    // Slow: room for one block's rise of an eighth, and the tip of the quiet blocks.
    tier("slow", 20 * GWEI * 9 / 8 + GWEI / 5, GWEI / 5);
    // Fast: the room of standard and the tip the busiest blocks paid.
    tier("fast", 40 * GWEI + 4 * GWEI, 4 * GWEI);
}

#[tokio::test]
async fn tiers_never_cross_and_a_network_where_they_collapse_offers_one_price() {
    // BNB Chain's tips hardly differ (0.05, 0.05, 0.07 gwei): slow and standard are the same price, and
    // the tip of the quiet blocks never lifts slow above standard, nor the busy ones' pull fast below it.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_tiers(host, 20, 1, 3 * GWEI, GWEI / 2);
    }
    let estimate = r.eth_estimate().await.unwrap();
    let fees = &estimate["fees"];
    assert_eq!(fees["slow"]["max_priority_fee_per_gas"], GWEI.to_string(), "{estimate}");
    assert_eq!(fees["fast"]["max_priority_fee_per_gas"], GWEI.to_string(), "{estimate}");
    assert_eq!(fees["fast"]["max_fee_per_gas"], fees["normal"]["max_fee_per_gas"]);
    // Slow is still the cheaper in what it bids over the base fee.
    let max = |name: &str| fees[name]["max_fee_per_gas"].as_str().unwrap().parse::<u128>().unwrap();
    assert!(max("slow") <= max("normal") && max("normal") <= max("fast"), "{estimate}");
}

#[tokio::test]
async fn a_tier_the_nodes_cannot_vouch_for_is_not_offered_and_the_estimate_still_is() {
    // The history of the last blocks cannot be had: standard is all there is, said so.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_host(host, 20, 1, 7);
        r.script.on(host, Some("eth_getCode"), vec![Reply::result(&json!("0x"))]);
        r.script.on_first(
            host,
            Some("[10,90]"),
            vec![Reply::error(-32601, "the method does not exist")],
        );
    }
    let estimate = r.eth_estimate().await.unwrap();
    assert_eq!(estimate["max_fee_per_gas"], (41 * GWEI).to_string());
    assert!(estimate["fees"]["slow"].is_null() && estimate["fees"]["fast"].is_null(), "{estimate}");
    assert_eq!(estimate["fees"]["normal"]["max_fee_per_gas"], (41 * GWEI).to_string());
    // Tips the nodes disagree on (one says 0.2, the other 30 gwei) are no tier either.
    let r = rig();
    for (host, p10) in [(PUBLICNODE[0], GWEI / 5), (DRPC, 30 * GWEI)] {
        r.eth_tiers(host, 20, 1, p10, 31 * GWEI);
    }
    let estimate = r.eth_estimate().await.unwrap();
    assert!(estimate["fees"]["slow"].is_null(), "{estimate}");
    assert_eq!(estimate["fees"]["normal"]["max_fee_per_gas"], (41 * GWEI).to_string());
    // A fast tier past the wallet's own ceiling is not offered, and standard is.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_tiers(host, 20, 1, GWEI / 5, 300 * GWEI);
    }
    let estimate = r.eth_estimate().await.unwrap();
    assert!(estimate["fees"]["fast"].is_null(), "{estimate}");
    assert!(estimate["fees"]["slow"].is_object());
}

#[tokio::test]
async fn a_fast_tier_whose_bid_is_past_the_ceiling_though_its_tip_is_not_is_not_offered() {
    // A base fee of 480 gwei: standard bids 2 x 480 + 1 = 961, inside Ethereum's ceiling of 1,000. The busy
    // blocks tipped 50 gwei, inside the tip's own ceiling (200), but 2 x 480 + 50 = 1,010 is past the other:
    // the wallet would refuse to sign it, so it is not offered.
    let r = rig();
    for host in [PUBLICNODE[0], DRPC] {
        r.eth_tiers(host, 480, 1, GWEI / 5, 50 * GWEI);
    }
    let estimate = r.eth_estimate().await.unwrap();
    assert_eq!(estimate["fees"]["normal"]["max_fee_per_gas"], (961 * GWEI).to_string());
    assert!(estimate["fees"]["fast"].is_null(), "{estimate}");
    assert!(estimate["fees"]["slow"].is_object(), "{estimate}");
}

const BSC_PUBLICNODE: &str = "bsc-rpc.publicnode.com";
const BSC_BLOCKRAZOR: &str = "bsc.blockrazor.xyz";

impl Rig {
    /// Makes `host` answer a BNB coin transfer's estimate as BNB Chain's nodes do (checked live on
    /// 2026-11-02): no code at the recipient, a base fee of nothing in every block, the nodes' tip in wei,
    /// and the tips of the last ten blocks at the 10th and the 90th percentile.
    fn bnb_tiers(&self, host: &str, tip: u128, p10: u128, p90: u128) {
        let s = &self.script;
        let on = |method: &str, result: Value| {
            s.on(host, Some(&format!("\"method\":\"{method}\"")), vec![Reply::result(&result)]);
        };
        on(
            "eth_feeHistory",
            json!({ "baseFeePerGas": ["0x0", "0x0"], "gasUsedRatio": [0.5], "oldestBlock": "0x1" }),
        );
        on("eth_maxPriorityFeePerGas", hex(tip));
        on("eth_getCode", json!("0x"));
        let reward: Vec<Value> = (0..10).map(|_| json!([hex(p10), hex(p90)])).collect();
        s.on_first(
            host,
            Some("[10,90]"),
            vec![Reply::result(&json!({
                "baseFeePerGas": vec![json!("0x0"); 11],
                "gasUsedRatio": [0.5], "oldestBlock": "0x1", "reward": reward,
            }))],
        );
    }
}

#[tokio::test]
async fn bnb_chain_is_offered_speeds_though_its_base_fee_is_nothing() {
    // BNB Chain's blocks carry a base fee, and it is 0, so a bid is its tip alone: the speeds are offered, and
    // they differ only by the tip. Slow cannot go under the 0.05 gwei the network asks, so it is standard.
    const TIP: u128 = 50_000_000;
    let r = rig();
    for host in [BSC_PUBLICNODE, BSC_BLOCKRAZOR] {
        r.bnb_tiers(host, TIP, TIP, 70_000_000);
    }
    let estimate = r
        .client
        .dispatch(
            "estimate",
            &json!({ "network": "bsc", "from": ME, "to": OTHER_EVM, "asset": "BNB",
                     "amount": "1000000000000000", "tiers": true }),
        )
        .await
        .unwrap();
    assert_eq!(estimate["max_fee_per_gas"], TIP.to_string(), "{estimate}");
    let fees = &estimate["fees"];
    assert!(fees.is_object(), "{estimate}");
    let tier = |name: &str, bid: u128| {
        let entry = &fees[name];
        assert_eq!(entry["max_fee_per_gas"], bid.to_string(), "{name}");
        assert_eq!(entry["max_priority_fee_per_gas"], bid.to_string(), "{name}");
        assert_eq!(entry["gas_price"], bid.to_string(), "{name}");
        assert_eq!(entry["fee"]["amount"], (21_000 * bid).to_string(), "{name}");
        assert_eq!(entry["fee"]["asset"], "BNB", "{name}");
    };
    tier("normal", TIP);
    tier("slow", TIP);
    tier("fast", 70_000_000);
    // The same estimate asked without speeds is the standard one and carries none.
    let plain = r
        .client
        .dispatch(
            "estimate",
            &json!({ "network": "bsc", "from": ME, "to": OTHER_EVM, "asset": "BNB",
                     "amount": "1000000000000000" }),
        )
        .await
        .unwrap();
    assert!(plain.get("fees").is_none(), "{plain}");
    assert_eq!(plain["max_fee_per_gas"], estimate["max_fee_per_gas"]);
}
