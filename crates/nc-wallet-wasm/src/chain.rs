//! The chain client in the extension's service worker: balances, the inputs a
//! send needs, fee estimates, prices and broadcast, read straight from each
//! network's public endpoints by the browser. There is no Nowcoin server.
//!
//! `nc-wallet-chain` does the work; this file only lends it the browser. The
//! worker gives it one function, **`fetch`** (see `src/background/chain-fetch.ts`):
//! it takes `{ method, url, body?, contentType?, timeoutMs, maxBytes }` and
//! resolves `{ status, headers: [[name, value]], body: Uint8Array }`, or
//! rejects with an `Error` named `TimeoutError` when the time ran out. The
//! worker's `fetch` is told to send no cookies, no credentials and no referrer,
//! and to follow no redirect; the extension's `host_permissions` (exactly the
//! endpoints' origins, generated from the same list) are what let it read the
//! answers.
//!
//! Sleeping is the worker's `setTimeout` and the clock is `Date.now()`.
//!
//! Every call answers JSON text, or rejects with the error's JSON text
//! (`{ code, message, retryable, details? }`).

use std::sync::Arc;

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use nc_wallet_chain::ChainClient;
use nc_wallet_chain::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Method, Platform};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The browser, as `nc-wallet-chain` sees a device.
struct BrowserPlatform {
    fetch: Function,
}

fn set(object: &Object, key: &str, value: &JsValue) {
    // Setting a property on a fresh object cannot fail.
    let _ = Reflect::set(object, &JsValue::from_str(key), value);
}

fn get(object: &JsValue, key: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

/// Whether a rejected `fetch` ran out of time.
fn timed_out(error: &JsValue) -> bool {
    get(error, "name")
        .as_string()
        .is_some_and(|name| name == "TimeoutError" || name == "AbortError")
}

impl Platform for BrowserPlatform {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            if !request.url.starts_with("https://") {
                return Err(HttpError::Network);
            }
            let object = Object::new();
            let method = if request.method == Method::Get { "GET" } else { "POST" };
            set(&object, "method", &JsValue::from_str(method));
            set(&object, "url", &JsValue::from_str(&request.url));
            if let Some(body) = &request.body {
                set(&object, "body", &Uint8Array::from(body.as_slice()).into());
            }
            if let Some(content_type) = request.content_type {
                set(&object, "contentType", &JsValue::from_str(content_type));
            }
            // Both fit 32 bits (a timeout in milliseconds, a limit in bytes).
            set(
                &object,
                "timeoutMs",
                &JsValue::from(u32::try_from(request.timeout_ms).unwrap_or(u32::MAX)),
            );
            set(
                &object,
                "maxBytes",
                &JsValue::from(u32::try_from(request.max_bytes).unwrap_or(u32::MAX)),
            );
            let promise: Promise = self
                .fetch
                .call1(&JsValue::NULL, &object)
                .map_err(|_| HttpError::Network)?
                .dyn_into()
                .map_err(|_| HttpError::Network)?;
            let response = JsFuture::from(promise)
                .await
                .map_err(|e| if timed_out(&e) { HttpError::Timeout } else { HttpError::Network })?;

            let status = get(&response, "status").as_f64().ok_or(HttpError::Network)?;
            let body: Uint8Array =
                get(&response, "body").dyn_into().map_err(|_| HttpError::Network)?;
            if body.length() as usize > request.max_bytes {
                return Err(HttpError::TooLarge);
            }
            let headers = Array::from(&get(&response, "headers"))
                .iter()
                .filter_map(|pair| {
                    let pair = Array::from(&pair);
                    Some((pair.get(0).as_string()?.to_ascii_lowercase(), pair.get(1).as_string()?))
                })
                .collect();
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(HttpResponse { status: status as u16, headers, body: body.to_vec() })
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let promise = Promise::new(&mut |resolve, _reject| {
                let global = js_sys::global();
                if let Ok(timer) = Reflect::get(&global, &JsValue::from_str("setTimeout"))
                    && let Ok(timer) = timer.dyn_into::<Function>()
                {
                    let wait = JsValue::from(u32::try_from(millis).unwrap_or(u32::MAX));
                    let _ = timer.call2(&global, &resolve, &wait);
                } else {
                    // No timer: do not wait.
                    let _ = resolve.call0(&JsValue::NULL);
                }
            });
            let _ = JsFuture::from(promise).await;
        })
    }

    fn now_ms(&self) -> u64 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            js_sys::Date::now() as u64
        }
    }
}

/// The chain client, for the service worker.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WalletChain {
    client: ChainClient,
}

#[wasm_bindgen]
impl WalletChain {
    /// A client that reads through `fetch` (see the module's description).
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(fetch: Function) -> WalletChain {
        #[allow(clippy::arc_with_non_send_sync)] // One thread: the worker's.
        let platform: Arc<dyn Platform> = Arc::new(BrowserPlatform { fetch });
        WalletChain { client: ChainClient::new(platform) }
    }

    /// Runs one operation (`networks`, `balances`, `inputs`, `estimate`,
    /// `broadcast`, `status`, `prices`, `health`) on a JSON request. Resolves the
    /// answer's JSON text; rejects with the error's JSON text.
    pub async fn call(&self, op: String, request: String) -> Result<String, JsValue> {
        self.client.call(&op, &request).await.map_err(|json| JsValue::from_str(&json))
    }

    /// What is worth keeping between launches, as JSON text to store: the price
    /// feeds already checked, the prices a day ago, the Bittensor runtimes
    /// already read. Nothing in it is about a person or an address.
    #[must_use]
    pub fn export_state(&self) -> String {
        self.client.export_state()
    }

    /// Takes back what [`Self::export_state`] wrote. Anything else is ignored.
    pub fn import_state(&self, state: &str) {
        self.client.import_state(state);
    }

    /// What this browser sent lately (nonces and hashes), as JSON text, to keep for a few minutes in
    /// memory that goes with the session (`chrome.storage.session`): the worker may be stopped
    /// and started again, and a nonce must not be put on one a send a moment ago already holds.
    #[must_use]
    pub fn export_sent(&self) -> String {
        self.client.export_sent()
    }

    /// Takes back what [`Self::export_sent`] wrote. Anything else, or anything stale, is ignored.
    pub fn import_sent(&self, state: &str) {
        self.client.import_sent(state);
    }

    /// Forgets the balances and prices held in memory (the wallet was removed).
    pub fn forget(&self) {
        self.client.forget_everything();
    }
}

/// Run as WebAssembly in Node (`scripts/test-wasm.sh`): the chain client reads through the
/// `fetch` it is lent, in the shapes the service worker's `chain-fetch.ts` speaks.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// The BIP-84 reference account: its key, and the first receive address it shows.
    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const BITCOIN: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    /// A Bitcoin balance asked for as the apps ask: by the account's `zpub`, with the hint of a wallet made
    /// here (nothing used yet, so a reading is a few lookups and not a walk of the whole account).
    fn bitcoin_request(extra: &str) -> String {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let at = (js_sys::Date::now() / 1000.0) as u64;
        let none = r#"{"last":null,"live":[],"resume":null}"#;
        format!(
            r#"{{"network":"bitcoin","address":"{BITCOIN}","zpub":"{ZPUB}","hint":{{"v":1,"at":{at},"r":{none},"c":{none}}}{extra}}}"#
        )
    }

    /// The Esplora answer for the first receive address (`150000 - 50000` confirmed, `-2000` waiting), and an
    /// unused address for any other.
    fn esplora_account() -> Function {
        fetch_that(
            &r#"
            const mine = request.url.endsWith("/address/ADDRESS");
            const text = JSON.stringify(mine ? {
              chain_stats: { funded_txo_sum: 150000, spent_txo_sum: 50000, tx_count: 2 },
              mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 2000, tx_count: 1 },
            } : {
              chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
              mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
            });
            return Promise.resolve({
              status: 200,
              headers: [["Content-Type", "application/json"]],
              body: new TextEncoder().encode(text),
            });
            "#
            .replace("ADDRESS", BITCOIN),
        )
    }

    /// A `fetch` written in JavaScript, as the worker lends one: it keeps each request it is asked
    /// in `globalThis.__chainSeen` and runs `reply` (which may use `request`).
    fn fetch_that(reply: &str) -> Function {
        let body = format!(
            "(globalThis.__chainSeen = globalThis.__chainSeen || []).push(request); {reply}"
        );
        Function::new_with_args("request", &body)
    }

    fn seen() -> Array {
        Array::from(&get(&js_sys::global(), "__chainSeen"))
    }

    fn forget_seen() {
        set(&js_sys::global(), "__chainSeen", &Array::new().into());
    }

    fn parsed(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    #[wasm_bindgen_test]
    async fn a_balance_is_read_through_the_lent_fetch() {
        forget_seen();
        let chain = WalletChain::new(esplora_account());
        let answer = parsed(&chain.call("balances".to_owned(), bitcoin_request("")).await.unwrap());

        assert_eq!(answer["balances"][0]["asset"], "BTC");
        assert_eq!(answer["balances"][0]["amount"], "98000");
        assert_eq!(answer["balances"][0]["confirmed"], "100000");
        assert_eq!(answer["balances"][0]["unconfirmed"], "-2000");

        // GETs for the account's addresses (the first one is used, so the walk goes on to the gap of 20
        // past it), each to an Esplora endpoint over HTTPS, with a deadline and a size limit.
        let asked = seen();
        assert!((1..=60).contains(&asked.length()), "{}", asked.length());
        for at in 0..asked.length() {
            let request = asked.get(at);
            assert_eq!(get(&request, "method").as_string().as_deref(), Some("GET"));
            let url = get(&request, "url").as_string().unwrap();
            assert!(url.starts_with("https://"), "{url}");
            assert!(url.contains("/address/bc1q"), "{url}");
            assert!(get(&request, "timeoutMs").as_f64().unwrap() > 0.0);
            assert!(get(&request, "maxBytes").as_f64().unwrap() > 0.0);
        }
    }

    #[wasm_bindgen_test]
    async fn a_second_ask_for_the_same_balance_is_answered_from_memory() {
        forget_seen();
        let chain = WalletChain::new(esplora_account());
        chain.call("balances".to_owned(), bitcoin_request("")).await.unwrap();
        let first = seen().length();
        assert!(first >= 1);
        chain.call("balances".to_owned(), bitcoin_request("")).await.unwrap();
        assert_eq!(seen().length(), first, "the second ask is answered from memory");
        // `fresh` is the one way to ask the endpoints again.
        chain.call("balances".to_owned(), bitcoin_request(r#","fresh":true"#)).await.unwrap();
        assert!(seen().length() > first);
    }

    #[wasm_bindgen_test]
    async fn a_fetch_that_runs_out_of_time_is_an_error_to_try_again_not_a_hang() {
        forget_seen();
        let fetch = fetch_that(
            r#"
            const error = new Error("timed out");
            error.name = "TimeoutError";
            return Promise.reject(error);
            "#,
        );
        let chain = WalletChain::new(fetch);
        let error = chain.call("balances".to_owned(), bitcoin_request("")).await.unwrap_err();
        let error = parsed(&error.as_string().unwrap());
        assert_eq!(error["code"], "upstream_unavailable");
        assert_eq!(error["retryable"], true);
    }

    #[wasm_bindgen_test]
    async fn an_operation_the_wallet_does_not_have_is_refused_without_a_request() {
        forget_seen();
        let chain = WalletChain::new(fetch_that("return Promise.reject(new Error('never'));"));
        let error = chain.call("delete_everything".to_owned(), "{}".to_owned()).await.unwrap_err();
        assert_eq!(parsed(&error.as_string().unwrap())["code"], "invalid_request");
        assert_eq!(seen().length(), 0);
    }

    #[wasm_bindgen_test]
    async fn the_networks_are_known_without_asking_anyone() {
        forget_seen();
        let chain = WalletChain::new(fetch_that("return Promise.reject(new Error('never'));"));
        let networks = parsed(&chain.call("networks".to_owned(), String::new()).await.unwrap());
        assert!(networks.to_string().contains("bittensor"));
        assert_eq!(seen().length(), 0);
    }

    #[wasm_bindgen_test]
    fn what_is_worth_keeping_survives_a_round_trip_and_nothing_else_is_taken() {
        let chain = WalletChain::new(fetch_that("return Promise.reject(new Error('never'));"));
        let state = chain.export_state();
        parsed(&state);
        chain.import_state(&state);
        chain.import_state("not json at all");
        chain.import_state(r#"{"unrelated":true}"#);
        assert_eq!(chain.export_state(), state);
    }
}
