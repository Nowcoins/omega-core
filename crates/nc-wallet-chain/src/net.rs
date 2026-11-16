//! Asking a network's endpoints: one request at a time with failover, several
//! at once for a second opinion, and JSON-RPC on top.
//!
//! The pool decides which endpoint and when ([`crate::pool`]); this decides
//! what a reply means. An endpoint's *failure* (nothing came back, a server
//! error, a rate limit, a challenge, an answer that is not what it documents,
//! a method it does not serve) is the pool's business and the request goes to
//! another endpoint. A *verdict* (the node answered, and its answer is "that
//! transaction reverts", "nonce too low", "no such account") is the caller's,
//! returned as it was written, without asking anyone else.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::error::{ChainError, ChainResult, clean};
use crate::platform::{HttpRequest, HttpResponse, Method, Platform};
use crate::pool::{EndpointSpec, Need, NoPick, Outcome, Pick, Pool};
use crate::util::bytes_from_hex;

/// How long one request may take.
pub const TIMEOUT_MS: u64 = 10_000;
/// The most bytes of an answer that are read: Bittensor's runtime metadata
/// (some 700 KB as hex) and a page of Esplora's transactions are the largest.
pub const MAX_BODY: usize = 8 << 20;
/// Endpoints one request is tried on before the network is called unavailable.
const MAX_TRIES: usize = 4;

/// A node's own error, as it wrote it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeError {
    /// JSON-RPC's `error.code`.
    pub code: i64,
    /// Its `error.message`.
    pub message: String,
    /// Its `error.data`, if any (a reverted call carries the revert there).
    pub data: Option<Value>,
}

impl NodeError {
    /// The message in lower case, to match phrases against.
    #[must_use]
    pub fn lower(&self) -> String {
        self.message.to_ascii_lowercase()
    }

    /// The error as JSON-RPC writes it.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(data) = &self.data {
            error["data"] = data.clone();
        }
        error
    }
}

/// What an endpoint said to a call, and which endpoint it was.
#[derive(Debug, Clone, PartialEq)]
pub struct Raw {
    /// The endpoint's index in the network's list.
    pub index: usize,
    /// Its result, or the error it wrote.
    pub outcome: Result<Value, NodeError>,
}

/// What a judge makes of an answer.
#[derive(Debug)]
pub enum Judged<T> {
    /// The endpoint answered; this is what it said.
    Done(T),
    /// The endpoint cannot be believed or used for this: ask another.
    Retry(Outcome),
}

/// A network's endpoints, over a platform.
#[derive(Debug)]
pub struct Net {
    platform: Arc<dyn Platform>,
    pool: Pool,
    specs: &'static [EndpointSpec],
    /// Where JSON-RPC is posted, after the endpoint's base URL (`/jsonrpc` on
    /// TRON, whose nodes speak it beside their own HTTP API).
    rpc_path: &'static str,
    next_id: AtomicU64,
}

impl std::fmt::Debug for dyn Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform")
    }
}

/// Builds the request for an endpoint. Where the target has threads (Android,
/// the host) the closure must be `Sync`, so that the future that holds it can
/// be sent; under WebAssembly there is one thread and no such bound.
#[cfg(not(target_arch = "wasm32"))]
type Build<'a> = dyn Fn(&'static EndpointSpec) -> HttpRequest + Sync + 'a;
#[cfg(target_arch = "wasm32")]
type Build<'a> = dyn Fn(&'static EndpointSpec) -> HttpRequest + 'a;
/// Reads an endpoint's answer.
#[cfg(not(target_arch = "wasm32"))]
type Judge<'a, T> = dyn Fn(&'static EndpointSpec, &HttpResponse) -> Judged<T> + Sync + 'a;
#[cfg(target_arch = "wasm32")]
type Judge<'a, T> = dyn Fn(&'static EndpointSpec, &HttpResponse) -> Judged<T> + 'a;

/// How an attempt on one endpoint ended, after the pool was told.
enum Attempt<T> {
    Got(T),
    Failed,
    /// The endpoint is resting or asked for time: for how many seconds at least.
    Busy(u64),
}

impl Net {
    /// A network over `specs`.
    #[must_use]
    pub fn new(platform: Arc<dyn Platform>, specs: &'static [EndpointSpec]) -> Self {
        Self { platform, pool: Pool::new(specs), specs, rpc_path: "", next_id: AtomicU64::new(1) }
    }

    /// Posts JSON-RPC to `path` after each endpoint's base URL.
    #[must_use]
    pub const fn with_rpc_path(mut self, path: &'static str) -> Self {
        self.rpc_path = path;
        self
    }

    /// The platform's clock.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.platform.now_ms()
    }

    /// The platform.
    #[must_use]
    pub fn platform(&self) -> &Arc<dyn Platform> {
        &self.platform
    }

    /// The endpoints' health, for a diagnostics screen.
    #[must_use]
    pub fn health(&self) -> Vec<Value> {
        self.pool.health(self.now())
    }

    /// The spec of an endpoint by index.
    #[must_use]
    pub fn spec(&self, index: usize) -> Option<&'static EndpointSpec> {
        self.specs.get(index)
    }

    /// How many endpoints the network has.
    #[must_use]
    pub fn endpoints(&self) -> usize {
        self.specs.len()
    }

    /// One try on the chosen endpoint: waits for its pace, sends, and tells the
    /// pool how it went.
    async fn attempt<T>(&self, pick: Pick, build: &Build<'_>, judge: &Judge<'_, T>) -> Attempt<T> {
        let Some(spec) = self.specs.get(pick.index) else { return Attempt::Failed };
        if pick.wait_ms > 0 {
            self.platform.sleep(pick.wait_ms).await;
        }
        let started = self.now();
        let sent = self.platform.send(build(spec)).await;
        let now = self.now();
        let took = now.saturating_sub(started);
        let Ok(response) = sent else {
            self.pool.report(now, pick.index, Outcome::Failed);
            return Attempt::Failed;
        };
        if response.is_challenge() {
            self.pool.report(now, pick.index, Outcome::Challenged);
            return Attempt::Busy(300);
        }
        match response.status {
            429 => {
                let wait = response.retry_after_seconds();
                self.pool.report(now, pick.index, Outcome::RateLimited(wait));
                return Attempt::Busy(wait.unwrap_or(10));
            }
            // Not ours to read: the endpoint is down, wants a key, or refuses us.
            401 | 402 | 403 | 407 | 408 | 425 | 451 | 500..=599 => {
                self.pool.report(now, pick.index, Outcome::Failed);
                return Attempt::Failed;
            }
            _ => {}
        }
        match judge(spec, &response) {
            Judged::Done(value) => {
                self.pool.report(now, pick.index, Outcome::Ok(took));
                Attempt::Got(value)
            }
            Judged::Retry(outcome) => {
                self.pool.report(now, pick.index, outcome);
                match outcome {
                    Outcome::RateLimited(seconds) => Attempt::Busy(seconds.unwrap_or(10)),
                    _ => Attempt::Failed,
                }
            }
        }
    }

    /// Asks endpoints in turn until one answers.
    ///
    /// `other_than` are endpoints already asked: they are not asked again, and
    /// their operators are preferably not asked either (the operators of earlier
    /// opinions). Returns the answer and the index of the endpoint it came from.
    pub async fn request<T>(
        &self,
        need: Need,
        other_than: &[usize],
        build: &Build<'_>,
        judge: &Judge<'_, T>,
    ) -> ChainResult<(T, usize)> {
        // Endpoints named are not asked again, and their operators are
        // preferably not asked at all.
        let mut tried: Vec<usize> = other_than.to_vec();
        let first = tried.len();
        let mut busy: Option<u64> = None;
        loop {
            if tried.len() - first >= MAX_TRIES {
                return Err(busy.map_or(ChainError::Unavailable, |s| ChainError::Busy {
                    retry_after_seconds: s,
                }));
            }
            let pick = match self.pool.pick(self.now(), need, &tried, other_than) {
                Ok(pick) => pick,
                Err(NoPick::Resting(ms)) => {
                    let seconds = ms.div_ceil(1000);
                    return Err(ChainError::Busy {
                        retry_after_seconds: busy.map_or(seconds, |b| b.min(seconds)),
                    });
                }
                Err(NoPick::Exhausted) => {
                    return Err(busy.map_or(ChainError::Unavailable, |s| ChainError::Busy {
                        retry_after_seconds: s,
                    }));
                }
            };
            tried.push(pick.index);
            match self.attempt(pick, build, judge).await {
                Attempt::Got(value) => return Ok((value, pick.index)),
                Attempt::Failed => {}
                Attempt::Busy(seconds) => busy = Some(busy.map_or(seconds, |b| b.min(seconds))),
            }
        }
    }

    /// Asks `count` endpoints at once, preferring endpoints of different
    /// operators, and returns the answers that came with the endpoint each
    /// came from. Fewer than `count` come back where the network could not
    /// supply them; none is an error.
    pub async fn request_many<T>(
        &self,
        need: Need,
        count: usize,
        build: &Build<'_>,
        judge: &Judge<'_, T>,
    ) -> ChainResult<Vec<(T, usize)>> {
        let mut picks: Vec<Pick> = Vec::new();
        let mut indexes: Vec<usize> = Vec::new();
        let mut busy: Option<u64> = None;
        while picks.len() < count {
            match self.pool.pick(self.now(), need, &indexes, &indexes) {
                Ok(pick) => {
                    indexes.push(pick.index);
                    picks.push(pick);
                }
                Err(NoPick::Resting(ms)) => {
                    busy = Some(ms.div_ceil(1000));
                    break;
                }
                Err(NoPick::Exhausted) => break,
            }
        }
        let attempts = picks
            .iter()
            .map(|&pick| async move { (pick.index, self.attempt(pick, build, judge).await) });
        let mut answers: Vec<(T, usize)> = Vec::new();
        let mut failed = 0_usize;
        for (index, attempt) in futures::future::join_all(attempts).await {
            match attempt {
                Attempt::Got(value) => answers.push((value, index)),
                Attempt::Failed => failed += 1,
                Attempt::Busy(seconds) => {
                    failed += 1;
                    busy = Some(busy.map_or(seconds, |b| b.min(seconds)));
                }
            }
        }
        // Replace what failed, one at a time, from endpoints not yet tried.
        let mut spent = indexes.len();
        while answers.len() < count && failed > 0 && spent < MAX_TRIES + count {
            // Those that failed are not asked again, but their operators are still candidates:
            // only the operators that have *answered* are heard from already.
            let answered: Vec<usize> = answers.iter().map(|(_, index)| *index).collect();
            let Ok(pick) = self.pool.pick(self.now(), need, &indexes, &answered) else { break };
            indexes.push(pick.index);
            spent += 1;
            match self.attempt(pick, build, judge).await {
                Attempt::Got(value) => {
                    answers.push((value, pick.index));
                    failed -= 1;
                }
                Attempt::Failed => {}
                Attempt::Busy(seconds) => busy = Some(busy.map_or(seconds, |b| b.min(seconds))),
            }
        }
        if answers.is_empty() {
            return Err(busy
                .map_or(ChainError::Unavailable, |s| ChainError::Busy { retry_after_seconds: s }));
        }
        Ok(answers)
    }

    // ---- log queries ---------------------------------------------------------

    /// The widest `eth_getLogs` any endpoint that is not resting answers for a
    /// query starting `depth` blocks back with a span of at least `min_span`
    /// (`u64::MAX`: no limit), or `None`.
    #[must_use]
    pub fn log_reach(&self, depth: u64, avoid: &[usize], min_span: u64) -> Option<u64> {
        self.pool.log_reach(Some(self.now()), depth, avoid, min_span)
    }

    /// Whether a bot challenge stands in front of every endpoint that serves
    /// `need` (see [`Pool::blocked`]).
    #[must_use]
    pub fn blocked(&self, need: Need) -> bool {
        self.pool.blocked(self.now(), need)
    }

    /// As [`Self::log_deepest`], counting endpoints that are resting for now.
    #[must_use]
    pub fn log_deepest_ever(&self, min_span: u64) -> Option<u64> {
        self.pool.log_deepest(None, min_span)
    }

    /// As [`Self::log_reach`], counting endpoints that are resting for now: is it
    /// possible at all?
    #[must_use]
    pub fn log_reach_ever(&self, depth: u64, min_span: u64) -> Option<u64> {
        self.pool.log_reach(None, depth, &[], min_span)
    }

    /// How far back any endpoint that is not resting answers logs with a span of
    /// at least `min_span` (`u64::MAX`: all the way), or `None`.
    #[must_use]
    pub fn log_deepest(&self, min_span: u64) -> Option<u64> {
        self.pool.log_deepest(Some(self.now()), min_span)
    }

    /// Notes that endpoint `index` refused a log query wider than `span`.
    pub fn learn_span(&self, index: usize, span: u64) {
        self.pool.learn_span(index, span);
    }

    /// Notes that endpoint `index` refused a log query starting `depth` blocks back.
    pub fn learn_depth(&self, index: usize, depth: u64) {
        self.pool.learn_depth(index, depth);
    }

    /// One JSON-RPC call whose refusal is the caller's to read: asks the
    /// endpoint the pool picks for `need`, and hands back what it said, a range
    /// or size refusal included, instead of treating that as the endpoint being
    /// at fault. Only an endpoint that did not answer at all (no connection, a
    /// server error, a rate limit, a challenge, not JSON-RPC) is passed over for
    /// the next. `avoid` are endpoints already seen to be no use for this.
    pub async fn rpc_raw(
        &self,
        need: Need,
        avoid: &[usize],
        method: &'static str,
        params: &Value,
    ) -> ChainResult<Raw> {
        let need = Need { method, ..need };
        let mut tried: Vec<usize> = avoid.to_vec();
        let first = tried.len();
        let mut busy: Option<u64> = None;
        loop {
            if tried.len() - first >= MAX_TRIES {
                return Err(busy.map_or(ChainError::Unavailable, |s| ChainError::Busy {
                    retry_after_seconds: s,
                }));
            }
            let pick = match self.pool.pick(self.now(), need, &tried, &[]) {
                Ok(pick) => pick,
                Err(NoPick::Resting(ms)) => {
                    return Err(ChainError::Busy { retry_after_seconds: ms.div_ceil(1000) });
                }
                Err(NoPick::Exhausted) => {
                    return Err(busy.map_or(ChainError::Unavailable, |s| ChainError::Busy {
                        retry_after_seconds: s,
                    }));
                }
            };
            tried.push(pick.index);
            let Some(spec) = self.specs.get(pick.index) else { continue };
            if pick.wait_ms > 0 {
                self.platform.sleep(pick.wait_ms).await;
            }
            let started = self.now();
            let sent = self.platform.send(self.rpc_request(spec, method, params)).await;
            let now = self.now();
            let Ok(response) = sent else {
                self.pool.report(now, pick.index, Outcome::Failed);
                continue;
            };
            if response.is_challenge() {
                self.pool.report(now, pick.index, Outcome::Challenged);
                continue;
            }
            if response.status == 429 || (500..600).contains(&response.status) {
                let wait = response.retry_after_seconds();
                self.pool.report(
                    now,
                    pick.index,
                    if response.status == 429 {
                        Outcome::RateLimited(wait)
                    } else {
                        Outcome::Failed
                    },
                );
                if response.status == 429 {
                    busy = Some(busy.map_or(wait.unwrap_or(10), |b| b.min(wait.unwrap_or(10))));
                }
                continue;
            }
            let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
                self.pool.report(now, pick.index, Outcome::Failed);
                continue;
            };
            let outcome = if let Some(error) = body.get("error").filter(|e| !e.is_null()) {
                Err(NodeError {
                    code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                    message: clean_message(error.get("message")),
                    data: error.get("data").cloned(),
                })
            } else if let Some(result) = body.get("result") {
                Ok(result.clone())
            } else {
                self.pool.report(now, pick.index, Outcome::Failed);
                continue;
            };
            // It answered; what it answered is for the caller to read.
            self.pool.report(now, pick.index, Outcome::Ok(now.saturating_sub(started)));
            return Ok(Raw { index: pick.index, outcome });
        }
    }

    // ---- JSON-RPC ----------------------------------------------------------

    fn rpc_request(
        &self,
        spec: &'static EndpointSpec,
        method: &str,
        params: &Value,
    ) -> HttpRequest {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        HttpRequest {
            method: Method::Post,
            url: format!("{}{}", spec.url, self.rpc_path),
            body: Some(body.to_string().into_bytes()),
            content_type: Some("application/json"),
            timeout_ms: TIMEOUT_MS,
            max_bytes: MAX_BODY,
        }
    }

    /// One JSON-RPC call, with failover. The node's own error comes back as
    /// `Ok(Err(..))`: the endpoint answered.
    pub async fn rpc(
        &self,
        need: Need,
        method: &'static str,
        params: &Value,
    ) -> ChainResult<Result<Value, NodeError>> {
        self.rpc_from(need, &[], method, params).await.map(|(answer, _)| answer)
    }

    /// As [`Self::rpc`], preferring an endpoint of another operator than those
    /// in `other_than`, and saying which endpoint answered.
    pub async fn rpc_from(
        &self,
        need: Need,
        other_than: &[usize],
        method: &'static str,
        params: &Value,
    ) -> ChainResult<(Result<Value, NodeError>, usize)> {
        let need = Need { method, ..need };
        self.request(
            need,
            other_than,
            &|spec| self.rpc_request(spec, method, params),
            &|_, response| judge_rpc(response, method),
        )
        .await
    }

    /// A web page's call, passed through: as [`Self::rpc`], except that the node's words teach
    /// the pool nothing (see [`Caller`]).
    pub async fn rpc_site(
        &self,
        need: Need,
        method: &'static str,
        params: &Value,
    ) -> ChainResult<Result<Value, NodeError>> {
        let need = Need { method, ..need };
        self.request(need, &[], &|spec| self.rpc_request(spec, method, params), &|_, response| {
            judge_rpc_for(Caller::Site, response, method)
        })
        .await
        .map(|(answer, _)| answer)
    }

    /// The same call asked of `count` endpoints of different operators.
    pub async fn rpc_many(
        &self,
        need: Need,
        count: usize,
        method: &'static str,
        params: &Value,
    ) -> ChainResult<Vec<(Result<Value, NodeError>, usize)>> {
        let need = Need { method, ..need };
        self.request_many(
            need,
            count,
            &|spec| self.rpc_request(spec, method, params),
            &|_, response| judge_rpc(response, method),
        )
        .await
    }

    // ---- REST --------------------------------------------------------------

    /// `GET`s `path` (beginning with `/`) with failover. The answer is the
    /// status and body of the first endpoint that gave one a caller can read
    /// (`2xx`, `400`, `404`, `409`, `410`, `422`).
    pub async fn get(&self, need: Need, path: &str) -> ChainResult<(u16, Vec<u8>)> {
        self.get_from(need, &[], path).await.map(|(answer, _)| answer)
    }

    /// As [`Self::get`], saying which endpoint answered and preferring others
    /// than those in `other_than`.
    pub async fn get_from(
        &self,
        need: Need,
        other_than: &[usize],
        path: &str,
    ) -> ChainResult<((u16, Vec<u8>), usize)> {
        self.request(
            need,
            other_than,
            &|spec| HttpRequest {
                method: Method::Get,
                url: format!("{}{path}", spec.url),
                body: None,
                content_type: None,
                timeout_ms: TIMEOUT_MS,
                max_bytes: MAX_BODY,
            },
            &|_, response| judge_rest(path, response),
        )
        .await
    }

    /// `GET`s `path` of `count` endpoints of different operators.
    pub async fn get_many(
        &self,
        need: Need,
        count: usize,
        path: &str,
    ) -> ChainResult<Vec<((u16, Vec<u8>), usize)>> {
        self.request_many(
            need,
            count,
            &|spec| HttpRequest {
                method: Method::Get,
                url: format!("{}{path}", spec.url),
                body: None,
                content_type: None,
                timeout_ms: TIMEOUT_MS,
                max_bytes: MAX_BODY,
            },
            &|_, response| judge_rest(path, response),
        )
        .await
    }

    /// `POST`s `body` to `path` with failover.
    pub async fn post(
        &self,
        need: Need,
        path: &str,
        content_type: &'static str,
        body: &[u8],
    ) -> ChainResult<(u16, Vec<u8>)> {
        self.post_from(need, &[], path, content_type, body).await.map(|(answer, _)| answer)
    }

    /// As [`Self::post`], saying which endpoint answered and not using the operators of
    /// those in `other_than` (a rule where `need` is [`Need::independent`], else a preference).
    pub async fn post_from(
        &self,
        need: Need,
        other_than: &[usize],
        path: &str,
        content_type: &'static str,
        body: &[u8],
    ) -> ChainResult<((u16, Vec<u8>), usize)> {
        self.request(
            need,
            other_than,
            &|spec| HttpRequest {
                method: Method::Post,
                url: format!("{}{path}", spec.url),
                body: Some(body.to_vec()),
                content_type: Some(content_type),
                timeout_ms: TIMEOUT_MS,
                max_bytes: MAX_BODY,
            },
            &|_, response| judge_rest(path, response),
        )
        .await
    }

    /// `POST`s `body` to `path` of `count` endpoints of different operators.
    pub async fn post_many(
        &self,
        need: Need,
        count: usize,
        path: &str,
        content_type: &'static str,
        body: &[u8],
    ) -> ChainResult<Vec<((u16, Vec<u8>), usize)>> {
        self.request_many(
            need,
            count,
            &|spec| HttpRequest {
                method: Method::Post,
                url: format!("{}{path}", spec.url),
                body: Some(body.to_vec()),
                content_type: Some(content_type),
                timeout_ms: TIMEOUT_MS,
                max_bytes: MAX_BODY,
            },
            &|_, response| judge_rest(path, response),
        )
        .await
    }
}

/// Reads a REST answer: the statuses a caller can make sense of are passed on, unless the node's
/// answer is the node saying it does not run what was asked ([`rest_endpoint_problem`]).
fn judge_rest(path: &str, response: &HttpResponse) -> Judged<(u16, Vec<u8>)> {
    match response.status {
        200..=299 | 400 | 404 | 409 | 410 | 422 => match rest_endpoint_problem(path, response) {
            Some(problem) => Judged::Retry(problem),
            None => Judged::Done((response.status, response.body.clone())),
        },
        _ => Judged::Retry(Outcome::Failed),
    }
}

/// Whether a REST answer is the node saying it is run without the method asked, which is the
/// endpoint's limit and not a verdict on the call.
///
/// A TRON node run without constant calls (Pocket's gateway is one) answers
/// `triggerconstantcontract` with a `200` of `CONTRACT_VALIDATE_ERROR` and the words "this node does
/// not support constant", written in hex. A call that ran carries the `energy_used` or
/// `constant_result` it made, a revert has both, and any other `CONTRACT_VALIDATE_ERROR` (a contract
/// that is not there) is the call's own: only that exact answer from the node itself counts, so a
/// call a site made up cannot switch a method off.
fn rest_endpoint_problem(path: &str, response: &HttpResponse) -> Option<Outcome> {
    const METHOD: &str = "triggerconstantcontract";
    if !path.ends_with(METHOD) {
        return None;
    }
    let answer: Value = serde_json::from_slice(&response.body).ok()?;
    let result = answer.get("result")?;
    let words = result.get("message").and_then(Value::as_str).and_then(bytes_from_hex)?;
    let limit = result.get("code").and_then(Value::as_str) == Some("CONTRACT_VALIDATE_ERROR")
        && String::from_utf8_lossy(&words)
            .to_ascii_lowercase()
            .contains("does not support constant")
        && answer.get("energy_used").is_none()
        && answer.get("constant_result").is_none();
    limit.then_some(Outcome::MethodOff(METHOD))
}

/// Whose call it is, which decides how much of a node's *words* may teach the pool.
///
/// The wallet's own reads may learn from what a node says ("rate limit", "method not
/// found"). A site's call may not: a site picks the parameters, and some nodes echo them
/// back, so a site could write the words that switch a method off for the wallet's own
/// reads. A site's call teaches the pool only through the error *code* a node chose
/// (`-32601`, `-32005`, ...), and through the transport (statuses, timeouts), which no
/// parameter can forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The wallet reading for itself.
    Wallet,
    /// A web page's request, passed through.
    Site,
}

/// Reads a JSON-RPC answer, for the wallet's own call.
fn judge_rpc(response: &HttpResponse, method: &'static str) -> Judged<Result<Value, NodeError>> {
    judge_rpc_for(Caller::Wallet, response, method)
}

/// Reads a JSON-RPC answer for `caller`.
fn judge_rpc_for(
    caller: Caller,
    response: &HttpResponse,
    method: &'static str,
) -> Judged<Result<Value, NodeError>> {
    let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
        return Judged::Retry(Outcome::Failed);
    };
    if let Some(error) = body.get("error").filter(|e| !e.is_null()) {
        let node = NodeError {
            code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: clean_message(error.get("message")),
            data: error.get("data").cloned(),
        };
        return match endpoint_problem(&node, method, caller == Caller::Wallet) {
            Some(outcome) => Judged::Retry(outcome.with_method(method)),
            None => Judged::Done(Err(node)),
        };
    }
    match body.get("result") {
        Some(result) => Judged::Done(Ok(result.clone())),
        // Neither a result nor an error: not a JSON-RPC answer.
        None => Judged::Retry(Outcome::Failed),
    }
}

trait WithMethod {
    fn with_method(self, method: &'static str) -> Outcome;
}

impl WithMethod for Outcome {
    fn with_method(self, method: &'static str) -> Outcome {
        match self {
            Outcome::MethodOff(_) => Outcome::MethodOff(method),
            other => other,
        }
    }
}

fn clean_message(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => clean(text),
        Some(other) => clean(&other.to_string()),
        None => String::new(),
    }
}

/// Whether a contract's own execution failed (a revert, or a custom error): that is a
/// verdict on the call, written by the contract, and never the endpoint's fault.
///
/// A revert carries text the contract chose ("transfers not allowed", "disabled", "rate
/// limit"), so nothing in a reverted call's words may be read as a statement about the
/// endpoint. The reason is passed on to the caller as it was written.
fn is_revert(error: &NodeError) -> bool {
    let lower = error.lower();
    let data = error.data.as_ref().and_then(Value::as_str);
    error.code == 3
        || lower.contains("revert")
        || lower.contains("vm execution error")
        // Revert data, from a node that wrote the reason elsewhere.
        || (matches!(error.code, -32000 | -32015)
            && data.is_some_and(|d| d.starts_with("0x") && d.len() > 2))
}

/// Whether a node's error is about the *endpoint* (it limits us, does not
/// serve the method, is behind, or wants a key) and not about the *request*.
/// A revert, a nonce, a balance are about the request: they are verdicts.
///
/// `trust_text` is whether the node's words may be read (the wallet's own call) or only its
/// error code (a site's call: see [`Caller`]). An execution failure is never the endpoint's.
fn endpoint_problem(error: &NodeError, method: &str, trust_text: bool) -> Option<Outcome> {
    if is_revert(error) {
        return None;
    }
    // The codes nodes chose, which no parameter writes.
    if matches!(error.code, -32005 | -32029 | -32097) {
        return Some(Outcome::RateLimited(None));
    }
    if matches!(error.code, -32601 | -32604) {
        return Some(Outcome::MethodOff(""));
    }
    if !trust_text {
        return None;
    }
    let lower = error.lower();
    let has = |phrases: &[&str]| phrases.iter().any(|phrase| lower.contains(phrase));
    if has(&[
        "rate limit",
        "rate-limit",
        "too many requests",
        "cu limit",
        "compute units",
        "daily request",
        "quota",
        "throttle",
    ]) {
        return Some(Outcome::RateLimited(None));
    }
    // What executes code (a call, an estimate) is answered with the code's verdicts; only a
    // node saying plainly that it has no such method takes the method off. The wider words
    // ("not allowed", "disabled", "too large") are for the calls that read a range.
    let executes = matches!(method, "eth_call" | "eth_estimateGas");
    if has(&[
        "method not found",
        "method not available",
        "does not exist/is not available",
        "unsupported method",
        "does not support",
    ]) || (!executes
        && has(&[
            "not supported",
            "disabled",
            "request blocked",
            "not allowed",
            "limit exceeded",
            "exceeds the range",
            "range limit",
            "block range",
            "too large",
            "query returned more than",
            "exceed maximum",
        ]))
    {
        return Some(Outcome::MethodOff(""));
    }
    // "Indexed requests require a personal token": the endpoint will not serve this
    // call without an account; another is asked, and this one is left alone for it.
    if has(&[
        "personal token",
        "requires a token",
        "require a token",
        "need a token",
        "token is required",
    ]) {
        return Some(Outcome::MethodOff(""));
    }
    if has(&[
        "api key",
        "apikey",
        "unauthorized",
        "authentication",
        "token required",
        "invalid token",
        "forbidden",
        "payment required",
    ]) {
        return Some(Outcome::Failed);
    }
    // A node that is behind or has pruned what was asked.
    if has(&[
        "header not found",
        "missing trie node",
        "block not found",
        "unknown block",
        "state not available",
        "pruned",
        "not synced",
        "syncing",
        "no historical rpc",
        "historical state",
    ]) {
        return Some(Outcome::Failed);
    }
    if has(&[
        "timeout",
        "timed out",
        "temporarily unavailable",
        "overloaded",
        "try again",
        "internal error",
        "service unavailable",
        "bad gateway",
        "capacity",
    ]) {
        return Some(Outcome::Failed);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(code: i64, message: &str) -> NodeError {
        NodeError { code, message: message.to_owned(), data: None }
    }

    #[test]
    fn a_verdict_is_not_an_endpoints_problem() {
        for verdict in [
            node(3, "execution reverted: ERC20: transfer amount exceeds balance"),
            node(-32000, "nonce too low"),
            node(-32000, "insufficient funds for gas * price + value"),
            node(-32000, "replacement transaction underpriced"),
            node(-32000, "already known"),
            node(-32602, "invalid argument 0: json: cannot unmarshal hex string"),
        ] {
            assert_eq!(endpoint_problem(&verdict, "eth_call", true), None, "{}", verdict.message);
        }
    }

    #[test]
    fn a_limit_a_missing_method_a_pruned_block_are_the_endpoints() {
        assert_eq!(
            endpoint_problem(&node(-32005, "limit exceeded"), "eth_getLogs", true),
            Some(Outcome::RateLimited(None))
        );
        assert_eq!(
            endpoint_problem(&node(429, "Too Many Requests"), "eth_getLogs", true),
            Some(Outcome::RateLimited(None))
        );
        assert_eq!(
            endpoint_problem(
                &node(-32601, "the method eth_getLogs does not exist"),
                "eth_getLogs",
                true
            ),
            Some(Outcome::MethodOff(""))
        );
        assert_eq!(
            endpoint_problem(&node(-32000, "Request blocked"), "eth_getLogs", true),
            Some(Outcome::MethodOff(""))
        );
        assert_eq!(
            endpoint_problem(&node(-32000, "missing trie node abc"), "eth_call", true),
            Some(Outcome::Failed)
        );
        assert_eq!(
            endpoint_problem(&node(-32000, "header not found"), "eth_call", true),
            Some(Outcome::Failed)
        );
    }

    #[test]
    fn an_answer_that_is_neither_a_result_nor_an_error_is_no_answer() {
        let reply = |body: &str| HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        assert!(matches!(judge_rpc(&reply("<html>"), "eth_call"), Judged::Retry(Outcome::Failed)));
        assert!(matches!(
            judge_rpc(&reply(r#"{"jsonrpc":"2.0","id":1}"#), "eth_call"),
            Judged::Retry(Outcome::Failed)
        ));
        match judge_rpc(&reply(r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#), "eth_call") {
            Judged::Done(Ok(value)) => assert_eq!(value, json!("0x1")),
            other => panic!("{other:?}"),
        }
        match judge_rpc(
            &reply(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x08c3"}}"#,
            ),
            "eth_call",
        ) {
            Judged::Done(Err(error)) => {
                assert_eq!((error.code, error.data), (3, Some(json!("0x08c3"))));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_tron_node_that_runs_no_constant_calls_says_so_in_a_200_and_that_is_the_nodes_limit() {
        let path = "/wallet/triggerconstantcontract";
        let reply = |body: &Value| HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        };
        let error = |words: &str| {
            reply(&json!({ "result": { "code": "CONTRACT_VALIDATE_ERROR",
                "message": hex::encode(words) } }))
        };
        // The node's own limit: another endpoint is asked, and this one is rested for the method.
        assert!(matches!(
            judge_rest(path, &error("this node does not support constant")),
            Judged::Retry(Outcome::MethodOff("triggerconstantcontract"))
        ));
        // The call's own verdicts are for the caller: a contract that is not there, a revert (which
        // carries the energy it used), a call that went through.
        assert!(matches!(
            judge_rest(path, &error("Smart contract is not exist.")),
            Judged::Done(_)
        ));
        let revert = json!({ "result": { "result": true, "message": hex::encode("REVERT opcode executed") },
                             "constant_result": [""], "energy_used": 8624 });
        assert!(matches!(judge_rest(path, &reply(&revert)), Judged::Done(_)));
        let done = json!({ "result": { "result": true }, "energy_used": 64285, "constant_result": ["00"] });
        assert!(matches!(judge_rest(path, &reply(&done)), Judged::Done(_)));
        // The same words at any other path are nothing the pool acts on.
        assert!(matches!(
            judge_rest("/wallet/getaccount", &error("this node does not support constant")),
            Judged::Done(_)
        ));
        // And a body that is not JSON is passed on as it always was.
        let junk = HttpResponse { status: 200, headers: Vec::new(), body: b"<html>".to_vec() };
        assert!(matches!(judge_rest(path, &junk), Judged::Done(_)));
    }

    fn with_data(code: i64, message: &str, data: &str) -> NodeError {
        NodeError { code, message: message.to_owned(), data: Some(json!(data)) }
    }

    #[test]
    fn a_contracts_own_words_never_say_anything_about_the_endpoint() {
        // Every phrase that would take a method off, rate-limit an endpoint or fail it, written by a
        // contract in its revert reason. It is the contract's verdict, and it reaches the caller.
        for reason in [
            "transfers not allowed",
            "disabled",
            "limit exceeded",
            "rate limit",
            "method not found",
            "too large",
            "forbidden",
            "internal error",
            "pruned",
            "personal token",
        ] {
            for method in ["eth_call", "eth_estimateGas"] {
                for error in [
                    node(3, &format!("execution reverted: {reason}")),
                    node(-32000, &format!("execution reverted: {reason}")),
                    node(-32015, &format!("VM execution error: {reason}")),
                    with_data(-32000, reason, "0x08c379a0000000000000000000000000"),
                    node(3, reason),
                    node(-32603, &format!("Reverted: {reason}")),
                ] {
                    assert_eq!(
                        endpoint_problem(&error, method, true),
                        None,
                        "{method}: {} ({})",
                        error.message,
                        error.code
                    );
                }
            }
        }
    }

    #[test]
    fn a_reverting_call_is_handed_back_with_its_reason_and_teaches_the_pool_nothing() {
        let reply = |body: &str| HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        let reverted = reply(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted: transfers not allowed","data":"0x08c379a0"}}"#,
        );
        for caller in [Caller::Wallet, Caller::Site] {
            match judge_rpc_for(caller, &reverted, "eth_call") {
                Judged::Done(Err(error)) => {
                    assert_eq!(error.message, "execution reverted: transfers not allowed");
                    assert_eq!(error.data, Some(json!("0x08c379a0")));
                }
                other => panic!("{caller:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_sites_call_teaches_the_pool_only_through_codes_not_through_words() {
        // The words are the same either way; a node that echoes a site's parameter into its error cannot
        // be made to say them for the wallet.
        let echo = node(-32602, "invalid argument 0: rate limit; method not found; disabled");
        assert!(endpoint_problem(&echo, "eth_getLogs", true).is_some());
        assert_eq!(endpoint_problem(&echo, "eth_getLogs", false), None);
        // A code is a node's own choice: it counts for a site's call too.
        assert_eq!(
            endpoint_problem(&node(-32601, "x"), "eth_getLogs", false),
            Some(Outcome::MethodOff(""))
        );
        assert_eq!(
            endpoint_problem(&node(-32005, "x"), "eth_getLogs", false),
            Some(Outcome::RateLimited(None))
        );
    }

    #[test]
    fn what_executes_code_is_not_taken_off_for_the_wider_words() {
        // A non-reverting failure of a call or an estimate with these words is the call's, not the
        // endpoint's; the same words on a range query are the endpoint's limit.
        for method in ["eth_call", "eth_estimateGas"] {
            assert_eq!(endpoint_problem(&node(-32000, "disabled"), method, true), None);
            assert_eq!(endpoint_problem(&node(-32000, "not allowed"), method, true), None);
            assert_eq!(endpoint_problem(&node(-32000, "request too large"), method, true), None);
        }
        assert_eq!(
            endpoint_problem(&node(-32000, "block range too large"), "eth_getLogs", true),
            Some(Outcome::MethodOff(""))
        );
        // A node plainly lacking the method is still the endpoint's.
        assert_eq!(
            endpoint_problem(
                &node(-32000, "the method eth_call does not exist/is not available"),
                "eth_call",
                true
            ),
            Some(Outcome::MethodOff(""))
        );
    }
}
