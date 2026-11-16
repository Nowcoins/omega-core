//! Platforms for tests: no network, a clock the test moves.
//!
//! * [`Script`]: answers a test sets up by hand, matched on a piece of the URL
//!   and of the body. A JSON-RPC helper answers by method.
//! * [`Replay`]: answers recorded from the live endpoints (read-only, keyless)
//!   by [`Recorder`], matched on the request's path and body (the JSON-RPC `id`
//!   and the host left out, so the order in which the pool visits endpoints does
//!   not matter).
//!
//! Both count time themselves: `sleep` moves the clock and returns at once, so a
//! test of pacing or of a circuit breaker takes no real time.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Method, Platform};

/// What a rule answers.
#[derive(Debug, Clone)]
pub enum Reply {
    /// An HTTP answer.
    Http {
        /// Status.
        status: u16,
        /// Headers (lower-case names).
        headers: Vec<(String, String)>,
        /// Body.
        body: Vec<u8>,
    },
    /// No answer.
    Fail(HttpError),
}

impl Reply {
    /// A 200 with a JSON body.
    #[must_use]
    pub fn json(body: &Value) -> Self {
        Self::Http { status: 200, headers: Vec::new(), body: body.to_string().into_bytes() }
    }

    /// An answer with a status and a text body.
    #[must_use]
    pub fn text(status: u16, body: &str) -> Self {
        Self::Http { status, headers: Vec::new(), body: body.as_bytes().to_vec() }
    }

    /// A JSON-RPC result.
    #[must_use]
    pub fn result(result: &Value) -> Self {
        Self::json(&json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }

    /// A JSON-RPC error.
    #[must_use]
    pub fn error(code: i64, message: &str) -> Self {
        Self::json(
            &json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } }),
        )
    }
}

#[derive(Debug)]
struct Rule {
    url: String,
    body: Option<String>,
    replies: Vec<Reply>,
    used: usize,
}

/// One request a test saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// `GET` or `POST`.
    pub method: Method,
    /// The URL.
    pub url: String,
    /// The body, as text.
    pub body: String,
    /// When it was sent, by the test clock.
    pub at: u64,
}

/// Answers a test sets up by hand.
#[derive(Debug, Default)]
pub struct Script {
    rules: Mutex<Vec<Rule>>,
    seen: Mutex<Vec<Seen>>,
    now: AtomicU64,
}

impl Script {
    /// An empty script whose clock starts at 2026-10-28 00:00:00 UTC.
    #[must_use]
    pub fn new() -> Self {
        let script = Self::default();
        script.now.store(1_793_145_600_000, Ordering::Relaxed);
        script
    }

    /// Answers requests whose URL contains `url` (and whose body contains
    /// `body`, where given) with `replies` in turn, the last one for ever.
    /// Rules are tried in the order they were added.
    pub fn on(&self, url: &str, body: Option<&str>, replies: Vec<Reply>) -> &Self {
        if let Ok(mut rules) = self.rules.lock() {
            rules.push(Rule {
                url: url.to_owned(),
                body: body.map(str::to_owned),
                replies,
                used: 0,
            });
        }
        self
    }

    /// As [`Self::on`], tried before every rule added so far (for a case more specific than a general
    /// rule already set).
    pub fn on_first(&self, url: &str, body: Option<&str>, replies: Vec<Reply>) -> &Self {
        if let Ok(mut rules) = self.rules.lock() {
            rules.insert(
                0,
                Rule { url: url.to_owned(), body: body.map(str::to_owned), replies, used: 0 },
            );
        }
        self
    }

    /// Answers a JSON-RPC `method` with a result, from any endpoint.
    pub fn rpc(&self, method: &str, result: &Value) -> &Self {
        self.on("", Some(&format!("\"method\":\"{method}\"")), vec![Reply::result(result)])
    }

    /// Answers a JSON-RPC `method` with an error, from any endpoint.
    pub fn rpc_error(&self, method: &str, code: i64, message: &str) -> &Self {
        self.on("", Some(&format!("\"method\":\"{method}\"")), vec![Reply::error(code, message)])
    }

    /// Answers `GET`s of a path with a JSON body.
    pub fn get(&self, path: &str, body: &Value) -> &Self {
        self.on(path, None, vec![Reply::json(body)])
    }

    /// Every request seen so far.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// How many requests contained `needle` in their URL or body.
    #[must_use]
    pub fn count(&self, needle: &str) -> usize {
        self.seen().iter().filter(|s| s.url.contains(needle) || s.body.contains(needle)).count()
    }

    /// Moves the clock.
    pub fn advance(&self, millis: u64) {
        self.now.fetch_add(millis, Ordering::Relaxed);
    }

    fn answer(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let body = request
            .body
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(Seen {
                method: request.method,
                url: request.url.clone(),
                body: body.clone(),
                at: self.now.load(Ordering::Relaxed),
            });
        }
        let mut rules = self.rules.lock().map_err(|_| HttpError::Network)?;
        let rule = rules.iter_mut().find(|rule| {
            request.url.contains(&rule.url)
                && rule.body.as_ref().is_none_or(|needle| body.contains(needle.as_str()))
        });
        let Some(rule) = rule else {
            // Nothing set up for it: as if the endpoint were down.
            return Err(HttpError::Network);
        };
        let reply = rule.replies.get(rule.used).or_else(|| rule.replies.last()).cloned();
        rule.used += 1;
        match reply {
            Some(Reply::Http { status, headers, body }) => {
                Ok(HttpResponse { status, headers, body })
            }
            Some(Reply::Fail(error)) => Err(error),
            None => Err(HttpError::Network),
        }
    }
}

impl Platform for Script {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move { self.answer(&request) })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        Box::pin(async move {
            self.now.fetch_add(millis, Ordering::Relaxed);
        })
    }

    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

// ---- recordings --------------------------------------------------------------

/// One recorded exchange.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// `GET` or `POST`.
    pub method: String,
    /// The request's path and query (the host is not part of the match).
    pub path: String,
    /// The request's body with the JSON-RPC `id` removed, or empty.
    pub body: String,
    /// The answer's status.
    pub status: u16,
    /// The answer's body.
    pub response: String,
}

/// What follows the endpoint's own address: `/address/bc1q...` for Esplora at
/// `https://mempool.space/api`, nothing for a node that is posted to at its base.
/// (The host and the base are not part of a match, so the order in which the pool
/// visits endpoints does not matter.)
fn path_of(url: &str) -> String {
    for network in crate::networks::ALL {
        for spec in crate::endpoints::specs(network) {
            if let Some(rest) = url.strip_prefix(spec.url) {
                return rest.to_owned();
            }
        }
    }
    let rest = url.strip_prefix("https://").unwrap_or(url);
    rest.find('/').map_or_else(String::new, |at| rest[at..].to_owned())
}

fn normal_body(body: &[u8]) -> String {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return String::from_utf8_lossy(body).into_owned();
    };
    if let Some(object) = value.as_object_mut() {
        object.remove("id");
    }
    value.to_string()
}

impl Entry {
    fn key(request: &HttpRequest) -> (String, String, String) {
        (
            if request.method == Method::Get { "GET" } else { "POST" }.to_owned(),
            path_of(&request.url),
            request.body.as_deref().map(normal_body).unwrap_or_default(),
        )
    }

    fn to_value(&self) -> Value {
        json!({
            "method": self.method,
            "path": self.path,
            "body": self.body,
            "status": self.status,
            "response": self.response,
        })
    }

    fn from_value(value: &Value) -> Option<Self> {
        Some(Self {
            method: value.get("method")?.as_str()?.to_owned(),
            path: value.get("path")?.as_str()?.to_owned(),
            body: value.get("body")?.as_str()?.to_owned(),
            status: u16::try_from(value.get("status")?.as_u64()?).ok()?,
            response: value.get("response")?.as_str()?.to_owned(),
        })
    }
}

/// Wraps a platform and remembers every exchange, for making a recording.
#[derive(Debug)]
pub struct Recorder<P> {
    inner: P,
    entries: Mutex<Vec<Entry>>,
}

impl<P: Platform> Recorder<P> {
    /// Records what `inner` answers.
    pub fn new(inner: P) -> Self {
        Self { inner, entries: Mutex::new(Vec::new()) }
    }

    /// The recording, as JSON text.
    #[must_use]
    pub fn to_json(&self) -> String {
        let entries = self.entries.lock().map(|e| e.clone()).unwrap_or_default();
        serde_json::to_string_pretty(&Value::Array(entries.iter().map(Entry::to_value).collect()))
            .unwrap_or_default()
    }
}

impl<P: Platform> Platform for Recorder<P> {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            let (method, path, body) = Entry::key(&request);
            let answer = self.inner.send(request).await?;
            // A rate limit or a server error is the moment's, not what the endpoint
            // says: a replay of it would never get past it.
            let passing = answer.status == 429 || answer.status >= 500;
            if let (false, Ok(mut entries)) = (passing, self.entries.lock()) {
                let new = Entry {
                    method,
                    path,
                    body,
                    status: answer.status,
                    response: String::from_utf8_lossy(&answer.body).into_owned(),
                };
                // The first answer to a request is the one kept, unless it was an
                // error body and this one is not: the pool went on to another endpoint
                // because the first could not serve it, and a replay should not.
                let same = |e: &Entry| {
                    (&e.method, &e.path, &e.body) == (&new.method, &new.path, &new.body)
                };
                match entries.iter_mut().find(|e| same(e)) {
                    Some(held)
                        if held.response.contains("\"error\"")
                            && !new.response.contains("\"error\"") =>
                    {
                        *held = new;
                    }
                    Some(_) => {}
                    None => entries.push(new),
                }
            }
            Ok(answer)
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        self.inner.sleep(millis)
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
}

/// Answers from a recording, on a clock fixed at the moment it was made.
#[derive(Debug)]
pub struct Replay {
    entries: Vec<Entry>,
    now: AtomicU64,
    misses: Mutex<Vec<String>>,
}

impl Replay {
    /// A replay of a recording made by [`Recorder::to_json`], with the clock at
    /// `now_ms`.
    ///
    /// # Panics
    /// If the recording is not one.
    #[must_use]
    pub fn new(recording: &str, now_ms: u64) -> Self {
        let parsed: Value = serde_json::from_str(recording).expect("a recording is JSON");
        let entries = parsed
            .as_array()
            .expect("a recording is a list")
            .iter()
            .map(|v| Entry::from_value(v).expect("a recording's entries are well formed"))
            .collect();
        Self { entries, now: AtomicU64::new(now_ms), misses: Mutex::new(Vec::new()) }
    }

    /// The requests that had no recorded answer.
    #[must_use]
    pub fn misses(&self) -> Vec<String> {
        self.misses.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

impl Platform for Replay {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            let key = Entry::key(&request);
            // An older recording kept the endpoint's base path (`/api/address/..`): a
            // path that ends the same way is the same request.
            let found = self
                .entries
                .iter()
                .find(|e| e.method == key.0 && e.body == key.2 && e.path.ends_with(key.1.as_str()));
            if let Some(entry) = found {
                Ok(HttpResponse {
                    status: entry.status,
                    headers: Vec::new(),
                    body: entry.response.clone().into_bytes(),
                })
            } else {
                if let Ok(mut misses) = self.misses.lock() {
                    misses.push(format!("{} {} {}", key.0, key.1, key.2));
                }
                Err(HttpError::Network)
            }
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        Box::pin(async move {
            self.now.fetch_add(millis, Ordering::Relaxed);
        })
    }

    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}
