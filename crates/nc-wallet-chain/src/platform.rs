//! What the chain client needs from the device: an HTTPS client, a clock and a
//! way to wait.
//!
//! Everything else in the crate is plain Rust that does not know which device
//! it runs on. The Android build supplies [`crate::native::ReqwestPlatform`]
//! (rustls); the extension's service worker supplies the browser's `fetch`
//! (`nc-wallet-wasm`); the tests supply a platform that replays recorded
//! answers on a clock they move by hand.
//!
//! What a request carries is fixed here, not by the caller: a path, the body of
//! a POST, `Accept` and `Content-Type`. No cookies, no credentials, no
//! referrer, no identifier of the device or the person.

use std::future::Future;
use std::pin::Pin;

/// A future that is `Send` where the target has threads (Android, the host)
/// and need not be under WebAssembly, where there is one.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// A future that is `Send` where the target has threads (Android, the host)
/// and need not be under WebAssembly, where there is one.
#[cfg(target_arch = "wasm32")]
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// `Send` where the target has threads.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
/// `Send` where the target has threads.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Sync` where the target has threads.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
/// `Sync` where the target has threads.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// The two verbs the client uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One HTTPS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// `GET` or `POST`.
    pub method: Method,
    /// The whole URL. HTTPS only: a platform refuses any other scheme.
    pub url: String,
    /// The body of a POST.
    pub body: Option<Vec<u8>>,
    /// `Content-Type` of the body (`application/json`, or a form).
    pub content_type: Option<&'static str>,
    /// How long the whole request may take, connecting to the last byte.
    pub timeout_ms: u64,
    /// The most bytes of the answer that are read; more is [`HttpError::TooLarge`].
    pub max_bytes: usize,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The headers, names in lower case. Only `retry-after` and `cf-mitigated`
    /// are read.
    pub headers: Vec<(String, String)>,
    /// The body, whole and bounded.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A header by lower-case name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// `Retry-After` in whole seconds, if it was sent in that form.
    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u64> {
        self.header("retry-after")?.trim().parse().ok()
    }

    /// Whether a bot challenge (Cloudflare's) stands where the answer should
    /// be. Its own header says so, or the page that comes in place of the
    /// answer does. JSON that merely mentions the words is not one.
    #[must_use]
    pub fn is_challenge(&self) -> bool {
        if self.header("cf-mitigated").is_some_and(|v| v.eq_ignore_ascii_case("challenge")) {
            return true;
        }
        let head = self.body.trim_ascii_start();
        if head.first() != Some(&b'<') {
            return false;
        }
        let head = String::from_utf8_lossy(&head[..head.len().min(4096)]);
        head.contains("<title>Just a moment...</title>") || head.contains("challenge-platform")
    }
}

/// Why a request did not come back with an answer. No URL, no address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// No answer in time.
    Timeout,
    /// The connection or the TLS handshake failed.
    Network,
    /// The answer was longer than the request allowed.
    TooLarge,
}

/// The device, as the client sees it.
pub trait Platform: MaybeSend + MaybeSync {
    /// Sends one request. A redirect is never followed.
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>>;

    /// Waits `millis` milliseconds.
    fn sleep(&self, millis: u64) -> BoxFut<'_, ()>;

    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

impl<P: Platform + ?Sized> Platform for std::sync::Arc<P> {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        (**self).send(request)
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        (**self).sleep(millis)
    }

    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}
