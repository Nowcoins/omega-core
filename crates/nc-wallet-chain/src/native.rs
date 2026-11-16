//! The Android (and host) transport: `reqwest` over rustls with the bundled
//! Mozilla roots, so the phone's certificate store and its JNI are not involved.
//!
//! * **HTTPS only.** Any other scheme is refused here, and a redirect is never
//!   followed (so nothing can lead the request off HTTPS or to another host),
//!   whatever an endpoint answers.
//! * **No cookies, no credentials, no referrer**, and no identifier of the
//!   phone or the person: a request carries its path, `Accept`, `Content-Type`
//!   and the fixed `User-Agent` `NowcoinOmega`, and the addresses it asks about.
//! * **A deadline on every request**, covering connecting, sending and reading.
//! * **No certificate pinning**: the roots decide. (A rotated certificate would
//!   lock every installed wallet out until an update.)

use std::time::Duration;

use crate::platform::{BoxFut, HttpError, HttpRequest, HttpResponse, Method, Platform};

/// The `User-Agent` of every request: the app's name, nothing of the device.
pub const USER_AGENT: &str = "NowcoinOmega";

/// `reqwest` as the device's HTTPS client.
#[derive(Debug, Clone)]
pub struct ReqwestPlatform {
    /// `None` when the client could not be built: every request then fails.
    client: Option<reqwest::Client>,
}

impl ReqwestPlatform {
    /// A client for public, read-mostly endpoints.
    ///
    /// # Errors
    /// [`HttpError::Network`] when the HTTP client cannot be built (the TLS backend could
    /// not start, or its roots could not be loaded). The wallet then reads no chain at all:
    /// it never falls back to a client with other settings, which could be one that follows
    /// a redirect to plain `http` or has no timeout.
    pub fn try_new() -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|_| HttpError::Network)?;
        Ok(Self { client: Some(client) })
    }

    /// As [`Self::try_new`], for a caller that has no way to carry the error. If the client
    /// cannot be built the platform **fails closed**: every request is `HttpError::Network`, so
    /// no endpoint is ever read through a client other than the one this wallet specifies
    /// (one that follows redirects to plain `http`, or has no timeout).
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().unwrap_or(Self { client: None })
    }
}

impl Default for ReqwestPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for ReqwestPlatform {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            if !request.url.starts_with("https://") {
                return Err(HttpError::Network);
            }
            let client = self.client.as_ref().ok_or(HttpError::Network)?;
            let mut builder = match request.method {
                Method::Get => client.get(&request.url),
                Method::Post => client.post(&request.url),
            }
            .timeout(Duration::from_millis(request.timeout_ms))
            .header("accept", "application/json, text/plain, */*");
            if let Some(content_type) = request.content_type {
                builder = builder.header("content-type", content_type);
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let mut response = builder.send().await.map_err(|e| classify(&e))?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter(|(name, _)| matches!(name.as_str(), "retry-after" | "cf-mitigated"))
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let mut body: Vec<u8> = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| classify(&e))? {
                if body.len() + chunk.len() > request.max_bytes {
                    return Err(HttpError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse { status, headers, body })
        })
    }

    fn sleep(&self, millis: u64) -> BoxFut<'_, ()> {
        Box::pin(tokio::time::sleep(Duration::from_millis(millis)))
    }

    #[allow(clippy::disallowed_methods)] // This is the platform's clock.
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
    }
}

fn classify(error: &reqwest::Error) -> HttpError {
    if error.is_timeout() { HttpError::Timeout } else { HttpError::Network }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_platform_without_a_client_fails_every_request() {
        let platform = ReqwestPlatform { client: None };
        let request = HttpRequest {
            method: Method::Get,
            url: "https://example.com/".to_owned(),
            content_type: None,
            body: None,
            timeout_ms: 1000,
            max_bytes: 1000,
        };
        let outcome = futures::executor::block_on(platform.send(request));
        assert!(matches!(outcome, Err(HttpError::Network)));
    }
}
