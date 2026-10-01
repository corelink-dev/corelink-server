//! Native [`JwksFetcher`] backed by `reqwest` (R2-2 production wiring).
//!
//! This module is gated behind the `http-fetcher` cargo feature and is
//! intended for **native** targets only — `apps/server`, the
//! `corelink-cli` end-to-end smoke tests, and CI integration suites
//! that need to spin up a real HTTPS client against `wiremock`. The
//! Cloudflare Worker target ([`crates/corelink-clerk-cf`])
//! intentionally does **not** depend on `reqwest`; it uses
//! [`worker::Fetch::Url`] via [`crate::JwksFetcher`] on the runtime
//! global. Both implementations coexist on the same
//! [`crate::JwksFetcher`] trait surface, so an outer crate picks one
//! based on its target:
//!
//! | Target | Fetcher implementation | Crate |
//! |---|---|---|
//! | `x86_64-unknown-linux-*` / native | [`HttpJwksFetcher`] | `corelink-clerk` (feature `http-fetcher`) |
//! | `wasm32-unknown-unknown` (CF Workers) | `CfJwksFetcher` | `corelink-clerk-cf` |
//!
//! # TLS posture
//!
//! `reqwest` is configured with `rustls-tls` (no OpenSSL dependency)
//! and `https-only(true)`; any attempt to redirect to plain HTTP
//! surfaces a [`JwksFetchError::Transport`]. The bounded request
//! timeout (5 s default; bounded ≤ 30 s) protects against a
//! slow-loris DoS on the JWKS endpoint.
//!
//! # Connection pooling
//!
//! A single `reqwest::Client` is shared across all calls via the
//! [`HttpJwksFetcher`] struct (cloning `reqwest::Client` is cheap and
//! shares the inner pool). The pool is bounded by `reqwest`'s defaults
//! (per-host connection cap = `usize::MAX` by default; we lower to 4
//! per host to keep the CF Worker control plane unaffected by a
//! `apps/server` JWKS burst).
//!
//! # Logging discipline
//!
//! We **never** log the JWKS body, the URL query string, or any
//! response header value. The only `tracing::debug!` line emitted is
//! `target = "corelink::clerk::http_fetcher"` with `status = u16` and
//! `bytes = usize` — both non-sensitive.

use std::time::Duration;

use reqwest::{redirect::Policy, Client, ClientBuilder, Url};

use crate::jwks::{Jwks, JwksFetchError, JwksFetchFuture, JwksFetcher};

/// Hard upper bound on per-request timeout (defensive: a 30 s JWKS
/// fetch is well outside Clerk's published SLA — anything past this
/// almost certainly means a network partition).
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// Canonical default timeout — 5 s. Clerk's JWKS endpoint p99 is
/// ~120 ms; this gives us 40× headroom for transient latency.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-host connection pool cap (lower than `reqwest`'s default to keep
/// the worker plane from saturating its egress quota on a JWKS burst).
const POOL_PER_HOST: usize = 4;

/// Production [`JwksFetcher`] backed by `reqwest`.
///
/// Cheap to clone — wraps a `reqwest::Client` which is `Arc`-shared
/// internally.
///
/// ```rust,no_run
/// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
/// use corelink_clerk::HttpJwksFetcher;
/// let fetcher = HttpJwksFetcher::new()?;
/// let _jwks = fetcher.fetch_jwks("https://clerk.example.dev/.well-known/jwks.json").await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct HttpJwksFetcher {
    client: Client,
    allow_loopback_http: bool,
}

/// Errors surfaced during [`HttpJwksFetcher::with_timeout`] /
/// [`HttpJwksFetcher::new`] construction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpFetcherBuildError {
    /// `reqwest` failed to build its internal client (TLS init / DNS
    /// resolver setup / etc.).
    #[error("reqwest client build failed: {0}")]
    ClientBuild(String),
    /// The caller passed an out-of-bounds timeout. See
    /// [`HttpJwksFetcher::with_timeout`] for the bounds.
    #[error("timeout {got_secs}s out of bounds (max {max_secs}s)")]
    TimeoutOutOfBounds {
        /// Caller-supplied timeout in seconds.
        got_secs: u64,
        /// Hard upper bound.
        max_secs: u64,
    },
}

impl HttpJwksFetcher {
    /// New fetcher with the canonical 5 s timeout.
    ///
    /// # Errors
    ///
    /// Returns [`HttpFetcherBuildError::ClientBuild`] if `reqwest`'s
    /// internal builder fails (rare: TLS init / DNS resolver setup).
    pub fn new() -> Result<Self, HttpFetcherBuildError> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// New fetcher with an explicit timeout. Bounded by [`MAX_TIMEOUT`]
    /// (30 s); larger values surface
    /// [`HttpFetcherBuildError::TimeoutOutOfBounds`].
    ///
    /// # Errors
    ///
    /// See [`HttpFetcherBuildError`].
    pub fn with_timeout(timeout: Duration) -> Result<Self, HttpFetcherBuildError> {
        if timeout > MAX_TIMEOUT {
            return Err(HttpFetcherBuildError::TimeoutOutOfBounds {
                got_secs: timeout.as_secs(),
                max_secs: MAX_TIMEOUT.as_secs(),
            });
        }
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .timeout(timeout)
            .pool_max_idle_per_host(POOL_PER_HOST)
            .user_agent(concat!("corelink-clerk/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| HttpFetcherBuildError::ClientBuild(e.to_string()))?;
        Ok(Self {
            client,
            allow_loopback_http: false,
        })
    }

    /// Build a production fetcher from a configured client builder.
    /// HTTPS is enforced both at URL validation and in the client, and
    /// redirects are disabled so credentials or JWKS requests cannot be
    /// forwarded to another scheme or host.
    #[must_use]
    pub fn from_client(builder: ClientBuilder) -> Result<Self, HttpFetcherBuildError> {
        let client = builder
            .https_only(true)
            .redirect(Policy::none())
            .build()
            .map_err(|e| HttpFetcherBuildError::ClientBuild(e.to_string()))?;
        Ok(Self {
            client,
            allow_loopback_http: false,
        })
    }

    /// Test-only transport for local mock servers. Plain HTTP is
    /// permitted only for loopback IP addresses or `localhost`; all
    /// redirects remain disabled. This API is omitted from default
    /// production builds and is exposed only with `test-utils`.
    #[doc(hidden)]
    #[cfg(feature = "test-utils")]
    pub fn for_loopback_http_tests(builder: ClientBuilder) -> Result<Self, HttpFetcherBuildError> {
        let client = builder
            .https_only(false)
            .redirect(Policy::none())
            .build()
            .map_err(|e| HttpFetcherBuildError::ClientBuild(e.to_string()))?;
        Ok(Self {
            client,
            allow_loopback_http: true,
        })
    }

    /// Fetch a JWKS document from `url` using the canonical
    /// `reqwest`-backed path. Surfaces canonical
    /// [`JwksFetchError`] variants.
    ///
    /// # Errors
    ///
    /// - [`JwksFetchError::Transport`] for network / TLS errors.
    /// - [`JwksFetchError::HttpStatus`] for non-2xx responses.
    /// - [`JwksFetchError::Malformed`] for body shape errors (caught
    ///   by [`Jwks::parse`]).
    pub async fn fetch_jwks(&self, url: &str) -> Result<Jwks, JwksFetchError> {
        // Defense-in-depth: the [`crate::config::ClerkConfig`] builder
        // already rejects non-HTTPS URLs, but we re-check here so a
        // Validate the URL before handing it to reqwest. Test mode is
        // limited to loopback HTTP; it does not permit external HTTP.
        let parsed = Url::parse(url)
            .map_err(|e| JwksFetchError::Transport(format!("invalid JWKS URL: {e}")))?;
        let is_https = parsed.scheme() == "https";
        let is_loopback_http = self.allow_loopback_http
            && parsed.scheme() == "http"
            && parsed.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        if !is_https && !is_loopback_http {
            return Err(JwksFetchError::Transport(
                "JWKS URL must be HTTPS (HTTP is allowed only for loopback test servers)"
                    .to_owned(),
            ));
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| JwksFetchError::Transport(format!("reqwest send: {e}")))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(JwksFetchError::HttpStatus { status });
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| JwksFetchError::Transport(format!("read body: {e}")))?;
        tracing::debug!(
            target: "corelink::clerk::http_fetcher",
            status,
            bytes = body.len(),
            "JWKS fetched"
        );
        Jwks::parse(&body)
    }
}

impl JwksFetcher for HttpJwksFetcher {
    fn fetch<'a>(&'a self, url: &'a str) -> JwksFetchFuture<'a> {
        Box::pin(async move { self.fetch_jwks(url).await })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test-only"
)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_timeout() {
        let err = HttpJwksFetcher::with_timeout(Duration::from_secs(60)).unwrap_err();
        assert!(matches!(
            err,
            HttpFetcherBuildError::TimeoutOutOfBounds { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_non_https_url() {
        let fetcher = HttpJwksFetcher::new().unwrap();
        let err = fetcher
            .fetch_jwks("http://insecure.example.dev/.well-known/jwks.json")
            .await
            .unwrap_err();
        assert!(matches!(err, JwksFetchError::Transport(_)));
    }

    #[tokio::test]
    async fn injected_production_client_rejects_http_before_sending() {
        let fetcher = HttpJwksFetcher::from_client(Client::builder()).unwrap();
        let err = fetcher
            .fetch_jwks("http://127.0.0.1:1/jwks")
            .await
            .unwrap_err();
        assert!(matches!(err, JwksFetchError::Transport(_)));
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn loopback_test_client_rejects_external_http_before_sending() {
        let fetcher = HttpJwksFetcher::for_loopback_http_tests(Client::builder()).unwrap();
        let err = fetcher
            .fetch_jwks("http://example.com/jwks")
            .await
            .unwrap_err();
        assert!(matches!(err, JwksFetchError::Transport(_)));
    }
}
