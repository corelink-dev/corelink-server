//! R2-2 integration tests for [`corelink_clerk::HttpJwksFetcher`].
//!
//! Uses `wiremock` to stand up a mock JWKS endpoint and exercises the
//! end-to-end fetch → parse → validate path. Plain HTTP is enabled only
//! through the explicitly named loopback test constructor.
//!
//! Coverage:
//!
//! 1. Successful JWKS fetch → parse → validate returns a `ClerkPrincipal`.
//! 2. Expired JWT (past leeway) → `AuthError::Expired`.
//! 3. Wrong issuer → `AuthError::IssuerMismatch`.
//! 4. Tampered signature → `AuthError::SignatureInvalid`.
//! 5. Key rotation: phase 1 serves kid_v1 only; phase 2 serves
//!    kid_v1+kid_v2; JWT signed by kid_v2 must succeed after lazy
//!    re-fetch.
//! 6. Cache hit avoids re-fetching: second validate must NOT increase
//!    the wiremock hit counter.
//! 7. HTTP 503 from JWKS endpoint surfaces `AuthError::JwksFetchFailed`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test-only"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::ClientBuilder;
use serde::Serialize;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use corelink_clerk::fakes::test_keys::TestRsaKey;
use corelink_clerk::fakes::InMemoryKvCache;
use corelink_clerk::{
    validate_session, AuthError, ClerkAdapter, ClerkConfig, HttpJwksFetcher, Jwks,
};

const AUDIENCE: &str = "corelink-api";
const NOW_FIXED: u64 = 1_750_000_000;

#[derive(Serialize, Clone)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    sid: String,
    org_id: Option<String>,
    email: String,
    clerk_role: Option<String>,
}

fn fixed_clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_FIXED)
}

fn baseline_claims(iss: &str) -> Claims {
    Claims {
        sub: "user_2abc".into(),
        iss: iss.into(),
        aud: AUDIENCE.into(),
        exp: (NOW_FIXED + 3600) as i64,
        iat: NOW_FIXED as i64,
        nbf: NOW_FIXED as i64,
        sid: "sess_xyz".into(),
        org_id: Some("org_xyz".into()),
        email: "alice@example.dev".into(),
        clerk_role: Some("member".into()),
    }
}

fn sign(key: &TestRsaKey, claims: &Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let encoding =
        EncodingKey::from_rsa_pem(key.private_pem.as_bytes()).expect("test key accepted");
    encode(&header, claims, &encoding).expect("test sign")
}

/// Build a `reqwest::Client` that targets a local wiremock server
/// over plain HTTP. The production fetcher enforces HTTPS only; this
/// test-only client disables that to keep the mock server simple.
fn http_test_client() -> ClientBuilder {
    ClientBuilder::new().timeout(Duration::from_secs(5))
}

/// Build a [`ClerkConfig`] that allows an HTTP JWKS URL. Bypasses the
/// builder's HTTPS check via direct construction — the production code
/// path still rejects HTTP. We accomplish this by overriding the
/// `jwks_url` post-build via reflection-free `from_env` would require
/// HTTPS too — so we tweak the wiremock URL to look like
/// `https://127.0.0.1:<port>/...` and instead pass the URL directly to
/// the fetcher (which has its own loopback-only test mode).
///
/// Concretely: the [`ClerkConfig`] still uses a placeholder HTTPS URL
/// (it's used by the cache instance_hash + freshness checks; the
/// actual fetch URL comes from `config.jwks_url()`). We build the
/// adapter with a `RewritingFetcher` that ignores the configured URL
/// and points at the wiremock root.
struct RewritingFetcher {
    inner: HttpJwksFetcher,
    target_url: String,
    hits: Arc<AtomicUsize>,
}

impl RewritingFetcher {
    fn new(inner: HttpJwksFetcher, target_url: String) -> (Self, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner,
                target_url,
                hits: Arc::clone(&hits),
            },
            hits,
        )
    }
}

impl std::fmt::Debug for RewritingFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RewritingFetcher").finish()
    }
}

impl corelink_clerk::JwksFetcher for RewritingFetcher {
    fn fetch<'a>(&'a self, _url: &'a str) -> corelink_clerk::jwks::JwksFetchFuture<'a> {
        Box::pin(async move {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.inner.fetch_jwks(&self.target_url).await
        })
    }
}

fn make_config(issuer: &str) -> ClerkConfig {
    ClerkConfig::builder()
        // The adapter's HTTPS check happens at builder time; a
        // placeholder is fine because the actual fetch URL is supplied
        // by the `RewritingFetcher`'s `target_url`.
        .jwks_url("https://placeholder.example.dev/.well-known/jwks.json")
        .issuer_allowlist([issuer])
        .audience(AUDIENCE)
        .build()
        .expect("valid config")
}

async fn mount_jwks(mock: &MockServer, jwks: Jwks) {
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jwks.to_json(), "application/json"))
        .mount(mock)
        .await;
}

async fn mount_jwks_status(mock: &MockServer, status: u16) {
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(status))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn loopback_test_client_does_not_follow_redirects() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/target", target.uri())),
        )
        .mount(&source)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("{}", "application/json"))
        .mount(&target)
        .await;

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let err = fetcher
        .fetch_jwks(&format!("{}/start", source.uri()))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        corelink_clerk::jwks::JwksFetchError::HttpStatus { status: 302 }
    ));
    assert_eq!(
        target.received_requests().await.unwrap_or_default().len(),
        0
    );
}

#[tokio::test]
async fn http_fetch_and_validate_happy_path() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    let jwt = sign(&key, &baseline_claims(&issuer));
    let principal = adapter.validate(&jwt).await.expect("validate ok");
    assert_eq!(principal.user_id.as_str(), "user_2abc");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly 1 JWKS fetch");
}

#[tokio::test]
async fn http_fetch_expired_jwt_rejected() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, _hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    let mut claims = baseline_claims(&issuer);
    claims.exp = (NOW_FIXED - 65) as i64; // past 60s leeway
    let jwt = sign(&key, &claims);
    let err = adapter.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, AuthError::Expired), "got {err:?}");
}

#[tokio::test]
async fn http_fetch_wrong_issuer_rejected() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let configured_issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let attacker_issuer = format!("https://attacker-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, _hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(
        make_config(&configured_issuer),
        rewriting,
        cache,
        fixed_clock,
    );

    // JWT carries the wrong issuer.
    let claims = baseline_claims(&attacker_issuer);
    let jwt = sign(&key, &claims);
    let err = adapter.validate(&jwt).await.unwrap_err();
    assert!(
        matches!(err, AuthError::IssuerMismatch { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn http_fetch_tampered_signature_rejected() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, _hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    let jwt = sign(&key, &baseline_claims(&issuer));
    // Mutate one byte in the signature segment.
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut sig = parts[2].to_string();
    let last_char = sig.pop().expect("non-empty sig");
    // Toggle the last character to ensure a mutation.
    let bumped = if last_char == 'A' { 'B' } else { 'A' };
    sig.push(bumped);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);

    let err = adapter.validate(&tampered).await.unwrap_err();
    assert!(
        matches!(err, AuthError::SignatureInvalid | AuthError::Malformed(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn http_fetch_key_rotation_triggers_refetch() {
    let mock = MockServer::start().await;
    let key_v1 = TestRsaKey::generate("kid_v1");
    let key_v2 = TestRsaKey::generate("kid_v2");

    // Phase 1: only kid_v1.
    let phase1 = Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            Jwks::from_keys(vec![key_v1.jwks_key.clone()]).to_json(),
            "application/json",
        ))
        .up_to_n_times(1);
    mock.register(phase1).await;
    // Phase 2: both kid_v1 + kid_v2.
    let phase2 = Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            Jwks::from_keys(vec![key_v1.jwks_key.clone(), key_v2.jwks_key.clone()]).to_json(),
            "application/json",
        ));
    mock.register(phase2).await;

    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    // JWT signed with key_v2 — must trigger a kid_miss → refetch.
    let jwt = sign(&key_v2, &baseline_claims(&issuer));
    let principal = adapter
        .validate(&jwt)
        .await
        .expect("validate after rotation");
    assert_eq!(principal.user_id.as_str(), "user_2abc");
    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "rotation must trigger at least 2 fetches, got {}",
        hits.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn http_fetch_cache_hit_avoids_refetch() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    let jwt = sign(&key, &baseline_claims(&issuer));
    adapter.validate(&jwt).await.expect("validate 1");
    adapter.validate(&jwt).await.expect("validate 2");
    adapter.validate(&jwt).await.expect("validate 3");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "cache hit must avoid re-fetch; got {} hits",
        hits.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn http_fetch_503_surfaces_canonical_error() {
    let mock = MockServer::start().await;
    mount_jwks_status(&mock, 503).await;
    let key = TestRsaKey::generate("kid_v1");
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, _hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    let adapter = ClerkAdapter::new_with_clock(make_config(&issuer), rewriting, cache, fixed_clock);

    let jwt = sign(&key, &baseline_claims(&issuer));
    let err = adapter.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, AuthError::JwksFetchFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn validate_session_free_function_works() {
    let mock = MockServer::start().await;
    let key = TestRsaKey::generate("kid_v1");
    mount_jwks(&mock, key.into_jwks()).await;
    let issuer = format!("https://issuer-{}.example.dev", port_tag(&mock));
    let target_url = format!("{}/.well-known/jwks.json", mock.uri());

    let fetcher = HttpJwksFetcher::for_loopback_http_tests(http_test_client()).unwrap();
    let (rewriting, _hits) = RewritingFetcher::new(fetcher, target_url);
    let cache = InMemoryKvCache::with_clock(fixed_clock);
    // The free-function surface uses `SystemTime::now()` for its clock;
    // sign claims around the wall clock so the validate path accepts
    // them regardless of when the test runs.
    let now_real = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let mut claims = baseline_claims(&issuer);
    claims.iat = now_real as i64;
    claims.nbf = now_real as i64;
    claims.exp = (now_real + 3600) as i64;
    let jwt = sign(&key, &claims);

    // Validate via the top-level convenience surface.
    let principal = validate_session(&jwt, make_config(&issuer), rewriting, cache)
        .await
        .expect("validate_session ok");
    assert_eq!(principal.email.as_str(), "alice@example.dev");
}

/// Derive a stable port-tag from a MockServer to vary issuer strings
/// across tests so they don't accidentally collide on shared state.
fn port_tag(mock: &MockServer) -> u16 {
    // `MockServer::address` returns SocketAddr.
    mock.address().port()
}
