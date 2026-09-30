//! Wave-31 wallet-broker series stream-1 integration tests.
//!
//! Pin the post-refactor URL + auth contract for the Stripe HTTPS
//! client against a `wiremock::MockServer` impersonating the HuGR
//! Wallet proxy. Three load-bearing assertions:
//!
//! - `client_uses_wallet_proxy_url` — the constructed request URL is
//!   `{wallet_base}/{stripe_ref}/v1/...` (NOT
//!   `api.stripe.com/...`).
//! - `client_uses_hugrw_token_auth` — the `Authorization` header is
//!   `Bearer hugrw_<token>` (NOT `Bearer sk_...` and NOT HTTP Basic
//!   with the upstream Stripe key).
//! - `fails_closed_on_wallet_5xx` — when the wallet proxy returns 5xx
//!   after retries exhaust, the client surfaces a CoreLink-side error
//!   (`StripeError::Generic` 5xx) WITHOUT any fallback to direct
//!   Stripe. This pins the charter "fail-CLOSED on wallet unavailability"
//!   (CoreLink no longer holds the upstream `STRIPE_SECRET_KEY`, so
//!   there can be no fallback path).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration tests are allowed to use these primitives"
)]

use corelink_stripe_real::{RetryPolicy, StripeClientConfig, StripeError, StripeRealClient};
use secrecy::SecretString;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(server: &MockServer, token: &str) -> StripeClientConfig {
    StripeClientConfig::wallet_broker(
        server.uri(),
        SecretString::from(token.to_string()),
        "stripe-prod",
    )
}

#[tokio::test]
async fn client_uses_wallet_proxy_url() {
    let server = MockServer::start().await;
    // Mount on the FULL wallet proxy path. If the client tried to hit
    // `api.stripe.com/v1/customers` directly the mock would never see
    // the request and wiremock would 404 it.
    Mock::given(method("POST"))
        .and(path("/stripe-prod/v1/customers"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"id":"cus_proxytest","email":"u@example.test"}"#),
        )
        .mount(&server)
        .await;

    let cfg = config_for(&server, "hugrw_url_test");
    let proxy_base = cfg.effective_base_url();
    let cust = tokio::task::spawn_blocking(move || {
        let client = StripeRealClient::builder()
            .config(cfg)
            .build()
            .expect("build");
        // Sanity: the effective base URL on the client matches what
        // we computed pre-spawn (i.e. the wallet ref is baked in
        // before any request hits the wire).
        assert_eq!(client.effective_base_url(), proxy_base);
        client.create_customer("u@example.test", "tenant_url_test", "idem-url-1")
    })
    .await
    .expect("join")
    .expect("create_customer");
    assert_eq!(cust.id, "cus_proxytest");

    // Defensive: confirm wiremock received exactly the proxy path.
    let received = server.received_requests().await.expect("wiremock log");
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].url.path(), "/stripe-prod/v1/customers");
}

#[tokio::test]
async fn client_uses_hugrw_token_auth() {
    let server = MockServer::start().await;
    // The mock REQUIRES `Authorization: Bearer hugrw_auth_test`. If
    // the client sent `Basic ...` (the pre-wave-31 form) or a Bearer
    // with a `sk_...` prefix the matcher would fail and wiremock
    // would respond 404 — which the client would surface as
    // StripeError::Generic, failing the assert below.
    Mock::given(method("POST"))
        .and(path("/stripe-prod/v1/customers"))
        .and(header("Authorization", "Bearer hugrw_auth_test"))
        .and(header_exists("Idempotency-Key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"id":"cus_authtest","email":"a@example.test"}"#),
        )
        .mount(&server)
        .await;

    let cfg = config_for(&server, "hugrw_auth_test");
    let cust = tokio::task::spawn_blocking(move || {
        let client = StripeRealClient::builder()
            .config(cfg)
            .build()
            .expect("build");
        client.create_customer("a@example.test", "tenant_auth_test", "idem-auth-1")
    })
    .await
    .expect("join")
    .expect("create_customer");
    assert_eq!(cust.id, "cus_authtest");

    // Cross-check the raw header captured by wiremock — pinning the
    // exact `Bearer hugrw_...` form (no Basic, no sk_ prefix).
    let received = server.received_requests().await.expect("wiremock log");
    assert_eq!(received.len(), 1);
    let auth = received[0]
        .headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert_eq!(auth, "Bearer hugrw_auth_test");
    assert!(
        !auth.contains("Basic"),
        "auth header must NOT be HTTP Basic (pre-wave-31 form): {auth}"
    );
    assert!(
        !auth.contains("sk_"),
        "auth header must NOT carry the upstream Stripe key: {auth}"
    );
}

#[tokio::test]
async fn fails_closed_on_wallet_5xx() {
    let server = MockServer::start().await;
    // Every attempt returns 503. The retry policy MUST exhaust and
    // the client MUST surface a CoreLink-side 5xx error — with NO
    // fallback to direct Stripe (CoreLink no longer holds the
    // upstream key; a fallback path would be structurally impossible
    // and the charter forbids it).
    Mock::given(method("POST"))
        .and(path("/stripe-prod/v1/customers"))
        .respond_with(ResponseTemplate::new(503).set_body_string(
            r#"{"error":{"type":"api_error","message":"wallet upstream unavailable"}}"#,
        ))
        .mount(&server)
        .await;

    let cfg = config_for(&server, "hugrw_failclosed_test");
    // Tight retry budget so the test runs fast (max_retries=2,
    // base_ms=1, cap_ms=5).
    let policy = RetryPolicy::new(2, 1, 5);
    let err = tokio::task::spawn_blocking(move || {
        let client = StripeRealClient::builder()
            .config(cfg)
            .retry_policy(policy)
            .build()
            .expect("build");
        client.create_customer("fc@example.test", "tenant_fc", "idem-fc-1")
    })
    .await
    .expect("join")
    .expect_err("wallet 5xx must surface as CoreLink-side error");

    match err {
        StripeError::Generic { http_status, .. } => {
            assert_eq!(
                http_status, 503,
                "wallet 5xx must map to CoreLink-side 5xx, NOT fall back to direct Stripe"
            );
        }
        other => panic!("expected Generic 503 on wallet outage, got {other:?}"),
    }

    // Verify the URL was the WALLET path — proving no fallback to
    // `api.stripe.com` was attempted on wallet failure.
    let received = server.received_requests().await.expect("wiremock log");
    assert!(!received.is_empty(), "wallet must have received the calls");
    for r in &received {
        assert_eq!(
            r.url.path(),
            "/stripe-prod/v1/customers",
            "every retry MUST hit the wallet proxy (no fallback to direct Stripe)"
        );
    }
}
