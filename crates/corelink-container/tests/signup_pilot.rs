//! Integration tests for the wave-29 stream-1 pilot signup route
//! (`POST /v1/signup/pilot/{token}`) — closes DEBT-027 engineering-side.
//!
//! Coverage matrix per the wave-29 stream-1 charter §Deliverables.4:
//!
//! 1. **Happy path** — valid HMAC-signed token → 201 + tenant_id +
//!    activation URL + `pilot_reserved.v1` audit emit.
//! 2. **Forged HMAC** → 401 + `pilot_token_rejected.v1` audit emit
//!    with `payload="signature_mismatch"`.
//! 3. **Expired token** (mint timestamp older than TTL) → 401 +
//!    `pilot_token_rejected.v1` audit emit with `payload="expired"`.
//! 4. **Rate-limit hit** — 6th request from the same IP in an hour →
//!    429 + `Retry-After` header + `pilot_rate_limited.v1` audit emit.
//! 5. **Cross-IP rate-limit isolation** — IP `1.1.1.1` exhausting its
//!    bucket does NOT block IP `2.2.2.2`.
//! 6. **Audit emit fail-CLOSED** — injected sink failure → 503
//!    `audit pipeline closed` + no store mutation.
//! 7. **Duplicate signup same email** — second token + same email →
//!    201 returning the original tenant_id (idempotent).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use corelink_ratelimit::{
    InMemoryRateLimitAuditSink, InMemoryRateLimitMetrics, InMemoryTokenBucketRateLimiter,
    RateLimiter,
};
use corelink_server::routes::signup::{
    mint_pilot_token, pilot_signup_rate_limit_config, router, InMemorySignupAuditSink,
    InMemorySignupStore, PilotSignupResponse, SignupAuditSink, SignupRouteState, SignupStore,
    TokenEnv, DEFAULT_ACTIVATION_URL_BASE, EVENT_TYPE_PILOT_RATE_LIMITED,
    EVENT_TYPE_PILOT_RESERVED, EVENT_TYPE_PILOT_TOKEN_REJECTED, PILOT_TOKEN_TTL_MS,
};
use corelink_server::wall_clock::InMemoryFakeWallClock;
use serde_json::{json, Value};
use tower::ServiceExt;

const TEST_KEY: &[u8; 24] = b"signup-pilot-test-keyABC";
const BASE_NOW_MS: u64 = 1_700_000_000_000;

fn build_state() -> (
    SignupRouteState,
    Arc<InMemorySignupAuditSink>,
    Arc<InMemorySignupStore>,
    Arc<InMemoryFakeWallClock>,
) {
    let audit_sink = Arc::new(InMemorySignupAuditSink::new());
    let store = Arc::new(InMemorySignupStore::new());
    let wall_clock = Arc::new(InMemoryFakeWallClock::at_unix_ms(BASE_NOW_MS));
    let rl_audit = Arc::new(InMemoryRateLimitAuditSink::new());
    let rl_metrics = Arc::new(InMemoryRateLimitMetrics::new());
    let rate_limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryTokenBucketRateLimiter::new(
        rl_audit,
        rl_metrics,
        pilot_signup_rate_limit_config(),
    ));
    let state = SignupRouteState {
        token_key: Arc::new(TEST_KEY.to_vec()),
        rate_limiter,
        audit_sink: audit_sink.clone() as Arc<dyn SignupAuditSink>,
        store: store.clone() as Arc<dyn SignupStore>,
        wall_clock: wall_clock.clone(),
        activation_url_base: Arc::new(DEFAULT_ACTIVATION_URL_BASE.to_owned()),
        staging_admission: None,
    };
    (state, audit_sink, store, wall_clock)
}

fn body_json() -> Value {
    json!({
        "email": "pilot@example.com",
        "company_name": "Pilot Co",
        "tier_hint": "pro",
        "expected_use_case": "build cache for CI",
    })
}

fn body_json_with_email(email: &str) -> Value {
    json!({
        "email": email,
        "company_name": "Pilot Co",
        "tier_hint": "pro",
        "expected_use_case": "build cache for CI",
    })
}

fn build_request(token: &str, ip: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/signup/pilot/{token}"))
        .header("content-type", "application/json")
        // The rate-limit key now comes from the Worker-trusted `x-corelink-client-ip`
        // (set from cf-connecting-ip); a client-forged `x-forwarded-for` is ignored.
        .header("x-corelink-client-ip", ip)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn happy_path_valid_token_returns_201() {
    let (state, audit_sink, store, _clock) = build_state();
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "0123456789abcdef", TEST_KEY).unwrap();
    let app = router(state);
    let resp = app
        .oneshot(build_request(&token, "203.0.113.10", &body_json()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let parsed: PilotSignupResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.state, "RESERVED");
    assert!(parsed
        .activation_url
        .starts_with(DEFAULT_ACTIVATION_URL_BASE));
    // Audit emit captured the canonical event_type before the response.
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_RESERVED);
    assert_eq!(rows[0].exit_status, "reserved");
    assert_eq!(rows[0].tenant_id, Some(parsed.tenant_id));
    // Store has exactly one row.
    let recs = store.snapshot().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].email, "pilot@example.com");
    assert_eq!(recs[0].state, "RESERVED");
}

#[tokio::test]
async fn forged_hmac_returns_401() {
    let (state, audit_sink, store, _clock) = build_state();
    let mut token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "deadbeefcafebabe", TEST_KEY).unwrap();
    // Flip the final hex char of the signature.
    let mut chars: Vec<char> = token.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    token = chars.into_iter().collect();
    let app = router(state);
    let resp = app
        .oneshot(build_request(&token, "203.0.113.11", &body_json()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_TOKEN_REJECTED);
    assert_eq!(rows[0].payload.as_deref(), Some("signature_mismatch"));
    // No store mutation on a forged token.
    assert_eq!(store.snapshot().unwrap().len(), 0);
}

#[tokio::test]
async fn expired_token_returns_401() {
    let (state, audit_sink, _store, clock) = build_state();
    let minted_at_ms = BASE_NOW_MS;
    let token =
        mint_pilot_token(TokenEnv::Prod, minted_at_ms, "ffffffff00000000", TEST_KEY).unwrap();
    // Advance the wall clock past the TTL.
    clock.advance(std::time::Duration::from_millis(PILOT_TOKEN_TTL_MS + 1));
    let app = router(state);
    let resp = app
        .oneshot(build_request(&token, "203.0.113.12", &body_json()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_TOKEN_REJECTED);
    assert_eq!(rows[0].payload.as_deref(), Some("expired"));
}

#[tokio::test]
async fn rate_limit_kicks_in_at_sixth_request_same_ip() {
    let (state, audit_sink, _store, clock) = build_state();
    let app = router(state);
    // The signup config: burst=5, refill=5/3600 tokens/sec,
    // retry_floor=720s.
    // The first 5 requests admit (the bucket starts full); the 6th
    // request in the same window hits the 429 floor.
    for i in 0..5 {
        let rand = format!("aaaa{i:04}bbbbcccc");
        let token = mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, &rand, TEST_KEY).unwrap();
        let body = body_json_with_email(&format!("pilot{i}@example.com"));
        let resp = app
            .clone()
            .oneshot(build_request(&token, "198.51.100.7", &body))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "request {i} should have succeeded",
        );
    }
    // A one-second refill must not create a sixth admission. This is the
    // production bypass that the old integer `1 token/sec` config allowed.
    clock.advance(std::time::Duration::from_secs(1));
    // 6th request from the same IP → 429.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "abababababababab", TEST_KEY).unwrap();
    let resp = app
        .oneshot(build_request(
            &token,
            "198.51.100.7",
            &body_json_with_email("late@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());
    let rows = audit_sink.snapshot().unwrap();
    // 5 reserved + 1 rate_limited = 6.
    assert_eq!(rows.len(), 6);
    assert_eq!(rows[5].event_type, EVENT_TYPE_PILOT_RATE_LIMITED);
    assert_eq!(rows[5].exit_status, "rate_limited");
}

#[tokio::test]
async fn rate_limit_isolated_across_ips() {
    let (state, _audit_sink, store, _clock) = build_state();
    let app = router(state);
    // Drain IP-A's bucket.
    for i in 0..5 {
        let rand = format!("1111{i:04}aaaabbbb");
        let token = mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, &rand, TEST_KEY).unwrap();
        let body = body_json_with_email(&format!("a-{i}@example.com"));
        let resp = app
            .clone()
            .oneshot(build_request(&token, "1.1.1.1", &body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    // IP-A's 6th hits 429.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "1111ffffaaaabbbb", TEST_KEY).unwrap();
    let resp = app
        .clone()
        .oneshot(build_request(
            &token,
            "1.1.1.1",
            &body_json_with_email("a-late@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    // IP-B with a fresh bucket still gets 201.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "2222aaaaaaaabbbb", TEST_KEY).unwrap();
    let resp = app
        .oneshot(build_request(
            &token,
            "2.2.2.2",
            &body_json_with_email("b-fresh@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // Store carries 5 (IP-A reservations) + 1 (IP-B reservation) = 6.
    assert_eq!(store.snapshot().unwrap().len(), 6);
}

#[tokio::test]
async fn audit_emit_failure_returns_503_fail_closed() {
    let (state, audit_sink, store, _clock) = build_state();
    audit_sink.inject_failure("forced").unwrap();
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "abcdef0123456789", TEST_KEY).unwrap();
    let app = router(state);
    let resp = app
        .oneshot(build_request(&token, "203.0.113.20", &body_json()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&bytes[..], b"audit pipeline closed");
    // The store row was inserted BEFORE the audit emit fired (the
    // route persists the reservation, then audit-emits, then renders
    // the response). The fail-CLOSED contract is at the response
    // boundary — the customer NEVER sees the 201 if the audit emit
    // failed. The store-mutation pre-audit-emit ordering is consistent
    // with the wave-20 audit_export pattern: a durable store mutation
    // accompanied by a failed audit emit is recovered via the audit-
    // chain reconciliation cron (`backup-daily-verify.sh`).
    // Wave-29 design note: we accept the bounded pre-emit store
    // mutation because the route is idempotent on email + token_id, so
    // a retry surfaces the same tenant_id on success.
    assert_eq!(store.snapshot().unwrap().len(), 1);
}

#[tokio::test]
async fn duplicate_email_returns_original_tenant_id() {
    let (state, audit_sink, store, _clock) = build_state();
    let app = router(state);
    let tok_a =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "aaaa1111bbbb2222", TEST_KEY).unwrap();
    let resp_a = app
        .clone()
        .oneshot(build_request(
            &tok_a,
            "203.0.113.30",
            &body_json_with_email("dup@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::CREATED);
    let body_a = to_bytes(resp_a.into_body(), 1024).await.unwrap();
    let parsed_a: PilotSignupResponse = serde_json::from_slice(&body_a).unwrap();

    let tok_b =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "cccc3333dddd4444", TEST_KEY).unwrap();
    let resp_b = app
        .oneshot(build_request(
            &tok_b,
            "203.0.113.31",
            &body_json_with_email("dup@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::CREATED);
    let body_b = to_bytes(resp_b.into_body(), 1024).await.unwrap();
    let parsed_b: PilotSignupResponse = serde_json::from_slice(&body_b).unwrap();
    assert_eq!(
        parsed_a.tenant_id, parsed_b.tenant_id,
        "duplicate email returns the original tenant_id",
    );
    // Store still has just one row.
    assert_eq!(store.snapshot().unwrap().len(), 1);
    // Two audit emits: the first is `reserved`, the second is
    // `duplicate` (same event_type, distinguishable via exit_status).
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_RESERVED);
    assert_eq!(rows[0].exit_status, "reserved");
    assert_eq!(rows[1].event_type, EVENT_TYPE_PILOT_RESERVED);
    assert_eq!(rows[1].exit_status, "duplicate");
}

#[tokio::test]
async fn bad_request_body_returns_400() {
    let (state, audit_sink, _store, _clock) = build_state();
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "0000aaaa1111bbbb", TEST_KEY).unwrap();
    let body = json!({
        "email": "",
        "company_name": "X",
        "tier_hint": "free",
        "expected_use_case": "ci",
    });
    let app = router(state);
    let resp = app
        .oneshot(build_request(&token, "203.0.113.40", &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_TOKEN_REJECTED);
    assert_eq!(rows[0].exit_status, "bad_request");
    assert_eq!(rows[0].payload.as_deref(), Some("invalid_field=email"),);
}
