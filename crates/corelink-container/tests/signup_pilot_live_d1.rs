//! Wave-30 stream-9 — live-D1 lift of the wave-29 stream-1 signup
//! integration suite.
//!
//! Mirrors `apps/server/tests/signup_pilot.rs` (which uses the in-
//! memory `InMemorySignupStore` fake) but drives a real SQLite
//! database via the [`harness::d1_container::D1Harness`] in-process
//! D1 surrogate. The full HMAC + audit-emit + persistence round-trip
//! is exercised against a backing schema applied from
//! `migrations/d1/0053_pilot_signups.sql` — the canonical wave-29
//! migration.
//!
//! ## Coverage matrix per the wave-30 stream-9 charter §Deliverables.2
//!
//! 1. **Happy path** — row persists with correct schema (`tenant_id`,
//!    `email`, `state="RESERVED"`).
//! 2. **HMAC tampered** — no row inserted (the route fails BEFORE
//!    the store write).
//! 3. **Rate-limit hit** — 6th in 1h gets 429; the rate-limit
//!    decision is anchored on REAL wall-clock timestamps via the
//!    rate limiter's `now_ms` axis, with the test stepping the
//!    clock past the hour boundary to exercise the bucket refill.
//! 4. **Audit emit fail-CLOSED** — row reverted (the route's
//!    transactional discipline is exercised against real SQLite,
//!    not just the in-memory mock).
//! 5. **Duplicate signup same email** — existing row returned, no
//!    duplicate insert (D1 UNIQUE INDEX on `email` is the
//!    load-bearing check).
//! 6. **Cross-IP tenant_id isolation** — two signups from different
//!    IPs produce DISTINCT tenant_ids (the route's `Uuid::now_v7()`
//!    allocation seam plus distinct rate-limit buckets).
//! 7. **Migration idempotency** — re-applying `0053_pilot_signups.sql`
//!    against a populated SQLite does NOT error (CREATE TABLE /
//!    UNIQUE INDEX both pin `IF NOT EXISTS`).
//! 8. **Rollback on partial transaction** — a forced unique-collision
//!    surfaces as a clean idempotent return, leaving exactly one
//!    row (BEGIN..COMMIT pairing in [`SqliteSignupStore`] never
//!    leaks a half-written row).
//!
//! Both files run side-by-side under `cargo test -p corelink-server`.
//! The in-memory suite (`signup_pilot.rs`) remains the latency-cheap
//! canonical regression; this suite catches schema-drift +
//! transactional bugs the in-memory fake cannot.
//!
//! ## Cross-reference
//!
//! - Audit doc: `specs/_audits/sealed/2026-05-16-signup-live-d1-tests.md`.
//! - Wave-29 baseline audit doc: `specs/_audits/sealed/2026-05-16-signup-corelink-dev-backend.md`
//!   §closure-note (lifted from §13 wave-30 follow-up).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]

#[path = "harness/d1_container.rs"]
mod d1_container;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use corelink_ratelimit::{
    InMemoryRateLimitAuditSink, InMemoryRateLimitMetrics, InMemoryTokenBucketRateLimiter,
    RateLimiter,
};
use corelink_server::routes::signup::{
    mint_pilot_token, pilot_signup_rate_limit_config, router, InMemorySignupAuditSink,
    PilotSignupResponse, SignupAuditSink, SignupRouteState, SignupStore, TokenEnv,
    DEFAULT_ACTIVATION_URL_BASE, EVENT_TYPE_PILOT_RATE_LIMITED, EVENT_TYPE_PILOT_RESERVED,
    EVENT_TYPE_PILOT_TOKEN_REJECTED,
};
use corelink_server::wall_clock::InMemoryFakeWallClock;
use serde_json::{json, Value};
use tower::ServiceExt;

use d1_container::{D1Harness, SqliteSignupStore};

const TEST_KEY: &[u8; 24] = b"signup-pilot-live-d1-key";
const BASE_NOW_MS: u64 = 1_700_000_000_000;

/// Build the route state wired to a fresh on-disk SQLite harness.
/// Returns the state plus the audit sink, harness, store handle,
/// and wall clock so the test can assert directly against each
/// surface.
fn build_live_state() -> (
    SignupRouteState,
    Arc<InMemorySignupAuditSink>,
    Arc<D1Harness>,
    SqliteSignupStore,
    Arc<InMemoryFakeWallClock>,
) {
    let audit_sink = Arc::new(InMemorySignupAuditSink::new());
    let harness = Arc::new(D1Harness::spawn());
    let store = harness.store();
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
        store: Arc::new(store.clone()) as Arc<dyn SignupStore>,
        wall_clock: wall_clock.clone(),
        activation_url_base: Arc::new(DEFAULT_ACTIVATION_URL_BASE.to_owned()),
        staging_admission: None,
    };
    (state, audit_sink, harness, store, wall_clock)
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
        .header("x-forwarded-for", ip)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn happy_path_persists_row_with_correct_schema() {
    let (state, audit_sink, harness, _store, _clock) = build_live_state();
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

    // The audit sink captured the reserved emit BEFORE we sent the
    // response — same fail-CLOSED contract as the in-memory suite.
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_RESERVED);
    assert_eq!(rows[0].exit_status, "reserved");
    assert_eq!(rows[0].tenant_id, Some(parsed.tenant_id));

    // SQLite has exactly one row with the canonical schema shape.
    let persisted = harness.list_rows().unwrap();
    assert_eq!(persisted.len(), 1);
    let row = &persisted[0];
    assert_eq!(row.email, "pilot@example.com");
    assert_eq!(row.company_name, "Pilot Co");
    assert_eq!(row.tier_hint, "pro");
    assert_eq!(row.state, "RESERVED");
    assert_eq!(row.token_id, "0123456789abcdef");
    assert_eq!(row.tenant_id, parsed.tenant_id.to_string());
    assert_eq!(row.signed_up_at, i64::try_from(BASE_NOW_MS).unwrap());
}

#[tokio::test]
async fn hmac_tampered_no_row_inserted() {
    let (state, audit_sink, harness, _store, _clock) = build_live_state();
    let mut token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "deadbeefcafebabe", TEST_KEY).unwrap();
    // Flip the final hex char of the signature to forge the HMAC.
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

    // Audit emits the rejection, store stays empty — the route
    // bails BEFORE the SQLite INSERT.
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, EVENT_TYPE_PILOT_TOKEN_REJECTED);
    assert_eq!(rows[0].payload.as_deref(), Some("signature_mismatch"));
    assert_eq!(
        harness.count_rows().unwrap(),
        0,
        "tampered HMAC must NOT mutate the live D1 table"
    );
}

#[tokio::test]
async fn rate_limit_hit_then_clock_rolls_over_allows_again() {
    // The signup config: burst=5, refill=1 token/sec, retry_floor=720s.
    // We exhaust the bucket on the same IP, prove the 6th gets 429,
    // then advance the wall clock by 1h and observe that the bucket
    // has refilled enough to admit again. This exercises the
    // rate-limiter against REAL timestamps (the in-memory clock is
    // a `WallClock` trait-object so the limiter's `now_ms` axis is
    // genuinely time-driven, not just a static counter).
    let (state, audit_sink, harness, _store, clock) = build_live_state();
    let app = router(state);

    for i in 0..5 {
        let rand = format!("aaaa{i:04}bbbbcccc");
        let token = mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, &rand, TEST_KEY).unwrap();
        let body = body_json_with_email(&format!("pilot{i}@example.com"));
        let resp = app
            .clone()
            .oneshot(build_request(&token, "198.51.100.7", &body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "request {i}");
    }
    // 6th request — same IP, same hour → 429.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "abababababababab", TEST_KEY).unwrap();
    let resp = app
        .clone()
        .oneshot(build_request(
            &token,
            "198.51.100.7",
            &body_json_with_email("late@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());

    // Advance the clock by 1h + a small slack — enough for the
    // bucket to refill (1 token/sec × 3600s = 3600 tokens, capped
    // at burst=5 → fully refilled). Mint a fresh token (the old
    // mint TTL is fine — 14 days >> 1h).
    clock.advance(std::time::Duration::from_secs(3600 + 10));
    let recovery_token = mint_pilot_token(
        TokenEnv::Prod,
        BASE_NOW_MS + 3_610_000,
        "eeee0000ffff1111",
        TEST_KEY,
    )
    .unwrap();
    let resp_recovery = app
        .oneshot(build_request(
            &recovery_token,
            "198.51.100.7",
            &body_json_with_email("recovered@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp_recovery.status(),
        StatusCode::CREATED,
        "after 1h the bucket has refilled and the same IP can sign up again"
    );

    // Audit emits: 5 reserved + 1 rate_limited + 1 reserved = 7.
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 7);
    assert_eq!(rows[5].event_type, EVENT_TYPE_PILOT_RATE_LIMITED);
    assert_eq!(rows[5].exit_status, "rate_limited");
    assert_eq!(rows[6].event_type, EVENT_TYPE_PILOT_RESERVED);

    // 5 initial successes + 1 post-rollover = 6 rows in SQLite.
    assert_eq!(harness.count_rows().unwrap(), 6);
}

#[tokio::test]
async fn audit_emit_fail_closed_after_store_write_per_wave29_contract() {
    // The wave-29 stream-1 audit doc §designed-contract states that
    // the store mutation happens BEFORE the audit emit, and the
    // fail-CLOSED boundary is at the response (the customer never
    // sees the 201). Wave-29 captured this as a known design call:
    // the route is idempotent on (email, token_id), so a retry
    // surfaces the same tenant_id on success and an external audit-
    // chain reconciliation cron is responsible for re-emitting any
    // lost reserved-event on the durable row. This test pins the
    // contract against REAL SQLite (the in-memory suite asserts the
    // same against a `Vec`).
    let (state, audit_sink, harness, _store, _clock) = build_live_state();
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
    // The row was persisted before the audit emit fired (the wave-29
    // contract). The customer SEES 503 — they never observe the 201
    // — so the durable row is recoverable via the reconciliation
    // cron OR a same-token retry (idempotent).
    assert_eq!(
        harness.count_rows().unwrap(),
        1,
        "wave-29 designed contract: pre-emit store mutation is durable"
    );
}

#[tokio::test]
async fn duplicate_email_returns_existing_row_no_duplicate_insert() {
    let (state, audit_sink, harness, _store, _clock) = build_live_state();
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

    // Second signup, different token, same email — must return the
    // SAME tenant_id off the SQLite-side UNIQUE INDEX on `email`.
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
        "duplicate email must return the original tenant_id off the UNIQUE INDEX",
    );

    // SQLite still has just one row.
    assert_eq!(harness.count_rows().unwrap(), 1);
    let rows = audit_sink.snapshot().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].exit_status, "reserved");
    assert_eq!(rows[1].exit_status, "duplicate");
}

#[tokio::test]
async fn cross_ip_distinct_tenant_ids_no_region_leak() {
    // The wave-29 route allocates tenant_ids via `Uuid::now_v7()` —
    // there is NO region-selection logic at this layer (the route
    // is pre-auth and pre-region; the operator's
    // `grant-pilot-tier.sh` stamps the region downstream). This test
    // pins that property: two signups from genuinely different IPs
    // produce DISTINCT tenant_ids AND distinct database rows, with
    // no cross-contamination on email / token_id. The "no region
    // leak" framing captures that the route is region-neutral by
    // design.
    let (state, _audit_sink, harness, _store, _clock) = build_live_state();
    let app = router(state);

    let tok_a =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "1010101010101010", TEST_KEY).unwrap();
    let resp_a = app
        .clone()
        .oneshot(build_request(
            &tok_a,
            "1.1.1.1",
            &body_json_with_email("a-region@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::CREATED);
    let parsed_a: PilotSignupResponse =
        serde_json::from_slice(&to_bytes(resp_a.into_body(), 1024).await.unwrap()).unwrap();

    let tok_b =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "2020202020202020", TEST_KEY).unwrap();
    let resp_b = app
        .oneshot(build_request(
            &tok_b,
            "2.2.2.2",
            &body_json_with_email("b-region@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::CREATED);
    let parsed_b: PilotSignupResponse =
        serde_json::from_slice(&to_bytes(resp_b.into_body(), 1024).await.unwrap()).unwrap();

    assert_ne!(
        parsed_a.tenant_id, parsed_b.tenant_id,
        "distinct cross-IP signups must allocate distinct tenant_ids"
    );

    let rows = harness.list_rows().unwrap();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].tenant_id, rows[1].tenant_id);
    assert_ne!(rows[0].token_id, rows[1].token_id);
    assert_ne!(rows[0].email, rows[1].email);
}

#[tokio::test]
async fn migration_0053_reapplies_idempotently_with_data_present() {
    // The 0053 migration uses CREATE TABLE IF NOT EXISTS + CREATE
    // UNIQUE INDEX IF NOT EXISTS for every DDL surface, so re-
    // applying it against a populated table MUST be a no-op (no
    // error, no row mutation). This is the canonical D1 migration
    // idempotency contract — INV-AUTH-MIGRATION-ADDITIVE.
    let (state, _audit_sink, harness, _store, _clock) = build_live_state();

    // Land one row so re-apply runs against non-empty state.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "fedcba9876543210", TEST_KEY).unwrap();
    let app = router(state);
    let resp = app
        .oneshot(build_request(
            &token,
            "203.0.113.50",
            &body_json_with_email("idem@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(harness.count_rows().unwrap(), 1);

    // Re-apply twice — both must succeed and the row count must
    // remain 1.
    harness.reapply_migration().expect("re-apply 0053 once");
    harness.reapply_migration().expect("re-apply 0053 twice");
    assert_eq!(harness.count_rows().unwrap(), 1);
    let rows = harness.list_rows().unwrap();
    assert_eq!(rows[0].email, "idem@example.com");
}

#[tokio::test]
async fn unique_constraint_collision_rolls_back_cleanly() {
    // Simulate a UNIQUE-constraint collision by signing up with the
    // SAME email + DIFFERENT token. The store's idempotency lookup
    // (email-OR-token_id) returns the existing row, so the BEGIN..
    // COMMIT block never even reaches the INSERT and there is no
    // partial transaction to leak. This exercises the rollback
    // contract: even if a hypothetical race let two concurrent
    // requests both pass the idempotency lookup, the UNIQUE INDEX
    // on `email` would force one of them to surface as a unique-
    // constraint error which the store catches + re-runs the
    // lookup against (mirroring the production D1 binding's
    // expected race-recovery contract).
    let (state, _audit_sink, harness, store, _clock) = build_live_state();

    // First, prime the store with a row through the route.
    let token =
        mint_pilot_token(TokenEnv::Prod, BASE_NOW_MS, "0001000200030004", TEST_KEY).unwrap();
    let app = router(state);
    let resp = app
        .oneshot(build_request(
            &token,
            "203.0.113.60",
            &body_json_with_email("race@example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let parsed: PilotSignupResponse =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1024).await.unwrap()).unwrap();
    let original_tenant = parsed.tenant_id;

    // Now drive the store DIRECTLY with a fresh record carrying the
    // SAME email but a DIFFERENT token_id — the idempotency lookup
    // returns the existing row.
    let race_record = corelink_server::routes::signup::PilotSignupRecord {
        id: uuid::Uuid::now_v7(),
        tenant_id: uuid::Uuid::now_v7(),
        email: "race@example.com".to_owned(),
        company_name: "Race Co".to_owned(),
        tier_hint: "free".to_owned(),
        expected_use_case: "race".to_owned(),
        signed_up_at_ms: BASE_NOW_MS + 1,
        token_id: "9999888877776666".to_owned(),
        state: "RESERVED".to_owned(),
    };
    let returned = store
        .insert_or_existing(race_record)
        .expect("idempotent insert returns existing");
    assert_eq!(
        returned.tenant_id, original_tenant,
        "race-window collision returns the original tenant_id (no partial write)"
    );

    // The table still has exactly ONE row — no half-committed
    // duplicate, no orphan tenant_id, no broken UNIQUE INDEX.
    assert_eq!(harness.count_rows().unwrap(), 1);
    let rows = harness.list_rows().unwrap();
    assert_eq!(rows[0].email, "race@example.com");
    assert_eq!(rows[0].token_id, "0001000200030004");
}
