//! Targeted regression tests that close mutation-testing surface
//! coverage gaps identified by `cargo mutants -p corelink-dual-approval`
//! on 2026-05-15.
//!
//! Each test is the minimum case required to kill a specific surviving
//! mutation; see `specs/_audits/sealed/2026-05-15-mutation-expansion.md` for
//! the full mutant-by-mutant classification.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args
)]

use std::sync::Arc;

use corelink_dual_approval::audit::{AdminOpCloudEventBuilder, FailingAdminOpAuditSink};
use corelink_dual_approval::types::{ActorIdentity, ApprovalOutcome};
use corelink_dual_approval::{
    compute_hmac, proptest_cases, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalError, DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink,
    InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore, AUDIT_TYPE_DENIED,
    AUDIT_TYPE_EXECUTED,
};
use uuid::Uuid;

// =====================================================================
// audit.rs:55 — `if self.outcome == ApprovalOutcome::Approved` selects
// EXECUTED vs DENIED event type. Mutating `==` to `!=` flips the choice
// for ALL outcomes; previous tests only checked the success path.
// =====================================================================

fn build_event(outcome: ApprovalOutcome) -> corelink_dual_approval::audit::AdminOpCloudEvent {
    AdminOpCloudEventBuilder {
        op_id: Uuid::now_v7(),
        region: "enam".to_owned(),
        outcome,
        caller: ActorIdentity::new(Uuid::now_v7(), ""),
        approver: ActorIdentity::new(Uuid::now_v7(), ""),
        mfa_ts_ms: 1_000_000,
        op_type: AdminOpType::ConfigRollback,
        op_payload_hash: [0u8; 32],
        prev_state_hash: [0u8; 32],
        nonce: [0u8; 16],
        hmac_chain_sig: [0u8; 32],
        now_ms: 2_000_000,
    }
    .build()
}

#[test]
fn audit_builder_approved_outcome_uses_executed_event_type() {
    let ev = build_event(ApprovalOutcome::Approved);
    assert_eq!(ev.event_type, AUDIT_TYPE_EXECUTED);
    assert_ne!(ev.event_type, AUDIT_TYPE_DENIED);
}

#[test]
fn audit_builder_denied_outcomes_use_denied_event_type() {
    // Sweep every denied variant — `==` mutated to `!=` would route
    // these to EXECUTED, which this assertion catches.
    for outcome in [
        ApprovalOutcome::DeniedMissing,
        ApprovalOutcome::DeniedSig,
        ApprovalOutcome::DeniedCallerEq,
        ApprovalOutcome::DeniedCollusion,
        ApprovalOutcome::DeniedMfaStale,
        ApprovalOutcome::DeniedApproverNotAdmin,
        ApprovalOutcome::DeniedNonceReplay,
        ApprovalOutcome::DeniedClockSkew,
    ] {
        let ev = build_event(outcome);
        assert_eq!(
            ev.event_type, AUDIT_TYPE_DENIED,
            "outcome {:?} must map to DENIED event type",
            outcome
        );
        assert_ne!(ev.event_type, AUDIT_TYPE_EXECUTED);
    }
}

// =====================================================================
// audit.rs:102 — `ms_to_rfc3339(ms)` is private but observable through
// `AdminOpCloudEvent.time`. Mutations:
//   - body → String::new()      (empty string)
//   - body → "xyzzy".into()
//   - `ms % 1000` div op flipped → `ms + 1000` etc.
// Each mutant changes the format observably. We pin both shape and a
// numerical example.
// =====================================================================

#[test]
fn audit_builder_time_field_is_non_empty_non_canary() {
    let ev = build_event(ApprovalOutcome::Approved);
    assert!(!ev.time.is_empty(), "time field must not be empty");
    assert_ne!(ev.time, "xyzzy", "time field must not be canary string");
    assert_ne!(ev.time, "xyzzy.000Z");
    assert!(ev.time.ends_with('Z'), "time must end with Z (RFC3339 UTC)");
    assert!(
        ev.time.contains('.'),
        "time must contain seconds.millis separator"
    );
}

#[test]
fn audit_builder_time_field_encodes_secs_and_millis() {
    // ms_to_rfc3339(ms) = format!("{secs}.{millis:03}Z")
    //   secs   = ms / 1000
    //   millis = ms % 1000
    // Mutations:
    //   `/` → `%` in `secs = ms / 1000`  → secs = ms % 1000 (small value)
    //   `/` → `*`                         → secs = ms * 1000 (huge)
    //   `%` → `+` in `millis = ms % 1000` → millis = ms + 1000 (long pad)
    //   `%` → `/`                         → millis = ms / 1000
    // Each changes the string observably; we pin exact values.
    let ev = AdminOpCloudEventBuilder {
        op_id: Uuid::now_v7(),
        region: "enam".to_owned(),
        outcome: ApprovalOutcome::Approved,
        caller: ActorIdentity::new(Uuid::now_v7(), ""),
        approver: ActorIdentity::new(Uuid::now_v7(), ""),
        mfa_ts_ms: 0,
        op_type: AdminOpType::ConfigRollback,
        op_payload_hash: [0u8; 32],
        prev_state_hash: [0u8; 32],
        nonce: [0u8; 16],
        hmac_chain_sig: [0u8; 32],
        now_ms: 2_000_000,
    }
    .build();
    // 2_000_000 ms → 2000 s + 0 ms.
    assert_eq!(ev.time, "2000.000Z");

    // Non-trivial modulus.
    let ev2 = AdminOpCloudEventBuilder {
        op_id: Uuid::now_v7(),
        region: "enam".to_owned(),
        outcome: ApprovalOutcome::Approved,
        caller: ActorIdentity::new(Uuid::now_v7(), ""),
        approver: ActorIdentity::new(Uuid::now_v7(), ""),
        mfa_ts_ms: 0,
        op_type: AdminOpType::ConfigRollback,
        op_payload_hash: [0u8; 32],
        prev_state_hash: [0u8; 32],
        nonce: [0u8; 16],
        hmac_chain_sig: [0u8; 32],
        now_ms: 1_234_567,
    }
    .build();
    // 1_234_567 ms → 1234 s + 567 ms.
    assert_eq!(ev2.time, "1234.567Z");
    assert!(!ev2.time.is_empty());
    assert_ne!(ev2.time, "xyzzy");
}

// =====================================================================
// collusion.rs:100 — `if entry.created_at_ms < window_start { break; }`
// Mutating `<` → `==` means entries strictly older than window_start
// would no longer terminate the walk → recent_approvers would return
// approvers from outside the 24h window.
// =====================================================================

#[test]
fn collusion_window_excludes_entries_strictly_older_than_window_start() {
    // WINDOW_MS = 24h = 86_400_000.
    // Place one entry well outside the window (e.g. older than 48h)
    // and check it is NOT counted.
    let store = InMemoryCollusionStore::new();
    let tenant = Uuid::now_v7();
    let old_approver = Uuid::now_v7();
    let new_approver = Uuid::now_v7();
    let now_ms = 100_000_000_000u64;

    // Entry from 48h ago (well outside 24h window).
    store
        .record_approval(
            tenant,
            old_approver,
            &AdminOpType::ConfigRollback,
            now_ms - 48 * 60 * 60 * 1_000,
        )
        .expect("record");
    // Entry from 1h ago (well inside 24h window).
    store
        .record_approval(
            tenant,
            new_approver,
            &AdminOpType::ConfigRollback,
            now_ms - 60 * 60 * 1_000,
        )
        .expect("record");

    // Proposing the OLD approver again must NOT trip collusion since
    // their entry is outside the window. If `<` were mutated to `==`,
    // entries with `created_at_ms < window_start` would NOT break the
    // walk, and the old approver WOULD be returned as recent →
    // collusion rotation false-positive.
    store
        .check_collusion(tenant, old_approver, now_ms)
        .expect("old approver outside 24h window must not collide");

    // Sanity: new approver IS inside window → collision detected.
    let err = store
        .check_collusion(tenant, new_approver, now_ms)
        .unwrap_err();
    assert!(matches!(err, DualApprovalError::CollusionRotation { .. }));
}

// =====================================================================
// collusion.rs:155 — `while log.front().is_some_and(|e| e.created_at_ms
// < window_start) { log.pop_front(); }` trims entries older than
// window. Mutating `<` → `==` would make trim a no-op (only entries
// EXACTLY at boundary trimmed). We assert memory bound + post-trim
// recency.
// =====================================================================

#[test]
fn collusion_trim_pops_entries_older_than_window_start() {
    let store = InMemoryCollusionStore::new();
    let tenant = Uuid::now_v7();
    let stale_approver = Uuid::now_v7();
    let fresh_approver = Uuid::now_v7();
    let day_ms: u64 = 24 * 60 * 60 * 1_000;

    // Record a destructive op 100 days ago.
    store
        .record_approval(
            tenant,
            stale_approver,
            &AdminOpType::ConfigRollback,
            1_000_000,
        )
        .expect("record stale");

    // Record a destructive op "now" (far in future from the stale one)
    // — this triggers the trim loop with window_start near `now`, which
    // must pop the stale entry.
    let now_ms = 1_000_000 + 100 * day_ms;
    store
        .record_approval(tenant, fresh_approver, &AdminOpType::ConfigRollback, now_ms)
        .expect("record fresh");

    // Proposing the stale approver again must NOT collide — the trim
    // step should have already evicted them. If `<` were mutated to
    // `==` they would still be present and collusion would trip.
    store
        .check_collusion(tenant, stale_approver, now_ms)
        .expect("stale approver must have been trimmed out");
}

// =====================================================================
// gate.rs:34 — `const CLOCK_SKEW_MAX_MS: u64 = 60 * 1_000;` Mutating
// `*` to `+` would give 60+1000 = 1060 ms (≈ 1 s tolerance).
// Mutating `*` to `/` would give 60/1000 = 0 ms tolerance.
// We test that a request at 59s skew is accepted and at 61s rejected.
// =====================================================================

fn make_signed_request(
    caller: Uuid,
    approver: Uuid,
    tenant: Uuid,
    ts_ms: u64,
    key: &AdminSigningKey,
) -> AdminOpRequest {
    let nonce = [42u8; 16];
    let payload = b"{}".to_vec();
    let sig = compute_hmac(key, &payload, &nonce, ts_ms);
    AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type: AdminOpType::ConfigRollback,
        op_payload: payload,
        nonce,
        ts_ms,
        tenant_id: tenant,
    }
}

fn make_gate(admins: Vec<Uuid>) -> (DualApprovalGateImpl, Arc<InMemoryAdminOpAuditSink>) {
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    let gate = DualApprovalGateImpl::new(
        // Explicit deterministic test fixture; never use as production key material.
        AdminSigningKey::new([0xA5; 32]),
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    );
    (gate, sink)
}

#[test]
fn gate_clock_skew_max_const_is_60_seconds_precisely() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, _sink) = make_gate(vec![caller, approver]);

    let now_ms = 100_000_000u64;
    let mfa_ts_ms = now_ms - 60_000; // 1 min ago, well under 30 min

    // 59s in the past — must be ACCEPTED (skew=59000 ≤ 60000).
    // If CLOCK_SKEW_MAX_MS mutated to 60+1000 = 1060ms, this 59s skew
    // would exceed and be rejected.
    let req59 = make_signed_request(caller, approver, tenant, now_ms - 59_000, &key);
    let res = gate.verify(&req59, mfa_ts_ms, now_ms);
    assert!(
        res.is_ok(),
        "59s skew must be accepted; got {:?}",
        res.err()
    );

    // 61s in the past — must be REJECTED.
    // If CLOCK_SKEW_MAX_MS mutated to 60/1000 = 0ms, even 1ms skew
    // would reject (caught by this assertion's accepted variant above).
    let (gate2, _) = make_gate(vec![caller, approver]);
    let req61 = make_signed_request(caller, approver, tenant, now_ms - 61_000, &key);
    let err = gate2.verify(&req61, mfa_ts_ms, now_ms).unwrap_err();
    assert!(
        matches!(err, DualApprovalError::ClockSkew { .. }),
        "61s skew must be rejected; got {:?}",
        err
    );
}

// =====================================================================
// gate.rs:137 — `fn sha256_32(data) -> [u8; 32]` Mutating to constant
// `[0; 32]` or `[1; 32]` breaks payload-hash audit chain. Output must
// be observable in the `op_payload_hash` audit field.
// =====================================================================

#[test]
fn gate_audit_payload_hash_reflects_real_sha256() {
    // Two distinct payloads must yield distinct op_payload_hash audit
    // fields. If sha256_32 collapsed to a constant, both audits would
    // share the same hash hex string.
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);

    let (gate_a, sink_a) = make_gate(vec![caller, approver]);
    let mut req_a = make_signed_request(caller, approver, tenant, 1_000_000, &key);
    req_a.op_payload = b"payload-A".to_vec();
    req_a.approver_signature = compute_hmac(&key, &req_a.op_payload, &req_a.nonce, req_a.ts_ms);
    gate_a.verify(&req_a, 999_000, 1_000_000).expect("verify A");
    let hash_a = sink_a.captured()[0].data.op_payload_hash.clone();

    let (gate_b, sink_b) = make_gate(vec![caller, approver]);
    let mut req_b = make_signed_request(caller, approver, tenant, 1_000_000, &key);
    req_b.op_payload = b"payload-B-different".to_vec();
    req_b.approver_signature = compute_hmac(&key, &req_b.op_payload, &req_b.nonce, req_b.ts_ms);
    gate_b.verify(&req_b, 999_000, 1_000_000).expect("verify B");
    let hash_b = sink_b.captured()[0].data.op_payload_hash.clone();

    assert_ne!(
        hash_a, hash_b,
        "distinct payloads must produce distinct sha256 hashes"
    );
    // And known SHA-256 of "payload-A" lowercase hex prefix.
    // (We don't pin the exact hash to avoid coupling to encoding details;
    // distinct + non-zero + non-canary is sufficient to kill the constant
    // substitution mutants.)
    assert_ne!(hash_a, "0".repeat(64), "hash must not be all zeros");
    assert_ne!(hash_b, "0".repeat(64));
    // [1; 32] mutant → hash hex = "0101...01" (32 bytes of 0x01).
    let ones_hex = "01".repeat(32);
    assert_ne!(hash_a, ones_hex, "hash must not be all 0x01 bytes");
    assert_ne!(hash_b, ones_hex);
}

// =====================================================================
// gate.rs:166 — `let age_min = (mfa_age_ms / 60_000) as u32;` Mutating
// `/` to `%` or `*` yields wrong reported staleness. We assert exact
// value in the MfaStale variant.
// =====================================================================

#[test]
fn gate_mfa_stale_reports_age_min_via_division() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, _sink) = make_gate(vec![caller, approver]);

    let now_ms = 100_000_000u64;
    let mfa_age_ms = 45 * 60 * 1_000; // 45 minutes — above 30 min limit.
    let mfa_ts_ms = now_ms - mfa_age_ms;

    let req = make_signed_request(caller, approver, tenant, now_ms, &key);
    let err = gate.verify(&req, mfa_ts_ms, now_ms).unwrap_err();
    match err {
        DualApprovalError::MfaStale { age_min } => {
            // mfa_age_ms / 60_000 = 45. Mutating `/` to `%` would give
            // mfa_age_ms % 60_000 = 0. Mutating `/` to `*` would
            // overflow u32 cast to a much different value.
            assert_eq!(
                age_min, 45,
                "age_min must be mfa_age_ms (={}) / 60_000",
                mfa_age_ms
            );
        }
        other => panic!("expected MfaStale, got {:?}", other),
    }
}

// =====================================================================
// gate.rs:262 — `pub fn proptest_cases(default: u32) -> u32` Mutations
// to return constant 0 or 1 break property-test arity downstream. The
// function reads PROPTEST_CASES env var or returns the provided
// default. We pin both branches.
// =====================================================================

// Serialize env-var manipulation across the two proptest_cases tests to
// avoid races (Cargo runs integration tests in parallel within a file).
static PROPTEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn proptest_cases_returns_default_when_env_unparseable() {
    // Contract: function returns the supplied default when env is unset
    // OR set to unparseable. Setting to an unparseable string is safer
    // than removing (some test runners pre-set the var). If body is
    // mutated to constant `0` or `1`, the assertions for default=10_000
    // and 42 catch it.
    let _g = PROPTEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = std::env::var("PROPTEST_CASES").ok();
    std::env::set_var("PROPTEST_CASES", "not-an-integer-xyzzy");
    let v = proptest_cases(10_000);
    assert_eq!(v, 10_000);
    let v2 = proptest_cases(42);
    assert_eq!(v2, 42);
    match prev {
        Some(p) => std::env::set_var("PROPTEST_CASES", p),
        None => std::env::remove_var("PROPTEST_CASES"),
    }
}

#[test]
fn proptest_cases_honors_env_var_when_set_to_integer() {
    let _g = PROPTEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = std::env::var("PROPTEST_CASES").ok();
    std::env::set_var("PROPTEST_CASES", "777");
    let v = proptest_cases(10_000);
    assert_eq!(v, 777);
    match prev {
        Some(p) => std::env::set_var("PROPTEST_CASES", p),
        None => std::env::remove_var("PROPTEST_CASES"),
    }
}

// =====================================================================
// audit.rs:178 — `FailingAdminOpAuditSink::captured -> Vec<...>` body
// is already `Vec::new()`; cargo-mutants substitution to `vec![]` is
// semantically identical (BOTH yield empty Vec). This is an
// **equivalent mutant** and we accept it. We still assert the
// contract: a failing sink reports no captured events and emit
// returns an Err.
// =====================================================================

#[test]
fn failing_audit_sink_emit_errors_and_captures_empty() {
    let sink = FailingAdminOpAuditSink;
    let ev = build_event(ApprovalOutcome::Approved);
    let err = sink.emit(ev).unwrap_err();
    assert!(format!("{}", err).contains("injected"));
    assert!(sink.captured().is_empty());
}
