//! Wave-14 mutation-kill closures for `corelink-dual-approval` — targets the
//! surviving mutants surfaced by the 2026-05-15 cargo-mutants run that the
//! wave-13 compliance-weekly-digest §11 trend section flagged at 65.9 %
//! (below the 75 % canonical floor).
//!
//! Every test in this file is the minimum surface required to kill one
//! specific surviving mutant; see
//! `specs/_audits/sealed/2026-05-15-mutation-full-sweep.md` (DEBT-008 closure
//! wave-14 section) for the mutant-by-mutant rationale.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args
)]

use std::sync::Arc;

use corelink_dual_approval::types::ApprovalOutcome;
use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalError, DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink,
    InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore, AUDIT_TYPE_DENIED,
    AUDIT_TYPE_EXECUTED,
};
use uuid::Uuid;

// =====================================================================
// types.rs:126 — `ApprovalOutcome::as_str` body mutated to `""` or
// `"xyzzy"` would break every audit outcome label and break the D1
// CHECK-constraint mapping. Tests must pin every variant to its exact
// canonical string.
// =====================================================================

#[test]
fn approval_outcome_as_str_pins_every_variant_to_canonical_d1_label() {
    // Every variant of ApprovalOutcome must map to the D1
    // admin_op_log.outcome CHECK-constraint accepted value. Mutating the
    // function body to `""` or `"xyzzy"` would collapse all variants to
    // the same canary string; this sweep kills both mutants.
    let pairs: &[(ApprovalOutcome, &str)] = &[
        (ApprovalOutcome::Approved, "approved"),
        (ApprovalOutcome::DeniedMissing, "denied_missing"),
        (ApprovalOutcome::DeniedSig, "denied_sig"),
        (ApprovalOutcome::DeniedCallerEq, "denied_caller_eq"),
        (ApprovalOutcome::DeniedCollusion, "denied_collusion"),
        (ApprovalOutcome::DeniedMfaStale, "denied_mfa_stale"),
        (
            ApprovalOutcome::DeniedApproverNotAdmin,
            "denied_approver_not_admin",
        ),
        (ApprovalOutcome::DeniedNonceReplay, "denied_nonce_replay"),
        (ApprovalOutcome::DeniedClockSkew, "denied_clock_skew"),
    ];
    for (outcome, expected) in pairs {
        let actual = outcome.as_str();
        assert_eq!(
            actual, *expected,
            "outcome {:?} must map to {:?}, got {:?}",
            outcome, expected, actual
        );
        assert!(!actual.is_empty(), "outcome string must never be empty");
        assert_ne!(actual, "xyzzy");
    }
    // Negative: assert each variant maps to a UNIQUE string (kills the
    // `""` mutant which would collapse all 9 to the same value).
    let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    for (outcome, _) in pairs {
        let s = outcome.as_str();
        assert!(
            seen.insert(s),
            "outcome strings must be unique; duplicate: {}",
            s
        );
    }
    assert_eq!(seen.len(), pairs.len());
}

// =====================================================================
// hmac_verify.rs:27 — `impl fmt::Debug for AdminSigningKey` redacts raw
// bytes. Mutating the body to `Ok(Default::default())` would produce an
// empty Debug string instead of the redacted struct shape. We pin the
// exact Debug output AND assert the key bytes never leak.
// =====================================================================

#[test]
fn admin_signing_key_debug_redacts_raw_and_pins_shape() {
    // Construct a key with non-trivial bytes so a body that printed raw
    // bytes would show distinctive content. The Debug impl must redact.
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let key = AdminSigningKey::new(raw);
    let dbg = format!("{:?}", key);
    // Shape: the redacted Debug impl shows the struct name + REDACTED.
    assert!(
        dbg.contains("AdminSigningKey"),
        "missing struct name: {:?}",
        dbg
    );
    assert!(
        dbg.contains("REDACTED"),
        "missing redaction marker: {:?}",
        dbg
    );
    // Negative: no raw byte leak (any of 0x00..0x1f would appear if
    // raw was printed via the derived Debug).
    assert!(
        !dbg.contains("0, 1, 2, 3"),
        "raw byte sequence leaked: {:?}",
        dbg
    );
    assert!(
        !dbg.contains("[0, 1, 2"),
        "raw array prefix leaked: {:?}",
        dbg
    );
    // Negative: mutant body → Ok(Default::default()) would yield "()".
    assert_ne!(dbg, "()", "Debug must not collapse to unit");
    assert!(!dbg.is_empty(), "Debug output must never be empty");
}

// =====================================================================
// gate.rs:132 — `emit_denial` writes a denial AdminOpCloudEvent to the
// audit sink. Mutating the body to `()` (no-op) means denial paths emit
// nothing — a CRITICAL audit-coverage gap. We exercise every denial
// path and assert the corresponding CloudEvent was captured.
//
// Covers all 7 denial outcomes (DeniedClockSkew, DeniedMfaStale,
// DeniedCallerEq, DeniedApproverNotAdmin, DeniedSig, DeniedCollusion,
// DeniedNonceReplay) by routing each one through `verify()` with a
// payload crafted to trigger that specific check.
// =====================================================================

fn make_signed_request(
    caller: Uuid,
    approver: Uuid,
    tenant: Uuid,
    ts_ms: u64,
    nonce: [u8; 16],
    op_type: AdminOpType,
    key: &AdminSigningKey,
) -> AdminOpRequest {
    let payload = b"{}".to_vec();
    let sig = compute_hmac(key, &payload, &nonce, ts_ms);
    AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type,
        op_payload: payload,
        nonce,
        ts_ms,
        tenant_id: tenant,
    }
}

fn make_gate_with_sink(admins: Vec<Uuid>) -> (DualApprovalGateImpl, Arc<InMemoryAdminOpAuditSink>) {
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
fn gate_denial_emits_audit_for_clock_skew() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    let now = 10_000_000u64;
    // ts > 60s in the past → ClockSkew.
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now - 120_000,
        [1u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let err = gate.verify(&req, now - 5 * 60_000, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::ClockSkew { .. }));
    let captured = sink.captured();
    assert_eq!(
        captured.len(),
        1,
        "ClockSkew denial must emit exactly 1 audit event"
    );
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_clock_skew");
}

#[test]
fn gate_denial_emits_audit_for_mfa_stale() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    let now = 10_000_000u64;
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [2u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    // MFA 45 min ago → MfaStale.
    let mfa_ts = now - 45 * 60 * 1_000;
    let err = gate.verify(&req, mfa_ts, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::MfaStale { .. }));
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_mfa_stale");
}

#[test]
fn gate_denial_emits_audit_for_caller_eq_approver() {
    let user = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![user]);
    let now = 10_000_000u64;
    let req = make_signed_request(
        user,
        user,
        tenant,
        now,
        [3u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let err = gate.verify(&req, now - 60_000, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::CallerEqualsApprover));
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_caller_eq");
}

#[test]
fn gate_denial_emits_audit_for_approver_not_admin() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    // Approver NOT in admin role.
    let (gate, sink) = make_gate_with_sink(vec![caller]);
    let now = 10_000_000u64;
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [4u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let err = gate.verify(&req, now - 60_000, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::ApproverNotAdmin));
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_approver_not_admin");
}

#[test]
fn gate_denial_emits_audit_for_sig_invalid() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    let now = 10_000_000u64;
    let mut req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [5u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    req.approver_signature[0] ^= 0xFF; // forge
    let err = gate.verify(&req, now - 60_000, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::SignatureInvalid));
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_sig");
}

#[test]
fn gate_denial_emits_audit_for_collusion() {
    let caller_a = Uuid::now_v7();
    let caller_b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;

    // Use a shared in-memory store across two gates so we can pre-load
    // history without going through the success-recording path.
    let collusion = InMemoryCollusionStore::new();
    collusion
        .record_approval(tenant, caller_a, &AdminOpType::ConfigRollback, now - 60_000)
        .unwrap();
    collusion
        .record_approval(tenant, caller_b, &AdminOpType::ConfigRollback, now - 30_000)
        .unwrap();

    // Now build a fresh gate sharing the collusion store; propose
    // caller_a again → CollusionRotation.
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller_b, caller_a]));
    let gate = DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        collusion,
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    );
    let req = make_signed_request(
        caller_b,
        caller_a,
        tenant,
        now,
        [6u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let err = gate.verify(&req, now - 60_000, now).unwrap_err();
    assert!(matches!(err, DualApprovalError::CollusionRotation { .. }));
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[0].data.outcome, "denied_collusion");
}

#[test]
fn gate_denial_emits_audit_for_nonce_replay() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    let now = 10_000_000u64;
    // Use non-destructive op to isolate from collusion tracking.
    let req1 = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [7u8; 16],
        AdminOpType::FeatureFlagToggleSafe,
        &key,
    );
    gate.verify(&req1, now - 60_000, now).unwrap();
    // captured[0] is the first success.
    let req2 = make_signed_request(
        caller,
        approver,
        tenant,
        now + 1,
        [7u8; 16],
        AdminOpType::FeatureFlagToggleSafe,
        &key,
    );
    let err = gate.verify(&req2, now - 60_000, now + 1).unwrap_err();
    assert!(matches!(err, DualApprovalError::NonceReplay { .. }));
    let captured = sink.captured();
    // Two events: 1 success + 1 denial.
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].event_type, AUDIT_TYPE_EXECUTED);
    assert_eq!(captured[1].event_type, AUDIT_TYPE_DENIED);
    assert_eq!(captured[1].data.outcome, "denied_nonce_replay");
}

// =====================================================================
// collusion.rs:84 — `recent_approvers` body mutated to
// `Ok(vec![])` collapses to empty; `Ok(vec![Default::default()])`
// returns a single zero-UUID. The zero-UUID mutant would slip through
// any test where the proposed_approver UUID is never the zero UUID.
// We assert recent_approvers returns the EXACT set we recorded.
// =====================================================================

#[test]
fn collusion_recent_approvers_returns_exactly_what_we_recorded() {
    let store = InMemoryCollusionStore::new();
    let tenant = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let now_ms = 10_000_000u64;

    // Empty store → empty result.
    let recent = store.recent_approvers(tenant, now_ms).unwrap();
    assert!(recent.is_empty(), "empty store must yield empty recent set");

    // After two recordings → both present, most-recent first.
    store
        .record_approval(tenant, a, &AdminOpType::ConfigRollback, now_ms - 60_000)
        .unwrap();
    store
        .record_approval(tenant, b, &AdminOpType::ConfigRollback, now_ms - 30_000)
        .unwrap();
    let recent = store.recent_approvers(tenant, now_ms).unwrap();
    assert_eq!(recent.len(), 2, "must return both recorded approvers");
    // Most recent first → b, then a.
    assert_eq!(recent[0], b);
    assert_eq!(recent[1], a);
    // Neither must be the zero/Default UUID (kills the
    // `vec![Default::default()]` mutant).
    let zero = Uuid::nil();
    assert_ne!(recent[0], zero, "recent[0] must not be zero/Default UUID");
    assert_ne!(recent[1], zero, "recent[1] must not be zero/Default UUID");
}

#[test]
fn collusion_check_against_zero_uuid_returns_ok_when_not_recorded() {
    // Kills `recent_approvers → Ok(vec![Default::default()])`: if the
    // function returned a singleton zero-UUID, proposing the zero UUID
    // for a tenant with NO history would falsely trigger collusion.
    let store = InMemoryCollusionStore::new();
    let tenant = Uuid::now_v7();
    let now_ms = 10_000_000u64;
    let zero = Uuid::nil();
    // Empty store: proposing zero UUID must NOT trip collusion.
    store
        .check_collusion(tenant, zero, now_ms)
        .expect("zero UUID against empty store must not collide");
}

// =====================================================================
// collusion.rs:141 — `record_approval` has an early `return Ok(())` for
// non-destructive ops. Mutating to an empty body (delete the if-return)
// causes non-destructive ops to be recorded as if destructive. We
// assert that non-destructive ops do NOT pollute recent_approvers.
// =====================================================================

#[test]
fn collusion_record_skips_non_destructive_ops() {
    let store = InMemoryCollusionStore::new();
    let tenant = Uuid::now_v7();
    let user = Uuid::now_v7();
    let now_ms = 10_000_000u64;

    // Non-destructive ops MUST NOT enter the log.
    store
        .record_approval(
            tenant,
            user,
            &AdminOpType::FeatureFlagToggleSafe,
            now_ms - 10_000,
        )
        .unwrap();
    store
        .record_approval(
            tenant,
            user,
            &AdminOpType::RateLimitAdjustUp,
            now_ms - 5_000,
        )
        .unwrap();

    let recent = store.recent_approvers(tenant, now_ms).unwrap();
    assert!(
        recent.is_empty(),
        "non-destructive ops must not enter the collusion log; got {:?}",
        recent
    );

    // Then add a destructive op and verify it DOES land.
    store
        .record_approval(tenant, user, &AdminOpType::ConfigRollback, now_ms - 1_000)
        .unwrap();
    let recent = store.recent_approvers(tenant, now_ms).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0], user);
}

// =====================================================================
// gate.rs:154 — `sha256_32` mutation to `[0; 32]` or `[1; 32]` was
// already covered for `op_payload_hash`. The `prev_state_hash` field
// uses a SECOND sha256_32 call (sha256 of the payload hash). Without a
// distinct test on that derivation chain, the mutant could survive if
// the hashing collapses both fields to the same constant. We assert
// op_payload_hash != prev_state_hash for a non-empty payload.
// =====================================================================

#[test]
fn gate_audit_payload_and_prev_state_hashes_are_distinct() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    let now = 10_000_000u64;
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [8u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    gate.verify(&req, now - 60_000, now).expect("verify");
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    let payload_hash = &captured[0].data.op_payload_hash;
    let prev_state_hash = &captured[0].data.prev_state_hash;
    // sha256(payload) != sha256(sha256(payload)) for any non-degenerate
    // input — kills the [0;32]/[1;32] constant-collapse mutant since
    // both fields would otherwise be identical.
    assert_ne!(
        payload_hash, prev_state_hash,
        "op_payload_hash and prev_state_hash must differ (two distinct sha256 layers)"
    );
    assert_ne!(payload_hash, &"0".repeat(64));
    assert_ne!(prev_state_hash, &"0".repeat(64));
    let ones_hex = "01".repeat(32);
    assert_ne!(payload_hash, &ones_hex);
    assert_ne!(prev_state_hash, &ones_hex);
}

// =====================================================================
// audit.rs:159 — `InMemoryAdminOpAuditSink::captured` body mutated to
// `vec![Default::default()]` would return a sentinel canary event
// regardless of actual captured state. Kill by asserting `captured`
// reflects emit history exactly.
// =====================================================================

#[test]
fn in_memory_audit_sink_captured_reflects_emit_history_exactly() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let (gate, sink) = make_gate_with_sink(vec![caller, approver]);
    // Pristine sink → captured is empty (kills `vec![Default::default()]`
    // which returns a 1-element canary even with zero emits).
    assert!(
        sink.captured().is_empty(),
        "pristine sink must report 0 captured events"
    );
    let now = 10_000_000u64;
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [9u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    gate.verify(&req, now - 60_000, now).expect("verify");
    assert_eq!(
        sink.captured().len(),
        1,
        "after 1 emit, captured len must be 1 (kills vec![Default::default()] canary)"
    );

    let req2 = make_signed_request(
        caller,
        approver,
        tenant,
        now + 1,
        [10u8; 16],
        AdminOpType::FeatureFlagToggleSafe,
        &key,
    );
    gate.verify(&req2, now - 60_000, now + 1).expect("verify");
    assert_eq!(
        sink.captured().len(),
        2,
        "after 2 emits, captured len must be 2"
    );
}

// =====================================================================
// gate.rs:31, 34 — `MFA_MAX_AGE_MS` and `CLOCK_SKEW_MAX_MS` are
// `60 * 1_000` and `30 * 60 * 1_000` respectively. The const folding
// math mutants (`*` → `+`, `*` → `/`) on line 31 (MFA_MAX_AGE_MS) are
// distinct from the clock-skew const mutants. Clock-skew is covered
// in `gate_clock_skew_max_const_is_60_seconds_precisely`; MFA must
// have an analogous boundary test.
// =====================================================================

#[test]
fn gate_mfa_max_age_const_is_30_minutes_precisely() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;

    // 29 min ago — must be accepted (1_740_000 ≤ 1_800_000).
    // Mutation MFA_MAX_AGE_MS = 30+60*1000 = 60030 → 29 min would reject.
    // Mutation MFA_MAX_AGE_MS = 30/(60*1000) = 0 → ANY age rejects.
    let (gate, _sink) = make_gate_with_sink(vec![caller, approver]);
    let req = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [11u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let mfa_29 = now - 29 * 60 * 1_000;
    let res = gate.verify(&req, mfa_29, now);
    assert!(
        res.is_ok(),
        "29 min MFA age must be accepted; got {:?}",
        res.err()
    );

    // 31 min ago — must be rejected.
    let (gate2, _sink2) = make_gate_with_sink(vec![caller, approver]);
    let req2 = make_signed_request(
        caller,
        approver,
        tenant,
        now,
        [12u8; 16],
        AdminOpType::ConfigRollback,
        &key,
    );
    let mfa_31 = now - 31 * 60 * 1_000;
    let err = gate2.verify(&req2, mfa_31, now).unwrap_err();
    assert!(
        matches!(err, DualApprovalError::MfaStale { .. }),
        "31 min MFA age must be MfaStale; got {:?}",
        err
    );
}

// =====================================================================
// types.rs:69 — `AdminOpType::is_destructive` body mutated to
// `true`/`false`. The existing mutation_kills tests catch this
// indirectly via collusion/nonce flow. Pin every variant explicitly
// here for defense-in-depth.
// =====================================================================

#[test]
fn admin_op_type_is_destructive_pins_every_variant() {
    let destructive: &[AdminOpType] = &[
        AdminOpType::ConfigRollback,
        AdminOpType::RetentionPolicyReduce,
        AdminOpType::FeatureFlagDisable,
        AdminOpType::SecretRotationStart,
        AdminOpType::TenantTombstone,
    ];
    let non_destructive: &[AdminOpType] = &[
        AdminOpType::FeatureFlagToggleSafe,
        AdminOpType::RateLimitAdjustUp,
    ];
    for op in destructive {
        assert!(
            op.is_destructive(),
            "{:?} must be destructive (kills `false` mutant)",
            op
        );
    }
    for op in non_destructive {
        assert!(
            !op.is_destructive(),
            "{:?} must NOT be destructive (kills `true` mutant)",
            op
        );
    }
}

// =====================================================================
// gate.rs:60 — `InMemoryAdminRoleStore::is_admin` body mutated to
// `true`/`false`. Already exercised by the adversarial revoked-approver
// test, but we pin the exact contract for both directions here.
// =====================================================================

#[test]
fn in_memory_admin_role_store_is_admin_reflects_membership_exactly() {
    use corelink_dual_approval::AdminRoleStore;
    let admin = Uuid::now_v7();
    let non_admin = Uuid::now_v7();
    let store = InMemoryAdminRoleStore::new(vec![admin]);
    // `is_admin → true` mutant would have non_admin → true; we assert false.
    assert!(!store.is_admin(non_admin), "non-admin must not be admin");
    // `is_admin → false` mutant would have admin → false; we assert true.
    assert!(store.is_admin(admin), "admin must be admin");
}

// =====================================================================
// audit.rs:151 — `InMemoryAdminOpAuditSink::emit` mutated to `Ok(())`
// (skip the push). Existing flows assert captured().len() after emit,
// but we add an explicit emit-then-captured assertion that pins exactly
// the event content so a body-replacement mutant cannot pass.
// =====================================================================

#[test]
fn in_memory_audit_sink_emit_pushes_into_captured() {
    use corelink_dual_approval::audit::AdminOpCloudEventBuilder;
    use corelink_dual_approval::types::ActorIdentity;

    let sink = InMemoryAdminOpAuditSink::new();
    assert!(sink.captured().is_empty());
    let ev = AdminOpCloudEventBuilder {
        op_id: Uuid::now_v7(),
        region: "enam".to_owned(),
        outcome: ApprovalOutcome::Approved,
        caller: ActorIdentity::new(Uuid::now_v7(), "cafe"),
        approver: ActorIdentity::new(Uuid::now_v7(), "babe"),
        mfa_ts_ms: 1_000_000,
        op_type: AdminOpType::ConfigRollback,
        op_payload_hash: [0xAAu8; 32],
        prev_state_hash: [0xBBu8; 32],
        nonce: [0xCCu8; 16],
        hmac_chain_sig: [0xDDu8; 32],
        now_ms: 2_000_000,
    }
    .build();
    sink.emit(ev.clone()).expect("emit ok");
    let cap = sink.captured();
    assert_eq!(
        cap.len(),
        1,
        "emit must push into captured (kills Ok(()) noop mutant)"
    );
    // Content-level assertion: the captured event matches what we built.
    // This kills `captured → vec![Default::default()]` since a default
    // event would have empty region/outcome strings.
    assert_eq!(cap[0].data.outcome, "approved");
    assert_eq!(cap[0].source, "/corelink/admin/enam");
    assert_eq!(cap[0].data.nonce, "cccccccccccccccccccccccccccccccc");
    assert_eq!(cap[0].data.op_payload_hash, "aa".repeat(32));
    assert_eq!(cap[0].data.prev_state_hash, "bb".repeat(32));
    assert_eq!(cap[0].data.signature, "dd".repeat(32));
}
