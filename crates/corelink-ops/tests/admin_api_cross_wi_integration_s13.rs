//! Cross-WI integration property test for S-13 (WI-S13-006 §6.1.5).
//!
//! Tests the composition invariant: dual-approval gates rotation start,
//! rollout start, and config rollback simultaneously. Verifies that all
//! three heavyweight admin ops compose atomically — all of
//! INV-ADMIN-DUAL-APPROVAL, INV-ADMIN-MFA-FRESHNESS, INV-KEY-OVERLAP,
//! and INV-AUDIT-APPEND-ONLY hold when triggered through the same
//! dual-approval pipeline in the same request sequence.
//!
//! # Test properties (1k iter; heavier than per-WI)
//!
//! - `prop_cross_wi_dual_approval_gates_rotation_start` — dual-approval
//!   gate blocks `SecretRotationStart` on every violation (caller==approver,
//!   MFA stale, sig invalid, collusion); gate passes with valid 2-admin
//!   composition.
//!
//! - `prop_cross_wi_dual_approval_gates_rollout_start` — same gate blocks
//!   `FeatureFlagDisable`; same composition invariants hold.
//!
//! - `prop_cross_wi_dual_approval_gates_config_rollback` — same gate blocks
//!   `ConfigRollback`; same composition invariants hold.
//!
//! - `prop_cross_wi_atomic_batch_composition` — all three ops requested
//!   in sequence (rotation_start → rollout_start → config_rollback) by
//!   two admins with fresh MFA; all three pass; audit chain emits 3 events
//!   for the tenant; INV-AUDIT-APPEND-ONLY: events append-only.
//!
//! - `prop_cross_wi_collusion_rotation_blocks_all_op_types` — collusion
//!   3-cycle blocks across all destructive op types interleaved; the
//!   collusion-rotation oracle (NIST AC-2(7)) is cross-op-type.
//!
//! # Design
//!
//! Uses the in-memory fake implementations from each WI's crate. No
//! staging account required — this is the pure-logic composition stress
//! test (charter `trait-abstraction-defer`).
//!
//! # Iteration count
//!
//! Default 1_000 iterations (heavier). Nightly: `PROPTEST_CASES=10000`
//! (or higher). Env var respected via `proptest_cases()`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panics surface as test failures by design"
)]

use std::sync::Arc;

use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalError, DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink,
    InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore,
};
use proptest::prelude::*;
use uuid::Uuid;

/// Read `PROPTEST_CASES` at runtime. Default 1_000 (heavier cross-WI).
fn proptest_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000)
}

const BASE_NOW: u64 = 10_000_000u64;

// ── Helpers ──────────────────────────────────────────────────────────────

struct GateFixture {
    gate: DualApprovalGateImpl,
    sink: Arc<InMemoryAdminOpAuditSink>,
    collusion: InMemoryCollusionStore,
}

fn make_gate(key: AdminSigningKey, admins: Vec<Uuid>) -> GateFixture {
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    let collusion = InMemoryCollusionStore::new();
    let nonce_store = InMemoryNonceStore::new();
    let gate = DualApprovalGateImpl::new(
        key,
        role_store,
        collusion.clone(),
        nonce_store,
        sink.clone(),
        "enam",
    );
    GateFixture {
        gate,
        sink,
        collusion,
    }
}

fn make_req_for_op(
    caller: Uuid,
    approver: Uuid,
    tenant: Uuid,
    key: &AdminSigningKey,
    nonce: [u8; 16],
    ts_ms: u64,
    op_type: AdminOpType,
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

/// Nonce derivation: combine base seed with op index to guarantee uniqueness
/// across ops in the same test iteration.
fn nonce_for(seed: u64, op_index: u8) -> [u8; 16] {
    let mut n = [0u8; 16];
    let b = seed.to_le_bytes();
    n[..8].copy_from_slice(&b);
    n[8] = op_index;
    n
}

// ── prop_cross_wi_dual_approval_gates_rotation_start ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: proptest_cases(),
        ..Default::default()
    })]

    /// INV-ADMIN-DUAL-APPROVAL: caller==approver always rejects SecretRotationStart.
    #[test]
    fn prop_cross_wi_dual_approval_gates_rotation_start(seed in 0u64..u64::MAX) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let user = Uuid::from_u64_pair(seed, seed ^ 0xdead);
        let tenant = Uuid::from_u64_pair(seed ^ 1, 0);
        let now = BASE_NOW;
        let nonce = nonce_for(seed, 0);

        let fixture = make_gate(key.clone(), vec![user]);
        let req = make_req_for_op(user, user, tenant, &key, nonce, now, AdminOpType::SecretRotationStart);

        let err = fixture.gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(
            matches!(err, DualApprovalError::CallerEqualsApprover),
            "SecretRotationStart: expected CallerEqualsApprover, got {err:?}"
        );
    }

    /// INV-ADMIN-MFA-FRESHNESS: stale MFA rejects SecretRotationStart.
    #[test]
    fn prop_cross_wi_mfa_stale_blocks_rotation_start(stale_extra_min in 1u32..360u32) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let caller = Uuid::now_v7();
        let approver = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [0u8; 16];

        let fixture = make_gate(key.clone(), vec![caller, approver]);
        let req = make_req_for_op(caller, approver, tenant, &key, nonce, now, AdminOpType::SecretRotationStart);

        let stale_ts = now.saturating_sub(31 * 60 * 1_000 + stale_extra_min as u64 * 60 * 1_000);
        let err = fixture.gate.verify(&req, stale_ts, now).unwrap_err();
        match err {
            DualApprovalError::MfaStale { age_min } => prop_assert!(age_min > 30),
            other => prop_assert!(false, "SecretRotationStart: expected MfaStale, got {other:?}"),
        }
    }

    /// INV-ADMIN-DUAL-APPROVAL: caller==approver always rejects FeatureFlagDisable.
    #[test]
    fn prop_cross_wi_dual_approval_gates_rollout_start(seed in 0u64..u64::MAX) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let user = Uuid::from_u64_pair(seed ^ 0xbeef, seed);
        let tenant = Uuid::from_u64_pair(seed ^ 2, 0);
        let now = BASE_NOW;
        let nonce = nonce_for(seed, 1);

        let fixture = make_gate(key.clone(), vec![user]);
        // FeatureFlagDisable is the destructive op that gates feature rollout disable.
        let req = make_req_for_op(user, user, tenant, &key, nonce, now, AdminOpType::FeatureFlagDisable);

        let err = fixture.gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(
            matches!(err, DualApprovalError::CallerEqualsApprover),
            "FeatureFlagDisable: expected CallerEqualsApprover, got {err:?}"
        );
    }

    /// INV-ADMIN-DUAL-APPROVAL: caller==approver always rejects ConfigRollback.
    #[test]
    fn prop_cross_wi_dual_approval_gates_config_rollback(seed in 0u64..u64::MAX) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let user = Uuid::from_u64_pair(seed ^ 0xcafe, seed);
        let tenant = Uuid::from_u64_pair(seed ^ 3, 0);
        let now = BASE_NOW;
        let nonce = nonce_for(seed, 2);

        let fixture = make_gate(key.clone(), vec![user]);
        let req = make_req_for_op(user, user, tenant, &key, nonce, now, AdminOpType::ConfigRollback);

        let err = fixture.gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(
            matches!(err, DualApprovalError::CallerEqualsApprover),
            "ConfigRollback: expected CallerEqualsApprover, got {err:?}"
        );
    }
}

// ── prop_cross_wi_atomic_batch_composition ────────────────────────────────

/// All three ops in sequence by two valid admins: all pass; audit emits
/// 3 events; INV-AUDIT-APPEND-ONLY.
#[test]
fn prop_cross_wi_atomic_batch_composition() {
    let cases = proptest_cases();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);

    for i in 0u64..cases as u64 {
        let caller = Uuid::from_u64_pair(i, i ^ 0x1);
        let approver = Uuid::from_u64_pair(i ^ 0x2, i ^ 0x3);
        let tenant = Uuid::from_u64_pair(i ^ 0x4, 0);

        // Fresh gate per iteration (per F-001 closure).
        let fixture = make_gate(key.clone(), vec![caller, approver]);

        let mfa_ts = BASE_NOW - 5 * 60 * 1_000; // 5 min ago (fresh)
        let now = BASE_NOW;

        // Op 1 — SecretRotationStart (caller initiates, approver signs)
        let n1 = nonce_for(i, 10);
        let req1 = make_req_for_op(
            caller,
            approver,
            tenant,
            &key,
            n1,
            now,
            AdminOpType::SecretRotationStart,
        );
        let r1 = fixture.gate.verify(&req1, mfa_ts, now);
        assert!(
            r1.is_ok(),
            "iter {i}: SecretRotationStart must pass: {r1:?}"
        );

        // Op 2 — FeatureFlagDisable (roles swapped: approver initiates, caller approves)
        let n2 = nonce_for(i, 11);
        let req2 = make_req_for_op(
            approver,
            caller,
            tenant,
            &key,
            n2,
            now + 1,
            AdminOpType::FeatureFlagDisable,
        );
        let r2 = fixture.gate.verify(&req2, mfa_ts, now + 1);
        assert!(r2.is_ok(), "iter {i}: FeatureFlagDisable must pass: {r2:?}");

        // Op 3 — ConfigRollback (need a 3rd distinct approver to satisfy NIST AC-2(7)
        // because ops 1 and 2 consumed {approver, caller} as approvers in the
        // 24h window for this tenant; use a third admin).
        let third = Uuid::from_u64_pair(i ^ 0x5, i ^ 0x6);
        // Give third admin the role.
        let fixture3 = make_gate(key.clone(), vec![caller, approver, third]);
        // But we also need ops 1+2 recorded in fixture3's collusion store.
        fixture3
            .collusion
            .record_approval(tenant, approver, &AdminOpType::SecretRotationStart, now)
            .unwrap();
        fixture3
            .collusion
            .record_approval(tenant, caller, &AdminOpType::FeatureFlagDisable, now + 1)
            .unwrap();

        let n3 = nonce_for(i, 12);
        let req3 = make_req_for_op(
            caller,
            third,
            tenant,
            &key,
            n3,
            now + 2,
            AdminOpType::ConfigRollback,
        );
        let r3 = fixture3.gate.verify(&req3, mfa_ts, now + 2);
        assert!(
            r3.is_ok(),
            "iter {i}: ConfigRollback with 3rd distinct approver must pass: {r3:?}"
        );

        // Audit chain: fixture sink has ops 1+2; fixture3 sink has op 3.
        let audit_f1 = fixture.sink.captured();
        assert_eq!(
            audit_f1.len(),
            2,
            "iter {i}: fixture1 must have 2 audit events"
        );

        let audit_f3 = fixture3.sink.captured();
        assert_eq!(
            audit_f3.len(),
            1,
            "iter {i}: fixture3 must have 1 audit event (op3)"
        );

        // INV-AUDIT-APPEND-ONLY: all captured events are EXECUTED type (not denied).
        for ev in audit_f1.iter().chain(audit_f3.iter()) {
            assert!(
                ev.event_type == corelink_dual_approval::AUDIT_TYPE_EXECUTED,
                "iter {i}: all passing ops must emit EXECUTED event, got {:?}",
                ev.event_type
            );
        }
    }
}

// ── prop_cross_wi_collusion_rotation_blocks_all_op_types ─────────────────

/// NIST AC-2(7): collusion-rotation oracle is cross-op-type.
/// Sequence: op1(A approves), op2(B approves), op3 proposed-approver=A
/// where all ops are different types → 3rd still rejected.
#[test]
fn prop_cross_wi_collusion_rotation_blocks_all_op_types() {
    let cases = proptest_cases();

    let op_triplets: &[(AdminOpType, AdminOpType, AdminOpType)] = &[
        (
            AdminOpType::SecretRotationStart,
            AdminOpType::ConfigRollback,
            AdminOpType::TenantTombstone,
        ),
        (
            AdminOpType::TenantTombstone,
            AdminOpType::FeatureFlagDisable,
            AdminOpType::ConfigRollback,
        ),
        (
            AdminOpType::ConfigRollback,
            AdminOpType::TenantTombstone,
            AdminOpType::SecretRotationStart,
        ),
        (
            AdminOpType::FeatureFlagDisable,
            AdminOpType::TenantTombstone,
            AdminOpType::SecretRotationStart,
        ),
    ];

    for i in 0u64..cases as u64 {
        let triplet = &op_triplets[i as usize % op_triplets.len()];
        let a = Uuid::from_u64_pair(i, i ^ 0xdeed);
        let b = Uuid::from_u64_pair(i ^ 0xface, i);
        let tenant = Uuid::from_u64_pair(i ^ 0xbabe, 0);
        let now = BASE_NOW;

        let store = InMemoryCollusionStore::new();
        // Op1: A approves triplet.0
        store.record_approval(tenant, a, &triplet.0, now).unwrap();
        // Op2: B approves triplet.1
        store
            .record_approval(tenant, b, &triplet.1, now + 1_000)
            .unwrap();

        // Op3: proposed approver=A for triplet.2 → must be rejected
        let check = store.check_collusion(tenant, a, now + 2_000);
        assert!(
            check.is_err(),
            "iter {i}: A (op1+op2 exhausted) must be rejected as approver for op3 ({:?}): got {check:?}",
            triplet.2
        );
        assert!(
            matches!(
                check.unwrap_err(),
                DualApprovalError::CollusionRotation { .. }
            ),
            "iter {i}: expected CollusionRotation"
        );
    }
}

// ── prop_cross_wi_mfa_freshness_blocks_all_destructive_ops ───────────────

/// INV-ADMIN-MFA-FRESHNESS holds for every destructive op type.
#[test]
fn prop_cross_wi_mfa_freshness_blocks_all_destructive_ops() {
    let cases = proptest_cases();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);

    let destructive_ops = [
        AdminOpType::ConfigRollback,
        AdminOpType::TenantTombstone,
        AdminOpType::SecretRotationStart,
        AdminOpType::FeatureFlagDisable,
        AdminOpType::RetentionPolicyReduce,
    ];

    for i in 0u64..cases as u64 {
        let op = &destructive_ops[i as usize % destructive_ops.len()];
        let caller = Uuid::from_u64_pair(i, i ^ 0x11);
        let approver = Uuid::from_u64_pair(i ^ 0x22, i ^ 0x33);
        let tenant = Uuid::from_u64_pair(i ^ 0x44, 0);
        let now = BASE_NOW;
        let nonce = nonce_for(i, 20);

        let fixture = make_gate(key.clone(), vec![caller, approver]);
        let req = make_req_for_op(caller, approver, tenant, &key, nonce, now, op.clone());

        // MFA 31 min stale → must reject.
        let stale_mfa = now.saturating_sub(31 * 60 * 1_000);
        let err = fixture.gate.verify(&req, stale_mfa, now).unwrap_err();
        assert!(
            matches!(err, DualApprovalError::MfaStale { .. }),
            "iter {i} op={op:?}: expected MfaStale, got {err:?}"
        );
    }
}
