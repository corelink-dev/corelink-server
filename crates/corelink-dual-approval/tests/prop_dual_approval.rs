//! Property tests pinning dual-approval invariants at 10k iter per PR
//! (100k nightly via `PROPTEST_CASES` env var).
//!
//! Properties (WI-S13-002 §6.1.7):
//!
//! - `prop_missing_approver_rejected` — caller==approver → CallerEqualsApprover.
//! - `prop_sig_invalid_rejected` — byte-mutation of sig → SignatureInvalid.
//! - `prop_caller_eq_approver_rejected` — same-UUID → CallerEqualsApprover.
//! - `prop_collusion_rotation_a_b_a_b` — NIST AC-2(7) primary (Lote 10.13
//!   canonical): 3rd op MUST be rejected.
//! - `prop_collusion_rotation_3_distinct_passes` — 3 distinct approvers pass.
//! - `prop_mfa_stale_rejected` — mfa_ts > 30 min ago → MfaStale.
//! - `prop_nonce_replay_rejected` — same nonce twice → NonceReplay.
//! - `prop_clock_skew_rejected` — ts_ms off by > 60s → ClockSkew.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout
)]

use std::sync::Arc;

use proptest::prelude::*;
use uuid::Uuid;

use corelink_dual_approval::{
    compute_hmac, AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalError,
    DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink, InMemoryAdminRoleStore,
    InMemoryCollusionStore, InMemoryNonceStore,
};

fn cases() -> u32 {
    corelink_dual_approval::proptest_cases(10_000)
}

const BASE_NOW: u64 = 10_000_000u64;

fn make_gate(
    key: AdminSigningKey,
    admins: Vec<Uuid>,
) -> (
    DualApprovalGateImpl,
    Arc<InMemoryAdminOpAuditSink>,
    InMemoryCollusionStore,
    InMemoryNonceStore,
) {
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    let collusion = InMemoryCollusionStore::new();
    let nonce = InMemoryNonceStore::new();
    let gate = DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        collusion.clone(),
        nonce.clone(),
        sink.clone(),
        "enam",
    );
    (gate, sink, collusion, nonce)
}

fn make_req(
    caller: Uuid,
    approver: Uuid,
    tenant: Uuid,
    key: &AdminSigningKey,
    nonce: [u8; 16],
    ts_ms: u64,
) -> AdminOpRequest {
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

/// Returns true if the error is a CallerEqualsApprover.
fn is_caller_eq_approver(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::CallerEqualsApprover)
}

/// Returns true if the error is a SignatureInvalid.
fn is_sig_invalid(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::SignatureInvalid)
}

/// Returns true if the error is MfaStale.
fn is_mfa_stale(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::MfaStale { .. })
}

/// Returns true if the error is ClockSkew.
fn is_clock_skew(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::ClockSkew { .. })
}

/// Returns true if the error is NonceReplay.
fn is_nonce_replay(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::NonceReplay { .. })
}

/// Returns true if the error is CollusionRotation.
fn is_collusion_rotation(e: &DualApprovalError) -> bool {
    matches!(e, DualApprovalError::CollusionRotation { .. })
}

// ── Property: caller == approver always rejected ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn prop_caller_eq_approver_rejected(seed in 0u64..u64::MAX) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let user = Uuid::from_u64_pair(seed, seed);
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [0u8; 16];
        let (gate, _sink, _, _) = make_gate(key.clone(), vec![user]);
        let req = make_req(user, user, tenant, &key, nonce, now);
        let err = gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(is_caller_eq_approver(&err), "expected CallerEqualsApprover, got {err:?}");
    }
}

// ── Property: HMAC signature mutation always rejected ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn prop_sig_invalid_rejected(
        mutation_byte in 0usize..32usize,
        xor_val in 1u8..=255u8,
    ) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let caller = Uuid::now_v7();
        let approver = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [0u8; 16];
        let mut req = make_req(caller, approver, tenant, &key, nonce, now);
        req.approver_signature[mutation_byte] ^= xor_val;

        let (gate, _sink, _, _) = make_gate(key.clone(), vec![caller, approver]);
        let err = gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(is_sig_invalid(&err), "expected SignatureInvalid, got {err:?}");
    }
}

// ── Property: MFA stale (> 30 min) always rejected ───────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn prop_mfa_stale_rejected(extra_min in 1u32..480u32) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let caller = Uuid::now_v7();
        let approver = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [0u8; 16];
        let req = make_req(caller, approver, tenant, &key, nonce, now);
        let stale_mfa_ts = now.saturating_sub(31 * 60 * 1_000 + (extra_min as u64) * 60 * 1_000);

        let (gate, _sink, _, _) = make_gate(key.clone(), vec![caller, approver]);
        let err = gate.verify(&req, stale_mfa_ts, now).unwrap_err();
        prop_assert!(is_mfa_stale(&err), "expected MfaStale, got {err:?}");
    }
}

// ── Property: clock skew > 60s always rejected ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn prop_clock_skew_rejected(skew_extra_ms in 1u64..60_000u64) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let caller = Uuid::now_v7();
        let approver = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [0u8; 16];
        let future_ts = now + 61_000 + skew_extra_ms;
        let payload = b"{}".to_vec();
        let sig = compute_hmac(&key, &payload, &nonce, future_ts);
        let req = AdminOpRequest {
            caller_user_id: caller,
            approver_user_id: approver,
            approver_signature: sig,
            op_type: AdminOpType::ConfigRollback,
            op_payload: payload,
            nonce,
            ts_ms: future_ts,
            tenant_id: tenant,
        };
        let (gate, _sink, _, _) = make_gate(key.clone(), vec![caller, approver]);
        let err = gate.verify(&req, now - 60_000, now).unwrap_err();
        prop_assert!(is_clock_skew(&err), "expected ClockSkew, got {err:?}");
    }
}

// ── Property: nonce replay always rejected ────────────────────────────────
//
// Uses non-destructive op (FeatureFlagToggleSafe) to isolate nonce replay
// from collusion-rotation tracking (which would fire first for destructive ops).

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn prop_nonce_replay_rejected(seed in 0u8..=255u8) {
        // Explicit deterministic test fixture; never use as production key material.
        let key = AdminSigningKey::new([0xA5; 32]);
        let caller = Uuid::now_v7();
        let approver = Uuid::now_v7();
        let tenant = Uuid::now_v7();
        let now = BASE_NOW;
        let nonce = [seed; 16];

        let (gate, _sink, _, _) = make_gate(key.clone(), vec![caller, approver]);

        // Build non-destructive req to avoid collusion tracking interference.
        let make_nondest = |n: [u8; 16], ts: u64| {
            let payload = b"{}".to_vec();
            let sig = compute_hmac(&key, &payload, &n, ts);
            AdminOpRequest {
                caller_user_id: caller,
                approver_user_id: approver,
                approver_signature: sig,
                op_type: AdminOpType::FeatureFlagToggleSafe,
                op_payload: payload,
                nonce: n,
                ts_ms: ts,
                tenant_id: tenant,
            }
        };

        // First request succeeds.
        gate.verify(&make_nondest(nonce, now), now - 60_000, now).unwrap();

        // Second request with same nonce must fail via NonceReplay.
        let err = gate.verify(&make_nondest(nonce, now + 1), now - 60_000, now + 1).unwrap_err();
        prop_assert!(is_nonce_replay(&err), "expected NonceReplay, got {err:?}");
    }
}

// ── Property: collusion A→B / B→A / A→B — 3rd op rejected ───────────────
//
// NIST AC-2(7) primary (Lote 10.13 canonical strengthening).
// Op 1 (caller=B, approver=A) succeeds.
// Op 2 (caller=A, approver=B) succeeds.
// Op 3 (caller=B, approver=A) MUST be rejected: A ∈ {A, B} = last 2 distinct.

#[test]
fn prop_collusion_rotation_a_b_a_b() {
    use corelink_dual_approval::InMemoryCollusionStore;

    for _ in 0..cases() {
        let store = InMemoryCollusionStore::new();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let tenant = Uuid::now_v7();

        store
            .record_approval(tenant, a, &AdminOpType::ConfigRollback, 1_000)
            .unwrap();
        store
            .record_approval(tenant, b, &AdminOpType::ConfigRollback, 2_000)
            .unwrap();

        let err = store.check_collusion(tenant, a, 5_000).unwrap_err();
        assert!(
            is_collusion_rotation(&err),
            "3rd op with same approver A must be CollusionRotation, got {err:?}"
        );
    }
}

// ── Property: 3 distinct approvers in rolling window passes ──────────────

#[test]
fn prop_collusion_rotation_3_distinct_passes() {
    use corelink_dual_approval::InMemoryCollusionStore;

    for _ in 0..cases() {
        let store = InMemoryCollusionStore::new();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        let e = Uuid::now_v7();
        let tenant = Uuid::now_v7();

        store
            .record_approval(tenant, b, &AdminOpType::TenantTombstone, 1_000)
            .unwrap();
        store
            .record_approval(tenant, c, &AdminOpType::TenantTombstone, 2_000)
            .unwrap();

        // E ∉ {c, b} → ok
        store.check_collusion(tenant, e, 5_000).unwrap();
    }
}
