//! Adversarial regression tests — 7+ CVE-class scenarios (WI-S13-002 §6.1.8).
//!
//! 1. Collusion A→B/B→A/A→B 3-cycle (Lote 10.13 canonical) — 3rd op rejected.
//! 2. HMAC signature forge (random byte mutation) → SignatureInvalid.
//! 3. Approver privilege revoked before verify → ApproverNotAdmin.
//! 4. Replay attack with old nonce → NonceReplay.
//! 5. Clock skew injection > 60s → ClockSkew.
//! 6. MFA timestamp stale → MfaStale.
//! 7. Audit emit failure fail-CLOSED → Internal (op blocked).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use uuid::Uuid;

use corelink_dual_approval::{
    compute_hmac, AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalError,
    DualApprovalGate, DualApprovalGateImpl, FailingAdminOpAuditSink, InMemoryAdminOpAuditSink,
    InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore,
};

fn make_valid_req(
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
        op_type: AdminOpType::TenantTombstone,
        op_payload: payload,
        nonce,
        ts_ms,
        tenant_id: tenant,
    }
}

fn make_gate(
    key: AdminSigningKey,
    admins: Vec<Uuid>,
    collusion: InMemoryCollusionStore,
    nonces: InMemoryNonceStore,
) -> DualApprovalGateImpl {
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    DualApprovalGateImpl::new(key, role_store, collusion, nonces, sink, "enam")
}

// ── 1. Collusion 3-cycle A→B/B→A/A→B ─────────────────────────────────────

#[test]
fn adversarial_collusion_3_cycle_third_op_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller_a = Uuid::now_v7();
    let caller_b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;

    let collusion = InMemoryCollusionStore::new();
    let nonces = InMemoryNonceStore::new();
    let gate = make_gate(
        key.clone(),
        vec![caller_a, caller_b],
        collusion.clone(),
        nonces.clone(),
    );

    // Op 1: caller=B, approver=A → succeeds
    let req1 = make_valid_req(caller_b, caller_a, tenant, &key, [1u8; 16], now);
    gate.verify(&req1, now - 5 * 60_000, now)
        .expect("op1 must succeed");

    // Op 2: caller=A, approver=B → succeeds
    let req2 = make_valid_req(caller_a, caller_b, tenant, &key, [2u8; 16], now + 1);
    gate.verify(&req2, now - 5 * 60_000, now + 1)
        .expect("op2 must succeed");

    // Op 3: caller=B, approver=A → MUST fail (A ∈ {A, B})
    let req3 = make_valid_req(caller_b, caller_a, tenant, &key, [3u8; 16], now + 2);
    let err = gate
        .verify(&req3, now - 5 * 60_000, now + 2)
        .expect_err("op3 must be rejected via collusion-rotation");
    assert!(
        matches!(err, DualApprovalError::CollusionRotation { .. }),
        "expected CollusionRotation, got: {err:?}"
    );
}

// ── 2. HMAC signature forge (1 byte mutation) ─────────────────────────────

#[test]
fn adversarial_hmac_forge_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;

    let mut req = make_valid_req(caller, approver, tenant, &key, [10u8; 16], now);
    req.approver_signature[0] ^= 0xFF; // corrupt 1 byte

    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
    );
    let err = gate
        .verify(&req, now - 5 * 60_000, now)
        .expect_err("forged sig must be rejected");
    assert!(
        matches!(err, DualApprovalError::SignatureInvalid),
        "expected SignatureInvalid, got {err:?}"
    );
}

// ── 3. Approver privilege revoked before verify ───────────────────────────

#[test]
fn adversarial_approver_role_revoked_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;

    let req = make_valid_req(caller, approver, tenant, &key, [20u8; 16], now);

    // Approver NOT in admin role (simulates revocation before verify).
    let gate = make_gate(
        key.clone(),
        vec![caller], // only caller is admin; approver is NOT
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
    );
    let err = gate
        .verify(&req, now - 5 * 60_000, now)
        .expect_err("revoked approver must be rejected");
    assert!(
        matches!(err, DualApprovalError::ApproverNotAdmin),
        "expected ApproverNotAdmin, got {err:?}"
    );
}

// ── 4. Replay attack with old nonce ───────────────────────────────────────
//
// Note: uses non-destructive op type (FeatureFlagToggleSafe) to isolate the
// nonce replay check without interference from collusion-rotation tracking.

#[test]
fn adversarial_nonce_replay_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;
    let nonce = [30u8; 16];

    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
    );

    // Helper to build non-destructive req (avoids collusion tracking interference).
    let make_nondest_req = |n: [u8; 16], ts: u64| -> AdminOpRequest {
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
    let req1 = make_nondest_req(nonce, now);
    gate.verify(&req1, now - 5 * 60_000, now)
        .expect("first request ok");

    // Replay same nonce.
    let req2 = make_nondest_req(nonce, now + 1);
    let err = gate
        .verify(&req2, now - 5 * 60_000, now + 1)
        .expect_err("replay must be rejected");
    assert!(
        matches!(err, DualApprovalError::NonceReplay { .. }),
        "expected NonceReplay, got {err:?}"
    );
}

// ── 5. Clock skew injection > 60s ─────────────────────────────────────────

#[test]
fn adversarial_clock_skew_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;
    let future_ts = now + 120_000; // 2 min ahead

    let payload = b"{}".to_vec();
    let nonce = [40u8; 16];
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

    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
    );
    let err = gate
        .verify(&req, now - 5 * 60_000, now)
        .expect_err("clock skew must be rejected");
    assert!(
        matches!(err, DualApprovalError::ClockSkew { .. }),
        "expected ClockSkew, got {err:?}"
    );
}

// ── 6. MFA timestamp stale (> 30 min) ────────────────────────────────────

#[test]
fn adversarial_mfa_stale_rejected() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;
    let stale_mfa = now - (31 * 60 * 1_000); // 31 min ago

    let req = make_valid_req(caller, approver, tenant, &key, [50u8; 16], now);
    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
    );
    let err = gate
        .verify(&req, stale_mfa, now)
        .expect_err("stale MFA must be rejected");
    assert!(
        matches!(err, DualApprovalError::MfaStale { .. }),
        "expected MfaStale, got {err:?}"
    );
}

// ── 7. Audit emit failure → op blocked (fail-CLOSED) ─────────────────────

#[test]
fn adversarial_audit_emit_failure_blocks_op() {
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = 10_000_000u64;

    // Use failing audit sink.
    let failing_sink = Arc::new(FailingAdminOpAuditSink);
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
    let gate = DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        failing_sink,
        "enam",
    );

    let req = make_valid_req(caller, approver, tenant, &key, [60u8; 16], now);
    let err = gate
        .verify(&req, now - 5 * 60_000, now)
        .expect_err("audit failure must block op");
    assert!(
        matches!(err, DualApprovalError::Internal(_)),
        "expected Internal (audit fail-closed), got {err:?}"
    );
}
