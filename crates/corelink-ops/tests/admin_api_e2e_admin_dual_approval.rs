//! E2E integration tests for admin API dual-approval pipeline (WI-S13-002 §6.1.9).
//!
//! Tests:
//! 1. Two distinct admins succeed → audit emitted → chain unbroken.
//! 2. Missing approver (caller==approver) → 403.
//! 3. Collusion A↔B 3-cycle → 3rd op rejected.
//! 4. Schema validation: empty payload → 400.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use uuid::Uuid;

use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalError, DualApprovalGateImpl, InMemoryAdminOpAuditSink, InMemoryAdminRoleStore,
    InMemoryCollusionStore, InMemoryNonceStore,
};
use corelink_ops::admin::api::{AdminApiError, AdminApiPipeline};

fn make_gate(
    key: AdminSigningKey,
    admins: Vec<Uuid>,
    collusion: InMemoryCollusionStore,
    nonces: InMemoryNonceStore,
    sink: Arc<InMemoryAdminOpAuditSink>,
) -> Arc<DualApprovalGateImpl> {
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    Arc::new(DualApprovalGateImpl::new(
        key, role_store, collusion, nonces, sink, "enam",
    ))
}

fn make_req(
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

// ── Test 1: 2 distinct admins succeed ─────────────────────────────────────

#[test]
fn e2e_two_admins_success_audit_emitted() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;
    let mfa_fresh = now - 5 * 60_000;

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
    );
    let pipeline = AdminApiPipeline::new(gate);

    let req = make_req(
        caller,
        approver,
        tenant,
        &key,
        [1u8; 16],
        now,
        AdminOpType::ConfigRollback,
    );
    let result = pipeline
        .process(&req, mfa_fresh, now)
        .expect("should succeed");

    assert_eq!(result.approval.caller_user_id, caller);
    assert_eq!(result.approval.approver_user_id, approver);
    // Audit emitted (1 event: approved).
    assert_eq!(sink.captured().len(), 1);
    assert_eq!(sink.captured()[0].data.outcome, "approved");
}

// ── Test 2: caller == approver rejected ───────────────────────────────────

#[test]
fn e2e_caller_eq_approver_rejected_403() {
    let user = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;
    let mfa_fresh = now - 5 * 60_000;

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let gate = make_gate(
        key.clone(),
        vec![user],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink,
    );
    let pipeline = AdminApiPipeline::new(gate);

    let req = make_req(
        user,
        user,
        tenant,
        &key,
        [2u8; 16],
        now,
        AdminOpType::TenantTombstone,
    );
    let err = pipeline
        .process(&req, mfa_fresh, now)
        .expect_err("must fail");

    assert_eq!(err.http_status(), 403);
    assert!(matches!(
        err,
        AdminApiError::DualApprovalRejected(DualApprovalError::CallerEqualsApprover)
    ));
}

// ── Test 3: collusion A↔B 3-cycle → 3rd rejected ─────────────────────────

#[test]
fn e2e_collusion_3_cycle_third_rejected() {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;
    let mfa_fresh = now - 5 * 60_000;

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let gate = make_gate(
        key.clone(),
        vec![a, b],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink,
    );
    let pipeline = AdminApiPipeline::new(gate);

    // Op 1: caller=B, approver=A
    let req1 = make_req(
        b,
        a,
        tenant,
        &key,
        [1u8; 16],
        now,
        AdminOpType::ConfigRollback,
    );
    pipeline.process(&req1, mfa_fresh, now).expect("op1 ok");

    // Op 2: caller=A, approver=B
    let req2 = make_req(
        a,
        b,
        tenant,
        &key,
        [2u8; 16],
        now + 1,
        AdminOpType::ConfigRollback,
    );
    pipeline.process(&req2, mfa_fresh, now + 1).expect("op2 ok");

    // Op 3: caller=B, approver=A → MUST reject
    let req3 = make_req(
        b,
        a,
        tenant,
        &key,
        [3u8; 16],
        now + 2,
        AdminOpType::ConfigRollback,
    );
    let err = pipeline
        .process(&req3, mfa_fresh, now + 2)
        .expect_err("op3 must fail");
    assert_eq!(err.http_status(), 403);
    assert!(
        matches!(
            err,
            AdminApiError::DualApprovalRejected(DualApprovalError::CollusionRotation { .. })
        ),
        "expected CollusionRotation, got {err:?}"
    );
}

// ── Test 4: empty payload schema validation ───────────────────────────────

#[test]
fn e2e_empty_payload_schema_400() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;
    let mfa_fresh = now - 5 * 60_000;

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let gate = make_gate(
        key.clone(),
        vec![caller, approver],
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink,
    );
    let pipeline = AdminApiPipeline::new(gate);

    // Empty payload
    let nonce = [0u8; 16];
    let empty_payload: Vec<u8> = Vec::new();
    let sig = compute_hmac(&key, &empty_payload, &nonce, now);
    let req = AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type: AdminOpType::ConfigRollback,
        op_payload: empty_payload,
        nonce,
        ts_ms: now,
        tenant_id: tenant,
    };

    let err = pipeline
        .process(&req, mfa_fresh, now)
        .expect_err("empty payload must fail");
    assert_eq!(err.http_status(), 400);
    assert!(matches!(err, AdminApiError::SchemaValidation(_)));
}
