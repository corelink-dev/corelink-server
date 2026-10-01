//! Example: collusion-rotation 3-cycle detection (WI-S13-002, NIST AC-2(7)).
//!
//! Demonstrates: A approves B's op, B approves A's op, then A tries to
//! approve B's op again — 3rd op is rejected with CollusionRotation.

#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]

use std::sync::Arc;
use uuid::Uuid;

use corelink_dual_approval::{
    compute_hmac, AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalError,
    DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink, InMemoryAdminRoleStore,
    InMemoryCollusionStore, InMemoryNonceStore,
};

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

fn main() {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now = 10_000_000u64;
    let mfa_fresh = now - 5 * 60_000;

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![a, b]));
    let gate = DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    );

    // Op 1: caller=B, approver=A → OK
    let r1 = gate.verify(
        &make_req(b, a, tenant, &key, [1u8; 16], now),
        mfa_fresh,
        now,
    );
    println!(
        "Op 1 (caller=B, approver=A): {}",
        if r1.is_ok() { "OK" } else { "FAIL" }
    );

    // Op 2: caller=A, approver=B → OK
    let r2 = gate.verify(
        &make_req(a, b, tenant, &key, [2u8; 16], now + 1),
        mfa_fresh,
        now + 1,
    );
    println!(
        "Op 2 (caller=A, approver=B): {}",
        if r2.is_ok() { "OK" } else { "FAIL" }
    );

    // Op 3: caller=B, approver=A → REJECTED (collusion-rotation)
    match gate.verify(
        &make_req(b, a, tenant, &key, [3u8; 16], now + 2),
        mfa_fresh,
        now + 2,
    ) {
        Err(DualApprovalError::CollusionRotation {
            recent_approver_uuids,
        }) => {
            println!("Op 3 REJECTED: CollusionRotation (recent: {recent_approver_uuids:?})");
            println!("NIST AC-2(7) collusion-rotation defense activated.");
        }
        other => {
            println!("Unexpected: {other:?}");
            std::process::exit(1);
        }
    }
}
