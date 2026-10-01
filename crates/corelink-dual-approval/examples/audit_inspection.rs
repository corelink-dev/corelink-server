//! Example: audit emission inspection (WI-S13-002, CAP-ADMIN-006).
//!
//! Demonstrates: successful op + denied op both emit CloudEvents; inspect
//! outcome + actor + op_type fields.

#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]

use std::sync::Arc;
use uuid::Uuid;

use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalGate,
    DualApprovalGateImpl, InMemoryAdminOpAuditSink, InMemoryAdminRoleStore, InMemoryCollusionStore,
    InMemoryNonceStore,
};

fn main() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now_ms = 100_000_000u64;
    let mfa_fresh = now_ms - 5 * 60_000;
    let payload = b"{}".to_vec();
    let nonce = [0xAAu8; 16];
    let sig = compute_hmac(&key, &payload, &nonce, now_ms);

    let req = AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type: AdminOpType::FeatureFlagDisable,
        op_payload: payload.clone(),
        nonce,
        ts_ms: now_ms,
        tenant_id: tenant,
    };

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
    let gate = DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    );

    // Successful op.
    gate.verify(&req, mfa_fresh, now_ms).unwrap();

    // Denied op (caller == approver).
    let bad_req = AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: caller,
        approver_signature: [0u8; 32],
        op_type: AdminOpType::FeatureFlagDisable,
        op_payload: payload,
        nonce: [0xBBu8; 16],
        ts_ms: now_ms,
        tenant_id: tenant,
    };
    let _ = gate.verify(&bad_req, mfa_fresh, now_ms);

    let events = sink.captured();
    println!("Audit events captured: {}", events.len());
    for (i, ev) in events.iter().enumerate() {
        println!(
            "  [{i}] type={} outcome={} op_type={}",
            ev.event_type, ev.data.outcome, ev.data.op_type
        );
    }
}
