//! Example: basic 2-admin successful dual-approval op (WI-S13-002).
//!
//! Demonstrates: caller A + approver B (distinct); valid HMAC signature;
//! fresh MFA; no prior collusion; gate returns VerifiedApproval.

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
    let nonce = [0x42u8; 16];
    let now_ms = 100_000_000u64;
    let mfa_ts_ms = now_ms - 5 * 60_000; // 5 min ago (fresh)

    let payload = b"{\"target\":\"tenant-x\"}".to_vec();
    let sig = compute_hmac(&key, &payload, &nonce, now_ms);

    let req = AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type: AdminOpType::TenantTombstone,
        op_payload: payload,
        nonce,
        ts_ms: now_ms,
        tenant_id: tenant,
    };

    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
    let gate = DualApprovalGateImpl::new(
        key,
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    );

    match gate.verify(&req, mfa_ts_ms, now_ms) {
        Ok(approved) => {
            println!("Op approved!");
            println!("  caller:   {}", approved.caller_user_id);
            println!("  approver: {}", approved.approver_user_id);
            println!("  op_type:  {:?}", approved.op_type);
            println!("  audit events emitted: {}", sink.captured().len());
        }
        Err(e) => {
            println!("Op denied: {e}");
            std::process::exit(1);
        }
    }
}
