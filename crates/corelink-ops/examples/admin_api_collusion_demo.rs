//! Example: collusion-rotation 3-cycle via admin-api pipeline.
#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]
use corelink_dual_approval::{
    compute_hmac, AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalGateImpl,
    InMemoryAdminOpAuditSink, InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore,
};
use corelink_ops::admin::api::middleware::AdminApiPipeline;
use std::sync::Arc;
use uuid::Uuid;

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
        op_type: AdminOpType::TenantTombstone,
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
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![a, b]));
    let gate = Arc::new(DualApprovalGateImpl::new(
        key.clone(),
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink,
        "enam",
    ));
    let pipeline = AdminApiPipeline::new(gate);
    let mfa = now - 5 * 60_000;

    let r1 = pipeline.process(&make_req(b, a, tenant, &key, [1u8; 16], now), mfa, now);
    println!("Op1: {}", if r1.is_ok() { "OK" } else { "FAIL" });
    let r2 = pipeline.process(
        &make_req(a, b, tenant, &key, [2u8; 16], now + 1),
        mfa,
        now + 1,
    );
    println!("Op2: {}", if r2.is_ok() { "OK" } else { "FAIL" });
    let r3 = pipeline.process(
        &make_req(b, a, tenant, &key, [3u8; 16], now + 2),
        mfa,
        now + 2,
    );
    println!(
        "Op3 (should fail): {}",
        r3.map(|_| "OK".to_owned())
            .unwrap_or_else(|e| e.to_string())
    );
}
