//! Example: audit emission inspection via admin-api pipeline.
#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::expect_used)]
use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalGateImpl, InMemoryAdminOpAuditSink, InMemoryAdminRoleStore, InMemoryCollusionStore,
    InMemoryNonceStore,
};
use corelink_ops::admin::api::middleware::AdminApiPipeline;
use std::sync::Arc;
use uuid::Uuid;

fn main() {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let now_ms = 10_000_000u64;
    let payload = b"{}".to_vec();
    let nonce = [0xCCu8; 16];
    let sig = compute_hmac(&key, &payload, &nonce, now_ms);
    let req = AdminOpRequest {
        caller_user_id: caller,
        approver_user_id: approver,
        approver_signature: sig,
        op_type: AdminOpType::FeatureFlagDisable,
        op_payload: payload,
        nonce,
        ts_ms: now_ms,
        tenant_id: tenant,
    };
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
    let gate = Arc::new(DualApprovalGateImpl::new(
        key,
        role_store,
        InMemoryCollusionStore::new(),
        InMemoryNonceStore::new(),
        sink.clone(),
        "enam",
    ));
    let pipeline = AdminApiPipeline::new(gate);
    pipeline.process(&req, now_ms - 5 * 60_000, now_ms).unwrap();
    for ev in sink.captured() {
        println!("audit: type={} outcome={}", ev.event_type, ev.data.outcome);
    }
}
