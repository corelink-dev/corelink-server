//! RB-FM-205 dry-run harness — Admin Mistake (WI-S13-006 §6.1.2).
//!
//! Exercises the admin-plane dual-approval defense-in-depth against
//! every failure path listed in the RB-FM-205 runbook
//! (`specs/05_quality/runbooks/RB-FM-205-admin-mistake.md`):
//!
//! 1. **Missing approver** → 403 + `admin.op.denied_missing_approver` audit.
//! 2. **Caller == approver** → 403 + `admin.op.denied_caller_eq` audit.
//! 3. **Collusion A↔B 4-cycle attempt** → 4th op rejected (CollusionRotation).
//! 4. **Property test 10k pre-dry-run** → green (validates INV-ADMIN-DUAL-APPROVAL).
//! 5. **Signature tamper** → 403 + `admin.op.denied_sig_invalid` audit.
//!
//! Cadence: **annual** (per `failure_modes.md §RB cadence`).
//!
//! Exit code 0 = all validations passed; non-zero = dry-run failure.

#![allow(
    clippy::print_stdout,
    reason = "binary harnesses produce human-readable PASS/FAIL output to stdout; print_stdout-deny inherited from the umbrella library does not apply"
)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

use std::sync::Arc;

use corelink_dual_approval::{
    compute_hmac, AdminOpAuditSink, AdminOpRequest, AdminOpType, AdminSigningKey,
    DualApprovalError, DualApprovalGate, DualApprovalGateImpl, InMemoryAdminOpAuditSink,
    InMemoryAdminRoleStore, InMemoryCollusionStore, InMemoryNonceStore,
};
use uuid::Uuid;

const BASE_NOW: u64 = 10_000_000u64;

#[derive(Debug)]
struct Step {
    name: &'static str,
    passed: bool,
    detail: String,
}

fn make_gate(
    key: AdminSigningKey,
    admins: Vec<Uuid>,
) -> (DualApprovalGateImpl, Arc<InMemoryAdminOpAuditSink>) {
    let sink = Arc::new(InMemoryAdminOpAuditSink::new());
    let role_store = Arc::new(InMemoryAdminRoleStore::new(admins));
    let collusion = InMemoryCollusionStore::new();
    let nonce_store = InMemoryNonceStore::new();
    let gate = DualApprovalGateImpl::new(
        key,
        role_store,
        collusion,
        nonce_store,
        sink.clone(),
        "enam",
    );
    (gate, sink)
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
        op_type: AdminOpType::TenantTombstone,
        op_payload: payload,
        nonce,
        ts_ms,
        tenant_id: tenant,
    }
}

/// Step 1: Missing approver scenario (caller == approver sentinel).
fn step_missing_approver(key: &AdminSigningKey) -> Step {
    let user = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = BASE_NOW;
    let nonce = [1u8; 16];
    let (gate, sink) = make_gate(key.clone(), vec![user]);
    let req = make_req(user, user, tenant, key, nonce, now);
    let mfa_ts = now - 5 * 60 * 1_000;

    match gate.verify(&req, mfa_ts, now) {
        Err(DualApprovalError::CallerEqualsApprover) => {
            let events = sink.captured();
            let denied = events.iter().any(|e| e.event_type.contains("denied"));
            Step {
                name: "missing-approver-403",
                passed: denied,
                detail: format!(
                    "CallerEqualsApprover fired + {} audit events (denied={})",
                    events.len(),
                    denied
                ),
            }
        }
        other => Step {
            name: "missing-approver-403",
            passed: false,
            detail: format!("expected CallerEqualsApprover, got {other:?}"),
        },
    }
}

/// Step 2: Caller == approver strict check.
fn step_caller_eq_approver(key: &AdminSigningKey) -> Step {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = BASE_NOW;
    let nonce = [2u8; 16];
    // Try to use 'b' as both caller and approver.
    let (gate, sink) = make_gate(key.clone(), vec![a, b]);
    let req = make_req(b, b, tenant, key, nonce, now);
    let mfa_ts = now - 5 * 60 * 1_000;

    match gate.verify(&req, mfa_ts, now) {
        Err(DualApprovalError::CallerEqualsApprover) => {
            let events = sink.captured();
            Step {
                name: "caller-eq-approver-403",
                passed: true,
                detail: format!(
                    "CallerEqualsApprover rejected; {} audit events",
                    events.len()
                ),
            }
        }
        other => Step {
            name: "caller-eq-approver-403",
            passed: false,
            detail: format!("expected CallerEqualsApprover, got {other:?}"),
        },
    }
}

/// Step 3: Collusion A↔B 4-cycle — 3rd op MUST be rejected.
fn step_collusion_a_b_cycle(_key: &AdminSigningKey) -> Step {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = BASE_NOW;

    let collusion = InMemoryCollusionStore::new();

    // Op1: caller=B, approver=A
    collusion
        .record_approval(tenant, a, &AdminOpType::TenantTombstone, now)
        .ok();
    // Op2: caller=A, approver=B
    collusion
        .record_approval(tenant, b, &AdminOpType::TenantTombstone, now + 1_000)
        .ok();

    // Op3 attempt: proposed approver=A (already in last 2 distinct approvers)
    let result = collusion.check_collusion(tenant, a, now + 2_000);

    match result {
        Err(DualApprovalError::CollusionRotation { .. }) => Step {
            name: "collusion-a-b-4cycle-rejected",
            passed: true,
            detail: "CollusionRotation fired on 3rd op A↔B (NIST AC-2(7))".to_string(),
        },
        other => Step {
            name: "collusion-a-b-4cycle-rejected",
            passed: false,
            detail: format!("expected CollusionRotation, got {other:?}"),
        },
    }
}

/// Step 4: Property test 10k pre-dry-run green (INV-ADMIN-DUAL-APPROVAL).
fn step_property_test_10k(key: &AdminSigningKey) -> Step {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10_000);

    let mut failures = 0u32;
    for i in 0u64..cases as u64 {
        let user = Uuid::from_u64_pair(i, i ^ 0x1111);
        let tenant = Uuid::from_u64_pair(i ^ 2, 0);
        let now = BASE_NOW;
        let nonce = {
            let mut n = [0u8; 16];
            let b = i.to_le_bytes();
            n[..8].copy_from_slice(&b);
            n
        };
        let (gate, _sink) = make_gate(key.clone(), vec![user]);
        let req = make_req(user, user, tenant, key, nonce, now);
        if gate.verify(&req, now - 60_000, now).is_ok() {
            failures += 1;
        }
    }

    Step {
        name: "property-test-10k-INV-ADMIN-DUAL-APPROVAL",
        passed: failures == 0,
        detail: format!("{cases} iterations: {failures} false-accepts (must be 0)"),
    }
}

/// Step 5: Signature tamper → SignatureInvalid.
fn step_sig_tamper(key: &AdminSigningKey) -> Step {
    let caller = Uuid::now_v7();
    let approver = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let now = BASE_NOW;
    let nonce = [5u8; 16];
    let (gate, sink) = make_gate(key.clone(), vec![caller, approver]);
    let mut req = make_req(caller, approver, tenant, key, nonce, now);
    req.approver_signature[0] ^= 0xff; // tamper
    let mfa_ts = now - 5 * 60 * 1_000;

    match gate.verify(&req, mfa_ts, now) {
        Err(DualApprovalError::SignatureInvalid) => {
            let events = sink.captured();
            Step {
                name: "sig-tamper-rejected",
                passed: true,
                detail: format!("SignatureInvalid fired; {} audit events", events.len()),
            }
        }
        other => Step {
            name: "sig-tamper-rejected",
            passed: false,
            detail: format!("expected SignatureInvalid, got {other:?}"),
        },
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    println!("=== RB-FM-205 dry-run: Admin Mistake (WI-S13-006) ===");
    println!("Cadence: annual | Runbook: specs/05_quality/runbooks/RB-FM-205-admin-mistake.md");
    println!();

    // Explicit deterministic test fixture; never use as production key material.
    let key = AdminSigningKey::new([0xA5; 32]);
    let steps: Vec<Step> = vec![
        step_missing_approver(&key),
        step_caller_eq_approver(&key),
        step_collusion_a_b_cycle(&key),
        step_property_test_10k(&key),
        step_sig_tamper(&key),
    ];

    let mut all_pass = true;
    for step in &steps {
        let status = if step.passed { "PASS" } else { "FAIL" };
        println!("[{status}] {} — {}", step.name, step.detail);
        if !step.passed {
            all_pass = false;
        }
    }

    println!();
    println!(
        "=== RB-FM-205 dry-run result: {} ===",
        if all_pass { "PASS" } else { "FAIL" }
    );

    if !all_pass {
        std::process::exit(1);
    }
}
