//! `corelink-dual-approval` — Admin API dual-approval enforcement +
//! collusion-rotation defense (WI-S13-002).
//!
//! # Production key construction
//!
//! Test fixtures in examples and external test targets construct an
//! explicit deterministic key with [`AdminSigningKey::new`]. Never use
//! that fixture as production key material. The all-zero unit-test
//! helper is private and compiled only under `cfg(test)`.
//!
//! ```compile_fail
//! use corelink_dual_approval::AdminSigningKey;
//! let _ = AdminSigningKey::test_zero();
//! ```
//!
//! # What this crate ships
//!
//! Per the corelink autonomous execution charter
//! (`trait-abstraction-defer`), this crate ships the **pure-logic
//! skeleton** of the dual-approval enforcement primitive: trait surfaces
//! every production CF Worker binding (D1 queries for role/collusion/nonce,
//! signing key from rotation worker WI-S13-003) will satisfy, plus an
//! in-memory orchestrator that exercises every load-bearing invariant.
//! Property tests pinned at 10k iter (PR-gate; 100k nightly) cover
//! INV-ADMIN-DUAL-APPROVAL CRITICAL and all 7 failure paths.
//!
//! Specifically, the crate ships:
//!
//! 1. [`types`] — [`AdminOpRequest`], [`VerifiedApproval`],
//!    [`AdminOpType`] `#[non_exhaustive]`, [`ApprovalOutcome`]
//!    `#[non_exhaustive]`, [`AdminAuditEventData`], [`ActorIdentity`],
//!    [`AdminOpLogRow`], [`RecentApprover`].
//!
//! 2. [`error`] — [`DualApprovalError`] `#[non_exhaustive]` (9 variants:
//!    MissingApprover / SignatureInvalid / CallerEqualsApprover /
//!    CollusionRotation / MfaStale / ApproverNotAdmin / NonceReplay /
//!    ClockSkew / UnknownKeyId / Internal).
//!
//! 3. [`hmac_verify`] — [`AdminSigningKey`] + [`compute_hmac`] +
//!    [`verify_hmac`] (constant-time `subtle::ConstantTimeEq`).
//!
//! 4. [`collusion`] — [`InMemoryCollusionStore`]: Lote 10.13 canonical
//!    oracle (proposed approver ∉ last 2 distinct destructive-op
//!    approvers in 24h window; forces 3 distinct approvers in any
//!    rolling 3-op window; stronger than prior LIMIT 3 + count-distinct
//!    oracle that missed A→B/B→A/A→B at op 3).
//!
//! 5. [`nonce`] — [`InMemoryNonceStore`]: 128-bit nonce replay protection
//!    (production: D1 UNIQUE (caller_user_id, nonce)).
//!
//! 6. [`audit`] — [`AdminOpAuditSink`] trait + [`InMemoryAdminOpAuditSink`] + [`FailingAdminOpAuditSink`] + [`AdminOpCloudEvent`] (CloudEvents v1.0.2 rich payload: actor, mfa_ts, dual_approver, op_payload_hash, prev_state_hash, signature).
//!
//! 7. [`gate`] — [`DualApprovalGate`] trait + [`DualApprovalGateImpl`]
//!    orchestrator (8-step pipeline: clock-skew → MFA freshness → caller≠approver
//!    → approver admin role → HMAC verify → collusion-rotation → nonce replay →
//!    audit emit fail-CLOSED → record approval). [`proptest_cases`] helper.
//!
//! # Invariants enforced
//!
//! - **INV-ADMIN-DUAL-APPROVAL** (CRITICAL — §3.12): caller ≠ approver hard-check;
//!   no env-gated bypass; property test 10k 0 false-accepts.
//! - **INV-ADMIN-MFA-FRESHNESS** (HIGH — §3.12): MFA age ≤ 30 min; stale = 401.
//! - **INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER** (CRITICAL): audit emit BEFORE op;
//!   emit failure → 503 (fail-CLOSED).
//! - **INV-AUTH-CLOCK-SKEW-BOUND** (HIGH): ts_ms skew ≤ 60s.
//! - **INV-AUDIT-NO-RAW-PII** (CRITICAL): email_hash in audit; raw email never
//!   persisted.
//!
//! # Quick start — basic 2-admin successful op
//!
//! ```rust
//! use std::sync::Arc;
//! use uuid::Uuid;
//! use corelink_dual_approval::{
//!     AdminOpAuditSink, AdminOpRequest, AdminOpType,
//!     DualApprovalGate, DualApprovalGateImpl,
//!     AdminSigningKey, compute_hmac,
//!     InMemoryCollusionStore, InMemoryNonceStore,
//!     InMemoryAdminOpAuditSink, InMemoryAdminRoleStore,
//! };
//!
//! let caller = Uuid::now_v7();
//! let approver = Uuid::now_v7();
//! let tenant = Uuid::now_v7();
//! // Explicit deterministic test fixture; never use as production key material.
//! let key = AdminSigningKey::new([0xA5; 32]);
//! let nonce = [42u8; 16];
//! let ts_ms = 1_000_000u64;
//! let payload = b"{}".to_vec();
//!
//! let sig = compute_hmac(&key, &payload, &nonce, ts_ms);
//!
//! let req = AdminOpRequest {
//!     caller_user_id: caller,
//!     approver_user_id: approver,
//!     approver_signature: sig,
//!     op_type: AdminOpType::ConfigRollback,
//!     op_payload: payload,
//!     nonce,
//!     ts_ms,
//!     tenant_id: tenant,
//! };
//!
//! let sink = Arc::new(InMemoryAdminOpAuditSink::new());
//! let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
//! let gate = DualApprovalGateImpl::new(
//! // Explicit deterministic test fixture; never use as production key material.
//!     AdminSigningKey::new([0xA5; 32]),
//!     role_store,
//!     InMemoryCollusionStore::new(),
//!     InMemoryNonceStore::new(),
//!     sink.clone(),
//!     "enam",
//! );
//!
//! let mfa_ts_ms = ts_ms - 5 * 60 * 1_000; // 5 min ago
//! let result = gate.verify(&req, mfa_ts_ms, ts_ms);
//! assert!(result.is_ok());
//! assert_eq!(sink.captured().len(), 1);
//! ```
//!
//! # Example — collusion-rotation detection
//!
//! See [`examples/collusion_demo.rs`](../../../examples/collusion_demo.rs).
//!
//! # Example — audit emission inspection
//!
//! See [`examples/audit_inspection.rs`](../../../examples/audit_inspection.rs).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod audit;
pub mod collusion;
pub mod error;
pub mod gate;
pub mod hmac_verify;
pub mod nonce;
pub mod types;

// Re-exports for ergonomic access.
pub use audit::{
    AdminAuditSinkError, AdminOpAuditSink, AdminOpCloudEvent, FailingAdminOpAuditSink,
    InMemoryAdminOpAuditSink, AUDIT_TYPE_DENIED, AUDIT_TYPE_EXECUTED,
};
pub use collusion::InMemoryCollusionStore;
pub use error::DualApprovalError;
pub use gate::{
    proptest_cases, AdminRoleStore, DualApprovalGate, DualApprovalGateImpl, InMemoryAdminRoleStore,
};
pub use hmac_verify::{compute_hmac, verify_hmac, AdminSigningKey};
pub use nonce::InMemoryNonceStore;
pub use types::{
    ActorIdentity, AdminAuditEventData, AdminOpLogRow, AdminOpRequest, AdminOpType,
    ApprovalOutcome, RecentApprover, VerifiedApproval,
};
