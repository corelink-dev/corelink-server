//! `corelink-admin-api` — internal admin-operation policy pipeline
//! (WI-S13-002), with no published HTTP binding.
//!
//! # What this crate ships
//!
//! Per the corelink autonomous execution charter
//! (`trait-abstraction-defer`), this crate ships the **pure-logic
//! pipeline** for admin op request processing. A production HTTP binding is
//! deliberately disabled until durable persistence and a safe CF Worker
//! binding are available.
//!
//! Specifically:
//!
//! 1. [`error`] — [`AdminApiError`] `#[non_exhaustive]` wrapping
//!    `DualApprovalError` + dispatch errors; `http_status()` helper.
//!
//! 2. [`handlers`] — [`dispatch_op`] dispatcher mapping `AdminOpType`
//!    to foundational handler stubs (each composes with its respective WI
//!    at production wiring time): ConfigRollback → WI-S13-001,
//!    SecretRotationStart → WI-S13-003, TenantTombstone → S-11, etc.
//!
//! 3. [`middleware`] — [`AdminApiPipeline`] logical middleware composition:
//!    schema-validate → dual-approval gate → op-dispatch. Tower
//!    `ServiceBuilder` wiring deferred to WI-S13-006.
//!
//! # Invariants enforced
//!
//! - All invariants from `corelink-dual-approval` are transitively
//!   enforced (INV-ADMIN-DUAL-APPROVAL CRITICAL; INV-ADMIN-MFA-FRESHNESS;
//!   INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER; INV-AUTH-CLOCK-SKEW-BOUND;
//!   INV-AUDIT-NO-RAW-PII).
//!
//! # Quick start
//!
//! ```rust
//! use std::sync::Arc;
//! use uuid::Uuid;
//! use corelink_dual_approval::{
//!     AdminOpRequest, AdminOpType, AdminSigningKey, DualApprovalGateImpl,
//!     InMemoryAdminOpAuditSink, InMemoryAdminRoleStore,
//!     InMemoryCollusionStore, InMemoryNonceStore, compute_hmac,
//! };
//! use corelink_ops::admin::api::middleware::AdminApiPipeline;
//!
//! let caller = Uuid::now_v7();
//! let approver = Uuid::now_v7();
//! let tenant = Uuid::now_v7();
//! // Explicit deterministic test fixture; never use as production key material.
//! let key = AdminSigningKey::new([0xA5; 32]);
//! let nonce = [0u8; 16];
//! let now_ms = 10_000_000u64;
//! let payload = b"{}".to_vec();
//! let sig = compute_hmac(&key, &payload, &nonce, now_ms);
//!
//! let req = AdminOpRequest {
//!     caller_user_id: caller,
//!     approver_user_id: approver,
//!     approver_signature: sig,
//!     op_type: AdminOpType::ConfigRollback,
//!     op_payload: payload,
//!     nonce,
//!     ts_ms: now_ms,
//!     tenant_id: tenant,
//! };
//!
//! let sink = Arc::new(InMemoryAdminOpAuditSink::new());
//! let role_store = Arc::new(InMemoryAdminRoleStore::new(vec![caller, approver]));
//! let gate = Arc::new(DualApprovalGateImpl::new(
//!     key,
//!     role_store,
//!     InMemoryCollusionStore::new(),
//!     InMemoryNonceStore::new(),
//!     sink.clone(),
//!     "enam",
//! ));
//!
//! let pipeline = AdminApiPipeline::new(gate);
//! let mfa_ts = now_ms - 5 * 60_000;
//! let result = pipeline.process(&req, mfa_ts, now_ms);
//! assert!(result.is_ok());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod error;
pub mod handlers;
pub mod middleware;

pub use error::AdminApiError;
pub use handlers::{dispatch_op, OpResult};
pub use middleware::{AdminApiPipeline, PipelineResult};
