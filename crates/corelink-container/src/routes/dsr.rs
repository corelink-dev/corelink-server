//! Internal DSR erasure endpoint (WI-S11-008 Wave 0).
//!
//! `POST /_internal/dsr/erase` — the queue consumer (signup-worker
//! `dsr_consumer.ts`) forwards `dsr.queued.v1` messages here. The handler
//! verifies the internal-auth shared secret (constant-time, mirroring
//! [`crate::routes::internal_pat`]), deserializes the request, maps it to a
//! canonical [`ErasureRequest`], and drives the 12-backend erasure orchestrator.
//!
//! ## WAVE 1 — LIVE (real data IS deleted)
//!
//! `build_d1_worker` wires the canonical 12-backend orchestrator with its REAL
//! transports (the all-placeholder `build_placeholder_worker` survives only as
//! the unconfigured-env fallback, e.g. tests). On a configured prod env the
//! pipeline (Clerk `user.deleted` → queue → consumer → this endpoint →
//! orchestrator → audit + idempotency ledger → 24h verify cron) actually erases:
//!
//! - **D1** (`adapter_d1`): real erase-set — every subject-indexed row across the
//!   canonical D1 erase-set is deleted per ADR-S11-013.
//! - **R2 CAS** (`adapter_r2_cas`) + **R2 AC** (`adapter_r2_ac`): the tenant's
//!   content-addressed + action-cache objects are deleted (keyed by the same
//!   `derive_prefix(tdk, tenant)` the write path used — matches by construction).
//! - **Stripe** (`adapter_stripe`): customer PII is pseudonymized (crypto-erase /
//!   detach, not a hard customer delete — billing records must survive for tax).
//! - The remaining **8** backends are reconciled to `NotApplicable` with a
//!   documented reason each (Neon / KV / Loki / R2 audit·legal-hold·evidence are
//!   NOT shipped in prod, so there is no durable subject PII to erase) — a
//!   truthful GDPR audit record, NOT a silent skip.
//!
//! Every state mutation is preceded (fail-CLOSED, ADR-S11-002) by a durable
//! CloudEvents audit envelope in `audit_outbox`, recorded in the D1 idempotency
//! ledger (so a retry never double-erases), and re-confirmed by the 24h
//! verification sweep. On `VerifiedComplete` the verify path additionally signs
//! and persists an Ed25519 erasure attestation (see [`attestation`]).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use corelink_privacy_erasure_worker::audit_emit::{
    ErasureAuditSink, ErasureRequestContext, InMemoryErasureAuditSink,
};
use corelink_privacy_erasure_worker::backends::{
    BackendErasureAdapter, InMemoryBackendErasureAdapter,
};
use corelink_privacy_erasure_worker::event::{
    canonical_backend_kinds, BackendKind, ErasureDecision, ErasureRequest, ErasureSalt,
};
use corelink_privacy_erasure_worker::idempotency::{
    ErasureIdempotencyLedger, InMemoryErasureIdempotencyLedger,
};
use corelink_privacy_erasure_worker::legitimacy::{DsrLegitimacyStore, InMemoryDsrLegitimacyStore};
use corelink_privacy_erasure_worker::orchestrator::{ErasureWorker, InMemoryErasureWorker};

// WI-S11-008 Wave 1 real transports. The 4 effective/pseudonymize backends
// (D1, R2Ac, R2Cas, Stripe) are real; the other 8 are reconciled to
// NotApplicable (not shipped in prod — ADR-S11-013).
pub(crate) mod access;
mod adapter_d1;
mod adapter_not_applicable;
mod adapter_r2_ac;
mod adapter_r2_cas;
mod adapter_r2_cas_legalhold;
mod adapter_stripe;
mod attestation;
mod audit;
mod d1util;
mod ledger;
pub(crate) mod legitimacy;
/// Customer-facing DSR self-service portal (`/v1/privacy/dsr/*`) — the intake
/// surface that drives THIS live pipeline.
pub mod portal;

const INTERNAL_AUTH_HEADER: &str = "x-corelink-internal-auth";

/// Wire shape of the `dsr.queued.v1` message produced by the Clerk
/// `user.deleted` webhook (`apps/signup-worker/src/webhooks/clerk.ts`). Unknown
/// fields (`schema`, `source`, `clerk_user_id`) are accepted and ignored.
#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct DsrQueuedV1 {
    /// Canonical UUID DSR id (idempotency key; deterministic per Clerk user).
    pub dsr_id: String,
    /// Tenant id whose data is erased.
    pub tenant_id: String,
    /// Data subject id (`== tenant_id` for a one-user-per-tenant account).
    pub subject_id: String,
    /// 64 hex chars (32-byte) per-DSR erasure salt.
    pub erasure_salt_hex: String,
    /// Enqueue instant (Unix epoch ms) — the SLA clock anchor.
    pub queued_at_ms: u64,
    /// Whether the upstream DSR ticket is under legal hold.
    pub legal_hold: bool,
}

/// Shared state for the DSR erasure route.
#[non_exhaustive]
#[derive(Clone)]
pub struct DsrRouteState {
    /// Accepted internal-auth keys: `[current]`, or `[current, previous]` during
    /// a rotation window (dual-key — see [`internal_auth_ok_any`]).
    internal_auth_keys: Vec<String>,
    worker: Arc<InMemoryErasureWorker>,
    /// D1 client for the verify-path attestation signer (G3). `None` in the
    /// unconfigured/test fallback (all-placeholder worker) — attestation is then
    /// skipped (fail-CLOSED), exactly as when the seed secret is unset.
    d1: Option<Arc<crate::storage::d1_http::D1HttpClient>>,
    /// R2 client bound to the region's audit bucket (`corelink-audit-{region}`),
    /// the AUTHORITATIVE store the verify-path attestation signer (Artifact 1)
    /// PUTs the signed bundle to BEFORE the D1 index row. `None` when storage is
    /// unconfigured OR no single-region attestation region is asserted — the
    /// signer then withholds the attestation (fail-CLOSED; never a dangling
    /// `r2_key`).
    r2_audit: Option<Arc<crate::storage::r2_s3::R2S3Client>>,
    /// Optional staging-only gate. Ordinary requests do not carry this header
    /// and continue through the legacy `None` path.
    staging_admission:
        Option<Arc<crate::storage::staging_load_test_admission::StagingLoadTestAdmissionGate>>,
}

/// Opaque carrier from the route admission gate into the shared DSR seams.
#[derive(Debug)]
struct StagingDsrRequestContext(
    Arc<crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext>,
);

impl ErasureRequestContext for StagingDsrRequestContext {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Recover only this route's typed, verified request context from the shared
/// erasure seam. An unrelated or forged carrier fails closed instead of being
/// treated as ordinary traffic.
pub(super) fn staging_admission_context(
    context: Option<&dyn ErasureRequestContext>,
) -> Result<
    Option<&crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext>,
    &'static str,
> {
    let Some(context) = context else {
        return Ok(None);
    };
    let context = context
        .as_any()
        .downcast_ref::<StagingDsrRequestContext>()
        .ok_or("DSR staging ownership context is invalid")?;
    context
        .0
        .require_ownership_scenario(
            crate::storage::staging_load_test_ownership::StagingLoadTestScenario::Dsr,
        )
        .map_err(|_| "DSR staging ownership context is invalid")?;
    Ok(Some(&context.0))
}

impl std::fmt::Debug for DsrRouteState {
    // Redact the internal-auth secret; never let it reach a log/Debug sink.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsrRouteState")
            .field("internal_auth_keys", &"<redacted>")
            .field("worker", &self.worker)
            .field("d1", &self.d1.as_ref().map(|_| "[D1HttpClient]"))
            .field("r2_audit", &self.r2_audit.as_ref().map(|_| "[R2S3Client]"))
            .field("staging_admission", &self.staging_admission.is_some())
            .finish()
    }
}

async fn admit_request(
    state: &DsrRouteState,
    headers: &HeaderMap,
) -> Result<
    Option<Arc<crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext>>,
    Response,
> {
    crate::storage::staging_load_test_admission::admit_staging_load_test_request(
        state.staging_admission.as_deref(),
        headers,
        crate::storage::staging_load_test_ownership::StagingLoadTestScenario::Dsr,
    )
    .await
    .map_err(|_| (StatusCode::FORBIDDEN, "invalid staging admission").into_response())
}

/// Constant-time internal-auth check. Mirrors
/// `internal_pat::internal_auth_ok` byte-for-byte so the internal-auth gates
/// stay consistent (pad provided to the secret length, run `ct_eq`, fold in the
/// real length-equality so a longer/shorter value can never match).
#[must_use]
fn internal_auth_ok(expected: &[u8], headers: &HeaderMap) -> bool {
    let provided = headers
        .get(INTERNAL_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided_bytes = provided.as_bytes();
    let provided_padded: Vec<u8> = if provided_bytes.len() >= expected.len() {
        provided_bytes.get(..expected.len()).unwrap_or(&[]).to_vec()
    } else {
        let mut v = provided_bytes.to_vec();
        v.resize(expected.len(), 0);
        v
    };
    let content_ok = expected.ct_eq(&provided_padded).unwrap_u8();
    let len_ok = u8::from(expected.len() == provided_bytes.len());
    (content_ok & len_ok) == 1
}

/// Constant-time internal-auth check against ANY of the accepted keys — the
/// dual-key rotation window. `keys` is `[current]` or `[current, previous]`
/// (see [`crate::routes::admin::erase_auth_keys_from_env`]): during a key
/// rotation the operator sets the new value AND keeps the old as
/// `CORELINK_ERASE_AUTH_KEY_PREVIOUS`, so an in-flight erase leg gated on either
/// value never 401s while the fleet's DO containers cycle onto the new key (the
/// env-read-at-start footgun). Every key is compared (no early return) so the
/// check does not leak, via timing, WHICH key matched or how many were tried.
#[must_use]
fn internal_auth_ok_any(keys: &[String], headers: &HeaderMap) -> bool {
    let mut matched = false;
    for key in keys {
        matched |= internal_auth_ok(key.as_bytes(), headers);
    }
    matched
}

/// Build the canonical 12-backend orchestrator. WAVE 0: every adapter is the
/// in-memory no-op placeholder; Wave 1 replaces each with its real transport.
///
/// # Errors
/// Returns an error string if the canonical 12-adapter invariant is violated
/// (should be impossible — `canonical_backend_kinds` is the source of truth).
pub fn build_placeholder_worker() -> Result<InMemoryErasureWorker, String> {
    let audit = Arc::new(InMemoryErasureAuditSink::new());
    let ledger = Arc::new(InMemoryErasureIdempotencyLedger::new());
    let adapters: Vec<Arc<dyn BackendErasureAdapter>> = canonical_backend_kinds()
        .iter()
        .map(|k| Arc::new(InMemoryBackendErasureAdapter::new(*k)) as Arc<dyn BackendErasureAdapter>)
        .collect();
    // rt-nuclear #18/#19: with no D1 there is no `dsr_requested` table to
    // authenticate a request against, so the placeholder worker MUST
    // fail-CLOSED — an EMPTY in-memory legitimacy store reports every
    // (dsr_id, tenant_id) as NOT requested → every erase is Rejected.
    // (NEVER the allow-all store on a route-mountable path.)
    let legitimacy: Arc<dyn DsrLegitimacyStore> = Arc::new(InMemoryDsrLegitimacyStore::new());
    InMemoryErasureWorker::try_new_with_legitimacy(audit, ledger, adapters, legitimacy)
        .map_err(|e| e.to_string())
}

/// Build the canonical orchestrator with the REAL D1-backed ledger + audit
/// sink + D1 erase adapter (WI-S11-008 Wave 1). The other 11 backends are
/// still in-memory placeholders (increments 3-4). `None` when `StorageEnv`
/// is not configured (so the route falls back to the all-placeholder
/// worker — e.g. in tests / unconfigured envs).
fn build_d1_worker() -> Option<(
    InMemoryErasureWorker,
    Arc<crate::storage::d1_http::D1HttpClient>,
)> {
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = Arc::new(crate::storage::d1_http::D1HttpClient::new(&storage_env).ok()?);

    let audit: Arc<dyn ErasureAuditSink> =
        Arc::new(audit::D1ErasureAuditSink::new(Arc::clone(&d1)));
    let ledger: Arc<dyn ErasureIdempotencyLedger> =
        Arc::new(ledger::D1ErasureIdempotencyLedger::new(Arc::clone(&d1)));
    // rt-nuclear #18/#19: bind every erase to a D1-authenticated
    // `dsr_requested` row (GDPR mass-erase authz gate). Fail-CLOSED on a
    // D1 fault (the trait surfaces Err → the orchestrator Rejects).
    let legitimacy: Arc<dyn DsrLegitimacyStore> =
        Arc::new(legitimacy::D1DsrLegitimacyStore::new(Arc::clone(&d1)));
    // Helper: a not-shipped backend reconciled to NotApplicable (ADR-S11-013).
    let na = |kind: BackendKind, reason: &'static str| -> Arc<dyn BackendErasureAdapter> {
        Arc::new(adapter_not_applicable::NotApplicableAdapter::new(
            kind, reason,
        ))
    };
    let adapters: Vec<Arc<dyn BackendErasureAdapter>> = canonical_backend_kinds()
        .iter()
        .map(|k| -> Arc<dyn BackendErasureAdapter> {
            match *k {
                BackendKind::D1 => Arc::new(adapter_d1::D1EraseAdapter::new(Arc::clone(&d1))),
                BackendKind::R2Ac => {
                    Arc::new(adapter_r2_ac::R2AcEraseAdapter::new(Arc::clone(&d1)))
                }
                BackendKind::R2Cas => {
                    Arc::new(adapter_r2_cas::R2CasEraseAdapter::new(Arc::clone(&d1)))
                }
                BackendKind::Stripe => {
                    Arc::new(adapter_stripe::StripePseudonymizeAdapter::new(Arc::clone(&d1)))
                }
                // The remaining 8 are NOT SHIPPED in prod (ADR-S11-013) — no
                // durable subject PII to erase → reconciled to NotApplicable
                // with a documented reason (truthful GDPR audit record).
                BackendKind::NeonMain => na(
                    BackendKind::NeonMain,
                    "Neon control-plane not shipped; subject identity lives in D1 (handled by the D1 adapter)",
                ),
                BackendKind::NeonBilling => na(
                    BackendKind::NeonBilling,
                    "Neon billing not shipped; billing state lives in D1 + Stripe",
                ),
                BackendKind::NeonPitrPseudo => na(
                    BackendKind::NeonPitrPseudo,
                    "Neon PITR not shipped; no Neon backups to tombstone",
                ),
                BackendKind::Kv => na(
                    BackendKind::Kv,
                    "KV namespaces are caches (metadata/JWKS/negative-cache); no durable PII, reconstructed from D1",
                ),
                BackendKind::Loki => na(
                    BackendKind::Loki,
                    "no active Loki sink shipped (observability references only)",
                ),
                BackendKind::R2AuditPseudo => na(
                    BackendKind::R2AuditPseudo,
                    "no R2 audit WORM bucket shipped; no subject-indexed audit store to pseudonymize",
                ),
                // Governance-mode legal-hold-aware CAS erase (B-009): under an
                // active hold it preserves the frozen bytes + pseudonymizes the
                // subject linkage into `cas_retention`; with no hold it delegates
                // to the effective CAS adapter's LIST+DELETE. Governance mode is
                // CODE-reversible — NOT storage Object-Lock (see the adapter).
                BackendKind::R2CasLegalHold => Arc::new(
                    adapter_r2_cas_legalhold::R2CasLegalHoldEraseAdapter::new(Arc::clone(&d1)),
                ),
                BackendKind::R2EvidencePseudo => na(
                    BackendKind::R2EvidencePseudo,
                    "no R2 evidence-* bucket shipped",
                ),
                // `BackendKind` is `#[non_exhaustive]`; a future canonical kind
                // defaults to NotApplicable until it gets a real adapter (the
                // orchestrator's count/order check still pins the canonical 12).
                _ => na(*k, "unrecognised canonical backend (non_exhaustive default)"),
            }
        })
        .collect();

    let worker =
        InMemoryErasureWorker::try_new_with_legitimacy(audit, ledger, adapters, legitimacy).ok()?;
    Some((worker, d1))
}

/// Build the R2 client bound to the region's audit bucket
/// (`corelink-audit-{region}`) for the verify-path signed-attestation store
/// (Artifact 1). `None` (signing then fails CLOSED) unless ALL hold:
/// `StorageEnv` is configured, the operator has EXPLICITLY asserted single
/// region (`ERASURE_ATTESTATION_SINGLE_REGION` truthy), and
/// `ERASURE_ATTESTATION_REGION` parses to a canonical region. Resolving the
/// bucket from the SAME env the signer reads guarantees the bucket can never
/// disagree with the region in the signed payload (no mis-attributed object).
fn build_audit_r2_client() -> Option<Arc<crate::storage::r2_s3::R2S3Client>> {
    // Honour the env region ONLY under an explicit single-region assertion —
    // mirrors `attestation::resolve_region_from_env` (never a silent default).
    let single_region = std::env::var("ERASURE_ATTESTATION_SINGLE_REGION")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if !single_region {
        return None;
    }
    let region = corelink_erasure_attestation::Region::parse(
        std::env::var("ERASURE_ATTESTATION_REGION").ok()?.trim(),
    )?;
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let bucket = region.audit_bucket();
    // `R2S3Client::new` is async; we are called from the multi-thread runtime
    // (main's async body), so bridge with `block_in_place` like `d1util`.
    let handle = tokio::runtime::Handle::current();
    let client = tokio::task::block_in_place(|| {
        handle.block_on(crate::storage::r2_s3::R2S3Client::new(&storage_env, bucket))
    })
    .ok()?;
    Some(Arc::new(client))
}

// ─── Account-deletion erasure sink (C-ACCTDEL transport) ───────────────────────

/// Production [`crate::routes::customer::DsrErasureSink`] that drives the SAME
/// in-process, D1-backed erasure worker the `/_internal/dsr/erase` consumer
/// (the Clerk `user.deleted` path) runs. A self-serve account-delete request and
/// a webhook-originated erasure thus converge on ONE prod-proven erasure engine —
/// no new erasure logic, and no CF Queue producer (the container has none, so the
/// "enqueue" is a direct, synchronous drive of the worker; `process_erasure` is
/// sync, with the async D1 round-trips bridged inside the adapters).
#[non_exhaustive]
pub struct InProcessErasureSink {
    worker: Arc<InMemoryErasureWorker>,
}

impl core::fmt::Debug for InProcessErasureSink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InProcessErasureSink").finish()
    }
}

impl InProcessErasureSink {
    /// Wire the sink over a shared D1-backed erasure worker.
    #[must_use]
    pub fn new(worker: Arc<InMemoryErasureWorker>) -> Self {
        Self { worker }
    }
}

impl crate::routes::customer::DsrErasureSink for InProcessErasureSink {
    fn enqueue(&self, message: &serde_json::Value) -> Result<(), String> {
        // Deserialize + field-parse the canonical dsr.queued.v1 through the EXACT
        // same path `handle_erase` uses (`parse_request`), then drive the shared
        // worker. Unknown fields (schema/source/clerk_user_id) are ignored.
        let msg: DsrQueuedV1 = serde_json::from_value(message.clone())
            .map_err(|e| format!("dsr.queued.v1 deserialize: {e}"))?;
        let request = parse_request(&msg)?;
        match self.worker.process_erasure(&request, now_ms()) {
            // The requester writes the `dsr_requested` anchor BEFORE enqueue, so a
            // legitimate request never rejects here. A Reject = legitimacy/D1 fault
            // → fail-CLOSED (Err → requester maps to 500; the durable anchor + the
            // 24h verify sweep retry the obligation — never a silent drop).
            Ok(ErasureDecision::Rejected { .. }) => {
                Err("erasure rejected (legitimacy gate)".to_owned())
            }
            Ok(_decision) => Ok(()),
            Err(e) => Err(format!("erasure engine error: {e}")),
        }
    }
}

/// Build the production in-process erasure sink over the real D1-backed worker.
/// `None` when `StorageEnv` is unset (dev/CI) → the account-delete route then
/// fails CLOSED (503), never a silently-unhonored erasure. The placeholder
/// (all-no-op, empty-legitimacy) worker is deliberately NOT used here: an
/// account-delete must reach the real backends or refuse the request.
#[must_use]
pub fn build_in_process_erasure_sink() -> Option<Arc<dyn crate::routes::customer::DsrErasureSink>> {
    let (worker, _d1) = build_d1_worker()?;
    Some(Arc::new(InProcessErasureSink::new(Arc::new(worker))))
}

/// Build the route state from env. `None` when `CORELINK_ERASE_AUTH_KEY` is
/// unset or shorter than 32 chars (route not mounted — fail-CLOSED). Mirrors
/// the ≥32-char floor set by the PAT-signing key standard and recommended by
/// F28/F15 of the 2026-06-13 CAA-360 security audit.
#[must_use]
pub fn build_state_from_env() -> Option<DsrRouteState> {
    // rt-nuclear #18/#19 + finding H4: DSR (GDPR mass-erase) MUST gate on the
    // dedicated ERASE key (CORELINK_ERASE_AUTH_KEY), not the shared key — so the
    // #297 per-consumer split actually reaches this destructive surface. The key
    // is DEDICATED-ONLY: NO fallback to the shared CORELINK_INTERNAL_AUTH_KEY
    // (H4 — a shared-key leak must not drive erases), and it preserves the
    // ≥32-char fail-CLOSED floor (F28/F15).
    // Dual-key: the current `CORELINK_ERASE_AUTH_KEY` plus, DURING A ROTATION, the
    // outgoing `CORELINK_ERASE_AUTH_KEY_PREVIOUS` (both dedicated-only, ≥32 — H4/
    // F28/F15 preserved). Accepting both bridges the window where the apex forwards
    // the NEW key but a not-yet-recycled DO container still booted with the OLD one
    // (the env-read-at-start footgun). Empty ⇒ route NOT mounted (fail-CLOSED).
    let internal_auth_keys = crate::routes::admin::erase_auth_keys_from_env();
    if internal_auth_keys.is_empty() {
        tracing::warn!(
            "no usable CORELINK_ERASE_AUTH_KEY (dedicated; NO shared fallback) \
             (< 32 chars); /_internal/dsr/* NOT mounted (fail-CLOSED)"
        );
        return None;
    }
    // Prefer the real D1-backed worker; fall back to the all-placeholder
    // worker when storage is unconfigured (keeps the route mountable in
    // tests / partially-configured envs). The D1 handle (when present) also
    // drives the verify-path attestation signer (G3).
    let (worker, d1) = match build_d1_worker() {
        Some((w, d1)) => (w, Some(d1)),
        None => (build_placeholder_worker().ok()?, None),
    };
    // R2 audit-bucket client for the verify-path signed attestation (Artifact
    // 1). Only built when D1 is present (no point signing without the index);
    // `None` ⇒ the signer fails CLOSED (no dangling r2_key).
    let r2_audit = if d1.is_some() {
        build_audit_r2_client()
    } else {
        None
    };
    Some(DsrRouteState {
        internal_auth_keys,
        worker: Arc::new(worker),
        d1,
        r2_audit,
        staging_admission:
            crate::storage::staging_load_test_admission::StagingLoadTestAdmissionGate::from_env()
                .ok()
                .map(Arc::new),
    })
}

/// Mount `POST /_internal/dsr/{erase,verify,access,portability,rectification}`.
///
/// `erase` (Art.17) + `verify` are the destructive/verification legs; `access`
/// (Art.15), `portability` (Art.20), and `rectification` (Art.16) complete the
/// data-subject-rights surface. All five share the SAME internal-auth gate +
/// audit + idempotency-ledger discipline.
pub fn router(state: DsrRouteState) -> Router {
    Router::new()
        .route("/_internal/dsr/erase", post(handle_erase))
        .route("/_internal/dsr/verify", post(handle_verify))
        .route("/_internal/dsr/access", post(handle_access))
        .route("/_internal/dsr/portability", post(handle_portability))
        .route("/_internal/dsr/rectification", post(handle_rectification))
        .with_state(state)
}

/// Wire shape for the read rights (access / portability). `dsr_id` is the
/// idempotency/audit key; `tenant_id` is the subject (one-user-per-tenant).
#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct DsrSubjectV1 {
    /// Canonical DSR id (idempotency key for the audit ledger).
    pub dsr_id: String,
    /// Tenant id whose data is gathered.
    pub tenant_id: String,
}

/// Wire shape for `POST /_internal/dsr/rectification` (Art.16).
#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct DsrRectifyV1 {
    /// Canonical DSR id (idempotency/audit key).
    pub dsr_id: String,
    /// Tenant id whose PII field is corrected.
    pub tenant_id: String,
    /// Target table (must host an editable subject-PII field).
    pub table: String,
    /// Target column (must be on the editable-PII allowlist).
    pub field: String,
    /// New value (e.g. the new contact email; stored pseudonymized).
    pub new_value: String,
}

/// `POST /_internal/dsr/access` (Art.15) — gather + return the subject's data
/// inline (machine-readable structured JSON). Audits BEFORE disclosing;
/// fail-CLOSED on any gather/D1 error (never a partial export).
async fn handle_access(
    State(state): State<DsrRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !internal_auth_ok_any(&state.internal_auth_keys, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let msg: DsrSubjectV1 = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/access: invalid request body");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let admission = match admit_request(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(d1) = state.d1.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage unconfigured").into_response();
    };
    match access::run_access(
        d1,
        &msg.dsr_id,
        &msg.tenant_id,
        now_ms(),
        admission.as_deref(),
    ) {
        Ok(export) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "dsr_id": msg.dsr_id, "export": export })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, dsr_id = %msg.dsr_id, "dsr/access: gather failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "access failed").into_response()
        }
    }
}

/// `POST /_internal/dsr/portability` (Art.20) — gather the SAME structured
/// bundle as access, return it inline (machine-readable), and best-effort
/// persist a signed durable copy to the R2 audit bucket. Fail-CLOSED on gather.
async fn handle_portability(
    State(state): State<DsrRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !internal_auth_ok_any(&state.internal_auth_keys, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let msg: DsrSubjectV1 = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/portability: invalid request body");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let admission = match admit_request(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(d1) = state.d1.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage unconfigured").into_response();
    };
    match access::run_portability(
        d1,
        state.r2_audit.as_ref(),
        &msg.dsr_id,
        &msg.tenant_id,
        now_ms(),
        admission.as_deref(),
    ) {
        Ok((export, receipt)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "dsr_id": msg.dsr_id,
                "export": export,
                "receipt": receipt,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, dsr_id = %msg.dsr_id, "dsr/portability: gather failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "portability export failed",
            )
                .into_response()
        }
    }
}

/// `POST /_internal/dsr/rectification` (Art.16) — correct an editable subject
/// PII field. Content-addressed cache data + non-editable fields fail CLOSED
/// (4xx). Audits BEFORE the mutation; idempotent at the value level.
async fn handle_rectification(
    State(state): State<DsrRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !internal_auth_ok_any(&state.internal_auth_keys, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let msg: DsrRectifyV1 = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/rectification: invalid request body");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let admission = match admit_request(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(d1) = state.d1.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage unconfigured").into_response();
    };
    match access::run_rectification(
        d1,
        &msg.dsr_id,
        &msg.tenant_id,
        &msg.table,
        &msg.field,
        &msg.new_value,
        now_ms(),
        admission.as_deref(),
    ) {
        // Applied.
        Ok(Ok(result)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "dsr_id": msg.dsr_id, "rectified": result })),
        )
            .into_response(),
        // Fail-CLOSED 4xx: content-immutable / non-editable / invalid value.
        Ok(Err(reject)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "ok": false, "error": reject.message() })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, dsr_id = %msg.dsr_id, "dsr/rectification: engine error");
            (StatusCode::INTERNAL_SERVER_ERROR, "rectification failed").into_response()
        }
    }
}

/// Compact, non-PII label for an [`ErasureDecision`] arm (the verify endpoint
/// returns this, never the full decision with its per-backend completions).
fn decision_label(decision: &ErasureDecision) -> &'static str {
    match decision {
        ErasureDecision::Started { .. } => "started",
        ErasureDecision::VerifiedComplete { .. } => "verified_complete",
        ErasureDecision::VerifiedPartial { .. } => "verified_partial",
        ErasureDecision::VerificationFailed { .. } => "verification_failed",
        ErasureDecision::SlaBreached { .. } => "sla_breached",
        ErasureDecision::Rejected { .. } => "rejected",
        // `ErasureDecision` is `#[non_exhaustive]`.
        _ => "unknown",
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

/// Wire shape for the 24h verify cron tick. The sweep needs only the ids + the
/// SLA-clock anchor; the per-DSR `erasure_salt` and raw `subject_id` are **not
/// retained** post-erasure (and `verify_erasure` never uses the salt — it
/// re-fingerprints by tenant), so they are omitted here.
#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct DsrVerifyV1 {
    /// Canonical UUID DSR id (matches the original erase request).
    pub dsr_id: String,
    /// Tenant id whose erasure is being verified.
    pub tenant_id: String,
    /// Original enqueue instant (Unix epoch ms) — the verification-deadline anchor.
    pub queued_at_ms: u64,
}

/// Build a canonical [`ErasureRequest`] for the verify sweep from the light
/// [`DsrVerifyV1`]. `subject_id == tenant_id` (one-user-per-tenant); the salt is
/// a zeroed placeholder (unused by `verify_erasure`).
fn parse_verify_request(msg: &DsrVerifyV1) -> Result<ErasureRequest, String> {
    let dsr_id = Uuid::parse_str(&msg.dsr_id).map_err(|e| format!("dsr_id: {e}"))?;
    let tenant_id = Uuid::parse_str(&msg.tenant_id).map_err(|e| format!("tenant_id: {e}"))?;
    Ok(ErasureRequest {
        dsr_id,
        tenant_id,
        subject_id: tenant_id,
        erasure_salt: ErasureSalt::new([0u8; 32]),
        queued_at_ms: msg.queued_at_ms,
        legal_hold: false,
    })
}

fn parse_request(msg: &DsrQueuedV1) -> Result<ErasureRequest, String> {
    let dsr_id = Uuid::parse_str(&msg.dsr_id).map_err(|e| format!("dsr_id: {e}"))?;
    let tenant_id = Uuid::parse_str(&msg.tenant_id).map_err(|e| format!("tenant_id: {e}"))?;
    let subject_id = Uuid::parse_str(&msg.subject_id).map_err(|e| format!("subject_id: {e}"))?;
    let salt_bytes = hex::decode(&msg.erasure_salt_hex).map_err(|e| format!("salt hex: {e}"))?;
    let salt_arr: [u8; 32] = salt_bytes
        .try_into()
        .map_err(|_| "erasure_salt_hex must decode to exactly 32 bytes".to_string())?;
    Ok(ErasureRequest {
        dsr_id,
        tenant_id,
        subject_id,
        erasure_salt: ErasureSalt::new(salt_arr),
        queued_at_ms: msg.queued_at_ms,
        legal_hold: msg.legal_hold,
    })
}

async fn handle_erase(
    State(state): State<DsrRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !internal_auth_ok_any(&state.internal_auth_keys, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let msg: DsrQueuedV1 = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/erase: invalid request body");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let request = match parse_request(&msg) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/erase: request field parse error");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let admission = match admit_request(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_context = admission.as_ref().map(|context| {
        Arc::new(StagingDsrRequestContext(Arc::clone(context))) as Arc<dyn ErasureRequestContext>
    });
    match state
        .worker
        .process_erasure_with_context(&request, now_ms(), request_context.as_deref())
    {
        // rt-nuclear #18/#19 tenant legitimacy pre-check rejected this
        // request: no `dsr_requested` row matches (dsr_id, tenant_id), OR
        // the D1 legitimacy lookup faulted (fail-CLOSED). A forged
        // body-asserted tenant_id (shared-internal-key mass-erase attempt)
        // lands here — no fan-out happened, no data was erased. 422.
        Ok(ErasureDecision::Rejected { .. }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "erasure rejected").into_response()
        }
        Ok(_decision) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "dsr_id": msg.dsr_id })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, dsr_id = %msg.dsr_id, "dsr/erase: erasure engine error");
            (StatusCode::INTERNAL_SERVER_ERROR, "erasure failed").into_response()
        }
    }
}

/// `POST /_internal/dsr/verify` — the 24h verification sweep tick (fired by the
/// signup-worker cron). Re-fingerprints every backend for `dsr_id` and lands the
/// canonical `verification_passed/failed` + `completed` audit arms. Same
/// internal-auth gate + wire shape as `/erase`.
async fn handle_verify(
    State(state): State<DsrRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !internal_auth_ok_any(&state.internal_auth_keys, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let msg: DsrVerifyV1 = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/verify: invalid request body");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let request = match parse_verify_request(&msg) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "dsr/verify: request field parse error");
            return (StatusCode::BAD_REQUEST, "invalid request body").into_response();
        }
    };
    let admission = match admit_request(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let request_context = admission.as_ref().map(|context| {
        Arc::new(StagingDsrRequestContext(Arc::clone(context))) as Arc<dyn ErasureRequestContext>
    });
    match state
        .worker
        .verify_erasure_with_context(&request, now_ms(), request_context.as_deref())
    {
        Ok(decision) => {
            // G3 / Artifact 1: on a fully-verified erasure, sign + persist a
            // REAL Ed25519 attestation (non-blocking — the erasure is already
            // complete + audited; the attestation is an extra evidence
            // artifact — but fail-CLOSED on the evidence/region/R2/D1 so a
            // forgeable "certificate" is never written). Strict ordering:
            // R2 PUT → pubkey → D1 index (see `attestation`).
            if let ErasureDecision::VerifiedComplete { completions } = &decision {
                if let Some(d1) = state.d1.as_ref() {
                    // Bind the signed attestation to the REAL per-backend
                    // verification evidence (audit #1 fix): refuses to sign
                    // unless every backend genuinely re-verified empty.
                    attestation::sign_and_persist(
                        d1,
                        state.r2_audit.as_ref(),
                        &msg.dsr_id,
                        &msg.tenant_id,
                        now_ms(),
                        completions,
                        admission.as_deref(),
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "dsr_id": msg.dsr_id,
                    "decision": decision_label(&decision),
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, dsr_id = %msg.dsr_id, "dsr/verify: verification engine error");
            (StatusCode::INTERNAL_SERVER_ERROR, "verification failed").into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// F28/F15 (CAA-360 2026-06-13) + finding H4: `build_state_from_env` must
    /// reject any DEDICATED erase key shorter than 32 chars and return `None`
    /// (route not mounted, fail-CLOSED). H4: a shared `CORELINK_INTERNAL_AUTH_KEY`
    /// (even a valid one) must NOT mount the erase route — only the dedicated key.
    #[test]
    fn build_state_rejects_short_dedicated_erase_key() {
        // 31-char dedicated key — just below the minimum floor.
        std::env::set_var("CORELINK_ERASE_AUTH_KEY", "a".repeat(31));
        assert!(
            build_state_from_env().is_none(),
            "31-char dedicated erase key must not mount the DSR route (< 32 floor)"
        );
        // H4: a VALID shared key with NO dedicated erase key must also NOT mount.
        std::env::remove_var("CORELINK_ERASE_AUTH_KEY");
        std::env::set_var("CORELINK_INTERNAL_AUTH_KEY", "a".repeat(64));
        assert!(
            build_state_from_env().is_none(),
            "H4: a valid shared key must NOT mount erase without the dedicated key"
        );
        std::env::remove_var("CORELINK_INTERNAL_AUTH_KEY");
    }

    #[test]
    fn dual_key_accepts_current_or_previous_rejects_unknown() {
        // Pure (no env): the dual-key rotation window accepts EITHER accepted key.
        let cur = "a".repeat(40);
        let prev = "b".repeat(40);
        let keys = vec![cur.clone(), prev.clone()];
        let hdr = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                axum::http::HeaderName::from_static("x-corelink-internal-auth"),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
            h
        };
        assert!(
            internal_auth_ok_any(&keys, &hdr(&cur)),
            "current key accepted"
        );
        assert!(
            internal_auth_ok_any(&keys, &hdr(&prev)),
            "previous key accepted"
        );
        assert!(
            !internal_auth_ok_any(&keys, &hdr(&"c".repeat(40))),
            "an unrelated key is rejected"
        );
        assert!(
            !internal_auth_ok_any(&keys, &hdr(&cur[..39])),
            "a length-truncated prefix of a valid key is rejected"
        );
        // No accepted keys ⇒ nothing matches (fail-CLOSED — mirrors an unmounted route).
        assert!(!internal_auth_ok_any(&[], &hdr(&cur)));
    }

    #[test]
    fn placeholder_worker_builds_with_12_canonical_adapters() {
        // Construction enforces the canonical 12-backend order; an error here
        // means canonical_backend_kinds drifted from BACKEND_COUNT.
        assert!(build_placeholder_worker().is_ok());
    }

    #[test]
    fn parse_verify_maps_ids_subject_equals_tenant_salt_zeroed() {
        let msg = DsrVerifyV1 {
            dsr_id: "00000000-0000-7000-8000-000000000001".to_string(),
            tenant_id: "00000000-0000-7000-8000-000000000002".to_string(),
            queued_at_ms: 1_700_000_000_000,
        };
        let req = parse_verify_request(&msg).unwrap();
        assert_eq!(
            req.subject_id, req.tenant_id,
            "subject == tenant for verify"
        );
        assert_eq!(
            req.erasure_salt.as_bytes(),
            &[0u8; 32],
            "salt unused → zeroed"
        );
        assert_eq!(req.queued_at_ms, 1_700_000_000_000);
    }

    #[test]
    fn parse_request_maps_wire_to_canonical() {
        let msg = DsrQueuedV1 {
            dsr_id: "00000000-0000-7000-8000-000000000001".to_string(),
            tenant_id: "00000000-0000-7000-8000-000000000002".to_string(),
            subject_id: "00000000-0000-7000-8000-000000000002".to_string(),
            erasure_salt_hex: "ab".repeat(32),
            queued_at_ms: 1_700_000_000_000,
            legal_hold: false,
        };
        let req = parse_request(&msg).unwrap();
        assert_eq!(req.queued_at_ms, 1_700_000_000_000);
        assert!(!req.legal_hold);
        assert_eq!(req.erasure_salt.as_bytes()[0], 0xab);
    }

    #[test]
    fn parse_request_rejects_bad_salt_length() {
        let msg = DsrQueuedV1 {
            dsr_id: "00000000-0000-7000-8000-000000000001".to_string(),
            tenant_id: "00000000-0000-7000-8000-000000000002".to_string(),
            subject_id: "00000000-0000-7000-8000-000000000002".to_string(),
            erasure_salt_hex: "abcd".to_string(), // 2 bytes, not 32
            queued_at_ms: 1,
            legal_hold: false,
        };
        assert!(parse_request(&msg).is_err());
    }

    #[test]
    fn in_process_sink_rejects_unlegitimate_request() {
        use crate::routes::customer::DsrErasureSink as _;
        // Placeholder worker = EMPTY legitimacy store → every (dsr_id, tenant) is
        // NOT-requested → Rejected (pre-fanout, no runtime needed). The sink MUST
        // surface that as Err (fail-CLOSED) so the requester returns 500 and the
        // obligation is retried — never a silent "ok" on an un-honored erasure.
        let sink = InProcessErasureSink::new(Arc::new(build_placeholder_worker().unwrap()));
        let msg = serde_json::json!({
            "schema": "dev.hugr.corelink.dsr.queued.v1",
            "dsr_id": "00000000-0000-7000-8000-000000000001",
            "tenant_id": "00000000-0000-7000-8000-000000000002",
            "subject_id": "00000000-0000-7000-8000-000000000002",
            "erasure_salt_hex": "ab".repeat(32),
            "queued_at_ms": 1_700_000_000_000_u64,
            "legal_hold": false,
            "source": "customer.account.delete",
        });
        let err = sink.enqueue(&msg).unwrap_err();
        assert!(
            err.contains("rejected"),
            "unlegitimate erase must Err (got: {err})"
        );
    }

    #[test]
    fn in_process_sink_errs_on_malformed_message() {
        use crate::routes::customer::DsrErasureSink as _;
        // A body missing the required dsr.queued.v1 fields must fail at
        // deserialize/parse — never a silent Ok that drops the erasure.
        let sink = InProcessErasureSink::new(Arc::new(build_placeholder_worker().unwrap()));
        let bad = serde_json::json!({ "dsr_id": "not-a-uuid", "tenant_id": "x" });
        assert!(
            sink.enqueue(&bad).is_err(),
            "malformed dsr.queued.v1 must Err"
        );
    }
}
