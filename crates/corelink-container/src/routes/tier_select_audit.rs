//! Production [`TierSelectAudit`] adapter: the fail-CLOSED audit seam
//! backing `POST /v1/onboarding/tier-select`.
//!
//! # What this implements
//!
//! [`TierSelectAudit::emit`] records the durable audit-chain entry for
//! `event` (one of the orchestration's static labels:
//! `tier_select_attempted`, `dpa_first_violation_attempt`,
//! `stripe_checkout_session_created`, `tier_activated_free`). The
//! orchestration calls `emit` BEFORE every state mutation; an `Err(String)`
//! ABORTS the whole operation (fail-CLOSED;
//! INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER) → 500 `internal`.
//!
//! The durable backing is a dedicated D1 table, `tier_select_audit_events`
//! (migration `0092`), mirroring the proven `customer_d1.rs::insert_audit_event`
//! precedent (real D1 INSERT, `Err` → fail-CLOSED). It is DELIBERATELY
//! SEPARATE from `customer_audit_events` (migration 0077): that table feeds
//! the customer-facing `GET /v1/customer/audit` dashboard, and these internal
//! money-path events must never leak onto it. The structured `tracing` event
//! is kept alongside as defense-in-depth (still ingested by the CF Logs
//! pipeline) but is no longer the durability source — the D1 write is.
//!
//! # SECURITY INVARIANTS (do NOT regress)
//!
//! - **Audit BEFORE mutation, fail-CLOSED.** `emit` returning `Err` MUST
//!   abort the orchestration — a real durable-write failure propagates as
//!   `Err`, never swallowed.
//! - **Tenant from the verified header only.** `emit` records the
//!   `tenant_id` the orchestration passes (extracted from the
//!   edge-verified `x-corelink-tenant-id`); this adapter never re-derives
//!   or defaults it.
//! - **No secrets / no PII in the audit line or row.** Only the static
//!   `event`, the `tenant_id`, the `correlation_id`, and a wall-clock
//!   timestamp are ever recorded — never tokens, never the buyer email,
//!   never a Stripe key.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::routes::tier_select::TierSelectAudit;
use crate::storage::d1_http::D1HttpClient;

/// Wall-clock epoch-millisecond timestamp for the audit row. A pre-epoch
/// system clock is impossible on a deployed container; the saturating
/// fallback keeps `emit` total rather than letting it panic.
fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Production audit sink for tier-select: a durable D1-over-HTTP INSERT into
/// `tier_select_audit_events` (migration `0092`).
///
/// Holds the shared [`D1HttpClient`] (which owns + redacts the CF API
/// token) — the same collaborator [`super::tier_select_store::D1HttpTierSelectStore`]
/// uses, wired from the same `Arc` at boot (`build_state_from_env`).
#[derive(Clone)]
pub struct TierSelectAuditAdapter {
    /// D1-over-HTTP client for the durable audit INSERT. `Arc` so the same
    /// connection is shared with the store rather than opening a second one.
    d1: Arc<D1HttpClient>,
}

impl TierSelectAuditAdapter {
    /// Wire the audit adapter over a shared [`D1HttpClient`].
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    /// Test-only constructor: an INERT adapter over a `D1HttpClient` built
    /// from dummy (never-reached in the auth-gate unit tests) credentials.
    /// Mirrors `D1HttpTierSelectStore::for_test`.
    #[cfg(test)]
    #[allow(
        clippy::panic,
        reason = "test-only constructor: panic on setup failure is fine"
    )]
    #[must_use]
    pub(crate) fn for_test() -> Self {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://example.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "test-akid".to_owned(),
            r2_secret_access_key: "test-secret".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test-account".to_owned(),
            cf_api_token: "test-token-never-sent".to_owned(),
            d1_database_id: "test-db".to_owned(),
        };
        let client = D1HttpClient::new(&env)
            .unwrap_or_else(|e| panic!("test D1HttpClient build failed: {e}"));
        Self::new(Arc::new(client))
    }
}

impl std::fmt::Debug for TierSelectAuditAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The D1 client redacts its own CF API token; nothing secret is
        // surfaced here. Shown as a marker so a leaked Debug can never
        // expose credentials.
        f.debug_struct("TierSelectAuditAdapter")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

impl TierSelectAudit for TierSelectAuditAdapter {
    async fn emit(
        &self,
        event: &'static str,
        tenant_id: &str,
        correlation_id: &str,
    ) -> Result<(), String> {
        // Defense-in-depth structured log (CF Logs pipeline) — kept alongside
        // the durable write, no longer the durability source itself.
        tracing::info!(
            target: "corelink.tier_select.audit",
            event = event,
            tenant_id = tenant_id,
            correlation_id = correlation_id,
            "tier-select audit",
        );

        let ts_ms = unix_millis_now();
        self.d1
            .query(
                "INSERT INTO tier_select_audit_events \
                 (tenant_id, event_type, correlation_id, ts_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    json!(tenant_id),
                    json!(event),
                    json!(correlation_id),
                    json!(ts_ms),
                ],
            )
            .await
            .map(|_rows| ())
            .map_err(|e| {
                // Fail-CLOSED: propagate so the caller ABORTS before the
                // primary mutation (audit-before-mutation). Never swallowed.
                tracing::error!(
                    error = %e,
                    event,
                    tenant_id,
                    correlation_id,
                    "tier_select_audit: durable D1 audit insert failed (fail-CLOSED)"
                );
                format!("tier_select_audit: D1 insert failed for {event}: {e}")
            })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;

    #[test]
    fn debug_surfaces_no_state() {
        // The redacting Debug never leaks the CF API token.
        let rendered = format!("{:?}", TierSelectAuditAdapter::for_test());
        assert!(rendered.contains("TierSelectAuditAdapter"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("test-token-never-sent"));
    }

    /// A D1 client that points at an unroutable host + carries bogus CF
    /// credentials — the real Cloudflare D1 REST API rejects the request
    /// (non-2xx), so every `query` fails. Mirrors `auth_introspect.rs`'s
    /// `unreachable_d1` fault-injection helper — this is the established
    /// pattern in this crate for driving the REAL async `D1HttpClient` down
    /// a real (not mocked) failure path.
    fn failing_d1() -> Arc<D1HttpClient> {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "http://127.0.0.1:1".to_owned(),
            r2_access_key_id: "x".to_owned(),
            r2_secret_access_key: "x".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "definitely-not-a-real-account".to_owned(),
            cf_api_token: "definitely-not-a-real-token".to_owned(),
            d1_database_id: "definitely-not-a-real-db".to_owned(),
        };
        Arc::new(D1HttpClient::new(&env).expect("build D1HttpClient"))
    }

    /// BEFORE this fix: `emit` was `tracing::info!(...); Ok(())` — infallible.
    /// AFTER: a durable D1 insert failure propagates as `Err`, closing the
    /// fail-CLOSED audit-before-mutation contract on the real durable store.
    #[tokio::test]
    async fn emit_returns_err_when_durable_insert_fails() {
        let adapter = TierSelectAuditAdapter::new(failing_d1());
        let result = adapter
            .emit("tier_select_attempted", "tenant-l2", "corr-l2")
            .await;
        assert!(
            result.is_err(),
            "emit must propagate a durable D1 failure as Err (fail-CLOSED), got {result:?}"
        );
    }
}
