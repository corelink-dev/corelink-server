//! Production [`BillingD1Writer`] adapter: the **durable** D1-over-HTTP
//! billing-state writer backing the native Stripe-webhook materializer.
//!
//! # Why this exists (the sync↔async bridge)
//!
//! The [`BillingD1Writer`] trait — and the whole
//! [`corelink_billing::stripe::real::webhook_dispatch::WebhookDispatcher`]
//! pipeline it feeds — is **synchronous by charter**: the trait is shared
//! with the wasm32 CF Worker, where the production binder wraps
//! `worker::D1Database` whose `JsFuture`s are `!Send`. Making the trait
//! async would break the Worker target's `Send` contract. So the trait
//! surface stays sync (see `corelink-billing-stripe-traits` /
//! `corelink-billing-stripe-materializer::wasm32_binders`).
//!
//! On the **native** container, however, D1 is reachable only over the
//! Cloudflare D1 REST API via the **async** [`D1HttpClient`]. This adapter
//! is the documented bridge: each sync trait method drives the async
//! client through
//! `tokio::task::block_in_place(|| Handle::current().block_on(async { … }))`.
//! The native server is `#[tokio::main]` (multi-thread), so
//! `block_in_place` is valid (it tells the runtime to move other tasks off
//! the current worker thread while we block on the D1 round-trip). This is
//! the same sync↔async bridge spirit as
//! `corelink-stripe-real::client` (which uses `spawn_blocking`).
//!
//! NO trait changes; NO touching the shared leaf / `stripe-real` / Worker
//! path. The Worker keeps its own `CfD1BillingWriter`; this writer is the
//! native-only sibling behind the SAME `BillingD1Writer` trait object.
//!
//! # SQL — single source of truth
//!
//! Every statement is one of the canonical literals re-exported from
//! `corelink-billing-stripe-materializer` (the `SQL_*` consts), reconciled
//! COLUMN-BY-COLUMN against the deployed schema (`migrations/d1/0048_*` +
//! `0044_*` + `0039_*`). We transcribe — never hand-roll — those strings
//! so the native and wasm32 targets can never drift. Binds are positional
//! (`?1..?n`); the bind order is documented next to each call and matches
//! the column order baked into the shared constant.
//!
//! # SECURITY / fail-CLOSED
//!
//! - **Parameterised SQL only** — every dynamic value is a positional
//!   `serde_json::Value` bind (no string interpolation).
//! - **Fail-CLOSED:** any D1 transport / non-2xx / decode error maps to
//!   [`BillingD1Error::Transient`] (→ dispatcher HTTP 500 → Stripe
//!   retries; the fenced pending-effect witness decides whether recovery may
//!   materialize again). A malformed
//!   row (missing a NOT-NULL value the schema requires) maps to
//!   [`BillingD1Error::InvalidPayload`] (→ HTTP 422, Stripe stops).
//! - **Secrets never logged:** the CF API bearer token lives inside
//!   [`D1HttpClient`] (which redacts it) and is NEVER surfaced by this
//!   adapter's `Debug`.

use std::sync::Arc;

use corelink_billing_stripe_materializer::{
    BillingD1Error, BillingD1Writer, EntitlementCasOutcome, MaterializedRow, RefundedProduct,
    RefundedPurchase, RunnerEntitlementRevision, WebhookOutcome,
    SQL_ADVANCE_RUNNER_ENTITLEMENT_FENCE, SQL_CAS_DELETE_RUNNERS_ENTITLEMENT,
    SQL_CAS_UPSERT_RUNNERS_ENTITLEMENT, SQL_DOWNGRADE_TIER, SQL_FIND_INVOICE_SUBSCRIPTION,
    SQL_INSERT_DISPUTE, SQL_INSERT_REFUND, SQL_INSERT_WEBHOOK_EVENT_PROCESSED,
    SQL_MARK_SUBSCRIPTION_CANCELED, SQL_READ_RUNNER_ENTITLEMENT_FENCE, SQL_READ_TIER,
    SQL_RESOLVE_REFUND_PRODUCT, SQL_UPSERT_CUSTOMER, SQL_UPSERT_INVOICE, SQL_UPSERT_SUBSCRIPTION,
    SQL_UPSERT_TIER,
};
use serde_json::{json, Value};

use crate::storage::d1_http::{D1BatchStatement, D1HttpClient};

/// Durable native billing writer, backed by Cloudflare D1 over the REST
/// API. Holds the shared [`D1HttpClient`] (which owns + redacts the CF API
/// token). Wired at boot in `main.rs` when `StorageEnv::from_env()` is
/// `Some`; dev/CI keep the in-memory mirror.
#[derive(Clone)]
pub struct D1HttpBillingWriter {
    /// D1-over-HTTP client. `Arc` so the connection pool is shared across
    /// the webhook dispatcher, the idempotency store, and any background
    /// reconciliation.
    d1: Arc<D1HttpClient>,
}

impl D1HttpBillingWriter {
    /// Wire the writer over a shared [`D1HttpClient`].
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    /// Borrow the underlying D1 client.
    #[must_use]
    pub fn d1(&self) -> &D1HttpClient {
        &self.d1
    }

    /// Run one parameterised statement against D1, bridging the sync trait
    /// surface to the async [`D1HttpClient::query`] via `block_in_place` +
    /// the current Tokio runtime handle. Returns the result rows (empty
    /// for non-`RETURNING` writes).
    ///
    /// Fail-CLOSED: a transport / non-2xx / decode error from the client
    /// (an `Err(String)`) is mapped to [`BillingD1Error::Transient`].
    fn run(
        &self,
        sql: &str,
        binds: Vec<Value>,
    ) -> Result<Vec<serde_json::Map<String, Value>>, BillingD1Error> {
        let d1 = Arc::clone(&self.d1);
        // The native server is `#[tokio::main]` (multi-thread). We are
        // inside an async task already (the axum handler), so we cannot
        // create a nested runtime; instead `block_in_place` hands the
        // current worker thread back to the scheduler while we block on
        // the D1 round-trip, and `Handle::current().block_on` drives the
        // future to completion. (Charter: the trait is sync — this is the
        // single documented bridge point.)
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.query(sql, &binds).await })
        })
        .map_err(|e| BillingD1Error::Transient(format!("d1-http-billing: {e}")))
    }

    /// Run a small rollback-on-error D1 batch. The CAS fence and entitlement
    /// mutation share this transaction, so instances cannot interleave a
    /// stale delete/grant between the compare and the write.
    fn run_batch(
        &self,
        statements: Vec<D1BatchStatement>,
    ) -> Result<Vec<Vec<serde_json::Map<String, Value>>>, BillingD1Error> {
        let d1 = Arc::clone(&self.d1);
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.batch(statements).await })
        })
        .map_err(|e| BillingD1Error::Transient(format!("d1-http-billing batch: {e:?}")))
    }

    /// Serialize the canonical [`MaterializedRow::payload`] to the TEXT
    /// `payload_json` column value. Serialization of a `serde_json::Value`
    /// is infallible in practice, but we map any error to a permanent
    /// shape error rather than panicking (charter: no `unwrap` in `src/`).
    fn payload_json(row: &MaterializedRow) -> Result<String, BillingD1Error> {
        serde_json::to_string(&row.payload).map_err(|e| {
            BillingD1Error::InvalidPayload(format!(
                "d1-http-billing: payload serialize failed: {e}"
            ))
        })
    }

    /// Extract a required string field from the row payload (a NOT-NULL
    /// column the trait does not carry as a typed field — e.g. the
    /// subscription `status` / invoice `outcome` the handler stashes in
    /// the JSON payload). Fail-CLOSED: a missing field is a permanent
    /// shape error (the deployed column is NOT NULL).
    fn required_payload_str<'a>(
        row: &'a MaterializedRow,
        key: &str,
    ) -> Result<&'a str, BillingD1Error> {
        row.payload.get(key).and_then(Value::as_str).ok_or_else(|| {
            BillingD1Error::InvalidPayload(format!(
                "d1-http-billing: row payload missing required `{key}` (NOT-NULL column)"
            ))
        })
    }

    /// `row.materialized_at_ms` (u64) → i64 for the BIGINT bind. The
    /// Stripe-event clock is ms-since-epoch, far below `i64::MAX`, so the
    /// cast is lossless in practice; we saturate defensively.
    fn mat_ms(row: &MaterializedRow) -> i64 {
        i64::try_from(row.materialized_at_ms).unwrap_or(i64::MAX)
    }
}

impl std::fmt::Debug for D1HttpBillingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The D1 client redacts its own CF API token; nothing secret is
        // surfaced here. Shown as a marker so a leaked Debug can never
        // expose credentials.
        f.debug_struct("D1HttpBillingWriter")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

impl BillingD1Writer for D1HttpBillingWriter {
    fn upsert_customer(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // Binds (?1..?5): tenant_id, stripe_customer_id, stripe_event_id,
        // materialized_at_ms, payload_json.
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_UPSERT_CUSTOMER,
            vec![
                json!(row.tenant_id),
                json!(row.stripe_id),
                json!(row.stripe_event_id),
                json!(Self::mat_ms(&row)),
                json!(payload_json),
            ],
        )?;
        Ok(())
    }

    fn upsert_subscription(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // Binds (?1..?6): tenant_id, stripe_subscription_id,
        // stripe_event_id, status, materialized_at_ms, payload_json.
        // `status` is the NOT-NULL mirror the handler stashes in payload.
        let status = Self::required_payload_str(&row, "status")?.to_owned();
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_UPSERT_SUBSCRIPTION,
            vec![
                json!(row.tenant_id),
                json!(row.stripe_id),
                json!(row.stripe_event_id),
                json!(status),
                json!(Self::mat_ms(&row)),
                json!(payload_json),
            ],
        )?;
        Ok(())
    }

    fn mark_subscription_canceled(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // UPDATE binds (?1..?4): payload_json, materialized_at_ms,
        // tenant_id, stripe_subscription_id. `status='canceled'` is a
        // literal in the statement.
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_MARK_SUBSCRIPTION_CANCELED,
            vec![
                json!(payload_json),
                json!(Self::mat_ms(&row)),
                json!(row.tenant_id),
                json!(row.stripe_id),
            ],
        )?;
        Ok(())
    }

    fn upsert_invoice(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // Binds (?1..?6): tenant_id, stripe_invoice_id, stripe_event_id,
        // outcome, materialized_at_ms, payload_json. `outcome` is the
        // NOT-NULL + CHECKed value the handler stashes in payload
        // (`paid` | `payment_failed`).
        let outcome = Self::required_payload_str(&row, "outcome")?.to_owned();
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_UPSERT_INVOICE,
            vec![
                json!(row.tenant_id),
                json!(row.stripe_id),
                json!(row.stripe_event_id),
                json!(outcome),
                json!(Self::mat_ms(&row)),
                json!(payload_json),
            ],
        )?;
        Ok(())
    }

    fn insert_dispute(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // Binds (?1..?5): tenant_id, stripe_dispute_id, stripe_event_id,
        // materialized_at_ms, payload_json. (severity/schema_version
        // DEFAULTed.)
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_INSERT_DISPUTE,
            vec![
                json!(row.tenant_id),
                json!(row.stripe_id),
                json!(row.stripe_event_id),
                json!(Self::mat_ms(&row)),
                json!(payload_json),
            ],
        )?;
        Ok(())
    }

    fn insert_refund(&self, row: MaterializedRow) -> Result<(), BillingD1Error> {
        // Binds (?1..?5): tenant_id, stripe_charge_id, stripe_event_id,
        // materialized_at_ms, payload_json. The refund PK is the parent
        // charge id, carried in `row.stripe_id` (the handler sets
        // `stripe_id = charge_id`).
        let payload_json = Self::payload_json(&row)?;
        self.run(
            SQL_INSERT_REFUND,
            vec![
                json!(row.tenant_id),
                json!(row.stripe_id),
                json!(row.stripe_event_id),
                json!(Self::mat_ms(&row)),
                json!(payload_json),
            ],
        )?;
        Ok(())
    }

    fn try_record_event(
        &self,
        stripe_event_id: &str,
        canonical_event_type: &str,
        now_ms: u64,
        outcome: WebhookOutcome,
    ) -> Result<bool, BillingD1Error> {
        if stripe_event_id.is_empty() {
            return Err(BillingD1Error::InvalidPayload(
                "d1-http-billing: empty stripe_event_id rejected".to_owned(),
            ));
        }
        // Binds (?1..?5): event_id, event_type, processed_at_ms, outcome,
        // correlation_id. `outcome` is bound from the caller's classification
        // (see `WebhookOutcome`); the Stripe event id doubles as the
        // NOT-NULL correlation_id (the sync trait carries neither).
        // `RETURNING event_id` → a row comes back iff WE inserted (first
        // delivery); a PK conflict (replay) yields no row → Ok(false) so the
        // dispatcher acks the duplicate without re-mutating state.
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let rows = self.run(
            SQL_INSERT_WEBHOOK_EVENT_PROCESSED,
            vec![
                json!(stripe_event_id),
                json!(canonical_event_type),
                json!(now),
                json!(outcome.as_str()),
                json!(stripe_event_id),
            ],
        )?;
        Ok(!rows.is_empty())
    }

    fn read_tier(&self, tenant_id: &str) -> Result<Option<String>, BillingD1Error> {
        // Bind (?1): tenant_id. SELECT → Ok(Some(tier)) when a row exists,
        // Ok(None) otherwise. A transport error is Transient (fail-CLOSED:
        // never silently treat a failed read as "no tier").
        let rows = self.run(SQL_READ_TIER, vec![json!(tenant_id)])?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let tier = row
            .get("tier")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BillingD1Error::Transient(
                    "d1-http-billing: tier_selections row missing `tier` column".to_owned(),
                )
            })?
            .to_owned();
        Ok(Some(tier))
    }

    fn resolve_refunded_purchase_by_subscription(
        &self,
        tenant_id: &str,
        stripe_subscription_id: &str,
    ) -> Result<Option<RefundedPurchase>, BillingD1Error> {
        let rows = self.run(
            SQL_RESOLVE_REFUND_PRODUCT,
            vec![
                json!(tenant_id),
                json!(stripe_subscription_id),
                json!(tenant_id),
                json!(stripe_subscription_id),
            ],
        )?;
        // Two rows means a corrupt/ambiguous ownership map. Keep the refund
        // pending; selecting either product could revoke an unrelated service.
        if rows.len() != 1 {
            return Ok(None);
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let product = match row.get("product_axis").and_then(Value::as_str) {
            Some("cache") => RefundedProduct::Cache,
            Some("runners") => RefundedProduct::Runners,
            _ => return Ok(None),
        };
        Ok(Some(RefundedPurchase {
            product,
            stripe_subscription_id: stripe_subscription_id.to_owned(),
        }))
    }

    fn resolve_refunded_purchase_by_invoice(
        &self,
        tenant_id: &str,
        stripe_invoice_id: &str,
    ) -> Result<Option<RefundedPurchase>, BillingD1Error> {
        let rows = self.run(
            SQL_FIND_INVOICE_SUBSCRIPTION,
            vec![json!(tenant_id), json!(stripe_invoice_id)],
        )?;
        let Some(subscription_id) = rows
            .first()
            .and_then(|row| row.get("stripe_subscription_id"))
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        self.resolve_refunded_purchase_by_subscription(tenant_id, subscription_id)
    }

    fn upsert_tier(
        &self,
        tenant_id: &str,
        tier_wire: &str,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<(), BillingD1Error> {
        // Binds (?1..?4): tenant_id, tier, subscription_started_at_ms
        // (= now_ms), correlation_id. The statement writes
        // `subscription_state='active'`; `subscription_started_at_ms` is
        // required NOT NULL when active (0039 CHECK).
        self.run(
            SQL_UPSERT_TIER,
            vec![
                json!(tenant_id),
                json!(tier_wire),
                json!(now_ms),
                json!(correlation_id),
            ],
        )?;
        Ok(())
    }

    fn downgrade_tier(
        &self,
        tenant_id: &str,
        tier_wire: &str,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<(), BillingD1Error> {
        // Binds (?1..?4): tenant_id, tier, subscription_started_at_ms
        // (= now_ms, used only on the INSERT/new-row path), correlation_id.
        // UNLIKE `upsert_tier`, the statement writes `subscription_state='inactive'`
        // (the access gate OFF for `customer.subscription.deleted`) and does NOT
        // reset `subscription_started_at_ms` on conflict — the original start is
        // preserved. Mirrors the wasm32 binder + in-memory downgrade write.
        self.run(
            SQL_DOWNGRADE_TIER,
            vec![
                json!(tenant_id),
                json!(tier_wire),
                json!(now_ms),
                json!(correlation_id),
            ],
        )?;
        Ok(())
    }

    fn cas_runners_entitlement(
        &self,
        tenant_id: &str,
        revision: RunnerEntitlementRevision<'_>,
        entitlement: Option<(u32, u32)>,
        now_ms: i64,
    ) -> Result<EntitlementCasOutcome, BillingD1Error> {
        if tenant_id.trim().is_empty()
            || revision.subscription_id.trim().is_empty()
            || revision.subscription_created_at_ms == 0
            || revision.stripe_event_created_at_ms == 0
            || revision.stripe_event_id.trim().is_empty()
        {
            return Err(BillingD1Error::InvalidPayload(
                "d1-http-billing: runner entitlement CAS requires non-empty identity and provider timestamps"
                    .to_owned(),
            ));
        }
        let mutation = match entitlement {
            Some((max_concurrency, max_vcpu_h)) => {
                if max_concurrency == 0 {
                    return Err(BillingD1Error::InvalidPayload(
                        "d1-http-billing: runner entitlement CAS max_concurrency must be > 0"
                            .to_owned(),
                    ));
                }
                D1BatchStatement::new(
                    SQL_CAS_UPSERT_RUNNERS_ENTITLEMENT,
                    vec![
                        json!(tenant_id),
                        json!(max_concurrency),
                        json!(now_ms),
                        json!(max_vcpu_h),
                        json!(tenant_id),
                        json!(revision.subscription_id),
                        json!(revision.subscription_created_at_ms),
                        json!(revision.stripe_event_created_at_ms),
                        json!(revision.stripe_event_id),
                    ],
                )
            }
            None => D1BatchStatement::new(
                SQL_CAS_DELETE_RUNNERS_ENTITLEMENT,
                vec![
                    json!(tenant_id),
                    json!(tenant_id),
                    json!(revision.subscription_id),
                    json!(revision.subscription_created_at_ms),
                    json!(revision.stripe_event_created_at_ms),
                    json!(revision.stripe_event_id),
                ],
            ),
        };
        let results = self.run_batch(vec![
            D1BatchStatement::new(
                SQL_ADVANCE_RUNNER_ENTITLEMENT_FENCE,
                vec![
                    json!(tenant_id),
                    json!(revision.subscription_id),
                    json!(revision.subscription_created_at_ms),
                    json!(revision.stripe_event_created_at_ms),
                    json!(revision.stripe_event_id),
                    json!(if revision.authority_is_current {
                        1_i64
                    } else {
                        0_i64
                    }),
                    json!(if entitlement.is_some() { 1_i64 } else { 0_i64 }),
                    json!(now_ms),
                ],
            ),
            mutation,
            D1BatchStatement::new(SQL_READ_RUNNER_ENTITLEMENT_FENCE, vec![json!(tenant_id)]),
        ])?;
        let advanced = results.first().is_some_and(|rows| !rows.is_empty());
        if advanced {
            return Ok(EntitlementCasOutcome::Applied);
        }
        let current = results
            .get(2)
            .and_then(|rows| rows.first())
            .and_then(|row| {
                Some((
                    row.get("stripe_subscription_id")?.as_str()?,
                    row.get("subscription_created_at_ms")?.as_u64()?,
                    row.get("stripe_event_created_at_ms")?.as_u64()?,
                    row.get("stripe_event_id")?.as_str()?,
                ))
            })
            .ok_or_else(|| {
                BillingD1Error::Transient(
                    "d1-http-billing: runner entitlement fence disappeared during CAS".to_owned(),
                )
            })?;
        if current.0 == revision.subscription_id
            && current.1 == revision.subscription_created_at_ms
            && current.2 == revision.stripe_event_created_at_ms
            && current.3 == revision.stripe_event_id
        {
            Ok(EntitlementCasOutcome::Duplicate)
        } else {
            Ok(EntitlementCasOutcome::Stale)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed these primitives"
)]
mod tests {
    use super::*;
    use crate::storage::StorageEnv;

    fn inert_writer() -> D1HttpBillingWriter {
        // Build over a `D1HttpClient` with never-reached dummy creds. The
        // unit tests below only exercise the side-effect-free helpers
        // (payload serialize, required-field extraction, debug redaction)
        // and NEVER perform a D1 round-trip. Behavioural coverage of the
        // real SQL uses the `#[ignore]` live-D1 harness in
        // `tier_select_store` / `d1_http` (same credentials shape).
        let env = StorageEnv {
            r2_endpoint: "https://example.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "test-akid".to_owned(),
            r2_secret_access_key: "test-secret".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test-account".to_owned(),
            cf_api_token: "test-token-never-sent".to_owned(),
            d1_database_id: "test-db".to_owned(),
        };
        let client = D1HttpClient::new(&env).expect("build inert D1HttpClient");
        D1HttpBillingWriter::new(Arc::new(client))
    }

    fn row_with(table: &str, payload: Value) -> MaterializedRow {
        MaterializedRow::new(table, "ten_1", "obj_1", "evt_1", payload, 1_700_000_000_000)
    }

    #[test]
    fn debug_is_redacted_marker_only() {
        let w = inert_writer();
        let dbg = format!("{w:?}");
        assert!(dbg.contains("[D1HttpClient]"), "{dbg}");
        assert!(!dbg.contains("test-token"), "must not leak token: {dbg}");
    }

    #[test]
    fn payload_json_serializes_value() {
        let row = row_with("stripe_customers", json!({"customer_id": "cus_1"}));
        let s = D1HttpBillingWriter::payload_json(&row).unwrap();
        assert!(s.contains("cus_1"), "{s}");
    }

    #[test]
    fn required_payload_str_extracts_status() {
        let row = row_with("stripe_subscriptions", json!({"status": "active"}));
        assert_eq!(
            D1HttpBillingWriter::required_payload_str(&row, "status").unwrap(),
            "active"
        );
    }

    #[test]
    fn required_payload_str_missing_is_invalid_payload() {
        let row = row_with("stripe_invoices", json!({"not_outcome": "x"}));
        let err = D1HttpBillingWriter::required_payload_str(&row, "outcome").unwrap_err();
        assert!(matches!(err, BillingD1Error::InvalidPayload(_)), "{err:?}");
    }

    #[test]
    fn mat_ms_casts_losslessly() {
        let row = row_with("stripe_customers", json!({}));
        assert_eq!(D1HttpBillingWriter::mat_ms(&row), 1_700_000_000_000_i64);
    }

    #[test]
    fn empty_event_id_rejected_without_d1_roundtrip() {
        // `try_record_event` must reject an empty id BEFORE any D1 call,
        // so this is safe to run against the inert writer.
        let w = inert_writer();
        let err = w
            .try_record_event("", "invoice.paid", 1, WebhookOutcome::Dispatched)
            .unwrap_err();
        assert!(matches!(err, BillingD1Error::InvalidPayload(_)), "{err:?}");
    }
}
