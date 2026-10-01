//! Production Stripe webhook dispatch pipeline.
//!
//! This module wires the canonical end-to-end flow that replaces the
//! in-process fake dispatch attached to `apps/server`. The pipeline is
//! intentionally pure / sync at this layer (no tokio) so it can be
//! driven from any HTTP server crate (axum, hyper, worker-rs, tests)
//! without runtime coupling.
//!
//! # Wave-36 Trigger A — trait surface moved
//!
//! The four port traits (`AuditEmitter`, `IdempotencyStore`,
//! `StateMaterializer`, `SliRecorder`) plus the identity / outcome /
//! error types (`IdempotencyToken`, `CanonicalWebhookEventType`,
//! `StripeWebhookEnvelope`, `IdempotencyOutcome`, `AuditRecord`,
//! `AuditOutcome`, `SliObservation`, `DispatchResponse`,
//! `MaterializerError`) now live in the leaf crate
//! `corelink-billing-stripe-traits`. They are re-exported from this
//! module at the previous paths so consumers using
//! `corelink_stripe_real::webhook_dispatch::*` keep working
//! unchanged. The concrete HTTPS dispatcher + in-memory store + test
//! fakes (`WebhookDispatcher`, `InMemoryIdempotencyStore`,
//! `RecordingStateMaterializer`, `RecordingAuditEmitter`,
//! `RecordingSliRecorder`, `FixedClock`) remain defined here; the
//! `impl` blocks now reference the traits crate explicitly. See
//! `specs/_audits/sealed/2026-05-27-w36-trigger-a-seal.md` for the cycle
//! resolution rationale.
//!
//! # Pipeline
//!
//! ```text
//! POST /v1/billing/stripe-webhook
//!   1. Read `Stripe-Signature` header.                 -> 400 if missing.
//!   2. Verify HMAC-SHA256 over raw payload bytes via
//!      `webhook::verify_webhook_signature` (constant-time, 5-min
//!      replay tolerance, multi-v1 key-rotation tolerant).
//!      -> 401 on signature mismatch / replay / future-dated.
//!   3. Parse JSON envelope (`event.id` + `event.type`).
//!      -> 422 on malformed envelope.
//!   4. Derive a 256-bit BLAKE3 idempotency token from `event.id`.
//!   5. Insert-or-ignore the token into the dedup store.
//!      - Already-processed -> return 200 immediately (NO dispatch).
//!      - Transient backend failure -> 500 (Stripe retries).
//!   6. Classify the event type into the canonical 10-element taxonomy.
//!   7. Hand to the `StateMaterializer` trait (production: D1 writer;
//!      tests: recording fake) which materializes the per-event row(s).
//!   8. Emit one `corelink.billing.stripe_event_processed.v1` audit
//!      record. Audit fail = the request returns 500 (fail-CLOSED).
//!   9. Record `corelink_billing_stripe_event_seconds` SLI histogram
//!      observation tagged with the canonical event type. (Always
//!      emitted, even on failure, so dashboards see latency for the
//!      sad path.)
//!  10. Return canonical [`DispatchResponse`] -> HTTP status code.
//! ```
//!
//! # 10-element SLA event taxonomy
//!
//! Per S-10 sprint contract + WI-S10-003 §6.1.6 + `0018_stripe_idem_keys.sql`
//! event_type CHECK constraint. The five subscription/dispute **state-mutating** events
//! (CTRL-BILLING-001 / INV-BILLING-NO-DUP) are:
//!
//! - `customer.subscription.deleted`        — downgrade to Free tier.
//! - `customer.subscription.updated`        — refresh tier + status.
//! - `invoice.paid`                         — extend access expiry.
//! - `invoice.payment_failed`               — set grace-period flag.
//! - `charge.dispute.created`               — freeze charges + notify Finance.
//!
//! The four **forward-compat / observability-only** events (acked + audited
//! but no state mutation today; reserved for S-13+ scope):
//!
//! - `customer.subscription.created`        — pre-checkout-complete echo.
//! - `customer.subscription.trial_will_end` — trial 3-day notice.
//! - `customer.created`                     — new customer record echo.
//! - `invoice.created`                      — invoice generated echo.
//!
//! `charge.refunded` is the sixth materialized event: it always records the
//! refund and revokes active access when Stripe marks the charge fully refunded.
//!
//! # Charter compliance
//!
//! - `#![forbid(unsafe_code)]` (crate-level).
//! - No `unwrap`/`expect`/`panic`/`indexing_slicing` in lib code.
//! - No tokio in src (sync trait surface; callers schedule the async
//!   read of the body and pass bytes in).
//! - Audit fail-CLOSED: emit BEFORE returning success; emit-failure
//!   propagates as 500.
//! - All public enums are `#[non_exhaustive]`.
//! - Idempotency token comparison via direct BLAKE3 32-byte equality;
//!   signature HMAC compare is constant-time via `subtle` (see
//!   `webhook::verify_webhook_signature`).
//! - PCI DSS SAQ-A error envelope: 401 (signature) / 422 (envelope) /
//!   500 (backend) / 200 (success or duplicate) per
//!   `compliance_matrix.md`.

use core::fmt;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::dlq::{WebhookDlqRow, WebhookDlqStore};
use crate::error::WebhookVerifyError;
use crate::webhook::{verify_webhook_signature, DEFAULT_TOLERANCE_SECONDS};

// =========================================================================
// Wave-36 Trigger A: re-export the trait + type surface from the leaf
// `corelink-billing-stripe-traits` crate. Preserves the canonical
// `corelink_stripe_real::webhook_dispatch::*` public paths.
// =========================================================================

pub use corelink_billing_stripe_traits::{
    AuditEmitter, AuditOutcome, AuditRecord, CanonicalWebhookEventType, DispatchResponse,
    DurableWebhookEvent, DurableWebhookInbox, DurableWebhookRequestContext, EffectReservation,
    IdempotencyOutcome, IdempotencyStore, IdempotencyToken, InboxClaim, InboxEffect,
    InboxReceiveOutcome, InboxTerminalState, MaterializerError, SliObservation, SliRecorder,
    StateMaterializer, StripeWebhookEnvelope, SLI_BILLING_STRIPE_EVENT_SECONDS,
};

// =========================================================================
// Idempotency in-memory fake (concrete adapter; trait def is upstream).
// =========================================================================

/// Internal row stored alongside each dedup token (event-type +
/// insertion timestamp). Kept private so the in-memory map type
/// alias factors cleanly past clippy::type_complexity.
type IdempotencyRow = (CanonicalWebhookEventType, u64);

/// Default in-memory store (D1 mirror; same `INSERT OR IGNORE` semantics).
#[derive(Clone, Debug, Default)]
pub struct InMemoryIdempotencyStore {
    seen: Arc<Mutex<std::collections::HashMap<[u8; 32], IdempotencyRow>>>,
}

impl InMemoryIdempotencyStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct tokens currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.seen.lock() {
            Ok(g) => g.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    /// `true` iff no events have been stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IdempotencyStore for InMemoryIdempotencyStore {
    fn try_insert(
        &self,
        token: IdempotencyToken,
        event_type: CanonicalWebhookEventType,
        now_ms: u64,
    ) -> Result<IdempotencyOutcome, String> {
        let mut g = self
            .seen
            .lock()
            .map_err(|e| format!("mutex poisoned: {e}"))?;
        if g.contains_key(token.as_bytes()) {
            Ok(IdempotencyOutcome::AlreadyProcessed)
        } else {
            g.insert(*token.as_bytes(), (event_type, now_ms));
            Ok(IdempotencyOutcome::FirstSight)
        }
    }
}

// =========================================================================
// State materializer test-only recorder (concrete fake; trait def is upstream).
// =========================================================================

/// Test-only recorder. Stores `(event_type, event_id)` per call so
/// the integration test can assert the right method fired for the
/// right event. Wraps an optional `force_error` to drive the 422/500
/// arms.
#[derive(Clone, Debug, Default)]
pub struct RecordingStateMaterializer {
    calls: Arc<Mutex<Vec<(CanonicalWebhookEventType, String)>>>,
    force_error: Arc<Mutex<Option<MaterializerError>>>,
    force_error_after_record: Arc<Mutex<Option<MaterializerError>>>,
}

impl RecordingStateMaterializer {
    /// Construct an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Force the next call to return `Err(err)`. Cleared after one use.
    pub fn arm_error(&self, err: MaterializerError) {
        if let Ok(mut g) = self.force_error.lock() {
            *g = Some(err);
        }
    }

    /// Force the next call to fail after recording its business mutation.
    pub fn arm_error_after_record(&self, err: MaterializerError) {
        if let Ok(mut g) = self.force_error_after_record.lock() {
            *g = Some(err);
        }
    }

    /// Snapshot recorded calls.
    #[must_use]
    pub fn calls(&self) -> Vec<(CanonicalWebhookEventType, String)> {
        match self.calls.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Count of recorded calls.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls().len()
    }

    fn record(
        &self,
        ty: CanonicalWebhookEventType,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        if let Ok(mut g) = self.force_error.lock() {
            if let Some(err) = g.take() {
                return Err(err);
            }
        }
        let mut g = self
            .calls
            .lock()
            .map_err(|e| MaterializerError::Transient(format!("mutex poisoned: {e}")))?;
        g.push((ty, env.id.clone()));
        drop(g);
        if let Ok(mut g) = self.force_error_after_record.lock() {
            if let Some(err) = g.take() {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl StateMaterializer for RecordingStateMaterializer {
    fn on_subscription_deleted(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::SubscriptionDeleted, env)
    }
    fn on_subscription_updated(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::SubscriptionUpdated, env)
    }
    fn on_invoice_paid(&self, env: &StripeWebhookEnvelope) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::InvoicePaid, env)
    }
    fn on_invoice_payment_failed(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::InvoicePaymentFailed, env)
    }
    fn on_charge_dispute_created(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::ChargeDisputeCreated, env)
    }

    fn on_charge_refunded(&self, env: &StripeWebhookEnvelope) -> Result<(), MaterializerError> {
        self.record(CanonicalWebhookEventType::ChargeRefunded, env)
    }
}

// =========================================================================
// Audit emitter test-only recorder (concrete fake; trait def is upstream).
// =========================================================================

/// Test-only in-memory audit emitter.
#[derive(Clone, Debug, Default)]
pub struct RecordingAuditEmitter {
    records: Arc<Mutex<Vec<AuditRecord>>>,
    /// If set, every `emit` call returns this error (drives fail-CLOSED tests).
    fail_with: Arc<Mutex<Option<String>>>,
}

impl RecordingAuditEmitter {
    /// Construct an empty emitter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Force every emit to fail with `msg`.
    pub fn fail_with(&self, msg: impl Into<String>) {
        if let Ok(mut g) = self.fail_with.lock() {
            *g = Some(msg.into());
        }
    }

    /// Snapshot emitted records.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        match self.records.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Count of records with `outcome`.
    #[must_use]
    pub fn count_with_outcome(&self, outcome: AuditOutcome) -> usize {
        self.records()
            .iter()
            .filter(|r| r.outcome == outcome)
            .count()
    }
}

impl AuditEmitter for RecordingAuditEmitter {
    fn emit(&self, record: &AuditRecord) -> Result<(), String> {
        if let Ok(g) = self.fail_with.lock() {
            if let Some(msg) = g.as_ref() {
                return Err(msg.clone());
            }
        }
        let mut g = self
            .records
            .lock()
            .map_err(|e| format!("mutex poisoned: {e}"))?;
        g.push(record.clone());
        Ok(())
    }
}

// =========================================================================
// SLI recorder (concrete fake; trait def is upstream).
// =========================================================================

/// Test-only recorder.
#[derive(Clone, Debug, Default)]
pub struct RecordingSliRecorder {
    obs: Arc<Mutex<Vec<SliObservation>>>,
}

impl RecordingSliRecorder {
    /// Construct an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot observations.
    #[must_use]
    pub fn observations(&self) -> Vec<SliObservation> {
        match self.obs.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Count observations.
    #[must_use]
    pub fn count(&self) -> usize {
        self.observations().len()
    }
}

impl SliRecorder for RecordingSliRecorder {
    fn observe(&self, obs: SliObservation) {
        if let Ok(mut g) = self.obs.lock() {
            g.push(obs);
        }
    }
}

// =========================================================================
// Time provider abstraction.
// =========================================================================
//
// Wave-20: the `Clock` trait + `SystemClock` impl moved to
// `crate::clock` so production wasm32 callers can inject
// `WasmWorkerClock` (which reads `js_sys::Date::now()` instead of
// panicking on `SystemTime::now()`). The trait + `SystemClock` are
// re-exported below for back-compat with all 51 existing tests and
// downstream callers; the `FixedClock` SLI helper stays here because
// it carries a hard-coded `latency_seconds` value used exclusively
// by webhook-pipeline tests.

pub use crate::clock::Clock;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::clock::SystemClock;

/// Fixed-time test clock; returns `seconds` for now-* queries and a
/// hard-coded `latency_seconds` from `observe_latency_seconds`.
///
/// Distinct from [`crate::clock::InMemoryFakeClock`]: this variant
/// pins the SLI latency to a fixed value (for deterministic SLI
/// histogram assertions in the webhook pipeline tests) rather than
/// computing it from the elapsed delta.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    /// Fixed unix seconds.
    pub seconds: u64,
    /// Latency to report regardless of start marker.
    pub latency_seconds: f64,
}

impl FixedClock {
    /// Construct a fixed clock pinned at `seconds` with `latency` SLI delta.
    #[must_use]
    pub const fn new(seconds: u64, latency_seconds: f64) -> Self {
        Self {
            seconds,
            latency_seconds,
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(self.seconds)
    }
    fn now_seconds(&self) -> u64 {
        self.seconds
    }
    fn now_ms(&self) -> u64 {
        self.seconds.saturating_mul(1_000)
    }
    fn start_marker(&self) -> u64 {
        0
    }
    fn observe_latency_seconds(&self, _start_marker: u64) -> f64 {
        self.latency_seconds
    }
}

// =========================================================================
// Dependency bundle + dispatcher.
// =========================================================================

/// Production dependency bundle. Held as `Arc<Dispatcher>` so axum /
/// hyper / worker-rs / cron callers can clone cheaply per-request.
pub struct WebhookDispatcher {
    /// Webhook signing secret (`whsec_...` raw bytes). NEVER logged.
    webhook_secret: Vec<u8>,
    /// Idempotency dedup store.
    idempotency: Arc<dyn IdempotencyStore>,
    /// State materializer.
    materializer: Arc<dyn StateMaterializer>,
    /// Audit sink.
    audit: Arc<dyn AuditEmitter>,
    /// SLI recorder.
    sli: Arc<dyn SliRecorder>,
    /// Clock.
    clock: Arc<dyn Clock>,
    /// Signature replay tolerance (seconds). Defaults to
    /// [`DEFAULT_TOLERANCE_SECONDS`] (300).
    tolerance_seconds: u64,
    /// Dead-letter quarantine sink (F-008 closure). When wired, a
    /// **transient** materialize failure quarantines the (already
    /// HMAC-verified) event so it is NOT lost: the idempotency dedup
    /// row was committed BEFORE materialize (step 5), so a Stripe retry
    /// hits `AlreadyProcessed` and SKIPS the handler — without this DLQ
    /// the state change would be permanently dropped while Stripe
    /// records success. With the DLQ wired the event is operator-replayable
    /// (`crates/corelink-stripe-real/src/dlq.rs`). `None` keeps the
    /// legacy behaviour for callers that have not yet provisioned a DLQ
    /// backend (the failure still returns 500 → Stripe retries within
    /// its 3-day window; the quarantine adds durability past that).
    dlq: Option<Arc<dyn WebhookDlqStore>>,
    /// Durable authenticated-event inbox. When present, this supersedes the
    /// legacy pre-effect idempotency marker for this dispatcher instance.
    inbox: Option<Arc<dyn DurableWebhookInbox>>,
}

struct DurableDispatchContext<'a> {
    inbox: &'a Arc<dyn DurableWebhookInbox>,
    body: &'a [u8],
    env: &'a StripeWebhookEnvelope,
    canon: CanonicalWebhookEventType,
    token: &'a IdempotencyToken,
    now_ms: u64,
    start: u64,
    request_context: Option<&'a dyn corelink_billing_stripe_traits::DurableWebhookRequestContext>,
}

impl fmt::Debug for WebhookDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDispatcher")
            .field("webhook_secret", &"<redacted>")
            .field("tolerance_seconds", &self.tolerance_seconds)
            .field("idempotency", &self.idempotency)
            .field("materializer", &self.materializer)
            .field("audit", &self.audit)
            .field("sli", &self.sli)
            .field("clock", &self.clock)
            .field("dlq", &self.dlq)
            .field("inbox", &self.inbox)
            .finish()
    }
}

impl WebhookDispatcher {
    /// Construct a dispatcher with the canonical 5-min replay tolerance.
    #[must_use]
    pub fn new(
        webhook_secret: Vec<u8>,
        idempotency: Arc<dyn IdempotencyStore>,
        materializer: Arc<dyn StateMaterializer>,
        audit: Arc<dyn AuditEmitter>,
        sli: Arc<dyn SliRecorder>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            webhook_secret,
            idempotency,
            materializer,
            audit,
            sli,
            clock,
            tolerance_seconds: DEFAULT_TOLERANCE_SECONDS,
            dlq: None,
            inbox: None,
        }
    }

    /// Override the signature replay tolerance (seconds). Tests use
    /// this to drive the future-dated arm.
    #[must_use]
    pub const fn with_tolerance_seconds(mut self, tolerance_seconds: u64) -> Self {
        self.tolerance_seconds = tolerance_seconds;
        self
    }

    /// Wire a dead-letter quarantine sink (F-008 closure).
    ///
    /// On a **transient** materialize failure the dispatcher will
    /// quarantine the (already HMAC-verified) event into `dlq` so the
    /// state change is recoverable even though the idempotency dedup row
    /// was already committed (a Stripe retry would otherwise hit
    /// `AlreadyProcessed` and silently skip the handler). Production
    /// wires the canonical D1-backed store; tests inject the in-memory
    /// fake.
    #[must_use]
    pub fn with_dlq(mut self, dlq: Arc<dyn WebhookDlqStore>) -> Self {
        self.dlq = Some(dlq);
        self
    }

    /// Wire durable receive/claim/fence ownership for authenticated events.
    #[must_use]
    pub fn with_durable_inbox(mut self, inbox: Arc<dyn DurableWebhookInbox>) -> Self {
        self.inbox = Some(inbox);
        self
    }

    /// Process one Stripe webhook delivery.
    ///
    /// Arguments:
    /// - `body` — exact raw bytes Stripe POSTed (BEFORE any JSON parse).
    ///   Signature verifies over these bytes, not over a re-serialized
    ///   form.
    /// - `signature_header` — `Stripe-Signature` HTTP header value (or
    ///   `None` if the header was missing/non-ascii — yields
    ///   [`DispatchResponse::BadRequest400`]).
    pub fn process(&self, body: &[u8], signature_header: Option<&str>) -> DispatchResponse {
        self.process_with_context(body, signature_header, None)
    }

    /// Process one Stripe delivery while carrying optional request authority to
    /// the durable inbox.
    ///
    /// The dispatcher never interprets this opaque value. It is retained only
    /// for the D1 inbox boundary, preserving request isolation across every
    /// shared dispatcher call.
    pub fn process_with_context(
        &self,
        body: &[u8],
        signature_header: Option<&str>,
        request_context: Option<&dyn corelink_billing_stripe_traits::DurableWebhookRequestContext>,
    ) -> DispatchResponse {
        let start = self.clock.start_marker();
        let now_seconds = self.clock.now_seconds();
        let now_ms = self.clock.now_ms();
        if request_context.is_some() && self.inbox.is_none() {
            return DispatchResponse::InternalError500;
        }
        let emit_audit = |record, event_type, outcome, start_marker| {
            self.emit_audit_and_sli_with_context(
                record,
                event_type,
                outcome,
                start_marker,
                request_context,
            )
        };

        // (1) Header present?
        let Some(sig_header) = signature_header else {
            emit_audit(
                AuditRecord::new(
                    "corelink.billing.stripe_event_processed.v1",
                    String::new(),
                    CanonicalWebhookEventType::Unknown,
                    AuditOutcome::SignatureInvalid,
                    None,
                    now_ms,
                    Some("missing or non-ascii Stripe-Signature header".to_string()),
                ),
                CanonicalWebhookEventType::Unknown,
                AuditOutcome::SignatureInvalid,
                start,
            );
            return DispatchResponse::BadRequest400;
        };

        // (2) Verify signature over EXACT bytes.
        if let Err(e) = verify_webhook_signature(
            body,
            sig_header,
            &self.webhook_secret,
            now_seconds,
            self.tolerance_seconds,
        ) {
            emit_audit(
                AuditRecord::new(
                    "corelink.billing.stripe_event_processed.v1",
                    String::new(),
                    CanonicalWebhookEventType::Unknown,
                    AuditOutcome::SignatureInvalid,
                    None,
                    now_ms,
                    Some(classify_verify_err(&e).to_string()),
                ),
                CanonicalWebhookEventType::Unknown,
                AuditOutcome::SignatureInvalid,
                start,
            );
            return DispatchResponse::Unauthorized401;
        }

        // (3) Parse envelope (ONLY after sig verify).
        let env: StripeWebhookEnvelope = match serde_json::from_slice(body) {
            Ok(e) => e,
            Err(e) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        String::new(),
                        CanonicalWebhookEventType::Unknown,
                        AuditOutcome::EnvelopeInvalid,
                        None,
                        now_ms,
                        Some(format!("json parse: {e}")),
                    ),
                    CanonicalWebhookEventType::Unknown,
                    AuditOutcome::EnvelopeInvalid,
                    start,
                );
                return DispatchResponse::Unprocessable422;
            }
        };

        // (4) Derive BLAKE3 idempotency token from event id.
        let token = IdempotencyToken::from_event_id(&env.id);
        let canon = CanonicalWebhookEventType::classify(&env.event_type);

        if let Some(inbox) = self.inbox.as_ref() {
            return self.process_durable(DurableDispatchContext {
                inbox,
                body,
                env: &env,
                canon,
                token: &token,
                now_ms,
                start,
                request_context,
            });
        }
        // (5) Idempotency dedup.
        match self.idempotency.try_insert(token, canon, now_ms) {
            Ok(IdempotencyOutcome::AlreadyProcessed) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::Duplicate,
                        Some(token.to_hex()),
                        now_ms,
                        None,
                    ),
                    canon,
                    AuditOutcome::Duplicate,
                    start,
                );
                return DispatchResponse::Ok200;
            }
            Ok(IdempotencyOutcome::FirstSight) => {} // proceed
            // `IdempotencyOutcome` is `#[non_exhaustive]` from the
            // upstream `corelink-billing-stripe-traits` crate; treat
            // any future variant conservatively as "proceed".
            Ok(_) => {}
            Err(e) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::MaterializerFailed,
                        Some(token.to_hex()),
                        now_ms,
                        Some(format!("idempotency store: {e}")),
                    ),
                    canon,
                    AuditOutcome::MaterializerFailed,
                    start,
                );
                return DispatchResponse::InternalError500;
            }
        }

        // (6) Dispatch.
        let dispatch_result = match canon {
            CanonicalWebhookEventType::SubscriptionDeleted => self
                .materializer
                .on_subscription_deleted_with_context(&env, request_context),
            CanonicalWebhookEventType::SubscriptionUpdated => self
                .materializer
                .on_subscription_updated_with_context(&env, request_context),
            CanonicalWebhookEventType::InvoicePaid => self
                .materializer
                .on_invoice_paid_with_context(&env, request_context),
            CanonicalWebhookEventType::InvoicePaymentFailed => self
                .materializer
                .on_invoice_payment_failed_with_context(&env, request_context),
            CanonicalWebhookEventType::ChargeDisputeCreated => self
                .materializer
                .on_charge_dispute_created_with_context(&env, request_context),
            // Refunds are a durable state transition when Stripe reports a
            // complete refund; the materializer still records partial refunds
            // without revoking access.
            CanonicalWebhookEventType::SubscriptionCreated
            | CanonicalWebhookEventType::SubscriptionTrialWillEnd
            | CanonicalWebhookEventType::CustomerCreated
            | CanonicalWebhookEventType::InvoiceCreated => Ok(()),
            CanonicalWebhookEventType::ChargeRefunded => self
                .materializer
                .on_charge_refunded_with_context(&env, request_context),
            CanonicalWebhookEventType::Unknown => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::UnknownEventType,
                        Some(token.to_hex()),
                        now_ms,
                        None,
                    ),
                    canon,
                    AuditOutcome::UnknownEventType,
                    start,
                );
                return DispatchResponse::Ok200;
            }
            // `CanonicalWebhookEventType` is `#[non_exhaustive]` from
            // the upstream traits crate; treat any future variant as
            // an observability-only echo (no state mutation).
            _ => Ok(()),
        };

        // (7) Audit + SLI per dispatch outcome.
        match dispatch_result {
            Ok(()) => {
                let resp = emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::Dispatched,
                        Some(token.to_hex()),
                        now_ms,
                        None,
                    ),
                    canon,
                    AuditOutcome::Dispatched,
                    start,
                );
                if resp.is_some() {
                    return DispatchResponse::InternalError500;
                }
                DispatchResponse::Ok200
            }
            Err(MaterializerError::Transient(msg)) => {
                // F-008 closure: the idempotency dedup row was committed
                // at step 5 BEFORE this materialize. A Stripe retry would
                // therefore hit `AlreadyProcessed` and SKIP the handler —
                // permanently dropping the state change while Stripe
                // records success. Quarantine the (already HMAC-verified)
                // event into the DLQ so it is operator-replayable rather
                // than lost. Best-effort: a DLQ backend failure must NOT
                // mask the 500 (Stripe still retries within its window).
                self.quarantine_transient(body, &env, canon, &token, &msg, now_ms);
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::MaterializerFailed,
                        Some(token.to_hex()),
                        now_ms,
                        Some(msg),
                    ),
                    canon,
                    AuditOutcome::MaterializerFailed,
                    start,
                );
                DispatchResponse::InternalError500
            }
            Err(MaterializerError::InvalidPayload(msg)) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::MaterializerInvalid,
                        Some(token.to_hex()),
                        now_ms,
                        Some(msg.clone()),
                    ),
                    canon,
                    AuditOutcome::MaterializerInvalid,
                    start,
                );
                // F-MP-2 (go-live audit): QUARANTINE the InvalidPayload event,
                // not just Transient. A 422 from price-map/config drift (e.g. a
                // `team` price the container can't map, or a future Stripe API
                // shape change) is otherwise SILENTLY dropped — Stripe stops
                // retrying on 4xx and the entitlement reconcile is lost with no
                // operator signal. The DLQ (depth/age alerting) makes it
                // observable + replayable. The dedup row is already committed, so
                // replay-from-DLQ is the recovery path. Genuinely-malformed garbage
                // also lands here, but a visible quarantine beats a silent loss.
                self.quarantine_transient(body, &env, canon, &token, &msg, now_ms);
                DispatchResponse::Unprocessable422
            }
            Err(MaterializerError::AppliedButUnconfirmed(msg)) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::MaterializerFailed,
                        Some(token.to_hex()),
                        now_ms,
                        Some(msg),
                    ),
                    canon,
                    AuditOutcome::MaterializerFailed,
                    start,
                );
                DispatchResponse::InternalError500
            }
            // `MaterializerError` is `#[non_exhaustive]` in the leaf traits
            // crate; treat any future variants as transient so the
            // dispatcher returns 500 (Stripe retries) rather than panicking.
            Err(_) => {
                // Same lost-event hazard as the explicit `Transient` arm
                // (the dedup row is already committed) — quarantine too.
                let msg = "unknown materializer error variant".to_string();
                self.quarantine_transient(body, &env, canon, &token, &msg, now_ms);
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        env.id.clone(),
                        canon,
                        AuditOutcome::MaterializerFailed,
                        Some(token.to_hex()),
                        now_ms,
                        Some(msg),
                    ),
                    canon,
                    AuditOutcome::MaterializerFailed,
                    start,
                );
                DispatchResponse::InternalError500
            }
        }
    }

    fn process_durable(&self, context: DurableDispatchContext<'_>) -> DispatchResponse {
        const OWNER: &str = "stripe-webhook-dispatcher";
        let emit_audit = |record, event_type, outcome, start_marker| {
            self.emit_audit_and_sli_with_context(
                record,
                event_type,
                outcome,
                start_marker,
                context.request_context,
            )
        };
        let event = DurableWebhookEvent {
            event_id: context.env.id.clone(),
            event_type: context.canon.label().to_owned(),
            raw_body_hex: hex::encode(context.body),
            payload_sha256: hex::encode(Sha256::digest(context.body)),
            stripe_created_at_ms: context.env.created.saturating_mul(1_000),
        };
        match context
            .inbox
            .receive_with_context(&event, context.now_ms, context.request_context)
        {
            Ok(InboxReceiveOutcome::Terminal) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        context.env.id.clone(),
                        context.canon,
                        AuditOutcome::Duplicate,
                        Some(context.token.to_hex()),
                        context.now_ms,
                        None,
                    ),
                    context.canon,
                    AuditOutcome::Duplicate,
                    context.start,
                );
                return DispatchResponse::Ok200;
            }
            Ok(InboxReceiveOutcome::LegacyAmbiguous) => {
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        context.env.id.clone(),
                        context.canon,
                        AuditOutcome::MaterializerFailed,
                        Some(context.token.to_hex()),
                        context.now_ms,
                        Some("legacy ambiguous inbox row requires reconciliation".to_owned()),
                    ),
                    context.canon,
                    AuditOutcome::MaterializerFailed,
                    context.start,
                );
                return DispatchResponse::InternalError500;
            }
            Ok(InboxReceiveOutcome::Received) => {}
            Err(_) => return DispatchResponse::InternalError500,
        }
        let claim = match context
            .inbox
            .claim(&context.env.id, OWNER, context.now_ms, 30_000)
        {
            Ok(Some(claim)) => claim,
            Ok(None) | Err(_) => return DispatchResponse::InternalError500,
        };
        let effect_key = format!("stripe-webhook-effect:{}", context.token.to_hex());
        let effect = InboxEffect::new(
            &claim,
            OWNER,
            &event,
            &effect_key,
            context.canon.label(),
            context.now_ms,
        );
        match context
            .inbox
            .reserve_effect_with_context(effect, context.request_context)
        {
            Ok(EffectReservation::Reserved) => {}
            Ok(EffectReservation::Applied) => {
                return if matches!(
                    context.inbox.finish(
                        &claim,
                        OWNER,
                        InboxTerminalState::Completed,
                        None,
                        context.now_ms,
                    ),
                    Ok(true)
                ) {
                    DispatchResponse::Ok200
                } else {
                    DispatchResponse::InternalError500
                };
            }
            Ok(EffectReservation::PendingRecovery) | Err(_) => {
                return DispatchResponse::InternalError500;
            }
        }
        let dispatch_result = match context.canon {
            CanonicalWebhookEventType::SubscriptionDeleted => self
                .materializer
                .on_subscription_deleted_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::SubscriptionUpdated => self
                .materializer
                .on_subscription_updated_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::InvoicePaid => self
                .materializer
                .on_invoice_paid_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::InvoicePaymentFailed => self
                .materializer
                .on_invoice_payment_failed_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::ChargeDisputeCreated => self
                .materializer
                .on_charge_dispute_created_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::ChargeRefunded => self
                .materializer
                .on_charge_refunded_with_context(context.env, context.request_context),
            CanonicalWebhookEventType::SubscriptionCreated
            | CanonicalWebhookEventType::SubscriptionTrialWillEnd
            | CanonicalWebhookEventType::CustomerCreated
            | CanonicalWebhookEventType::InvoiceCreated
            | CanonicalWebhookEventType::Unknown => Ok(()),
            _ => Ok(()),
        };
        match dispatch_result {
            Ok(()) => {
                let outcome = if context.canon == CanonicalWebhookEventType::Unknown {
                    AuditOutcome::UnknownEventType
                } else {
                    AuditOutcome::Dispatched
                };
                if emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        context.env.id.clone(),
                        context.canon,
                        outcome,
                        Some(context.token.to_hex()),
                        context.now_ms,
                        None,
                    ),
                    context.canon,
                    outcome,
                    context.start,
                )
                .is_some()
                    || !matches!(
                        context
                            .inbox
                            .commit_effect_with_context(effect, context.request_context),
                        Ok(true)
                    )
                {
                    return DispatchResponse::InternalError500;
                }
                DispatchResponse::Ok200
            }
            Err(MaterializerError::AppliedButUnconfirmed(message)) => {
                let sealed = matches!(
                    context
                        .inbox
                        .commit_effect_with_context(effect, context.request_context),
                    Ok(true)
                );
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        context.env.id.clone(),
                        context.canon,
                        AuditOutcome::MaterializerFailed,
                        Some(context.token.to_hex()),
                        context.now_ms,
                        Some(message),
                    ),
                    context.canon,
                    AuditOutcome::MaterializerFailed,
                    context.start,
                );
                let _ = sealed;
                DispatchResponse::InternalError500
            }
            Err(error) => {
                let (outcome, status, message) = match error {
                    MaterializerError::Transient(message) => (
                        AuditOutcome::MaterializerFailed,
                        DispatchResponse::InternalError500,
                        message,
                    ),
                    MaterializerError::InvalidPayload(message) => (
                        AuditOutcome::MaterializerInvalid,
                        DispatchResponse::Unprocessable422,
                        message,
                    ),
                    _ => (
                        AuditOutcome::MaterializerFailed,
                        DispatchResponse::InternalError500,
                        "unknown materializer error".to_owned(),
                    ),
                };
                let quarantined = self.quarantine_owned(&context, &claim, &message);
                let _ = context.inbox.abort_reserved_effect(
                    &claim,
                    OWNER,
                    &event,
                    &effect_key,
                    context.canon.label(),
                    context.now_ms,
                );
                emit_audit(
                    AuditRecord::new(
                        "corelink.billing.stripe_event_processed.v1",
                        context.env.id.clone(),
                        context.canon,
                        outcome,
                        Some(context.token.to_hex()),
                        context.now_ms,
                        Some(message),
                    ),
                    context.canon,
                    outcome,
                    context.start,
                );
                if quarantined {
                    status
                } else {
                    DispatchResponse::InternalError500
                }
            }
        }
    }

    fn quarantine_owned(
        &self,
        context: &DurableDispatchContext<'_>,
        claim: &InboxClaim,
        error: &str,
    ) -> bool {
        let Some(dlq) = self.dlq.as_ref() else {
            return false;
        };
        let row = WebhookDlqRow::new_quarantine(
            context.env.id.clone(),
            format!("dlq_{}", blake3::hash(context.env.id.as_bytes()).to_hex()),
            context.canon.label().to_owned(),
            hex::encode(context.body),
            context.token.to_hex(),
            error.to_owned(),
            context.now_ms,
        );
        if dlq.try_quarantine(row).is_err() {
            return false;
        }
        matches!(
            context.inbox.finish(
                claim,
                "stripe-webhook-dispatcher",
                InboxTerminalState::Quarantined,
                Some(error),
                context.now_ms
            ),
            Ok(true)
        )
    }

    /// Quarantine a transiently-failed (but already HMAC-verified)
    /// event into the DLQ (F-008). No-op when no DLQ is wired.
    ///
    /// Best-effort by design: the caller still returns 500 so Stripe
    /// retries within its window; the quarantine is the durable backstop
    /// for the case where the idempotency dedup row (committed at step 5)
    /// causes the retry to short-circuit as `AlreadyProcessed`. A DLQ
    /// backend failure therefore MUST NOT change the HTTP outcome — it is
    /// observed via the DLQ depth/age metrics, not by failing harder here.
    ///
    /// `dlq_row_id` is derived deterministically from the event id
    /// (BLAKE3) so the DLQ store's `ON CONFLICT (event_id)` idempotency
    /// keeps a stable row identity across re-quarantines (no `uuid`
    /// dependency in this wasm32-safe crate).
    fn quarantine_transient(
        &self,
        body: &[u8],
        env: &StripeWebhookEnvelope,
        canon: CanonicalWebhookEventType,
        token: &IdempotencyToken,
        last_error: &str,
        now_ms: u64,
    ) {
        let Some(dlq) = self.dlq.as_ref() else {
            return;
        };
        let dlq_row_id = format!("dlq_{}", blake3::hash(env.id.as_bytes()).to_hex());
        let row = WebhookDlqRow::new_quarantine(
            env.id.clone(),
            dlq_row_id,
            canon.label().to_string(),
            hex::encode(body),
            // Correlation id = idempotency token hex (ties the DLQ row to
            // the `*_processed.v1` audit record carrying the same token).
            token.to_hex(),
            last_error.to_string(),
            now_ms,
        );
        // Best-effort: drop the error (the 500 already drives Stripe's
        // retry; DLQ-backend health is surfaced via its own metrics).
        let _ = dlq.try_quarantine(row);
    }

    /// Emit one audit row + one SLI observation under the request's ownership
    /// context. Returns `Some(audit_err)` iff the audit emit failed (caller
    /// maps to 500).
    fn emit_audit_and_sli_with_context(
        &self,
        record: AuditRecord,
        event_type: CanonicalWebhookEventType,
        outcome: AuditOutcome,
        start_marker: u64,
        request_context: Option<&dyn corelink_billing_stripe_traits::DurableWebhookRequestContext>,
    ) -> Option<String> {
        let audit_err = self.audit.emit_with_context(&record, request_context).err();
        self.sli.observe(SliObservation::new(
            SLI_BILLING_STRIPE_EVENT_SECONDS,
            self.clock.observe_latency_seconds(start_marker),
            event_type,
            outcome,
        ));
        audit_err
    }
}

/// Map a verify error to a short label string (NEVER logs body/secret).
fn classify_verify_err(e: &WebhookVerifyError) -> &'static str {
    match e {
        WebhookVerifyError::MalformedHeader(_) => "malformed_header",
        WebhookVerifyError::ReplayWindowExceeded { .. } => "replay_window_exceeded",
        WebhookVerifyError::FutureDated { .. } => "future_dated",
        WebhookVerifyError::SignatureMismatch => "signature_mismatch",
        WebhookVerifyError::HexDecode(_) => "hex_decode",
    }
}

// =========================================================================
// Inline unit tests (sig+dedup+dispatch coverage).
// =========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed these primitives"
)]
#[path = "tests.rs"]
mod tests;
