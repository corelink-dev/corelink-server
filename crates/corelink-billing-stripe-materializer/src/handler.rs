//! Production [`StateMaterializer`] implementation
//! ([`D1SubscriptionStateHandler`]).
//!
//! Drives [`BillingD1Writer`] + [`BillingAuditEmitter`] +
//! [`TierSelector`] for the five **state-mutating** canonical Stripe
//! events. The five observability-only echoes
//! (`customer.subscription.created`, `customer.subscription.trial_will_end`,
//! `charge.refunded`, `customer.created`, `invoice.created`) are
//! materialised here too via the `echo_*`-style entry points the
//! dispatcher does NOT route — instead the handler exposes a
//! [`D1SubscriptionStateHandler::materialize_echo`] entry that the
//! integration harness drives directly. This keeps the trait surface
//! 1:1 with the dispatcher's `StateMaterializer` (five methods) while
//! still allowing the e2e suite to pin all 10 event types.
//!
//! # Audit ordering (fail-CLOSED)
//!
//! Every state mutation goes through this exact sequence:
//!
//! 1. **Emit billing audit** (`corelink.billing.<event>.materialized.v1`).
//!    If this fails, the materializer returns
//!    `MaterializerError::Transient(...)` — the D1 write is **not**
//!    performed (orphan-state-free).
//! 2. **Perform D1 write.** If this fails, return `Transient` or
//!    `InvalidPayload` per the underlying writer error.
//! 3. **(subscription.updated only)** Recompute tier; if changed,
//!    persist new tier + emit `corelink.tenant.tier_changed.v1`. If
//!    the tier-emit fails after the D1 write succeeded, that is a
//!    transient error → dispatcher returns 500 → Stripe retries →
//!    next delivery hits the dedup row → no re-mutation.

use std::fmt;
use std::sync::{Arc, Mutex};

// Wave-36 Trigger A: trait + type surface migrated to the leaf
// `corelink-billing-stripe-traits` crate (no `corelink-stripe-real`
// dep in production sources of the materializer).
use corelink_billing_stripe_traits::{
    CanonicalWebhookEventType, DurableWebhookRequestContext, MaterializerError, StateMaterializer,
    StripeWebhookEnvelope,
};
use corelink_tier_selection::tier::TierKind;

use crate::audit::{AuditSeverity, BillingAuditEmitter, BillingAuditError, BillingAuditRecord};
use crate::clock::{default_mat_clock, MatClock};
use crate::current_subscription::CurrentSubscriptionAuthority;
use crate::d1::{
    BillingD1Error, BillingD1Writer, EntitlementCasOutcome, MaterializedRow,
    RunnerEntitlementRevision,
};
use crate::runners::RunnersEntitlementResolver;
use crate::tier::{TierSelectError, TierSelector};

/// The canonical 10-event × table × audit-event-name matrix.
///
/// Surface-stable for the audit-doc auto-generation step + the
/// regression test in `materializers_e2e.rs`. Each entry is
/// `(stripe_event_type, d1_table_or_none, audit_event_name)`.
pub const EVENT_MATERIALIZATION_MATRIX: &[(&str, Option<&str>, &str)] = &[
    // 5 state mutators ↓
    (
        "customer.subscription.deleted",
        Some("stripe_subscriptions"),
        "corelink.billing.subscription_canceled.materialized.v1",
    ),
    (
        "customer.subscription.updated",
        Some("stripe_subscriptions"),
        "corelink.billing.subscription.materialized.v1",
    ),
    (
        "invoice.paid",
        Some("stripe_invoices"),
        "corelink.billing.invoice.materialized.v1",
    ),
    (
        "invoice.payment_failed",
        Some("stripe_invoices"),
        "corelink.billing.invoice.materialized.v1",
    ),
    (
        "charge.dispute.created",
        Some("stripe_disputes"),
        "corelink.billing.dispute.materialized.v1",
    ),
    // 5 observability echoes ↓ (3 with table writes, 2 without)
    (
        "customer.subscription.created",
        Some("stripe_subscriptions"),
        "corelink.billing.subscription.materialized.v1",
    ),
    (
        "customer.subscription.trial_will_end",
        None,
        "corelink.billing.echo.v1",
    ),
    (
        "charge.refunded",
        Some("stripe_refunds"),
        "corelink.billing.refund.materialized.v1",
    ),
    (
        "customer.created",
        Some("stripe_customers"),
        "corelink.billing.customer.materialized.v1",
    ),
    ("invoice.created", None, "corelink.billing.echo.v1"),
];

/// Materializer error → dispatcher error conversion.
fn d1_to_mat(e: BillingD1Error) -> MaterializerError {
    match e {
        BillingD1Error::Transient(s) => MaterializerError::Transient(s),
        BillingD1Error::InvalidPayload(s) => MaterializerError::InvalidPayload(s),
    }
}

fn audit_to_mat(e: BillingAuditError) -> MaterializerError {
    MaterializerError::Transient(format!("audit fail-CLOSED: {e}"))
}

fn tier_to_mat(e: TierSelectError) -> MaterializerError {
    match e {
        TierSelectError::UnknownPlan(s) => MaterializerError::InvalidPayload(s),
        TierSelectError::Transient(s) => MaterializerError::Transient(s),
    }
}

/// Whether a Stripe subscription `status` is one this container materializer is
/// allowed to GRANT entitlement on. Mirrors the signup-worker's
/// `subscriptionStatusGrantsAccess` (`apps/signup-worker/src/webhooks/stripe.ts`):
/// ONLY `active` and `trialing` qualify. Fail-safe: an unknown/absent status is
/// treated as NOT grantable.
///
/// IMPORTANT — on a `customer.subscription.updated`, this status-gated path is
/// GRANT-ONLY: a non-granting status (`past_due`, `unpaid`, `incomplete`,
/// `incomplete_expired`, `paused`, `disputed`, unknown/absent) is NOT downgraded
/// here — the entitlement write is simply skipped. Active access DOWNGRADE on
/// those payment statuses is the signup-worker's responsibility — it is the
/// authoritative writer that flips the `subscription_state` gate off (see the
/// inline note in `reconcile_tier`). (Explicit `customer.subscription.deleted`
/// is handled separately and DOES downgrade to Free.) This gate is the
/// defense-in-depth guard that stops the container materializer (a SECOND writer
/// of `subscription_state`) from (re-)granting `subscription_state='active'` on
/// an `updated` event carrying a recognized plan but a non-granting status.
fn subscription_status_grants_access(status: &str) -> bool {
    matches!(status, "active" | "trialing")
}

/// Stripe's signed event creation time is the revision for one subscription.
/// A local wall clock or price identifier cannot establish provider order.
fn event_created_at_ms(env: &StripeWebhookEnvelope) -> Result<u64, MaterializerError> {
    env.created
        .checked_mul(1_000)
        .filter(|created_at_ms| *created_at_ms > 0)
        .ok_or_else(|| {
            MaterializerError::InvalidPayload("missing Stripe event created timestamp".to_owned())
        })
}

/// Extract the subscription's price/plan id, tolerant to Stripe API-version
/// shape (F-MP-3, go-live audit): prefer the legacy `data.object.plan.id`, fall
/// back to the modern `data.object.items.data[0].price.id`. Both the cache-tier
/// and Runners reconcile use this so a pinned-API-version change (which can drop
/// the legacy `plan.id`) doesn't 422 every subscription event.
fn extract_plan_id(env: &StripeWebhookEnvelope) -> Option<&str> {
    let obj = env.data.get("object")?;
    obj.get("plan")
        .and_then(|p| p.get("id"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            obj.get("items")
                .and_then(|i| i.get("data"))
                .and_then(|d| d.get(0))
                .and_then(|it| it.get("price"))
                .and_then(|p| p.get("id"))
                .and_then(serde_json::Value::as_str)
        })
}

/// Extract a subscription relationship from an expanded invoice/charge object.
/// This is a Stripe object relationship, not user-controlled metadata.
fn extract_subscription_id(object: &serde_json::Value) -> Option<&str> {
    object
        .get("subscription")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            object
                .get("subscription_details")
                .and_then(|details| details.get("subscription"))
                .and_then(serde_json::Value::as_str)
        })
}

/// Extract the invoice id from a Charge, accepting Stripe's normal string form
/// and an expanded invoice object for replay tooling.
fn extract_invoice_id(object: &serde_json::Value) -> Option<&str> {
    object
        .get("invoice")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            object
                .get("invoice")
                .and_then(|invoice| invoice.get("id"))
                .and_then(serde_json::Value::as_str)
        })
}

/// The subscription relation carried by a refund's Charge, including an
/// expanded invoice used by replay tooling.
fn extract_refund_subscription_id(object: &serde_json::Value) -> Option<&str> {
    extract_subscription_id(object).or_else(|| {
        object
            .get("invoice")
            .and_then(|invoice| extract_subscription_id(invoice))
    })
}

/// Production [`StateMaterializer`] implementation.
pub struct D1SubscriptionStateHandler {
    d1: Arc<dyn BillingD1Writer>,
    audit: Arc<dyn BillingAuditEmitter>,
    tier_selector: Arc<dyn TierSelector>,
    /// Optional Runners-tier entitlement resolver. `None` (default) ⇒ the
    /// Runners seed path is dormant and every subscription is treated as a
    /// cache-tier event (exact pre-existing behavior). Wired via
    /// [`Self::with_runners_resolver`] once the `STRIPE_PRICE_ID_RUNNER_*`
    /// prices exist — env-gated activation, mirroring the cache tier selector.
    runners_resolver: Option<Arc<dyn RunnersEntitlementResolver>>,
    /// Provider read used to make a webhook an idempotent reconciliation trigger
    /// instead of trusting its delivered snapshot.
    runners_authority: Option<Arc<dyn CurrentSubscriptionAuthority>>,
    /// Holds the provider read and the corresponding entitlement mutation in one
    /// local critical section, so two native deliveries cannot finish in reverse
    /// order and let an earlier read overwrite a later reconciliation.
    runners_reconcile_lock: Mutex<()>,
    clock: Arc<dyn MatClock>,
}

impl fmt::Debug for D1SubscriptionStateHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("D1SubscriptionStateHandler")
            .field("d1", &self.d1)
            .field("audit", &self.audit)
            .field("tier_selector", &self.tier_selector)
            .field("runners_resolver", &self.runners_resolver)
            .field("runners_authority", &self.runners_authority)
            .field("clock", &self.clock)
            .finish()
    }
}

impl D1SubscriptionStateHandler {
    /// Construct a new handler wiring `d1` + `audit` + `tier_selector`
    /// behind the canonical production [`MatClock`]
    /// ([`crate::clock::default_mat_clock`]): native targets get
    /// [`crate::clock::SystemMatClock`]; wasm32 targets get
    /// `crate::clock::WasmWorkerMatClock` which reads
    /// `js_sys::Date::now()` (avoiding the
    /// `wasm32-unknown-unknown` `SystemTime::now()` runtime panic per
    /// wave-22 closure of the wave-20 follow-on caveat).
    #[must_use]
    pub fn new(
        d1: Arc<dyn BillingD1Writer>,
        audit: Arc<dyn BillingAuditEmitter>,
        tier_selector: Arc<dyn TierSelector>,
    ) -> Self {
        Self {
            d1,
            audit,
            tier_selector,
            runners_resolver: None,
            runners_authority: None,
            runners_reconcile_lock: Mutex::new(()),
            clock: default_mat_clock(),
        }
    }

    /// Wire a [`RunnersEntitlementResolver`] so a Runners-tier subscription
    /// seeds `runners_entitlement` instead of `tier_selections`. Without it,
    /// the Runners path is dormant (every subscription → cache-tier path).
    #[must_use]
    pub fn with_runners_resolver(mut self, resolver: Arc<dyn RunnersEntitlementResolver>) -> Self {
        self.runners_resolver = Some(resolver);
        self
    }

    /// Wire the provider-authoritative reader required before a Runners
    /// entitlement is changed. Without it, a configured Runners resolver
    /// fails closed rather than deriving entitlement from webhook arrival order.
    #[must_use]
    pub fn with_current_subscription_authority(
        mut self,
        authority: Arc<dyn CurrentSubscriptionAuthority>,
    ) -> Self {
        self.runners_authority = Some(authority);
        self
    }

    /// Inject a custom [`MatClock`] (tests use
    /// [`crate::clock::InMemoryFakeMatClock`] for deterministic
    /// timestamps).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn MatClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Materialize one observability-only echo event. Drives the
    /// same code path the dispatcher takes for state-mutating events
    /// (audit emit + optional D1 write) for the 5 echo arms.
    ///
    /// Returns Ok(()) on the no-table observability arms
    /// (`customer.subscription.trial_will_end`, `invoice.created`)
    /// after emitting only the `corelink.billing.echo.v1` audit row.
    pub fn materialize_echo(
        &self,
        event_type: CanonicalWebhookEventType,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        match event_type {
            CanonicalWebhookEventType::CustomerCreated => self.do_customer_created(env, None),
            CanonicalWebhookEventType::SubscriptionCreated => {
                self.do_subscription_upsert(env, false /* not canceled */, None)
            }
            CanonicalWebhookEventType::ChargeRefunded => self.do_refund(env, None),
            CanonicalWebhookEventType::SubscriptionTrialWillEnd
            | CanonicalWebhookEventType::InvoiceCreated => self.do_pure_echo(event_type, env, None),
            // The five state mutators have dedicated trait methods —
            // drive the typed materializer methods directly so the
            // dispatcher-level routing stays the only seam.
            other => Err(MaterializerError::InvalidPayload(format!(
                "materialize_echo not valid for {other:?}"
            ))),
        }
    }

    // ===== Per-event execution =====

    fn tenant_id_from(&self, env: &StripeWebhookEnvelope) -> Result<String, MaterializerError> {
        // Stripe attaches the tenant id via `metadata.tenant_id` per
        // the `corelink-tier-selection` checkout-session contract. We
        // tolerate both the canonical location and the legacy top-level
        // `tenant_id` echo (some webhook fixtures include it as a sibling
        // of `data.object` for replay convenience).
        let from_metadata = env
            .data
            .get("object")
            .and_then(|o| o.get("metadata"))
            .and_then(|m| m.get("tenant_id"))
            .and_then(|v| v.as_str());
        let from_envelope = env.data.get("tenant_id").and_then(|v| v.as_str());
        from_metadata
            .or(from_envelope)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                MaterializerError::InvalidPayload(
                    "missing tenant_id (expected at data.object.metadata.tenant_id)".to_string(),
                )
            })
    }

    fn stripe_object_id(&self, env: &StripeWebhookEnvelope) -> Option<String> {
        env.data
            .get("object")
            .and_then(|o| o.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn do_subscription_upsert(
        &self,
        env: &StripeWebhookEnvelope,
        canceled: bool,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let tenant_id = self.tenant_id_from(env)?;
        let sub_id = self.stripe_object_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload("missing data.object.id".to_string())
        })?;
        // WP-J: a missing `status` field on the subscription object must
        // NOT silently become "active" (fail-OPEN: would grant paid
        // access with zero signal) NOR "canceled" (fail-OPEN in the
        // OTHER direction: would deny a paying customer). The Stripe
        // Subscription API always sends a status on the canonical
        // events the dispatcher routes here (`customer.subscription.*`);
        // an absent status is a signal integrity problem (proxy
        // truncating the body, a beta endpoint shipping a partial
        // payload, an attacker probing the dispatcher) and we fail
        // CLOSED on the write — the audit/observability line below is
        // the operational signal a SRE needs to find the cause. The
        // sibling `materialize_customer` (which is the FIRST write
        // path for any subscription) does the same on its own status
        // field.
        let status = env
            .data
            .get("object")
            .and_then(|o| o.get("status"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(status) = status else {
            tracing::warn!(
                event = "subscription_status_missing",
                tenant_id = %tenant_id,
                stripe_subscription_id = %sub_id,
                canceled = canceled,
                "Stripe subscription object arrived with no `status` \
                 field — refusing to write a fabricated value. The \
                 downstream gate `subscription_status_grants_access` \
                 would have granted paid access on 'active' (fail-OPEN). \
                 The dispatcher's signature-verify already passed; this \
                 is a payload integrity problem, not an authz one. \
                 Operator action: inspect the upstream payload."
            );
            // Err, NOT Ok. `Ok(())` reads as "dispatched successfully" to
            // `webhook_dispatch`: it audits `Dispatched`, answers 200, and
            // quarantines nothing. Meanwhile the idempotency dedup row was
            // already committed BEFORE this materialize, so a Stripe retry
            // hits `AlreadyProcessed` and skips the handler entirely — the
            // event would be gone for good, with the audit trail asserting
            // it succeeded. `InvalidPayload` is the arm that already exists
            // for exactly this: it audits `MaterializerInvalid` and
            // QUARANTINES the (HMAC-verified) event into the DLQ, which has
            // depth/age alerting, so an operator can replay it. Refusing the
            // write and losing the event are not the same outcome, and only
            // the first one is what this fix wanted.
            return Err(MaterializerError::InvalidPayload(format!(
                "subscription {sub_id} arrived with no `status` field"
            )));
        };
        let event_price_id = extract_plan_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload(
                "missing data.object.plan.id / items.data[].price.id (required for subscription axis routing)"
                    .to_string(),
            )
        })?;
        // Resolve the provider snapshot before writing the subscription row or
        // choosing the Runner/cache axis. The webhook's product and status are
        // delivery data only; a stale cache-shaped event must not downgrade a
        // currently Runner subscription.
        let _runner_guard = self
            .runners_resolver
            .as_ref()
            .map(|_| {
                self.runners_reconcile_lock.lock().map_err(|e| {
                    MaterializerError::Transient(format!(
                        "Runners reconciliation lock poisoned: {e}"
                    ))
                })
            })
            .transpose()?;
        let current = self.current_subscription(&sub_id)?;

        let audit_name = if canceled {
            "corelink.billing.subscription_canceled.materialized.v1"
        } else {
            "corelink.billing.subscription.materialized.v1"
        };

        let now_ms = self.clock.now_ms();

        // 1) Audit BEFORE state mutation (fail-CLOSED).
        let payload = serde_json::json!({
            "stripe_event_type": env.event_type,
            "stripe_subscription_id": sub_id,
            "status": status,
            "provider_current": current,
        });
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: audit_name,
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.clone(),
                    stripe_object_id: Some(sub_id.clone()),
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: payload.clone(),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        // 2) D1 write.
        let row = MaterializedRow {
            table: "stripe_subscriptions".to_string(),
            tenant_id: tenant_id.clone(),
            stripe_id: sub_id.clone(),
            stripe_event_id: env.id.clone(),
            payload,
            materialized_at_ms: now_ms,
        };
        if canceled && current.is_none() {
            self.d1.mark_subscription_canceled(row).map_err(d1_to_mat)?;
        } else {
            self.d1.upsert_subscription(row).map_err(d1_to_mat)?;
        }

        // 3) Entitlement reconciliation (the *.updated and *.deleted arms). Route
        // by PRODUCT: a Runners-tier price seeds/revokes `runners_entitlement`;
        // any other price reconciles the cache `tier_selections`.
        // `reconcile_runners` returns Ok(true) when it HANDLED a Runners price (so
        // we must NOT also run the cache path — a Runners price is not a cache
        // tier and would 422 UnknownPlan there); Ok(false) when the resolver is
        // dormant or the price is not a Runners price ⇒ fall through to the cache
        // path (exact pre-existing behavior).
        //
        // The SAME mutual-exclusion routing applies to BOTH the `updated` and the
        // `deleted` arms: on a runner-price subscription that goes non-granting
        // (`updated` with `past_due`/`unpaid`/`canceled`/…) OR is
        // `customer.subscription.deleted`, `reconcile_runners` REVOKES the
        // entitlement (symmetric to how it seeds) rather than leaving it stale;
        // in either handled case the caller skips the cache reconcile/downgrade.
        let is_runner_reconcile_event = matches!(
            env.event_type.as_str(),
            "customer.subscription.created"
                | "customer.subscription.updated"
                | "customer.subscription.deleted"
        );
        if is_runner_reconcile_event {
            let runners_handled = self.reconcile_runners(
                env,
                &tenant_id,
                &sub_id,
                event_price_id,
                current.as_deref(),
                now_ms,
                request_context,
            )?;
            if env.event_type == "customer.subscription.updated" && !runners_handled {
                self.reconcile_tier(env, &tenant_id, &status, now_ms, request_context)?;
            } else if canceled && !runners_handled {
                // `customer.subscription.deleted`. If the price is a Runners price,
                // `reconcile_runners` revokes `runners_entitlement` (the `canceled`
                // status is non-granting → revoke branch) and returns Ok(true), so we
                // must NOT then run the cache downgrade (a Runners price is not a
                // cache tier). Otherwise fall through to the cache-tier downgrade.
                // On cancel, downgrade tenant to Free (per dispatcher contract —
                // `customer.subscription.deleted` → "downgrade to Free tier").
                // Emit audit if the downgrade is a real change. This uses the
                // dedicated DOWNGRADE path, which writes
                // `subscription_state='inactive'` (the access gate OFF) — NOT the
                // grant path's 'active' — so a canceled tenant never lands a
                // contradictory active-free row (the signup-worker is the primary
                // downgrade authority; this is the container's defense-in-depth
                // convergent write).
                self.persist_tier_downgrade(
                    &tenant_id,
                    TierKind::Free,
                    env,
                    now_ms,
                    request_context,
                )?;
            }
        }

        Ok(())
    }

    fn current_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<Vec<crate::CurrentSubscription>>, MaterializerError> {
        let Some(_resolver) = self.runners_resolver.as_ref() else {
            return Ok(None);
        };
        let authority = self.runners_authority.as_ref().ok_or_else(|| {
            MaterializerError::Transient(
                "Runners entitlement authority is unavailable; refusing webhook snapshot"
                    .to_owned(),
            )
        })?;
        let current = authority
            .current_customer_subscriptions(subscription_id)
            .map_err(|e| {
                MaterializerError::Transient(format!(
                    "Runners entitlement authority unavailable for {subscription_id}: {e}"
                ))
            })?;
        Ok(Some(current))
    }

    /// Reconcile `runners_entitlement` when the subscription's plan is a
    /// Runners-tier price. Returns `Ok(true)` when it WAS a Runners price
    /// (handled — the caller must not also run the cache-tier reconcile/downgrade),
    /// `Ok(false)` when the resolver is dormant or the price is not a Runners price
    /// (caller falls back to the cache path). Status-gated + audit-before-write,
    /// mirroring `reconcile_tier`.
    ///
    /// SYMMETRIC seed/revoke: a granting status (`active`/`trialing`) SEEDS the
    /// entitlement (`corelink.tenant.runners_entitlement_seeded.v1`); a
    /// NON-granting status (`past_due`, `unpaid`, `paused`, `canceled`, unknown —
    /// this includes `customer.subscription.deleted`, whose status is `canceled`)
    /// REVOKES it (`corelink.tenant.runners_entitlement_revoked.v1`) rather than
    /// leaving a permanently-granted stale row. The signup-worker is the primary
    /// authority; this is the container's defense-in-depth convergent write.
    #[allow(clippy::too_many_arguments)] // six reconcile inputs plus the request context (#2660)
    fn reconcile_runners(
        &self,
        env: &StripeWebhookEnvelope,
        tenant_id: &str,
        subscription_id: &str,
        event_price_id: &str,
        current: Option<&[crate::CurrentSubscription]>,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<bool, MaterializerError> {
        let Some(resolver) = self.runners_resolver.as_ref() else {
            return Ok(false); // dormant (no STRIPE_PRICE_ID_RUNNER_* wired)
        };
        let event_is_runner = resolver.resolve(event_price_id).is_some();
        let snapshots = current.ok_or_else(|| {
            MaterializerError::Transient(
                "Runners entitlement authority is unavailable; refusing webhook snapshot"
                    .to_owned(),
            )
        })?;
        let active = snapshots
            .iter()
            .filter(|snapshot| {
                subscription_status_grants_access(&snapshot.status)
                    && resolver.resolve(&snapshot.price_id).is_some()
            })
            .collect::<Vec<_>>();
        let (current, authority_is_current) = match active.as_slice() {
            [current] if current.subscription_id == subscription_id => (*current, true),
            // A cancellation for a replaced predecessor may legitimately resolve
            // to the current successor, which must retain the tenant entitlement.
            // A granting event for a different identity is not sufficient proof
            // that this event's subscription is authoritative, so fail closed.
            [current] if env.event_type == "customer.subscription.deleted" => (*current, true),
            [current] => {
                return Err(MaterializerError::Transient(format!(
                    "Runners entitlement authority returned {} for event subscription {subscription_id}",
                    current.subscription_id
                )));
            }
            [] => {
                let Some(current) = snapshots.iter().find(|snapshot| {
                    snapshot.subscription_id == subscription_id
                        && resolver.resolve(&snapshot.price_id).is_some()
                }) else {
                    if event_is_runner {
                        return Err(MaterializerError::Transient(format!(
                            "Runners entitlement authority has no current Runners identity for {subscription_id}"
                        )));
                    }
                    return Ok(false);
                };
                (current, false)
            }
            _ => {
                return Err(MaterializerError::Transient(format!(
                    "Runners entitlement authority is ambiguous for {subscription_id}"
                )));
            }
        };
        let ent = resolver.resolve(&current.price_id).ok_or_else(|| {
            MaterializerError::Transient(format!(
                "Runners entitlement authority returned non-Runners price {} for {subscription_id}",
                current.price_id
            ))
        })?;
        // It IS a Runners-tier price ⇒ handled (return Ok(true) either way so the
        // caller never falls through to the cache reconcile, which would 422
        // UnknownPlan on a Runners price).
        if !subscription_status_grants_access(&current.status) {
            // Non-granting status (or a `customer.subscription.deleted`, status
            // 'canceled'): REVOKE the entitlement symmetrically to the seed so the
            // container materializer never leaves a stale grant. Audit BEFORE the
            // state mutation (fail-CLOSED ordering), mirroring the seed emit.
            self.audit
                .emit_billing_with_context(
                    &BillingAuditRecord {
                        event_name: "corelink.tenant.runners_entitlement_revoked.v1",
                        stripe_event_id: env.id.clone(),
                        stripe_event_type: env.event_type.clone(),
                        tenant_id: tenant_id.to_string(),
                        stripe_object_id: None,
                        severity: AuditSeverity::Notice,
                        ts_ms: now_ms,
                        payload: serde_json::json!({
                            "status": current.status,
                            "stripe_subscription_id": current.subscription_id,
                        }),
                    },
                    request_context,
                )
                .map_err(audit_to_mat)?;
            self.apply_runner_cas(
                tenant_id,
                RunnerEntitlementRevision {
                    subscription_id: &current.subscription_id,
                    subscription_created_at_ms: current.subscription_created_at_ms,
                    stripe_event_created_at_ms: event_created_at_ms(env)?,
                    stripe_event_id: &env.id,
                    authority_is_current,
                },
                None,
                now_ms,
            )?;
            return Ok(true);
        }
        // Granting status: SEED. Audit BEFORE the state mutation (fail-CLOSED).
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.tenant.runners_entitlement_seeded.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.to_string(),
                    stripe_object_id: None,
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: serde_json::json!({
                        "max_concurrency": ent.max_concurrency,
                        "max_vcpu_h": ent.max_vcpu_h,
                        "stripe_subscription_id": current.subscription_id,
                    }),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;
        self.apply_runner_cas(
            tenant_id,
            RunnerEntitlementRevision {
                subscription_id: &current.subscription_id,
                subscription_created_at_ms: current.subscription_created_at_ms,
                stripe_event_created_at_ms: event_created_at_ms(env)?,
                stripe_event_id: &env.id,
                authority_is_current,
            },
            Some((ent.max_concurrency, ent.max_vcpu_h)),
            now_ms,
        )?;
        Ok(true)
    }

    fn apply_runner_cas(
        &self,
        tenant_id: &str,
        revision: RunnerEntitlementRevision<'_>,
        entitlement: Option<(u32, u32)>,
        now_ms: u64,
    ) -> Result<(), MaterializerError> {
        let outcome = self
            .d1
            .cas_runners_entitlement(tenant_id, revision, entitlement, now_ms as i64)
            .map_err(d1_to_mat)?;
        if outcome == EntitlementCasOutcome::Stale {
            return Err(MaterializerError::Transient(format!(
                "stale Stripe provider revision rejected for {}",
                revision.subscription_id,
            )));
        }
        Ok(())
    }

    fn reconcile_tier(
        &self,
        env: &StripeWebhookEnvelope,
        tenant_id: &str,
        status: &str,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let plan_id = extract_plan_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload(
                "missing data.object.plan.id / items.data[].price.id (required for tier reconciliation)"
                    .to_string(),
            )
        })?;
        let seat_count = env
            .data
            .get("object")
            .and_then(|o| o.get("quantity"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        let new_tier = self
            .tier_selector
            .compute_tier(plan_id, seat_count)
            .map_err(tier_to_mat)?;

        // SUBSCRIPTION-STATUS GATE (defense-in-depth, mirrors the
        // signup-worker's `subscriptionStatusGrantsAccess`): this materializer
        // is a SECOND writer of the canonical `tier_selections.subscription_state`
        // gate, and `persist_tier_change` → `upsert_tier` UNCONDITIONALLY writes
        // `subscription_state='active'`. A `customer.subscription.updated`
        // carrying a recognized plan but a NON-granting status (`past_due`,
        // `unpaid`, `incomplete`, `incomplete_expired`, `paused`, `canceled`,
        // unknown) must therefore NOT reach the 'active' upsert — otherwise it
        // (re-)grants a paid entitlement for unpaid/lapsed money. We skip the
        // entitlement write (and its tier_changed audit) for non-granting
        // statuses; the `subscription.materialized` audit + the
        // `stripe_subscriptions` row (with the real status) were already
        // recorded above, so the event remains fully observable. The
        // signup-worker (the authority) is responsible for actively flipping
        // the gate to a non-active state.
        if !subscription_status_grants_access(status) {
            return Ok(());
        }

        self.persist_tier_change(tenant_id, new_tier, env, now_ms, request_context)
    }

    fn persist_tier_change(
        &self,
        tenant_id: &str,
        new_tier: TierKind,
        env: &StripeWebhookEnvelope,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let current = self.d1.read_tier(tenant_id).map_err(d1_to_mat)?;
        let new_wire = new_tier.as_str();
        let changed = current.as_deref() != Some(new_wire);
        if !changed {
            return Ok(());
        }

        // Audit BEFORE write.
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.tenant.tier_changed.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.to_string(),
                    stripe_object_id: None,
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: serde_json::json!({
                        "from": current,
                        "to": new_wire,
                    }),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            // `now_ms` (u64) → i64 for the `subscription_started_at_ms`
            // bind. The Stripe-event clock is far below i64::MAX (ms
            // since epoch), so the cast is lossless in practice.
            .upsert_tier(tenant_id, new_wire, now_ms as i64, &env.id)
            .map_err(d1_to_mat)?;
        Ok(())
    }

    /// Cancel/downgrade twin of [`Self::persist_tier_change`]: same
    /// read_tier/changed short-circuit + the same
    /// `corelink.tenant.tier_changed.v1` audit-BEFORE-write ordering, but
    /// drives [`BillingD1Writer::downgrade_tier`] (which writes
    /// `subscription_state='inactive'` — the access gate OFF) instead of
    /// `upsert_tier` (which hard-codes `'active'`). Used ONLY on
    /// `customer.subscription.deleted` so a canceled tenant converges to an
    /// access-OFF row rather than the contradictory active-free row the grant
    /// path would leave (defense-in-depth; the signup-worker is the primary
    /// downgrade authority).
    fn persist_tier_downgrade(
        &self,
        tenant_id: &str,
        new_tier: TierKind,
        env: &StripeWebhookEnvelope,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let current = self.d1.read_tier(tenant_id).map_err(d1_to_mat)?;
        let new_wire = new_tier.as_str();
        let changed = current.as_deref() != Some(new_wire);
        if !changed {
            return Ok(());
        }

        // Audit BEFORE write.
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.tenant.tier_changed.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.to_string(),
                    stripe_object_id: None,
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: serde_json::json!({
                        "from": current,
                        "to": new_wire,
                    }),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            // `now_ms` (u64) → i64 for the `subscription_started_at_ms`
            // bind (INSERT/new-row path only; the DO UPDATE preserves the
            // original start). Lossless in practice (ms since epoch).
            .downgrade_tier(tenant_id, new_wire, now_ms as i64, &env.id)
            .map_err(d1_to_mat)?;
        Ok(())
    }

    fn do_invoice(
        &self,
        env: &StripeWebhookEnvelope,
        outcome: &'static str,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let tenant_id = self.tenant_id_from(env)?;
        let inv_id = self.stripe_object_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload("missing data.object.id".to_string())
        })?;
        let now_ms = self.clock.now_ms();

        let subscription_id = env.data.get("object").and_then(extract_subscription_id);
        let payload = serde_json::json!({
            "stripe_event_type": env.event_type,
            "invoice_id": inv_id,
            "stripe_subscription_id": subscription_id,
            "outcome": outcome,
        });
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.billing.invoice.materialized.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.clone(),
                    stripe_object_id: Some(inv_id.clone()),
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: payload.clone(),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            .upsert_invoice(MaterializedRow {
                table: "stripe_invoices".to_string(),
                tenant_id,
                stripe_id: inv_id,
                stripe_event_id: env.id.clone(),
                payload,
                materialized_at_ms: now_ms,
            })
            .map_err(d1_to_mat)
    }

    fn do_dispute(
        &self,
        env: &StripeWebhookEnvelope,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let tenant_id = self.tenant_id_from(env)?;
        let dispute_id = self.stripe_object_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload("missing data.object.id".to_string())
        })?;
        let now_ms = self.clock.now_ms();

        let payload = serde_json::json!({
            "stripe_event_type": env.event_type,
            "dispute_id": dispute_id,
        });
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.billing.dispute.materialized.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.clone(),
                    stripe_object_id: Some(dispute_id.clone()),
                    // Sev1: Finance + customer attention required.
                    severity: AuditSeverity::Sev1,
                    ts_ms: now_ms,
                    payload: payload.clone(),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            .insert_dispute(MaterializedRow {
                table: "stripe_disputes".to_string(),
                tenant_id,
                stripe_id: dispute_id,
                stripe_event_id: env.id.clone(),
                payload,
                materialized_at_ms: now_ms,
            })
            .map_err(d1_to_mat)
    }

    fn do_refund(
        &self,
        env: &StripeWebhookEnvelope,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let tenant_id = self.tenant_id_from(env)?;
        let charge_id = self.stripe_object_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload("missing data.object.id".to_string())
        })?;
        let now_ms = self.clock.now_ms();

        let object = env.data.get("object");
        let fully_refunded = object
            .and_then(|o| o.get("refunded").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
            || object
                .and_then(|o| o.get("amount").and_then(serde_json::Value::as_i64))
                .zip(
                    object
                        .and_then(|o| o.get("amount_refunded").and_then(serde_json::Value::as_i64)),
                )
                .is_some_and(|(amount, refunded)| amount > 0 && refunded >= amount);
        // Tenant identity does not identify a purchased product. Prefer an
        // expanded Charge/Invoice subscription relationship; otherwise resolve
        // the Charge's invoice through the materialized invoice and the durable
        // Cache/Runners purchase maps. Missing or ambiguous history deliberately
        // stays pending rather than silently selecting Cache.
        let refunded_purchase = match object.and_then(extract_refund_subscription_id) {
            Some(subscription_id) => self
                .d1
                .resolve_refunded_purchase_by_subscription(&tenant_id, subscription_id)
                .map_err(d1_to_mat)?,
            None => match object.and_then(extract_invoice_id) {
                Some(invoice_id) => self
                    .d1
                    .resolve_refunded_purchase_by_invoice(&tenant_id, invoice_id)
                    .map_err(d1_to_mat)?,
                None => None,
            },
        };
        let invoice_id = object.and_then(extract_invoice_id);
        let payload = serde_json::json!({
            "stripe_event_type": env.event_type,
            "charge_id": charge_id,
            "invoice_id": invoice_id,
            "stripe_subscription_id": refunded_purchase.as_ref().map(|p| &p.stripe_subscription_id),
            "refunded_product_axis": refunded_purchase.as_ref().map(|p| p.product.as_str()).unwrap_or("pending"),
            "fully_refunded": fully_refunded,
        });
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.billing.refund.materialized.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.clone(),
                    stripe_object_id: Some(charge_id.clone()),
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: payload.clone(),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            .insert_refund(MaterializedRow {
                table: "stripe_refunds".to_string(),
                tenant_id: tenant_id.clone(),
                stripe_id: charge_id,
                stripe_event_id: env.id.clone(),
                payload,
                materialized_at_ms: now_ms,
            })
            .map_err(d1_to_mat)?;
        if fully_refunded {
            match refunded_purchase {
                Some(purchase) if purchase.product == crate::d1::RefundedProduct::Cache => {
                    self.persist_tier_downgrade(
                        &tenant_id,
                        TierKind::Free,
                        env,
                        now_ms,
                        request_context,
                    )?;
                }
                Some(purchase) if purchase.product == crate::d1::RefundedProduct::Runners => {
                    let snapshots = self
                        .current_subscription(&purchase.stripe_subscription_id)?
                        .ok_or_else(|| {
                            MaterializerError::Transient(
                                "Runners refund cannot bypass provider entitlement authority"
                                    .to_owned(),
                            )
                        })?;
                    let current = snapshots
                        .iter()
                        .find(|snapshot| {
                            snapshot.subscription_id == purchase.stripe_subscription_id
                        })
                        .ok_or_else(|| {
                            MaterializerError::Transient(
                                "Runners refund authority omitted the purchased subscription"
                                    .to_owned(),
                            )
                        })?;
                    self.apply_runner_cas(
                        &tenant_id,
                        RunnerEntitlementRevision {
                            subscription_id: &current.subscription_id,
                            subscription_created_at_ms: current.subscription_created_at_ms,
                            stripe_event_created_at_ms: event_created_at_ms(env)?,
                            stripe_event_id: &env.id,
                            authority_is_current: false,
                        },
                        None,
                        now_ms,
                    )?;
                }
                Some(_) | None => {}
            }
        }
        Ok(())
    }

    fn do_customer_created(
        &self,
        env: &StripeWebhookEnvelope,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        let tenant_id = self.tenant_id_from(env)?;
        let cus_id = self.stripe_object_id(env).ok_or_else(|| {
            MaterializerError::InvalidPayload("missing data.object.id".to_string())
        })?;
        let now_ms = self.clock.now_ms();

        let payload = serde_json::json!({
            "stripe_event_type": env.event_type,
            "customer_id": cus_id,
        });
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.billing.customer.materialized.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id: tenant_id.clone(),
                    stripe_object_id: Some(cus_id.clone()),
                    severity: AuditSeverity::Notice,
                    ts_ms: now_ms,
                    payload: payload.clone(),
                },
                request_context,
            )
            .map_err(audit_to_mat)?;

        self.d1
            .upsert_customer(MaterializedRow {
                table: "stripe_customers".to_string(),
                tenant_id,
                stripe_id: cus_id,
                stripe_event_id: env.id.clone(),
                payload,
                materialized_at_ms: now_ms,
            })
            .map_err(d1_to_mat)
    }

    fn do_pure_echo(
        &self,
        event_type: CanonicalWebhookEventType,
        env: &StripeWebhookEnvelope,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        // No D1 mutation; just emit the audit echo so the chain still
        // pins the delivery. Tenant id is optional for these arms
        // (`invoice.created` arrives before the tenant linkage is
        // resolved in some Stripe flows). We tolerate its absence.
        let tenant_id = self
            .tenant_id_from(env)
            .unwrap_or_else(|_| "__unknown__".to_string());
        let now_ms = self.clock.now_ms();
        self.audit
            .emit_billing_with_context(
                &BillingAuditRecord {
                    event_name: "corelink.billing.echo.v1",
                    stripe_event_id: env.id.clone(),
                    stripe_event_type: env.event_type.clone(),
                    tenant_id,
                    stripe_object_id: self.stripe_object_id(env),
                    severity: AuditSeverity::Info,
                    ts_ms: now_ms,
                    payload: serde_json::json!({
                        "canonical_event_type": event_type.label(),
                    }),
                },
                request_context,
            )
            .map_err(audit_to_mat)
    }
}

impl StateMaterializer for D1SubscriptionStateHandler {
    fn on_subscription_deleted(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.do_subscription_upsert(env, true, None)
    }

    fn on_subscription_deleted_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_subscription_upsert(env, true, context)
    }

    fn on_subscription_updated(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.do_subscription_upsert(env, false, None)
    }

    fn on_subscription_updated_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_subscription_upsert(env, false, context)
    }

    fn on_invoice_paid(&self, env: &StripeWebhookEnvelope) -> Result<(), MaterializerError> {
        self.do_invoice(env, "paid", None)
    }

    fn on_invoice_paid_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_invoice(env, "paid", context)
    }

    fn on_invoice_payment_failed(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.do_invoice(env, "payment_failed", None)
    }

    fn on_invoice_payment_failed_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_invoice(env, "payment_failed", context)
    }

    fn on_charge_dispute_created(
        &self,
        env: &StripeWebhookEnvelope,
    ) -> Result<(), MaterializerError> {
        self.do_dispute(env, None)
    }

    fn on_charge_dispute_created_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_dispute(env, context)
    }

    fn on_charge_refunded(&self, env: &StripeWebhookEnvelope) -> Result<(), MaterializerError> {
        self.do_refund(env, None)
    }

    fn on_charge_refunded_with_context(
        &self,
        env: &StripeWebhookEnvelope,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<(), MaterializerError> {
        self.do_refund(env, context)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]
mod tests;
