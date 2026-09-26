//! Durable Stripe webhook inbox adapter over the D1 HTTP client.
//!
//! This module is intentionally not wired into the dispatcher yet. It freezes
//! the persistence operations needed by the later dispatcher/materializer wave.

use std::sync::Arc;

use corelink_billing::stripe::real::webhook_dispatch::{
    DurableWebhookEvent, DurableWebhookInbox, DurableWebhookRequestContext, EffectReservation,
    InboxClaim as DispatcherInboxClaim, InboxReceiveOutcome,
    InboxTerminalState as DispatcherInboxTerminalState,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::storage::{
    d1_http::{D1BatchStatement, D1HttpClient, D1Row},
    staging_load_test_admission::StagingLoadTestAdmissionContext,
    staging_load_test_ownership::{
        StagingLoadTestDisposition, StagingLoadTestResourceClass, StagingLoadTestScenario,
    },
};

/// Insert an authenticated event without replacing an existing body.
pub const SQL_RECEIVE: &str = "INSERT INTO stripe_webhook_event_inbox (event_id, event_type, raw_body_hex, payload_sha256, stripe_created_at_ms, state, received_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, 'received', ?6, ?6) ON CONFLICT(event_id) DO NOTHING RETURNING state";
/// Read a stored event's identity and ownership state.
pub const SQL_READ: &str =
    "SELECT event_type, payload_sha256, state FROM stripe_webhook_event_inbox WHERE event_id = ?1";
/// Claim a received event or reclaim an expired claim, advancing its fence.
pub const SQL_CLAIM: &str = "UPDATE stripe_webhook_event_inbox SET state = 'claimed', fence = fence + 1, claim_owner = ?1, claim_expires_at_ms = ?2, updated_at_ms = ?3 WHERE event_id = ?4 AND (state = 'received' OR (state = 'claimed' AND claim_expires_at_ms <= ?3)) RETURNING event_id, event_type, raw_body_hex, payload_sha256, fence";
/// Complete only the claim which still owns the current fence.
pub const SQL_COMPLETE: &str = "UPDATE stripe_webhook_event_inbox SET state = 'completed', claim_owner = NULL, claim_expires_at_ms = NULL, updated_at_ms = ?1, terminal_at_ms = ?1, last_error = NULL WHERE event_id = ?2 AND state = 'claimed' AND fence = ?3 AND claim_owner = ?4 AND claim_expires_at_ms > ?5 RETURNING event_id";
/// Quarantine only the claim which still owns the current fence.
pub const SQL_QUARANTINE: &str = "UPDATE stripe_webhook_event_inbox SET state = 'quarantined', claim_owner = NULL, claim_expires_at_ms = NULL, updated_at_ms = ?1, terminal_at_ms = ?1, last_error = ?2 WHERE event_id = ?3 AND state = 'claimed' AND fence = ?4 AND claim_owner = ?5 AND claim_expires_at_ms > ?6 RETURNING event_id";
/// Insert the idempotent effect witness only while this exact lease is live.
pub const SQL_EFFECT_INSERT: &str = "INSERT INTO stripe_webhook_event_effects (event_id, effect_key, payload_sha256, fence, effect_kind, applied_at_ms) SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM stripe_webhook_event_inbox WHERE event_id = ?1 AND state = 'claimed' AND fence = ?4 AND claim_owner = ?7 AND claim_expires_at_ms > ?6) ON CONFLICT(event_id) DO NOTHING RETURNING event_id";
/// Read the existing witness after a reservation conflict.
pub const SQL_EFFECT_READ: &str = "SELECT effect_key, payload_sha256, fence, effect_kind FROM stripe_webhook_event_effects WHERE event_id = ?1";
/// Seal only the pending witness owned by this live claim.
pub const SQL_EFFECT_SEAL: &str = "UPDATE stripe_webhook_event_effects SET effect_kind = ?1, applied_at_ms = ?2 WHERE event_id = ?3 AND effect_key = ?4 AND payload_sha256 = ?5 AND fence = ?6 AND effect_kind = ?7 AND EXISTS (SELECT 1 FROM stripe_webhook_event_inbox WHERE event_id = ?3 AND state = 'claimed' AND fence = ?6 AND claim_owner = ?8 AND claim_expires_at_ms > ?2) RETURNING event_id";
/// Abort a reservation only while its claim remains live.
pub const SQL_EFFECT_ABORT: &str = "DELETE FROM stripe_webhook_event_effects WHERE event_id = ?1 AND effect_key = ?2 AND payload_sha256 = ?3 AND fence = ?4 AND effect_kind = ?5 AND EXISTS (SELECT 1 FROM stripe_webhook_event_inbox WHERE event_id = ?1 AND state = 'claimed' AND fence = ?4 AND claim_owner = ?6 AND claim_expires_at_ms > ?7) RETURNING event_id";
/// Terminalize only when the witness just inserted by the same fenced claim exists.
pub const SQL_EFFECT_COMPLETE: &str = "UPDATE stripe_webhook_event_inbox SET state = 'completed', claim_owner = NULL, claim_expires_at_ms = NULL, updated_at_ms = ?1, terminal_at_ms = ?1, last_error = NULL WHERE event_id = ?2 AND state = 'claimed' AND fence = ?3 AND claim_owner = ?4 AND claim_expires_at_ms > ?1 AND EXISTS (SELECT 1 FROM stripe_webhook_event_effects WHERE event_id = ?2 AND effect_key = ?5 AND payload_sha256 = ?6 AND fence = ?3 AND effect_kind = ?7) RETURNING event_id";

const SQL_VERIFY_OWNERSHIP: &str = "SELECT resource.receipt_ref FROM staging_load_test_resources AS resource JOIN staging_load_test_runs AS run ON run.run_id = resource.run_id AND run.scenario = resource.scenario WHERE resource.run_id = ?1 AND resource.scenario = 'webhook' AND run.target_environment = 'staging' AND run.target_deployment_sha = ?2 AND run.state = 'open' AND resource.resource_class = ?3 AND resource.opaque_handle = ?4 AND resource.disposition = ?5 LIMIT 1";
const SQL_REQUIRE_ONE_CHANGE: &str = "INSERT INTO staging_load_test_resources (run_id, scenario, resource_class, receipt_ref, opaque_handle, disposition, state, registered_at_ms) SELECT '', 'webhook', 'webhook_effect', '', '', 'disposable', 'invalid', 0 WHERE changes() != 1";
const SQL_REQUIRE_NEW_OWNERSHIP: &str = SQL_REQUIRE_ONE_CHANGE;
const SQL_REQUIRE_EXISTING_OWNERSHIP: &str = "INSERT INTO staging_load_test_resources (run_id, scenario, resource_class, receipt_ref, opaque_handle, disposition, state, registered_at_ms) SELECT '', 'webhook', 'webhook_effect', '', '', 'disposable', 'invalid', 0 WHERE NOT EXISTS (SELECT 1 FROM staging_load_test_resources AS resource JOIN staging_load_test_runs AS run ON run.run_id = resource.run_id AND run.scenario = resource.scenario WHERE resource.run_id = ?1 AND resource.scenario = 'webhook' AND run.target_environment = 'staging' AND run.target_deployment_sha = ?2 AND run.state = 'open' AND resource.resource_class = ?3 AND resource.opaque_handle = ?4 AND resource.disposition = ?5)";

/// Authenticated event bytes and identity persisted before processing.
#[derive(Clone, Debug)]
pub struct AuthenticatedWebhookEvent {
    /// Stripe event id.
    pub event_id: String,
    /// Canonical Stripe event type.
    pub event_type: String,
    /// Exact signed body, hex encoded for D1 text storage.
    pub raw_body_hex: String,
    /// SHA-256 digest of the exact raw body, lower hexadecimal.
    pub payload_sha256: String,
    /// Stripe's event creation timestamp, if the envelope supplied one.
    pub stripe_created_at_ms: Option<u64>,
}

/// Result of making an authenticated delivery durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxReceipt {
    /// A fresh, recoverable event awaits a claim.
    Received,
    /// A completed or quarantined event may be acknowledged as terminal.
    Terminal,
    /// A historical marker requires manual reconciliation.
    LegacyAmbiguous,
}

/// Lease-backed ownership of a durable inbox event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxClaim {
    /// Stripe event id.
    pub event_id: String,
    /// Monotonically increasing ownership fence.
    pub fence: u64,
}

/// Terminal state selected after a durable outcome is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxTerminalState {
    /// The materialized effect completed durably.
    Completed,
    /// A durable DLQ record exists for the event.
    Quarantined,
}

/// D1-backed inbox persistence. Later wiring must make effect plus completion
/// one D1 transaction, and must call quarantine only after its DLQ write.
#[derive(Clone)]
pub struct D1WebhookInbox {
    d1: Arc<D1HttpClient>,
}

impl std::fmt::Debug for D1WebhookInbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("D1WebhookInbox").finish_non_exhaustive()
    }
}

impl D1WebhookInbox {
    /// Construct the durable inbox over a shared D1 client.
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    fn run(&self, sql: &str, binds: Vec<Value>) -> Result<Vec<D1Row>, String> {
        let d1 = Arc::clone(&self.d1);
        let sql = sql.to_owned();
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.query(&sql, &binds).await })
        })
    }

    fn run_batch(&self, statements: Vec<D1BatchStatement>) -> Result<Vec<Vec<D1Row>>, String> {
        let d1 = Arc::clone(&self.d1);
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.batch(statements).await })
        })
        .map_err(|error| format!("webhook inbox effect batch: {}", error.message))
    }

    /// Persist an authenticated event. A changed body or type for an existing
    /// event id is rejected so it can never be acknowledged as a duplicate.
    pub fn receive(
        &self,
        event: &AuthenticatedWebhookEvent,
        now_ms: u64,
    ) -> Result<InboxReceipt, String> {
        self.receive_with_ownership_context(event, now_ms, None)
    }

    /// Persist an authenticated event and, for admitted staging traffic,
    /// register its run ownership in the same D1 batch.
    pub fn receive_with_ownership_context(
        &self,
        event: &AuthenticatedWebhookEvent,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<InboxReceipt, String> {
        validate_authenticated_event(event)?;
        let receive = D1BatchStatement::new(
            SQL_RECEIVE,
            vec![
                json!(event.event_id),
                json!(event.event_type),
                json!(event.raw_body_hex),
                json!(event.payload_sha256),
                json!(event
                    .stripe_created_at_ms
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX))),
                json!(i64::try_from(now_ms).unwrap_or(i64::MAX)),
            ],
        );
        let rows = if let Some(context) = request_context {
            let context = verified_staging_context(Some(context))?
                .ok_or_else(|| "webhook ownership: context is missing".to_owned())?;
            let handle = opaque_handle(context, "stripe-webhook-inbox", &event.event_id);
            let [registration, unique_guard, verify] = ownership_statements(
                context,
                StagingLoadTestResourceClass::WebhookInbox,
                "webhook_inbox",
                StagingLoadTestDisposition::Disposable,
                &handle,
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            )?;
            let locator = teardown_locator_statement(
                context,
                "webhook_inbox",
                "webhook_inbox_v1",
                &handle,
                json!({ "event_id": event.event_id }),
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            );
            let result = self.run_batch(vec![
                receive,
                D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]),
                registration,
                locator,
                unique_guard,
                verify,
            ])?;
            require_ownership_result(&result, 5)?;
            result
                .first()
                .cloned()
                .ok_or_else(|| "webhook inbox: receive batch result is missing".to_owned())?
        } else {
            self.run(
                SQL_RECEIVE,
                vec![
                    json!(event.event_id),
                    json!(event.event_type),
                    json!(event.raw_body_hex),
                    json!(event.payload_sha256),
                    json!(event
                        .stripe_created_at_ms
                        .map(|v| i64::try_from(v).unwrap_or(i64::MAX))),
                    json!(i64::try_from(now_ms).unwrap_or(i64::MAX)),
                ],
            )?
        };
        if !rows.is_empty() {
            return Ok(InboxReceipt::Received);
        }
        let row = self
            .run(SQL_READ, vec![json!(event.event_id)])?
            .into_iter()
            .next()
            .ok_or_else(|| "webhook inbox: existing event disappeared".to_owned())?;
        let state = text(&row, "state")?;
        if state == "legacy_ambiguous" {
            return Ok(InboxReceipt::LegacyAmbiguous);
        }
        if text(&row, "event_type")? != event.event_type
            || text(&row, "payload_sha256")? != event.payload_sha256
        {
            return Err("webhook inbox: event id conflicts with authenticated body".to_owned());
        }
        match state.as_str() {
            "completed" | "quarantined" => Ok(InboxReceipt::Terminal),
            "received" | "claimed" => Ok(InboxReceipt::Received),
            _ => Err("webhook inbox: invalid stored state".to_owned()),
        }
    }

    /// Atomically claim or reclaim an expired event. `None` means terminal,
    /// legacy, or another owner's unexpired claim.
    pub fn claim(
        &self,
        event_id: &str,
        owner: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<InboxClaim>, String> {
        let expires = now_ms
            .checked_add(lease_ms)
            .ok_or_else(|| "webhook inbox: lease overflow".to_owned())?;
        let rows = self.run(
            SQL_CLAIM,
            vec![
                json!(owner),
                json!(i64::try_from(expires).unwrap_or(i64::MAX)),
                json!(i64::try_from(now_ms).unwrap_or(i64::MAX)),
                json!(event_id),
            ],
        )?;
        match rows.into_iter().next() {
            None => Ok(None),
            Some(row) => Ok(Some(InboxClaim {
                event_id: text(&row, "event_id")?,
                fence: number(&row, "fence")?,
            })),
        }
    }

    /// Fenced terminal transition. `false` means ownership was lost or expired.
    pub fn finish(
        &self,
        claim: &InboxClaim,
        owner: &str,
        state: InboxTerminalState,
        error: Option<&str>,
        now_ms: u64,
    ) -> Result<bool, String> {
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let rows = match state {
            InboxTerminalState::Completed => self.run(
                SQL_COMPLETE,
                vec![
                    json!(now),
                    json!(claim.event_id),
                    json!(i64::try_from(claim.fence).unwrap_or(i64::MAX)),
                    json!(owner),
                    json!(now),
                ],
            )?,
            InboxTerminalState::Quarantined => self.run(
                SQL_QUARANTINE,
                vec![
                    json!(now),
                    json!(error.unwrap_or("quarantined")),
                    json!(claim.event_id),
                    json!(i64::try_from(claim.fence).unwrap_or(i64::MAX)),
                    json!(owner),
                    json!(now),
                ],
            )?,
        };
        Ok(!rows.is_empty())
    }

    /// Persist the effect witness and terminal inbox state in one D1 batch.
    /// A response lost after this call is safe: the next delivery observes the
    /// terminal state and is the only duplicate path that returns 200.
    pub fn commit_effect(
        &self,
        claim: &InboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<bool, String> {
        self.commit_effect_with_ownership_context(
            claim,
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
            None,
        )
    }

    fn commit_effect_with_ownership_context(
        &self,
        claim: &InboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<bool, String> {
        validate_durable_event(event)?;
        if claim.event_id != event.event_id {
            return Err("webhook inbox: claim and authenticated event differ".to_owned());
        }
        if effect_key.is_empty() || effect_kind.is_empty() || owner.is_empty() {
            return Err("webhook inbox: effect identity is empty".to_owned());
        }
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let fence = i64::try_from(claim.fence).unwrap_or(i64::MAX);
        let pending_kind = format!("pending:{effect_kind}");
        let mut statements = vec![
            D1BatchStatement::new(
                SQL_EFFECT_SEAL,
                vec![
                    json!(effect_kind),
                    json!(now),
                    json!(claim.event_id),
                    json!(effect_key),
                    json!(event.payload_sha256),
                    json!(fence),
                    json!(pending_kind),
                    json!(owner),
                ],
            ),
            D1BatchStatement::new(
                SQL_EFFECT_COMPLETE,
                vec![
                    json!(now),
                    json!(claim.event_id),
                    json!(fence),
                    json!(owner),
                    json!(effect_key),
                    json!(event.payload_sha256),
                    json!(effect_kind),
                ],
            ),
        ];
        if let Some(request_context) = request_context {
            let context = verified_staging_context(Some(request_context))?
                .ok_or_else(|| "webhook ownership: context is missing".to_owned())?;
            let handle = effect_handle(context, event, effect_key);
            let [_registration, _unique_guard, verify] = ownership_statements(
                context,
                StagingLoadTestResourceClass::WebhookEffect,
                "webhook_effect",
                StagingLoadTestDisposition::Disposable,
                &handle,
                now,
            )?;
            statements.insert(1, D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]));
            statements.insert(3, D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]));
            statements.push(verify);
            statements.push(D1BatchStatement::new(
                SQL_REQUIRE_EXISTING_OWNERSHIP,
                vec![
                    json!(context.run_id()),
                    json!(context.target_deployment_sha()),
                    json!("webhook_effect"),
                    json!(handle),
                    json!("disposable"),
                ],
            ));
        }
        let result = self.run_batch(statements)?;
        if request_context.is_some() {
            require_ownership_result(&result, 4)?;
        }
        let inserted = result.first().is_some_and(|rows| !rows.is_empty());
        let completed = result
            .get(if request_context.is_some() { 2 } else { 1 })
            .is_some_and(|rows| !rows.is_empty());
        Ok(inserted && completed)
    }

    fn reserve_effect(
        &self,
        claim: &InboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<EffectReservation, String> {
        self.reserve_effect_with_ownership_context(
            claim,
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
            None,
        )
    }

    fn reserve_effect_with_ownership_context(
        &self,
        claim: &InboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
        request_context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<EffectReservation, String> {
        validate_durable_event(event)?;
        if claim.event_id != event.event_id || effect_key.is_empty() || effect_kind.is_empty() {
            return Err("webhook inbox: invalid effect reservation identity".to_owned());
        }
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let fence = i64::try_from(claim.fence).unwrap_or(i64::MAX);
        let pending_kind = format!("pending:{effect_kind}");
        let effect_insert = D1BatchStatement::new(
            SQL_EFFECT_INSERT,
            vec![
                json!(claim.event_id),
                json!(effect_key),
                json!(event.payload_sha256),
                json!(fence),
                json!(pending_kind),
                json!(now),
                json!(owner),
            ],
        );
        let rows = if let Some(request_context) = request_context {
            let context = verified_staging_context(Some(request_context))?
                .ok_or_else(|| "webhook ownership: context is missing".to_owned())?;
            let handle = effect_handle(context, event, effect_key);
            let [registration, unique_guard, verify] = ownership_statements(
                context,
                StagingLoadTestResourceClass::WebhookEffect,
                "webhook_effect",
                StagingLoadTestDisposition::Disposable,
                &handle,
                now,
            )?;
            let locator = teardown_locator_statement(
                context,
                "webhook_effect",
                "webhook_effect_v1",
                &handle,
                json!({ "event_id": event.event_id, "effect_key": effect_key }),
                now,
            );
            let result = self.run_batch(vec![
                effect_insert,
                D1BatchStatement::new(SQL_REQUIRE_ONE_CHANGE, vec![]),
                registration,
                locator,
                unique_guard,
                verify,
            ])?;
            require_ownership_result(&result, 5)?;
            result
                .first()
                .cloned()
                .ok_or_else(|| "webhook inbox: effect batch result is missing".to_owned())?
        } else {
            self.run(
                SQL_EFFECT_INSERT,
                vec![
                    json!(claim.event_id),
                    json!(effect_key),
                    json!(event.payload_sha256),
                    json!(fence),
                    json!(pending_kind),
                    json!(now),
                    json!(owner),
                ],
            )?
        };
        if !rows.is_empty() {
            return Ok(EffectReservation::Reserved);
        }
        let row = self
            .run(SQL_EFFECT_READ, vec![json!(claim.event_id)])?
            .into_iter()
            .next()
            .ok_or_else(|| "webhook inbox: effect reservation disappeared".to_owned())?;
        if text(&row, "effect_key")? != effect_key
            || text(&row, "payload_sha256")? != event.payload_sha256
        {
            return Err("webhook inbox: effect conflicts with authenticated event".to_owned());
        }
        let stored_fence = number(&row, "fence")?;
        let stored_kind = text(&row, "effect_kind")?;
        if stored_kind == effect_kind {
            return Ok(EffectReservation::Applied);
        }
        if stored_kind == pending_kind && stored_fence == claim.fence {
            return Ok(EffectReservation::PendingRecovery);
        }
        Err("webhook inbox: stale or incompatible pending effect".to_owned())
    }

    fn abort_reserved_effect(
        &self,
        claim: &InboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<bool, String> {
        validate_durable_event(event)?;
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let fence = i64::try_from(claim.fence).unwrap_or(i64::MAX);
        let rows = self.run(
            SQL_EFFECT_ABORT,
            vec![
                json!(claim.event_id),
                json!(effect_key),
                json!(event.payload_sha256),
                json!(fence),
                json!(format!("pending:{effect_kind}")),
                json!(owner),
                json!(now),
            ],
        )?;
        Ok(!rows.is_empty())
    }
}

impl DurableWebhookInbox for D1WebhookInbox {
    fn receive(
        &self,
        event: &DurableWebhookEvent,
        now_ms: u64,
    ) -> Result<InboxReceiveOutcome, String> {
        match self.receive(
            &AuthenticatedWebhookEvent {
                event_id: event.event_id.clone(),
                event_type: event.event_type.clone(),
                raw_body_hex: event.raw_body_hex.clone(),
                payload_sha256: event.payload_sha256.clone(),
                stripe_created_at_ms: Some(event.stripe_created_at_ms),
            },
            now_ms,
        )? {
            InboxReceipt::Received => Ok(InboxReceiveOutcome::Received),
            InboxReceipt::Terminal => Ok(InboxReceiveOutcome::Terminal),
            InboxReceipt::LegacyAmbiguous => Ok(InboxReceiveOutcome::LegacyAmbiguous),
        }
    }

    fn receive_with_context(
        &self,
        event: &DurableWebhookEvent,
        now_ms: u64,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<InboxReceiveOutcome, String> {
        match self.receive_with_ownership_context(
            &AuthenticatedWebhookEvent {
                event_id: event.event_id.clone(),
                event_type: event.event_type.clone(),
                raw_body_hex: event.raw_body_hex.clone(),
                payload_sha256: event.payload_sha256.clone(),
                stripe_created_at_ms: Some(event.stripe_created_at_ms),
            },
            now_ms,
            context,
        )? {
            InboxReceipt::Received => Ok(InboxReceiveOutcome::Received),
            InboxReceipt::Terminal => Ok(InboxReceiveOutcome::Terminal),
            InboxReceipt::LegacyAmbiguous => Ok(InboxReceiveOutcome::LegacyAmbiguous),
        }
    }

    fn claim(
        &self,
        event_id: &str,
        owner: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<DispatcherInboxClaim>, String> {
        self.claim(event_id, owner, now_ms, lease_ms)
            .map(|claim| claim.map(|claim| DispatcherInboxClaim::new(claim.event_id, claim.fence)))
    }

    fn finish(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        state: DispatcherInboxTerminalState,
        error: Option<&str>,
        now_ms: u64,
    ) -> Result<bool, String> {
        let state = match state {
            DispatcherInboxTerminalState::Completed => InboxTerminalState::Completed,
            DispatcherInboxTerminalState::Quarantined => InboxTerminalState::Quarantined,
        };
        self.finish(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            state,
            error,
            now_ms,
        )
    }

    fn reserve_effect(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<EffectReservation, String> {
        self.reserve_effect(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
        )
    }

    fn reserve_effect_with_context(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<EffectReservation, String> {
        self.reserve_effect_with_ownership_context(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
            context,
        )
    }

    fn abort_reserved_effect(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<bool, String> {
        self.abort_reserved_effect(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
        )
    }

    fn commit_effect(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
    ) -> Result<bool, String> {
        self.commit_effect(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
        )
    }

    fn commit_effect_with_context(
        &self,
        claim: &DispatcherInboxClaim,
        owner: &str,
        event: &DurableWebhookEvent,
        effect_key: &str,
        effect_kind: &str,
        now_ms: u64,
        context: Option<&dyn DurableWebhookRequestContext>,
    ) -> Result<bool, String> {
        self.commit_effect_with_ownership_context(
            &InboxClaim {
                event_id: claim.event_id.clone(),
                fence: claim.fence,
            },
            owner,
            event,
            effect_key,
            effect_kind,
            now_ms,
            context,
        )
    }
}

fn text(row: &D1Row, name: &str) -> Result<String, String> {
    row.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("webhook inbox: row missing `{name}`"))
}

fn number(row: &D1Row, name: &str) -> Result<u64, String> {
    row.get(name)
        .and_then(Value::as_i64)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| format!("webhook inbox: row missing `{name}`"))
}

fn verified_staging_context(
    context: Option<&dyn DurableWebhookRequestContext>,
) -> Result<Option<&StagingLoadTestAdmissionContext>, String> {
    context
        .map(|context| {
            context
                .as_any()
                .downcast_ref::<StagingLoadTestAdmissionContext>()
                .ok_or_else(|| "webhook ownership: request context is invalid".to_owned())
        })
        .transpose()
}

fn ownership_statements(
    context: &StagingLoadTestAdmissionContext,
    class: StagingLoadTestResourceClass,
    class_name: &'static str,
    disposition: StagingLoadTestDisposition,
    opaque_handle: &str,
    now_ms: i64,
) -> Result<[D1BatchStatement; 3], String> {
    context
        .require_ownership_scenario(StagingLoadTestScenario::Webhook)
        .map_err(|_| "webhook ownership: admitted scenario is invalid".to_owned())?;
    let registration = context
        .ownership_registration(class, disposition, opaque_handle)
        .map_err(|_| "webhook ownership: registration identity is invalid".to_owned())?;
    let statement = registration
        .d1_statement(now_ms)
        .map_err(|_| "webhook ownership: registration statement is invalid".to_owned())?;
    let disposition_name = match disposition {
        StagingLoadTestDisposition::Disposable => "disposable",
        StagingLoadTestDisposition::Retained => "retained",
    };
    let verify = D1BatchStatement::new(
        SQL_VERIFY_OWNERSHIP,
        vec![
            json!(context.run_id()),
            json!(context.target_deployment_sha()),
            json!(class_name),
            json!(opaque_handle),
            json!(disposition_name),
        ],
    );
    let unique_guard = D1BatchStatement::new(SQL_REQUIRE_NEW_OWNERSHIP, vec![]);
    Ok([statement, unique_guard, verify])
}

fn require_ownership_result(result: &[Vec<D1Row>], statement_index: usize) -> Result<(), String> {
    if result
        .get(statement_index)
        .is_some_and(|rows| rows.len() == 1)
    {
        Ok(())
    } else {
        Err("webhook ownership: durable registration is missing".to_owned())
    }
}

fn teardown_locator_statement(
    context: &StagingLoadTestAdmissionContext,
    class_name: &'static str,
    locator_kind: &'static str,
    opaque_handle: &str,
    locator: Value,
    now_ms: i64,
) -> D1BatchStatement {
    let mut digest = Sha256::new();
    digest.update(b"corelink-staging-load-test-resource-receipt-v1\0");
    for part in [
        context.run_id().as_bytes(),
        context.scenario().as_str().as_bytes(),
        context.target_deployment_sha().as_bytes(),
        class_name.as_bytes(),
        opaque_handle.as_bytes(),
        b"disposable".as_slice(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    D1BatchStatement::new(
        "INSERT INTO staging_load_test_teardown_locators (run_id, scenario, resource_class, receipt_ref, locator_kind, locator_json, registered_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        vec![json!(context.run_id()), json!(context.scenario().as_str()), json!(class_name), json!(hex::encode(digest.finalize())), json!(locator_kind), json!(locator.to_string()), json!(now_ms)],
    )
}

fn opaque_handle(context: &StagingLoadTestAdmissionContext, domain: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"corelink/webhook-ownership-handle/v1\0");
    digest.update(context.run_id().as_bytes());
    digest.update([0]);
    digest.update(context.target_deployment_sha().as_bytes());
    digest.update([0]);
    digest.update(context.admitted_at_ms().to_be_bytes());
    digest.update([0]);
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    format!("{}:{}", domain, hex::encode(digest.finalize()))
}

fn effect_handle(
    context: &StagingLoadTestAdmissionContext,
    event: &DurableWebhookEvent,
    effect_key: &str,
) -> String {
    opaque_handle(
        context,
        "stripe-webhook-effect",
        &format!("{}\0{}", event.event_id, effect_key),
    )
}

fn validate_authenticated_event(event: &AuthenticatedWebhookEvent) -> Result<(), String> {
    if event.event_id.is_empty()
        || event.event_type.is_empty()
        || event.payload_sha256.len() != 64
        || !event
            .payload_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || event.raw_body_hex.len() > 200_000
    {
        return Err("webhook inbox: invalid authenticated event identity".to_owned());
    }
    let raw_body = hex::decode(&event.raw_body_hex)
        .map_err(|_| "webhook inbox: raw body is not hex".to_owned())?;
    if hex::encode(Sha256::digest(raw_body)) != event.payload_sha256 {
        return Err("webhook inbox: raw body digest mismatch".to_owned());
    }
    Ok(())
}

fn validate_durable_event(event: &DurableWebhookEvent) -> Result<(), String> {
    validate_authenticated_event(&AuthenticatedWebhookEvent {
        event_id: event.event_id.clone(),
        event_type: event.event_type.clone(),
        raw_body_hex: event.raw_body_hex.clone(),
        payload_sha256: event.payload_sha256.clone(),
        stripe_created_at_ms: Some(event.stripe_created_at_ms),
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests use direct SQLite assertions"
)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use hmac::{Hmac, KeyInit, Mac};
    use rusqlite::Connection;

    use super::*;

    #[test]
    fn migration_preserves_legacy_marker_as_manual_work() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0044_stripe_webhook_events_processed.sql"
        ))
        .unwrap();
        db.execute("INSERT INTO stripe_webhook_events_processed VALUES ('evt_legacy','invoice.paid',1,'dispatched','evt_legacy')", []).unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0132_stripe_webhook_inbox.sql"
        ))
        .unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM stripe_webhook_event_inbox WHERE event_id='evt_legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "legacy_ambiguous");
    }

    #[test]
    fn fenced_sql_reclaims_only_expired_claims() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0044_stripe_webhook_events_processed.sql"
        ))
        .unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0132_stripe_webhook_inbox.sql"
        ))
        .unwrap();
        let _: String = db
            .query_row(
                SQL_RECEIVE,
                rusqlite::params!["evt_1", "invoice.paid", "aa", "a".repeat(64), 1_i64, 1_i64],
                |r| r.get(0),
            )
            .unwrap();
        let first_fence: i64 = db
            .query_row(
                SQL_CLAIM,
                rusqlite::params!["one", 10_i64, 1_i64, "evt_1"],
                |r| r.get(4),
            )
            .unwrap();
        assert_eq!(first_fence, 1);
        let expired_finish = db.query_row(
            SQL_COMPLETE,
            rusqlite::params![10_i64, "evt_1", 1_i64, "one", 10_i64],
            |r| r.get::<_, String>(0),
        );
        assert!(matches!(
            expired_finish,
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        let blocked = db.query_row(
            SQL_CLAIM,
            rusqlite::params!["two", 20_i64, 9_i64, "evt_1"],
            |r| r.get::<_, String>(0),
        );
        assert!(matches!(blocked, Err(rusqlite::Error::QueryReturnedNoRows)));
        let reclaimed_fence: i64 = db
            .query_row(
                SQL_CLAIM,
                rusqlite::params!["two", 21_i64, 10_i64, "evt_1"],
                |r| r.get(4),
            )
            .unwrap();
        assert_eq!(reclaimed_fence, 2);
    }

    #[test]
    fn effect_witness_and_completion_share_one_fenced_transaction() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0044_stripe_webhook_events_processed.sql"
        ))
        .unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0132_stripe_webhook_inbox.sql"
        ))
        .unwrap();
        db.execute_batch(include_str!(
            "../../../migrations/d1/0133_stripe_webhook_effect_ledger.sql"
        ))
        .unwrap();
        let raw = "00";
        let digest = hex::encode(Sha256::digest(hex::decode(raw).unwrap()));
        db.query_row(
            SQL_RECEIVE,
            rusqlite::params!["evt_effect", "invoice.paid", raw, digest, 1_i64, 1_i64],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
        let fence: i64 = db
            .query_row(
                SQL_CLAIM,
                rusqlite::params!["owner-a", 100_i64, 1_i64, "evt_effect"],
                |row| row.get(4),
            )
            .unwrap();

        let tx = db.transaction().unwrap();
        tx.query_row(
            SQL_EFFECT_INSERT,
            rusqlite::params![
                "evt_effect",
                "stripe-webhook-effect:key",
                digest,
                fence,
                "pending:invoice.paid",
                2_i64,
                "owner-a",
            ],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
        tx.query_row(
            SQL_EFFECT_SEAL,
            rusqlite::params![
                "invoice.paid",
                2_i64,
                "evt_effect",
                "stripe-webhook-effect:key",
                digest,
                fence,
                "pending:invoice.paid",
                "owner-a",
            ],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
        tx.query_row(
            SQL_EFFECT_COMPLETE,
            rusqlite::params![
                2_i64,
                "evt_effect",
                fence,
                "owner-a",
                "stripe-webhook-effect:key",
                digest,
                "invoice.paid"
            ],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
        tx.commit().unwrap();

        let effects: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM stripe_webhook_event_effects WHERE event_id='evt_effect'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM stripe_webhook_event_inbox WHERE event_id='evt_effect'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effects, 1, "lost ACK retry cannot create another effect");
        assert_eq!(state, "completed", "only a committed effect can ack 200");

        let stale = db.query_row(
            SQL_EFFECT_INSERT,
            rusqlite::params![
                "evt_effect",
                "stripe-webhook-effect:key",
                digest,
                fence,
                "invoice.paid",
                3_i64,
                "owner-a",
            ],
            |row| row.get::<_, String>(0),
        );
        assert!(matches!(stale, Err(rusqlite::Error::QueryReturnedNoRows)));

        db.query_row(
            SQL_RECEIVE,
            rusqlite::params!["evt_race", "invoice.paid", raw, digest, 1_i64, 1_i64],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
        let old_fence: i64 = db
            .query_row(
                SQL_CLAIM,
                rusqlite::params!["owner-old", 10_i64, 1_i64, "evt_race"],
                |row| row.get(4),
            )
            .unwrap();
        let new_fence: i64 = db
            .query_row(
                SQL_CLAIM,
                rusqlite::params!["owner-new", 30_i64, 10_i64, "evt_race"],
                |row| row.get(4),
            )
            .unwrap();
        let stale_owner = db.query_row(
            SQL_EFFECT_INSERT,
            rusqlite::params![
                "evt_race",
                "stripe-webhook-effect:race",
                digest,
                old_fence,
                "pending:invoice.paid",
                11_i64,
                "owner-old",
            ],
            |row| row.get::<_, String>(0),
        );
        assert!(matches!(
            stale_owner,
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        assert_eq!(new_fence, old_fence + 1, "new lease fences stale owner");
    }

    #[test]
    fn receive_rejects_raw_body_digest_mismatch() {
        let event = AuthenticatedWebhookEvent {
            event_id: "evt_1".to_owned(),
            event_type: "invoice.paid".to_owned(),
            raw_body_hex: "00".to_owned(),
            payload_sha256: "0".repeat(64),
            stripe_created_at_ms: None,
        };
        assert!(validate_authenticated_event(&event).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verified_admission_context_registers_the_inbox_in_its_d1_batch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let server = std::thread::spawn(move || {
            for request_index in 0..4 {
                let (mut stream, _) = listener.accept().expect("loopback accept");
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0_u8; 4096];
                    let read = stream.read(&mut buffer).expect("request read");
                    bytes.extend_from_slice(&buffer[..read]);
                    let Some(headers_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = std::str::from_utf8(&bytes[..headers_end]).expect("headers utf8");
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .expect("content length")
                        .parse::<usize>()
                        .expect("content length number");
                    if bytes.len() >= headers_end + 4 + length {
                        break;
                    }
                }
                let body_start = bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[body_start..]).expect("D1 request");
                let statements = request["batch"].as_array().expect("D1 batch");
                assert_eq!(
                    statements.len(),
                    match request_index {
                        0 => 2,
                        1 | 2 => 5,
                        _ => 6,
                    }
                );
                if request_index == 1 {
                    assert!(statements[0]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("stripe_webhook_event_inbox"));
                    assert!(statements[2]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("staging_load_test_resources"));
                    assert!(statements[4]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("SELECT resource.receipt_ref"));
                }
                if request_index == 2 {
                    assert!(statements[0]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("stripe_webhook_event_effects"));
                    assert!(statements[2]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("staging_load_test_resources"));
                }
                if request_index == 3 {
                    assert!(statements[0]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("UPDATE stripe_webhook_event_effects"));
                    assert!(statements[4]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("SELECT resource.receipt_ref"));
                    assert!(statements[5]["sql"]
                        .as_str()
                        .unwrap()
                        .contains("NOT EXISTS"));
                }
                let results = (0..statements.len())
                    .map(|index| {
                        serde_json::json!({
                        "results": if (request_index == 1 && index == 0)
                            || (request_index == 2 && index == 0)
                            || (request_index == 3 && (index == 0 || index == 2)) {
                            vec![serde_json::json!({"event_id": "evt_owned"})]
                        } else if (request_index == 1 || request_index == 2 || request_index == 3) && index == 4 {
                            vec![serde_json::json!({"receipt_ref": "a".repeat(64)})]
                                } else { vec![] },
                                "success": true
                            })
                    })
                    .collect::<Vec<_>>();
                let body = serde_json::json!({"result": results, "success": true, "errors": []})
                    .to_string();
                write!(stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body).expect("response write");
            }
        });

        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let admission_client =
            D1HttpClient::new_for_loopback_test(&env, &endpoint).expect("admission D1 client");
        let inbox_client = Arc::new(
            D1HttpClient::new_for_loopback_test(&env, &endpoint).expect("inbox D1 client"),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let issued = now - 1;
        let expires = now + 60_000;
        let target_sha = "a".repeat(40);
        let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = format!(
            "v1.123.webhook.staging.{}.{}.{}.{}",
            target_sha, issued, expires, nonce
        );
        let key = b"01234567890123456789012345678901";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC key");
        mac.update(b"corelink/staging-load-admission-auth/v1\0");
        mac.update(payload.as_bytes());
        let credential = format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()));
        let verifier =
            crate::storage::staging_load_test_admission::StagingLoadTestAdmissionVerifier::new(
                "staging", key,
            )
            .expect("staging verifier");
        let verified = verifier
            .verify(&credential, now)
            .expect("verified admission");
        let store = crate::storage::staging_load_test_admission::StagingLoadTestAdmissionStore::from_d1_client_for_test(admission_client);
        let context = store
            .consume_verified_admission(
                crate::storage::staging_load_test_admission::StagingLoadTestAdmissionExpectation {
                    run_id: "123",
                    scenario: StagingLoadTestScenario::Webhook,
                    target_environment: "staging",
                    target_deployment_sha: &target_sha,
                },
                verified,
            )
            .await
            .expect("durably consumed admission");
        let inbox = D1WebhookInbox::new(inbox_client);
        let raw = "00";
        let event = AuthenticatedWebhookEvent {
            event_id: "evt_owned".to_owned(),
            event_type: "invoice.paid".to_owned(),
            raw_body_hex: raw.to_owned(),
            payload_sha256: hex::encode(Sha256::digest(hex::decode(raw).unwrap())),
            stripe_created_at_ms: None,
        };
        let outcome = inbox
            .receive_with_ownership_context(&event, 10, Some(&context))
            .expect("atomic inbox write");
        assert_eq!(outcome, InboxReceipt::Received);
        let durable_event = DurableWebhookEvent {
            event_id: event.event_id.clone(),
            event_type: event.event_type.clone(),
            raw_body_hex: event.raw_body_hex.clone(),
            payload_sha256: event.payload_sha256.clone(),
            stripe_created_at_ms: 0,
        };
        let claim = InboxClaim {
            event_id: durable_event.event_id.clone(),
            fence: 1,
        };
        assert_eq!(
            inbox
                .reserve_effect_with_ownership_context(
                    &claim,
                    "owner",
                    &durable_event,
                    "effect-key",
                    "invoice.paid",
                    11,
                    Some(&context),
                )
                .expect("atomic effect reservation"),
            EffectReservation::Reserved
        );
        assert!(inbox
            .commit_effect_with_ownership_context(
                &claim,
                "owner",
                &durable_event,
                "effect-key",
                "invoice.paid",
                12,
                Some(&context),
            )
            .expect("effect commit verifies prior ownership"));
        server.join().expect("loopback D1 server");
    }
}
