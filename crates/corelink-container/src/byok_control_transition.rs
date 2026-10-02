//! Token-guarded, tenant-granular BYOK control transitions over D1.

use std::{sync::Arc, time::Duration};

use corelink_hash::Digest;
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::byok_transition_fence::{
    ByokStatus, ConfigState, D1ByokFence, FenceError, TransitionFence,
};
use crate::customer_d1::{ByokActivation, ByokState, ByokWriteError};
use crate::storage::d1_http::{D1BatchStatement, D1HttpClient, D1Row};
use crate::storage::{
    staging_load_test_admission::StagingLoadTestAdmissionContext,
    staging_load_test_ownership::{
        StagingLoadTestDisposition, StagingLoadTestResourceClass, StagingLoadTestScenario,
        StagingLoadTestWriteContext,
    },
};

const TRANSITION_LEASE: Duration = Duration::from_secs(60);
const ACTIVATION_DEADLINE_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const GUARD_EXISTS: &str = "EXISTS (SELECT 1 FROM byok_transition_commit_guard a \
    WHERE a.tenant_id = ?1 AND a.token = ?2 AND a.epoch = ?3 AND a.action = ?4)";

/// Complete customer-CMK identity. Tenant resolution and status transitions
/// always compare all three fields; key text alone is not an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmkIdentity {
    /// Canonical provider name (`aws`, `gcp`, `azure`, or `vault`).
    pub provider: String,
    /// Provider-native CMK resource identifier.
    pub key_id: String,
    /// Canonical CMK region or provider endpoint region.
    pub region: String,
}

/// One exact tenant binding returned for a checked CMK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCmkBinding {
    /// Tenant whose active/partial configuration names this CMK.
    pub tenant_id: String,
    /// Complete CMK identity observed for the tenant.
    pub identity: CmkIdentity,
}

/// Opaque exact-run identity passed from the sealed migration-0151 locator.
/// The IDs are deliberately omitted from debug output.
pub(crate) struct StagingByokPendingTeardownLocator {
    pub(crate) tenant_id: String,
    pub(crate) intent_id: String,
}

impl core::fmt::Debug for StagingByokPendingTeardownLocator {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagingByokPendingTeardownLocator")
            .field("tenant_id", &"[REDACTED]")
            .field("intent_id", &"[REDACTED]")
            .finish()
    }
}

/// Fixed, redacted result for synthetic BYOK teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagingByokTeardownError {
    /// The internal locator is absent, malformed, or does not bind one exact
    /// disposable synthetic activation.
    InvalidLocator,
    /// The tenant has left the permitted pending, generation-zero state.
    UnsafeState,
    /// The durable readback or cancellation batch could not be verified.
    StorageUnavailable,
}

impl core::fmt::Display for StagingByokTeardownError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLocator => "staging BYOK teardown locator is invalid",
            Self::UnsafeState => "staging BYOK teardown state is not safely cancellable",
            Self::StorageUnavailable => "staging BYOK teardown readback is unavailable",
        })
    }
}

impl std::error::Error for StagingByokTeardownError {}

/// Production control authority. Every successful method completes its fence,
/// state mutation, gate-epoch change and durable outcome in one D1 batch.
#[derive(Debug)]
pub struct D1ByokControl {
    client: Arc<D1HttpClient>,
    fence: D1ByokFence<D1HttpClient>,
}

impl D1ByokControl {
    /// Construct the guarded control authority over one durable D1 client.
    #[must_use]
    pub fn new(client: Arc<D1HttpClient>) -> Self {
        Self {
            fence: D1ByokFence::new(Arc::clone(&client)),
            client,
        }
    }

    /// Read-only idempotency preflight for the public activation route.
    ///
    /// Returns `true` only when the canonical request hash matches durable
    /// live work or a result that is still actively committed. A divergent
    /// live request remains a conflict; a divergent active result returns
    /// `false` so the normal rotation validation and KMS checks still run.
    pub async fn activation_retry_preflight(
        &self,
        activation: &ByokActivation,
    ) -> Result<bool, ByokWriteError> {
        activation.validate_for_control()?;
        let region = required_region(activation.cmk_region.as_deref())?;
        if let Some(current) = self.active_config_identity(&activation.tenant_id).await? {
            validate_current_rotation_boundary(&current, activation, region)?;
        }
        let request_hash = ActivationHashes::new(activation, region).request;
        let Some(existing) = self
            .activation_request(&activation.tenant_id, &request_hash)
            .await?
        else {
            return Ok(false);
        };
        if existing.same_request {
            return Ok(true);
        }
        if existing.state != ByokState::Active {
            return Err(ByokWriteError::IllegalTransition {
                from: existing.state,
                to: ByokState::Active,
            });
        }
        validate_rotation_boundary(&existing, activation, region)?;
        Ok(false)
    }

    /// Persist validated custody material as `pending`. Publication is a
    /// separate WP4 backfill commit guarded by its own transition token; this
    /// method never changes `current_generation` or claims encryption active.
    pub async fn prepare_activation(
        &self,
        activation: &ByokActivation,
        now_ms: i64,
    ) -> Result<(), ByokWriteError> {
        self.prepare_activation_with_context(activation, now_ms, None)
            .await
    }

    /// Persist validated custody material and register a synthetic activation
    /// in the same D1 transaction when request-scoped staging authority exists.
    pub async fn prepare_activation_with_context(
        &self,
        activation: &ByokActivation,
        now_ms: i64,
        context: StagingLoadTestWriteContext<'_>,
    ) -> Result<(), ByokWriteError> {
        if context.is_some() {
            return Err(ByokWriteError::Invalid(
                "staging BYOK activation requires a sealed synthetic tenant reference".to_owned(),
            ));
        }
        self.prepare_activation_authorized(activation, now_ms, context, None)
            .await
    }

    /// Persist BYOK activation only for a freshly provisioned synthetic tenant
    /// bound to the exact admitted run, scenario, and deployment.
    pub(crate) async fn prepare_staging_synthetic_activation(
        &self,
        activation: &ByokActivation,
        now_ms: i64,
        context: &StagingLoadTestAdmissionContext,
        tenant_ref: &str,
    ) -> Result<(), ByokWriteError> {
        let tenant_id = self
            .resolve_staging_synthetic_tenant(context, tenant_ref)
            .await?;
        if !activation.tenant_id.is_empty() && activation.tenant_id != tenant_id {
            return Err(ByokWriteError::Invalid(
                "staging synthetic tenant reference does not match the activation".to_owned(),
            ));
        }
        let mut bound_activation = activation.clone();
        bound_activation.tenant_id = tenant_id;
        self.prepare_activation_authorized(
            &bound_activation,
            now_ms,
            Some(context),
            Some(tenant_ref),
        )
        .await
    }

    async fn prepare_activation_authorized(
        &self,
        activation: &ByokActivation,
        now_ms: i64,
        context: StagingLoadTestWriteContext<'_>,
        tenant_ref: Option<&str>,
    ) -> Result<(), ByokWriteError> {
        validate_byok_context(context)?;
        activation.validate_for_control()?;
        if now_ms < 0 {
            return Err(ByokWriteError::Invalid(
                "activation timestamp must not be negative".to_owned(),
            ));
        }
        if let Some(context) = context {
            let tenant_ref = tenant_ref.ok_or_else(|| {
                ByokWriteError::Invalid(
                    "staging BYOK activation requires a sealed synthetic tenant reference"
                        .to_owned(),
                )
            })?;
            self.validate_staging_synthetic_baseline(&activation.tenant_id, context, tenant_ref)
                .await?;
        } else if tenant_ref.is_some() {
            return Err(ByokWriteError::Invalid(
                "synthetic tenant reference requires staging admission".to_owned(),
            ));
        }
        let region = required_region(activation.cmk_region.as_deref())?;
        let current_identity = self.active_config_identity(&activation.tenant_id).await?;
        if let Some(current) = current_identity.as_ref() {
            validate_current_rotation_boundary(current, activation, region)?;
        }
        let hashes = ActivationHashes::new(activation, region);
        if let Some(existing) = self
            .activation_request(&activation.tenant_id, &hashes.request)
            .await?
        {
            if existing.same_request {
                return Ok(());
            }
            if existing.state != ByokState::Active {
                return Err(ByokWriteError::IllegalTransition {
                    from: existing.state,
                    to: ByokState::Active,
                });
            }
            validate_rotation_boundary(&existing, activation, region)?;
            // A divergent committed request is a rotation from the exact
            // active generation; it proceeds through a fresh guarded intent.
        }
        let snapshot = self
            .fence
            .load_snapshot(&activation.tenant_id)
            .await
            .map_err(map_fence)?;
        if !matches!(
            snapshot.config_state,
            ConfigState::Absent
                | ConfigState::Inactive
                | ConfigState::Pending
                | ConfigState::Active
        ) || snapshot.byok_status != ByokStatus::Active
        {
            return Err(ByokWriteError::IllegalTransition {
                from: state_for_error(snapshot.config_state),
                to: ByokState::Active,
            });
        }
        if snapshot.config_state == ConfigState::Active && current_identity.is_none() {
            return Err(ByokWriteError::Transport(
                "active BYOK snapshot has no authoritative config/secret identity".to_owned(),
            ));
        }
        self.commit_activation_preparation(
            &snapshot,
            activation,
            region,
            &hashes,
            current_identity.as_ref(),
            now_ms,
            context,
            tenant_ref,
        )
        .await
    }

    /// Cancel only an unpublished activation. A retry after cancellation has
    /// restored the preceding active generation (or the initial inactive
    /// state) is authorized exclusively by the latest durable control
    /// outcome; it can never fall through to crypto-shred behavior.
    pub async fn cancel_activation(
        &self,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<(), ByokWriteError> {
        if now_ms < 0 {
            return Err(ByokWriteError::Invalid(
                "deactivation timestamp must not be negative".to_owned(),
            ));
        }
        let snapshot = self
            .fence
            .load_snapshot(tenant_id)
            .await
            .map_err(map_fence)?;
        if snapshot.config_state == ConfigState::Pending {
            let intent = self.load_live_activation(tenant_id).await?;
            return self
                .commit_activation_cancellation(&snapshot, &intent)
                .await;
        }
        if matches!(
            snapshot.config_state,
            ConfigState::Active | ConfigState::Inactive
        ) && self.latest_completed_action(tenant_id).await?.as_deref() == Some("deactivate")
        {
            return Ok(());
        }
        Err(ByokWriteError::IllegalTransition {
            from: state_for_error(snapshot.config_state),
            to: ByokState::Inactive,
        })
    }

    /// Carry optional request-scoped staging authority to cancellation.
    pub async fn cancel_activation_with_context(
        &self,
        tenant_id: &str,
        now_ms: i64,
        context: StagingLoadTestWriteContext<'_>,
    ) -> Result<(), ByokWriteError> {
        validate_byok_context(context)?;
        self.cancel_activation(tenant_id, now_ms).await
    }

    /// Deliberately crypto-shred a published/active tenant. Pending copy work
    /// must be cancelled instead: shredding it before generation-zero source
    /// discovery is complete cannot prove exhaustive purge coverage.
    pub async fn shred(&self, tenant_id: &str, now_ms: i64) -> Result<(), ByokWriteError> {
        if now_ms < 0 {
            return Err(ByokWriteError::Invalid(
                "shred timestamp must not be negative".to_owned(),
            ));
        }
        let snapshot = self
            .fence
            .load_snapshot(tenant_id)
            .await
            .map_err(map_fence)?;
        if snapshot.config_state == ConfigState::Shredded {
            return if self.latest_completed_action(tenant_id).await?.as_deref() == Some("shred") {
                Ok(())
            } else {
                Err(ByokWriteError::Transport(
                    "shredded BYOK state has no latest durable shred outcome".to_owned(),
                ))
            };
        }
        if snapshot.config_state == ConfigState::Partial {
            let intent = self.load_live_activation(tenant_id).await?;
            return self
                .commit_activation_preemption(&snapshot, &intent, now_ms)
                .await;
        }
        if snapshot.config_state != ConfigState::Active {
            return Err(ByokWriteError::IllegalTransition {
                from: state_for_error(snapshot.config_state),
                to: ByokState::Shredded,
            });
        }
        let fence = self
            .fence
            .acquire_transition_fence(tenant_id, &snapshot, TRANSITION_LEASE)
            .await
            .map_err(map_fence)?;
        self.commit_status_transition(&fence, "shred", None, now_ms)
            .await
    }

    /// Carry optional request-scoped staging authority to the shred boundary.
    pub async fn shred_with_context(
        &self,
        tenant_id: &str,
        now_ms: i64,
        context: StagingLoadTestWriteContext<'_>,
    ) -> Result<(), ByokWriteError> {
        validate_byok_context(context)?;
        self.shred(tenant_id, now_ms).await
    }

    /// Cancel and verify one exact-run synthetic activation. This path never
    /// reaches shred; any non-copy, nonzero-generation, or nonempty graph state
    /// is rejected before the production cancellation batch runs.
    pub(crate) async fn cancel_staging_pending_activation_and_readback(
        &self,
        locator: &StagingByokPendingTeardownLocator,
    ) -> Result<(), StagingByokTeardownError> {
        if !valid_staging_locator(locator) {
            return Err(StagingByokTeardownError::InvalidLocator);
        }
        let rows = self
            .client
            .query(
                "SELECT run.run_id,run.scenario,run.target_deployment_sha AS target_deployment_sha, \
                 json_extract(l.locator_json,'$.tenant_ref') AS tenant_ref \
                 FROM staging_load_test_teardown_locators l \
                 JOIN staging_load_test_resources resource ON resource.run_id=l.run_id \
                  AND resource.scenario=l.scenario AND resource.resource_class=l.resource_class \
                  AND resource.receipt_ref=l.receipt_ref \
                 JOIN staging_load_test_runs run ON run.run_id=l.run_id AND run.scenario=l.scenario \
                 JOIN staging_load_test_synthetic_tenants synthetic \
                  ON synthetic.run_id=l.run_id AND synthetic.scenario=l.scenario \
                 JOIN tenant t ON t.tenant_id=synthetic.tenant_id \
                 JOIN byok_tenant_gate gate ON gate.tenant_id=t.tenant_id \
                 JOIN byok_activation_intent activation ON activation.tenant_id=t.tenant_id \
                 JOIN tenant_byok_config config ON config.tenant_id=t.tenant_id \
                 JOIN tenant_byok_secret secret ON secret.tenant_id=t.tenant_id \
                 WHERE l.locator_kind='byok_pending_synthetic_v1' \
                  AND l.resource_class='byok_artifact' AND l.scenario='byok' \
                  AND json_extract(l.locator_json,'$.tenant_id')=?1 \
                  AND json_extract(l.locator_json,'$.intent_id')=?2 \
                  AND synthetic.tenant_id=?1 AND synthetic.baseline_marker='generation_zero_empty' \
                  AND activation.intent_id=?2 AND activation.phase='copy' \
                  AND activation.source_generation=0 AND activation.target_generation=1 \
                  AND config.state='pending' AND t.byok_status='active' \
                  AND secret.tcs_wrapped IS NOT NULL AND secret.cmk_key_id=config.cmk_key_id \
                  AND gate.current_generation=0 \
                  AND run.target_environment='staging' AND run.state='teardown_started' \
                  AND resource.disposition='disposable' AND resource.state='delete_started' \
                  AND resource.opaque_handle=('byok-activation:' || ?2) \
                  AND (SELECT count(*) FROM byok_activation_intent live \
                    WHERE live.tenant_id=t.tenant_id AND live.phase IN \
                     ('copy','published_partial','purging','ready_finalize'))=1 \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_object source \
                    WHERE source.tenant_id=t.tenant_id OR source.intent_id=activation.intent_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_capture source \
                    WHERE source.tenant_id=t.tenant_id) \
                  AND EXISTS (SELECT 1 FROM byok_activation_guard guard \
                    WHERE guard.guard_id=activation.guard_id AND guard.outcome='active') \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_generation generation \
                    WHERE generation.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_publication publication \
                    WHERE publication.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_item purge \
                    WHERE purge.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_cause cause \
                    JOIN byok_object_purge_item purge ON purge.purge_id=cause.purge_id \
                    WHERE purge.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_purge_identity_quarantine quarantine \
                    WHERE quarantine.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_data_intent data_intent \
                    WHERE data_intent.tenant_id=t.tenant_id AND data_intent.outcome='active')",
                &[json!(locator.tenant_id), json!(locator.intent_id)],
            )
            .await
            .map_err(|_| StagingByokTeardownError::StorageUnavailable)?;
        if rows.len() != 1 {
            return Err(StagingByokTeardownError::InvalidLocator);
        }
        let run_id = rows[0]
            .get("run_id")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::InvalidLocator)?;
        let scenario = rows[0]
            .get("scenario")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::InvalidLocator)?;
        let target_sha = rows[0]
            .get("target_deployment_sha")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::InvalidLocator)?;
        let tenant_ref = rows[0]
            .get("tenant_ref")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::InvalidLocator)?;
        if tenant_ref
            != staging_synthetic_tenant_ref(run_id, scenario, target_sha, &locator.tenant_id)
        {
            return Err(StagingByokTeardownError::InvalidLocator);
        }
        let snapshot = self
            .fence
            .load_snapshot(&locator.tenant_id)
            .await
            .map_err(|_| StagingByokTeardownError::StorageUnavailable)?;
        if snapshot.config_state != ConfigState::Pending || snapshot.current_generation != 0 {
            return Err(StagingByokTeardownError::UnsafeState);
        }
        let intent = self
            .load_live_activation(&locator.tenant_id)
            .await
            .map_err(|_| StagingByokTeardownError::StorageUnavailable)?;
        if intent.intent_id != locator.intent_id || intent.source_generation != 0 {
            return Err(StagingByokTeardownError::UnsafeState);
        }
        self.commit_activation_cancellation(&snapshot, &intent)
            .await
            .map_err(|_| StagingByokTeardownError::StorageUnavailable)?;
        self.verify_staging_cancellation_readback(locator, tenant_ref)
            .await
    }

    async fn verify_staging_cancellation_readback(
        &self,
        locator: &StagingByokPendingTeardownLocator,
        expected_tenant_ref: &str,
    ) -> Result<(), StagingByokTeardownError> {
        let rows = self
            .client
            .query(
                "SELECT run.run_id,run.scenario,run.target_deployment_sha, \
                 json_extract(l.locator_json,'$.tenant_ref') AS tenant_ref \
                 FROM staging_load_test_teardown_locators l \
                 JOIN staging_load_test_resources resource ON resource.run_id=l.run_id \
                  AND resource.scenario=l.scenario AND resource.resource_class=l.resource_class \
                  AND resource.receipt_ref=l.receipt_ref \
                 JOIN staging_load_test_runs run ON run.run_id=l.run_id AND run.scenario=l.scenario \
                 JOIN staging_load_test_synthetic_tenants synthetic \
                  ON synthetic.run_id=l.run_id AND synthetic.scenario=l.scenario \
                 JOIN tenant t ON t.tenant_id=synthetic.tenant_id \
                 JOIN byok_tenant_gate gate ON gate.tenant_id=t.tenant_id \
                 JOIN byok_activation_intent activation ON activation.tenant_id=t.tenant_id \
                 JOIN tenant_byok_config config ON config.tenant_id=t.tenant_id \
                 JOIN tenant_byok_secret secret ON secret.tenant_id=t.tenant_id \
                 WHERE l.locator_kind='byok_pending_synthetic_v1' \
                  AND l.resource_class='byok_artifact' AND l.scenario='byok' \
                  AND json_extract(l.locator_json,'$.tenant_id')=?1 \
                  AND json_extract(l.locator_json,'$.intent_id')=?2 \
                  AND synthetic.tenant_id=?1 AND synthetic.baseline_marker='generation_zero_empty' \
                  AND activation.intent_id=?2 AND activation.phase='aborted' \
                  AND activation.source_generation=0 AND activation.target_generation=1 \
                  AND config.state='inactive' AND config.cmk_provider IS NULL \
                  AND config.cmk_key_id IS NULL AND config.cmk_region IS NULL \
                  AND secret.tcs_wrapped IS NULL AND secret.cmk_key_id IS NULL \
                  AND gate.current_generation=0 AND t.byok_status='active' \
                  AND run.target_environment='staging' AND run.state='teardown_started' \
                  AND resource.disposition='disposable' AND resource.state='delete_started' \
                  AND resource.opaque_handle=('byok-activation:' || ?2) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_config active_config \
                    WHERE active_config.tenant_id=t.tenant_id AND active_config.state IN ('pending','active','partial')) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_secret active_secret \
                    WHERE active_secret.tenant_id=t.tenant_id AND active_secret.tcs_wrapped IS NOT NULL) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_secret_history secret_history \
                    WHERE secret_history.tenant_id=t.tenant_id AND secret_history.tcs_wrapped IS NOT NULL) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_config_history config_history \
                    WHERE config_history.tenant_id=t.tenant_id AND config_history.state IN ('active','partial')) \
                  AND EXISTS (SELECT 1 FROM byok_activation_guard guard \
                    WHERE guard.guard_id=activation.guard_id AND guard.outcome='aborted') \
                  AND EXISTS (SELECT 1 FROM byok_activation_postcondition postcondition \
                    WHERE postcondition.intent_id=activation.intent_id \
                     AND postcondition.expected_phase='aborted') \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_guard live_guard \
                    WHERE live_guard.tenant_id=t.tenant_id AND live_guard.outcome='active') \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_intent live \
                    WHERE live.tenant_id=t.tenant_id AND live.phase IN \
                     ('copy','published_partial','purging','ready_finalize')) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_capture source_capture \
                    WHERE source_capture.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_object source \
                    WHERE source.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_generation generation \
                    WHERE generation.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_publication publication \
                    WHERE publication.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_item purge \
                    WHERE purge.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_cause cause \
                    JOIN byok_object_purge_item purge ON purge.purge_id=cause.purge_id \
                    WHERE purge.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_purge_identity_quarantine quarantine \
                    WHERE quarantine.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_data_intent data_intent \
                    WHERE data_intent.tenant_id=t.tenant_id AND data_intent.outcome='active')",
                &[json!(locator.tenant_id), json!(locator.intent_id)],
            )
            .await
            .map_err(|_| StagingByokTeardownError::StorageUnavailable)?;
        if rows.len() != 1 {
            return Err(StagingByokTeardownError::UnsafeState);
        }
        let run_id = rows[0]
            .get("run_id")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::UnsafeState)?;
        let scenario = rows[0]
            .get("scenario")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::UnsafeState)?;
        let target_sha = rows[0]
            .get("target_deployment_sha")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::UnsafeState)?;
        let stored_ref = rows[0]
            .get("tenant_ref")
            .and_then(Value::as_str)
            .ok_or(StagingByokTeardownError::UnsafeState)?;
        let computed_ref =
            staging_synthetic_tenant_ref(run_id, scenario, target_sha, &locator.tenant_id);
        if stored_ref != expected_tenant_ref || stored_ref != computed_ref {
            return Err(StagingByokTeardownError::UnsafeState);
        }
        Ok(())
    }

    async fn latest_completed_action(
        &self,
        tenant_id: &str,
    ) -> Result<Option<String>, ByokWriteError> {
        let rows = self
            .client
            .query(
                "SELECT action FROM byok_control_outcome WHERE tenant_id=?1 \
                 AND outcome='completed' ORDER BY epoch DESC LIMIT 1",
                &[json!(tenant_id)],
            )
            .await
            .map_err(ByokWriteError::Transport)?;
        rows.first()
            .map(|row| text(row, "action"))
            .transpose()
            .map_err(ByokWriteError::Transport)
    }

    async fn validate_staging_synthetic_baseline(
        &self,
        tenant_id: &str,
        context: &StagingLoadTestAdmissionContext,
        tenant_ref: &str,
    ) -> Result<(), ByokWriteError> {
        let expected_ref = staging_synthetic_tenant_ref(
            context.run_id(),
            context.scenario().as_str(),
            context.target_deployment_sha(),
            tenant_id,
        );
        if tenant_ref != expected_ref {
            return Err(ByokWriteError::Invalid(
                "staging synthetic tenant reference does not match the admitted run".to_owned(),
            ));
        }
        let rows = self
            .client
            .query(
                "SELECT 1 AS ready FROM staging_load_test_synthetic_tenants st \
                 JOIN staging_load_test_runs run ON run.run_id=st.run_id AND run.scenario=st.scenario \
                 JOIN tenant t ON t.tenant_id=st.tenant_id \
                 JOIN byok_tenant_gate gate ON gate.tenant_id=t.tenant_id \
                 WHERE st.run_id=?1 AND st.scenario=?2 AND st.tenant_id=?3 \
                  AND st.baseline_marker='generation_zero_empty' \
                  AND run.target_environment='staging' AND run.target_deployment_sha=?4 \
                  AND run.state='open' AND t.byok_status='active' AND gate.current_generation=0 \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_config c WHERE c.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_secret s WHERE s.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_config_history h WHERE h.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM tenant_byok_secret_history h WHERE h.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_intent a WHERE a.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_guard a WHERE a.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_capture a WHERE a.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_source_object a WHERE a.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_key_health a WHERE a.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_operation_guard a \
                    JOIN byok_activation_intent i ON i.intent_id=a.intent_id WHERE i.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_worker_assertion a \
                    JOIN byok_activation_intent i ON i.intent_id=a.intent_id WHERE i.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_postcondition a \
                    JOIN byok_activation_intent i ON i.intent_id=a.intent_id WHERE i.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_suspension_postcondition a \
                    JOIN byok_activation_intent i ON i.intent_id=a.intent_id WHERE i.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_activation_transition_assertion a \
                    JOIN byok_activation_guard g ON g.guard_id=a.guard_id WHERE g.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_generation g WHERE g.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_publication p WHERE p.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_item p WHERE p.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_object_purge_cause p JOIN byok_object_purge_item i \
                    ON i.purge_id=p.purge_id WHERE i.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_purge_identity_quarantine p WHERE p.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_data_intent d WHERE d.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_transition_fence f WHERE f.tenant_id=t.tenant_id) \
                  AND NOT EXISTS (SELECT 1 FROM byok_control_outcome o WHERE o.tenant_id=t.tenant_id)",
                &[
                    json!(context.run_id()),
                    json!(context.scenario().as_str()),
                    json!(tenant_id),
                    json!(context.target_deployment_sha()),
                ],
            )
            .await
            .map_err(|_| {
                ByokWriteError::Invalid(
                    "staging synthetic tenant baseline could not be verified".to_owned(),
                )
            })?;
        if rows.len() != 1 {
            return Err(ByokWriteError::Invalid(
                "staging synthetic tenant baseline is not empty".to_owned(),
            ));
        }
        Ok(())
    }

    async fn resolve_staging_synthetic_tenant(
        &self,
        context: &StagingLoadTestAdmissionContext,
        tenant_ref: &str,
    ) -> Result<String, ByokWriteError> {
        validate_byok_context(Some(context))?;
        let rows = self
            .client
            .query(
                "SELECT synthetic.tenant_id FROM staging_load_test_synthetic_tenants synthetic \
                 JOIN staging_load_test_runs run ON run.run_id=synthetic.run_id \
                  AND run.scenario=synthetic.scenario \
                 WHERE synthetic.run_id=?1 AND synthetic.scenario=?2 \
                  AND synthetic.baseline_marker='generation_zero_empty' \
                  AND run.target_environment='staging' AND run.target_deployment_sha=?3 \
                  AND run.state='open'",
                &[
                    json!(context.run_id()),
                    json!(context.scenario().as_str()),
                    json!(context.target_deployment_sha()),
                ],
            )
            .await
            .map_err(|_| {
                ByokWriteError::Invalid(
                    "staging synthetic tenant locator could not be verified".to_owned(),
                )
            })?;
        if rows.len() != 1 {
            return Err(ByokWriteError::Invalid(
                "staging synthetic tenant locator is absent or ambiguous".to_owned(),
            ));
        }
        let tenant_id = text(&rows[0], "tenant_id").map_err(|_| {
            ByokWriteError::Invalid("staging synthetic tenant locator is invalid".to_owned())
        })?;
        if tenant_ref
            != staging_synthetic_tenant_ref(
                context.run_id(),
                context.scenario().as_str(),
                context.target_deployment_sha(),
                &tenant_id,
            )
        {
            return Err(ByokWriteError::Invalid(
                "staging synthetic tenant reference does not match the admitted run".to_owned(),
            ));
        }
        Ok(tenant_id)
    }

    /// Resolve every encryption-active or activating tenant for one complete
    /// key identity. Pending activation already depends on the customer key.
    pub async fn resolve_active_tenants(
        &self,
        identity: &CmkIdentity,
    ) -> Result<Vec<TenantCmkBinding>, String> {
        let rows = self
            .client
            .query(
                "SELECT DISTINCT tenant_id FROM ( \
                  SELECT c.tenant_id FROM tenant_byok_config c JOIN tenant t ON t.tenant_id=c.tenant_id \
                   WHERE c.state IN ('pending','active','partial') AND t.byok_status<>'revoked' \
                    AND c.cmk_provider=?1 AND c.cmk_key_id=?2 AND c.cmk_region=?3 \
                  UNION \
                  SELECT a.tenant_id FROM byok_activation_intent a JOIN tenant t ON t.tenant_id=a.tenant_id \
                   WHERE a.phase IN ('copy','published_partial','purging','ready_finalize') \
                    AND t.byok_status<>'revoked' AND a.source_generation>0 \
                    AND a.source_cmk_provider=?1 AND a.source_cmk_key_id=?2 \
                    AND a.source_cmk_region=?3) ORDER BY tenant_id",
                &[
                    json!(identity.provider),
                    json!(identity.key_id),
                    json!(identity.region),
                ],
            )
            .await?;
        rows.into_iter()
            .map(|row| {
                let tenant_id = text(&row, "tenant_id")?;
                Ok(TenantCmkBinding {
                    tenant_id,
                    identity: identity.clone(),
                })
            })
            .collect()
    }

    /// Whether any exact binding remains degraded. Unlike the legacy
    /// `LIMIT 1` query, this cannot hide a degraded tenant behind an active
    /// tenant sharing the same CMK.
    pub async fn has_degraded_tenant(&self, identity: &CmkIdentity) -> Result<bool, String> {
        let rows = self
            .client
            .query(
                "SELECT 1 AS present FROM tenant t WHERE t.byok_status='degraded_read_only' \
                 AND (EXISTS (SELECT 1 FROM tenant_byok_config c WHERE c.tenant_id=t.tenant_id \
                   AND c.state IN ('pending','active','partial') AND c.cmk_provider=?1 \
                   AND c.cmk_key_id=?2 AND c.cmk_region=?3) OR EXISTS (SELECT 1 \
                   FROM byok_activation_intent a WHERE a.tenant_id=t.tenant_id \
                   AND a.phase IN ('copy','published_partial','purging','ready_finalize') \
                   AND a.source_generation>0 AND a.source_cmk_provider=?1 \
                   AND a.source_cmk_key_id=?2 AND a.source_cmk_region=?3)) LIMIT 1",
                &[
                    json!(identity.provider),
                    json!(identity.key_id),
                    json!(identity.region),
                ],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    async fn record_activation_key_health(
        &self,
        binding: &TenantCmkBinding,
        access_state: &str,
        at_ms: i64,
    ) -> Result<(), String> {
        let rows = self
            .client
            .query(
                "UPDATE byok_activation_key_health SET access_state=?1, \
             checked_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000) \
             WHERE tenant_id=?2 AND cmk_provider=?3 AND cmk_key_id=?4 AND cmk_region=?5 \
              AND ?6>=0 AND EXISTS (SELECT 1 FROM byok_activation_intent a \
               WHERE a.intent_id=byok_activation_key_health.intent_id \
                AND a.phase IN ('copy','published_partial','purging','ready_finalize')) \
             RETURNING intent_id",
                &[
                    json!(access_state),
                    json!(binding.tenant_id),
                    json!(binding.identity.provider),
                    json!(binding.identity.key_id),
                    json!(binding.identity.region),
                    json!(at_ms),
                ],
            )
            .await?;
        if rows.is_empty() {
            return Err("checked CMK does not match a live activation dependency".to_owned());
        }
        Ok(())
    }

    async fn has_unhealthy_activation_dependency(&self, tenant_id: &str) -> Result<bool, String> {
        self.client
            .query(
                "SELECT 1 AS present FROM byok_activation_key_health kh \
             JOIN byok_activation_intent a ON a.intent_id=kh.intent_id \
             WHERE kh.tenant_id=?1 AND kh.access_state='unavailable' \
              AND a.phase IN ('copy','published_partial','purging','ready_finalize') LIMIT 1",
                &[json!(tenant_id)],
            )
            .await
            .map(|rows| !rows.is_empty())
    }

    /// Fence one exact tenant/CMK binding and mark it degraded read-only.
    pub async fn degrade_tenant(
        &self,
        binding: &TenantCmkBinding,
        detected_at_ms: i64,
    ) -> Result<bool, String> {
        self.transition_binding(binding, "degrade", detected_at_ms)
            .await
    }

    /// Restore one exact degraded tenant/CMK binding after KMS recovery.
    pub async fn restore_tenant(
        &self,
        binding: &TenantCmkBinding,
        restored_at_ms: i64,
    ) -> Result<bool, String> {
        self.transition_binding(binding, "restore", restored_at_ms)
            .await
    }

    async fn transition_binding(
        &self,
        binding: &TenantCmkBinding,
        action: &'static str,
        at_ms: i64,
    ) -> Result<bool, String> {
        let snapshot = self
            .fence
            .load_snapshot(&binding.tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        if matches!(
            snapshot.config_state,
            ConfigState::Pending | ConfigState::Partial
        ) {
            if action == "restore" {
                self.record_activation_key_health(binding, "healthy", at_ms)
                    .await?;
                if self
                    .has_unhealthy_activation_dependency(&binding.tenant_id)
                    .await?
                {
                    return Ok(false);
                }
            } else if snapshot.byok_status == ByokStatus::DegradedReadOnly {
                self.record_activation_key_health(binding, "unavailable", at_ms)
                    .await?;
                return Ok(true);
            }
        }
        let expected_status = if action == "degrade" {
            ByokStatus::Active
        } else {
            ByokStatus::DegradedReadOnly
        };
        if !matches!(
            snapshot.config_state,
            ConfigState::Pending | ConfigState::Active | ConfigState::Partial
        ) || snapshot.byok_status != expected_status
        {
            return Ok(false);
        }
        if matches!(
            snapshot.config_state,
            ConfigState::Pending | ConfigState::Partial
        ) {
            let intent = self
                .load_live_activation(&binding.tenant_id)
                .await
                .map_err(|error| error.to_string())?;
            return self
                .commit_activation_status_transition(
                    &snapshot,
                    &intent,
                    action,
                    &binding.identity,
                    at_ms,
                )
                .await
                .map(|()| true)
                .map_err(|error| error.to_string());
        }
        let fence = self
            .fence
            .acquire_transition_fence(&binding.tenant_id, &snapshot, TRANSITION_LEASE)
            .await
            .map_err(|e| e.to_string())?;
        self.commit_status_transition(&fence, action, Some(&binding.identity), at_ms)
            .await
            .map(|()| true)
            .map_err(|e| e.to_string())
    }

    /// Priority degrade/restore while an activation owns the ordinary tenant
    /// fence. The single D1 batch revokes worker/data capabilities, changes
    /// tenant status, invalidates caches, and (on restore) binds a fresh exact
    /// activation fence before work can be claimed again.
    async fn commit_activation_status_transition(
        &self,
        snapshot: &crate::byok_transition_fence::ConfigSnapshot,
        intent: &LiveActivation,
        action: &'static str,
        identity: &CmkIdentity,
        at_ms: i64,
    ) -> Result<(), ByokWriteError> {
        let lease_ms = i64::try_from(TRANSITION_LEASE.as_millis())
            .map_err(|_| ByokWriteError::Invalid("activation control lease overflow".to_owned()))?;
        let control_token = random_capability();
        let activation_token = random_capability();
        let activation_capability = random_capability();
        let postcondition_token = random_capability();
        let expected_status = if action == "degrade" {
            "active"
        } else {
            "degraded_read_only"
        };
        let next_status = if action == "degrade" {
            "degraded_read_only"
        } else {
            "active"
        };
        let next_state_version = intent.state_version.checked_add(1).ok_or_else(|| {
            ByokWriteError::Invalid("activation state version overflow".to_owned())
        })?;
        let now = "(CAST(strftime('%s','now') AS INTEGER)*1000)";
        let mut statements = Vec::new();

        if action == "degrade" {
            statements.push(activation_health_statement(
                intent,
                identity,
                "unavailable",
                at_ms,
            ));
            statements.push(D1BatchStatement::new(
                format!(
                    "UPDATE byok_data_intent SET outcome='expired',completed_at_ms={now} \
                         WHERE tenant_id=?1 AND outcome='active'"
                ),
                vec![json!(intent.tenant_id)],
            ));
            statements.push(D1BatchStatement::new(
                format!(
                    "UPDATE byok_activation_guard SET outcome='expired',completed_at_ms={now} \
                         WHERE guard_id=?1 AND tenant_id=?2 AND outcome='active'"
                ),
                vec![json!(intent.guard_id), json!(intent.tenant_id)],
            ));
            statements.push(D1BatchStatement::new(
                format!("UPDATE byok_transition_fence SET outcome='aborted',completed_at_ms={now} \
                         WHERE token=(SELECT transition_token FROM byok_activation_guard WHERE guard_id=?1) \
                           AND tenant_id=?2 AND outcome='active'"),
                vec![json!(intent.guard_id), json!(intent.tenant_id)],
            ));
        }

        statements.push(D1BatchStatement::new(
            format!("INSERT INTO byok_transition_fence \
              (token,tenant_id,epoch,observed_gate_epoch,observed_generation,observed_config_version, \
               observed_config_state,observed_byok_status,acquired_at_ms,expires_at_ms) \
             SELECT ?1,g.tenant_id,COALESCE((SELECT MAX(p.epoch) FROM byok_transition_fence p \
               WHERE p.tenant_id=g.tenant_id),0)+1,g.gate_epoch,g.current_generation,c.config_version, \
               c.state,t.byok_status,{now},{now}+?2 \
             FROM byok_tenant_gate g JOIN tenant t ON t.tenant_id=g.tenant_id \
             JOIN tenant_byok_config c ON c.tenant_id=g.tenant_id \
             JOIN byok_activation_intent a ON a.tenant_id=g.tenant_id \
             JOIN byok_activation_guard ag ON ag.guard_id=a.guard_id \
             WHERE g.tenant_id=?3 AND a.intent_id=?4 AND a.state_version=?5 \
               AND a.phase IN ('copy','published_partial','purging','ready_finalize') \
               AND a.suspension_state=?6 AND ag.outcome=?7 \
               AND g.gate_epoch=?8 AND g.current_generation=?9 \
               AND c.config_version=?10 AND c.state=?11 AND t.byok_status=?12 \
               AND ((c.cmk_provider=?13 AND c.cmk_key_id=?14 AND c.cmk_region=?15) \
                OR (a.source_generation>0 AND a.source_cmk_provider=?13 \
                 AND a.source_cmk_key_id=?14 AND a.source_cmk_region=?15)) \
               AND (?16<>'restore' OR NOT EXISTS (SELECT 1 FROM byok_activation_key_health kh \
                 WHERE kh.intent_id=a.intent_id AND kh.access_state='unavailable')) \
               AND NOT EXISTS (SELECT 1 FROM byok_data_intent d WHERE d.tenant_id=g.tenant_id \
                 AND d.outcome='active' AND d.expires_at_ms>{now}) \
               AND NOT EXISTS (SELECT 1 FROM byok_transition_fence f WHERE f.tenant_id=g.tenant_id \
                 AND f.outcome='active' AND f.expires_at_ms>{now})"),
            vec![
                json!(control_token), json!(lease_ms), json!(intent.tenant_id),
                json!(intent.intent_id), json!(intent.state_version),
                json!(if action == "degrade" { "active" } else { "degraded_read_only" }),
                json!("expired"),
                json!(snapshot.gate_epoch), json!(snapshot.current_generation),
                json!(snapshot.config_version), json!(config_state_name(snapshot.config_state)),
                json!(expected_status), json!(identity.provider), json!(identity.key_id),
                json!(identity.region),
                json!(action),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_transition_commit_guard \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region) \
             SELECT token,tenant_id,epoch,?3,?4,?5,?6 FROM byok_transition_fence \
             WHERE token=?1 AND tenant_id=?2",
            vec![
                json!(control_token),
                json!(intent.tenant_id),
                json!(action),
                json!(identity.provider),
                json!(identity.key_id),
                json!(identity.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!("UPDATE tenant SET byok_status=?3, \
              byok_revoked_at_ms=CASE ?4 WHEN 'degrade' THEN {now} ELSE NULL END, \
              byok_revoked_provider=CASE ?4 WHEN 'degrade' THEN ?5 ELSE NULL END, \
              byok_revoked_kms_key_id=CASE ?4 WHEN 'degrade' THEN ?6 ELSE NULL END \
             WHERE tenant_id=?1 AND ?7>=0 AND EXISTS (SELECT 1 FROM byok_transition_commit_guard cg \
              WHERE cg.token=?2 AND cg.tenant_id=?1 AND cg.action=?4)"),
            vec![json!(intent.tenant_id), json!(control_token), json!(next_status), json!(action),
                 json!(identity.provider), json!(identity.key_id), json!(at_ms)],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE byok_tenant_gate SET gate_epoch=gate_epoch+1 WHERE tenant_id=?1 \
             AND EXISTS (SELECT 1 FROM byok_transition_commit_guard cg \
              WHERE cg.token=?2 AND cg.tenant_id=?1 AND cg.action=?3)",
            vec![json!(intent.tenant_id), json!(control_token), json!(action)],
        ));

        if action == "restore" {
            statements.push(D1BatchStatement::new(
                format!("INSERT INTO byok_transition_fence \
                 (token,tenant_id,epoch,observed_gate_epoch,observed_generation,observed_config_version, \
                  observed_config_state,observed_byok_status,acquired_at_ms,expires_at_ms) \
                 SELECT ?1,g.tenant_id,COALESCE((SELECT MAX(p.epoch) FROM byok_transition_fence p \
                   WHERE p.tenant_id=g.tenant_id),0)+1,g.gate_epoch,g.current_generation,c.config_version, \
                   c.state,t.byok_status,{now},{now}+?2 FROM byok_tenant_gate g \
                 JOIN tenant t ON t.tenant_id=g.tenant_id JOIN tenant_byok_config c ON c.tenant_id=g.tenant_id \
                 WHERE g.tenant_id=?3 AND t.byok_status='active' \
                  AND EXISTS (SELECT 1 FROM byok_transition_commit_guard cg WHERE cg.token=?4 \
                    AND cg.tenant_id=g.tenant_id AND cg.action='restore')"),
                vec![json!(activation_token), json!(lease_ms), json!(intent.tenant_id), json!(control_token)],
            ));
            statements.push(D1BatchStatement::new(
                format!(
                    "UPDATE byok_activation_guard SET transition_token=?1, \
                  transition_epoch=(SELECT epoch FROM byok_transition_fence WHERE token=?1), \
                  capability_token=?2,epoch=epoch+1,outcome='active',acquired_at_ms={now}, \
                  expires_at_ms={now}+?3,completed_at_ms=NULL \
                 WHERE guard_id=?4 AND tenant_id=?5 AND outcome='expired'"
                ),
                vec![
                    json!(activation_token),
                    json!(activation_capability),
                    json!(lease_ms),
                    json!(intent.guard_id),
                    json!(intent.tenant_id),
                ],
            ));
            statements.push(D1BatchStatement::new(
                format!("UPDATE byok_activation_intent SET suspension_state='active',suspended_at_ms=NULL, \
                  observed_gate_epoch=CASE WHEN phase='copy' THEN \
                    (SELECT gate_epoch FROM byok_tenant_gate WHERE tenant_id=?2) ELSE observed_gate_epoch END, \
                  publication_gate_epoch=CASE WHEN phase<>'copy' THEN \
                    (SELECT gate_epoch FROM byok_tenant_gate WHERE tenant_id=?2) ELSE publication_gate_epoch END, \
                  claim_owner=NULL,claim_token=NULL,claim_expires_at_ms=NULL,claim_epoch=claim_epoch+1, \
                  state_version=state_version+1,checkpointed_at_ms={now} \
                 WHERE intent_id=?1 AND tenant_id=?2 AND state_version=?3"),
                vec![json!(intent.intent_id), json!(intent.tenant_id), json!(intent.state_version)],
            ));
        } else {
            statements.push(D1BatchStatement::new(
                format!("UPDATE byok_activation_intent SET suspension_state='degraded_read_only', \
                  suspended_at_ms={now},claim_owner=NULL,claim_token=NULL,claim_expires_at_ms=NULL, \
                  claim_epoch=claim_epoch+1,state_version=state_version+1,checkpointed_at_ms={now} \
                 WHERE intent_id=?1 AND tenant_id=?2 AND state_version=?3"),
                vec![json!(intent.intent_id), json!(intent.tenant_id), json!(intent.state_version)],
            ));
        }
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_transition_fence SET outcome='committed',completed_at_ms={now} \
             WHERE token=?1 AND tenant_id=?2 AND outcome='active'"
            ),
            vec![json!(control_token), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_control_outcome \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region,outcome, \
              alert_recipient,alert_outcome,completed_at_ms) \
             SELECT token,tenant_id,epoch,?3,?4,?5,?6,'completed',tenant_id, \
              'customer_activity_recorded',{now} FROM byok_transition_fence \
             WHERE token=?1 AND tenant_id=?2 AND outcome='committed'"
            ),
            vec![
                json!(control_token),
                json!(intent.tenant_id),
                json!(action),
                json!(identity.provider),
                json!(identity.key_id),
                json!(identity.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_transition_commit_guard WHERE token=?1 AND tenant_id=?2 AND action=?3",
            vec![json!(control_token), json!(intent.tenant_id), json!(action)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_activation_suspension_postcondition \
              (operation_token,intent_id,expected_state_version,action,checked_at_ms) \
              VALUES (?1,?2,?3,?4,{now})"
            ),
            vec![
                json!(postcondition_token),
                json!(intent.intent_id),
                json!(next_state_version),
                json!(action),
            ],
        ));
        self.run_batch(statements)
            .await
            .map_err(ByokWriteError::Transport)
    }

    async fn commit_activation_preparation(
        &self,
        snapshot: &crate::byok_transition_fence::ConfigSnapshot,
        act: &ByokActivation,
        region: &str,
        hashes: &ActivationHashes,
        current_identity: Option<&ActiveConfigIdentity>,
        now_ms: i64,
        context: StagingLoadTestWriteContext<'_>,
        tenant_ref: Option<&str>,
    ) -> Result<(), ByokWriteError> {
        use base64::Engine as _;
        let wrapped = base64::engine::general_purpose::STANDARD.encode(&act.tcs_wrapped);
        let config_version = snapshot.next_config_version().map_err(map_fence)?;
        let target_generation = snapshot.next_generation().map_err(map_fence)?;
        let transition_token = random_capability();
        let guard_id = random_capability();
        let capability_token = random_capability();
        let intent_id = random_capability();
        let assertion_token = random_capability();
        let postcondition_token = random_capability();
        let lease_ms = i64::try_from(TRANSITION_LEASE.as_millis()).map_err(|_| {
            ByokWriteError::Invalid("activation transition lease overflow".to_owned())
        })?;
        // Every statement below is one D1 REST batch. Conditional zero-row
        // writes are converted into a real SQLite error by the final
        // postcondition, so HTTP 202 can only follow a durable `copy` intent.
        let mut statements = vec![D1BatchStatement::new(
            "INSERT INTO byok_transition_fence \
             (token,tenant_id,epoch,observed_gate_epoch,observed_generation, \
              observed_config_version,observed_config_state,observed_byok_status, \
              acquired_at_ms,expires_at_ms) \
             SELECT ?1,g.tenant_id, \
              COALESCE((SELECT MAX(p.epoch) FROM byok_transition_fence p \
                        WHERE p.tenant_id=g.tenant_id),0)+1, \
              g.gate_epoch,g.current_generation,c.config_version,COALESCE(c.state,'absent'), \
              t.byok_status,(CAST(strftime('%s','now') AS INTEGER)*1000), \
              (CAST(strftime('%s','now') AS INTEGER)*1000)+?2 \
             FROM byok_tenant_gate g JOIN tenant t ON t.tenant_id=g.tenant_id \
             LEFT JOIN tenant_byok_config c ON c.tenant_id=g.tenant_id \
             LEFT JOIN tenant_byok_secret s ON s.tenant_id=g.tenant_id \
             WHERE g.tenant_id=?3 AND g.gate_epoch=?4 AND g.current_generation=?5 \
              AND ((?6 IS NULL AND c.config_version IS NULL) OR c.config_version=?6) \
              AND COALESCE(c.state,'absent')=?7 AND t.byok_status='active' \
              AND COALESCE(c.state,'absent') IN ('absent','inactive','pending','active') \
              AND (?8 IS NULL OR (c.config_version=?8 AND c.cmk_provider=?9 \
                AND c.cmk_key_id=?10 AND c.cmk_region=?11 AND s.tcs_version=?12 \
                AND s.cmk_key_id=c.cmk_key_id AND s.tcs_wrapped IS NOT NULL)) \
              AND NOT EXISTS (SELECT 1 FROM byok_data_intent i WHERE i.tenant_id=g.tenant_id \
                  AND i.outcome='active' AND i.expires_at_ms>(CAST(strftime('%s','now') AS INTEGER)*1000)) \
              AND NOT EXISTS (SELECT 1 FROM byok_transition_fence f WHERE f.tenant_id=g.tenant_id \
                  AND f.outcome='active' AND f.expires_at_ms>(CAST(strftime('%s','now') AS INTEGER)*1000))",
            vec![
                json!(transition_token),
                json!(lease_ms),
                json!(act.tenant_id),
                json!(snapshot.gate_epoch),
                json!(snapshot.current_generation),
                json!(snapshot.config_version),
                json!(config_state_name(snapshot.config_state)),
                json!(current_identity.map(|identity| identity.config_version)),
                json!(current_identity.map(|identity| identity.provider.as_str())),
                json!(current_identity.map(|identity| identity.key_id.as_str())),
                json!(current_identity.map(|identity| identity.region.as_str())),
                json!(current_identity.map(|identity| identity.tcs_version)),
            ],
        )];
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_source_capture \
             (transition_token,tenant_id,source_generation,source_config_version, \
              source_cmk_provider,source_cmk_key_id,source_cmk_region,source_tcs_version,captured_at_ms) \
             SELECT f.token,f.tenant_id,g.current_generation, \
              CASE WHEN g.current_generation=0 THEN NULL ELSE c.config_version END, \
              CASE WHEN g.current_generation=0 THEN NULL ELSE c.cmk_provider END, \
              CASE WHEN g.current_generation=0 THEN NULL ELSE c.cmk_key_id END, \
              CASE WHEN g.current_generation=0 THEN NULL ELSE c.cmk_region END, \
              CASE WHEN g.current_generation=0 THEN NULL ELSE s.tcs_version END, \
              (CAST(strftime('%s','now') AS INTEGER)*1000) \
             FROM byok_transition_fence f JOIN byok_tenant_gate g ON g.tenant_id=f.tenant_id \
             LEFT JOIN tenant_byok_config c ON c.tenant_id=f.tenant_id \
             LEFT JOIN tenant_byok_secret s ON s.tenant_id=f.tenant_id \
             WHERE f.token=?1 AND f.tenant_id=?2 AND f.outcome='active'",
            vec![json!(transition_token), json!(act.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_transition_commit_guard \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region) \
             SELECT token,tenant_id,epoch,'prepare',?3,?4,?5 \
             FROM byok_transition_fence WHERE tenant_id=?1 AND token=?2",
            vec![
                json!(act.tenant_id),
                json!(transition_token),
                json!(act.cmk_provider),
                json!(act.cmk_key_id),
                json!(region),
            ],
        ));
        // Config first: the 0121 history trigger observes and archives the
        // exact old config/secret identity before policy replacement.
        statements.push(D1BatchStatement::new(
            "INSERT INTO tenant_byok_config \
             (tenant_id,mode,crypto_mode,cmk_provider,cmk_key_id,cmk_region,state,created_at_ms,updated_at_ms,config_version) \
             VALUES (?1,?2,?3,?4,?5,?6,'pending', \
              (CAST(strftime('%s','now') AS INTEGER)*1000), \
              (CAST(strftime('%s','now') AS INTEGER)*1000),1) \
             ON CONFLICT(tenant_id) DO UPDATE SET mode=excluded.mode,crypto_mode=excluded.crypto_mode, \
             cmk_provider=excluded.cmk_provider,cmk_key_id=excluded.cmk_key_id,cmk_region=excluded.cmk_region, \
             state='pending',updated_at_ms=excluded.updated_at_ms,config_version=tenant_byok_config.config_version+1 \
             WHERE ?7>=0 AND EXISTS (SELECT 1 FROM byok_transition_commit_guard a \
              WHERE a.tenant_id=?1 AND a.token=?8 AND a.action='prepare')",
            vec![
                json!(act.tenant_id),
                json!(act.mode.as_str()),
                json!(act.crypto_mode.as_str()),
                json!(act.cmk_provider),
                json!(act.cmk_key_id),
                json!(region),
                json!(now_ms),
                json!(transition_token),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO tenant_byok_secret \
             (tenant_id,tcs_wrapped,cmk_key_id,tcs_version,wrapped_at_ms) \
             VALUES (?1,?2,?3,1,(CAST(strftime('%s','now') AS INTEGER)*1000)) \
             ON CONFLICT(tenant_id) DO UPDATE SET \
             tcs_wrapped=excluded.tcs_wrapped,cmk_key_id=excluded.cmk_key_id, \
             tcs_version=tenant_byok_secret.tcs_version+1,wrapped_at_ms=excluded.wrapped_at_ms \
             WHERE ?4>=0 AND EXISTS (SELECT 1 FROM byok_transition_commit_guard a \
              WHERE a.tenant_id=?1 AND a.token=?5 AND a.action='prepare')",
            vec![
                json!(act.tenant_id),
                json!(wrapped),
                json!(act.cmk_key_id),
                json!(now_ms),
                json!(transition_token),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_guard \
             (guard_id,tenant_id,transition_token,transition_epoch,capability_token,epoch, \
              action,priority,acquired_at_ms,expires_at_ms) \
             SELECT ?1,?2,f.token,f.epoch,?3, \
              COALESCE((SELECT MAX(old.epoch) FROM byok_activation_guard old \
                        WHERE old.tenant_id=?2),0)+1, \
              'activate',10,(CAST(strftime('%s','now') AS INTEGER)*1000),f.expires_at_ms \
             FROM byok_transition_fence f WHERE f.tenant_id=?2 AND f.token=?4 \
              AND f.outcome='active' AND f.expires_at_ms>(CAST(strftime('%s','now') AS INTEGER)*1000)",
            vec![
                json!(guard_id),
                json!(act.tenant_id),
                json!(capability_token),
                json!(transition_token),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_intent \
             (intent_id,tenant_id,guard_id,request_blake3,config_version,mode,crypto_mode, \
              cmk_provider,cmk_key_id,cmk_region,policy_blake3,tcs_version,wrapped_tcs_blake3, \
              source_generation,source_config_version,source_cmk_provider,source_cmk_key_id, \
              source_cmk_region,source_tcs_version,target_generation,observed_gate_epoch,deadline_at_ms, \
              created_at_ms,checkpointed_at_ms) \
             SELECT ?1,c.tenant_id,?2,?3,c.config_version,c.mode,c.crypto_mode, \
              c.cmk_provider,c.cmk_key_id,c.cmk_region,?4,s.tcs_version,?5, \
              g.current_generation,src.source_config_version,src.source_cmk_provider, \
              src.source_cmk_key_id,src.source_cmk_region,src.source_tcs_version,?6,g.gate_epoch, \
              (CAST(strftime('%s','now') AS INTEGER)*1000)+?7, \
              (CAST(strftime('%s','now') AS INTEGER)*1000), \
              (CAST(strftime('%s','now') AS INTEGER)*1000) \
             FROM tenant_byok_config c JOIN tenant_byok_secret s ON s.tenant_id=c.tenant_id \
             JOIN byok_tenant_gate g ON g.tenant_id=c.tenant_id \
             JOIN byok_activation_guard a ON a.guard_id=?2 AND a.tenant_id=c.tenant_id \
             JOIN byok_transition_fence f ON f.token=a.transition_token AND f.epoch=a.transition_epoch \
             JOIN byok_activation_source_capture src ON src.transition_token=f.token \
              AND src.tenant_id=c.tenant_id AND src.source_generation=g.current_generation \
             WHERE c.tenant_id=?8 AND c.state='pending' AND c.config_version=?9 \
              AND c.cmk_provider=?10 AND c.cmk_key_id=?11 AND c.cmk_region=?12 \
              AND s.cmk_key_id=c.cmk_key_id AND g.current_generation=?13 \
              AND (g.current_generation=0 OR (f.observed_config_state='active' \
               AND src.source_tcs_version IS NOT NULL))",
            vec![
                json!(intent_id),
                json!(guard_id),
                json!(hashes.request),
                json!(hashes.policy),
                json!(hashes.wrapped_tcs),
                json!(target_generation),
                json!(ACTIVATION_DEADLINE_MS),
                json!(act.tenant_id),
                json!(config_version),
                json!(act.cmk_provider),
                json!(act.cmk_key_id),
                json!(region),
                json!(snapshot.current_generation),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_key_health \
             (intent_id,tenant_id,dependency_role,cmk_provider,cmk_key_id,cmk_region,access_state,checked_at_ms) \
             SELECT intent_id,tenant_id,'target',cmk_provider,cmk_key_id,cmk_region,'healthy', \
              (CAST(strftime('%s','now') AS INTEGER)*1000) FROM byok_activation_intent WHERE intent_id=?1 \
             UNION ALL SELECT intent_id,tenant_id,'source',source_cmk_provider,source_cmk_key_id, \
              source_cmk_region,'healthy',(CAST(strftime('%s','now') AS INTEGER)*1000) \
              FROM byok_activation_intent WHERE intent_id=?1 AND source_generation>0",
            vec![json!(intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_control_outcome \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region, \
              outcome,alert_recipient,alert_outcome,completed_at_ms) \
             SELECT token,tenant_id,epoch,'prepare',?3,?4,?5,'completed',tenant_id, \
              'not_applicable',(CAST(strftime('%s','now') AS INTEGER)*1000) \
             FROM byok_transition_fence WHERE tenant_id=?1 AND token=?2",
            vec![
                json!(act.tenant_id),
                json!(transition_token),
                json!(act.cmk_provider),
                json!(act.cmk_key_id),
                json!(region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_transition_commit_guard \
             WHERE tenant_id=?1 AND token=?2 AND action='prepare'",
            vec![json!(act.tenant_id), json!(transition_token)],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_transition_assertion \
             (assertion_token,guard_id,checked_at_ms) VALUES \
             (?1,?2,(CAST(strftime('%s','now') AS INTEGER)*1000))",
            vec![json!(assertion_token), json!(guard_id)],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_activation_postcondition \
             (operation_token,intent_id,expected_state_version,expected_phase,checked_at_ms) \
             VALUES (?1,?2,1,'copy',(CAST(strftime('%s','now') AS INTEGER)*1000))",
            vec![json!(postcondition_token), json!(intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_activation_source_capture \
             WHERE transition_token=?1 AND tenant_id=?2",
            vec![json!(transition_token), json!(act.tenant_id)],
        ));
        if let Some(context) = context {
            // The BYOK activation intent is the durable owner for its later
            // bounded R2 copy/reconciliation work. Register that opaque intent
            // identity in this same D1 batch before the worker can claim it.
            statements.push(byok_ownership_statement(context, &intent_id, now_ms)?);
            let tenant_ref = tenant_ref.ok_or_else(|| {
                ByokWriteError::Invalid(
                    "staging BYOK activation requires a sealed synthetic tenant reference"
                        .to_owned(),
                )
            })?;
            statements.push(byok_teardown_locator_statement(
                context,
                &act.tenant_id,
                tenant_ref,
                &intent_id,
                now_ms,
            )?);
        }
        self.run_batch(statements)
            .await
            .map_err(ByokWriteError::Transport)
    }

    async fn activation_request(
        &self,
        tenant_id: &str,
        request_blake3: &str,
    ) -> Result<Option<ExistingActivationRequest>, ByokWriteError> {
        // Live work and a still-active committed result are idempotency
        // authorities. Aborted work is intentionally retryable; preempted work
        // is ignored here so the terminal shredded snapshot rejects it below.
        let rows = self
            .client
            .query(
                "SELECT a.request_blake3,a.phase,c.cmk_provider,c.cmk_region FROM byok_activation_intent a \
                 JOIN tenant_byok_config c ON c.tenant_id=a.tenant_id \
                 JOIN tenant t ON t.tenant_id=a.tenant_id \
                 WHERE a.tenant_id=?1 AND ( \
                  a.phase IN ('copy','published_partial','purging','ready_finalize') \
                  OR (a.phase='committed' AND c.state='active' AND t.byok_status='active')) \
                 ORDER BY a.created_at_ms DESC,a.intent_id DESC LIMIT 1",
                &[json!(tenant_id)],
            )
            .await
            .map_err(ByokWriteError::Transport)?;
        rows.first()
            .map(|row| {
                let phase = text(row, "phase")?;
                Ok(ExistingActivationRequest {
                    same_request: text(row, "request_blake3")? == request_blake3,
                    state: if phase == "committed" {
                        ByokState::Active
                    } else {
                        ByokState::Pending
                    },
                    provider: text(row, "cmk_provider")?,
                    region: text(row, "cmk_region")?,
                })
            })
            .transpose()
            .map_err(ByokWriteError::Transport)
    }

    /// Current mutable custody identity. This is intentionally independent of
    /// activation history so legacy/pre-0121 active tenants cannot bypass the
    /// provider/region rotation boundary.
    async fn active_config_identity(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ActiveConfigIdentity>, ByokWriteError> {
        let rows = self
            .client
            .query(
                "SELECT c.config_version,c.cmk_provider,c.cmk_key_id,c.cmk_region,s.tcs_version \
                 FROM tenant_byok_config c LEFT JOIN tenant_byok_secret s ON s.tenant_id=c.tenant_id \
                 WHERE c.tenant_id=?1 AND c.state='active' LIMIT 1",
                &[json!(tenant_id)],
            )
            .await
            .map_err(ByokWriteError::Transport)?;
        rows.first()
            .map(|row| {
                Ok(ActiveConfigIdentity {
                    config_version: integer(row, "config_version")?,
                    provider: text(row, "cmk_provider")?,
                    key_id: text(row, "cmk_key_id")?,
                    region: text(row, "cmk_region")?,
                    tcs_version: integer(row, "tcs_version")?,
                })
            })
            .transpose()
            .map_err(ByokWriteError::Transport)
    }

    async fn load_live_activation(
        &self,
        tenant_id: &str,
    ) -> Result<LiveActivation, ByokWriteError> {
        let rows = self
            .client
            .query(
                "SELECT a.intent_id,a.state_version,a.guard_id,a.cmk_provider,a.cmk_key_id,a.cmk_region, \
                 a.source_generation,a.tcs_version,a.source_config_version, \
                 a.source_cmk_provider,a.source_cmk_key_id,a.source_cmk_region,a.source_tcs_version \
                 FROM byok_activation_intent a WHERE a.tenant_id=?1 \
                  AND a.phase IN ('copy','published_partial','purging','ready_finalize') LIMIT 1",
                &[json!(tenant_id)],
            )
            .await
            .map_err(ByokWriteError::Transport)?;
        let row = rows.first().ok_or_else(|| {
            ByokWriteError::Transport(
                "pending/partial BYOK config has no durable live activation intent".to_owned(),
            )
        })?;
        let source_generation =
            integer(row, "source_generation").map_err(ByokWriteError::Transport)?;
        let source_identity = if source_generation == 0 {
            None
        } else {
            Some(LiveSourceIdentity {
                config_version: integer(row, "source_config_version")
                    .map_err(ByokWriteError::Transport)?,
                provider: text(row, "source_cmk_provider").map_err(ByokWriteError::Transport)?,
                key_id: text(row, "source_cmk_key_id").map_err(ByokWriteError::Transport)?,
                region: text(row, "source_cmk_region").map_err(ByokWriteError::Transport)?,
                tcs_version: integer(row, "source_tcs_version")
                    .map_err(ByokWriteError::Transport)?,
            })
        };
        Ok(LiveActivation {
            tenant_id: tenant_id.to_owned(),
            intent_id: text(row, "intent_id").map_err(ByokWriteError::Transport)?,
            state_version: integer(row, "state_version").map_err(ByokWriteError::Transport)?,
            guard_id: text(row, "guard_id").map_err(ByokWriteError::Transport)?,
            provider: text(row, "cmk_provider").map_err(ByokWriteError::Transport)?,
            key_id: text(row, "cmk_key_id").map_err(ByokWriteError::Transport)?,
            region: text(row, "cmk_region").map_err(ByokWriteError::Transport)?,
            source_generation,
            source_identity,
            tcs_version: integer(row, "tcs_version").map_err(ByokWriteError::Transport)?,
        })
    }

    async fn commit_activation_preemption(
        &self,
        snapshot: &crate::byok_transition_fence::ConfigSnapshot,
        intent: &LiveActivation,
        now_ms: i64,
    ) -> Result<(), ByokWriteError> {
        let next_state_version = intent.state_version.checked_add(1).ok_or_else(|| {
            ByokWriteError::Invalid("activation state version overflow".to_owned())
        })?;
        let control_token = random_capability();
        let operation_token = random_capability();
        let lease_ms = i64::try_from(TRANSITION_LEASE.as_millis()).map_err(|_| {
            ByokWriteError::Invalid("activation preemption lease overflow".to_owned())
        })?;
        let now = "(CAST(strftime('%s','now') AS INTEGER)*1000)";
        let mut statements = vec![D1BatchStatement::new(
            format!(
                "UPDATE byok_data_intent SET outcome='expired',completed_at_ms={now} \
                 WHERE tenant_id=?1 AND outcome='active'"
            ),
            vec![json!(intent.tenant_id)],
        )];
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_transition_fence \
             (token,tenant_id,epoch,observed_gate_epoch,observed_generation, \
              observed_config_version,observed_config_state,observed_byok_status, \
              acquired_at_ms,expires_at_ms) \
             SELECT ?1,g.tenant_id, \
              COALESCE((SELECT MAX(p.epoch) FROM byok_transition_fence p \
                        WHERE p.tenant_id=g.tenant_id),0)+1, \
              g.gate_epoch,g.current_generation,c.config_version,c.state,t.byok_status, \
              (CAST(strftime('%s','now') AS INTEGER)*1000), \
              (CAST(strftime('%s','now') AS INTEGER)*1000)+?2 \
             FROM byok_tenant_gate g JOIN tenant t ON t.tenant_id=g.tenant_id \
             JOIN tenant_byok_config c ON c.tenant_id=g.tenant_id \
             JOIN byok_activation_intent a ON a.tenant_id=g.tenant_id \
             WHERE g.tenant_id=?3 AND a.intent_id=?4 AND a.state_version=?5 \
              AND a.phase IN ('copy','published_partial','purging','ready_finalize') \
              AND g.gate_epoch=?6 AND g.current_generation=?7 \
              AND c.config_version=?8 AND c.state=?9 AND t.byok_status='active'",
            vec![
                json!(control_token),
                json!(lease_ms),
                json!(intent.tenant_id),
                json!(intent.intent_id),
                json!(intent.state_version),
                json!(snapshot.gate_epoch),
                json!(snapshot.current_generation),
                json!(snapshot.config_version),
                json!(config_state_name(snapshot.config_state)),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_transition_commit_guard \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region) \
             SELECT token,tenant_id,epoch,'shred',?3,?4,?5 \
             FROM byok_transition_fence WHERE tenant_id=?1 AND token=?2",
            vec![
                json!(intent.tenant_id),
                json!(control_token),
                json!(intent.provider),
                json!(intent.key_id),
                json!(intent.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_activation_operation_guard \
                 (operation_token,intent_id,claim_token,control_token,expected_state_version,action,checked_at_ms) \
                 VALUES (?1,?2,NULL,?3,?4,'preempt',{now})"
            ),
            vec![
                json!(operation_token),
                json!(intent.intent_id),
                json!(control_token),
                json!(intent.state_version),
            ],
        ));
        self.append_preemption_purge(&mut statements, intent, now);
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_logical_object_publication WHERE tenant_id=?1 \
             AND physical_key IN (SELECT physical_key FROM byok_logical_object_generation \
              WHERE tenant_id=?1 AND backfill_run_id=?2)",
            vec![json!(intent.tenant_id), json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_logical_object_generation SET outcome='abandoned',completed_at_ms={now} \
                 WHERE tenant_id=?1 AND backfill_run_id=?2 AND outcome='allocated'"
            ),
            vec![json!(intent.tenant_id), json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE tenant SET byok_status='revoked', \
             byok_revoked_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000), \
             byok_revoked_provider=?3,byok_revoked_kms_key_id=?4 \
             WHERE tenant_id=?1 AND ?2>=0",
            vec![
                json!(intent.tenant_id),
                json!(now_ms),
                json!(intent.provider),
                json!(intent.key_id),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE byok_tenant_gate SET gate_epoch=gate_epoch+1 WHERE tenant_id=?1",
            vec![json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_config SET state='shredded',config_version=config_version+1, \
                 cmk_provider=NULL,cmk_key_id=NULL,cmk_region=NULL,updated_at_ms={now} \
                 WHERE tenant_id=?1 AND state IN ('pending','partial')"
            ),
            vec![json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE tenant_byok_secret SET tcs_wrapped=NULL,cmk_key_id=NULL,wrapped_at_ms=NULL, \
             tcs_version=tcs_version+1 WHERE tenant_id=?1",
            vec![json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_secret_history SET tcs_wrapped=NULL,retired_at_ms={now} \
                 WHERE tenant_id=?1 AND tcs_wrapped IS NOT NULL"
            ),
            vec![json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_activation_intent SET phase='preempted', \
                 failure_reason='operator_crypto_shred',cmk_provider=NULL,cmk_key_id=NULL,cmk_region=NULL, \
                 completed_at_ms={now},claim_owner=NULL,claim_token=NULL,claim_expires_at_ms=NULL, \
                 state_version=state_version+1,checkpointed_at_ms={now} \
                 WHERE intent_id=?1 AND tenant_id=?2 AND state_version=?3 \
                  AND phase IN ('copy','published_partial','purging','ready_finalize')"
            ),
            vec![
                json!(intent.intent_id),
                json!(intent.tenant_id),
                json!(intent.state_version),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_transition_fence SET outcome='committed',completed_at_ms={now} \
                 WHERE token=?1 AND tenant_id=?2 AND outcome='active'"
            ),
            vec![json!(control_token), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_control_outcome \
                 (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region,outcome, \
                  alert_recipient,alert_outcome,completed_at_ms) \
                 SELECT token,tenant_id,epoch,'shred',?3,?4,?5,'completed',tenant_id, \
                  'not_applicable',{now} FROM byok_transition_fence \
                 WHERE token=?1 AND tenant_id=?2"
            ),
            vec![
                json!(control_token),
                json!(intent.tenant_id),
                json!(intent.provider),
                json!(intent.key_id),
                json!(intent.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_transition_commit_guard WHERE token=?1 AND tenant_id=?2 AND action='shred'",
            vec![json!(control_token), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_activation_postcondition \
                 (operation_token,intent_id,expected_state_version,expected_phase,checked_at_ms) \
                 VALUES (?1,?2,?3,'preempted',{now})"
            ),
            vec![
                json!(operation_token),
                json!(intent.intent_id),
                json!(next_state_version),
            ],
        ));
        self.run_batch(statements)
            .await
            .map_err(ByokWriteError::Transport)
    }

    async fn commit_activation_cancellation(
        &self,
        snapshot: &crate::byok_transition_fence::ConfigSnapshot,
        intent: &LiveActivation,
    ) -> Result<(), ByokWriteError> {
        let next_state_version = intent.state_version.checked_add(1).ok_or_else(|| {
            ByokWriteError::Invalid("activation state version overflow".to_owned())
        })?;
        let control_token = random_capability();
        let operation_token = random_capability();
        let lease_ms = i64::try_from(TRANSITION_LEASE.as_millis()).map_err(|_| {
            ByokWriteError::Invalid("activation cancellation lease overflow".to_owned())
        })?;
        let now = "(CAST(strftime('%s','now') AS INTEGER)*1000)";
        let mut statements = vec![D1BatchStatement::new(
            format!(
                "UPDATE byok_data_intent SET outcome='expired',completed_at_ms={now} \
                 WHERE tenant_id=?1 AND outcome='active'"
            ),
            vec![json!(intent.tenant_id)],
        )];
        statements.push(control_fence_statement(
            &control_token,
            lease_ms,
            snapshot,
            intent,
        ));
        statements.push(D1BatchStatement::new(
            "INSERT INTO byok_transition_commit_guard \
             (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region) \
             SELECT token,tenant_id,epoch,'deactivate',?3,?4,?5 \
             FROM byok_transition_fence WHERE tenant_id=?1 AND token=?2",
            vec![
                json!(intent.tenant_id),
                json!(control_token),
                json!(intent.provider),
                json!(intent.key_id),
                json!(intent.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_activation_operation_guard \
                 (operation_token,intent_id,claim_token,control_token,expected_state_version,action,checked_at_ms) \
                 VALUES (?1,?2,NULL,?3,?4,'cancel',{now})"
            ),
            vec![
                json!(operation_token),
                json!(intent.intent_id),
                json!(control_token),
                json!(intent.state_version),
            ],
        ));
        self.append_preemption_purge(&mut statements, intent, now);
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_logical_object_generation SET outcome='abandoned',completed_at_ms={now} \
                 WHERE tenant_id=?1 AND backfill_run_id=?2 AND outcome='allocated'"
            ),
            vec![json!(intent.tenant_id), json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_config SET state='inactive',config_version=config_version+1, \
                 cmk_provider=NULL,cmk_key_id=NULL,cmk_region=NULL,updated_at_ms={now} \
                 WHERE tenant_id=?1 AND state='pending' AND ?2=0"
            ),
            vec![json!(intent.tenant_id), json!(intent.source_generation)],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE tenant_byok_secret SET tcs_wrapped=NULL,cmk_key_id=NULL,wrapped_at_ms=NULL, \
             tcs_version=tcs_version+1 WHERE tenant_id=?1 AND ?2=0",
            vec![json!(intent.tenant_id), json!(intent.source_generation)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_config SET \
                 mode=(SELECT h.mode FROM tenant_byok_config_history h \
                       WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active'), \
                 crypto_mode=(SELECT h.crypto_mode FROM tenant_byok_config_history h \
                       WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active'), \
                 cmk_provider=(SELECT h.cmk_provider FROM tenant_byok_config_history h \
                       WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active'), \
                 cmk_key_id=(SELECT h.cmk_key_id FROM tenant_byok_config_history h \
                       WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active'), \
                 cmk_region=(SELECT h.cmk_region FROM tenant_byok_config_history h \
                       WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active'), \
                 state='active',config_version=config_version+1,updated_at_ms={now} \
                 WHERE tenant_id=?1 AND state='pending' AND ?2>0 \
                  AND EXISTS (SELECT 1 FROM tenant_byok_config_history h \
                      WHERE h.tenant_id=?1 AND h.config_version=?3 AND h.state='active' \
                       AND h.cmk_provider=?4 AND h.cmk_key_id=?5 AND h.cmk_region=?6) \
                  AND NOT EXISTS (SELECT 1 FROM byok_logical_object_publication p \
                      WHERE p.tenant_id=?1 AND p.generation<>?2)"
            ),
            vec![
                json!(intent.tenant_id),
                json!(intent.source_generation),
                json!(intent
                    .source_identity
                    .as_ref()
                    .map(|source| source.config_version)),
                json!(intent
                    .source_identity
                    .as_ref()
                    .map(|source| &source.provider)),
                json!(intent.source_identity.as_ref().map(|source| &source.key_id)),
                json!(intent.source_identity.as_ref().map(|source| &source.region)),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_secret SET \
                 tcs_wrapped=(SELECT h.tcs_wrapped FROM tenant_byok_secret_history h \
                     WHERE h.tenant_id=?1 AND h.tcs_version=?3 AND h.cmk_provider=?4 \
                      AND h.cmk_key_id=?5 AND h.cmk_region=?6 AND h.tcs_wrapped IS NOT NULL), \
                 cmk_key_id=(SELECT h.cmk_key_id FROM tenant_byok_secret_history h \
                     WHERE h.tenant_id=?1 AND h.tcs_version=?3 AND h.cmk_provider=?4 \
                      AND h.cmk_key_id=?5 AND h.cmk_region=?6 AND h.tcs_wrapped IS NOT NULL), \
                 tcs_version=tcs_version+1,wrapped_at_ms={now} \
                 WHERE tenant_id=?1 AND ?2>0 AND EXISTS (SELECT 1 \
                    FROM tenant_byok_secret_history h JOIN tenant_byok_config c ON c.tenant_id=h.tenant_id \
                    WHERE h.tenant_id=?1 AND h.tcs_version=?3 AND h.tcs_wrapped IS NOT NULL \
                     AND h.cmk_provider=c.cmk_provider AND h.cmk_key_id=c.cmk_key_id \
                     AND h.cmk_region=c.cmk_region)"
            ),
            vec![
                json!(intent.tenant_id),
                json!(intent.source_generation),
                json!(intent.source_identity.as_ref().map(|source| source.tcs_version)),
                json!(intent.source_identity.as_ref().map(|source| &source.provider)),
                json!(intent.source_identity.as_ref().map(|source| &source.key_id)),
                json!(intent.source_identity.as_ref().map(|source| &source.region)),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE tenant_byok_secret_history SET tcs_wrapped=NULL,retired_at_ms={now} \
                 WHERE tenant_id=?1 AND ?2>=0 AND ?3>=0 AND tcs_wrapped IS NOT NULL"
            ),
            vec![
                json!(intent.tenant_id),
                json!(intent.tcs_version),
                json!(intent.source_generation),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_activation_intent SET phase='aborted',failure_reason='operator_deactivate', \
                 completed_at_ms={now},claim_owner=NULL,claim_token=NULL,claim_expires_at_ms=NULL, \
                 state_version=state_version+1,checkpointed_at_ms={now} \
                 WHERE intent_id=?1 AND tenant_id=?2 AND state_version=?3 AND phase='copy'"
            ),
            vec![
                json!(intent.intent_id),
                json!(intent.tenant_id),
                json!(intent.state_version),
            ],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "UPDATE byok_transition_fence SET outcome='committed',completed_at_ms={now} \
                 WHERE token=?1 AND tenant_id=?2 AND outcome='active'"
            ),
            vec![json!(control_token), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_control_outcome \
                 (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region,outcome, \
                  alert_recipient,alert_outcome,completed_at_ms) \
                 SELECT token,tenant_id,epoch,'deactivate',?3,?4,?5,'completed',tenant_id, \
                  'not_applicable',{now} FROM byok_transition_fence \
                 WHERE token=?1 AND tenant_id=?2 AND outcome='committed'"
            ),
            vec![
                json!(control_token),
                json!(intent.tenant_id),
                json!(intent.provider),
                json!(intent.key_id),
                json!(intent.region),
            ],
        ));
        statements.push(D1BatchStatement::new(
            "DELETE FROM byok_transition_commit_guard \
             WHERE token=?1 AND tenant_id=?2 AND action='deactivate'",
            vec![json!(control_token), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT INTO byok_activation_postcondition \
                 (operation_token,intent_id,expected_state_version,expected_phase,checked_at_ms) \
                 VALUES (?1,?2,?3,'aborted',{now})"
            ),
            vec![
                json!(operation_token),
                json!(intent.intent_id),
                json!(next_state_version),
            ],
        ));
        self.run_batch(statements)
            .await
            .map_err(ByokWriteError::Transport)
    }

    fn append_preemption_purge(
        &self,
        statements: &mut Vec<D1BatchStatement>,
        intent: &LiveActivation,
        now: &str,
    ) {
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT OR IGNORE INTO byok_object_purge_item \
                 (purge_id,tenant_id,intent_id,object_kind,logical_key,generation,allocation_id, \
                  physical_key,object_size,object_blake3,crypto_mode,reason,state,next_attempt_at_ms,created_at_ms) \
                 SELECT lower(hex(randomblob(16))),s.tenant_id,s.intent_id,s.object_kind,s.logical_key, \
                  s.source_generation,s.source_allocation_id,s.source_physical_key,s.source_stored_size, \
                  s.source_blake3,s.source_crypto_mode,'activation_source','pending',{now},{now} \
                 FROM byok_activation_source_object s JOIN byok_activation_intent a ON a.intent_id=s.intent_id \
                 WHERE s.intent_id=?1 AND a.phase IN ('published_partial','purging','ready_finalize')"
            ),
            vec![json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT OR IGNORE INTO byok_object_purge_cause \
                 (purge_id,cause_kind,cause_id,created_at_ms) \
                 SELECT p.purge_id,'activation_source',s.intent_id,{now} \
                 FROM byok_activation_source_object s JOIN byok_object_purge_item p \
                  ON p.tenant_id=s.tenant_id AND p.physical_key=s.source_physical_key \
                 JOIN byok_activation_intent a ON a.intent_id=s.intent_id \
                 WHERE s.intent_id=?1 AND a.phase IN ('published_partial','purging','ready_finalize')"
            ),
            vec![json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            "UPDATE byok_activation_source_object SET copy_state='purge_queued' \
             WHERE intent_id=?1 AND copy_state IN ('published','purge_queued') \
              AND EXISTS (SELECT 1 FROM byok_activation_intent a WHERE a.intent_id=?1 \
               AND a.phase IN ('published_partial','purging','ready_finalize'))",
            vec![json!(intent.intent_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT OR IGNORE INTO byok_object_purge_item \
                 (purge_id,tenant_id,intent_id,object_kind,logical_key,generation,allocation_id, \
                  physical_key,object_size,object_blake3,crypto_mode,reason,state,next_attempt_at_ms,created_at_ms) \
                 SELECT lower(hex(randomblob(16))),s.tenant_id,s.intent_id,s.object_kind,s.logical_key, \
                  a.target_generation,s.target_allocation_id,s.target_physical_key, \
                  x.ciphertext_size,x.ciphertext_blake3,a.crypto_mode, \
                  'publish_loser','pending',{now},{now} \
                 FROM byok_activation_source_object s JOIN byok_activation_intent a ON a.intent_id=s.intent_id \
                 LEFT JOIN byok_logical_object_generation x ON x.tenant_id=s.tenant_id \
                  AND x.backfill_run_id=s.intent_id AND x.object_kind=s.object_kind \
                  AND x.logical_key=s.logical_key AND x.allocation_id=s.target_allocation_id \
                 WHERE s.intent_id=?1 AND s.tenant_id=?2 AND s.target_physical_key IS NOT NULL"
            ),
            vec![json!(intent.intent_id), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT OR IGNORE INTO byok_object_purge_item \
                 (purge_id,tenant_id,intent_id,object_kind,logical_key,generation,allocation_id, \
                  physical_key,object_size,object_blake3,crypto_mode,reason,state,next_attempt_at_ms,created_at_ms) \
                 SELECT lower(hex(randomblob(16))),x.tenant_id,?1,x.object_kind,x.logical_key,x.generation, \
                  x.allocation_id,x.physical_key,x.ciphertext_size,x.ciphertext_blake3,a.crypto_mode, \
                  'publish_loser','pending',{now},{now} \
                 FROM byok_logical_object_generation x JOIN byok_activation_intent a ON a.intent_id=?1 \
                 WHERE x.tenant_id=?2 AND x.backfill_run_id=?1"
            ),
            vec![json!(intent.intent_id), json!(intent.tenant_id)],
        ));
        statements.push(D1BatchStatement::new(
            format!(
                "INSERT OR IGNORE INTO byok_object_purge_cause \
                 (purge_id,cause_kind,cause_id,created_at_ms) \
                 SELECT p.purge_id,'publish_loser',p.allocation_id,{now} FROM byok_object_purge_item p \
                 WHERE p.tenant_id=?2 AND p.allocation_id IS NOT NULL AND (EXISTS (SELECT 1 FROM byok_activation_source_object s \
                   WHERE s.intent_id=?1 AND s.tenant_id=p.tenant_id \
                    AND s.target_physical_key=p.physical_key AND s.target_allocation_id=p.allocation_id) \
                  OR EXISTS (SELECT 1 FROM byok_logical_object_generation x \
                   WHERE x.backfill_run_id=?1 AND x.tenant_id=p.tenant_id \
                    AND x.physical_key=p.physical_key AND x.allocation_id=p.allocation_id \
                    AND x.generation=p.generation))"
            ),
            vec![json!(intent.intent_id), json!(intent.tenant_id)],
        ));
    }

    async fn commit_status_transition(
        &self,
        fence: &TransitionFence,
        action: &'static str,
        identity: Option<&CmkIdentity>,
        at_ms: i64,
    ) -> Result<(), ByokWriteError> {
        let full = identity.map(|i| (i.provider.as_str(), i.key_id.as_str(), i.region.as_str()));
        let mut statements = vec![guard_statement(fence, action, full)];
        match action {
            "shred" => {
                statements.push(D1BatchStatement::new(
                    "UPDATE tenant SET byok_status='revoked', \
                     byok_revoked_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000), \
                     byok_revoked_provider=(SELECT cmk_provider FROM tenant_byok_config WHERE tenant_id=?1), \
                     byok_revoked_kms_key_id=(SELECT cmk_key_id FROM tenant_byok_config WHERE tenant_id=?1) \
                     WHERE tenant_id=?1 AND ?5>=0 AND " .to_owned() + GUARD_EXISTS,
                    mutation_params(fence, action, at_ms),
                ));
                statements.push(D1BatchStatement::new(
                    "UPDATE tenant_byok_config SET state='shredded',cmk_provider=NULL,cmk_key_id=NULL,cmk_region=NULL, \
                     updated_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000),config_version=config_version+1 \
                     WHERE tenant_id=?1 AND ?5>=0 AND " .to_owned() + GUARD_EXISTS,
                    mutation_params(fence, action, at_ms),
                ));
                statements.push(D1BatchStatement::new(
                    "UPDATE tenant_byok_secret SET tcs_wrapped=NULL,cmk_key_id=NULL,wrapped_at_ms=NULL, \
                     tcs_version=tcs_version+1 WHERE tenant_id=?1 AND ?5>=0 AND " .to_owned() + GUARD_EXISTS,
                    mutation_params(fence, action, at_ms),
                ));
                statements.push(D1BatchStatement::new(
                    "UPDATE tenant_byok_secret_history SET tcs_wrapped=NULL, \
                     retired_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000) \
                     WHERE tenant_id=?1 AND tcs_wrapped IS NOT NULL AND ?5>=0 AND "
                        .to_owned()
                        + GUARD_EXISTS,
                    mutation_params(fence, action, at_ms),
                ));
            }
            "degrade" => statements.push(D1BatchStatement::new(
                "UPDATE tenant SET byok_status='degraded_read_only',byok_revoked_at_ms=?5, \
                 byok_revoked_provider=?6,byok_revoked_kms_key_id=?7 WHERE tenant_id=?1 AND "
                    .to_owned()
                    + GUARD_EXISTS,
                identity_params(fence, action, identity, at_ms),
            )),
            "restore" => statements.push(D1BatchStatement::new(
                "UPDATE tenant SET byok_status='active',byok_revoked_at_ms=NULL, \
                 byok_revoked_provider=NULL,byok_revoked_kms_key_id=NULL WHERE tenant_id=?1 AND "
                    .to_owned()
                    + GUARD_EXISTS,
                identity_params(fence, action, identity, at_ms),
            )),
            _ => {
                return Err(ByokWriteError::Invalid(
                    "unknown control transition".to_owned(),
                ));
            }
        }
        append_completion(&mut statements, fence, action, full, at_ms, false);
        self.run_batch(statements)
            .await
            .map_err(ByokWriteError::Transport)
    }

    async fn run_batch(&self, statements: Vec<D1BatchStatement>) -> Result<(), String> {
        self.client
            .batch(statements)
            .await
            .map(|_| ())
            .map_err(|error| {
                format!(
                    "BYOK atomic batch failed at {:?}: {}",
                    error.statement, error.message
                )
            })
    }
}

fn activation_health_statement(
    intent: &LiveActivation,
    identity: &CmkIdentity,
    access_state: &str,
    at_ms: i64,
) -> D1BatchStatement {
    D1BatchStatement::new(
        "UPDATE byok_activation_key_health SET access_state=?1, \
         checked_at_ms=(CAST(strftime('%s','now') AS INTEGER)*1000) \
         WHERE intent_id=?2 AND tenant_id=?3 AND cmk_provider=?4 \
          AND cmk_key_id=?5 AND cmk_region=?6 AND ?7>=0",
        vec![
            json!(access_state),
            json!(intent.intent_id),
            json!(intent.tenant_id),
            json!(identity.provider),
            json!(identity.key_id),
            json!(identity.region),
            json!(at_ms),
        ],
    )
}

fn guard_statement(
    fence: &TransitionFence,
    action: &str,
    identity: Option<(&str, &str, &str)>,
) -> D1BatchStatement {
    let (provider, key, region) = identity.unwrap_or(("", "", ""));
    D1BatchStatement::new(
        "INSERT INTO byok_transition_commit_guard \
         (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        vec![
            json!(fence.token()),
            json!(fence.tenant_id()),
            json!(fence.epoch()),
            json!(action),
            json!(provider),
            json!(key),
            json!(region),
        ],
    )
}

fn control_fence_statement(
    token: &str,
    lease_ms: i64,
    snapshot: &crate::byok_transition_fence::ConfigSnapshot,
    intent: &LiveActivation,
) -> D1BatchStatement {
    D1BatchStatement::new(
        "INSERT INTO byok_transition_fence \
         (token,tenant_id,epoch,observed_gate_epoch,observed_generation, \
          observed_config_version,observed_config_state,observed_byok_status, \
          acquired_at_ms,expires_at_ms) \
         SELECT ?1,g.tenant_id,COALESCE((SELECT MAX(p.epoch) FROM byok_transition_fence p \
          WHERE p.tenant_id=g.tenant_id),0)+1,g.gate_epoch,g.current_generation, \
          c.config_version,c.state,t.byok_status, \
          (CAST(strftime('%s','now') AS INTEGER)*1000), \
          (CAST(strftime('%s','now') AS INTEGER)*1000)+?2 \
         FROM byok_tenant_gate g JOIN tenant t ON t.tenant_id=g.tenant_id \
         JOIN tenant_byok_config c ON c.tenant_id=g.tenant_id \
         JOIN byok_activation_intent a ON a.tenant_id=g.tenant_id \
         WHERE g.tenant_id=?3 AND a.intent_id=?4 AND a.state_version=?5 \
          AND a.phase='copy' AND g.gate_epoch=?6 AND g.current_generation=?7 \
          AND c.config_version=?8 AND c.state='pending' AND t.byok_status='active'",
        vec![
            json!(token),
            json!(lease_ms),
            json!(intent.tenant_id),
            json!(intent.intent_id),
            json!(intent.state_version),
            json!(snapshot.gate_epoch),
            json!(snapshot.current_generation),
            json!(snapshot.config_version),
        ],
    )
}

fn mutation_params(fence: &TransitionFence, action: &str, at_ms: i64) -> Vec<Value> {
    vec![
        json!(fence.tenant_id()),
        json!(fence.token()),
        json!(fence.epoch()),
        json!(action),
        json!(at_ms),
    ]
}

fn identity_params(
    fence: &TransitionFence,
    action: &str,
    identity: Option<&CmkIdentity>,
    at_ms: i64,
) -> Vec<Value> {
    let mut values = mutation_params(fence, action, at_ms);
    let (provider, key) = identity
        .map(|value| (value.provider.as_str(), value.key_id.as_str()))
        .unwrap_or(("", ""));
    values.extend([json!(provider), json!(key)]);
    values
}

fn append_completion(
    statements: &mut Vec<D1BatchStatement>,
    fence: &TransitionFence,
    action: &str,
    identity: Option<(&str, &str, &str)>,
    _at_ms: i64,
    switch_generation: bool,
) {
    let mut gate_sql = "UPDATE byok_tenant_gate SET gate_epoch=gate_epoch+1".to_owned();
    if switch_generation {
        gate_sql.push_str(",current_generation=current_generation+1");
    }
    gate_sql.push_str(" WHERE tenant_id=?1 AND ");
    gate_sql.push_str(GUARD_EXISTS);
    statements.push(D1BatchStatement::new(gate_sql, auth_params(fence, action)));
    statements.push(D1BatchStatement::new(
        "UPDATE byok_transition_fence SET outcome='committed', \
         completed_at_ms=(CAST(strftime('%s', 'now') AS INTEGER) * 1000) \
         WHERE tenant_id=?1 AND token=?2 AND epoch=?3 AND outcome='active' AND \
         EXISTS (SELECT 1 FROM byok_transition_commit_guard a WHERE a.tenant_id=?1 AND a.token=?2 AND a.epoch=?3 AND a.action=?4)",
        auth_params(fence, action),
    ));
    let (provider, key, region) = identity.unwrap_or(("", "", ""));
    let alert = if matches!(action, "degrade" | "restore") {
        "customer_activity_recorded"
    } else {
        "not_applicable"
    };
    statements.push(D1BatchStatement::new(
        "INSERT INTO byok_control_outcome \
         (token,tenant_id,epoch,action,cmk_provider,cmk_key_id,cmk_region,outcome,alert_recipient,alert_outcome,completed_at_ms) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,'completed',?2,?8, \
                 (CAST(strftime('%s', 'now') AS INTEGER) * 1000))",
        vec![json!(fence.token()),json!(fence.tenant_id()),json!(fence.epoch()),json!(action),json!(provider),json!(key),json!(region),json!(alert)],
    ));
    statements.push(D1BatchStatement::new(
        "DELETE FROM byok_transition_commit_guard WHERE tenant_id=?1 AND token=?2 AND epoch=?3 AND action=?4",
        auth_params(fence, action),
    ));
}

fn auth_params(fence: &TransitionFence, action: &str) -> Vec<Value> {
    vec![
        json!(fence.tenant_id()),
        json!(fence.token()),
        json!(fence.epoch()),
        json!(action),
    ]
}

fn required_region(region: Option<&str>) -> Result<&str, ByokWriteError> {
    region
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ByokWriteError::Invalid("cmk_region is required for complete CMK identity".to_owned())
        })
}

fn validate_byok_context(context: StagingLoadTestWriteContext<'_>) -> Result<(), ByokWriteError> {
    if let Some(context) = context {
        context
            .require_ownership_scenario(StagingLoadTestScenario::Byok)
            .map_err(|error| ByokWriteError::Invalid(error.to_string()))?;
    }
    Ok(())
}

fn byok_ownership_statement(
    context: &StagingLoadTestAdmissionContext,
    intent_id: &str,
    registered_at_ms: i64,
) -> Result<D1BatchStatement, ByokWriteError> {
    validate_byok_context(Some(context))?;
    let opaque_handle = format!("byok-activation:{intent_id}");
    let registration = context
        .ownership_registration(
            StagingLoadTestResourceClass::ByokArtifact,
            StagingLoadTestDisposition::Disposable,
            &opaque_handle,
        )
        .map_err(|error| ByokWriteError::Invalid(error.to_string()))?;
    registration
        .d1_statement(registered_at_ms)
        .map_err(|error| ByokWriteError::Invalid(error.to_string()))
}

fn byok_teardown_locator_statement(
    context: &StagingLoadTestAdmissionContext,
    tenant_id: &str,
    tenant_ref: &str,
    intent_id: &str,
    registered_at_ms: i64,
) -> Result<D1BatchStatement, ByokWriteError> {
    validate_byok_context(Some(context))?;
    let opaque_handle = format!("byok-activation:{intent_id}");
    let sql = "INSERT INTO staging_load_test_teardown_locators \
        (run_id,scenario,resource_class,receipt_ref,locator_kind,locator_json,registered_at_ms) \
        VALUES (?1,?2,'byok_artifact',( \
          SELECT resource.receipt_ref FROM staging_load_test_resources resource \
          JOIN staging_load_test_runs run ON run.run_id=resource.run_id \
            AND run.scenario=resource.scenario \
          JOIN staging_load_test_synthetic_tenants synthetic \
            ON synthetic.run_id=resource.run_id AND synthetic.scenario=resource.scenario \
           AND synthetic.tenant_id=?3 AND synthetic.baseline_marker='generation_zero_empty' \
          WHERE resource.run_id=?1 AND resource.scenario=?2 \
            AND resource.resource_class='byok_artifact' AND resource.opaque_handle=?7 \
            AND resource.disposition='disposable' AND resource.state='registered' \
            AND run.target_environment='staging' AND run.target_deployment_sha=?8 \
            AND run.state='open' LIMIT 1), \
          'byok_pending_synthetic_v1',json_object('tenant_id',?3,'intent_id',?4,'tenant_ref',?5),?6)";
    Ok(D1BatchStatement::new(
        sql,
        vec![
            json!(context.run_id()),
            json!(context.scenario().as_str()),
            json!(tenant_id),
            json!(intent_id),
            json!(tenant_ref),
            json!(registered_at_ms),
            json!(opaque_handle),
            json!(context.target_deployment_sha()),
        ],
    ))
}

fn staging_synthetic_tenant_ref(
    run_id: &str,
    scenario: &str,
    target_deployment_sha: &str,
    tenant_id: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"corelink/staging-synthetic-tenant-ref/v1\0");
    for field in [run_id, scenario, target_deployment_sha, tenant_id] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn valid_staging_locator(locator: &StagingByokPendingTeardownLocator) -> bool {
    let tenant = locator.tenant_id.as_bytes();
    let intent = locator.intent_id.as_bytes();
    tenant.len() == 36
        && tenant.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
        && intent.len() == 64
        && intent
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

struct ActivationHashes {
    request: String,
    policy: String,
    wrapped_tcs: String,
}

struct ExistingActivationRequest {
    same_request: bool,
    state: ByokState,
    provider: String,
    region: String,
}

struct ActiveConfigIdentity {
    config_version: i64,
    provider: String,
    key_id: String,
    region: String,
    tcs_version: i64,
}

fn validate_current_rotation_boundary(
    current: &ActiveConfigIdentity,
    activation: &ByokActivation,
    region: &str,
) -> Result<(), ByokWriteError> {
    if current.provider != activation.cmk_provider || current.region != region {
        return Err(ByokWriteError::Invalid(
            "cross-provider or cross-region BYOK rotation is not supported".to_owned(),
        ));
    }
    Ok(())
}

fn validate_rotation_boundary(
    existing: &ExistingActivationRequest,
    activation: &ByokActivation,
    region: &str,
) -> Result<(), ByokWriteError> {
    if existing.provider != activation.cmk_provider || existing.region != region {
        return Err(ByokWriteError::Invalid(
            "cross-provider or cross-region BYOK rotation is not supported".to_owned(),
        ));
    }
    Ok(())
}

struct LiveActivation {
    tenant_id: String,
    intent_id: String,
    state_version: i64,
    guard_id: String,
    provider: String,
    key_id: String,
    region: String,
    source_generation: i64,
    source_identity: Option<LiveSourceIdentity>,
    tcs_version: i64,
}

struct LiveSourceIdentity {
    config_version: i64,
    provider: String,
    key_id: String,
    region: String,
    tcs_version: i64,
}

impl ActivationHashes {
    fn new(activation: &ByokActivation, region: &str) -> Self {
        let policy = framed_blake3(
            b"corelink.byok.activation-policy.v1",
            &[
                activation.mode.as_str().as_bytes(),
                activation.crypto_mode.as_str().as_bytes(),
                activation.cmk_provider.as_bytes(),
                activation.cmk_key_id.as_bytes(),
                region.as_bytes(),
            ],
        );
        let wrapped_tcs = Digest::compute(&activation.tcs_wrapped).to_hex();
        let request = framed_blake3(
            b"corelink.byok.activation-request.v1",
            &[
                activation.tenant_id.as_bytes(),
                policy.as_bytes(),
                wrapped_tcs.as_bytes(),
            ],
        );
        Self {
            request,
            policy,
            wrapped_tcs,
        }
    }
}

fn framed_blake3(domain: &[u8], fields: &[&[u8]]) -> String {
    let capacity = domain.len()
        + fields
            .iter()
            .map(|field| 8_usize.saturating_add(field.len()))
            .sum::<usize>();
    let mut canonical = Vec::with_capacity(capacity);
    canonical.extend_from_slice(domain);
    for field in fields {
        canonical.extend_from_slice(&(field.len() as u64).to_be_bytes());
        canonical.extend_from_slice(field);
    }
    Digest::compute(&canonical).to_hex()
}

fn random_capability() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    hex::encode(token)
}

fn config_state_name(state: ConfigState) -> &'static str {
    match state {
        ConfigState::Absent => "absent",
        ConfigState::Inactive => "inactive",
        ConfigState::Pending => "pending",
        ConfigState::Active => "active",
        ConfigState::Partial => "partial",
        ConfigState::Shredded => "shredded",
    }
}

fn integer(row: &D1Row, column: &str) -> Result<i64, String> {
    row.get(column)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{column} missing from BYOK activation"))
}

fn state_for_error(state: ConfigState) -> ByokState {
    match state {
        ConfigState::Absent | ConfigState::Inactive => ByokState::Inactive,
        ConfigState::Pending => ByokState::Pending,
        ConfigState::Active => ByokState::Active,
        ConfigState::Partial => ByokState::Partial,
        ConfigState::Shredded => ByokState::Shredded,
    }
}

fn map_fence(error: FenceError) -> ByokWriteError {
    ByokWriteError::Transport(error.to_string())
}

fn text(row: &D1Row, column: &str) -> Result<String, String> {
    row.get(column)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{column} missing from BYOK tenant binding"))
}

#[cfg(test)]
#[path = "byok_control_transition_ownership_tests.rs"]
mod ownership_tests;
