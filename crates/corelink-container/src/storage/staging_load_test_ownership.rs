//! Append-only resource registration for the #2161 staging teardown ledger.
//!
//! This is a persistence seam only. It does not authenticate a caller, prove
//! that a resource was created by the named scenario, scan inventory, or
//! delete resources. Callers must obtain the run identity from a trusted
//! admission path before invoking it.

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::{
    d1_http::{D1BatchStatement, D1HttpClient},
    staging_load_test_admission::StagingLoadTestAdmissionContext,
};

const SQL_REGISTER_RESOURCE: &str = "INSERT INTO staging_load_test_resources \
     (run_id, scenario, resource_class, receipt_ref, opaque_handle, disposition, state, registered_at_ms) \
     SELECT ?1, ?2, ?4, ?5, ?6, ?7, 'registered', ?8 \
     WHERE EXISTS (SELECT 1 FROM staging_load_test_runs \
       WHERE run_id = ?1 AND scenario = ?2 AND target_environment = 'staging' \
         AND target_deployment_sha = ?3 AND state = 'open') \
     RETURNING receipt_ref";

// Keep ?3 unused here to preserve the same positional parameter array as the
// insert query. D1's HTTP API accepts positional values, including values for
// skipped numbered placeholders.
const SQL_FIND_REGISTERED_RESOURCE: &str = "SELECT receipt_ref FROM staging_load_test_resources \
     WHERE run_id = ?1 AND scenario = ?2 AND resource_class = ?4 \
       AND receipt_ref = ?5 AND opaque_handle = ?6 AND disposition = ?7 \
     LIMIT 1";

const SQL_REGISTER_RESOURCE_IN_BATCH: &str = "INSERT INTO staging_load_test_resources \
     (run_id, scenario, resource_class, receipt_ref, opaque_handle, disposition, state, registered_at_ms) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'registered', ?7) \
     ON CONFLICT (run_id, scenario, resource_class, receipt_ref) DO NOTHING";

const SQL_PREPARE_R2_INTENT: &str = "INSERT INTO staging_load_test_r2_intents \
     (operation_id, run_id, scenario, target_deployment_sha, resource_class, receipt_ref, opaque_handle, disposition, state, prepared_at_ms) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'prepared', ?9)";

const SQL_COMMIT_R2_INTENT: &str = "UPDATE staging_load_test_r2_intents \
     SET state = 'committed', committed_at_ms = ?2 \
     WHERE operation_id = ?1 AND state IN ('prepared', 'committed')";

/// Optional request-scoped provenance. `None` is ordinary non-synthetic traffic.
pub type StagingLoadTestWriteContext<'a> = Option<&'a StagingLoadTestAdmissionContext>;

/// Fixed, redacted failures shared by every writer family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingLoadTestOwnershipError {
    /// The context is valid but belongs to another scenario.
    ScenarioMismatch,
    /// A bounded public identifier is malformed.
    InvalidIdentifier,
    /// The resource class cannot use the requested disposition.
    InvalidDisposition,
}

impl core::fmt::Display for StagingLoadTestOwnershipError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::ScenarioMismatch => "staging ownership scenario mismatch",
            Self::InvalidIdentifier => "staging ownership identifier is invalid",
            Self::InvalidDisposition => "staging ownership disposition is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StagingLoadTestOwnershipError {}

/// One of the scenarios admitted by migration 0147.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingLoadTestScenario {
    /// Signup flow scenario.
    Signup,
    /// Stripe webhook scenario.
    Webhook,
    /// Data-subject request scenario.
    Dsr,
    /// Content-addressable storage scenario.
    Cas,
    /// Bring-your-own-key scenario.
    Byok,
    /// Two-hour endurance scenario.
    Endurance2h,
    /// Cargo write-path scenario B-103.
    B103CargoWrite,
}

impl StagingLoadTestScenario {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::Webhook => "webhook",
            Self::Dsr => "dsr",
            Self::Cas => "cas",
            Self::Byok => "byok",
            Self::Endurance2h => "endurance-2h",
            Self::B103CargoWrite => "b103-cargo-write",
        }
    }
}

/// Resource classes admitted by migration 0147.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingLoadTestResourceClass {
    /// Run-owned reference to a potentially shared CAS object.
    CasReference,
    /// Run-unique webhook inbox row.
    WebhookInbox,
    /// Effect row attributed to a run-unique webhook event.
    WebhookEffect,
    /// Synthetic DSR artifact whose disposition requires owner classification.
    DsrArtifact,
    /// Durable DSR obligation retained for compliance.
    DsrObligation,
    /// Audit evidence retained for chain integrity.
    AuditEvidence,
    /// Billing audit evidence retained for financial accountability.
    BillingAudit,
    /// Signup artifact whose disposition requires owner classification.
    SignupArtifact,
    /// BYOK artifact whose disposition requires owner classification.
    ByokArtifact,
}

impl StagingLoadTestResourceClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CasReference => "cas_reference",
            Self::WebhookInbox => "webhook_inbox",
            Self::WebhookEffect => "webhook_effect",
            Self::DsrArtifact => "dsr_artifact",
            Self::DsrObligation => "dsr_obligation",
            Self::AuditEvidence => "audit_evidence",
            Self::BillingAudit => "billing_audit",
            Self::SignupArtifact => "signup_artifact",
            Self::ByokArtifact => "byok_artifact",
        }
    }

    const fn requires_retention(self) -> bool {
        matches!(
            self,
            Self::CasReference | Self::DsrObligation | Self::AuditEvidence | Self::BillingAudit
        )
    }
}

/// The closed migration-0147 resource census.  Teardown must account for every
/// class, including classes with no rows, before it can report success.
pub(crate) const STAGING_LOAD_TEST_RESOURCE_CLASSES: [StagingLoadTestResourceClass; 9] = [
    StagingLoadTestResourceClass::CasReference,
    StagingLoadTestResourceClass::WebhookInbox,
    StagingLoadTestResourceClass::WebhookEffect,
    StagingLoadTestResourceClass::DsrArtifact,
    StagingLoadTestResourceClass::DsrObligation,
    StagingLoadTestResourceClass::AuditEvidence,
    StagingLoadTestResourceClass::BillingAudit,
    StagingLoadTestResourceClass::SignupArtifact,
    StagingLoadTestResourceClass::ByokArtifact,
];

/// Explicit retention decision made by the resource-owning adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingLoadTestDisposition {
    /// Eligible for the later exact-run teardown flow only after its own
    /// resource-specific safety checks pass.
    Disposable,
    /// Receipt-only state that teardown must preserve.
    Retained,
}

impl StagingLoadTestDisposition {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Disposable => "disposable",
            Self::Retained => "retained",
        }
    }
}

/// Terminal-safe result supplied by a resource-specific disposable deleter.
/// The ledger never treats an unclassified external result as deletion success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagingLoadTestTeardownAction {
    /// The disposable, exact-run resource was deleted.
    Deleted,
    /// A retained resource or shared CAS reference was intentionally preserved.
    Preserved,
    /// The external operation could not prove a safe result.
    Quarantined,
}

/// One ledger row after an exact bounded inventory query.  Handles remain
/// private so receipts and diagnostic output cannot expose them.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StagingLoadTestTeardownResource {
    class: StagingLoadTestResourceClass,
    receipt_ref: String,
    opaque_handle: String,
    disposition: StagingLoadTestDisposition,
}

impl core::fmt::Debug for StagingLoadTestTeardownResource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagingLoadTestTeardownResource")
            .field("class", &self.class)
            .field("receipt_ref", &self.receipt_ref)
            .field("opaque_handle", &"[REDACTED]")
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl StagingLoadTestTeardownResource {
    #[cfg(test)]
    fn for_test(
        class: StagingLoadTestResourceClass,
        receipt_ref: &str,
        disposition: StagingLoadTestDisposition,
    ) -> Self {
        Self {
            class,
            receipt_ref: receipt_ref.to_owned(),
            opaque_handle: "test-handle".to_owned(),
            disposition,
        }
    }
}

/// Bounded scan evidence for exactly one migration-0147 class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StagingLoadTestTeardownScan {
    class: StagingLoadTestResourceClass,
    observed_count: usize,
    complete: bool,
    truncated: bool,
}

/// Exact immutable identity copied from an already admitted request.  This
/// avoids accepting caller-provided run coordinates at the teardown seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StagingLoadTestTeardownIdentity {
    run_id: String,
    scenario: StagingLoadTestScenario,
    target_deployment_sha: String,
}

impl StagingLoadTestTeardownIdentity {
    pub(crate) fn from_admission(context: &StagingLoadTestAdmissionContext) -> Self {
        Self {
            run_id: context.run_id().to_owned(),
            scenario: context.scenario(),
            target_deployment_sha: context.target_deployment_sha().to_owned(),
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            run_id: "123".to_owned(),
            scenario: StagingLoadTestScenario::Cas,
            target_deployment_sha: "a".repeat(40),
        }
    }
}

/// Redacted per-class terminal accounting in the canonical teardown receipt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct StagingLoadTestTeardownCounts {
    inventory: usize,
    attempted: usize,
    deleted: usize,
    preserved: usize,
    quarantined: usize,
    remaining: usize,
}

/// Canonical success receipt.  It deliberately contains no handles, tokens,
/// raw admission material, or tenant/provider identifiers.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct StagingLoadTestTeardownReceipt {
    schema: &'static str,
    run_id: String,
    scenario: &'static str,
    target_deployment_sha: String,
    terminal_state: &'static str,
    cross_run_deletions: usize,
    resources: std::collections::BTreeMap<&'static str, StagingLoadTestTeardownCounts>,
}

/// Fixed, redacted failures for any unsafe or incomplete teardown attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagingLoadTestTeardownError {
    MissingClass,
    DuplicateClass,
    IncompleteScan,
    TruncatedScan,
    OverBudget,
    CountMismatch,
    DuplicateResource,
    InvalidDisposition,
    PartialDelete,
}

impl core::fmt::Display for StagingLoadTestTeardownError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::MissingClass => "staging teardown inventory is missing a resource class",
            Self::DuplicateClass => "staging teardown inventory has duplicate resource classes",
            Self::IncompleteScan => "staging teardown inventory scan is incomplete",
            Self::TruncatedScan => "staging teardown inventory scan is truncated",
            Self::OverBudget => "staging teardown inventory exceeds its bound",
            Self::CountMismatch => "staging teardown inventory count does not reconcile",
            Self::DuplicateResource => "staging teardown inventory has duplicate resource evidence",
            Self::InvalidDisposition => "staging teardown disposition is unsafe",
            Self::PartialDelete => "staging teardown did not reach a terminal state",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StagingLoadTestTeardownError {}

/// Reconcile bounded scans to the exact ledger inventory, then invoke the
/// resource-owned deleter only for disposable rows.  Any ambiguity produces no
/// receipt; callers can persist a failed/quarantined terminal state and retry
/// only after recovery has established a new complete inventory.
pub(crate) fn reconcile_staging_load_test_teardown(
    identity: &StagingLoadTestTeardownIdentity,
    prior_terminal_receipt: Option<&StagingLoadTestTeardownReceipt>,
    scans: &[StagingLoadTestTeardownScan],
    resources: &[StagingLoadTestTeardownResource],
    max_resources: usize,
    mut delete_disposable: impl FnMut(&StagingLoadTestTeardownResource) -> StagingLoadTestTeardownAction,
) -> Result<StagingLoadTestTeardownReceipt, StagingLoadTestTeardownError> {
    if let Some(receipt) = prior_terminal_receipt {
        if receipt.schema == "corelink.staging-load-test-teardown-receipt.v2"
            && receipt.terminal_state == "reconciled"
            && receipt.run_id == identity.run_id
            && receipt.scenario == identity.scenario.as_str()
            && receipt.target_deployment_sha == identity.target_deployment_sha
            && receipt.cross_run_deletions == 0
        {
            // A durable terminal receipt makes a replay a read only operation:
            // no inventory mutation and no disposable deleter invocation.
            return Ok(receipt.clone());
        }
        return Err(StagingLoadTestTeardownError::CountMismatch);
    }
    if resources.len() > max_resources {
        return Err(StagingLoadTestTeardownError::OverBudget);
    }
    let mut scan_counts = std::collections::BTreeMap::new();
    for scan in scans {
        if scan.truncated {
            return Err(StagingLoadTestTeardownError::TruncatedScan);
        }
        if !scan.complete {
            return Err(StagingLoadTestTeardownError::IncompleteScan);
        }
        if scan_counts
            .insert(scan.class.as_str(), scan.observed_count)
            .is_some()
        {
            return Err(StagingLoadTestTeardownError::DuplicateClass);
        }
    }
    if scan_counts.len() != STAGING_LOAD_TEST_RESOURCE_CLASSES.len() {
        return Err(StagingLoadTestTeardownError::MissingClass);
    }
    let mut by_class: std::collections::BTreeMap<
        &'static str,
        Vec<&StagingLoadTestTeardownResource>,
    > = std::collections::BTreeMap::new();
    let mut receipts = std::collections::BTreeSet::new();
    for resource in resources {
        if !receipts.insert((resource.class.as_str(), resource.receipt_ref.as_str())) {
            return Err(StagingLoadTestTeardownError::DuplicateResource);
        }
        if resource.class.requires_retention()
            && resource.disposition != StagingLoadTestDisposition::Retained
        {
            return Err(StagingLoadTestTeardownError::InvalidDisposition);
        }
        by_class
            .entry(resource.class.as_str())
            .or_default()
            .push(resource);
    }
    let mut counts = std::collections::BTreeMap::new();
    for class in STAGING_LOAD_TEST_RESOURCE_CLASSES {
        let class_name = class.as_str();
        let rows = by_class.remove(class_name).unwrap_or_default();
        if scan_counts.get(class_name) != Some(&rows.len()) {
            return Err(StagingLoadTestTeardownError::CountMismatch);
        }
        let mut attempted = 0;
        let mut deleted = 0;
        let mut preserved = 0;
        let mut quarantined = 0;
        for resource in rows {
            attempted += 1;
            let action = if resource.disposition == StagingLoadTestDisposition::Retained {
                StagingLoadTestTeardownAction::Preserved
            } else {
                delete_disposable(resource)
            };
            match action {
                StagingLoadTestTeardownAction::Deleted
                    if resource.disposition == StagingLoadTestDisposition::Disposable =>
                {
                    deleted += 1
                }
                StagingLoadTestTeardownAction::Preserved
                    if resource.disposition == StagingLoadTestDisposition::Retained =>
                {
                    preserved += 1
                }
                StagingLoadTestTeardownAction::Quarantined => quarantined += 1,
                _ => return Err(StagingLoadTestTeardownError::InvalidDisposition),
            }
        }
        if quarantined != 0 || deleted + preserved != attempted {
            return Err(StagingLoadTestTeardownError::PartialDelete);
        }
        counts.insert(
            class_name,
            StagingLoadTestTeardownCounts {
                inventory: attempted,
                attempted,
                deleted,
                preserved,
                quarantined,
                remaining: 0,
            },
        );
    }
    Ok(StagingLoadTestTeardownReceipt {
        schema: "corelink.staging-load-test-teardown-receipt.v2",
        run_id: identity.run_id.clone(),
        scenario: identity.scenario.as_str(),
        target_deployment_sha: identity.target_deployment_sha.clone(),
        terminal_state: "reconciled",
        cross_run_deletions: 0,
        resources: counts,
    })
}

/// Narrow durable inventory used by the exact-run teardown service.  The
/// locator is deliberately kept private: callers receive only the receipt.
pub(crate) struct StagingLoadTestPhysicalTeardown {
    d1: Arc<D1HttpClient>,
    r2: Arc<crate::storage::r2_s3::R2S3Client>,
    byok: Arc<crate::byok_control_transition::D1ByokControl>,
}

impl StagingLoadTestPhysicalTeardown {
    /// Builds only when the D1 mutation capability is configured.  The route
    /// remains absent otherwise, so an unconfigured process cannot accept a
    /// teardown request and accidentally claim success.
    pub(crate) async fn from_env() -> Result<Self, String> {
        let d1 = Arc::new(D1HttpClient::for_staging_load_test_ownership_writes()?);
        let storage = crate::storage::StorageEnv::from_env()
            .ok_or_else(|| "staging teardown requires configured R2 storage".to_owned())?;
        // DSR's admitted export writer uses the audit bucket.  Keeping the
        // bucket selection here identical makes an absent/incorrect R2
        // capability leave the teardown route unmounted instead of guessing a
        // provider location from an opaque handle.
        let bucket = crate::storage::env_or("R2_AUDIT_BUCKET", "corelink-audit-weur");
        let r2 = Arc::new(crate::storage::r2_s3::R2S3Client::new(&storage, bucket).await?);
        Ok(Self {
            byok: Arc::new(crate::byok_control_transition::D1ByokControl::new(
                Arc::clone(&d1),
            )),
            d1,
            r2,
        })
    }

    async fn prior_reconciled_receipt(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
    ) -> Result<Option<StagingLoadTestTeardownReceipt>, StagingLoadTestTeardownError> {
        let terminal = self.d1.query(
            "SELECT terminal_state FROM staging_load_test_teardown_receipts WHERE run_id=?1 AND scenario=?2 AND target_deployment_sha=?3",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha)],
        ).await.map_err(|_| StagingLoadTestTeardownError::CountMismatch)?;
        let Some(row) = terminal.first() else {
            return Ok(None);
        };
        if row
            .get("terminal_state")
            .and_then(serde_json::Value::as_str)
            != Some("reconciled")
        {
            return Err(StagingLoadTestTeardownError::PartialDelete);
        }
        let rows = self.d1.query(
            "SELECT resource_class,inventory_count,attempted_count,deleted_count,preserved_count,quarantined_count,remaining_count FROM staging_load_test_teardown_receipt_counts WHERE run_id=?1 AND scenario=?2 ORDER BY resource_class",
            &[json!(identity.run_id), json!(identity.scenario.as_str())],
        ).await.map_err(|_| StagingLoadTestTeardownError::CountMismatch)?;
        let mut resources = std::collections::BTreeMap::new();
        for row in rows {
            let class = resource_class(
                row.get("resource_class")
                    .and_then(serde_json::Value::as_str),
            )
            .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            let count = |name| {
                row.get(name)
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or(StagingLoadTestTeardownError::CountMismatch)
            };
            resources.insert(
                class.as_str(),
                StagingLoadTestTeardownCounts {
                    inventory: count("inventory_count")?,
                    attempted: count("attempted_count")?,
                    deleted: count("deleted_count")?,
                    preserved: count("preserved_count")?,
                    quarantined: count("quarantined_count")?,
                    remaining: count("remaining_count")?,
                },
            );
        }
        if resources.len() != STAGING_LOAD_TEST_RESOURCE_CLASSES.len() {
            return Err(StagingLoadTestTeardownError::CountMismatch);
        }
        Ok(Some(StagingLoadTestTeardownReceipt {
            schema: "corelink.staging-load-test-teardown-receipt.v2",
            run_id: identity.run_id.clone(),
            scenario: identity.scenario.as_str(),
            target_deployment_sha: identity.target_deployment_sha.clone(),
            terminal_state: "reconciled",
            cross_run_deletions: 0,
            resources,
        }))
    }

    async fn preserve_and_readback(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        resource: &StagingLoadTestTeardownResource,
    ) -> Result<StagingLoadTestTeardownAction, StagingLoadTestTeardownError> {
        let changed = self.d1.query(
            "UPDATE staging_load_test_resources SET state='preserved' WHERE run_id=?1 AND scenario=?2 AND resource_class=?3 AND receipt_ref=?4 AND disposition='retained' AND state='registered' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.class.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if changed.len() != 1 {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let readback = self.d1.query(
            "SELECT receipt_ref FROM staging_load_test_resources WHERE run_id=?1 AND scenario=?2 AND resource_class=?3 AND receipt_ref=?4 AND disposition='retained' AND state='preserved'",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.class.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        Ok(if readback.len() == 1 {
            StagingLoadTestTeardownAction::Preserved
        } else {
            StagingLoadTestTeardownAction::Quarantined
        })
    }

    async fn persist_reconciled(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        receipt: &StagingLoadTestTeardownReceipt,
    ) -> Result<(), StagingLoadTestTeardownError> {
        let completed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StagingLoadTestTeardownError::PartialDelete)?
            .as_millis();
        let completed_at_ms = i64::try_from(completed_at_ms)
            .map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        let encoded =
            serde_json::to_vec(receipt).map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        let receipt_sha256 = hex::encode(sha2::Sha256::digest(encoded));
        let mut statements = Vec::new();
        for class in STAGING_LOAD_TEST_RESOURCE_CLASSES {
            let count = receipt
                .resources
                .get(class.as_str())
                .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            let readback = if class.requires_retention() {
                "preserved"
            } else {
                "absent"
            };
            statements.push(super::d1_http::D1BatchStatement::new(
                "INSERT INTO staging_load_test_teardown_receipt_counts (run_id,scenario,resource_class,inventory_count,attempted_count,deleted_count,preserved_count,remaining_count,quarantined_count,cross_run_deletion_count,readback_state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10)",
                vec![json!(identity.run_id), json!(identity.scenario.as_str()), json!(class.as_str()), json!(count.inventory), json!(count.attempted), json!(count.deleted), json!(count.preserved), json!(count.remaining), json!(count.quarantined), json!(readback)],
            ));
        }
        statements.push(super::d1_http::D1BatchStatement::new(
            "INSERT INTO staging_load_test_teardown_receipts (run_id,scenario,target_deployment_sha,schema_version,terminal_state,completed_at_ms,receipt_sha256) VALUES (?1,?2,?3,'corelink.staging-load-test-teardown-receipt.v2','reconciled',?4,?5)",
            vec![json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha), json!(completed_at_ms), json!(receipt_sha256)],
        ));
        statements.push(super::d1_http::D1BatchStatement::new(
            "UPDATE staging_load_test_runs SET state='reconciled' WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 AND state='teardown_started'",
            vec![json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha)],
        ));
        self.d1
            .batch(statements)
            .await
            .map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        Ok(())
    }

    async fn mark_failed(&self, identity: &StagingLoadTestTeardownIdentity) {
        let _ = self.d1.query(
            "UPDATE staging_load_test_runs SET state='failed' WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 AND state='teardown_started'",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha)],
        ).await;
    }

    /// Start only an exact, already sealed staging run.  The predicate binds
    /// all immutable admission coordinates before a resource can transition.
    pub(crate) async fn begin(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
    ) -> Result<(), StagingLoadTestTeardownError> {
        let rows = self.d1.query(
            "UPDATE staging_load_test_runs SET state='teardown_started' WHERE run_id=?1 AND scenario=?2 AND target_environment='staging' AND target_deployment_sha=?3 AND state='sealed' RETURNING run_id",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(identity.target_deployment_sha)],
        ).await.map_err(|_| StagingLoadTestTeardownError::CountMismatch)?;
        if rows.len() == 1 {
            Ok(())
        } else {
            Err(StagingLoadTestTeardownError::CountMismatch)
        }
    }

    /// Read the immutable nine-class scan census and exact resource rows.  An
    /// absent locator for a disposable resource is deliberately an error: old
    /// rows may never be guessed from a one-way receipt reference.
    pub(crate) async fn inventory(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        max_resources: usize,
    ) -> Result<
        (
            Vec<StagingLoadTestTeardownScan>,
            Vec<StagingLoadTestTeardownResource>,
        ),
        StagingLoadTestTeardownError,
    > {
        let scans = self.d1.query(
            "SELECT resource_class,state,observed_count FROM staging_load_test_resource_scans WHERE run_id=?1 AND scenario=?2 ORDER BY resource_class",
            &[json!(identity.run_id), json!(identity.scenario.as_str())],
        ).await.map_err(|_| StagingLoadTestTeardownError::IncompleteScan)?;
        let resources = self.d1.query(
            "SELECT resource_class,receipt_ref,opaque_handle,disposition FROM staging_load_test_resources WHERE run_id=?1 AND scenario=?2 ORDER BY resource_class,receipt_ref LIMIT ?3",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(i64::try_from(max_resources.saturating_add(1)).unwrap_or(i64::MAX))],
        ).await.map_err(|_| StagingLoadTestTeardownError::IncompleteScan)?;
        if resources.len() > max_resources {
            return Err(StagingLoadTestTeardownError::OverBudget);
        }
        let mut parsed_scans = Vec::new();
        for row in scans {
            let class = resource_class(
                row.get("resource_class")
                    .and_then(serde_json::Value::as_str),
            )
            .ok_or(StagingLoadTestTeardownError::MissingClass)?;
            let count = row
                .get("observed_count")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            parsed_scans.push(StagingLoadTestTeardownScan {
                class,
                observed_count: count,
                complete: row.get("state").and_then(serde_json::Value::as_str) == Some("complete"),
                truncated: false,
            });
        }
        let mut parsed_resources = Vec::new();
        for row in resources {
            let class = resource_class(
                row.get("resource_class")
                    .and_then(serde_json::Value::as_str),
            )
            .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            let disposition = match row.get("disposition").and_then(serde_json::Value::as_str) {
                Some("disposable") => StagingLoadTestDisposition::Disposable,
                Some("retained") => StagingLoadTestDisposition::Retained,
                _ => return Err(StagingLoadTestTeardownError::InvalidDisposition),
            };
            let receipt_ref = row
                .get("receipt_ref")
                .and_then(serde_json::Value::as_str)
                .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            let handle = row
                .get("opaque_handle")
                .and_then(serde_json::Value::as_str)
                .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
            parsed_resources.push(StagingLoadTestTeardownResource {
                class,
                receipt_ref: receipt_ref.to_owned(),
                opaque_handle: handle.to_owned(),
                disposition,
            });
        }
        Ok((parsed_scans, parsed_resources))
    }

    /// Delete only a locator-backed D1 row, then read it back.  Handles are
    /// never interpreted as primary keys: the immutable 0151 JSON locator is
    /// the sole authority for these three classes.
    pub(crate) async fn delete_d1_owned_and_readback(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        resource: &StagingLoadTestTeardownResource,
    ) -> Result<StagingLoadTestTeardownAction, StagingLoadTestTeardownError> {
        if resource.disposition == StagingLoadTestDisposition::Retained {
            return Ok(StagingLoadTestTeardownAction::Preserved);
        }
        let locator = self.d1.query(
            "SELECT locator_kind,locator_json FROM staging_load_test_teardown_locators WHERE run_id=?1 AND scenario=?2 AND resource_class=?3 AND receipt_ref=?4",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.class.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        let Some(locator) = locator.first() else {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        };
        let kind = locator
            .get("locator_kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let payload = locator
            .get("locator_json")
            .and_then(serde_json::Value::as_str)
            .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
            .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let params = match (resource.class, kind) {
            (StagingLoadTestResourceClass::WebhookInbox, "webhook_inbox_v1") => payload
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .map(|event_id| vec![json!(event_id)]),
            (StagingLoadTestResourceClass::WebhookEffect, "webhook_effect_v1") => payload
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .zip(
                    payload
                        .get("effect_key")
                        .and_then(serde_json::Value::as_str),
                )
                .map(|(event_id, effect_key)| vec![json!(event_id), json!(effect_key)]),
            (StagingLoadTestResourceClass::SignupArtifact, "signup_pilot_v1") => payload
                .get("signup_id")
                .and_then(serde_json::Value::as_str)
                .map(|signup_id| vec![json!(signup_id)]),
            _ => None,
        }
        .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let (delete, readback) = match resource.class {
            StagingLoadTestResourceClass::WebhookInbox => (
                "DELETE FROM stripe_webhook_event_inbox WHERE event_id=?1 RETURNING event_id",
                "SELECT event_id FROM stripe_webhook_event_inbox WHERE event_id=?1",
            ),
            StagingLoadTestResourceClass::WebhookEffect => (
                "DELETE FROM stripe_webhook_event_effects WHERE event_id=?1 AND effect_key=?2 RETURNING event_id",
                "SELECT event_id FROM stripe_webhook_event_effects WHERE event_id=?1 AND effect_key=?2",
            ),
            StagingLoadTestResourceClass::SignupArtifact => (
                "DELETE FROM pilot_signups WHERE id=?1 RETURNING id",
                "SELECT id FROM pilot_signups WHERE id=?1",
            ),
            _ => return Ok(StagingLoadTestTeardownAction::Quarantined),
        };
        let started = self.d1.query(
            "UPDATE staging_load_test_resources SET state='delete_started' WHERE run_id=?1 AND scenario=?2 AND resource_class=?3 AND receipt_ref=?4 AND disposition='disposable' AND state='registered' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.class.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if started.len() != 1 {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        if self.d1.query(delete, &params).await.is_err() {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        if !self
            .d1
            .query(readback, &params)
            .await
            .map_err(|_| StagingLoadTestTeardownError::PartialDelete)?
            .is_empty()
        {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let done = self.d1.query(
            "UPDATE staging_load_test_resources SET state='deleted' WHERE run_id=?1 AND scenario=?2 AND resource_class=?3 AND receipt_ref=?4 AND state='delete_started' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.class.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if done.len() == 1 {
            Ok(StagingLoadTestTeardownAction::Deleted)
        } else {
            Ok(StagingLoadTestTeardownAction::Quarantined)
        }
    }

    /// Delete one DSR export only through the owner adapter, which performs
    /// DELETE followed by HEAD and rejects every retained/non-export locator.
    pub(crate) async fn delete_dsr_export_and_readback(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        resource: &StagingLoadTestTeardownResource,
        r2: &crate::storage::r2_s3::R2S3Client,
    ) -> Result<StagingLoadTestTeardownAction, StagingLoadTestTeardownError> {
        if resource.class != StagingLoadTestResourceClass::DsrArtifact
            || resource.disposition != StagingLoadTestDisposition::Disposable
        {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let rows = self.d1.query(
            "SELECT locator_kind,locator_json FROM staging_load_test_teardown_locators WHERE run_id=?1 AND scenario=?2 AND resource_class='dsr_artifact' AND receipt_ref=?3",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        let Some(row) = rows.first() else {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        };
        let key = (row.get("locator_kind").and_then(serde_json::Value::as_str)
            == Some("dsr_r2_export_v1"))
        .then(|| {
            row.get("locator_json")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
                .and_then(|v| {
                    v.get("object_key")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
        })
        .flatten()
        .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let pending = self.d1.query(
            "SELECT operation_id FROM staging_load_test_r2_intents WHERE run_id=?1 AND scenario=?2 AND resource_class='dsr_artifact' AND state<>'committed'",
            &[json!(identity.run_id), json!(identity.scenario.as_str())],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if !pending.is_empty() {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let started = self.d1.query(
            "UPDATE staging_load_test_resources SET state='delete_started' WHERE run_id=?1 AND scenario=?2 AND resource_class='dsr_artifact' AND receipt_ref=?3 AND state='registered' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if started.len() != 1 {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let locator = crate::routes::dsr::access::StagingDsrR2ExportLocator { object_key: key };
        if crate::routes::dsr::access::delete_staging_dsr_export_and_readback(r2, &locator)
            .await
            .is_err()
        {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let done = self.d1.query(
            "UPDATE staging_load_test_resources SET state='deleted' WHERE run_id=?1 AND scenario=?2 AND resource_class='dsr_artifact' AND receipt_ref=?3 AND state='delete_started' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        Ok(if done.len() == 1 {
            StagingLoadTestTeardownAction::Deleted
        } else {
            StagingLoadTestTeardownAction::Quarantined
        })
    }

    /// Cancel, never shred, one immutable generation-zero synthetic BYOK
    /// activation.  The owner adapter rechecks marker, empty baseline, exact
    /// pending intent and terminal readback before it can return success.
    pub(crate) async fn cancel_byok_pending_and_readback(
        &self,
        identity: &StagingLoadTestTeardownIdentity,
        resource: &StagingLoadTestTeardownResource,
        control: &crate::byok_control_transition::D1ByokControl,
    ) -> Result<StagingLoadTestTeardownAction, StagingLoadTestTeardownError> {
        if resource.class != StagingLoadTestResourceClass::ByokArtifact
            || resource.disposition != StagingLoadTestDisposition::Disposable
        {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let rows = self.d1.query(
            "SELECT locator_kind,locator_json FROM staging_load_test_teardown_locators WHERE run_id=?1 AND scenario=?2 AND resource_class='byok_artifact' AND receipt_ref=?3",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        let Some(row) = rows.first() else {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        };
        let value = (row.get("locator_kind").and_then(serde_json::Value::as_str)
            == Some("byok_pending_synthetic_v1"))
        .then(|| {
            row.get("locator_json")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
        })
        .flatten()
        .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let tenant_id = value
            .get("tenant_id")
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let intent_id = value
            .get("intent_id")
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or(StagingLoadTestTeardownError::PartialDelete)?;
        let started = self.d1.query(
            "UPDATE staging_load_test_resources SET state='delete_started' WHERE run_id=?1 AND scenario=?2 AND resource_class='byok_artifact' AND receipt_ref=?3 AND state='registered' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        if started.len() != 1 {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let locator = crate::byok_control_transition::StagingByokPendingTeardownLocator {
            tenant_id,
            intent_id,
        };
        if control
            .cancel_staging_pending_activation_and_readback(&locator)
            .await
            .is_err()
        {
            return Ok(StagingLoadTestTeardownAction::Quarantined);
        }
        let done = self.d1.query(
            "UPDATE staging_load_test_resources SET state='deleted' WHERE run_id=?1 AND scenario=?2 AND resource_class='byok_artifact' AND receipt_ref=?3 AND state='delete_started' RETURNING receipt_ref",
            &[json!(identity.run_id), json!(identity.scenario.as_str()), json!(resource.receipt_ref)],
        ).await.map_err(|_| StagingLoadTestTeardownError::PartialDelete)?;
        Ok(if done.len() == 1 {
            StagingLoadTestTeardownAction::Deleted
        } else {
            StagingLoadTestTeardownAction::Quarantined
        })
    }
}

const MAX_STAGING_LOAD_TEST_TEARDOWN_RESOURCES: usize = 256;

#[async_trait]
impl crate::routes::staging_load_test_teardown::StagingLoadTestTeardownService
    for StagingLoadTestPhysicalTeardown
{
    async fn teardown(
        &self,
        identity: StagingLoadTestTeardownIdentity,
    ) -> Result<StagingLoadTestTeardownReceipt, ()> {
        let result = async {
            if let Some(receipt) = self.prior_reconciled_receipt(&identity).await? {
                return Ok(receipt);
            }
            self.begin(&identity).await?;
            let (scans, resources) = self
                .inventory(&identity, MAX_STAGING_LOAD_TEST_TEARDOWN_RESOURCES)
                .await?;
            // This pure pass proves the whole immutable census before any
            // provider operation. The real pass below repeats no discovery.
            reconcile_staging_load_test_teardown(
                &identity,
                None,
                &scans,
                &resources,
                MAX_STAGING_LOAD_TEST_TEARDOWN_RESOURCES,
                |_| StagingLoadTestTeardownAction::Deleted,
            )?;

            let mut counts = std::collections::BTreeMap::new();
            for scan in &scans {
                counts.insert(
                    scan.class.as_str(),
                    StagingLoadTestTeardownCounts {
                        inventory: scan.observed_count,
                        attempted: 0,
                        deleted: 0,
                        preserved: 0,
                        quarantined: 0,
                        remaining: 0,
                    },
                );
            }
            for resource in &resources {
                let action = if resource.disposition == StagingLoadTestDisposition::Retained {
                    self.preserve_and_readback(&identity, resource).await?
                } else {
                    match resource.class {
                        StagingLoadTestResourceClass::DsrArtifact => {
                            self.delete_dsr_export_and_readback(&identity, resource, &self.r2)
                                .await?
                        }
                        StagingLoadTestResourceClass::ByokArtifact => {
                            self.cancel_byok_pending_and_readback(&identity, resource, &self.byok)
                                .await?
                        }
                        _ => {
                            self.delete_d1_owned_and_readback(&identity, resource)
                                .await?
                        }
                    }
                };
                let count = counts
                    .get_mut(resource.class.as_str())
                    .ok_or(StagingLoadTestTeardownError::CountMismatch)?;
                match action {
                    StagingLoadTestTeardownAction::Deleted => {
                        count.attempted += 1;
                        count.deleted += 1;
                    }
                    StagingLoadTestTeardownAction::Preserved => count.preserved += 1,
                    StagingLoadTestTeardownAction::Quarantined => {
                        count.quarantined += 1;
                        return Err(StagingLoadTestTeardownError::PartialDelete);
                    }
                }
            }
            let receipt = StagingLoadTestTeardownReceipt {
                schema: "corelink.staging-load-test-teardown-receipt.v2",
                run_id: identity.run_id.clone(),
                scenario: identity.scenario.as_str(),
                target_deployment_sha: identity.target_deployment_sha.clone(),
                terminal_state: "reconciled",
                cross_run_deletions: 0,
                resources: counts,
            };
            self.persist_reconciled(&identity, &receipt).await?;
            Ok(receipt)
        }
        .await;
        if result.is_err() {
            self.mark_failed(&identity).await;
        }
        result.map_err(|_| ())
    }
}

fn resource_class(value: Option<&str>) -> Option<StagingLoadTestResourceClass> {
    Some(match value? {
        "cas_reference" => StagingLoadTestResourceClass::CasReference,
        "webhook_inbox" => StagingLoadTestResourceClass::WebhookInbox,
        "webhook_effect" => StagingLoadTestResourceClass::WebhookEffect,
        "dsr_artifact" => StagingLoadTestResourceClass::DsrArtifact,
        "dsr_obligation" => StagingLoadTestResourceClass::DsrObligation,
        "audit_evidence" => StagingLoadTestResourceClass::AuditEvidence,
        "billing_audit" => StagingLoadTestResourceClass::BillingAudit,
        "signup_artifact" => StagingLoadTestResourceClass::SignupArtifact,
        "byok_artifact" => StagingLoadTestResourceClass::ByokArtifact,
        _ => return None,
    })
}

/// Exact staging run identity and opaque resource handle to register.
///
/// `opaque_handle` is intentionally omitted from `Debug` and is never emitted
/// by this adapter. It must be a non-empty, bounded identifier without
/// control characters; callers remain responsible for ensuring it contains
/// no credentials or personal data.
pub struct StagingLoadTestResourceRegistration<'a> {
    /// Canonical positive decimal GitHub Actions run ID.
    run_id: &'a str,
    /// Allowlisted scenario associated with this run.
    scenario: StagingLoadTestScenario,
    /// Lowercase 40-hex deployment commit identity stored on the staging run.
    target_deployment_sha: &'a str,
    /// Resource class defined by migration 0147.
    resource_class: StagingLoadTestResourceClass,
    /// Caller classification is required even for classes with flexible
    /// treatment. DSR obligations, audit/billing evidence, and CAS references
    /// are retained here; a CAS reference is never a deletion claim about its
    /// potentially shared physical object.
    disposition: StagingLoadTestDisposition,
    /// Nonsecret opaque handle for the persistent resource.
    opaque_handle: &'a str,
}

impl core::fmt::Debug for StagingLoadTestResourceRegistration<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StagingLoadTestResourceRegistration")
            .field("run_id", &self.run_id)
            .field("scenario", &self.scenario)
            .field("target_deployment_sha", &self.target_deployment_sha)
            .field("resource_class", &self.resource_class)
            .field("disposition", &self.disposition)
            .field("opaque_handle", &"[REDACTED]")
            .finish()
    }
}

impl StagingLoadTestAdmissionContext {
    /// Require a writer family's fixed scenario before it can mutate state.
    pub(crate) fn require_ownership_scenario(
        &self,
        expected: StagingLoadTestScenario,
    ) -> Result<(), StagingLoadTestOwnershipError> {
        if self.scenario() == expected {
            Ok(())
        } else {
            Err(StagingLoadTestOwnershipError::ScenarioMismatch)
        }
    }

    /// Derive a registration whose run identity cannot be supplied by a caller.
    pub(crate) fn ownership_registration<'a>(
        &'a self,
        resource_class: StagingLoadTestResourceClass,
        disposition: StagingLoadTestDisposition,
        opaque_handle: &'a str,
    ) -> Result<StagingLoadTestResourceRegistration<'a>, StagingLoadTestOwnershipError> {
        let registration = StagingLoadTestResourceRegistration {
            run_id: self.run_id(),
            scenario: self.scenario(),
            target_deployment_sha: self.target_deployment_sha(),
            resource_class,
            disposition,
            opaque_handle,
        };
        validate_registration(&registration).map_err(|message| {
            if message.contains("disposition") {
                StagingLoadTestOwnershipError::InvalidDisposition
            } else {
                StagingLoadTestOwnershipError::InvalidIdentifier
            }
        })?;
        Ok(registration)
    }
}

impl StagingLoadTestResourceRegistration<'_> {
    /// Build the ledger statement that a writer appends to its domain batch.
    pub(crate) fn d1_statement(
        &self,
        registered_at_ms: i64,
    ) -> Result<D1BatchStatement, StagingLoadTestOwnershipError> {
        if registered_at_ms < 0 {
            return Err(StagingLoadTestOwnershipError::InvalidIdentifier);
        }
        validate_registration(self).map_err(|message| {
            if message.contains("disposition") {
                StagingLoadTestOwnershipError::InvalidDisposition
            } else {
                StagingLoadTestOwnershipError::InvalidIdentifier
            }
        })?;
        Ok(D1BatchStatement::new(
            SQL_REGISTER_RESOURCE_IN_BATCH,
            vec![
                json!(self.run_id),
                json!(self.scenario.as_str()),
                json!(self.resource_class.as_str()),
                json!(receipt_ref(self)),
                json!(self.opaque_handle),
                json!(self.disposition.as_str()),
                json!(registered_at_ms),
            ],
        ))
    }

    /// Bind an R2 operation to the same immutable admitted identity.
    pub(crate) fn r2_intent(
        &self,
        operation_id: &str,
    ) -> Result<StagingLoadTestR2Intent, StagingLoadTestOwnershipError> {
        if !is_lower_hex(operation_id, 64) {
            return Err(StagingLoadTestOwnershipError::InvalidIdentifier);
        }
        Ok(StagingLoadTestR2Intent {
            operation_id: operation_id.to_owned(),
            run_id: self.run_id.to_owned(),
            scenario: self.scenario,
            target_deployment_sha: self.target_deployment_sha.to_owned(),
            resource_class: self.resource_class,
            receipt_ref: receipt_ref(self),
            opaque_handle: self.opaque_handle.to_owned(),
            disposition: self.disposition,
        })
    }
}

/// Durable prepare/commit identity for mutations outside D1's transaction.
pub(crate) struct StagingLoadTestR2Intent {
    operation_id: String,
    run_id: String,
    scenario: StagingLoadTestScenario,
    target_deployment_sha: String,
    resource_class: StagingLoadTestResourceClass,
    receipt_ref: String,
    opaque_handle: String,
    disposition: StagingLoadTestDisposition,
}

impl core::fmt::Debug for StagingLoadTestR2Intent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StagingLoadTestR2Intent")
            .field("operation_id", &self.operation_id)
            .field("run_id", &self.run_id)
            .field("scenario", &self.scenario)
            .field("target_deployment_sha", &self.target_deployment_sha)
            .field("resource_class", &self.resource_class)
            .field("receipt_ref", &self.receipt_ref)
            .field("opaque_handle", &"[REDACTED]")
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl StagingLoadTestR2Intent {
    /// Persist before the external R2 mutation is attempted.
    pub(crate) fn prepare_statement(&self, prepared_at_ms: i64) -> D1BatchStatement {
        D1BatchStatement::new(
            SQL_PREPARE_R2_INTENT,
            vec![
                json!(self.operation_id),
                json!(self.run_id),
                json!(self.scenario.as_str()),
                json!(self.target_deployment_sha),
                json!(self.resource_class.as_str()),
                json!(self.receipt_ref),
                json!(self.opaque_handle),
                json!(self.disposition.as_str()),
                json!(prepared_at_ms),
            ],
        )
    }

    /// Atomically register the resource and close its durable intent.
    pub(crate) fn commit_statements(&self, committed_at_ms: i64) -> [D1BatchStatement; 2] {
        let registration = D1BatchStatement::new(
            SQL_REGISTER_RESOURCE_IN_BATCH,
            vec![
                json!(self.run_id),
                json!(self.scenario.as_str()),
                json!(self.resource_class.as_str()),
                json!(self.receipt_ref),
                json!(self.opaque_handle),
                json!(self.disposition.as_str()),
                json!(committed_at_ms),
            ],
        );
        let close_intent = D1BatchStatement::new(
            SQL_COMMIT_R2_INTENT,
            vec![json!(self.operation_id), json!(committed_at_ms)],
        );
        [registration, close_intent]
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Outcome of an attempted exact-run registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StagingLoadTestRegistrationOutcome {
    /// D1 inserted the row and returned this redacted receipt reference.
    Registered {
        /// Domain-separated SHA-256 receipt reference.
        receipt_ref: String,
    },
    /// No open staging run matched the supplied exact identity.
    NoMatchingOpenRun,
}

/// Restricted writer for the append-only staging load-test ownership ledger.
///
/// Construct with [`StagingLoadTestOwnershipWriter::from_d1_env`] so this path
/// loads only D1 scope and credentials, never R2 object-delete credentials.
pub struct StagingLoadTestOwnershipWriter {
    d1: D1HttpClient,
}

impl core::fmt::Debug for StagingLoadTestOwnershipWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StagingLoadTestOwnershipWriter")
            .field("d1", &"[REDACTED]")
            .finish()
    }
}

impl StagingLoadTestOwnershipWriter {
    /// Load the D1-only, writable capability needed by this adapter.
    ///
    /// The wrapped client is private, so this API exposes registration only;
    /// it does not expose arbitrary SQL or any delete operation.
    pub fn from_d1_env() -> Result<Self, String> {
        Ok(Self {
            d1: D1HttpClient::for_staging_load_test_ownership_writes()?,
        })
    }

    /// Append one run-owned resource reference to the migration 0147 ledger.
    ///
    /// The single `INSERT ... SELECT` binds the supplied run, scenario and
    /// deployment SHA to an exact open staging run. The caller supplies an
    /// explicit per-resource disposition. The adapter rejects disposable
    /// treatment for classes whose contract requires preservation or shared
    /// reference safety; it cannot delete or update ledger rows.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a D1 failure/uniqueness conflict,
    /// or an unexpected D1 response. Error text does not include the opaque
    /// handle or any bound parameter.
    pub async fn register_staging_load_test_resource(
        &self,
        registration: StagingLoadTestResourceRegistration<'_>,
    ) -> Result<StagingLoadTestRegistrationOutcome, String> {
        validate_registration(&registration)?;

        let receipt_ref = receipt_ref(&registration);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_millis();
        let now_ms = i64::try_from(now_ms)
            .map_err(|_| "system clock timestamp is out of range".to_owned())?;
        let params = [
            json!(registration.run_id),
            json!(registration.scenario.as_str()),
            json!(registration.target_deployment_sha),
            json!(registration.resource_class.as_str()),
            json!(receipt_ref),
            json!(registration.opaque_handle),
            json!(registration.disposition.as_str()),
            json!(now_ms),
        ];
        let rows = match self.d1.query(SQL_REGISTER_RESOURCE, &params).await {
            Ok(rows) => rows,
            Err(_) => {
                // A uniqueness error is the normal signal for an exact
                // idempotent retry. It can also indicate a conflicting
                // resource_class/opaque_handle owned by another run, so only
                // an exact identity lookup is allowed to recover success.
                let existing = self
                    .d1
                    .query(SQL_FIND_REGISTERED_RESOURCE, lookup_params(&params))
                    .await
                    .map_err(|_| "staging load-test resource registration failed".to_owned())?;
                return recover_exact_replay(&existing, &receipt_ref);
            }
        };

        let Some(row) = rows.first() else {
            return Ok(StagingLoadTestRegistrationOutcome::NoMatchingOpenRun);
        };
        let returned_receipt = row
            .get("receipt_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "D1 returned a malformed registration result".to_owned())?;
        if returned_receipt != receipt_ref {
            return Err("D1 returned an unexpected registration receipt".to_owned());
        }
        Ok(StagingLoadTestRegistrationOutcome::Registered { receipt_ref })
    }
}

fn lookup_params(params: &[serde_json::Value; 8]) -> &[serde_json::Value] {
    // SQL_FIND_REGISTERED_RESOURCE uses ?1, ?2, and ?4 through ?7. Retain the
    // unused deployment SHA at ?3 so the positional binding indices stay
    // aligned with SQL_REGISTER_RESOURCE.
    &params[..7]
}

fn replay_receipt(
    rows: &[serde_json::Map<String, serde_json::Value>],
    expected_receipt: &str,
) -> Result<Option<String>, String> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let receipt = row
        .get("receipt_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "D1 returned a malformed registration result".to_owned())?;
    if receipt != expected_receipt {
        return Err("D1 returned an unexpected registration receipt".to_owned());
    }
    Ok(Some(receipt.to_owned()))
}

fn recover_exact_replay(
    rows: &[serde_json::Map<String, serde_json::Value>],
    expected_receipt: &str,
) -> Result<StagingLoadTestRegistrationOutcome, String> {
    let Some(receipt_ref) = replay_receipt(rows, expected_receipt)? else {
        return Err("staging load-test resource registration failed".to_owned());
    };
    Ok(StagingLoadTestRegistrationOutcome::Registered { receipt_ref })
}

fn validate_registration(
    registration: &StagingLoadTestResourceRegistration<'_>,
) -> Result<(), String> {
    let run_id = registration.run_id;
    if run_id.is_empty()
        || run_id.len() > 20
        || run_id.starts_with('0')
        || !run_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("run_id must be canonical positive decimal text".to_owned());
    }
    let sha = registration.target_deployment_sha;
    if sha.len() != 40
        || !sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("target deployment SHA must be 40 lowercase hexadecimal characters".to_owned());
    }
    let handle = registration.opaque_handle;
    if handle.is_empty() || handle.len() > 512 || handle.chars().any(char::is_control) {
        return Err(
            "opaque resource handle must be 1-512 bytes without control characters".to_owned(),
        );
    }
    if registration.resource_class.requires_retention()
        && registration.disposition != StagingLoadTestDisposition::Retained
    {
        return Err("resource class requires retained disposition".to_owned());
    }
    Ok(())
}

fn receipt_ref(registration: &StagingLoadTestResourceRegistration<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"corelink-staging-load-test-resource-receipt-v1\0");
    for part in [
        registration.run_id.as_bytes(),
        registration.scenario.as_str().as_bytes(),
        registration.target_deployment_sha.as_bytes(),
        registration.resource_class.as_str().as_bytes(),
        registration.opaque_handle.as_bytes(),
        registration.disposition.as_str().as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration<'a>(
        run_id: &'a str,
        deployment_sha: &'a str,
        opaque_handle: &'a str,
        resource_class: StagingLoadTestResourceClass,
        disposition: StagingLoadTestDisposition,
    ) -> StagingLoadTestResourceRegistration<'a> {
        StagingLoadTestResourceRegistration {
            run_id,
            scenario: StagingLoadTestScenario::Cas,
            target_deployment_sha: deployment_sha,
            resource_class,
            disposition,
            opaque_handle,
        }
    }

    #[test]
    fn rejects_noncanonical_or_out_of_scope_identity() {
        let sha = "a".repeat(40);
        assert!(validate_registration(&registration(
            "01",
            &sha,
            "handle",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        ))
        .is_err());
        assert!(validate_registration(&registration(
            "1",
            &"A".repeat(40),
            "handle",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        ))
        .is_err());
        assert!(validate_registration(&registration(
            "1",
            &sha,
            "bad\nhandle",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        ))
        .is_err());
    }

    #[test]
    fn receipt_is_deterministic_but_run_scoped() {
        let sha = "a".repeat(40);
        let first = registration(
            "123",
            &sha,
            "opaque-id",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        );
        let same = registration(
            "123",
            &sha,
            "opaque-id",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        );
        let other_run = registration(
            "124",
            &sha,
            "opaque-id",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        );
        assert_eq!(receipt_ref(&first), receipt_ref(&same));
        assert_ne!(receipt_ref(&first), receipt_ref(&other_run));
    }

    #[test]
    fn retained_and_shared_reference_classes_reject_disposable_treatment() {
        let sha = "a".repeat(40);
        for class in [
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestResourceClass::DsrObligation,
            StagingLoadTestResourceClass::AuditEvidence,
            StagingLoadTestResourceClass::BillingAudit,
        ] {
            let registration = registration(
                "123",
                &sha,
                "opaque-id",
                class,
                StagingLoadTestDisposition::Disposable,
            );
            assert!(validate_registration(&registration).is_err());
        }
    }

    #[test]
    fn every_known_class_fails_closed_for_disposition_conflicts() {
        let sha = "a".repeat(40);
        let classes = [
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestResourceClass::WebhookInbox,
            StagingLoadTestResourceClass::WebhookEffect,
            StagingLoadTestResourceClass::DsrArtifact,
            StagingLoadTestResourceClass::DsrObligation,
            StagingLoadTestResourceClass::AuditEvidence,
            StagingLoadTestResourceClass::BillingAudit,
            StagingLoadTestResourceClass::SignupArtifact,
            StagingLoadTestResourceClass::ByokArtifact,
        ];
        for class in classes {
            for disposition in [
                StagingLoadTestDisposition::Disposable,
                StagingLoadTestDisposition::Retained,
            ] {
                let registration = registration("123", &sha, "opaque-id", class, disposition);
                let expected_valid = !class.requires_retention()
                    || disposition == StagingLoadTestDisposition::Retained;
                assert_eq!(validate_registration(&registration).is_ok(), expected_valid);
            }
        }
    }

    #[test]
    fn debug_redacts_opaque_handle() {
        let sha = "a".repeat(40);
        let value = registration(
            "123",
            &sha,
            "must-not-appear",
            StagingLoadTestResourceClass::WebhookInbox,
            StagingLoadTestDisposition::Disposable,
        );
        let rendered = format!("{value:?}");
        assert!(!rendered.contains("must-not-appear"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn d1_and_r2_contracts_accept_only_bounded_canonical_inputs() {
        let sha = "a".repeat(40);
        let value = registration(
            "123",
            &sha,
            "must-not-appear",
            StagingLoadTestResourceClass::CasReference,
            StagingLoadTestDisposition::Retained,
        );
        assert!(value.d1_statement(1).is_ok());
        assert!(value.d1_statement(-1).is_err());
        assert!(value.r2_intent(&"b".repeat(64)).is_ok());
        assert!(value.r2_intent(&"B".repeat(64)).is_err());
        assert!(value.r2_intent("short").is_err());
        let intent = value.r2_intent(&"c".repeat(64)).expect("valid intent");
        let _prepare = intent.prepare_statement(1);
        let _commit = intent.commit_statements(2);
        let rendered = format!("{intent:?}");
        assert!(!rendered.contains("must-not-appear"));
        assert!(rendered.contains("[REDACTED]"));
    }

    fn complete_scans() -> Vec<StagingLoadTestTeardownScan> {
        STAGING_LOAD_TEST_RESOURCE_CLASSES
            .into_iter()
            .map(|class| StagingLoadTestTeardownScan {
                class,
                observed_count: 0,
                complete: true,
                truncated: false,
            })
            .collect()
    }

    #[test]
    fn teardown_requires_the_closed_nine_class_census_even_when_zero() {
        let identity = StagingLoadTestTeardownIdentity::for_test();
        let receipt = reconcile_staging_load_test_teardown(
            &identity,
            None,
            &complete_scans(),
            &[],
            10,
            |_| panic!("zero inventory cannot delete"),
        )
        .expect("all zero-count classes reconcile");
        assert_eq!(receipt.resources.len(), 9);
        assert_eq!(receipt.cross_run_deletions, 0);
        assert_eq!(receipt.terminal_state, "reconciled");
    }

    #[test]
    fn teardown_fails_closed_for_truncation_duplicates_bounds_and_count_mismatch() {
        let identity = StagingLoadTestTeardownIdentity::for_test();
        let mut scans = complete_scans();
        scans[0].truncated = true;
        assert_eq!(
            reconcile_staging_load_test_teardown(&identity, None, &scans, &[], 10, |_| {
                StagingLoadTestTeardownAction::Deleted
            }),
            Err(StagingLoadTestTeardownError::TruncatedScan)
        );
        let mut scans = complete_scans();
        scans.push(scans[0]);
        assert_eq!(
            reconcile_staging_load_test_teardown(&identity, None, &scans, &[], 10, |_| {
                StagingLoadTestTeardownAction::Deleted
            }),
            Err(StagingLoadTestTeardownError::DuplicateClass)
        );
        let resource = StagingLoadTestTeardownResource::for_test(
            StagingLoadTestResourceClass::WebhookInbox,
            &"b".repeat(64),
            StagingLoadTestDisposition::Disposable,
        );
        assert_eq!(
            reconcile_staging_load_test_teardown(
                &identity,
                None,
                &complete_scans(),
                &[resource],
                0,
                |_| { StagingLoadTestTeardownAction::Deleted }
            ),
            Err(StagingLoadTestTeardownError::OverBudget)
        );
        let mut scans = complete_scans();
        scans[1].observed_count = 1;
        assert_eq!(
            reconcile_staging_load_test_teardown(&identity, None, &scans, &[], 10, |_| {
                StagingLoadTestTeardownAction::Deleted
            }),
            Err(StagingLoadTestTeardownError::CountMismatch)
        );
    }

    #[test]
    fn teardown_deletes_disposable_only_and_redacts_handles() {
        let identity = StagingLoadTestTeardownIdentity::for_test();
        let mut scans = complete_scans();
        scans[0].observed_count = 1;
        scans[1].observed_count = 1;
        let shared_cas = StagingLoadTestTeardownResource::for_test(
            StagingLoadTestResourceClass::CasReference,
            &"c".repeat(64),
            StagingLoadTestDisposition::Retained,
        );
        let disposable = StagingLoadTestTeardownResource::for_test(
            StagingLoadTestResourceClass::WebhookInbox,
            &"d".repeat(64),
            StagingLoadTestDisposition::Disposable,
        );
        let receipt = reconcile_staging_load_test_teardown(
            &identity,
            None,
            &scans,
            &[shared_cas, disposable],
            10,
            |resource| {
                assert_eq!(resource.class, StagingLoadTestResourceClass::WebhookInbox);
                StagingLoadTestTeardownAction::Deleted
            },
        )
        .expect("only disposable state reaches the deleter");
        let encoded = serde_json::to_string(&receipt).expect("receipt serializes");
        assert!(!encoded.contains("test-handle"));
        assert_eq!(receipt.resources["cas_reference"].preserved, 1);
        assert_eq!(receipt.resources["webhook_inbox"].deleted, 1);
    }

    #[test]
    fn teardown_never_emits_success_after_partial_delete() {
        let identity = StagingLoadTestTeardownIdentity::for_test();
        let mut scans = complete_scans();
        scans[1].observed_count = 1;
        let resource = StagingLoadTestTeardownResource::for_test(
            StagingLoadTestResourceClass::WebhookInbox,
            &"e".repeat(64),
            StagingLoadTestDisposition::Disposable,
        );
        assert_eq!(
            reconcile_staging_load_test_teardown(&identity, None, &scans, &[resource], 10, |_| {
                StagingLoadTestTeardownAction::Quarantined
            }),
            Err(StagingLoadTestTeardownError::PartialDelete)
        );
    }

    #[test]
    fn terminal_receipt_replay_is_read_only_and_cannot_delete_again() {
        let identity = StagingLoadTestTeardownIdentity::for_test();
        let terminal = reconcile_staging_load_test_teardown(
            &identity,
            None,
            &complete_scans(),
            &[],
            10,
            |_| panic!("zero inventory cannot delete"),
        )
        .expect("initial terminal receipt");
        let replay =
            reconcile_staging_load_test_teardown(&identity, Some(&terminal), &[], &[], 0, |_| {
                panic!("terminal replay must not invoke a deleter")
            })
            .expect("terminal receipt replay");
        assert_eq!(replay, terminal);
    }

    #[test]
    fn exact_replay_returns_original_receipt_and_other_run_lookup_fails_closed() {
        let expected_receipt = "b".repeat(64);
        let row = serde_json::Map::from_iter([(
            "receipt_ref".to_owned(),
            serde_json::Value::String(expected_receipt.clone()),
        )]);
        assert_eq!(
            recover_exact_replay(&[row], &expected_receipt),
            Ok(StagingLoadTestRegistrationOutcome::Registered {
                receipt_ref: expected_receipt.clone()
            })
        );
        // The SQL lookup is bound to the exact run and resource identity. A
        // collision on the global (resource_class, opaque_handle) key from a
        // different run therefore returns no row and remains an error.
        assert!(recover_exact_replay(&[], &expected_receipt).is_err());
    }

    #[test]
    fn replay_lookup_uses_first_seven_positional_values_with_skipped_three() {
        let params = std::array::from_fn(|index| json!(index + 1));
        assert_eq!(
            lookup_params(&params),
            &[
                json!(1),
                json!(2),
                json!(3),
                json!(4),
                json!(5),
                json!(6),
                json!(7)
            ]
        );
        assert!(SQL_FIND_REGISTERED_RESOURCE.contains("?1"));
        assert!(SQL_FIND_REGISTERED_RESOURCE.contains("?2"));
        assert!(!SQL_FIND_REGISTERED_RESOURCE.contains("?3"));
        for position in ["?4", "?5", "?6", "?7"] {
            assert!(SQL_FIND_REGISTERED_RESOURCE.contains(position));
        }
    }
}
