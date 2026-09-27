//! Real D1 effective erase adapter (`BackendKind::D1`), WI-S11-008 Wave 1
//! increment 2. Hard-deletes a tenant's subject PII from the D1
//! `corelink-config-prod` database.
//!
//! The erase-set + the erase-vs-retain classification are OWNER-RATIFIED
//! in ADR-S11-013 (2026-06-11). Every table/column below was cold-verified
//! against its `migrations/d1/*.sql` `CREATE TABLE`. Load-bearing
//! subtleties, all honored here:
//!
//! - **Ordering.** Child rows first, then the root `tenant` row LAST (so a
//!   FK-enforced delete never blocks); `signup_attempts` is deleted BEFORE
//!   `signup_orchestration` because it joins through
//!   `signup_orchestration.idempotency_key`.
//! - **No cross-tenant break.** `adapter_cache_map` / `adapter_npm_meta` /
//!   `adapter_pip_index` are keyed by `namespace`, which is either a tenant
//!   UUID or the synthetic `'_public'` (shared public-registry content,
//!   `INV-TENANT-ISOLATION`). We delete `WHERE namespace = <tenant_uuid>`;
//!   a tenant UUID can never equal `'_public'`, so shared content is safe.
//! - **No phantom tables.** `tenant_primary_region` (0028) and
//!   `byok_tenant_status` (0031) are ALTER COLUMNS on `tenant`, not tables;
//!   deleting the `tenant` row covers them.
//! - **SQL safety.** Table + column names are compile-time constants
//!   (never request input); only the tenant id is a bound `?1` parameter.
//! - **D1 does NOT enforce FOREIGN KEYs (CAA-360 #21).** D1/SQLite ships with
//!   `PRAGMA foreign_keys = OFF` and D1 does not expose a reliable per-connection
//!   way to turn it on, so tenant-keyed tables (`tenant_quota`, `cas_tombstone`,
//!   …) intentionally omit FK declarations — they would be inert. Referential
//!   integrity is therefore an APPLICATION invariant, maintained two ways:
//!   (1) on erase, child rows are deleted BEFORE the parent `tenant` row (the
//!   ordering above), so no orphan is ever left pointing at a deleted tenant;
//!   (2) on insert, the writing path only creates a `tenant_quota` /
//!   `cas_tombstone` row for a tenant that already exists (provisioned first).
//!   Adding `FOREIGN KEY` clauses to the migrations would NOT change runtime
//!   behavior on D1 and is deliberately not done (see migrations 0066/0067).

use std::sync::Arc;

use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use corelink_privacy_erasure_worker::backends::{
    BackendErasureAdapter, VerificationContext, CANONICAL_EMPTY_TENANT_HASH,
};
use corelink_privacy_erasure_worker::error::ErasureBackendError;
use corelink_privacy_erasure_worker::event::{BackendErasureOutcome, BackendKind};

use super::d1util::{col_str, d1_batch_blocking, d1_query_blocking, scalar_count};
use crate::storage::d1_http::{D1BatchStatement, D1HttpClient, D1Row};

#[path = "adapter_d1_registry.rs"]
mod registry;
use registry::ALL_TENANT_KEYED_TABLES;

mod classification;
use classification::ensure_classification;
#[cfg(test)]
use classification::{classification_count, unclassified_tenant_keyed_tables, CLASSIFICATION_SETS};

/// Erase-set tables keyed directly by a `tenant_id` column (incl.
/// tenant-leftmost composite PKs, where `WHERE tenant_id = ?` is exact).
/// `tenant` itself is handled separately (deleted LAST).
///
/// `remaining_rows()` scans this whole slice, so any table added here is
/// automatically covered by the post-erase verification sweep (no separate
/// edit needed) — the property the **CF-1 fix** relies on.
///
/// `pub(super)` so the DSR ACCESS / PORTABILITY gather pipeline
/// ([`super::access`]) single-sources this exact erase-set — a future table
/// added here is then covered by BOTH erase AND access (no parallel list to
/// drift).
pub(super) const TENANT_ID_TABLES: &[&str] = &[
    // ⚠️ FK-ORDER — D1 enforces `PRAGMA foreign_keys = ON` (verified on the prod
    // REST path 2026-08-18). `stripe_checkout_sessions` carries
    // `FOREIGN KEY (tenant_id) REFERENCES tier_selections(tenant_id)`, so the
    // CHILD MUST be deleted BEFORE the PARENT `tier_selections`. The adapter
    // deletes this slice in ORDER via separate per-statement D1-REST calls, so if
    // the parent is deleted while an orphan child row is still pending, the
    // parent DELETE fails the FK constraint → the D1 backend Errs → the tenant's
    // Art.17 erasure 500s and stays stuck. ROOT CAUSE of the 2026-08-18 drain
    // tail: 4 tenants with an un-completed checkout session were the only rows
    // left un-erased for weeks. Keep every erase-set CHILD ahead of its PARENT;
    // the `stripe_checkout_sessions_precedes_tier_selections` test guards this edge.
    // Recoverable Stripe Checkout ownership state (migr. 0111). This row has
    // a foreign key to `tier_selections`, so it MUST be deleted before that
    // parent (the checkout-session child immediately below is ordered for the
    // same reason).
    "stripe_checkout_ownership_ledger",
    // Stripe Checkout *session* state, `tenant_id`-keyed (migr. 0039/0062).
    // Transient pre-purchase intent — NOT the fiscal record (the retained
    // invoice/customer/subscription rows are the 5y fiscal artifact). ERASE.
    "stripe_checkout_sessions",
    "tier_selections",
    "tenant_billing",
    "pilot_signups",
    "devenv_credential_obligation",
    "runner_credential_obligation",
    "tenant_credential_revocation_floor",
    "credential_generation_revocation",
    "credential_generation_event_receipts",
    "pat",
    "usage_counter",
    "tenant_storage_state",
    "tenant_offboarding_state",
    "usage_event_staging",
    // Ingest conflict quarantine is tenant-owned operational staging state
    // (migr. 0133), with no fiscal or audit retention basis. Existing rows are
    // deleted by the same tenant_id sweep and included in post-erase counts.
    "usage_event_staging_conflicts",
    "dpa_acceptance_pending",
    "tenant_config",
    "hot_blobs",
    "quota_reservations",
    // Audit-drain partition lease (migr. 0101, B-038): transient, self-expiring
    // coordination state (holder uuid + acquired/expires ms), NO subject PII and
    // NOT audit evidence — a lease self-heals on TTL expiry. No lawful retention
    // basis and no FK, so it is order-safe and ERASE-by-tenant_id (privacy-forward:
    // wiped with the tenant, harmless since an erased tenant is not draining).
    "audit_drain_lease",
    "quota_cas_attempts",
    "quota_fsm_state",
    "ratelimit_buckets",
    "byok_envelope",
    "tenant_byok_config",
    "tenant_byok_secret",
    // BYOK transition/activation ledgers (migrations 0118-0121). These are
    // operational tenant state, not retained evidence, and must be erased.
    // FK children precede their guards/intents/fences when D1 FK enforcement
    // is enabled by a test or a future production path.
    "tenant_byok_config_history",
    "tenant_byok_secret_history",
    "byok_activation_key_health",
    "byok_activation_source_object",
    "byok_activation_source_capture",
    "byok_transition_commit_guard",
    "byok_control_outcome",
    "byok_backfill_run",
    "byok_logical_object_generation",
    "byok_logical_object_publication",
    "byok_purge_identity_quarantine",
    // B-083 purge ledger. Both the identity quarantine and
    // `byok_object_purge_cause` are FK children of the purge item. The former
    // uses the direct tenant lane; the latter is deleted in the bespoke
    // child+parent batch below.
    "byok_object_purge_item",
    "byok_activation_intent",
    "byok_activation_guard",
    "byok_tenant_gate",
    "byok_data_intent",
    "byok_transition_fence",
    "adapter_oci_kv",
    // CAA-360 #4: tenant-linked NPS/CSAT PII (recipient_hash); `tenant_id`-keyed
    // (migration 0046). Not a legal-retention category, so it IS erased on a DSR
    // (GDPR Art.17) — distinct from the retained fiscal `stripe_*` records.
    "survey_responses",
    // CAA-360 #11: per-tenant spend ledger (`tenant_id` PK, migration 0066).
    // Operational quota state, not a fiscal invoice record → erased on a DSR.
    "tenant_quota",
    // githugr issuer → isolated tenant identity map (migr. 0112). This is
    // operational identity state, not a retained audit/fiscal record.
    "githugr_tenant_org_map",
    // ── CF-1 (2026-06-28): tenant-keyed tables added AFTER the 2026-06-11
    // ADR-S11-013 ratification that were never back-added to the erase-set.
    // Each is operational tenant state / tenant PII with no legal-retention
    // basis → ERASE per ADR-S11-013's classification policy. ───────────────
    // Seat PII: `tenant_id` + raw Clerk `user_id` + `email_hash` (migr. 0074).
    // The worst gap — a team-tenant's member roster survived "VerifiedComplete".
    "team_member",
    // CAS deletion tombstones `(tenant_id, digest)` (migr. 0067). Operational
    // 410-Gone state; meaningless once the tenant is gone → ERASE.
    "cas_tombstone",
    // Pilot enrolment rows keyed by `tenant_id` (migr. 0065). Subject PII.
    "pilot_tenants",
    // Runners add-on entitlement, `tenant_id` PK (migr. 0070/0072). Operational.
    "runners_entitlement",
    // Per-tenant monthly request counters (migr. 0071). Operational usage state.
    "monthly_request_counts",
    // Advisory tier-selection lock, `tenant_id` PK (migr. 0039). Operational.
    "tier_selection_locks",
    // Runner subscription↔tenant billing mirror, `tenant_id`-indexed (migr. 0087).
    // The runner analog of `tenant_billing`: an OPERATIONAL subscription-state
    // mirror (plan/status), NOT the fiscal record (the retained Stripe
    // customer/invoice/subscription rows are the 5y fiscal artifact). Same class
    // as `tenant_billing` / `stripe_checkout_sessions` above → ERASE per
    // ADR-S11-013 (`DELETE ... WHERE tenant_id = ?`; the tenant_id index covers it).
    "runner_billing",
    // Runner entitlement reconciliation fence (migr. 0139/0140) is
    // tenant-scoped operational ordering state with no retention basis → ERASE.
    "runner_entitlement_reconcile_fence",
    // Runner checkout attempts are recoverable provider-intent state (migr.
    // 0136), analogous to stripe_checkout_sessions. They are not the fiscal
    // invoice/customer/subscription records retained by ADR-S11-013.
    "runner_checkout_attempts",
    // GC run + candidate state, `tenant_id`-keyed (migr. 0006/0007). Operational
    // storage-GC bookkeeping over the tenant's own blobs → ERASE.
    "gc_run",
    "gc_candidates",
    // Region-migration request + progress, `tenant_id`-keyed (migr. 0023/0027).
    // Operational residency-move state, no retention basis → ERASE.
    "region_migration_request",
    "region_migration_progress",
    // Clerk org → isolated tenant identity map (migr. 0083). PRIMARY identity is
    // `clerk_org_id`, but it CARRIES `tenant_id` — classify by tenant_id: the
    // org→tenant mapping is operational identity state with no retention basis
    // and is removed when that tenant is erased (GDPR Art.17). ERASE.
    "tenant_org_map",
    // GitHub App installation → isolated tenant identity map (migr. 0084).
    // PRIMARY identity is `installation_id`, but it CARRIES `tenant_id` —
    // classify by tenant_id: the installation→tenant mapping is operational
    // identity state with no retention basis and is removed when that tenant is
    // erased (GDPR Art.17). ERASE.
    "tenant_gh_installation_map",
    // Per-tenant runner repo allowlist, tenant-leftmost composite PK
    // `(tenant_id, repo_full_name)` (migr. 0085). Operational entitlement state
    // with no retention basis → ERASE.
    "runner_repo_allowlist",
    // Per-tenant workspace snapshots, tenant-leftmost composite PK
    // `(tenant_id, workspace_id)` (migr. 0088). A workspace is a named snapshot
    // of the tenant's OWN cached state (name + size + snapshot ref) — the
    // tenant's own content with no retention basis, removed when the tenant is
    // erased (GDPR Art.17). ERASE.
    "workspaces",
    // Per-tenant, per-day usage rollup for the dashboard ROI surface
    // `(tenant_id, day)` (migr. 0089). Display telemetry — the tenant's own
    // operational usage state, no retention basis → ERASE.
    "usage_daily",
    // Per-tenant, per-region, per-period runner vCPU-seconds aggregate,
    // tenant-leftmost composite PK `(tenant_id, region, billing_period)`
    // (migr. 0094). The runner analog of `usage_counter` above: an OPERATIONAL
    // pre-invoice usage counter, NOT the fiscal record (the retained Stripe
    // invoice/customer/subscription rows are the fiscal artifact). Same class
    // as `usage_counter` / `usage_daily` → ERASE per ADR-S11-013
    // (`DELETE ... WHERE tenant_id = ?`; the tenant-leftmost PK covers it).
    "runner_usage_counter",
    // Monthly aggregated vCPU-second meter for the DevEnv product
    // (migration 0106). Same class as `runner_usage_counter` above: a
    // pre-invoice usage aggregate keyed tenant-leftmost, NOT the fiscal
    // record → ERASE per ADR-S11-013.
    //
    // Registered in the SAME PR that adds the migration, deliberately. #1405
    // put this name in both registries citing a migration that creates a
    // different table, and the phantom split an Art.17 erasure in half. The
    // mirror gate added in #1419 now fails a registry name no migration
    // creates; `every_migrated_tenant_keyed_table_is_classified` fails the
    // opposite. Shipping the table without this line trades a loud 500 for
    // silent UNDER-erasure, which is the worse half of that pair.
    "devenv_monthly_vcpu",
    // B-071 GC/CAS intent fences (migr. 0115). These are transient recovery
    // state and must not survive tenant erasure.
    "gc_purge_intent",
    "cas_write_intent",
    "cas_reconciliation_intent",
    "storage_mutation_liability",
];

/// Erase-set tables keyed by a `namespace` column. The bound value is the
/// tenant UUID, which can never equal the shared `'_public'` namespace —
/// so shared public-registry content is never touched.
///
/// `pub(super)` — single-sourced by the DSR ACCESS gather ([`super::access`]).
pub(super) const NAMESPACE_TABLES: &[&str] =
    &["adapter_cache_map", "adapter_npm_meta", "adapter_pip_index"];

/// Tables that MUST NEVER appear in the erase-set (retain-set per
/// ADR-S11-013: a lawful retention basis — the erasure record itself,
/// fiscal 5y, audit/legal 7y WORM). Used by the guard test to catch an
/// accidental erase-set addition AND by the completeness gate to confirm
/// every tenant-keyed table is consciously classified.
///
/// **CF-1 (2026-06-28): PROMOTED out of `#[cfg(test)]`** so it exists at
/// runtime — the completeness gate / runtime drift assertion can consult it,
/// not just the test build.
pub(super) const RETAIN_SET: &[&str] = &[
    "dsr_erasure_log",
    "dsr_requested",
    // Customer-facing DSR ticket store (migr. 0090). The durable record that
    // CoreLink RECEIVED + honoured a data-subject-rights request — Art.5(2)
    // accountability evidence, the intake sibling of `dsr_requested`. Stores no
    // raw PII (subject == tenant_id; rectified values are hashed by the live
    // pipeline before D1), so it SURVIVES an Art.17 erasure (RETAIN).
    "dsr_tickets",
    // Migration 0145's envelope is the bounded authority needed to complete a
    // DSR after its main queue retries are exhausted. Keep its tenant/DSR
    // binding and actor/approval transition evidence until the existing
    // seven-day cleanup removes the envelope and linked audit rows together
    // (issue #2166); this is bounded DSR accountability under ADR-S11-013.
    "dsr_dlq_redrive_envelopes",
    "dpa_acceptances",
    // NOTE: the table is `erasure_attestations` (plural, migr. 0032). A
    // singular `"erasure_attestation"` sat here too and matched nothing —
    // harmless (RETAIN entries are never deleted, and the Art.15 disclosable
    // subset in `access.rs` uses the plural), but it is exactly the shape the
    // mirror gate below now refuses.
    "erasure_attestations",
    "export_audit_log",
    "stripe_customers",
    "stripe_subscriptions",
    "stripe_invoices",
    "stripe_disputes",
    "stripe_refunds",
    "audit_outbox",
    // ── CF-1: tenant-keyed tables with a lawful retention basis (ADR-S11-013
    // RETAIN policy: fiscal / billing-reconciliation / audit-evidence). ─────
    "billing_replay_audit",         // billing replay audit trail (migr. 0021)
    "stripe_idempotency_keys",      // fiscal idempotency ledger (migr. 0018)
    "billing_reconciliation_drift", // billing reconciliation evidence (migr. 0019)
    "stripe_submission_state",      // billing submission state (migr. 0019)
    "customer_audit_events",        // per-tenant audit evidence (migr. 0077)
    "audit_chain_head",             // audit-chain seal head — integrity (migr. 0078)
    // B-054 epoch-contract evidence (migr. 0109). These are append-only
    // audit-chain authority/projection/manifest rows and therefore remain as
    // legal audit evidence after tenant erasure.
    "audit_chain_epoch_ledger",
    "audit_chain_epoch",
    "audit_chain_archive_manifest",
    // Audit-chain repair/witness receipts (migrations 0123/0124) are
    // integrity evidence and remain under the lawful audit-retention basis.
    "audit_chain_legacy_tail_resolution",
    "audit_chain_witness_receipt",
    // Durable money-path audit-before-mutation record (migr. 0092): the
    // tier-select orchestration's `tier_select_attempted` / `dpa_first_violation`
    // / `stripe_checkout_session_created` / `tier_activated_free` events. Holds
    // no raw subject PII (tenant_id is the pseudonymous tenant ref; the rest is
    // event_type / correlation_id / ts_ms) — the same audit-evidence class as
    // `audit_outbox` / `customer_audit_events`. Erasing it would defeat the very
    // audit-before-mutation guarantee it exists for → RETAIN (Art.5(2)).
    "tier_select_audit_events",
    // Durable billing-audit evidence (migr. 0095, WP-D1/MED-5): one append-only
    // row per materializer audit-before-mutation emit. Subject-free by
    // construction (tenant_id is the pseudonymous ref; the rest is Stripe ids /
    // severity / ts_ms / canonical payload JSON). Same audit-evidence class as
    // `tier_select_audit_events` — erasing it would defeat the guarantee it
    // exists for → RETAIN (Art.5(2)).
    "stripe_billing_audit_events",
    // Historical runner billing authority (migr. 0134). The immutable terms
    // snapshot and per-event claim bind the accounting result to the exact
    // terms/evidence used; they are retained billing evidence under the
    // existing ADR-S11-013 fiscal/billing-reconciliation basis.
    "runner_period_terms_snapshot",
    "runner_aggregate_event_claim",
    // B-089 SLA-credit settlement evidence (migr. 0117). The observation is
    // the provider's canonical monthly report input, the measurement is the
    // immutable eligibility/decision record, and the credit ledger is the
    // money-path record (including amount, currency, Stripe object and
    // idempotency state). Together they substantiate the contractual service
    // credit and any invoice or SLA dispute, so they have the same lawful
    // fiscal/legal-retention basis as the other billing evidence above. They
    // are retained, not hard-deleted, on an Art. 17 request. `tenant_id` and
    // `stripe_customer_id` are opaque provider references; no raw account
    // identity fields are stored. There are no foreign keys in migration
    // 0117, so no erase ordering is needed.
    "sla_monthly_observations",
    "sla_monthly_measurements",
    "sla_credit_ledger",
    // Legal-hold control record (migr. 0076): the durable signal that gates
    // erasure itself. A row = "destructive erasure refused"; it is a
    // legal-process / audit anchor (`placed_at`), `reason` is operator-internal
    // and explicitly NOT DSR-disclosable per the migration → RETAIN.
    "tenant_legal_hold",
    // CAS legal-hold retention index (migr. 0102, B-009): one subject-free row per
    // CAS object frozen under a Governance-mode legal hold. A row = "this held CAS
    // object is retained pending hold release" — the litigation/retention anchor
    // whose whole purpose is to SURVIVE the erasure it defers; erasing it would
    // orphan the frozen bytes and lose the drain's worklist. Sibling of
    // `tenant_legal_hold`. Carries NO raw subject PII (tenant_id + region +
    // object_key + timestamps only; subject-free by construction) → RETAIN.
    "cas_retention",
    // abuse_score_history (migr. 0013): OWNER-DECIDED RETAIN — fraud/abuse
    // prevention is a legitimate interest under GDPR Art.17(3)(... ) / Art.6(1)(f);
    // retaining behavioural abuse scores survives an Art.17 erasure as an
    // anti-abuse safeguard. This is an owner/legal call (ADR-S11-013 FLAGGED
    // "abuse_scores"); revisit if the legal basis changes.
    "abuse_score_history",
    // session_exchange_throttle (migr. 0068): keyed by `clerk_sub` — an opaque
    // SHA-256-derived principal id (NOT raw Clerk id, NOT email — already
    // pseudonymous) — with NO `tenant_id` column, so the tenant-scoped D1
    // adapter cannot target it by `WHERE tenant_id = ?`. It is also an
    // ephemeral fixed-window throttle counter (self-expiring). RETAIN-by-
    // construction. ⚠ FLAGGED for owner: if per-principal erasure is later
    // required, it needs a principal-keyed delete path (out of this adapter's
    // tenant-scoped contract).
    "session_exchange_throttle",
    // Migration 0151 records the immutable exact-run staging ownership
    // witness here. UPDATE/DELETE are rejected by its append-only triggers;
    // retain the marker with that technical ownership evidence rather than
    // route it through the tenant erase loop.
    "staging_load_test_synthetic_tenants",
];

/// Tenant-keyed tables whose erasure is owned by ANOTHER canonical backend
/// (ADR-S11-013 backend mapping), so they are intentionally NOT in this D1
/// adapter's erase-set — but MUST still be consciously accounted for by the
/// completeness gate (they are not "unclassified").
///
/// - `blob_meta` → `R2Cas` (refcount-aware: decrement, delete object only at 0).
/// - `ac_meta`   → `R2Ac` (D1-driven per-region action-cache delete).
/// - `chunks` / `manifest_chunks` / `multipart_sessions` → the multipart/chunk
///   CAS path is the in-memory sim with **zero prod write sites** (ADR-S11-013
///   §"R2-erasure design"), so no durable rows exist; ownership sits with the
///   CAS plane if/when it ships.
const CAS_PLANE_OWNED: &[&str] = &[
    "blob_meta",
    "ac_meta",
    "chunks",
    "manifest_chunks",
    "multipart_sessions",
];

/// Erase-set tables handled by bespoke logic (not the simple
/// `WHERE <col> = ?1` loop): `signup_attempts` joins through
/// `signup_orchestration.idempotency_key`; `clerk_provisioning_lock` is keyed
/// by `tenant.clerk_user_id` and is deleted before the root; `tenant` is
/// deleted LAST.
pub(super) const SPECIAL_ERASE_TABLES: &[&str] = &[
    // These 0121 assertion/guard rows have no tenant_id. Their ownership is
    // resolved through activation_intent/activation_guard and is cleaned by
    // delete_byok_activation_indirect_children before those parents.
    "byok_activation_worker_assertion",
    "byok_activation_operation_guard",
    "byok_activation_postcondition",
    "byok_activation_suspension_postcondition",
    "byok_activation_transition_assertion",
    "signup_orchestration",
    "signup_attempts",
    "clerk_provisioning_lock",
    "tenant",
];

/// `byok_object_purge_cause` is durable provenance for a purge item, but it
/// deliberately has no `tenant_id` of its own. Its `purge_id` foreign key is
/// also not `ON DELETE CASCADE`, so it must be removed through the tenant-
/// keyed parent before `byok_object_purge_item` is deleted. Keep this alias
/// outside `TENANT_ID_TABLES`: putting it in that slice would generate an
/// invalid `WHERE tenant_id = ?1` query and leave the FK child in place.
const BYOK_PURGE_CAUSE_TABLE: &str = "byok_object_purge_cause";
const BYOK_PURGE_CAUSE_PARENT_KEY: &str = "purge_id";
const BYOK_PURGE_PARENT_TABLE: &str = "byok_object_purge_item";
const BYOK_ACTIVATION_WORKER_ASSERTION_TABLE: &str = "byok_activation_worker_assertion";
const BYOK_ACTIVATION_OPERATION_GUARD_TABLE: &str = "byok_activation_operation_guard";
const BYOK_ACTIVATION_POSTCONDITION_TABLE: &str = "byok_activation_postcondition";
const BYOK_ACTIVATION_SUSPENSION_POSTCONDITION_TABLE: &str =
    "byok_activation_suspension_postcondition";
const BYOK_ACTIVATION_TRANSITION_ASSERTION_TABLE: &str = "byok_activation_transition_assertion";
const BYOK_PURGE_CAUSE_ORPHAN_SQL: &str =
    "SELECT COUNT(*) AS n FROM byok_object_purge_cause c LEFT JOIN byok_object_purge_item p ON p.purge_id=c.purge_id WHERE p.purge_id IS NULL";
/// Global orphan preflight for all 0121 tables whose ownership is indirect.
/// FK enforcement was historically disabled on some D1 paths, so a tenant
/// join alone can hide a row whose parent has already disappeared. Count every
/// missing parent relation before erase and verification and fail closed.
const BYOK_ACTIVATION_ORPHAN_SQL: &str = r#"
SELECT COUNT(*) AS n FROM (
    SELECT w.assertion_token AS row_id
      FROM byok_activation_worker_assertion w
      LEFT JOIN byok_activation_operation_guard og
        ON og.operation_token = w.operation_token
      LEFT JOIN byok_activation_intent i ON i.intent_id = w.intent_id
     WHERE og.operation_token IS NULL
        OR i.intent_id IS NULL
        OR og.intent_id <> w.intent_id
    UNION ALL
    SELECT og.operation_token AS row_id
      FROM byok_activation_operation_guard og
      LEFT JOIN byok_activation_intent i ON i.intent_id = og.intent_id
     WHERE i.intent_id IS NULL
    UNION ALL
    SELECT p.operation_token AS row_id
      FROM byok_activation_postcondition p
      LEFT JOIN byok_activation_intent i ON i.intent_id = p.intent_id
     WHERE i.intent_id IS NULL
    UNION ALL
    SELECT p.operation_token AS row_id
      FROM byok_activation_suspension_postcondition p
      LEFT JOIN byok_activation_intent i ON i.intent_id = p.intent_id
     WHERE i.intent_id IS NULL
    UNION ALL
    SELECT a.assertion_token AS row_id
      FROM byok_activation_transition_assertion a
      LEFT JOIN byok_activation_guard g ON g.guard_id = a.guard_id
     WHERE g.guard_id IS NULL
) orphan
"#;

/// Validate the production registry before erasure, access, or verification.
pub(super) fn ensure_tenant_keyed_tables_classified() -> Result<(), String> {
    ensure_classification(ALL_TENANT_KEYED_TABLES)
}

/// Real D1 effective erase adapter.
pub(super) struct D1EraseAdapter {
    d1: Arc<D1HttpClient>,
}

impl std::fmt::Debug for D1EraseAdapter {
    // Never surface the inner client's Debug — it holds the CF API token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("D1EraseAdapter")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

impl D1EraseAdapter {
    /// Construct over a shared [`D1HttpClient`].
    pub(super) fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    /// `SELECT COUNT(*)` for `<table> WHERE <col> = ?1`. `table`/`col` are
    /// compile-time constants (injection-safe); `val` is the bound param.
    fn count(&self, table: &str, col: &str, val: &str) -> Result<u64, ErasureBackendError> {
        let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE {col} = ?1");
        let rows = d1_query_blocking(&self.d1, &sql, vec![json!(val)])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    /// Count then (only if non-zero) hard-delete `<table> WHERE <col> = ?1`.
    /// Returns the number of rows that were present (= deleted).
    fn count_then_delete(
        &self,
        table: &str,
        col: &str,
        val: &str,
    ) -> Result<u64, ErasureBackendError> {
        let n = self.count(table, col, val)?;
        if n > 0 {
            let sql = format!("DELETE FROM {table} WHERE {col} = ?1");
            d1_query_blocking(&self.d1, &sql, vec![json!(val)])
                .map_err(ErasureBackendError::Transport)?;
        }
        Ok(n)
    }

    /// Read the tenant's residency pin before any child or root deletion.
    ///
    /// Erasure evidence is region-scoped, so a missing/invalid pin cannot be
    /// treated as the default region. This query deliberately runs before the
    /// first DELETE: once the root row is gone, the residency fact needed to
    /// route/attest the operation is no longer recoverable. The value is not
    /// currently needed by the D1 SQL itself, but retaining it in this scope
    /// makes the ordering an explicit fail-closed invariant and prevents a
    /// future caller from accidentally deleting first.
    fn primary_region_before_delete(&self, tid: &str) -> Result<String, ErasureBackendError> {
        let rows = d1_query_blocking(
            &self.d1,
            "SELECT primary_region FROM tenant WHERE tenant_id = ?1 LIMIT 1",
            vec![json!(tid)],
        )
        .map_err(ErasureBackendError::Transport)?;
        let Some(region) = rows.first().and_then(|row| col_str(row, "primary_region")) else {
            return Err(ErasureBackendError::Transport(
                "tenant.primary_region missing; refusing DSR deletion".to_owned(),
            ));
        };
        if !matches!(
            region.as_str(),
            "wnam" | "enam" | "weur" | "sam" | "apac" | "afr"
        ) {
            return Err(ErasureBackendError::Transport(format!(
                "tenant.primary_region invalid ({region}); refusing DSR deletion"
            )));
        }
        Ok(region)
    }

    /// Decode the Clerk principal needed to clean up the special lock. A
    /// missing, non-string, or blank value is not safe to treat as "no lock":
    /// the erasure would otherwise delete the tenant root while leaving an
    /// unaddressable identity lease behind.
    fn clerk_user_id_from_rows(rows: &[D1Row]) -> Result<String, String> {
        let Some(clerk_user_id) = rows.first().and_then(|row| col_str(row, "clerk_user_id")) else {
            return Err("tenant.clerk_user_id missing; refusing DSR deletion".to_owned());
        };
        if clerk_user_id.trim().is_empty() {
            return Err("tenant.clerk_user_id blank; refusing DSR deletion".to_owned());
        }
        Ok(clerk_user_id)
    }

    /// Read the Clerk principal that owns the tenant before any row is
    /// deleted. `clerk_provisioning_lock` is keyed by this value rather than
    /// `tenant_id`, so a missing/blank value is a fail-closed error: deleting
    /// the tenant without it would make the lock impossible to target and
    /// could leave identity state behind.
    fn clerk_user_id_before_delete(&self, tid: &str) -> Result<String, ErasureBackendError> {
        let rows = d1_query_blocking(
            &self.d1,
            "SELECT clerk_user_id FROM tenant WHERE tenant_id = ?1 LIMIT 1",
            vec![json!(tid)],
        )
        .map_err(ErasureBackendError::Transport)?;
        Self::clerk_user_id_from_rows(&rows).map_err(ErasureBackendError::Transport)
    }

    /// `signup_attempts` has no `tenant_id`; its rows join to the tenant via
    /// `idempotency_key` → `signup_orchestration`. MUST run before the
    /// `signup_orchestration` delete (else the subquery finds nothing).
    fn count_signup_attempts(&self, tid: &str) -> Result<u64, ErasureBackendError> {
        let sql = "SELECT COUNT(*) AS n FROM signup_attempts WHERE idempotency_key IN \
             (SELECT idempotency_key FROM signup_orchestration WHERE tenant_id = ?1)";
        let rows = d1_query_blocking(&self.d1, sql, vec![json!(tid)])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    fn delete_signup_attempts(&self, tid: &str) -> Result<u64, ErasureBackendError> {
        let n = self.count_signup_attempts(tid)?;
        if n > 0 {
            let sql = "DELETE FROM signup_attempts WHERE idempotency_key IN \
                 (SELECT idempotency_key FROM signup_orchestration WHERE tenant_id = ?1)";
            d1_query_blocking(&self.d1, sql, vec![json!(tid)])
                .map_err(ErasureBackendError::Transport)?;
        }
        Ok(n)
    }

    /// Count durable purge-cause rows through their tenant-keyed parent.
    ///
    /// `byok_object_purge_cause` cannot be placed in [`TENANT_ID_TABLES`]: it
    /// has no `tenant_id` column. The join is the only safe tenant scope and
    /// also doubles as a schema/FK preflight before any parent delete.
    fn count_byok_purge_causes(&self, tid: &str) -> Result<u64, ErasureBackendError> {
        let sql = format!(
            "SELECT COUNT(*) AS n FROM {BYOK_PURGE_CAUSE_TABLE} c \
             JOIN {BYOK_PURGE_PARENT_TABLE} p ON p.purge_id=c.{BYOK_PURGE_CAUSE_PARENT_KEY} \
             WHERE p.tenant_id = ?1"
        );
        let rows = d1_query_blocking(&self.d1, &sql, vec![json!(tid)])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    /// D1 historically ran with FK enforcement off, so old/manual writes may
    /// have left a cause row with no purge-item parent. It has no tenant scope
    /// left to resolve; proceeding would silently attest an incomplete ledger.
    fn count_orphan_byok_purge_causes(&self) -> Result<u64, ErasureBackendError> {
        let rows = d1_query_blocking(&self.d1, BYOK_PURGE_CAUSE_ORPHAN_SQL, vec![])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    /// Count every orphan in the five 0121 indirect-ownership relations. This
    /// query is deliberately tenant-global: a missing parent has no safe
    /// tenant scope left, so silently ignoring it would over-attest erasure.
    fn count_orphan_byok_activation_rows(&self) -> Result<u64, ErasureBackendError> {
        let rows = d1_query_blocking(&self.d1, BYOK_ACTIVATION_ORPHAN_SQL, vec![])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    /// Delete purge-cause children and their `byok_object_purge_item` parent
    /// in one D1 transaction. The child FK has no cascade, and D1/SQLite may
    /// enforce FKs on the production REST path; deleting the parent first
    /// would therefore fail. Keeping both DELETEs in one batch also prevents
    /// a transport error between them from leaving a half-erased purge ledger.
    /// The post-delete counts are intentional: a successful transport response
    /// is not accepted as proof that the mutation removed every row, so the
    /// adapter fails closed if either side remains.
    fn delete_byok_purge_causes_and_items(&self, tid: &str) -> Result<u64, ErasureBackendError> {
        let causes = self.count_byok_purge_causes(tid)?;
        let items = self.count(BYOK_PURGE_PARENT_TABLE, "tenant_id", tid)?;
        if causes == 0 && items == 0 {
            return Ok(0);
        }

        let child_sql = format!(
            "DELETE FROM {BYOK_PURGE_CAUSE_TABLE} \
             WHERE {BYOK_PURGE_CAUSE_PARENT_KEY} IN \
                 (SELECT purge_id FROM {BYOK_PURGE_PARENT_TABLE} WHERE tenant_id = ?1)"
        );
        let parent_sql = format!("DELETE FROM {BYOK_PURGE_PARENT_TABLE} WHERE tenant_id = ?1");
        d1_batch_blocking(
            &self.d1,
            vec![
                D1BatchStatement::new(child_sql, vec![json!(tid)]),
                D1BatchStatement::new(parent_sql, vec![json!(tid)]),
            ],
        )
        .map_err(ErasureBackendError::Transport)?;

        let remaining = self.count_byok_purge_causes(tid)?;
        let remaining_items = self.count(BYOK_PURGE_PARENT_TABLE, "tenant_id", tid)?;
        if remaining != 0 || remaining_items != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "{BYOK_PURGE_CAUSE_TABLE}/{BYOK_PURGE_PARENT_TABLE} cleanup incomplete for tenant; refusing DSR completion ({remaining} causes, {remaining_items} items remain)"
            )));
        }
        Ok(causes.saturating_add(items))
    }

    /// Return the tenant-ownership predicate for one 0121 table that lacks a
    /// `tenant_id` column. Every identifier here is a compile-time constant;
    /// the only request-derived value remains the bound tenant parameter.
    fn byok_activation_indirect_scope(table: &str) -> Option<&'static str> {
        match table {
            BYOK_ACTIVATION_WORKER_ASSERTION_TABLE => Some(
                "intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1) OR operation_token IN (SELECT operation_token FROM byok_activation_operation_guard WHERE intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1))",
            ),
            BYOK_ACTIVATION_OPERATION_GUARD_TABLE
            | BYOK_ACTIVATION_POSTCONDITION_TABLE
            | BYOK_ACTIVATION_SUSPENSION_POSTCONDITION_TABLE => Some(
                "intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1)",
            ),
            BYOK_ACTIVATION_TRANSITION_ASSERTION_TABLE => Some(
                "guard_id IN (SELECT guard_id FROM byok_activation_guard WHERE tenant_id = ?1)",
            ),
            _ => None,
        }
    }

    fn count_byok_activation_indirect(
        &self,
        table: &str,
        tid: &str,
    ) -> Result<u64, ErasureBackendError> {
        let scope = Self::byok_activation_indirect_scope(table).ok_or_else(|| {
            ErasureBackendError::Transport(format!(
                "unknown indirect BYOK activation table {table}; refusing DSR cleanup"
            ))
        })?;
        let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE {scope}");
        let rows = d1_query_blocking(&self.d1, &sql, vec![json!(tid)])
            .map_err(ErasureBackendError::Transport)?;
        Ok(scalar_count(&rows, "n"))
    }

    /// Delete all 0121 assertion/guard rows whose ownership is indirect via
    /// this tenant's activation intent/guard. They are FK children of those
    /// parents, so the complete child set is sent in one transaction before
    /// the direct tenant registry reaches `byok_activation_intent` or
    /// `byok_activation_guard`. Post-delete counts fail closed if a row is
    /// still attributable to the tenant.
    fn delete_byok_activation_indirect_children(
        &self,
        tid: &str,
    ) -> Result<u64, ErasureBackendError> {
        let tables = [
            BYOK_ACTIVATION_WORKER_ASSERTION_TABLE,
            BYOK_ACTIVATION_TRANSITION_ASSERTION_TABLE,
            BYOK_ACTIVATION_OPERATION_GUARD_TABLE,
            BYOK_ACTIVATION_POSTCONDITION_TABLE,
            BYOK_ACTIVATION_SUSPENSION_POSTCONDITION_TABLE,
        ];
        let mut counts = [0u64; 5];
        for (count, table) in counts.iter_mut().zip(tables.iter().copied()) {
            *count = self.count_byok_activation_indirect(table, tid)?;
        }
        if counts.iter().all(|count| *count == 0) {
            return Ok(0);
        }

        let mut statements = Vec::with_capacity(tables.len());
        for table in tables {
            let scope = Self::byok_activation_indirect_scope(table).ok_or_else(|| {
                ErasureBackendError::Transport(format!(
                    "unknown indirect BYOK activation table {table}; refusing DSR cleanup"
                ))
            })?;
            statements.push(D1BatchStatement::new(
                format!("DELETE FROM {table} WHERE {scope}"),
                vec![json!(tid)],
            ));
        }
        d1_batch_blocking(&self.d1, statements).map_err(ErasureBackendError::Transport)?;

        let mut remaining = [0u64; 5];
        for (count, table) in remaining.iter_mut().zip(tables.iter().copied()) {
            *count = self.count_byok_activation_indirect(table, tid)?;
        }
        if remaining.iter().any(|count| *count != 0) {
            return Err(ErasureBackendError::Transport(format!(
                "indirect BYOK activation cleanup incomplete for tenant; refusing parent delete ({remaining:?} rows remain)"
            )));
        }
        Ok(counts.iter().copied().sum())
    }

    /// `clerk_provisioning_lock` is keyed by `tenant.clerk_user_id`, not by
    /// `tenant_id`; the caller must obtain the principal before deleting the
    /// tenant root. The lock is transient provisioning state and is erased
    /// before the root deletion.
    fn count_clerk_provisioning_lock(
        &self,
        clerk_user_id: &str,
    ) -> Result<u64, ErasureBackendError> {
        self.count("clerk_provisioning_lock", "clerk_user_id", clerk_user_id)
    }

    fn delete_clerk_provisioning_lock(
        &self,
        clerk_user_id: &str,
    ) -> Result<u64, ErasureBackendError> {
        self.count_then_delete("clerk_provisioning_lock", "clerk_user_id", clerk_user_id)
    }

    /// Count all remaining erase-set rows for a tenant (verification sweep).
    fn remaining_rows(&self, tid: &str) -> Result<u64, ErasureBackendError> {
        let orphan_activation_rows = self.count_orphan_byok_activation_rows()?;
        if orphan_activation_rows != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "0121 indirect BYOK activation tables have {orphan_activation_rows} orphan rows; refusing remaining-row verification"
            )));
        }
        let mut remaining = 0u64;
        for table in [
            BYOK_ACTIVATION_WORKER_ASSERTION_TABLE,
            BYOK_ACTIVATION_OPERATION_GUARD_TABLE,
            BYOK_ACTIVATION_POSTCONDITION_TABLE,
            BYOK_ACTIVATION_SUSPENSION_POSTCONDITION_TABLE,
            BYOK_ACTIVATION_TRANSITION_ASSERTION_TABLE,
        ] {
            remaining = remaining.saturating_add(self.count_byok_activation_indirect(table, tid)?);
        }
        for t in TENANT_ID_TABLES {
            remaining = remaining.saturating_add(self.count(t, "tenant_id", tid)?);
        }
        for t in NAMESPACE_TABLES {
            remaining = remaining.saturating_add(self.count(t, "namespace", tid)?);
        }
        remaining = remaining.saturating_add(self.count_signup_attempts(tid)?);
        remaining =
            remaining.saturating_add(self.count("signup_orchestration", "tenant_id", tid)?);
        // The lock is keyed by tenant.clerk_user_id. If the root is still
        // present (for example after a partial failure), count it through the
        // same tenant binding; after a successful root deletion there can be
        // no lock that this tenant-scoped adapter can legitimately identify.
        let clerk_rows = d1_query_blocking(
            &self.d1,
            "SELECT clerk_user_id FROM tenant WHERE tenant_id = ?1 LIMIT 1",
            vec![json!(tid)],
        )
        .map_err(ErasureBackendError::Transport)?;
        if let Some(clerk_user_id) = clerk_rows
            .first()
            .and_then(|row| col_str(row, "clerk_user_id"))
            .filter(|id| !id.trim().is_empty())
        {
            remaining =
                remaining.saturating_add(self.count_clerk_provisioning_lock(&clerk_user_id)?);
        }
        remaining = remaining.saturating_add(self.count("tenant", "tenant_id", tid)?);
        Ok(remaining)
    }
}

impl BackendErasureAdapter for D1EraseAdapter {
    fn kind(&self) -> BackendKind {
        BackendKind::D1
    }

    fn erase(
        &self,
        tenant_id: Uuid,
        _subject_id: Uuid,
        _erasure_salt: &[u8; 32],
        legal_hold: bool,
    ) -> Result<BackendErasureOutcome, ErasureBackendError> {
        // Effective backend under legal hold: preserve (CTRL-PRIV-033).
        if legal_hold {
            return Ok(BackendErasureOutcome::NotApplicable);
        }
        // CF-1 runtime drift gate: never run an erasure (and then attest
        // VerifiedComplete) while a known tenant-keyed table is unclassified.
        // This is an always-on Result path, not a debug assertion: release
        // builds must fail closed before the first mutation as well.
        ensure_tenant_keyed_tables_classified().map_err(ErasureBackendError::Transport)?;
        // The cause ledger is scoped through this tenant-keyed parent. If a
        // future registry edit drops the parent, the bespoke child cleanup
        // below would otherwise be unreachable and the erasure could falsely
        // proceed while leaving durable provenance behind.
        if !TENANT_ID_TABLES.contains(&BYOK_PURGE_PARENT_TABLE) {
            return Err(ErasureBackendError::Transport(format!(
                "{BYOK_PURGE_PARENT_TABLE} missing from DSR erase registry; refusing bespoke {BYOK_PURGE_CAUSE_TABLE} cleanup"
            )));
        }
        let orphan_causes = self.count_orphan_byok_purge_causes()?;
        if orphan_causes != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "{BYOK_PURGE_CAUSE_TABLE} has {orphan_causes} orphan rows; refusing DSR deletion"
            )));
        }
        let orphan_activation_rows = self.count_orphan_byok_activation_rows()?;
        if orphan_activation_rows != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "0121 indirect BYOK activation tables have {orphan_activation_rows} orphan rows; refusing DSR deletion"
            )));
        }
        let tid = tenant_id.to_string();
        // MUST precede every mutation, including child cleanup. A missing or
        // malformed residency pin fails closed and leaves the tenant intact.
        let _primary_region = self.primary_region_before_delete(&tid)?;
        // This lookup is deliberately before the first DELETE. The special
        // lock cleanup below is keyed by this value and therefore cannot be
        // safely deferred until after the tenant root is gone.
        let clerk_user_id = self.clerk_user_id_before_delete(&tid)?;
        let mut total = 0u64;

        // 0121 assertion/guard tables have no tenant_id. Resolve their
        // ownership through the activation intent/guard and remove them in a
        // single FK-safe transaction before the direct registry lane reaches
        // those parents.
        total = total.saturating_add(self.delete_byok_activation_indirect_children(&tid)?);

        // Group A — tenant_id-keyed child tables.
        for t in TENANT_ID_TABLES {
            // `byok_object_purge_cause` has no tenant_id. Remove this FK child
            // immediately before its tenant-keyed parent reaches the loop;
            // the batch also deletes that parent, so do not issue a second
            // non-transactional parent DELETE below.
            if *t == BYOK_PURGE_PARENT_TABLE {
                total = total.saturating_add(self.delete_byok_purge_causes_and_items(&tid)?);
                continue;
            }
            total = total.saturating_add(self.count_then_delete(t, "tenant_id", &tid)?);
        }
        // Group B — namespace-keyed (tenant UUID; never '_public').
        for t in NAMESPACE_TABLES {
            total = total.saturating_add(self.count_then_delete(t, "namespace", &tid)?);
        }
        // Group C — signup_attempts BEFORE signup_orchestration.
        total = total.saturating_add(self.delete_signup_attempts(&tid)?);
        total = total.saturating_add(self.count_then_delete(
            "signup_orchestration",
            "tenant_id",
            &tid,
        )?);
        // Group D — the Clerk provisioning lease is keyed by the tenant's
        // Clerk principal. It MUST be removed before the tenant root.
        total = total.saturating_add(self.delete_clerk_provisioning_lock(&clerk_user_id)?);
        // Group E — the root identity row LAST (covers the ALTER columns
        // primary_region / byok_status / clerk_user_id / email_hash /
        // stripe_customer_id on `tenant`).
        total = total.saturating_add(self.count_then_delete("tenant", "tenant_id", &tid)?);

        Ok(BackendErasureOutcome::Erased {
            records_deleted: total,
        })
    }

    fn verification_hash(&self, ctx: VerificationContext) -> Result<[u8; 32], ErasureBackendError> {
        // Keep verification fail-closed too. A partial registry must never
        // produce the canonical empty hash and over-attest a tenant.
        ensure_tenant_keyed_tables_classified().map_err(ErasureBackendError::Transport)?;
        let orphan_causes = self.count_orphan_byok_purge_causes()?;
        if orphan_causes != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "{BYOK_PURGE_CAUSE_TABLE} has {orphan_causes} orphan rows; refusing verification"
            )));
        }
        let orphan_activation_rows = self.count_orphan_byok_activation_rows()?;
        if orphan_activation_rows != 0 {
            return Err(ErasureBackendError::Transport(format!(
                "0121 indirect BYOK activation tables have {orphan_activation_rows} orphan rows; refusing verification"
            )));
        }
        let remaining = self.remaining_rows(&ctx.tenant_id.to_string())?;
        if remaining == 0 {
            // Canonical "no rows for tenant" sentinel (effective backend).
            Ok(CANONICAL_EMPTY_TENANT_HASH)
        } else {
            // Non-empty → a deterministic non-canonical fingerprint (Sha256,
            // a container dep; differs from the blake3-empty canonical hash),
            // so the verify sweep maps the mismatch to VerifiedPartial + SEV-1.
            let mut h = Sha256::new();
            h.update(b"corelink/v1/d1-erasure-remaining:");
            h.update(remaining.to_le_bytes());
            let digest = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
    }
}

#[cfg(test)]
#[path = "adapter_d1_tests.rs"]
mod tests;
