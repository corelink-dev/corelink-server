//! DSR ACCESS (GDPR Art.15) + PORTABILITY (Art.20) + RECTIFICATION (Art.16) —
//! the three data-subject rights that complete the `/_internal/dsr/*` surface
//! alongside ERASURE (Art.17) + verify.
//!
//! ## Design (frozen tech-lead policy)
//!
//! - **Gather is single-sourced with the erase-set.** [`build_gather_plan`]
//!   enumerates the subject's rows across the EXACT same tenant-keyed tables the
//!   D1 erase adapter deletes ([`super::adapter_d1::TENANT_ID_TABLES`] +
//!   [`super::adapter_d1::NAMESPACE_TABLES`] + the bespoke
//!   [`super::adapter_d1::SPECIAL_ERASE_TABLES`]). A future tenant-keyed table
//!   added to the erase-set is therefore covered by BOTH erase AND access — no
//!   parallel list to drift (asserted by `access_set_equals_erase_set`).
//! - **Retained data is disclosed, not erased.** RETAIN-set tables (fiscal /
//!   audit, e.g. `stripe_*`) carry a lawful retention basis so they survive an
//!   Art.17 erasure — but the subject has an Art.15 right to SEE them. They are
//!   gathered with `retained = true` (the `tenant_id`-keyed disclosable subset
//!   [`RETAIN_DISCLOSABLE_TABLES`] of [`super::adapter_d1::RETAIN_SET`]).
//! - **Secrets are never exported raw.** [`redact_row`] replaces credential /
//!   key material (PAT digests, reveal tokens, BYOK envelopes, …) with a
//!   `"<redacted>"` marker — presence/metadata is disclosed, the secret material
//!   is not.
//! - **Fail-CLOSED.** Any gather / D1 error aborts the whole export with `Err`
//!   (never a partial-looking "complete" bundle), and every access / portability
//!   / rectification request emits its audit envelope BEFORE the disclosure /
//!   mutation (ADR-S11-002 discipline; idempotent on a deterministic id so a
//!   retry never double-acts).
//! - **Rectification is bounded + honest.** Cache CONTENT is content-addressed +
//!   immutable → NOT rectifiable. Only the editable subject PII allowlist
//!   ([`RECTIFIABLE_FIELDS`]) is correctable; any other target fails CLOSED 4xx.

use std::future::Future;
use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::d1util::{clamp_ms, d1_batch_blocking, d1_query_blocking};
use crate::customer_d1::ms_to_iso8601;
use crate::storage::d1_http::{D1BatchStatement, D1HttpClient, D1Row};
use crate::storage::r2_s3::R2S3Client;
use crate::storage::staging_load_test_ownership::{
    StagingLoadTestDisposition, StagingLoadTestR2Intent, StagingLoadTestResourceClass,
    StagingLoadTestWriteContext,
};

/// CloudEvents `type` for the Art.15 access event (audit_outbox).
pub(super) const EVENT_ACCESS: &str = "corelink.dsr.access";
/// CloudEvents `type` for the Art.20 portability event.
pub(super) const EVENT_PORTABILITY: &str = "corelink.dsr.portability";
/// CloudEvents `type` for the Art.16 rectification event.
pub(super) const EVENT_RECTIFICATION: &str = "corelink.dsr.rectification";

/// Schema tag on the machine-readable export bundle (portability contract).
const EXPORT_SCHEMA: &str = "corelink.dsr.subject_export.v1";

/// The `tenant_id`-keyed disclosable subset of
/// [`super::adapter_d1::RETAIN_SET`]. These tables survive an Art.17 erasure
/// (lawful retention basis) but are disclosed under Art.15. Every entry is a
/// real `tenant_id`-keyed table (verified against `migrations/d1/*.sql`) — the
/// two RETAIN entries WITHOUT a `tenant_id` column (`export_audit_log` is
/// `authenticated_tenant`-keyed; `session_exchange_throttle` is `clerk_sub`-
/// keyed) and the legacy singular `erasure_attestation` alias are intentionally
/// excluded so a `SELECT … WHERE tenant_id = ?` never errors. Asserted a subset
/// of RETAIN_SET + disjoint from the erase-set by tests.
const RETAIN_DISCLOSABLE_TABLES: &[&str] = &[
    "dsr_erasure_log",
    "dsr_requested",
    "dpa_acceptances",
    "erasure_attestations",
    "stripe_customers",
    "stripe_subscriptions",
    "stripe_invoices",
    "stripe_disputes",
    "stripe_refunds",
    "audit_outbox",
    "billing_replay_audit",
    "stripe_idempotency_keys",
    "billing_reconciliation_drift",
    "stripe_submission_state",
    "customer_audit_events",
    "audit_chain_head",
    "tenant_legal_hold",
    "abuse_score_history",
    // B-089 contractual SLA evidence. These rows survive Art.17 under the
    // retained billing/legal basis and remain part of the subject's Art.15/20
    // export (the fields are provider references and measurement evidence,
    // not credentials, so redact_row must not mask them).
    "sla_monthly_observations",
    "sla_monthly_measurements",
    "sla_credit_ledger",
    // Runner aggregation's immutable terms/claim rows are retained billing
    // evidence under ADR-S11-013 and are disclosed with the retained set.
    "runner_period_terms_snapshot",
    "runner_aggregate_event_claim",
];

/// Lower-snake column-name tokens that mark a column as secret/credential
/// material. Any column whose lowercased name CONTAINS one of these is redacted
/// (presence kept, value replaced) before export — never the secret itself.
/// Deliberately precise: `token` catches `shown_once_token` but not `key_id`
/// (we do NOT redact `key_id` / `idempotency_key` — they are not secrets).
const SENSITIVE_COL_TOKENS: &[&str] = &[
    "secret",
    "pat_hash",
    "token",
    "envelope",
    "cipher",
    "wrapped",
    "private_key",
    "signing_key",
    "kms_key",
    "key_material",
];

/// The ONLY editable subject-PII fields a rectification (Art.16) may correct,
/// as `(table, field)` pairs. Bounded + honest: CoreLink stores PII
/// pseudonymized, so the one meaningful editable contact field is the account
/// email — stored as `tenant.email_hash` (SHA-256 of the normalized email per
/// CTRL-PRIV-001). The rectification takes the new RAW email and stores its
/// hash (we never persist the raw email), reusing the canonical scheme.
const RECTIFIABLE_FIELDS: &[(&str, &str)] = &[("tenant", "email_hash")];

/// Content-addressed / cache tables whose data is IMMUTABLE by construction —
/// a rectification target here gets the "content is immutable" message.
const CONTENT_IMMUTABLE_TABLES: &[&str] = &[
    "blob_meta",
    "ac_meta",
    "chunks",
    "manifest_chunks",
    "multipart_sessions",
    "cas_tombstone",
    "hot_blobs",
];

/// Canonical pseudonymized email hash (CTRL-PRIV-001) — delegates to the ONE
/// shared [`crate::email_hash::hash_email`] so this rectification site stays
/// byte-identical to the `customer_d1` team-invite write (and the signup-worker
/// `emailHashFor` accept-match): normalized email, HMAC-SHA256 under
/// `EMAIL_HASH_SALT` when set, else unsalted SHA-256. The raw email is NEVER
/// stored.
#[must_use]
pub(crate) fn email_hash(email: &str) -> String {
    crate::email_hash::hash_email(email)
}

/// Whether `col` names secret/credential material that must be redacted.
#[must_use]
fn is_sensitive_col(col: &str) -> bool {
    let lower = col.to_ascii_lowercase();
    SENSITIVE_COL_TOKENS.iter().any(|t| lower.contains(t))
}

/// Redact a gathered row in place: any sensitive-named column with a non-null
/// value is replaced by `"<redacted>"` (presence disclosed, secret withheld);
/// a SQL NULL stays null (so the export truthfully shows "no value present").
#[must_use]
fn redact_row(mut row: D1Row) -> D1Row {
    for (col, val) in row.iter_mut() {
        if is_sensitive_col(col) && !val.is_null() {
            *val = Value::String("<redacted>".to_owned());
        }
    }
    row
}

/// One per-table slice of the subject export.
#[derive(Debug, Clone, Serialize)]
pub(super) struct SubjectTable {
    /// D1 table name.
    pub table: String,
    /// `true` for RETAIN-set tables (disclosed under Art.15 but NOT erased —
    /// a lawful retention basis survives an Art.17 erasure).
    pub retained: bool,
    /// Number of rows gathered for the subject.
    pub row_count: usize,
    /// The redacted rows (secret columns replaced; per-table JSON objects).
    pub rows: Vec<D1Row>,
}

/// The structured, machine-readable subject data export (Art.15 access body /
/// Art.20 portability payload). Serializes as `{ schema, tenant_id,
/// generated_at_ms, tables: [{ table, retained, row_count, rows }] }`.
#[derive(Debug, Clone, Serialize)]
pub(super) struct SubjectExport {
    /// Stable schema tag.
    pub schema: &'static str,
    /// The subject's tenant id (one-user-per-tenant).
    pub tenant_id: String,
    /// Generation instant (Unix epoch ms).
    pub generated_at_ms: u64,
    /// Per-table data slices (erase-set tables first, then retained tables).
    pub tables: Vec<SubjectTable>,
}

/// One planned gather query: the table label, whether it is RETAIN-set, and the
/// exact SQL + bound params. Pure (no I/O) so the plan is unit-testable and the
/// erase-set/access-set coverage invariant is asserted offline.
#[derive(Debug, Clone)]
pub(super) struct GatherQuery {
    pub table: &'static str,
    pub retained: bool,
    pub sql: String,
    pub params: Vec<Value>,
}

/// Build the full gather plan for `tenant_id`, single-sourced with the D1
/// erase-set (so a future erase-set table is covered by access too):
///
/// 1. erase-set `tenant_id`-keyed tables ([`super::adapter_d1::TENANT_ID_TABLES`]);
/// 2. erase-set `namespace`-keyed tables (bound value = tenant UUID, never
///    `'_public'`, so shared public-registry content is never gathered);
/// 3. the bespoke specials (`signup_orchestration`/`tenant` by `tenant_id`;
///    `signup_attempts` via the `idempotency_key` join the erase path uses;
///    `clerk_provisioning_lock` via `tenant.clerk_user_id`);
/// 4. the `tenant_id`-keyed RETAIN-set disclosable subset (marked retained).
#[must_use]
pub(super) fn build_gather_plan(tenant_id: &str) -> Vec<GatherQuery> {
    let mut plan: Vec<GatherQuery> = Vec::new();
    let tid = || vec![json!(tenant_id)];

    for t in super::adapter_d1::TENANT_ID_TABLES {
        plan.push(GatherQuery {
            table: t,
            retained: false,
            sql: format!("SELECT * FROM {t} WHERE tenant_id = ?1"),
            params: tid(),
        });
    }
    for t in super::adapter_d1::NAMESPACE_TABLES {
        plan.push(GatherQuery {
            table: t,
            retained: false,
            sql: format!("SELECT * FROM {t} WHERE namespace = ?1"),
            params: tid(),
        });
    }
    // Indirect 0121 specials (kept exactly aligned with SPECIAL_ERASE_TABLES):
    // these tables have no tenant_id, so ACCESS must use the same intent/guard
    // ownership relations as erase rather than generating an invalid direct
    // tenant predicate. The worker assertion has both FK paths represented so
    // a valid-but-mismatched legacy row cannot disappear from the export.
    let byok_activation_indirect = [
        (
            "byok_activation_worker_assertion",
            "SELECT * FROM byok_activation_worker_assertion w \
             JOIN byok_activation_operation_guard og \
               ON og.operation_token = w.operation_token \
              AND og.intent_id = w.intent_id \
             JOIN byok_activation_intent i ON i.intent_id = w.intent_id \
            WHERE i.tenant_id = ?1",
        ),
        (
            "byok_activation_operation_guard",
            "SELECT * FROM byok_activation_operation_guard WHERE \
             intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1)",
        ),
        (
            "byok_activation_postcondition",
            "SELECT * FROM byok_activation_postcondition WHERE \
             intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1)",
        ),
        (
            "byok_activation_suspension_postcondition",
            "SELECT * FROM byok_activation_suspension_postcondition WHERE \
             intent_id IN (SELECT intent_id FROM byok_activation_intent WHERE tenant_id = ?1)",
        ),
        (
            "byok_activation_transition_assertion",
            "SELECT * FROM byok_activation_transition_assertion WHERE \
             guard_id IN (SELECT guard_id FROM byok_activation_guard WHERE tenant_id = ?1)",
        ),
    ];
    for (table, sql) in byok_activation_indirect {
        plan.push(GatherQuery {
            table,
            retained: false,
            sql: sql.to_owned(),
            params: tid(),
        });
    }

    // Remaining specials: identity rows by tenant_id, signup_attempts via the
    // join, and the Clerk lock via tenant.clerk_user_id.
    plan.push(GatherQuery {
        table: "signup_orchestration",
        retained: false,
        sql: "SELECT * FROM signup_orchestration WHERE tenant_id = ?1".to_owned(),
        params: tid(),
    });
    plan.push(GatherQuery {
        table: "signup_attempts",
        retained: false,
        sql: "SELECT * FROM signup_attempts WHERE idempotency_key IN \
              (SELECT idempotency_key FROM signup_orchestration WHERE tenant_id = ?1)"
            .to_owned(),
        params: tid(),
    });
    plan.push(GatherQuery {
        table: "clerk_provisioning_lock",
        retained: false,
        sql: "SELECT * FROM clerk_provisioning_lock WHERE clerk_user_id = \
              (SELECT clerk_user_id FROM tenant WHERE tenant_id = ?1)"
            .to_owned(),
        params: tid(),
    });
    plan.push(GatherQuery {
        table: "tenant",
        retained: false,
        sql: "SELECT * FROM tenant WHERE tenant_id = ?1".to_owned(),
        params: tid(),
    });
    // RETAIN-set disclosable subset (Art.15 right to SEE retained data).
    for t in RETAIN_DISCLOSABLE_TABLES {
        plan.push(GatherQuery {
            table: t,
            retained: true,
            sql: format!("SELECT * FROM {t} WHERE tenant_id = ?1"),
            params: tid(),
        });
    }
    plan
}

/// Gather the subject's data into a structured [`SubjectExport`], running each
/// planned query through `query` and redacting secret columns. FAIL-CLOSED: the
/// FIRST query error aborts with `Err` (never a partial export); a table with
/// zero rows is included with an empty `rows` (truthful "no data here").
///
/// `query` is injected so the assembly + fail-closed + redaction behaviour is
/// unit-testable offline; the live caller passes a D1-backed closure.
pub(super) fn gather_subject_data<Q>(
    tenant_id: &str,
    generated_at_ms: u64,
    mut query: Q,
) -> Result<SubjectExport, String>
where
    Q: FnMut(&str, &[Value]) -> Result<Vec<D1Row>, String>,
{
    // The access/portability plan is derived from the same D1 registry as
    // erasure. Refuse to disclose a partial view if that registry is ever
    // ambiguous or incomplete, including in release builds.
    super::adapter_d1::ensure_tenant_keyed_tables_classified()?;
    let plan = build_gather_plan(tenant_id);
    let mut tables: Vec<SubjectTable> = Vec::with_capacity(plan.len());
    for q in plan {
        // Fail-CLOSED: propagate the first error — no partial "complete" export.
        let rows = query(&q.sql, &q.params)
            .map_err(|e| format!("gather {table}: {e}", table = q.table))?;
        let redacted: Vec<D1Row> = rows.into_iter().map(redact_row).collect();
        tables.push(SubjectTable {
            table: q.table.to_owned(),
            retained: q.retained,
            row_count: redacted.len(),
            rows: redacted,
        });
    }
    Ok(SubjectExport {
        schema: EXPORT_SCHEMA,
        tenant_id: tenant_id.to_owned(),
        generated_at_ms,
        tables,
    })
}

/// Deterministic audit-row id for a DSR right-event, so a retry is an
/// `INSERT OR IGNORE` no-op (idempotent — never double-acts). Mirrors the
/// erase audit sink's keying.
#[must_use]
pub(super) fn audit_event_id(dsr_id: &str, event_type: &str, suffix: &str) -> String {
    format!("{dsr_id}:{event_type}:{suffix}")
}

/// Append a DSR right-event to `audit_outbox` (unchained row, same posture as
/// the erase audit sink). Deterministic id ⇒ idempotent on retry. FAIL-CLOSED:
/// the caller emits this BEFORE the disclosure / mutation and propagates an
/// `Err` (no audit ⇒ no act).
fn audit_dsr_event(
    d1: &Arc<D1HttpClient>,
    dsr_id: &str,
    tenant_id: &str,
    event_type: &str,
    suffix: &str,
    context: &Value,
    now_ms: u64,
    ownership_context: StagingLoadTestWriteContext<'_>,
) -> Result<(), String> {
    let id = audit_event_id(dsr_id, event_type, suffix);
    let ownership = ownership_context
        .map(|context| {
            context
                .ownership_registration(
                    StagingLoadTestResourceClass::AuditEvidence,
                    StagingLoadTestDisposition::Retained,
                    &id,
                )
                .and_then(|registration| registration.d1_statement(clamp_ms(now_ms)))
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    let request_id = format!("{dsr_id}:dsr");
    let payload = json!({
        "specversion": "1.0",
        "type": event_type,
        "source": "corelink/dsr",
        "id": id,
        "subject": dsr_id,
        "time": ms_to_iso8601(clamp_ms(now_ms)),
        "data": {
            "dsr_id": dsr_id,
            "tenant_id": tenant_id,
            "context": context,
        }
    });
    let payload_json =
        serde_json::to_string(&payload).map_err(|e| format!("audit payload serialize: {e}"))?;
    // `region` MUST equal tenant.primary_region (migration 0023 residency trigger
    // RAISE(ABORT)s otherwise; tenants default to 'enam', 0028). Do NOT rely on the
    // 'wnam' column default — it fails the DSR access/export audit CLOSED → 503.
    // Tag from the tenant's correlated residency lookup. A missing tenant is
    // rejected by migration 0107 rather than silently assigned to `wnam`.
    let sql = "INSERT OR IGNORE INTO audit_outbox \
         (id, tenant_id, digest, request_id, event_type, payload_json, enqueued_at, emitted_at, region) \
         VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, NULL, \
                 (SELECT primary_region FROM tenant WHERE tenant_id = ?2))";
    let params = vec![
        json!(id),
        json!(tenant_id),
        json!(request_id),
        json!(event_type),
        json!(payload_json),
        json!(clamp_ms(now_ms)),
    ];
    if let Some(registration) = ownership {
        d1_batch_blocking(d1, vec![D1BatchStatement::new(sql, params), registration]).map(|_| ())
    } else {
        d1_query_blocking(d1, sql, params).map(|_| ())
    }
}

/// Live D1-backed gather closure for a real handler.
fn gather_live(
    d1: &Arc<D1HttpClient>,
    tenant_id: &str,
    now_ms: u64,
) -> Result<SubjectExport, String> {
    gather_subject_data(tenant_id, now_ms, |sql, params| {
        d1_query_blocking(d1, sql, params.to_vec())
    })
}

/// Run the ACCESS (Art.15) right: audit FIRST (no disclosure without a logged
/// access), then gather. FAIL-CLOSED on either step.
pub(super) fn run_access(
    d1: &Arc<D1HttpClient>,
    dsr_id: &str,
    tenant_id: &str,
    now_ms: u64,
    ownership_context: StagingLoadTestWriteContext<'_>,
) -> Result<SubjectExport, String> {
    audit_dsr_event(
        d1,
        dsr_id,
        tenant_id,
        EVENT_ACCESS,
        "-",
        &json!({ "surface": "access" }),
        now_ms,
        ownership_context,
    )?;
    gather_live(d1, tenant_id, now_ms)
}

/// A portability receipt: the durable signed export handle (when the per-region
/// signing infra is configured). The machine-readable bundle is always returned
/// inline alongside this (the Art.20 core); a `persisted`/`signed` copy is an
/// additional, non-blocking durable artifact.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ExportReceipt {
    /// SHA-256 hex of the canonical export bundle bytes (integrity handle).
    pub content_sha256: String,
    /// Whether the bundle was persisted to the R2 audit bucket.
    pub persisted: bool,
    /// Bucket-qualified R2 key of the persisted bundle (when `persisted`).
    pub r2_key: Option<String>,
    /// Whether a detached Ed25519 signature over the content digest was written.
    pub signed: bool,
}

/// Run the PORTABILITY (Art.20) right: audit FIRST, gather the SAME structured
/// bundle as access (fail-closed), then best-effort persist a durable signed
/// copy to the R2 audit bucket. Returns the machine-readable bundle (always)
/// plus a receipt describing the durable copy.
pub(super) fn run_portability(
    d1: &Arc<D1HttpClient>,
    r2_audit: Option<&Arc<R2S3Client>>,
    dsr_id: &str,
    tenant_id: &str,
    now_ms: u64,
    ownership_context: StagingLoadTestWriteContext<'_>,
) -> Result<(SubjectExport, ExportReceipt), String> {
    audit_dsr_event(
        d1,
        dsr_id,
        tenant_id,
        EVENT_PORTABILITY,
        "-",
        &json!({ "surface": "portability" }),
        now_ms,
        ownership_context,
    )?;
    let export = gather_live(d1, tenant_id, now_ms)?;
    let receipt = persist_export(
        d1,
        r2_audit,
        dsr_id,
        tenant_id,
        &export,
        now_ms,
        ownership_context,
    );
    Ok((export, receipt))
}

pub(super) fn persist_owned_r2(
    r2: &Arc<R2S3Client>,
    d1: &Arc<D1HttpClient>,
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    resource_class: StagingLoadTestResourceClass,
    disposition: StagingLoadTestDisposition,
    object_key: &str,
    bytes: Vec<u8>,
    now_ms: u64,
) -> Result<(), String> {
    persist_owned_r2_with(
        d1,
        context,
        resource_class,
        disposition,
        object_key,
        bytes,
        now_ms,
        |key, bytes| {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| handle.block_on(r2.put(key, bytes)))
        },
    )
}

fn persist_owned_r2_with(
    d1: &Arc<D1HttpClient>,
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    resource_class: StagingLoadTestResourceClass,
    disposition: StagingLoadTestDisposition,
    object_key: &str,
    bytes: Vec<u8>,
    now_ms: u64,
    put_object: impl FnOnce(&str, Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    let class_name = match resource_class {
        StagingLoadTestResourceClass::DsrArtifact => "dsr_artifact",
        StagingLoadTestResourceClass::AuditEvidence => "audit_evidence",
        _ => return Err("unsupported DSR R2 ownership class".to_owned()),
    };
    let disposition_name = match disposition {
        StagingLoadTestDisposition::Disposable => "disposable",
        StagingLoadTestDisposition::Retained => "retained",
    };
    let registration = context
        .ownership_registration(resource_class, disposition, object_key)
        .map_err(|error| error.to_string())?;
    if resource_class == StagingLoadTestResourceClass::DsrArtifact
        && disposition == StagingLoadTestDisposition::Disposable
        && !is_staging_dsr_export_key(object_key)
    {
        return Err("staging DSR export key is invalid".to_owned());
    }
    let mut operation = Sha256::new();
    operation.update(b"corelink/dsr/r2-operation/v1\0");
    operation.update(context.run_id().as_bytes());
    operation.update([0]);
    operation.update(context.scenario().as_str().as_bytes());
    operation.update([0]);
    operation.update(context.target_deployment_sha().as_bytes());
    operation.update([0]);
    operation.update(class_name.as_bytes());
    operation.update([0]);
    operation.update(object_key.as_bytes());
    let operation_id = hex::encode(operation.finalize());
    let intent = registration
        .r2_intent(&operation_id)
        .map_err(|error| error.to_string())?;

    let prepared_at_ms = clamp_ms(now_ms);
    if d1_batch_blocking(d1, vec![intent.prepare_statement(prepared_at_ms)]).is_err() {
        // Recover only an exact durable intent. Any mismatch or lookup error
        // leaves the object write unopened and the caller reports failure.
        let rows = d1_query_blocking(
            d1,
            "SELECT operation_id, run_id, scenario, target_deployment_sha, resource_class, receipt_ref, opaque_handle, disposition, state FROM staging_load_test_r2_intents WHERE operation_id = ?1",
            vec![json!(operation_id)],
        )?;
        let Some(row) = rows.first() else {
            return Err("staging R2 ownership intent could not be prepared".to_owned());
        };
        let expected_receipt =
            staging_receipt_ref(context, class_name, object_key, disposition_name);
        let exact = [
            ("run_id", context.run_id()),
            ("scenario", context.scenario().as_str()),
            ("target_deployment_sha", context.target_deployment_sha()),
            ("resource_class", class_name),
            ("receipt_ref", expected_receipt.as_str()),
            ("opaque_handle", object_key),
            ("disposition", disposition_name),
        ]
        .iter()
        .all(|(key, value)| row.get(*key).and_then(Value::as_str) == Some(*value));
        let state = row.get("state").and_then(Value::as_str);
        if !exact || !matches!(state, Some("prepared" | "committed")) {
            return Err("staging R2 ownership intent conflicts with this write".to_owned());
        }
        if state == Some("committed") {
            verify_committed_staging_r2_resource(
                d1,
                context,
                class_name,
                disposition_name,
                &expected_receipt,
                object_key,
            )?;
            return Ok(());
        }
    }

    put_object(object_key, bytes)?;
    let committed_at_ms = clamp_ms(now_ms);
    let [register_resource, close_intent] = intent.commit_statements(clamp_ms(now_ms));
    let mut batch = vec![register_resource];
    if resource_class == StagingLoadTestResourceClass::DsrArtifact
        && disposition == StagingLoadTestDisposition::Disposable
    {
        batch.push(staging_dsr_export_locator_statement(
            context,
            object_key,
            committed_at_ms,
        )?);
    }
    batch.push(close_intent);
    d1_batch_blocking(d1, batch).map_err(|_| "staging R2 ownership commit failed".to_owned())?;
    Ok(())
}

fn verify_committed_staging_r2_resource(
    d1: &Arc<D1HttpClient>,
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    resource_class: &str,
    disposition: &str,
    receipt_ref: &str,
    object_key: &str,
) -> Result<(), String> {
    let resources = d1_query_blocking(
        d1,
        "SELECT opaque_handle, disposition, state FROM staging_load_test_resources \
         WHERE run_id = ?1 AND scenario = ?2 AND resource_class = ?3 AND receipt_ref = ?4",
        vec![
            json!(context.run_id()),
            json!(context.scenario().as_str()),
            json!(resource_class),
            json!(receipt_ref),
        ],
    )
    .map_err(|_| "staging R2 committed resource could not be verified".to_owned())?;
    let Some(resource) = resources.first() else {
        return Err("staging R2 committed resource could not be verified".to_owned());
    };
    if resources.len() != 1
        || resource.get("opaque_handle").and_then(Value::as_str) != Some(object_key)
        || resource.get("disposition").and_then(Value::as_str) != Some(disposition)
        || resource.get("state").and_then(Value::as_str) != Some("registered")
    {
        return Err("staging R2 committed resource conflicts with this write".to_owned());
    }
    if resource_class == "dsr_artifact" && disposition == "disposable" {
        let locators = d1_query_blocking(
            d1,
            "SELECT locator_kind, locator_json FROM staging_load_test_teardown_locators \
             WHERE run_id = ?1 AND scenario = ?2 AND resource_class = ?3 AND receipt_ref = ?4",
            vec![
                json!(context.run_id()),
                json!(context.scenario().as_str()),
                json!(resource_class),
                json!(receipt_ref),
            ],
        )
        .map_err(|_| "staging DSR teardown locator could not be verified".to_owned())?;
        let Some(locator) = locators.first() else {
            return Err("staging DSR teardown locator could not be verified".to_owned());
        };
        let locator_json = locator
            .get("locator_json")
            .and_then(Value::as_str)
            .and_then(|serialized| serde_json::from_str::<Value>(serialized).ok());
        if locators.len() != 1
            || locator.get("locator_kind").and_then(Value::as_str) != Some("dsr_r2_export_v1")
            || locator_json
                .as_ref()
                .and_then(|value| value.get("object_key"))
                .and_then(Value::as_str)
                != Some(object_key)
            || locator_json
                .as_ref()
                .and_then(Value::as_object)
                .is_none_or(|value| value.len() != 1)
        {
            return Err("staging DSR teardown locator conflicts with this write".to_owned());
        }
    }
    Ok(())
}

fn is_staging_dsr_export_key(object_key: &str) -> bool {
    let Some(name) = object_key.strip_prefix("dsr_exports/") else {
        return false;
    };
    let id = name
        .strip_suffix(".sig.json")
        .or_else(|| name.strip_suffix(".json"));
    let Some(id) = id else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn staging_dsr_export_locator_statement(
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    object_key: &str,
    registered_at_ms: i64,
) -> Result<D1BatchStatement, String> {
    if registered_at_ms < 0 || !is_staging_dsr_export_key(object_key) {
        return Err("staging DSR export locator is invalid".to_owned());
    }
    let receipt_ref = staging_receipt_ref(context, "dsr_artifact", object_key, "disposable");
    let locator_json = json!({ "object_key": object_key }).to_string();
    Ok(D1BatchStatement::new(
        "INSERT INTO staging_load_test_teardown_locators \
         (run_id, scenario, resource_class, receipt_ref, locator_kind, locator_json, registered_at_ms) \
         VALUES (?1, ?2, 'dsr_artifact', ?3, 'dsr_r2_export_v1', ?4, ?5)",
        vec![
            json!(context.run_id()),
            json!(context.scenario().as_str()),
            json!(receipt_ref),
            json!(locator_json),
            json!(registered_at_ms),
        ],
    ))
}

pub(crate) struct StagingDsrR2ExportLocator {
    pub(crate) object_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagingDsrTeardownError {
    InvalidLocator,
    DeleteFailed,
    HeadFailed,
    ObjectStillPresent,
}

pub(crate) async fn delete_staging_dsr_export_and_readback(
    r2: &R2S3Client,
    locator: &StagingDsrR2ExportLocator,
) -> Result<(), StagingDsrTeardownError> {
    delete_staging_dsr_export_and_readback_with(
        locator,
        |key| async move { r2.delete(&key).await },
        |key| async move { r2.head_size(&key).await },
    )
    .await
}

async fn delete_staging_dsr_export_and_readback_with<Delete, DeleteFuture, Head, HeadFuture>(
    locator: &StagingDsrR2ExportLocator,
    delete: Delete,
    head_size: Head,
) -> Result<(), StagingDsrTeardownError>
where
    Delete: FnOnce(String) -> DeleteFuture,
    DeleteFuture: Future<Output = Result<(), String>>,
    Head: FnOnce(String) -> HeadFuture,
    HeadFuture: Future<Output = Result<Option<u64>, String>>,
{
    if !is_staging_dsr_export_key(&locator.object_key) {
        return Err(StagingDsrTeardownError::InvalidLocator);
    }
    delete(locator.object_key.clone())
        .await
        .map_err(|_| StagingDsrTeardownError::DeleteFailed)?;
    match head_size(locator.object_key.clone())
        .await
        .map_err(|_| StagingDsrTeardownError::HeadFailed)?
    {
        None => Ok(()),
        Some(_) => Err(StagingDsrTeardownError::ObjectStillPresent),
    }
}

fn staging_receipt_ref(
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    resource_class: &str,
    opaque_handle: &str,
    disposition: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"corelink-staging-load-test-resource-receipt-v1\0");
    for part in [
        context.run_id().as_bytes(),
        context.scenario().as_str().as_bytes(),
        context.target_deployment_sha().as_bytes(),
        resource_class.as_bytes(),
        opaque_handle.as_bytes(),
        disposition.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

/// Best-effort durable persistence of the export bundle to the R2 audit bucket,
/// plus a detached Ed25519 signature over its content digest (reusing the
/// erasure attestation signer infra). NON-BLOCKING: a missing R2 client / sign
/// infra (or a transient PUT failure) downgrades to `persisted: false` — the
/// inline machine-readable bundle is the Art.20 core and always returns.
fn persist_export(
    d1: &Arc<D1HttpClient>,
    r2_audit: Option<&Arc<R2S3Client>>,
    dsr_id: &str,
    tenant_id: &str,
    export: &SubjectExport,
    now_ms: u64,
    ownership_context: StagingLoadTestWriteContext<'_>,
) -> ExportReceipt {
    let bundle_bytes = serde_json::to_vec(export).unwrap_or_default();
    let content_sha256 = hex::encode(Sha256::digest(&bundle_bytes));

    let Some(r2) = r2_audit else {
        return ExportReceipt {
            content_sha256,
            persisted: false,
            r2_key: None,
            signed: false,
        };
    };

    let object_key = format!("dsr_exports/{dsr_id}.json");
    let handle = tokio::runtime::Handle::current();
    let put_ok = if let Some(context) = ownership_context {
        persist_owned_r2(
            r2,
            d1,
            context,
            StagingLoadTestResourceClass::DsrArtifact,
            StagingLoadTestDisposition::Disposable,
            &object_key,
            bundle_bytes.clone(),
            now_ms,
        )
    } else {
        tokio::task::block_in_place(|| handle.block_on(r2.put(&object_key, bundle_bytes.clone())))
    };
    if let Err(e) = put_ok {
        tracing::warn!(dsr_id = %dsr_id, error = %e, "dsr/portability: export bundle R2 PUT failed (inline bundle still returned)");
        return ExportReceipt {
            content_sha256,
            persisted: false,
            r2_key: None,
            signed: false,
        };
    }

    // Detached Ed25519 signature over the content digest (reuses the per-region
    // erasure-attestation signer). Best-effort: skipped (signed=false) when the
    // region/seed infra is unset — never a forgeable certificate.
    let mut signed = false;
    if let Some((attestation, _region)) =
        super::attestation::sign_export_digest(dsr_id, tenant_id, now_ms, &content_sha256)
    {
        if let Ok(sig_bytes) = serde_json::to_vec(&attestation) {
            let sig_key = format!("dsr_exports/{dsr_id}.sig.json");
            let sig_ok = if let Some(context) = ownership_context {
                persist_owned_r2(
                    r2,
                    d1,
                    context,
                    StagingLoadTestResourceClass::DsrArtifact,
                    StagingLoadTestDisposition::Disposable,
                    &sig_key,
                    sig_bytes,
                    now_ms,
                )
            } else {
                tokio::task::block_in_place(|| handle.block_on(r2.put(&sig_key, sig_bytes)))
            };
            match sig_ok {
                Ok(()) => signed = true,
                Err(e) => {
                    tracing::warn!(dsr_id = %dsr_id, error = %e, "dsr/portability: export signature PUT failed")
                }
            }
        }
    }

    ExportReceipt {
        content_sha256,
        persisted: true,
        r2_key: Some(object_key),
        signed,
    }
}

/// Why a rectification was refused (maps to a fail-CLOSED 4xx).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RectifyReject {
    /// Target is content-addressed / immutable cache data (Art.16 N/A).
    ContentImmutable(String),
    /// Target is not an editable subject-PII field.
    NotEditable(String),
    /// The supplied new value failed validation (e.g. not a plausible email).
    InvalidValue(String),
}

impl RectifyReject {
    /// Human-readable reason (also the HTTP body).
    #[must_use]
    pub(super) fn message(&self) -> &str {
        match self {
            Self::ContentImmutable(m) | Self::NotEditable(m) | Self::InvalidValue(m) => m,
        }
    }
}

/// A validated rectification plan: the exact UPDATE to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RectifyPlan {
    pub sql: String,
    /// Stored value (already transformed, e.g. email → email_hash).
    pub stored_value: String,
}

/// Classify a rectification target against the editable-PII allowlist, applying
/// the field-specific value transform. FAIL-CLOSED: a content / non-editable
/// target or an invalid value is a [`RectifyReject`] (4xx), never a silent
/// pass. Pure (no I/O) so the policy is unit-tested offline.
pub(super) fn classify_rectify(
    table: &str,
    field: &str,
    new_value: &str,
) -> Result<RectifyPlan, RectifyReject> {
    if CONTENT_IMMUTABLE_TABLES.contains(&table) {
        return Err(RectifyReject::ContentImmutable(
            "cache content is content-addressed and immutable; \
             rectification (Art.16) applies to editable PII fields only"
                .to_owned(),
        ));
    }
    if !RECTIFIABLE_FIELDS.contains(&(table, field)) {
        return Err(RectifyReject::NotEditable(format!(
            "field '{table}.{field}' is not a rectifiable subject-PII field; \
             rectification (Art.16) applies to editable PII fields only"
        )));
    }
    // The only allowlisted field is tenant.email_hash — the account contact
    // email, stored pseudonymized. Validate a plausible email + hash it (never
    // store the raw email).
    let email = new_value.trim();
    if email.len() < 3 || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(RectifyReject::InvalidValue(
            "new value must be a valid email address".to_owned(),
        ));
    }
    Ok(RectifyPlan {
        sql: format!(
            "UPDATE {table} SET {field} = ?2 WHERE tenant_id = ?1 RETURNING 1 AS rows_updated"
        ),
        stored_value: email_hash(email),
    })
}

/// Outcome of a successful rectification.
#[derive(Debug, Clone, Serialize)]
pub(super) struct RectifyResult {
    pub table: String,
    pub field: String,
    pub rows_updated: u64,
}

/// Run the RECTIFICATION (Art.16) right: classify (fail-CLOSED on content /
/// non-editable / invalid), audit BEFORE the mutation, then apply the bounded
/// UPDATE. Idempotent: re-applying the same value is a no-op at the value level
/// and the audit row is `INSERT OR IGNORE` on a deterministic id.
pub(super) fn run_rectification(
    d1: &Arc<D1HttpClient>,
    dsr_id: &str,
    tenant_id: &str,
    table: &str,
    field: &str,
    new_value: &str,
    now_ms: u64,
    ownership_context: StagingLoadTestWriteContext<'_>,
) -> Result<Result<RectifyResult, RectifyReject>, String> {
    let plan = match classify_rectify(table, field, new_value) {
        Ok(p) => p,
        Err(reject) => return Ok(Err(reject)),
    };
    // Audit BEFORE the mutation (ADR-S11-002). Records the (table, field) — NOT
    // the new value (which is PII) — so the trail never re-leaks the email.
    audit_dsr_event(
        d1,
        dsr_id,
        tenant_id,
        EVENT_RECTIFICATION,
        &format!("{table}.{field}"),
        &json!({ "surface": "rectification", "table": table, "field": field }),
        now_ms,
        ownership_context,
    )?;
    let params = vec![json!(tenant_id), json!(plan.stored_value)];
    let rows = d1_query_blocking(d1, &plan.sql, params)?;
    let rows_updated = u64::try_from(rows.len()).unwrap_or(0);
    Ok(Ok(RectifyResult {
        table: table.to_owned(),
        field: field.to_owned(),
        rows_updated,
    }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use std::collections::HashSet;

    const TID: &str = "00000000-0000-7000-8000-000000000002";

    /// The access gather covers EXACTLY the erase-set (single-sourced): the
    /// non-retained (erasable) tables in the plan == TENANT_ID_TABLES ∪
    /// NAMESPACE_TABLES ∪ SPECIAL_ERASE_TABLES. A future erase-set table is then
    /// automatically gathered by access too — no parallel list to drift.
    #[test]
    fn access_set_equals_erase_set() {
        let plan = build_gather_plan(TID);
        let gathered: HashSet<&str> = plan
            .iter()
            .filter(|q| !q.retained)
            .map(|q| q.table)
            .collect();
        let mut erase_set: HashSet<&str> = HashSet::new();
        erase_set.extend(super::super::adapter_d1::TENANT_ID_TABLES.iter().copied());
        erase_set.extend(super::super::adapter_d1::NAMESPACE_TABLES.iter().copied());
        erase_set.extend(
            super::super::adapter_d1::SPECIAL_ERASE_TABLES
                .iter()
                .copied(),
        );
        assert_eq!(
            gathered, erase_set,
            "access gather (erasable) must equal the D1 erase-set exactly"
        );
    }

    #[test]
    fn clerk_provisioning_lock_access_is_bound_through_tenant_root() {
        let plan = build_gather_plan(TID);
        let lock = plan
            .iter()
            .find(|query| query.table == "clerk_provisioning_lock")
            .expect("Clerk provisioning lock must be in the access plan");
        assert!(!lock.retained);
        assert!(lock.sql.contains("clerk_user_id"));
        assert!(lock.sql.contains("FROM tenant WHERE tenant_id = ?1"));
        assert_eq!(lock.params, vec![json!(TID)]);
    }

    #[test]
    fn byok_activation_indirect_access_uses_fk_ownership_not_direct_tenant_id() {
        let plan = build_gather_plan(TID);
        let tables = [
            "byok_activation_worker_assertion",
            "byok_activation_operation_guard",
            "byok_activation_postcondition",
            "byok_activation_suspension_postcondition",
            "byok_activation_transition_assertion",
        ];
        for table in tables {
            let query = plan
                .iter()
                .find(|query| query.table == table)
                .expect("indirect 0121 table must be exported");
            assert!(!query.retained);
            assert!(!query
                .sql
                .starts_with(&format!("SELECT * FROM {table} WHERE tenant_id = ?1")));
            assert_eq!(query.params, vec![json!(TID)]);
            assert!(
                query.sql.contains("byok_activation_intent")
                    || query.sql.contains("byok_activation_guard"),
                "{table} must be scoped through an ownership parent"
            );
        }
        let worker = plan
            .iter()
            .find(|query| query.table == "byok_activation_worker_assertion")
            .expect("worker assertion query");
        assert!(worker.sql.contains("operation_token"));
        assert!(worker.sql.contains("intent_id"));
    }

    #[test]
    fn byok_activation_worker_access_is_exactly_owned_and_isolated_between_tenants() {
        let plan = build_gather_plan(TID);
        let worker = plan
            .iter()
            .find(|query| query.table == "byok_activation_worker_assertion")
            .expect("worker assertion query");
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE byok_activation_intent (intent_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);
             CREATE TABLE byok_activation_operation_guard (operation_token TEXT PRIMARY KEY, intent_id TEXT NOT NULL);
             CREATE TABLE byok_activation_worker_assertion (assertion_token TEXT PRIMARY KEY, operation_token TEXT NOT NULL, intent_id TEXT NOT NULL);
             INSERT INTO byok_activation_intent VALUES ('ia', 'tenant-a'), ('ib', 'tenant-b');
             INSERT INTO byok_activation_operation_guard VALUES ('opa', 'ia'), ('opb', 'ib'), ('op-mismatch', 'ib');
             INSERT INTO byok_activation_worker_assertion VALUES
                 ('wa', 'opa', 'ia'), ('wb', 'opb', 'ib'), ('wm', 'op-mismatch', 'ia');",
        )
        .unwrap();

        let count_for = |tenant: &str| -> i64 {
            let mut statement = db.prepare(&worker.sql).unwrap();
            let mut rows = statement.query(params![tenant]).unwrap();
            let mut count = 0;
            while rows.next().unwrap().is_some() {
                count += 1;
            }
            count
        };
        // The valid A/B rows are each visible only to their own tenant.
        assert_eq!(count_for("tenant-a"), 1);
        assert_eq!(count_for("tenant-b"), 1);
        // The mismatched worker is not exported for either side: exact
        // operation_guard.intent_id = worker.intent_id is mandatory.
        db.execute(
            "DELETE FROM byok_activation_worker_assertion WHERE assertion_token IN ('wa', 'wb')",
            [],
        )
        .unwrap();
        assert_eq!(count_for("tenant-a"), 0);
        assert_eq!(count_for("tenant-b"), 0);
    }

    /// The retained disclosable subset is a real subset of RETAIN_SET and never
    /// overlaps the erase-set (so we disclose retained data without ever
    /// touching it on an erasure).
    #[test]
    fn retain_disclosable_is_subset_and_disjoint_from_erase_set() {
        let retain: HashSet<&str> = super::super::adapter_d1::RETAIN_SET
            .iter()
            .copied()
            .collect();
        for t in RETAIN_DISCLOSABLE_TABLES {
            assert!(retain.contains(t), "{t} must be in RETAIN_SET");
        }
        let mut erase_set: HashSet<&str> = HashSet::new();
        erase_set.extend(super::super::adapter_d1::TENANT_ID_TABLES.iter().copied());
        erase_set.extend(super::super::adapter_d1::NAMESPACE_TABLES.iter().copied());
        erase_set.extend(
            super::super::adapter_d1::SPECIAL_ERASE_TABLES
                .iter()
                .copied(),
        );
        for t in RETAIN_DISCLOSABLE_TABLES {
            assert!(
                !erase_set.contains(t),
                "{t} is retained — must NOT be in the erase-set"
            );
        }
        // The plan tags exactly the disclosable subset as retained.
        let plan = build_gather_plan(TID);
        let plan_retained: HashSet<&str> = plan
            .iter()
            .filter(|q| q.retained)
            .map(|q| q.table)
            .collect();
        let want: HashSet<&str> = RETAIN_DISCLOSABLE_TABLES.iter().copied().collect();
        assert_eq!(plan_retained, want);
    }

    #[test]
    fn sla_credit_retained_rows_are_exported_without_masking_evidence() {
        let expected = [
            "sla_monthly_observations",
            "sla_monthly_measurements",
            "sla_credit_ledger",
        ];
        let export = gather_subject_data(TID, 1_700_000_000_000, |sql, _params| {
            let table = expected
                .iter()
                .find(|table| sql.starts_with(&format!("SELECT * FROM {table} ")))
                .copied();
            let Some(table) = table else {
                return Ok(vec![]);
            };
            let mut row = D1Row::new();
            row.insert("tenant_id".into(), json!(TID));
            row.insert("service_period".into(), json!("2026-08"));
            row.insert("table_marker".into(), json!(table));
            row.insert("stripe_customer_id".into(), json!("cus_sla_evidence"));
            row.insert("idempotency_key".into(), json!("sla-credit:stable"));
            row.insert("amount_minor".into(), json!(250));
            Ok(vec![row])
        })
        .unwrap();

        for table in expected {
            let exported = export
                .tables
                .iter()
                .find(|slice| slice.table == table)
                .expect("SLA retained table must be in the access export");
            assert!(exported.retained, "{table} must be marked retained");
            assert_eq!(exported.row_count, 1);
            assert_eq!(exported.rows[0]["table_marker"], json!(table));
            assert_eq!(
                exported.rows[0]["stripe_customer_id"],
                json!("cus_sla_evidence")
            );
            assert_eq!(
                exported.rows[0]["idempotency_key"],
                json!("sla-credit:stable")
            );
            assert_eq!(exported.rows[0]["amount_minor"], json!(250));
        }
    }

    /// gather assembles rows across multiple tables for a seeded tenant, and
    /// secret columns are NEVER exported raw.
    #[test]
    fn gather_assembles_rows_and_redacts_secrets() {
        let export = gather_subject_data(TID, 1_700_000_000_000, |sql, _params| {
            if sql.starts_with("SELECT * FROM pat ") {
                let mut row = D1Row::new();
                row.insert("pat_id".into(), json!("p1"));
                row.insert("tenant_id".into(), json!(TID));
                row.insert("pat_hash".into(), json!("SECRET-DIGEST"));
                row.insert("shown_once_token".into(), json!("SECRET-TOKEN"));
                row.insert("scope".into(), json!("read-write"));
                Ok(vec![row])
            } else if sql.starts_with("SELECT * FROM tenant ") {
                let mut row = D1Row::new();
                row.insert("tenant_id".into(), json!(TID));
                row.insert("email_hash".into(), json!("abc123"));
                Ok(vec![row])
            } else {
                Ok(vec![])
            }
        })
        .unwrap();

        let pat = export
            .tables
            .iter()
            .find(|t| t.table == "pat")
            .expect("pat table present");
        assert_eq!(pat.row_count, 1);
        let row = &pat.rows[0];
        assert_eq!(row.get("pat_hash").unwrap(), &json!("<redacted>"));
        assert_eq!(row.get("shown_once_token").unwrap(), &json!("<redacted>"));
        // Non-secret columns survive verbatim.
        assert_eq!(row.get("scope").unwrap(), &json!("read-write"));
        assert_eq!(row.get("pat_id").unwrap(), &json!("p1"));

        // The bundle is machine-readable structured JSON (per-table).
        let v = serde_json::to_value(&export).unwrap();
        assert_eq!(v["schema"], json!(EXPORT_SCHEMA));
        assert!(v["tables"].is_array());
    }

    /// FAIL-CLOSED: a D1 error on ANY table aborts the whole export — never a
    /// partial-looking "complete" bundle.
    #[test]
    fn gather_fails_closed_on_d1_error() {
        let res = gather_subject_data(TID, 1, |sql, _params| {
            if sql.contains("FROM tenant_quota") {
                Err("simulated D1 outage".to_owned())
            } else {
                Ok(vec![])
            }
        });
        assert!(res.is_err(), "a D1 error must fail the whole export");
        assert!(res.unwrap_err().contains("tenant_quota"));
    }

    /// SQL NULL in a secret column stays null (presence truthfully absent),
    /// non-null secret material is redacted.
    #[test]
    fn redact_keeps_null_present_redacts_value() {
        let mut row = D1Row::new();
        row.insert("pat_hash".into(), Value::Null);
        row.insert("secret_blob".into(), json!("xyz"));
        row.insert("region".into(), json!("weur"));
        let out = redact_row(row);
        assert!(out.get("pat_hash").unwrap().is_null());
        assert_eq!(out.get("secret_blob").unwrap(), &json!("<redacted>"));
        assert_eq!(out.get("region").unwrap(), &json!("weur"));
    }

    #[test]
    fn sensitive_col_detection() {
        assert!(is_sensitive_col("pat_hash"));
        assert!(is_sensitive_col("shown_once_token"));
        assert!(is_sensitive_col("byok_envelope"));
        assert!(is_sensitive_col("dek_ciphertext"));
        // Not secrets — must NOT be redacted.
        assert!(!is_sensitive_col("key_id"));
        assert!(!is_sensitive_col("idempotency_key"));
        assert!(!is_sensitive_col("tenant_id"));
        // email_hash is a pseudonym (the subject's own data), intentionally NOT
        // a credential token — disclosed, not redacted.
        assert!(!is_sensitive_col("email_hash"));
    }

    /// Rectification: content target → ContentImmutable; non-editable field →
    /// NotEditable; the allowlisted email field → a hashing UPDATE plan.
    #[test]
    fn rectify_rejects_content_and_non_editable_allows_email() {
        // `email_hash` reads process-global `EMAIL_HASH_SALT`; hold the shared
        // lock (forces it UNSET) so the unsalted assertion below is stable.
        let _env = crate::email_hash::EnvGuard::acquire();
        // Cache content is immutable.
        let r = classify_rectify("blob_meta", "digest", "x");
        assert!(matches!(r, Err(RectifyReject::ContentImmutable(_))));

        // A non-editable field fails CLOSED.
        let r = classify_rectify("tenant", "tier", "enterprise");
        assert!(matches!(r, Err(RectifyReject::NotEditable(_))));

        // The allowlisted email field is accepted + hashed (raw email never stored).
        let plan = classify_rectify("tenant", "email_hash", "  New.User@Example.COM ").unwrap();
        assert!(plan
            .sql
            .starts_with("UPDATE tenant SET email_hash = ?2 WHERE tenant_id = ?1"));
        assert_eq!(plan.stored_value, email_hash("new.user@example.com"));
        assert_ne!(
            plan.stored_value, "new.user@example.com",
            "raw email never stored"
        );
    }

    #[test]
    fn rectify_rejects_invalid_email() {
        let r = classify_rectify("tenant", "email_hash", "not-an-email");
        assert!(matches!(r, Err(RectifyReject::InvalidValue(_))));
        let r = classify_rectify("tenant", "email_hash", "a b@c.com");
        assert!(matches!(r, Err(RectifyReject::InvalidValue(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_rectification_registers_retained_audit_only() {
        let (database, endpoint) = ownership_d1_fixture(false, 3);
        let context = accepted_dsr_context(&endpoint).await;
        let d1 = Arc::new(test_d1_client(&endpoint));
        let result = run_rectification(
            &d1,
            "00000000-0000-7000-8000-000000000001",
            TID,
            "tenant",
            "email_hash",
            "new@example.invalid",
            1_700_000_000_000,
            Some(&context),
        )
        .expect("rectification audit and update succeed")
        .expect("email hash is rectifiable");
        assert_eq!(result.rows_updated, 1);

        let db = database.lock().expect("fixture database");
        let (resource_class, disposition): (String, String) = db
            .query_row(
                "SELECT resource_class, disposition FROM staging_load_test_resources",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("retained audit ownership row");
        let locator_count: i64 = db
            .query_row(
                "SELECT count(*) FROM staging_load_test_teardown_locators",
                [],
                |row| row.get(0),
            )
            .expect("no rectification locator");
        let stored_email_hash: String = db
            .query_row(
                "SELECT email_hash FROM tenant WHERE tenant_id = ?1",
                [TID],
                |row| row.get(0),
            )
            .expect("rectified tenant value");
        assert_eq!(resource_class, "audit_evidence");
        assert_eq!(disposition, "retained");
        assert_eq!(
            locator_count, 0,
            "rectification creates no disposable locator"
        );
        assert_eq!(stored_email_hash, email_hash("new@example.invalid"));
    }

    #[test]
    fn staging_dsr_key_accepts_only_single_safe_export_or_signature_keys() {
        for key in [
            "dsr_exports/dsr-2581.json",
            "dsr_exports/dsr-2581.sig.json",
            "dsr_exports/00000000-0000-7000-8000-000000000001.json",
        ] {
            assert!(is_staging_dsr_export_key(key), "{key}");
        }
        for key in [
            "../dsr_exports/dsr-2581.json",
            "dsr_exports/../secret.json",
            "dsr_exports/a/b.json",
            "dsr_exports/%2f.json",
            "dsr_exports/a.sig.json.json",
            "dsr_exports/.json",
            "dsr_exports/a.json/extra",
        ] {
            assert!(!is_staging_dsr_export_key(key), "{key}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_r2_writer_rejects_invalid_key_before_intent_or_put() {
        let (database, endpoint) = ownership_d1_fixture(false, 1);
        let context = accepted_dsr_context(&endpoint).await;
        let d1 = Arc::new(test_d1_client(&endpoint));
        let put_called = std::sync::atomic::AtomicBool::new(false);
        let result = persist_owned_r2_with(
            &d1,
            &context,
            StagingLoadTestResourceClass::DsrArtifact,
            StagingLoadTestDisposition::Disposable,
            "dsr_exports/../outside.json",
            b"synthetic bundle".to_vec(),
            1_700_000_000_000,
            |_, _| {
                put_called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!put_called.load(std::sync::atomic::Ordering::SeqCst));
        let db = database.lock().expect("fixture database");
        let (intents, resources, locators): (i64, i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM staging_load_test_r2_intents), (SELECT count(*) FROM staging_load_test_resources), (SELECT count(*) FROM staging_load_test_teardown_locators)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("invalid key created no durable rows");
        assert_eq!((intents, resources, locators), (0, 0, 0));
    }

    #[tokio::test]
    async fn exact_dsr_export_delete_requires_absent_head_for_both_object_kinds() {
        for key in ["dsr_exports/dsr-2581.json", "dsr_exports/dsr-2581.sig.json"] {
            let locator = StagingDsrR2ExportLocator {
                object_key: key.to_owned(),
            };
            let deleted_key = key.to_owned();
            let headed_key = key.to_owned();
            delete_staging_dsr_export_and_readback_with(
                &locator,
                move |actual| {
                    assert_eq!(actual, deleted_key);
                    async { Ok(()) }
                },
                move |actual| {
                    assert_eq!(actual, headed_key);
                    async { Ok(None) }
                },
            )
            .await
            .expect("exact-key delete followed by absent HEAD");
        }
    }

    #[tokio::test]
    async fn exact_dsr_export_delete_fails_closed_on_bad_delete_head_error_or_residue() {
        let locator = StagingDsrR2ExportLocator {
            object_key: "dsr_exports/dsr-2581.json".to_owned(),
        };
        assert_eq!(
            delete_staging_dsr_export_and_readback_with(
                &locator,
                |_| async { Err("private transport detail".to_owned()) },
                |_| async { panic!("HEAD must not run after failed DELETE") },
            )
            .await,
            Err(StagingDsrTeardownError::DeleteFailed)
        );
        assert_eq!(
            delete_staging_dsr_export_and_readback_with(
                &locator,
                |_| async { Ok(()) },
                |_| async { Err("private transport detail".to_owned()) },
            )
            .await,
            Err(StagingDsrTeardownError::HeadFailed)
        );
        assert_eq!(
            delete_staging_dsr_export_and_readback_with(
                &locator,
                |_| async { Ok(()) },
                |_| async { Ok(Some(0)) },
            )
            .await,
            Err(StagingDsrTeardownError::ObjectStillPresent)
        );
        let invalid = StagingDsrR2ExportLocator {
            object_key: "dsr_exports/../other.json".to_owned(),
        };
        assert_eq!(
            delete_staging_dsr_export_and_readback_with(
                &invalid,
                |_| async { panic!("DELETE must not run for an invalid key") },
                |_| async { panic!("HEAD must not run for an invalid key") },
            )
            .await,
            Err(StagingDsrTeardownError::InvalidLocator)
        );
    }

    /// Audit ids are deterministic per (dsr_id, event_type, suffix) — the
    /// idempotency key that makes a retry an INSERT OR IGNORE no-op.
    #[test]
    fn audit_event_id_is_deterministic() {
        let a = audit_event_id("dsr-1", EVENT_ACCESS, "-");
        let b = audit_event_id("dsr-1", EVENT_ACCESS, "-");
        assert_eq!(a, b);
        // Distinct per surface + per rectification target.
        assert_ne!(a, audit_event_id("dsr-1", EVENT_PORTABILITY, "-"));
        assert_ne!(
            audit_event_id("dsr-1", EVENT_RECTIFICATION, "tenant.email_hash"),
            audit_event_id("dsr-1", EVENT_RECTIFICATION, "tenant.tier")
        );
    }

    #[test]
    fn email_hash_matches_canonical_scheme() {
        let env = crate::email_hash::EnvGuard::acquire(); // salt UNSET
                                                          // Unsalted: equals hex(sha256(trim+lowercase)) — pre-salt parity.
        let want = hex::encode(Sha256::digest(b"user@example.com"));
        assert_eq!(email_hash("  USER@Example.com  "), want);

        // Matching invariant: this rectification site routes through the ONE
        // shared helper, so it equals it in BOTH modes (hence equals the
        // customer_d1 write site, which also delegates to the helper).
        assert_eq!(
            email_hash("user@example.com"),
            crate::email_hash::hash_email("user@example.com")
        );
        env.set_salt("the-server-salt");
        assert_eq!(
            email_hash("user@example.com"),
            crate::email_hash::hash_email("user@example.com")
        );
        // Under a salt the pseudonym is no longer the rainbow-attackable SHA-256.
        assert_ne!(email_hash("user@example.com"), want);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_access_audit_batches_registration_from_accepted_context() {
        let (database, endpoint) = ownership_d1_fixture(false, 3);
        let context = accepted_dsr_context(&endpoint).await;
        let d1 = Arc::new(test_d1_client(&endpoint));
        let emit = || {
            audit_dsr_event(
                &d1,
                "dsr-2581",
                TID,
                EVENT_ACCESS,
                "-",
                &json!({ "surface": "access" }),
                1_700_000_000_000,
                Some(&context),
            )
        };
        let result = emit();
        assert!(
            result.is_ok(),
            "writer should commit with its ownership row"
        );
        assert!(emit().is_ok(), "duplicate logical events are idempotent");
        let db = database.lock().expect("fixture database");
        let audit_count: i64 = db
            .query_row("SELECT count(*) FROM audit_outbox", [], |row| row.get(0))
            .expect("audit count");
        let mut resource_query = db
            .prepare("SELECT resource_class, disposition, run_id, scenario, opaque_handle, receipt_ref FROM staging_load_test_resources")
            .expect("resource query");
        let resources = resource_query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .expect("resource rows")
            .map(|row| row.expect("resource row"))
            .collect::<Vec<(String, String, String, String, String, String)>>();
        assert_eq!(audit_count, 1);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].0, "audit_evidence");
        assert_eq!(resources[0].1, "retained");
        assert_eq!(resources[0].2, "2581");
        assert_eq!(resources[0].3, "dsr");
        assert_eq!(
            resources[0].4,
            audit_event_id("dsr-2581", EVENT_ACCESS, "-")
        );
        assert_eq!(
            resources[0].5.len(),
            64,
            "ownership receipts are SHA-256 only"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_access_audit_batch_failure_rolls_back_domain_write() {
        let (database, endpoint) = ownership_d1_fixture(true, 2);
        let context = accepted_dsr_context(&endpoint).await;
        let d1 = Arc::new(test_d1_client(&endpoint));
        let result = audit_dsr_event(
            &d1,
            "dsr-2581",
            TID,
            EVENT_ACCESS,
            "-",
            &json!({ "surface": "access" }),
            1_700_000_000_000,
            Some(&context),
        );
        assert!(result.is_err(), "registration failure must fail the writer");
        let db = database.lock().expect("fixture database");
        let audit_count: i64 = db
            .query_row("SELECT count(*) FROM audit_outbox", [], |row| row.get(0))
            .expect("audit count");
        let resource_count: i64 = db
            .query_row(
                "SELECT count(*) FROM staging_load_test_resources",
                [],
                |row| row.get(0),
            )
            .expect("resource count");
        assert_eq!(audit_count, 0, "the earlier audit insert rolled back");
        assert_eq!(
            resource_count, 0,
            "failed registration left no ownership row"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_r2_writer_recovers_exact_prepare_and_replays_once() {
        let (database, endpoint) = ownership_d1_fixture(false, 11);
        let context = Arc::new(accepted_dsr_context(&endpoint).await);
        let d1 = Arc::new(test_d1_client(&endpoint));
        let put_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let run = |put_result: Result<(), String>| {
            let d1 = Arc::clone(&d1);
            let context = Arc::clone(&context);
            let put_attempts = Arc::clone(&put_attempts);
            async move {
                // The test seam substitutes only the external R2 PUT; the real
                // DSR writer still prepares, recovers and commits through D1.
                persist_owned_r2_with(
                    &d1,
                    context.as_ref(),
                    StagingLoadTestResourceClass::DsrArtifact,
                    StagingLoadTestDisposition::Disposable,
                    "dsr_exports/00000000-0000-7000-8000-000000002581.json",
                    b"synthetic bundle".to_vec(),
                    1_700_000_000_000,
                    move |_, _| {
                        put_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        put_result
                    },
                )
            }
        };

        assert!(run(Err("simulated R2 failure".into())).await.is_err());
        {
            let db = database.lock().expect("fixture database");
            let (state, resources): (String, i64) = db
                .query_row(
                    "SELECT (SELECT state FROM staging_load_test_r2_intents), (SELECT count(*) FROM staging_load_test_resources)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("failed PUT remains prepared without claiming a resource");
            assert_eq!(state, "prepared");
            assert_eq!(
                resources, 0,
                "failed external PUT never reports a registered artifact"
            );
        }
        assert!(
            run(Ok(())).await.is_ok(),
            "exact prepared intent should reconcile"
        );
        assert!(
            run(Ok(())).await.is_ok(),
            "committed exact replay remains idempotent"
        );
        assert_eq!(put_attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        persist_owned_r2_with(
            &d1,
            context.as_ref(),
            StagingLoadTestResourceClass::DsrArtifact,
            StagingLoadTestDisposition::Disposable,
            "dsr_exports/00000000-0000-7000-8000-000000002581.sig.json",
            b"synthetic signature".to_vec(),
            1_700_000_000_000,
            |_, _| {
                put_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("signature has its own exact typed locator");
        assert_eq!(put_attempts.load(std::sync::atomic::Ordering::SeqCst), 3);

        let db = database.lock().expect("fixture database");
        let state: String = db
            .query_row(
                "SELECT state FROM staging_load_test_r2_intents",
                [],
                |row| row.get(0),
            )
            .expect("intent state");
        let (intent_count, resource_count, resource_class, disposition, opaque_handle): (i64, i64, String, String, String) = db
            .query_row(
                "SELECT (SELECT count(*) FROM staging_load_test_r2_intents), \
                        (SELECT count(*) FROM staging_load_test_resources), \
                        (SELECT resource_class FROM staging_load_test_resources WHERE opaque_handle = 'dsr_exports/00000000-0000-7000-8000-000000002581.json'), \
                        (SELECT disposition FROM staging_load_test_resources WHERE opaque_handle = 'dsr_exports/00000000-0000-7000-8000-000000002581.json'), \
                        (SELECT opaque_handle FROM staging_load_test_resources WHERE opaque_handle = 'dsr_exports/00000000-0000-7000-8000-000000002581.json')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("durable counts");
        assert_eq!(state, "committed");
        assert_eq!(intent_count, 2, "retry reused the exact immutable intent");
        assert_eq!(resource_count, 2, "each R2 object has one ownership row");
        assert_eq!(resource_class, "dsr_artifact");
        assert_eq!(disposition, "disposable");
        assert_eq!(
            opaque_handle,
            "dsr_exports/00000000-0000-7000-8000-000000002581.json"
        );
        let locators = db
            .prepare(
                "SELECT l.locator_kind, l.locator_json, l.receipt_ref, r.receipt_ref \
                 FROM staging_load_test_teardown_locators AS l \
                 JOIN staging_load_test_resources AS r USING (run_id, scenario, resource_class, receipt_ref) \
                 ORDER BY l.locator_json",
            )
            .expect("locator/resource join")
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .expect("locator/resource rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("valid locator/resource rows");
        assert_eq!(locators.len(), 2);
        let keys = locators
            .iter()
            .map(|(kind, json, receipt, resource_receipt)| {
                assert_eq!(kind, "dsr_r2_export_v1");
                assert_eq!(receipt, resource_receipt, "locator binds exact 0147 row");
                serde_json::from_str::<Value>(json).unwrap()["object_key"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert!(keys.contains(&"dsr_exports/00000000-0000-7000-8000-000000002581.json".to_owned()));
        assert!(
            keys.contains(&"dsr_exports/00000000-0000-7000-8000-000000002581.sig.json".to_owned())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_r2_commit_failure_leaves_prepared_intent_without_locator() {
        let (database, endpoint) = ownership_d1_fixture(true, 3);
        let context = accepted_dsr_context(&endpoint).await;
        let d1 = Arc::new(test_d1_client(&endpoint));
        let result = persist_owned_r2_with(
            &d1,
            &context,
            StagingLoadTestResourceClass::DsrArtifact,
            StagingLoadTestDisposition::Disposable,
            "dsr_exports/dsr-2581.json",
            b"synthetic bundle".to_vec(),
            1_700_000_000_000,
            |_, _| Ok(()),
        );
        assert!(
            result.is_err(),
            "failed D1 commit must not claim durable ownership"
        );
        let db = database.lock().expect("fixture database");
        let (state, resources, locators): (String, i64, i64) = db
            .query_row(
                "SELECT (SELECT state FROM staging_load_test_r2_intents), (SELECT count(*) FROM staging_load_test_resources), (SELECT count(*) FROM staging_load_test_teardown_locators)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("prepared D1 intent remains recoverable");
        assert_eq!(state, "prepared");
        assert_eq!(resources, 0);
        assert_eq!(locators, 0);
    }

    fn test_storage_env(endpoint: &str) -> crate::storage::StorageEnv {
        crate::storage::StorageEnv {
            r2_endpoint: endpoint.to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        }
    }

    fn test_d1_client(endpoint: &str) -> D1HttpClient {
        D1HttpClient::new_for_loopback_test(&test_storage_env(endpoint), endpoint)
            .expect("loopback D1 test client")
    }

    async fn accepted_dsr_context(
        endpoint: &str,
    ) -> crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let sha = "a".repeat(40);
        let key = [0x63_u8; 32];
        let verifier =
            crate::storage::staging_load_test_admission::StagingLoadTestAdmissionVerifier::new(
                "staging", key,
            )
            .expect("test staging verifier");
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_millis(),
        )
        .expect("timestamp fits i64");
        let issued = now_ms - 1_000;
        let expires = now_ms + 60_000;
        let nonce = hex::encode([0x39_u8; 32]);
        let payload = format!("v1.2581.dsr.staging.{sha}.{issued}.{expires}.{nonce}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
        mac.update(b"corelink/staging-load-admission-auth/v1\0");
        mac.update(payload.as_bytes());
        let credential = format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()));
        let verified = verifier
            .verify(&credential, now_ms)
            .expect("verified claim");
        let store = crate::storage::staging_load_test_admission::StagingLoadTestAdmissionStore::from_d1_client_for_test(
            test_d1_client(endpoint),
        );
        let expectation =
            crate::storage::staging_load_test_admission::StagingLoadTestAdmissionExpectation {
                run_id: "2581",
                scenario: crate::storage::staging_load_test_ownership::StagingLoadTestScenario::Dsr,
                target_environment: "staging",
                target_deployment_sha: &sha,
            };
        let context = store
            .consume_verified_admission(expectation, verified)
            .await
            .expect("atomic admission consumption");
        context
    }

    fn ownership_d1_fixture(
        fail_resource_registration: bool,
        request_count: usize,
    ) -> (std::sync::Arc<std::sync::Mutex<Connection>>, String) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("D1 loopback listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let database = Connection::open_in_memory().expect("SQLite D1 fixture");
        database
            .execute_batch(
                "CREATE TABLE staging_load_test_runs (run_id TEXT, scenario TEXT, target_environment TEXT, target_deployment_sha TEXT, state TEXT, admitted_at_ms INTEGER, PRIMARY KEY (run_id, scenario));
                 CREATE TABLE staging_load_test_admission_nonces (nonce_digest TEXT PRIMARY KEY, run_id TEXT, scenario TEXT, target_environment TEXT, target_deployment_sha TEXT, issued_at_ms INTEGER, expires_at_ms INTEGER, admitted_at_ms INTEGER);
                 CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, email_hash TEXT NOT NULL, primary_region TEXT NOT NULL);
                 CREATE TABLE audit_outbox (id TEXT PRIMARY KEY, tenant_id TEXT, digest TEXT, request_id TEXT, event_type TEXT, payload_json TEXT, enqueued_at INTEGER, emitted_at INTEGER, region TEXT);
                 CREATE TABLE staging_load_test_resources (run_id TEXT, scenario TEXT, resource_class TEXT, receipt_ref TEXT, opaque_handle TEXT, disposition TEXT, state TEXT, registered_at_ms INTEGER, PRIMARY KEY (run_id, scenario, resource_class, receipt_ref));
                 CREATE TABLE staging_load_test_r2_intents (operation_id TEXT PRIMARY KEY, run_id TEXT, scenario TEXT, target_deployment_sha TEXT, resource_class TEXT, receipt_ref TEXT, opaque_handle TEXT, disposition TEXT, state TEXT, prepared_at_ms INTEGER, committed_at_ms INTEGER);
                 CREATE TABLE staging_load_test_teardown_locators (run_id TEXT, scenario TEXT, resource_class TEXT, receipt_ref TEXT, locator_kind TEXT, locator_json TEXT, registered_at_ms INTEGER, PRIMARY KEY (run_id, scenario, resource_class, receipt_ref));
                 INSERT INTO tenant VALUES ('00000000-0000-7000-8000-000000000002', 'old@example.invalid', 'weur');",
            )
            .expect("fixture schema");
        if fail_resource_registration {
            database
                .execute_batch(
                    "CREATE TRIGGER fail_staging_resource BEFORE INSERT ON staging_load_test_resources BEGIN SELECT RAISE(ABORT, 'forced registration failure'); END;",
                )
                .expect("failure trigger");
        }
        let database = Arc::new(Mutex::new(database));
        let thread_db = Arc::clone(&database);
        std::thread::spawn(move || {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().expect("D1 request connection");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("read timeout");
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0_u8; 4096];
                    let read = stream.read(&mut buffer).expect("HTTP request read");
                    bytes.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then_some(value.trim())
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .expect("HTTP content length");
                    if bytes.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let header_end = bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap();
                let body: Value =
                    serde_json::from_slice(&bytes[header_end + 4..]).expect("D1 JSON");
                let result = if let Some(batch) = body.get("batch").and_then(Value::as_array) {
                    let mut db = thread_db.lock().expect("fixture database lock");
                    let tx = db.transaction().expect("D1 batch transaction");
                    let executed = batch.iter().try_for_each(|statement| {
                        let sql = statement["sql"].as_str().expect("batch SQL");
                        let values =
                            json_sql_values(statement["params"].as_array().expect("batch params"));
                        tx.execute(sql, rusqlite::params_from_iter(values.iter()))
                            .map(|_| ())
                    });
                    match executed {
                        Ok(()) => {
                            tx.commit().expect("commit D1 fixture transaction");
                            Ok(serde_json::json!({
                                "result": batch.iter().map(|_| serde_json::json!({"results": [], "success": true})).collect::<Vec<_>>(),
                                "success": true,
                                "errors": []
                            }))
                        }
                        Err(error) => {
                            drop(tx);
                            Err(error.to_string())
                        }
                    }
                } else {
                    let sql = body["sql"].as_str().expect("query SQL");
                    let values = json_sql_values(body["params"].as_array().expect("query params"));
                    let db = thread_db.lock().expect("fixture database lock");
                    query_json_rows(&db, sql, &values)
                        .map_err(|error| error.to_string())
                        .map(|rows| serde_json::json!({ "result": [{"results": rows, "success": true}], "success": true, "errors": [] }))
                };
                let (status, response) = match result {
                    Ok(response) => ("200 OK", response),
                    Err(error) => (
                        "400 Bad Request",
                        serde_json::json!({"result": [], "success": false, "errors": [{"message": error}]}),
                    ),
                };
                let response = response.to_string();
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).expect("D1 HTTP response");
            }
        });
        (database, endpoint)
    }

    fn json_sql_values(values: &[Value]) -> Vec<rusqlite::types::Value> {
        values
            .iter()
            .map(|value| match value {
                Value::Null => rusqlite::types::Value::Null,
                Value::Bool(value) => rusqlite::types::Value::Integer(i64::from(*value)),
                Value::Number(value) => {
                    rusqlite::types::Value::Integer(value.as_i64().expect("integer D1 param"))
                }
                Value::String(value) => rusqlite::types::Value::Text(value.clone()),
                _ => rusqlite::types::Value::Text(value.to_string()),
            })
            .collect()
    }

    fn query_json_rows(
        connection: &Connection,
        sql: &str,
        values: &[rusqlite::types::Value],
    ) -> Result<Vec<Value>, rusqlite::Error> {
        let mut statement = connection.prepare(sql)?;
        let columns = statement
            .column_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        let mut rows = statement.query(rusqlite::params_from_iter(values.iter()))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let mut object = serde_json::Map::new();
            for (index, name) in columns.iter().enumerate() {
                let value = match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(value) => json!(value),
                    rusqlite::types::ValueRef::Real(value) => json!(value),
                    rusqlite::types::ValueRef::Text(value) => json!(String::from_utf8_lossy(value)),
                    rusqlite::types::ValueRef::Blob(value) => json!(hex::encode(value)),
                };
                object.insert(name.clone(), value);
            }
            result.push(Value::Object(object));
        }
        Ok(result)
    }
}
