#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use rusqlite::Connection;
use serde_json::json;

use super::*;

/// FK-ORDER guard. D1 enforces `PRAGMA foreign_keys = ON`, and
/// `stripe_checkout_sessions` has `FOREIGN KEY (tenant_id) REFERENCES
/// tier_selections(tenant_id)`. The erase loop deletes `TENANT_ID_TABLES` in
/// order via separate D1-REST statements, so the CHILD
/// (`stripe_checkout_sessions`) MUST be deleted BEFORE the PARENT
/// (`tier_selections`) — otherwise deleting the parent while an orphan child
/// is still pending fails the FK constraint, the D1 backend Errs, and the
/// tenant's Art.17 erasure 500s and stays stuck (the 2026-08-18 drain-tail
/// root cause). If a future edit reorders these, this test fails LOUD.
#[test]
fn stripe_checkout_sessions_precedes_tier_selections() {
    // (`.unwrap()` — the test module allow-lists `clippy::unwrap_used`; both
    // tables are compile-time constants in the slice, so these never panic.)
    let child = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == "stripe_checkout_sessions")
        .unwrap();
    let parent = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == "tier_selections")
        .unwrap();
    assert!(
        child < parent,
        "FK-ORDER VIOLATION: stripe_checkout_sessions (idx {child}) must be \
             deleted BEFORE tier_selections (idx {parent}) — it holds \
             FOREIGN KEY (tenant_id) REFERENCES tier_selections(tenant_id) and D1 \
             enforces FKs, so parent-first deletion 500s the whole erasure."
    );
}

#[test]
fn stripe_checkout_ownership_ledger_precedes_tier_selections() {
    let child = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == "stripe_checkout_ownership_ledger")
        .unwrap();
    let parent = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == "tier_selections")
        .unwrap();
    assert!(
        child < parent,
        "FK-ORDER VIOLATION: stripe_checkout_ownership_ledger (idx {child}) \
         must be deleted BEFORE tier_selections (idx {parent})"
    );
}

#[test]
fn clerk_lock_is_special_and_precedes_tenant_root() {
    let lock = SPECIAL_ERASE_TABLES
        .iter()
        .position(|&t| t == "clerk_provisioning_lock")
        .unwrap();
    let root = SPECIAL_ERASE_TABLES
        .iter()
        .position(|&t| t == "tenant")
        .unwrap();
    assert!(
        lock < root,
        "clerk_provisioning_lock must be erased by tenant.clerk_user_id \
         before the tenant root is deleted"
    );
    assert!(!TENANT_ID_TABLES.contains(&"clerk_provisioning_lock"));
}

#[test]
fn clerk_lookup_fails_closed_for_missing_or_blank_key() {
    assert!(D1EraseAdapter::clerk_user_id_from_rows(&[]).is_err());

    let mut missing = D1Row::new();
    missing.insert("tenant_id".to_owned(), json!("tenant-1"));
    assert!(D1EraseAdapter::clerk_user_id_from_rows(&[missing]).is_err());

    let mut blank = D1Row::new();
    blank.insert("clerk_user_id".to_owned(), json!("  "));
    assert!(D1EraseAdapter::clerk_user_id_from_rows(&[blank]).is_err());

    let mut valid = D1Row::new();
    valid.insert("clerk_user_id".to_owned(), json!("user_123"));
    assert_eq!(
        D1EraseAdapter::clerk_user_id_from_rows(&[valid]).unwrap(),
        "user_123"
    );
}

/// The purge-cause ledger is an FK child whose tenant scope is an alias
/// through `byok_object_purge_item`, not a direct `tenant_id` predicate. This
/// guard is deliberately mutation-sensitive: moving the child into the
/// direct tenant loop would emit `WHERE tenant_id = ?1` against a table that
/// has no such column, while dropping the bespoke constants would permit a
/// parent-first delete and a production FK failure.
#[test]
fn byok_purge_cause_is_a_bespoke_parent_joined_child() {
    assert_eq!(BYOK_PURGE_CAUSE_TABLE, "byok_object_purge_cause");
    assert_eq!(BYOK_PURGE_CAUSE_PARENT_KEY, "purge_id");
    assert_eq!(BYOK_PURGE_PARENT_TABLE, "byok_object_purge_item");
    assert!(!TENANT_ID_TABLES.contains(&BYOK_PURGE_CAUSE_TABLE));
    assert!(!SPECIAL_ERASE_TABLES.contains(&BYOK_PURGE_CAUSE_TABLE));
    let parent = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == BYOK_PURGE_PARENT_TABLE)
        .unwrap();
    assert_eq!(classification_count(BYOK_PURGE_PARENT_TABLE), 1);
    assert!(
        TENANT_ID_TABLES
            .get(parent)
            .is_some_and(|table| *table == BYOK_PURGE_PARENT_TABLE),
        "purge item parent must remain in the direct tenant_id registry lane"
    );
}

#[test]
fn byok_purge_parent_is_deleted_by_the_atomic_bespoke_lane() {
    let quarantine = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == "byok_purge_identity_quarantine")
        .unwrap();
    let parent = TENANT_ID_TABLES
        .iter()
        .position(|&t| t == BYOK_PURGE_PARENT_TABLE)
        .unwrap();
    assert!(
        quarantine < parent,
        "purge identity quarantine FK child must precede the purge parent"
    );
    assert_eq!(
        TENANT_ID_TABLES.get(parent),
        Some(&BYOK_PURGE_PARENT_TABLE),
        "the bespoke batch is anchored at the tenant-keyed purge parent"
    );
    assert!(
        TENANT_ID_TABLES
            .iter()
            .all(|table| *table != BYOK_PURGE_CAUSE_TABLE),
        "the FK child must never be routed through WHERE tenant_id = ?1"
    );
}

#[test]
fn byok_activation_indirect_children_are_special_and_fk_scoped() {
    let tables = [
        BYOK_ACTIVATION_WORKER_ASSERTION_TABLE,
        BYOK_ACTIVATION_OPERATION_GUARD_TABLE,
        BYOK_ACTIVATION_POSTCONDITION_TABLE,
        BYOK_ACTIVATION_SUSPENSION_POSTCONDITION_TABLE,
        BYOK_ACTIVATION_TRANSITION_ASSERTION_TABLE,
    ];
    for table in tables {
        assert!(SPECIAL_ERASE_TABLES.contains(&table));
        assert!(!TENANT_ID_TABLES.contains(&table));
        assert_eq!(classification_count(table), 1);
    }

    let migration = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/d1/0121_byok_activation_pipeline.sql"
    );
    let sql = std::fs::read_to_string(migration).unwrap();
    assert!(
        sql.contains("FOREIGN KEY (operation_token) REFERENCES byok_activation_operation_guard")
    );
    assert!(sql.contains("FOREIGN KEY (intent_id) REFERENCES byok_activation_intent"));
    assert!(sql.contains("FOREIGN KEY (guard_id) REFERENCES byok_activation_guard"));
    let intent = TENANT_ID_TABLES
        .iter()
        .position(|&table| table == "byok_activation_intent")
        .unwrap();
    let guard = TENANT_ID_TABLES
        .iter()
        .position(|&table| table == "byok_activation_guard")
        .unwrap();
    assert!(
        intent < guard,
        "activation intent must be deleted before its activation-guard parent"
    );
    assert!(BYOK_PURGE_CAUSE_ORPHAN_SQL.contains("LEFT JOIN"));
    assert!(BYOK_PURGE_CAUSE_ORPHAN_SQL.contains("IS NULL"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.contains("byok_activation_worker_assertion"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.contains("byok_activation_operation_guard"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.contains("byok_activation_postcondition"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.contains("byok_activation_suspension_postcondition"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.contains("byok_activation_transition_assertion"));
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.matches("UNION ALL").count() >= 4);
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.matches("LEFT JOIN").count() >= 6);
    assert!(BYOK_ACTIVATION_ORPHAN_SQL.matches("IS NULL").count() >= 6);
}

#[test]
fn byok_activation_orphan_sql_is_valid_and_global_in_sqlite() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE byok_activation_intent (intent_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);
         CREATE TABLE byok_activation_guard (guard_id TEXT PRIMARY KEY);
         CREATE TABLE byok_activation_operation_guard (operation_token TEXT PRIMARY KEY, intent_id TEXT NOT NULL);
         CREATE TABLE byok_activation_worker_assertion (assertion_token TEXT PRIMARY KEY, operation_token TEXT NOT NULL, intent_id TEXT NOT NULL);
         CREATE TABLE byok_activation_postcondition (operation_token TEXT PRIMARY KEY, intent_id TEXT NOT NULL);
         CREATE TABLE byok_activation_suspension_postcondition (operation_token TEXT PRIMARY KEY, intent_id TEXT NOT NULL);
         CREATE TABLE byok_activation_transition_assertion (assertion_token TEXT PRIMARY KEY, guard_id TEXT NOT NULL);",
    )
    .unwrap();
    db.execute_batch(
        "INSERT INTO byok_activation_intent VALUES ('ia', 'tenant-a'), ('ib', 'tenant-b');
         INSERT INTO byok_activation_guard VALUES ('ga'), ('gb');
         INSERT INTO byok_activation_operation_guard VALUES ('opa', 'ia'), ('opb', 'ib');
         INSERT INTO byok_activation_worker_assertion VALUES ('wa', 'opa', 'ia'), ('wb', 'opb', 'ib');
         INSERT INTO byok_activation_transition_assertion VALUES ('ta', 'ga'), ('tb', 'gb');",
    )
    .unwrap();
    let count: i64 = db
        .query_row(BYOK_ACTIVATION_ORPHAN_SQL, [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "valid A/B fixture must have no indirect orphans");

    // One adversarial row per indirect relation: the worker mismatch has both
    // parents present but belongs to different intents, proving the global
    // query catches inconsistent ownership rather than only missing rows.
    db.execute_batch(
        "INSERT INTO byok_activation_operation_guard VALUES ('op-orphan', 'missing-intent');
         INSERT INTO byok_activation_worker_assertion VALUES ('w-mismatch', 'opb', 'ia');
         INSERT INTO byok_activation_postcondition VALUES ('p-orphan', 'missing-intent');
         INSERT INTO byok_activation_suspension_postcondition VALUES ('sp-orphan', 'missing-intent');
         INSERT INTO byok_activation_transition_assertion VALUES ('t-orphan', 'missing-guard');",
    )
    .unwrap();
    let count: i64 = db
        .query_row(BYOK_ACTIVATION_ORPHAN_SQL, [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 5,
        "all five indirect orphan relations must fail closed"
    );
}

#[test]
fn classification_gate_rejects_unknown_table_fail_closed() {
    let err = ensure_classification(&["tenant", "future_unclassified_table"]).unwrap_err();
    assert!(err.contains("future_unclassified_table"));
}

#[test]
fn runner_entitlement_reconcile_fence_is_registered_for_tenant_erasure() {
    let table = "runner_entitlement_reconcile_fence";
    assert!(ALL_TENANT_KEYED_TABLES.contains(&table));
    assert!(TENANT_ID_TABLES.contains(&table));
    assert_eq!(classification_count(table), 1);
    assert!(!RETAIN_SET.contains(&table));
}

#[test]
fn staging_synthetic_tenant_marker_is_classified_once_and_never_erased() {
    let table = "staging_load_test_synthetic_tenants";
    assert!(ALL_TENANT_KEYED_TABLES.contains(&table));
    assert!(RETAIN_SET.contains(&table));
    assert!(!TENANT_ID_TABLES.contains(&table));
    assert!(!NAMESPACE_TABLES.contains(&table));
    assert!(!SPECIAL_ERASE_TABLES.contains(&table));
    assert!(!CAS_PLANE_OWNED.contains(&table));
    assert_eq!(classification_count(table), 1);
}

#[test]
fn epoch_contract_tables_are_retained_and_new_intents_are_erased() {
    for table in [
        "audit_chain_epoch_ledger",
        "audit_chain_epoch",
        "audit_chain_archive_manifest",
    ] {
        assert!(
            ALL_TENANT_KEYED_TABLES.contains(&table),
            "{table} must be in the tenant-keyed registry"
        );
        assert!(RETAIN_SET.contains(&table), "{table} must be retained");
        assert!(!TENANT_ID_TABLES.contains(&table));
    }
    for table in [
        "stripe_checkout_ownership_ledger",
        "githugr_tenant_org_map",
        "gc_purge_intent",
        "cas_write_intent",
        "cas_reconciliation_intent",
    ] {
        assert!(
            ALL_TENANT_KEYED_TABLES.contains(&table),
            "{table} must be in the tenant-keyed registry"
        );
        assert!(
            TENANT_ID_TABLES.contains(&table),
            "{table} must be erased by tenant_id"
        );
        assert!(!RETAIN_SET.contains(&table));
    }
}

#[test]
fn erase_set_has_no_overlap_and_no_dupes() {
    // Duplicate guard (kept from the original) across the full erase-set:
    // tenant_id + namespace + the bespoke specials.
    let all: Vec<&str> = TENANT_ID_TABLES
        .iter()
        .chain(NAMESPACE_TABLES.iter())
        .chain(SPECIAL_ERASE_TABLES.iter())
        .copied()
        .collect();
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len(), "erase-set has a duplicate table");
}

#[test]
fn erase_set_never_touches_a_retain_table() {
    for t in TENANT_ID_TABLES
        .iter()
        .chain(NAMESPACE_TABLES.iter())
        .chain(SPECIAL_ERASE_TABLES.iter())
    {
        assert!(
            !RETAIN_SET.contains(t),
            "RETAIN-set table {t} must NEVER be in the D1 erase-set (ADR-S11-013)"
        );
    }
}

#[test]
fn tenant_linked_pii_tables_are_in_the_erase_set() {
    // Regression: these tenant_id-keyed tables carry tenant PII / seat PII /
    // spend state and MUST be erased on a DSR (GDPR Art.17). A removal would
    // silently leave tenant data behind after an erasure request.
    // `team_member` is the CF-1 worst-case (seat roster: raw Clerk user_id +
    // email_hash) that previously survived a "VerifiedComplete" attestation.
    for t in ["survey_responses", "tenant_quota", "team_member"] {
        assert!(
            TENANT_ID_TABLES.contains(&t),
            "{t} must be in the D1 erase-set (tenant PII)"
        );
        assert!(!RETAIN_SET.contains(&t), "{t} is not a retain-set table");
    }
}

/// #1889: classify every tenant-keyed table introduced by the runner billing
/// migrations. Conflict/checkout rows are operational and erased; immutable
/// terms/claim rows are historical billing authority and retained under the
/// existing ADR-S11-013 fiscal/billing-reconciliation basis. Each assertion
/// also checks the exact-one-bucket invariant so a future edit cannot silently
/// move one table out of the DSR registry.
#[test]
fn runner_billing_tables_have_exact_dsr_dispositions() {
    for table in ["usage_event_staging_conflicts", "runner_checkout_attempts"] {
        assert!(ALL_TENANT_KEYED_TABLES.contains(&table));
        assert!(
            TENANT_ID_TABLES.contains(&table),
            "{table} must be erased by tenant_id"
        );
        assert!(
            !RETAIN_SET.contains(&table),
            "{table} has no retention basis"
        );
        assert_eq!(classification_count(table), 1);
    }
    for table in [
        "runner_period_terms_snapshot",
        "runner_aggregate_event_claim",
    ] {
        assert!(ALL_TENANT_KEYED_TABLES.contains(&table));
        assert!(RETAIN_SET.contains(&table), "{table} must be retained");
        assert!(
            !TENANT_ID_TABLES.contains(&table),
            "{table} is retained billing evidence"
        );
        assert_eq!(classification_count(table), 1);
    }
}

/// Pin the four row-bearing migrations to the registry and their tenant scope.
/// The broad migration drift test catches future tables; this named regression
/// catches removal or reclassification of any #1889 table directly.
#[test]
fn runner_billing_migration_tables_remain_classified() {
    for (migration, tables) in [
        (
            "0134_usage_event_staging_conflicts.sql",
            ["usage_event_staging_conflicts"].as_slice(),
        ),
        (
            "0135_runner_aggregate_durable_state.sql",
            [
                "runner_period_terms_snapshot",
                "runner_aggregate_event_claim",
            ]
            .as_slice(),
        ),
        (
            "0137_runner_checkout_attempts.sql",
            ["runner_checkout_attempts"].as_slice(),
        ),
    ] {
        let path = format!(
            "{}/../../migrations/d1/{migration}",
            env!("CARGO_MANIFEST_DIR")
        );
        let sql = std::fs::read_to_string(path).unwrap();
        for table in tables {
            assert!(sql.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")));
            assert!(sql.contains("tenant_id TEXT NOT NULL"));
            assert!(ALL_TENANT_KEYED_TABLES.contains(table));
            assert_eq!(classification_count(table), 1);
        }
    }
}

/// B-089 retention guard. These rows are keyed by `tenant_id`, but they are
/// contractual billing evidence rather than operational tenant state:
/// observations feed the published report, measurements freeze the
/// eligibility decision, and the ledger records the credit/invoice settlement
/// and Stripe idempotency boundary. A DSR must therefore not delete them or
/// accidentally classify them as an erase-set child.
#[test]
fn sla_credit_pipeline_is_retained_and_not_deleted_by_dsr() {
    for table in [
        "sla_monthly_observations",
        "sla_monthly_measurements",
        "sla_credit_ledger",
    ] {
        assert!(ALL_TENANT_KEYED_TABLES.contains(&table));
        assert!(RETAIN_SET.contains(&table), "{table} must be retained");
        assert!(
            !TENANT_ID_TABLES.contains(&table),
            "{table} is contractual billing evidence and must not be deleted by the D1 DSR loop"
        );
        assert_eq!(classification_count(table), 1);
    }
}

/// Pin the migration-to-registry edge for B-089 explicitly. The broad drift
/// test below catches future omissions, while this adversarial check makes a
/// removal of one of the three migration 0117 entries fail with the exact
/// table name instead of relying on parser output from the whole directory.
#[test]
fn sla_credit_migration_tables_remain_classified() {
    let migration = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/d1/0117_sla_credit_ledger.sql"
    );
    let sql = std::fs::read_to_string(migration).unwrap();
    let found = extract_tenant_keyed_tables(&sql);
    for table in [
        "sla_monthly_observations",
        "sla_monthly_measurements",
        "sla_credit_ledger",
    ] {
        assert!(
            found.iter().any(|candidate| candidate == table),
            "migration 0117 must keep {table} tenant-scoped"
        );
        assert!(
            ALL_TENANT_KEYED_TABLES.contains(&table),
            "migration 0117 table {table} is missing from the production DSR registry"
        );
        assert_eq!(
            classification_count(table),
            1,
            "migration 0117 table {table} must have one DSR classification"
        );
    }
}

#[test]
fn dsr_redrive_envelope_is_retained_for_bounded_accountability() {
    let migration = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/d1/0145_dsr_dlq_redrive_authority.sql"
    );
    let sql = std::fs::read_to_string(migration).unwrap();
    let found = extract_tenant_keyed_tables(&sql);

    assert!(found
        .iter()
        .any(|table| table.as_str() == "dsr_dlq_redrive_envelopes"));
    assert!(ALL_TENANT_KEYED_TABLES.contains(&"dsr_dlq_redrive_envelopes"));
    assert!(RETAIN_SET.contains(&"dsr_dlq_redrive_envelopes"));
    assert!(!TENANT_ID_TABLES.contains(&"dsr_dlq_redrive_envelopes"));
    assert_eq!(classification_count("dsr_dlq_redrive_envelopes"), 1);
}

#[test]
fn rebuild_next_artifact_is_excluded_while_live_tables_remain_visible() {
    let rebuild = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations/d1/0144_cas_retention_compliance_metadata.sql"
    );
    let sql = std::fs::read_to_string(rebuild).unwrap();
    assert!(!extract_tenant_keyed_tables(&sql)
        .iter()
        .any(|table| table.as_str() == "cas_retention_next"));
    assert!(!extract_all_created_tables(&sql)
        .iter()
        .any(|table| table.as_str() == "cas_retention_next"));

    let migrations = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/d1");
    let mut live_tables = Vec::new();
    for entry in std::fs::read_dir(migrations).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("sql") {
            live_tables.extend(extract_tenant_keyed_tables(
                &std::fs::read_to_string(path).unwrap(),
            ));
        }
    }
    assert!(live_tables
        .iter()
        .any(|table| table.as_str() == "cas_retention"));
    assert!(live_tables
        .iter()
        .any(|table| table.as_str() == "dsr_dlq_redrive_envelopes"));

    // A genuinely live future table still reaches the fail-closed registry
    // gate; excluding rebuild artifacts cannot hide an ordinary tenant table.
    let future = extract_tenant_keyed_tables(
        "CREATE TABLE future_live_tenant_table (tenant_id TEXT NOT NULL);",
    );
    assert_eq!(future, vec!["future_live_tenant_table".to_owned()]);
    assert_eq!(classification_count(&future[0]), 0);
    assert!(ensure_classification(&[future[0].as_str()]).is_err());

    let live_next_sql = "CREATE TABLE future_live_next (tenant_id TEXT NOT NULL);";
    let live_next = extract_tenant_keyed_tables(live_next_sql);
    assert_eq!(live_next, vec!["future_live_next".to_owned()]);
    assert_eq!(
        extract_all_created_tables(live_next_sql),
        vec!["future_live_next".to_owned()]
    );
}

/// CF-1 in-code completeness gate: every table in the hand-maintained
/// registry is classified into EXACTLY ONE bucket (no unclassified, no
/// ambiguous double-classification). This is the registry half of the
/// always-on runtime gate in `erase()` and `verification_hash()`.
#[test]
fn every_registered_tenant_keyed_table_is_classified_exactly_once() {
    let gaps = unclassified_tenant_keyed_tables();
    assert!(
        gaps.is_empty(),
        "CF-1: these tenant-keyed tables are unclassified (0) or \
             ambiguously multi-classified (>1) — they would be silently \
             skipped on erase yet attested VerifiedComplete: {gaps:?}"
    );
    // Registry itself must be dupe-free.
    let mut sorted: Vec<&str> = ALL_TENANT_KEYED_TABLES.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        ALL_TENANT_KEYED_TABLES.len(),
        "ALL_TENANT_KEYED_TABLES has a duplicate"
    );
}

/// CF-1 LOAD-BEARING drift gate: parse `migrations/d1/*.sql` on disk and
/// assert EVERY live tenant-scoped table (keyed by tenant_id / namespace /
/// an opaque principal id / a subject hash) is present in the registry —
/// and therefore classified erase-or-retain by the test above. This is what
/// makes a FUTURE tenant-keyed migration impossible to land without a
/// conscious erase-vs-retain decision: add the table to a migration and
/// forget the adapter, and THIS test goes red.
#[test]
fn every_migrated_tenant_keyed_table_is_classified() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/d1");
    let mut found: Vec<String> = Vec::new();
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("CF-1 drift gate cannot read {dir}: {e}"));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let sql = std::fs::read_to_string(&path).unwrap();
        found.extend(extract_tenant_keyed_tables(&sql));
    }
    found.sort();
    found.dedup();
    assert!(
        !found.is_empty(),
        "CF-1 drift gate parsed ZERO tables — parser or path is broken"
    );

    let missing: Vec<&String> = found
        .iter()
        .filter(|t| !ALL_TENANT_KEYED_TABLES.contains(&t.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "CF-1: tenant-keyed table(s) exist in migrations/d1 but are NOT in \
             the DSR classification registry (a future table escaped erasure \
             classification — add to ALL_TENANT_KEYED_TABLES + classify \
             erase-vs-retain per ADR-S11-013): {missing:?}"
    );
}

/// The MIRROR of `every_migrated_tenant_keyed_table_is_classified`, and
/// the direction that gate never checked.
///
/// CF-1 walked migrations → registry: a table that exists on disk but is
/// unclassified fails. Nothing walked registry → migrations, so a name in
/// the registry that no migration ever creates was structurally invisible.
///
/// That is not hypothetical. `devenv_monthly_vcpu` was added to both
/// `TENANT_ID_TABLES` and `ALL_TENANT_KEYED_TABLES` in #1405 citing
/// "migr. 0094", but 0094 is `0094_runner_usage_counter.sql` and no
/// migration creates that table on `main` — it ships with the unmerged
/// #1397. Because `erase()` runs `count_then_delete` in a bare `for` loop
/// with `?` and NO transaction, the phantom sat at the boundary and turned
/// an Art.17 erasure into: delete the 16 operational tables before it,
/// error on the phantom, and never reach `byok_envelope`,
/// `tenant_byok_config`, `tenant_byok_secret`, the namespace tables,
/// `signup_*`, or the root `tenant` row. Operational data destroyed,
/// identity PII left intact, 500 returned, no attestation, no SEV-1.
///
/// Compared against EVERY `CREATE TABLE` in the migrations, not just the
/// tenant-keyed ones, so a registry entry whose key column the CF-1
/// heuristic does not recognise is not failed for the wrong reason.
#[test]
fn every_registry_table_is_actually_created_by_a_migration() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/d1");
    let mut created: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("CF-1 mirror gate cannot read {dir}: {e}"));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let sql = std::fs::read_to_string(&path).unwrap();
        created.extend(extract_all_created_tables(&sql));
    }
    created.sort();
    created.dedup();
    assert!(
        !created.is_empty(),
        "CF-1 mirror gate parsed ZERO CREATE TABLEs — parser or path is broken"
    );

    // EVERY registry, not just `ALL_TENANT_KEYED_TABLES`. `erase()` walks
    // `TENANT_ID_TABLES` and `NAMESPACE_TABLES` directly, so a phantom in
    // one of THOSE is what actually splits a sweep in half — checking only
    // the completeness registry would leave the load-bearing lists
    // unguarded. Caught by mutating the fix: re-adding the phantom to
    // `TENANT_ID_TABLES` alone left an ALL_TENANT_KEYED_TABLES-only
    // version of this test GREEN.
    let mut registry: Vec<&str> = ALL_TENANT_KEYED_TABLES.to_vec();
    for (_, set) in CLASSIFICATION_SETS {
        registry.extend_from_slice(set);
    }
    registry.sort_unstable();
    registry.dedup();

    let phantom: Vec<&&str> = registry
        .iter()
        .filter(|t| !created.iter().any(|c| c == *t))
        .collect();
    assert!(
        phantom.is_empty(),
        "CF-1 MIRROR: table(s) are classified in the DSR registry but no \
             migration in migrations/d1 creates them. A DSR erase runs its \
             deletes in a bare loop with no transaction, so a name that does \
             not exist aborts the sweep PART-WAY — destroying the tables \
             before it and leaving every table after it, including the \
             identity rows, intact. Remove the entry or land its migration: \
             {phantom:?}"
    );
}

#[test]
fn kind_is_d1() {
    // Construction needs a client; assert the const instead (kind() is
    // a pure const map). The orchestrator pins the canonical position.
    assert_eq!(BackendKind::D1.as_str(), "d1");
}

/// Strip SQL line (`--`) and block (`/* */`) comments so `CREATE TABLE`
/// inside doc-comments is not mistaken for a real DDL statement.
///
/// ⚠️ **Line comments are stripped FIRST, and the order is load-bearing.**
/// This helper used to run the block pass first, which made an unpaired
/// `/*` inside a LINE comment swallow the rest of the file: the scan for
/// the closing `*/` ran to EOF and everything after it disappeared. Two
/// migrations contain exactly that — `0090_dsr_tickets.sql:3` documents
/// the `/v1/privacy/dsr/*` route and `0061_adapter_oci_kv.sql` has the
/// same shape — so `dsr_tickets` and `adapter_oci_kv` were INVISIBLE to
/// the CF-1 drift gate that exists to notice unclassified tables. Both
/// happen to be classified already, so nothing was mis-erased; the hole
/// was in the gate, and any future table declared in either file (or any
/// file whose prose mentions a `/*` glob) would have escaped it silently.
fn strip_sql_comments(sql: &str) -> String {
    // Line comments FIRST: a `--` comment can contain an unpaired `/*`
    // (a route glob, a path), and stripping blocks first would treat it
    // as the start of a block that never ends.
    let mut no_line = String::with_capacity(sql.len());
    for line in sql.lines() {
        let l = match line.find("--") {
            Some(k) => &line[..k],
            None => line,
        };
        no_line.push_str(l);
        no_line.push('\n');
    }
    // then block comments (migrations are ASCII; byte scan is safe)
    let mut out = String::with_capacity(no_line.len());
    let bytes = no_line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // skip to closing */
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            i = (j + 2).min(bytes.len());
            out.push(' ');
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Every `CREATE TABLE` name in a migration, regardless of its columns.
///
/// The tenant-keyed extractor below answers "which tables need
/// classification"; this one answers "which tables exist at all", which is
/// what the mirror gate needs — a registry entry must correspond to a real
/// table even when the CF-1 key-column heuristic would not have flagged it.
fn extract_all_created_tables(sql: &str) -> Vec<String> {
    let clean = strip_sql_comments(sql);
    let mut out = Vec::new();
    let mut rest = clean.as_str();
    while let Some(pos) = rest.find("CREATE TABLE") {
        let after = rest[pos + "CREATE TABLE".len()..].trim_start();
        let after = {
            let lower = after.to_ascii_lowercase();
            if lower.starts_with("if not exists") {
                after["if not exists".len()..].trim_start()
            } else {
                after
            }
        };
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // A `*_new` or `*_next` table is transient only when this migration
        // drops its canonical table and renames the artifact into its place.
        if !name.is_empty() && !is_transient_rebuild_table(&clean, &name) {
            out.push(name);
        }
        rest = after;
    }
    out
}

/// Extract the names of `CREATE TABLE`s that have a tenant-scoping key
/// column. Transient table-rebuild artifacts (`*_new` and `*_next`) are
/// excluded only when the same migration drops the canonical table and
/// renames the artifact into its place.
fn extract_tenant_keyed_tables(sql: &str) -> Vec<String> {
    const KEY_COLS: &[&str] = &[
        "tenant_id",
        "namespace",
        "clerk_sub",
        "clerk_user_id",
        "email_hash",
        "recipient_hash",
    ];
    let clean = strip_sql_comments(sql);
    let mut out = Vec::new();
    let mut rest = clean.as_str();
    while let Some(pos) = rest.find("CREATE TABLE") {
        let after = rest[pos + "CREATE TABLE".len()..].trim_start();
        // optional IF NOT EXISTS (case-insensitive)
        let after = {
            let lower = after.to_ascii_lowercase();
            if lower.starts_with("if not exists") {
                after["if not exists".len()..].trim_start()
            } else {
                after
            }
        };
        // table name = up to first whitespace or '('
        let name_end = after
            .find(|c: char| c.is_whitespace() || c == '(')
            .unwrap_or(after.len());
        let name = after[..name_end].trim().to_string();
        // body = from first '(' to the first "); " statement terminator.
        // tenant_id/namespace are early columns, so truncating at the first
        // ");" is sufficient for key-column detection.
        let body = match after.find('(') {
            Some(open) => {
                let from_open = &after[open..];
                match from_open.find(");") {
                    Some(close) => &from_open[..close],
                    None => from_open,
                }
            }
            None => "",
        };
        if !name.is_empty()
            && !is_transient_rebuild_table(&clean, &name)
            && KEY_COLS.iter().any(|k| contains_word(body, k))
        {
            out.push(name);
        }
        rest = &after[name_end..];
    }
    out
}

fn is_transient_rebuild_table(sql: &str, name: &str) -> bool {
    let Some(canonical_name) = ["_new", "_next"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
    else {
        return false;
    };
    let normalized_sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let rename = format!("ALTER TABLE {name} RENAME TO {canonical_name}");
    let dropped_canonical = format!("DROP TABLE {canonical_name}");
    let has_rename = normalized_sql
        .split(';')
        .map(str::trim)
        .any(|statement| statement == rename);
    let has_drop = normalized_sql
        .split(';')
        .map(str::trim)
        .any(|statement| statement == dropped_canonical);
    has_rename && has_drop
}

/// `body.contains(key)` but only as a whole identifier token, so e.g.
/// `actor_email_hash` does NOT match `email_hash` and `kv_namespace_id`
/// does NOT match `namespace` (word char = ASCII alnum or `_`).
fn contains_word(body: &str, key: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let kb = key.as_bytes();
    let bb = body.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = body[i..].find(key) {
        let start = i + rel;
        let end = start + kb.len();
        let before_ok = start == 0 || !is_word(bb[start - 1] as char);
        let after_ok = end >= bb.len() || !is_word(bb[end] as char);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}
