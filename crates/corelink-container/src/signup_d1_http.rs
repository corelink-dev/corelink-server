//! Production [`D1HttpSignupStore`] adapter: the **durable** D1-over-HTTP
//! backing store for `POST /v1/signup/pilot/{token}` (`routes/signup.rs`).
//!
//! # Why this exists
//!
//! `routes::signup::build_state_from_env()` — the production wiring — used
//! to unconditionally delegate to `build_state_with_key()`, which injects
//! `InMemorySignupStore`. That store is a per-process `Vec` behind a
//! `Mutex`: every pilot reservation was lost on the next container roll,
//! and because the container runs behind 5 regional Workers the advertised
//! 10-slot pilot cap + the email-idempotency guarantee only ever held
//! *within one instance*. Proven live: a `201 {"tenant_id": "...",
//! "state": "RESERVED"}` response with `COUNT(*) = 0` in both
//! `pilot_signups` and `pilot_tenants` in prod D1 (`corelink-prod-d1`).
//! This module is the durable replacement, wired ONLY into
//! `build_state_from_env()` (never `build_state_with_key()`, which stays
//! the dev/test in-memory path).
//!
//! # The sync↔async bridge
//!
//! [`SignupStore`] is synchronous (it is called from the axum handler via
//! a plain trait object; no async trait methods exist in that module). On
//! the native container D1 is reachable only via the **async**
//! [`D1HttpClient`]. Exactly like
//! [`crate::billing_d1_http::D1HttpBillingWriter::run`] and
//! [`crate::customer_d1::D1HttpCustomerDb::query`], the bridge drives the
//! async client through
//! `tokio::task::block_in_place(|| Handle::current().block_on(async { … }))`
//! — valid because the native server is `#[tokio::main]` (multi-thread).
//!
//! For unit-testability (a fake HTTP layer, no live D1 round-trip) the row
//! source is behind the [`SignupD1`] seam — mirrors
//! [`crate::customer_d1::CustomerD1`] exactly: production binds
//! [`D1HttpSignupDb`] (the async bridge over [`D1HttpClient`]); tests
//! supply a hermetic in-process fake.
//!
//! # Schema — single source of truth
//!
//! `migrations/d1/0053_pilot_signups.sql`. Columns transcribed verbatim:
//! `id, tenant_id, email, company_name, tier_hint, expected_use_case,
//! signed_up_at, activated_at, state, token_id`. Two UNIQUE indexes make
//! the idempotency contract load-bearing at the D1 layer:
//! `idx_pilot_signups_email` (on `email`) and `idx_pilot_signups_token_id`
//! (on `token_id`). This adapter mirrors the SELECT-then-INSERT-with-
//! unique-fallback strategy already proven against a real SQLite engine
//! by `tests/harness/d1_container.rs::SqliteSignupStore` (the live-D1
//! regression harness for this exact table) — same column list, same
//! idempotency query, same unique-constraint recovery path.
//!
//! # SECURITY / fail-CLOSED
//!
//! - **Parameterised SQL only** — every dynamic value is a positional
//!   `serde_json::Value` bind; no string interpolation.
//! - D1-over-REST binds numeric parameters as REAL, not INTEGER — the
//!   `signed_up_at` bind is wrapped `CAST(?N AS INTEGER)` (this repo's
//!   documented D1-REST gotcha; see `crates/corelink-container/src/
//!   storage/d1_http.rs` callers).
//! - **Fail-CLOSED:** any D1 transport / non-2xx / decode error maps to
//!   the static `"signup store: D1 ... failed"` error strings the
//!   `SignupStore` trait already contracts for → the route converts to
//!   503 `"signup store unavailable"`.
//! - **Secrets never logged:** the CF API bearer token lives inside
//!   [`D1HttpClient`] (which redacts it) and is never surfaced by this
//!   adapter's `Debug`.

use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::routes::signup::{PilotSignupRecord, SignupStore};
use crate::storage::{
    d1_http::{D1BatchStatement, D1HttpClient, D1Row},
    staging_load_test_ownership::{
        StagingLoadTestDisposition, StagingLoadTestResourceClass, StagingLoadTestScenario,
        StagingLoadTestWriteContext,
    },
};

/// Idempotency lookup — same email OR same token_id returns the existing
/// row verbatim. Binds (?1..?2): email, token_id.
const SQL_LOOKUP_EXISTING: &str = "SELECT id, tenant_id, email, company_name, tier_hint, \
     expected_use_case, signed_up_at, state, token_id \
     FROM pilot_signups WHERE email = ?1 OR token_id = ?2 LIMIT 1";

/// Canonical INSERT against `pilot_signups` (migration 0053). Binds
/// (?1..?9): id, tenant_id, email, company_name, tier_hint,
/// expected_use_case, signed_up_at (`CAST(?7 AS INTEGER)` — D1-over-REST
/// binds numbers as REAL), state, token_id.
const SQL_INSERT: &str = "INSERT INTO pilot_signups \
     (id, tenant_id, email, company_name, tier_hint, expected_use_case, signed_up_at, state, token_id) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, CAST(?7 AS INTEGER), ?8, ?9)";

// ─── Seam (sync trait surface over the async/blocking backend) ──────────────

/// Sync row-source seam over D1. The production impl ([`D1HttpSignupDb`])
/// bridges to the async [`D1HttpClient`]; tests supply a hermetic fake
/// (mirrors `customer_d1::CustomerD1` / `billing_d1_http`'s test layout).
pub trait SignupD1: Send + Sync + core::fmt::Debug {
    /// Run one parameterised statement; return the result rows (empty for
    /// non-`RETURNING` writes). `Err(String)` is a transport / decode /
    /// D1-level failure.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` on any D1 transport, HTTP, or decode failure.
    fn query(&self, sql: &str, binds: Vec<Value>) -> Result<Vec<D1Row>, String>;

    /// Execute the reservation and ownership statements in one D1 transaction.
    ///
    /// Legacy implementations do not claim batch atomicity. An ownership-aware
    /// store must fail closed when it receives `Some(context)` and this seam is
    /// unavailable.
    fn batch(&self, _statements: Vec<D1BatchStatement>) -> Result<Vec<Vec<D1Row>>, String> {
        Err("signup store: D1 batch unavailable".to_owned())
    }
}

/// Production [`SignupD1`] over the CF D1 REST API. Single documented
/// sync↔async bridge point (same pattern as
/// `billing_d1_http::D1HttpBillingWriter::run` /
/// `customer_d1::D1HttpCustomerDb::query`).
pub struct D1HttpSignupDb {
    d1: Arc<D1HttpClient>,
}

impl D1HttpSignupDb {
    /// Wire the row source over a shared [`D1HttpClient`].
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }
}

impl core::fmt::Debug for D1HttpSignupDb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("D1HttpSignupDb")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

impl SignupD1 for D1HttpSignupDb {
    fn query(&self, sql: &str, binds: Vec<Value>) -> Result<Vec<D1Row>, String> {
        let d1 = Arc::clone(&self.d1);
        let sql = sql.to_owned();
        // The native server is `#[tokio::main]` (multi-thread); we are
        // inside an async task (the axum handler), so `block_in_place`
        // hands the worker thread back to the scheduler while
        // `Handle::current().block_on` drives the D1 round-trip.
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.query(&sql, &binds).await })
        })
    }

    fn batch(&self, statements: Vec<D1BatchStatement>) -> Result<Vec<Vec<D1Row>>, String> {
        let d1 = Arc::clone(&self.d1);
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move { d1.batch(statements).await })
        })
        .map_err(|error| format!("signup store: D1 batch failed: {}", error.message))
    }
}

// ─── D1HttpSignupStore ────────────────────────────────────────────────────

/// Durable [`SignupStore`], backed by Cloudflare D1 over the REST API via
/// the [`SignupD1`] seam.
pub struct D1HttpSignupStore {
    db: Arc<dyn SignupD1>,
}

impl D1HttpSignupStore {
    /// Wire the store over an explicit [`SignupD1`] row source (production
    /// + tests).
    #[must_use]
    pub fn new(db: Arc<dyn SignupD1>) -> Self {
        Self { db }
    }

    /// Convenience constructor: wire over a fresh [`D1HttpSignupDb`] bridge
    /// for a shared [`D1HttpClient`]. Production wiring
    /// (`routes::signup::build_state_from_env`) uses this.
    #[must_use]
    pub fn from_d1_client(d1: Arc<D1HttpClient>) -> Self {
        Self::new(Arc::new(D1HttpSignupDb::new(d1)))
    }

    /// Row → [`PilotSignupRecord`] decode. Fail-CLOSED: a missing / wrong-
    /// typed required column is a static shape error rather than a
    /// fabricated default (mirrors `d1_container::lookup_existing`'s
    /// column list exactly, plus the D1-REST JSON-typed decode).
    fn row_to_record(row: &D1Row) -> Result<PilotSignupRecord, &'static str> {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("signup store: pilot_signups row missing/invalid id")?;
        let tenant_id = row
            .get("tenant_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("signup store: pilot_signups row missing/invalid tenant_id")?;
        let email = row
            .get("email")
            .and_then(Value::as_str)
            .ok_or("signup store: pilot_signups row missing email")?
            .to_owned();
        let company_name = row
            .get("company_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let tier_hint = row
            .get("tier_hint")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let expected_use_case = row
            .get("expected_use_case")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let signed_up_at_ms = row
            .get("signed_up_at")
            .and_then(Value::as_i64)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0);
        let state = row
            .get("state")
            .and_then(Value::as_str)
            .ok_or("signup store: pilot_signups row missing state")?
            .to_owned();
        let token_id = row
            .get("token_id")
            .and_then(Value::as_str)
            .ok_or("signup store: pilot_signups row missing token_id")?
            .to_owned();
        Ok(PilotSignupRecord {
            id,
            tenant_id,
            email,
            company_name,
            tier_hint,
            expected_use_case,
            signed_up_at_ms,
            token_id,
            state,
        })
    }

    /// Run [`SQL_LOOKUP_EXISTING`] and decode the first row, if any.
    fn lookup_existing(
        &self,
        email: &str,
        token_id: &str,
    ) -> Result<Option<PilotSignupRecord>, &'static str> {
        let rows = self
            .db
            .query(SQL_LOOKUP_EXISTING, vec![json!(email), json!(token_id)])
            .map_err(|_| "signup store: D1 lookup failed")?;
        rows.first().map(Self::row_to_record).transpose()
    }
}

impl core::fmt::Debug for D1HttpSignupStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The D1 client redacts its own CF API token; nothing secret is
        // surfaced here.
        f.debug_struct("D1HttpSignupStore")
            .field("db", &"[SignupD1]")
            .finish()
    }
}

/// Yield a DURABLE [`SignupStore`] from a D1-client construction result, or
/// REFUSE (fail-CLOSED) when the D1 client could not be built. Mirrors
/// `storage::d1_audit_sink::cas_audit_sink_from_d1` exactly — the caller
/// (`routes::signup::build_state_from_env`) passes
/// `D1HttpClient::new(&storage_env)` straight in, so the `Result` seam
/// makes the refusal deterministically testable (a durable store can't
/// force `reqwest` to fail).
///
/// # Errors
///
/// Returns `Err(String)` when `d1` is `Err` — the caller maps that to
/// `None` and the route is NOT mounted (never a silent in-memory
/// fallback).
pub fn signup_store_from_d1(
    d1: Result<D1HttpClient, String>,
) -> Result<Arc<dyn SignupStore>, String> {
    let d1 = d1
        .map(Arc::new)
        .map_err(|e| format!("durable signup store unavailable: D1 client build failed: {e}"))?;
    Ok(Arc::new(D1HttpSignupStore::from_d1_client(d1)))
}

impl SignupStore for D1HttpSignupStore {
    fn insert_or_existing(
        &self,
        record: PilotSignupRecord,
    ) -> Result<PilotSignupRecord, &'static str> {
        // 1) Idempotency lookup FIRST — same email OR token_id returns the
        //    existing row verbatim, avoiding a round-trip that would just
        //    bounce off the UNIQUE index on the common (retry) path.
        //    Mirrors the live-D1 regression harness's `SqliteSignupStore`
        //    exactly (`tests/harness/d1_container.rs`).
        if let Some(existing) = self.lookup_existing(&record.email, &record.token_id)? {
            return Ok(existing);
        }

        // 2) Insert the new reservation. Every field is CLONED (never
        //    moved) so `record` stays whole for the `Ok(record)` /
        //    fallback-lookup arms below.
        let insert_binds = vec![
            json!(record.id.to_string()),
            json!(record.tenant_id.to_string()),
            json!(record.email.clone()),
            json!(record.company_name.clone()),
            json!(record.tier_hint.clone()),
            json!(record.expected_use_case.clone()),
            json!(i64::try_from(record.signed_up_at_ms).unwrap_or(i64::MAX)),
            json!(record.state.clone()),
            json!(record.token_id.clone()),
        ];
        match self.db.query(SQL_INSERT, insert_binds) {
            Ok(_) => Ok(record),
            Err(e) => {
                let lowered = e.to_ascii_lowercase();
                if lowered.contains("unique") {
                    // A concurrent racer landed first between our lookup and
                    // our insert (or a follow-up path we haven't seen yet
                    // reused the email/token_id) — re-run the idempotent
                    // lookup and return that record instead of a fabricated
                    // error.
                    return self
                        .lookup_existing(&record.email, &record.token_id)?
                        .ok_or("signup store: race window: unique-fail without follow-up row");
                }
                tracing::warn!(error = %e, "signup_d1_http: insert failed");
                Err("signup store: D1 insert failed")
            }
        }
    }

    fn insert_or_existing_with_context(
        &self,
        record: PilotSignupRecord,
        context: StagingLoadTestWriteContext<'_>,
    ) -> Result<PilotSignupRecord, &'static str> {
        let Some(context) = context else {
            return self.insert_or_existing(record);
        };
        context
            .require_ownership_scenario(StagingLoadTestScenario::Signup)
            .map_err(|_| "signup store: staging ownership context rejected")?;

        // Synthetic retries must not reuse an existing reservation as a new
        // successful write. The ordinary `None` path retains its historical
        // idempotent lookup behavior above.
        if self
            .lookup_existing(&record.email, &record.token_id)?
            .is_some()
        {
            return Err("signup store: duplicate staging signup rejected");
        }

        let opaque_handle = record.id.to_string();
        let registration = context
            .ownership_registration(
                StagingLoadTestResourceClass::SignupArtifact,
                StagingLoadTestDisposition::Disposable,
                &opaque_handle,
            )
            .map_err(|_| "signup store: staging ownership registration rejected")?;
        let registered_at_ms = i64::try_from(record.signed_up_at_ms)
            .map_err(|_| "signup store: staging ownership timestamp rejected")?;
        let ownership = registration
            .d1_statement(registered_at_ms)
            .map_err(|_| "signup store: staging ownership registration rejected")?;
        let locator = signup_teardown_locator_statement(&context, &opaque_handle, registered_at_ms);

        let insert_binds = vec![
            json!(record.id.to_string()),
            json!(record.tenant_id.to_string()),
            json!(record.email.clone()),
            json!(record.company_name.clone()),
            json!(record.tier_hint.clone()),
            json!(record.expected_use_case.clone()),
            json!(registered_at_ms),
            json!(record.state.clone()),
            json!(record.token_id.clone()),
        ];
        self.db
            .batch(vec![
                D1BatchStatement::new(SQL_INSERT, insert_binds),
                ownership,
                locator,
            ])
            .map_err(|_| "signup store: staging signup batch failed")?;
        Ok(record)
    }
}

fn signup_teardown_locator_statement(
    context: &crate::storage::staging_load_test_admission::StagingLoadTestAdmissionContext,
    signup_id: &str,
    now_ms: i64,
) -> D1BatchStatement {
    let mut digest = Sha256::new();
    digest.update(b"corelink-staging-load-test-resource-receipt-v1\0");
    for part in [context.run_id().as_bytes(), context.scenario().as_str().as_bytes(), context.target_deployment_sha().as_bytes(), b"signup_artifact".as_slice(), signup_id.as_bytes(), b"disposable".as_slice()] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    D1BatchStatement::new(
        "INSERT INTO staging_load_test_teardown_locators (run_id, scenario, resource_class, receipt_ref, locator_kind, locator_json, registered_at_ms) VALUES (?1, ?2, 'signup_artifact', ?3, 'signup_pilot_v1', ?4, ?5)",
        vec![json!(context.run_id()), json!(context.scenario().as_str()), json!(hex::encode(digest.finalize())), json!(json!({ "signup_id": signup_id }).to_string()), json!(now_ms)],
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed these primitives"
)]
mod tests {
    use std::sync::Mutex;

    use uuid::Uuid;

    use super::*;

    /// Hermetic fake [`SignupD1`] — no live D1 round-trip. Simulates one
    /// pre-existing row (or none) and can be told to fail every call, so
    /// the store's happy-path / duplicate / fail-CLOSED branches are all
    /// exercisable without a network.
    #[derive(Debug, Default)]
    struct FakeSignupD1 {
        /// A row that already "exists" in the table — returned by both
        /// the lookup query and (as a UNIQUE-constraint error text) by an
        /// INSERT attempt.
        existing: Mutex<Option<D1Row>>,
        /// When true, every call fails with a plain transport error (no
        /// "unique" substring) — drives the non-duplicate error path.
        fail_transport: bool,
        /// Insert calls observed, for assertions.
        insert_calls: Mutex<u32>,
    }

    impl SignupD1 for FakeSignupD1 {
        fn query(&self, sql: &str, _binds: Vec<Value>) -> Result<Vec<D1Row>, String> {
            if self.fail_transport {
                return Err("transport down: connection reset".to_owned());
            }
            if sql.starts_with("SELECT") {
                let g = self.existing.lock().unwrap();
                return Ok(g.clone().into_iter().collect());
            }
            if sql.starts_with("INSERT") {
                *self.insert_calls.lock().unwrap() += 1;
                let g = self.existing.lock().unwrap();
                if g.is_some() {
                    return Err(
                        "D1 query errors: UNIQUE constraint failed: pilot_signups.email".to_owned(),
                    );
                }
                return Ok(vec![]);
            }
            Ok(vec![])
        }
    }

    fn record(email: &str, token_id: &str) -> PilotSignupRecord {
        PilotSignupRecord {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            email: email.to_owned(),
            company_name: "Co".to_owned(),
            tier_hint: "free".to_owned(),
            expected_use_case: "ci".to_owned(),
            signed_up_at_ms: 1_700_000_000_000,
            token_id: token_id.to_owned(),
            state: "RESERVED".to_owned(),
        }
    }

    fn row_from(record: &PilotSignupRecord) -> D1Row {
        let mut m = serde_json::Map::new();
        m.insert("id".to_owned(), json!(record.id.to_string()));
        m.insert("tenant_id".to_owned(), json!(record.tenant_id.to_string()));
        m.insert("email".to_owned(), json!(record.email));
        m.insert("company_name".to_owned(), json!(record.company_name));
        m.insert("tier_hint".to_owned(), json!(record.tier_hint));
        m.insert(
            "expected_use_case".to_owned(),
            json!(record.expected_use_case),
        );
        m.insert(
            "signed_up_at".to_owned(),
            json!(i64::try_from(record.signed_up_at_ms).unwrap()),
        );
        m.insert("state".to_owned(), json!(record.state));
        m.insert("token_id".to_owned(), json!(record.token_id));
        m
    }

    #[test]
    fn happy_path_insert_returns_the_record() {
        let fake = Arc::new(FakeSignupD1::default());
        let store = D1HttpSignupStore::new(fake.clone() as Arc<dyn SignupD1>);
        let rec = record("new@example.com", "tok-new");
        let out = store.insert_or_existing(rec.clone()).unwrap();
        assert_eq!(out, rec);
        assert_eq!(*fake.insert_calls.lock().unwrap(), 1);
    }

    #[test]
    fn duplicate_email_returns_the_original_row_not_the_new_one() {
        let original = record("dup@example.com", "tok-original");
        let fake = Arc::new(FakeSignupD1 {
            existing: Mutex::new(Some(row_from(&original))),
            ..Default::default()
        });
        let store = D1HttpSignupStore::new(fake.clone() as Arc<dyn SignupD1>);
        let attempted = record("dup@example.com", "tok-different");
        let out = store.insert_or_existing(attempted.clone()).unwrap();
        assert_eq!(out.id, original.id, "must return the ORIGINAL id");
        assert_eq!(
            out.tenant_id, original.tenant_id,
            "must return the ORIGINAL tenant_id"
        );
        assert_ne!(out.id, attempted.id);
        // The idempotency lookup short-circuits before any INSERT attempt.
        assert_eq!(*fake.insert_calls.lock().unwrap(), 0);
    }

    #[test]
    fn duplicate_token_id_returns_the_original_row() {
        let original = record("a@example.com", "shared-token");
        let fake = Arc::new(FakeSignupD1 {
            existing: Mutex::new(Some(row_from(&original))),
            ..Default::default()
        });
        let store = D1HttpSignupStore::new(fake as Arc<dyn SignupD1>);
        let attempted = record("b@example.com", "shared-token");
        let out = store.insert_or_existing(attempted).unwrap();
        assert_eq!(out.id, original.id);
    }

    #[test]
    fn transport_failure_is_a_static_error_not_a_fabricated_record() {
        let fake = Arc::new(FakeSignupD1 {
            fail_transport: true,
            ..Default::default()
        });
        let store = D1HttpSignupStore::new(fake as Arc<dyn SignupD1>);
        let err = store
            .insert_or_existing(record("x@example.com", "tok-x"))
            .unwrap_err();
        assert_eq!(err, "signup store: D1 lookup failed");
    }

    #[test]
    fn row_to_record_rejects_missing_required_column() {
        let mut row = serde_json::Map::new();
        row.insert("id".to_owned(), json!(Uuid::now_v7().to_string()));
        // tenant_id / email / state / token_id all missing.
        let err = D1HttpSignupStore::row_to_record(&row).unwrap_err();
        assert!(err.contains("pilot_signups"));
    }

    #[test]
    fn debug_never_leaks_the_underlying_client_marker_only() {
        let fake = Arc::new(FakeSignupD1::default());
        let store = D1HttpSignupStore::new(fake as Arc<dyn SignupD1>);
        let dbg = format!("{store:?}");
        assert!(dbg.contains("SignupD1"), "{dbg}");
    }

    // ── fail-CLOSED: `signup_store_from_d1` when D1 config is absent ──────────
    //
    // Mirrors `storage::d1_audit_sink`'s `cas_sink_fails_closed_when_d1_client_
    // unavailable` / `deployed_cas_builder_yields_durable_non_inmemory_sink`
    // exactly: no process-env mutation (this crate's established
    // no-set_var-on-StorageEnv-vars convention — see `routes/residency.rs` +
    // `storage::d1_audit_sink::tests::stub_env`), just direct `Result`
    // injection at the `D1HttpClient` construction boundary.

    /// A stub, fully-populated `StorageEnv` — struct literal (fields are
    /// `pub(crate)`), no process env touched.
    fn stub_storage_env() -> crate::storage::StorageEnv {
        crate::storage::StorageEnv {
            r2_endpoint: "https://acct.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "ak".to_owned(),
            r2_secret_access_key: "sk".to_owned(),
            cloudflare_account_id: "acct123".to_owned(),
            cf_api_token: "tok".to_owned(),
            d1_database_id: "db456".to_owned(),
        }
    }

    #[test]
    fn deployed_builder_yields_durable_non_inmemory_store_when_config_present() {
        // Exactly the construction `build_state_from_env` performs
        // (`signup_store_from_d1(D1HttpClient::new(&storage_env))`).
        let store = signup_store_from_d1(D1HttpClient::new(&stub_storage_env()))
            .expect("durable store builds when D1 config is present");
        let dbg = format!("{store:?}");
        assert!(
            dbg.contains("D1HttpSignupStore"),
            "must be the durable D1 store, got: {dbg}"
        );
        assert!(
            !dbg.contains("InMemory"),
            "must NOT be the volatile in-memory store, got: {dbg}"
        );
    }

    #[test]
    fn signup_store_fails_closed_when_d1_client_unavailable() {
        // Config absent/invalid (the caller's `D1HttpClient::new` failed) →
        // REFUSE (Err), never a silent in-memory fallback. The route builder
        // maps this to `None` so `/v1/signup/pilot` is not mounted.
        let err = signup_store_from_d1(Err("reqwest tls unavailable".to_owned()))
            .expect_err("must fail closed");
        assert!(
            err.contains("durable signup store unavailable"),
            "loud fail-closed message, got: {err}"
        );
    }
}
