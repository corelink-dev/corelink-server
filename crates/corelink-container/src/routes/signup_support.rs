use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use uuid::Uuid;

/// Extract the client IP for the per-IP rate-limit bucket.
pub(super) fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-corelink-client-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| "_no_ip".to_owned(), str::to_owned)
}

/// Pre-auth signup requests share a nil tenant dimension and are bucketed by IP.
pub(super) const PRE_AUTH_TENANT: Uuid = Uuid::nil();

/// Truncate the raw token to its first 32 chars for the audit emit's
/// `token_id_or_prefix` field — the route MUST never log the full
/// signature (HMAC values are operator-internal forensic data).
pub(super) fn token_prefix(token: &str) -> String {
    token.chars().take(32).collect()
}

/// Persisted pilot-signup record (one row in the `pilot_signups` D1
/// table per `migrations/d1/0053_pilot_signups.sql`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PilotSignupRecord {
    /// Surrogate UUID v7 PK.
    pub id: Uuid,
    /// Reserved tenant id (also UUID v7).
    pub tenant_id: Uuid,
    /// Pilot contact email.
    pub email: String,
    /// Free-text company name.
    pub company_name: String,
    /// Free-text tier hint.
    pub tier_hint: String,
    /// Free-text expected use-case.
    pub expected_use_case: String,
    /// Signup wall-clock (Unix epoch ms).
    pub signed_up_at_ms: u64,
    /// Source token id (16-hex random segment).
    pub token_id: String,
    /// Pilot lifecycle state — always `RESERVED` at insertion time.
    pub state: String,
}

/// Persistence trait for the pilot-signup store.
///
/// Production wiring binds this to D1 (`pilot_signups` table per
/// `migrations/d1/0053_pilot_signups.sql`). Native dev/CI uses
/// [`InMemorySignupStore`].
pub trait SignupStore: Send + Sync + core::fmt::Debug {
    /// Insert `record` into the store. If a row with the same `email`
    /// or `token_id` already exists, return the existing record
    /// (idempotent — the route returns the original tenant_id).
    ///
    /// # Errors
    ///
    /// Returns a static error string on store unavailability. The
    /// route converts to 503.
    fn insert_or_existing(
        &self,
        record: PilotSignupRecord,
    ) -> Result<PilotSignupRecord, &'static str>;

    /// Insert one reservation while carrying optional verified staging context.
    ///
    /// Existing stores preserve ordinary behavior through this default. The
    /// durable child implementation replaces it with one D1 batch containing
    /// both the reservation and context-derived ownership statement.
    fn insert_or_existing_with_context(
        &self,
        record: PilotSignupRecord,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<PilotSignupRecord, &'static str> {
        if context.is_some() {
            return Err("signup store: staging ownership requires durable D1");
        }
        self.insert_or_existing(record)
    }
}

/// In-memory pilot-signup store.
#[derive(Clone, Debug, Default)]
pub struct InMemorySignupStore {
    inner: Arc<Mutex<Vec<PilotSignupRecord>>>,
    injected_failure: Arc<Mutex<Option<&'static str>>>,
}

impl InMemorySignupStore {
    /// Construct a fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every persisted record in insertion order.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the inner mutex is poisoned.
    pub fn snapshot(&self) -> Result<Vec<PilotSignupRecord>, &'static str> {
        let g = self
            .inner
            .lock()
            .map_err(|_| "signup store mutex poisoned")?;
        Ok(g.clone())
    }

    /// Inject a static failure to drive the 503 regression.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the inner mutex is poisoned.
    pub fn inject_failure(&self, msg: &'static str) -> Result<(), &'static str> {
        let mut g = self
            .injected_failure
            .lock()
            .map_err(|_| "signup store mutex poisoned")?;
        *g = Some(msg);
        Ok(())
    }
}

impl SignupStore for InMemorySignupStore {
    fn insert_or_existing(
        &self,
        record: PilotSignupRecord,
    ) -> Result<PilotSignupRecord, &'static str> {
        let injected = *self
            .injected_failure
            .lock()
            .map_err(|_| "injected failure mutex poisoned")?;
        if let Some(msg) = injected {
            return Err(msg);
        }
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "signup store mutex poisoned")?;
        for existing in g.iter() {
            if existing.email == record.email || existing.token_id == record.token_id {
                return Ok(existing.clone());
            }
        }
        g.push(record.clone());
        Ok(record)
    }

    fn insert_or_existing_with_context(
        &self,
        record: PilotSignupRecord,
        context: crate::storage::staging_load_test_ownership::StagingLoadTestWriteContext<'_>,
    ) -> Result<PilotSignupRecord, &'static str> {
        if context.is_some() {
            return Err("signup store: staging ownership requires durable D1");
        }
        self.insert_or_existing(record)
    }
}
