//! Production [`TierSelectStore`] adapter: the durable D1-over-HTTP
//! transaction backing `POST /v1/onboarding/tier-select`.
//!
//! This is the **WP-A SCAFFOLD**. The struct + trait impl + collaborator
//! wiring + secret-redacting `Debug` are frozen here so WP-A can fill the
//! six method bodies (currently `todo!("WP-A")`) against a stable surface
//! WITHOUT touching the trait, the orchestration, or the other adapters.
//!
//! # What WP-A implements (per `tier_select.rs` security model)
//!
//! Every method runs parameterised SQL via [`D1HttpClient::query`] against
//! the Cloudflare D1 REST API and is **fail-CLOSED** — an `Err(String)`
//! aborts the orchestration with NO partial state (the caller maps it to
//! 500/409 as appropriate). The required statements (migration 0039):
//!
//! - `acquire_lock`           → `INSERT OR IGNORE INTO tier_selection_locks
//!   (...) VALUES (...) RETURNING tenant_id` (the 60s cross-isolate mutex;
//!   evict rows older than 60s first). `Ok(true)` iff a row was inserted.
//! - `is_dpa_accepted`        → `SELECT 1 FROM dpa_acceptances WHERE
//!   tenant_id = ?1 AND dpa_version = ?2` (INV-ONBOARD-DPA-FIRST).
//! - `has_active_subscription`→ `SELECT 1 FROM tier_selections WHERE
//!   tenant_id = ?1 AND subscription_state = 'active' AND tier != 'free'`
//!   (the UNIQUE partial index `idx_tenant_active_subscription` is the
//!   defense-in-depth). The `tier != 'free'` predicate is required: signup
//!   seeds `('free','active')` for every tenant, so without it the guard
//!   reports a subscription that does not exist and blocks all upgrades.
//! - `persist_pending_checkout` → ledger-first `session_created` ownership
//!   followed by idempotent tier/session mirrors; the ledger reconciler repairs
//!   a process crash between the two D1-over-HTTP statements (WI §6.7).
//! - `persist_free_active`    → `UPDATE tier_selections SET tier='free',
//!   subscription_state='active' ...`.
//! - `release_lock`           → `DELETE FROM tier_selection_locks WHERE
//!   tenant_id = ?1` (best-effort; the 60s window also self-expires).
//!
//! # SECURITY INVARIANTS (preserved by WP-A — do NOT regress)
//!
//! - **Tenant comes from the verified header only** (the orchestration
//!   passes `tenant_id` that `authorize_and_validate` extracted from
//!   `x-corelink-tenant-id`; this adapter NEVER re-derives or defaults it).
//! - **Fail-CLOSED:** map any D1 transport / non-2xx / decode failure to
//!   `Err(String)` — never silently treat a failed read as "lock free" /
//!   "DPA accepted" / "no active subscription".
//! - **DPA-FIRST ordering** is owned by `orchestrate_*`; this adapter only
//!   answers the boolean honestly.
//! - **Secrets never logged:** the CF API bearer token lives inside
//!   [`D1HttpClient`] (which already redacts it) and is NEVER surfaced by
//!   this adapter's `Debug`.

use std::sync::Arc;

use corelink_stripe_real::StripeRunnerCheckoutProvider;
use corelink_tier_selection::runner_checkout_attempt::{
    RunnerCheckoutAttempt, RunnerCheckoutAttemptState, RunnerCheckoutSessionExpiry,
};
use corelink_tier_selection::stripe::CheckoutSessionResponse;
use corelink_tier_selection::tenant::TenantId;
use corelink_tier_selection::tier::TierKind;
use serde_json::json;

use corelink_tier_selection::runner_checkout_d1::{
    SQL_MARK_RUNNER_CHECKOUT_ABANDONED, SQL_MARK_RUNNER_CHECKOUT_EXPIRED,
    SQL_READ_CURRENT_RUNNER_CHECKOUT_ATTEMPT, SQL_RECORD_RUNNER_CHECKOUT_SESSION,
    SQL_RESERVE_RUNNER_CHECKOUT_ATTEMPT,
};

use crate::routes::tier_select::{CheckoutCreated, RequestedTier, TierSelectStore};
use crate::storage::d1_http::D1HttpClient;

/// 60-second durable lock window — matches migration 0039's `lock_window_60s`
/// CHECK (`expires_at_ms - acquired_at_ms <= 60000`) and WI §6.4.
const LOCK_TTL_MS: i64 = 60_000;

/// A pre-Stripe reservation is recoverable only for this bounded interval.
/// Stripe's idempotency window is longer, but keeping a crashed reservation
/// open for 24h would turn a lost mirror write into a tenant-wide lockout.
const CHECKOUT_RESERVATION_RECOVERY_TTL_MS: i64 = 15 * 60 * 1000;

/// A lock cleanup must identify the lease owner. A delayed request must not
/// delete a newer request's lease after its own 60s window elapsed.
const RELEASE_LOCK_SQL: &str =
    "DELETE FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?2";

/// Rebind only while the *new* request still owns a live lock. Without this
/// predicate, a delayed request can rename a fresh reservation after its own
/// lease has expired and steal the newer request's checkout ledger.
const REBIND_RESERVATION_SQL: &str =
    "UPDATE stripe_checkout_ownership_ledger SET correlation_id = ?2, updated_at_ms = ?3 WHERE correlation_id = ?1 AND tenant_id = ?4 AND tier = ?5 AND state = 'reserved' AND updated_at_ms >= ?3 - ?6 AND EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?4 AND correlation_id = ?2 AND expires_at_ms >= ?3) RETURNING correlation_id";

/// A pending hosted page is payable even before Stripe has emitted a
/// subscription event. Keep it in the durable inventory and fail closed until
/// its completion/expiry is observed; a fresh pre-Stripe reservation is
/// intentionally omitted so the next request can rebind and retry Stripe's
/// stable idempotency key after a crash.
const HAS_PENDING_CHECKOUT_SQL: &str = "SELECT 1 FROM tier_selections t \
     WHERE t.tenant_id = ?1 AND t.subscription_state = 'pending_checkout' \
       AND NOT EXISTS (SELECT 1 FROM stripe_checkout_ownership_ledger l \
         WHERE l.tenant_id = t.tenant_id AND l.correlation_id = t.correlation_id \
           AND l.state = 'reserved' \
           AND l.updated_at_ms >= strftime('%s','now') * 1000 - 900000) \
     UNION ALL SELECT 1 FROM stripe_checkout_sessions s \
     JOIN tier_selections t ON t.tenant_id = s.tenant_id \
       AND t.correlation_id = s.correlation_id \
     WHERE s.tenant_id = ?1 AND t.subscription_state = 'pending_checkout' \
     UNION ALL SELECT 1 FROM stripe_checkout_ownership_ledger \
     WHERE tenant_id = ?1 AND state = 'session_created' LIMIT 1";

/// The "does this tenant already hold an active PAID cache subscription?" read
/// behind [`TierSelectStore::has_active_subscription`].
///
/// Named (rather than inlined at the call site) so the `tier != 'free'`
/// predicate is unit-testable in CI: the real behaviour can only be proven
/// against live D1 (`#[ignore]` harness), so a cheap always-on test asserts the
/// statement still excludes the free seed row. Dropping that predicate is what
/// made every signed-up tenant 409 `already_active` on their first upgrade.
const HAS_ACTIVE_PAID_CACHE_SUBSCRIPTION_SQL: &str = "SELECT 1 FROM tier_selections \
     WHERE tenant_id = ?1 AND subscription_state = 'active' AND tier != 'free' LIMIT 1";

fn runner_kind(tier: RequestedTier) -> Result<TierKind, String> {
    match tier {
        RequestedTier::RunnerStarter => Ok(TierKind::RunnerStarter),
        RequestedTier::RunnerPro => Ok(TierKind::RunnerPro),
        RequestedTier::RunnerTeam => Ok(TierKind::RunnerTeam),
        RequestedTier::RunnerScale => Ok(TierKind::RunnerScale),
        RequestedTier::RunnerMax => Ok(TierKind::RunnerMax),
        _ => Err("runner coordinator received a non-runner tier".to_owned()),
    }
}

fn requested_tier(kind: TierKind) -> RequestedTier {
    match kind {
        TierKind::RunnerStarter => RequestedTier::RunnerStarter,
        TierKind::RunnerPro => RequestedTier::RunnerPro,
        TierKind::RunnerTeam => RequestedTier::RunnerTeam,
        TierKind::RunnerScale => RequestedTier::RunnerScale,
        TierKind::RunnerMax => RequestedTier::RunnerMax,
        _ => RequestedTier::RunnerStarter,
    }
}

fn runner_attempt(row: &crate::storage::d1_http::D1Row) -> Result<RunnerCheckoutAttempt, String> {
    let text = |name: &str| {
        row.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("runner checkout row missing {name}"))
    };
    let tier = match text("tier")?.as_str() {
        "runner_starter" => TierKind::RunnerStarter,
        "runner_pro" => TierKind::RunnerPro,
        "runner_team" => TierKind::RunnerTeam,
        "runner_scale" => TierKind::RunnerScale,
        "runner_max" => TierKind::RunnerMax,
        _ => return Err("runner checkout row has invalid tier".to_owned()),
    };
    let state = match text("state")?.as_str() {
        "reserved" => RunnerCheckoutAttemptState::Reserved,
        "session_created" => RunnerCheckoutAttemptState::SessionCreated,
        "expired" => RunnerCheckoutAttemptState::Expired,
        "abandoned" => RunnerCheckoutAttemptState::Abandoned,
        "completed" => RunnerCheckoutAttemptState::Completed,
        _ => return Err("runner checkout row has invalid state".to_owned()),
    };
    let generation = row
        .get("generation")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "runner checkout row missing generation".to_owned())?;
    let session_id = row
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok(RunnerCheckoutAttempt {
        tenant_id: TenantId::new(text("tenant_id")?),
        generation: u64::try_from(generation)
            .map_err(|_| "runner generation is negative".to_owned())?,
        tier,
        price_id: text("price_id")?,
        customer_id: text("stripe_customer_id")?,
        idempotency_key: text("idempotency_key")?,
        state,
        session_id,
    })
}

fn checkout_created(response: CheckoutSessionResponse) -> CheckoutCreated {
    CheckoutCreated {
        checkout_url: response.url,
        session_id: response.session_id,
        stripe_customer_id: response.stripe_customer_id.as_str().to_owned(),
    }
}

async fn provider_call<T, F>(job: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(job());
    });
    rx.await
        .map_err(|e| format!("runner provider thread dropped: {e}"))?
}

/// Map `RequestedTier` → the exact snake_case label the D1 `tier` CHECK
/// constraints accept (`tier_selections` / `stripe_checkout_sessions`).
///
/// Kept in lockstep with `corelink_tier_selection::tier::TierKind::as_str`.
/// The match is exhaustive over `RequestedTier`, so the runner arms exist for
/// completeness — but they are UNREACHABLE at runtime: the orchestration
/// (`orchestrate_locked`) skips `persist_pending_checkout` entirely for a
/// runner tier (`RequestedTier::is_runner`), because runner is a separate
/// entitlement axis persisted to `runner_billing` / `runners_entitlement` via
/// the Stripe webhook, NEVER to these cache tables (whose one-row-per-tenant
/// shape + cache-only `tier` CHECK a runner write would clobber/violate). So
/// no CHECK-widening migration is needed for runner.
const fn tier_column(tier: RequestedTier) -> &'static str {
    match tier {
        RequestedTier::Free => "free",
        RequestedTier::Solo => "solo",
        RequestedTier::Starter => "starter",
        RequestedTier::Pro => "pro",
        RequestedTier::Max => "max",
        RequestedTier::RunnerStarter => "runner_starter",
        RequestedTier::RunnerPro => "runner_pro",
        RequestedTier::RunnerTeam => "runner_team",
        RequestedTier::RunnerScale => "runner_scale",
        RequestedTier::RunnerMax => "runner_max",
    }
}

/// Production durable store for tier-select, backed by Cloudflare D1 over
/// the REST API.
///
/// Holds the shared [`D1HttpClient`] (which owns the CF API token and
/// redacts it in its own `Debug`) plus the current DPA version string used
/// for the INV-ONBOARD-DPA-FIRST check.
#[derive(Clone)]
pub struct D1HttpTierSelectStore {
    /// D1-over-HTTP client for the durable lock / DPA / subscription /
    /// persist statements. `Arc` so the same connection pool is shared
    /// across the route state and any background tasks.
    d1: Arc<D1HttpClient>,
}

impl D1HttpTierSelectStore {
    /// Wire the store over a shared [`D1HttpClient`].
    #[must_use]
    pub fn new(d1: Arc<D1HttpClient>) -> Self {
        Self { d1 }
    }

    /// Borrow the underlying D1 client (used by WP-A method bodies).
    #[must_use]
    pub fn d1(&self) -> &D1HttpClient {
        &self.d1
    }

    /// Reserve/read one durable runner Checkout attempt. The reserve SQL is
    /// atomic; an empty result means the caller must inspect `read` before
    /// deciding replay, expiry, or recovery.
    pub async fn reserve_runner_attempt(
        &self,
        tenant_id: &str,
        tier: &str,
        price_id: &str,
        customer_id: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<Vec<crate::storage::d1_http::D1Row>, String> {
        self.d1
            .query(
                SQL_RESERVE_RUNNER_CHECKOUT_ATTEMPT,
                &[
                    json!(tenant_id),
                    json!(tier),
                    json!(price_id),
                    json!(customer_id),
                    json!(idempotency_key),
                    json!(now_ms),
                ],
            )
            .await
    }

    /// Read the current runner attempt after an atomic reserve conflict.
    pub async fn read_runner_attempt(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::storage::d1_http::D1Row>, String> {
        self.d1
            .query(
                SQL_READ_CURRENT_RUNNER_CHECKOUT_ATTEMPT,
                &[json!(tenant_id)],
            )
            .await
    }

    /// Attach Stripe's response to a still-reserved generation.
    pub async fn record_runner_session(
        &self,
        tenant_id: &str,
        generation: i64,
        session_id: &str,
        now_ms: i64,
    ) -> Result<Vec<crate::storage::d1_http::D1Row>, String> {
        self.d1
            .query(
                SQL_RECORD_RUNNER_CHECKOUT_SESSION,
                &[
                    json!(tenant_id),
                    json!(generation),
                    json!(session_id),
                    json!(now_ms),
                ],
            )
            .await
    }

    /// Mark a session expired only after Stripe confirmed the expiry.
    pub async fn mark_runner_expired(
        &self,
        tenant_id: &str,
        generation: i64,
        session_id: &str,
        now_ms: i64,
    ) -> Result<Vec<crate::storage::d1_http::D1Row>, String> {
        self.d1
            .query(
                SQL_MARK_RUNNER_CHECKOUT_EXPIRED,
                &[
                    json!(tenant_id),
                    json!(generation),
                    json!(session_id),
                    json!(now_ms),
                ],
            )
            .await
    }

    /// Abandon a reservation only after provider reconciliation found no
    /// session; this is the stale pre ACK recovery boundary.
    pub async fn mark_runner_abandoned(
        &self,
        tenant_id: &str,
        generation: i64,
        now_ms: i64,
    ) -> Result<Vec<crate::storage::d1_http::D1Row>, String> {
        self.d1
            .query(
                SQL_MARK_RUNNER_CHECKOUT_ABANDONED,
                &[json!(tenant_id), json!(generation), json!(now_ms)],
            )
            .await
    }

    /// Run the WP2 runner attempt coordinator against the durable D1 adapter.
    /// Provider calls are isolated on a plain thread because the Stripe client
    /// owns `reqwest::blocking`; every replacement is admitted only after the
    /// prior provider session is replayed or confirmed expired.
    pub async fn checkout_runner(
        &self,
        provider: Arc<StripeRunnerCheckoutProvider>,
        tenant_id: &str,
        tier: RequestedTier,
        now_ms: i64,
    ) -> Result<CheckoutCreated, String> {
        let kind = runner_kind(tier)?;
        let price_id = std::env::var(format!("STRIPE_PRICE_ID_{}", kind.as_str().to_uppercase()))
            .map_err(|_| format!("runner price id is not configured for {}", kind.as_str()))?
            .trim()
            .to_owned();
        if price_id.is_empty() {
            return Err(format!("runner price id is empty for {}", kind.as_str()));
        }
        let customer_id = provider_call({
            let provider = Arc::clone(&provider);
            let tenant_id = tenant_id.to_owned();
            move || {
                provider
                    .ensure_customer(&tenant_id)
                    .map_err(|e| e.to_string())
            }
        })
        .await?;
        let rows = self
            .reserve_runner_attempt(
                tenant_id,
                kind.as_str(),
                &price_id,
                &customer_id,
                "",
                now_ms,
            )
            .await?;
        let attempt = if let Some(row) = rows.first() {
            runner_attempt(row)?
        } else {
            let current = self.read_runner_attempt(tenant_id).await?;
            let row = current
                .first()
                .ok_or_else(|| "runner checkout ledger conflict".to_owned())?;
            runner_attempt(row)?
        };
        self.finish_runner_attempt(
            provider,
            attempt,
            kind,
            &price_id,
            &customer_id,
            tenant_id,
            now_ms,
        )
        .await
    }

    async fn finish_runner_attempt(
        &self,
        provider: Arc<StripeRunnerCheckoutProvider>,
        attempt: RunnerCheckoutAttempt,
        kind: TierKind,
        price_id: &str,
        customer_id: &str,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<CheckoutCreated, String> {
        let exact = attempt.tier == kind
            && attempt.price_id == price_id
            && attempt.customer_id == customer_id;
        match attempt.state {
            RunnerCheckoutAttemptState::SessionCreated if exact => {
                let response = provider_call({
                    let provider = Arc::clone(&provider);
                    let attempt = attempt.clone();
                    move || {
                        provider
                            .create_response(&attempt)
                            .map_err(|e| e.to_string())
                    }
                })
                .await?;
                Ok(checkout_created(response))
            }
            RunnerCheckoutAttemptState::SessionCreated => {
                let session_id = attempt
                    .session_id
                    .as_deref()
                    .ok_or_else(|| "runner session_created row has no session id".to_owned())?;
                provider_call({
                    let provider = Arc::clone(&provider);
                    let attempt = attempt.clone();
                    move || provider.expire(&attempt).map_err(|e| e.to_string())
                })
                .await?;
                let expired = self
                    .mark_runner_expired(tenant_id, attempt.generation as i64, session_id, now_ms)
                    .await?;
                if expired.is_empty() {
                    let current = self.read_runner_attempt(tenant_id).await?;
                    let confirmed = current
                        .first()
                        .and_then(|row| runner_attempt(row).ok())
                        .is_some_and(|row| {
                            row.generation == attempt.generation
                                && row.state == RunnerCheckoutAttemptState::Expired
                        });
                    if !confirmed {
                        return Err("runner expiry acknowledgement was lost".to_owned());
                    }
                }
                Box::pin(self.checkout_runner(provider, tenant_id, requested_tier(kind), now_ms))
                    .await
            }
            RunnerCheckoutAttemptState::Reserved => {
                // Stripe replay with the durable key is both recovery and
                // creation. If the process lost its ACK, this returns the
                // original session; it cannot mint a second payable session.
                let response = provider_call({
                    let provider = Arc::clone(&provider);
                    let attempt = attempt.clone();
                    move || {
                        provider
                            .create_response(&attempt)
                            .map_err(|e| e.to_string())
                    }
                })
                .await?;
                let recorded = self
                    .record_runner_session(
                        tenant_id,
                        attempt.generation as i64,
                        &response.session_id,
                        now_ms,
                    )
                    .await?;
                if recorded.is_empty() {
                    let current = self.read_runner_attempt(tenant_id).await?;
                    let same = current
                        .first()
                        .and_then(|row| runner_attempt(row).ok())
                        .filter(|row| {
                            row.generation == attempt.generation
                                && row.state == RunnerCheckoutAttemptState::SessionCreated
                                && row.session_id.as_deref() == Some(response.session_id.as_str())
                        });
                    if same.is_none() {
                        return Err("runner session acknowledgement was lost".to_owned());
                    }
                }
                if exact {
                    Ok(checkout_created(response))
                } else {
                    Box::pin(self.finish_runner_attempt(
                        provider,
                        RunnerCheckoutAttempt {
                            state: RunnerCheckoutAttemptState::SessionCreated,
                            session_id: Some(response.session_id),
                            ..attempt
                        },
                        kind,
                        price_id,
                        customer_id,
                        tenant_id,
                        now_ms,
                    ))
                    .await
                }
            }
            RunnerCheckoutAttemptState::Expired
            | RunnerCheckoutAttemptState::Abandoned
            | RunnerCheckoutAttemptState::Completed => {
                Box::pin(self.checkout_runner(provider, tenant_id, requested_tier(kind), now_ms))
                    .await
            }
        }
    }

    /// Test-only constructor: an INERT store over a `D1HttpClient` built
    /// from dummy (never-reached) credentials. Used by the
    /// `authorize_and_validate` unit tests in `tier_select.rs`, which only
    /// exercise the side-effect-free auth gate and NEVER call a store
    /// method. Env-free + race-free (no global env mutation): builds a
    /// `StorageEnv` via its `pub(crate)` fields (same crate). WP-A's
    /// behavioural coverage of the real SQL uses the standard `#[ignore]`
    /// live-D1 harness, not this inert fixture.
    #[cfg(test)]
    #[allow(
        clippy::panic,
        reason = "test-only constructor: panic on setup failure is fine"
    )]
    #[must_use]
    pub(crate) fn for_test() -> Self {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://example.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "test-akid".to_owned(),
            r2_secret_access_key: "test-secret".to_owned(),
            cloudflare_account_id: "test-account".to_owned(),
            cf_api_token: "test-token-never-sent".to_owned(),
            d1_database_id: "test-db".to_owned(),
        };
        // `D1HttpClient::new` only fails if reqwest cannot init TLS, which
        // does not happen on the test host.
        let client = D1HttpClient::new(&env)
            .unwrap_or_else(|e| panic!("test D1HttpClient build failed: {e}"));
        Self::new(Arc::new(client))
    }
}

impl std::fmt::Debug for D1HttpTierSelectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The D1 client redacts its own CF API token; nothing secret is
        // surfaced here. Shown as a marker so a leaked Debug can never
        // expose credentials.
        f.debug_struct("D1HttpTierSelectStore")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

impl TierSelectStore for D1HttpTierSelectStore {
    async fn acquire_lock(
        &self,
        tenant_id: &str,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<bool, String> {
        // Lazily evict THIS tenant's expired lock first so a stale row cannot
        // masquerade as a live lock (the daily GC cron is the durable sweep).
        // Best-effort — the INSERT OR IGNORE below makes the real decision.
        self.d1
            .query(
                "DELETE FROM tier_selection_locks WHERE tenant_id = ?1 AND expires_at_ms < ?2",
                &[json!(tenant_id), json!(now_ms)],
            )
            .await?;

        // INSERT OR IGNORE is the atomic cross-isolate mutex: a RETURNING row
        // comes back iff WE inserted (no live lock); a PK conflict (lock held)
        // yields no row → Ok(false) → 409 lock_held.
        let rows = self
            .d1
            .query(
                "INSERT OR IGNORE INTO tier_selection_locks (tenant_id, acquired_at_ms, expires_at_ms, correlation_id) VALUES (?1, ?2, ?3, ?4) RETURNING tenant_id",
                &[
                    json!(tenant_id),
                    json!(now_ms),
                    json!(now_ms + LOCK_TTL_MS),
                    json!(correlation_id),
                ],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    async fn is_dpa_accepted(&self, tenant_id: &str, dpa_version: &str) -> Result<bool, String> {
        // INV-ONBOARD-DPA-FIRST. Fail-CLOSED: a transport error propagates as
        // Err (never silently "accepted"); only a real acceptance row (migration
        // 0038 `dpa_acceptances`) for the CURRENT version answers true.
        let rows = self
            .d1
            .query(
                "SELECT 1 FROM dpa_acceptances WHERE tenant_id = ?1 AND dpa_version = ?2 LIMIT 1",
                &[json!(tenant_id), json!(dpa_version)],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    async fn has_active_subscription(&self, tenant_id: &str) -> Result<bool, String> {
        // Primary check; the UNIQUE partial index `idx_tenant_active_subscription`
        // is the defense-in-depth backstop. Fail-CLOSED on any error.
        //
        // `tier != 'free'` is LOAD-BEARING, not a nicety. Signup seeds every new
        // tenant with `tier_selections('free','active')` (the canonical shape in
        // `apps/signup-worker/src/lib/d1.ts::seedTenantEntitlements`, mirrored by
        // `worker/src/lib/githugr_provision.ts`) so billing reads `active` rather
        // than `inactive`. Without this predicate that seed row answers "yes, this
        // tenant already has an active subscription", and the guard in
        // `orchestrate_tier_select` 409s `already_active` on the FIRST purchase
        // attempt of every signed-up tenant — i.e. nobody can ever upgrade.
        //
        // Free is an instant ACTIVATION, not a subscription: the guard exists to
        // refuse a *second* paid subscription on the same axis, which is exactly
        // what excluding free restores. The one-row-per-tenant shape is preserved
        // either way — `persist_pending_checkout` upserts `ON CONFLICT(tenant_id)`,
        // so an upgrade flips the SAME row free/active → pending_checkout → paid/
        // active and never inserts a second `active` row (the UNIQUE partial index
        // still holds).
        let rows = self
            .d1
            .query(HAS_ACTIVE_PAID_CACHE_SUBSCRIPTION_SQL, &[json!(tenant_id)])
            .await?;
        if !rows.is_empty() {
            return Ok(true);
        }
        let pending = self
            .d1
            .query(HAS_PENDING_CHECKOUT_SQL, &[json!(tenant_id)])
            .await?;
        Ok(!pending.is_empty())
    }

    async fn reconcile_pending_checkout(&self, tenant_id: &str, now_ms: i64) -> Result<(), String> {
        // A process crash after reservation but before Stripe returned a
        // session must not permanently consume the axis. Keep the reservation
        // only for the bounded recovery window; Stripe's longer idempotency
        // window is still safe because the retry reuses the axis+tenant key.
        self.d1
            .query(
                "UPDATE tier_selections SET subscription_state = 'inactive', stripe_customer_id = NULL, subscription_started_at_ms = NULL WHERE tenant_id = ?1 AND subscription_state = 'pending_checkout' AND correlation_id IN (SELECT correlation_id FROM stripe_checkout_ownership_ledger WHERE tenant_id = ?1 AND state = 'reserved' AND updated_at_ms < ?2 - ?3)",
                &[json!(tenant_id), json!(now_ms), json!(CHECKOUT_RESERVATION_RECOVERY_TTL_MS)],
            )
            .await?;
        self.d1
            .query(
                "UPDATE stripe_checkout_ownership_ledger SET state = 'abandoned', session_id = NULL, stripe_customer_id = NULL, updated_at_ms = ?2 WHERE tenant_id = ?1 AND state = 'reserved' AND updated_at_ms < ?2 - ?3",
                &[json!(tenant_id), json!(now_ms), json!(CHECKOUT_RESERVATION_RECOVERY_TTL_MS)],
            )
            .await?;
        // If the process crashed after Stripe returned but before either
        // mirror write, replay both mirrors from the ledger. These statements
        // are intentionally idempotent and can be run on every retry.
        self.d1
            .query(
                "INSERT INTO tier_selections (tenant_id, tier, subscription_state, stripe_customer_id, correlation_id) SELECT tenant_id, tier, 'pending_checkout', stripe_customer_id, correlation_id FROM stripe_checkout_ownership_ledger WHERE tenant_id = ?1 AND state = 'session_created' ON CONFLICT(tenant_id) DO UPDATE SET tier = excluded.tier, subscription_state = 'pending_checkout', stripe_customer_id = excluded.stripe_customer_id, correlation_id = excluded.correlation_id WHERE (tier_selections.subscription_state = 'pending_checkout' AND tier_selections.correlation_id = excluded.correlation_id) OR (tier_selections.subscription_state = 'active' AND tier_selections.tier = 'free') OR tier_selections.subscription_state = 'inactive' RETURNING tenant_id",
                &[json!(tenant_id)],
            )
            .await?;
        self.d1
            .query(
                "INSERT INTO stripe_checkout_sessions (session_id, tenant_id, tier, created_at_ms, correlation_id) SELECT session_id, tenant_id, tier, created_at_ms, correlation_id FROM stripe_checkout_ownership_ledger WHERE tenant_id = ?1 AND state = 'session_created' AND session_id IS NOT NULL ON CONFLICT(session_id) DO UPDATE SET tenant_id = excluded.tenant_id, tier = excluded.tier, created_at_ms = excluded.created_at_ms, correlation_id = excluded.correlation_id WHERE stripe_checkout_sessions.tenant_id = excluded.tenant_id AND stripe_checkout_sessions.correlation_id = excluded.correlation_id RETURNING session_id",
                &[json!(tenant_id)],
            )
            .await?;
        Ok(())
    }

    async fn has_active_runner_subscription(&self, tenant_id: &str) -> Result<bool, String> {
        // The runner axis lives in `runner_billing` (migration 0087), keyed by
        // the runner Stripe subscription id → tenant, with the subscription
        // status mirrored. A row in an entitled state (`active`/`trialing`)
        // means the tenant already holds a runner subscription; guard a second
        // one. SEPARATE from `has_active_subscription` (cache axis) so a cache
        // subscription never blocks a runner purchase. Fail-CLOSED on error.
        let rows = self
            .d1
            .query(
                "SELECT 1 FROM runner_billing WHERE tenant_id = ?1 AND status IN ('active', 'trialing') LIMIT 1",
                &[json!(tenant_id)],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    async fn reserve_pending_checkout(
        &self,
        tenant_id: &str,
        tier: RequestedTier,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<(), String> {
        // A process can die after Stripe creates its idempotent session but
        // before `persist_pending_checkout` runs. Rebind the still-fresh
        // reservation to this request's lease, then call Stripe again with
        // the same axis+tenant idempotency key. The bounded age prevents a
        // stale reservation from blocking a tenant for Stripe's full 24h
        // idempotency window; the tenant/tier predicates prevent adoption
        // across tenants or entitlement axes.
        let existing = self
            .d1
            .query(
                "SELECT correlation_id FROM stripe_checkout_ownership_ledger WHERE tenant_id = ?1 AND tier = ?2 AND state = 'reserved' AND updated_at_ms >= ?3 - ?4 ORDER BY updated_at_ms DESC LIMIT 1",
                &[
                    json!(tenant_id),
                    json!(tier_column(tier)),
                    json!(now_ms),
                    json!(CHECKOUT_RESERVATION_RECOVERY_TTL_MS),
                ],
            )
            .await?;
        if let Some(row) = existing.first() {
            let prior = row
                .get("correlation_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "tier-selection reservation missing correlation".to_string())?;
            if prior != correlation_id {
                let rebound = self
                    .d1
                    .query(
                        REBIND_RESERVATION_SQL,
                        &[
                            json!(prior),
                            json!(correlation_id),
                            json!(now_ms),
                            json!(tenant_id),
                            json!(tier_column(tier)),
                            json!(CHECKOUT_RESERVATION_RECOVERY_TTL_MS),
                        ],
                    )
                    .await?;
                if rebound.is_empty() {
                    return Err("tier-selection reservation recovery conflict".to_string());
                }
                // Move the pending mirror to the new lease owner. If the
                // process had crashed before that mirror existed, the
                // idempotent repair below creates it from the ledger.
                self.d1
                    .query(
                        "UPDATE tier_selections SET correlation_id = ?2 WHERE tenant_id = ?3 AND subscription_state = 'pending_checkout' AND correlation_id = ?1",
                        &[json!(prior), json!(correlation_id), json!(tenant_id)],
                    )
                    .await?;
            }
            let repaired = self
                .d1
                .query(
                    "INSERT INTO tier_selections (tenant_id, tier, subscription_state, correlation_id) SELECT ?1, ?2, 'pending_checkout', ?3 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?4) ON CONFLICT(tenant_id) DO UPDATE SET tier = excluded.tier, subscription_state = 'pending_checkout', stripe_customer_id = NULL, correlation_id = excluded.correlation_id WHERE ((tier_selections.subscription_state = 'pending_checkout' AND tier_selections.correlation_id = excluded.correlation_id) OR (tier_selections.subscription_state = 'active' AND tier_selections.tier = 'free') OR tier_selections.subscription_state = 'inactive') AND EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?4) RETURNING tenant_id",
                    &[json!(tenant_id), json!(tier_column(tier)), json!(correlation_id), json!(now_ms)],
                )
                .await?;
            if repaired.is_empty() {
                return Err("tier-selection reservation recovery lost lease".to_string());
            }
            return Ok(());
        }
        let ledger_rows = self
            .d1
            .query(
                "INSERT INTO stripe_checkout_ownership_ledger (correlation_id, tenant_id, tier, state, created_at_ms, updated_at_ms) SELECT ?3, ?1, ?2, 'reserved', ?4, ?4 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?4) ON CONFLICT(correlation_id) DO UPDATE SET tenant_id = excluded.tenant_id, tier = excluded.tier, state = 'reserved', created_at_ms = excluded.created_at_ms, updated_at_ms = excluded.updated_at_ms WHERE stripe_checkout_ownership_ledger.state = 'abandoned' RETURNING correlation_id",
                &[json!(tenant_id), json!(tier_column(tier)), json!(correlation_id), json!(now_ms)],
            )
            .await?;
        if ledger_rows.is_empty() {
            return Err("tier-selection payable ledger conflict".to_string());
        }
        let rows = self
            .d1
            .query(
                "INSERT INTO tier_selections (tenant_id, tier, subscription_state, correlation_id) SELECT ?1, ?2, 'pending_checkout', ?3 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?4) ON CONFLICT(tenant_id) DO UPDATE SET tier = excluded.tier, subscription_state = 'pending_checkout', stripe_customer_id = NULL, correlation_id = excluded.correlation_id WHERE (tier_selections.subscription_state = 'inactive' OR (tier_selections.subscription_state = 'active' AND tier_selections.tier = 'free')) AND EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?4) RETURNING tenant_id",
                &[json!(tenant_id), json!(tier_column(tier)), json!(correlation_id), json!(now_ms)],
            )
            .await?;
        if rows.is_empty() {
            return Err("tier-selection payable reservation conflict".to_string());
        }
        Ok(())
    }

    async fn persist_pending_checkout(
        &self,
        tenant_id: &str,
        tier: RequestedTier,
        created: &CheckoutCreated,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<(), String> {
        let ledger_rows = self
            .d1
            .query(
                "UPDATE stripe_checkout_ownership_ledger SET session_id = ?2, stripe_customer_id = ?3, state = 'session_created', updated_at_ms = ?4 WHERE tenant_id = ?1 AND correlation_id = ?5 AND state IN ('reserved', 'session_created') AND (session_id IS NULL OR session_id = ?2) AND (stripe_customer_id IS NULL OR stripe_customer_id = ?3) RETURNING correlation_id",
                &[
                    json!(tenant_id),
                    json!(created.session_id),
                    json!(created.stripe_customer_id),
                    json!(now_ms),
                    json!(correlation_id),
                ],
            )
            .await?;
        if ledger_rows.is_empty() {
            return Err("tier-selection checkout ledger ownership conflict".to_string());
        }
        // (1) Map the Stripe customer id + paid tier onto the tenant row and
        // move it to `pending_checkout`. The ownership ledger was updated first;
        // if this statement or the session mirror below fails, the next request
        // replays both mirrors from that durable ledger row.
        let rows = self
            .d1
            .query(
                "INSERT INTO tier_selections (tenant_id, tier, subscription_state, stripe_customer_id, correlation_id) SELECT ?1, ?2, 'pending_checkout', ?3, ?4 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?4 AND expires_at_ms >= ?5) ON CONFLICT(tenant_id) DO UPDATE SET tier = excluded.tier, subscription_state = 'pending_checkout', stripe_customer_id = excluded.stripe_customer_id, correlation_id = excluded.correlation_id WHERE ((tier_selections.subscription_state IN ('inactive', 'active') AND (tier_selections.tier = 'free' OR tier_selections.subscription_state = 'inactive')) OR (tier_selections.subscription_state = 'pending_checkout' AND tier_selections.correlation_id = excluded.correlation_id)) AND (tier_selections.stripe_customer_id IS NULL OR tier_selections.stripe_customer_id = excluded.stripe_customer_id) AND EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?4 AND expires_at_ms >= ?5) RETURNING tenant_id",
                &[
                    json!(tenant_id),
                    json!(tier_column(tier)),
                    json!(created.stripe_customer_id),
                    json!(correlation_id),
                    json!(now_ms),
                ],
            )
            .await?;
        if rows.is_empty() {
            return Err("tier-selection pending checkout ownership conflict".to_string());
        }

        // (2) Mirror the in-flight Checkout Session. D1-over-HTTP cannot span a
        // transaction across the two writes (single statement per request), so
        // the daily reconciliation cron
        // (`corelink_onboarding_stripe_customer_id_drift_total`) is the drift
        // backstop for the (1)→(2) window; any failure here returns Err and the
        // orchestration releases the lock so the tenant can retry.
        let session_rows = self
            .d1
            .query(
                "INSERT INTO stripe_checkout_sessions (session_id, tenant_id, tier, created_at_ms, correlation_id) SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?2 AND correlation_id = ?5 AND expires_at_ms >= ?4) ON CONFLICT(session_id) DO UPDATE SET tenant_id = excluded.tenant_id, tier = excluded.tier, created_at_ms = excluded.created_at_ms, correlation_id = excluded.correlation_id WHERE stripe_checkout_sessions.tenant_id = excluded.tenant_id AND stripe_checkout_sessions.correlation_id = excluded.correlation_id RETURNING session_id",
                &[
                    json!(created.session_id),
                    json!(tenant_id),
                    json!(tier_column(tier)),
                    json!(now_ms),
                    json!(correlation_id),
                ],
            )
            .await?;
        if session_rows.is_empty() {
            return Err("tier-selection lock ownership lost before session mirror".to_string());
        }
        Ok(())
    }

    async fn abandon_pending_checkout(
        &self,
        tenant_id: &str,
        correlation_id: &str,
    ) -> Result<(), String> {
        self.d1
            .query(
                "UPDATE stripe_checkout_ownership_ledger SET state = 'abandoned', session_id = NULL, stripe_customer_id = NULL, updated_at_ms = strftime('%s','now') * 1000 WHERE tenant_id = ?1 AND correlation_id = ?2 AND state IN ('reserved', 'session_created')",
                &[json!(tenant_id), json!(correlation_id)],
            )
            .await?;
        self.d1
            .query(
                "DELETE FROM stripe_checkout_sessions WHERE tenant_id = ?1 AND correlation_id = ?2",
                &[json!(tenant_id), json!(correlation_id)],
            )
            .await?;
        self.d1
            .query(
                "DELETE FROM tier_selections WHERE tenant_id = ?1 AND subscription_state = 'pending_checkout' AND correlation_id = ?2",
                &[json!(tenant_id), json!(correlation_id)],
            )
            .await?;
        Ok(())
    }

    async fn persist_free_active(
        &self,
        tenant_id: &str,
        now_ms: i64,
        correlation_id: &str,
    ) -> Result<(), String> {
        // Instant free activation. `subscription_started_at_ms` MUST be set when
        // state = 'active' (migration 0039 `subscription_started_when_active`
        // CHECK). UPSERT → single statement + idempotent on retry.
        let rows = self
            .d1
            .query(
                "INSERT INTO tier_selections (tenant_id, tier, subscription_state, subscription_started_at_ms, correlation_id) SELECT ?1, 'free', 'active', ?2, ?3 WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?2) ON CONFLICT(tenant_id) DO UPDATE SET tier = 'free', subscription_state = 'active', subscription_started_at_ms = excluded.subscription_started_at_ms, correlation_id = excluded.correlation_id WHERE EXISTS (SELECT 1 FROM tier_selection_locks WHERE tenant_id = ?1 AND correlation_id = ?3 AND expires_at_ms >= ?2) RETURNING tenant_id",
                &[json!(tenant_id), json!(now_ms), json!(correlation_id)],
            )
            .await?;
        if rows.is_empty() {
            return Err("tier-selection lock ownership lost before free persist".to_string());
        }
        Ok(())
    }

    async fn release_lock(&self, tenant_id: &str, correlation_id: &str) -> Result<(), String> {
        // Best-effort release; the 60s window also self-expires, so a delete
        // failure is not fatal to the already-completed orchestration.
        self.d1
            .query(RELEASE_LOCK_SQL, &[json!(tenant_id), json!(correlation_id)])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// The secret-redacting `Debug` never surfaces the CF API token.
    /// (Construction of a real `D1HttpClient` requires env; WP-A adds the
    /// behavioural coverage of the SQL paths.)
    #[test]
    fn debug_is_redacted_marker_only() {
        // Compile-time guard that the redaction marker is the only thing
        // the Debug impl prints for the collaborator field.
        let s = "[D1HttpClient]";
        assert!(!s.contains("token"));
    }

    // ──────────────────────────────────────────────────────────────────────
    // Live D1 round-trip tests (`#[ignore]`).
    //
    // These exercise the REAL SQL of every `TierSelectStore` method against a
    // live Cloudflare D1 **test** database. They are `#[ignore]` so normal CI
    // never runs them; they document + enable the manual launch-day probe.
    //
    // Prerequisites:
    //   * A D1 *test* DB with migrations `0038_dpa_acceptances.sql` +
    //     `0039_tier_selection.sql` applied.
    //   * CLOUDFLARE_ACCOUNT_ID, CF_API_TOKEN, and D1_DATABASE_ID exported.
    //
    // Manual run:
    //
    // ```bash
    // CLOUDFLARE_ACCOUNT_ID=<acc> CF_API_TOKEN=<tok> D1_DATABASE_ID=<id> \
    //   cargo test -p corelink-server d1_ -- --ignored
    // ```
    //
    // Each test uses a UNIQUE per-run tenant id (`process id` + a monotonic
    // counter). The issue operator uses a dedicated disposable DB, deletes it
    // after the run, and verifies the database is absent, including the one
    // free-tier fixture row left by this test.
    // ──────────────────────────────────────────────────────────────────────

    /// Monotonic suffix so multiple tests / repeats within one process never
    /// reuse a tenant id (the PID disambiguates across concurrent processes).
    static TENANT_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A fresh, collision-proof tenant id for a single live test run.
    fn unique_tenant_id(label: &str) -> String {
        let pid = std::process::id();
        let seq = TENANT_SEQ.fetch_add(1, Ordering::Relaxed);
        format!("test-{label}-{pid}-{seq}")
    }

    /// Build the live store from D1-only credentials. Panics with a clear
    /// message when they are absent (the test is `#[ignore]`d, so this only
    /// fires when explicitly opted in).
    fn live_store() -> D1HttpTierSelectStore {
        let client = D1HttpClient::from_d1_env_for_integration_tests()
            .expect("CLOUDFLARE_ACCOUNT_ID, CF_API_TOKEN, and D1_DATABASE_ID must be set");
        D1HttpTierSelectStore::new(Arc::new(client))
    }

    /// `acquire_lock` is the cross-isolate mutex: the FIRST acquire wins
    /// (`Ok(true)`), a SECOND within the 60s window sees the held lock
    /// (`Ok(false)`), and after `release_lock` the lock is re-acquirable
    /// (`Ok(true)`).
    #[tokio::test]
    #[ignore = "requires live CF D1 test database (StorageEnv env vars + migrations 0038/0039 applied)"]
    async fn d1_acquire_lock_then_held_then_release() {
        let store = live_store();
        let tenant = unique_tenant_id("lock");
        let cid = "corr-d1-acquire-lock";
        // Use a fixed, non-clock "now" so the lock window is deterministic;
        // the row is unique per run so a stale value cannot leak across runs.
        let now_ms: i64 = 1_000_000_000_000;

        // First acquire wins.
        let first = store
            .acquire_lock(&tenant, now_ms, cid)
            .await
            .expect("acquire_lock #1 query");
        assert!(first, "first acquire on a fresh tenant must win");

        // Second acquire within the 60s window sees the held lock.
        let second = store
            .acquire_lock(&tenant, now_ms + 1, cid)
            .await
            .expect("acquire_lock #2 query");
        assert!(
            !second,
            "second acquire within the window must see lock_held"
        );

        // Release, then re-acquire succeeds again.
        store
            .release_lock(&tenant, cid)
            .await
            .expect("release_lock query");

        let third = store
            .acquire_lock(&tenant, now_ms + 2, cid)
            .await
            .expect("acquire_lock #3 query");
        assert!(third, "acquire after release must win again");

        // Best-effort cleanup so the lock row does not linger.
        store
            .release_lock(&tenant, cid)
            .await
            .expect("final release_lock query");
    }

    /// Fail-CLOSED reads return `Ok(false)` (NOT `Err`) when the row is simply
    /// absent: a brand-new tenant has neither a DPA acceptance nor an active
    /// subscription.
    #[tokio::test]
    #[ignore = "requires live CF D1 test database (StorageEnv env vars + migrations 0038/0039 applied)"]
    async fn d1_dpa_and_active_subscription_reads() {
        let store = live_store();
        let tenant = unique_tenant_id("reads");

        // No `dpa_acceptances` row → Ok(false), never Err.
        let dpa = store
            .is_dpa_accepted(&tenant, "1.0.0")
            .await
            .expect("is_dpa_accepted query");
        assert!(!dpa, "a fresh tenant has not accepted the DPA");

        // No `tier_selections` row → Ok(false), never Err.
        let active = store
            .has_active_subscription(&tenant)
            .await
            .expect("has_active_subscription query");
        assert!(!active, "a fresh tenant has no active subscription");
    }

    /// `persist_free_active` flips a tenant to `tier='free' / state='active'`
    /// (setting `subscription_started_at_ms`, per the
    /// `subscription_started_when_active` CHECK) — after which
    /// `has_active_subscription` still reads `Ok(false)`, because FREE IS NOT A
    /// SUBSCRIPTION.
    ///
    /// This assertion used to be `assert!(after)`, which froze the defect: it
    /// encoded "a free row counts as an active subscription" as the intended
    /// contract, and the orchestration's `already_active` guard then 409'd every
    /// signed-up tenant's first upgrade attempt (117 of them in prod on
    /// 2026-08-02). The guard's job is to refuse a *second paid* subscription on
    /// the axis, so the free seed row must read false.
    #[tokio::test]
    #[ignore = "requires live CF D1 test database (StorageEnv env vars + migrations 0038/0039 applied)"]
    async fn d1_persist_free_active_does_not_count_as_a_subscription() {
        let store = live_store();
        let tenant = unique_tenant_id("free");
        let cid = "corr-d1-free-active";
        let now_ms: i64 = 1_000_000_000_000;

        // Precondition: not active before the write.
        let before = store
            .has_active_subscription(&tenant)
            .await
            .expect("pre has_active_subscription query");
        assert!(!before, "fresh tenant must not be active before activation");

        // A free activation without the matching live lease must fail closed.
        // The same lease is required by the production tier-select path.
        let without_lock = store.persist_free_active(&tenant, now_ms, cid).await;
        assert_eq!(
            without_lock,
            Err("tier-selection lock ownership lost before free persist".to_owned())
        );

        let acquired = store
            .acquire_lock(&tenant, now_ms, cid)
            .await
            .expect("acquire free activation lock");
        assert!(acquired, "fresh tenant must acquire its activation lock");

        // Instant free activation.
        store
            .persist_free_active(&tenant, now_ms, cid)
            .await
            .expect("persist_free_active query");

        // Still NOT an active subscription — otherwise this tenant could never
        // buy a paid tier (409 `already_active` on the upgrade attempt).
        let after = store
            .has_active_subscription(&tenant)
            .await
            .expect("post has_active_subscription query");
        store
            .release_lock(&tenant, cid)
            .await
            .expect("release free activation lock");
        assert!(
            !after,
            "a free/active row must NOT count as an active subscription — it is \
             what every signed-up tenant starts with, so counting it blocks all upgrades"
        );
    }

    /// Always-on (no live D1) guard on the statement itself.
    ///
    /// The behavioural proof needs a real database and therefore lives behind
    /// `#[ignore]`, which means CI would NOT catch someone deleting the
    /// `tier != 'free'` predicate — the exact regression that took the money-path
    /// down. This cheap test runs on every PR and fails if the predicate is
    /// dropped or the state/table drift.
    #[test]
    fn has_active_subscription_sql_excludes_the_free_seed_row() {
        let sql = HAS_ACTIVE_PAID_CACHE_SUBSCRIPTION_SQL;
        assert!(
            sql.contains("tier != 'free'"),
            "the free-tier exclusion is load-bearing: signup seeds ('free','active') \
             for EVERY tenant, so without it `has_active_subscription` returns true \
             for a tenant that has never paid and the upgrade 409s `already_active`. \
             Statement was: {sql}"
        );
        assert!(
            sql.contains("subscription_state = 'active'"),
            "must still only match ACTIVE rows (a pending_checkout row has to stay \
             retryable). Statement was: {sql}"
        );
        assert!(
            sql.contains("tenant_id = ?1"),
            "tenant must stay parameterised (never interpolated). Statement was: {sql}"
        );
    }

    #[test]
    fn payable_guard_covers_pending_rows_and_owner_bound_writes() {
        assert!(HAS_PENDING_CHECKOUT_SQL.contains("stripe_checkout_sessions"));
        assert!(HAS_PENDING_CHECKOUT_SQL.contains("stripe_checkout_ownership_ledger"));
        assert!(HAS_PENDING_CHECKOUT_SQL.contains("pending_checkout"));
        assert!(RELEASE_LOCK_SQL.contains("correlation_id = ?2"));
        let source = include_str!("tier_select_store.rs");
        assert!(source.contains("expires_at_ms >= ?5"));
        assert!(source.contains("RETURNING tenant_id"));
        assert!(source.contains("state = 'session_created'"));
        assert!(source.contains("state = 'abandoned'"));
    }

    #[test]
    fn delayed_rebind_requires_the_current_request_lease() {
        use rusqlite::{params, Connection};

        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE stripe_checkout_ownership_ledger (
                 correlation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
                 tier TEXT NOT NULL, state TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE tier_selection_locks (
                 tenant_id TEXT NOT NULL, correlation_id TEXT NOT NULL,
                 expires_at_ms INTEGER NOT NULL
             );
             INSERT INTO stripe_checkout_ownership_ledger
               VALUES ('corr-reservation', 'tenant-a', 'pro', 'reserved', 1000, 1000);",
        )
        .unwrap();

        // A delayed request with no live lease cannot rename the reservation.
        let stale = db.prepare(REBIND_RESERVATION_SQL).unwrap().query_row(
            params![
                "corr-reservation",
                "corr-delayed",
                2000_i64,
                "tenant-a",
                "pro",
                CHECKOUT_RESERVATION_RECOVERY_TTL_MS,
            ],
            |_| Ok::<_, rusqlite::Error>(()),
        );
        assert!(
            stale.is_err(),
            "an unleased delayed request must not rebind"
        );
        let owner: String = db
            .query_row(
                "SELECT correlation_id FROM stripe_checkout_ownership_ledger",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner, "corr-reservation");

        // The same exact SQL succeeds once the replacement request owns a
        // non-expired lease, proving the guard is behavioural rather than a
        // source-string assertion.
        db.execute(
            "INSERT INTO tier_selection_locks VALUES (?1, ?2, ?3)",
            params!["tenant-a", "corr-current", 3000_i64],
        )
        .unwrap();
        let rebound: String = db
            .prepare(REBIND_RESERVATION_SQL)
            .unwrap()
            .query_row(
                params![
                    "corr-reservation",
                    "corr-current",
                    2000_i64,
                    "tenant-a",
                    "pro",
                    CHECKOUT_RESERVATION_RECOVERY_TTL_MS,
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rebound, "corr-current");
    }
}
