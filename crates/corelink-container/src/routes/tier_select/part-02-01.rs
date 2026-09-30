#[derive(Default)]
struct MemStore {
    /// Tenants holding a live lock.
    locks: Mutex<HashSet<String>>,
    /// Tenants that have accepted the current DPA.
    dpa_accepted: HashSet<String>,
    /// Tenants with an active (cache-axis) subscription.
    active: HashSet<String>,
    /// Tenants with an active RUNNER subscription (separate axis).
    active_runner: HashSet<String>,
    /// Tenants holding a payable reservation across the Stripe call.
    pending: Mutex<HashSet<String>>,
    /// Persisted side-effects (for assertions).
    persisted: Mutex<Vec<String>>,
    /// Force `acquire_lock` to report "already held".
    lock_already_held: bool,
}

impl TierSelectStore for MemStore {
    async fn acquire_lock(&self, t: &str, _now: i64, _cid: &str) -> Result<bool, String> {
        if self.lock_already_held {
            return Ok(false);
        }
        let mut g = self.locks.lock().unwrap();
        Ok(g.insert(t.to_owned()))
    }
    async fn is_dpa_accepted(&self, t: &str, _v: &str) -> Result<bool, String> {
        Ok(self.dpa_accepted.contains(t))
    }
    async fn has_active_subscription(&self, t: &str) -> Result<bool, String> {
        Ok(self.active.contains(t) || self.pending.lock().unwrap().contains(t))
    }
    async fn reconcile_pending_checkout(&self, _t: &str, _now: i64) -> Result<(), String> {
        Ok(())
    }
    async fn has_active_runner_subscription(&self, t: &str) -> Result<bool, String> {
        Ok(self.active_runner.contains(t))
    }
    async fn reserve_pending_checkout(
        &self,
        t: &str,
        _tier: RequestedTier,
        _now: i64,
        _cid: &str,
    ) -> Result<(), String> {
        if self.active.contains(t) || !self.pending.lock().unwrap().insert(t.to_owned()) {
            return Err("payable reservation conflict".to_string());
        }
        Ok(())
    }
    async fn persist_pending_checkout(
        &self,
        t: &str,
        _tier: RequestedTier,
        _c: &CheckoutCreated,
        _now: i64,
        _cid: &str,
    ) -> Result<(), String> {
        self.persisted.lock().unwrap().push(format!("paid:{t}"));
        Ok(())
    }
    async fn abandon_pending_checkout(&self, t: &str, _cid: &str) -> Result<(), String> {
        self.pending.lock().unwrap().remove(t);
        Ok(())
    }
    async fn persist_free_active(&self, t: &str, _now: i64, _cid: &str) -> Result<(), String> {
        self.persisted.lock().unwrap().push(format!("free:{t}"));
        Ok(())
    }
    async fn release_lock(&self, t: &str, _cid: &str) -> Result<(), String> {
        self.locks.lock().unwrap().remove(t);
        Ok(())
    }
}

/// Checkout creator that records whether it was called (to prove the
/// DPA-first ordering: Stripe MUST NOT be hit when DPA is not accepted).
#[derive(Default)]
struct SpyCheckout {
    called: Mutex<bool>,
    fail: bool,
}
impl CheckoutCreator for SpyCheckout {
    async fn create(
        &self,
        _t: &str,
        _tier: RequestedTier,
        _s: &str,
        _c: &str,
    ) -> Result<CheckoutCreated, String> {
        *self.called.lock().unwrap() = true;
        if self.fail {
            return Err("stripe down".into());
        }
        Ok(CheckoutCreated {
            checkout_url: "https://checkout.stripe.com/c/pay/cs_test_123".into(),
            session_id: "cs_test_123".into(),
            stripe_customer_id: "cus_123".into(),
        })
    }
}

#[derive(Default)]
struct SpyAudit {
    events: Mutex<Vec<String>>,
    fail_on: Option<&'static str>,
}
impl TierSelectAudit for SpyAudit {
    async fn emit(&self, e: &'static str, _t: &str, _c: &str) -> Result<(), String> {
        if self.fail_on == Some(e) {
            return Err("audit sink down".into());
        }
        self.events.lock().unwrap().push(e.to_owned());
        Ok(())
    }
}

/// A D1 client that points at bogus CF credentials — the real Cloudflare
/// D1 REST API rejects the request (non-2xx), so every `query` fails.
/// Used to wire the REAL `TierSelectAuditAdapter` (not the `SpyAudit`
/// fake) down a real failure path for the L2 regression below. Mirrors
/// `auth_introspect.rs`'s `unreachable_d1` fault-injection helper and
/// `tier_select_audit.rs`'s own `failing_d1` test helper.
fn failing_d1() -> std::sync::Arc<crate::storage::d1_http::D1HttpClient> {
    let env = crate::storage::StorageEnv {
        r2_endpoint: "http://127.0.0.1:1".to_owned(),
        r2_access_key_id: "x".to_owned(),
        r2_secret_access_key: "x".to_owned(),
        r2_session_token: None,
        cloudflare_account_id: "definitely-not-a-real-account".to_owned(),
        cf_api_token: "definitely-not-a-real-token".to_owned(),
        d1_database_id: "definitely-not-a-real-db".to_owned(),
    };
    std::sync::Arc::new(
        crate::storage::d1_http::D1HttpClient::new(&env).expect("build D1HttpClient"),
    )
}

async fn run(
    store: MemStore,
    checkout: SpyCheckout,
    audit: SpyAudit,
    tier: RequestedTier,
) -> (
    Result<TierSelectResponse, TierSelectHttpError>,
    MemStore,
    SpyCheckout,
    SpyAudit,
) {
    let r = orchestrate_tier_select(
        &store,
        &checkout,
        &audit,
        "tenant-x",
        tier,
        "https://app/upgraded",
        "https://app/pricing",
        "v3",
        1_700_000_000_000,
        "corr-1",
    )
    .await;
    (r, store, checkout, audit)
}

#[tokio::test]
async fn paid_happy_path_returns_checkout_url_and_persists() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let (r, store, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Pro,
    )
    .await;
    let resp = r.unwrap();
    assert_eq!(
        resp.checkout_url.as_deref(),
        Some("https://checkout.stripe.com/c/pay/cs_test_123")
    );
    assert_eq!(resp.session_id, "cs_test_123");
    assert!(*checkout.called.lock().unwrap());
    assert_eq!(*store.persisted.lock().unwrap(), vec!["paid:tenant-x"]);
    assert!(
        store.locks.lock().unwrap().is_empty(),
        "lock released after success"
    );
}

#[tokio::test]
async fn dpa_not_accepted_blocks_before_stripe() {
    // INV-ONBOARD-DPA-FIRST: no DPA acceptance → 403 and Stripe is NEVER called.
    let (r, store, checkout, _a) = run(
        MemStore::default(),
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Pro,
    )
    .await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::DpaRequired);
    assert!(
        !*checkout.called.lock().unwrap(),
        "Stripe MUST NOT be called when DPA not accepted"
    );
    assert!(store.persisted.lock().unwrap().is_empty());
    assert!(
        store.locks.lock().unwrap().is_empty(),
        "lock released on DPA reject"
    );
}

#[tokio::test]
async fn lock_held_returns_409_without_touching_stripe() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.lock_already_held = true;
    let (r, _s, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Pro,
    )
    .await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::LockHeld);
    assert!(!*checkout.called.lock().unwrap());
}

#[tokio::test]
async fn already_active_blocks_without_touching_stripe() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.active.insert("tenant-x".into());
    let (r, _s, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Max,
    )
    .await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::AlreadyActive);
    assert!(!*checkout.called.lock().unwrap());
}

#[tokio::test]
async fn pending_checkout_blocks_different_tier_before_touching_stripe() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.pending.lock().unwrap().insert("tenant-x".into());
    let (r, _s, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Max,
    )
    .await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::AlreadyActive);
    assert!(!*checkout.called.lock().unwrap());
}

#[tokio::test]
async fn failed_stripe_call_abandons_payable_reservation() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let (r, store, checkout, _a) = run(
        store,
        SpyCheckout {
            fail: true,
            ..Default::default()
        },
        SpyAudit::default(),
        RequestedTier::Pro,
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        TierSelectHttpError::StripeUnavailable(Some("stripe down".to_owned()))
    );
    assert!(*checkout.called.lock().unwrap());
    assert!(store.pending.lock().unwrap().is_empty());
    assert!(store.locks.lock().unwrap().is_empty());
}

// ── WP6: runner is a SEPARATE entitlement axis ────────────────────────────
// A runner checkout must (a) create the Stripe session but NOT persist the
// cache tables (`tier_selections`/`stripe_checkout_sessions`) — those are
// one-row-per-tenant with a cache-only `tier` CHECK, so a runner write would
// clobber the cache tier + violate the CHECK; and (b) guard the runner axis
// independently of the cache axis.

#[tokio::test]
async fn runner_checkout_creates_session_but_does_not_persist_cache_tables() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let (r, store, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::RunnerPro,
    )
    .await;
    let resp = r.expect("runner checkout should succeed");
    assert_eq!(
        resp.checkout_url.as_deref(),
        Some("https://checkout.stripe.com/c/pay/cs_test_123"),
        "runner checkout still returns a Stripe Checkout URL"
    );
    assert!(
        *checkout.called.lock().unwrap(),
        "Stripe IS called for runner"
    );
    assert!(
        store.persisted.lock().unwrap().is_empty(),
        "runner checkout must NOT write the cache tier_selections / \
             stripe_checkout_sessions tables (clobber + CHECK-violation guard)"
    );
    assert!(
        store.locks.lock().unwrap().is_empty(),
        "lock released after runner success"
    );
}

#[tokio::test]
async fn cache_active_tenant_can_still_buy_runner() {
    // A tenant with an ACTIVE CACHE subscription is NOT blocked from buying
    // runner — the axes are independent (cache-active must not 409 a runner).
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.active.insert("tenant-x".into()); // active on the CACHE axis
    let (r, _s, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::RunnerStarter,
    )
    .await;
    assert!(
        r.is_ok(),
        "a cache-active tenant must be able to buy runner (separate axis)"
    );
    assert!(*checkout.called.lock().unwrap());
}

#[tokio::test]
async fn runner_active_tenant_blocked_from_second_runner() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.active_runner.insert("tenant-x".into()); // already has a runner sub
    let (r, _s, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::RunnerMax,
    )
    .await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::AlreadyActive);
    assert!(
        !*checkout.called.lock().unwrap(),
        "second runner subscription blocked before Stripe"
    );
}

#[tokio::test]
async fn runner_active_tenant_can_still_buy_cache() {
    // The mirror of the guard: an active RUNNER subscription must not block a
    // CACHE purchase, and the cache purchase persists normally.
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    store.active_runner.insert("tenant-x".into());
    let (r, store, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Pro,
    )
    .await;
    assert!(
        r.is_ok(),
        "a runner-active tenant can still buy a cache tier"
    );
    assert!(*checkout.called.lock().unwrap());
    assert_eq!(
        *store.persisted.lock().unwrap(),
        vec!["paid:tenant-x"],
        "cache purchase persists the cache tables as normal"
    );
}

#[tokio::test]
async fn stripe_failure_maps_to_502_and_releases_lock() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let checkout = SpyCheckout {
        fail: true,
        ..Default::default()
    };
    let (r, store, _c, _a) =
        run(store, checkout, SpyAudit::default(), RequestedTier::Starter).await;
    assert!(matches!(
        r.unwrap_err(),
        TierSelectHttpError::StripeUnavailable(_)
    ));
    assert!(store.persisted.lock().unwrap().is_empty());
    assert!(
        store.locks.lock().unwrap().is_empty(),
        "lock released on Stripe failure"
    );
}

#[tokio::test]
async fn audit_failure_aborts_before_any_mutation() {
    // Fail-CLOSED: a failing audit on the FIRST event aborts → 500, no lock, no Stripe.
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let audit = SpyAudit {
        fail_on: Some("tier_select_attempted"),
        ..Default::default()
    };
    let (r, store, checkout, _a) =
        run(store, SpyCheckout::default(), audit, RequestedTier::Pro).await;
    assert_eq!(r.unwrap_err(), TierSelectHttpError::Internal);
    assert!(!*checkout.called.lock().unwrap());
    assert!(store.persisted.lock().unwrap().is_empty());
    assert!(store.locks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn real_audit_adapter_durable_d1_failure_aborts_before_any_mutation() {
    // Regression for finding L2: the PRODUCTION `TierSelectAuditAdapter`
    // (not the `SpyAudit` test fake) wired to a D1 client whose queries
    // always fail must abort the orchestration BEFORE any mutation. This
    // proves the abort-before-mutation wiring binds on the real durable
    // adapter, not merely on a test fake — the bug this fix closes is
    // that the prod adapter was `tracing::info!(...); Ok(())`, i.e.
    // always-Ok, so this exact scenario could never abort in prod.
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let checkout = SpyCheckout::default();
    let audit = crate::routes::tier_select_audit::TierSelectAuditAdapter::new(failing_d1());

    let r = orchestrate_tier_select(
        &store,
        &checkout,
        &audit,
        "tenant-x",
        RequestedTier::Pro,
        "https://app/upgraded",
        "https://app/pricing",
        "v3",
        1_700_000_000_000,
        "corr-l2",
    )
    .await;

    assert_eq!(r.unwrap_err(), TierSelectHttpError::Internal);
    assert!(
        !*checkout.called.lock().unwrap(),
        "Stripe MUST NOT be called when the FIRST audit emit already fails"
    );
    assert!(
        store.persisted.lock().unwrap().is_empty(),
        "no persist may happen when the audit-before-mutation write fails"
    );
    assert!(
        store.locks.lock().unwrap().is_empty(),
        "lock must not be left held on an audit-emit abort"
    );
}

#[tokio::test]
async fn free_tier_activates_instantly_without_stripe() {
    let mut store = MemStore::default();
    store.dpa_accepted.insert("tenant-x".into());
    let (r, store, checkout, _a) = run(
        store,
        SpyCheckout::default(),
        SpyAudit::default(),
        RequestedTier::Free,
    )
    .await;
    let resp = r.unwrap();
    assert!(resp.checkout_url.is_none());
    assert!(
        !*checkout.called.lock().unwrap(),
        "free tier never calls Stripe"
    );
    assert_eq!(*store.persisted.lock().unwrap(), vec!["free:tenant-x"]);
}
