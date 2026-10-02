/// Validate the request envelope: auth → verified tenant → typed tier.
/// This is the fully-implemented, side-effect-free security gate that
/// every request crosses BEFORE any D1/Stripe work. Returned to the
/// handler (PR2) which performs the durable orchestration.
fn authorize_and_validate(
    state: &TierSelectRouteState,
    headers: &HeaderMap,
    body: &TierSelectRequest,
) -> Result<(String, RequestedTier), TierSelectHttpError> {
    // (1) internal-auth boundary (constant-time).
    verify_internal_auth(headers, &state.internal_auth_key)?;
    // (2) verified tenant (fail-CLOSED; never from the body).
    let tenant_id = extract_verified_tenant(headers)?;
    // (3) tier parse + enterprise routing.
    let tier = match RequestedTier::parse_self_serve(&body.tier) {
        ParsedTier::Tier(t) => t,
        ParsedTier::Enterprise => return Err(TierSelectHttpError::UseInquiryForm),
        ParsedTier::Invalid => return Err(TierSelectHttpError::BadRequest),
    };
    // (4) F6/F10: redirect URLs must point to a CoreLink-owned origin.
    // The Worker normally builds these server-side from a trusted origin, but
    // an authenticated user can POST directly to the Worker bypassing the
    // admin-ui and supply arbitrary https:// URLs.  Validate both URLs against
    // the host allowlist (parse URL → assert host ∈ ALLOWED_REDIRECT_HOSTS,
    // reject userinfo/@/explicit ports).  Fail-CLOSED: any violation → 400,
    // structured tracing warning.  The https scheme check is also enforced
    // inside `validate_redirect_url`.
    if tier.is_paid() {
        validate_redirect_url(&body.success_url, "success_url")?;
        validate_redirect_url(&body.cancel_url, "cancel_url")?;
    }
    Ok((tenant_id, tier))
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP transport (WP-E) — axum handler + router.
//
// This layer is deliberately thin: every security + durability invariant
// lives in `authorize_and_validate` (the fail-CLOSED gate) and
// `orchestrate_tier_select` (the durable ordering). The handler only adapts
// bytes ⇄ typed values and the typed error ⇄ HTTP status, so it has no
// branch a test of the gate/orchestration doesn't already cover.
// ──────────────────────────────────────────────────────────────────────────────

/// `POST /v1/onboarding/tier-select`.
///
/// The body is taken as raw [`Bytes`] and parsed here rather than via the
/// `Json` extractor so that EVERY failure — malformed JSON, an unknown field
/// (`deny_unknown_fields`), or a typed orchestration error — returns the one
/// `{ "error": <code> }` envelope instead of axum's default rejection shape.
/// The route is internal-only (mounted behind the Durable Object + the
/// constant-time `X-Corelink-Internal-Auth` gate) and axum's default body
/// limit applies, so parsing the envelope before the auth check inside
/// `authorize_and_validate` is bounded; auth is still step 1 of that gate and
/// nothing downstream runs on a failed gate.
pub async fn handle(
    State(state): State<TierSelectRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Parse the envelope (`deny_unknown_fields` blocks a smuggled tenant_id);
    // any parse error is a 400 in the canonical shape.
    let req: TierSelectRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => return TierSelectHttpError::BadRequest.into_response(),
    };

    // Fail-CLOSED gate: internal-auth (constant-time) → verified tenant
    // (header-only, never the body) → typed tier (+ https redirect check).
    let (tenant_id, tier) = match authorize_and_validate(&state, &headers, &req) {
        Ok(parts) => parts,
        Err(e) => return e.into_response(),
    };

    // Time-sortable correlation id threading the request through the audit
    // chain + durable store (mirrors the crate's `Uuid::now_v7` convention).
    let correlation_id = Uuid::now_v7().to_string();
    let now_ms = unix_millis_now();

    // Runner is a separate entitlement axis. Route it through the durable
    // WP2 attempt coordinator so a lost Stripe ACK replays its key and a plan
    // change expires the prior session before any replacement is created.
    if tier.is_runner() {
        return match orchestrate_runner_tier_select(
            &state,
            &tenant_id,
            tier,
            &req.success_url,
            &req.cancel_url,
            &state.current_dpa_version,
            now_ms,
            &correlation_id,
        )
        .await
        {
            Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
            Err(e) => e.into_response(),
        };
    }

    // The durable orchestration owns the load-bearing order (audit-before-
    // mutate → lock → DPA-first → active-sub → checkout → persist → release);
    // map its typed result to HTTP.
    match orchestrate_tier_select(
        &*state.store,
        &*state.checkout,
        &*state.audit,
        &tenant_id,
        tier,
        &req.success_url,
        &req.cancel_url,
        &state.current_dpa_version,
        now_ms,
        &correlation_id,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors orchestrate_tier_select's stable argument order, with the route state in \
              place of its three collaborators"
)]
async fn orchestrate_runner_tier_select(
    state: &TierSelectRouteState,
    tenant_id: &str,
    tier: RequestedTier,
    success_url: &str,
    cancel_url: &str,
    dpa_version: &str,
    now_ms: i64,
    correlation_id: &str,
) -> Result<TierSelectResponse, TierSelectHttpError> {
    state
        .audit
        .emit("tier_select_attempted", tenant_id, correlation_id)
        .await
        .map_err(|_| TierSelectHttpError::Internal)?;
    if !state
        .store
        .acquire_lock(tenant_id, now_ms, correlation_id)
        .await
        .map_err(|_| TierSelectHttpError::Internal)?
    {
        return Err(TierSelectHttpError::LockHeld);
    }
    let result = async {
        if !state
            .store
            .is_dpa_accepted(tenant_id, dpa_version)
            .await
            .map_err(|_| TierSelectHttpError::Internal)?
        {
            state
                .audit
                .emit("dpa_first_violation_attempt", tenant_id, correlation_id)
                .await
                .map_err(|_| TierSelectHttpError::Internal)?;
            return Err(TierSelectHttpError::DpaRequired);
        }
        if state
            .store
            .has_active_runner_subscription(tenant_id)
            .await
            .map_err(|_| TierSelectHttpError::Internal)?
        {
            return Err(TierSelectHttpError::AlreadyActive);
        }
        state
            .audit
            .emit("stripe_checkout_reserved", tenant_id, correlation_id)
            .await
            .map_err(|_| TierSelectHttpError::Internal)?;
        let provider = Arc::new(corelink_stripe_real::StripeRunnerCheckoutProvider::new(
            Arc::clone(state.checkout.stripe()),
            success_url,
            cancel_url,
        ));
        let created = state
            .store
            .checkout_runner(provider, tenant_id, tier, now_ms)
            .await
            .map_err(|error| TierSelectHttpError::StripeUnavailable(Some(error)))?;
        if !created.checkout_url.starts_with("https://") {
            return Err(TierSelectHttpError::StripeUnavailable(Some(
                "checkout url was not https".to_owned(),
            )));
        }
        Ok(TierSelectResponse {
            checkout_url: Some(created.checkout_url),
            session_id: created.session_id,
        })
    }
    .await;
    let _ = state.store.release_lock(tenant_id, correlation_id).await;
    result
}

/// Epoch-millisecond clock for lock expiry + audit timestamps. A pre-epoch
/// system clock is impossible on a deployed container; the saturating
/// fallback keeps the handler total rather than letting it panic.
fn unix_millis_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Build the tier-select router. `main.rs` mounts it via
/// [`build_state_from_env`] only when the internal-auth + D1 + Stripe
/// configuration is present (the same env gate as `internal_pat`), so the
/// route is never reachable without its production collaborators wired.
pub fn router(state: TierSelectRouteState) -> Router {
    Router::new()
        .route("/v1/onboarding/tier-select", post(handle))
        .with_state(state)
}

/// Dedicated environment name for the tier-select money-path credential.
const TIER_SELECT_AUTH_KEY_ENV: &str = "CORELINK_TIER_SELECT_AUTH_KEY";

/// Resolve the tier-select credential through the common 32-character
/// fail-closed gate. A deployment may use the shared key during migration, but
/// a valid dedicated key always wins and can therefore be rotated independently.
fn tier_select_auth_key_from_env() -> Option<Arc<str>> {
    crate::routes::admin::resolve_internal_auth_key(TIER_SELECT_AUTH_KEY_ENV)
}

/// Assemble the production [`TierSelectRouteState`] from the environment, or
/// `None` when the route must NOT be mounted. **Fail-safe:** the money path is
/// mounted ONLY when the dedicated internal-auth secret (or its documented
/// shared fallback), the D1 config, the Stripe config, AND the current DPA
/// version are all present; a missing/short secret or any client-init failure
/// leaves `/v1/onboarding/tier-select` unmounted (404) rather than half-wired.
/// Mirrors
/// [`crate::routes::internal_pat::build_state_from_env`].
#[must_use]
pub fn build_state_from_env() -> Option<TierSelectRouteState> {
    let auth_key = tier_select_auth_key_from_env()?;

    let Some(dpa_version) = std::env::var("CORELINK_DPA_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        tracing::warn!("CORELINK_DPA_VERSION unset; /v1/onboarding/tier-select NOT mounted");
        return None;
    };

    // D1 config travels in `StorageEnv` (CF account / token / database id).
    // Shared as one `Arc<D1HttpClient>` between the store AND the audit
    // adapter so both durable collaborators ride the same connection.
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = match crate::storage::d1_http::D1HttpClient::new(&storage_env) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            tracing::warn!(error = %e, "D1HttpClient init failed; tier-select NOT mounted");
            return None;
        }
    };

    build_state_with_d1(auth_key, Arc::from(dpa_version), d1)
}

fn build_state_with_d1(
    auth_key: Arc<str>,
    dpa_version: Arc<str>,
    d1: Arc<crate::storage::d1_http::D1HttpClient>,
) -> Option<TierSelectRouteState> {
    let stripe = match corelink_stripe_real::StripeRealClient::from_env() {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = %e, "StripeRealClient init failed; tier-select NOT mounted");
            return None;
        }
    };

    Some(TierSelectRouteState {
        internal_auth_key: auth_key,
        store: Arc::new(
            crate::routes::tier_select_store::D1HttpTierSelectStore::new(Arc::clone(&d1)),
        ),
        checkout: Arc::new(
            crate::routes::tier_select_checkout::StripeCheckoutCreator::new(Arc::new(stripe)),
        ),
        audit: Arc::new(crate::routes::tier_select_audit::TierSelectAuditAdapter::new(d1)),
        current_dpa_version: dpa_version,
    })
}

/// Test-only environment builder that keeps every production env/auth gate
/// while injecting an explicitly validated loopback D1 URL.
#[must_use]
pub fn build_state_from_env_for_loopback_test(query_url: &str) -> Option<TierSelectRouteState> {
    let auth_key = tier_select_auth_key_from_env()?;
    let Some(dpa_version) = std::env::var("CORELINK_DPA_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        tracing::warn!("CORELINK_DPA_VERSION unset; /v1/onboarding/tier-select NOT mounted");
        return None;
    };
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = match crate::storage::d1_http::D1HttpClient::new_for_loopback_test(
        &storage_env,
        query_url,
    ) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            tracing::warn!(error = %e, "loopback D1HttpClient init failed; tier-select NOT mounted");
            return None;
        }
    };
    build_state_with_d1(auth_key, Arc::from(dpa_version), d1)
}
