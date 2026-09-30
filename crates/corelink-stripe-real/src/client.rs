//! HTTPS Stripe API client implementing
//! [`corelink_tier_selection::stripe::StripeClient`].
//!
//! # Wave-31 dual-mode auth (2026-05-21)
//!
//! Outbound Stripe API calls can route through either of two auth modes,
//! selected at process start via the `STRIPE_AUTH_MODE` env var:
//!
//! - `direct` (DEFAULT — current production): direct call to
//!   `api.stripe.com/v1/...` with `Authorization: Bearer sk_live_...`.
//!   CoreLink holds the upstream Stripe secret in
//!   `STRIPE_SECRET_KEY`. This is the path that runs while the HuGR
//!   Wallet broker is temporarily unavailable.
//! - `wallet-broker` (the wave-31 stream-1 path, kept whole — see
//!   `specs/_audits/sealed/2026-05-16-wallet-broker-stripe.md`): call routes
//!   through `{HUGR_WALLET_BASE}/{HUGR_STRIPE_REF}/<path>`
//!   with `Authorization: Bearer hugrw_<token>`; CoreLink never holds
//!   the real upstream `sk_live_...`. Re-enable by flipping
//!   `STRIPE_AUTH_MODE=wallet-broker` once the wallet is healthy.
//!
//! Both modes fail CLOSED: missing required env vars OR upstream 5xx
//! after retries → typed error to caller. There is NEVER a silent
//! fallback to the other mode (that would expose the upstream key
//! through the broker, or vice versa).
//!
//! Webhook signature verification stays direct (see `webhook.rs`) — it
//! is inbound (Stripe → CoreLink) and uses a local
//! `STRIPE_WEBHOOK_SECRET` for HMAC verify; same in both modes.
//!
//! Uses `reqwest::blocking` for synchronous trait compatibility. The
//! consumer in `apps/server` wraps `create_checkout_session` calls in
//! `tokio::task::spawn_blocking` to keep the async runtime unblocked.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use corelink_tier_selection::error::TierError;
use corelink_tier_selection::runner_checkout_attempt::{
    RunnerCheckoutAttempt, RunnerCheckoutSessionCreator, RunnerCheckoutSessionExpiry,
    RunnerCheckoutSessionReconciler,
};
use corelink_tier_selection::stripe::{
    CheckoutSessionRequest, CheckoutSessionResponse, StripeClient,
};
use corelink_tier_selection::tenant::StripeCustomerId;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
#[cfg(feature = "live-integration")]
use sha2::{Digest, Sha256};

use crate::clock::{default_clock, Clock};
use crate::error::StripeError;
use crate::retry::RetryPolicy;

/// Default direct-to-Stripe API base URL.
pub const DEFAULT_STRIPE_API_BASE: &str = "https://api.stripe.com";

/// Default HuGR Wallet broker base URL (production).
///
/// Tests inject a `wiremock::MockServer` URI here so they never hit the
/// real wallet. Production is set via the `HUGR_WALLET_BASE` env var
/// (see [`StripeClientConfig::from_env`]).
pub const DEFAULT_HUGR_WALLET_BASE: &str = "https://api.humangr.com";

/// Default HuGR Wallet ref name for the Stripe upstream.
///
/// Per wave-31 wallet-broker series stream-1 the canonical ref is
/// `stripe-prod`. Tests can override via `HUGR_STRIPE_REF`.
pub const DEFAULT_HUGR_STRIPE_REF: &str = "stripe-prod";

/// Selectable auth mode for the Stripe HTTPS client.
///
/// Switched per process via the `STRIPE_AUTH_MODE` env var (see
/// [`StripeClientConfig::from_env`]). Both variants are
/// `#[non_exhaustive]` so future modes can be added without breaking
/// callers; every credential field is wrapped in
/// [`secrecy::SecretString`] so it cannot leak via `Debug` / `Display`
/// / panic output.
#[derive(Clone)]
#[non_exhaustive]
pub enum StripeAuthMode {
    /// Direct to `api.stripe.com` with
    /// `Authorization: Bearer sk_live_…` (or `sk_test_…`).
    ///
    /// This is the DEFAULT mode until the HuGR Wallet broker is
    /// operational again.
    Direct {
        /// Stripe API base URL (default
        /// [`DEFAULT_STRIPE_API_BASE`]).
        api_base: String,
        /// Upstream Stripe secret key (`sk_live_…` or `sk_test_…`).
        /// The value's prefix tells us live vs test; we do not branch
        /// on it here. Held as [`SecretString`] — never printed.
        api_key: SecretString,
    },
    /// Through the HuGR Wallet broker at
    /// `{wallet_base}/{stripe_ref}/…` with
    /// `Authorization: Bearer hugrw_…`.
    WalletBroker {
        /// Base URL of the HuGR Wallet broker (e.g.
        /// `https://api.humangr.com` in prod, or a `wiremock` URI in
        /// tests).
        wallet_base: String,
        /// CoreLink-side `hugrw_` token authorising the proxy call.
        /// The wallet validates the token + its `proxy` scope on
        /// `stripe_ref`. Held as [`SecretString`] — never printed.
        wallet_token: SecretString,
        /// Wallet ref name for the Stripe upstream (canonical:
        /// `stripe-prod`).
        stripe_ref: String,
    },
}

impl core::fmt::Debug for StripeAuthMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct { api_base, .. } => f
                .debug_struct("StripeAuthMode::Direct")
                .field("api_base", api_base)
                .field("api_key", &"<redacted>")
                .finish(),
            Self::WalletBroker {
                wallet_base,
                stripe_ref,
                ..
            } => f
                .debug_struct("StripeAuthMode::WalletBroker")
                .field("wallet_base", wallet_base)
                .field("wallet_token", &"<redacted>")
                .field("stripe_ref", stripe_ref)
                .finish(),
        }
    }
}

/// Auth-mode-agnostic configuration for the Stripe HTTPS client.
///
/// Wraps a [`StripeAuthMode`] which carries the credentials + URL
/// shape for the selected mode. Both this struct and the enum are
/// `#[non_exhaustive]`; the `Debug` impl redacts every credential.
/// Construct via [`StripeClientConfig::direct`] /
/// [`StripeClientConfig::wallet_broker`] /
/// [`StripeClientConfig::from_env`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct StripeClientConfig {
    /// Auth mode the client is configured for.
    pub mode: StripeAuthMode,
}

impl StripeClientConfig {
    /// Construct a Direct-mode config explicitly.
    #[must_use]
    pub fn direct(api_base: impl Into<String>, api_key: SecretString) -> Self {
        Self {
            mode: StripeAuthMode::Direct {
                api_base: api_base.into(),
                api_key,
            },
        }
    }

    /// Construct a Wallet-broker-mode config explicitly.
    #[must_use]
    pub fn wallet_broker(
        wallet_base: impl Into<String>,
        wallet_token: SecretString,
        stripe_ref: impl Into<String>,
    ) -> Self {
        Self {
            mode: StripeAuthMode::WalletBroker {
                wallet_base: wallet_base.into(),
                wallet_token,
                stripe_ref: stripe_ref.into(),
            },
        }
    }

    /// Resolve a [`StripeClientConfig`] from env vars.
    ///
    /// `STRIPE_AUTH_MODE` (default `direct` if unset) selects the
    /// mode. Accepted values:
    /// - `direct` → reads `STRIPE_API_BASE` (default
    ///   [`DEFAULT_STRIPE_API_BASE`]) + `STRIPE_SECRET_KEY`
    ///   (REQUIRED).
    /// - `wallet-broker` / `wallet_broker` → reads
    ///   `HUGR_WALLET_BASE` (default [`DEFAULT_HUGR_WALLET_BASE`]) +
    ///   `HUGR_WALLET_TOKEN` (REQUIRED) + `HUGR_STRIPE_REF` (default
    ///   [`DEFAULT_HUGR_STRIPE_REF`]).
    ///
    /// Both kebab-case (`wallet-broker`) and snake-case
    /// (`wallet_broker`) spellings of the mode are accepted to be
    /// friendly to deploy templating systems with different
    /// case-folding conventions.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::Authentication`] with a mode-specific
    /// message if:
    /// - `STRIPE_AUTH_MODE` is set to an unknown value, OR
    /// - the required credential for the selected mode is
    ///   missing/empty.
    pub fn from_env() -> Result<Self, StripeError> {
        // `.trim()` is load-bearing: secrets are frequently bound via a shell
        // here-string (`... <<< "$V"`) or an API `text:` field that appends a
        // trailing newline. Without trimming, `STRIPE_AUTH_MODE="direct\n"`
        // falls through the exact-match arm below to `other =>` and the entire
        // Stripe client fails to initialise (`stripe_unavailable` 502 on EVERY
        // tier). This exact class already bit `CORELINK_DPA_VERSION` in prod.
        let mode_raw = env::var("STRIPE_AUTH_MODE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "direct".to_string());
        match mode_raw.as_str() {
            "direct" => Self::from_env_direct(),
            "wallet-broker" | "wallet_broker" => Self::from_env_wallet_broker(),
            other => Err(StripeError::Authentication(format!(
                "STRIPE_AUTH_MODE={other} is not recognised; expected 'direct' or 'wallet-broker'"
            ))),
        }
    }

    fn from_env_direct() -> Result<Self, StripeError> {
        // Trim for the same reason as `STRIPE_AUTH_MODE` above: a stray newline
        // on the key produces a 401 from Stripe (also surfaced as a generic
        // `stripe_unavailable` 502), and a newline on the base URL breaks the
        // request URL. Env-derived Stripe config must be whitespace-robust.
        let api_base = env::var("STRIPE_API_BASE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_STRIPE_API_BASE.to_string());
        let api_key = env::var("STRIPE_SECRET_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                StripeError::Authentication(
                    "STRIPE_AUTH_MODE=direct requires STRIPE_SECRET_KEY (set $STRIPE_SECRET_KEY \
                     to your sk_live_… or sk_test_… key)"
                        .to_string(),
                )
            })?;
        Ok(Self::direct(api_base, SecretString::from(api_key)))
    }

    fn from_env_wallet_broker() -> Result<Self, StripeError> {
        let wallet_base = env::var("HUGR_WALLET_BASE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_HUGR_WALLET_BASE.to_string());
        let stripe_ref = env::var("HUGR_STRIPE_REF")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_HUGR_STRIPE_REF.to_string());
        let wallet_token = env::var("HUGR_WALLET_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                StripeError::Authentication(
                    "STRIPE_AUTH_MODE=wallet-broker requires HUGR_WALLET_TOKEN (set \
                     $HUGR_WALLET_TOKEN to the hugrw_ proxy token)"
                        .to_string(),
                )
            })?;
        Ok(Self::wallet_broker(
            wallet_base,
            SecretString::from(wallet_token),
            stripe_ref,
        ))
    }

    /// Compute the effective base URL the next request will be POSTed
    /// under. Stripe paths (`/v1/...`) are appended by the HTTP layer.
    ///
    /// - `Direct` → `{api_base}` (e.g. `https://api.stripe.com`).
    /// - `WalletBroker` →
    ///   `{wallet_base}/{stripe_ref}`.
    ///
    /// Trailing slashes on the base inputs are normalised.
    #[must_use]
    pub fn effective_base_url(&self) -> String {
        match &self.mode {
            StripeAuthMode::Direct { api_base, .. } => api_base.trim_end_matches('/').to_string(),
            StripeAuthMode::WalletBroker {
                wallet_base,
                stripe_ref,
                ..
            } => {
                let base = wallet_base.trim_end_matches('/');
                format!("{base}/{stripe_ref}")
            }
        }
    }

    /// Return the bearer token the client uses for the
    /// `Authorization` header. Crate-internal — never leaks across
    /// the public API.
    fn bearer_token(&self) -> &SecretString {
        match &self.mode {
            StripeAuthMode::Direct { api_key, .. } => api_key,
            StripeAuthMode::WalletBroker { wallet_token, .. } => wallet_token,
        }
    }
}

/// Builder for [`StripeRealClient`].
#[derive(Debug)]
#[non_exhaustive]
pub struct StripeRealClientBuilder {
    config: Option<StripeClientConfig>,
    retry_policy: RetryPolicy,
    timeout: Duration,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl Default for StripeRealClientBuilder {
    fn default() -> Self {
        Self {
            config: None,
            retry_policy: RetryPolicy::default(),
            timeout: Duration::from_secs(30),
            // Wave-20: default = `SystemClock` on native, `WasmWorkerClock`
            // on wasm32 (this module is native-only so always `SystemClock`,
            // but `default_clock()` keeps the call site target-agnostic for
            // when the HTTPS client surface is ported to wasm32 in a
            // future wave).
            clock: default_clock(),
        }
    }
}

impl StripeRealClientBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a [`StripeClientConfig`] explicitly (overrides env
    /// resolution at [`Self::build`]).
    #[must_use]
    pub fn config(mut self, cfg: StripeClientConfig) -> Self {
        self.config = Some(cfg);
        self
    }

    /// Override the retry policy.
    #[must_use]
    pub const fn retry_policy(mut self, p: RetryPolicy) -> Self {
        self.retry_policy = p;
        self
    }

    /// Override the per-request timeout.
    #[must_use]
    pub const fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Inject a [`Clock`] implementation. Default = `SystemClock`
    /// (native) / `WasmWorkerClock` (wasm32). Tests typically pass
    /// [`crate::clock::InMemoryFakeClock`] for deterministic
    /// timestamps in idempotency keys / SLI markers.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// - [`StripeError::Authentication`] if no config was injected and
    ///   env resolution fails for the selected `STRIPE_AUTH_MODE`.
    /// - [`StripeError::ApiConnection`] if the underlying HTTP client
    ///   fails to initialize.
    pub fn build(self) -> Result<StripeRealClient, StripeError> {
        let config = match self.config {
            Some(c) => c,
            None => StripeClientConfig::from_env()?,
        };
        let http = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| StripeError::ApiConnection(e.to_string()))?;
        let base_url = config.effective_base_url();
        Ok(StripeRealClient {
            config,
            base_url,
            retry_policy: self.retry_policy,
            http,
            clock: self.clock,
        })
    }
}

/// Production Stripe HTTPS client (dual-mode: direct or wallet-broker).
///
/// The `Debug` impl REDACTS every credential — secrets MUST never
/// appear in logs.
pub struct StripeRealClient {
    config: StripeClientConfig,
    /// Cached effective base URL — either `{api_base}` (Direct) or
    /// `{wallet_base}/{stripe_ref}` (WalletBroker).
    /// Avoids recomputing per-request.
    base_url: String,
    retry_policy: RetryPolicy,
    http: reqwest::blocking::Client,
    // Wave-20: held for future timestamp-bearing operations (idempotency
    // key TTL eviction, retry-budget windows). Currently the production
    // HTTPS layer reads no wall-clock — Stripe owns idempotency-key
    // retention. Kept here as the canonical injection point so test
    // harnesses can pin time via `.with_clock(...)` once a clock-dependent
    // operation lands.
    #[allow(
        dead_code,
        reason = "wave-20 injection scaffold; consumed by future timestamp ops"
    )]
    clock: Arc<dyn Clock + Send + Sync>,
}

impl core::fmt::Debug for StripeRealClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StripeRealClient")
            .field("config", &self.config)
            .field("base_url", &self.base_url)
            .field("retry_policy", &self.retry_policy)
            .field("clock", &self.clock)
            .finish()
    }
}

impl StripeRealClient {
    /// Construct from env vars via [`StripeClientConfig::from_env`].
    ///
    /// # Errors
    /// See [`StripeRealClientBuilder::build`].
    pub fn from_env() -> Result<Self, StripeError> {
        StripeRealClientBuilder::new().build()
    }

    /// Returns a new [`StripeRealClientBuilder`].
    #[must_use]
    pub fn builder() -> StripeRealClientBuilder {
        StripeRealClientBuilder::new()
    }

    /// Borrow the effective base URL — the value the next request
    /// will be POSTed under. Used by tests to pin the per-mode URL
    /// contract.
    #[must_use]
    pub fn effective_base_url(&self) -> &str {
        &self.base_url
    }

    /// Verify that the configured Wallet broker ref resolves to the expected
    /// Stripe account and that the configured Starter price and product are
    /// explicitly in TEST mode. Stripe Account objects do not expose
    /// `livemode`; account identity is checked against the owner-supplied
    /// expected test account ID, while Price and Product must each report
    /// `livemode=false`. Uses only read-only GETs through this client's normal
    /// transport.
    #[cfg(feature = "live-integration")]
    pub fn verify_test_mode_starter_catalog(
        &self,
        expected_account_id: &str,
        price_id: &str,
    ) -> Result<(), StripeError> {
        if !expected_account_id.starts_with("acct_")
            || expected_account_id.len() <= "acct_".len()
            || !expected_account_id["acct_".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(StripeError::InvalidRequest(
                "expected Stripe TEST account id is invalid".into(),
            ));
        }
        if !price_id.starts_with("price_")
            || price_id.len() <= "price_".len()
            || !price_id["price_".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(StripeError::InvalidRequest(
                "configured Starter price id is invalid".into(),
            ));
        }
        let account: serde_json::Value = self.get("/v1/account")?;
        if account.get("object").and_then(serde_json::Value::as_str) != Some("account")
            || account.get("id").and_then(serde_json::Value::as_str) != Some(expected_account_id)
        {
            return Err(StripeError::InvalidRequest(
                "configured Stripe account does not match expected TEST account".into(),
            ));
        }
        let price: serde_json::Value = self.get(&format!("/v1/prices/{price_id}"))?;
        let product_id = price.get("product").and_then(serde_json::Value::as_str);
        if price.get("id").and_then(serde_json::Value::as_str) != Some(price_id)
            || price.get("livemode").and_then(serde_json::Value::as_bool) != Some(false)
            || price.get("active").and_then(serde_json::Value::as_bool) != Some(true)
            || price.get("currency").and_then(serde_json::Value::as_str) != Some("usd")
            || price
                .pointer("/unit_amount")
                .and_then(serde_json::Value::as_i64)
                != Some(3500)
            || price
                .pointer("/recurring/interval")
                .and_then(serde_json::Value::as_str)
                != Some("month")
            || price
                .pointer("/recurring/interval_count")
                .and_then(serde_json::Value::as_i64)
                != Some(1)
            || product_id.is_none()
        {
            return Err(StripeError::InvalidRequest(
                "configured Starter price is not proven to be the active $35 monthly TEST price"
                    .into(),
            ));
        }
        let product_id = product_id.expect("checked above");
        if !product_id.starts_with("prod_")
            || product_id.len() <= "prod_".len()
            || !product_id["prod_".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(StripeError::InvalidRequest(
                "configured Starter price product id is invalid".into(),
            ));
        }
        let product: serde_json::Value = self.get(&format!("/v1/products/{product_id}"))?;
        if product.get("id").and_then(serde_json::Value::as_str) != Some(product_id)
            || product.get("livemode").and_then(serde_json::Value::as_bool) != Some(false)
            || product.get("active").and_then(serde_json::Value::as_bool) != Some(true)
            || product.get("name").and_then(serde_json::Value::as_str) != Some("CoreLink Starter")
        {
            return Err(StripeError::InvalidRequest(
                "configured Starter product is not proven to be active CoreLink TEST product"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Borrow the [`StripeClientConfig`] used to construct this client.
    #[must_use]
    pub fn config(&self) -> &StripeClientConfig {
        &self.config
    }

    /// POST to a Stripe form-encoded endpoint with idempotency + retry.
    ///
    /// `idempotency_key` MUST be deterministic per logical request so
    /// retries are safe per Stripe spec.
    fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        form: &[(&str, String)],
        idempotency_key: &str,
    ) -> Result<T, StripeError> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt: u32 = 0;
        loop {
            let req = self
                .http
                .post(&url)
                .bearer_auth(self.config.bearer_token().expose_secret())
                .header("Idempotency-Key", idempotency_key)
                .header("Stripe-Version", "2024-06-20")
                .form(form);
            let resp = match req.send() {
                Ok(r) => r,
                Err(e) => {
                    // Transport-level failure — fail-CLOSED retry up to
                    // budget. No silent fallback to the OTHER mode
                    // (would expose the upstream key through the
                    // broker, or vice versa).
                    if let Some(ms) = self.retry_policy.next_sleep_ms(attempt, None) {
                        std::thread::sleep(Duration::from_millis(ms));
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(StripeError::ApiConnection(e.to_string()));
                }
            };
            let status = resp.status().as_u16();
            let retry_after = parse_retry_after(&resp);
            if (200..300).contains(&status) {
                return resp
                    .json::<T>()
                    .map_err(|e| StripeError::ApiConnection(format!("json decode: {e}")));
            }
            if RetryPolicy::is_retryable_status(status) {
                if let Some(ms) = self.retry_policy.next_sleep_ms(attempt, retry_after) {
                    std::thread::sleep(Duration::from_millis(ms));
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            }
            // Non-retryable OR retries exhausted → map to typed error.
            let body = resp.text().unwrap_or_default();
            return Err(map_api_error(status, &body, retry_after));
        }
    }

    /// GET a Stripe endpoint with retry on 5xx/429.
    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, StripeError> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt: u32 = 0;
        loop {
            let req = self
                .http
                .get(&url)
                .bearer_auth(self.config.bearer_token().expose_secret())
                .header("Stripe-Version", "2024-06-20");
            let resp = match req.send() {
                Ok(r) => r,
                Err(e) => {
                    if let Some(ms) = self.retry_policy.next_sleep_ms(attempt, None) {
                        std::thread::sleep(Duration::from_millis(ms));
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(StripeError::ApiConnection(e.to_string()));
                }
            };
            let status = resp.status().as_u16();
            let retry_after = parse_retry_after(&resp);
            if (200..300).contains(&status) {
                return resp
                    .json::<T>()
                    .map_err(|e| StripeError::ApiConnection(format!("json decode: {e}")));
            }
            if RetryPolicy::is_retryable_status(status) {
                if let Some(ms) = self.retry_policy.next_sleep_ms(attempt, retry_after) {
                    std::thread::sleep(Duration::from_millis(ms));
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            }
            let body = resp.text().unwrap_or_default();
            return Err(map_api_error(status, &body, retry_after));
        }
    }

    /// `POST /v1/customers` — create a customer.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn create_customer(
        &self,
        email: &str,
        tenant_id: &str,
        idempotency_key: &str,
    ) -> Result<CustomerObject, StripeError> {
        // Omit `email` when empty — Stripe rejects a literal empty string
        // (`Invalid email address: `). A customer with no email is valid; the
        // hosted Checkout page collects + saves the buyer's email onto it.
        let mut form = vec![("metadata[tenant_id]", tenant_id.to_string())];
        #[cfg(feature = "live-integration")]
        if let Some(run_id) = live_harness_run_id() {
            form.push(("metadata[test_run_id]", run_id));
        }
        let email = email.trim();
        if !email.is_empty() {
            form.push(("email", email.to_string()));
        }
        self.post_form::<CustomerObject>("/v1/customers", &form, idempotency_key)
    }

    /// `GET /v1/customers/:id` — fetch a customer.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn get_customer(&self, id: &str) -> Result<CustomerObject, StripeError> {
        self.get::<CustomerObject>(&format!("/v1/customers/{id}"))
    }

    /// Build the form for GDPR/LGPD erasure pseudonymization of a Stripe
    /// customer. Extracted so the pseudonymize-only invariant is unit-testable
    /// WITHOUT a live Stripe round-trip. By construction this form NEVER
    /// carries a delete primitive — it only overwrites the PII fields
    /// (`email`/`name`) and clears the optional PII fields (`phone`/`address`),
    /// then stamps the `pii_redacted` + `erasure_dsr_id` metadata markers.
    fn pseudonymize_customer_form(
        pseudo_email: &str,
        pseudo_name: &str,
        erasure_dsr_id: &str,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("email", pseudo_email.to_string()),
            ("name", pseudo_name.to_string()),
            // Clear the optional PII fields (Stripe interprets an empty value
            // as an unset). Belt-and-suspenders even if they were never set.
            ("phone", String::new()),
            ("address", String::new()),
            ("metadata[pii_redacted]", "true".to_string()),
            ("metadata[erasure_dsr_id]", erasure_dsr_id.to_string()),
        ]
    }

    /// `POST /v1/customers/:id` — pseudonymize a customer's PII for a DSR
    /// erasure (WI-S11-008 Stripe backend; `backends/stripe.rs`).
    ///
    /// Overwrites `email`/`name`, clears `phone`/`address`, and stamps the
    /// `pii_redacted` + `erasure_dsr_id` metadata. **NEVER calls
    /// `Customer.delete`** — deleting the customer object would break invoice
    /// integrity (GAAP ASC 606 + LGPD Art. 16 fiscal 5y retention). This crate
    /// deliberately exposes NO customer-delete primitive (WI AC-004 / §28
    /// R-004; ADR-S11-013).
    ///
    /// `idempotency_key` MUST be deterministic per `(dsr_id, customer)` so a
    /// retried erasure is a safe replay.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn pseudonymize_customer(
        &self,
        id: &str,
        pseudo_email: &str,
        pseudo_name: &str,
        erasure_dsr_id: &str,
        idempotency_key: &str,
    ) -> Result<CustomerObject, StripeError> {
        let form = Self::pseudonymize_customer_form(pseudo_email, pseudo_name, erasure_dsr_id);
        self.post_form::<CustomerObject>(&format!("/v1/customers/{id}"), &form, idempotency_key)
    }

    /// `POST /v1/subscriptions` — create a subscription.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn create_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
        idempotency_key: &str,
    ) -> Result<SubscriptionObject, StripeError> {
        let form = vec![
            ("customer", customer_id.to_string()),
            ("items[0][price]", price_id.to_string()),
        ];
        self.post_form::<SubscriptionObject>("/v1/subscriptions", &form, idempotency_key)
    }

    /// `GET /v1/subscriptions/:id` — fetch a subscription.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn get_subscription(&self, id: &str) -> Result<SubscriptionObject, StripeError> {
        self.get::<SubscriptionObject>(&format!("/v1/subscriptions/{id}"))
    }

    /// `GET /v1/subscriptions?customer=...&status=all` — list one customer's
    /// current subscription state. The caller validates the authoritative
    /// active/trialing identity; this client deliberately performs no ranking.
    pub fn list_customer_subscriptions(
        &self,
        customer_id: &str,
    ) -> Result<SubscriptionList, StripeError> {
        let customer =
            url::form_urlencoded::byte_serialize(customer_id.as_bytes()).collect::<String>();
        self.get::<SubscriptionList>(&format!(
            "/v1/subscriptions?customer={customer}&status=all&limit=100"
        ))
    }

    /// `POST /v1/billing_portal/sessions` — create a Customer Portal
    /// session.
    ///
    /// # Errors
    /// See [`StripeError`] taxonomy.
    pub fn create_billing_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
        idempotency_key: &str,
    ) -> Result<BillingPortalSession, StripeError> {
        let form = vec![
            ("customer", customer_id.to_string()),
            ("return_url", return_url.to_string()),
        ];
        self.post_form::<BillingPortalSession>(
            "/v1/billing_portal/sessions",
            &form,
            idempotency_key,
        )
    }

    /// Create a runner Checkout session with the ledger's exact idempotency
    /// key and price/customer binding. Retries with that key replay Stripe's
    /// cached response instead of opening another payable session.
    pub fn create_runner_checkout_session(
        &self,
        attempt: &RunnerCheckoutAttempt,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSessionResponse, StripeError> {
        let req = CheckoutSessionRequest::new(
            attempt.tenant_id.clone(),
            attempt.tier,
            String::new(),
            success_url,
            cancel_url,
        );
        let raw = self.create_checkout_session_raw(
            &req,
            &attempt.idempotency_key,
            &attempt.price_id,
            &CheckoutPromo::from_env(),
            &attempt.customer_id,
        )?;
        let customer = raw.customer.unwrap_or_else(|| attempt.customer_id.clone());
        let url = raw
            .url
            .ok_or_else(|| StripeError::InvalidRequest("missing url on checkout session".into()))?;
        Ok(CheckoutSessionResponse::new(
            raw.id,
            StripeCustomerId::new(customer),
            url,
        ))
    }

    /// Expire an unpaid Stripe Checkout session. Stripe treats the operation
    /// as terminal; callers must only advance the D1 attempt after `Ok(())`.
    pub fn expire_checkout_session(&self, session_id: &str) -> Result<(), StripeError> {
        let key = format!("checkout-expire:{session_id}");
        let _: CheckoutSessionObject = self.post_form(
            &format!("/v1/checkout/sessions/{session_id}/expire"),
            &[],
            &key,
        )?;
        Ok(())
    }

    /// Clean up one exact run-owned Checkout Session through the configured
    /// transport. This deliberately exists only in the explicitly enabled
    /// live harness feature; it is not a production customer/session API.
    #[cfg(feature = "live-integration")]
    pub fn cleanup_harness_checkout(
        &self,
        id: &str,
        expected_customer_id: &str,
        run_id: &str,
    ) -> Result<(), StripeError> {
        let before: serde_json::Value = self.get(&format!("/v1/checkout/sessions/{id}"))?;
        let metadata_run = before
            .pointer("/metadata/test_run_id")
            .and_then(|v| v.as_str());
        if before.get("id").and_then(|v| v.as_str()) != Some(id)
            || before.get("customer").and_then(|v| v.as_str()) != Some(expected_customer_id)
            || metadata_run != Some(run_id)
            || before.get("livemode").and_then(serde_json::Value::as_bool) != Some(false)
            || before.get("status").and_then(|v| v.as_str()) != Some("open")
            || before.get("payment_status").and_then(|v| v.as_str()) != Some("unpaid")
            || before.get("payment_intent") != Some(&serde_json::Value::Null)
            || before.get("subscription") != Some(&serde_json::Value::Null)
        {
            return Err(StripeError::InvalidRequest(
                "harness checkout is not exact-run-owned and unpaid/open".into(),
            ));
        }
        self.expire_checkout_session(id)?;
        let after: serde_json::Value = self.get(&format!("/v1/checkout/sessions/{id}"))?;
        if after.get("id").and_then(|v| v.as_str()) != Some(id)
            || after.get("customer").and_then(|v| v.as_str()) != Some(expected_customer_id)
            || after.get("status").and_then(|v| v.as_str()) != Some("expired")
            || after
                .pointer("/metadata/test_run_id")
                .and_then(|v| v.as_str())
                != Some(run_id)
        {
            return Err(StripeError::InvalidRequest(
                "harness checkout expiry readback did not match".into(),
            ));
        }
        Ok(())
    }

    /// Delete one exact run-owned customer only after readback proves it has
    /// no subscription or PaymentIntent. Kept behind the live-harness feature
    /// because normal DSR flows intentionally retain Stripe customer records.
    #[cfg(feature = "live-integration")]
    pub fn cleanup_harness_customer(&self, id: &str, run_id: &str) -> Result<(), StripeError> {
        let customer: serde_json::Value = self.get(&format!("/v1/customers/{id}"))?;
        if customer.get("id").and_then(serde_json::Value::as_str) != Some(id)
            || customer
                .pointer("/metadata/test_run_id")
                .and_then(|v| v.as_str())
                != Some(run_id)
            || customer
                .get("livemode")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
        {
            return Err(StripeError::InvalidRequest(
                "harness customer is not exact-run-owned".into(),
            ));
        }
        for path in [
            format!("/v1/subscriptions?customer={id}&status=all&limit=100"),
            format!("/v1/payment_intents?customer={id}&limit=100"),
        ] {
            let list: serde_json::Value = self.get(&path)?;
            if list
                .pointer("/data")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|v| !v.is_empty())
                || list.get("has_more") != Some(&serde_json::Value::Bool(false))
            {
                return Err(StripeError::InvalidRequest(
                    "harness customer has payment/subscription state or incomplete readback".into(),
                ));
            }
        }
        let url = format!("{}/v1/customers/{id}", self.base_url);
        let response = self
            .http
            .delete(&url)
            .bearer_auth(self.config.bearer_token().expose_secret())
            .header("Stripe-Version", "2024-06-20")
            .send()
            .map_err(|e| StripeError::ApiConnection(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(map_api_error(status, &body, None));
        }
        let deleted: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| StripeError::ApiConnection(format!("json decode: {e}")))?;
        if deleted.get("deleted").and_then(serde_json::Value::as_bool) != Some(true)
            || deleted.get("id").and_then(serde_json::Value::as_str) != Some(id)
        {
            return Err(StripeError::InvalidRequest(
                "customer delete readback did not match".into(),
            ));
        }
        match self.get::<serde_json::Value>(&format!("/v1/customers/{id}")) {
            Err(StripeError::Generic {
                http_status: 404, ..
            }) => Ok(()),
            _ => Err(StripeError::InvalidRequest(
                "customer delete follow-up readback did not return 404".into(),
            )),
        }
    }

    /// `POST /v1/checkout/sessions` — typed Stripe Checkout creation
    /// (returns the raw Stripe object).
    ///
    /// # Promotion / coupon capability
    ///
    /// `promo` selects the checkout-level discount capability (see
    /// [`build_checkout_form`] for the exact form pairs it emits). Stripe
    /// forbids sending `allow_promotion_codes` and `discounts[…]` together on
    /// the same session, so the two are mutually exclusive: a configured
    /// launch coupon is PRE-APPLIED (`discounts[0][coupon]`) for a clean
    /// checkout → $0, otherwise the hosted page shows the promo-code field
    /// (`allow_promotion_codes=true`).
    fn create_checkout_session_raw(
        &self,
        req: &CheckoutSessionRequest,
        idempotency_key: &str,
        price_id: &str,
        promo: &CheckoutPromo,
        customer_id: &str,
    ) -> Result<CheckoutSessionObject, StripeError> {
        let form = build_checkout_form(req, price_id, promo, customer_id);
        self.post_form::<CheckoutSessionObject>("/v1/checkout/sessions", &form, idempotency_key)
    }
}

/// Checkout-level promotion capability for a Checkout Session.
///
/// Stripe rejects a `/v1/checkout/sessions` request that sets BOTH
/// `allow_promotion_codes` and `discounts[…]`, so this is a closed choice of
/// one-or-the-other (never both):
///
/// - [`CheckoutPromo::AllowCodes`] → `allow_promotion_codes=true`: Stripe's
///   hosted page shows a promo-code field the buyer can fill (a code mapped to
///   e.g. a 100%-off coupon → checkout → $0). This is the DEFAULT.
/// - [`CheckoutPromo::Coupon`] → `discounts[0][coupon]=<id>`: the coupon is
///   PRE-APPLIED, so a 100%-off launch coupon yields a clean checkout → $0 with
///   no field to fill. Sourced from the `STRIPE_LAUNCH_COUPON` env var (never
///   hardcoded); when unset the client uses `AllowCodes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutPromo {
    /// Show the hosted promo-code field (`allow_promotion_codes=true`).
    AllowCodes,
    /// Pre-apply a specific coupon id (`discounts[0][coupon]=<id>`).
    Coupon(String),
}

impl CheckoutPromo {
    /// Resolve the promotion capability from the environment. If
    /// `STRIPE_LAUNCH_COUPON` is set (and non-empty after trim) the coupon is
    /// pre-applied; otherwise the hosted promo-code field is enabled. Never
    /// hardcodes a coupon id.
    #[must_use]
    pub fn from_env() -> Self {
        match env::var("STRIPE_LAUNCH_COUPON") {
            Ok(id) if !id.trim().is_empty() => Self::Coupon(id.trim().to_string()),
            _ => Self::AllowCodes,
        }
    }
}

/// Build the `/v1/checkout/sessions` form pairs. Extracted so the promo /
/// coupon wiring is unit-testable without a live Stripe round-trip. The
/// `allow_promotion_codes` and `discounts[…]` pairs are mutually exclusive
/// (Stripe rejects both together) — [`CheckoutPromo`] enforces the choice.
fn build_checkout_form(
    req: &CheckoutSessionRequest,
    price_id: &str,
    promo: &CheckoutPromo,
    customer_id: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("mode", "subscription".to_string()),
        // `if_required` (not the subscription-mode default `always`): at a $0
        // total — a 100%-off / comp coupon fully discounting the first invoice —
        // Stripe SKIPS the card field, so a full-discount checkout completes
        // CARDLESS. The default `always` forces a card even at $0, which both
        // blocks a headless $0 e2e and is real self-serve friction for a comp
        // customer (runners-TL finding). A genuine paid total still collects a
        // card (payment IS required), so paying subscribers are unaffected.
        ("payment_method_collection", "if_required".to_string()),
        // Attach the pre-created Customer. A `mode=subscription` session created
        // WITHOUT a customer leaves `session.customer` NULL until the buyer
        // completes checkout (Stripe creates it then) — which the caller rejects
        // as `missing customer on checkout session`. Attaching a customer
        // (created with no email) up-front makes `session.customer` present at
        // creation; Stripe's hosted page still collects + saves the buyer email
        // onto this customer. We therefore NEVER send `customer_email` (an empty
        // one is rejected `Invalid email address: `, and it's redundant with
        // `customer`).
        ("customer", customer_id.to_string()),
        ("success_url", req.success_url.clone()),
        ("cancel_url", req.cancel_url.clone()),
        ("line_items[0][price]", price_id.to_string()),
        ("line_items[0][quantity]", "1".to_string()),
        ("metadata[tenant_id]", req.tenant_id.as_str().to_string()),
        ("metadata[tier]", req.tier.as_str().to_string()),
    ];
    #[cfg(feature = "live-integration")]
    if let Some(run_id) = live_harness_run_id() {
        form.push(("metadata[test_run_id]", run_id));
    }
    match promo {
        // Hosted promo-code field (mutually exclusive with `discounts`).
        CheckoutPromo::AllowCodes => {
            form.push(("allow_promotion_codes", "true".to_string()));
        }
        // Pre-applied coupon (mutually exclusive with `allow_promotion_codes`).
        CheckoutPromo::Coupon(coupon_id) => {
            form.push(("discounts[0][coupon]", coupon_id.clone()));
        }
    }
    form
}

#[cfg(feature = "live-integration")]
fn live_harness_run_id() -> Option<String> {
    // A GitHub run id alone is not authority to mark provider objects for
    // cleanup. Require the canonical, protected manual Stripe profile context;
    // the executor workflow exposes the Stripe settings only for stripe/all.
    let required_context = [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "HuGR-dev/corelink-server"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW",
            "real ignored integration harnesses (B-068)",
        ),
        ("HUGR_STRIPE_REF", "stripe-prod-test"),
        ("STRIPE_AUTH_MODE", "wallet-broker"),
    ];
    if required_context
        .iter()
        .any(|(name, value)| env::var(name).ok().as_deref() != Some(*value))
    {
        return None;
    }
    let value = env::var("GITHUB_RUN_ID").ok()?;
    if value.is_empty()
        || value.len() > 20
        || !value.chars().all(|c| c.is_ascii_digit())
        || value.bytes().all(|b| b == b'0')
    {
        return None;
    }
    Some(value)
}

#[cfg(feature = "live-integration")]
fn harness_recovery_receipt(run_id: &str, kind: &str, id: &str, status: &str) -> String {
    let digest = hex::encode(Sha256::digest(id.as_bytes()));
    format!(
        "{{\"run_id\":\"{run_id}\",\"kind\":\"{kind}\",\"id_sha256\":\"{digest}\",\"status\":\"{status}\"}}"
    )
}

/// Stable Stripe idempotency identity for one tenant/entitlement axis.
/// Cache and runner subscriptions are independent products and must never
/// reuse one another's Stripe idempotency namespace.
fn checkout_idempotency_key(
    tenant_id: &str,
    tier: corelink_tier_selection::tier::TierKind,
) -> String {
    let axis = if matches!(
        tier,
        corelink_tier_selection::tier::TierKind::RunnerStarter
            | corelink_tier_selection::tier::TierKind::RunnerPro
            | corelink_tier_selection::tier::TierKind::RunnerTeam
            | corelink_tier_selection::tier::TierKind::RunnerScale
            | corelink_tier_selection::tier::TierKind::RunnerMax
    ) {
        "runner"
    } else {
        "cache"
    };
    format!("checkout:{axis}:{tenant_id}")
}

impl StripeClient for StripeRealClient {
    fn create_checkout_session(
        &self,
        req: &CheckoutSessionRequest,
    ) -> Result<CheckoutSessionResponse, TierError> {
        // A tenant owns one payable Checkout identity per entitlement axis.
        // The D1 lease and pending-session ownership decide which request is
        // valid within that axis; cache and runner purchases remain distinct.
        let idem = checkout_idempotency_key(req.tenant_id.as_str(), req.tier);
        // Production wiring resolves price_id per tier via env or a
        // config map; we pull from env for now so callers can override
        // without touching this crate.
        let price_env = format!("STRIPE_PRICE_ID_{}", req.tier.as_str().to_uppercase());
        let price_id = env::var(&price_env)
            .map_err(|_| TierError::Stripe(format!("env var {price_env} not set")))?;

        // Promo-code capability: pre-apply a configured launch coupon
        // (`STRIPE_LAUNCH_COUPON`, for a clean checkout → $0) or, absent one,
        // enable the hosted promo-code field (`allow_promotion_codes=true`).
        // Mutually exclusive by construction — Stripe rejects both together.
        let promo = CheckoutPromo::from_env();

        // Pre-create the Customer (no email — Stripe's hosted Checkout page
        // collects + saves the buyer's email onto it). A `mode=subscription`
        // Checkout Session created WITHOUT a customer leaves `session.customer`
        // null until completion, which we treat as an error below; attaching a
        // customer up-front gives a stable id for the pending-checkout row + the
        // `checkout.session.completed` webhook. Idempotent per tenant so a retry
        // within the lock window reuses the same customer (no orphan spam).
        let customer_idem = format!("customer:{}", req.tenant_id.as_str());
        let created_customer = self
            .create_customer("", req.tenant_id.as_str(), &customer_idem)
            .map_err(|e| TierError::Stripe(e.to_string()))?;
        #[cfg(feature = "live-integration")]
        if let Some(run_id) = live_harness_run_id() {
            if created_customer.livemode == Some(true) {
                let receipt = harness_recovery_receipt(
                    &run_id,
                    "customer",
                    &created_customer.id,
                    "live_mode_retained_no_recovery",
                );
                return Err(TierError::Stripe(format!(
                    "created customer is explicitly LIVE; retained without recovery request; receipt {receipt}"
                )));
            }
            if created_customer.livemode.is_none() {
                // Only an absent mode may be reconciled by re-reading this
                // exact object. Cleanup refuses DELETE unless that read proves
                // TEST mode and exact run ownership.
                let recovered = self.cleanup_harness_customer(&created_customer.id, &run_id);
                let status = if recovered.is_ok() {
                    "deleted_readback_pass"
                } else {
                    "retained_recovery_required"
                };
                let receipt =
                    harness_recovery_receipt(&run_id, "customer", &created_customer.id, status);
                return Err(TierError::Stripe(format!(
                    "created customer mode is unknown; recovery receipt {receipt}"
                )));
            }
        }

        let raw = match self.create_checkout_session_raw(
            req,
            &idem,
            &price_id,
            &promo,
            &created_customer.id,
        ) {
            Ok(raw) => raw,
            Err(error) => {
                // The live harness marks the customer with its run id. If
                // session creation is rejected before returning a session id,
                // perform the exact-run customer cleanup here: the caller has
                // not received a response yet and cannot register the id in
                // its Drop guard. Normal production calls have no run marker
                // and retain their existing behavior.
                #[cfg(feature = "live-integration")]
                let cleanup = live_harness_run_id().map(|run_id| {
                    if matches!(
                        &error,
                        StripeError::InvalidRequest(_) | StripeError::Authentication(_)
                    ) {
                        self.cleanup_harness_customer(&created_customer.id, &run_id)
                    } else {
                        Err(StripeError::InvalidRequest(
                            "checkout outcome is ambiguous; customer retained for recovery".into(),
                        ))
                    }
                });
                #[cfg(feature = "live-integration")]
                let suffix = match cleanup {
                    Some(Ok(())) => "; run-owned customer cleanup passed",
                    Some(Err(_))
                        if matches!(
                            &error,
                            StripeError::InvalidRequest(_) | StripeError::Authentication(_)
                        ) =>
                    {
                        "; run-owned customer cleanup failed"
                    }
                    Some(Err(_)) => {
                        "; run-owned customer retained because Checkout outcome is ambiguous"
                    }
                    None => "",
                };
                #[cfg(not(feature = "live-integration"))]
                let suffix = "";
                return Err(TierError::Stripe(format!("{error}{suffix}")));
            }
        };
        #[cfg(feature = "live-integration")]
        if let Some(run_id) = live_harness_run_id() {
            if raw.livemode == Some(true) {
                let session_receipt = harness_recovery_receipt(
                    &run_id,
                    "checkout",
                    &raw.id,
                    "live_mode_retained_no_recovery",
                );
                let customer_receipt = harness_recovery_receipt(
                    &run_id,
                    "customer",
                    &created_customer.id,
                    "retained_dependency_session_live",
                );
                return Err(TierError::Stripe(format!(
                    "created checkout is explicitly LIVE; session and customer retained without recovery request; receipts [{session_receipt},{customer_receipt}]"
                )));
            }
            if raw.livemode.is_none() {
                let session_recovered = self.cleanup_harness_checkout(
                    &raw.id,
                    raw.customer.as_deref().unwrap_or(&created_customer.id),
                    &run_id,
                );
                let session_status = if session_recovered.is_ok() {
                    "expired_readback_pass"
                } else {
                    "retained_recovery_required"
                };
                let session_receipt =
                    harness_recovery_receipt(&run_id, "checkout", &raw.id, session_status);
                let customer_status = if session_recovered.is_ok()
                    && self
                        .cleanup_harness_customer(&created_customer.id, &run_id)
                        .is_ok()
                {
                    "deleted_readback_pass"
                } else {
                    "retained_recovery_required"
                };
                let customer_receipt = harness_recovery_receipt(
                    &run_id,
                    "customer",
                    &created_customer.id,
                    customer_status,
                );
                return Err(TierError::Stripe(format!(
                    "created checkout mode is unknown; recovery receipts [{session_receipt},{customer_receipt}]"
                )));
            }
        }

        // Stripe echoes the attached customer; fall back to the one we created
        // (belt-and-suspenders — the field is present because we passed it).
        let customer = raw.customer.unwrap_or_else(|| created_customer.id.clone());

        let url = match raw.url {
            Some(url) => url,
            None => {
                // Here Stripe did return an exact session id. Expire and
                // read it back before deleting its customer; if expiry fails,
                // leave the customer for bounded recovery rather than deleting
                // a still-open Checkout dependency.
                #[cfg(feature = "live-integration")]
                let cleanup = live_harness_run_id().map(|run_id| {
                    if customer == created_customer.id
                        && self
                            .cleanup_harness_checkout(&raw.id, &customer, &run_id)
                            .is_ok()
                    {
                        self.cleanup_harness_customer(&customer, &run_id).is_ok()
                    } else {
                        false
                    }
                });
                #[cfg(feature = "live-integration")]
                let suffix = match cleanup {
                    Some(true) => "; run-owned checkout/customer cleanup passed",
                    Some(false) => "; run-owned checkout/customer cleanup failed",
                    None => "",
                };
                #[cfg(not(feature = "live-integration"))]
                let suffix = "";
                return Err(TierError::Stripe(format!(
                    "missing url on checkout session{suffix}"
                )));
            }
        };
        Ok(CheckoutSessionResponse::new(
            raw.id,
            StripeCustomerId::new(customer),
            url,
        ))
    }
}

/// Stripe provider adapter consumed by the runner checkout coordinator.
#[derive(Clone)]
pub struct StripeRunnerCheckoutProvider {
    stripe: Arc<StripeRealClient>,
    success_url: String,
    cancel_url: String,
}

impl StripeRunnerCheckoutProvider {
    /// Bind Stripe and the trusted redirect URLs used for runner sessions.
    #[must_use]
    pub fn new(
        stripe: Arc<StripeRealClient>,
        success_url: impl Into<String>,
        cancel_url: impl Into<String>,
    ) -> Self {
        Self {
            stripe,
            success_url: success_url.into(),
            cancel_url: cancel_url.into(),
        }
    }

    /// Create the stable Stripe customer used by the runner attempt ledger.
    /// The idempotency key is tenant scoped, so a lost response is safe to
    /// replay before reserving the payable Checkout attempt.
    pub fn ensure_customer(&self, tenant_id: &str) -> Result<String, StripeError> {
        self.stripe
            .create_customer("", tenant_id, &format!("customer:{tenant_id}"))
            .map(|customer| customer.id)
    }

    /// Create or replay the hosted session and retain the URL for HTTP
    /// responses. Replaying this call with the attempt key is the provider's
    /// reconciliation primitive after a lost ACK.
    pub fn create_response(
        &self,
        attempt: &RunnerCheckoutAttempt,
    ) -> Result<CheckoutSessionResponse, StripeError> {
        self.stripe
            .create_runner_checkout_session(attempt, &self.success_url, &self.cancel_url)
    }
}

impl core::fmt::Debug for StripeRunnerCheckoutProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StripeRunnerCheckoutProvider")
            .field("stripe", &"[StripeRealClient]")
            .field("success_url", &self.success_url)
            .field("cancel_url", &self.cancel_url)
            .finish()
    }
}

impl RunnerCheckoutSessionCreator for StripeRunnerCheckoutProvider {
    fn create(
        &self,
        attempt: &RunnerCheckoutAttempt,
    ) -> Result<String, corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError>
    {
        self.create_response(attempt)
            .map(|response| response.session_id)
            .map_err(|error| corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError::ProviderCreateFailed(error.to_string()))
    }
}

impl RunnerCheckoutSessionExpiry for StripeRunnerCheckoutProvider {
    fn expire(
        &self,
        attempt: &RunnerCheckoutAttempt,
    ) -> Result<(), corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError>
    {
        let session_id = attempt
            .session_id
            .as_deref()
            .ok_or(corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError::InvalidTransition)?;
        self.stripe
            .expire_checkout_session(session_id)
            .map_err(|error| corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError::ProviderExpiryFailed(error.to_string()))
    }
}

impl RunnerCheckoutSessionReconciler for StripeRunnerCheckoutProvider {
    fn reconcile(
        &self,
        attempt: &RunnerCheckoutAttempt,
    ) -> Result<
        Option<String>,
        corelink_tier_selection::runner_checkout_attempt::RunnerCheckoutAttemptError,
    > {
        // Stripe has no search endpoint for an Idempotency-Key. Replaying the
        // original POST is the provider-supported reconciliation primitive and
        // is safe because the key is the durable attempt identity.
        self.create(attempt).map(Some)
    }
}

/// Parse `Retry-After` header (seconds).
fn parse_retry_after(resp: &reqwest::blocking::Response) -> Option<u64> {
    resp.headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Map a non-2xx Stripe response to the typed [`StripeError`].
fn map_api_error(http_status: u16, body: &str, retry_after_seconds: Option<u64>) -> StripeError {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<ApiErr>,
    }
    #[derive(Deserialize)]
    struct ApiErr {
        #[serde(rename = "type")]
        ty: Option<String>,
        code: Option<String>,
        message: Option<String>,
    }

    let parsed: Option<ApiErr> = serde_json::from_str::<Envelope>(body)
        .ok()
        .and_then(|e| e.error);
    let ty = parsed
        .as_ref()
        .and_then(|p| p.ty.clone())
        .unwrap_or_default();
    let code = parsed
        .as_ref()
        .and_then(|p| p.code.clone())
        .unwrap_or_default();
    let message = parsed
        .as_ref()
        .and_then(|p| p.message.clone())
        .unwrap_or_else(|| body.to_string());

    match http_status {
        401 => StripeError::Authentication(message),
        402 => StripeError::CardDeclined {
            code: if code.is_empty() {
                "card_declined".to_string()
            } else {
                code
            },
            message,
        },
        429 => StripeError::RateLimited {
            message,
            retry_after_seconds,
        },
        400 if ty == "idempotency_error" => StripeError::Idempotency(message),
        400 => StripeError::InvalidRequest(message),
        _ => StripeError::Generic {
            http_status,
            code,
            message,
        },
    }
}

/// Stripe `customer` object (subset of fields we read).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct CustomerObject {
    /// Stripe-assigned customer id (`cus_...`).
    pub id: String,
    /// Customer email (echoed).
    pub email: Option<String>,
    /// Stripe account mode. Missing means unknown and is never accepted by
    /// the live TEST harness.
    #[serde(default)]
    pub livemode: Option<bool>,
}

/// Stripe `subscription` object (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionObject {
    /// Stripe-assigned subscription id (`sub_...`).
    pub id: String,
    /// Subscription status (`active`, `past_due`, `canceled`, ...).
    pub status: String,
    /// Customer id.
    pub customer: String,
    /// Provider-assigned subscription creation time (Unix seconds).
    /// This is the replacement generation; it is distinct from billing period
    /// boundaries and local webhook receive time.
    pub created: Option<i64>,
    /// Current subscription items. Stripe returns one item for the CoreLink
    /// products; callers that reconcile entitlements must validate that
    /// cardinality before using the price.
    #[serde(default)]
    pub items: Option<SubscriptionItems>,
}

/// Stripe subscription list response (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionList {
    /// Subscriptions for the requested customer.
    #[serde(default)]
    pub data: Vec<SubscriptionObject>,
    /// A truncated list cannot establish unique authority.
    #[serde(default)]
    pub has_more: bool,
}

/// Stripe subscription item collection (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionItems {
    /// Items currently attached to the subscription.
    #[serde(default)]
    pub data: Vec<SubscriptionItem>,
}

/// Stripe subscription item (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionItem {
    /// Price selected for this item.
    pub price: Option<SubscriptionPrice>,
}

/// Stripe price embedded in a subscription item (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionPrice {
    /// Stripe price identifier (`price_...`).
    pub id: String,
}

/// Stripe `billing_portal.session` object (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct BillingPortalSession {
    /// Session id (`bps_...`).
    pub id: String,
    /// Hosted portal URL.
    pub url: String,
    /// Customer id.
    pub customer: String,
}

/// Stripe `checkout.session` object (subset).
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct CheckoutSessionObject {
    /// Session id (`cs_...`).
    pub id: String,
    /// Hosted checkout URL (None for `mode=setup` etc.).
    pub url: Option<String>,
    /// Customer id (None until session completes for some flows; for
    /// `mode=subscription` Stripe sets it pre-completion).
    pub customer: Option<String>,
    /// Stripe account mode. Missing means unknown and is never accepted by
    /// the live TEST harness.
    #[serde(default)]
    pub livemode: Option<bool>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]
mod tests;
