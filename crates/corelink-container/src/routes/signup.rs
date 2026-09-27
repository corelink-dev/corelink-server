//! Pilot signup route — `POST /v1/signup/pilot/{token}`.
//!
//! Wave-29 stream-1 deliverable closing **DEBT-027** engineering-side.
//! Wave-27 (commit `6761860`) shipped the operator-facing pilot admin
//! shell scripts (`grant-pilot-tier.sh`, `list-pilot-tenants.sh`,
//! `pilot-24h-checkin.sh`) and the Grafana dashboard panel template;
//! wave-28's pilot-comms package (`docs/internal/pilot-comms-templates.md`)
//! references a public URL for token redemption. That URL was
//! `https://signup.corelink.humangr.com/pilot/<token>`, on the retired
//! dotted hostname scheme; the live one is
//! `https://corelink-api.humangr.com/v1/signup/pilot/<token>`. This
//! module is the production backend that redeems those tokens.
//!
//! # Token format
//!
//! `pilot_<env>_<unix_ms>_<16-hex-random>.<hmac-hex>`
//!
//! - `env` ∈ {`staging`, `prod`} — segregates staging / prod tokens so
//!   a staging mint never opens a prod slot.
//! - `unix_ms` — token mint timestamp (Unix epoch ms). The route
//!   refuses any token older than [`PILOT_TOKEN_TTL_MS`] (14 days —
//!   matches the operator's pilot-window policy referenced in
//!   `docs/internal/customer-success-playbook.md §1`).
//! - `16-hex-random` — `getrandom::getrandom(&mut [u8; 8])` then hex.
//!   8 random bytes = 64 bits of entropy ≫ the per-month outreach
//!   volume bound on the pilot programme (DEBT-027 caps at single-
//!   digit pilots before GA-cutover).
//! - `hmac-hex` — `HMAC-SHA256(SIGNUP_TOKEN_KEY,
//!   "pilot_<env>_<unix_ms>_<16-hex>")`, hex-encoded. Verified in
//!   constant time via [`subtle::ConstantTimeEq`].
//!
//! The HMAC key comes from the `SIGNUP_TOKEN_KEY` env var at boot.
//! Production wiring binds this to a Cloudflare Workers secret;
//! native dev/CI uses a deterministic in-memory key fed via
//! [`build_state_with_key`].
//!
//! # Request shape
//!
//! ```text
//! POST /v1/signup/pilot/{token}
//! Content-Type: application/json
//! X-Corelink-Client-Ip: <client-ip>  (rate-limit anchor; set by the Worker
//!                                      from cf-connecting-ip; NOT client-controlled)
//!
//! {
//!   "email": "...",
//!   "company_name": "...",
//!   "tier_hint": "free|pro|enterprise",
//!   "expected_use_case": "..."
//! }
//! ```
//!
//! All four body fields are required (`400` if any is missing) and
//! capped at [`MAX_FIELD_LEN`] characters (`400` if any exceeds).
//!
//! # Response shape (201)
//!
//! ```text
//! HTTP/1.1 201 Created
//! Content-Type: application/json
//!
//! {
//!   "tenant_id": "<uuid v7>",
//!   "activation_url": "https://humangr.com/corelink/sign-up?pilot=<id>",
//!   "state": "RESERVED"
//! }
//! ```
//!
//! # Failure modes
//!
//! | Condition                          | Status | Body / header                  |
//! |------------------------------------|--------|--------------------------------|
//! | malformed token / bad HMAC         | 401    | `unauthorized`                 |
//! | expired token (> TTL)              | 401    | `unauthorized`                 |
//! | missing / oversize body field      | 400    | `bad_request`                  |
//! | rate-limit exceeded (5/IP/hour)    | 429    | `Retry-After: <secs>`          |
//! | audit emit failure (fail-CLOSED)   | 503    | `audit pipeline closed`        |
//! | D1 store failure                   | 503    | `signup store unavailable`     |
//!
//! # Charter compliance
//!
//! - `#![forbid(unsafe_code)]` inherited from `corelink-server`.
//! - No `unwrap`/`expect`/`panic` in src (clippy lints).
//! - HMAC verify uses `subtle::ConstantTimeEq` (timing-safe).
//! - Audit emit BEFORE response (fail-CLOSED per
//!   `INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER`).
//! - Rate-limit gate at the route boundary uses the canonical
//!   `corelink-ratelimit::RateLimiter` trait (per-IP bucket, keyed on
//!   the server-trusted `x-corelink-client-ip` header; missing header
//!   collapses to the shared `"_no_ip"` bucket — fail-CLOSED).
//!
//! # Audit cross-reference
//!
//! `specs/_audits/sealed/2026-05-16-signup-corelink-dev-backend.md`.

// W35-P2: module-level `//!` docs reference items defined further down
// this file via short paths; under the umbrella crate's scope they
// would require full prefixes. Suppressing the lint preserves the
// original reference text.
#![allow(rustdoc::broken_intra_doc_links)]

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use corelink_ratelimit::{
    BucketKey, InMemoryRateLimitAuditSink, InMemoryRateLimitMetrics,
    InMemoryTokenBucketRateLimiter, RateLimitConfig, RateLimitDecision, RateLimiter,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::wall_clock::{default_wall_clock, WallClock};

/// Canonical pilot-signup route path. The `:token` segment is the
/// `pilot_<env>_<unix_ms>_<16-hex>.<hmac-hex>` token described in the
/// module-level docs.
///
/// **axum 0.7 path-param syntax**: this codebase pins axum 0.7 +
/// matchit 0.7, which uses the `:name` capture syntax (axum 0.8 +
/// matchit 0.8 switch to `{name}`). The audit-doc cross-reference
/// uses `{token}` in prose but the wire path is `:token` in the
/// matchit registration above.
pub const SIGNUP_PILOT_ROUTE: &str = "/v1/signup/pilot/{token}";

/// Canonical CloudEvents-1.0 `type` literal for the pilot-reserved
/// audit emit.
pub const EVENT_TYPE_PILOT_RESERVED: &str = "corelink.signup.pilot_reserved.v1";

/// Canonical CloudEvents-1.0 `type` literal for the token-rejected
/// audit emit (forged HMAC / malformed / expired token).
pub const EVENT_TYPE_PILOT_TOKEN_REJECTED: &str = "corelink.signup.pilot_token_rejected.v1";

/// Canonical CloudEvents-1.0 `type` literal for the rate-limit-deny
/// audit emit.
pub const EVENT_TYPE_PILOT_RATE_LIMITED: &str = "corelink.signup.pilot_rate_limited.v1";

/// Canonical D1 audit namespace for the pilot route.
///
/// Pilot requests are pre-tenant: token rejection and rate limiting happen
/// before a tenant exists, while a successful reservation only allocates the
/// placeholder id in `pilot_signups` (the real `tenant` row is created later
/// by operator provisioning). All pilot audit rows therefore use the shared
/// public namespace in `audit_outbox`; the reserved id remains in the
/// CloudEvents data payload for correlation.
pub const PILOT_AUDIT_NAMESPACE: &str = "_public";

/// Residency pinned by the canonical `_public` audit namespace.
pub const PILOT_AUDIT_REGION: &str = "wnam";

/// Pilot signup token TTL — tokens older than this (by mint
/// timestamp) are rejected as expired. 14 days mirrors the operator
/// pilot-window policy in
/// `docs/internal/customer-success-playbook.md §1`.
pub const PILOT_TOKEN_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Maximum length (chars) for every free-text body field. 256 is the
/// canonical bound declared in the wave-29 stream-1 charter.
pub const MAX_FIELD_LEN: usize = 256;

/// Token environment discriminator — segregates `staging` from `prod`
/// at the parse layer so a staging mint never opens a prod slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEnv {
    /// Staging mint (test outreach).
    Staging,
    /// Production mint (live pilot programme).
    Prod,
}

impl TokenEnv {
    /// Canonical string form (matches the token body prefix).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }

    /// Parse from the leading token segment.
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "staging" => Some(Self::Staging),
            "prod" => Some(Self::Prod),
            _ => None,
        }
    }
}

/// Parsed pilot token (post-verify).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PilotToken {
    /// Token environment (`staging` / `prod`).
    pub env: TokenEnv,
    /// Mint timestamp (Unix epoch ms).
    pub minted_at_ms: u64,
    /// 16-hex random body — preserved verbatim for replay detection.
    pub token_id: String,
}

/// Token-parse / verify failure taxonomy. Mapped to 401 at the route
/// boundary; the variant disambiguates the audit emit `payload`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    /// Token did not contain a `.` separator or the body / signature
    /// segments were empty.
    Malformed,
    /// Token body had fewer than the canonical 4 underscore-separated
    /// fields (`pilot`, `<env>`, `<unix_ms>`, `<16-hex>`).
    BadStructure,
    /// Token did not start with the `pilot` literal.
    NotPilotToken,
    /// Token environment segment was neither `staging` nor `prod`.
    BadEnv,
    /// Timestamp segment failed to parse as `u64`.
    BadTimestamp,
    /// 16-hex random segment was not 16 hex chars.
    BadRandom,
    /// HMAC signature segment was not valid hex.
    BadSignatureEncoding,
    /// HMAC verification failed (forged signature).
    SignatureMismatch,
    /// Token mint timestamp is older than [`PILOT_TOKEN_TTL_MS`] ago.
    Expired,
}

impl TokenError {
    /// Canonical short tag — surfaced on the audit emit `payload`.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadStructure => "bad_structure",
            Self::NotPilotToken => "not_pilot_token",
            Self::BadEnv => "bad_env",
            Self::BadTimestamp => "bad_timestamp",
            Self::BadRandom => "bad_random",
            Self::BadSignatureEncoding => "bad_signature_encoding",
            Self::SignatureMismatch => "signature_mismatch",
            Self::Expired => "expired",
        }
    }
}

/// Parse + HMAC-verify a pilot signup token.
///
/// `token` is the raw URL path segment; `key` is the
/// `SIGNUP_TOKEN_KEY` HMAC secret; `now_ms` is the current wall clock
/// (TTL check anchor).
///
/// # Errors
///
/// Returns the canonical [`TokenError`] taxonomy. Each variant maps to
/// 401 at the route boundary; the route's audit emit records the
/// `.tag()` for operator forensics.
pub fn parse_and_verify_pilot_token(
    token: &str,
    key: &[u8],
    now_ms: u64,
) -> Result<PilotToken, TokenError> {
    // 1) split body + signature on the single `.` separator.
    let (body, sig_hex) = match token.split_once('.') {
        Some((b, s)) if !b.is_empty() && !s.is_empty() => (b, s),
        _ => return Err(TokenError::Malformed),
    };
    // 2) split body into the 4 canonical underscore-separated fields:
    //    `pilot_<env>_<unix_ms>_<16-hex>`. We use splitn(4) to ensure
    //    exactly 4 fields; the env allowlist ({"staging","prod"}) and
    //    u64 timestamp validation provide the real security barrier.
    let parts: Vec<&str> = body.splitn(4, '_').collect();
    if parts.len() != 4 {
        return Err(TokenError::BadStructure);
    }
    if parts.first().copied() != Some("pilot") {
        return Err(TokenError::NotPilotToken);
    }
    let env_str = parts.get(1).copied().ok_or(TokenError::BadStructure)?;
    let env = TokenEnv::from_str(env_str).ok_or(TokenError::BadEnv)?;
    let ts_str = parts.get(2).copied().ok_or(TokenError::BadStructure)?;
    let minted_at_ms: u64 = ts_str.parse().map_err(|_| TokenError::BadTimestamp)?;
    let rand_str = parts.get(3).copied().ok_or(TokenError::BadStructure)?;
    if rand_str.len() != 16 || !rand_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TokenError::BadRandom);
    }
    // 3) decode the signature hex.
    let sig_bytes = hex::decode(sig_hex).map_err(|_| TokenError::BadSignatureEncoding)?;
    // 4) compute the expected HMAC over the body.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| TokenError::SignatureMismatch)?;
    mac.update(body.as_bytes());
    let expected = mac.finalize().into_bytes();
    // 5) constant-time compare. Bail on length mismatch first
    //    (length is not secret; HMAC-SHA256 is always 32 bytes).
    if sig_bytes.len() != expected.len() {
        return Err(TokenError::SignatureMismatch);
    }
    if sig_bytes.as_slice().ct_eq(expected.as_slice()).unwrap_u8() != 1 {
        return Err(TokenError::SignatureMismatch);
    }
    // 6) TTL check. `now_ms < minted_at_ms` (clock skew) is NOT an
    //    error — the route always accepts tokens minted "in the
    //    future" if the signature is valid (operator may pre-mint
    //    a batch for a future programme launch). We only reject
    //    tokens older than `PILOT_TOKEN_TTL_MS`.
    if now_ms >= minted_at_ms.saturating_add(PILOT_TOKEN_TTL_MS) {
        return Err(TokenError::Expired);
    }
    Ok(PilotToken {
        env,
        minted_at_ms,
        token_id: rand_str.to_owned(),
    })
}

/// Render the canonical pilot token over the four body segments
/// signed with `key`. Used by `scripts/admin/mint-pilot-token.sh` via
/// the binary `target/debug/mint-pilot-token` (not shipped — the
/// shell wrapper invokes a one-shot `cargo run` per mint, see the
/// script for details). Exposed for unit + integration tests.
///
/// # Errors
///
/// Returns a static error string if the HMAC key length is zero.
pub fn mint_pilot_token(
    env: TokenEnv,
    minted_at_ms: u64,
    rand_hex16: &str,
    key: &[u8],
) -> Result<String, &'static str> {
    if rand_hex16.len() != 16 || !rand_hex16.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("rand_hex16 must be 16 lower-case ASCII hex chars");
    }
    let body = format!("pilot_{}_{}_{}", env.as_str(), minted_at_ms, rand_hex16);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| "hmac key invalid")?;
    mac.update(body.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(format!("{body}.{}", hex::encode(sig)))
}

/// Request body for the pilot signup route. Every field is required;
/// each must be ≤ [`MAX_FIELD_LEN`] characters.
#[derive(Clone, Debug, Deserialize)]
pub struct PilotSignupBody {
    /// Pilot contact email.
    pub email: String,
    /// Free-text company name.
    pub company_name: String,
    /// Free-text tier preference (`free` / `pro` / `enterprise` — not
    /// binding; operator pre-screening signal only).
    pub tier_hint: String,
    /// Free-text expected use-case (operator pre-screening signal).
    pub expected_use_case: String,
}

impl PilotSignupBody {
    /// Validate the body — every field non-empty + within
    /// [`MAX_FIELD_LEN`] chars.
    ///
    /// # Errors
    ///
    /// Returns the offending field's canonical name on failure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.email.is_empty() || self.email.chars().count() > MAX_FIELD_LEN {
            return Err("email");
        }
        if !self.email.contains('@') {
            return Err("email");
        }
        if self.company_name.is_empty() || self.company_name.chars().count() > MAX_FIELD_LEN {
            return Err("company_name");
        }
        if self.tier_hint.is_empty() || self.tier_hint.chars().count() > MAX_FIELD_LEN {
            return Err("tier_hint");
        }
        if self.expected_use_case.is_empty()
            || self.expected_use_case.chars().count() > MAX_FIELD_LEN
        {
            return Err("expected_use_case");
        }
        Ok(())
    }
}

/// Successful pilot reservation response (201 body).
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PilotSignupResponse {
    /// Reserved tenant id (UUID v7, lexicographic-sortable).
    pub tenant_id: Uuid,
    /// Activation URL the operator follows up with (per pilot-comms
    /// templates `docs/internal/pilot-comms-templates.md`).
    pub activation_url: String,
    /// Pilot lifecycle state — always `"RESERVED"` on this arm.
    pub state: String,
}

/// Audit-row shape captured by the route on every emit arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignupAuditRow {
    /// Canonical CloudEvents `type` (one of the `EVENT_TYPE_*`
    /// constants in this module).
    pub event_type: String,
    /// Tenant id stamped at reservation time — `Some` only on the
    /// happy-path `pilot_reserved.v1` arm.
    pub tenant_id: Option<Uuid>,
    /// Source token id (16-hex random body, or the raw token prefix
    /// up to 32 chars on the reject arms when the body did not parse).
    pub token_id_or_prefix: Option<String>,
    /// Canonical exit status: `"reserved"` / `"duplicate"` /
    /// `"rejected"` / `"rate_limited"` / `"bad_request"`.
    pub exit_status: String,
    /// Optional structured payload (e.g. token reject `tag`).
    pub payload: Option<String>,
    /// Server-side emit wall-clock (Unix epoch ms).
    pub emitted_at_ms: u64,
}

/// Audit-emit trait for the pilot-signup route.
///
/// Production wiring binds this to the CloudEvents audit emitter
/// (mirrors the `audit_export` route pattern); native dev/CI uses
/// [`InMemorySignupAuditSink`].
pub trait SignupAuditSink: Send + Sync + core::fmt::Debug {
    /// Persist one [`SignupAuditRow`].
    ///
    /// # Errors
    ///
    /// Returns a static error string when the audit pipeline is
    /// closed. The route converts to 503 (fail-CLOSED per
    /// `INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER`).
    fn emit(&self, row: SignupAuditRow) -> Result<(), &'static str>;
}

/// In-memory capture sink. Cloning shares the captured buffer so the
/// test harness can inspect emits without re-handing the sink to the
/// route state.
#[derive(Clone, Debug, Default)]
pub struct InMemorySignupAuditSink {
    inner: Arc<Mutex<Vec<SignupAuditRow>>>,
    injected_failure: Arc<Mutex<Option<&'static str>>>,
}

impl InMemorySignupAuditSink {
    /// Construct a fresh empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the captured rows in emit order.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the inner mutex is poisoned.
    pub fn snapshot(&self) -> Result<Vec<SignupAuditRow>, &'static str> {
        let g = self
            .inner
            .lock()
            .map_err(|_| "signup audit sink mutex poisoned")?;
        Ok(g.clone())
    }

    /// Inject a static failure to drive the 503 fail-CLOSED regression.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the inner mutex is poisoned.
    pub fn inject_failure(&self, msg: &'static str) -> Result<(), &'static str> {
        let mut g = self
            .injected_failure
            .lock()
            .map_err(|_| "injected failure mutex poisoned")?;
        *g = Some(msg);
        Ok(())
    }
}

impl SignupAuditSink for InMemorySignupAuditSink {
    fn emit(&self, row: SignupAuditRow) -> Result<(), &'static str> {
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
            .map_err(|_| "signup audit sink mutex poisoned")?;
        g.push(row);
        Ok(())
    }
}

/// Fail-CLOSED audit-emit helper. Mirrors `audit_export::emit_or_503`.
#[must_use]
pub fn emit_or_503(sink: &Arc<dyn SignupAuditSink>, row: SignupAuditRow) -> Option<Response> {
    if sink.emit(row).is_err() {
        return Some((StatusCode::SERVICE_UNAVAILABLE, "audit pipeline closed").into_response());
    }
    None
}

/// Rate-limit config — 5 requests / IP / hour. The wave-29 stream-1
/// charter §Deliverables.1 specifies `5/IP/hour`; the
/// `RateLimitConfig` shape gives us
/// `(refill_rate_per_sec, burst_capacity, retry_floor_secs,
///   retry_ceiling_secs, retry_canceled_secs)`. We pick
/// `burst_capacity = 5` (the bucket starts FULL so the first 5
/// requests admit) and retain the exact `5 / 3600` tokens/sec ratio.
/// Keeping the fractional ratio is load-bearing: the integer constructor's
/// old `1 token/sec` value let an attacker refill one pilot request every
/// second after the initial burst. With `retry_after_floor = 720s`
/// (hour / 5), a drained bucket surfaces 429 + `Retry-After: 720`.
/// The hard ceiling is 1d; the canceled-tenant value is 7d
/// (mirrors the audit-export config).
#[must_use]
pub fn pilot_signup_rate_limit_config() -> RateLimitConfig {
    // (refill=5/3600 tokens/sec, burst=5, floor=720s,
    // ceiling=86_400s, canceled=7*86_400s).
    RateLimitConfig::with_fractional_refill_ratio(5, 3_600, 5, 720, 86_400, 7 * 86_400)
        .unwrap_or_else(RateLimitConfig::canonical)
}

/// Shared route state.
#[derive(Clone)]
pub struct SignupRouteState {
    /// HMAC-SHA256 key for token verify (production wiring binds to
    /// the `SIGNUP_TOKEN_KEY` env var / Worker secret).
    pub token_key: Arc<Vec<u8>>,
    /// Per-IP rate limiter.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Audit sink.
    pub audit_sink: Arc<dyn SignupAuditSink>,
    /// Pilot signup persistence.
    pub store: Arc<dyn SignupStore>,
    /// Wall clock — anchors the TTL check + emit wall-clock.
    pub wall_clock: Arc<dyn WallClock>,
    /// Activation URL base — production binds to
    /// [`DEFAULT_ACTIVATION_URL_BASE`], the live Clerk sign-up surface.
    pub activation_url_base: Arc<String>,
    /// Staging-only request gate. A present credential is consumed before an
    /// ownership-aware store boundary receives its immutable context.
    pub staging_admission:
        Option<Arc<crate::storage::staging_load_test_admission::StagingLoadTestAdmissionGate>>,
}

impl core::fmt::Debug for SignupRouteState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignupRouteState").finish_non_exhaustive()
    }
}

/// Canonical activation-URL base (production wiring). Tests inject a
/// fixture base via [`build_state_with_key`].
///
/// This points at the **live Clerk sign-up surface**, which is the only
/// account-creation path that exists. The previous value
/// (`https://signup.corelink.humangr.com/pilot/activate`) was dead twice
/// over: the `signup.corelink.humangr.com` name is NXDOMAIN (dotted
/// scheme, retired in favour of the flat `corelink-*.humangr.com` one),
/// and no `/pilot/activate` page was ever built on any host — so an
/// applicant who reserved a slot received a link that could not resolve
/// and, had it resolved, would have 404'd.
///
/// The reservation id rides as the `pilot` query parameter rather than a
/// path segment: `/corelink/sign-up` is a Clerk catch-all route
/// (`sign-up/[[...sign-up]]`) that owns its own sub-paths for the
/// multi-step flow, so an extra path segment would collide with Clerk's
/// routing. A query parameter passes through untouched.
pub const DEFAULT_ACTIVATION_URL_BASE: &str = "https://humangr.com/corelink/sign-up";

/// Construct the native dev/CI route state with the given HMAC key.
///
/// The HMAC key is mandatory — production wiring SHOULD pass the
/// `SIGNUP_TOKEN_KEY` env var bytes here; the boot path in
/// `apps/server/src/main.rs` is responsible for failing CLOSED if the
/// env var is missing.
#[must_use]
pub fn build_state_with_key(token_key: Vec<u8>) -> SignupRouteState {
    let rl_audit = Arc::new(InMemoryRateLimitAuditSink::new());
    let rl_metrics = Arc::new(InMemoryRateLimitMetrics::new());
    let rate_limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryTokenBucketRateLimiter::new(
        rl_audit,
        rl_metrics,
        pilot_signup_rate_limit_config(),
    ));
    let audit_sink: Arc<dyn SignupAuditSink> = Arc::new(InMemorySignupAuditSink::new());
    let store: Arc<dyn SignupStore> = Arc::new(InMemorySignupStore::new());
    let wall_clock = default_wall_clock();
    SignupRouteState {
        token_key: Arc::new(token_key),
        rate_limiter,
        audit_sink,
        store,
        wall_clock,
        activation_url_base: Arc::new(DEFAULT_ACTIVATION_URL_BASE.to_owned()),
        staging_admission: None,
    }
}

/// Default dev/CI key — deterministic 32-byte value. Production wiring
/// MUST override via [`build_state_from_env`] with the live secret.
const DEV_TOKEN_KEY: &[u8; 32] = b"corelink-dev-pilot-signup-key!!\0";

/// Construct route state with the canonical **dev/CI key**.
///
/// ⚠️ **TESTS / dev only.** This wires the public, hardcoded
/// [`DEV_TOKEN_KEY`] — a value that lives in the open repo and is
/// therefore forgeable. Production MUST mount via [`build_state_from_env`]
/// (which fail-CLOSED requires the `SIGNUP_TOKEN_KEY` secret); this builder
/// exists only for the test module and any explicit dev path.
#[must_use]
pub fn build_state() -> SignupRouteState {
    build_state_with_key(DEV_TOKEN_KEY.to_vec())
}

/// Build the pilot-signup route state from the environment, fail-CLOSED.
///
/// Reads:
///
/// - `SIGNUP_TOKEN_KEY` — hex-encoded HMAC token key (≥ 32 bytes decoded).
///   Missing or invalid → returns `None`; the caller logs a warning and
///   skips mounting the route (so `/v1/signup/pilot` is simply absent in
///   dev/CI without the secret, rather than running with a forgeable key).
/// - The native-container [`crate::storage::StorageEnv`] set
///   (`R2_S3_ENDPOINT`, `R2_S3_ACCESS_KEY_ID`, `R2_S3_SECRET_ACCESS_KEY`,
///   `CLOUDFLARE_ACCOUNT_ID`, `CF_API_TOKEN`, `D1_DATABASE_ID`) — the SAME
///   secrets `billing_d1_http` / `customer_d1` already require, already
///   registered in `docs/internal/secrets-checklist.md`. **No new secret
///   is introduced by this route.** Missing/invalid → `None` (fail-CLOSED
///   — the route is never mounted with the volatile in-memory store /
///   audit sink in production; see the module-level docs' "D1 store
///   failure" row).
///
/// Mirrors [`internal_pat::build_state_from_env`]'s `PAT_SIGNING_KEY`
/// hex+length handling for the token key. Unlike [`build_state_with_key`]
/// (dev/test path — always `InMemorySignupStore` /
/// `InMemorySignupAuditSink`), this is the ONLY production wiring: it
/// binds [`crate::signup_d1_http::D1HttpSignupStore`] (durable D1-over-
/// HTTP persistence, `migrations/d1/0053_pilot_signups.sql`) and
/// [`crate::storage::d1_audit_sink::D1AuditOutboxSink`] (the SAME durable
/// `audit_outbox` seam the CAS/AC data plane already writes to) so pilot
/// reservations and their `pilot_reserved.v1` audit rows survive a
/// container roll and are enforceable across all 5 regional workers.
#[must_use]
pub fn build_state_from_env() -> Option<SignupRouteState> {
    let token_key_hex = std::env::var("SIGNUP_TOKEN_KEY").ok()?;
    let token_key = hex::decode(token_key_hex.trim())
        .map_err(|e| {
            tracing::warn!(error = %e, "SIGNUP_TOKEN_KEY not valid hex; /v1/signup/pilot NOT mounted");
        })
        .ok()?;
    if token_key.len() < 32 {
        tracing::warn!(
            len = token_key.len(),
            "SIGNUP_TOKEN_KEY too short (< 32 bytes decoded); /v1/signup/pilot NOT mounted"
        );
        return None;
    }

    // Durable D1 store + audit sink — fail-CLOSED exactly like the
    // SIGNUP_TOKEN_KEY gate above: production must NEVER silently fall
    // back to the in-memory fakes (that was the bug — a live 201 with
    // COUNT(*)=0 in prod D1's pilot_signups/pilot_tenants).
    let Some(storage_env) = crate::storage::StorageEnv::from_env() else {
        tracing::warn!(
            "signup: storage env (R2_S3_*/CLOUDFLARE_ACCOUNT_ID/CF_API_TOKEN/D1_DATABASE_ID) \
             unset; /v1/signup/pilot NOT mounted (fail-CLOSED — refusing the in-memory store \
             in production)"
        );
        return None;
    };
    let store: Arc<dyn SignupStore> = match crate::signup_d1_http::signup_store_from_d1(
        crate::storage::d1_http::D1HttpClient::new(&storage_env),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "signup: durable store unavailable; /v1/signup/pilot NOT mounted");
            return None;
        }
    };
    let audit_sink: Arc<dyn SignupAuditSink> =
        match crate::storage::d1_audit_sink::signup_audit_sink_from_d1(
            crate::storage::d1_http::D1HttpClient::new(&storage_env),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "signup: durable audit sink unavailable; /v1/signup/pilot NOT mounted");
                return None;
            }
        };

    let rl_audit = Arc::new(InMemoryRateLimitAuditSink::new());
    let rl_metrics = Arc::new(InMemoryRateLimitMetrics::new());
    let rate_limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryTokenBucketRateLimiter::new(
        rl_audit,
        rl_metrics,
        pilot_signup_rate_limit_config(),
    ));
    let wall_clock = default_wall_clock();

    Some(SignupRouteState {
        token_key: Arc::new(token_key),
        rate_limiter,
        audit_sink,
        store,
        wall_clock,
        activation_url_base: Arc::new(DEFAULT_ACTIVATION_URL_BASE.to_owned()),
        staging_admission:
            crate::storage::staging_load_test_admission::StagingLoadTestAdmissionGate::from_env()
                .ok()
                .map(Arc::new),
    })
}

/// Build the axum router exposing the pilot-signup route.
pub fn router(state: SignupRouteState) -> Router {
    Router::new()
        .route(SIGNUP_PILOT_ROUTE, post(handle_pilot_signup))
        .with_state(state)
}

#[path = "signup_support.rs"]
mod support;
use support::{extract_client_ip, token_prefix, PRE_AUTH_TENANT};
pub use support::{InMemorySignupStore, PilotSignupRecord, SignupStore};

/// Pilot signup route handler.
#[allow(clippy::too_many_lines, reason = "single-handler route surface")]
async fn handle_pilot_signup(
    State(state): State<SignupRouteState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PilotSignupBody>,
) -> Response {
    let admission =
        match crate::storage::staging_load_test_admission::admit_staging_load_test_request(
            state.staging_admission.as_deref(),
            &headers,
            crate::storage::staging_load_test_ownership::StagingLoadTestScenario::Signup,
        )
        .await
        {
            Ok(context) => context,
            Err(_) => return (StatusCode::FORBIDDEN, "forbidden").into_response(),
        };
    let now_ms = state.wall_clock.now_ms();
    let client_ip = extract_client_ip(&headers);

    // 1) Rate-limit gate — per-IP bucket. The decision lands BEFORE the
    //    token verify so an adversary cannot probe the HMAC space with
    //    high QPS.
    let rl_key = BucketKey::per_ip(PRE_AUTH_TENANT, client_ip.clone());
    match state
        .rate_limiter
        .try_acquire(PRE_AUTH_TENANT, rl_key, 1, now_ms)
    {
        Ok(outcome) => match outcome.decision {
            RateLimitDecision::Allow { .. } => {}
            RateLimitDecision::Deny429 {
                retry_after_secs, ..
            } => {
                let audit_row = SignupAuditRow {
                    event_type: EVENT_TYPE_PILOT_RATE_LIMITED.to_owned(),
                    tenant_id: None,
                    token_id_or_prefix: Some(token_prefix(&token)),
                    exit_status: "rate_limited".to_owned(),
                    payload: Some(format!("retry_after_secs={retry_after_secs}")),
                    emitted_at_ms: now_ms,
                };
                if let Some(resp) = emit_or_503(&state.audit_sink, audit_row) {
                    return resp;
                }
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", retry_after_secs.to_string())],
                    "rate_limited",
                )
                    .into_response();
            }
            _ => {
                // `RateLimitDecision` is `#[non_exhaustive]`; any future
                // variant falls back to deny for fail-CLOSED.
                return (StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
            }
        },
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "rate limiter unavailable").into_response();
        }
    }

    // 2) Token parse + HMAC verify.
    let parsed = match parse_and_verify_pilot_token(&token, &state.token_key, now_ms) {
        Ok(t) => t,
        Err(err) => {
            let audit_row = SignupAuditRow {
                event_type: EVENT_TYPE_PILOT_TOKEN_REJECTED.to_owned(),
                tenant_id: None,
                token_id_or_prefix: Some(token_prefix(&token)),
                exit_status: "rejected".to_owned(),
                payload: Some(err.tag().to_owned()),
                emitted_at_ms: now_ms,
            };
            if let Some(resp) = emit_or_503(&state.audit_sink, audit_row) {
                return resp;
            }
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    };

    // 3) Body validation.
    if let Err(field) = body.validate() {
        let audit_row = SignupAuditRow {
            event_type: EVENT_TYPE_PILOT_TOKEN_REJECTED.to_owned(),
            tenant_id: None,
            token_id_or_prefix: Some(parsed.token_id.clone()),
            exit_status: "bad_request".to_owned(),
            payload: Some(format!("invalid_field={field}")),
            emitted_at_ms: now_ms,
        };
        if let Some(resp) = emit_or_503(&state.audit_sink, audit_row) {
            return resp;
        }
        return (StatusCode::BAD_REQUEST, "bad_request").into_response();
    }

    // 4) Reserve the row in the store (idempotent on email / token_id).
    let signup_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let record = PilotSignupRecord {
        id: signup_id,
        tenant_id,
        email: body.email.clone(),
        company_name: body.company_name.clone(),
        tier_hint: body.tier_hint.clone(),
        expected_use_case: body.expected_use_case.clone(),
        signed_up_at_ms: now_ms,
        token_id: parsed.token_id.clone(),
        state: "RESERVED".to_owned(),
    };
    let stored = match state
        .store
        .insert_or_existing_with_context(record, admission.as_deref())
    {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "signup store unavailable").into_response();
        }
    };

    // 5) Audit emit BEFORE we serialise the response body. The
    //    `pilot_reserved.v1` emit fails CLOSED.
    let exit_status = if stored.id == signup_id {
        "reserved"
    } else {
        "duplicate"
    }
    .to_owned();
    let audit_row = SignupAuditRow {
        event_type: EVENT_TYPE_PILOT_RESERVED.to_owned(),
        tenant_id: Some(stored.tenant_id),
        token_id_or_prefix: Some(stored.token_id.clone()),
        exit_status,
        payload: None,
        emitted_at_ms: now_ms,
    };
    if let Some(resp) = emit_or_503(&state.audit_sink, audit_row) {
        return resp;
    }

    // 6) Render the 201 response.
    let activation_url = format!("{}?pilot={}", state.activation_url_base, stored.id);
    let resp_body = PilotSignupResponse {
        tenant_id: stored.tenant_id,
        activation_url,
        state: stored.state,
    };
    (StatusCode::CREATED, Json(resp_body)).into_response()
}

#[cfg(test)]
#[path = "signup_tests.rs"]
mod tests;
