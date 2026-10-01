//! `POST /v1/onboarding/dpa-accept` — the DPA click-through acceptance
//! endpoint that writes the durable `dpa_acceptances` row the tier-select
//! money-path gate (`is_dpa_accepted`) reads (INV-ONBOARD-DPA-FIRST).
//!
//! # Why this route exists
//!
//! The checkout gate `TierSelectStore::is_dpa_accepted` does
//! `SELECT 1 FROM dpa_acceptances WHERE tenant_id = ? AND dpa_version = ?`.
//! Until a row is written it always returns `false`, so EVERY paid checkout
//! 403s `dpa_required`. This route is the writer: an authenticated tenant's
//! DPA click-through produces a real acceptance record + an RS256 JWT receipt.
//!
//! # Auth contract (identical to tier-select)
//!
//! The browser holds a Clerk SESSION token, not a CoreLink PAT, so the Worker
//! edge is the trust boundary: it Clerk-verifies the session, resolves the
//! tenant, and forwards `/v1/onboarding/*` to this container's Durable Object
//! with `x-corelink-internal-auth` (constant-time dedicated secret, with the
//! documented shared fallback) +
//! `x-corelink-tenant-id` (the verified tenant). This route re-uses those exact
//! header constants (`super::tier_select::{INTERNAL_AUTH_HEADER, TENANT_HEADER}`)
//! and the same fail-CLOSED gate. The tenant is taken ONLY from the verified
//! header, NEVER from the request body or URL path.
//!
//! # What is persisted (every field is REAL — no placeholders)
//!
//! The engine crate [`corelink_dpa_acceptance`] supplies the real crypto +
//! schema primitives; this route composes them into an async path that writes
//! `dpa_acceptances` (migration `0038`) via [`super::dpa_accept_store`]:
//!
//! - `signup_id` — deterministic idempotency key `dpa:{tenant}:{version}` (one
//!   acceptance per tenant per DPA version; a re-accept is a no-op success).
//! - `notice_hash` — the client-attested SHA-256 hex64 of the exact notice the
//!   user saw (CTRL-PRIV-CONSENT-001; the client is authoritative for "what I
//!   was shown"). Validated well-formed (64 lowercase hex) before persistence.
//! - `locale` — mapped from the UI locale to the closed GA BCP-47 enum
//!   (`en`→`en-US`, `pt`→`pt-BR`, `es`→`es-419`); any other locale (incl. `de`,
//!   outside the 3-locale GA set) is REJECTED (`unsupported_locale`).
//! - `wording_id` — deterministic UUIDv5 over the DPA version (stable identity
//!   of the accepted wording; CTRL-PRIV-CONSENT-006).
//! - `ui_capture_ts` — client-captured click timestamp (clamped to
//!   `≤ submission_ts` so the `submission_after_capture` CHECK holds under
//!   client clock skew; falls back to the server time when absent).
//! - `submission_ts` / `accepted_at` — server clock (HuGR authoritative).
//! - `jwt_receipt_jti` — the `jti` of a freshly RS256-signed receipt
//!   ([`corelink_dpa_acceptance::sign_receipt`]); UNIQUE replay sentinel.
//! - `accepted_ip_hash` — `sha256(ip‖salt)` hex64 (CTRL-PRIV-001; the raw IP is
//!   never persisted).
//!
//! # Notice-hash verification note
//!
//! The engine's `DpaAcceptanceService::accept` also RE-derives the notice hash
//! from a server-side [`corelink_dpa_acceptance::LocaleNoticeRegistry`] and
//! rejects a mismatch. That defence-in-depth requires the container to hold the
//! EXACT bytes the client hashed. Today those bytes live in the admin-ui content
//! pipeline (`apps/admin-ui/src/content/dpa.<locale>.md`), which is NOT
//! byte-identical to the legal artifact (`legal/dpa/v1.0.0.<locale>.md`), so
//! there is no co-located canonical copy the container can recompute against
//! without a fragile cross-package duplication. This route therefore stores the
//! CLIENT-ATTESTED hash (validated well-formed) — the forensically correct
//! record of "the exact bytes the user saw" — rather than re-deriving from a
//! divergent second copy. See the PR description for the follow-up.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use corelink_dpa_acceptance::{
    sign_receipt, IpHashSalt, Jurisdiction, JwtReceiptClaims, LocaleBcp47, RsaPrivateKeyPem,
    TenantId,
};

use crate::routes::tier_select::{INTERNAL_AUTH_HEADER, TENANT_HEADER};

/// Key id stamped in the RS256 receipt header. A stable, non-secret label
/// (the private key rotates behind `DPA_RECEIPT_SIGNING_KEY`; the verify path
/// keys off this `kid`).
const RECEIPT_KID: &str = "dpa-receipt-v1";

// ──────────────────────────────────────────────────────────────────────────────
// Store seam (impl: `super::dpa_accept_store::D1HttpDpaAcceptStore`)
// ──────────────────────────────────────────────────────────────────────────────

/// One `dpa_acceptances` row (migration `0038`) — every field is a real,
/// server-produced or client-attested consent value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceRow {
    /// Idempotency key (PRIMARY KEY): `dpa:{tenant}:{version}`.
    pub signup_id: String,
    /// Verified owning tenant (from `x-corelink-tenant-id`).
    pub tenant_id: String,
    /// Accepted DPA version (semver).
    pub dpa_version: String,
    /// Closed GA BCP-47 locale string (`en-US` / `pt-BR` / `es-419`).
    pub locale: String,
    /// Client-attested SHA-256 hex64 of the rendered notice text.
    pub notice_hash: String,
    /// Deterministic UUIDv5 wording identity.
    pub wording_id: String,
    /// Client-captured click timestamp (ms; `≤ submission_ts`).
    pub ui_capture_ts: i64,
    /// Server submission timestamp (ms).
    pub submission_ts: i64,
    /// RS256 receipt `jti` (UNIQUE replay sentinel).
    pub jwt_receipt_jti: String,
    /// `sha256(ip‖salt)` hex64 (raw IP never persisted).
    pub accepted_ip_hash: String,
    /// Acceptance time (ms; equals `submission_ts` at insert).
    pub accepted_at: i64,
    /// Schema version (migration `0038` default = 1).
    pub schema_version: i64,
}

/// The minimal projection of an existing acceptance needed to return an
/// idempotent replay response without a re-sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAcceptance {
    /// Original receipt `jti`.
    pub jwt_receipt_jti: String,
    /// Accepted DPA version.
    pub dpa_version: String,
    /// Accepted locale (BCP-47 string).
    pub locale: String,
    /// Original acceptance time (ms).
    pub accepted_at: i64,
}

/// Durable store seam for DPA acceptances. Fail-CLOSED: any error surfaces as
/// `Err(String)` (never silently "already accepted").
pub trait DpaAcceptStore: Send + Sync {
    /// Idempotency replay lookup by `signup_id`.
    fn find_by_signup_id(
        &self,
        signup_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredAcceptance>, String>> + Send;

    /// Insert a fresh acceptance. `Ok(true)` iff WE inserted (no prior row);
    /// `Ok(false)` on a PK race (caller re-reads the winner).
    fn insert_acceptance(
        &self,
        row: &AcceptanceRow,
    ) -> impl std::future::Future<Output = Result<bool, String>> + Send;
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP envelope
// ──────────────────────────────────────────────────────────────────────────────

/// Request body the admin-ui DPA click-through submits. `deny_unknown_fields`
/// blocks a smuggled `tenant_id` (the tenant is header-only).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DpaAcceptRequestBody {
    /// DPA template version accepted (must equal the server's current version).
    dpa_version: String,
    /// UI locale (`en` / `pt` / `es` / `en-US` / `pt-BR` / `es-419`).
    dpa_locale: String,
    /// Client-computed SHA-256 hex64 of the rendered notice text.
    notice_text_hash: String,
    /// Client-captured click timestamp (ms since epoch). Optional for
    /// backward-compatibility with older clients; absent → server time.
    #[serde(default)]
    ui_capture_ts: Option<i64>,
}

/// Response body — matches the admin-ui `DpaAccepted` interface
/// (`onboarding/actions.ts`).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DpaAcceptResponse {
    /// Immutable audit reference (the RS256 receipt `jti`).
    pub audit_event_id: String,
    /// Accepted DPA version (echoed).
    pub dpa_version: String,
    /// Accepted locale (canonical BCP-47).
    pub dpa_locale: String,
    /// Acceptance time (ms since epoch, as a string).
    pub dpa_accepted_at: String,
}

/// Typed transport error → `{ "error": <code> }` envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpaAcceptHttpError {
    /// Internal-auth secret missing / wrong (constant-time).
    Unauthenticated,
    /// `x-corelink-tenant-id` missing / empty.
    NoVerifiedTenant,
    /// Malformed JSON / unknown field / malformed notice hash.
    BadRequest,
    /// Locale outside the closed 3-locale GA set (incl. `de`).
    UnsupportedLocale,
    /// Payload `dpa_version` ≠ the server's current DPA version.
    VersionMismatch,
    /// Durable store / signing failure (fail-CLOSED).
    Internal,
}

impl DpaAcceptHttpError {
    const fn parts(self) -> (StatusCode, &'static str) {
        match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::NoVerifiedTenant => (StatusCode::UNAUTHORIZED, "no_verified_tenant"),
            Self::BadRequest => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::UnsupportedLocale => (StatusCode::BAD_REQUEST, "unsupported_locale"),
            Self::VersionMismatch => (StatusCode::BAD_REQUEST, "dpa_version_mismatch"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for DpaAcceptHttpError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Fail-CLOSED auth gate (mirrors tier_select's constant-time contract)
// ──────────────────────────────────────────────────────────────────────────────

/// Constant-time internal-auth check. Neither the secret length nor its content
/// leaks via an early return (mirrors `tier_select::verify_internal_auth`).
fn verify_internal_auth(
    headers: &HeaderMap,
    expected_secret: &str,
) -> Result<(), DpaAcceptHttpError> {
    let presented = headers
        .get(INTERNAL_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected_bytes = expected_secret.as_bytes();
    let provided_bytes = presented.as_bytes();
    let provided_padded: Vec<u8> = if provided_bytes.len() >= expected_bytes.len() {
        provided_bytes
            .get(..expected_bytes.len())
            .unwrap_or(&[])
            .to_vec()
    } else {
        let mut v = provided_bytes.to_vec();
        v.resize(expected_bytes.len(), 0);
        v
    };
    let content_ok = expected_bytes.ct_eq(&provided_padded).unwrap_u8();
    let len_ok = u8::from(expected_bytes.len() == provided_bytes.len());
    if (content_ok & len_ok) == 1 {
        Ok(())
    } else {
        Err(DpaAcceptHttpError::Unauthenticated)
    }
}

/// Extract the edge-verified tenant id (fail-CLOSED; never from body/path).
fn extract_verified_tenant(headers: &HeaderMap) -> Result<String, DpaAcceptHttpError> {
    headers
        .get(TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or(DpaAcceptHttpError::NoVerifiedTenant)
}

/// Best-effort real client IP for the consent record. Prefers Cloudflare's
/// `cf-connecting-ip`, then the first `x-forwarded-for` hop; falls back to a
/// stable sentinel (still hashed — an unobserved IP is honestly recorded).
fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        let ip = ip.trim();
        if !ip.is_empty() {
            return ip.to_owned();
        }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let first = first.trim();
            if !first.is_empty() {
                return first.to_owned();
            }
        }
    }
    "unknown".to_owned()
}

// ──────────────────────────────────────────────────────────────────────────────
// Validation + derivations (pure)
// ──────────────────────────────────────────────────────────────────────────────

/// Map a UI locale string onto the closed GA BCP-47 enum. Accepts both the
/// admin-ui short form (`en`/`pt`/`es`) and the canonical form
/// (`en-US`/`pt-BR`/`es-419`). Any other value (incl. `de`) → `None`.
fn map_locale(raw: &str) -> Option<LocaleBcp47> {
    match raw.trim() {
        "en" | "en-US" => Some(LocaleBcp47::EnUs),
        "pt" | "pt-BR" => Some(LocaleBcp47::PtBr),
        "es" | "es-419" => Some(LocaleBcp47::Es419),
        _ => None,
    }
}

/// Jurisdiction embedded in the RS256 receipt, derived from the accepted locale.
/// `LocaleBcp47` is `#[non_exhaustive]`; the wildcard defends a future locale
/// variant (unreachable today — the three GA locales are exhaustive).
fn jurisdiction_for(locale: LocaleBcp47) -> Jurisdiction {
    match locale {
        LocaleBcp47::EnUs => Jurisdiction::Us,
        LocaleBcp47::PtBr => Jurisdiction::Br,
        LocaleBcp47::Es419 => Jurisdiction::Latam,
        _ => Jurisdiction::Us,
    }
}

/// `true` iff `s` is exactly 64 lowercase hex chars (a well-formed SHA-256).
fn is_sha256_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Hashes of the exact static DPA markdown served by the admin UI. A
/// syntactically valid SHA-256 for arbitrary text is not consent evidence:
/// only the server-approved wording is accepted here.
fn canonical_notice_hash(locale: LocaleBcp47) -> &'static str {
    match locale {
        LocaleBcp47::EnUs => "0b8d023331a3e23a8be9750277bd178229a89de57770f5c2fed82752340e9171",
        LocaleBcp47::PtBr => "045af95b063dccd6b7b5e9bb9e5710a14c8b37c25ed0eedc4785b50bc6fc4f9a",
        LocaleBcp47::Es419 => "995276f5c839da7547da5ddaeb6421e22083806e65d510b77a9a324cc7a4779b",
        _ => "",
    }
}

/// Deterministic `wording_id`: UUIDv5 over the DPA version (stable identity of
/// the accepted wording; same version ⇒ same id).
fn wording_id_for(dpa_version: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("corelink/dpa/wording/{dpa_version}").as_bytes(),
    )
    .to_string()
}

/// Validated, engine-ready request (locale mapped, hash checked, version pinned
/// to the server's current DPA version).
#[derive(Debug, Clone)]
struct ValidatedDpaRequest {
    dpa_version: String,
    locale: LocaleBcp47,
    notice_hash: String,
    ui_capture_ts: Option<i64>,
    client_ip: String,
}

/// Validate the parsed body against the route state. Pure + side-effect-free.
fn validate_request(
    current_dpa_version: &str,
    body: DpaAcceptRequestBody,
    client_ip: String,
) -> Result<ValidatedDpaRequest, DpaAcceptHttpError> {
    // Version pin: only the CURRENT version can be accepted, so the written row
    // is exactly what `is_dpa_accepted(tenant, current_version)` reads.
    if body.dpa_version.trim() != current_dpa_version {
        return Err(DpaAcceptHttpError::VersionMismatch);
    }
    let locale = map_locale(&body.dpa_locale).ok_or(DpaAcceptHttpError::UnsupportedLocale)?;
    let notice_hash = body.notice_text_hash.trim().to_owned();
    if !is_sha256_hex64(&notice_hash) || notice_hash != canonical_notice_hash(locale) {
        return Err(DpaAcceptHttpError::BadRequest);
    }
    Ok(ValidatedDpaRequest {
        dpa_version: current_dpa_version.to_owned(),
        locale,
        notice_hash,
        ui_capture_ts: body.ui_capture_ts,
        client_ip,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Orchestration (generic over the store seam → unit-testable off live D1)
// ──────────────────────────────────────────────────────────────────────────────

/// Drive one acceptance: idempotency replay → RS256 receipt sign → durable
/// `dpa_acceptances` write. Fail-CLOSED on any store/sign error.
async fn orchestrate_dpa_accept<S: DpaAcceptStore>(
    store: &S,
    signing_key: &RsaPrivateKeyPem,
    kid: &str,
    ip_salt: &IpHashSalt,
    tenant_id: &str,
    req: &ValidatedDpaRequest,
    now_ms: i64,
) -> Result<DpaAcceptResponse, DpaAcceptHttpError> {
    let signup_id = format!("dpa:{tenant_id}:{}", req.dpa_version);

    // (1) Idempotent replay: an existing row returns the ORIGINAL receipt with
    // NO re-sign and NO new row (PAT-RETRY-IDEMPOTENT-001).
    if let Some(existing) = store
        .find_by_signup_id(&signup_id)
        .await
        .map_err(|_| DpaAcceptHttpError::Internal)?
    {
        return Ok(DpaAcceptResponse {
            audit_event_id: existing.jwt_receipt_jti,
            dpa_version: existing.dpa_version,
            dpa_locale: existing.locale,
            dpa_accepted_at: existing.accepted_at.to_string(),
        });
    }

    // (2) Stamp server time. `ui_capture_ts` is clamped to `≤ submission_ts`
    // (the click cannot logically follow submission; client clock skew or an
    // absent value falls back to the server time) so the D1
    // `submission_after_capture` CHECK holds.
    let submission_ts = now_ms;
    let ui_capture_ts = match req.ui_capture_ts {
        Some(ts) if ts > 0 && ts <= submission_ts => ts,
        _ => submission_ts,
    };

    // (3) Mint the RS256 receipt (real signature; jti = UNIQUE replay sentinel).
    let jti = Uuid::now_v7().to_string();
    let claims = JwtReceiptClaims::new(
        &TenantId(tenant_id.to_owned()),
        &req.dpa_version,
        submission_ts,
        jurisdiction_for(req.locale),
        &jti,
    );
    let _jwt = sign_receipt(signing_key, kid, &claims).map_err(|_| DpaAcceptHttpError::Internal)?;

    // (4) Build + persist the real row.
    let ip_hash = ip_salt.hash_ip(&req.client_ip);
    let row = AcceptanceRow {
        signup_id: signup_id.clone(),
        tenant_id: tenant_id.to_owned(),
        dpa_version: req.dpa_version.clone(),
        locale: req.locale.as_bcp47().to_owned(),
        notice_hash: req.notice_hash.clone(),
        wording_id: wording_id_for(&req.dpa_version),
        ui_capture_ts,
        submission_ts,
        jwt_receipt_jti: jti.clone(),
        accepted_ip_hash: ip_hash,
        accepted_at: submission_ts,
        schema_version: 1,
    };

    let inserted = store
        .insert_acceptance(&row)
        .await
        .map_err(|_| DpaAcceptHttpError::Internal)?;
    if !inserted {
        // Lost a PK race with a concurrent accept → return the winner's row.
        if let Some(existing) = store
            .find_by_signup_id(&signup_id)
            .await
            .map_err(|_| DpaAcceptHttpError::Internal)?
        {
            return Ok(DpaAcceptResponse {
                audit_event_id: existing.jwt_receipt_jti,
                dpa_version: existing.dpa_version,
                dpa_locale: existing.locale,
                dpa_accepted_at: existing.accepted_at.to_string(),
            });
        }
        return Err(DpaAcceptHttpError::Internal);
    }

    Ok(DpaAcceptResponse {
        audit_event_id: jti,
        dpa_version: req.dpa_version.clone(),
        dpa_locale: req.locale.as_bcp47().to_owned(),
        dpa_accepted_at: submission_ts.to_string(),
    })
}

/// Epoch-millisecond clock (saturating; a pre-epoch clock is impossible on a
/// deployed container).
fn unix_millis_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// ──────────────────────────────────────────────────────────────────────────────
// Route state + axum wiring
// ──────────────────────────────────────────────────────────────────────────────

/// Route state injected at boot. The internal-auth secret + the RS256 private
/// key are NEVER logged (redacted in `Debug`).
#[derive(Clone)]
pub struct DpaAcceptRouteState {
    internal_auth_key: Arc<str>,
    store: Arc<super::dpa_accept_store::D1HttpDpaAcceptStore>,
    signing_key: Arc<RsaPrivateKeyPem>,
    kid: Arc<str>,
    current_dpa_version: Arc<str>,
    ip_salt: Arc<IpHashSalt>,
}

impl std::fmt::Debug for DpaAcceptRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpaAcceptRouteState")
            .field("internal_auth_key", &"[REDACTED]")
            .field("store", &self.store)
            .field("signing_key", &"[REDACTED RSA PRIVATE KEY]")
            .field("kid", &self.kid)
            .field("current_dpa_version", &self.current_dpa_version)
            .field("ip_salt", &self.ip_salt)
            .finish()
    }
}

/// `POST /v1/onboarding/dpa-accept`.
pub async fn handle(
    State(state): State<DpaAcceptRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Fail-CLOSED gate FIRST: internal-auth (constant-time) → verified tenant.
    if let Err(e) = verify_internal_auth(&headers, &state.internal_auth_key) {
        return e.into_response();
    }
    let tenant_id = match extract_verified_tenant(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let parsed: DpaAcceptRequestBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return DpaAcceptHttpError::BadRequest.into_response(),
    };
    let client_ip = extract_client_ip(&headers);
    let validated = match validate_request(&state.current_dpa_version, parsed, client_ip) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    match orchestrate_dpa_accept(
        &*state.store,
        &state.signing_key,
        &state.kid,
        &state.ip_salt,
        &tenant_id,
        &validated,
        unix_millis_now(),
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Parse + validate the RS256 signing key PEM by trial-signing a dummy receipt.
/// Returns `None` (⇒ route UNMOUNTED, fail-CLOSED) when the key is
/// missing/short/unparseable, so a misconfigured key never 500s at request time.
fn parse_signing_key(pem: &str) -> Option<RsaPrivateKeyPem> {
    if pem.trim().is_empty() {
        return None;
    }
    let key = RsaPrivateKeyPem(pem.to_owned());
    let probe = JwtReceiptClaims::new(
        &TenantId("_probe".to_owned()),
        "0.0.0",
        0,
        Jurisdiction::Us,
        "_probe",
    );
    match sign_receipt(&key, RECEIPT_KID, &probe) {
        Ok(_) => Some(key),
        Err(e) => {
            tracing::warn!(error = %e, "DPA_RECEIPT_SIGNING_KEY failed trial-sign; /v1/onboarding/dpa-accept NOT mounted");
            None
        }
    }
}

/// Dedicated environment name for the DPA acceptance credential.
const DPA_ACCEPT_AUTH_KEY_ENV: &str = "CORELINK_DPA_ACCEPT_AUTH_KEY";
/// Dedicated 32-byte IP-hash salt, provisioned as 64 hexadecimal characters.
const DPA_ACCEPT_IP_HASH_SALT_ENV: &str = "DPA_ACCEPT_IP_HASH_SALT";

/// Resolve the DPA acceptance credential through the common 32-character
/// fail-closed gate. The shared key remains a documented migration fallback;
/// a valid dedicated key always wins and can be rotated independently.
fn dpa_accept_auth_key_from_env() -> Option<Arc<str>> {
    super::admin::resolve_internal_auth_key(DPA_ACCEPT_AUTH_KEY_ENV)
}

/// Resolve and validate the dedicated IP-hash salt. No development or
/// deterministic fallback is allowed in mounted production state.
fn dpa_accept_ip_hash_salt_from_env() -> Option<Arc<IpHashSalt>> {
    let value = std::env::var(DPA_ACCEPT_IP_HASH_SALT_ENV).ok()?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        tracing::warn!("DPA_ACCEPT_IP_HASH_SALT invalid; /v1/onboarding/dpa-accept NOT mounted");
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    match IpHashSalt::new(Some(&bytes)) {
        Ok(salt) => Some(Arc::new(salt)),
        Err(_) => {
            tracing::warn!(
                "DPA_ACCEPT_IP_HASH_SALT invalid; /v1/onboarding/dpa-accept NOT mounted"
            );
            None
        }
    }
}

/// Assemble the production [`DpaAcceptRouteState`] from the environment, or
/// `None` when the route must NOT be mounted (fail-CLOSED). Mounted ONLY when
/// the dedicated internal-auth secret (or its documented shared fallback), the
/// DPA version, the RS256 signing key (`DPA_RECEIPT_SIGNING_KEY`, valid PEM),
/// the valid `DPA_ACCEPT_IP_HASH_SALT` (32 bytes encoded as hex), AND the D1
/// config are all present.
#[must_use]
pub fn build_state_from_env() -> Option<DpaAcceptRouteState> {
    let auth_key = dpa_accept_auth_key_from_env()?;
    let Some(dpa_version) = std::env::var("CORELINK_DPA_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        tracing::warn!("CORELINK_DPA_VERSION unset; /v1/onboarding/dpa-accept NOT mounted");
        return None;
    };
    let Some(signing_key) = std::env::var("DPA_RECEIPT_SIGNING_KEY")
        .ok()
        .and_then(|pem| parse_signing_key(&pem))
    else {
        tracing::warn!(
            "DPA_RECEIPT_SIGNING_KEY unset/invalid (RSA PKCS#8/PKCS#1 PEM required); \
             /v1/onboarding/dpa-accept NOT mounted (fail-CLOSED)"
        );
        return None;
    };
    let Some(ip_salt) = dpa_accept_ip_hash_salt_from_env() else {
        tracing::warn!(
            "DPA_ACCEPT_IP_HASH_SALT unset/invalid; /v1/onboarding/dpa-accept NOT mounted"
        );
        return None;
    };

    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = match crate::storage::d1_http::D1HttpClient::new(&storage_env) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            tracing::warn!(error = %e, "D1HttpClient init failed; /v1/onboarding/dpa-accept NOT mounted");
            return None;
        }
    };

    Some(build_state_with_d1(
        auth_key,
        Arc::from(dpa_version),
        signing_key,
        ip_salt,
        d1,
    ))
}

fn build_state_with_d1(
    auth_key: Arc<str>,
    dpa_version: Arc<str>,
    signing_key: RsaPrivateKeyPem,
    ip_salt: Arc<IpHashSalt>,
    d1: Arc<crate::storage::d1_http::D1HttpClient>,
) -> DpaAcceptRouteState {
    DpaAcceptRouteState {
        internal_auth_key: auth_key,
        store: Arc::new(super::dpa_accept_store::D1HttpDpaAcceptStore::new(d1)),
        signing_key: Arc::new(signing_key),
        kid: Arc::from(RECEIPT_KID),
        current_dpa_version: dpa_version,
        ip_salt,
    }
}

/// Test-only environment builder that keeps every production env/auth/DPA
/// gate while injecting an explicitly validated loopback D1 URL.
#[must_use]
pub fn build_state_from_env_for_loopback_test(query_url: &str) -> Option<DpaAcceptRouteState> {
    let auth_key = dpa_accept_auth_key_from_env()?;
    let Some(dpa_version) = std::env::var("CORELINK_DPA_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        tracing::warn!("CORELINK_DPA_VERSION unset; /v1/onboarding/dpa-accept NOT mounted");
        return None;
    };
    let Some(signing_key) = std::env::var("DPA_RECEIPT_SIGNING_KEY")
        .ok()
        .and_then(|pem| parse_signing_key(&pem))
    else {
        tracing::warn!(
            "DPA_RECEIPT_SIGNING_KEY unset/invalid (RSA PKCS#8/PKCS#1 PEM required); \
             /v1/onboarding/dpa-accept NOT mounted (fail-CLOSED)"
        );
        return None;
    };
    let ip_salt = dpa_accept_ip_hash_salt_from_env()?;
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = match crate::storage::d1_http::D1HttpClient::new_for_loopback_test(
        &storage_env,
        query_url,
    ) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            tracing::warn!(error = %e, "loopback D1HttpClient init failed; dpa-accept NOT mounted");
            return None;
        }
    };
    Some(build_state_with_d1(
        auth_key,
        Arc::from(dpa_version),
        signing_key,
        ip_salt,
        d1,
    ))
}

/// Build the DPA-accept router.
pub fn router(state: DpaAcceptRouteState) -> Router {
    Router::new()
        .route("/v1/onboarding/dpa-accept", post(handle))
        .with_state(state)
}

#[cfg(test)]
#[path = "dpa_accept_tests.rs"]
mod tests;
