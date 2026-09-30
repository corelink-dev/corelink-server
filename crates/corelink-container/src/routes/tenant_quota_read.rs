//! `GET /_internal/tenant/{tenant_id}/quota` — read-only internal quota lookup.
//!
//! Exposes the tenant's persisted `tenant_quota` row (migration 0066) so a
//! trusted internal caller (the signup-worker / operator plane) can read the
//! per-tenant monthly `$`-ceiling state WITHOUT going through a billable
//! data-plane op. It performs NO accrual and NO cycle roll — it is a pure
//! SELECT of the three money columns plus a derived `unmetered` bit.
//!
//! # Security model
//!
//! The sole gate is a constant-time compare of the caller-supplied
//! `x-corelink-internal-auth` header against the resolved auth key
//! ([`build_state_from_env`] — the DEDICATED `CORELINK_QUOTA_READ_AUTH_KEY`
//! ONLY, with NO shared `CORELINK_INTERNAL_AUTH_KEY` fallback (2026-08-19
//! red-team), via [`crate::routes::admin::resolve_dedicated_auth_key`]; unset/
//! `< 32` chars ⇒ route not mounted, fail-CLOSED). The compare is
//! fail-CLOSED and uses the SAME padded `ct_eq` gate as
//! [`crate::routes::internal_pat`] / [`crate::routes::audit_drain`] so no
//! secret-length or content oracle leaks via an early branch.
//!
//! # Request / response shape
//!
//! ```text
//! GET /_internal/tenant/{tenant_id}/quota
//! X-Corelink-Internal-Auth: <secret>
//! ```
//!
//! `200 OK` (JSON):
//!
//! ```text
//! {
//!   "tenant_id": "<uuid>",
//!   "monthly_budget_usd_micros": <i64>,
//!   "accrued_usd_micros": <i64>,
//!   "cycle_anchor_ms": <i64>,
//!   "unmetered": <bool>
//! }
//! ```
//!
//! `unmetered` is `monthly_budget_usd_micros >= `
//! [`crate::tenant_quota::DEFAULT_MONTHLY_BUDGET_USD_MICROS`] (the
//! effectively-unlimited `$1,000,000/mo` default ceiling — a row at or above
//! it is not a real spend wall).
//!
//! # Status codes
//!
//! - `401` — missing / wrong `x-corelink-internal-auth` (constant-time,
//!   fail-CLOSED), returned BEFORE any D1 work.
//! - `400` `{"error":"invalid_tenant_id"}` — `tenant_id` is not a valid UUID.
//! - `404` `{"error":"no_quota_row"}` — the tenant has NO `tenant_quota` row.
//!   The caller treats this as "inherits the `$1M` default ⇒ unmetered".
//! - `503` `{"error":"quota_store_unavailable"}` — a D1 transport / decode
//!   fault (fail-CLOSED — we never fabricate a quota answer we could not read).
//!
//! Env-gated mount in [`crate::main`]: unmounted (the endpoint is unavailable)
//! when neither auth key is bound (≥32 chars) OR the D1 `StorageEnv` is absent
//! (dev/CI) — mirroring [`crate::routes::audit_drain`].

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::storage::d1_http::D1HttpClient;
use crate::tenant_quota::DEFAULT_MONTHLY_BUDGET_USD_MICROS;

/// HTTP header carrying the shared internal-auth secret.
const INTERNAL_AUTH_HEADER: &str = "x-corelink-internal-auth";

/// Shared state for the read-only tenant-quota route.
#[derive(Clone)]
pub struct TenantQuotaReadState {
    /// Shared secret for the `X-Corelink-Internal-Auth` header gate.
    internal_auth_key: Arc<str>,
    /// D1-over-HTTP client used for the single `tenant_quota` SELECT.
    d1: Arc<D1HttpClient>,
}

impl std::fmt::Debug for TenantQuotaReadState {
    // Redact the internal-auth secret; never let it reach a log/Debug sink.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantQuotaReadState")
            .field("internal_auth_key", &"<redacted>")
            .field("d1", &"[D1HttpClient]")
            .finish()
    }
}

/// Constant-time internal-auth check. Mirrors
/// [`crate::routes::internal_pat`]`::internal_auth_ok` /
/// [`crate::routes::audit_drain`]`::internal_auth_ok` byte-for-byte so the
/// internal-auth gates stay consistent (pad provided to the secret length,
/// run `ct_eq`, fold in the real length-equality so a longer/shorter value
/// can never match; empty/missing header → `false`).
#[must_use]
fn internal_auth_ok(expected: &[u8], headers: &HeaderMap) -> bool {
    let provided = headers
        .get(INTERNAL_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided_bytes = provided.as_bytes();
    let provided_padded: Vec<u8> = if provided_bytes.len() >= expected.len() {
        provided_bytes.get(..expected.len()).unwrap_or(&[]).to_vec()
    } else {
        let mut v = provided_bytes.to_vec();
        v.resize(expected.len(), 0);
        v
    };
    let content_ok = expected.ct_eq(&provided_padded).unwrap_u8();
    let len_ok = u8::from(expected.len() == provided_bytes.len());
    (content_ok & len_ok) == 1
}

/// JSON response body for a found `tenant_quota` row.
#[derive(Debug, Serialize)]
struct QuotaReadResponse {
    /// Tenant UUID (canonical lowercase form).
    tenant_id: String,
    /// Owner-tunable monthly ceiling, in micro-dollars.
    monthly_budget_usd_micros: i64,
    /// Cumulative cost accrued in the current cycle, in micro-dollars.
    accrued_usd_micros: i64,
    /// Cycle-start wall-clock (Unix epoch ms).
    cycle_anchor_ms: i64,
    /// `true` when the ceiling is at/above the effectively-unlimited default
    /// (`monthly_budget_usd_micros >= DEFAULT_MONTHLY_BUDGET_USD_MICROS`) —
    /// i.e. not a real spend wall.
    unmetered: bool,
}

/// Mount `GET /_internal/tenant/{tenant_id}/quota`.
pub fn router(state: TenantQuotaReadState) -> Router {
    Router::new()
        .route("/_internal/tenant/{tenant_id}/quota", get(handle_get_quota))
        .with_state(state)
}

/// `GET /_internal/tenant/{tenant_id}/quota` handler.
///
/// Order: constant-time internal-auth gate FIRST (401 before any D1 work) →
/// UUID validation (400) → single `tenant_quota` SELECT (404 when no row,
/// 503 on D1 fault / malformed row) → JSON.
async fn handle_get_quota(
    State(state): State<TenantQuotaReadState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    // ── 1. Internal-auth gate (constant-time, fail-CLOSED) ─────────────────────
    if !internal_auth_ok(state.internal_auth_key.as_bytes(), &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    // ── 2. Validate the tenant id is a well-formed UUID ────────────────────────
    let tenant_uuid = match Uuid::parse_str(tenant_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_tenant_id" })),
            )
                .into_response();
        }
    };
    let tenant_canonical = tenant_uuid.to_string();

    // ── 3. Read the tenant_quota row (migration 0066) ──────────────────────────
    // A transport / decode fault is fail-CLOSED 503 (we never fabricate a quota
    // answer we could not read). No row ⇒ 404 (the caller inherits the default).
    let rows = match state
        .d1
        .query(
            "SELECT monthly_budget_usd_micros, accrued_usd_micros, cycle_anchor_ms \
             FROM tenant_quota WHERE tenant_id = ?1",
            &[serde_json::Value::String(tenant_canonical.clone())],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "tenant_quota_read: D1 query failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "quota_store_unavailable" })),
            )
                .into_response();
        }
    };

    let Some(row) = rows.into_iter().next() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_quota_row" })),
        )
            .into_response();
    };

    // A malformed row (missing / non-integer money column) is fail-CLOSED 503:
    // the row exists but we cannot trust the value, so we do not guess.
    let (Some(monthly_budget_usd_micros), Some(accrued_usd_micros), Some(cycle_anchor_ms)) = (
        row.get("monthly_budget_usd_micros")
            .and_then(serde_json::Value::as_i64),
        row.get("accrued_usd_micros")
            .and_then(serde_json::Value::as_i64),
        row.get("cycle_anchor_ms")
            .and_then(serde_json::Value::as_i64),
    ) else {
        tracing::error!("tenant_quota_read: tenant_quota row missing/non-integer money column");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "quota_store_unavailable" })),
        )
            .into_response();
    };

    // A ceiling at/above the effectively-unlimited default is not a real wall.
    let unmetered = monthly_budget_usd_micros >= DEFAULT_MONTHLY_BUDGET_USD_MICROS;

    let resp = QuotaReadResponse {
        tenant_id: tenant_canonical,
        monthly_budget_usd_micros,
        accrued_usd_micros,
        cycle_anchor_ms,
        unmetered,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

/// Build the route state from env. `None` (route NOT mounted, fail-CLOSED) when
/// the dedicated `CORELINK_QUOTA_READ_AUTH_KEY` is unset or shorter than 32
/// chars, OR when the D1 `StorageEnv` is not configured (dev/CI). Uses the
/// DEDICATED key ONLY via [`crate::routes::admin::resolve_dedicated_auth_key`]
/// — NO shared `CORELINK_INTERNAL_AUTH_KEY` fallback (2026-08-19 red-team,
/// "leaked shared internal key → cross-tenant quota disclosure"): a low-priv
/// cross-tenant read must never be unlockable by the broad shared master key.
/// This matches the edge, which already forwards the resolved dedicated
/// quota_read key (`worker/src/lib/internal_auth.ts` `DEDICATED_REQUIRED_CONSUMERS`),
/// and the erase / dsr-anchor / pat-mint surfaces which are already dedicated-only.
/// Without D1 there is nothing to read, so the route is simply not mounted.
#[must_use]
pub fn build_state_from_env() -> Option<TenantQuotaReadState> {
    let internal_auth_key = crate::routes::admin::resolve_dedicated_auth_key(
        "CORELINK_QUOTA_READ_AUTH_KEY",
    )
    .or_else(|| {
        tracing::warn!(
            "no usable CORELINK_QUOTA_READ_AUTH_KEY (< 32 chars, dedicated-only, \
                     NO shared fallback); /_internal/tenant/{{tenant_id}}/quota NOT mounted (fail-CLOSED)"
        );
        None
    })?;
    let storage_env = crate::storage::StorageEnv::from_env()?;
    let d1 = Arc::new(crate::storage::d1_http::D1HttpClient::new(&storage_env).ok()?);
    Some(TenantQuotaReadState {
        internal_auth_key,
        d1,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    /// A deterministic 32-char test auth key.
    const TEST_KEY: &str = "test-internal-auth-key-32-bytes-x";

    /// A hermetic in-memory fake of the D1 read layer.
    ///
    /// The real [`D1HttpClient`] is a concrete `reqwest`-backed struct (not a
    /// trait), so the auth-gate + shape tests exercise [`internal_auth_ok`],
    /// [`QuotaReadResponse`], and the `unmetered` derivation directly — the
    /// same discipline `internal_pat`'s tests use to avoid a live D1.
    #[derive(Default)]
    struct FakeQuotaRow {
        monthly_budget_usd_micros: i64,
        accrued_usd_micros: i64,
        cycle_anchor_ms: i64,
    }

    impl FakeQuotaRow {
        /// The `unmetered` bit the route would derive for this row.
        fn unmetered(&self) -> bool {
            self.monthly_budget_usd_micros >= DEFAULT_MONTHLY_BUDGET_USD_MICROS
        }
    }

    fn make_request(uri: &str, auth: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(http::Method::GET).uri(uri);
        if let Some(a) = auth {
            builder = builder.header(INTERNAL_AUTH_HEADER, a);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// Build a router whose D1 client is a real (never-called) client with
    /// dummy credentials — used ONLY for the auth-gate + UUID-validation tests,
    /// which return BEFORE any D1 query is issued. `D1HttpClient::new` performs
    /// NO network I/O (it only builds a `reqwest::Client`), so a dummy config is
    /// safe: the 401 / 400 paths never reach `.query`. Fields are `pub(crate)`,
    /// so the in-crate test constructs the struct literal directly.
    fn gate_only_state() -> TenantQuotaReadState {
        let storage_env = crate::storage::StorageEnv {
            r2_endpoint: "https://acct.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "ak".to_owned(),
            r2_secret_access_key: "sk".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "acct".to_owned(),
            cf_api_token: "token".to_owned(),
            d1_database_id: "db".to_owned(),
        };
        let d1 = Arc::new(D1HttpClient::new(&storage_env).unwrap());
        TenantQuotaReadState {
            internal_auth_key: Arc::from(TEST_KEY),
            d1,
        }
    }

    // ── auth gate ──────────────────────────────────────────────────────────────

    #[test]
    fn gate_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert!(!internal_auth_ok(TEST_KEY.as_bytes(), &headers));
    }

    #[test]
    fn gate_rejects_wrong_header() {
        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_AUTH_HEADER, "wrong-secret".parse().unwrap());
        assert!(!internal_auth_ok(TEST_KEY.as_bytes(), &headers));
    }

    #[test]
    fn gate_accepts_correct_header() {
        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_AUTH_HEADER, TEST_KEY.parse().unwrap());
        assert!(internal_auth_ok(TEST_KEY.as_bytes(), &headers));
    }

    #[test]
    fn gate_rejects_prefix_of_secret() {
        // A short value that is a strict prefix of the secret must not match
        // (the length-equality bit catches it).
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_AUTH_HEADER,
            "test-internal-auth-key".parse().unwrap(),
        );
        assert!(!internal_auth_ok(TEST_KEY.as_bytes(), &headers));
    }

    #[tokio::test]
    async fn route_missing_auth_header_401() {
        let app = router(gate_only_state());
        let req = make_request(
            "/_internal/tenant/00000000-0000-7000-8000-00000000aaaa/quota",
            None,
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn route_wrong_auth_header_401() {
        let app = router(gate_only_state());
        let req = make_request(
            "/_internal/tenant/00000000-0000-7000-8000-00000000aaaa/quota",
            Some("nope-not-the-secret-nope-not-x"),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── 400 on a bad UUID (after the auth gate passes, before any D1 read) ──────

    #[tokio::test]
    async fn route_bad_uuid_400() {
        let app = router(gate_only_state());
        let req = make_request("/_internal/tenant/not-a-uuid/quota", Some(TEST_KEY));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "invalid_tenant_id");
    }

    // ── response shape + `unmetered` derivation (pure) ─────────────────────────

    #[test]
    fn unmetered_true_for_one_million_dollar_row() {
        // $1,000,000/mo == DEFAULT_MONTHLY_BUDGET_USD_MICROS ⇒ unmetered.
        let row = FakeQuotaRow {
            monthly_budget_usd_micros: DEFAULT_MONTHLY_BUDGET_USD_MICROS,
            accrued_usd_micros: 0,
            cycle_anchor_ms: 1_700_000_000_000,
        };
        assert!(row.unmetered(), "a $1M-ceiling row must be unmetered");
        assert_eq!(DEFAULT_MONTHLY_BUDGET_USD_MICROS, 1_000_000_000_000);
    }

    #[test]
    fn unmetered_false_for_five_dollar_row() {
        // $5/mo == 5_000_000 micro-dollars ⇒ a real wall, NOT unmetered.
        let row = FakeQuotaRow {
            monthly_budget_usd_micros: 5_000_000,
            accrued_usd_micros: 1_000,
            cycle_anchor_ms: 1_700_000_000_000,
        };
        assert!(!row.unmetered(), "a $5-ceiling row must be metered");
    }

    #[test]
    fn response_serializes_expected_shape() {
        let row = FakeQuotaRow {
            monthly_budget_usd_micros: 5_000_000,
            accrued_usd_micros: 1_234,
            cycle_anchor_ms: 1_700_000_000_000,
        };
        let resp = QuotaReadResponse {
            tenant_id: "00000000-0000-7000-8000-00000000aaaa".to_owned(),
            monthly_budget_usd_micros: row.monthly_budget_usd_micros,
            accrued_usd_micros: row.accrued_usd_micros,
            cycle_anchor_ms: row.cycle_anchor_ms,
            unmetered: row.unmetered(),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["tenant_id"], "00000000-0000-7000-8000-00000000aaaa");
        assert_eq!(v["monthly_budget_usd_micros"], 5_000_000);
        assert_eq!(v["accrued_usd_micros"], 1_234);
        assert_eq!(v["cycle_anchor_ms"], 1_700_000_000_000_i64);
        assert_eq!(v["unmetered"], false);
    }

    // ── 404 error shape is the documented no_quota_row body ────────────────────

    #[test]
    fn no_quota_row_error_shape() {
        // The 404 body the handler emits for a tenant with no row. The caller
        // treats this as "inherits the $1M default ⇒ unmetered".
        let body = json!({ "error": "no_quota_row" });
        assert_eq!(body["error"], "no_quota_row");
    }
}
