//! `POST /_internal/dsr/anchor` — per-user DSR legitimacy-anchor registration
//! (GDPR1; the hugit/githugr per-user erasure path).
//!
//! ## Why this exists
//!
//! The CAS physical-erase seam (`/_internal/cas/:tenant/:hash/erase`,
//! [`crate::routes::cas_erase`]) authorises a per-digest delete ONLY if a
//! `dsr_requested` legitimacy row exists for `(dsr_id, tenant)` — so a leaked
//! erase key alone cannot erase arbitrary blobs. The two existing writers of that
//! anchor are BOTH whole-account (the Clerk `user.deleted` webhook and self-serve
//! `POST /v1/customer/account/delete`, keyed by the caller's own Clerk user id).
//! Neither fits a **per-user** erasure inside a shared multi-user tenant — e.g.
//! hugit's git-CAS tenant `d863fafb`, where a githugr user is NOT a Clerk user of
//! the tenant and hugit erases one user's digests, not the whole tenant.
//!
//! ## The anti-forge model
//!
//! This seam lets the erasure-REQUEST authority (e.g. githugr, which
//! authenticated the user's request) register the anchor: it derives the
//! deterministic `dsr_id` from a stable subject key and `INSERT OR IGNORE`s the
//! `dsr_requested` row, so the downstream executor (hugit) can then call the
//! per-digest erase with that `dsr_id`. It is gated by a DEDICATED key
//! (`CORELINK_DSR_ANCHOR_AUTH_KEY`) that MUST be held by a DIFFERENT authority
//! than the erase key — the whole point of the legitimacy gate is that the party
//! writing the anchor is not the party doing the delete (mirroring the Clerk
//! model: the webhook writes the anchor, a different consumer erases).
//!
//! Fail-CLOSED: wrong/absent auth → 401; non-UUID tenant or empty subject → 400;
//! any D1 fault → 500. Idempotent: `dsr_id` is deterministic and the write is
//! `INSERT OR IGNORE`, so a repeat registration is a harmless no-op.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::storage::d1_http::D1HttpClient;

/// HTTP header carrying the internal-auth secret (byte-for-byte the other
/// `/_internal/*` surfaces).
const INTERNAL_AUTH_HEADER: &str = "x-corelink-internal-auth";

/// Canonical anchor route path.
pub const DSR_ANCHOR_ROUTE: &str = "/_internal/dsr/anchor";

/// Route state: a D1 client for the `dsr_requested` write + the internal-auth key.
#[derive(Clone)]
pub struct DsrAnchorRouteState {
    d1: Arc<D1HttpClient>,
    internal_auth_key: Arc<str>,
}

impl core::fmt::Debug for DsrAnchorRouteState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DsrAnchorRouteState")
            .field("internal_auth_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// `POST /_internal/dsr/anchor` router.
pub fn router(state: DsrAnchorRouteState) -> Router {
    Router::new()
        .route(DSR_ANCHOR_ROUTE, post(handle_anchor))
        .with_state(state)
}

/// Build the route state from the environment (D1 via `StorageEnv`). Returns
/// `None` (route unmounted, fail-CLOSED) when the auth key is absent or D1 is
/// unconfigured — mirrors [`crate::routes::cas_erase::build_state_from_env`].
pub fn build_state_from_env(internal_auth_key: Option<Arc<str>>) -> Option<DsrAnchorRouteState> {
    let internal_auth_key = internal_auth_key?;
    let env = crate::storage::StorageEnv::from_env()?;
    let d1 = match D1HttpClient::new(&env) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::warn!(error = %e, "dsr_anchor: D1 client build failed; route NOT mounted");
            return None;
        }
    };
    Some(DsrAnchorRouteState {
        d1,
        internal_auth_key,
    })
}

/// Constant-time internal-auth check (folds length; mirrors the other
/// `/_internal/*` gates).
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Request body: the tenant that owns the data + a STABLE subject key (e.g. a
/// githugr user id) from which the deterministic `dsr_id` is derived.
#[derive(serde::Deserialize)]
struct AnchorBody {
    tenant: String,
    subject_key: String,
}

/// `POST /_internal/dsr/anchor`.
///
/// Order (fail-CLOSED): internal-auth gate (constant-time, BEFORE body parse) →
/// parse body → tenant-UUID + non-empty-subject validation → derive `dsr_id` →
/// `INSERT OR IGNORE` the `dsr_requested` anchor. Returns `{ "dsr_id": … }`.
async fn handle_anchor(
    State(state): State<DsrAnchorRouteState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // 1. Internal-auth gate — BEFORE body parse (no shape leak to an unauth'd caller).
    if !internal_auth_ok(state.internal_auth_key.as_bytes(), &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    // 2. Parse + validate.
    let Ok(parsed) = serde_json::from_slice::<AnchorBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json body").into_response();
    };
    // Tenant MUST be a UUID (the `dsr_requested` gate binds tenant as a UUID; a
    // non-UUID could never satisfy the erase legitimacy check).
    let Ok(tenant_uuid) = Uuid::parse_str(parsed.tenant.trim()) else {
        return (StatusCode::BAD_REQUEST, "tenant must be a uuid").into_response();
    };
    let subject_key = parsed.subject_key.trim();
    if subject_key.is_empty() {
        return (StatusCode::BAD_REQUEST, "subject_key required").into_response();
    }

    // 3. Derive the deterministic dsr_id (SAME algorithm as the Clerk/self-serve
    //    paths, so a per-user anchor is idempotency-compatible with any other
    //    writer for the same subject key).
    let dsr_id = crate::routes::customer::deterministic_dsr_id(subject_key);

    // 4. INSERT OR IGNORE the legitimacy anchor (idempotent).
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let sql = "INSERT OR IGNORE INTO dsr_requested (dsr_id, tenant_id, requested_at, status) \
               VALUES (?1, ?2, ?3, 'requested')";
    let params = [json!(dsr_id), json!(tenant_uuid.to_string()), json!(now)];
    match state.d1.query(sql, &params).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "dsr_id": dsr_id }))).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "dsr_anchor: anchor write failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "anchor write failed").into_response()
        }
    }
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
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    const TEST_KEY: &str = "test-internal-auth-key-0123456789abcdef";
    const TENANT: &str = "d863fafb-17c3-4ec3-92f6-b5a85c27d7bd";

    // A state whose D1 client merely BUILDS (no connection). The security-critical
    // paths (auth gate + input validation) all short-circuit BEFORE any D1 call,
    // so these tests never touch the network.
    fn state() -> DsrAnchorRouteState {
        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            r2_session_token: None,
            cloudflare_account_id: "acct123".to_owned(),
            cf_api_token: "tok".to_owned(),
            d1_database_id: "db456".to_owned(),
        };
        DsrAnchorRouteState {
            d1: Arc::new(D1HttpClient::new(&env).expect("client")),
            internal_auth_key: Arc::from(TEST_KEY),
        }
    }

    fn req(auth: Option<&str>, body: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(DSR_ANCHOR_ROUTE);
        if let Some(a) = auth {
            b = b.header(INTERNAL_AUTH_HEADER, a);
        }
        b.body(Body::from(body.to_owned())).expect("req")
    }

    #[tokio::test]
    async fn missing_auth_is_401_before_body() {
        let resp = router(state())
            .oneshot(req(None, "not even json"))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_auth_is_401() {
        let resp = router(state())
            .oneshot(req(Some("wrong-key"), "{}"))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_uuid_tenant_is_400() {
        let resp = router(state())
            .oneshot(req(
                Some(TEST_KEY),
                r#"{"tenant":"not-a-uuid","subject_key":"u1"}"#,
            ))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_subject_is_400() {
        let resp = router(state())
            .oneshot(req(
                Some(TEST_KEY),
                &format!(r#"{{"tenant":"{TENANT}","subject_key":"  "}}"#),
            ))
            .await
            .expect("resp");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // The authed happy path reaches a real D1 HTTP write, which the shape-only
    // container test harness cannot serve; its behaviour is exercised end-to-end
    // by hugit's integration smoke. The security-critical gate + input validation
    // (above) all short-circuit before any D1 call and are fully covered here.
}
