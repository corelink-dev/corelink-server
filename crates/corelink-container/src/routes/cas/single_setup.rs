/// Build the canonical `Arc<dyn CasReadHandler>` for the current
/// build target and runtime environment.
///
/// # Runtime selection (WP-S1 Phase 1)
///
/// On native targets the function probes for storage credentials at
/// runtime:
///
/// - When `R2_S3_ACCESS_KEY_ID`, `R2_S3_SECRET_ACCESS_KEY`,
///   `R2_S3_ENDPOINT`, `CLOUDFLARE_ACCOUNT_ID`, `CF_API_TOKEN`, and
///   `D1_DATABASE_ID` are all present in the environment,
///   [`R2CasHandler`](crate::storage::r2_s3::R2CasHandler) is
///   constructed against `corelink-cas-prod` (override via
///   `R2_CAS_BUCKET`). This is the **production path**.
///
/// - When credentials are absent (unit tests, local dev, CI) the
///   function falls back to `InMemoryCasHandler`. No network I/O
///   occurs.
///
/// - When credentials ARE present but the R2 handler refuses to build
///   (today exactly the "`R2_TDK_HEX` required" case — F1, CAA-360) the
///   function does NOT silently degrade to `InMemoryCasHandler` (that
///   would serve a non-durable cache with no alarm). It instead mounts
///   the fail-CLOSED [`UnavailableCasHandler`], whose every read/write
///   maps to HTTP 503 until `R2_TDK_HEX` is set, and emits a loud,
///   structured `tracing::error!`.
///
/// On `wasm32-unknown-unknown` (Cloudflare Worker target) a
/// compile-error placeholder is emitted per the
/// `trait-abstraction-defer` rule; the wasm32 binding is out of
/// scope for WP-S1.
///
/// # Panics
///
/// Does not panic. If the R2 client cannot be constructed with creds
/// present (malformed endpoint URL, missing `R2_TDK_HEX`, etc.) an
/// error is logged and the route is served by the fail-CLOSED
/// [`UnavailableCasHandler`] (HTTP 503), never the silent `InMemory`
/// fallback.
#[must_use]
pub fn build_handlers() -> CasHandlers {
    build_handlers_with_byok(None)
}

/// Attach the boot-owned BYOK collaborators to a real CAS handler.
///
/// Keeping this small composition seam separate lets the router factory and
/// its controlled integration test exercise the exact production attachment.
pub(crate) fn attach_byok_to_r2_handler(
    handler: crate::storage::r2_s3::R2CasHandler,
    byok: Option<&crate::storage::byok_cas::DataPlaneByok>,
) -> crate::storage::r2_s3::R2CasHandler {
    let Some(byok) = byok else {
        return handler;
    };
    // An unarmed (no-provider) set has no resolver or encryptor: attach its
    // config view only, so engaged tenants are refused fail-closed (#1648).
    let (Some(resolver), Some(mode_b)) = (byok.tcs_resolver(), byok.mode_b()) else {
        return handler.with_byok_unarmed(byok.config_cache());
    };
    let handler = handler
        .with_byok(byok.config_cache(), resolver)
        .with_byok_random(mode_b);
    match byok.runtime_gate() {
        Some(gate) => handler.with_byok_runtime_gate(gate),
        None => handler,
    }
}

/// Build CAS handlers with the process's one BYOK collaborator set.
///
/// `build_handlers` remains the compatibility entry point for callers that do
/// not own production composition.  The router uses this form so storage and
/// accounting can share the identical config-cache `Arc`.
#[must_use]
pub fn build_handlers_with_byok(
    byok: Option<&crate::storage::byok_cas::DataPlaneByok>,
) -> CasHandlers {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::storage::{r2_s3, StorageEnv};

        // Probe for storage credentials.
        if StorageEnv::from_env().is_some() {
            // Credentials are present — try to build the real handler.
            // Empty-or-absent → default (see storage::env_or; mirrors the
            // AC fix for the 2026-06-05 prod incident — latent here).
            let bucket = crate::storage::env_or("R2_CAS_BUCKET", "corelink-cas-prod");
            // F7 (2026-06-13 CAA-360 audit) — CAS residency. The CAS storage
            // region is keyed per-env from `R2_CAS_REGION` (FROZEN CONTRACT),
            // set by `[env.prod-<region>].vars` in `wrangler.toml` and forwarded
            // by the DO `container.start({env})` list (F8). This is what makes a
            // regional env (sam/lhr/nrt/syd) key its CAS objects under its OWN
            // region instead of the US default — closing the Schrems-II / GDPR
            // Art. 44 gap for CAS content. The default `"iad"` applies only to
            // the IAD env; a regional env that lacks the binding silently
            // degrades to IAD, so the binding is asserted by the residency
            // invariant test (`residency_invariant_every_regional_env_sets_cas_region`)
            // that fails the build if any `[env.prod-<r>]` omits `R2_CAS_REGION`.
            let region = crate::storage::env_or("R2_CAS_REGION", "iad");

            // Construction is now sync-only (commit ead0f37a removed the
            // aws_config::defaults() IMDS probe). We keep block_in_place +
            // block_on around the async signature in case future R2 init
            // grows network work; the cost is zero when the inner future
            // resolves immediately.
            let handle = tokio::runtime::Handle::current();
            let built = tokio::task::block_in_place(|| {
                handle.block_on(r2_s3::build_r2_cas_handler_from_env(&bucket, &region))
            });
            match built {
                Some(Ok(handler)) => {
                    tracing::info!(
                        bucket = %bucket,
                        region = %region,
                        "CAS handler: R2S3 (real storage)"
                    );
                    // R2CasHandler implements both CasReadHandler and
                    // CasWriteHandler against the same R2 bucket; share
                    // one Arc behind both trait objects.
                    let handler = attach_byok_to_r2_handler(handler, byok);
                    let shared: Arc<r2_s3::R2CasHandler> = Arc::new(handler);
                    let read: Arc<dyn CasReadHandler> = shared.clone();
                    let write: Arc<dyn CasWriteHandler> = shared.clone();
                    let delete: Arc<dyn CasDeleteHandler> = shared.clone();
                    let list: Arc<dyn CasListHandler> = shared;
                    return (read, write, delete, list);
                }
                Some(Err(e)) => {
                    // F1 (CAA-360) fail-CLOSED + LOUD: storage creds ARE present
                    // (this is the production data plane), but the R2 handler
                    // refused to build — today exactly "R2_TDK_HEX required". We
                    // MUST NOT silently fall back to the non-durable `InMemory`
                    // cache (that is fail-OPEN-ish: a broken cache with no
                    // alarm). Mount the fail-CLOSED `UnavailableCasHandler`
                    // instead: every read/write returns 503 until `R2_TDK_HEX` is
                    // set. Distinct from the creds-ABSENT case below (`None` ⇒
                    // dev/CI `InMemory`, which is fine).
                    tracing::error!(
                        error = %e,
                        bucket = %bucket,
                        region = %region,
                        "CAS handler: R2S3 build REFUSED with storage creds present \
                         (R2_TDK_HEX unset/invalid?) — mounting fail-CLOSED 503 \
                         handler, NOT InMemory (F1 INV-TENANT-ISOLATION)"
                    );
                    let shared: Arc<UnavailableCasHandler> = Arc::new(UnavailableCasHandler);
                    let read: Arc<dyn CasReadHandler> = shared.clone();
                    let write: Arc<dyn CasWriteHandler> = shared.clone();
                    let delete: Arc<dyn CasDeleteHandler> = shared.clone();
                    let list: Arc<dyn CasListHandler> = shared;
                    return (read, write, delete, list);
                }
                None => {
                    // Should not happen: we already checked is_some().
                }
            }
        }

        // Fallback: InMemory — creds ABSENT (unit tests, local dev, CI). This is
        // the dev/CI path; production always has storage creds and takes the R2
        // branch above (which now fails CLOSED on a missing TDK).
        tracing::info!("CAS handler: InMemory (no storage credentials configured)");
        let audit = Arc::new(InMemoryAuditSink::new());
        let sli = Arc::new(InMemorySliObserver::new());
        let shared: Arc<InMemoryCasHandler> = Arc::new(InMemoryCasHandler::new(audit, sli));
        let read: Arc<dyn CasReadHandler> = shared.clone();
        let write: Arc<dyn CasWriteHandler> = shared.clone();
        let delete: Arc<dyn CasDeleteHandler> = shared.clone();
        let list: Arc<dyn CasListHandler> = shared;
        (read, write, delete, list)
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Placeholder for `corelink_handler_cas::cf_worker::CfWorkerCasHandler`
        // (deferred per trait-abstraction-defer; see crate-level docs).
        // Until that impl lands, the wasm32 build does not include
        // this route — the binary entry asserts the cfg at link time.
        compile_error!(
            "wasm32 CF-Worker CAS handler not implemented yet; \
             tracked as WI-S04-CF-WIRING"
        );
    }
}

/// Build the axum `Router` exposing the CAS read + write routes.
///
/// Both routes share the `/v1/cas/:tenant/:hash` template; axum
/// disambiguates by HTTP method (GET vs PUT).
pub fn router(state: CasRouteState) -> Router {
    Router::new()
        .route(
            CAS_READ_ROUTE,
            get(handle_read)
                .put(handle_write)
                .delete(handle_delete)
                .layer(axum::extract::DefaultBodyLimit::max(
                    corelink_hash::CACHE_ENTRY_MAX_BYTES,
                )),
        )
        .route(CAS_LIST_ROUTE, get(handle_list))
        // Bulk routes. These are SIBLINGS of `/v1/cas/:tenant/:hash`, not
        // captures of it: matchit-0.7 ranks the static `batch` / `batch-read` /
        // `batch-exists` literals ABOVE the `:hash` wildcard, so `POST
        // /v1/cas/t/batch` matches this route and `GET /v1/cas/t/<hash>` still
        // matches the read route (no method collision either — these are POST).
        .route(
            CAS_BATCH_ROUTE,
            post(handle_batch_write).layer(axum::extract::DefaultBodyLimit::max(
                BATCH_REQUEST_BODY_LIMIT_BYTES,
            )),
        )
        .route(
            CAS_BATCH_READ_ROUTE,
            post(handle_batch_read).layer(axum::extract::DefaultBodyLimit::max(
                BATCH_REQUEST_BODY_LIMIT_BYTES,
            )),
        )
        .route(
            CAS_BATCH_EXISTS_ROUTE,
            post(handle_batch_exists).layer(axum::extract::DefaultBodyLimit::max(
                BATCH_REQUEST_BODY_LIMIT_BYTES,
            )),
        )
        .with_state(state)
}

/// `true` if `headers` declares a `Content-Type` whose media type (ignoring any
/// `; charset=…` suffix and ASCII case) is one of `accepted`. Used by the batch
/// routes for the FROZEN 415 gate: a wrong/absent type is rejected BEFORE the
/// body is parsed (the length-framed wire format must not be misread as a
/// generic octet-stream).
fn content_type_is(headers: &axum::http::HeaderMap, accepted: &[&str]) -> bool {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip parameters (`application/x-ndjson; charset=utf-8`) and trim.
    let media = ct.split(';').next().unwrap_or("").trim();
    accepted.iter().any(|a| media.eq_ignore_ascii_case(a))
}

/// 413 over-cap body shared by `/batch` and `/batch-read` (FROZEN contract).
fn batch_too_large() -> axum::response::Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({
            "error": "batch_too_large",
            "limit_objects": BATCH_MAX_OBJECTS,
            "limit_bytes": BATCH_MAX_BYTES,
        })),
    )
        .into_response()
}

/// One manifest line of a `/batch` upload: a claimed content hash + the exact
/// byte length that follows for that object in the concatenated payload.
#[derive(serde::Deserialize)]
struct BatchUploadManifestEntry {
    /// Claimed blake3 content hash (validated canonical per object).
    hash: String,
    /// Exact byte length of this object in the length-framed payload.
    len: u64,
}

/// One NDJSON request line of `/batch-read` and `/batch-exists`.
#[derive(serde::Deserialize)]
struct BatchHashRequest {
    /// Requested content hash.
    hash: String,
}

/// Split a length-framed batch body into its manifest text and the raw payload
/// bytes at the FIRST blank line (`\n\n`). The manifest is the bytes before the
/// terminating blank line; the payload is everything after it. `None` ⇒ no blank
/// line terminator present (a framing error ⇒ 400 for the whole request).
fn split_manifest(body: &[u8]) -> Option<(&[u8], &[u8])> {
    // The manifest is newline-delimited JSON terminated by a SINGLE blank line.
    // After the last manifest line's `\n` there is one more `\n` (the blank
    // line), so the separator is `\n\n`. An empty manifest (zero objects) is
    // still framed by a leading blank line, i.e. the body begins with `\n`.
    let sep = body.windows(2).position(|w| w == b"\n\n")?;
    // `sep` is the index of the manifest-terminating `\n`; `sep + 1` is the
    // blank line's `\n`. The manifest is `..=sep` (includes the terminating
    // newline) and the payload is everything after the blank line (`sep + 2..`).
    // `position` guarantees `sep + 1 < body.len()`, so `sep + 2 <= body.len()`
    // and both `split_at` indices are in bounds (no panic — clippy-safe).
    let (manifest, rest) = body.split_at(sep + 1);
    let payload = rest.get(1..).unwrap_or(&[]);
    Some((manifest, payload))
}

/// Run the native PAT possession gate (finding #4) when it is wired.
///
/// Reads the bearer PAT from the `Authorization` header and re-verifies it
/// (Argon2id, full Option-B pipeline) against the claimed `tenant`. `Some(resp)`
/// ⇒ REJECT (401 forged/wrong-tenant / 503 verifier fault); `None` ⇒ proceed (or
/// when the gate is absent in dev/CI). Called at the TOP of each billable
/// handler, AFTER the scope+tenant gate, BEFORE storage.
async fn pat_gate_reject(
    state: &CasRouteState,
    tenant: &str,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    let gate = state.pat_gate.as_ref()?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    gate.verify(tenant, bearer).await.err()
}

/// Write-path variant of [`pat_gate_reject`]: independently re-derives the
/// PAT's D1-stored `can_write` capability at the container (via
/// `NativePatGate::verify_write`), not just tenant possession. This upholds the
/// Option-B invariant — "a compromised or misconfigured Worker cannot grant
/// write on its own" — on the CAS write path, matching the sibling build
/// surfaces (Bazel `pat_gate_reject_write`, Turbo/cargo/OCI `verify_write`).
/// A read-only PAT presented on a write path is rejected `403` even if the
/// Worker-set scope header claimed write (deep-audit money/auth F-1).
async fn pat_gate_reject_write(
    state: &CasRouteState,
    tenant: &str,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    let gate = state.pat_gate.as_ref()?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    gate.verify_write(tenant, bearer).await.err()
}
