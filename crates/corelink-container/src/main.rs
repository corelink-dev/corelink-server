//! CoreLink server binary entry point.
//!
//! Hosts a single HTTP/1.1 stack on `PORT` (default 50051) — the port the
//! Cloudflare Durable Object talks to via `container.getTcpPort()` (an HTTP
//! fetcher). It serves:
//! - the composed data-plane router (CAS / AC / Admin / audit-export /
//!   audit-analytics / signup),
//! - `GET /_health` for the DO's container-readiness probe,
//! - and the R2-12 Stripe webhook route at `/v1/billing/stripe-webhook`
//!   (merged in only when `STRIPE_WEBHOOK_SECRET` is set).
//!
//! Historical note: this binary previously bound a tonic gRPC server on
//! 50051 that served only the Health service, while the composed axum router
//! was built and DISCARDED (`_composed_router`) — so the product data plane
//! was never reachable. The DO only ever speaks HTTP to this port, so the
//! gRPC server was dead weight blocking the port; it has been removed in
//! favour of serving the real HTTP data plane here.
#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![allow(
    clippy::uninlined_format_args,
    clippy::format_in_format_args,
    reason = "scaffolding lints — main.rs is the binary entry"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use corelink_billing::stripe::real::webhook_dispatch::{
    InMemoryIdempotencyStore, RecordingSliRecorder, StateMaterializer, SystemClock,
    WebhookDispatcher,
};
use corelink_billing_stripe_materializer::{
    BillingAuditEmitter, BillingD1Writer, D1SubscriptionStateHandler, InMemoryBillingAuditEmitter,
    InMemoryBillingD1, RealStripeAuditEmitter,
};
use corelink_server::billing_d1_http::D1HttpBillingWriter;
use corelink_server::current_subscription_authority::StripeCurrentSubscriptionAuthority;
use corelink_server::routes;
use corelink_server::routes::audit_analytics::ShadowSinkFactory;
use corelink_server::webhook::{router as webhook_router, WebhookState};
use tracing::{info, warn};

#[path = "main_boot.rs"]
mod boot;
#[path = "main_byok.rs"]
mod byok;
#[path = "main_runtime.rs"]
mod runtime;
#[cfg(any(
    test,
    feature = "byok-aws-real",
    feature = "byok-gcp-real",
    feature = "byok-azure-real",
    feature = "byok-vault-real"
))]
use boot::byok_revocation_scheduler_enabled;
use boot::{
    build_runners_resolver, build_tier_selector, cache_tier_price_ids_missing_in_prod,
    email_hash_salt_missing_in_prod, should_fatal_on_missing_gate,
};
#[cfg(test)]
use boot::{build_runners_resolver_from, build_tier_selector_from};
use byok::start_byok_background_tasks;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,corelink_server=info".into()),
        )
        .init();

    // B-077: refuse to serve if the compiled process-wide memory envelope no
    // longer fits the deployed basic container. This is intentionally before
    // route construction or listener bind so a stale resize fails closed.
    corelink_server::container_capacity::validate_runtime_budget()
        .map_err(|reason| format!("container capacity invariant failed: {reason}"))?;

    // Determine storage backing once at boot so `/_health` can surface it.
    // This mirrors the decision gate in `routes/cas.rs` and `routes/ac.rs`
    // without touching those files (they are owned by agent A3).
    let storage_backing: &'static str =
        if corelink_server::storage::StorageEnv::from_env().is_some() {
            "r2"
        } else {
            warn!(
                storage = "inmemory",
                "CAS/AC falling back to InMemory store — set R2_S3_* env vars for durable storage"
            );
            "inmemory"
        };
    // Unwrap is safe: this is the only setter and it runs before the listener.
    runtime::record_storage_backing(storage_backing);
    info!(storage = storage_backing, "storage backing selected");

    // ── Native PAT-gate fail-CLOSED boot guard (red-team finding #7, HIGH) ──
    // The native planes (CAS/AC/Bazel/Turbo) only carry their container-side
    // Argon2id possession backstop when `adapter_pat::PatVerifier::from_env()`
    // builds. That builder fails-CLOSED to `None` on a PRESENT-but-malformed
    // `PAT_SIGNING_KEY` rotation sibling — and in PROD that `None` would
    // silently mount the planes WITHOUT the backstop fleet-wide. So in prod a
    // missing gate is FATAL: we refuse to boot rather than serve degraded.
    //
    // Prod is detected by the same two signals that PROVE prod: the D1 /
    // `StorageEnv` config is present (durable backing, not the InMemory
    // dev/CI fallback) AND `PAT_SIGNING_KEY` is set. Re-calling `from_env()`
    // here is fine — both are idempotent, side-effect-free env reads.
    {
        let storage_present = corelink_server::storage::StorageEnv::from_env().is_some();
        let signing_key_present = std::env::var("PAT_SIGNING_KEY")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let prod = storage_present && signing_key_present;
        let gate_present = corelink_server::adapter_pat::PatVerifier::from_env().is_some();
        if should_fatal_on_missing_gate(prod, gate_present) {
            tracing::error!(
                event = "native_pat_gate_missing_in_prod",
                severity = "FATAL",
                "PROD detected (D1 + PAT_SIGNING_KEY present) but the native PAT \
                 verifier did NOT build — refusing to boot the data plane WITHOUT \
                 its Argon2id possession backstop. The most likely cause is a \
                 PRESENT-but-malformed PAT_SIGNING_KEY rotation sibling \
                 (PAT_SIGNING_KEY_PREV / PAT_SIGNING_KEY_NEW): bad hex, < 32 bytes, \
                 or a stray newline. Fix the sibling secret (or unset it) and \
                 redeploy."
            );
            std::process::exit(1);
        }
    }

    // ── Positive prod-arming assertion (config-drift finding #3, MEDIUM) ──
    // The native-PAT FATAL above keys on the SAME `StorageEnv` signal that ALSO
    // gates the $-ceiling (`tenant_quota::quota_guard_from_env`), byte-cap
    // (`byte_accounting::byte_accountant_from_env`) and request-count
    // (`request_count::RequestCountGate::from_env`) controls. NOTE the scope
    // asymmetry: the $-ceiling, byte-cap and native-PAT backstop are wired
    // FLEET-WIDE into every native container state (CAS/AC/Bazel/Turbo); the
    // request-count gate is wired ONLY into the OCI router (it is the OCI op-cap
    // mirror — native is op-count-bounded at the Worker edge instead, see the
    // `missing.push("request-count gate …")` note below). All four are still
    // co-gated by `StorageEnv`, so the drift hazard is identical: a single
    // dropped
    // or renamed `R2_S3_*` / `CLOUDFLARE_ACCOUNT_ID` / `CF_API_TOKEN` /
    // `D1_DATABASE_ID` var flips `StorageEnv` to `None`, which SILENTLY disarms
    // every one of those guards AND simultaneously makes prod-detection FALSE —
    // so the watchdog that should scream goes quiet. The missing config that
    // disables the controls also disables the alarm (the circular dependency).
    //
    // Close the loop with an INDEPENDENT positive prod signal that does NOT
    // depend on `StorageEnv`: the multi-region R2 placement vars
    // (`R2_AC_REGION` / `R2_CAS_REGION` / `R2_AC_BUCKET`). Every prod env
    // (`[env.prod*.vars]` in wrangler.toml) sets them and the DO forwards them
    // into the container (`worker/src/durable_object.ts`); dev/CI sets NONE of
    // them, so this whole block is a no-op there (dev/CI behavior unchanged).
    // They are NOT part of `StorageEnv` and gate NONE of the controls, so they
    // cannot be co-dropped with the very thing they witness — and we read all
    // THREE so dropping any one still leaves the prod signal standing. If this
    // signal says "prod", then ALL of the launch controls MUST be armed; if any
    // is missing we refuse to boot a HALF-ARMED prod (loud FATAL naming it).
    {
        let prod_by_independent_signal = ["R2_AC_REGION", "R2_CAS_REGION", "R2_AC_BUCKET"]
            .iter()
            .any(|v| {
                std::env::var(v)
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false)
            });
        if prod_by_independent_signal {
            let mut missing: Vec<&str> = Vec::new();
            if corelink_server::storage::StorageEnv::from_env().is_none() {
                missing.push(
                    "durable StorageEnv (R2_S3_ENDPOINT / R2_S3_ACCESS_KEY_ID / \
                     R2_S3_SECRET_ACCESS_KEY / CLOUDFLARE_ACCOUNT_ID / CF_API_TOKEN / \
                     D1_DATABASE_ID)",
                );
            }
            let signing_key_present = std::env::var("PAT_SIGNING_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !signing_key_present {
                missing.push("PAT_SIGNING_KEY");
            }
            if corelink_server::adapter_pat::PatVerifier::from_env().is_none() {
                missing.push("native PAT verifier (Argon2id possession backstop)");
            }
            if corelink_server::tenant_quota::quota_guard_from_env().is_none() {
                missing.push("$-ceiling quota guard (tenant_quota)");
            }
            if corelink_server::byte_accounting::byte_accountant_from_env().is_none() {
                missing.push("byte-cap accountant (tenant_storage_state)");
            }
            if corelink_server::request_count::RequestCountGate::from_env().is_none() {
                // SCOPE: this gate is the OCI-surface monthly op-cap (the
                // container-side mirror of the Worker's `checkRequestQuota`).
                // The Worker forwards `/v2/*` + `/token` RAW and returns BEFORE
                // its quota block, so OCI is the ONE surface the edge cannot
                // count — the container gate is its sole enforcer and so is a
                // genuine must-arm. The native CAS/AC/Bazel/Turbo + cargo/brew/
                // npm/pip surfaces are op-count-bounded at the WORKER edge
                // (`incrementMonthlyRequestCount`, exactly once per request);
                // they deliberately do NOT carry this gate at the container —
                // doing so would double-increment `monthly_request_counts` and
                // false-deny legitimate native traffic. So this assertion is
                // NOT a fleet-wide-native claim; it asserts exactly what is
                // wired (the OCI op-cap, routes.rs).
                missing.push("request-count gate (OCI monthly op cap)");
            }
            // ERASURE_SALT_KEY: the GDPR DSR account-delete / erasure path derives
            // a per-DSR salt via `HMAC-SHA256(ERASURE_SALT_KEY, dsr_id)` in
            // `routes/customer.rs::derive_salt_hex`, which fail-CLOSEDs to a 500 when
            // the key is absent/empty. Without this assertion a prod boot missing the
            // key looks "healthy" while EVERY erasure/account-delete call silently
            // 500s — the GDPR Art. 17 path is broken with no early alarm. Treat it as
            // a must-arm prod control (read identically to PAT_SIGNING_KEY).
            let erasure_salt_key_present = std::env::var("ERASURE_SALT_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !erasure_salt_key_present {
                missing.push("ERASURE_SALT_KEY (GDPR erasure/account-delete salt)");
            }
            // EMAIL_HASH_SALT: the CTRL-PRIV-001 email_hash pseudonym helper
            // (`email_hash::hash_email` — every team-invite WRITE / accept-time
            // MATCH / DSR Art.16 rectification routes through it) HMAC-SHA256s the
            // normalized email under this server-held salt when set+non-empty, but
            // silently falls back to plain `SHA-256(email)` — a RAINBOW-TABLE-
            // reversible pseudonym — when it is unset/empty. The salt is now SET on
            // all prod targets, so a future deploy that DROPPED it would silently
            // regress every new pseudonym to the unsalted scheme with NO alarm.
            // Treat it as a must-arm prod control (read identically to
            // ERASURE_SALT_KEY / PAT_SIGNING_KEY). NOTE the fail-fast lives HERE at
            // boot, NOT inside `hash_email()` per-call: a per-call error would break
            // non-prod tests and add hot-path cost — the boot gate just guarantees
            // the salt exists in prod while `hash_email`'s dual-path logic (salted
            // write + legacy-unsalted lookup candidate) stays intact.
            let email_hash_salt_present = std::env::var("EMAIL_HASH_SALT")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if email_hash_salt_missing_in_prod(prod_by_independent_signal, email_hash_salt_present)
            {
                missing.push("EMAIL_HASH_SALT (CTRL-PRIV-001 email_hash pseudonym salt)");
            }
            // STRIPE_PRICE_ID_{SOLO,STARTER,PRO,MAX}: the revenue path. The
            // container is a live Stripe activation writer; an unset cache-tier
            // price id silently maps a real `price_live_…` to the un-matchable
            // `plan_{tier}` placeholder → `UnknownPlan` → 422 on a paying customer
            // (see cache_tier_price_ids_missing_in_prod). Must-arm in prod, and
            // kept identical to the signup-worker's reverse map.
            for env_name in cache_tier_price_ids_missing_in_prod(prod_by_independent_signal, |n| {
                std::env::var(n).ok()
            }) {
                missing.push(env_name);
            }
            if !missing.is_empty() {
                tracing::error!(
                    event = "prod_controls_not_fully_armed",
                    severity = "FATAL",
                    missing_controls = ?missing,
                    "PROD detected via an INDEPENDENT signal (R2_AC_REGION / \
                     R2_CAS_REGION / R2_AC_BUCKET is set) but one or more launch \
                     controls did NOT arm — refusing to boot a HALF-ARMED prod. The \
                     most likely cause is a dropped or renamed config var (an \
                     R2_S3_* / CLOUDFLARE_ACCOUNT_ID / CF_API_TOKEN / D1_DATABASE_ID) \
                     that silently disabled the listed guard(s) WHILE leaving the \
                     independent prod signal set. Restore the missing config and \
                     redeploy."
                );
                std::process::exit(1);
            }
        }
    }

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50051u16);

    let serve_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    // Audit-analytics data source (#71). The `/v1/audit/analytics/*` routes are
    // backed by the live D1 `customer_audit_events` table (migration 0077 — the
    // SAME table `/v1/customer/audit` reads). The former per-region Neon
    // "analytics shadow" (`TokioPgShadowSinkFactory`, feature `neon-real`) was
    // never wired in prod: the per-region DSN env was never set and the real
    // driver was never compiled into the shipped container, so the boot path
    // silently fell back to the in-memory sink and EVERY analytics query returned
    // an empty result. That dead scaffold is removed; the D1-backed factory below
    // serves real aggregates. Env-gated: when the D1 storage env is absent
    // (dev/CI) the routes stay on the in-memory factory so the surface still
    // boots (mirrors the customer-plane `*_from_env` fail-closed pattern).
    let shadow_factory: Arc<dyn ShadowSinkFactory> =
        match routes::audit_analytics::D1ShadowSinkFactory::from_env() {
            Some(f) => {
                info!(
                    "audit-analytics: D1-backed factory wired over customer_audit_events (real aggregates)"
                );
                Arc::new(f) as Arc<dyn ShadowSinkFactory>
            }
            None => {
                warn!(
                    "audit-analytics: D1 storage env absent — analytics on InMemoryShadowSinkFactory (dev/CI)"
                );
                Arc::new(routes::InMemoryShadowSinkFactory::new()) as Arc<dyn ShadowSinkFactory>
            }
        };

    info!(
        "routes: building composed data-plane router (CAS + AC + Admin + audit-export + audit-analytics + signup) + /_health"
    );
    // Construct BYOK data-plane collaborators once before route assembly.  The
    // router passes this one cache Arc to both storage surfaces and both byte
    // accounting decorators, so a config transition cannot split encryption
    // from physical-byte reservation.  A binary without a real provider keeps
    // the existing non-BYOK path; a real-provider production setup that cannot
    // construct its D1/KMS collaborators refuses boot.
    let byok_data_plane = corelink_server::storage::byok_cas::DataPlaneByok::from_env()
        .await
        .map_err(|error| format!("BYOK data-plane wiring failed: {error}"))?;
    // The composed data-plane router is the product surface. We bind it to the
    // HTTP listener on PORT (50051) — the exact port the DO forwards HTTP to and
    // probes for /_health. `/_health` is added here so the DO's container
    // readiness probe (GET /_health, expects 200) succeeds.
    // H5 DoS guard: cap the request body for EVERY route at 10 MiB so an
    // authenticated PAT cannot OOM the shared container with a multi-GB body on
    // any JSON/CAS route. `DefaultBodyLimit` is an outer layer; axum honours the
    // innermost limit, so the Turbo `/v8/artifacts/:hash` PUT (which legitimately
    // carries larger build artifacts) sets its own larger per-route limit inside
    // `turbo_v8::router()` and is NOT constrained by this global default.
    const GLOBAL_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
    let mut app = routes::build_with_factory_and_byok(shadow_factory, byok_data_plane)
        // The failover heartbeat is deliberately a separate authenticated
        // internal route. Public `/_health` readiness probes never refresh
        // failover state and therefore cannot spoof liveness anonymously.
        .merge(corelink_server::routes::failover::internal_heartbeat_router())
        .route("/_health", get(runtime::health_handler))
        .layer(axum::extract::DefaultBodyLimit::max(
            GLOBAL_BODY_LIMIT_BYTES,
        ));

    // Stream-5: `POST /_internal/pat/mint` — gated by shared secret.
    // Mounted when CORELINK_INTERNAL_AUTH_KEY + PAT_SIGNING_KEY are both set.
    if let Some(internal_pat_state) = corelink_server::routes::internal_pat::build_state_from_env()
    {
        info!("routes: /_internal/pat/mint route mounted (internal auth key + PAT signing key present)");
        app = app.merge(corelink_server::routes::internal_pat::router(
            internal_pat_state,
        ));
    } else {
        warn!(
            "CORELINK_INTERNAL_AUTH_KEY or PAT_SIGNING_KEY unset; \
             /_internal/pat/mint route NOT mounted (dev/CI mode)"
        );
    }

    // M1: `POST /internal/v1/auth/introspect` — corelink-runners fabric PAT
    // introspection. Gated by a DEDICATED `FABRIC_INTROSPECT_AUTH_KEY` (NOT the
    // mint secret — tight blast radius). Mounted only when that secret (≥32
    // chars) + the PAT signing key + the D1 `StorageEnv` are ALL present
    // (fail-CLOSED: unmounted in dev/CI).
    if let Some(introspect_state) = corelink_server::routes::auth_introspect::build_state_from_env()
    {
        info!(
            "routes: /internal/v1/auth/introspect mounted (FABRIC_INTROSPECT_AUTH_KEY + PAT signing key + D1 present)"
        );
        app = app.merge(corelink_server::routes::auth_introspect::router(
            introspect_state,
        ));
    } else {
        warn!(
            "FABRIC_INTROSPECT_AUTH_KEY / PAT_SIGNING_KEY / D1 config incomplete; \
             /internal/v1/auth/introspect NOT mounted (dev/CI mode)"
        );
    }

    // ASK-2: `POST /internal/v1/billing/usage` — corelink-runners billing
    // usage-push INGEST. Gated by a DEDICATED `BILLING_INGEST_AUTH_KEY` (NOT the
    // mint / introspect / erase secrets — tight blast radius). Mounted only when
    // that secret (≥32 chars) + the D1 `StorageEnv` are present (fail-CLOSED:
    // unmounted in dev/CI). Idempotently stages raw per-lease usage records into
    // the canonical `usage_event_staging` table the aggregator drains; it does
    // NOT aggregate or touch Stripe.
    if let Some(billing_ingest_state) =
        corelink_server::routes::billing_ingest::build_state_from_env()
    {
        info!("routes: /internal/v1/billing/usage mounted (BILLING_INGEST_AUTH_KEY + D1 present)");
        app = app.merge(corelink_server::routes::billing_ingest::router(
            billing_ingest_state,
        ));
    } else {
        warn!(
            "BILLING_INGEST_AUTH_KEY / D1 config incomplete; \
             /internal/v1/billing/usage NOT mounted (dev/CI mode)"
        );
    }

    // WI-S11-008: `POST /_internal/dsr/erase` — gated by the
    // CORELINK_INTERNAL_AUTH_KEY. Drives the 12-backend erasure orchestrator
    // (Wave 1: real D1/R2/Stripe/KV/Loki transports wired in #254).
    if let Some(dsr_state) = corelink_server::routes::dsr::build_state_from_env() {
        info!(
            "routes: /_internal/dsr/{{erase,verify,access,portability,rectification}} mounted \
             (Art.17/15/20/16 data-subject rights; Wave 1 real adapters)"
        );
        app = app.merge(corelink_server::routes::dsr::router(dsr_state));
    } else {
        warn!("CORELINK_INTERNAL_AUTH_KEY unset; /_internal/dsr/* routes NOT mounted (dev/CI)");
    }

    // #2584: exact-run physical teardown is an authenticated staging-only
    // capability. Its builder requires the staging admission verifier, D1
    // writer and export R2 client; any absent or invalid piece leaves this
    // destructive route unmounted.
    if let Some(teardown_router) =
        corelink_server::routes::staging_load_test_teardown::build_router_from_env().await
    {
        info!("routes: exact staging load-test teardown route mounted");
        app = app.merge(teardown_router);
    } else {
        warn!(
            "staging admission / D1 / R2 config incomplete or non-staging; \
             exact staging load-test teardown route NOT mounted (fail-CLOSED)"
        );
    }

    // #2708: inventory sealing is a staging-only capability. The route uses
    // the same mandatory admission verifier as teardown and is absent unless
    // both it and the narrow D1 ownership writer are configured.
    if let Some(seal_router) =
        corelink_server::routes::staging_load_test_seal::build_router_from_env().await
    {
        info!("routes: exact staging load-test seal route mounted");
        app = app.merge(seal_router);
    } else {
        warn!(
            "staging admission / D1 config incomplete or non-staging; \\
             exact staging load-test seal route NOT mounted (fail-CLOSED)"
        );
    }

    // S-09 audit-chain drain: `POST /_internal/audit/drain` — seals the live
    // `audit_outbox` trail into the BLAKE3 tamper-evident hash chain (closes the
    // "audit trail is mutable / not tamper-evident" gap). Gated by the dedicated
    // ERASE key (falls back to CORELINK_INTERNAL_AUTH_KEY), same as the DSR
    // surface; mounts only when that key (≥32 chars) + the D1 `StorageEnv` are
    // present. Without D1 there is nothing to seal → unmounted (fail-CLOSED).
    if let Some(audit_drain_state) = corelink_server::routes::audit_drain::build_state_from_env() {
        info!(
            "routes: /_internal/audit/drain route mounted (erase/internal auth key + D1 present)"
        );
        app = app.merge(corelink_server::routes::audit_drain::router(
            audit_drain_state,
        ));
    } else {
        warn!(
            "CORELINK_ERASE_AUTH_KEY/CORELINK_INTERNAL_AUTH_KEY (<32) or D1 absent; \
             /_internal/audit/drain route NOT mounted (fail-CLOSED)"
        );
    }

    // Edge-probe audit emit: `POST /_internal/audit/cas-attempted`. Lets the
    // Worker serve `findMissingBlobs` from its in-colo R2 binding while the
    // `ReadAttempted` rows are still written by THIS sink — the edge awaits
    // this call and falls through to the container on anything but 204, so an
    // unmounted route degrades to today's behaviour rather than to an
    // unaudited answer. Dedicated key only (no shared fallback): this writes
    // tenant-attributed audit rows on behalf of an arbitrary tenant.
    if let Some(state) = corelink_server::routes::audit_cas_attempted::build_state_from_env() {
        info!(
            "routes: /_internal/audit/cas-attempted mounted \
             (CORELINK_AUDIT_ATTEMPTED_AUTH_KEY + D1 present)"
        );
        app = app.merge(corelink_server::routes::audit_cas_attempted::router(state));
    } else {
        warn!(
            "CORELINK_AUDIT_ATTEMPTED_AUTH_KEY (dedicated, <32/unset) or D1 absent; \
             /_internal/audit/cas-attempted NOT mounted (fail-CLOSED) — the edge \
             findMissingBlobs path falls through to the container"
        );
    }

    // S-09 audit ARCHIVE: `POST /_internal/audit/archive` — copies rows the
    // drain already sealed into immutable NDJSON chunks in the R2 audit bucket
    // (7-year Object Lock), closing the "the seal lands in mutable D1 with no
    // offsite copy" gap. Deliberately a SEPARATE endpoint from the drain: an R2
    // outage must never be able to abort or corrupt a D1 seal. Gated by the
    // dedicated ERASE key (≥32 chars) + the D1/R2 `StorageEnv`; unmounted
    // (fail-CLOSED) without them.
    if let Some(audit_archive_state) =
        corelink_server::routes::audit_archive::build_state_from_env().await
    {
        info!("routes: /_internal/audit/archive route mounted (erase auth key + D1 + R2 present)");
        app = app.merge(corelink_server::routes::audit_archive::router(
            audit_archive_state,
        ));
    } else {
        warn!(
            "CORELINK_ERASE_AUTH_KEY (<32) or D1/R2 absent; \
             /_internal/audit/archive route NOT mounted (fail-CLOSED)"
        );
    }

    // B-050 at-rest CAS integrity scrubber: `POST /_internal/cas/scrub`. The
    // read-path digest re-verify only ever covers objects a client actually
    // asks for, so cold objects go unchecked forever; this cron-driven sweep
    // re-hashes stored objects directly. Same dedicated ERASE key + D1/R2 gate
    // as the archive route, plus `R2_TDK_HEX` (without it no tenant prefix can
    // be derived, so the sweep could not address a single object); unmounted
    // fail-CLOSED without them.
    if let Some(cas_scrub_state) = corelink_server::routes::cas_scrub::build_state_from_env().await
    {
        info!("routes: /_internal/cas/scrub route mounted (erase auth key + TDK + D1 + R2)");
        app = app.merge(corelink_server::routes::cas_scrub::router(cas_scrub_state));
    } else {
        warn!(
            "CORELINK_ERASE_AUTH_KEY (<32), R2_TDK_HEX or D1/R2 absent; \
             /_internal/cas/scrub route NOT mounted (fail-CLOSED)"
        );
    }

    // Read-only internal tenant-quota lookup: `GET /_internal/tenant/{tenant_id}/quota`.
    // Returns the persisted `tenant_quota` row + a derived `unmetered` bit for a
    // trusted internal caller (signup-worker / operator plane) WITHOUT a billable
    // op. Gated by the dedicated `CORELINK_QUOTA_READ_AUTH_KEY` (falls back to
    // CORELINK_INTERNAL_AUTH_KEY), same resolver as the DSR/erase surfaces; mounts
    // only when that key (≥32 chars) + the D1 `StorageEnv` are present. Without D1
    // there is nothing to read → unmounted (fail-CLOSED), mirroring audit/drain.
    if let Some(quota_read_state) =
        corelink_server::routes::tenant_quota_read::build_state_from_env()
    {
        info!("routes: /_internal/tenant/{{tenant_id}}/quota route mounted (quota-read/internal auth key + D1 present)");
        app = app.merge(corelink_server::routes::tenant_quota_read::router(
            quota_read_state,
        ));
    } else {
        warn!(
            "CORELINK_QUOTA_READ_AUTH_KEY/CORELINK_INTERNAL_AUTH_KEY (<32) or D1 absent; \
             /_internal/tenant/{{tenant_id}}/quota route NOT mounted (fail-CLOSED)"
        );
    }

    // Artifact 1 (WP-C1): PUBLIC erasure-attestation verifier routes —
    // `GET /v1/public/attestation/{request_id}` + `GET /v1/public/keys/erasure/{region}.pub`.
    // UNAUTHENTICATED by design (an erasure proof is publicly verifiable): merged
    // here, OUTSIDE the ratelimit/residency/auth layers (same as the `/_internal/*`
    // family above) but with NO internal-auth gate. D1-read only; mounts only when
    // the D1 `StorageEnv` is present (nothing to serve without the index).
    //
    // M22(a): the router itself now carries a SCOPED per-IP token-bucket rate
    // limit (`public_attestation::rate_limit_public_verifier`) — reachable
    // internet-wide + unauthenticated, this surface had NO container-side
    // rate limiting at all before this fix. `PublicVerifierRateLimitState` is
    // a dedicated limiter instance local to this router (never the shared
    // `ratelimit_layer.rs` gate), so it cannot re-throttle the data plane.
    if let Some(public_att_state) =
        corelink_server::routes::public_attestation::build_state_from_env()
    {
        info!("routes: /v1/public/{{attestation,keys}} mounted (public verifier; D1 present; M22a per-IP rate limit armed)");
        app = app.merge(corelink_server::routes::public_attestation::router(
            public_att_state,
            corelink_server::routes::public_attestation::PublicVerifierRateLimitState::new(),
        ));
    } else {
        warn!(
            "D1 StorageEnv absent; /v1/public/attestation + /v1/public/keys/erasure \
             NOT mounted (dev/CI mode)"
        );
    }

    // hugit-P2 seam B, WP-B: `POST /_internal/cas/:tenant/:hash/erase` — per-hash
    // CAS erase + 410-Gone tombstone, gated by the dedicated CORELINK_ERASE_AUTH_KEY.
    // The WRITE route mounts only when ALL prod transports build from env: the
    // internal-auth key, the R2 TDK (`R2_TDK_HEX`), and the D1 tombstone store.
    // Without the TDK the eraser cannot derive the writer's tenant prefix, so the
    // route stays UNMOUNTED (fail-CLOSED) — it can never tombstone a blob whose
    // bytes it could not address (mirrors the DSR R2 CAS adapter's fail-closed
    // posture). The read-side 410 gate is wired separately in `routes::cas`.
    // rt-nuclear #20/#21: CAS-erase MUST gate on the dedicated ERASE key
    // (CORELINK_ERASE_AUTH_KEY), not the ADMIN key — so an admin-key leak cannot
    // drive irreversible erases. `erase_auth_key_from_env` reads the DEDICATED
    // CORELINK_ERASE_AUTH_KEY ONLY (NO shared fallback; finding H4) — the erase
    // surface stays fail-CLOSED until the operator binds that secret (Track-2).
    let cas_erase_auth_key = corelink_server::routes::admin::erase_auth_key_from_env();
    if let Some(cas_erase_state) =
        corelink_server::routes::cas_erase::build_state_from_env(cas_erase_auth_key)
    {
        info!("routes: /_internal/cas/:tenant/:hash/erase route mounted (R2 TDK + D1 tombstone present)");
        app = app.merge(corelink_server::routes::cas_erase::router(cas_erase_state));
    } else {
        warn!(
            "CORELINK_ERASE_AUTH_KEY / R2_TDK_HEX / D1 incomplete; \
             /_internal/cas/:tenant/:hash/erase route NOT mounted (fail-CLOSED)"
        );
    }

    // F3.2 BLOCKER-1 (B1b): `POST /_internal/public/revoke` — the `_public`
    // shared-dedup blob kill-switch (blocklist → map-delete → audit → R2 hard-delete
    // across CAS regions). Gated by the SAME dedicated CORELINK_ERASE_AUTH_KEY as
    // cas_erase (it is an irreversible R2 delete; an admin-key leak must not drive
    // it — finding H4), and fail-CLOSED (unmounted) without the erase key + R2 TDK
    // + D1. Reuses the `_public`-aware R2CasBlobEraser so the erase key matches the
    // sentinel-prefix key the `_public` writer created.
    let public_revoke_auth_key = corelink_server::routes::admin::erase_auth_key_from_env();
    if let Some(public_revoke_state) =
        corelink_server::routes::public_revoke::build_state_from_env(public_revoke_auth_key)
    {
        info!("routes: /_internal/public/revoke route mounted (erase key + R2 TDK + D1 present)");
        app = app.merge(corelink_server::routes::public_revoke::router(
            public_revoke_state,
        ));
    } else {
        warn!(
            "CORELINK_ERASE_AUTH_KEY / R2_TDK_HEX / D1 incomplete; \
             /_internal/public/revoke route NOT mounted (fail-CLOSED)"
        );
    }

    // F3.2 public-base MIRROR (admin-gated). The route lives under
    // /_internal/admin/*, which the edge maps to the admin consumer and forwards
    // verbatim, so the container gates on CORELINK_ADMIN_AUTH_KEY (shared
    // CORELINK_INTERNAL_AUTH_KEY fallback) — NOT a dedicated mirror key (which
    // could never match the forwarded header) and NOT the erase key.
    if let Some(public_mirror_state) =
        corelink_server::routes::public_mirror::build_state_from_env()
    {
        info!("routes: /_internal/admin/public-mirror route mounted (admin key present)");
        app = app.merge(corelink_server::routes::public_mirror::router(
            public_mirror_state,
        ));
    } else {
        warn!(
            "CORELINK_ADMIN_AUTH_KEY / CORELINK_INTERNAL_AUTH_KEY absent; \
             /_internal/admin/public-mirror route NOT mounted (fail-CLOSED)"
        );
    }

    // L3: `POST /v1/onboarding/tier-select` — self-serve Stripe Checkout.
    // Mounted only when the dedicated tier-select auth secret (or its
    // documented CORELINK_INTERNAL_AUTH_KEY fallback) + D1 + Stripe + DPA
    // version are ALL configured (fail-safe; same 32-char gate as other
    // internal-auth routes).
    if let Some(tier_select_state) = corelink_server::routes::tier_select::build_state_from_env() {
        info!(
            "routes: /v1/onboarding/tier-select mounted (internal auth + D1 + Stripe + DPA version present)"
        );
        app = app.merge(corelink_server::routes::tier_select::router(
            tier_select_state,
        ));
    } else {
        warn!(
            "tier-select config incomplete (CORELINK_TIER_SELECT_AUTH_KEY or CORELINK_INTERNAL_AUTH_KEY / CORELINK_DPA_VERSION / \
             D1 / Stripe); /v1/onboarding/tier-select NOT mounted (dev/CI mode)"
        );
    }

    // Launch money-path unblock: `POST /v1/onboarding/dpa-accept` — writes the
    // durable `dpa_acceptances` row the tier-select gate (`is_dpa_accepted`)
    // reads (INV-ONBOARD-DPA-FIRST). Same onboarding proxy contract as
    // tier-select (worker sets x-corelink-internal-auth + x-corelink-tenant-id).
    // Mounted only when the dedicated DPA auth secret (or its documented
    // CORELINK_INTERNAL_AUTH_KEY fallback) + D1 + DPA version + the RS256
    // receipt signing key (DPA_RECEIPT_SIGNING_KEY) are ALL present — fail-CLOSED
    // (unmounted, logged) rather than 500 when the key is unset/invalid.
    if let Some(dpa_accept_state) = corelink_server::routes::dpa_accept::build_state_from_env() {
        info!(
            "routes: /v1/onboarding/dpa-accept mounted (internal auth + D1 + DPA version + DPA_RECEIPT_SIGNING_KEY present)"
        );
        app = app.merge(corelink_server::routes::dpa_accept::router(
            dpa_accept_state,
        ));
    } else {
        warn!(
            "dpa-accept config incomplete (CORELINK_DPA_ACCEPT_AUTH_KEY or CORELINK_INTERNAL_AUTH_KEY / CORELINK_DPA_VERSION / \
             DPA_RECEIPT_SIGNING_KEY / D1); /v1/onboarding/dpa-accept NOT mounted (fail-CLOSED)"
        );
    }

    // Shared D1 client (WP-D1): one StorageEnv → one D1HttpClient shared by
    // the billing state writer, durable audit emitter (MED-5), and durable
    // webhook DLQ. Build it before the mount gate so a webhook secret alone
    // can never enable a non-durable money path; dev/CI without D1 remain
    // unmounted (fail-CLOSED).
    let d1_client: Option<Arc<corelink_server::storage::d1_http::D1HttpClient>> =
        match corelink_server::storage::StorageEnv::from_env() {
            Some(storage_env) => {
                match corelink_server::storage::d1_http::D1HttpClient::new(&storage_env) {
                    Ok(client) => Some(Arc::new(client)),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "billing: D1HttpClient init failed; \
                             webhook NOT mounted (fail-CLOSED)"
                        );
                        None
                    }
                }
            }
            None => {
                warn!(
                    "billing: D1 config absent (R2_S3_*/CF D1); \
                     Stripe webhook NOT mounted (fail-CLOSED)"
                );
                None
            }
        };

    // R2-12: the Stripe webhook route is MERGED onto the same listener when
    // STRIPE_WEBHOOK_SECRET is present; absent → skip (dev/CI without billing
    // config stays green). Either way the data plane above is always served.
    // A webhook secret alone is not enough to mount billing: deduplication,
    // materialization, audit, and DLQ all require durable D1. Never substitute
    // an in-memory DLQ after claiming an idempotency row: a restart would lose
    // the only copy of a failed event.
    if let (Ok(secret), Some(client)) = (std::env::var("STRIPE_WEBHOOK_SECRET"), d1_client.as_ref())
    {
        // Wave 17 + 18: the HTTP shell binds the production
        // materializer + audit emitter + D1-backed idempotency store
        // from `corelink-billing-stripe-materializer`. The native
        // gRPC server (this binary) ALWAYS uses
        // `InMemoryBillingD1` + `InMemoryBillingAuditEmitter` —
        // D1 is a CF Worker binding (`worker::D1Database`) not
        // reachable from outside the Worker isolate, so even with
        // `--features cf-billing-real` the native binary stays on
        // the in-memory mirrors. The `cf-billing-real` feature is
        // a **build-time witness** that the wasm32 binder module
        // (`corelink_billing_stripe_materializer::wasm32_binders`)
        // is compiled in; the actual production cutover happens at
        // the CF Worker boot layer in `corelink-clerk-cf::prod_wiring`
        // which constructs `CfD1BillingWriter` +
        // `ArchiveProducerBillingEmitter` behind the same
        // `BillingD1Writer` / `BillingAuditEmitter` trait objects.
        //
        // The single canonical seam (`WebhookDispatcher::new`) is
        // preserved end-to-end — axum, CF Worker, and the replay
        // cron all hit this exact constructor with target-specific
        // collaborators.
        #[cfg(feature = "cf-billing-real")]
        {
            // Build-time witness: compile-check the wasm32 binder
            // re-exports are reachable. The actual `CfD1BillingWriter`
            // construction requires a `CfD1DatabaseReal` which is only
            // built at the CF Worker boot path; on native we keep the
            // InMemory* wiring and rely on the per-crate integration
            // test (`tests/wasm32_binders.rs`) to pin the binder
            // contract via the `stub_for_native_tests` path.
            #[allow(unused_imports)]
            use corelink_billing_stripe_materializer::{
                ArchiveProducerBillingEmitter as _, CfD1BillingWriter as _,
            };
        }
        let billing_d1: Arc<dyn BillingD1Writer> = match &d1_client {
            Some(client) => {
                info!(
                    "billing: DURABLE D1-HTTP writer wired (CF D1 REST API); \
                     Stripe-webhook state persists across restarts"
                );
                Arc::new(D1HttpBillingWriter::new(Arc::clone(client)))
            }
            None => Arc::new(InMemoryBillingD1::new()),
        };
        // MED-5 closure (WP-D1): audit evidence must be as durable as the
        // state it witnesses — route the materializer's billing-audit rows
        // to D1 when available instead of the volatile in-memory mirror.
        let billing_audit: Arc<dyn BillingAuditEmitter> = match &d1_client {
            Some(client) => {
                info!("billing: DURABLE D1 billing-audit emitter wired");
                Arc::new(corelink_server::webhook_dlq_d1::D1BillingAuditEmitter::new(
                    Arc::clone(client),
                ))
            }
            None => Arc::new(InMemoryBillingAuditEmitter::new()),
        };
        // Canonical Stripe-plan-id → tier mapping (F-001 fix).
        //
        // Real `customer.subscription.updated` events carry
        // `data.object.plan.id = price_…` (the live Stripe price id),
        // NOT the literal `plan_solo/…` placeholders. The Worker
        // forwards the real ids as `STRIPE_PRICE_ID_{SOLO,STARTER,PRO,MAX}`
        // (`worker/src/durable_object.ts:554-558`), so the mapping MUST
        // be keyed off those env values — otherwise every real event
        // resolves to `UnknownPlan` → 422 and Stripe stops retrying.
        //
        // This mirrors the signup-worker resolver
        // (`apps/signup-worker/src/webhooks/stripe.ts:287-296`) which
        // keys the same map off the same env vars. The literal
        // `plan_{tier}` keys are retained as a backward-compatible
        // fallback (test fixtures / pre-price-id deployments) ONLY when
        // the corresponding env var is unset/empty.
        let tier_selector = Arc::new(build_tier_selector());
        let mut sub_handler = D1SubscriptionStateHandler::new(
            billing_d1.clone(),
            billing_audit.clone(),
            tier_selector,
        );
        // Runners entitlement seed (env-gated): when STRIPE_PRICE_ID_RUNNER_* are
        // set, a Runners-tier subscription seeds `runners_entitlement` instead of
        // `tier_selections`. Dormant (no-op) until those prices exist.
        if let Some(runners_resolver) = build_runners_resolver() {
            tracing::info!(
                "Runners entitlement seed ENABLED ({} tier price(s) wired)",
                runners_resolver.len()
            );
            sub_handler = sub_handler.with_runners_resolver(Arc::new(runners_resolver));
            // Runner reconciliation is provider-authoritative. If native
            // Stripe credentials are unavailable, keep the webhook mounted
            // for observability but leave this authority unwired: the
            // materializer then returns a transient error before any Runner
            // entitlement mutation (fail-CLOSED, Stripe retries).
            match corelink_stripe_real::StripeRealClient::from_env() {
                Ok(stripe) => {
                    sub_handler = sub_handler.with_current_subscription_authority(Arc::new(
                        StripeCurrentSubscriptionAuthority::new(Arc::new(stripe)),
                    ));
                    tracing::info!("Runners current-subscription authority wired to Stripe");
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Runners current-subscription authority unavailable; Runner entitlement writes fail CLOSED"
                    );
                }
            }
        } else {
            tracing::info!("Runners entitlement seed dormant (no STRIPE_PRICE_ID_RUNNER_* set)");
        }
        let materializer: Arc<dyn StateMaterializer> = Arc::new(sub_handler);
        let dispatcher_audit = Arc::new(RealStripeAuditEmitter::new(billing_audit.clone()));
        let idempotency = Arc::new(InMemoryIdempotencyStore::new());
        let webhook_inbox = Arc::new(corelink_server::webhook_inbox_d1::D1WebhookInbox::new(
            Arc::clone(client),
        ));
        // F-008 closure: wire a DLQ sink so a TRANSIENT materialize
        // failure quarantines the (already HMAC-verified) event instead
        // of silently dropping it. The idempotency dedup row is committed
        // BEFORE materialize, so a Stripe retry hits `AlreadyProcessed`
        // and skips the handler — without the DLQ the state change is
        // lost while Stripe records success. The in-memory store captures
        // the event for the container's lifetime + exposes it via the DLQ
        // depth/age metrics; the durable D1-backed `WebhookDlqStore`
        // (`migrations/d1/0045_stripe_webhook_dlq.sql`) is the operator
        // follow-up so quarantines survive container restarts.
        // WP-D1: durable DLQ — a quarantined event MUST survive a container
        // restart (the dedup row committed before materialize means Stripe's
        // retries can never re-run the handler; the DLQ is the only copy).
        info!("billing: DURABLE D1 webhook-DLQ store wired (migrations 0045+0094)");
        let webhook_dlq: Arc<dyn corelink_billing::stripe::real::dlq::WebhookDlqStore> = Arc::new(
            corelink_server::webhook_dlq_d1::D1WebhookDlqStore::new(Arc::clone(client)),
        );
        let dispatcher = Arc::new(
            WebhookDispatcher::new(
                secret.into_bytes(),
                idempotency,
                materializer,
                dispatcher_audit,
                Arc::new(RecordingSliRecorder::new()),
                Arc::new(SystemClock),
            )
            .with_durable_inbox(webhook_inbox)
            .with_dlq(webhook_dlq),
        );
        let staging_admission =
            corelink_server::storage::staging_load_test_admission::StagingLoadTestAdmissionGate::from_env()
                .ok()
                .map(Arc::new);
        let state =
            Arc::new(WebhookState::new(dispatcher).with_staging_admission(staging_admission));
        info!(
            route = corelink_server::webhook::STRIPE_WEBHOOK_ROUTE,
            "Stripe webhook route mounted on the data-plane listener"
        );
        app = app.merge(webhook_router(state));
    } else if std::env::var("STRIPE_WEBHOOK_SECRET").is_ok() {
        warn!("Stripe webhook secret present but durable D1 is unavailable; webhook NOT mounted (fail-CLOSED)");
    } else {
        warn!("STRIPE_WEBHOOK_SECRET unset; Stripe webhook route NOT mounted (dev/CI mode)");
    }

    // GDPR1 per-user erasure: `POST /_internal/dsr/anchor` — register the
    // `dsr_requested` legitimacy anchor for a per-user (not whole-account)
    // erasure, so the per-digest CAS erase can authorize it. Gated by the
    // dedicated CORELINK_DSR_ANCHOR_AUTH_KEY ONLY (NO shared fallback; finding
    // H4) — held by the erasure-request authority (githugr), a DIFFERENT
    // party than the eraser (hugit), or the legitimacy gate is moot. (Mounted last,
    // after the cited-in-OKF blocks above, to keep the anti-drift line-anchors stable.)
    let dsr_anchor_auth_key = corelink_server::routes::admin::dsr_anchor_auth_key_from_env();
    if let Some(dsr_anchor_state) =
        corelink_server::routes::dsr_anchor::build_state_from_env(dsr_anchor_auth_key)
    {
        info!("routes: /_internal/dsr/anchor route mounted (auth key + D1 present)");
        app = app.merge(corelink_server::routes::dsr_anchor::router(
            dsr_anchor_state,
        ));
    } else {
        warn!(
            "CORELINK_DSR_ANCHOR_AUTH_KEY / D1 incomplete; \
             /_internal/dsr/anchor route NOT mounted (fail-CLOSED)"
        );
    }

    // ── BYOK provider readiness boot note (C1) ──
    // A binary without a real provider is deliberately unavailable; there is
    // no plaintext/XOR fallback. The activation route repeats this readiness
    // check immediately before any D1 mutation, so a feature flag or stale
    // boot state can never masquerade as usable KMS custody.
    if corelink_server::byok_orchestrator::active_provider()
        == corelink_server::byok_orchestrator::ActiveProvider::Unavailable
    {
        info!(
            event = "byok_activation_unavailable",
            provider = corelink_server::byok_orchestrator::active_provider().as_str(),
            "BYOK activation is UNAVAILABLE (no real KmsProvider) — \
             /v1/admin/byok/activate returns 501"
        );
    }

    // ── B-083: production BYOK revocation scheduler ──
    // The detector is only useful when its active-key population, status
    // store, and customer notification sink are all durable.  In particular,
    // never start a loop backed by the detector's hermetic empty source: that
    // would be a healthy-looking but vacuous scheduler.  A real-provider
    // binary therefore refuses to serve when durable D1 wiring is absent.
    #[cfg(any(
        feature = "byok-aws-real",
        feature = "byok-gcp-real",
        feature = "byok-azure-real",
        feature = "byok-vault-real"
    ))]
    let _byok_revocation_task = if byok_revocation_scheduler_enabled(
        std::env::var("CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED")
            .ok()
            .as_deref(),
    ) {
        let storage_env = corelink_server::storage::StorageEnv::from_env()
            .ok_or("BYOK revocation scheduler requires durable D1/R2 configuration")?;
        let client = corelink_server::storage::d1_http::D1HttpClient::new(&storage_env)
            .map_err(|error| format!("BYOK revocation D1 client init failed: {error}"))?;
        let provider = corelink_server::byok_orchestrator::make_provider()
            .await
            .map_err(|error| format!("BYOK provider init failed: {error}"))?;
        let detector = corelink_server::byok_revocation_runtime::detector_for_client(
            Arc::new(client),
            provider,
        )
        .map_err(|error| format!("BYOK revocation detector init failed: {error}"))?;
        debug_assert!(detector.has_key_source());
        info!(
            event = "byok_revocation_scheduler_started",
            provider = corelink_server::byok_orchestrator::active_provider().as_str(),
            "BYOK revocation run_loop wired before listener bind"
        );
        Some(tokio::spawn(detector.run_loop()))
    } else {
        info!(
            event = "byok_revocation_scheduler_disabled",
            "BYOK revocation scheduler disabled; set \
             CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED=true only after durable \
             provider credentials and notification wiring are provisioned"
        );
        None
    };

    #[cfg(not(any(
        feature = "byok-aws-real",
        feature = "byok-gcp-real",
        feature = "byok-azure-real",
        feature = "byok-vault-real"
    )))]
    let _byok_revocation_task: Option<tokio::task::JoinHandle<()>> = None;

    // B-083 activation and physical cleanup are explicitly enabled by the
    // operator and remain nonfatal to listener boot. Each child job is finite;
    // durable D1 claims make restart and multi-container overlap safe.
    let _byok_background_tasks = start_byok_background_tasks(d1_client.as_ref());

    // Single HTTP/1.1 listener on PORT (50051) — the DO's getTcpPort target.
    let listener = tokio::net::TcpListener::bind(serve_addr).await?;
    info!(%serve_addr, "CoreLink HTTP data-plane server starting");
    // F-017 (drain half): wire graceful shutdown so a Cloudflare containers
    // rollout (SIGTERM) stops accepting new connections and lets the
    // in-flight HTTP requests finish before the process exits. Without this,
    // SIGTERM would abort every active request mid-flight during a rollout.
    // The complementary halves — wrangler containers-rollout drain policy +
    // the /_health/container storage==r2 readiness assertion — are tracked
    // separately (see TODO below) and are NOT in this change's scope.
    // TODO(F-017): wrangler containers-rollout drain policy + /_health/container storage==r2 assertion
    axum::serve(listener, app)
        .with_graceful_shutdown(runtime::shutdown_signal())
        .await?;

    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
