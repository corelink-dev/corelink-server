//! HTTP route surface for the CoreLink server.
//!
//! Wave-8 landed the CAS read end-to-end as the **example wire-up**
//! for the R-prep handler-crate skeleton (see
//! `specs/_audits/sealed/2026-05-14-slo-instrumentation-gaps.md §6`):
//! `apps/server::routes::cas` wires `corelink-handler-cas` + in-memory
//! fakes into an axum route, demonstrating where the
//! `#[cfg(target_arch = "wasm32")]` CF-Worker handler slots in.
//!
//! Wave-11 (this commit) extends the same pattern to the AC and
//! Admin handler crates:
//!
//! - [`ac`] — `GET/PUT /v1/ac/{tenant}/{action_digest}` against
//!   `corelink-handler-ac::{AcLookupHandler, AcUpdateHandler}`.
//!   Emits `Sli::AvailAcLookup` + `Sli::LatencyAcHitP99` on every
//!   route entry; enforces `INV-TENANT-ISOLATION` at the route
//!   boundary on top of handler-layer enforcement.
//! - [`admin`] — `GET /v1/admin/read/{resource}` +
//!   `POST /v1/admin/mutate` against
//!   `corelink-handler-admin::{AdminReadHandler, AdminMutateHandler}`.
//!   Emits `Sli::AvailControlPlane` on every route entry; the
//!   mutate route is gated by dual-approval (per
//!   `dual_approval.md §3`).
//!
//! # Router composition
//!
//! [`build`] returns a fully composed `axum::Router` merging all
//! three sub-routers (cas, ac, admin). Each sub-router owns its
//! own `State<...>` so the trait-object swap surface stays local
//! to each module.

use std::sync::Arc;

use axum::Router;
use corelink_analytics::Region;
use corelink_audit_chain::{InMemoryNeonShadowSink, InMemoryShadowSyncAuditSink, NeonShadowSink};
use uuid::Uuid;

use crate::routes::audit_analytics::ShadowSinkFactory;

/// AC HTTP routes (R-prep wire-up; wave-11).
pub mod ac;
/// Admin HTTP routes (R-prep wire-up; wave-11).
pub mod admin;
/// Pilot-admin HTTP routes (Wave-29 stream-3): replaces the wave-27
/// placeholder scripts (`grant-pilot-tier.sh`, `list-pilot-tenants.sh`,
/// `pilot-24h-checkin.sh`) with proper endpoints + audit-emit
/// fail-CLOSED ordering + 5-Layer Defense scope gating.
pub mod admin_pilot;
/// Operator per-tenant deep-dive reads (usage/billing/consents/dsr/pats).
/// Operator posture: internal-auth gated, same as `admin` — reached via the
/// operator path, NOT the customer Worker (which strips internal-auth on
/// `/v1/*`). Wiring the admin-ui operator console to this surface is a separate
/// follow-up that applies to the whole operator plane, not just this module.
pub mod admin_tenant_detail;
/// Customer-facing audit-analytics routes (Wave-18 wiring of the
/// Neon analytics shadow sync): `GET /v1/audit/analytics/event-count`
/// + `GET /v1/audit/analytics/timeline` over the per-tenant
/// `audit_events_shadow` Neon table. The shadow is analytics-only;
/// the canonical chain-integrity store is the R2 NDJSON archive
/// (Wave 15) — see `specs/_audits/sealed/2026-05-15-neon-analytics-shadow.md`.
pub mod audit_analytics;
/// Internal audit-emit route for edge-served existence probes:
/// `POST /_internal/audit/cas-attempted`. Writes the `ReadAttempted` rows a
/// `findMissingBlobs` batch owes when the PROBE ran at the edge, through the
/// same `D1AuditOutboxSink` the container uses — so the edge never becomes a
/// second author of the audit row. Dedicated-key gated; fail-CLOSED mount.
pub mod audit_cas_attempted;
/// Internal S-09 audit-chain drain route: `POST /_internal/audit/drain`.
/// Seals the live `audit_outbox` trail into the BLAKE3 tamper-evident hash
/// chain (computes each row's RFC-8785 JCS canonical bytes + BLAKE3 link,
/// flips `emitted_at`, advances the per-partition `audit_chain_head`
/// checkpoint under a compare-and-set anti-fork guard). Internal-auth gated
/// (mirrors [`dsr`]); env-gated mount in [`crate::main`] (erase key + D1).
pub mod audit_drain;

/// Internal S-09 audit ARCHIVE route: `POST /_internal/audit/archive`.
///
/// Copies rows the drain already sealed into immutable NDJSON chunks in R2.
/// Deliberately SEPARATE from [`audit_drain`] so an R2 outage can never
/// endanger a D1 seal — see the module docs.
pub mod audit_archive;
/// Customer-facing audit-export route (Wave-15.3 wiring of
/// WI-S09-008): `GET /v1/audit/export?from=&to=` streams NDJSON
/// audit events + inclusion proofs.
pub mod audit_export;
/// Fabric PAT introspection route (M1): `POST /internal/v1/auth/introspect`.
/// Reached only from the corelink-runners fabric via the container's
/// internal listener. Gated by the `X-Corelink-Internal-Auth` header bound
/// to a DEDICATED `FABRIC_INTROSPECT_AUTH_KEY` secret (tight blast radius —
/// distinct from the mint secret). Verifies an inbound PAT via the shared
/// [`crate::adapter_pat`] pipeline and resolves the tenant's plan; fail-CLOSED
/// (503) on any backend fault, uniform `{valid:false}` on a bad PAT.
pub mod auth_introspect;
/// REAPI v2 Bazel remote-cache routes (Phase 0 Stream B1):
/// `GET/PUT /bazel/v2/:instance/blobs/:hash/:size`,
/// `PUT /bazel/v2/:instance/uploads/:uuid/blobs/:hash/:size`,
/// `GET/PUT /bazel/v2/:instance/blobs/ac/:hash/:size`, and
/// `POST /bazel/v2/:instance/findMissingBlobs`.
///
/// Enables `--remote_cache=https://corelink-api.humangr.com/bazel/v2`
/// for any Bazel user; backed by the same R2 CAS/AC blobs as the
/// native `/v1/cas` and `/v1/ac` routes.
pub mod bazel_v2;
/// Runner billing usage-push INGEST route (ASK-2):
/// `POST /internal/v1/billing/usage`. Reached only from the corelink-runners
/// fabric via the container's internal listener. Gated by the
/// `X-Corelink-Internal-Auth` header bound to a DEDICATED
/// `BILLING_INGEST_AUTH_KEY` secret (tight blast radius — distinct from the
/// mint / introspect / erase secrets). Idempotently stages a JSON BATCH of
/// raw per-lease usage records into the canonical `usage_event_staging` D1
/// table the [`corelink_billing_aggregator`] drains + rolls up; it does NOT
/// aggregate or touch Stripe. Fail-CLOSED (503) on any backend fault, 400
/// on a malformed batch. Env-gated mount in [`crate::main`] (unmounted in
/// dev/CI).
pub mod billing_ingest;
/// Homebrew bottle cache surface (Phase B): `/brew/<tenant>/<bottle-path>`
/// nests the `corelink_adapter_host::brew` read-through proxy. Option-B PAT
/// re-verify via the shared [`crate::adapter_pat`] verifier; public bottle
/// bytes dedup cross-tenant through the 2-level [`crate::adapter_cache`] moat.
/// Env-gated mount in [`build_with_factory`].
pub mod brew;
/// Operator-gated BYOK **activation** control plane
/// (`POST /v1/admin/byok/{activate,deactivate}`): the WRITE authority that flips
/// a tenant's `tenant_byok_config.state` to `active` (engaging the r2_s3
/// at-rest encryption gate) + persists its CMK-wrapped Tcs, plus the crypto-shred
/// kill switch. Internal-auth gated exactly like `admin`. Closes the H5 gap
/// left by migration 0081 (the read model + engagement gate were inert with no
/// writer).
pub mod byok_admin;
/// sccache HTTP build-cache surface: `/cargo/<tenant>/<key>` (FINDING
/// Gap 1). Mounts `corelink_adapter_host::cargo` with a D1-backed PAT
/// resolver (Option B) + per-operation scope gate. Mounted only when
/// `PAT_SIGNING_KEY` + the D1/R2 `StorageEnv` are present (fail-CLOSED:
/// unmounted in dev/CI). See module docs.
pub mod cargo;
/// CAS HTTP routes (R-prep example wire-up; wave-8).
pub mod cas;
/// Per-hash CAS erase + 410-Gone tombstone (hugit-P2 seam B, WP-B):
/// `POST /_internal/cas/:tenant/:hash/erase` (internal-auth gated, write-side).
/// Deletes a blob from R2 (composing the DSR Wave 1 / PR #254 R2 CAS erase
/// primitives) and writes a `cas_tombstone` row (migration 0067) so a
/// subsequent GET returns HTTP 410 Gone. Pure decision logic lives in
/// `corelink-handler-cas-erase`. Route mounting is owner-gated on the R2 eraser
/// (the #254 seam); until then `build_state_from_env` returns `None`.
pub mod cas_erase;
/// At-rest CAS integrity scrubber (B-050): `POST /_internal/cas/scrub`.
/// Re-hashes stored CAS objects so the read-path re-verify stops being the only
/// integrity coverage — a cold object is never read and therefore never checked
/// today. Enumerates R2 per tenant (an R2 key's tenant prefix is a secret-keyed
/// HMAC and cannot be inverted), skips BYOK-encrypting tenants whole, and
/// reports `examined` / `skipped_encrypted` / `failed` as three distinct
/// counters. Hard prerequisite for streaming CAS reads — ADR-S34-001.
pub mod cas_scrub;
/// Customer self-serve HTTP routes (Stream-2.6): `/v1/customer/*` endpoints
/// (overview, usage, billing, keys, team, audit) wired via
/// `corelink-handler-customer` trait objects. Worker matchRoute already
/// forwards these paths to the container; this module is the final link
/// that makes them return real responses instead of 404.
pub mod customer;
/// Customer self-serve tenant bulk export (SEAM): `POST /v1/customer/account/export`
/// streams the full portability bundle (CAS+AC blob bytes + RBAC/DPA/audit records)
/// the CLI `corelink tenant export` needs. Owns the `TenantExportSource` seam +
/// the streaming NDJSON assembler; the handler lives in `customer`.
pub mod customer_export;
/// Customer Runners read surface (BE-10): tenant-scoped entitlement/allowlist/runs.
pub mod customer_runners;
/// DPA click-through acceptance route: `POST /v1/onboarding/dpa-accept`.
/// Writes the durable `dpa_acceptances` row (migration `0038`) that the
/// tier-select money-path gate (`is_dpa_accepted`) reads — same internal-auth +
/// verified-tenant contract as `tier_select`. Drives the real
/// `corelink-dpa-acceptance` crypto/schema primitives (RS256 receipt, IP hash,
/// locale enum) + a real RS256 receipt; gated on `DPA_RECEIPT_SIGNING_KEY`.
pub mod dpa_accept;
/// Production D1-over-HTTP [`dpa_accept::DpaAcceptStore`] adapter: the durable
/// `dpa_acceptances` reader/writer (mirrors `tier_select_store`).
pub mod dpa_accept_store;
/// Internal DSR erasure route (WI-S11-008): `POST /_internal/dsr/erase`.
/// Reachable only from the Cloudflare DO; gated by the same
/// `X-Corelink-Internal-Auth` shared secret. Drives the 12-backend erasure
/// orchestrator (Wave 0: in-memory no-op adapters; Wave 1 wires real transports).
pub mod dsr;
/// Read-side FAILOVER Tower layer + a REAL `HealthProbe` (WI-MULTI-REGION-V1
/// prod-wiring). A router `layer` — mirror of `residency_guard` — that drives
/// `corelink-failover-router`'s decision core with a live-traffic
/// [`failover::RollingMetricsHealthProbe`]. When THIS container's region is
/// degraded (sustained multi-signal outage) it fail-CLOSED blocks writes (503
/// `failover_readonly`) and stamps a sibling read-region hint header so the edge
/// Worker re-routes reads. Inert (pass-through) in a healthy region, in dev/CI,
/// and on APAC colos with no sibling in the 4-macro graph. Wired as one
/// `.layer(...)` line in [`build_with_factory`].
pub mod failover;
/// Internal PAT mint route (Stream-5): `POST /_internal/pat/mint`.
/// Only reachable from the Cloudflare Durable Object via
/// `container.getTcpPort(50051)`. Gated by the `X-Corelink-Internal-Auth`
/// shared-secret header. Mints a fresh PAT plaintext using
/// `corelink_pat::mint::mint(...)` and returns the hash + plaintext
/// for the signup-worker to write to D1 and Clerk session metadata.
pub mod internal_pat;
/// npm registry cache surface (Phase B): `/npm/<tenant>/<rest>` nests the
/// `corelink_adapter_host::npm` read-through `registry.npmjs.org` mirror.
/// Option-B PAT re-verify via the shared [`crate::adapter_pat`] verifier;
/// tarball bytes dedup through the 2-level [`crate::adapter_cache`] moat,
/// mutable package metadata in the D1-backed [`crate::adapter_kv`] KV.
/// Env-gated mount in [`build_with_factory`].
pub mod npm;
/// OCI Distribution v1.1 registry surface (Phase B): `/v2/*` + `/token`
/// mounts the `corelink_adapter_host::oci` adapter (docker / podman / buildah
/// / containerd / Helm OCI). Two-leg auth: `/token` exchanges a PAT (Option-B
/// re-verify via the shared [`crate::adapter_pat`] verifier) for a short-lived
/// HMAC registry bearer, downscoped to the PAT's capability; `/v2` ops verify
/// the bearer locally + enforce its repo scope. Blobs dedup through the
/// [`crate::adapter_cache`] moat; mutable manifests/tags in the durable
/// [`crate::adapter_oci_kv`] D1 KV. Env-gated mount in [`build_with_factory`].
pub mod oci;
/// PyPI (pip / uv / poetry / pdm) cache surface (Phase B):
/// `/pip/<tenant>/<pep-path>` nests the `corelink_adapter_host::pip`
/// read-through PyPI mirror (PEP 503/691 simple index + content-addressed
/// wheels/sdists). Option-B PAT re-verify via the shared [`crate::adapter_pat`]
/// verifier; wheel bytes dedup through the 2-level [`crate::adapter_cache`] moat,
/// the mutable simple index in a per-tenant D1 KV. Env-gated mount in
/// [`build_with_factory`].
pub mod pip;
/// PUBLIC erasure-attestation verifier routes (Artifact 1, WP-C1):
/// `GET /v1/public/attestation/{request_id}` + `GET /v1/public/keys/erasure/{region}.pub`.
/// UNAUTHENTICATED by design (an erasure proof is publicly verifiable) — D1-read
/// only, mounted OUTSIDE the ratelimit/residency/auth layers in [`crate::main`].
pub mod public_attestation;
/// F3.2 increment-4b server-only public-base MIRROR endpoint (admin-gated;
/// S0 ships the mount seam + stub, bodies land in inc4b).
pub mod public_mirror;
/// WP-G per-tenant OCI manifest + blob upstream-on-miss resolver (M1 of the
/// manifest-resolution keystone, `OCI_UPSTREAM_ON_MISS`). Flag-gated OFF, INERT
/// until a repin: on a per-tenant manifest KV miss it fetches + verifies +
/// per-tenant-caches the manifest (and, for an image, its config + layer blobs)
/// from the fixed upstream instead of 404-ing. Fail-open at every step; reuses
/// the ONE audited SSRF/token client from [`public_mirror`].
pub mod public_pullthrough;
/// `_public` shared-dedup blob revocation endpoint (F3.2 BLOCKER-1, B1b). The
/// write-side incident-response counterpart to [`cas_erase`]: blocklist +
/// map-delete + audit + R2 hard-delete of a poisoned cross-tenant public blob,
/// gated by the dedicated `CORELINK_ERASE_AUTH_KEY`.
pub mod public_revoke;
/// Per-tenant request-rate token-bucket middleware (audit #14/#16). A router
/// `layer` wrapping the already-built `corelink-ratelimit` engine: it charges
/// one token per request against the DO-injected `x-corelink-tenant-id`
/// tenant's bucket and rejects over-limit traffic with 429 + `Retry-After`.
/// Wired with ONE `.layer(...)` line in [`build_with_factory`] so it covers
/// the composed data plane (CAS/AC, Bazel, Turbo, sccache, adapters) but NOT
/// the `/_health` probe or `/_internal/*` routes (those mount in `main.rs`
/// AFTER `build_with_factory` returns). Fail-OPEN on absent tenant + on the
/// limiter's own internal fault (logged); see module docs.
pub mod ratelimit_layer;
/// Data-residency guard middleware (backlog #29 — Schrems II leak). A router
/// `layer` that runs BEFORE any handler: it reads the trusted
/// `x-corelink-primary-region` macro (set by the edge Worker), maps it to a colo
/// via the FROZEN [`crate::storage::region_map`], and rejects with 409
/// `residency_violation` if it does not match THIS container's own
/// `R2_CAS_REGION` — defence-in-depth against a mis-bound regional Worker
/// landing an EU tenant's bytes in a US container. Disjoint from cas.rs/ac.rs
/// (no handler-body edits); wired as one `.layer(...)` line in [`build_with_factory`].
pub mod residency;
/// Pilot signup route (wave-29 stream-1; closes DEBT-027 engineering-side).
/// Surfaces `POST /v1/signup/pilot/{token}` over an HMAC-SHA256
/// signed token + per-IP rate-limit + fail-CLOSED audit emit. See
/// `specs/_audits/sealed/2026-05-16-signup-corelink-dev-backend.md`.
pub mod signup;
/// Dedicated authenticated exact-run teardown route.  Router composition stays
/// with the boot owner; this module supplies the bounded route and service seam.
pub mod staging_load_test_teardown;
/// Read-only internal tenant-quota lookup:
/// `GET /_internal/tenant/{tenant_id}/quota`. Returns the persisted
/// `tenant_quota` row (monthly `$`-ceiling / accrued / cycle anchor) plus a
/// derived `unmetered` bit. Internal-auth gated (constant-time; dedicated
/// `CORELINK_QUOTA_READ_AUTH_KEY` → shared-key fallback via
/// [`admin::resolve_internal_auth_key`]); 404 `no_quota_row` when the tenant
/// has no row, 503 fail-CLOSED on a D1 fault. Env-gated mount in [`crate::main`]
/// (unmounted when the key or D1 is absent) — mirrors [`audit_drain`].
pub mod tenant_quota_read;
/// `POST /v1/onboarding/tier-select` — server-side Stripe Checkout
/// Session creation for self-serve tier upgrades. Internal-auth gated
/// (constant-time) + edge-verified `x-corelink-tenant-id` (fail-CLOSED);
/// INV-ONBOARD-DPA-FIRST + durable 60s lock + hosted Stripe Checkout.
/// WI-S19-004 production wiring.
pub mod tier_select;
/// Production [`tier_select::TierSelectAudit`] adapter (WP-C scaffold):
/// fail-CLOSED audit-chain emit (mirrors `internal_pat` tracing-audit).
pub mod tier_select_audit;
/// Production [`tier_select::CheckoutCreator`] adapter (WP-B scaffold):
/// hosted Stripe Checkout via `StripeRealClient` (`spawn_blocking`). Holds
/// the email-seam decision (trait stays email-free; Stripe collects it).
pub mod tier_select_checkout;
/// Production [`tier_select::TierSelectStore`] adapter (WP-A scaffold):
/// the durable D1-over-HTTP lock / DPA / active-subscription / persist
/// transaction. Stub bodies (`todo!("WP-A")`) until WP-A fills the SQL.
pub mod tier_select_store;
/// Turborepo remote-cache routes (Phase 0 / Stream B2):
/// `GET/PUT /v8/artifacts/:hash`, `POST /v8/artifacts/events`,
/// `POST /v8/artifacts/status`.
///
/// Wires [`corelink_turbo_bridge`] into the container router so Turborepo
/// users can set `TURBO_API=https://corelink-api.humangr.com` and use
/// CoreLink CAS as their remote build cache.
///
/// Phase 0 backing store: `InMemoryKvStore` (non-persistent).
/// TODO(v2): swap for `R2KvStore` — see module doc.
pub mod turbo_v8;
/// Caller-identity reflection route: `GET /v1/users/me` reads the
/// Worker-injected `x-corelink-tenant-id` / `-token-prefix` /
/// `-route-kind` headers and echoes them as JSON. Lets clients verify
/// PAT wiring without exercising any data-plane (CAS/AC) surface.
pub mod users;
/// Customer Workspaces surface (BE-11): tenant-scoped snapshot CRUD + pin.
pub mod workspaces;

/// Per-route handle to the per-tenant monthly $-ceiling gate (ADR-0068;
/// hugit-P2 WP-G1). Bundles the shared [`crate::tenant_quota::QuotaGuard`]
/// with the FLAT per-op cost resolved once at boot
/// ([`crate::tenant_quota::cost_per_op_micros`]), so each billable handler
/// can charge a fixed cost without re-reading env on the hot path.
///
/// A billable handler holds an `Option<QuotaGate>` in its route state
/// (`None` in dev/CI without D1) and calls [`QuotaGate::check`] at the TOP,
/// AFTER the rate-limit / scope gate and BEFORE the work:
///
/// ```ignore
/// if let Some(gate) = state.quota.as_ref() {
///     if let Some(resp) = gate.check(&tenant).await { return resp; }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct QuotaGate {
    guard: Arc<crate::tenant_quota::QuotaGuard>,
    cost_micros: i64,
}

impl QuotaGate {
    /// Build the production gate from process env, or `None` in dev/CI
    /// (no D1 storage env). The flat per-op cost is resolved once here.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let guard = crate::tenant_quota::quota_guard_from_env()?;
        Some(Self {
            guard,
            cost_micros: crate::tenant_quota::cost_per_op_micros(),
        })
    }

    /// Charge ONE flat-cost billable op against `tenant`'s monthly
    /// $-ceiling. `Some(resp)` ⇒ REJECT (402 over-ceiling / 503
    /// fail-CLOSED); `None` ⇒ proceed. Delegates to
    /// [`crate::tenant_quota::QuotaGuard::check`].
    ///
    /// Timed as the `oquota` sub-phase of the Worker's `origin` block: the
    /// check-and-accrue is a D1 round trip on every billable request, so it is
    /// the other prime candidate (with the `pat` read) for the ~300 ms `origin`
    /// measured in prod. `timed` wraps the call and changes nothing about it.
    pub async fn check(&self, tenant: &str) -> Option<axum::response::Response> {
        crate::origin_timing::timed(
            crate::origin_timing::Phase::Quota,
            self.guard.check(tenant, self.cost_micros),
        )
        .await
    }

    /// Charge a BATCH of `n` flat-cost billable ops against `tenant`'s
    /// monthly $-ceiling in a SINGLE check-and-accrue (CAA-360 #14/#18).
    ///
    /// `findMissingBlobs` fans one request out to up to `FIND_MISSING_BLOB_CAP`
    /// (4096) backend existence probes, so charging one flat op cost for the
    /// whole batch let a tenant drive thousands of probes per accrued dollar
    /// (the per-request cost model assumes one). The prior fix charged per
    /// digest in a loop capped at 64 iterations, which still under-charged any
    /// batch over 64 digests. This delegates to
    /// [`crate::tenant_quota::QuotaGuard::check_batch`], which charges the FULL
    /// `n × cost` in one atomic statement — proportional for every batch size,
    /// no per-digest D1 round-trips, and no iteration cap.
    ///
    /// `Some(resp)` ⇒ REJECT (402 over-ceiling / 503 fail-CLOSED); `None` ⇒
    /// proceed. `n = 0` charges nothing and returns `None`.
    /// Timed as `oquota`, exactly like [`Self::check`] — one batched round trip
    /// is still one round trip inside `origin`.
    pub async fn check_batch(&self, tenant: &str, n: usize) -> Option<axum::response::Response> {
        crate::origin_timing::timed(
            crate::origin_timing::Phase::Quota,
            self.guard.check_batch(tenant, n, self.cost_micros),
        )
        .await
    }

    /// Construct a gate from an explicit guard + per-op cost. Used by route
    /// integration tests to wire a hermetic in-memory quota store (the
    /// production path uses [`Self::from_env`]).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_for_test(
        guard: Arc<crate::tenant_quota::QuotaGuard>,
        cost_micros: i64,
    ) -> Self {
        Self { guard, cost_micros }
    }
}

/// Per-tenant in-memory shadow-sink factory. Production wiring
/// replaces this with a Neon-backed factory (see
/// `apps/server/src/main.rs` boot path); the in-memory factory
/// keeps the `/v1/audit/analytics/*` routes mounted in dev/CI so the
/// handler surface stays exercised end-to-end without a live Postgres
/// dependency.
///
/// Each `for_tenant` call returns a FRESH `InMemoryNeonShadowSink` so
/// the tenant's RLS-binding (the sink owns the `tenant_id`) is
/// preserved per request. The sink's in-memory state is per-instance —
/// the dev/CI shadow does NOT persist across requests (this is
/// intentional: the in-memory factory is a route-shape fixture, not a
/// stand-in for the production Neon backing store).
#[derive(Debug, Default)]
pub struct InMemoryShadowSinkFactory;

impl InMemoryShadowSinkFactory {
    /// Construct the canonical in-memory factory.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ShadowSinkFactory for InMemoryShadowSinkFactory {
    fn for_tenant(&self, tenant_id: Uuid) -> Result<Arc<dyn NeonShadowSink>, &'static str> {
        // Default region for the in-memory dev/CI sink is IAD — the
        // production factory resolves the per-tenant pinned region
        // from the tenant-config store.
        let audit = Arc::new(InMemoryShadowSyncAuditSink::new());
        Ok(Arc::new(InMemoryNeonShadowSink::new(
            tenant_id,
            Region::Iad,
            audit,
        )))
    }
}

/// Build the composed handler router merging CAS, AC, Admin,
/// audit-export, and (Wave-20 closure) audit-analytics sub-routers.
/// Each sub-router carries its own state.
///
/// The audit-analytics router is mounted unconditionally — the
/// [`InMemoryShadowSinkFactory`] is the default backing for dev/CI;
/// production swaps in `audit_analytics::D1ShadowSinkFactory` at the
/// boot path (`crates/corelink-container/src/main.rs`), which serves the
/// `/v1/audit/analytics/*` aggregates from the live D1
/// `customer_audit_events` table (migration 0077 — the SAME table
/// `/v1/customer/audit` reads). The swap is env-gated by
/// `D1ShadowSinkFactory::from_env`: when the D1 storage env is absent
/// (dev/CI) the routes stay on the in-memory factory so the surface
/// still boots.
///
/// RETIRED (#71): the former per-region Neon "analytics shadow" — the
/// container-side `neon-real` feature, `TokioPgShadowSinkFactory`, and
/// the per-region `NEON_DB_URL_<REGION>` env vars — is REMOVED, not
/// merely disabled. It was never wired in prod (the DSN env was never
/// set and the driver was never compiled into the shipped container), so
/// the boot path always fell back to the in-memory sink and every
/// analytics query returned empty. Do not re-derive that design from
/// this comment: D1 is the only production backing for these routes.
pub fn build() -> Router {
    build_with_factory(Arc::new(InMemoryShadowSinkFactory::new()))
}

/// Boot-time credential-separation invariant for the admin dual-approve gate
/// (2026-08-19 red-team, "two-person control collapses to one shared secret").
///
/// Two-person control on `/v1/admin/approve` + `/v1/admin/mutate` is only real
/// if the approver key and the mutate/internal key are DIFFERENT secrets. The
/// dedicated-only [`admin::approver_auth_key_from_env`] already refuses the
/// shared-key fallback, but this closes the residual foot-gun where an operator
/// binds `CORELINK_ADMIN_APPROVER_AUTH_KEY` to the SAME value as
/// `CORELINK_INTERNAL_AUTH_KEY`: if the resolved approver key is byte-equal to
/// the internal/mutate key, it is treated as unconfigured (`None`) so the
/// approve route fails CLOSED (403) rather than silently permitting
/// self-approval. Enforced in code, not by an operator remembering to pick
/// distinct values. The comparison is constant-time (no secret-length or
/// content timing oracle).
#[must_use]
pub(crate) fn approver_key_distinct_or_none(
    approver_auth_key: Option<Arc<str>>,
    internal_auth_key: Option<&Arc<str>>,
) -> Option<Arc<str>> {
    use subtle::ConstantTimeEq;
    let approver = approver_auth_key?;
    if let Some(internal) = internal_auth_key {
        // Constant-time equality; length difference short-circuits to "distinct"
        // without leaking either length via a content compare.
        if approver.len() == internal.len()
            && approver.as_bytes().ct_eq(internal.as_bytes()).unwrap_u8() == 1
        {
            tracing::error!(
                "CORELINK_ADMIN_APPROVER_AUTH_KEY is byte-equal to \
                 CORELINK_INTERNAL_AUTH_KEY — two-person control would collapse; \
                 treating the approver key as UNSET so POST /v1/admin/approve fails \
                 CLOSED (403). Provision a DISTINCT approver key (`openssl rand -hex 32`)."
            );
            return None;
        }
    }
    Some(approver)
}

/// Internal DSR legitimacy-anchor register route (GDPR1, per-user erasure):
/// `POST /_internal/dsr/anchor`. Lets the erasure-REQUEST authority register a
/// `dsr_requested` anchor for `(dsr_id, tenant)` so the per-digest CAS erase can
/// authorize a per-user (not whole-account) erasure. Dedicated key, held by a
/// DIFFERENT authority than the eraser (anti-forge). See `routes/dsr_anchor.rs`.
/// (Declared here, after the OKF-cited items above, to keep line-anchors stable.)
pub mod dsr_anchor;

/// OTel-export request-path layer (observability SEAM closure): constructs the
/// configured `corelink-telemetry` exporter from the `[observability.export.*]`
/// env surface and streams a canonical `MetricPoint` + `TraceSpan` per data-plane
/// request through the fail-OPEN boundary. Wired with ONE `.layer(...)` line at
/// the end of [`build_with_factory`]. (Declared here, after the OKF-cited blocks
/// above, to keep the anti-drift line-anchors stable.)
pub mod otel_layer;

/// Router assembly (B-126): the 649-line `build_with_factory` that composes
/// every surface, moved out so this file keeps one job — declaring the tree.
pub mod build;
pub use build::{
    build_with_factory, build_with_factory_and_byok, build_with_factory_and_byok_and_reapi_ingress,
    RouterWithReapiIngress,
};

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

    #[test]
    fn build_returns_composed_router() {
        // Smoke test: the composed router is constructable on the
        // native target. Per-route behaviour is covered by the
        // module-level integration tests in cas.rs / ac.rs / admin.rs.
        let _router = build();
    }

    #[test]
    fn approver_key_distinct_or_none_enforces_credential_separation() {
        let internal: Arc<str> = Arc::from("internal-shared-key-32-bytes-aaaa");
        let same: Arc<str> = Arc::from("internal-shared-key-32-bytes-aaaa");
        let distinct: Arc<str> = Arc::from("dedicated-approver-key-32-bytes-b");

        // Byte-equal to the internal/mutate key ⇒ treated as unset (fail-closed).
        assert!(
            approver_key_distinct_or_none(Some(same), Some(&internal)).is_none(),
            "an approver key byte-equal to the internal key must collapse to None"
        );
        // A genuinely distinct approver key survives.
        assert_eq!(
            approver_key_distinct_or_none(Some(distinct.clone()), Some(&internal)).as_deref(),
            Some(distinct.as_ref()),
        );
        // No approver key ⇒ None regardless of the internal key.
        assert!(approver_key_distinct_or_none(None, Some(&internal)).is_none());
        // No internal key bound (dev/CI) ⇒ the approver key passes through as-is.
        assert_eq!(
            approver_key_distinct_or_none(Some(distinct.clone()), None).as_deref(),
            Some(distinct.as_ref()),
        );
        // Different lengths are distinct (constant-time path short-circuits).
        let shorter: Arc<str> = Arc::from("short-approver-key-32-bytes-cccc");
        assert!(
            approver_key_distinct_or_none(Some(shorter.clone()), Some(&internal)).is_some(),
            "a different-length approver key is distinct"
        );
    }

    #[test]
    fn in_memory_shadow_sink_factory_resolves_per_tenant() {
        // Wave-20: the dev/CI default factory yields a fresh
        // InMemoryNeonShadowSink per tenant id, with the tenant pin
        // load-bearing for the route's RLS-like construction-time gate.
        let f = InMemoryShadowSinkFactory::new();
        let tenant = uuid::Uuid::now_v7();
        let sink = f.for_tenant(tenant).expect("resolves");
        assert_eq!(sink.tenant_id(), tenant);
        assert_eq!(sink.region(), Region::Iad);
    }
}
