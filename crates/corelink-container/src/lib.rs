//! `corelink-server` — CoreLink server binary support library.
//!
//! Hosts modules that are exercised by integration tests (which need
//! to link against the crate as a library, not just the binary).
//!
//! # Modules
//!
//! - [`webhook`] — Stripe webhook HTTP shell (axum). Thin boundary
//!   over the canonical
//!   [`corelink_stripe_real::webhook_dispatch::WebhookDispatcher`]
//!   pipeline (wave-16 unification, audit doc
//!   `specs/_audits/sealed/2026-05-15-stripe-webhook-production.md`).
//! - [`routes`] — HTTP route surface. Currently exposes the CAS read
//!   end-to-end as the example wire-up for the R-prep handler-crate
//!   skeleton (see
//!   `specs/_audits/sealed/2026-05-14-slo-instrumentation-gaps.md §6`).
//! - `byok` — feature-gated per-provider BYOK factory (built when ANY
//!   `byok-*-real` flag is set). Exposes a thin convenience constructor
//!   per provider (`make_{aws,gcp,azure,vault}_kms_provider`) plus
//!   `make_active_provider`, which delegates to [`byok_orchestrator`];
//!   new code should prefer the orchestrator directly.
//! - [`byok_orchestrator`] — singleton trait-object dispatch over the
//!   four production BYOK providers (AWS / GCP / Azure / Vault),
//!   feature-flag-selected at compile time. Default (no flag) fails
//!   closed with no provider; there is no in-memory crypto fallback.
//!   Multiple `byok-*-real` flags is a HARD
//!   compile error. See
//!   `specs/_audits/sealed/2026-05-15-byok-real-provider-pattern.md §7`.
//! - [`wall_clock`] — cross-route wall-clock trait (`WallClock` +
//!   `SystemWallClock` + `InMemoryFakeWallClock`). Wave-21 closure of
//!   the `A-P2-05` (audit-export) + `B-P2-03` (audit-analytics)
//!   findings: both routes consume `Arc<dyn WallClock>` in their route
//!   state so the rate-limit `now_ms` becomes wall-clock-derived rather
//!   than window-derived. See
//!   `specs/_audits/sealed/2026-05-16-wave18-adversarial-review-streamA-audit-export.md`
//!   and `…-streamB-neon-shadow.md`.
//!
//! # INV pin map (W36-PROPTEST-FU-001 closure)
//!
//! This crate carries INV references in route-boundary doc comments
//! that name **which invariant is pinned at the HTTP boundary**, not
//! where the load-bearing property tests live. Per WI-PROPTEST-FU-W33-001
//! closure (`specs/_audits/sealed/2026-05-26-w36-proptest-fu-001-seal.md`),
//! the property tests for each pinned INV live in the owning crate
//! listed below; this crate is listed in
//! `scripts/proptest-density-allowlist.txt` as an
//! "inv-pin documentation" exemption:
//!
//! | INV ref pinned here              | Property-test owner crate(s)                         |
//! |----------------------------------|------------------------------------------------------|
//! | `INV-AUTH-MIGRATION-ADDITIVE`    | `corelink-d1-migrations` (`tests/prop_migration_additivity.rs`) |
//! | `INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER` | `corelink-audit` + `corelink-slack-real` (`tests/prop_slack_emit_atomic.rs`) |
//! | `INV-TENANT-ISOLATION`           | `corelink-tenant-path` + `corelink-auth::schema` (`corelink-auth/tests/schema_prop_schema.rs`) |
//!
//! The route-boundary references in `src/routes/*.rs` are **pin
//! annotations** documenting which invariant the route enforces; they
//! do NOT relocate the property logic. See the SEAL audit above for
//! the full closure narrative.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#[cfg(any(
    feature = "byok-aws-real",
    feature = "byok-gcp-real",
    feature = "byok-azure-real",
    feature = "byok-vault-real"
))]
pub mod byok;

/// 2-level content-dedup MOAT store shared by the cache adapters: bytes
/// are content-addressed in CAS (blake3, deduped) behind a D1
/// `(namespace, url_hash) → content_hash` map. Public deps share the
/// `_public` namespace (cross-tenant dedup — the network-effect moat);
/// private artifacts stay per-tenant. See module docs.
pub mod adapter_cache;
/// D1-backed KV for the cache adapters' MUTABLE metadata (npm package
/// documents in `adapter_npm_meta`, public/private namespaced). See module docs.
pub mod adapter_kv;
/// Durable D1-backed `ManifestKvStore` for the OCI registry adapter
/// (mutable manifests + tag lists in `adapter_oci_kv`; blobs go through the
/// content-addressed moat). See module docs.
pub mod adapter_oci_kv;
/// Shared container-side PAT verifier (Option B) for ALL cache adapters
/// (cargo / brew / npm / oci / pip). Trait-agnostic
/// [`adapter_pat::PatVerifier::verify`]; each adapter route wraps it in a
/// thin newtype impl of that adapter's `TenantResolver` port. The HMAC
/// fast-reject → D1 lookup → Argon2id → fail-CLOSED scope pipeline lives
/// here once (replaces the cargo-only `cargo_pat_resolver`). See module docs.
pub mod adapter_pat;
pub mod auth_tenant;
/// Durable native [`corelink_billing_stripe_materializer::BillingD1Writer`]
/// over the CF D1 REST API (`billing_d1_http::D1HttpBillingWriter`). Bridges
/// the SYNC billing-writer trait (shared with the wasm32 Worker) to the
/// async [`storage::d1_http::D1HttpClient`] via `block_in_place`, so the
/// native Stripe-webhook materializer writes DURABLY to D1 instead of the
/// in-memory mirror. See module docs.
pub mod billing_d1_http;
pub mod byok_control_transition;
pub mod byok_orchestrator;
/// Native D1 collaborators and complete production wiring for the BYOK
/// revocation detector scheduler.
pub mod byok_revocation_runtime;
/// Tenant-wide D1 lease protocol excluding CAS/AC work from BYOK state and
/// revocation transitions.
pub mod byok_transition_fence;
/// Per-tenant **storage byte accounting** (red-team finding #1): the
/// [`byte_accounting::ByteAccountant`] that atomically check-and-accrues
/// `tenant_storage_state.bytes_used` after a store write (closing the
/// structurally-inert storage cap) and saturating-releases it on delete.
pub mod byte_accounting;
/// Deployed container capacity and the shared process-wide memory envelope.
/// All cache-plane concurrency budgets derive from this module's basic
/// (1 GiB / 0.25 vCPU) truth.
pub mod container_capacity;
/// Native Stripe current-subscription authority used by Runner entitlement
/// reconciliation. The module is intentionally separate from webhook parsing
/// so delivery payloads cannot become the provider authority by accident.
pub mod current_subscription_authority;
/// Production D1-backed customer-dashboard handler (dashboard revival
/// WP-3): [`customer_d1::D1CustomerHandler`] implements all 6
/// `corelink-handler-customer` traits over the CF D1 REST API
/// (sync↔async bridge per [`billing_d1_http`]), replacing the
/// InMemory 404-stub for real tenants. HONEST v1: real data where a
/// deployed table exists, explicit empty/zero/501 where it doesn't.
/// See module docs for the per-endpoint matrix.
pub mod customer_d1;
/// The request-scoped **co-read cell**: how the container's per-request D1
/// `pat` row read carries the url-map row the storage lookup is about to need,
/// so the two cost ONE round trip instead of two (`opat` + `ostore` were 55 %
/// of `origin` in prod, one RTT apiece). The hint is never authority — a
/// prefetched row is served only under the PAT-derived tenant.
pub mod d1_coread;
/// Canonical pseudonymized email-hash helper (CTRL-PRIV-001) — the ONE
/// `hash_email` every email-hash site shares so the invite→match flow and DSR
/// rectification stay byte-identical (HMAC-SHA256 under `EMAIL_HASH_SALT`, with
/// a no-regression unsalted SHA-256 fallback).
pub mod email_hash;
/// Native production GC sweep entrypoint adapters over the shared D1/R2
/// clients. The pure `corelink-gc` crate remains network-free.
pub mod gc_sweep;
/// Private staging-only native gRPC transport diagnostic.
///
/// This module has no listener mount. The mount is owned by #2578's serial
/// integration slot after #2708 and #2574 have landed.
pub mod grpc_staging_probe;
/// Native data-plane **PAT possession gate** (red-team finding #4): the
/// [`native_pat_gate::NativePatGate`] that re-runs the full Argon2id Option-B
/// verification (via [`adapter_pat::PatVerifier`]) at the container, so a leaked
/// `PAT_SIGNING_KEY` (HMAC-only forgery) cannot serve a forged tenant's PAT.
pub mod native_pat_gate;
/// Container-side resolution of a tenant's resolved per-tier storage cap for the
/// OCI `/token` mint (WP #10). Ports the Worker's `tier → storageBytesMax`
/// derivation so a DOWNGRADED tenant pushing exclusively over OCI reserves
/// against the resolved cap (the Worker forwards OCI RAW and never sets the
/// native `STORAGE_QUOTA_HEADER`). Fail-CLOSED on an unconfirmable tier.
pub mod oci_cap;
/// Container-side **tenant-suspend gate** for the OCI plane (go-live gap G4b):
/// a tenant whose `tenant_offboarding_state.state ∈ {suspended, erased}` is
/// DENIED push AND pull on `/v2/*` + `/token`. The worker-side suspend gate
/// (PR #677) does NOT cover OCI (the Worker forwards it RAW), so this closes the
/// bypass container-side at both the token mint and the residual `/v2` legs.
/// Fail-CLOSED (a known-suspended tenant stays denied through a D1 read fault).
pub mod oci_suspend;
/// Container-side decomposition of the Worker's `origin` Server-Timing phase:
/// a task-local phase ledger (`opat` / `oquota` / `ostore` / `oother`) plus the
/// outermost data-plane layer that reports it on the subresponse's own
/// `Server-Timing`, which the Worker merges under `origin`. Instrumentation
/// only — no behaviour, ordering or D1 access pattern depends on it. (Declared
/// last, after the alphabetical block above, so adding it shifts no existing
/// OKF line-anchor.)
pub mod origin_timing;
/// F3.2 increment 3 — the digest-pinned, owner-gated **public-base allowlist**
/// trust root: loads the container-baked manifest of upstream OCI base-layer
/// digests eligible for the cross-tenant `_public` namespace, fail-closed on any
/// non-digest (tag) entry. Inert until the increment-6 `OciMoatStore` router
/// consumes `is_allowlisted`; ships deny-all.
pub mod public_base_allowlist;
/// Boot-read F3.2 feature flags (increment-6 OCI `_public` dedup activation).
pub mod public_flags;
/// Per-tenant monthly **request-count** middleware primitive (rt-nuclear #8):
/// the container-side mirror of `worker/src/lib/quota.ts::checkRequestQuota`,
/// backed by the `monthly_request_counts` D1 table (migration 0071). Wired into
/// the OCI router so OCI billable writes — which the Worker forwards RAW and so
/// never counts — are metered against the tenant's monthly request cap, keyed
/// on the verified-HMAC-bearer tenant (the same one #318's `$`-ceiling gate
/// resolves). Fail-OPEN (SLO-style allowance, not a cost cap).
/// Centralized STRUCTURED-JSON bodies for the per-tenant `$`-ceiling quota
/// rejects (402 over-ceiling / 503 fail-CLOSED). Body/`Content-Type` only —
/// status codes and quota LOGIC are unchanged.
pub mod quota_error;
/// Unmounted REAPI ActionCache and cache-only Capabilities services.
pub mod reapi_action_cache;
/// Unmounted authenticated REAPI ByteStream service contract.
pub mod reapi_bytestream;
/// Unmounted REAPI CAS unary service over the authenticated ingress kernel.
pub mod reapi_cas;
/// Unmounted composition of the authenticated cache-only REAPI services.
pub mod reapi_composition;
/// Authenticated, tenant-scoped ingress kernel for future REAPI gRPC services.
pub mod reapi_ingress;
pub mod request_count;
pub mod routes;
/// Cache-scope enforcement helper + extractor.
///
/// Parses the Worker-set, server-trusted `x-corelink-scope` header (the
/// PAT's D1 scope string) into a checkable form and gates the cache
/// surfaces (CAS / AC / Turbo) on read vs write capability. Fail-CLOSED:
/// missing/empty scope grants nothing. See module docs for the grammar.
pub mod scope;
/// Durable native [`crate::routes::signup::SignupStore`] over the CF D1
/// REST API (`signup_d1_http::D1HttpSignupStore`). Bridges the SYNC
/// `SignupStore` trait to the async [`storage::d1_http::D1HttpClient`] via
/// `block_in_place`, so `POST /v1/signup/pilot/{token}` persists pilot
/// reservations DURABLY to D1 instead of the in-memory fake. Wired ONLY
/// into `routes::signup::build_state_from_env()`; the dev/test path
/// (`build_state_with_key`) keeps `InMemorySignupStore`. See module docs.
pub mod signup_d1_http;
/// Constant-memory SLI sink for the deployed CAS + AC handlers (B-057).
///
/// Replaces the capture-everything `InMemorySliObserver` the storage
/// builders used to wire, which retained every observation in a `Vec`
/// for the life of the container with no production reader.
pub mod sli_aggregate;
/// Native-container storage adapters (R2 S3-compatible API + D1 HTTP).
///
/// WP-S1 Phase 1 — provides [`storage::r2_s3::R2CasHandler`] (real
/// CAS read/write against Cloudflare R2 via `aws-sdk-s3`) and
/// [`storage::d1_http::D1HttpClient`] (metadata reads via the CF D1
/// HTTP API). Runtime selection: when `R2_S3_ACCESS_KEY_ID` etc. are
/// present the real adapters are used; otherwise the InMemory fakes
/// remain active for tests + local dev.
pub mod storage;
/// Generated types for the staging transport diagnostic protocol.
///
/// `prost` emits these public items without Rust documentation; keep the
/// exception scoped to this generated module.
#[allow(missing_docs)]
pub mod staging_transport_probe {
    tonic::include_proto!("corelink.staging.v1");
}
/// Per-tenant monthly $-ceiling middleware (WP-FOUND-2 / G1, ADR-0068):
/// a fail-CLOSED cumulative-dollar cap, orthogonal to the existing
/// per-tenant rate limit. Backed by the `tenant_quota` D1 table
/// (migration 0066).
pub mod tenant_quota;
/// In-process **display** usage aggregator (BE-1 reads/writes/daily + BE-2 cache
/// hit-rate / $-saved) feeding the `usage_daily` D1 table (migration 0089).
/// `record` is a cheap in-memory increment (no hot-path D1 write); a background
/// task flushes additive deltas every ~30s. DISPLAY telemetry, never billing.
pub mod usage_meter;
pub mod wall_clock;
pub mod webhook;
pub mod webhook_dlq_d1;
/// Durable D1 persistence for restart-safe Stripe webhook ownership.
pub mod webhook_inbox_d1;
