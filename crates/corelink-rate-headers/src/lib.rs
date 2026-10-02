//! `corelink-rate-headers` — RFC 9331 rate-limit headers + 5-arm
//! response-code taxonomy + 3-state global circuit-breaker
//! (WI-S08-005).
//!
//! # What this crate ships
//!
//! Per the corelink autonomous execution charter
//! (`trait-abstraction-defer`), this crate ships the **canonical
//! pure-logic skeleton** of camada-0 of the 4-layer rate-limit bulkhead
//! PAT-RATE-LIMIT-001 + the system-wide RFC 9331 IETF stable header
//! plane (CAP-RATE-004 implementation):
//!
//! 1. The canonical SQL artifact
//!    `migrations/d1/0014_global_circuit_state.sql` embedded via
//!    [`MIGRATION_0014_GLOBAL_CIRCUIT_STATE`] so production code can
//!    pass the DDL to `wrangler d1 migrations apply` without re-reading
//!    from disk. Schema mirrors the per-region durable state machine +
//!    append-only trips_history ring; cold-start recovery reloads from
//!    these rows.
//! 2. The [`headers`] module ships [`headers::RateLimitHeaderBuilder`]
//!    composing canonical RFC 9331 `RateLimit: limit=N, remaining=M,
//!    reset=S` + `RateLimit-Policy: <limit>;w=<window>` headers (IETF
//!    stable; supersedes legacy custom `X-RateLimit-*` per sprint
//!    contract §14.s08.5) + [`headers::XRateLimitTypeKind`]
//!    `#[non_exhaustive]` 5-arm enum mapping the per-camada
//!    response-code taxonomy (`tenant_quota` / `per_ip` / `per_pat` /
//!    `over_quota` / `global_circuit_open` per sprint contract §5
//!    R-S08-8) + [`headers::RateLimitHeaders`] typed payload + Retry-
//!    After clamping (RFC 6585 §4 always present; ≤ 30d hard ceiling).
//! 3. The [`circuit`] module ships [`circuit::GlobalCircuitBreaker`]
//!    trait + [`circuit::InMemoryGlobalCircuitBreaker`] orchestrator
//!    with canonical 3-state lifecycle (Closed / Open / HalfOpen) +
//!    [`circuit::evaluate_signals`] multi-signal trip evaluator
//!    (5xx-rate AND p99-latency AND DO-error-rate; ≥ 2 signals required
//!    per sprint contract §15 R-S08-004 + canonical Netflix Hystrix /
//!    Resilience4j absorption; single-signal is investigation-only,
//!    NOT a trip) + hysteresis recovery (90% threshold dwell 2min Open
//!    → HalfOpen; 50% + ≥ 90% sample success Closed; immediate revert
//!    on signal re-trip) + [`circuit::allow_halfopen_request`] 10%
//!    deterministic sampler (no thundering herd) +
//!    [`circuit::ManualOverrideTarget`] admin S-13 escape hatch.
//! 4. The [`audit`] module ships [`audit::CircuitEventType`]
//!    (`#[non_exhaustive]` 5-event taxonomy:
//!    `corelink.circuit.{tripped, half_open_probe, closed_recovery,
//!    request_rejected, manual_override}`) +
//!    [`audit::CircuitAuditSink`] + [`audit::InMemoryCircuitAuditSink`]
//!    + fail-closed envelope per `INV-AUDIT-EMIT-ATOMIC-WITH-HANDLER`.
//! 5. The [`metrics`] module ships [`metrics::CircuitMetricsObserver`]
//!    + [`metrics::InMemoryCircuitMetrics`] + canonical 9-metric ladder
//!    (`corelink.{rate_limited_within_quota_total,
//!    rate_limited_over_quota_total, global_circuit.state,
//!    global_circuit.trips_total, global_circuit.recoveries_total,
//!    global_circuit.single_signal_alarm_total,
//!    global_circuit.half_open_duration_ms,
//!    global_circuit.manual_override_total,
//!    rate_limit_headers.rfc9331_compliance_total}`).
//! 6. The [`error`] module ships [`error::CircuitError`]
//!    `#[non_exhaustive]`. `AdminAuthFailed` is the AdminCtx S-13
//!    bypass canary — programmatic manual-override attempts without a
//!    valid admin id ALWAYS hit this arm.
//!
//! # Why RFC 9331 IETF stable canonical
//!
//! Per sprint contract §14.s08.5: legacy custom `X-RateLimit-*`
//! vendor-specific headers vary across vendors (Bazel / Buck2 / Stripe
//! / GitHub) so customer SDKs cannot reliably consume them without
//! per-vendor adaptation. RFC 9331 IETF stable `RateLimit` +
//! `RateLimit-Policy` is the canonical format these SDKs already
//! consume; adopting it = customer SDK works without per-vendor
//! adaptation.
//!
//! # SLI distinction CRITICAL
//!
//! Per sprint contract §7.10.s08.1, the SLO-AVAIL-CAS-GET denominator
//! must exclude legitimate over-plan responses (`per_ip` / `per_pat` /
//! `over_quota`) from the SLI numerator + denominator entirely. Without
//! this, error budget exhausts in legitimate over-quota scenarios +
//! obscures real failures. The
//! [`headers::XRateLimitTypeKind::counts_against_sli`] predicate carries
//! this distinction; the `record_within_quota` vs `record_over_quota`
//! metric API surface enforces the separation at the dashboard layer.
//!
//! Per Lote 10.8bis P1-3 R5 fix, the `GlobalCircuitOpen` arm carries an
//! optional `is_manual_override: bool` flag — planned admin drills
//! (S-13 force-open) are NOT system overload bugs and so are EXCLUDED
//! from the SLI denominator.
//!
//! # Multi-signal canonical (NOT single-signal)
//!
//! Per sprint contract §15 R-S08-004 + canonical Netflix Hystrix /
//! Resilience4j absorption: single-signal trip is a false-positive
//! vulnerability (e.g. an S-09 metrics endpoint blip causing 5xx for
//! ALL request types simultaneously). Trip requires **≥ 2 of 3 signals
//! concurrently breached**:
//!
//! - **Signal A**: `error_5xx_rate > 0.5` over the rolling window.
//! - **Signal B**: `p99_latency_us > 5×SLO_threshold_us`.
//! - **Signal C**: `do_error_rate > 0.3` (per-DO actor failure rate).
//!
//! Per Lote 10.8bis P1-2 R5 fix, `do_error_rate` is sourced from the
//! **most-recent** observation (NOT averaged across the rolling window
//! which produces moving-average-of-moving-average smoothing biased
//! toward LATE detection).
//!
//! # Composition with WI-S08-001/002/003/004 (camadas 1-4)
//!
//! The 4-layer bulkhead PAT-RATE-LIMIT-001 composes camada-0 (THIS WI)
//! IN FRONT of camadas 1-3:
//!
//! 0. **Camada 0 — THIS crate `GlobalCircuitBreaker`** (WI-S08-005):
//!    system-wide last-resort defense; trip → 429 GlobalCircuitOpen
//!    ALL requests. Multi-signal canonical; hysteresis no-flapping;
//!    HalfOpen 10% sample no-thundering-herd.
//! 1. **Camada 2 — `corelink-edge::EdgePolicy`** (WI-S08-002): pre-auth
//!    IP / CIDR blocklist; consulted SECOND; zero-cost adversarial drop.
//! 2. **Camada 1 — `corelink-ratelimit::RateLimiter`** (WI-S08-001):
//!    per-tenant + per-IP token bucket; consulted THIRD; aggregate
//!    enforcement.
//! 3. **Camada 3 — `corelink-quota-cas::AtomicQuotaChecker`**
//!    (WI-S08-003): per-tenant storage hard-block via atomic CAS at
//!    100% boundary; consulted FOURTH; canonical days-until-month-reset
//!    Retry-After per ADR-0020 FROZEN.
//! 4. **Camada 4 — `corelink-abuse::AbuseScorer`** (WI-S08-004):
//!    heuristic 4-feature weighted-sum scoring; consulted FIFTH
//!    (proactive layer).
//!
//! Production wiring at WI-S08-006 composes the five in this canonical
//! order. The Tower middleware response wrapper at the worker boundary
//! consumes [`headers::RateLimitHeaderBuilder`] to render the canonical
//! RFC 9331 + Retry-After + X-Rate-Limit-Type header set on every 429
//! emitted by ANY of the 5 camadas.
//!
//! # Cripto-driven invariants enforced
//!
//! - **INV-AVAIL-ISOLATION** (HIGH; spec_contract §8 +
//!   invariant_registry §3.8): camada-0 last-resort defense per-region;
//!   cross-region cascade requires ≥ 2 regions tripped (rare; deferred
//!   S-14 federation per sprint contract §10 anti-scope).
//! - **INV-AUDIT-APPEND-ONLY** (CRITICAL, TLA+): every state transition
//!   audited BEFORE state mutation; pinned by
//!   `prop_audit_emit_per_decision_arm` +
//!   `audit_failure_aborts_check_decision`.
//! - **INV-TENANT-ISOLATION** (CRITICAL, TLA+): circuit state itself
//!   is system-wide tenant-agnostic; the RFC 9331 headers it composes
//!   ARE per-tenant scoped (sprint contract §7.10.s08.4).
//! - **Multi-signal trip canonical**: ≥ 2 of 3 signals required; pinned
//!   by `prop_multi_signal_trigger_no_single_signal_trip`.
//! - **Hysteresis no-flapping**: 2min dwell + 90/50% recovery ratios;
//!   pinned by `prop_hysteresis_no_flapping`.
//! - **HalfOpen 10% deterministic sample**: pinned by
//!   `prop_halfopen_sample_deterministic`.
//! - **5-arm taxonomy canonical**: pinned by
//!   `prop_x_rate_limit_type_5_canonical_arms`.
//! - **RFC 9331 format**: pinned by `prop_rfc9331_format_canonical`.
//! - **Remaining ≤ limit invariant**: pinned by
//!   `prop_rate_limit_remaining_consistent_with_bucket_state`.
//! - **SLI distinction canonical**: pinned by
//!   `prop_sli_distinction_canonical_5_arm`.
//!
//! # Customer-facing 429 UX (audit 2026-05-15)
//!
//! The audit `specs/_audits/sealed/2026-05-15-ratelimit-ux-audit.md` closed
//! the 429 customer-UX gap; this crate now additionally ships:
//!
//! - Three CoreLink-vendor informational headers alongside the
//!   IETF RFC 9331 canonical pair: `X-CoreLink-Tier`,
//!   `X-CoreLink-Quota-Reset-UTC`, `X-CoreLink-Tier-Upgrade-URL`
//!   (frozen [`headers::TIER_UPGRADE_URL`]). Composed via
//!   [`headers::RateLimitHeaderBuilder::build_with_vendor`]; the legacy
//!   [`headers::RateLimitHeaderBuilder::build`] entrypoint defaults the
//!   vendor fields to empty strings + the frozen upgrade URL.
//! - The canonical 429 JSON body schema
//!   [`headers::RateLimitErrorBody`] with frozen `error.code` =
//!   [`headers::ERROR_CODE_RATE_LIMIT_EXCEEDED`] + every header field
//!   mirrored byte-for-byte (pinned by
//!   `prop_rate_limit_body_always_consistent_with_headers` at 10k
//!   iterations PR-gate; 100k nightly).
//! - The canonical customer-facing docs URL
//!   [`headers::DOCS_URL`] = `https://corelink-docs.humangr.com/explanation/rate-limits`
//!   (matches `apps/docs/docs/explanation/rate-limits.mdx`).
//!
//! Customer SDKs pattern-match on `error.kind` (5-arm taxonomy) +
//! honour `error.retry_after_seconds` (mirrors `Retry-After`) + click
//! through `error.tier_upgrade_url`. Long deferred retries use
//! `error.reset_utc` (RFC 3339, robust against clock skew) over
//! `error.reset_seconds`. See
//! `apps/docs/docs/explanation/rate-limits.mdx` for the customer
//! narrative + `marketing/sales/RATE-LIMIT-FAQ.md` for the sales-facing
//! 9-question subset.
//!
//! # Forbidden surface
//!
//! - **No `unsafe`** anywhere in the crate.
//! - **No `unwrap` / `expect` / `panic` / direct `[i]` indexing** in
//!   library code (all crate-strict clippy lints are `deny`).
//! - **No `tokio`** in `src/` (wasm32-clean lib code; tokio only in
//!   tests if needed).
//! - **No process-global `static LazyLock<Mutex<>>`** — F-001 closure
//!   preserved via per-instance `Arc<Mutex<CircuitInner>>`.
//!
//! # Trait-abstraction-defer
//!
//! Real CF DO singleton `GlobalRateLimiter-<region>`, real D1 atomic
//! batch, Tower-layer production wiring (gated
//! `corelink-worker/tower-middleware`), 100k nightly proptest sustained
//! 7d, chaos 12, customer self-service endpoints (S-13 dependency),
//! admin endpoints, RFC 9331 3rd-party fixture parser (BuildBuddy /
//! Bazel SDK), and `POST /v1/admin/global_circuit/override` admin
//! endpoint — all consolidated alongside WI-S08-006 PRR ship gate.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    reason = "module-level docs use deep nested numbered/bulleted lists; \
              clippy's auto-detection is over-aggressive on the canonical \
              5-camada bulkhead prose"
)]

/// Embedded canonical migration SQL (D1 Cloudflare SQLite) for the
/// global circuit state plane (WI-S08-005; per-region durable state +
/// append-only trips_history; companion DASH-RATE widget deferred
/// WI-S08-006 PRR ship gate).
///
/// The exact bytes ship to production via `scripts/migrate_d1.sh` /
/// `wrangler d1 migrations apply`. The simulator does not parse this
/// string; the algorithmic invariants are re-implemented directly so
/// test failures are easy to triage.
pub const MIGRATION_0014_GLOBAL_CIRCUIT_STATE: &str =
    include_str!("../../../migrations/d1/0014_global_circuit_state.sql");

pub mod audit;
pub mod circuit;
pub mod error;
pub mod headers;
pub mod metrics;

pub use audit::{
    canonical_audit_event_strings, CircuitAuditRecord, CircuitAuditSink, CircuitAuditSinkError,
    CircuitEventType, FailingCircuitAuditSink, InMemoryCircuitAuditSink,
};
pub use circuit::{
    allow_halfopen_request, evaluate_signals, CircuitDecision, CircuitState, CircuitStateSnapshot,
    CircuitThresholds, GlobalCircuitBreaker, HealthObservation, InMemoryGlobalCircuitBreaker,
    ManualOverrideTarget, ObservationStatus, SignalEvaluation, TripReason, HALFOPEN_DWELL_MS,
    HALFOPEN_SAMPLE_PCT, OBSERVATION_BUFFER_CAP, RECOVERY_RATIO_HALFOPEN_TO_CLOSED,
    RECOVERY_RATIO_OPEN_TO_HALFOPEN, RECOVERY_SAMPLE_SUCCESS_FLOOR, ROLLING_WINDOW_MS,
};
pub use error::CircuitError;
pub use headers::{
    canonical_kind_list, RateLimitErrorBody, RateLimitHeaderBuilder, RateLimitHeaders,
    RateLimitPolicy, XRateLimitTypeKind, DOCS_URL, ERROR_CODE_RATE_LIMIT_EXCEEDED,
    GLOBAL_CIRCUIT_RETRY_AFTER_SECS, PER_IP_RETRY_AFTER_SECS, RETRY_AFTER_HARD_CEILING_SECS,
    TIER_UPGRADE_URL,
};
pub use metrics::{
    canonical_metric_names, CircuitMetricKind, CircuitMetricsObserver, CircuitMetricsObserverError,
    FailingCircuitMetrics, InMemoryCircuitMetrics,
};

/// Returns the canonical schema version recorded by the latest
/// migration in the global-circuit D1 domain.
///
/// Version is sequential within the D1 domain (`blob_meta` = 1,
/// `ac_meta` = 2, …, `quota_reservations` = 9, `ratelimit_buckets` = 10,
/// `edge_blocklist` = 11, `quota_cas_attempts` = 12,
/// `abuse_score_history` = 13,
/// **`global_circuit_state` + `global_circuit_trips_history` = 14**).
#[must_use]
pub const fn rate_headers_schema_version() -> u32 {
    14
}
