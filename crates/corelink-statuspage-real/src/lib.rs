//! `corelink-statuspage-real` — Atlassian Statuspage real client
//! (wave-16; closes WI-S11-002 §6 status-page deferral from
//! `specs/_audits/sealed/2026-05-15-dsr-worker-production.md` §5).
//!
//! # Purpose
//!
//! WI-S11-002 §6 mandates publication of aggregated DSR completion
//! stats to the public status page. This crate is the canonical wiring
//! that publishes the rolling 24h DSR completion summary (count of
//! `VerifiedComplete`, count of `VerifiedPartial`, p95 resolution-hours
//! observation, count of `SlaBreached`) to the Atlassian Statuspage
//! Public Metrics API.
//!
//! # Wire surface
//!
//! - [`StatuspageBackend`] — canonical trait every implementation
//!   satisfies (real HTTP + in-memory fake).
//! - [`DsrCompletionReport`] — 24h-rolling DSR completion stats payload.
//! - [`StatuspageHttpClient`] — real wiring (reqwest blocking,
//!   `POST /v1/pages/{page_id}/metrics/{metric_id}/data.json`).
//! - [`InMemoryStatuspageBackend`] — fake for unit tests / orchestration
//!   plumbing tests downstream.
//! - [`StatuspageRateLimiter`] — 1 publish per 5 min per metric_id
//!   (per Atlassian Statuspage public-API quota policy).
//! - [`StatuspageAuditSink`] / [`StatuspageAuditEvent`] —
//!   audit-emit-BEFORE-result, fail-CLOSED (INV-AUDIT-EMIT-ATOMIC).
//! - [`RetryPolicy`] — 3 retries exponential backoff on 5xx + 429;
//!   4xx (other than 429) is fatal (give-up immediately).
//! - [`redact_api_key`] — credential redaction
//!   (`OAuth abcd…1234` → `OAuth ***1234`).
//!
//! # Privacy / safety
//!
//! - The full `STATUSPAGE_API_KEY` is NEVER logged. The audit envelope
//!   carries only [`redact_api_key`] output.
//! - The published payload contains aggregate counts + a single p95
//!   observation; no per-tenant or per-subject PII is emitted
//!   (CTRL-PRIV-002 — DSR completion telemetry is aggregate-only).
//! - Rate-limited fail-CLOSED: a publish denied by the limiter emits
//!   `corelink.privacy.statuspage_rate_limited.v1` BEFORE returning the
//!   error (so the audit chain proves the limiter fired).
//!
//! # Runtime
//!
//! Production wiring uses `reqwest::blocking`. No `tokio` dependency in
//! `src/`. `wiremock` is dev-only.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod audit;
pub mod backend;
pub mod dsr_bridge;
// `http.rs` (wave-16 reqwest::blocking client) is native-only: reqwest's
// blocking flavour does not link against wasm32-unknown-unknown. The
// wasm32 target uses `wasm32_backend.rs` (wave-18 follow-on) which wires
// `worker::Fetch` instead.
#[cfg(not(target_arch = "wasm32"))]
pub mod http;
pub mod memory;
pub mod rate_limit;
pub mod redact;
pub mod report;
pub mod retry;
/// wave-18 wasm32 real backend — `worker::Fetch`-driven Statuspage
/// Public-Metric publisher. Mirrors the wave-16 native `StatuspageHttpClient`
/// semantics (auth header, redaction, rate-limit gate, retry policy, audit
/// emit fail-CLOSED) but uses the async CF Workers Fetch API so the
/// `#[event(scheduled)]` cron handler in `corelink-clerk-cf::dsr_statuspage_cron`
/// can actually publish on the wasm32 target. The trait surface
/// (`StatuspageBackend`) is sync; the wasm32 backend therefore exposes an
/// async `publish_dsr_metric_async` method (the trait cannot be implemented
/// directly without a sync→async bridge that workers-rs does not provide).
#[cfg(target_arch = "wasm32")]
pub mod wasm32_backend;

pub use audit::{
    InMemoryStatuspageAuditSink, StatuspageAuditError, StatuspageAuditEvent,
    StatuspageAuditOutcome, StatuspageAuditSink,
};
pub use backend::{PublishOutcome, StatuspageBackend, StatuspageClientError};
pub use dsr_bridge::bridge_to_report;
#[cfg(not(target_arch = "wasm32"))]
pub use http::StatuspageHttpClient;
pub use memory::{InMemoryStatuspageBackend, RecordedPublish};
pub use rate_limit::{RateLimitDecision, StatuspageRateLimiter};
pub use redact::redact_api_key;
pub use report::{DsrCompletionReport, DsrCompletionReportError};
pub use retry::{RetryDecision, RetryPolicy};
#[cfg(target_arch = "wasm32")]
pub use wasm32_backend::{StatuspageWasm32Client, Wasm32BackendError};
