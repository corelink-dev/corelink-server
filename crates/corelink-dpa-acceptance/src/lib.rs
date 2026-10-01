//! `corelink-dpa-acceptance` — DPA click-through 6-field consent capture
//! + RS256 JWT receipt + 3 locales (WI-S19-002, S-19 Onboarding,
//!   HIGH_RISK lane).
//!
//! # What this crate ships
//!
//! Per the `trait-abstraction-defer` charter, this crate ships the
//! **pure-logic skeleton** of the DPA acceptance endpoint
//! (`POST /v1/dpa/accept`) with full coverage of the load-bearing
//! invariants:
//!
//! - 6-field [`schema::ConsentProofPayload`] (CTRL-PRIV-CONSENT-001..006
//!   reflection) matching `specs/03_architecture/canonical/privacy_model.md`.
//! - 3-locale closed enum [`schema::LocaleBcp47`] (`en-US`, `pt-BR`,
//!   `es-419`) with content-addressable notice text hash registry.
//! - Locale mismatch enforcement (Lote 10.16 canonical: `corelink_locale`
//!   cookie ≠ payload locale → reject 400 + audit
//!   `dpa.locale_mismatch`).
//! - Idempotency per `signup_id` (replay-safe; matching payload returns
//!   the original receipt; conflicting payload errors).
//! - RS256-signed JWT receipt with claims
//!   `{tenant_id, dpa_version, accepted_at, jurisdiction, jti}` (per
//!   `data_model.md §4.1` — separate signing key family from PAT format
//!   S-03 hybrid HMAC + Argon2id).
//! - Notification path stub (`NotificationSink` trait) for the existing
//!   transactional email pipeline; in-memory fake captures sends for
//!   tests.
//! - `accepted_ip_hash` = `sha256(ip || salt)` server-side hashing per
//!   CTRL-PRIV-001 (zero raw IPs persisted).
//!
//! # Invariants enforced
//!
//! - **CTRL-PRIV-CONSENT-001..006** — reflected verbatim in the
//!   [`schema::ConsentProofPayload`] field layout; pinned by
//!   `integration_acceptance_flow`.
//! - **CTRL-PRIV-CONSENT-005** (locale match) — enforced in
//!   [`locale::enforce_locale_match`]; pinned by `prop_locale_mismatch`.
//! - **INV-CONSENT-PROOF-VERIFIABLE** (CRITICAL, §3.12) — RS256
//!   signature roundtrip integrity via [`jwt::verify_receipt`]; pinned
//!   by `prop_jwt_signature`.
//! - **PAT-RETRY-IDEMPOTENT-001** — idempotent per `signup_id` 5-tuple;
//!   pinned by `prop_idempotency`.
//!
//! # Modules
//!
//! 1. [`schema`] — types: [`schema::ConsentProofPayload`],
//!    [`schema::LocaleBcp47`], [`schema::DpaAcceptanceRequest`],
//!    [`schema::DpaAcceptanceReceipt`], [`schema::TenantCtx`].
//! 2. [`locale`] — locale match enforcement +
//!    content-addressable notice registry per locale.
//! 3. [`jwt`] — RS256 JWT receipt signing + offline verify with
//!    deterministic claim ordering.
//! 4. [`store`] — [`store::DpaAcceptanceStore`] trait +
//!    in-memory implementation (D1 mirror surface; production wiring at
//!    PRR ship gate).
//! 5. [`audit`] — audit event sink trait + canonical event names.
//! 6. [`notify`] — notification sink trait (transactional email stub).
//! 7. [`service`] — [`service::DpaAcceptanceService`] orchestrator
//!    (locale match → idempotency lookup → hash + IP hashing → JWT
//!    sign → store → audit → notify).
//! 8. [`error`] — [`error::DpaAcceptanceError`] `#[non_exhaustive]`
//!    taxonomy.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![allow(clippy::format_in_format_args, clippy::uninlined_format_args)]

pub mod audit;
pub mod error;
pub mod ip_hash_salt;
pub mod jwt;
pub mod locale;
pub mod notify;
pub mod schema;
pub mod service;
pub mod store;

pub use audit::{
    canonical_dpa_audit_event_names, DpaAuditEvent, DpaAuditSink, InMemoryDpaAuditSink,
};
pub use error::DpaAcceptanceError;
pub use ip_hash_salt::IpHashSalt;
pub use jwt::{sign_receipt, verify_receipt, JwtReceiptClaims, RsaPrivateKeyPem, RsaPublicKeyPem};
pub use locale::{enforce_locale_match, notice_text_hash, LocaleNoticeRegistry};
pub use notify::{InMemoryNotificationSink, NotificationEnvelope, NotificationSink};
pub use schema::{
    ConsentProofPayload, DpaAcceptanceReceipt, DpaAcceptanceRequest, Jurisdiction, LocaleBcp47,
    SignupId, TenantCtx, TenantId,
};
pub use service::DpaAcceptanceService;
pub use store::{DpaAcceptanceRecord, DpaAcceptanceStore, InMemoryDpaAcceptanceStore};

/// Crate schema version. Mirrors the D1 migration slot
/// (`migrations/d1/0038_dpa_acceptances.sql`).
#[must_use]
pub const fn dpa_schema_version() -> u32 {
    1
}
