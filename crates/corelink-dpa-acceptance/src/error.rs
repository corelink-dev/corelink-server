//! Error taxonomy for the DPA acceptance service.

use thiserror::Error;

/// All recoverable + non-recoverable errors surfaced by this crate.
///
/// `#[non_exhaustive]` so downstream wirings can match without breaking
/// on additive variants.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum DpaAcceptanceError {
    /// The server-provisioned IP-hash salt is absent, all zeroes, or not
    /// exactly 32 bytes.
    #[error("invalid IP-hash salt: expected a non-zero 32-byte secret")]
    InvalidIpHashSalt,

    /// Locale mismatch — `corelink_locale` cookie vs payload locale
    /// differ. Returns HTTP 400 at the wiring layer and emits
    /// `dpa.locale_mismatch` audit. Lote 10.16 canonical enforcement
    /// (CTRL-PRIV-CONSENT-005).
    #[error(
        "locale mismatch: server-resolved={server} payload={payload} (Lote 10.16; \
         CTRL-PRIV-CONSENT-005)"
    )]
    LocaleMismatch {
        /// Server-resolved locale (`corelink_locale` cookie).
        server: &'static str,
        /// Payload-claimed locale.
        payload: &'static str,
    },

    /// `notice_text_hash` supplied by the client does not match the
    /// server-side recompute over the locale-resolved notice text.
    /// CTRL-PRIV-CONSENT-001 enforcement.
    #[error("notice_text_hash mismatch: expected={expected} got={got}")]
    NoticeHashMismatch {
        /// Hex64 SHA-256 of the canonical notice text for the locale.
        expected: String,
        /// Hex64 SHA-256 the client supplied.
        got: String,
    },

    /// Notice text for the requested locale is not registered. Indicates
    /// a deployment configuration error (locale enum entry without a
    /// corresponding `legal/dpa/v*.<locale>.md` artefact).
    #[error("notice text not registered for locale {locale}")]
    NoticeTextNotRegistered {
        /// Locale missing from the registry.
        locale: &'static str,
    },

    /// The same `signup_id` was reused with a conflicting payload.
    /// Idempotent retries with an **identical** payload return the
    /// original receipt; conflicting retries surface this error so the
    /// caller can investigate (PAT-RETRY-IDEMPOTENT-001).
    #[error("idempotency conflict: signup_id reused with diverging payload")]
    IdempotencyConflict,

    /// RS256 JWT signing failed (key parse or signature error).
    #[error("jwt signing failed: {0}")]
    JwtSign(String),

    /// RS256 JWT verification failed (signature mismatch, malformed
    /// header, or expired). Used by the verify path.
    #[error("jwt verify failed: {0}")]
    JwtVerify(String),

    /// Backing store error (D1 in production). Surfaces fail-CLOSED
    /// at the orchestrator.
    #[error("store error: {0}")]
    Store(String),

    /// Audit emit failure — fail-CLOSED before state mutation per
    /// INV-AUDIT-APPEND-ONLY.
    #[error("audit emit failure: {0}")]
    AuditEmit(String),

    /// Notification sink failure (transactional email pipeline). Does
    /// not roll back the acceptance — the receipt is still returned
    /// inline.
    #[error("notification send failure: {0}")]
    Notify(String),
}
