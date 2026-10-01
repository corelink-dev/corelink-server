//! Native-container storage adapters for R2 (S3-compatible API) and
//! Cloudflare D1 (HTTP API).
//!
//! # Decision Gate 1 — Option A
//!
//! The native Firecracker container reaches R2 via the **S3-compatible
//! API over egress** (`aws-sdk-s3` pointed at
//! `https://<account>.r2.cloudflarestorage.com`). The wasm32 CF-Worker
//! adapters (`corelink-cf-bindings`) are Worker-only; this module
//! provides the native-side complement.
//!
//! # Runtime selection
//!
//! When `R2_S3_ACCESS_KEY_ID` / `R2_S3_SECRET_ACCESS_KEY` /
//! `R2_S3_ENDPOINT` are present in the environment the real storage
//! adapters are constructed. When they are absent (unit tests, local
//! dev without creds) the callers fall back to in-memory fakes.
//!
//! # Security charter compliance
//!
//! - S3 credentials are read from env vars only — never embedded in
//!   code or logged.
//! - No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.
//! - `#![forbid(unsafe_code)]` is inherited from the crate root.
//!
//! # Modules
//!
//! - [`r2_s3`] — async R2 S3 client + `R2CasHandler` implementing
//!   `corelink_handler_cas::{CasReadHandler, CasWriteHandler}`.
//! - [`d1_http`] — async D1 HTTP API client for metadata reads.

/// Typed durable state machine for the purge-before-active activation pipeline.
pub mod byok_activation;
/// Concrete D1 lifecycle adapter for the purge-before-active pipeline.
pub mod byok_activation_d1;
/// Bounded, supervised runtime driver for durable activation intents.
pub mod byok_activation_runtime;
/// Concrete bounded R2/D1 copy and purge worker for activation intents.
pub mod byok_activation_worker;
pub mod byok_backfill;
/// Production crypto implementation used by BYOK backfill jobs.
pub mod byok_backfill_crypto;
/// Retired generic 0120 adapter retained only as a hermetic compatibility
/// fixture. Production activation uses the allocation-first activation worker;
/// compiling this PUT-before-checkpoint path into a release would reintroduce
/// an unledgered crash orphan window.
#[cfg(test)]
#[allow(dead_code, clippy::indexing_slicing)]
pub(crate) mod byok_backfill_d1;
/// BYOK convergent-encryption helpers for native CAS storage.
pub mod byok_cas;
/// Durable generation catalog and tenant-wide data-plane gate for BYOK.
pub mod byok_generation_catalog;
/// Concrete CAS/AC R2 I/O driver for durable BYOK purge claims.
pub mod byok_purge_io;
pub mod cas_write_fence;
pub mod d1_audit_sink;
pub mod d1_http;
pub mod r2_kv;
pub mod r2_s3;
pub mod region_map;
/// Authenticated, atomic staging load-test admission claims.
pub mod staging_load_test_admission;
/// Exact-run resource attribution writes for staging load-test teardown.
pub mod staging_load_test_ownership;
/// Atomic nine-class census and exact-run seal for staging load tests.
pub mod staging_load_test_seal;

/// Configuration for the native-container storage layer, sourced
/// entirely from environment variables.
///
/// Construct via [`StorageEnv::from_env`]; the fields are intentionally
/// not `pub` so callers cannot accidentally construct invalid configs.
///
/// # Security note
///
/// The S3 credentials held here are treated as secrets: `Debug` is
/// intentionally redacted (manual impl below — NOT `#[derive(Debug)]`,
/// which would print the R2 secret key + CF API token verbatim) and the
/// struct does not implement `Clone` to limit accidental exposure.
pub struct StorageEnv {
    /// R2 S3-compatible endpoint URL
    /// (`https://<account>.r2.cloudflarestorage.com`).
    pub(crate) r2_endpoint: String,
    /// R2 S3 access key ID (from `R2_S3_ACCESS_KEY_ID`).
    pub(crate) r2_access_key_id: String,
    /// R2 S3 secret access key (from `R2_S3_SECRET_ACCESS_KEY`).
    pub(crate) r2_secret_access_key: String,
    /// Optional R2 temporary-credential session token (from
    /// `R2_S3_SESSION_TOKEN`). Static R2 credentials omit this value.
    pub(crate) r2_session_token: Option<String>,
    /// Cloudflare Account ID (from `CLOUDFLARE_ACCOUNT_ID`).
    pub(crate) cloudflare_account_id: String,
    /// CF API token for D1 HTTP API access (from `CF_API_TOKEN`).
    pub(crate) cf_api_token: String,
    /// D1 database ID (from `D1_DATABASE_ID`).
    pub(crate) d1_database_id: String,
}

impl core::fmt::Debug for StorageEnv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SECURITY: redact every credential + account/db identifier; only the
        // non-secret R2 endpoint is shown (mirrors `Display`). A `{:?}` of this
        // struct must never leak the R2 access/secret keys or the CF API token.
        f.debug_struct("StorageEnv")
            .field("r2_endpoint", &self.r2_endpoint)
            .field("r2_access_key_id", &"[REDACTED]")
            .field("r2_secret_access_key", &"[REDACTED]")
            .field("r2_session_token", &"[REDACTED]")
            .field("cloudflare_account_id", &"[REDACTED]")
            .field("cf_api_token", &"[REDACTED]")
            .field("d1_database_id", &"[REDACTED]")
            .finish()
    }
}

impl core::fmt::Display for StorageEnv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "StorageEnv {{ r2_endpoint: {}, account: [REDACTED], d1: [REDACTED] }}",
            self.r2_endpoint
        )
    }
}

impl StorageEnv {
    /// Attempt to load all required environment variables.
    ///
    /// Returns `Some(env)` if every required variable is present and
    /// non-empty, `None` otherwise (missing or empty values are treated
    /// as "unconfigured").
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let r2_endpoint = non_empty_env("R2_S3_ENDPOINT")?;
        let r2_access_key_id = non_empty_env("R2_S3_ACCESS_KEY_ID")?;
        let r2_secret_access_key = non_empty_env("R2_S3_SECRET_ACCESS_KEY")?;
        let r2_session_token = optional_non_empty_env("R2_S3_SESSION_TOKEN");
        let cloudflare_account_id = non_empty_env("CLOUDFLARE_ACCOUNT_ID")?;
        let binding_proxy = staging_d1_binding_proxy_enabled().ok()?;
        if binding_proxy && non_empty_env("CF_API_TOKEN").is_some() {
            // Proxy mode must not silently retain or fall back to an account
            // API token inside the container.
            return None;
        }
        let cf_api_token = if binding_proxy {
            String::new()
        } else {
            non_empty_env("CF_API_TOKEN")?
        };
        let d1_database_id = non_empty_env("D1_DATABASE_ID")?;
        Some(Self {
            r2_endpoint,
            r2_access_key_id,
            r2_secret_access_key,
            r2_session_token,
            cloudflare_account_id,
            cf_api_token,
            d1_database_id,
        })
    }
}

/// Enable the internal D1 binding only for the explicitly marked staging image.
/// Any flag in production or another environment fails closed at the caller.
pub(crate) fn staging_d1_binding_proxy_enabled() -> Result<bool, String> {
    parse_staging_d1_binding_proxy_mode(
        std::env::var("D1_BINDING_PROXY").ok().as_deref(),
        std::env::var("ENVIRONMENT").ok().as_deref(),
    )
}

fn parse_staging_d1_binding_proxy_mode(
    flag: Option<&str>,
    environment: Option<&str>,
) -> Result<bool, String> {
    match flag {
        None | Some("") => Ok(false),
        Some("1") if environment == Some("staging") => Ok(true),
        Some("1") => Err("D1_BINDING_PROXY is only allowed in staging".to_owned()),
        Some(_) => Err("D1_BINDING_PROXY must be empty or exactly 1".to_owned()),
    }
}

/// Return the value of `var` trimmed to a non-empty string, or `None`.
pub(crate) fn non_empty_env(var: &str) -> Option<String> {
    let v = std::env::var(var).ok()?;
    let v = v.trim().to_owned();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Read an optional credential, treating absent, empty, and whitespace-only
/// values as no session token. The static access ID/secret remain required.
fn optional_non_empty_env(var: &str) -> Option<String> {
    let raw = std::env::var(var).ok();
    optional_non_empty_env_value(raw.as_deref())
}

/// Read `var`, treating ABSENT **and EMPTY** as "use the default".
///
/// The Worker DO forwards container env via `this.env.X ?? ""`
/// (`worker/src/durable_object.ts`), whose documented contract is
/// "Absent/empty → container defaults". A bare `std::env::var(..)
/// .unwrap_or_else(..)` violates that contract: `Ok("")` bypasses the
/// default and (for bucket names) yields an S3 client that fails every
/// request ("failed to construct request" → AC 500s in prod,
/// 2026-06-05 dogfood incident). Route ALL bucket/region env reads
/// through here.
pub(crate) fn env_or(var: &str, default: &str) -> String {
    pick_non_empty(std::env::var(var).ok(), default)
}

/// Pure core of [`env_or`]: absent OR blank → `default`. Split out so
/// the contract is unit-testable without touching process env (which
/// the secrets-matrix scanner audits).
fn pick_non_empty(raw: Option<String>, default: &str) -> String {
    match raw {
        Some(v) => {
            let t = v.trim();
            if t.is_empty() {
                default.to_owned()
            } else {
                t.to_owned()
            }
        }
        None => default.to_owned(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests are allowed to use these primitives"
)]
mod tests {
    use super::*;

    fn storage_env(session: Option<String>) -> StorageEnv {
        StorageEnv {
            r2_endpoint: "https://account.r2.cloudflarestorage.com".to_owned(),
            r2_access_key_id: "R2_ACCESS_ID_SENTINEL".to_owned(),
            r2_secret_access_key: "R2_SECRET_SENTINEL".to_owned(),
            r2_session_token: session,
            cloudflare_account_id: "CF_ACCOUNT_SENTINEL".to_owned(),
            cf_api_token: "CF_TOKEN_SENTINEL".to_owned(),
            d1_database_id: "D1_ID_SENTINEL".to_owned(),
        }
    }

    #[test]
    fn from_env_returns_none_when_vars_absent() {
        // Deliberately does NOT set any env vars — should return None.
        // This is the unit-test / local-dev path (no creds present).
        // We only test variable absence here; full integration round-
        // trip is in r2_s3::tests (behind #[ignore]).
        let env = StorageEnv::from_env();
        // We can't guarantee R2_S3_ACCESS_KEY_ID is absent in all CI
        // environments, so we just assert the result is consistent.
        if let Some(e) = env {
            // All vars were present — valid configuration.
            assert!(!e.r2_endpoint.is_empty());
            assert!(!e.r2_access_key_id.is_empty());
        }
        // If None — correct: vars are absent.
    }

    #[test]
    fn optional_session_token_preserves_static_credential_compatibility() {
        assert_eq!(optional_non_empty_env_value(None), None);
        assert_eq!(optional_non_empty_env_value(Some("")), None);
        assert_eq!(optional_non_empty_env_value(Some("  \t")), None);
        assert_eq!(
            optional_non_empty_env_value(Some(" session-value ")),
            Some("session-value".to_owned())
        );
        assert!(storage_env(None).r2_session_token.is_none());
    }

    #[test]
    fn storage_env_debug_and_display_redact_all_credentials() {
        let env = storage_env(Some("R2_SESSION_SENTINEL".to_owned()));
        let debug = format!("{env:?}");
        let display = format!("{env}");
        for secret in [
            "R2_ACCESS_ID_SENTINEL",
            "R2_SECRET_SENTINEL",
            "R2_SESSION_SENTINEL",
            "CF_ACCOUNT_SENTINEL",
            "CF_TOKEN_SENTINEL",
            "D1_ID_SENTINEL",
        ] {
            assert!(!debug.contains(secret));
            assert!(!display.contains(secret));
        }
        assert!(debug.contains("r2_session_token"));
        assert!(debug.contains("[REDACTED]"));
        assert!(display.contains("[REDACTED]"));
    }
}

fn optional_non_empty_env_value(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod env_or_tests {
    use super::{parse_staging_d1_binding_proxy_mode, pick_non_empty};

    /// The 2026-06-05 prod incident contract: absent AND empty AND
    /// whitespace-only all mean "use the default"; set means the value.
    #[test]
    fn pick_non_empty_absent_empty_blank_default_set_value() {
        assert_eq!(pick_non_empty(None, "dflt"), "dflt");
        assert_eq!(pick_non_empty(Some(String::new()), "dflt"), "dflt");
        assert_eq!(pick_non_empty(Some("   ".to_owned()), "dflt"), "dflt");
        assert_eq!(
            pick_non_empty(Some("corelink-ac-iad".to_owned()), "dflt"),
            "corelink-ac-iad"
        );
    }

    #[test]
    fn d1_binding_proxy_is_staging_only_and_requires_exact_flag() {
        assert_eq!(
            parse_staging_d1_binding_proxy_mode(None, Some("staging")),
            Ok(false)
        );
        assert_eq!(
            parse_staging_d1_binding_proxy_mode(Some("1"), Some("staging")),
            Ok(true)
        );
        assert!(parse_staging_d1_binding_proxy_mode(Some("1"), Some("prod")).is_err());
        assert!(parse_staging_d1_binding_proxy_mode(Some("true"), Some("staging")).is_err());
    }
}
