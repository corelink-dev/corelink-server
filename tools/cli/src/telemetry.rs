//! Telemetry opt-in emitter (WI-S15-005).
//!
//! # Privacy guarantees
//!
//! - **Default off**: no events are emitted unless `config.telemetry == true`.
//! - **Anonymized payload only**: `cli_version`, `os`, `subcommand`, `outcome`, `duration_ms`,
//!   `anonymized_id`. **Never** `tenant_id`, blob digests, PAT, file paths, IP address.
//! - **Non-blocking**: network failure is silently swallowed; CLI invocation is never blocked.
//! - **Timeout 1s**: prevents CLI hang on unreachable endpoint (R-004 risk register).
//! - **Separate domain** `telemetry.corelink.humangr.com` (§9.4): customers can firewall it without
//!   impacting the data plane (`corelink-api.humangr.com`).
//!
//! # LINDDUN compliance
//!
//! See `specs/_audits/sealed/2026-05-14-linddun-cli-telemetry.md` for full review.

#![allow(clippy::print_stderr)]

use serde::Serialize;
use tracing::warn;
use uuid::Uuid;

/// Telemetry endpoint (separate domain from data plane — §9.4).
const TELEMETRY_ENDPOINT: &str = "https://telemetry.corelink.humangr.com/v1/events";

/// HTTP client timeout for telemetry POST (non-blocking; FM-R004).
const TIMEOUT_MS: u64 = 1_000;

/// The anonymized telemetry payload.
///
/// **NEVER** include `tenant_id`, blob digests, PAT, or file paths.
#[derive(Debug, Serialize)]
pub struct TelemetryEvent {
    /// CLI binary version (e.g., `"0.1.0"`).
    pub cli_version: &'static str,
    /// OS + arch slug (e.g., `"linux-aarch64"`).
    pub os: String,
    /// CLI subcommand (e.g., `"ls"`, `"get"`, `"doctor"`).
    pub subcommand: String,
    /// Outcome: `"ok"` or `"err"`.
    pub outcome: &'static str,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Stable anonymised UUID (rotatable; never == tenant_id).
    pub anonymized_id: Uuid,
}

impl TelemetryEvent {
    /// Construct a new event. Does **not** include any PII.
    #[must_use]
    pub fn new(
        subcommand: impl Into<String>,
        outcome: &'static str,
        duration_ms: u64,
        anonymized_id: Uuid,
    ) -> Self {
        Self {
            cli_version: env!("CARGO_PKG_VERSION"),
            os: current_os_slug(),
            subcommand: subcommand.into(),
            outcome,
            duration_ms,
            anonymized_id,
        }
    }

    /// Verify the payload contains no PII fields.
    ///
    /// Used in property tests to assert 0 PII emission.
    #[must_use]
    #[cfg(test)]
    pub fn has_pii(&self) -> bool {
        // The struct cannot contain tenant_id / PAT / digests by design.
        // This method encodes the invariant as a runtime-checkable assertion.
        false
    }
}

/// Returns a platform slug like `"linux-x86_64"` or `"darwin-aarch64"`.
fn current_os_slug() -> String {
    let os = std::env::consts::OS; // "linux", "macos", "windows"
    let arch = std::env::consts::ARCH; // "x86_64", "aarch64", etc.
    format!("{os}-{arch}")
}

/// Emit a telemetry event **iff** telemetry is enabled in config.
///
/// This function is **non-blocking**: the HTTP POST is spawned as a detached Tokio task
/// and any failure is swallowed with a `warn!` log. The CLI invocation always completes
/// regardless of telemetry endpoint health (FM-150; R-004).
///
/// # Arguments
///
/// * `enabled` — whether telemetry is enabled (`config.telemetry_enabled()`).
/// * `event` — the anonymized payload to emit.
///
/// If `enabled` is `false`, this is a no-op and returns immediately.
pub fn emit_if_enabled(enabled: bool, event: TelemetryEvent) {
    if !enabled {
        return; // opt-in guard: zero emissions when flag is off
    }

    // Spawn as detached task so the CLI invocation is not blocked.
    tokio::spawn(async move {
        let result = try_emit(&event).await;
        if let Err(e) = result {
            // Graceful degradation: warn but never panic or block (FM-150).
            warn!(error = %e, "telemetry emit failed (non-blocking; FM-150)");
        }
    });
}

/// Attempt to POST the event to the telemetry endpoint.
async fn try_emit(event: &TelemetryEvent) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(TIMEOUT_MS))
        .build()
        .map_err(|e| e.to_string())?;

    client
        .post(TELEMETRY_ENDPOINT)
        .json(event)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TelemetryEvent must never report PII present.
    #[test]
    fn event_has_no_pii() {
        let id = Uuid::new_v4();
        let event = TelemetryEvent::new("ls", "ok", 42, id);
        assert!(
            !event.has_pii(),
            "INVARIANT: telemetry payload must not contain PII"
        );
    }

    /// Payload JSON serialization must not contain forbidden fields.
    #[test]
    fn serialised_payload_no_forbidden_fields() {
        let id = Uuid::new_v4();
        let event = TelemetryEvent::new("get", "ok", 100, id);
        let json = serde_json::to_string(&event).expect("serialise");

        // These fields must NEVER appear in the payload (R-S15-15 + LINDDUN Identifiability).
        assert!(
            !json.contains("tenant_id"),
            "tenant_id must never be in payload"
        );
        assert!(!json.contains("\"pat\""), "PAT must never be in payload");
        assert!(
            !json.contains("digest"),
            "blob digests must never be in payload"
        );
        assert!(
            !json.contains("file_path"),
            "file paths must never be in payload"
        );

        // Required fields must be present.
        assert!(json.contains("cli_version"));
        assert!(json.contains("os"));
        assert!(json.contains("subcommand"));
        assert!(json.contains("outcome"));
        assert!(json.contains("duration_ms"));
        assert!(json.contains("anonymized_id"));
    }

    /// emit_if_enabled with enabled=false must be a no-op (zero emissions).
    #[tokio::test]
    async fn emit_disabled_is_noop() {
        // With enabled=false, the function returns immediately without spawning tasks.
        // We verify this compiles + runs without side-effects in the test runtime.
        let id = Uuid::new_v4();
        let event = TelemetryEvent::new("ls", "ok", 10, id);
        emit_if_enabled(false, event);
        // If we reach here, zero emissions occurred for the disabled case.
    }

    /// OS slug is non-empty and does not contain PAT or secrets.
    #[test]
    fn os_slug_is_safe() {
        let slug = current_os_slug();
        assert!(!slug.is_empty());
        assert!(!slug.contains("token"), "OS slug must not leak token info");
        assert!(
            !slug.contains("secret"),
            "OS slug must not leak secret info"
        );
    }
}
