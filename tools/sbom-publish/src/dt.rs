//! Dependency-Track ingestion client.
//!
//! Implements `POST /api/v1/bom` (multipart) with exponential-backoff retry
//! (1 s → 4 s → 16 s) and a fallback-queue sink when all retries are exhausted.
//!
//! # Retry policy
//!
//! | Attempt | Delay before |
//! |---------|-------------|
//! | 1 (first)  | 0 s |
//! | 2 (retry 1)| 1 s |
//! | 3 (retry 2)| 4 s |
//! | 4 (retry 3)| 16 s |
//!
//! After 4 total attempts (3 retries), the SBOM bytes are written to the
//! fallback queue (a local file path or CF KV blob) and an SEV-3 alert is
//! logged. The calling release pipeline **continues** — DT ingestion failure
//! is non-blocking by design (§9.7).
//!
//! # Authentication
//!
//! DT API key is read from the environment variable named by the caller (e.g.
//! `DT_API_KEY`). The key is **never logged** — it is redacted as `[REDACTED]`
//! in all structured log events.

use std::time::Duration;

use tracing::{info, warn};
use url::Url;

use crate::error::SbomError;
use crate::metrics::{DtOutcome, METRICS};

/// Project UUID returned by Dependency-Track after successful ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtProjectUuid(pub String);

impl std::fmt::Display for DtProjectUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Opaque DT API key wrapper.  Never implements `Display` to prevent accidental logging.
#[derive(Clone)]
pub struct DtApiKey(String);

impl std::fmt::Debug for DtApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DtApiKey").field(&"[REDACTED]").finish()
    }
}

impl DtApiKey {
    /// Read the API key from the named environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`SbomError::ApiKeyMissing`] when the variable is not set or is empty.
    pub fn from_env(var: &str) -> Result<Self, SbomError> {
        let val = std::env::var(var)
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SbomError::ApiKeyMissing(var.to_owned()))?;
        Ok(Self(val))
    }

    /// Expose the raw key value — use only when sending HTTP headers.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// Ingest SBOM bytes into Dependency-Track via `POST /api/v1/bom`.
///
/// # Arguments
///
/// * `sbom_bytes`    — raw `sbom.cdx.json` bytes.
/// * `dt_endpoint`   — base URL of the DT instance (e.g. `https://dependency-track.example.com`).
/// * `api_key`       — DT API key (read from env via [`DtApiKey::from_env`]).
/// * `project_name`  — DT project name; a new project is created if absent (`autoCreate=true`).
/// * `project_version` — project version string (e.g. `0.1.2`).
/// * `client`        — optional pre-configured `reqwest::Client`.
///
/// # Returns
///
/// [`DtProjectUuid`] on success.
///
/// # Errors
///
/// Returns [`SbomError::DtRetryExhausted`] after all retries fail, having already
/// written the SBOM to the fallback queue path (`.sbom_fallback_queue` in CWD).
///
/// # Example
///
/// ```ignore
/// use sbom_publish::dt::{ingest_into_dt, DtApiKey};
/// use url::Url;
///
/// std::env::set_var("DT_API_KEY", "test-key");
/// let key = DtApiKey::from_env("DT_API_KEY").unwrap();
/// let endpoint = Url::parse("https://dependency-track.example.com").unwrap();
/// let uuid = ingest_into_dt(b"{}", &endpoint, &key, "corelink-server", "0.1.0", None).await;
/// println!("{uuid:?}");
/// ```
pub async fn ingest_into_dt(
    sbom_bytes: &[u8],
    dt_endpoint: &Url,
    api_key: &DtApiKey,
    project_name: &str,
    project_version: &str,
    client: Option<reqwest::Client>,
) -> Result<DtProjectUuid, SbomError> {
    let http_client = client.unwrap_or_else(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_default()
    });

    // Retry delays (seconds): 0 (first attempt), 1, 4, 16
    let delays: [u64; 4] = [0, 1, 4, 16];
    let mut last_err: Option<String> = None;

    for (attempt, &delay_secs) in delays.iter().enumerate() {
        if delay_secs > 0 {
            warn!(attempt = attempt + 1, delay_secs, "DT ingestion retry");
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }

        let bom_url = {
            let mut u = dt_endpoint.clone();
            u.set_path("/api/v1/bom");
            u
        };

        let form = reqwest::multipart::Form::new()
            .text("projectName", project_name.to_owned())
            .text("projectVersion", project_version.to_owned())
            .text("autoCreate", "true")
            .part(
                "bom",
                reqwest::multipart::Part::bytes(sbom_bytes.to_vec())
                    .file_name("sbom.cdx.json")
                    .mime_str("application/json")
                    .map_err(|e| SbomError::DtIngestionFailed {
                        status: 0,
                        body: format!("form build error: {e}"),
                    })?,
            );

        let result = http_client
            .post(bom_url.as_str())
            .header("X-Api-Key", api_key.expose())
            .multipart(form)
            .send()
            .await;

        match result {
            Err(e) => {
                last_err = Some(format!("HTTP request error: {e}"));
                warn!(attempt = attempt + 1, error = %last_err.as_deref().unwrap_or(""), "DT request failed");
            }
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    let body = resp.text().await.unwrap_or_else(|_| "{}".to_owned());
                    // DT returns JSON with `token` (processing token); extract project UUID
                    // from Location header or body.
                    let project_uuid = extract_project_uuid(&body);
                    info!(
                        attempt = attempt + 1,
                        project_uuid = %project_uuid,
                        project_name,
                        project_version,
                        "DT ingestion succeeded"
                    );
                    METRICS.record_dt(DtOutcome::Ok);
                    return Ok(DtProjectUuid(project_uuid));
                } else if status.as_u16() == 400 || status.as_u16() == 422 {
                    // Non-retryable validation failure
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unreadable>".to_owned());
                    warn!(
                        http_status = status.as_u16(),
                        body = %body,
                        "DT ingestion validation failure (non-retryable)"
                    );
                    METRICS.record_dt(DtOutcome::ValidationFailed);
                    return Err(SbomError::DtIngestionFailed {
                        status: status.as_u16(),
                        body,
                    });
                } else {
                    // Retryable (5xx, 429, etc.)
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unreadable>".to_owned());
                    last_err = Some(format!("HTTP {}: {}", status.as_u16(), body));
                    warn!(
                        attempt = attempt + 1,
                        http_status = status.as_u16(),
                        "DT ingestion retryable error"
                    );
                }
            }
        }
    }

    // All retries exhausted → fallback queue
    let fallback_msg = last_err.unwrap_or_else(|| "unknown error".to_owned());
    warn!(
        fallback_msg = %fallback_msg,
        "DT ingestion exhausted all retries; writing to fallback queue"
    );
    write_fallback_queue(sbom_bytes, project_name, project_version)?;
    METRICS.record_dt(DtOutcome::RetryExhausted);
    Err(SbomError::DtRetryExhausted(fallback_msg))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract project UUID from DT API response body.
///
/// DT returns `{"token": "<processing-token>"}` for `/api/v1/bom`.
/// We use the token as the project reference until DT provides a project UUID.
fn extract_project_uuid(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("token")
                .or_else(|| v.get("uuid"))
                .or_else(|| v.get("project"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_owned())
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Persist SBOM bytes to the local fallback queue file.
///
/// In production this would write to a CF KV entry or S3-compatible blob.
/// For the CLI binary it writes to `.sbom_fallback_queue/<timestamp>.cdx.json`.
fn write_fallback_queue(
    sbom_bytes: &[u8],
    project_name: &str,
    project_version: &str,
) -> Result<(), SbomError> {
    let dir = std::path::Path::new(".sbom_fallback_queue");
    std::fs::create_dir_all(dir)?;
    let filename = format!(
        "{project_name}-{project_version}-{}.cdx.json",
        uuid::Uuid::new_v4()
    );
    let path = dir.join(&filename);
    std::fs::write(&path, sbom_bytes)?;
    warn!(
        path = %path.display(),
        size_bytes = sbom_bytes.len(),
        "SBOM written to fallback queue (SEV-3: DT ingestion failed)"
    );
    Ok(())
}
