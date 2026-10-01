//! `sbom-publish` CLI binary.
//!
//! # Subcommands
//!
//! | Command | Description |
//! |---|---|
//! | `generate` | Invoke `cargo cyclonedx` + PURL normalisation + NTIA strict gate + TSA timestamp |
//! | `validate-ntia` | NTIA minimum elements check only (exit 0 = compliant, exit 2 = fail) |
//! | `attest-tsa` | Request RFC 3161 TSA timestamp for an existing SBOM file |
//! | `ingest-dt` | Ingest SBOM into Dependency-Track via API |
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Success |
//! | 1 | Generation or schema error |
//! | 2 | NTIA validation failed |
//! | 3 | TSA timestamp failed |
//! | 4 | DT ingestion failed after retry exhaustion |

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
// CLI binary must emit output to stdout by design.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use url::Url;

use sbom_publish::dt::{ingest_into_dt, DtApiKey};
use sbom_publish::error::SbomError;
use sbom_publish::metrics::METRICS;
use sbom_publish::ntia::{validate_ntia_json, ValidationMode};
use sbom_publish::publisher::{DefaultSbomPublisher, ReleaseMetadata, SbomPublisher};
use sbom_publish::tsa::{request_tsa_timestamp, verify_tsr_binding};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// CoreLink SBOM pipeline CLI (WI-S12-002).
#[derive(Debug, Parser)]
#[command(name = "sbom-publish", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate SBOM via cargo-cyclonedx, validate NTIA, attest TSA.
    Generate {
        /// Path to Cargo.lock
        #[arg(long)]
        cargo_lock: PathBuf,
        /// Path to workspace root Cargo.toml
        #[arg(long)]
        cargo_toml: PathBuf,
        /// Release version string (e.g. "0.1.2")
        #[arg(long)]
        version: String,
        /// Git commit SHA (40-char hex)
        #[arg(long, default_value = "0000000000000000000000000000000000000000")]
        commit_sha: String,
        /// Project name
        #[arg(long, default_value = "corelink-server")]
        project_name: String,
        /// Output path for sbom.cdx.json
        #[arg(long, default_value = "sbom.cdx.json")]
        output: PathBuf,
        /// TSA endpoint URL
        #[arg(long, default_value = "https://tsa.sigstore.dev/api/v1/timestamp")]
        tsa_url: Url,
        /// Output path for sbom.cdx.json.tsr (TSA timestamp response)
        #[arg(long, default_value = "sbom.cdx.json.tsr")]
        output_tsr: PathBuf,
    },
    /// Validate NTIA minimum elements for an existing SBOM file.
    ValidateNtia {
        /// Path to sbom.cdx.json
        #[arg(long)]
        input: PathBuf,
        /// Enable auditor mode (soft warnings, no exit 2)
        #[arg(long)]
        auditor: bool,
    },
    /// Request RFC 3161 TSA timestamp for an existing SBOM file.
    AttestTsa {
        /// Path to sbom.cdx.json
        #[arg(long)]
        input: PathBuf,
        /// TSA endpoint URL
        #[arg(long, default_value = "https://tsa.sigstore.dev/api/v1/timestamp")]
        tsa_url: Url,
        /// Output path for .tsr file
        #[arg(long, default_value = "sbom.cdx.json.tsr")]
        output_tsr: PathBuf,
    },
    /// Ingest SBOM into Dependency-Track via API.
    IngestDt {
        /// Path to sbom.cdx.json
        #[arg(long)]
        input: PathBuf,
        /// Dependency-Track base URL
        #[arg(long)]
        dt_url: Url,
        /// Environment variable name containing the DT API key
        #[arg(long, default_value = "DT_API_KEY")]
        api_key_env: String,
        /// DT project name
        #[arg(long, default_value = "corelink-server")]
        project_name: String,
        /// DT project version
        #[arg(long, default_value = "0.0.0")]
        project_version: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    // Initialise structured JSON logging
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    let exit_code = match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "sbom-publish failed");
            exit_code_for_error(&e)
        }
    };

    METRICS.emit_summary();
    exit_code
}

async fn run(cli: Cli) -> Result<(), SbomError> {
    match cli.command {
        Commands::Generate {
            cargo_lock,
            cargo_toml,
            version,
            commit_sha,
            project_name,
            output,
            tsa_url,
            output_tsr,
        } => {
            let publisher = DefaultSbomPublisher::new(tsa_url, &[], &[]);
            let meta = ReleaseMetadata {
                version,
                commit_sha,
                project_name,
            };
            let signed = publisher.generate(&cargo_lock, &cargo_toml, &meta).await?;

            // Write SBOM JSON
            let sbom_bytes = serde_json::to_vec_pretty(&signed.sbom)?;
            std::fs::write(&output, &sbom_bytes)?;
            info!(path = %output.display(), "SBOM written");

            // Write TSR if present
            if let Some(tsr) = &signed.tsr_token {
                std::fs::write(&output_tsr, &tsr.der_bytes)?;
                info!(path = %output_tsr.display(), "TSR written");
            }

            println!(
                "{{\"sbom_path\":\"{}\",\"component_count\":{},\"ntia_compliant\":{},\"has_tsr\":{}}}",
                output.display(),
                signed.component_count,
                signed.ntia_compliant,
                signed.tsr_token.is_some()
            );
        }

        Commands::ValidateNtia { input, auditor } => {
            let sbom_bytes = std::fs::read(&input)?;
            let sbom_json: serde_json::Value = serde_json::from_slice(&sbom_bytes)?;
            let mode = if auditor {
                ValidationMode::Auditor
            } else {
                ValidationMode::Strict
            };
            let result = validate_ntia_json(&sbom_json, mode);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "overall_compliant": result.overall_compliant,
                    "author_present": result.author_present,
                    "timestamp_present": result.timestamp_present,
                    "component_name_present": result.component_name_present,
                    "component_version_present": result.component_version_present,
                    "component_supplier_present": result.component_supplier_present,
                    "component_unique_id_present": result.component_unique_id_present,
                    "dependency_relationships_present": result.dependency_relationships_present,
                }))?
            );
            if !result.overall_compliant && !auditor {
                return Err(SbomError::NtiaValidationFailed(result));
            }
        }

        Commands::AttestTsa {
            input,
            tsa_url,
            output_tsr,
        } => {
            let sbom_bytes = std::fs::read(&input)?;
            let token = request_tsa_timestamp(&sbom_bytes, &tsa_url, None).await?;
            // Verify binding before writing
            verify_tsr_binding(&sbom_bytes, &token)?;
            std::fs::write(&output_tsr, &token.der_bytes)?;
            info!(path = %output_tsr.display(), sha256 = %token.sbom_sha256_hex, "TSR written");
        }

        Commands::IngestDt {
            input,
            dt_url,
            api_key_env,
            project_name,
            project_version,
        } => {
            let sbom_bytes = std::fs::read(&input)?;
            let api_key = DtApiKey::from_env(&api_key_env)?;
            let uuid = ingest_into_dt(
                &sbom_bytes,
                &dt_url,
                &api_key,
                &project_name,
                &project_version,
                None,
            )
            .await?;
            println!("{}", ingestion_summary(&uuid.0));
        }
    }

    Ok(())
}

fn ingestion_summary(_project_uuid: &str) -> serde_json::Value {
    serde_json::json!({ "ingested": true })
}

fn exit_code_for_error(e: &SbomError) -> ExitCode {
    match e {
        SbomError::GenerationFailed(_)
        | SbomError::SchemaInvalid(_)
        | SbomError::Json(_)
        | SbomError::Io(_) => ExitCode::from(1),
        SbomError::NtiaValidationFailed(_) => ExitCode::from(2),
        SbomError::TsaRequestFailed(_) => ExitCode::from(3),
        SbomError::DtIngestionFailed { .. }
        | SbomError::DtRetryExhausted(_)
        | SbomError::ApiKeyMissing(_) => ExitCode::from(4),
        SbomError::Http(_) => ExitCode::from(4),
        _ => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::ingestion_summary;

    #[test]
    fn ingestion_summary_reports_success_without_project_uuid() {
        let secret_uuid = "8f14e45f-ea3e-45e3-aab7-080f14617aaf";
        let summary = ingestion_summary(secret_uuid);
        let output = summary.to_string();

        assert!(output.contains("\"ingested\":true"));
        assert!(!output.contains(secret_uuid));
        assert!(summary.get("project_uuid").is_none());
    }
}
