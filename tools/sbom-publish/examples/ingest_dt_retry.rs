//! Example: ingest an SBOM into Dependency-Track with retry + fallback queue.
//!
//! # Usage
//!
//! ```sh
//! DT_API_KEY=my-secret cargo run --example ingest_dt_retry -- \
//!   --input /tmp/sbom.cdx.json \
//!   --dt-url https://dependency-track.example.com \
//!   --project-name corelink-server \
//!   --project-version 0.1.0
//! ```
//!
//! If DT returns 503 on the first attempt the client will retry up to 3 times
//! with exponential backoff (1 s → 4 s → 16 s).  On exhaustion the SBOM is
//! written to `.sbom_fallback_queue/` and exit code 4 is returned.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used)]

use url::Url;

use sbom_publish::dt::{ingest_into_dt, DtApiKey};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);

    let mut input = String::from("/tmp/sbom.cdx.json");
    let mut dt_url_str = String::from("https://dependency-track.example.com");
    let mut api_key_env = String::from("DT_API_KEY");
    let mut project_name = String::from("corelink-server");
    let mut project_version = String::from("0.0.0");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                if let Some(v) = args.next() {
                    input = v;
                }
            }
            "--dt-url" => {
                if let Some(v) = args.next() {
                    dt_url_str = v;
                }
            }
            "--api-key-env" => {
                if let Some(v) = args.next() {
                    api_key_env = v;
                }
            }
            "--project-name" => {
                if let Some(v) = args.next() {
                    project_name = v;
                }
            }
            "--project-version" => {
                if let Some(v) = args.next() {
                    project_version = v;
                }
            }
            _ => {}
        }
    }

    let sbom_bytes = std::fs::read(&input).unwrap_or_else(|e| {
        eprintln!("Cannot read {input}: {e}");
        std::process::exit(1);
    });

    let api_key = DtApiKey::from_env(&api_key_env).unwrap_or_else(|e| {
        eprintln!("API key error: {e}");
        std::process::exit(4);
    });

    let dt_url = Url::parse(&dt_url_str).unwrap_or_else(|e| {
        eprintln!("Invalid DT URL: {e}");
        std::process::exit(1);
    });

    match ingest_into_dt(
        &sbom_bytes,
        &dt_url,
        &api_key,
        &project_name,
        &project_version,
        None,
    )
    .await
    {
        Ok(uuid) => {
            println!("{{\"project_uuid\":\"{uuid}\"}}");
        }
        Err(e) => {
            eprintln!("DT ingestion failed: {e}");
            std::process::exit(4);
        }
    }
}
