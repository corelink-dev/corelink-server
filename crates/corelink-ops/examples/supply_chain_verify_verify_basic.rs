//! Example: Basic SLSA L3 provenance verification (WI-S12-001).
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::uninlined_format_args,
    clippy::format_in_format_args,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//!
//! Demonstrates verifying a `provenance.intoto.bundle` file using an org-scoped
//! builder pattern (`corelink-dev/corelink-server`).
//!
//! ```sh
//! cargo run --example verify_basic -- --bundle provenance.intoto.bundle
//! ```

use corelink_ops::supply_chain::verify::{
    types::{BuilderIdentity, SlsaAttestation},
    verifier::{DefaultSlsaVerifier, SlsaProvenanceVerifier},
};

#[tokio::main]
async fn main() {
    // In production: read from the release asset download
    let bundle_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "provenance.intoto.bundle".to_string());

    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read bundle file `{}`: {}", bundle_path, e);
            eprintln!("Hint: Download provenance.intoto.bundle from the GitHub release assets.");
            std::process::exit(3);
        }
    };

    let attestation: SlsaAttestation = match serde_json::from_str(&bundle_json) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to parse attestation: {}", e);
            std::process::exit(3);
        }
    };

    // Use org-scoped pattern for flexibility across release tags
    let expected = BuilderIdentity::from_org_pattern("corelink-dev/corelink-server");

    let verifier = DefaultSlsaVerifier::with_plan("example");
    match verifier.verify(&attestation, &expected).await {
        Ok(prov) => {
            println!("SLSA L3 provenance verification PASSED");
            println!("  builder_id:    {}", prov.builder_id);
            println!("  commit_sha:    {}", prov.commit_sha);
            println!("  workflow_ref:  {}", prov.workflow_ref);
            println!("  rekor_index:   {}", prov.rekor_log_index);
            println!("  rekor_url:     {}", prov.rekor_inclusion_proof_url);
            println!("  schema:        {}", prov.in_toto_schema_version);
        }
        Err(e) => {
            eprintln!("SLSA L3 verification FAILED: {}", e);
            std::process::exit(e.exit_code());
        }
    }
}
