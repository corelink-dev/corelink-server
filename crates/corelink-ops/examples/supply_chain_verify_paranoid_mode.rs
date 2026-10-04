//! Example: Paranoid mode — verify with exact builder SAN URI + Rekor log consistency (WI-S12-001).
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
//! Inspects a retained historical artifact, not a current release acceptance gate.
//! Demonstrates the strictest historical verification mode:
//! - Exact SAN URI match (specific release tag, not org pattern).
//! - Prints Rekor log entry URL for manual audit verification.
//! - Prints instructions for offline Merkle log consistency proof check.
//!
//! ```sh
//! cargo run --example paranoid_mode -- --bundle provenance.intoto.bundle --tag v0.1.0
//! ```

use corelink_ops::supply_chain::verify::{
    types::{BuilderIdentity, SlsaAttestation},
    verifier::{DefaultSlsaVerifier, SlsaProvenanceVerifier},
};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mut bundle_path = "provenance.intoto.bundle".to_string();
    let mut release_tag = "v0.1.0".to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bundle" => bundle_path = args.next().unwrap_or(bundle_path),
            "--tag" => release_tag = args.next().unwrap_or(release_tag),
            _ => {}
        }
    }

    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read bundle file `{}`: {}", bundle_path, e);
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

    // PARANOID MODE: exact SAN URI including the specific release tag
    // This rejects any attestation not pinned to this exact release tag + workflow ref.
    let exact_san = format!(
        "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/{}",
        release_tag
    );
    let expected = BuilderIdentity::from_historical_exact(&exact_san);

    println!("Paranoid mode: verifying against exact SAN URI:");
    println!("  {}", exact_san);
    println!();

    let verifier = DefaultSlsaVerifier::with_plan("paranoid");
    match verifier.verify(&attestation, &expected).await {
        Ok(prov) => {
            println!("SLSA L3 provenance verification PASSED (paranoid mode)");
            println!();
            println!("Cryptographic evidence:");
            println!("  builder_id:              {}", prov.builder_id);
            println!("  commit_sha:              {}", prov.commit_sha);
            println!("  workflow_ref:            {}", prov.workflow_ref);
            println!("  rekor_log_index:         {}", prov.rekor_log_index);
            println!("  rekor_merkle_root:       {}", prov.rekor_merkle_root);
            println!("  artifact_digest_sha256:  {}", prov.artifact_digest);
            println!();
            println!("Manual Rekor verification:");
            println!(
                "  rekor-cli get --rekor_server https://rekor.sigstore.dev --log-index {}",
                prov.rekor_log_index
            );
            println!(
                "  rekor-cli verify --rekor_server https://rekor.sigstore.dev --log-index {}",
                prov.rekor_log_index
            );
            println!();
            println!("Rekor entry URL (publicly auditable):");
            println!("  {}", prov.rekor_inclusion_proof_url);
        }
        Err(e) => {
            eprintln!("SLSA L3 verification FAILED (paranoid mode): {}", e);
            if e.is_security_failure() {
                eprintln!();
                eprintln!("SECURITY ALERT: Do NOT use this artifact.");
                eprintln!("Report to: https://github.com/HuGR-dev/corelink-server/security");
            }
            std::process::exit(e.exit_code());
        }
    }
}
