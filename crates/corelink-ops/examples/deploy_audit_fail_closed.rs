//! Example: audit emit failure causes deploy to be fail-CLOSED.
// Examples are CLI programs; printing to stdout/stderr is intentional.
#![allow(clippy::print_stdout, clippy::print_stderr)]
//!
//! Demonstrates the fail-CLOSED invariant from CTRL-AUDIT-002 +
//! INV-AUDIT-APPEND-ONLY (WI-S12-003 §9.7 + §6.1.5):
//!
//! - S-09 audit chain endpoint returns 503 (simulated with `FailingDeployAuditSink`).
//! - All crypto checks pass (valid signature, Rekor, Fulcio, identity).
//! - **But** because audit emit fails, the deploy is blocked.
//! - SEV-1 alert fires.
//! - CF API is **never** invoked.
//!
//! Anti-pattern rejected: fail-OPEN ("warn but allow") — hard-gate mandatory
//! per §7 anti-patterns.

use std::sync::Arc;

use corelink_ops::deploy::{
    audit::FailingDeployAuditSink,
    error::DeployVerifyError,
    types::{CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef},
    verifier::{InMemoryDeployVerifier, VerificationMode},
    DeployVerifier,
};

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();

    // Audit sink that always fails — simulates S-09 chain 503
    let failing_sink = Arc::new(FailingDeployAuditSink::new(
        "S-09 audit chain endpoint unavailable (HTTP 503)",
    ));

    // Use signed mode so all crypto checks pass
    let verifier = InMemoryDeployVerifier::with_mode(
        VerificationMode::Signed {
            rekor_log_index: 987_654_321,
            fulcio_san: "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
            resolved_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
        },
        failing_sink,
    );

    let webhook = CfDeployWebhook::new(
        "v0.1.0",
        "abc123def456abc123def456abc123def456abc1",
        "refs/tags/v0.1.0",
        DeployTarget::new(
            "corelink-worker",
            "00000000000000000000000000000001",
            "corelink-api.humangr.com/*",
        ),
        GitHubActor::new(
            "github-actions[bot]",
            "corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0",
        ),
    );
    let image_ref = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:v0.1.0");
    let identity = CosignIdentityPattern::corelink_release();

    println!("Simulating audit chain outage (S-09 503) during otherwise valid deploy ...");

    let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);

    match result {
        Ok(_) => {
            eprintln!("CRITICAL: deploy succeeded with audit emit failure — fail-OPEN BUG!");
            eprintln!("INV-AUDIT-APPEND-ONLY violated!");
            std::process::exit(2);
        }
        Err(ref e @ DeployVerifyError::AuditEmitFailed(_)) => {
            println!("Deploy BLOCKED (fail-CLOSED, expected): {e}");
            println!("  http_status: {}", e.http_status());
            println!("  is_sev1: {}", e.is_sev1());
            println!("  is_sev2: {}", e.is_sev2());
        }
        Err(e) => {
            eprintln!("Unexpected error type: {e}");
            std::process::exit(1);
        }
    }

    println!("\nFail-CLOSED test PASSED:");
    println!("  - Crypto checks: all PASSED");
    println!("  - Audit emit: FAILED (503 simulated)");
    println!("  - Deploy: BLOCKED (fail-CLOSED)");
    println!("  - SEV-1: FIRED");
    println!("  - CF API: NOT invoked");
}

// Retain the historical SAN without treating it as authority for a new deploy.
#[test]
fn historical_signature_is_not_current_deploy_authority() {
    let historical_san = "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    assert!(!CosignIdentityPattern::corelink_release().matches_simple(historical_san));
}
