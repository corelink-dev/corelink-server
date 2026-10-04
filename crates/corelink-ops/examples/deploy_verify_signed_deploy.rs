//! Example: verify a fully signed deploy (happy path).
// Examples are CLI programs; printing to stdout/stderr is intentional.
#![allow(clippy::print_stdout, clippy::print_stderr)]
//!
//! Demonstrates the complete flow:
//! 1. Webhook HMAC authentication.
//! 2. Cosign signature + Rekor inclusion + Fulcio chain verification.
//! 3. Audit event emit (success).
//! 4. Cloudflare API propagation with pinned digest.
//!
//! In production this uses the `sigstore` Rust crate for cryptographic
//! verification and the Cloudflare REST API for propagation.  This example
//! uses the in-memory verifier to demonstrate the trait contract.

use std::sync::Arc;

use corelink_ops::deploy::{
    audit::InMemoryDeployAuditSink,
    types::{
        CfDeployWebhook, CosignIdentityPattern, DeployPropagated, DeployTarget, GitHubActor,
        OciImageRef,
    },
    verifier::InMemoryDeployVerifier,
    DeployVerifier,
};

fn main() {
    // Set up structured logging (optional in tests; useful for demo output).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_signed_from(Arc::clone(&sink));

    // Build webhook payload from GitHub Actions release event
    let webhook = CfDeployWebhook::new(
        "v0.1.0",
        "abc123def456abc123def456abc123def456abc1",
        "refs/tags/v0.1.0",
        DeployTarget::new(
            "corelink-worker",
            // 32-hex-char Cloudflare zone ID
            "00000000000000000000000000000001",
            "corelink-api.humangr.com/*",
        ),
        GitHubActor::new(
            "github-actions[bot]",
            "corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0",
        ),
    );

    // OCI image reference (tag; digest resolved during verify)
    let image_ref = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:v0.1.0");

    // Expected identity: canonical CoreLink release pipeline pattern
    let identity = CosignIdentityPattern::corelink_release();

    println!("Verifying deploy for release_tag=v0.1.0 ...");

    match verifier.verify_and_propagate(&webhook, &image_ref, &identity) {
        Ok(propagated) => {
            print!("{}", propagated_summary(&propagated));
        }
        Err(e) => {
            eprintln!("Deploy BLOCKED: {e}");
            std::process::exit(1);
        }
    }

    println!("\nAudit events emitted: {}", sink.len());
    for event in sink.events() {
        println!(
            "  [{}] type={} outcome={:?} tag={}",
            event.event_id, event.event_type, event.outcome, event.release_tag
        );
    }
}

fn propagated_summary(propagated: &DeployPropagated) -> String {
    format!(
        "Deploy PROPAGATED:\n  release_tag:              {}\n  cosign_signature_verified: {}\n  rekor_log_index:           {}\n  cf_deployment_id:          {}\n",
        propagated.release_tag,
        propagated.cosign_signature_verified,
        propagated.rekor_log_index,
        propagated.cf_deployment_id,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use corelink_ops::deploy::{
        audit::InMemoryDeployAuditSink,
        types::{CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef},
        verifier::InMemoryDeployVerifier,
        DeployVerifier,
    };

    use super::propagated_summary;

    #[test]
    fn propagated_summary_keeps_outcome_and_metadata_without_certificate_san() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_signed_from(Arc::clone(&sink));
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
        let propagated = verifier
            .verify_and_propagate(&webhook, &image_ref, &identity)
            .expect("signed test deploy should propagate");
        let summary = propagated_summary(&propagated);

        assert!(!summary.contains(&propagated.fulcio_cert_san));
        assert!(summary.contains("Deploy PROPAGATED:"));
        assert!(summary.contains("cosign_signature_verified: true"));
        assert!(summary.contains("release_tag:              v0.1.0"));
        assert!(summary.contains("cf_deployment_id:"));
    }
}

// Retain the historical SAN without treating it as authority for a new deploy.
#[test]
fn historical_signature_is_not_current_deploy_authority() {
    let historical_san = "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    assert!(!CosignIdentityPattern::corelink_release().matches_simple(historical_san));
}
