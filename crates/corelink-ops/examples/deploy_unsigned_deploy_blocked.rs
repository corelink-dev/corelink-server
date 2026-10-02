//! Example: unsigned deploy attempt is hard-blocked.
// Examples are CLI programs; printing to stdout/stderr is intentional.
#![allow(clippy::print_stdout, clippy::print_stderr)]
//!
//! Demonstrates the chaos test scenario from WI-S12-003 §6.1.11:
//! - Attacker stages unsigned image in ghcr.io.
//! - Triggers CF deploy webhook.
//! - Verifier rejects with `SignatureInvalid`.
//! - SEV-2 alert fires.
//! - Audit event `dev.hugr.corelink.deploy.blocked.v1` emitted.
//! - CF API is **never** invoked.
//!
//! This validates INV-SUPPLY-SIGNED-DEPLOY enforcement.

use std::sync::Arc;

use corelink_ops::deploy::{
    audit::InMemoryDeployAuditSink,
    error::DeployVerifyError,
    types::{CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef},
    verifier::InMemoryDeployVerifier,
    DeployVerifier,
};

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();

    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_unsigned_from(Arc::clone(&sink));

    // Attacker payload: tries to deploy unsigned malicious image
    let webhook = CfDeployWebhook::new(
        "malicious",
        "e v 1 l 1 2 3 4 5 6 7 8 9 0 a b c d e f",
        "refs/tags/malicious",
        DeployTarget::new(
            "corelink-worker",
            "99999999999999999999999999999999",
            "corelink-api.humangr.com/*",
        ),
        GitHubActor::new(
            "attacker",
            "attacker/corelink-server/.github/workflows/evil.yml@refs/tags/malicious",
        ),
    );
    let image_ref = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:malicious");
    let identity = CosignIdentityPattern::corelink_release();

    println!("Simulating unsigned deploy attempt ...");

    let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);

    match result {
        Ok(_) => {
            eprintln!(
                "CRITICAL: unsigned deploy was NOT blocked — INV-SUPPLY-SIGNED-DEPLOY violated!"
            );
            std::process::exit(2);
        }
        Err(ref e @ DeployVerifyError::SignatureInvalid(_)) => {
            println!("Deploy BLOCKED (expected): {e}");
            println!("  http_status: {}", e.http_status());
            println!("  blocked_reason: {}", e.blocked_reason_label());
            println!("  is_sev2: {}", e.is_sev2());
        }
        Err(e) => {
            eprintln!("Unexpected error type: {e}");
            std::process::exit(1);
        }
    }

    println!("\nAudit events emitted: {}", sink.len());
    for event in sink.events() {
        println!(
            "  [BLOCKED] type={} outcome={:?}",
            event.event_type, event.outcome
        );
    }

    assert_eq!(sink.len(), 1, "exactly one blocked audit event");
    println!("\nChaos test PASSED: unsigned deploy blocked + audit emitted.");
}
