//! Adversarial regression tests — 5 CVE-class scenarios.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//!
//! Each test validates a specific attack vector from WI-S12-003 §6.1.9:
//!
//! 1. **Unsigned deploy attempt** — blocked + alert SEV-2 + audit emit.
//! 2. **Rekor missing attempt** — blocked (offline signature, no Rekor publish).
//! 3. **Identity confusion (fork attack)** — blocked via SAN URI mismatch.
//! 4. **Replay attack (TOCTOU)** — blocked via image digest binding.
//! 5. **Audit emit failure fail-CLOSED** — deploy blocked even if crypto OK.

use std::sync::Arc;

use corelink_ops::deploy::{
    audit::{FailingDeployAuditSink, InMemoryDeployAuditSink},
    error::DeployVerifyError,
    types::{
        CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef,
        VerifyOutcome,
    },
    verifier::{InMemoryDeployVerifier, VerificationMode},
    DeployVerifier,
};

fn make_webhook(tag: &str) -> CfDeployWebhook {
    CfDeployWebhook::new(
        tag,
        "deadbeef".repeat(5),
        format!("refs/tags/{tag}"),
        DeployTarget::new(
            "corelink-worker",
            "b".repeat(32),
            "corelink-api.humangr.com/*",
        ),
        GitHubActor::new(
            "github-actions[bot]",
            format!(
                "HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/{tag}"
            ),
        ),
    )
}

fn make_image_ref(tag: &str) -> OciImageRef {
    OciImageRef::from_tag(format!("ghcr.io/HumanGuardrail/corelink-worker:{tag}"))
}

// ── CVE-1: Unsigned deploy attempt ────────────────────────────────────────

/// An attacker stages an unsigned image and triggers the deploy webhook.
/// Expected: `SignatureInvalid` returned, CF API NOT invoked,
/// alert SEV-2 fires, audit event emitted.
#[test]
fn adversarial_unsigned_deploy_blocked_with_sev2_alert_and_audit() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_unsigned_from(Arc::clone(&sink));

    let result = verifier.verify_and_propagate(
        &make_webhook("malicious"),
        &make_image_ref("malicious"),
        &CosignIdentityPattern::corelink_release(),
    );

    // Verify gate rejects
    assert!(
        matches!(result, Err(DeployVerifyError::SignatureInvalid(_))),
        "unsigned deploy must be blocked; got {result:?}"
    );

    // SEV-2 error classification
    let err = result.unwrap_err();
    assert!(err.is_sev2(), "SignatureInvalid must trigger SEV-2");
    assert!(!err.is_sev1(), "SEV-1 is for audit emit failures only");

    // Audit event emitted (blocked)
    assert_eq!(sink.len(), 1, "exactly one audit event for blocked deploy");
    let event = &sink.events()[0];
    assert_eq!(event.event_type, "dev.hugr.corelink.deploy.blocked.v1");
    assert_eq!(event.outcome, VerifyOutcome::SigInvalid);
    assert_eq!(event.release_tag, "malicious");
}

// ── CVE-2: Rekor missing attempt ──────────────────────────────────────────

/// Attacker generates a Cosign signature offline (does not publish to Rekor).
/// Expected: `RekorMissing` returned, deploy blocked.
/// Validates INV-SUPPLY-PROVENANCE-IN-REKOR enforcement.
#[test]
fn adversarial_rekor_missing_deploy_blocked() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_rekor_missing_from(Arc::clone(&sink));

    let image_ref = make_image_ref("v0.5.0");
    let result = verifier.verify_and_propagate(
        &make_webhook("v0.5.0"),
        &image_ref,
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(
        matches!(result, Err(DeployVerifyError::RekorMissing { .. })),
        "offline signature (no Rekor) must be blocked; got {result:?}"
    );

    let err = result.unwrap_err();
    // Rekor missing is a SEV-2 class event
    assert!(err.is_sev2(), "RekorMissing must trigger SEV-2");

    assert_eq!(sink.len(), 1);
    assert_eq!(sink.events()[0].outcome, VerifyOutcome::RekorMissing);
}

// ── CVE-3: Identity confusion (fork attack) ───────────────────────────────

/// Attacker creates a fork at `attacker/corelink-server` and generates a
/// valid Cosign signature — but the SAN URI points to the attacker's repo.
/// Expected: `IdentityMismatch` returned, deploy blocked.
#[test]
fn adversarial_fork_identity_mismatch_blocked() {
    let attacker_san = "https://github.com/attacker/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";

    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier =
        InMemoryDeployVerifier::new_identity_mismatch_from(Arc::clone(&sink), attacker_san);

    let result = verifier.verify_and_propagate(
        &make_webhook("v0.1.0"),
        &make_image_ref("v0.1.0"),
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(
        matches!(result, Err(DeployVerifyError::IdentityMismatch { .. })),
        "fork SAN URI must be rejected; got {result:?}"
    );

    // Validate error contents
    if let Err(DeployVerifyError::IdentityMismatch { got, expected }) = &result {
        assert!(
            got.contains("attacker"),
            "got should contain attacker org: {got}"
        );
        assert!(
            expected.contains("HumanGuardrail"),
            "expected should contain canonical org: {expected}"
        );
    }

    assert_eq!(sink.events()[0].outcome, VerifyOutcome::IdentityMismatch);
}

// ── CVE-4: Replay attack (TOCTOU) ─────────────────────────────────────────

/// Attacker captures a valid signature for v0.1.0 and replays it for v0.2.0.
/// At deploy time the resolved digest (v0.2.0) does not match the signature
/// binding (v0.1.0 digest).
/// Expected: `DigestMismatch` returned, deploy blocked.
#[test]
fn adversarial_replay_attack_toctou_blocked() {
    let old_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let new_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier =
        InMemoryDeployVerifier::new_replay_attack_from(Arc::clone(&sink), old_digest, new_digest);

    let result = verifier.verify_and_propagate(
        &make_webhook("v0.2.0"),
        &make_image_ref("v0.2.0"),
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(
        matches!(result, Err(DeployVerifyError::DigestMismatch { .. })),
        "replay attack (digest mismatch) must be blocked; got {result:?}"
    );

    if let Err(DeployVerifyError::DigestMismatch {
        signed_digest,
        resolved_digest,
    }) = &result
    {
        assert_eq!(signed_digest, old_digest);
        assert_eq!(resolved_digest, new_digest);
    }

    // DigestMismatch maps to SigInvalid outcome in audit
    let event = &sink.events()[0];
    assert_eq!(event.event_type, "dev.hugr.corelink.deploy.blocked.v1");
}

// ── CVE-5: Audit emit failure fail-CLOSED ────────────────────────────────

/// S-09 audit chain endpoint returns 503 (simulated via FailingDeployAuditSink).
/// Even though all crypto checks pass, the deploy must be blocked and
/// SEV-1 alert must fire.
#[test]
fn adversarial_audit_emit_failure_blocks_deploy_fail_closed() {
    let failing_sink = Arc::new(FailingDeployAuditSink::new("S-09 audit chain 503"));
    let verifier = InMemoryDeployVerifier::with_mode(
        VerificationMode::Signed {
            rekor_log_index: 42,
            fulcio_san: "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
            resolved_digest: "sha256:cafecafe".to_string(),
        },
        failing_sink,
    );

    let result = verifier.verify_and_propagate(
        &make_webhook("v0.1.0"),
        &make_image_ref("v0.1.0"),
        &CosignIdentityPattern::corelink_release(),
    );

    // Deploy MUST be blocked (fail-CLOSED)
    assert!(
        matches!(result, Err(DeployVerifyError::AuditEmitFailed(_))),
        "audit emit failure must block deploy; got {result:?}"
    );

    // SEV-1 classification
    let err = result.unwrap_err();
    assert!(err.is_sev1(), "AuditEmitFailed must trigger SEV-1");
    assert!(!err.is_sev2(), "SEV-2 is for supply chain errors");
}

// ── Fulcio chain invalid ──────────────────────────────────────────────────

/// Malicious cert chain not anchored to sigstore Fulcio root.
/// Expected: `FulcioChainInvalid` returned, deploy blocked.
#[test]
fn adversarial_fulcio_chain_invalid_blocked() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_fulcio_invalid_from(Arc::clone(&sink));

    let result = verifier.verify_and_propagate(
        &make_webhook("v0.3.0"),
        &make_image_ref("v0.3.0"),
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(
        matches!(result, Err(DeployVerifyError::FulcioChainInvalid(_))),
        "invalid Fulcio chain must be blocked; got {result:?}"
    );

    let event = &sink.events()[0];
    assert_eq!(event.outcome, VerifyOutcome::FulcioInvalid);
}

// ── Combined: all 5 CVE-class errors produce HTTP status ≥ 400 ───────────

#[test]
fn all_adversarial_errors_map_to_blocking_http_status() {
    use corelink_ops::deploy::worker::error_to_http_response;

    let errors = vec![
        DeployVerifyError::SignatureInvalid("unsigned".into()),
        DeployVerifyError::RekorMissing {
            image: "img".into(),
        },
        DeployVerifyError::FulcioChainInvalid("bad chain".into()),
        DeployVerifyError::IdentityMismatch {
            got: "attacker".into(),
            expected: "legit".into(),
        },
        DeployVerifyError::DigestMismatch {
            signed_digest: "old".into(),
            resolved_digest: "new".into(),
        },
        DeployVerifyError::AuditEmitFailed("503".into()),
    ];

    for err in &errors {
        let (status, body) = error_to_http_response(err);
        assert!(
            status >= 400,
            "adversarial error must produce HTTP 4xx/5xx; got {status} for {err:?}"
        );
        assert!(!body.is_empty(), "response body must not be empty");
    }
}
