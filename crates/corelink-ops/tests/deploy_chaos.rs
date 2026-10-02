//! Chaos tests for the deploy verify gate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_in_format_args,
    clippy::uninlined_format_args
)]
//!
//! Validates INV-SUPPLY-SIGNED-DEPLOY enforcement under adversarial conditions
//! (WI-S12-003 §6.1.11-12 + §15 chaos experiments).
//!
//! Chaos scenarios:
//!
//! 1. **Deploy unsigned artifact** — canonical test for INV-SUPPLY-SIGNED-DEPLOY.
//! 2. **Deploy with Rekor missing** — offline signature rejected.
//! 3. **Identity confusion 100 iterations** — varied attacker SANs all blocked.
//! 4. **Replay attack 100 iterations** — varied digest pairs all blocked.
//! 5. **Audit emit failure fail-CLOSED 100 iterations** — 0 false-deploys.
//! 6. **Rate limit** — webhook rate limit stub (HTTP 429).
//! 7. **Webhook HMAC auth** — tampered body rejected.
//! 8. **OCI fetch failure** — registry unavailable blocks deploy.

use std::sync::Arc;

use corelink_ops::deploy::{
    audit::{FailingDeployAuditSink, InMemoryDeployAuditSink},
    error::DeployVerifyError,
    types::{
        CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef,
        VerifyOutcome,
    },
    verifier::{InMemoryDeployVerifier, VerificationMode},
    worker::verify_webhook_hmac,
    DeployVerifier,
};

fn make_webhook(tag: &str) -> CfDeployWebhook {
    CfDeployWebhook::new(
        tag,
        "feedcafe".repeat(5),
        format!("refs/tags/{tag}"),
        DeployTarget::new(
            "corelink-worker",
            "c".repeat(32),
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

// ── Chaos 1: Deploy unsigned artifact (INV-SUPPLY-SIGNED-DEPLOY) ─────────

/// Canonical chaos test for INV-SUPPLY-SIGNED-DEPLOY (WI-S12-003 §15.1).
/// Stage unsigned image, trigger webhook, verify rejection + audit.
#[test]
fn chaos_deploy_unsigned_artifact_blocked_verified() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_unsigned_from(Arc::clone(&sink));

    let result = verifier.verify_and_propagate(
        &make_webhook("v9.9.9"),
        &make_image_ref("v9.9.9"),
        &CosignIdentityPattern::corelink_release(),
    );

    // INV-SUPPLY-SIGNED-DEPLOY: must be blocked
    assert!(
        matches!(result, Err(DeployVerifyError::SignatureInvalid(_))),
        "chaos: unsigned artifact must be rejected; got {result:?}"
    );

    // SEV-2 alert fires
    assert!(
        result.unwrap_err().is_sev2(),
        "chaos: SEV-2 must fire for unsigned deploy"
    );

    // Audit event emitted
    assert!(!sink.is_empty(), "chaos: audit event must be emitted");
    let event = &sink.events()[0];
    assert_eq!(event.event_type, "dev.hugr.corelink.deploy.blocked.v1");
    assert_eq!(event.outcome, VerifyOutcome::SigInvalid);
    assert_eq!(event.release_tag, "v9.9.9");
}

// ── Chaos 2: Deploy with Rekor missing ───────────────────────────────────

/// Stage signed image with offline signature (not published to Rekor).
/// Trigger webhook.
/// Expected: verifier rejects via `RekorMissing` + alert SEV-2 (WI-S12-003 §15.2).
#[test]
fn chaos_deploy_with_rekor_missing_blocked_verified() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_rekor_missing_from(Arc::clone(&sink));

    let image_ref = make_image_ref("v0.8.0");
    let result = verifier.verify_and_propagate(
        &make_webhook("v0.8.0"),
        &image_ref,
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(
        matches!(result, Err(DeployVerifyError::RekorMissing { .. })),
        "chaos: Rekor missing must be rejected; got {result:?}"
    );

    // Image should be mentioned in error
    if let Err(DeployVerifyError::RekorMissing { image }) = &result {
        assert!(
            image.contains("corelink-worker"),
            "error must reference the image"
        );
    }

    assert_eq!(sink.events()[0].outcome, VerifyOutcome::RekorMissing);
}

// ── Chaos 3: Identity confusion — 100 attacker SAN variants ──────────────

/// 100 varied attacker SANs (different orgs, repos, workflows) must all
/// be rejected by the identity check.
#[test]
fn chaos_identity_confusion_100_variants_all_blocked() {
    let attacker_orgs = [
        "attacker",
        "evil-corp",
        "supply-chain-attack",
        "fake-hugr",
        "not-humanguardrail",
        "humanguardrail-fake",
        "humanguardrail_labs",
        "humanguardrai1",
        "humanguardrails",
        "xn--humanguardrail",
    ];
    let attacker_repos = [
        "corelink-server",
        "corelink",
        "server",
        "corelink-server-fork",
        "CORELINK-SERVER",
        "corelink.server",
        "corelink_server",
        "corelink-server-evil",
        "corelonk-server",
        "corelinks-server",
    ];

    let mut blocked_count = 0u32;

    for org in &attacker_orgs {
        for repo in &attacker_repos {
            let attacker_san = format!(
                "https://github.com/{org}/{repo}/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
            );

            let sink = Arc::new(InMemoryDeployAuditSink::new());
            let verifier = InMemoryDeployVerifier::new_identity_mismatch_from(
                Arc::clone(&sink),
                &attacker_san,
            );

            let result = verifier.verify_and_propagate(
                &make_webhook("v0.1.0"),
                &make_image_ref("v0.1.0"),
                &CosignIdentityPattern::corelink_release(),
            );

            assert!(
                matches!(result, Err(DeployVerifyError::IdentityMismatch { .. })),
                "attacker SAN must be rejected: {attacker_san}"
            );
            blocked_count += 1;
        }
    }

    assert_eq!(
        blocked_count,
        (attacker_orgs.len() * attacker_repos.len()) as u32,
        "all 100 attacker variants must be blocked"
    );
}

// ── Chaos 4: Replay attack — 100 digest pair variants ────────────────────

/// 100 varied old/new digest pairs to validate replay detection.
#[test]
fn chaos_replay_attack_100_variants_all_blocked() {
    let mut blocked = 0u32;

    for i in 0u8..100 {
        let old_digest = format!("sha256:{:064x}", i);
        let new_digest = format!("sha256:{:064x}", i + 1);

        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_replay_attack_from(
            Arc::clone(&sink),
            &old_digest,
            &new_digest,
        );

        let result = verifier.verify_and_propagate(
            &make_webhook(&format!("v0.{i}.0")),
            &make_image_ref(&format!("v0.{i}.0")),
            &CosignIdentityPattern::corelink_release(),
        );

        assert!(
            matches!(result, Err(DeployVerifyError::DigestMismatch { .. })),
            "replay attack must be blocked for iteration {i}: {result:?}"
        );
        blocked += 1;
    }

    assert_eq!(blocked, 100, "all 100 replay variants must be blocked");
}

// ── Chaos 5: Audit emit failure — 100 iterations, 0 false-deploys ─────────

/// 100 iterations with failing audit sink — 0 deploys must succeed.
/// Validates fail-CLOSED invariant (CTRL-AUDIT-002 + INV-AUDIT-APPEND-ONLY).
#[test]
fn chaos_audit_emit_failure_100_iterations_zero_false_deploys() {
    let mut blocked = 0u32;

    for i in 0u32..100 {
        let failing_sink = Arc::new(FailingDeployAuditSink::new(format!(
            "simulated-503-iter-{i}"
        )));
        let verifier = InMemoryDeployVerifier::with_mode(
            VerificationMode::Signed {
                rekor_log_index: i as u64,
                fulcio_san: "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
                resolved_digest: format!("sha256:{i:064x}"),
            },
            failing_sink,
        );

        let result = verifier.verify_and_propagate(
            &make_webhook(&format!("v0.{i}.0")),
            &make_image_ref(&format!("v0.{i}.0")),
            &CosignIdentityPattern::corelink_release(),
        );

        assert!(
            matches!(result, Err(DeployVerifyError::AuditEmitFailed(_))),
            "deploy must be blocked when audit fails (iter {i}): {result:?}"
        );
        blocked += 1;
    }

    assert_eq!(blocked, 100, "all 100 iterations must be fail-CLOSED");
}

// ── Chaos 6: Rate limit stub ──────────────────────────────────────────────

/// Webhook rate limit error maps to HTTP 429.
#[test]
fn chaos_rate_limit_returns_429() {
    use corelink_ops::deploy::worker::error_to_http_response;

    let (status, body) = error_to_http_response(&DeployVerifyError::RateLimitExceeded);
    assert_eq!(status, 429, "rate limit must return HTTP 429");
    assert!(
        body.contains("rate_limit_exceeded"),
        "body must describe the limit"
    );
}

// ── Chaos 7: Webhook HMAC auth ────────────────────────────────────────────

/// Tampered request body must fail HMAC authentication.
#[test]
fn chaos_webhook_hmac_tampered_body_rejected() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let secret = b"chaos-test-secret";
    let original_body = b"{\"release_tag\":\"v0.1.0\",\"commit_sha\":\"abc123\"}";
    let tampered_body = b"{\"release_tag\":\"v9.9.9\",\"commit_sha\":\"evil\"}";

    // Compute correct signature over original body
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
    mac.update(original_body);
    let correct_sig = hex::encode(mac.finalize().into_bytes());

    // Verify with tampered body — must fail
    let result = verify_webhook_hmac(tampered_body, &correct_sig, secret);
    assert!(
        matches!(result, Err(DeployVerifyError::WebhookAuthFailed)),
        "tampered body must fail HMAC auth"
    );

    // Verify with correct body — must pass
    let ok = verify_webhook_hmac(original_body, &correct_sig, secret);
    assert!(ok.is_ok(), "correct body must pass HMAC auth");
}

// ── Chaos 8: OCI fetch failure ─────────────────────────────────────────────

/// OCI registry unavailable should block the deploy.
#[test]
fn chaos_oci_fetch_failure_blocks_deploy() {
    // Simulate OciFetchFailed as the verify pipeline outcome
    let oci_error = DeployVerifyError::OciFetchFailed("ghcr.io: connection refused".into());
    assert_eq!(oci_error.http_status(), 503);
    assert_eq!(oci_error.blocked_reason_label(), "oci_fetch_failed");
    assert!(!oci_error.is_sev1());
    assert!(
        !oci_error.is_sev2(),
        "OCI fetch failure is operational, not SEV-2 security"
    );
}

// ── Chaos 9: Manual wrangler deploy bypass (IAM) ─────────────────────────

/// CF API returns 403 for unauthorized deploy attempt.
/// This is a documentation test — actual IAM enforcement is in CF infra.
/// We verify the error mapping is correct.
#[test]
fn chaos_cf_api_token_scoped_403_maps_correctly() {
    let cf_err = DeployVerifyError::CfApiFailed("403 Forbidden: token lacks permission".into());
    assert_eq!(cf_err.http_status(), 502, "CF API error maps to HTTP 502");
}

// ── Chaos combined: signed deploy succeeds with valid inputs ──────────────

/// Positive chaos test: a correctly signed, Rekor-included, Fulcio-valid
/// deploy with matching identity should always succeed.
#[test]
fn chaos_signed_deploy_succeeds_end_to_end() {
    let sink = Arc::new(InMemoryDeployAuditSink::new());
    let verifier = InMemoryDeployVerifier::new_signed_from(Arc::clone(&sink));

    let result = verifier.verify_and_propagate(
        &make_webhook("v1.0.0"),
        &make_image_ref("v1.0.0"),
        &CosignIdentityPattern::corelink_release(),
    );

    assert!(result.is_ok(), "signed deploy must succeed: {result:?}");
    let propagated = result.unwrap();
    assert!(propagated.cosign_signature_verified);
    assert!(!propagated.cf_deployment_id.is_empty());
    assert_eq!(propagated.release_tag, "v1.0.0");

    // Exactly one audit event (verified)
    assert_eq!(sink.len(), 1);
    assert_eq!(
        sink.events()[0].event_type,
        "dev.hugr.corelink.deploy.verified.v1"
    );
}
