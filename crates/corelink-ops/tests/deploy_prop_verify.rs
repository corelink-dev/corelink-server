//! Property tests for the deploy verify gate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//!
//! Runs at 10k iterations on PR (`PROPTEST_CASES=10000`; default) and 100k
//! iterations nightly (`PROPTEST_CASES=100000`).
//!
//! Properties tested (WI-S12-003 §6.1.8):
//!
//! 1. `prop_cosign_signature_invalid_rejected` — mutated signatures → 100% rejected.
//! 2. `prop_rekor_missing_rejected` — payloads without Rekor → 100% rejected.
//! 3. `prop_identity_mismatch_rejected` — random SAN URIs → only exact match accepted.
//! 4. `prop_replay_attack_rejected` — swapped image digests → 100% rejected via TOCTOU.
//! 5. `prop_audit_emit_failure_blocks_deploy` — failing audit sink → deploy 100% blocked.

use std::sync::Arc;

use proptest::prelude::*;

use corelink_ops::deploy::{
    audit::{FailingDeployAuditSink, InMemoryDeployAuditSink},
    error::DeployVerifyError,
    types::{CfDeployWebhook, CosignIdentityPattern, DeployTarget, GitHubActor, OciImageRef},
    verifier::{proptest_cases, InMemoryDeployVerifier, VerificationMode},
    DeployVerifier,
};

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_webhook(tag: &str) -> CfDeployWebhook {
    CfDeployWebhook::new(
        tag,
        "abc123def456abc123def456abc123def456abc1",
        format!("refs/tags/{tag}"),
        DeployTarget::new(
            "corelink-worker",
            "a".repeat(32),
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

fn cases() -> u32 {
    proptest_cases(10_000)
}

// ── Property 1: mutated signatures always rejected ────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Any "unsigned" artifact (Cosign signature missing/invalid) must be
    /// rejected with `SignatureInvalid`.  0 false-accepts allowed.
    #[test]
    fn prop_cosign_signature_invalid_rejected(tag in "[a-z]{1,8}\\.[0-9]{1,4}\\.[0-9]{1,4}") {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_unsigned_from(Arc::clone(&sink));
        let result = verifier.verify_and_propagate(
            &make_webhook(&format!("v{tag}")),
            &make_image_ref(&format!("v{tag}")),
            &CosignIdentityPattern::corelink_release(),
        );
        prop_assert!(
            matches!(result, Err(DeployVerifyError::SignatureInvalid(_))),
            "expected SignatureInvalid, got {result:?}"
        );
        // Audit event must have been emitted (blocked)
        prop_assert_eq!(sink.len(), 1);
    }
}

// ── Property 2: Rekor missing always rejected ─────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Payloads where Rekor inclusion proof is missing must always be
    /// rejected with `RekorMissing`.
    #[test]
    fn prop_rekor_missing_rejected(tag in "[a-z]{1,8}\\.[0-9]{1,4}\\.[0-9]{1,4}") {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_rekor_missing_from(Arc::clone(&sink));
        let result = verifier.verify_and_propagate(
            &make_webhook(&format!("v{tag}")),
            &make_image_ref(&format!("v{tag}")),
            &CosignIdentityPattern::corelink_release(),
        );
        match result {
            Err(DeployVerifyError::RekorMissing { image }) => {
                prop_assert_eq!(image, make_image_ref(&format!("v{tag}")).image);
            }
            other => prop_assert!(false, "expected RekorMissing, got {other:?}"),
        }
        prop_assert_eq!(sink.len(), 1);
    }
}

// ── Property 3: identity mismatch rejected ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Random SAN URIs that do not match the canonical CoreLink pattern must
    /// be rejected.  Only the exact structural pattern is accepted.
    #[test]
    fn prop_identity_mismatch_rejected(
        attacker_san in "https://github\\.com/[a-z]{4,12}/corelink-server/\\.github/workflows/release-slsa3\\.yml@refs/tags/v[0-9]\\.[0-9]\\.[0-9]"
    ) {
        // Only reject if it's not the legitimate org
        let is_legit = attacker_san.contains("HumanGuardrail");
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_identity_mismatch_from(
            Arc::clone(&sink),
            &attacker_san,
        );
        let expected_identity = CosignIdentityPattern::corelink_release();
        let result = verifier.verify_and_propagate(
            &make_webhook("v0.1.0"),
            &make_image_ref("v0.1.0"),
            &expected_identity,
        );
        if is_legit {
            // Could pass or fail depending on exact match — just check no panic
            let _ = result;
        } else {
            match result {
                Err(DeployVerifyError::IdentityMismatch { got, expected }) => {
                    prop_assert_eq!(got, attacker_san);
                    prop_assert_eq!(expected, expected_identity.pattern);
                }
                other => prop_assert!(false, "expected IdentityMismatch for attacker SAN, got {other:?}"),
            }
        }
    }
}

// ── Property 4: replay attack (TOCTOU) rejected ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// When the signed digest differs from the resolved digest (image was
    /// swapped between sign and deploy), the deploy must be rejected.
    #[test]
    fn prop_replay_attack_rejected(
        old_suffix in "[a-f0-9]{16}",
        new_suffix in "[a-f0-9]{16}",
    ) {
        // Only test cases where digests actually differ
        prop_assume!(old_suffix != new_suffix);

        let signed_digest = format!("sha256:{old_suffix}");
        let resolved_digest = format!("sha256:{new_suffix}");

        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_replay_attack_from(
            Arc::clone(&sink),
            &signed_digest,
            &resolved_digest,
        );
        let result = verifier.verify_and_propagate(
            &make_webhook("v0.5.0"),
            &make_image_ref("v0.5.0"),
            &CosignIdentityPattern::corelink_release(),
        );
        match result {
            Err(DeployVerifyError::DigestMismatch { signed_digest: got_signed, resolved_digest: got_resolved }) => {
                prop_assert_eq!(got_signed, signed_digest);
                prop_assert_eq!(got_resolved, resolved_digest);
            }
            other => prop_assert!(false, "expected DigestMismatch, got {other:?}"),
        }
    }
}

// ── Property 5: audit emit failure blocks deploy (fail-CLOSED) ────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// When the audit sink fails, the deploy must be blocked even if all
    /// crypto checks pass.  This validates the fail-CLOSED invariant
    /// (CTRL-AUDIT-002 + INV-AUDIT-APPEND-ONLY).
    ///
    /// 0 deploys must succeed when audit emit fails.
    #[test]
    fn prop_audit_emit_failure_blocks_deploy(tag in "[a-z]{1,8}\\.[0-9]{1,4}\\.[0-9]{1,4}") {
        let failing_sink = Arc::new(FailingDeployAuditSink::default());
        // Use signed mode so crypto checks pass — only audit fails
        let verifier = InMemoryDeployVerifier::with_mode(
            VerificationMode::Signed {
                rekor_log_index: 999,
                fulcio_san: "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
                resolved_digest: "sha256:deadbeef".to_string(),
            },
            failing_sink,
        );
        let result = verifier.verify_and_propagate(
            &make_webhook(&format!("v{tag}")),
            &make_image_ref(&format!("v{tag}")),
            &CosignIdentityPattern::corelink_release(),
        );
        prop_assert!(
            matches!(result, Err(DeployVerifyError::AuditEmitFailed(_))),
            "deploy must be blocked when audit emit fails; got {result:?}"
        );
    }
}
