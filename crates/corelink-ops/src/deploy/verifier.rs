//! [`DeployVerifier`] implementations.
//!
//! # Implementations
//!
//! - [`InMemoryDeployVerifier`] — fully in-process verifier for testing.
//!   Supports two construction modes:
//!   - `new_signed`: all checks pass, simulating a valid signed deploy.
//!   - `new_unsigned`: Cosign signature check fails, simulating an unsigned deploy.
//!   - `new_rekor_missing`: signature present but Rekor lookup fails.
//!   - `new_fulcio_invalid`: Fulcio chain validation fails.
//!   - `new_identity_mismatch`: SAN URI identity check fails.
//!
//! Production integration uses the Cloudflare Workers runtime and the `sigstore`
//! Rust crate for cryptographic verification (not bundled here — see §6.2 anti-scope
//! and §7 anti-patterns: ❌ Custom Cosign client).

use std::sync::Arc;
use std::time::SystemTime;

use tracing::{error, info, warn};
use uuid::Uuid;

use super::audit::{alert_sev1_audit_emit_failed, alert_sev2_deploy_blocked, DeployAuditSink};
use super::cf_api::{CfApiClient, PropagateResult};
use super::error::DeployVerifyError;
use super::types::{
    CfDeployWebhook, CosignIdentityPattern, DeployAuditEvent, DeployPropagated, OciImageRef,
    VerifyOutcome,
};
use super::DeployVerifier;

// ── PROPTEST_CASES env-var fn ─────────────────────────────────────────────

/// Returns the number of proptest cases to run.
///
/// Reads `PROPTEST_CASES` environment variable; falls back to `default`.
/// Used by property tests to switch between 10k (PR) and 100k (nightly).
pub fn proptest_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

// ── InMemory verifier ─────────────────────────────────────────────────────

/// Verification mode for [`InMemoryDeployVerifier`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerificationMode {
    /// All checks pass — simulates a valid signed deploy.
    Signed {
        /// Rekor log index to embed in the propagated result.
        rekor_log_index: u64,
        /// Fulcio SAN URI to embed in the propagated result.
        fulcio_san: String,
        /// Image digest resolved by the OCI fetch.
        resolved_digest: String,
    },
    /// Cosign signature missing or invalid.
    Unsigned,
    /// Signature present but Rekor inclusion proof unavailable.
    RekorMissing,
    /// Fulcio certificate chain invalid.
    FulcioInvalid,
    /// SAN URI does not match expected identity.
    IdentityMismatch {
        /// Attacker SAN URI to embed in error.
        got_san: String,
    },
    /// Replay attack: signature bound to different image digest.
    ReplayAttack {
        /// Digest in the Cosign signature (attacker's old version).
        signed_digest: String,
        /// Digest resolved from the OCI registry (current release).
        resolved_digest: String,
    },
}

/// In-process deploy verifier for testing and staging.
///
/// Thread-safe via `Arc<dyn DeployAuditSink>`.  Supports injecting a failing
/// audit sink to validate fail-CLOSED behaviour.
///
/// # Example
///
/// ```rust
/// use corelink_ops::deploy::{
///     audit::InMemoryDeployAuditSink,
///     verifier::{InMemoryDeployVerifier, VerificationMode},
///     types::{CfDeployWebhook, OciImageRef, CosignIdentityPattern, DeployTarget, GitHubActor},
///     DeployVerifier,
/// };
/// use std::sync::Arc;
///
/// let sink = Arc::new(InMemoryDeployAuditSink::new());
/// let verifier = InMemoryDeployVerifier::new_signed_from(Arc::clone(&sink));
///
/// let webhook = CfDeployWebhook::new(
///     "v0.1.0",
///     "deadbeef".repeat(5),
///     "refs/tags/v0.1.0",
///     DeployTarget::new("corelink-worker", "a".repeat(32), "corelink-api.humangr.com/*"),
///     GitHubActor::new(
///         "github-actions[bot]",
///         "HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0",
///     ),
/// );
/// let image_ref = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:v0.1.0");
/// let identity = CosignIdentityPattern::corelink_release();
///
/// let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);
/// assert!(result.is_ok());
/// assert_eq!(sink.len(), 1);
/// ```
pub struct InMemoryDeployVerifier {
    mode: VerificationMode,
    audit_sink: Arc<dyn DeployAuditSink>,
    cf_client: InMemoryCfApiClient,
}

impl std::fmt::Debug for InMemoryDeployVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryDeployVerifier")
            .field("mode", &self.mode)
            .field("cf_client", &self.cf_client)
            .finish_non_exhaustive()
    }
}

impl InMemoryDeployVerifier {
    /// Construct a verifier that simulates a fully valid signed deploy.
    pub fn new_signed(audit_sink: Arc<dyn DeployAuditSink>) -> Self {
        Self {
            mode: VerificationMode::Signed {
                rekor_log_index: 123_456_789,
                fulcio_san: "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
                resolved_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            },
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier that simulates a fully valid signed deploy from a concrete sink.
    ///
    /// This is a convenience constructor that wraps a concrete sink type in `Arc<dyn DeployAuditSink>`.
    pub fn new_signed_from<S: DeployAuditSink + 'static>(audit_sink: Arc<S>) -> Self {
        Self::new_signed(audit_sink as Arc<dyn DeployAuditSink>)
    }

    /// Construct a verifier that simulates an unsigned artifact (no Cosign signature).
    pub fn new_unsigned(audit_sink: Arc<dyn DeployAuditSink>) -> Self {
        Self {
            mode: VerificationMode::Unsigned,
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier for unsigned simulation from a concrete sink.
    pub fn new_unsigned_from<S: DeployAuditSink + 'static>(audit_sink: Arc<S>) -> Self {
        Self::new_unsigned(audit_sink as Arc<dyn DeployAuditSink>)
    }

    /// Construct a verifier that simulates Rekor inclusion proof missing.
    pub fn new_rekor_missing(audit_sink: Arc<dyn DeployAuditSink>) -> Self {
        Self {
            mode: VerificationMode::RekorMissing,
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier for Rekor missing simulation from a concrete sink.
    pub fn new_rekor_missing_from<S: DeployAuditSink + 'static>(audit_sink: Arc<S>) -> Self {
        Self::new_rekor_missing(audit_sink as Arc<dyn DeployAuditSink>)
    }

    /// Construct a verifier that simulates Fulcio chain invalid.
    pub fn new_fulcio_invalid(audit_sink: Arc<dyn DeployAuditSink>) -> Self {
        Self {
            mode: VerificationMode::FulcioInvalid,
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier for Fulcio invalid simulation from a concrete sink.
    pub fn new_fulcio_invalid_from<S: DeployAuditSink + 'static>(audit_sink: Arc<S>) -> Self {
        Self::new_fulcio_invalid(audit_sink as Arc<dyn DeployAuditSink>)
    }

    /// Construct a verifier that simulates identity mismatch (fork attack).
    pub fn new_identity_mismatch(
        audit_sink: Arc<dyn DeployAuditSink>,
        got_san: impl Into<String>,
    ) -> Self {
        Self {
            mode: VerificationMode::IdentityMismatch {
                got_san: got_san.into(),
            },
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier for identity mismatch simulation from a concrete sink.
    pub fn new_identity_mismatch_from<S: DeployAuditSink + 'static>(
        audit_sink: Arc<S>,
        got_san: impl Into<String>,
    ) -> Self {
        Self::new_identity_mismatch(audit_sink as Arc<dyn DeployAuditSink>, got_san)
    }

    /// Construct a verifier that simulates a replay attack (TOCTOU).
    pub fn new_replay_attack(
        audit_sink: Arc<dyn DeployAuditSink>,
        signed_digest: impl Into<String>,
        resolved_digest: impl Into<String>,
    ) -> Self {
        Self {
            mode: VerificationMode::ReplayAttack {
                signed_digest: signed_digest.into(),
                resolved_digest: resolved_digest.into(),
            },
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Construct a verifier for replay attack simulation from a concrete sink.
    pub fn new_replay_attack_from<S: DeployAuditSink + 'static>(
        audit_sink: Arc<S>,
        signed_digest: impl Into<String>,
        resolved_digest: impl Into<String>,
    ) -> Self {
        Self::new_replay_attack(
            audit_sink as Arc<dyn DeployAuditSink>,
            signed_digest,
            resolved_digest,
        )
    }

    /// Construct a verifier with a custom mode and audit sink.
    pub fn with_mode(mode: VerificationMode, audit_sink: Arc<dyn DeployAuditSink>) -> Self {
        Self {
            mode,
            audit_sink,
            cf_client: InMemoryCfApiClient::new_ok(),
        }
    }

    /// Internal: run the verification pipeline.
    ///
    /// Returns `Ok(VerifyOutcome::Ok)` or the appropriate blocking outcome.
    fn run_verify_pipeline(
        &self,
        webhook: &CfDeployWebhook,
        cosign_image_ref: &OciImageRef,
        expected_identity: &CosignIdentityPattern,
    ) -> Result<(u64, String, String), DeployVerifyError> {
        match &self.mode {
            VerificationMode::Unsigned => {
                warn!(
                    release_tag = %webhook.release_tag,
                    image = %cosign_image_ref.image,
                    "Cosign signature missing — deploy blocked"
                );
                Err(DeployVerifyError::SignatureInvalid(
                    "no Cosign signature found in OCI registry".to_string(),
                ))
            }

            VerificationMode::RekorMissing => {
                warn!(
                    release_tag = %webhook.release_tag,
                    image = %cosign_image_ref.image,
                    "Rekor inclusion proof missing — deploy blocked (INV-SUPPLY-PROVENANCE-IN-REKOR)"
                );
                Err(DeployVerifyError::RekorMissing {
                    image: cosign_image_ref.image.clone(),
                })
            }

            VerificationMode::FulcioInvalid => {
                warn!(
                    release_tag = %webhook.release_tag,
                    "Fulcio chain invalid — deploy blocked"
                );
                Err(DeployVerifyError::FulcioChainInvalid(
                    "certificate not anchored to sigstore Fulcio root (TUF-pinned)".to_string(),
                ))
            }

            VerificationMode::IdentityMismatch { got_san } => {
                warn!(
                    release_tag = %webhook.release_tag,
                    got = %got_san,
                    expected_pattern = %expected_identity.pattern,
                    "Identity mismatch — fork attack rejected"
                );
                Err(DeployVerifyError::IdentityMismatch {
                    got: got_san.clone(),
                    expected: expected_identity.pattern.clone(),
                })
            }

            VerificationMode::ReplayAttack {
                signed_digest,
                resolved_digest,
            } => {
                warn!(
                    release_tag = %webhook.release_tag,
                    signed_digest = %signed_digest,
                    resolved_digest = %resolved_digest,
                    "Image digest mismatch — replay attack detected (TOCTOU)"
                );
                Err(DeployVerifyError::DigestMismatch {
                    signed_digest: signed_digest.clone(),
                    resolved_digest: resolved_digest.clone(),
                })
            }

            VerificationMode::Signed {
                rekor_log_index,
                fulcio_san,
                resolved_digest,
            } => {
                // Validate identity pattern (structural check, wasm32-safe)
                if !expected_identity.matches_simple(fulcio_san) {
                    warn!(
                        release_tag = %webhook.release_tag,
                        san = %fulcio_san,
                        "Identity pattern mismatch in signed mode"
                    );
                    return Err(DeployVerifyError::IdentityMismatch {
                        got: fulcio_san.clone(),
                        expected: expected_identity.pattern.clone(),
                    });
                }
                info!(
                    release_tag = %webhook.release_tag,
                    rekor_log_index = %rekor_log_index,
                    fulcio_san = %fulcio_san,
                    image = %cosign_image_ref.image,
                    "Cosign verify OK: signature + Rekor inclusion + Fulcio chain valid"
                );
                Ok((
                    *rekor_log_index,
                    fulcio_san.clone(),
                    resolved_digest.clone(),
                ))
            }
        }
    }
}

impl DeployVerifier for InMemoryDeployVerifier {
    fn verify_and_propagate(
        &self,
        webhook: &CfDeployWebhook,
        cosign_image_ref: &OciImageRef,
        expected_identity: &CosignIdentityPattern,
    ) -> Result<DeployPropagated, DeployVerifyError> {
        let trace_id = Uuid::now_v7().to_string();

        // Step 1-6: run verification pipeline
        let pipeline_result =
            self.run_verify_pipeline(webhook, cosign_image_ref, expected_identity);

        match pipeline_result {
            Err(ref verify_err) => {
                // Determine audit outcome from error
                let outcome = match verify_err {
                    DeployVerifyError::SignatureInvalid(_) => VerifyOutcome::SigInvalid,
                    DeployVerifyError::RekorMissing { .. } => VerifyOutcome::RekorMissing,
                    DeployVerifyError::FulcioChainInvalid(_) => VerifyOutcome::FulcioInvalid,
                    DeployVerifyError::IdentityMismatch { .. } => VerifyOutcome::IdentityMismatch,
                    DeployVerifyError::DigestMismatch { .. } => VerifyOutcome::SigInvalid,
                    DeployVerifyError::OciFetchFailed(_) => VerifyOutcome::OciFetchFailed,
                    _ => VerifyOutcome::SigInvalid,
                };

                // Emit blocked audit event (fail-CLOSED)
                let audit_event = DeployAuditEvent::blocked(
                    webhook.release_tag.clone(),
                    outcome,
                    trace_id.clone(),
                );
                if let Err(audit_err) = self.emit_audit_event(audit_event) {
                    // Audit emit failed — SEV-1
                    alert_sev1_audit_emit_failed(&webhook.release_tag, &audit_err);
                    return Err(audit_err);
                }

                // Fire SEV-2 alert for blocked deploy
                if verify_err.is_sev2() {
                    alert_sev2_deploy_blocked(
                        &webhook.release_tag,
                        verify_err.blocked_reason_label(),
                        verify_err,
                    );
                }

                Err(verify_err.clone_for_propagation())
            }

            Ok((rekor_log_index, fulcio_cert_san, resolved_digest)) => {
                // Step 7: emit audit event BEFORE propagating (fail-CLOSED)
                let audit_event =
                    DeployAuditEvent::verified(webhook.release_tag.clone(), trace_id.clone());
                if let Err(audit_err) = self.emit_audit_event(audit_event) {
                    // Audit emit failed — SEV-1, deploy blocked
                    alert_sev1_audit_emit_failed(&webhook.release_tag, &audit_err);
                    return Err(audit_err);
                }

                // Step 8: propagate to Cloudflare API with pinned digest
                let cf_result = self
                    .cf_client
                    .propagate(&webhook.deploy_target.script_name, &resolved_digest)?;

                info!(
                    release_tag = %webhook.release_tag,
                    cf_deployment_id = %cf_result.deployment_id,
                    "Deploy propagated successfully"
                );

                Ok(DeployPropagated {
                    release_tag: webhook.release_tag.clone(),
                    cosign_signature_verified: true,
                    rekor_log_index,
                    fulcio_cert_san,
                    propagated_at: SystemTime::now(),
                    cf_deployment_id: cf_result.deployment_id,
                })
            }
        }
    }

    fn emit_audit_event(&self, event: DeployAuditEvent) -> Result<(), DeployVerifyError> {
        self.audit_sink.emit(event)
    }
}

// ── DeployVerifyError: clone for propagation ─────────────────────────────

/// Extension: clone-like conversion for returning the original error after
/// side-effects (audit emit, alert) have been performed.
///
/// `DeployVerifyError` is not `Clone` because `thiserror` errors generally
/// aren't.  We construct a semantically equivalent variant here.
trait CloneForPropagation {
    /// Return a propagatable copy of this error.
    fn clone_for_propagation(&self) -> Self;
}

impl CloneForPropagation for DeployVerifyError {
    fn clone_for_propagation(&self) -> Self {
        match self {
            Self::SignatureInvalid(msg) => Self::SignatureInvalid(msg.clone()),
            Self::RekorMissing { image } => Self::RekorMissing {
                image: image.clone(),
            },
            Self::FulcioChainInvalid(msg) => Self::FulcioChainInvalid(msg.clone()),
            Self::IdentityMismatch { got, expected } => Self::IdentityMismatch {
                got: got.clone(),
                expected: expected.clone(),
            },
            Self::OciFetchFailed(msg) => Self::OciFetchFailed(msg.clone()),
            Self::CfApiFailed(msg) => Self::CfApiFailed(msg.clone()),
            Self::AuditEmitFailed(msg) => Self::AuditEmitFailed(msg.clone()),
            Self::DigestMismatch {
                signed_digest,
                resolved_digest,
            } => Self::DigestMismatch {
                signed_digest: signed_digest.clone(),
                resolved_digest: resolved_digest.clone(),
            },
            Self::WebhookAuthFailed => Self::WebhookAuthFailed,
            Self::RateLimitExceeded => Self::RateLimitExceeded,
        }
    }
}

// ── InMemory CF API client ─────────────────────────────────────────────────

/// In-memory Cloudflare API client for testing.
#[derive(Debug)]
pub struct InMemoryCfApiClient {
    fail: bool,
}

impl InMemoryCfApiClient {
    /// Returns a client that always propagates successfully.
    pub fn new_ok() -> Self {
        Self { fail: false }
    }

    /// Returns a client that always returns a CF API error.
    pub fn new_failing() -> Self {
        Self { fail: true }
    }
}

impl CfApiClient for InMemoryCfApiClient {
    fn propagate(
        &self,
        script_name: &str,
        pinned_digest: &str,
    ) -> Result<PropagateResult, DeployVerifyError> {
        if self.fail {
            error!(
                script_name = %script_name,
                "CF API propagation failed (simulated)"
            );
            return Err(DeployVerifyError::CfApiFailed(
                "CF API unavailable (simulated)".to_string(),
            ));
        }
        let deployment_id = format!(
            "dep-{}-{}",
            script_name,
            &pinned_digest[..8.min(pinned_digest.len())]
        );
        info!(
            script_name = %script_name,
            pinned_digest = %pinned_digest,
            deployment_id = %deployment_id,
            "CF API: deploy propagated (in-memory)"
        );
        Ok(PropagateResult { deployment_id })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::super::audit::InMemoryDeployAuditSink;
    use super::super::types::{DeployTarget, GitHubActor};
    use super::*;

    fn make_webhook(tag: &str) -> CfDeployWebhook {
        CfDeployWebhook::new(
            tag,
            "abc123def456abc123def456abc123def456abc1",
            format!("refs/tags/{tag}"),
            DeployTarget::new("corelink-worker", "a".repeat(32), "corelink-api.humangr.com/*"),
            GitHubActor::new(
                "github-actions[bot]",
                format!("HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/{tag}"),
            ),
        )
    }

    fn make_image_ref(tag: &str) -> OciImageRef {
        OciImageRef::from_tag(format!("ghcr.io/HumanGuardrail/corelink-worker:{tag}"))
    }

    #[test]
    fn signed_deploy_succeeds_and_emits_audit() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_signed_from(Arc::clone(&sink));
        let webhook = make_webhook("v0.1.0");
        let image_ref = make_image_ref("v0.1.0");
        let identity = CosignIdentityPattern::corelink_release();

        let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);
        assert!(result.is_ok(), "signed deploy must succeed: {result:?}");
        let propagated = result.unwrap();
        assert!(propagated.cosign_signature_verified);
        assert_eq!(propagated.release_tag, "v0.1.0");
        assert!(!propagated.cf_deployment_id.is_empty());
        assert_eq!(sink.len(), 1);
        let event = &sink.events()[0];
        assert_eq!(event.event_type, "dev.hugr.corelink.deploy.verified.v1");
    }

    #[test]
    fn unsigned_deploy_blocked_and_emits_blocked_audit() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_unsigned_from(Arc::clone(&sink));
        let webhook = make_webhook("v0.1.0");
        let image_ref = make_image_ref("v0.1.0");
        let identity = CosignIdentityPattern::corelink_release();

        let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);
        assert!(matches!(
            result,
            Err(DeployVerifyError::SignatureInvalid(_))
        ));
        assert_eq!(sink.len(), 1);
        let event = &sink.events()[0];
        assert_eq!(event.event_type, "dev.hugr.corelink.deploy.blocked.v1");
        assert_eq!(event.outcome, VerifyOutcome::SigInvalid);
    }

    #[test]
    fn rekor_missing_blocked() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_rekor_missing_from(Arc::clone(&sink));
        let webhook = make_webhook("v0.2.0");
        let image_ref = make_image_ref("v0.2.0");
        let identity = CosignIdentityPattern::corelink_release();

        let result = verifier.verify_and_propagate(&webhook, &image_ref, &identity);
        assert!(matches!(
            result,
            Err(DeployVerifyError::RekorMissing { .. })
        ));
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.events()[0].outcome, VerifyOutcome::RekorMissing);
    }

    #[test]
    fn fulcio_invalid_blocked() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_fulcio_invalid_from(Arc::clone(&sink));
        let result = verifier.verify_and_propagate(
            &make_webhook("v0.3.0"),
            &make_image_ref("v0.3.0"),
            &CosignIdentityPattern::corelink_release(),
        );
        assert!(matches!(
            result,
            Err(DeployVerifyError::FulcioChainInvalid(_))
        ));
        assert_eq!(sink.events()[0].outcome, VerifyOutcome::FulcioInvalid);
    }

    #[test]
    fn identity_mismatch_blocked() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_identity_mismatch_from(
            Arc::clone(&sink),
            "https://github.com/attacker/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0",
        );
        let result = verifier.verify_and_propagate(
            &make_webhook("v0.1.0"),
            &make_image_ref("v0.1.0"),
            &CosignIdentityPattern::corelink_release(),
        );
        assert!(matches!(
            result,
            Err(DeployVerifyError::IdentityMismatch { .. })
        ));
        assert_eq!(sink.events()[0].outcome, VerifyOutcome::IdentityMismatch);
    }

    #[test]
    fn replay_attack_blocked() {
        let sink = Arc::new(InMemoryDeployAuditSink::new());
        let verifier = InMemoryDeployVerifier::new_replay_attack_from(
            Arc::clone(&sink),
            "sha256:old_digest_from_v0_1_0",
            "sha256:new_digest_for_v0_2_0",
        );
        let result = verifier.verify_and_propagate(
            &make_webhook("v0.2.0"),
            &make_image_ref("v0.2.0"),
            &CosignIdentityPattern::corelink_release(),
        );
        assert!(matches!(
            result,
            Err(DeployVerifyError::DigestMismatch { .. })
        ));
    }
}
