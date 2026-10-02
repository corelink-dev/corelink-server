//! # corelink-deploy-verifier
//!
//! Cloudflare Workers deploy webhook verifier — **hard gate non-bypassable**.
//!
//! Implements the deploy verify gate from WI-S12-003: every `POST /webhook/deploy`
//! request is authenticated via HMAC-SHA256, then the Cosign signature + Rekor
//! inclusion proof + Fulcio certificate chain are validated before the Cloudflare
//! Workers rollout is propagated.
//!
//! ## Design invariants
//!
//! - **INV-SUPPLY-SIGNED-DEPLOY** (CRITICAL): unsigned artifact = blocked deploy.
//! - **INV-SUPPLY-PROVENANCE-IN-REKOR** (HIGH): no Rekor inclusion = blocked.
//! - **INV-AUDIT-APPEND-ONLY** (CRITICAL): audit emit is fail-CLOSED.
//! - **NO bypass mode**: no "emergency override", no soft-fail, no cache reuse.
//!
//! ## Quick start
//!
//! ```rust
//! use corelink_ops::deploy::{
//!     types::{CfDeployWebhook, OciImageRef, CosignIdentityPattern, DeployTarget, GitHubActor},
//!     verifier::InMemoryDeployVerifier,
//!     audit::InMemoryDeployAuditSink,
//!     DeployVerifier,
//! };
//! use std::sync::Arc;
//!
//! let sink = Arc::new(InMemoryDeployAuditSink::new());
//! let verifier = InMemoryDeployVerifier::new_signed(sink);
//!
//! let webhook = CfDeployWebhook::new(
//!     "v0.1.0",
//!     "abc123def456abc123def456abc123def456abc1",
//!     "refs/tags/v0.1.0",
//!     DeployTarget::new("corelink-worker", "a".repeat(32), "corelink-api.humangr.com/*"),
//!     GitHubActor::new(
//!         "github-actions[bot]",
//!         "HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0",
//!     ),
//! );
//! let image_ref = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:v0.1.0");
//! let identity = CosignIdentityPattern::corelink_release();
//!
//! // Validate types compile correctly; in real usage call verify_and_propagate.
//! let _ = (webhook, image_ref, identity, verifier);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod audit;
pub mod cf_api;
pub mod error;
pub mod types;
pub mod verifier;
pub mod worker;

use self::error::DeployVerifyError;
use self::types::{
    CfDeployWebhook, CosignIdentityPattern, DeployAuditEvent, DeployPropagated, OciImageRef,
};

/// Core trait for the deploy verify gate.
///
/// All implementations **must** be fail-CLOSED: any check failure blocks the
/// deploy.  There is **no** bypass mode (§7 anti-patterns, ADR-0025).
///
/// # Contract
///
/// 1. Authenticate the webhook HMAC before any crypto verification.
/// 2. Fetch Cosign signature from OCI registry.
/// 3. Validate Rekor inclusion proof (mandatory; no grace period).
/// 4. Validate Fulcio certificate chain (TUF-pinned root).
/// 5. Validate SAN URI against `expected_identity` pattern.
/// 6. Validate image digest binding (TOCTOU prevention).
/// 7. Emit audit event (fail-CLOSED: emit failure = deploy blocked).
/// 8. Propagate to Cloudflare API using pinned digest (not floating tag).
pub trait DeployVerifier: Send + Sync {
    /// Verify deploy artifact signature + Rekor inclusion + Fulcio chain,
    /// then propagate to the Cloudflare API if all checks pass.
    ///
    /// **Hard gate**: rejects deploy if **any** check fails.  No bypass mode.
    ///
    /// # Errors
    ///
    /// Returns [`DeployVerifyError::SignatureInvalid`] if Cosign signature is
    /// absent or cryptographically invalid.
    ///
    /// Returns [`DeployVerifyError::RekorMissing`] if the Rekor inclusion proof
    /// cannot be fetched.  This is **intentional** during Rekor outages — the
    /// release is blocked per INV-SUPPLY-PROVENANCE-IN-REKOR.
    ///
    /// Returns [`DeployVerifyError::AuditEmitFailed`] if audit emit fails —
    /// deploy is **also** blocked (fail-CLOSED per CTRL-AUDIT-002).
    fn verify_and_propagate(
        &self,
        webhook: &CfDeployWebhook,
        cosign_image_ref: &OciImageRef,
        expected_identity: &CosignIdentityPattern,
    ) -> Result<DeployPropagated, DeployVerifyError>;

    /// Emit a deploy audit event (CloudEvents 1.0+).
    ///
    /// **Fail-CLOSED contract**: if emit fails the caller must block the deploy
    /// and fire an SEV-1 alert.  Implementors must never silently drop events.
    ///
    /// # Errors
    ///
    /// Returns [`DeployVerifyError::AuditEmitFailed`] on any persistence failure.
    fn emit_audit_event(&self, event: DeployAuditEvent) -> Result<(), DeployVerifyError>;
}
