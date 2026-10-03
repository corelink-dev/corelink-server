//! Core domain types for the Cloudflare Workers deploy webhook verifier.
//!
//! These types model the incoming deploy webhook payload, the deploy outcome
//! after signature verification, and the audit event emitted for every deploy
//! attempt (success or rejection).  All types are `#[non_exhaustive]` so
//! downstream crates cannot exhaustively match against them — breaking changes
//! require a major version bump per WI-S12-003 §14.s12.003.8.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Deploy target ──────────────────────────────────────────────────────────

/// Cloudflare Workers deployment target: script name, zone, and route pattern.
///
/// # Invariant
/// `script_name` must be a non-empty string; `zone_id` must be a 32-hex-char
/// Cloudflare zone ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeployTarget {
    /// Cloudflare Workers script name (e.g. `"corelink-worker"`).
    pub script_name: String,
    /// Cloudflare zone ID (32-hex-char string).
    pub zone_id: String,
    /// Route pattern (e.g. `"corelink-api.humangr.com/*"`).
    pub route_pattern: String,
}

impl DeployTarget {
    /// Construct a `DeployTarget`.
    pub fn new(
        script_name: impl Into<String>,
        zone_id: impl Into<String>,
        route_pattern: impl Into<String>,
    ) -> Self {
        Self {
            script_name: script_name.into(),
            zone_id: zone_id.into(),
            route_pattern: route_pattern.into(),
        }
    }
}

// ── GitHub actor ───────────────────────────────────────────────────────────

/// GitHub Actions actor that triggered the deploy webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitHubActor {
    /// GitHub login of the actor.
    pub login: String,
    /// OIDC workflow ref, e.g.
    /// `"HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"`.
    pub workflow_ref: String,
}

impl GitHubActor {
    /// Construct a `GitHubActor`.
    pub fn new(login: impl Into<String>, workflow_ref: impl Into<String>) -> Self {
        Self {
            login: login.into(),
            workflow_ref: workflow_ref.into(),
        }
    }
}

// ── Deploy webhook ─────────────────────────────────────────────────────────

/// Incoming Cloudflare deploy webhook payload.
///
/// Webhook is authenticated via HMAC-SHA256 (shared secret, rotation
/// quarterly per CTRL-AUTH-014).  Verification is performed in
/// [`super::worker`] before this struct is deserialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CfDeployWebhook {
    /// Release tag, e.g. `"v0.1.0"`.
    pub release_tag: String,
    /// Full commit SHA-256 hex (40-char lowercase).
    pub commit_sha: String,
    /// Git ref, e.g. `"refs/tags/v0.1.0"`.
    pub workflow_ref: String,
    /// Cloudflare Workers deployment target.
    pub deploy_target: DeployTarget,
    /// GitHub Actions identity that triggered this deploy.
    pub triggered_by: GitHubActor,
}

impl CfDeployWebhook {
    /// Construct a `CfDeployWebhook`.
    pub fn new(
        release_tag: impl Into<String>,
        commit_sha: impl Into<String>,
        workflow_ref: impl Into<String>,
        deploy_target: DeployTarget,
        triggered_by: GitHubActor,
    ) -> Self {
        Self {
            release_tag: release_tag.into(),
            commit_sha: commit_sha.into(),
            workflow_ref: workflow_ref.into(),
            deploy_target,
            triggered_by,
        }
    }
}

// ── OCI image reference ────────────────────────────────────────────────────

/// OCI image reference with optional digest pinning.
///
/// Cosign always signs the digest, not the tag.  After verification the
/// resolved digest is passed to the Cloudflare deploy API to prevent TOCTOU
/// (WI-S12-003 §2 threat 10).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OciImageRef {
    /// Registry + repository + tag, e.g.
    /// `"ghcr.io/HumanGuardrail/corelink-worker:v0.1.0"`.
    pub image: String,
    /// SHA-256 digest of the image manifest, e.g. `"sha256:abc123…"`.
    /// Set after OCI fetch; empty string means "not yet resolved".
    pub digest: String,
}

impl OciImageRef {
    /// Construct an `OciImageRef` with a floating tag (digest resolved later).
    pub fn from_tag(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            digest: String::new(),
        }
    }

    /// Construct an `OciImageRef` with a pinned digest.
    pub fn from_digest(image: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            digest: digest.into(),
        }
    }

    /// Returns `true` when the digest has been resolved.
    pub fn has_digest(&self) -> bool {
        !self.digest.is_empty()
    }
}

// ── Cosign identity pattern ────────────────────────────────────────────────

/// Expected SAN URI regex for Cosign identity verification.
///
/// The canonical pattern for CoreLink is:
/// ```text
/// ^https://github\.com/(?:HumanGuardrail|HuGR-Labs|HuGR-dev|corelink-dev)/corelink-server/\.github/workflows/release-slsa3\.yml@refs/tags/v\d+\.\d+\.\d+$
/// ```
///
/// `corelink-dev` is the current owner. `HumanGuardrail`, `HuGR-Labs` and
/// `HuGR-dev` owned the server repository before it was recreated under
/// `corelink-dev`; they stay in the alternation so artifacts they signed still
/// verify, and those names are never released.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CosignIdentityPattern {
    /// Raw regex string. It is compiled and full-string matched when checked;
    /// invalid patterns fail closed.
    pub pattern: String,
}

impl CosignIdentityPattern {
    /// Canonical identity pattern for CoreLink release pipeline.
    pub fn corelink_release() -> Self {
        Self {
            pattern: r"^https://github\.com/(?:HumanGuardrail|HuGR-Labs|HuGR-dev|corelink-dev)/corelink-server/\.github/workflows/release-slsa3\.yml@refs/tags/v\d+\.\d+\.\d+$".to_string(),
        }
    }

    /// Construct from an arbitrary regex pattern.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// Returns `true` if `san_uri` matches this pattern.
    ///
    /// Evaluates the supplied regular expression against the entire SAN URI.
    /// Invalid patterns fail closed; unanchored expressions cannot match a substring.
    pub fn matches_simple(&self, san_uri: &str) -> bool {
        regex::Regex::new(&format!(r"\A(?:{})\z", self.pattern))
            .map(|pattern| pattern.is_match(san_uri))
            .unwrap_or(false)
    }
}

// ── Verify outcome ─────────────────────────────────────────────────────────

/// Outcome of a deploy verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VerifyOutcome {
    /// All checks passed; deploy propagated.
    Ok,
    /// Cosign signature missing or invalid.
    SigInvalid,
    /// Rekor inclusion proof missing.
    RekorMissing,
    /// Fulcio certificate chain invalid.
    FulcioInvalid,
    /// SAN URI identity mismatch.
    IdentityMismatch,
    /// OCI registry fetch failed.
    OciFetchFailed,
    /// Audit emit failed (fail-CLOSED).
    AuditEmitFailed,
}

impl VerifyOutcome {
    /// Prometheus label value for `corelink_supply_cosign_verify_total`.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::SigInvalid => "sig_invalid",
            Self::RekorMissing => "rekor_missing",
            Self::FulcioInvalid => "fulcio_chain_invalid",
            Self::IdentityMismatch => "identity_mismatch",
            Self::OciFetchFailed => "oci_fetch_failed",
            Self::AuditEmitFailed => "audit_emit_failed",
        }
    }
}

// ── Deploy propagated ──────────────────────────────────────────────────────

/// Successful deploy propagation result.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeployPropagated {
    /// Release tag, e.g. `"v0.1.0"`.
    pub release_tag: String,
    /// Whether the Cosign signature was verified.
    pub cosign_signature_verified: bool,
    /// Rekor transparency log index for the inclusion proof.
    pub rekor_log_index: u64,
    /// Fulcio certificate SAN URI (criptically bound to the workflow identity).
    pub fulcio_cert_san: String,
    /// Timestamp when propagation completed.
    pub propagated_at: SystemTime,
    /// Cloudflare deployment ID returned by the CF API.
    pub cf_deployment_id: String,
}

// ── Audit event ────────────────────────────────────────────────────────────

/// CloudEvents 1.0 aligned audit event emitted for every deploy attempt.
///
/// Event type: `dev.hugr.corelink.deploy.verified.v1` (success) or
/// `dev.hugr.corelink.deploy.blocked.v1` (rejection).
///
/// Audit emit is **fail-CLOSED** per CTRL-AUDIT-002 + INV-AUDIT-APPEND-ONLY:
/// if emit fails, the deploy is rejected and an SEV-1 alert fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeployAuditEvent {
    /// CloudEvents type.
    pub event_type: String,
    /// Release tag.
    pub release_tag: String,
    /// Verification outcome.
    pub outcome: VerifyOutcome,
    /// Wall-clock timestamp.
    pub timestamp: SystemTime,
    /// OpenTelemetry trace ID (hex string).
    pub trace_id: String,
    /// Unique event ID (UUIDv7).
    pub event_id: Uuid,
}

impl DeployAuditEvent {
    /// Construct a `deploy.verified.v1` audit event.
    pub fn verified(release_tag: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            event_type: "dev.hugr.corelink.deploy.verified.v1".to_string(),
            release_tag: release_tag.into(),
            outcome: VerifyOutcome::Ok,
            timestamp: SystemTime::now(),
            trace_id: trace_id.into(),
            event_id: Uuid::now_v7(),
        }
    }

    /// Construct a `deploy.blocked.v1` audit event.
    pub fn blocked(
        release_tag: impl Into<String>,
        outcome: VerifyOutcome,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            event_type: "dev.hugr.corelink.deploy.blocked.v1".to_string(),
            release_tag: release_tag.into(),
            outcome,
            timestamp: SystemTime::now(),
            trace_id: trace_id.into(),
            event_id: Uuid::now_v7(),
        }
    }

    /// Canonical audit event type strings (used in surface-pinning tests).
    pub fn canonical_event_types() -> [&'static str; 2] {
        [
            "dev.hugr.corelink.deploy.verified.v1",
            "dev.hugr.corelink.deploy.blocked.v1",
        ]
    }
}

// ── Metrics labels ─────────────────────────────────────────────────────────

/// Prometheus metric name constants (§6.1.6).
pub mod metrics {
    /// `corelink_supply_cosign_verify_total{outcome,plan}`.
    pub const COSIGN_VERIFY_TOTAL: &str = "corelink_supply_cosign_verify_total";
    /// `corelink_supply_cosign_verify_duration_seconds_bucket`.
    pub const COSIGN_VERIFY_DURATION: &str = "corelink_supply_cosign_verify_duration_seconds";
    /// `corelink_supply_deploy_blocked_total{reason,plan}`.
    pub const DEPLOY_BLOCKED_TOTAL: &str = "corelink_supply_deploy_blocked_total";
    /// `corelink_supply_deploy_propagated_total{plan}`.
    pub const DEPLOY_PROPAGATED_TOTAL: &str = "corelink_supply_deploy_propagated_total";
    /// `corelink_supply_audit_emit_total{outcome}`.
    pub const AUDIT_EMIT_TOTAL: &str = "corelink_supply_audit_emit_total";
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::const_is_empty
)]
mod tests {
    use super::*;

    #[test]
    fn verify_outcome_labels_exhaustive() {
        let outcomes = [
            VerifyOutcome::Ok,
            VerifyOutcome::SigInvalid,
            VerifyOutcome::RekorMissing,
            VerifyOutcome::FulcioInvalid,
            VerifyOutcome::IdentityMismatch,
            VerifyOutcome::OciFetchFailed,
            VerifyOutcome::AuditEmitFailed,
        ];
        for o in &outcomes {
            assert!(!o.as_label().is_empty());
        }
    }

    #[test]
    fn audit_event_types_pinned() {
        let types = DeployAuditEvent::canonical_event_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"dev.hugr.corelink.deploy.verified.v1"));
        assert!(types.contains(&"dev.hugr.corelink.deploy.blocked.v1"));
    }

    #[test]
    fn cosign_identity_pattern_corelink_release_matches() {
        let p = CosignIdentityPattern::corelink_release();
        assert!(p.matches_simple(
            "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(p.matches_simple(
            "https://github.com/HuGR-Labs/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(p.matches_simple(
            "https://github.com/HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(p.matches_simple(
            "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(p.matches_simple(
            "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v1.23.456"
        ));
        assert!(p.matches_simple(
            "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v1.23.456"
        ));
    }

    #[test]
    fn cosign_identity_pattern_fork_rejected() {
        let p = CosignIdentityPattern::corelink_release();
        // Attacker fork
        assert!(!p.matches_simple(
            "https://github.com/attacker/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        // Different workflow
        assert!(!p.matches_simple(
            "https://github.com/HumanGuardrail/corelink-server/.github/workflows/build.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/attacker/HuGR-Labs/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/HuGR-Labs/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0.evil"
        ));
        assert!(!p.matches_simple(
            "https://github.com/HuGR-Labs/corelink-cli/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        // The current owner is accepted only as the exact owner of the server
        // repository's release workflow at a release tag.
        assert!(!p.matches_simple(
            "https://github.com/attacker/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/corelink-dev-evil/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/corelink-dev/corelink-server-evil/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/corelink-dev/corelink-runners/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/corelink-dev/corelink-server/.github/workflows/build.yml@refs/tags/v0.1.0"
        ));
        assert!(!p.matches_simple(
            "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/heads/main"
        ));
    }

    #[test]
    fn cosign_identity_pattern_uses_the_supplied_expression() {
        let p = CosignIdentityPattern::new(
            r"^https://github\.com/ExampleOrg/example-repo/\.github/workflows/release\.yml@refs/heads/main$",
        );
        assert!(p.matches_simple(
            "https://github.com/ExampleOrg/example-repo/.github/workflows/release.yml@refs/heads/main"
        ));
        assert!(!p.matches_simple(
            "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v1.2.3"
        ));
        assert!(!CosignIdentityPattern::new("[").matches_simple("anything"));
        assert!(!CosignIdentityPattern::new("ExampleOrg/example-repo")
            .matches_simple("https://github.com/ExampleOrg/example-repo/workflow"));
        assert!(CosignIdentityPattern::new("ExampleOrg/example-repo")
            .matches_simple("ExampleOrg/example-repo"));
    }

    #[test]
    fn oci_image_ref_digest_detection() {
        let r = OciImageRef::from_tag("ghcr.io/HumanGuardrail/corelink-worker:v0.1.0");
        assert!(!r.has_digest());
        let r2 = OciImageRef::from_digest(
            "ghcr.io/HumanGuardrail/corelink-worker:v0.1.0",
            "sha256:abc123",
        );
        assert!(r2.has_digest());
    }

    #[test]
    fn metrics_constants_non_empty() {
        assert!(!metrics::COSIGN_VERIFY_TOTAL.is_empty());
        assert!(!metrics::COSIGN_VERIFY_DURATION.is_empty());
        assert!(!metrics::DEPLOY_BLOCKED_TOTAL.is_empty());
        assert!(!metrics::DEPLOY_PROPAGATED_TOTAL.is_empty());
        assert!(!metrics::AUDIT_EMIT_TOTAL.is_empty());
    }
}
