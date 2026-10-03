//! Core types for SLSA L3 provenance verification (WI-S12-001).
//!
//! Defines [`SlsaAttestation`], [`BuilderIdentity`], [`VerifiedProvenance`], and supporting
//! structures. All public types implement [`Debug`] and [`Clone`]; structs are
//! `#[non_exhaustive]` to allow forward-compatible field additions without breaking
//! downstream semver.

use serde::{Deserialize, Serialize};

/// In-toto v1.0 DSSE attestation envelope (SLSA L3 provenance).
///
/// Encodes the signed attestation produced by `slsa-github-generator/generator_generic_slsa3.yml`.
/// The `payload` field is base64-encoded JSON of the in-toto `Statement` (predicateType
/// `https://slsa.dev/provenance/v1`). The `signatures` field contains Fulcio-bound ECDSA
/// signatures; each signature includes the Fulcio certificate chain and Rekor log entry.
///
/// # Example
///
/// ```no_run
/// use corelink_ops::supply_chain::verify::types::SlsaAttestation;
/// let raw = std::fs::read_to_string("provenance.intoto.jsonl").unwrap();
/// let att: SlsaAttestation = serde_json::from_str(&raw).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SlsaAttestation {
    /// DSSE envelope payload type (must equal `"application/vnd.in-toto+json"`).
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// Base64-encoded in-toto `Statement` JSON.
    pub payload: String,

    /// DSSE signatures; each entry carries the Fulcio certificate chain embedded via
    /// `x509Certificate` extension and the Rekor bundle in `annotations`.
    pub signatures: Vec<DsseSignature>,
}

impl SlsaAttestation {
    /// Construct a new `SlsaAttestation`.
    ///
    /// Use this constructor in tests and examples (struct literal is blocked by `#[non_exhaustive]`
    /// outside the defining crate).
    pub fn new(payload_type: String, payload: String, signatures: Vec<DsseSignature>) -> Self {
        Self {
            payload_type,
            payload,
            signatures,
        }
    }
}

/// A single DSSE signature entry.
///
/// Contains the raw signature bytes, the signing certificate (PEM, Fulcio-issued), and
/// Rekor bundle metadata for inclusion-proof validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DsseSignature {
    /// Base64-encoded raw signature (ECDSA P-256 or Ed25519).
    pub sig: String,

    /// Key hint (typically the SHA-256 fingerprint of the Fulcio certificate).
    #[serde(rename = "keyid", default)]
    pub key_id: String,

    /// PEM-encoded Fulcio-issued short-lived certificate (≤ 10 min validity).
    #[serde(rename = "cert", default)]
    pub cert: String,

    /// Rekor transparency log bundle (inclusion proof + log entry).
    #[serde(rename = "bundle", default)]
    pub bundle: Option<RekorBundle>,
}

impl DsseSignature {
    /// Construct a new `DsseSignature`.
    ///
    /// Use this constructor in tests and examples (struct literal is blocked by `#[non_exhaustive]`
    /// outside the defining crate).
    pub fn new(sig: String, key_id: String, cert: String, bundle: Option<RekorBundle>) -> Self {
        Self {
            sig,
            key_id,
            cert,
            bundle,
        }
    }
}

/// Rekor transparency log bundle embedded within a DSSE signature.
///
/// Contains the log index, SHA-256 digest of the Rekor entry, and the
/// Merkle inclusion proof path for offline verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RekorBundle {
    /// Rekor log entry index (monotonically increasing; globally unique).
    #[serde(rename = "rekorLogIndex")]
    pub rekor_log_index: u64,

    /// SHA-256 digest of the Rekor log entry (hex-encoded).
    #[serde(rename = "rekorLogEntryDigest", default)]
    pub rekor_log_entry_digest: String,

    /// Merkle inclusion proof path (leaf-to-root hashes, hex-encoded).
    #[serde(rename = "inclusionProof", default)]
    pub inclusion_proof: Option<MerkleInclusionProof>,
}

impl RekorBundle {
    /// Construct a new `RekorBundle`.
    ///
    /// Use this constructor in tests and examples (struct literal is blocked by `#[non_exhaustive]`
    /// outside the defining crate).
    pub fn new(
        rekor_log_index: u64,
        rekor_log_entry_digest: String,
        inclusion_proof: Option<MerkleInclusionProof>,
    ) -> Self {
        Self {
            rekor_log_index,
            rekor_log_entry_digest,
            inclusion_proof,
        }
    }
}

/// Merkle tree inclusion proof for a Rekor log entry.
///
/// Verifying this proof against the published Rekor log root hash confirms
/// the entry is immutably recorded in the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MerkleInclusionProof {
    /// Leaf index within the Rekor log tree.
    #[serde(rename = "logIndex")]
    pub log_index: u64,

    /// Total tree size at the time of inclusion (number of leaves).
    #[serde(rename = "treeSize")]
    pub tree_size: u64,

    /// Root hash of the Rekor log tree (hex-encoded SHA-256).
    #[serde(rename = "rootHash")]
    pub root_hash: String,

    /// Inclusion proof hashes (hex-encoded SHA-256, leaf-to-root order).
    pub hashes: Vec<String>,
}

impl MerkleInclusionProof {
    /// Construct a new `MerkleInclusionProof`.
    ///
    /// Use this constructor in tests and examples (struct literal is blocked by `#[non_exhaustive]`
    /// outside the defining crate).
    pub fn new(log_index: u64, tree_size: u64, root_hash: String, hashes: Vec<String>) -> Self {
        Self {
            log_index,
            tree_size,
            root_hash,
            hashes,
        }
    }
}

/// Identity of the expected SLSA L3 builder (workflow ref).
///
/// The `id` must be the full Fulcio certificate SAN URI matching the expected GitHub Actions
/// workflow ref, e.g.:
/// `https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.X.Y`
///
/// The `org_pattern` is an org/repo path prefix (e.g., `corelink-dev/corelink-server`)
/// used when the caller does not know the exact release tag at verify time.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BuilderIdentity {
    /// Exact SAN URI (if known); takes precedence over `org_pattern`.
    pub id: Option<String>,

    /// Org/repo prefix matched at the GitHub SAN URI path boundary.
    /// Must include org + repo, e.g., `corelink-dev/corelink-server`.
    pub org_pattern: String,
}

impl BuilderIdentity {
    /// Create a builder identity from an exact SAN URI.
    pub fn from_exact(san_uri: impl Into<String>) -> Self {
        let id = san_uri.into();
        // Extract org_pattern from the URI for fallback display
        let org_pattern = id
            .strip_prefix("https://github.com/")
            .and_then(|s| s.split("/.github/").next())
            .unwrap_or(&id)
            .to_string();
        Self {
            id: Some(id),
            org_pattern,
        }
    }

    /// Create a builder identity from an org-scoped pattern.
    ///
    /// Matches any workflow ref within the specified org/repo.
    pub fn from_org_pattern(pattern: impl Into<String>) -> Self {
        Self {
            id: None,
            org_pattern: pattern.into(),
        }
    }

    /// Check whether a Fulcio certificate SAN URI matches this identity.
    pub fn matches_san(&self, san: &str) -> bool {
        if let Some(ref exact) = self.id {
            san == exact.as_str()
        } else {
            let expected_path = format!("{}/", self.org_pattern.trim_end_matches('/'));
            san.strip_prefix("https://github.com/")
                .is_some_and(|path| path.starts_with(&expected_path))
        }
    }
}

#[cfg(test)]
mod builder_identity_tests {
    use super::BuilderIdentity;

    const HISTORICAL_SAN: &str = "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    const SOURCE_SAN: &str = "https://github.com/HuGR-Labs/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    // The owner before the corelink-dev rebuild. Artifacts it signed must keep
    // verifying, so the fixture stays alongside the new destination.
    const PREVIOUS_DESTINATION_SAN: &str = "https://github.com/HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    const DESTINATION_SAN: &str = "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";

    #[test]
    fn exact_builder_identity_preserves_historical_and_destination_verification() {
        assert!(BuilderIdentity::from_exact(HISTORICAL_SAN).matches_san(HISTORICAL_SAN));
        assert!(BuilderIdentity::from_exact(SOURCE_SAN).matches_san(SOURCE_SAN));
        assert!(BuilderIdentity::from_exact(PREVIOUS_DESTINATION_SAN)
            .matches_san(PREVIOUS_DESTINATION_SAN));
        assert!(BuilderIdentity::from_exact(DESTINATION_SAN).matches_san(DESTINATION_SAN));
        assert!(!BuilderIdentity::from_exact(DESTINATION_SAN).matches_san(SOURCE_SAN));
        assert!(!BuilderIdentity::from_exact(DESTINATION_SAN).matches_san(PREVIOUS_DESTINATION_SAN));
        assert!(!BuilderIdentity::from_exact(PREVIOUS_DESTINATION_SAN).matches_san(DESTINATION_SAN));
    }

    #[test]
    fn org_pattern_matches_only_the_requested_github_repository_path() {
        let historical = BuilderIdentity::from_org_pattern("HumanGuardrail/corelink-server");
        assert!(historical.matches_san(HISTORICAL_SAN));

        let source = BuilderIdentity::from_org_pattern("HuGR-Labs/corelink-server");
        assert!(source.matches_san(SOURCE_SAN));
        assert!(!source.matches_san(DESTINATION_SAN));

        let previous = BuilderIdentity::from_org_pattern("HuGR-dev/corelink-server");
        assert!(previous.matches_san(PREVIOUS_DESTINATION_SAN));
        assert!(!previous.matches_san(SOURCE_SAN));
        assert!(!previous.matches_san(DESTINATION_SAN));
        assert!(!previous.matches_san(
            "https://github.com/attacker/HuGR-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!previous.matches_san(
            "https://github.com/HuGR-dev/corelink-server-evil/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));

        let destination = BuilderIdentity::from_org_pattern("corelink-dev/corelink-server");
        assert!(destination.matches_san(DESTINATION_SAN));
        assert!(!destination.matches_san(SOURCE_SAN));
        assert!(!destination.matches_san(PREVIOUS_DESTINATION_SAN));
        assert!(!destination.matches_san(
            "https://github.com/attacker/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!destination.matches_san(
            "https://github.com/corelink-dev/corelink-server-evil/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
        assert!(!destination.matches_san(
            "https://github.com/corelink-dev-evil/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        ));
    }
}

/// Result of a successful SLSA L3 provenance verification.
///
/// All fields are cryptographically bound to the attestation and can be independently
/// verified against the Rekor transparency log and Fulcio certificate chain.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedProvenance {
    /// Fulcio certificate SAN URI (builder identity, workflow ref).
    pub builder_id: String,

    /// GitHub commit SHA pinned at build time (40-char hex).
    pub commit_sha: String,

    /// GitHub Actions workflow ref (e.g., `refs/tags/v0.1.0`).
    pub workflow_ref: String,

    /// Rekor log index of the published inclusion proof entry.
    pub rekor_log_index: u64,

    /// Public URL to the Rekor log entry.
    pub rekor_inclusion_proof_url: String,

    /// Whether the Fulcio certificate chain was validated to the TUF-pinned root.
    pub fulcio_cert_chain_valid: bool,

    /// in-toto schema version of the attestation predicate.
    pub in_toto_schema_version: String,

    /// Merkle root hash of the Rekor log tree at inclusion time (hex-encoded SHA-256).
    pub rekor_merkle_root: String,

    /// SHA-256 digest of the artifact this attestation covers (hex-encoded).
    pub artifact_digest: String,
}

/// The decoded in-toto v1.0 Statement (predicateType = `https://slsa.dev/provenance/v1`).
///
/// Fields populated via serde; some fields used only in verifier logic or future extensions.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) struct InTotoStatement {
    /// Must be `"https://in-toto.io/Statement/v1"`.
    #[serde(rename = "_type")]
    pub statement_type: Option<String>,

    /// Must be `"https://slsa.dev/provenance/v1"`.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// Subject artifacts this attestation covers.
    pub subject: Vec<DigestSubject>,

    /// SLSA v1.0 predicate.
    pub predicate: SLSAPredicateV1,
}

/// A single subject artifact entry (name + digest map).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) struct DigestSubject {
    /// Artifact name (e.g., `corelink-worker.wasm`).
    pub name: String,

    /// Digest map, keyed by algorithm (e.g., `{"sha256": "abcdef..."}`).
    pub digest: std::collections::HashMap<String, String>,
}

/// SLSA v1.0 predicate fields (partial; sufficient for verification).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) struct SLSAPredicateV1 {
    /// Build definition (inputs + builder).
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,

    /// Run details (builder + metadata).
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

/// SLSA v1.0 build definition.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub(crate) struct BuildDefinition {
    /// Build type URI (e.g., `https://github.com/slsa-framework/slsa-github-generator/generic@v1`).
    #[serde(rename = "buildType")]
    pub build_type: String,

    /// External parameters (includes source repository + commit SHA).
    #[serde(rename = "externalParameters", default)]
    pub external_parameters: serde_json::Value,
}

/// SLSA v1.0 run details.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) struct RunDetails {
    /// Builder information.
    pub builder: BuilderInfo,

    /// Build metadata (invocation id, started/finished timestamps).
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// SLSA v1.0 builder information.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) struct BuilderInfo {
    /// Builder ID URI (Fulcio certificate SAN URI).
    pub id: String,
}
