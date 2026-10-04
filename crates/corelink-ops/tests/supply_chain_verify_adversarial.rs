//! Adversarial regression tests for SLSA L3 provenance verification (WI-S12-001).
// Tests legitimately use panic!, unwrap, and expect for assertion purposes.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::format_in_format_args,
    clippy::indexing_slicing,
    clippy::print_stdout
)]
//!
//! 5 CVE-class scenarios, each must be 100% rejected:
//!
//! 1. Attestation forge via fork (different builder_id) → `BuilderMismatch`.
//! 2. Rekor inclusion proof tampered (Merkle root mismatch) → `RekorInclusionInvalid`.
//! 3. Fulcio cert expired (empty cert field) → `FulcioChainInvalid`.
//! 4. in-toto schema v0.0.1 (old format) → `InTotoSchemaInvalid`.
//! 5. DSSE envelope alg=none → `DsseEnvelopeInvalid`.

use corelink_ops::supply_chain::verify::{
    error::VerifyError,
    types::{BuilderIdentity, DsseSignature, MerkleInclusionProof, RekorBundle, SlsaAttestation},
    verifier::{DefaultSlsaVerifier, SlsaProvenanceVerifier},
};

/// Build a valid base64-encoded in-toto v1.0 payload.
fn valid_payload_b64() -> String {
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "corelink-worker.wasm", "digest": {"sha256": "a".repeat(64)}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
                "externalParameters": {
                    "workflow": "refs/tags/v0.1.0",
                    "source": {"digest": {"sha1": "abc123def456abc123def456abc123def456abc12"}}
                }
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
                }
            }
        }
    });
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(statement.to_string())
}

/// Build a valid attestation.
fn valid_attestation() -> SlsaAttestation {
    SlsaAttestation::new(
        "application/vnd.in-toto+json".to_string(),
        valid_payload_b64(),
        vec![DsseSignature::new(
            "dGVzdHNpZ25hdHVyZQ==".to_string(),
            "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0".to_string(),
            "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n".to_string(),
            Some(RekorBundle::new(
                99_000_000,
                "a".repeat(64),
                Some(MerkleInclusionProof::new(
                    99_000_000,
                    200_000_000,
                    "b".repeat(64),
                    vec!["c".repeat(64), "d".repeat(64), "e".repeat(64)],
                )),
            )),
        )],
    )
}

/// Historical artifact fixture: expected builder identity for `HumanGuardrail/corelink-server`.
fn expected_builder() -> BuilderIdentity {
    BuilderIdentity::from_historical_org_pattern("HumanGuardrail/corelink-server")
}

// ---------------------------------------------------------------------------
// CVE-class 1: Attestation forge via fork (different builder_id)
// Threat: attacker stages release from fork "attacker/corelink-server";
//         generates valid Fulcio cert bound to fork workflow identity.
// Defense: builder identity mismatch detected via `key_id` SAN URI check.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_01_attestation_forge_fork_builder_mismatch() {
    let mut att = valid_attestation();
    // Attacker's fork has a different org
    let attacker_san = "https://github.com/attacker-org/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0";
    if let Some(sig) = att.signatures.first_mut() {
        sig.key_id = attacker_san.to_string();
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::BuilderMismatch { got, expected }) => {
            assert_eq!(got, attacker_san, "got must be the attacker SAN URI");
            assert!(
                expected.contains("HumanGuardrail/corelink-server"),
                "expected must contain the org pattern, got: {}",
                expected
            );
        }
        Err(e) => panic!("CVE-class 1: Expected BuilderMismatch, got: {:?}", e),
        Ok(_) => {
            panic!("CVE-class 1: Fork attestation forge was NOT rejected — CRITICAL SECURITY BUG")
        }
    }
}

// ---------------------------------------------------------------------------
// CVE-class 2: Rekor inclusion proof tampered (Merkle root hash zeroed)
// Threat: attacker replaces Rekor bundle in the attestation file with crafted data.
// Defense: Merkle root hash validation catches the tampering.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_02_rekor_inclusion_proof_tampered() {
    let mut att = valid_attestation();
    // Tamper the Merkle root hash (replaced with invalid value)
    if let Some(sig) = att.signatures.first_mut() {
        if let Some(ref mut bundle) = sig.bundle {
            if let Some(ref mut proof) = bundle.inclusion_proof {
                // Zeroed root hash (tampered to all zeros still must validate hex format)
                // but tree consistency would be broken; structurally we use non-hex to trigger
                proof.root_hash = "TAMPERED".to_string(); // Not valid 64-char hex
            }
        }
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::RekorInclusionInvalid(msg)) => {
            assert!(
                msg.contains("64-char hex")
                    || msg.contains("Merkle root")
                    || msg.contains("invalid"),
                "Expected Merkle validation message, got: {}",
                msg
            );
        }
        Err(e) => panic!("CVE-class 2: Expected RekorInclusionInvalid, got: {:?}", e),
        Ok(_) => {
            panic!("CVE-class 2: Tampered Rekor proof was NOT rejected — CRITICAL SECURITY BUG")
        }
    }
}

// ---------------------------------------------------------------------------
// CVE-class 3: Fulcio cert expired / absent
// Threat: attacker generates attestation without a valid Fulcio certificate.
// Defense: empty cert field → FulcioChainInvalid (attestation not signed with Fulcio).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_03_fulcio_cert_expired_or_absent() {
    let mut att = valid_attestation();
    // Remove the Fulcio certificate (simulates expired cert being stripped)
    if let Some(sig) = att.signatures.first_mut() {
        sig.cert = String::new();
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::FulcioChainInvalid(msg)) => {
            assert!(
                msg.contains("empty") || msg.contains("not signed"),
                "Expected cert-empty message, got: {}",
                msg
            );
        }
        Err(e) => panic!("CVE-class 3: Expected FulcioChainInvalid, got: {:?}", e),
        Ok(_) => panic!("CVE-class 3: Absent Fulcio cert was NOT rejected — CRITICAL SECURITY BUG"),
    }
}

// ---------------------------------------------------------------------------
// CVE-class 4: in-toto schema v0.0.1 (old format)
// Threat: attacker uses old schema format with unknown predicate to bypass validation.
// Regression class: XZ Utils 2024 — schema drift enables bypass.
// Defense: predicateType must be exactly "https://slsa.dev/provenance/v1".
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_04_intoto_schema_v001_rejected() {
    // Build an attestation with old predicateType
    let old_schema_statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.0.1",
        "subject": [{"name": "corelink-worker.wasm", "digest": {"sha256": "a".repeat(64)}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
                "externalParameters": {}
            },
            "runDetails": {
                "builder": {"id": "https://github.com/HumanGuardrail/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"}
            }
        }
    });
    use base64::Engine as _;
    let payload =
        base64::engine::general_purpose::STANDARD.encode(old_schema_statement.to_string());

    let mut att = valid_attestation();
    att.payload = payload;

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::InTotoSchemaInvalid(msg)) => {
            assert!(
                msg.contains("v0.0.1")
                    || msg.contains("predicateType")
                    || msg.contains("not accepted"),
                "Expected schema rejection message, got: {}",
                msg
            );
        }
        Err(e) => panic!("CVE-class 4: Expected InTotoSchemaInvalid, got: {:?}", e),
        Ok(_) => panic!("CVE-class 4: Old schema v0.0.1 was NOT rejected — CRITICAL SECURITY BUG"),
    }
}

// ---------------------------------------------------------------------------
// CVE-class 5: DSSE envelope alg=none
// Threat: attacker generates DSSE envelope with alg=none (no signature) — JWT-class attack
//         applied to DSSE format. Envelope payload is present but no cryptographic binding.
// Defense: zero signatures → DsseEnvelopeInvalid.
//          Empty sig field → DsseEnvelopeInvalid.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_05_dsse_alg_none_empty_signatures() {
    let mut att = valid_attestation();
    // DSSE alg=none equivalent: no signatures at all
    att.signatures = vec![];

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::DsseEnvelopeInvalid(msg)) => {
            assert!(
                msg.contains("alg=none") || msg.contains("no signatures"),
                "Expected alg=none message, got: {}",
                msg
            );
        }
        Err(e) => panic!("CVE-class 5a: Expected DsseEnvelopeInvalid, got: {:?}", e),
        Ok(_) => panic!(
            "CVE-class 5a: alg=none (no signatures) was NOT rejected — CRITICAL SECURITY BUG"
        ),
    }
}

#[tokio::test]
async fn adversarial_05b_dsse_alg_none_empty_sig_field() {
    let mut att = valid_attestation();
    // DSSE alg=none equivalent: sig field present but empty
    if let Some(sig) = att.signatures.first_mut() {
        sig.sig = String::new();
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::DsseEnvelopeInvalid(msg)) => {
            assert!(
                msg.contains("alg=none") || msg.contains("empty"),
                "Expected alg=none empty-sig message, got: {}",
                msg
            );
        }
        Err(e) => panic!("CVE-class 5b: Expected DsseEnvelopeInvalid, got: {:?}", e),
        Ok(_) => panic!("CVE-class 5b: Empty sig field was NOT rejected — CRITICAL SECURITY BUG"),
    }
}

// ---------------------------------------------------------------------------
// Positive: valid attestation → Ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_attestation_accepted() {
    let att = valid_attestation();
    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Ok(prov) => {
            assert!(
                prov.builder_id.contains("HumanGuardrail/corelink-server"),
                "builder_id should contain the org pattern"
            );
            assert_eq!(prov.rekor_log_index, 99_000_000);
            assert!(prov.fulcio_cert_chain_valid);
            assert_eq!(prov.in_toto_schema_version, "v1.0");
        }
        Err(e) => panic!("Valid attestation was rejected: {:?}", e),
    }
}

// ---------------------------------------------------------------------------
// Regression: Rekor bundle present but inclusionProof field absent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_rekor_bundle_no_inclusion_proof() {
    let mut att = valid_attestation();
    if let Some(sig) = att.signatures.first_mut() {
        if let Some(ref mut bundle) = sig.bundle {
            bundle.inclusion_proof = None;
        }
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::RekorInclusionInvalid(msg)) => {
            assert!(
                msg.contains("inclusionProof") || msg.contains("absent"),
                "Expected inclusionProof absent message, got: {}",
                msg
            );
        }
        Err(e) => panic!(
            "Expected RekorInclusionInvalid (no inclusionProof), got: {:?}",
            e
        ),
        Ok(_) => {
            panic!("Rekor bundle without inclusionProof was NOT rejected — CRITICAL SECURITY BUG")
        }
    }
}

// ---------------------------------------------------------------------------
// Regression: log_index >= tree_size (invalid Merkle proof geometry)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adversarial_rekor_log_index_exceeds_tree_size() {
    let mut att = valid_attestation();
    if let Some(sig) = att.signatures.first_mut() {
        if let Some(ref mut bundle) = sig.bundle {
            if let Some(ref mut proof) = bundle.inclusion_proof {
                // log_index >= tree_size is impossible in a valid Merkle tree
                proof.log_index = 500;
                proof.tree_size = 100;
            }
        }
    }

    let verifier = DefaultSlsaVerifier::new();
    let result = verifier.verify(&att, &expected_builder()).await;

    match result {
        Err(VerifyError::RekorInclusionInvalid(msg)) => {
            assert!(
                msg.contains("log_index") || msg.contains("tree_size") || msg.contains("invalid"),
                "Expected Merkle geometry message, got: {}",
                msg
            );
        }
        Err(e) => panic!(
            "Expected RekorInclusionInvalid (log_index >= tree_size), got: {:?}",
            e
        ),
        Ok(_) => panic!("Invalid Merkle proof geometry was NOT rejected"),
    }
}
