//! # corelink-supply-verify
//!
//! SLSA L3 build provenance verifier for CoreLink (WI-S12-001).
//!
//! ## Capabilities
//!
//! - Parse and validate DSSE-wrapped in-toto v1.0 attestation envelopes.
//! - Enforce Fulcio certificate presence and structural chain validation.
//! - Enforce Rekor transparency log inclusion proof (fail-CLOSED; INV-SUPPLY-PROVENANCE-IN-REKOR).
//! - Match builder identity against caller-supplied pattern (forge rejection).
//! - Emit 4 Prometheus-compatible structured metrics.
//! - Emit OTel trace spans `slsa.attestation.verify`.
//!
//! ## Security invariants
//!
//! - **INV-SUPPLY-PROVENANCE-IN-REKOR**: Missing Rekor bundle = hard error. No `--skip-rekor` flag.
//! - **alg=none rejected**: Empty `sig` field or zero signatures = `VerifyError::DsseEnvelopeInvalid`.
//! - **Schema drift rejected**: Only `predicateType = "https://slsa.dev/provenance/v1"` accepted.
//! - **Builder mismatch rejected**: Fork-sourced attestations with wrong `builder_id` fail.
//!
//! ## Quick example
//!
//! ```no_run
//! use corelink_ops::supply_chain::verify::{
//!     verifier::{DefaultSlsaVerifier, SlsaProvenanceVerifier},
//!     types::{BuilderIdentity, SlsaAttestation},
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let bundle_json = std::fs::read_to_string("provenance.intoto.bundle").unwrap();
//!     let attestation: SlsaAttestation = serde_json::from_str(&bundle_json).unwrap();
//!     let expected = BuilderIdentity::from_org_pattern("corelink-dev/corelink-server");
//!     let verifier = DefaultSlsaVerifier::new();
//!     match verifier.verify(&attestation, &expected).await {
//!         Ok(prov) => println!("Verified! Rekor index: {}", prov.rekor_log_index),
//!         Err(e) => eprintln!("Verification failed: {}", e),
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
// S-12 sprint-close P1 fix: format!() in format-args is a style preference,
// not a correctness issue; the inline-variable rewrite hurts readability
// for multi-line URL/error templates. Pinned with allow rather than fight
// every error-path format!().
#![allow(clippy::format_in_format_args, clippy::uninlined_format_args)]

pub mod error;
pub mod metrics;
pub mod types;
pub mod verifier;
