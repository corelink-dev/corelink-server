//! Adversarial 2 — JWT receipt signature is invalid.
//!
//! A tampered receipt (the signature segment mutated by an attacker)
//! must fail the canonical issuer's `verify` path. The status endpoint
//! still resolves by `(tenant_id, request_id)` (the receipt is the
//! CUSTOMER's proof of submission, not the server lookup key) — so
//! the test focuses on the receipt verify boundary.
//!
//! Mutating any of the 3 compact-JWT segments produces a verify-fail.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]

use corelink_dsr::{
    DsrDecision, DsrEndpoint, DsrJurisdiction, DsrReceiptError, DsrRequestKind, JwtReceiptIssuer,
    JwtReceiptToken,
};
use e2e_dsr::{canonical_dsr_for, make_test_tenant, setup_test_env};

#[test]
fn tampered_jwt_signature_rejected() {
    let env = setup_test_env();
    let tenant = make_test_tenant("jwt-tamper-tenant");

    let request = canonical_dsr_for(
        &tenant,
        DsrRequestKind::Access,
        DsrJurisdiction::Gdpr,
        env.now_ms,
    );
    let decision = match env.dsr.submit(&request) {
        Ok(d) => d,
        Err(e) => panic!("submit failed: {e:?}"),
    };
    let receipt = match decision {
        DsrDecision::RequestAccepted { receipt, .. } => receipt,
        other => panic!(
            "expected RequestAccepted, got decision variant {}",
            other.as_str()
        ),
    };

    // Sanity: pristine receipt verifies.
    if let Err(e) = env.dsr_receipt_issuer.verify(&receipt, env.now_ms) {
        panic!("pristine receipt verify failed: {e:?}");
    }

    // Mutate the signature segment.
    let s = receipt.as_str();
    let parts: Vec<&str> = s.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWT expects 3 segments");
    let header = match parts.first() {
        Some(v) => *v,
        None => panic!("missing header segment"),
    };
    let claims = match parts.get(1) {
        Some(v) => *v,
        None => panic!("missing claims segment"),
    };
    let sig = match parts.get(2) {
        Some(v) => *v,
        None => panic!("missing signature segment"),
    };

    // Flip the last char of the signature segment.
    let mut sig_chars: Vec<char> = sig.chars().collect();
    let last = match sig_chars.last_mut() {
        Some(c) => c,
        None => panic!("empty signature"),
    };
    *last = if *last == 'A' { 'B' } else { 'A' };
    let tampered_sig: String = sig_chars.into_iter().collect();
    let tampered = JwtReceiptToken::synthetic_for_test(format!("{header}.{claims}.{tampered_sig}"));

    let err = match env.dsr_receipt_issuer.verify(&tampered, env.now_ms) {
        Ok(_) => panic!("tampered signature must NOT verify"),
        Err(e) => e,
    };
    assert!(
        matches!(err, DsrReceiptError::SignatureInvalid),
        "expected SignatureInvalid, got {err:?}"
    );

    // Mutating the claims segment also fails (the signature was bound
    // to the original claims).
    let mut claims_chars: Vec<char> = claims.chars().collect();
    if let Some(c) = claims_chars.first_mut() {
        *c = if *c == 'A' { 'B' } else { 'A' };
    }
    let tampered_claims: String = claims_chars.into_iter().collect();
    let claim_tampered =
        JwtReceiptToken::synthetic_for_test(format!("{header}.{tampered_claims}.{sig}"));
    let err = match env.dsr_receipt_issuer.verify(&claim_tampered, env.now_ms) {
        Ok(_) => panic!("tampered claims must NOT verify"),
        Err(e) => e,
    };
    assert!(matches!(err, DsrReceiptError::SignatureInvalid));
}
