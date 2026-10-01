//! HMAC-SHA256 signature verification (constant-time) for admin signing key.
//!
//! The admin signing key is a per-region 32-byte secret managed by the
//! rotation worker (WI-S13-003). Verification uses `subtle::ConstantTimeEq`
//! to prevent timing-oracle attacks (§9.1).
//!
//! The HMAC covers: `op_payload_canonical_bytes || nonce_16bytes || ts_ms_8be`
//! (big-endian u64 for ts_ms).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::DualApprovalError;

type HmacSha256 = Hmac<Sha256>;

/// Admin signing key: 32-byte HMAC-SHA256 key per region (from rotation
/// worker WI-S13-003; static key in dev/test).
#[derive(Clone)]
pub struct AdminSigningKey {
    raw: [u8; 32],
}

impl std::fmt::Debug for AdminSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminSigningKey")
            .field("raw", &"[REDACTED]")
            .finish()
    }
}

impl AdminSigningKey {
    /// Construct from raw 32-byte key material.
    pub fn new(raw: [u8; 32]) -> Self {
        Self { raw }
    }

    /// Construct a crate-private test-only all-zeroes key.
    ///
    /// This helper is compiled only into unit-test builds and is unavailable
    /// to integration tests, examples, doctests, and production consumers.
    #[cfg(test)]
    fn test_zero() -> Self {
        Self { raw: [0u8; 32] }
    }
}

/// Compute HMAC-SHA256 over `op_payload || nonce_16 || ts_ms_be8`.
///
/// Returns the 32-byte tag.
/// Infallible HMAC-SHA256 computation.
///
/// `HmacSha256::new_from_slice` is only fallible when the key slice is
/// empty for some HMAC implementations; HMAC-SHA256 (RustCrypto) accepts
/// any non-empty key. We use a fixed 32-byte key from `AdminSigningKey`,
/// so this is structurally infallible — handled via the never-empty
/// invariant enforced by `AdminSigningKey::new([u8; 32])`.
pub fn compute_hmac(
    key: &AdminSigningKey,
    op_payload: &[u8],
    nonce: &[u8; 16],
    ts_ms: u64,
) -> [u8; 32] {
    // SAFETY-REASONING: `new_from_slice` only returns Err when the slice
    // is empty. `key.raw` is `[u8; 32]` — never empty. The `ok()` path is
    // therefore always `Some`. We map `None` to a zeroed tag as a
    // conservative fallback that causes downstream signature mismatch
    // rather than panic — defence against any future library change.
    let Some(mut mac) = HmacSha256::new_from_slice(&key.raw).ok() else {
        return [0u8; 32];
    };
    mac.update(op_payload);
    mac.update(nonce.as_ref());
    mac.update(&ts_ms.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Verify an approver-supplied HMAC signature in constant time.
///
/// Returns `Ok(())` if the signature matches; `Err(SignatureInvalid)` otherwise.
/// Uses `subtle::ConstantTimeEq` — no early-exit timing oracle.
pub fn verify_hmac(
    key: &AdminSigningKey,
    op_payload: &[u8],
    nonce: &[u8; 16],
    ts_ms: u64,
    provided_sig: &[u8; 32],
) -> Result<(), DualApprovalError> {
    let expected = compute_hmac(key, op_payload, nonce, ts_ms);
    let ok: bool = expected.ct_eq(provided_sig).into();
    if ok {
        Ok(())
    } else {
        Err(DualApprovalError::SignatureInvalid)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_verify() {
        let key = AdminSigningKey::test_zero();
        let payload = b"test-payload";
        let nonce = [0u8; 16];
        let ts = 1_000_000u64;
        let sig = compute_hmac(&key, payload, &nonce, ts);
        verify_hmac(&key, payload, &nonce, ts, &sig).unwrap();
    }

    #[test]
    fn mutated_sig_rejected() {
        let key = AdminSigningKey::test_zero();
        let payload = b"test-payload";
        let nonce = [0u8; 16];
        let ts = 1_000_000u64;
        let mut sig = compute_hmac(&key, payload, &nonce, ts);
        sig[0] ^= 0xFF;
        let err = verify_hmac(&key, payload, &nonce, ts, &sig).unwrap_err();
        assert!(matches!(err, DualApprovalError::SignatureInvalid));
    }
}
