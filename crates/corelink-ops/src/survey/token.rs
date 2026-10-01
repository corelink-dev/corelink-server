//! Survey invite token wire format + HMAC-SHA256 sign / verify helpers.
//!
//! Wire format (URL-safe base64 of the JSON payload, then `.`, then
//! URL-safe base64 of the 32-byte truncated HMAC sig):
//!
//! ```text
//! <b64url(payload_json)>.<b64url(hmac_sha256_32)>
//! ```
//!
//! The payload JSON is canonical (`serde_json` default; keys sorted via
//! field order in the struct) and includes:
//!
//! - `v` — wire version (currently 1)
//! - `jti` — UUIDv7 unique-id (used for replay rejection)
//! - `t` — tenant id (UUIDv7)
//! - `s` — survey id slug
//! - `k` — survey kind (snake_case string)
//! - `r` — recipient_hash (64-char hex SHA-256)
//! - `iat` — issued-at unix ms
//! - `exp` — expires-at unix ms
//!
//! Signature is HMAC-SHA256 over the **exact base64-encoded payload
//! bytes** (the dot is not part of the preimage), keyed by the
//! per-environment 32-byte [`super::SigningKey`]. Verify is via
//! [`subtle::ConstantTimeEq`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::error::SurveyError;
use super::hash::RecipientHash;
use super::ids::{SurveyId, TenantId};
use super::signer::SigningKey;
use super::types::SurveyKind;

type HmacSha256 = Hmac<Sha256>;

/// Wire-format version. Bumped only on a breaking payload-shape change.
pub const TOKEN_WIRE_VERSION: u8 = 1;

/// Length of the HMAC-SHA256 signature segment in bytes (full 32-byte
/// digest; not truncated). The PAT crate truncates to 16 bytes for
/// DDoS-throttle reasons; survey tokens are not on a hot path so we
/// carry the full 32 bytes.
pub const TOKEN_HMAC_LEN: usize = 32;

/// Plaintext token payload, serialized into the URL.
///
/// Field names are short (1-3 chars) to keep the URL compact when
/// rendered as the `t` query parameter of a survey-invite URL (`/r?t=<token>`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TokenPayload {
    /// Wire version. Validated to equal [`TOKEN_WIRE_VERSION`].
    pub v: u8,
    /// Unique invite id (UUIDv7). Used as the replay-rejection key.
    pub jti: Uuid,
    /// Tenant id.
    pub t: TenantId,
    /// Survey id slug.
    pub s: SurveyId,
    /// Survey kind.
    pub k: SurveyKind,
    /// Recipient hash (32-byte SHA-256, rendered as 64-char hex).
    pub r: RecipientHash,
    /// Issued-at, unix ms.
    pub iat: u64,
    /// Expires-at, unix ms.
    pub exp: u64,
}

/// Decoded, signature-verified survey invite token.
///
/// Holds all the fields the recorder needs to validate the response +
/// emit the audit envelope + insert the row. Cloneable so the recorder
/// can fan out the payload to multiple downstream collaborators
/// (audit emitter + storage backend + abuse pipeline) without re-decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurveyToken {
    pub(crate) payload: TokenPayload,
    /// The full encoded token string, kept for replay logging + audit.
    encoded: String,
}

impl SurveyToken {
    /// Borrow the encoded URL-form token string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Unique invite id. Used by the recorder for replay rejection.
    #[must_use]
    pub const fn jti(&self) -> Uuid {
        self.payload.jti
    }

    /// Tenant id.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.payload.t
    }

    /// Survey id slug.
    #[must_use]
    pub fn survey_id(&self) -> &SurveyId {
        &self.payload.s
    }

    /// Survey kind encoded by the issuer.
    #[must_use]
    pub const fn kind(&self) -> SurveyKind {
        self.payload.k
    }

    /// Recipient hash bound at sign time.
    #[must_use]
    pub fn recipient(&self) -> &RecipientHash {
        &self.payload.r
    }

    /// Issued-at unix ms.
    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.payload.iat
    }

    /// Expires-at unix ms.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.payload.exp
    }
}

pub(crate) fn encode_token(
    key: &SigningKey,
    payload: &TokenPayload,
) -> Result<SurveyToken, SurveyError> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| SurveyError::Storage(format!("token payload serialize: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&json);
    let sig = compute_hmac(key, payload_b64.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    let encoded = format!("{payload_b64}.{sig_b64}");
    Ok(SurveyToken {
        payload: payload.clone(),
        encoded,
    })
}

/// Decode + verify a `&str` token under `key`. Returns the parsed
/// [`SurveyToken`] on success.
///
/// Constant-time over the signature compare; payload decode happens
/// **after** the sig check fails (we still need to decode first to
/// compute the HMAC over the payload segment, but variants that fail
/// the sig path never reach the JSON decoder and so cannot leak via
/// JSON error timing).
///
/// # Errors
///
/// - [`SurveyError::MalformedToken`] — wire shape wrong, b64 decode failed,
///   payload JSON parse failed, wire version mismatch.
/// - [`SurveyError::InvalidSignature`] — HMAC mismatch.
pub fn decode_and_verify(key: &SigningKey, encoded: &str) -> Result<SurveyToken, SurveyError> {
    let dot = encoded.find('.').ok_or(SurveyError::MalformedToken)?;
    let payload_b64 = encoded.get(..dot).ok_or(SurveyError::MalformedToken)?;
    let sig_b64 = encoded
        .get(dot.saturating_add(1)..)
        .ok_or(SurveyError::MalformedToken)?;
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(SurveyError::MalformedToken);
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| SurveyError::MalformedToken)?;
    if sig_bytes.len() != TOKEN_HMAC_LEN {
        return Err(SurveyError::MalformedToken);
    }
    // Compute expected sig BEFORE decoding the payload JSON: a caller
    // who flips a single payload bit gets a sig miss, not a JSON parse
    // hint. Even though both errors map to MalformedToken /
    // InvalidSignature, the metric label is distinct.
    let expected = compute_hmac(key, payload_b64.as_bytes())?;
    if !bool::from(expected.as_slice().ct_eq(sig_bytes.as_slice())) {
        return Err(SurveyError::InvalidSignature);
    }
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| SurveyError::MalformedToken)?;
    let payload: TokenPayload =
        serde_json::from_slice(&payload_json).map_err(|_| SurveyError::MalformedToken)?;
    if payload.v != TOKEN_WIRE_VERSION {
        return Err(SurveyError::MalformedToken);
    }
    Ok(SurveyToken {
        payload,
        encoded: encoded.to_owned(),
    })
}

fn compute_hmac(key: &SigningKey, preimage: &[u8]) -> Result<[u8; TOKEN_HMAC_LEN], SurveyError> {
    let mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Err(SurveyError::SigningKeyLength),
    };
    let result = mac.chain_update(preimage).finalize().into_bytes();
    let mut sig = [0u8; TOKEN_HMAC_LEN];
    for (dst, src) in sig.iter_mut().zip(result.iter()) {
        *dst = *src;
    }
    Ok(sig)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test module — assertions panic by design"
)]
mod tests {
    use super::*;

    fn sample_payload() -> TokenPayload {
        TokenPayload {
            v: TOKEN_WIRE_VERSION,
            jti: Uuid::nil(),
            t: TenantId::from_uuid(Uuid::nil()),
            s: SurveyId::new("nps-w1"),
            k: SurveyKind::Nps,
            r: RecipientHash::derive_with_salt("user@example.com", b"salt"),
            iat: 1_700_000_000_000,
            exp: 1_700_000_010_000,
        }
    }

    #[test]
    fn roundtrip_token() {
        let key = SigningKey::from_bytes([0x11; 32]);
        let payload = sample_payload();
        let tok = encode_token(&key, &payload).unwrap();
        let decoded = decode_and_verify(&key, tok.as_str()).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn flipped_sig_byte_rejects() {
        let key = SigningKey::from_bytes([0x11; 32]);
        let payload = sample_payload();
        let tok = encode_token(&key, &payload).unwrap();
        let mut bytes = tok.as_str().as_bytes().to_vec();
        let last = bytes.len() - 1;
        // Flip the last sig byte (avoiding any base64 boundary issue —
        // base64 NO_PAD URL-safe alphabet is contiguous).
        bytes[last] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        let err = decode_and_verify(&key, &tampered).unwrap_err();
        // Bit-flip on a base64 char often still decodes; assert the
        // failure is either signature or malformed.
        assert!(
            matches!(
                err,
                SurveyError::InvalidSignature | SurveyError::MalformedToken
            ),
            "expected sig/malformed, got {err:?}"
        );
    }

    #[test]
    fn wrong_key_rejects() {
        let key1 = SigningKey::from_bytes([0x11; 32]);
        let key2 = SigningKey::from_bytes([0x22; 32]);
        let payload = sample_payload();
        let tok = encode_token(&key1, &payload).unwrap();
        assert!(matches!(
            decode_and_verify(&key2, tok.as_str()),
            Err(SurveyError::InvalidSignature)
        ));
    }

    #[test]
    fn dot_missing_rejects() {
        let key = SigningKey::from_bytes([0x11; 32]);
        assert!(matches!(
            decode_and_verify(&key, "no-dot-here"),
            Err(SurveyError::MalformedToken)
        ));
    }
}
