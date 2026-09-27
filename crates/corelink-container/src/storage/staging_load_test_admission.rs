//! Authenticated and atomic admission for staging load-test runs.
//!
//! A caller supplies one server-verified claim to the D1 adapter.  This module
//! neither trusts request headers nor mounts a route or contacts a provider.

use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::Arc;

use super::{
    d1_http::{D1BatchStatement, D1HttpClient},
    staging_load_test_ownership::StagingLoadTestScenario,
};

const AUTH_DOMAIN: &[u8] = b"corelink/staging-load-admission-auth/v1\0";
const NONCE_DOMAIN: &[u8] = b"corelink/staging-load-admission-nonce/v1\0";
const MAX_CLAIM_LIFETIME_MS: i64 = 15 * 60 * 1_000;
const SQL_INSERT_RUN: &str = "INSERT INTO staging_load_test_runs (run_id, scenario, target_environment, target_deployment_sha, state, admitted_at_ms) VALUES (?1, ?2, 'staging', ?3, 'open', ?4)";
const SQL_INSERT_NONCE: &str = "INSERT INTO staging_load_test_admission_nonces (nonce_digest, run_id, scenario, target_environment, target_deployment_sha, issued_at_ms, expires_at_ms, admitted_at_ms) VALUES (?1, ?2, ?3, 'staging', ?4, ?5, ?6, ?7)";

/// Header carrying an untrusted, signed staging-admission credential.
///
/// A request never receives an admitted context merely because this header is
/// present. [`StagingLoadTestAdmissionGate`] verifies the credential and
/// durably consumes its nonce before returning one.
pub const STAGING_LOAD_TEST_ADMISSION_HEADER: &str = "x-corelink-staging-load-admission";

type HmacSha256 = Hmac<Sha256>;

/// Exact identity expected by a writer before it consumes a verified claim.
#[derive(Debug)]
pub struct StagingLoadTestAdmissionExpectation<'a> {
    /// Canonical positive GitHub Actions run ID.
    pub run_id: &'a str,
    /// Allowlisted scenario for the run.
    pub scenario: StagingLoadTestScenario,
    /// Must be the literal string `staging`.
    pub target_environment: &'a str,
    /// Lowercase 40-hex deployment commit SHA.
    pub target_deployment_sha: &'a str,
}

/// Fixed, parameter-free failures for verification and durable consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingLoadTestAdmissionError {
    /// Credential format or tag is invalid.
    InvalidCredential,
    /// Run ID or deployment SHA is not canonical.
    InvalidIdentity,
    /// Only the staging environment is permitted.
    NonStaging,
    /// Nonce is not 32 bytes encoded as lowercase hex.
    InvalidNonce,
    /// Issuance/expiry relation is malformed or over 15 minutes.
    InvalidLifetime,
    /// Claim is expired or issued in the future.
    Expired,
    /// Claim differs from the caller's exact expected identity.
    MismatchedIdentity,
    /// A nonce or run/scenario identity was previously consumed.
    AlreadyConsumed,
    /// The D1 capability or batch was unavailable.
    PersistenceUnavailable,
}

impl fmt::Display for StagingLoadTestAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCredential => "staging admission credential is invalid",
            Self::InvalidIdentity => "staging admission identity is invalid",
            Self::NonStaging => "staging admission requires the staging environment",
            Self::InvalidNonce => "staging admission nonce is invalid",
            Self::InvalidLifetime => "staging admission lifetime is invalid",
            Self::Expired => "staging admission is expired or not yet valid",
            Self::MismatchedIdentity => "staging admission identity does not match expectation",
            Self::AlreadyConsumed => "staging admission was already consumed",
            Self::PersistenceUnavailable => "staging admission persistence is unavailable",
        };
        f.write_str(message)
    }
}

impl std::error::Error for StagingLoadTestAdmissionError {}

/// Server-only verifier for version-one staging admission credentials.
pub struct StagingLoadTestAdmissionVerifier {
    key: Vec<u8>,
}

impl fmt::Debug for StagingLoadTestAdmissionVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagingLoadTestAdmissionVerifier")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl StagingLoadTestAdmissionVerifier {
    /// Create a verifier only for an explicitly staging server with a 32-byte key.
    pub fn new(
        runtime_environment: &str,
        key: impl AsRef<[u8]>,
    ) -> Result<Self, StagingLoadTestAdmissionError> {
        if runtime_environment != "staging" {
            return Err(StagingLoadTestAdmissionError::NonStaging);
        }
        let key = key.as_ref();
        if key.len() < 32 {
            return Err(StagingLoadTestAdmissionError::InvalidCredential);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Load the staging-only verifier from process configuration.
    pub fn from_env() -> Result<Self, StagingLoadTestAdmissionError> {
        let environment = std::env::var("CORELINK_ENVIRONMENT").unwrap_or_default();
        let key = std::env::var("CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY")
            .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)?;
        Self::new(&environment, key.as_bytes())
    }

    /// Verify `v1.run.scenario.staging.sha.issued.expires.nonce.tag` at `now_ms`.
    ///
    /// The tag covers the exact canonical fields under a domain-separated HMAC;
    /// [`Mac::verify_slice`] provides the tag's constant-time comparison.
    pub fn verify(
        &self,
        credential: &str,
        now_ms: i64,
    ) -> Result<VerifiedStagingLoadTestAdmission, StagingLoadTestAdmissionError> {
        let mut fields = credential.split('.');
        let version = fields.next();
        let run_id = fields.next();
        let scenario = fields.next();
        let environment = fields.next();
        let sha = fields.next();
        let issued = fields.next();
        let expires = fields.next();
        let nonce = fields.next();
        let tag = fields.next();
        if version != Some("v1") || fields.next().is_some() {
            return Err(StagingLoadTestAdmissionError::InvalidCredential);
        }
        let (
            Some(run_id),
            Some(scenario),
            Some(environment),
            Some(sha),
            Some(issued),
            Some(expires),
            Some(nonce),
            Some(tag),
        ) = (
            run_id,
            scenario,
            environment,
            sha,
            issued,
            expires,
            nonce,
            tag,
        )
        else {
            return Err(StagingLoadTestAdmissionError::InvalidCredential);
        };
        let scenario = parse_scenario(scenario)?;
        validate_identity(run_id, scenario, sha)?;
        if environment != "staging" {
            return Err(StagingLoadTestAdmissionError::NonStaging);
        }
        let nonce_digest = nonce_digest_hex(&decode_nonce(nonce)?)?;
        let issued_at_ms = parse_canonical_i64(issued)?;
        let expires_at_ms = parse_canonical_i64(expires)?;
        validate_lifetime(issued_at_ms, expires_at_ms)?;
        if issued_at_ms > now_ms || now_ms >= expires_at_ms {
            return Err(StagingLoadTestAdmissionError::Expired);
        }
        let tag = decode_hex_32(tag).ok_or(StagingLoadTestAdmissionError::InvalidCredential)?;
        let signed =
            canonical_signed_payload(run_id, scenario, sha, issued_at_ms, expires_at_ms, nonce);
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)?;
        mac.update(AUTH_DOMAIN);
        mac.update(signed.as_bytes());
        mac.verify_slice(&tag)
            .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)?;
        Ok(VerifiedStagingLoadTestAdmission {
            run_id: run_id.to_owned(),
            scenario,
            target_environment: environment.to_owned(),
            target_deployment_sha: sha.to_owned(),
            nonce_digest,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Mint a short-lived, request-bound envelope for the signup Worker.
    ///
    /// The same staging-only key is reused under a distinct domain. The
    /// envelope contains only the already-redacted admitted identity and a
    /// caller-generated 128-bit request identifier.
    #[allow(dead_code)] // Frozen seam consumed by the signup writer child after this anchor lands.
    pub(crate) fn mint_ownership_envelope(
        &self,
        context: &StagingLoadTestAdmissionContext,
        request_id: &str,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<String, StagingLoadTestAdmissionError> {
        if !is_lower_hex(request_id, 32) {
            return Err(StagingLoadTestAdmissionError::InvalidIdentity);
        }
        validate_lifetime(issued_at_ms, expires_at_ms)?;
        if issued_at_ms < 0 {
            return Err(StagingLoadTestAdmissionError::InvalidLifetime);
        }
        let payload = format!(
            "v1.{}.{}.staging.{}.{}.{}.{}",
            context.run_id(),
            context.scenario().as_str(),
            context.target_deployment_sha(),
            issued_at_ms,
            expires_at_ms,
            request_id,
        );
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)?;
        mac.update(b"corelink/staging-ownership-envelope/v1\0");
        mac.update(payload.as_bytes());
        let tag = lower_hex(mac.finalize().into_bytes())?;
        Ok(format!("{payload}.{tag}"))
    }

    #[cfg(test)]
    fn sign_for_test(
        &self,
        run_id: &str,
        scenario: StagingLoadTestScenario,
        sha: &str,
        issued_at_ms: i64,
        expires_at_ms: i64,
        nonce: &str,
    ) -> String {
        let signed =
            canonical_signed_payload(run_id, scenario, sha, issued_at_ms, expires_at_ms, nonce);
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("test key is valid");
        mac.update(AUTH_DOMAIN);
        mac.update(signed.as_bytes());
        let tag = lower_hex(mac.finalize().into_bytes()).expect("String formatting is infallible");
        format!("{signed}.{tag}")
    }
}

/// Authenticated claim with private fields, consumable only by this module.
pub struct VerifiedStagingLoadTestAdmission {
    run_id: String,
    scenario: StagingLoadTestScenario,
    target_environment: String,
    target_deployment_sha: String,
    nonce_digest: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl fmt::Debug for VerifiedStagingLoadTestAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedStagingLoadTestAdmission")
            .field("run_id", &self.run_id)
            .field("scenario", &self.scenario)
            .field("target_environment", &self.target_environment)
            .field("target_deployment_sha", &self.target_deployment_sha)
            .field("nonce_digest", &"[REDACTED]")
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl VerifiedStagingLoadTestAdmission {
    /// Construct only after a server verifier authenticated every field.
    #[cfg(test)]
    fn from_verified_claims(
        run_id: String,
        scenario: StagingLoadTestScenario,
        target_environment: String,
        target_deployment_sha: String,
        nonce_digest: String,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Self {
        Self {
            run_id,
            scenario,
            target_environment,
            target_deployment_sha,
            nonce_digest,
            issued_at_ms,
            expires_at_ms,
        }
    }
}

/// Immutable, nonsecret context returned after durable one-time consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingLoadTestAdmissionContext {
    run_id: String,
    scenario: StagingLoadTestScenario,
    target_environment: String,
    target_deployment_sha: String,
    admitted_at_ms: i64,
}

impl StagingLoadTestAdmissionContext {
    /// Canonical admitted run ID.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    /// Allowlisted admitted scenario.
    #[must_use]
    pub const fn scenario(&self) -> StagingLoadTestScenario {
        self.scenario
    }
    /// Admitted environment, always `staging`.
    #[must_use]
    pub fn target_environment(&self) -> &str {
        &self.target_environment
    }
    /// Canonical admitted deployment SHA.
    #[must_use]
    pub fn target_deployment_sha(&self) -> &str {
        &self.target_deployment_sha
    }
    /// Server timestamp at durable admission.
    #[must_use]
    pub const fn admitted_at_ms(&self) -> i64 {
        self.admitted_at_ms
    }
}

/// Restricted D1 adapter that atomically creates a run and consumes its nonce.
pub struct StagingLoadTestAdmissionStore {
    d1: D1HttpClient,
}

impl fmt::Debug for StagingLoadTestAdmissionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagingLoadTestAdmissionStore")
            .field("d1", &"[REDACTED]")
            .finish()
    }
}

impl StagingLoadTestAdmissionStore {
    /// Construct the restricted D1 writer from its server-side environment.
    pub fn from_d1_env() -> Result<Self, StagingLoadTestAdmissionError> {
        D1HttpClient::for_staging_load_test_ownership_writes()
            .map(|d1| Self { d1 })
            .map_err(|_| StagingLoadTestAdmissionError::PersistenceUnavailable)
    }

    /// Construct the restricted store over an already constrained D1 client.
    ///
    /// This exists for in-crate loopback tests. Production construction remains
    /// [`Self::from_d1_env`], which obtains the narrow ownership writer from
    /// process configuration. The client still has to execute the same atomic
    /// run-plus-nonce batch, so this constructor cannot fabricate an admission
    /// context or bypass durable consumption.
    #[cfg(test)]
    pub(crate) fn from_d1_client_for_test(d1: D1HttpClient) -> Self {
        Self { d1 }
    }

    /// Validate, then submit run creation and digest-only nonce persistence in one batch.
    pub async fn consume_verified_admission(
        &self,
        expected: StagingLoadTestAdmissionExpectation<'_>,
        admission: VerifiedStagingLoadTestAdmission,
    ) -> Result<StagingLoadTestAdmissionContext, StagingLoadTestAdmissionError> {
        let now_ms = unix_time_ms()?;
        validate_claim(&expected, &admission, now_ms)?;
        let scenario = scenario_name(admission.scenario);
        let run_params = vec![
            json!(admission.run_id),
            json!(scenario),
            json!(admission.target_deployment_sha),
            json!(now_ms),
        ];
        let nonce_params = vec![
            json!(admission.nonce_digest),
            json!(admission.run_id),
            json!(scenario),
            json!(admission.target_deployment_sha),
            json!(admission.issued_at_ms),
            json!(admission.expires_at_ms),
            json!(now_ms),
        ];
        self.d1
            .batch(vec![
                D1BatchStatement::new(SQL_INSERT_RUN, run_params),
                D1BatchStatement::new(SQL_INSERT_NONCE, nonce_params),
            ])
            .await
            .map_err(|error| {
                if error.statement.is_some() {
                    StagingLoadTestAdmissionError::AlreadyConsumed
                } else {
                    StagingLoadTestAdmissionError::PersistenceUnavailable
                }
            })?;
        Ok(StagingLoadTestAdmissionContext {
            run_id: admission.run_id,
            scenario: admission.scenario,
            target_environment: admission.target_environment,
            target_deployment_sha: admission.target_deployment_sha,
            admitted_at_ms: now_ms,
        })
    }
}

/// Server-side, request-scoped admission gate shared by writer mounts.
///
/// The gate owns neither a route nor writer behavior. It turns an optional
/// wire credential into an optional immutable context exactly once per
/// request. A missing header is ordinary traffic; a present malformed,
/// mismatched, expired, or replayed header is an error and callers must fail
/// closed instead of treating it as absence.
#[derive(Clone, Debug)]
pub struct StagingLoadTestAdmissionGate {
    verifier: Arc<StagingLoadTestAdmissionVerifier>,
    store: Arc<StagingLoadTestAdmissionStore>,
}

impl StagingLoadTestAdmissionGate {
    /// Construct the staging-only gate from server configuration.
    pub fn from_env() -> Result<Self, StagingLoadTestAdmissionError> {
        Ok(Self {
            verifier: Arc::new(StagingLoadTestAdmissionVerifier::from_env()?),
            store: Arc::new(StagingLoadTestAdmissionStore::from_d1_env()?),
        })
    }

    /// Admit a supplied credential for one fixed writer scenario.
    pub async fn admit(
        &self,
        credential: Option<&str>,
        expected_scenario: StagingLoadTestScenario,
    ) -> Result<Option<Arc<StagingLoadTestAdmissionContext>>, StagingLoadTestAdmissionError> {
        let Some(credential) = credential else {
            return Ok(None);
        };
        let now_ms = unix_time_ms()?;
        let admission = self.verifier.verify(credential, now_ms)?;
        if admission.scenario != expected_scenario {
            return Err(StagingLoadTestAdmissionError::MismatchedIdentity);
        }
        // The expectation deliberately mirrors only verifier-authenticated
        // fields. Keep owned copies so the verified claim can move into the
        // durable consume operation that returns the immutable context.
        let run_id = admission.run_id.clone();
        let target_environment = admission.target_environment.clone();
        let target_deployment_sha = admission.target_deployment_sha.clone();
        let expected = StagingLoadTestAdmissionExpectation {
            run_id: &run_id,
            scenario: expected_scenario,
            target_environment: &target_environment,
            target_deployment_sha: &target_deployment_sha,
        };
        self.store
            .consume_verified_admission(expected, admission)
            .await
            .map(|context| Some(Arc::new(context)))
    }

    /// Authenticate a teardown credential without consuming its one-time
    /// admission nonce.  Teardown operates only on an already sealed durable
    /// run; consuming again would make a lost terminal response impossible to
    /// replay.  This context is therefore identity-only and must never reach a
    /// staging writer.
    pub(crate) fn verify_for_teardown(
        &self,
        credential: &str,
        expected_scenario: StagingLoadTestScenario,
    ) -> Result<Arc<StagingLoadTestAdmissionContext>, StagingLoadTestAdmissionError> {
        let now_ms = unix_time_ms()?;
        let admission = self.verifier.verify(credential, now_ms)?;
        teardown_context_from_verified(admission, expected_scenario, now_ms).map(Arc::new)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        verifier: StagingLoadTestAdmissionVerifier,
        store: StagingLoadTestAdmissionStore,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            store: Arc::new(store),
        }
    }
}

fn teardown_context_from_verified(
    admission: VerifiedStagingLoadTestAdmission,
    expected_scenario: StagingLoadTestScenario,
    now_ms: i64,
) -> Result<StagingLoadTestAdmissionContext, StagingLoadTestAdmissionError> {
    let expected = StagingLoadTestAdmissionExpectation {
        run_id: &admission.run_id,
        scenario: expected_scenario,
        target_environment: &admission.target_environment,
        target_deployment_sha: &admission.target_deployment_sha,
    };
    validate_claim(&expected, &admission, now_ms)?;
    Ok(StagingLoadTestAdmissionContext {
        run_id: admission.run_id,
        scenario: admission.scenario,
        target_environment: admission.target_environment,
        target_deployment_sha: admission.target_deployment_sha,
        admitted_at_ms: now_ms,
    })
}

/// Read the optional staging admission header and run its mandatory gate.
///
/// Routes use this helper so an unconfigured gate still accepts ordinary
/// requests without the header, while a supplied credential cannot silently
/// fall back to `None`.
pub async fn admit_staging_load_test_request(
    gate: Option<&StagingLoadTestAdmissionGate>,
    headers: &axum::http::HeaderMap,
    expected_scenario: StagingLoadTestScenario,
) -> Result<Option<Arc<StagingLoadTestAdmissionContext>>, StagingLoadTestAdmissionError> {
    let header = headers.get(STAGING_LOAD_TEST_ADMISSION_HEADER);
    match (gate, header) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(StagingLoadTestAdmissionError::InvalidCredential),
        (Some(gate), None) => gate.admit(None, expected_scenario).await,
        (Some(gate), Some(value)) => {
            gate.admit(
                value
                    .to_str()
                    .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)
                    .map(Some)?,
                expected_scenario,
            )
            .await
        }
    }
}

/// Read and authenticate a mandatory teardown admission header without
/// creating a run or consuming a nonce.  The physical service itself requires
/// an exact sealed run before it can mutate or replay its immutable receipt.
pub(crate) fn verify_staging_load_test_teardown_request(
    gate: Option<&StagingLoadTestAdmissionGate>,
    headers: &axum::http::HeaderMap,
    expected_scenario: StagingLoadTestScenario,
) -> Result<Arc<StagingLoadTestAdmissionContext>, StagingLoadTestAdmissionError> {
    let gate = gate.ok_or(StagingLoadTestAdmissionError::InvalidCredential)?;
    let credential = headers
        .get(STAGING_LOAD_TEST_ADMISSION_HEADER)
        .ok_or(StagingLoadTestAdmissionError::InvalidCredential)?
        .to_str()
        .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)?;
    gate.verify_for_teardown(credential, expected_scenario)
}

fn validate_claim(
    expected: &StagingLoadTestAdmissionExpectation<'_>,
    admission: &VerifiedStagingLoadTestAdmission,
    now_ms: i64,
) -> Result<(), StagingLoadTestAdmissionError> {
    validate_identity(
        &admission.run_id,
        admission.scenario,
        &admission.target_deployment_sha,
    )?;
    validate_identity(
        expected.run_id,
        expected.scenario,
        expected.target_deployment_sha,
    )?;
    if admission.target_environment != "staging" || expected.target_environment != "staging" {
        return Err(StagingLoadTestAdmissionError::NonStaging);
    }
    if admission.run_id != expected.run_id
        || admission.scenario != expected.scenario
        || admission.target_environment != expected.target_environment
        || admission.target_deployment_sha != expected.target_deployment_sha
    {
        return Err(StagingLoadTestAdmissionError::MismatchedIdentity);
    }
    decode_hex_32(&admission.nonce_digest)
        .ok_or(StagingLoadTestAdmissionError::PersistenceUnavailable)?;
    validate_lifetime(admission.issued_at_ms, admission.expires_at_ms)?;
    if admission.issued_at_ms > now_ms || now_ms >= admission.expires_at_ms {
        return Err(StagingLoadTestAdmissionError::Expired);
    }
    Ok(())
}

fn validate_identity(
    run_id: &str,
    _scenario: StagingLoadTestScenario,
    sha: &str,
) -> Result<(), StagingLoadTestAdmissionError> {
    if run_id.is_empty()
        || run_id.len() > 20
        || run_id.starts_with('0')
        || !run_id.bytes().all(|byte| byte.is_ascii_digit())
        || sha.len() != 40
        || !sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StagingLoadTestAdmissionError::InvalidIdentity);
    }
    Ok(())
}

fn validate_lifetime(
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> Result<(), StagingLoadTestAdmissionError> {
    let lifetime = expires_at_ms.checked_sub(issued_at_ms);
    if issued_at_ms < 0
        || expires_at_ms < 0
        || !matches!(lifetime, Some(value) if value > 0 && value <= MAX_CLAIM_LIFETIME_MS)
    {
        return Err(StagingLoadTestAdmissionError::InvalidLifetime);
    }
    Ok(())
}

fn parse_canonical_i64(value: &str) -> Result<i64, StagingLoadTestAdmissionError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(StagingLoadTestAdmissionError::InvalidCredential);
    }
    value
        .parse()
        .map_err(|_| StagingLoadTestAdmissionError::InvalidCredential)
}

fn decode_nonce(nonce: &str) -> Result<[u8; 32], StagingLoadTestAdmissionError> {
    decode_hex_32(nonce).ok_or(StagingLoadTestAdmissionError::InvalidNonce)
}

#[allow(dead_code)] // Validation helper for the frozen child-facing envelope seam above.
fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    let mut input = value.bytes();
    for byte in output.iter_mut() {
        let high = input.next().and_then(hex_nibble)?;
        let low = input.next().and_then(hex_nibble)?;
        *byte = (high << 4) | low;
    }
    if input.next().is_some() {
        return None;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn nonce_digest_hex(nonce_bytes: &[u8; 32]) -> Result<String, StagingLoadTestAdmissionError> {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN);
    for byte in nonce_bytes.iter().copied() {
        hasher.update([byte]);
    }
    lower_hex(hasher.finalize())
}

fn lower_hex(bytes: impl IntoIterator<Item = u8>) -> Result<String, StagingLoadTestAdmissionError> {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| StagingLoadTestAdmissionError::PersistenceUnavailable)?;
    }
    Ok(encoded)
}

fn parse_scenario(value: &str) -> Result<StagingLoadTestScenario, StagingLoadTestAdmissionError> {
    match value {
        "signup" => Ok(StagingLoadTestScenario::Signup),
        "webhook" => Ok(StagingLoadTestScenario::Webhook),
        "dsr" => Ok(StagingLoadTestScenario::Dsr),
        "cas" => Ok(StagingLoadTestScenario::Cas),
        "byok" => Ok(StagingLoadTestScenario::Byok),
        "endurance-2h" => Ok(StagingLoadTestScenario::Endurance2h),
        "b103-cargo-write" => Ok(StagingLoadTestScenario::B103CargoWrite),
        _ => Err(StagingLoadTestAdmissionError::InvalidIdentity),
    }
}

fn scenario_name(scenario: StagingLoadTestScenario) -> &'static str {
    match scenario {
        StagingLoadTestScenario::Signup => "signup",
        StagingLoadTestScenario::Webhook => "webhook",
        StagingLoadTestScenario::Dsr => "dsr",
        StagingLoadTestScenario::Cas => "cas",
        StagingLoadTestScenario::Byok => "byok",
        StagingLoadTestScenario::Endurance2h => "endurance-2h",
        StagingLoadTestScenario::B103CargoWrite => "b103-cargo-write",
    }
}

fn canonical_signed_payload(
    run_id: &str,
    scenario: StagingLoadTestScenario,
    sha: &str,
    issued: i64,
    expires: i64,
    nonce: &str,
) -> String {
    format!(
        "v1.{run_id}.{}.staging.{sha}.{issued}.{expires}.{nonce}",
        scenario_name(scenario)
    )
}

fn unix_time_ms() -> Result<i64, StagingLoadTestAdmissionError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StagingLoadTestAdmissionError::PersistenceUnavailable)?;
    i64::try_from(elapsed.as_millis())
        .map_err(|_| StagingLoadTestAdmissionError::PersistenceUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn verifier() -> StagingLoadTestAdmissionVerifier {
        StagingLoadTestAdmissionVerifier::new("staging", b"01234567890123456789012345678901")
            .expect("test key")
    }

    #[test]
    fn worker_ownership_envelope_is_domain_separated_bounded_and_request_bound() {
        let verifier = verifier();
        let context = StagingLoadTestAdmissionContext {
            run_id: "123".to_owned(),
            scenario: StagingLoadTestScenario::Signup,
            target_environment: "staging".to_owned(),
            target_deployment_sha: "a".repeat(40),
            admitted_at_ms: 999,
        };
        let request_id = "b".repeat(32);
        let envelope = verifier
            .mint_ownership_envelope(&context, &request_id, 1_000, 61_000)
            .expect("canonical envelope");
        assert!(envelope.starts_with(&format!(
            "v1.123.signup.staging.{}.1000.61000.{request_id}.",
            "a".repeat(40)
        )));
        assert!(envelope.len() <= 512);
        assert_eq!(envelope.split('.').count(), 9);
        assert_eq!(envelope.rsplit('.').next().map(str::len), Some(64));
        assert_eq!(
            verifier.mint_ownership_envelope(&context, "not-hex", 1_000, 61_000),
            Err(StagingLoadTestAdmissionError::InvalidIdentity)
        );
        assert_eq!(
            verifier.mint_ownership_envelope(&context, &request_id, 1_000, 1_000),
            Err(StagingLoadTestAdmissionError::InvalidLifetime)
        );
    }
    #[test]
    fn verifies_exact_authenticated_claim_and_redacts_secrets() {
        let verifier = verifier();
        let credential =
            verifier.sign_for_test("123", StagingLoadTestScenario::Cas, SHA, 100, 200, NONCE);
        let claim = verifier.verify(&credential, 150).expect("valid credential");
        assert!(format!("{verifier:?}").contains("[REDACTED]"));
        assert!(format!("{claim:?}").contains("[REDACTED]"));
        assert!(!format!("{claim:?}").contains(NONCE));
        let epoch_credential =
            verifier.sign_for_test("124", StagingLoadTestScenario::Cas, SHA, 0, 100, NONCE);
        assert!(verifier.verify(&epoch_credential, 50).is_ok());
    }
    #[test]
    fn rejects_forgery_nonstaging_and_lifetime_edges() {
        let verifier = verifier();
        let credential =
            verifier.sign_for_test("123", StagingLoadTestScenario::Cas, SHA, 100, 200, NONCE);
        assert!(matches!(
            verifier.verify(&credential.replace(".cas.", ".dsr."), 150),
            Err(StagingLoadTestAdmissionError::InvalidCredential)
        ));
        assert!(matches!(
            verifier.verify(&credential, 200),
            Err(StagingLoadTestAdmissionError::Expired)
        ));
        assert!(StagingLoadTestAdmissionVerifier::new(
            "production",
            b"01234567890123456789012345678901"
        )
        .is_err());
    }
    #[test]
    fn nonce_digest_is_lowercase_domain_separated_without_indexing() {
        let digest =
            nonce_digest_hex(&decode_nonce(NONCE).expect("canonical nonce")).expect("digest");
        assert_eq!(
            digest,
            "1fff857caecccadff3a32ad2952ad385c0e9c40e165de7a86bc2a86f2ce4dfc2"
        );
        assert!(decode_nonce(&"A".repeat(64)).is_err());
    }
    #[test]
    fn expected_identity_rejects_rebinding_and_future_claims() {
        let expected = StagingLoadTestAdmissionExpectation {
            run_id: "123",
            scenario: StagingLoadTestScenario::Cas,
            target_environment: "staging",
            target_deployment_sha: SHA,
        };
        let claim = VerifiedStagingLoadTestAdmission::from_verified_claims(
            "123".into(),
            StagingLoadTestScenario::Cas,
            "staging".into(),
            SHA.into(),
            "a".repeat(64),
            151,
            200,
        );
        assert_eq!(
            validate_claim(&expected, &claim, 150),
            Err(StagingLoadTestAdmissionError::Expired)
        );
    }

    #[test]
    fn teardown_verification_is_read_only_and_replayable_for_one_exact_identity() {
        let claim = || {
            VerifiedStagingLoadTestAdmission::from_verified_claims(
                "123".into(),
                StagingLoadTestScenario::Cas,
                "staging".into(),
                SHA.into(),
                "a".repeat(64),
                100,
                200,
            )
        };
        let first = teardown_context_from_verified(claim(), StagingLoadTestScenario::Cas, 150)
            .expect("first authenticated teardown context");
        let replay = teardown_context_from_verified(claim(), StagingLoadTestScenario::Cas, 151)
            .expect("replayed authenticated teardown context");
        assert_eq!(first.run_id(), replay.run_id());
        assert_eq!(
            first.target_deployment_sha(),
            replay.target_deployment_sha()
        );
        assert_eq!(first.scenario(), replay.scenario());
    }

    #[tokio::test]
    async fn loopback_store_consumes_a_verified_claim_in_the_real_d1_batch_shape() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("loopback connection");
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).expect("request read");
                bytes.extend_from_slice(&buffer[..read]);
                let Some(headers_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&bytes[..headers_end]).expect("headers utf8");
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .expect("content length")
                    .parse::<usize>()
                    .expect("content length number");
                if bytes.len() >= headers_end + 4 + length {
                    break;
                }
            }
            let body_start = bytes
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .expect("headers")
                + 4;
            let request: serde_json::Value =
                serde_json::from_slice(&bytes[body_start..]).expect("D1 batch JSON");
            let batch = request["batch"].as_array().expect("D1 batch");
            assert_eq!(batch.len(), 2);
            assert!(batch[0]["sql"]
                .as_str()
                .is_some_and(|sql| sql == SQL_INSERT_RUN));
            assert!(batch[1]["sql"]
                .as_str()
                .is_some_and(|sql| sql == SQL_INSERT_NONCE));
            let body = serde_json::json!({
                "result": [
                    { "results": [], "success": true },
                    { "results": [], "success": true }
                ],
                "success": true,
                "errors": []
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("response write");
        });

        let env = crate::storage::StorageEnv {
            r2_endpoint: "https://localhost:1".to_owned(),
            r2_access_key_id: "test".to_owned(),
            r2_secret_access_key: "test".to_owned(),
            cloudflare_account_id: "test".to_owned(),
            cf_api_token: "test".to_owned(),
            d1_database_id: "test".to_owned(),
        };
        let store = StagingLoadTestAdmissionStore::from_d1_client_for_test(
            D1HttpClient::new_for_loopback_test(&env, &endpoint).expect("loopback D1 client"),
        );
        let verifier = verifier();
        let now_ms = unix_time_ms().expect("clock");
        let credential = verifier.sign_for_test(
            "123",
            StagingLoadTestScenario::Cas,
            SHA,
            now_ms - 1,
            now_ms + 60_000,
            NONCE,
        );
        let gate = StagingLoadTestAdmissionGate::from_parts_for_test(verifier, store);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            STAGING_LOAD_TEST_ADMISSION_HEADER,
            credential.parse().expect("credential header"),
        );
        let context =
            admit_staging_load_test_request(Some(&gate), &headers, StagingLoadTestScenario::Cas)
                .await
                .expect("verified durable consume")
                .expect("context");
        assert_eq!(context.run_id(), "123");
        server.join().expect("loopback server");
    }

    #[tokio::test]
    async fn present_admission_header_fails_closed_when_the_gate_is_not_configured() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            STAGING_LOAD_TEST_ADMISSION_HEADER,
            axum::http::HeaderValue::from_static("forged"),
        );
        assert_eq!(
            admit_staging_load_test_request(None, &headers, StagingLoadTestScenario::Cas).await,
            Err(StagingLoadTestAdmissionError::InvalidCredential)
        );
    }
}
