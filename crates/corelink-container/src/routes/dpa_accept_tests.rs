#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use super::*;

use std::collections::HashMap;
use std::sync::Mutex;

use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;

const TEST_SHARED_KEY: &str = "shared-key-000000000000000000000";
const TEST_DEDICATED_KEY: &str = "dedicated-key-000000000000000000";

fn test_ip_hash_salt() -> IpHashSalt {
    IpHashSalt::new(Some(&[0x54; 32])).expect("valid route test salt")
}

fn clear_auth_env() {
    std::env::remove_var(DPA_ACCEPT_AUTH_KEY_ENV);
    std::env::remove_var("CORELINK_INTERNAL_AUTH_KEY");
}

#[test]
fn dpa_accept_auth_resolution_is_dedicated_first_and_32_char_fail_closed() {
    let _guard = super::super::admin::INTERNAL_AUTH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_auth_env();

    // Dedicated beats shared: mutating the call back to the old raw
    // shared read makes this assertion fail.
    std::env::set_var("CORELINK_INTERNAL_AUTH_KEY", TEST_SHARED_KEY);
    std::env::set_var(DPA_ACCEPT_AUTH_KEY_ENV, TEST_DEDICATED_KEY);
    assert_eq!(
        dpa_accept_auth_key_from_env().as_deref(),
        Some(TEST_DEDICATED_KEY)
    );

    // The migration fallback remains available when dedicated is absent.
    std::env::remove_var(DPA_ACCEPT_AUTH_KEY_ENV);
    assert_eq!(
        dpa_accept_auth_key_from_env().as_deref(),
        Some(TEST_SHARED_KEY)
    );

    // A 16-character key must not mount the consent path, even if it is
    // the dedicated value; this kills a mutation restoring the old gate.
    std::env::set_var(DPA_ACCEPT_AUTH_KEY_ENV, "1234567890123456");
    std::env::remove_var("CORELINK_INTERNAL_AUTH_KEY");
    assert!(dpa_accept_auth_key_from_env().is_none());

    // A present but short dedicated value fails closed instead of falling
    // back to a valid shared key.
    std::env::set_var("CORELINK_INTERNAL_AUTH_KEY", TEST_SHARED_KEY);
    assert!(dpa_accept_auth_key_from_env().is_none());
    clear_auth_env();
}

#[test]
fn dpa_accept_ip_salt_is_required_and_validated_before_state_construction() {
    let _guard = super::super::admin::INTERNAL_AUTH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::remove_var(DPA_ACCEPT_IP_HASH_SALT_ENV);
    assert!(dpa_accept_ip_hash_salt_from_env().is_none());

    std::env::set_var(DPA_ACCEPT_IP_HASH_SALT_ENV, hex::encode([0; 32]));
    assert!(dpa_accept_ip_hash_salt_from_env().is_none());
    std::env::set_var(DPA_ACCEPT_IP_HASH_SALT_ENV, "not-hex");
    assert!(dpa_accept_ip_hash_salt_from_env().is_none());
    std::env::set_var(DPA_ACCEPT_IP_HASH_SALT_ENV, hex::encode([0x55; 32]));
    let salt = dpa_accept_ip_hash_salt_from_env().expect("valid configured salt");
    assert_eq!(salt.hash_ip("203.0.113.7").len(), 64);
    std::env::remove_var(DPA_ACCEPT_IP_HASH_SALT_ENV);
}

/// In-memory `DpaAcceptStore` that also exposes the tier-select gate query
/// (`SELECT 1 ... WHERE tenant_id=? AND dpa_version=?`) so a test can prove
/// the round-trip: accept → row written → `is_accepted` reads true.
#[derive(Debug, Default)]
struct FakeStore {
    rows: Mutex<HashMap<String, AcceptanceRow>>,
}

impl FakeStore {
    fn new() -> Self {
        Self::default()
    }
    fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
    /// Mirror of `D1HttpTierSelectStore::is_dpa_accepted`.
    fn is_accepted(&self, tenant_id: &str, dpa_version: &str) -> bool {
        self.rows
            .lock()
            .unwrap()
            .values()
            .any(|r| r.tenant_id == tenant_id && r.dpa_version == dpa_version)
    }
    fn get_row(&self, signup_id: &str) -> Option<AcceptanceRow> {
        self.rows.lock().unwrap().get(signup_id).cloned()
    }
}

impl DpaAcceptStore for FakeStore {
    async fn find_by_signup_id(&self, signup_id: &str) -> Result<Option<StoredAcceptance>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(signup_id)
            .map(|r| StoredAcceptance {
                jwt_receipt_jti: r.jwt_receipt_jti.clone(),
                dpa_version: r.dpa_version.clone(),
                locale: r.locale.clone(),
                accepted_at: r.accepted_at,
            }))
    }
    async fn insert_acceptance(&self, row: &AcceptanceRow) -> Result<bool, String> {
        let mut g = self.rows.lock().unwrap();
        if g.contains_key(&row.signup_id) {
            return Ok(false); // PK conflict → INSERT OR IGNORE no-op.
        }
        g.insert(row.signup_id.clone(), row.clone());
        Ok(true)
    }
}

fn test_signing_key() -> RsaPrivateKeyPem {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    RsaPrivateKeyPem(
        key.to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string(),
    )
}

fn valid_req(locale: LocaleBcp47) -> ValidatedDpaRequest {
    ValidatedDpaRequest {
        dpa_version: "1.0.0".to_owned(),
        locale,
        notice_hash: "a".repeat(64),
        ui_capture_ts: Some(1_700_000_000_000),
        client_ip: "203.0.113.7".to_owned(),
    }
}

#[tokio::test]
async fn accept_writes_row_and_gate_reads_true() {
    let store = FakeStore::new();
    let key = test_signing_key();
    let tenant = "tenant-abc";
    let now = 1_700_000_500_000_i64;

    let resp = orchestrate_dpa_accept(
        &store,
        &key,
        RECEIPT_KID,
        &test_ip_hash_salt(),
        tenant,
        &valid_req(LocaleBcp47::EnUs),
        now,
    )
    .await
    .expect("accept succeeds");

    // The tier-select money-path gate now reads true.
    assert!(store.is_accepted(tenant, "1.0.0"));
    assert_eq!(store.len(), 1);
    assert_eq!(resp.dpa_version, "1.0.0");
    assert_eq!(resp.dpa_locale, "en-US");
    assert!(!resp.audit_event_id.is_empty());

    // Row columns are all real + CHECK-valid.
    let row = store.get_row(&format!("dpa:{tenant}:1.0.0")).unwrap();
    assert_eq!(row.tenant_id, tenant);
    assert_eq!(row.locale, "en-US");
    assert_eq!(row.notice_hash.len(), 64);
    assert_eq!(row.accepted_ip_hash.len(), 64); // sha256 hex64 (CHECK)
    assert!(!row.wording_id.is_empty());
    assert_eq!(row.schema_version, 1);
    assert_eq!(row.accepted_at, now);
    assert!(row.submission_ts >= row.ui_capture_ts); // submission_after_capture CHECK
    assert_eq!(row.jwt_receipt_jti, resp.audit_event_id);
}

#[tokio::test]
async fn reaccept_is_idempotent_no_new_row() {
    let store = FakeStore::new();
    let key = test_signing_key();
    let tenant = "tenant-idem";

    let first = orchestrate_dpa_accept(
        &store,
        &key,
        RECEIPT_KID,
        &test_ip_hash_salt(),
        tenant,
        &valid_req(LocaleBcp47::PtBr),
        1_700_000_000_000,
    )
    .await
    .expect("first accept");

    let second = orchestrate_dpa_accept(
        &store,
        &key,
        RECEIPT_KID,
        &test_ip_hash_salt(),
        tenant,
        &valid_req(LocaleBcp47::PtBr),
        1_700_000_999_000,
    )
    .await
    .expect("re-accept");

    assert_eq!(store.len(), 1, "re-accept must NOT write a second row");
    assert_eq!(
        first.audit_event_id, second.audit_event_id,
        "same original receipt"
    );
    assert_eq!(second.dpa_accepted_at, first.dpa_accepted_at);
}

#[test]
fn unsupported_locale_rejected() {
    // `de` is outside the closed 3-locale GA set.
    let body = DpaAcceptRequestBody {
        dpa_version: "1.0.0".to_owned(),
        dpa_locale: "de".to_owned(),
        notice_text_hash: "a".repeat(64),
        ui_capture_ts: None,
    };
    let err = validate_request("1.0.0", body, "ip".to_owned()).unwrap_err();
    assert_eq!(err, DpaAcceptHttpError::UnsupportedLocale);
}

#[test]
fn locales_map_short_and_canonical() {
    assert_eq!(map_locale("en"), Some(LocaleBcp47::EnUs));
    assert_eq!(map_locale("en-US"), Some(LocaleBcp47::EnUs));
    assert_eq!(map_locale("pt"), Some(LocaleBcp47::PtBr));
    assert_eq!(map_locale("es-419"), Some(LocaleBcp47::Es419));
    assert_eq!(map_locale("de"), None);
    assert_eq!(map_locale("fr-FR"), None);
}

#[test]
fn bad_notice_hash_rejected() {
    for bad in ["", "xyz", &"a".repeat(63), &"A".repeat(64), &"g".repeat(64)] {
        let body = DpaAcceptRequestBody {
            dpa_version: "1.0.0".to_owned(),
            dpa_locale: "en".to_owned(),
            notice_text_hash: bad.to_owned(),
            ui_capture_ts: None,
        };
        assert_eq!(
            validate_request("1.0.0", body, "ip".to_owned()).unwrap_err(),
            DpaAcceptHttpError::BadRequest,
            "hash {bad:?} must be rejected",
        );
    }
}

#[test]
fn version_mismatch_rejected() {
    let body = DpaAcceptRequestBody {
        dpa_version: "2.0.0".to_owned(),
        dpa_locale: "en".to_owned(),
        notice_text_hash: "a".repeat(64),
        ui_capture_ts: None,
    };
    assert_eq!(
        validate_request("1.0.0", body, "ip".to_owned()).unwrap_err(),
        DpaAcceptHttpError::VersionMismatch,
    );
}

#[test]
fn valid_request_accepted() {
    let body = DpaAcceptRequestBody {
        dpa_version: "1.0.0".to_owned(),
        dpa_locale: "pt".to_owned(),
        notice_text_hash: canonical_notice_hash(LocaleBcp47::PtBr).to_owned(),
        ui_capture_ts: Some(123),
    };
    let v = validate_request("1.0.0", body, "9.9.9.9".to_owned()).unwrap();
    assert_eq!(v.locale, LocaleBcp47::PtBr);
    assert_eq!(v.notice_hash, canonical_notice_hash(LocaleBcp47::PtBr));
}

#[test]
fn canonical_hash_rejects_a_forged_but_well_formed_digest() {
    let body = DpaAcceptRequestBody {
        dpa_version: "1.0.0".to_owned(),
        dpa_locale: "en-US".to_owned(),
        // SHA-256-shaped, but not the hash of the versioned notice.
        notice_text_hash: "a".repeat(64),
        ui_capture_ts: None,
    };
    assert_eq!(
        validate_request("1.0.0", body, "ip".to_owned()).unwrap_err(),
        DpaAcceptHttpError::BadRequest
    );
}

#[test]
fn missing_key_fails_closed() {
    // Empty / garbage PEM ⇒ None ⇒ route UNMOUNTED (fail-CLOSED).
    assert!(parse_signing_key("").is_none());
    assert!(parse_signing_key("   ").is_none());
    assert!(parse_signing_key("not-a-pem").is_none());
    assert!(parse_signing_key(
        "-----BEGIN PRIVATE KEY-----\nbm90YWtleQ==\n-----END PRIVATE KEY-----\n"
    )
    .is_none());
    // A real generated key ⇒ Some ⇒ mountable.
    let pem = {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    };
    assert!(parse_signing_key(&pem).is_some());
}

#[test]
fn auth_gate_constant_time_rejects() {
    let mut h = HeaderMap::new();
    // Missing header → Unauthenticated.
    assert_eq!(
        verify_internal_auth(&h, "the-secret-value-1234").unwrap_err(),
        DpaAcceptHttpError::Unauthenticated,
    );
    // Wrong secret → Unauthenticated.
    h.insert(INTERNAL_AUTH_HEADER, "wrong".parse().unwrap());
    assert_eq!(
        verify_internal_auth(&h, "the-secret-value-1234").unwrap_err(),
        DpaAcceptHttpError::Unauthenticated,
    );
    // Correct secret → Ok.
    h.insert(
        INTERNAL_AUTH_HEADER,
        "the-secret-value-1234".parse().unwrap(),
    );
    assert!(verify_internal_auth(&h, "the-secret-value-1234").is_ok());
}

#[test]
fn tenant_extracted_from_header_only() {
    let mut h = HeaderMap::new();
    assert_eq!(
        extract_verified_tenant(&h).unwrap_err(),
        DpaAcceptHttpError::NoVerifiedTenant,
    );
    h.insert(TENANT_HEADER, "  tenant-xyz  ".parse().unwrap());
    assert_eq!(extract_verified_tenant(&h).unwrap(), "tenant-xyz");
}

#[test]
fn wording_id_is_deterministic() {
    assert_eq!(wording_id_for("1.0.0"), wording_id_for("1.0.0"));
    assert_ne!(wording_id_for("1.0.0"), wording_id_for("1.0.1"));
}
