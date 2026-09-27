#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use super::*;

const TEST_KEY: &[u8; 16] = b"test-hmac-key!!!";

fn fixed_now_ms() -> u64 {
    1_700_000_000_000
}

#[test]
fn mint_then_verify_roundtrips() {
    let token =
        mint_pilot_token(TokenEnv::Prod, fixed_now_ms(), "0123456789abcdef", TEST_KEY).unwrap();
    let parsed = parse_and_verify_pilot_token(&token, TEST_KEY, fixed_now_ms()).expect("verify");
    assert_eq!(parsed.env, TokenEnv::Prod);
    assert_eq!(parsed.minted_at_ms, fixed_now_ms());
    assert_eq!(parsed.token_id, "0123456789abcdef");
}

#[test]
fn forged_signature_rejected() {
    let token = mint_pilot_token(
        TokenEnv::Staging,
        fixed_now_ms(),
        "deadbeefcafef00d",
        TEST_KEY,
    )
    .unwrap();
    // Flip the last hex char of the signature.
    let mut bytes: Vec<char> = token.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
    let forged: String = bytes.into_iter().collect();
    let err = parse_and_verify_pilot_token(&forged, TEST_KEY, fixed_now_ms())
        .expect_err("forged rejected");
    assert_eq!(err, TokenError::SignatureMismatch);
}

#[test]
fn wrong_key_rejected() {
    let token =
        mint_pilot_token(TokenEnv::Prod, fixed_now_ms(), "ffffffff00000000", TEST_KEY).unwrap();
    let err = parse_and_verify_pilot_token(&token, b"other-key-zzzz!!", fixed_now_ms())
        .expect_err("wrong key rejected");
    assert_eq!(err, TokenError::SignatureMismatch);
}

#[test]
fn expired_token_rejected() {
    let minted_at_ms = fixed_now_ms();
    let token =
        mint_pilot_token(TokenEnv::Prod, minted_at_ms, "0000000011111111", TEST_KEY).unwrap();
    // Advance well beyond the TTL.
    let later = minted_at_ms + PILOT_TOKEN_TTL_MS + 1;
    let err = parse_and_verify_pilot_token(&token, TEST_KEY, later).expect_err("expired rejected");
    assert_eq!(err, TokenError::Expired);
}

#[test]
fn future_minted_token_accepted() {
    // Clock skew tolerance: a token minted 1h "in the future"
    // still verifies (operator may pre-mint for a launch).
    let minted_at_ms = fixed_now_ms() + 3_600_000;
    let token =
        mint_pilot_token(TokenEnv::Prod, minted_at_ms, "aaaaaaaabbbbbbbb", TEST_KEY).unwrap();
    let parsed = parse_and_verify_pilot_token(&token, TEST_KEY, fixed_now_ms())
        .expect("future-mint accepted");
    assert_eq!(parsed.minted_at_ms, minted_at_ms);
}

#[test]
fn malformed_tokens_rejected() {
    let key = TEST_KEY;
    let now = fixed_now_ms();
    // No `.`.
    assert_eq!(
        parse_and_verify_pilot_token("pilot_prod_0_aaaaaaaaaaaaaaaa", key, now),
        Err(TokenError::Malformed),
    );
    // Bad env.
    let body = format!("pilot_dev_{}_aaaaaaaaaaaaaaaa", now);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let tok = format!("{body}.{sig}");
    assert_eq!(
        parse_and_verify_pilot_token(&tok, key, now),
        Err(TokenError::BadEnv),
    );
    // Not pilot.
    let body = format!("admin_prod_{}_aaaaaaaaaaaaaaaa", now);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let tok = format!("{body}.{sig}");
    assert_eq!(
        parse_and_verify_pilot_token(&tok, key, now),
        Err(TokenError::NotPilotToken),
    );
    // Bad random (not hex).
    let body = format!("pilot_prod_{}_zzzzzzzzzzzzzzzz", now);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let tok = format!("{body}.{sig}");
    assert_eq!(
        parse_and_verify_pilot_token(&tok, key, now),
        Err(TokenError::BadRandom),
    );
}

#[test]
fn body_validation_catches_missing_and_oversize() {
    let mut body = PilotSignupBody {
        email: "a@b.com".to_owned(),
        company_name: "Co".to_owned(),
        tier_hint: "free".to_owned(),
        expected_use_case: "ci".to_owned(),
    };
    body.validate().unwrap();
    body.email = String::new();
    assert_eq!(body.validate(), Err("email"));
    body.email = "a@b.com".to_owned();
    body.tier_hint = "x".repeat(MAX_FIELD_LEN + 1);
    assert_eq!(body.validate(), Err("tier_hint"));
    body.tier_hint = "free".to_owned();
    body.email = "not-an-email".to_owned();
    assert_eq!(body.validate(), Err("email"));
}

#[test]
fn pilot_rate_limit_uses_exact_five_per_hour_refill() {
    let config = pilot_signup_rate_limit_config();
    assert_eq!(config.default_burst_capacity(), 5);
    assert_eq!(config.default_refill_rate_per_sec(), 0);
    assert!((config.default_refill_rate_per_sec_exact() - (5.0 / 3_600.0)).abs() < 1e-12);
    assert_eq!(config.retry_after_floor_secs(), 720);
}

#[test]
fn in_memory_store_dedupes_on_email() {
    let store = InMemorySignupStore::new();
    let mk = |email: &str, token_id: &str| PilotSignupRecord {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        email: email.to_owned(),
        company_name: "X".to_owned(),
        tier_hint: "free".to_owned(),
        expected_use_case: "ci".to_owned(),
        signed_up_at_ms: 0,
        token_id: token_id.to_owned(),
        state: "RESERVED".to_owned(),
    };
    let r1 = mk("dup@example.com", "tok1");
    let r2 = mk("dup@example.com", "tok2"); // same email, different token
    let stored1 = store.insert_or_existing(r1.clone()).unwrap();
    let stored2 = store.insert_or_existing(r2).unwrap();
    assert_eq!(stored1.id, stored2.id, "duplicate email returns original");
    assert_eq!(stored1.tenant_id, stored2.tenant_id);
}

#[test]
fn router_builds() {
    let _r = router(build_state());
}

#[tokio::test]
async fn forged_staging_admission_is_rejected_before_signup_write() {
    let store = Arc::new(InMemorySignupStore::new());
    let mut state = build_state_with_key(TEST_KEY.to_vec());
    state.store = store.clone();
    let mut headers = HeaderMap::new();
    headers.insert(
        crate::storage::staging_load_test_admission::STAGING_LOAD_TEST_ADMISSION_HEADER,
        "forged".parse().unwrap(),
    );
    let body = PilotSignupBody {
        email: "pilot@example.com".to_owned(),
        company_name: "Example".to_owned(),
        tier_hint: "free".to_owned(),
        expected_use_case: "staging admission regression".to_owned(),
    };

    let response = handle_pilot_signup(
        State(state),
        Path("not-a-valid-pilot-token".to_owned()),
        headers,
        Json(body),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(store.snapshot().unwrap().is_empty());
}

// ── F1 regressions: extract_client_ip ─────────────────────────────────────

/// F1: `x-corelink-client-ip` is read as the trusted rate-limit key.
#[test]
fn extract_client_ip_reads_trusted_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-corelink-client-ip", "203.0.113.42".parse().unwrap());
    assert_eq!(extract_client_ip(&headers), "203.0.113.42");
}

/// F1: a client-forged `x-forwarded-for` is completely ignored.
#[test]
fn extract_client_ip_ignores_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    // Only XFF is present; x-corelink-client-ip is absent.
    headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
    // Must NOT return "1.2.3.4" (or any value from XFF).
    // Must return the shared no-ip sentinel.
    assert_eq!(
        extract_client_ip(&headers),
        "_no_ip",
        "forged x-forwarded-for must be ignored; missing trusted header must collapse to _no_ip"
    );
}

/// F1: both XFF and the trusted header are present — only the
/// trusted header wins.
#[test]
fn extract_client_ip_trusted_header_wins_over_xff() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());
    headers.insert("x-corelink-client-ip", "203.0.113.99".parse().unwrap());
    assert_eq!(
        extract_client_ip(&headers),
        "203.0.113.99",
        "trusted header must win; XFF must not influence the bucket key"
    );
}

/// F1: absent `x-corelink-client-ip` → shared `"_no_ip"` sentinel
/// (fail-CLOSED: one shared bucket, not unlimited unique keys).
#[test]
fn extract_client_ip_missing_header_returns_shared_no_ip_bucket() {
    let headers = HeaderMap::new();
    assert_eq!(
        extract_client_ip(&headers),
        "_no_ip",
        "missing trusted header must yield the shared _no_ip bucket"
    );
}

/// F1: empty-value `x-corelink-client-ip` → shared `"_no_ip"` sentinel.
#[test]
fn extract_client_ip_empty_header_returns_shared_no_ip_bucket() {
    let mut headers = HeaderMap::new();
    // An empty (whitespace-only) value must also collapse.
    headers.insert("x-corelink-client-ip", "   ".parse().unwrap());
    assert_eq!(
        extract_client_ip(&headers),
        "_no_ip",
        "empty trusted header must yield the shared _no_ip bucket"
    );
}

// ── env-gate: build_state_from_env (fail-CLOSED) ───────────────────────────
//
// These two tests mutate the process-global `SIGNUP_TOKEN_KEY`, so they are
// serialized through a module-local lock and each restores the prior value.
// No OTHER test in this crate reads `SIGNUP_TOKEN_KEY`, so the only possible
// race is between these two — which the lock removes. (edition-2021:
// `set_var`/`remove_var` are safe; see `tier_select_checkout.rs`.)
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Fail-CLOSED: no `SIGNUP_TOKEN_KEY` in the environment → `None`, so the
/// caller never mounts `/v1/signup/pilot` with the public dev key.
#[test]
fn build_state_from_env_is_none_without_secret() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SIGNUP_TOKEN_KEY").ok();
    std::env::remove_var("SIGNUP_TOKEN_KEY");
    assert!(
        build_state_from_env().is_none(),
        "absent SIGNUP_TOKEN_KEY must yield None (fail-CLOSED)"
    );
    if let Some(v) = prev {
        std::env::set_var("SIGNUP_TOKEN_KEY", v);
    }
}

/// The D1 storage env vars `build_state_from_env` needs for the durable
/// store + audit sink. Values are syntactically valid but point nowhere —
/// `from_env` only reads them, so nothing is dialled here.
const STORAGE_ENV: [(&str, &str); 6] = [
    ("R2_S3_ENDPOINT", "https://example.invalid"),
    ("R2_S3_ACCESS_KEY_ID", "test-access-key-id"),
    ("R2_S3_SECRET_ACCESS_KEY", "test-secret-access-key"),
    ("CLOUDFLARE_ACCOUNT_ID", "test-account-id"),
    ("CF_API_TOKEN", "test-api-token"),
    ("D1_DATABASE_ID", "test-database-id"),
];

/// The token key ALONE is NOT enough: without the D1 config the route
/// must stay unmounted rather than silently fall back to the in-memory
/// store. That fallback was a real shipped bug — the route answered
/// `201 Created` while prod D1 stayed at `COUNT(*)=0`.
#[test]
fn build_state_from_env_is_none_without_storage_env() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev_key = std::env::var("SIGNUP_TOKEN_KEY").ok();
    let prev_storage: Vec<_> = STORAGE_ENV
        .iter()
        .map(|(k, _)| (*k, std::env::var(k).ok()))
        .collect();
    for (k, _) in STORAGE_ENV {
        std::env::remove_var(k);
    }
    std::env::set_var("SIGNUP_TOKEN_KEY", "ab".repeat(32));
    assert!(
        build_state_from_env().is_none(),
        "a valid SIGNUP_TOKEN_KEY without the D1 storage env must yield \
             None (fail-CLOSED — never the in-memory store in production)"
    );
    for (k, v) in prev_storage {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    match prev_key {
        Some(v) => std::env::set_var("SIGNUP_TOKEN_KEY", v),
        None => std::env::remove_var("SIGNUP_TOKEN_KEY"),
    }
}

/// A valid hex key AND the D1 storage env together yield `Some`, so
/// production with both mounts the route — on the durable store.
#[test]
fn build_state_from_env_is_some_with_valid_hex_secret_and_storage_env() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev_key = std::env::var("SIGNUP_TOKEN_KEY").ok();
    let prev_storage: Vec<_> = STORAGE_ENV
        .iter()
        .map(|(k, _)| (*k, std::env::var(k).ok()))
        .collect();
    // 32 bytes (0xAB) hex-encoded.
    std::env::set_var("SIGNUP_TOKEN_KEY", "ab".repeat(32));
    for (k, v) in STORAGE_ENV {
        std::env::set_var(k, v);
    }
    assert!(
        build_state_from_env().is_some(),
        "valid SIGNUP_TOKEN_KEY + D1 storage env must yield Some"
    );
    for (k, v) in prev_storage {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    match prev_key {
        Some(v) => std::env::set_var("SIGNUP_TOKEN_KEY", v),
        None => std::env::remove_var("SIGNUP_TOKEN_KEY"),
    }
}

/// A too-short hex key (< 32 bytes decoded) is rejected → `None`
/// (fail-CLOSED), mirroring `internal_pat`'s length floor.
#[test]
fn build_state_from_env_is_none_with_short_secret() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("SIGNUP_TOKEN_KEY").ok();
    // 16 bytes — below the 32-byte floor.
    std::env::set_var("SIGNUP_TOKEN_KEY", "cd".repeat(16));
    assert!(
        build_state_from_env().is_none(),
        "SIGNUP_TOKEN_KEY shorter than 32 decoded bytes must yield None"
    );
    match prev {
        Some(v) => std::env::set_var("SIGNUP_TOKEN_KEY", v),
        None => std::env::remove_var("SIGNUP_TOKEN_KEY"),
    }
}
