use super::*;

/// Process-wide env-var lock to serialise tests that mutate
/// `STRIPE_AUTH_MODE` / `STRIPE_SECRET_KEY` / `HUGR_WALLET_*` /
/// `STRIPE_API_BASE` / `HUGR_STRIPE_REF`. Cargo runs `#[test]`s
/// concurrently per binary, and these process-global env vars
/// race otherwise.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Capture + clear every env var these tests touch; restore on
/// drop. Used as a scope guard inside each env-touching test.
struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn new(vars: &[&'static str]) -> Self {
        // .unwrap_or_else on poison so a previous test panic
        // doesn't take down the whole suite — we still want the
        // exclusion semantics. Tests are allowed to panic per
        // module-level allow.
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved: Vec<_> = vars.iter().map(|k| (*k, env::var(*k).ok())).collect();
        for k in vars {
            env::remove_var(k);
        }
        Self { saved, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => env::set_var(k, val),
                None => env::remove_var(k),
            }
        }
    }
}

const ENV_KEYS: &[&str] = &[
    "STRIPE_AUTH_MODE",
    "STRIPE_API_BASE",
    "STRIPE_SECRET_KEY",
    "HUGR_WALLET_BASE",
    "HUGR_WALLET_TOKEN",
    "HUGR_STRIPE_REF",
];

fn direct_test_config() -> StripeClientConfig {
    StripeClientConfig::direct(
        "https://api.stripe.test",
        SecretString::from("sk_test_DUMMY".to_string()),
    )
}

fn wallet_test_config() -> StripeClientConfig {
    StripeClientConfig::wallet_broker(
        "https://wallet.test",
        SecretString::from("hugrw_test_token".to_string()),
        "stripe-prod",
    )
}

#[test]
fn debug_redacts_in_both_modes() {
    // Direct.
    let cfg_direct = StripeClientConfig::direct(
        "https://api.stripe.test",
        SecretString::from("sk_test_DO_NOT_LOG_ME".to_string()),
    );
    let dbg_direct = format!("{cfg_direct:?}");
    assert!(
        dbg_direct.contains("<redacted>"),
        "Direct config Debug must redact: {dbg_direct}"
    );
    assert!(
        !dbg_direct.contains("sk_"),
        "Direct config Debug must NOT contain sk_ prefix: {dbg_direct}"
    );
    assert!(
        !dbg_direct.contains("DO_NOT_LOG_ME"),
        "Direct config Debug must NOT contain raw key: {dbg_direct}"
    );

    // WalletBroker.
    let cfg_wallet = StripeClientConfig::wallet_broker(
        "https://wallet.test",
        SecretString::from("hugrw_DO_NOT_LOG_ME".to_string()),
        "stripe-prod",
    );
    let dbg_wallet = format!("{cfg_wallet:?}");
    assert!(
        dbg_wallet.contains("<redacted>"),
        "Wallet config Debug must redact: {dbg_wallet}"
    );
    assert!(
        !dbg_wallet.contains("hugrw_"),
        "Wallet config Debug must NOT contain hugrw_ prefix: {dbg_wallet}"
    );
    assert!(
        !dbg_wallet.contains("DO_NOT_LOG_ME"),
        "Wallet config Debug must NOT contain raw token: {dbg_wallet}"
    );
}

#[test]
fn debug_redacts_on_built_client_both_modes() {
    // Direct client.
    let c_direct = StripeRealClient::builder()
        .config(StripeClientConfig::direct(
            "https://api.stripe.test",
            SecretString::from("sk_test_SECRET".to_string()),
        ))
        .build()
        .unwrap();
    let dbg = format!("{c_direct:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(
        !dbg.contains("sk_"),
        "Direct client Debug leaked sk_: {dbg}"
    );
    assert!(!dbg.contains("SECRET"));

    // Wallet client.
    let c_wallet = StripeRealClient::builder()
        .config(StripeClientConfig::wallet_broker(
            "https://wallet.test",
            SecretString::from("hugrw_SECRET".to_string()),
            "stripe-prod",
        ))
        .build()
        .unwrap();
    let dbg = format!("{c_wallet:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(
        !dbg.contains("hugrw_"),
        "Wallet client Debug leaked hugrw_: {dbg}"
    );
    assert!(!dbg.contains("SECRET"));
}

#[test]
fn builder_direct_yields_api_stripe_base() {
    let c = StripeRealClient::builder()
        .config(direct_test_config())
        .build()
        .unwrap();
    assert_eq!(c.effective_base_url(), "https://api.stripe.test");
}

#[test]
fn builder_wallet_yields_wallet_proxy_base() {
    let c = StripeRealClient::builder()
        .config(wallet_test_config())
        .build()
        .unwrap();
    assert_eq!(c.effective_base_url(), "https://wallet.test/stripe-prod");
}

#[test]
fn effective_base_url_trims_trailing_slash_direct() {
    let cfg = StripeClientConfig::direct(
        "https://api.stripe.test/",
        SecretString::from("sk_test_x".to_string()),
    );
    assert_eq!(cfg.effective_base_url(), "https://api.stripe.test");
}

#[test]
fn effective_base_url_trims_trailing_slash_wallet() {
    let cfg = StripeClientConfig::wallet_broker(
        "https://wallet.test/",
        SecretString::from("hugrw_x".to_string()),
        "stripe-prod",
    );
    assert_eq!(cfg.effective_base_url(), "https://wallet.test/stripe-prod");
}

#[test]
fn from_env_direct_default_when_unset() {
    let _g = EnvGuard::new(ENV_KEYS);
    // STRIPE_AUTH_MODE unset → defaults to "direct".
    env::set_var("STRIPE_SECRET_KEY", "sk_test_envdefault");
    let cfg = StripeClientConfig::from_env().unwrap();
    match cfg.mode {
        StripeAuthMode::Direct { ref api_base, .. } => {
            assert_eq!(api_base, DEFAULT_STRIPE_API_BASE);
        }
        other => panic!("expected Direct mode by default, got {other:?}"),
    }
}

#[test]
fn from_env_direct_explicit() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "direct");
    env::set_var("STRIPE_SECRET_KEY", "sk_test_explicit");
    env::set_var("STRIPE_API_BASE", "https://api.stripe.local");
    let cfg = StripeClientConfig::from_env().unwrap();
    match cfg.mode {
        StripeAuthMode::Direct {
            ref api_base,
            ref api_key,
        } => {
            assert_eq!(api_base, "https://api.stripe.local");
            assert_eq!(api_key.expose_secret(), "sk_test_explicit");
        }
        other => panic!("expected Direct mode, got {other:?}"),
    }
}

#[test]
fn from_env_direct_tolerates_trailing_newline_on_mode() {
    // Regression: a secret bound via a shell here-string or an API `text:`
    // field appends a trailing "\n". Before trimming, `"direct\n"` fell to
    // the `other =>` arm and `from_env()` returned an Authentication error,
    // taking down Stripe checkout for EVERY tier (stripe_unavailable 502).
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "direct\n");
    env::set_var("STRIPE_SECRET_KEY", "sk_test_newline");
    let cfg = StripeClientConfig::from_env()
        .expect("STRIPE_AUTH_MODE=\"direct\\n\" must parse as Direct mode");
    match cfg.mode {
        StripeAuthMode::Direct { ref api_key, .. } => {
            assert_eq!(api_key.expose_secret(), "sk_test_newline");
        }
        other => panic!("expected Direct mode for \"direct\\n\", got {other:?}"),
    }
}

#[test]
fn from_env_direct_trims_whitespace_on_mode_key_and_base() {
    // Whitespace on any of the three env inputs must not corrupt config.
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "  direct  ");
    env::set_var("STRIPE_SECRET_KEY", "  sk_test_padded\n");
    env::set_var("STRIPE_API_BASE", " https://api.stripe.local \n");
    let cfg = StripeClientConfig::from_env().unwrap();
    match cfg.mode {
        StripeAuthMode::Direct {
            ref api_base,
            ref api_key,
        } => {
            assert_eq!(api_base, "https://api.stripe.local");
            assert_eq!(api_key.expose_secret(), "sk_test_padded");
        }
        other => panic!("expected trimmed Direct mode, got {other:?}"),
    }
}

#[test]
fn from_env_wallet_broker() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "wallet-broker");
    env::set_var("HUGR_WALLET_TOKEN", "hugrw_envtest");
    env::set_var("HUGR_WALLET_BASE", "https://wallet.local");
    env::set_var("HUGR_STRIPE_REF", "stripe-staging");
    let cfg = StripeClientConfig::from_env().unwrap();
    match cfg.mode {
        StripeAuthMode::WalletBroker {
            ref wallet_base,
            ref wallet_token,
            ref stripe_ref,
        } => {
            assert_eq!(wallet_base, "https://wallet.local");
            assert_eq!(wallet_token.expose_secret(), "hugrw_envtest");
            assert_eq!(stripe_ref, "stripe-staging");
        }
        other => panic!("expected WalletBroker mode, got {other:?}"),
    }
}

#[test]
fn from_env_wallet_broker_snake_case() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "wallet_broker");
    env::set_var("HUGR_WALLET_TOKEN", "hugrw_snake");
    let cfg = StripeClientConfig::from_env().unwrap();
    match cfg.mode {
        StripeAuthMode::WalletBroker {
            ref wallet_base,
            ref stripe_ref,
            ..
        } => {
            assert_eq!(wallet_base, DEFAULT_HUGR_WALLET_BASE);
            assert_eq!(stripe_ref, DEFAULT_HUGR_STRIPE_REF);
        }
        other => panic!("expected WalletBroker mode (snake_case), got {other:?}"),
    }
}

#[test]
fn pseudonymize_customer_form_redacts_pii_and_never_deletes() {
    let form = StripeRealClient::pseudonymize_customer_form(
        "erased+cus_x@redacted.invalid",
        "erased_ab12cd34",
        "0190a1b2-c3d4-7890-abcd-ef0123456789",
    );
    let get = |k: &str| {
        form.iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.clone())
    };

    // PII fields overwritten with the pseudonyms.
    assert_eq!(
        get("email").as_deref(),
        Some("erased+cus_x@redacted.invalid")
    );
    assert_eq!(get("name").as_deref(), Some("erased_ab12cd34"));
    // Optional PII fields cleared (Stripe unsets on empty value).
    assert_eq!(get("phone").as_deref(), Some(""));
    assert_eq!(get("address").as_deref(), Some(""));
    // Redaction markers stamped.
    assert_eq!(get("metadata[pii_redacted]").as_deref(), Some("true"));
    assert_eq!(
        get("metadata[erasure_dsr_id]").as_deref(),
        Some("0190a1b2-c3d4-7890-abcd-ef0123456789")
    );
    // INVARIANT: pseudonymize-only — the form must carry NO delete
    // primitive (WI AC-004 / ADR-S11-013). A `Customer.delete` is a POST
    // to /v1/customers/:id/delete or a DELETE verb, never a form field —
    // but assert no key hints at deletion as a defensive tripwire.
    assert!(
        form.iter()
            .all(|(k, _)| !k.contains("delete") && !k.contains("deleted")),
        "erasure form must never carry a delete primitive: {form:?}"
    );
}

#[test]
fn from_env_unknown_mode_fails() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "lol");
    let err = StripeClientConfig::from_env().unwrap_err();
    match err {
        StripeError::Authentication(msg) => {
            assert!(
                msg.contains("STRIPE_AUTH_MODE")
                    && msg.contains("lol")
                    && msg.contains("direct")
                    && msg.contains("wallet-broker"),
                "unknown-mode error must name the var + reject + valid modes: {msg}"
            );
        }
        other => panic!("expected Authentication for unknown mode, got {other:?}"),
    }
}

#[test]
fn from_env_direct_missing_key_fails() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "direct");
    // STRIPE_SECRET_KEY intentionally not set.
    let err = StripeClientConfig::from_env().unwrap_err();
    match err {
        StripeError::Authentication(msg) => {
            assert!(
                msg.contains("STRIPE_SECRET_KEY"),
                "direct-mode missing-key error must name STRIPE_SECRET_KEY: {msg}"
            );
            assert!(
                msg.contains("direct"),
                "direct-mode missing-key error must be mode-specific: {msg}"
            );
        }
        other => panic!("expected Authentication, got {other:?}"),
    }

    // Empty also fails (filter-empty semantics).
    env::set_var("STRIPE_SECRET_KEY", "");
    let err = StripeClientConfig::from_env().unwrap_err();
    assert!(matches!(err, StripeError::Authentication(_)));
}

#[test]
fn from_env_wallet_broker_missing_token_fails() {
    let _g = EnvGuard::new(ENV_KEYS);
    env::set_var("STRIPE_AUTH_MODE", "wallet-broker");
    // HUGR_WALLET_TOKEN intentionally not set.
    let err = StripeClientConfig::from_env().unwrap_err();
    match err {
        StripeError::Authentication(msg) => {
            assert!(
                msg.contains("HUGR_WALLET_TOKEN"),
                "wallet-broker missing-token error must name HUGR_WALLET_TOKEN: {msg}"
            );
            assert!(
                msg.contains("wallet-broker"),
                "wallet-broker missing-token error must be mode-specific: {msg}"
            );
        }
        other => panic!("expected Authentication, got {other:?}"),
    }

    // Empty also fails.
    env::set_var("HUGR_WALLET_TOKEN", "");
    let err = StripeClientConfig::from_env().unwrap_err();
    assert!(matches!(err, StripeError::Authentication(_)));
}

#[test]
fn map_api_error_authentication() {
    let body = r#"{"error":{"type":"invalid_request_error","message":"Invalid API Key"}}"#;
    let e = map_api_error(401, body, None);
    assert!(matches!(e, StripeError::Authentication(_)));
}

#[test]
fn map_api_error_card_declined() {
    let body = r#"{"error":{"type":"card_error","code":"insufficient_funds","message":"Your card has insufficient funds."}}"#;
    let e = map_api_error(402, body, None);
    match e {
        StripeError::CardDeclined { code, .. } => assert_eq!(code, "insufficient_funds"),
        other => panic!("expected CardDeclined, got {other:?}"),
    }
}

#[test]
fn map_api_error_rate_limited_with_retry_after() {
    let body = r#"{"error":{"type":"rate_limit_error","message":"Too many requests"}}"#;
    let e = map_api_error(429, body, Some(7));
    match e {
        StripeError::RateLimited {
            retry_after_seconds,
            ..
        } => assert_eq!(retry_after_seconds, Some(7)),
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
fn map_api_error_idempotency() {
    let body = r#"{"error":{"type":"idempotency_error","message":"Keys collide"}}"#;
    let e = map_api_error(400, body, None);
    assert!(matches!(e, StripeError::Idempotency(_)));
}

#[test]
fn map_api_error_invalid_request() {
    let body = r#"{"error":{"type":"invalid_request_error","message":"Bad param"}}"#;
    let e = map_api_error(400, body, None);
    assert!(matches!(e, StripeError::InvalidRequest(_)));
}

#[test]
fn map_api_error_generic_5xx() {
    let body = r#"{"error":{"type":"api_error","message":"Internal"}}"#;
    let e = map_api_error(500, body, None);
    match e {
        StripeError::Generic { http_status, .. } => assert_eq!(http_status, 500),
        other => panic!("expected Generic, got {other:?}"),
    }
}

#[test]
fn map_api_error_unparseable_body() {
    let e = map_api_error(503, "<html>nginx</html>", None);
    match e {
        StripeError::Generic {
            http_status,
            message,
            ..
        } => {
            assert_eq!(http_status, 503);
            assert!(message.contains("nginx"));
        }
        other => panic!("expected Generic, got {other:?}"),
    }
}

// ── Checkout promo / coupon wiring (allow_promotion_codes / discounts) ──
