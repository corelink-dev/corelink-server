//! Live integration tests against Stripe TEST mode, called directly.
//!
//! Owner decision (2026-10-02, #2565): the protected B-068 Stripe profile
//! runs in `direct-test` mode against `https://api.stripe.com` with a Stripe
//! TEST secret key, not through the HuGR Wallet broker. Three layers keep it
//! in TEST mode:
//!
//! 1. `scripts/run-real-ignored-harnesses.sh` refuses any key that is not
//!    `sk_test_`/`rk_test_` (naming `sk_live_`/`rk_live_` explicitly) before
//!    Cargo starts;
//! 2. `require_direct_test_client` refuses the same before the first request;
//! 3. after authenticating, the harness proves the expected TEST account and
//!    `livemode=false` on the account Balance before any write, and every
//!    created object must report `livemode=false`.
//!
//! The Starter price is a disposable, run-owned fixture: each checkout test
//! creates a TEST-mode product and $35 monthly price, proves them with the
//! catalog readback, and archives both with readback during cleanup.
//!
//! Gated behind `#[cfg(feature = "live-integration")]` so the default
//! `cargo test -p corelink-stripe-real` NEVER hits the network. Run with:
//!
//! ```sh
//! STRIPE_AUTH_MODE=direct-test \
//! STRIPE_SECRET_KEY_TEST=sk_test_... \
//! STRIPE_TEST_ACCOUNT_ID=acct_... \
//! cargo test -p corelink-stripe-real --features live-integration -- --ignored
//! ```
//!
//! Tests are `#[ignore]` even with the feature flag so CI must opt in
//! explicitly with `--include-ignored`.

#![cfg(feature = "live-integration")]

use std::collections::HashSet;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::panic;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use corelink_stripe_real::{StripeError, StripeRealClient};
use corelink_tier_selection::stripe::{CheckoutSessionRequest, StripeClient};
use corelink_tier_selection::tenant::TenantId;
use corelink_tier_selection::tier::TierKind;

/// The only auth mode the protected Stripe profile accepts.
const DIRECT_TEST_MODE: &str = "direct-test";

fn require_direct_test_client() -> StripeRealClient {
    assert_eq!(
        env::var("STRIPE_AUTH_MODE").ok().as_deref(),
        Some(DIRECT_TEST_MODE),
        "Stripe profile requires explicit direct-test mode"
    );
    let key = env::var("STRIPE_SECRET_KEY_TEST")
        .expect("STRIPE_SECRET_KEY_TEST must be set for the Stripe profile");
    // The base is pinned here, never read from STRIPE_API_BASE, and the
    // constructor refuses any non-TEST key before a client exists.
    let config = corelink_stripe_real::StripeClientConfig::direct_test(
        corelink_stripe_real::DEFAULT_STRIPE_API_BASE,
        secrecy::SecretString::from(key),
    )
    .expect("Stripe profile accepts only a Stripe TEST secret key");
    let client = StripeRealClient::builder()
        .config(config)
        .build()
        .expect("client init");
    assert_eq!(
        client.effective_base_url(),
        corelink_stripe_real::DEFAULT_STRIPE_API_BASE
    );
    let expected_account_id = env::var("STRIPE_TEST_ACCOUNT_ID")
        .expect("STRIPE_TEST_ACCOUNT_ID must be set for the Stripe profile");
    client
        .verify_direct_test_mode_account(&expected_account_id)
        .expect("Stripe TEST account identity and livemode=false must be proven before writes");
    client
}

/// Per-test cleanup guard. Provider IDs remain in process memory and only
/// SHA-256 digests plus bounded status labels are written to the public receipt.
/// Rust drops this guard during assertion unwinding, so cleanup also runs after
/// a failing assertion (unless the runner is forcibly terminated).
struct HarnessCleanup {
    client: StripeRealClient,
    run_id: String,
    receipt_dir: PathBuf,
    test_name: String,
    customers: Vec<String>,
    checkouts: Vec<(String, String)>,
    prices: Vec<(String, String)>,
    products: Vec<String>,
    cleanup_failed: bool,
}

impl HarnessCleanup {
    fn new(client: StripeRealClient) -> Self {
        let run_id = require_protected_stripe_run_id();
        let test_name = current_test_selector().expect("libtest test name must be available");
        Self::with_receipt_dir(client, run_id, repo_receipt_dir(), test_name)
    }

    fn with_receipt_dir(
        client: StripeRealClient,
        run_id: String,
        receipt_dir: PathBuf,
        test_name: String,
    ) -> Self {
        assert!(safe_selector(&run_id, 80));
        assert!(safe_selector(&test_name, 100));
        Self {
            client,
            run_id,
            receipt_dir,
            test_name,
            customers: Vec::new(),
            checkouts: Vec::new(),
            prices: Vec::new(),
            products: Vec::new(),
            cleanup_failed: false,
        }
    }

    fn customer(&mut self, id: &str) {
        self.customers.push(id.to_owned());
    }
    fn checkout(&mut self, id: &str, customer_id: &str) {
        self.checkouts.push((id.to_owned(), customer_id.to_owned()));
    }

    /// Create this test's disposable TEST-mode Starter product and price,
    /// registering each for archive cleanup as soon as it exists, prove the
    /// pair with the catalog readback, and expose the price to the production
    /// checkout path through `STRIPE_PRICE_ID_STARTER` for this test process.
    fn starter_price_fixture(&mut self) {
        let idem = format!(
            "b068-starter-{}-{}-{}",
            self.run_id,
            self.test_name,
            uuid_like()
        );
        let product_id = self
            .client
            .create_harness_starter_product(&self.run_id, &idem)
            .expect("TEST-mode Starter product fixture");
        self.products.push(product_id.clone());
        let price_id = self
            .client
            .create_harness_starter_price(&product_id, &self.run_id, &idem)
            .expect("TEST-mode Starter price fixture");
        self.prices.push((price_id.clone(), product_id));
        let expected_account_id = env::var("STRIPE_TEST_ACCOUNT_ID")
            .expect("STRIPE_TEST_ACCOUNT_ID must be set for the Stripe profile");
        self.client
            .verify_test_mode_starter_catalog(&expected_account_id, &price_id)
            .expect("Starter fixture must read back as the active $35 monthly TEST price");
        env::set_var("STRIPE_PRICE_ID_STARTER", &price_id);
    }

    fn receipt(&mut self, kind: &str, id: &str, status: &str) {
        let digest = hex::encode(Sha256::digest(id.as_bytes()));
        let path = self.receipt_dir.join("cleanup.jsonl");
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(
                file,
                "{{\"run_id\":\"{}\",\"test\":\"{}\",\"kind\":\"{}\",\"id_sha256\":\"{}\",\"status\":\"{}\"}}",
                self.run_id, self.test_name, kind, digest, status
            )
        })();
        if result.is_err() {
            self.cleanup_failed = true;
        }
    }
}

fn safe_selector(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn safe_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.chars().all(|c| c.is_ascii_digit())
        && value.bytes().any(|b| b != b'0')
}

fn require_protected_stripe_run_id() -> String {
    let required_context = [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "HuGR-dev/corelink-server"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW",
            "real ignored integration harnesses (B-068)",
        ),
        ("STRIPE_AUTH_MODE", DIRECT_TEST_MODE),
    ];
    for (name, expected) in required_context {
        assert_eq!(env::var(name).ok().as_deref(), Some(expected));
    }
    let run_id = env::var("GITHUB_RUN_ID").expect("GITHUB_RUN_ID must be set");
    assert!(safe_run_id(&run_id));
    run_id
}

fn current_test_selector() -> Option<String> {
    let thread = std::thread::current();
    let name = thread.name()?.rsplit("::").next()?;
    safe_selector(name, 100).then(|| name.to_owned())
}

fn repo_receipt_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/real-ignored-harnesses")
}

#[cfg(test)]
mod cleanup_fault_injection {
    use super::*;
    use corelink_stripe_real::{StripeClientConfig, StripeRealClient};
    use secrecy::SecretString;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct RestoreEnv(String, Option<String>);

    impl RestoreEnv {
        fn set(key: &str, value: &str) -> Self {
            let old = env::var(key).ok();
            env::set_var(key, value);
            Self(key.to_owned(), old)
        }

        fn remove(key: &str) -> Self {
            let old = env::var(key).ok();
            env::remove_var(key);
            Self(key.to_owned(), old)
        }
    }

    fn protected_stripe_context(run_id: &str) -> [RestoreEnv; 8] {
        [
            RestoreEnv::set("GITHUB_RUN_ID", run_id),
            RestoreEnv::set("GITHUB_EVENT_NAME", "workflow_dispatch"),
            RestoreEnv::set("GITHUB_REPOSITORY", "HuGR-dev/corelink-server"),
            RestoreEnv::set("GITHUB_REF", "refs/heads/main"),
            RestoreEnv::set(
                "GITHUB_WORKFLOW",
                "real ignored integration harnesses (B-068)",
            ),
            RestoreEnv::remove("HUGR_STRIPE_REF"),
            RestoreEnv::set("STRIPE_AUTH_MODE", DIRECT_TEST_MODE),
            RestoreEnv::set("STRIPE_PRICE_ID_STARTER", "price_test_fixture"),
        ]
    }

    #[test]
    fn github_run_id_alone_does_not_enable_run_owned_metadata() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _run_id = RestoreEnv::set("GITHUB_RUN_ID", "424244");
        let _event = RestoreEnv::remove("GITHUB_EVENT_NAME");
        let _repository = RestoreEnv::remove("GITHUB_REPOSITORY");
        let _ref_name = RestoreEnv::remove("GITHUB_REF");
        let _workflow = RestoreEnv::remove("GITHUB_WORKFLOW");
        let _stripe_ref = RestoreEnv::remove("HUGR_STRIPE_REF");
        let _auth_mode = RestoreEnv::remove("STRIPE_AUTH_MODE");
        let _price = RestoreEnv::set("STRIPE_PRICE_ID_STARTER", "price_test_fixture");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_outside_profile_fixture";
        let session_id = "cs_outside_profile_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session",
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
        });
        let constructor = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            HarnessCleanup::new(mock_client(server.uri()))
        }));
        assert!(
            constructor.is_err(),
            "run id alone cannot arm the cleanup harness"
        );
        let client = mock_client(server.uri());
        let req = CheckoutSessionRequest::new(
            TenantId::new("tenant_outside_profile"),
            TierKind::Starter,
            "outside-profile@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let response = client
            .create_checkout_session(&req)
            .expect("ordinary mock checkout");
        assert_eq!(response.session_id, session_id);
        let requests = runtime
            .block_on(server.received_requests())
            .expect("captured mock requests");
        assert_eq!(requests.len(), 2);
        for request in requests {
            let body = String::from_utf8_lossy(&request.body);
            assert!(!body.contains("test_run_id"));
        }
    }

    /// Direct-transport mock client holding a TEST-shaped fake key, which is
    /// what the protected profile builds against `api.stripe.com`.
    fn mock_client(base_url: String) -> StripeRealClient {
        mock_client_with_key(base_url, "sk_test_mockfixture")
    }

    fn mock_client_with_key(base_url: String, key: &str) -> StripeRealClient {
        StripeRealClient::builder()
            .config(StripeClientConfig::direct(
                base_url,
                SecretString::from(key.to_string()),
            ))
            .build()
            .expect("mock client")
    }

    fn catalog_result(
        account: serde_json::Value,
        price: Option<serde_json::Value>,
        product: Option<serde_json::Value>,
        expected_success: bool,
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        runtime.block_on(async {
            Mock::given(method("GET"))
                .and(path("/v1/account"))
                .respond_with(ResponseTemplate::new(200).set_body_json(account))
                .expect(1)
                .mount(&server)
                .await;
            if let Some(price) = price {
                Mock::given(method("GET"))
                    .and(path("/v1/prices/price_catalogfixture"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(price))
                    .expect(1)
                    .mount(&server)
                    .await;
            } else {
                Mock::given(method("GET"))
                    .and(path("/v1/prices/price_catalogfixture"))
                    .respond_with(ResponseTemplate::new(200))
                    .expect(0)
                    .mount(&server)
                    .await;
            }
            if let Some(product) = product {
                Mock::given(method("GET"))
                    .and(path("/v1/products/prod_catalogfixture"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(product))
                    .expect(1)
                    .mount(&server)
                    .await;
            } else {
                Mock::given(method("GET"))
                    .and(path("/v1/products/prod_catalogfixture"))
                    .respond_with(ResponseTemplate::new(200))
                    .expect(0)
                    .mount(&server)
                    .await;
            }
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
        });
        let result = mock_client(server.uri())
            .verify_test_mode_starter_catalog("acct_catalogfixture", "price_catalogfixture");
        assert_eq!(
            result.is_ok(),
            expected_success,
            "catalog result: {result:?}"
        );
        runtime.block_on(server.verify());
    }

    fn valid_test_price() -> serde_json::Value {
        serde_json::json!({
            "id": "price_catalogfixture",
            "product": "prod_catalogfixture",
            "livemode": false,
            "active": true,
            "currency": "usd",
            "unit_amount": 3500,
            "recurring": {"interval": "month", "interval_count": 1}
        })
    }

    fn valid_test_product() -> serde_json::Value {
        serde_json::json!({
            "id": "prod_catalogfixture",
            "livemode": false,
            "active": true,
            "name": "CoreLink Starter"
        })
    }

    #[test]
    fn test_account_identity_without_livemode_accepts_valid_test_catalog() {
        // Stripe Account does not provide livemode. The owner-bound account
        // identity is checked first; Price and Product prove TEST mode.
        catalog_result(
            serde_json::json!({"object": "account", "id": "acct_catalogfixture"}),
            Some(valid_test_price()),
            Some(valid_test_product()),
            true,
        );
    }

    #[test]
    fn bad_account_identity_stops_before_price_or_any_mutation() {
        for account in [
            serde_json::json!({}),
            serde_json::json!({"object": "customer", "id": "acct_catalogfixture"}),
            serde_json::json!({"object": "account"}),
            serde_json::json!({"object": "account", "id": "acct_bad!"}),
            serde_json::json!({"object": "account", "id": "acct_otherfixture"}),
        ] {
            catalog_result(account, None, None, false);
        }
    }

    #[test]
    fn price_requires_exact_test_mode_and_expected_price_id() {
        let account = serde_json::json!({"object": "account", "id": "acct_catalogfixture"});
        // Unknown mode, explicit LIVE mode, and a different returned ID all
        // stop before product lookup or any provider mutation.
        let mut unknown_mode = valid_test_price();
        unknown_mode
            .as_object_mut()
            .expect("price object")
            .remove("livemode");
        catalog_result(account.clone(), Some(unknown_mode), None, false);

        let mut live_mode = valid_test_price();
        live_mode["livemode"] = serde_json::Value::Bool(true);
        catalog_result(account.clone(), Some(live_mode), None, false);

        let mut mismatched = valid_test_price();
        mismatched["id"] = serde_json::Value::String("price_otherfixture".to_string());
        catalog_result(account, Some(mismatched), None, false);
    }

    #[test]
    fn product_requires_exact_test_mode_and_expected_product_id() {
        let account = serde_json::json!({"object": "account", "id": "acct_catalogfixture"});
        let mut unknown_mode = valid_test_product();
        unknown_mode
            .as_object_mut()
            .expect("product object")
            .remove("livemode");
        catalog_result(
            account.clone(),
            Some(valid_test_price()),
            Some(unknown_mode),
            false,
        );

        let mut live_mode = valid_test_product();
        live_mode["livemode"] = serde_json::Value::Bool(true);
        catalog_result(
            account.clone(),
            Some(valid_test_price()),
            Some(live_mode),
            false,
        );

        let mut mismatched = valid_test_product();
        mismatched["id"] = serde_json::Value::String("prod_otherfixture".to_string());
        catalog_result(account, Some(valid_test_price()), Some(mismatched), false);
    }

    #[test]
    fn repeated_run_identity_marks_only_exact_requests() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424246");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_retry_fixture";
        let session_id = "cs_retry_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(2)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session",
                    "livemode": false
                })))
                .expect(2)
                .mount(&server)
                .await;
        });
        let client = mock_client(server.uri());
        let req = CheckoutSessionRequest::new(
            TenantId::new("tenant_retry_fixture"),
            TierKind::Starter,
            "retry@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let first = client.create_checkout_session(&req).expect("first request");
        let retry = client.create_checkout_session(&req).expect("retry request");
        assert_eq!(first.session_id, session_id);
        assert_eq!(retry.session_id, first.session_id);
        let requests = runtime
            .block_on(server.received_requests())
            .expect("captured mock requests");
        assert_eq!(requests.len(), 4);
        for request in requests {
            let body = String::from_utf8_lossy(&request.body);
            assert!(body.contains("metadata%5Btest_run_id%5D=424246"));
        }
        // Retry labels repeat the same run identity; cleanup still operates
        // only on exact IDs registered in the in-memory guard.
    }

    #[test]
    fn receipt_selector_and_path_are_bounded() {
        assert_eq!(
            current_test_selector().as_deref(),
            Some("receipt_selector_and_path_are_bounded")
        );
        assert!(repo_receipt_dir().ends_with("artifacts/real-ignored-harnesses"));
        assert!(safe_run_id("424245"));
        assert!(!safe_run_id("run-424245"));
    }

    #[test]
    fn wallet_broker_mode_does_not_arm_the_direct_test_harness() {
        // Mode selection: the exact protected GitHub context with the retired
        // Wallet-broker mode must neither arm cleanup nor mark provider objects.
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424252");
        let _mode = RestoreEnv::set("STRIPE_AUTH_MODE", "wallet-broker");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_wallet_mode_fixture";
        let session_id = "cs_wallet_mode_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session",
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
        });
        let constructor = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            HarnessCleanup::new(mock_client(server.uri()))
        }));
        assert!(
            constructor.is_err(),
            "wallet-broker mode cannot arm the direct-test cleanup harness"
        );
        let request = CheckoutSessionRequest::new(
            TenantId::new("tenant_wallet_mode"),
            TierKind::Starter,
            "wallet-mode@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let response = mock_client(server.uri())
            .create_checkout_session(&request)
            .expect("ordinary mock checkout");
        assert_eq!(response.session_id, session_id);
        let requests = runtime
            .block_on(server.received_requests())
            .expect("captured mock requests");
        assert_eq!(requests.len(), 2);
        for request in requests {
            let body = String::from_utf8_lossy(&request.body);
            assert!(!body.contains("test_run_id"));
        }
    }

    #[test]
    fn direct_test_refuses_live_and_non_test_keys_before_any_request() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        runtime.block_on(async {
            for verb in ["GET", "POST", "DELETE"] {
                Mock::given(method(verb))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
            }
        });
        // (key, is a LIVE key, distinctive key material that must never be
        // echoed by the refusal; empty when the key has none).
        let refused = [
            ("sk_live_fixtureA0123", true, "fixtureA0123"),
            ("rk_live_fixtureB0123", true, "fixtureB0123"),
            ("pk_test_fixtureC0123", false, "fixtureC0123"),
            ("whsec_fixtureD0123", false, "fixtureD0123"),
            ("hugrw_fixtureE0123", false, "fixtureE0123"),
            ("sk_test_bad!fixtureF", false, "bad!fixtureF"),
            ("sk_test_", false, ""),
            ("", false, ""),
        ];
        for (key, live, material) in refused {
            let error =
                StripeClientConfig::direct_test(server.uri(), SecretString::from(key.to_string()))
                    .expect_err("only a Stripe TEST secret key may build a direct-test config");
            let message = error.to_string();
            assert!(matches!(&error, StripeError::Authentication(_)));
            assert_eq!(message.contains("LIVE"), live, "LIVE refusal: {message}");
            if !material.is_empty() {
                assert!(!message.contains(material), "refusal echoed key material");
            }
            // A Direct client built without the constructor is still refused
            // by the client guard before any transport.
            let client = mock_client_with_key(server.uri(), key);
            assert!(client
                .verify_direct_test_mode_account("acct_catalogfixture")
                .is_err());
            assert!(client
                .create_harness_starter_product("424253", "idem-refused")
                .is_err());
            assert!(client
                .cleanup_harness_customer("cus_refusedfixture", "424253")
                .is_err());
        }
        // The Wallet broker transport is never a direct-test client, even
        // with a TEST-shaped credential.
        let wallet = StripeRealClient::builder()
            .config(StripeClientConfig::wallet_broker(
                server.uri(),
                SecretString::from("sk_test_walletshape0123".to_string()),
                "stripe-ref-fixture",
            ))
            .build()
            .expect("wallet mock client");
        assert!(wallet
            .verify_direct_test_mode_account("acct_catalogfixture")
            .is_err());
        // Positive control: both TEST prefixes pass the same constructor.
        for key in ["sk_test_fixtureG0123", "rk_test_fixtureH0123"] {
            assert!(StripeClientConfig::direct_test(
                server.uri(),
                SecretString::from(key.to_string())
            )
            .is_ok());
        }
        runtime.block_on(server.verify());
    }

    fn direct_account_result(
        account: serde_json::Value,
        balance: Option<serde_json::Value>,
        expected_success: bool,
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        runtime.block_on(async {
            Mock::given(method("GET"))
                .and(path("/v1/account"))
                .respond_with(ResponseTemplate::new(200).set_body_json(account))
                .expect(1)
                .mount(&server)
                .await;
            let balance_reads = u64::from(balance.is_some());
            Mock::given(method("GET"))
                .and(path("/v1/balance"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(balance.unwrap_or(serde_json::Value::Null)),
                )
                .expect(balance_reads)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
        });
        let result =
            mock_client(server.uri()).verify_direct_test_mode_account("acct_catalogfixture");
        assert_eq!(
            result.is_ok(),
            expected_success,
            "direct account result: {result:?}"
        );
        runtime.block_on(server.verify());
    }

    #[test]
    fn direct_test_account_proof_requires_identity_then_balance_livemode_false() {
        let account = serde_json::json!({"object": "account", "id": "acct_catalogfixture"});
        direct_account_result(
            account.clone(),
            Some(serde_json::json!({"object": "balance", "livemode": false})),
            true,
        );
        // After the call, only an explicit `livemode=false` Balance passes.
        for balance in [
            serde_json::json!({"object": "balance", "livemode": true}),
            serde_json::json!({"object": "balance"}),
            serde_json::json!({"object": "balance", "livemode": "false"}),
            serde_json::json!({"object": "customer", "livemode": false}),
        ] {
            direct_account_result(account.clone(), Some(balance), false);
        }
        // A wrong or malformed account stops before the Balance readback.
        for wrong in [
            serde_json::json!({"object": "account", "id": "acct_otherfixture"}),
            serde_json::json!({"object": "customer", "id": "acct_catalogfixture"}),
            serde_json::json!({}),
        ] {
            direct_account_result(wrong, None, false);
        }
    }

    #[test]
    fn starter_fixture_is_run_owned_test_mode_and_archived_with_readback() {
        use wiremock::matchers::body_string_contains;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let run_id = "424254";
        let product_id = "prod_fixturestarter";
        let price_id = "price_fixturestarter";
        let owned = serde_json::json!({ "test_run_id": run_id });
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/products"))
                .and(body_string_contains("name=CoreLink+Starter"))
                .and(body_string_contains("metadata%5Btest_run_id%5D=424254"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": product_id,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/prices"))
                .and(body_string_contains("unit_amount=3500"))
                .and(body_string_contains("recurring%5Binterval%5D=month"))
                .and(body_string_contains("metadata%5Btest_run_id%5D=424254"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": price_id,
                    "product": product_id,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            for (object_path, product) in [
                (format!("/v1/prices/{price_id}"), Some(product_id)),
                (format!("/v1/products/{product_id}"), None),
            ] {
                let id = object_path.rsplit('/').next().expect("object id");
                let mut active = serde_json::json!({
                    "id": id,
                    "livemode": false,
                    "active": true,
                    "metadata": owned.clone()
                });
                if let Some(product) = product {
                    active["product"] = serde_json::Value::String(product.to_string());
                }
                let mut archived = active.clone();
                archived["active"] = serde_json::Value::Bool(false);
                Mock::given(method("GET"))
                    .and(path(object_path.clone()))
                    .respond_with(ResponseTemplate::new(200).set_body_json(active))
                    .up_to_n_times(1)
                    .mount(&server)
                    .await;
                Mock::given(method("POST"))
                    .and(path(object_path.clone()))
                    .and(body_string_contains("active=false"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(archived.clone()))
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(object_path))
                    .respond_with(ResponseTemplate::new(200).set_body_json(archived))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
        });
        let client = mock_client(server.uri());
        let product = client
            .create_harness_starter_product(run_id, "idem-fixture")
            .expect("product fixture");
        let price = client
            .create_harness_starter_price(&product, run_id, "idem-fixture")
            .expect("price fixture");
        assert_eq!((product.as_str(), price.as_str()), (product_id, price_id));
        client
            .cleanup_harness_price(&price, &product, run_id)
            .expect("price archived with readback");
        client
            .cleanup_harness_product(&product, run_id)
            .expect("product archived with readback");
        runtime.block_on(server.verify());
    }

    #[test]
    fn starter_fixture_not_proven_test_mode_is_retained_without_archive() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/products"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "prod_livefixture",
                    "livemode": true
                })))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/products"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "prod_unknownfixture"
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/prices/price_livefixture"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "price_livefixture",
                    "product": "prod_livefixture",
                    "livemode": true,
                    "active": true,
                    "metadata": {"test_run_id": "424255"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            for archive_path in ["/v1/prices", "/v1/prices/price_livefixture"] {
                Mock::given(method("POST"))
                    .and(path(archive_path))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
            }
        });
        let client = mock_client(server.uri());
        let live = client
            .create_harness_starter_product("424255", "idem-live")
            .expect_err("explicit LIVE product fixture is refused");
        assert!(live.to_string().contains("live_mode_retained_no_recovery"));
        assert!(!live.to_string().contains("prod_livefixture"));
        let unknown = client
            .create_harness_starter_product("424255", "idem-unknown")
            .expect_err("unknown-mode product fixture is refused");
        assert!(unknown.to_string().contains("retained_recovery_required"));
        assert!(!unknown.to_string().contains("prod_unknownfixture"));
        assert!(client
            .cleanup_harness_price("price_livefixture", "prod_livefixture", "424255")
            .is_err());
        runtime.block_on(server.verify());
    }

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            if let Some(value) = self.1.take() {
                env::set_var(&self.0, value);
            } else {
                env::remove_var(&self.0);
            }
        }
    }

    #[test]
    fn failed_checkout_creation_cleans_customer_before_returning_error() {
        use wiremock::matchers::query_param;

        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424242");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_create_failure_fixture";

        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "message": "injected"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424242"}
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/subscriptions"))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/payment_intents"))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id, "deleted": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "code": "resource_missing"}
                })))
                .expect(1)
                .mount(&server)
                .await;
        });

        let client = mock_client(server.uri());
        let req = CheckoutSessionRequest::new(
            TenantId::new("tenant_checkout_failure"),
            TierKind::Starter,
            "failure@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = client
            .create_checkout_session(&req)
            .expect_err("injected failure");
        assert!(error
            .to_string()
            .contains("run-owned customer cleanup passed"));
    }

    #[test]
    fn missing_checkout_url_expires_session_then_deletes_customer_without_ids_in_error() {
        use wiremock::matchers::query_param;

        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424243");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_missing_url_fixture";
        let checkout_id = "cs_missing_url_fixture";
        let open_session = serde_json::json!({
            "id": checkout_id,
            "customer": customer_id,
            "url": null,
            "livemode": false,
            "status": "open",
            "payment_status": "unpaid",
            "payment_intent": null,
            "subscription": null,
            "metadata": {"test_run_id": "424243"}
        });
        let expired_session = serde_json::json!({
            "id": checkout_id,
            "customer": customer_id,
            "url": null,
            "livemode": false,
            "status": "expired",
            "metadata": {"test_run_id": "424243"}
        });

        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&open_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/checkout/sessions/{checkout_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&open_session))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v1/checkout/sessions/{checkout_id}/expire")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&expired_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/checkout/sessions/{checkout_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&expired_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424243"}
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/subscriptions"))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/payment_intents"))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id, "deleted": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "code": "resource_missing"}
                })))
                .expect(1)
                .mount(&server)
                .await;
        });

        let client = mock_client(server.uri());
        let req = CheckoutSessionRequest::new(
            TenantId::new("tenant_missing_url"),
            TierKind::Starter,
            "missing-url@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = client
            .create_checkout_session(&req)
            .expect_err("missing URL must fail closed");
        let message = error.to_string();
        assert!(message.contains("run-owned checkout/customer cleanup passed"));
        assert!(!message.contains(customer_id));
        assert!(!message.contains(checkout_id));
    }

    #[test]
    fn panic_still_attempts_guarded_cleanup_and_receipt_redacts_ids() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_run_owned_secret_id";
        runtime.block_on(
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": { "test_run_id": "different-run" }
                })))
                .expect(1)
                .mount(&server),
        );
        let client = mock_client(server.uri());
        let receipt_dir =
            std::env::temp_dir().join(format!("stripe-cleanup-fault-{}", uuid_like()));
        std::fs::create_dir_all(&receipt_dir).expect("temp receipt dir");
        let test_name = current_test_selector().expect("libtest test name");
        let result = runtime.block_on(async move {
            tokio::task::spawn_blocking(move || {
                let panic_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                    let mut guard = HarnessCleanup::with_receipt_dir(
                        client,
                        "run-fault-1".into(),
                        receipt_dir.clone(),
                        test_name,
                    );
                    guard.customer(customer_id);
                    panic!("injected assertion failure");
                }));
                (panic_result, receipt_dir)
            })
            .await
            .expect("cleanup worker")
        });
        assert!(result.0.is_err());
        let receipt =
            std::fs::read_to_string(result.1.join("cleanup.jsonl")).expect("cleanup receipt");
        assert!(receipt.contains("cleanup_failed"));
        assert!(!receipt.contains(customer_id));
        let row: serde_json::Value = serde_json::from_str(receipt.trim()).expect("receipt row");
        assert_eq!(
            row.get("run_id").and_then(|v| v.as_str()),
            Some("run-fault-1")
        );
        assert_eq!(
            row.get("test").and_then(|v| v.as_str()),
            Some("panic_still_attempts_guarded_cleanup_and_receipt_redacts_ids")
        );
        assert_eq!(row.get("kind").and_then(|v| v.as_str()), Some("customer"));
        assert_eq!(
            row.get("status").and_then(|v| v.as_str()),
            Some("cleanup_failed")
        );
        assert_eq!(
            row.get("id_sha256").and_then(|v| v.as_str()).map(str::len),
            Some(64)
        );
        std::fs::remove_dir_all(result.1).expect("remove test receipt");
    }

    #[test]
    fn unknown_or_live_mode_fails_closed_before_catalog_or_cleanup_mutations() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_unknown_mode_fixture";
        let session_id = "cs_unknown_mode_fixture";
        runtime.block_on(async {
            Mock::given(method("GET"))
                .and(path("/v1/account"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": {"test_run_id": "424247"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/checkout/sessions/{session_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "metadata": {"test_run_id": "424247"},
                    "status": "open",
                    "payment_status": "unpaid",
                    "payment_intent": null,
                    "subscription": null
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/prices/price_unknownmodefixture"))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v1/checkout/sessions/{session_id}/expire")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let client = mock_client(server.uri());
        assert!(client
            .verify_test_mode_starter_catalog("acct_catalogfixture", "price_unknownmodefixture")
            .is_err());
        assert!(client
            .cleanup_harness_checkout(session_id, customer_id, "424247")
            .is_err());
        assert!(client
            .cleanup_harness_customer(customer_id, "424247")
            .is_err());
        runtime.block_on(server.verify());
    }

    #[test]
    fn customer_without_test_mode_is_retained_before_checkout_creation() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424248");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_unknown_mode_created_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": {"test_run_id": "424248"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let client = mock_client(server.uri());
        let request = CheckoutSessionRequest::new(
            TenantId::new("tenant_unknown_customer_mode"),
            TierKind::Starter,
            "unknown-mode@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = client
            .create_checkout_session(&request)
            .expect_err("customer without explicit TEST mode must stop before Checkout");
        assert!(error
            .to_string()
            .contains("created customer mode is unknown"));
        assert!(error.to_string().contains("retained_recovery_required"));
        assert!(error.to_string().contains("id_sha256"));
        assert!(!error.to_string().contains(customer_id));
        runtime.block_on(server.verify());
    }

    #[test]
    fn checkout_without_test_mode_is_read_back_and_retained_without_expire_or_delete() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424249");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_checkout_unknown_mode_fixture";
        let session_id = "cs_checkout_unknown_mode_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session"
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/checkout/sessions/{session_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "metadata": {"test_run_id": "424249"},
                    "status": "open",
                    "payment_status": "unpaid",
                    "payment_intent": null,
                    "subscription": null
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v1/checkout/sessions/{session_id}/expire")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let client = mock_client(server.uri());
        let request = CheckoutSessionRequest::new(
            TenantId::new("tenant_checkout_unknown_mode"),
            TierKind::Starter,
            "unknown-session-mode@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = client.create_checkout_session(&request).expect_err(
            "session without explicit TEST mode must stop and leave exact recovery data",
        );
        assert!(error.to_string().contains("recovery receipts"));
        assert!(error.to_string().contains("id_sha256"));
        assert!(!error.to_string().contains(customer_id));
        assert!(!error.to_string().contains(session_id));
        runtime.block_on(server.verify());
    }

    #[test]
    fn customer_explicitly_live_is_never_reconciled_or_deleted() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424250");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_explicit_live_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424250"}
                })))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let request = CheckoutSessionRequest::new(
            TenantId::new("tenant_explicit_live_customer"),
            TierKind::Starter,
            "live-customer@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = mock_client(server.uri())
            .create_checkout_session(&request)
            .expect_err("explicit LIVE customer must be retained without requests");
        assert!(error.to_string().contains("explicitly LIVE"));
        assert!(error.to_string().contains("live_mode_retained_no_recovery"));
        assert!(!error.to_string().contains(customer_id));
        runtime.block_on(server.verify());
    }

    #[test]
    fn checkout_explicitly_live_is_never_reconciled_expired_or_deleted() {
        let _env_lock = ENV_LOCK.lock().expect("env lock");
        let _context = protected_stripe_context("424251");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(MockServer::start());
        let customer_id = "cus_explicit_live_checkout_fixture";
        let session_id = "cs_explicit_live_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path("/v1/customers"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1/checkout/sessions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session",
                    "livemode": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/checkout/sessions/{session_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424251"},
                    "status": "open",
                    "payment_status": "unpaid",
                    "payment_intent": null,
                    "subscription": null
                })))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v1/checkout/sessions/{session_id}/expire")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let request = CheckoutSessionRequest::new(
            TenantId::new("tenant_explicit_live_checkout"),
            TierKind::Starter,
            "live-checkout@example.test",
            "https://example.test/ok",
            "https://example.test/cancel",
        );
        let error = mock_client(server.uri())
            .create_checkout_session(&request)
            .expect_err("explicit LIVE checkout must be retained without requests");
        assert!(error.to_string().contains("explicitly LIVE"));
        assert!(error.to_string().contains("live_mode_retained_no_recovery"));
        assert!(!error.to_string().contains(customer_id));
        assert!(!error.to_string().contains(session_id));
        runtime.block_on(server.verify());
    }
}

impl Drop for HarnessCleanup {
    fn drop(&mut self) {
        let mut sessions = HashSet::new();
        for (id, customer_id) in std::mem::take(&mut self.checkouts) {
            if !sessions.insert((id.clone(), customer_id.clone())) {
                continue;
            }
            let status = if self
                .client
                .cleanup_harness_checkout(&id, &customer_id, &self.run_id)
                .is_ok()
            {
                "expired_readback_pass"
            } else {
                "cleanup_failed"
            };
            self.receipt("checkout", &id, status);
            self.cleanup_failed |= status == "cleanup_failed";
        }
        let mut customers = HashSet::new();
        for id in std::mem::take(&mut self.customers) {
            if !customers.insert(id.clone()) {
                continue;
            }
            let status = if self
                .client
                .cleanup_harness_customer(&id, &self.run_id)
                .is_ok()
            {
                "deleted_readback_pass"
            } else {
                "cleanup_failed"
            };
            self.receipt("customer", &id, status);
            self.cleanup_failed |= status == "cleanup_failed";
        }
        // Fixtures go last: an expired Checkout may still reference the
        // price, and the product is archived only after its price.
        let mut prices = HashSet::new();
        for (id, product_id) in std::mem::take(&mut self.prices) {
            if !prices.insert(id.clone()) {
                continue;
            }
            let status = if self
                .client
                .cleanup_harness_price(&id, &product_id, &self.run_id)
                .is_ok()
            {
                "archived_readback_pass"
            } else {
                "cleanup_failed"
            };
            self.receipt("price", &id, status);
            self.cleanup_failed |= status == "cleanup_failed";
        }
        let mut products = HashSet::new();
        for id in std::mem::take(&mut self.products) {
            if !products.insert(id.clone()) {
                continue;
            }
            let status = if self
                .client
                .cleanup_harness_product(&id, &self.run_id)
                .is_ok()
            {
                "archived_readback_pass"
            } else {
                "cleanup_failed"
            };
            self.receipt("product", &id, status);
            self.cleanup_failed |= status == "cleanup_failed";
        }
        if self.cleanup_failed && !std::thread::panicking() {
            panic!(
                "run-owned Stripe test cleanup failed; inspect redacted receipt and keep issue open"
            );
        }
    }
}

#[test]
#[ignore = "live network"]
fn live_create_customer() {
    let c = require_direct_test_client();
    let mut cleanup = HarnessCleanup::new(c);
    let idem = format!("live-test-customer-{}", uuid_like());
    let cust = cleanup
        .client
        .create_customer("integration@example.test", "tenant_live_int", &idem)
        .expect("create customer");
    cleanup.customer(&cust.id);
    assert_eq!(
        cust.livemode,
        Some(false),
        "Stripe customer must be TEST mode"
    );
    assert!(cust.id.starts_with("cus_"));
}

#[test]
#[ignore = "live network"]
fn live_get_customer_404() {
    let c = require_direct_test_client();
    let err = c.get_customer("cus_does_not_exist_xyz").unwrap_err();
    // Stripe returns 404 with `resource_missing` → Generic.
    match err {
        StripeError::Generic { http_status, .. } => assert_eq!(http_status, 404),
        other => panic!("expected Generic 404, got {other:?}"),
    }
}

#[test]
#[ignore = "live network"]
fn live_create_checkout_session_starter() {
    let c = require_direct_test_client();
    let mut cleanup = HarnessCleanup::new(c);
    cleanup.starter_price_fixture();
    let req = CheckoutSessionRequest::new(
        TenantId::new(format!("live_t_{}", uuid_like())),
        TierKind::Starter,
        "live@example.test",
        "https://example.test/ok",
        "https://example.test/cancel",
    );
    let resp = cleanup
        .client
        .create_checkout_session(&req)
        .expect("checkout session");
    cleanup.customer(resp.stripe_customer_id.as_str());
    cleanup.checkout(&resp.session_id, resp.stripe_customer_id.as_str());
    assert!(resp.session_id.starts_with("cs_"));
    assert!(resp.url.starts_with("https://"));
}

#[test]
#[ignore = "live network"]
fn live_idempotent_checkout_returns_same_session() {
    let c = require_direct_test_client();
    let mut cleanup = HarnessCleanup::new(c);
    cleanup.starter_price_fixture();
    let tenant = TenantId::new(format!("live_idem_{}", uuid_like()));
    let req = CheckoutSessionRequest::new(
        tenant,
        TierKind::Starter,
        "idem@example.test",
        "https://example.test/ok",
        "https://example.test/cancel",
    );
    let a = cleanup.client.create_checkout_session(&req).expect("first");
    cleanup.customer(a.stripe_customer_id.as_str());
    cleanup.checkout(&a.session_id, a.stripe_customer_id.as_str());
    let b = cleanup
        .client
        .create_checkout_session(&req)
        .expect("second");
    cleanup.customer(b.stripe_customer_id.as_str());
    cleanup.checkout(&b.session_id, b.stripe_customer_id.as_str());
    assert_eq!(a.session_id, b.session_id, "idempotency-key replay");
}

#[test]
#[ignore = "live network"]
fn live_billing_portal_session() {
    let c = require_direct_test_client();
    let mut cleanup = HarnessCleanup::new(c);
    let idem_cust = format!("live-portal-cust-{}", uuid_like());
    let cust = cleanup
        .client
        .create_customer("portal@example.test", "tenant_portal", &idem_cust)
        .expect("customer");
    cleanup.customer(&cust.id);
    assert_eq!(
        cust.livemode,
        Some(false),
        "Stripe customer must be TEST mode"
    );
    let idem_portal = format!("live-portal-{}", uuid_like());
    let session = cleanup
        .client
        .create_billing_portal_session(&cust.id, "https://example.test/return", &idem_portal)
        .expect("portal");
    assert!(session.id.starts_with("bps_"));
    assert!(session.url.starts_with("https://"));
}

#[test]
#[ignore = "live network"]
fn live_authentication_failure_bad_token() {
    use corelink_stripe_real::{StripeClientConfig, DEFAULT_STRIPE_API_BASE};
    use secrecy::SecretString;
    // The invalid key keeps the TEST prefix, so the direct-test guard admits
    // it and Stripe itself must reject it. A LIVE-shaped value is never sent.
    let cfg = StripeClientConfig::direct_test(
        DEFAULT_STRIPE_API_BASE,
        SecretString::from("sk_test_INVALIDb068harnesskey".to_string()),
    )
    .expect("TEST-shaped invalid key passes the prefix guard");
    let c = StripeRealClient::builder()
        .config(cfg)
        .build()
        .expect("builder");
    let err = c.get_customer("cus_anything").unwrap_err();
    // Stripe answers an unknown API key with HTTP 401 → Authentication.
    assert!(
        matches!(err, StripeError::Authentication(_)),
        "expected Authentication for an invalid Stripe TEST key, got {err:?}"
    );
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{ns:x}")
}
