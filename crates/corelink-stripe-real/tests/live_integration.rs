//! Live integration tests against the HuGR Wallet broker → Stripe test
//! mode upstream.
//!
//! Wave-31 (wallet-broker series, stream-1): the client no longer holds
//! a real `STRIPE_SECRET_KEY`. The wallet ref `stripe-prod-test` MUST
//! be pre-provisioned by the wallet operator with a `sk_test_...`
//! upstream secret + `proxy` scope on the `hugrw_` token below.
//!
//! Gated behind `#[cfg(feature = "live-integration")]` so the default
//! `cargo test -p corelink-stripe-real` NEVER hits the network. Run with:
//!
//! ```sh
//! HUGR_WALLET_BASE=https://api.humangr.com \
//! HUGR_WALLET_TOKEN=hugrw_live_test_... \
//! HUGR_STRIPE_REF=stripe-prod-test \
//! STRIPE_PRICE_ID_STARTER=price_... \
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

fn require_wallet_token() -> StripeRealClient {
    assert_eq!(
        env::var("STRIPE_AUTH_MODE").ok().as_deref(),
        Some("wallet-broker"),
        "Stripe profile requires explicit wallet-broker mode"
    );
    assert_eq!(
        env::var("HUGR_STRIPE_REF").ok().as_deref(),
        Some("stripe-prod-test"),
        "Stripe profile requires the exact TEST wallet ref"
    );
    assert!(
        env::var("HUGR_WALLET_BASE").is_ok_and(|base| !base.trim().is_empty()),
        "Stripe profile requires explicit Wallet broker base"
    );
    let _ = env::var("HUGR_WALLET_TOKEN").expect("HUGR_WALLET_TOKEN must be set");
    let client = StripeRealClient::from_env().expect("client init");
    let price_id = env::var("STRIPE_PRICE_ID_STARTER")
        .expect("STRIPE_PRICE_ID_STARTER must be set for the Stripe profile");
    client
        .verify_test_mode_starter_catalog(&price_id)
        .expect("Stripe Wallet ref and Starter catalog must be proven TEST mode before writes");
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
            cleanup_failed: false,
        }
    }

    fn customer(&mut self, id: &str) {
        self.customers.push(id.to_owned());
    }
    fn checkout(&mut self, id: &str, customer_id: &str) {
        self.checkouts.push((id.to_owned(), customer_id.to_owned()));
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
        ("HUGR_STRIPE_REF", "stripe-prod-test"),
        ("STRIPE_AUTH_MODE", "wallet-broker"),
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
            RestoreEnv::set("HUGR_STRIPE_REF", "stripe-prod-test"),
            RestoreEnv::set("STRIPE_AUTH_MODE", "wallet-broker"),
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
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

    fn mock_client(base_url: String) -> StripeRealClient {
        StripeRealClient::builder()
            .config(StripeClientConfig::wallet_broker(
                base_url,
                SecretString::from("hugrw_fake_test_token"),
                "stripe-prod-test",
            ))
            .build()
            .expect("mock client")
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(2)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
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
        let proxy = "/_wallet/proxy/stripe-prod-test";

        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
                .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "message": "injected"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424242"}
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/subscriptions")))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/payment_intents")))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id, "deleted": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "code": "resource_missing"}
                })))
                .expect(1)
                .mount(&server)
                .await;
        });

        let client = StripeRealClient::builder()
            .config(StripeClientConfig::wallet_broker(
                server.uri(),
                SecretString::from("hugrw_fake_test_token"),
                "stripe-prod-test",
            ))
            .build()
            .expect("mock client");
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
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
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&open_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/checkout/sessions/{checkout_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&open_session))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "{proxy}/v1/checkout/sessions/{checkout_id}/expire"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(&expired_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/checkout/sessions/{checkout_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&expired_session))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424243"}
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/subscriptions")))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/payment_intents")))
                .and(query_param("customer", customer_id))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [], "has_more": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id, "deleted": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {"type": "invalid_request_error", "code": "resource_missing"}
                })))
                .expect(1)
                .mount(&server)
                .await;
        });

        let client = StripeRealClient::builder()
            .config(StripeClientConfig::wallet_broker(
                server.uri(),
                SecretString::from("hugrw_fake_test_token"),
                "stripe-prod-test",
            ))
            .build()
            .expect("mock client");
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
                .and(path(format!(
                    "/_wallet/proxy/stripe-prod-test/v1/customers/{customer_id}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": { "test_run_id": "different-run" }
                })))
                .expect(1)
                .mount(&server),
        );
        let client = StripeRealClient::builder()
            .config(StripeClientConfig::wallet_broker(
                server.uri(),
                SecretString::from("hugrw_fake_test_token"),
                "stripe-prod-test",
            ))
            .build()
            .expect("mock client");
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        let customer_id = "cus_unknown_mode_fixture";
        let session_id = "cs_unknown_mode_fixture";
        runtime.block_on(async {
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/account")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": {"test_run_id": "424247"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/checkout/sessions/{session_id}")))
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
                .and(path(format!(
                    "{proxy}/v1/prices/price_unknown_mode_fixture"
                )))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "{proxy}/v1/checkout/sessions/{session_id}/expire"
                )))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
        });
        let client = mock_client(server.uri());
        assert!(client
            .verify_test_mode_starter_catalog("price_unknown_mode_fixture")
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        let customer_id = "cus_unknown_mode_created_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "metadata": {"test_run_id": "424248"}
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
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
            .contains("customer mode is not proven TEST"));
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        let customer_id = "cus_checkout_unknown_mode_fixture";
        let session_id = "cs_checkout_unknown_mode_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "email": null,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": session_id,
                    "customer": customer_id,
                    "url": "https://example.test/session"
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/checkout/sessions/{session_id}")))
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
                .and(path(format!(
                    "{proxy}/v1/checkout/sessions/{session_id}/expire"
                )))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        let customer_id = "cus_explicit_live_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": true
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false,
                    "metadata": {"test_run_id": "424250"}
                })))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
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
        let proxy = "/_wallet/proxy/stripe-prod-test";
        let customer_id = "cus_explicit_live_checkout_fixture";
        let session_id = "cs_explicit_live_fixture";
        runtime.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/customers")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": customer_id,
                    "livemode": false
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("{proxy}/v1/checkout/sessions")))
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
                .and(path(format!("{proxy}/v1/checkout/sessions/{session_id}")))
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
                .and(path(format!(
                    "{proxy}/v1/checkout/sessions/{session_id}/expire"
                )))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("{proxy}/v1/customers/{customer_id}")))
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
    let c = require_wallet_token();
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
    let c = require_wallet_token();
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
    let c = require_wallet_token();
    let mut cleanup = HarnessCleanup::new(c);
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
    let c = require_wallet_token();
    let mut cleanup = HarnessCleanup::new(c);
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
    let c = require_wallet_token();
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
    use corelink_stripe_real::StripeClientConfig;
    use secrecy::SecretString;
    let cfg = StripeClientConfig::wallet_broker(
        env::var("HUGR_WALLET_BASE").unwrap_or_else(|_| "https://api.humangr.com".to_string()),
        SecretString::from("hugrw_INVALID_TOKEN".to_string()),
        env::var("HUGR_STRIPE_REF").unwrap_or_else(|_| "stripe-prod-test".to_string()),
    );
    let c = StripeRealClient::builder()
        .config(cfg)
        .build()
        .expect("builder");
    let err = c.get_customer("cus_anything").unwrap_err();
    // Wallet broker rejects the invalid hugrw_ token before forwarding;
    // it returns an HTTP error mapped to either Authentication (401)
    // or Generic (403/4xx) depending on the wallet's error contract.
    assert!(
        matches!(
            err,
            StripeError::Authentication(_) | StripeError::Generic { .. }
        ),
        "expected Authentication/Generic for bad hugrw_ token, got {err:?}"
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
