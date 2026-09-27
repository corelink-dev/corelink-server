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
    let _ = env::var("HUGR_WALLET_TOKEN").expect("HUGR_WALLET_TOKEN must be set");
    StripeRealClient::from_env().expect("client init")
}

/// Per-test cleanup guard. Provider IDs remain in process memory and only
/// SHA-256 digests plus bounded status labels are written to the public receipt.
/// Rust drops this guard during assertion unwinding, so cleanup also runs after
/// a failing assertion (unless the runner is forcibly terminated).
struct HarnessCleanup {
    client: StripeRealClient,
    run_id: String,
    receipt_dir: PathBuf,
    customers: Vec<String>,
    checkouts: Vec<(String, String)>,
    cleanup_failed: bool,
}

impl HarnessCleanup {
    fn new(client: StripeRealClient) -> Self {
        let run_id = env::var("REAL_HARNESS_RUN_ID").expect("REAL_HARNESS_RUN_ID must be set");
        assert!(safe_selector(&run_id, 80));
        let receipt_dir = env::var_os("REAL_HARNESS_RECEIPT_DIR")
            .map(PathBuf::from)
            .expect("receipt directory must be set");
        Self::with_receipt_dir(client, run_id, receipt_dir)
    }

    fn with_receipt_dir(client: StripeRealClient, run_id: String, receipt_dir: PathBuf) -> Self {
        assert!(safe_selector(&run_id, 80));
        Self {
            client,
            run_id,
            receipt_dir,
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
        let test_name =
            env::var("REAL_HARNESS_TEST_NAME").unwrap_or_else(|_| "cleanup_fault_injection".into());
        if !safe_selector(&test_name, 100) {
            self.cleanup_failed = true;
            return;
        }
        let path = self.receipt_dir.join("cleanup.jsonl");
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{{\"run_id\":\"{}\",\"test\":\"{}\",\"kind\":\"{}\",\"id_sha256\":\"{}\",\"status\":\"{}\"}}", self.run_id, test_name, kind, digest, status)
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

#[cfg(test)]
mod cleanup_fault_injection {
    use super::*;
    use corelink_stripe_real::{StripeClientConfig, StripeRealClient};
    use secrecy::SecretString;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let result = runtime.block_on(async move {
            tokio::task::spawn_blocking(move || {
                let panic_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                    let mut guard = HarnessCleanup::with_receipt_dir(
                        client,
                        "run-fault-1".into(),
                        receipt_dir.clone(),
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
        std::fs::remove_dir_all(result.1).expect("remove test receipt");
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
            panic!("run-owned Stripe test cleanup failed; inspect redacted receipt and keep issue open");
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
