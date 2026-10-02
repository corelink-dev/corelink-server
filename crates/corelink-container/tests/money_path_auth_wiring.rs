//! Executable PR #1485 replacement: canonical auth resolution and effect gates.
//!
//! This deliberately remains one sequential test because the route builders
//! read process-global configuration. It exercises the real `router().oneshot`
//! wiring, not only pure authorization helpers: invalid auth must stop before
//! D1/Stripe, while a valid control reaches exactly one D1 attempt. The local
//! refusing probe and bounded assertions keep the test hermetic and non-hanging.

use std::{
    env,
    ffi::OsString,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use corelink_server::routes::{dpa_accept, tier_select};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use tower::ServiceExt;

const KEY_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_KEY_64: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const WRONG_KEY_64: &str = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
const KEY_20: &str = "01234567890123456789";

const ENV_VARS: &[&str] = &[
    "CLOUDFLARE_ACCOUNT_ID",
    "CF_API_TOKEN",
    "CORELINK_DPA_VERSION",
    "CORELINK_DPA_ACCEPT_AUTH_KEY",
    "CORELINK_INTERNAL_AUTH_KEY",
    "CORELINK_TIER_SELECT_AUTH_KEY",
    "D1_DATABASE_ID",
    "DPA_ACCEPT_IP_HASH_SALT",
    "DPA_RECEIPT_SIGNING_KEY",
    "R2_S3_ACCESS_KEY_ID",
    "R2_S3_ENDPOINT",
    "R2_S3_SECRET_ACCESS_KEY",
    "STRIPE_API_BASE",
    "STRIPE_AUTH_MODE",
    "STRIPE_SECRET_KEY",
];

struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn capture(names: &'static [&'static str]) -> Self {
        Self {
            saved: names
                .iter()
                .map(|name| (*name, env::var_os(name)))
                .collect(),
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            if let Some(value) = value {
                env::set_var(name, value);
            } else {
                env::remove_var(name);
            }
        }
    }
}

/// Refuses all traffic while classifying the D1 and Stripe URL paths.
struct EffectProbe {
    d1_requests: Arc<AtomicUsize>,
    stripe_requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    d1_url: String,
    stripe_url: String,
}

impl EffectProbe {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let d1_requests = Arc::new(AtomicUsize::new(0));
        let stripe_requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let d1_for_thread = Arc::clone(&d1_requests);
        let stripe_for_thread = Arc::clone(&stripe_requests);
        let stop_for_thread = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("money-path-effect-probe".into())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            classify_and_refuse(stream, &d1_for_thread, &stripe_for_thread)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            })?;
        let base_url = format!("http://{address}");
        Ok(Self {
            d1_requests,
            stripe_requests,
            stop,
            worker: Some(worker),
            d1_url: format!("{base_url}/d1"),
            stripe_url: format!("{base_url}/stripe"),
        })
    }

    fn d1_url(&self) -> &str {
        &self.d1_url
    }
    fn stripe_url(&self) -> &str {
        &self.stripe_url
    }

    fn reset(&self) {
        self.d1_requests.store(0, Ordering::Release);
        self.stripe_requests.store(0, Ordering::Release);
    }
    fn d1_requests(&self) -> usize {
        self.d1_requests.load(Ordering::Acquire)
    }
    fn stripe_requests(&self) -> usize {
        self.stripe_requests.load(Ordering::Acquire)
    }

    /// Poll only for the bounded observation window; a missing effect is a failure,
    /// never an unbounded await or a test that can hang indefinitely.
    fn wait_for_d1(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && self.d1_requests() < expected {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            self.d1_requests(),
            expected,
            "D1 effect count did not settle before bounded deadline"
        );
    }
}

impl Drop for EffectProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn classify_and_refuse(mut stream: TcpStream, d1: &AtomicUsize, stripe: &AtomicUsize) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut request = [0_u8; 1024];
    let bytes_read = stream.read(&mut request).unwrap_or(0);
    let request_target = request
        .get(..bytes_read)
        .and_then(|request| request.split(|byte| *byte == b'\n').next())
        .and_then(|line| line.split(|byte| *byte == b' ').nth(1));
    match request_target {
        Some(path) if path.starts_with(b"/d1") => {
            d1.fetch_add(1, Ordering::AcqRel);
        }
        Some(path) if path.starts_with(b"/stripe") => {
            stripe.fetch_add(1, Ordering::AcqRel);
        }
        _ => {}
    }
    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
}

fn set_common_env(signing_key_pem: &str, stripe_url: &str) {
    env::set_var("CORELINK_DPA_VERSION", "1.0.0");
    env::set_var("R2_S3_ENDPOINT", "https://example.invalid");
    env::set_var("R2_S3_ACCESS_KEY_ID", "test-r2-access-id");
    env::set_var("R2_S3_SECRET_ACCESS_KEY", "test-r2-placeholder");
    env::set_var("CLOUDFLARE_ACCOUNT_ID", "0123456789abcdef0123456789abcdef");
    env::set_var("CF_API_TOKEN", "test-cf-placeholder");
    env::set_var("D1_DATABASE_ID", "00000000-0000-0000-0000-000000000000");
    env::set_var("STRIPE_AUTH_MODE", "direct");
    env::set_var("STRIPE_API_BASE", stripe_url);
    env::set_var("STRIPE_SECRET_KEY", "test-stripe-placeholder");
    env::set_var("DPA_RECEIPT_SIGNING_KEY", signing_key_pem);
    // dpa-accept mounts only with a valid 32-byte salt since #2852; a fixed
    // non-zero fixture keeps the auth matrix the only variable under test.
    env::set_var("DPA_ACCEPT_IP_HASH_SALT", "5a".repeat(32));
}

fn clear_auth_env() {
    env::remove_var("CORELINK_INTERNAL_AUTH_KEY");
    env::remove_var("CORELINK_TIER_SELECT_AUTH_KEY");
    env::remove_var("CORELINK_DPA_ACCEPT_AUTH_KEY");
}

fn test_signing_key_pem() -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    Ok(RsaPrivateKey::new(&mut rng, 2048)?
        .to_pkcs8_pem(LineEnding::LF)?
        .to_string())
}

fn assert_resolver_matrix<T>(route: &str, dedicated_env: &str, build: impl Fn() -> Option<T>) {
    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", KEY_64);
    assert!(
        build().is_some(),
        "{route}: valid shared key must mount when dedicated is unset"
    );
    clear_auth_env();
    env::set_var(dedicated_env, KEY_64);
    assert!(
        build().is_some(),
        "{route}: valid dedicated key alone must mount"
    );
    clear_auth_env();
    assert!(
        build().is_none(),
        "{route}: all auth keys absent must leave route unmounted"
    );
    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", KEY_20);
    assert!(
        build().is_none(),
        "{route}: short shared key must leave route unmounted"
    );
    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", KEY_64);
    env::set_var(dedicated_env, KEY_20);
    assert!(
        build().is_none(),
        "{route}: short dedicated key must fail closed, not fall back"
    );
    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", KEY_64);
    env::set_var(dedicated_env, "                                ");
    assert!(
        build().is_none(),
        "{route}: whitespace-only dedicated key must fail closed, not fall back"
    );
    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", KEY_20);
    env::set_var(dedicated_env, KEY_20);
    assert!(
        build().is_none(),
        "{route}: both short keys must leave route unmounted"
    );
}

fn tier_request(auth: &str) -> Result<Request<Body>, http::Error> {
    Request::builder().method("POST").uri("/v1/onboarding/tier-select")
        .header(tier_select::INTERNAL_AUTH_HEADER, auth).header(tier_select::TENANT_HEADER, "tenant-money-proof")
        .header("content-type", "application/json").body(Body::from(
            r#"{"tier":"free","success_url":"https://humangr.com/success","cancel_url":"https://humangr.com/cancel"}"#,
        ))
}

fn dpa_request(auth: &str) -> Result<Request<Body>, http::Error> {
    Request::builder().method("POST").uri("/v1/onboarding/dpa-accept")
        .header(tier_select::INTERNAL_AUTH_HEADER, auth).header(tier_select::TENANT_HEADER, "tenant-money-proof")
        .header("content-type", "application/json").body(Body::from(
            r#"{"dpa_version":"1.0.0","dpa_locale":"en","notice_text_hash":"0b8d023331a3e23a8be9750277bd178229a89de57770f5c2fed82752340e9171"}"#,
        ))
}

fn assert_no_effects(probe: &EffectProbe, route: &str, case: &str) {
    assert_eq!(
        probe.d1_requests(),
        0,
        "{route}: {case} must make exactly zero D1 requests"
    );
    assert_eq!(
        probe.stripe_requests(),
        0,
        "{route}: {case} must make exactly zero Stripe requests"
    );
}

#[test]
fn money_path_enforces_resolver_matrix_and_stops_unauthenticated_requests_before_effects(
) -> Result<(), Box<dyn std::error::Error>> {
    let _env = EnvGuard::capture(ENV_VARS);
    let probe = EffectProbe::start()?;
    let pem = test_signing_key_pem()?;
    set_common_env(&pem, probe.stripe_url());

    assert_resolver_matrix("tier-select", "CORELINK_TIER_SELECT_AUTH_KEY", || {
        tier_select::build_state_from_env_for_loopback_test(probe.d1_url())
    });
    assert_resolver_matrix("dpa-accept", "CORELINK_DPA_ACCEPT_AUTH_KEY", || {
        dpa_accept::build_state_from_env_for_loopback_test(probe.d1_url())
    });

    clear_auth_env();
    env::set_var("CORELINK_INTERNAL_AUTH_KEY", OTHER_KEY_64);
    env::set_var("CORELINK_TIER_SELECT_AUTH_KEY", KEY_64);
    let tier_state = tier_select::build_state_from_env_for_loopback_test(probe.d1_url())
        .ok_or("tier-select did not mount")?;
    env::set_var("CORELINK_DPA_ACCEPT_AUTH_KEY", KEY_64);
    let dpa_state = dpa_accept::build_state_from_env_for_loopback_test(probe.d1_url())
        .ok_or("dpa-accept did not mount")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        probe.reset();
        let response = tier_select::router(tier_state.clone())
            .oneshot(tier_request(KEY_64)?)
            .await?;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "tier positive control must clear auth"
        );
        probe.wait_for_d1(1);
        assert_eq!(
            probe.d1_requests(),
            1,
            "tier positive control must reach D1 exactly once"
        );
        assert_eq!(
            probe.stripe_requests(),
            0,
            "tier audit failure must stop before Stripe"
        );

        probe.reset();
        let response = dpa_accept::router(dpa_state.clone())
            .oneshot(dpa_request(KEY_64)?)
            .await?;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "DPA positive control must clear auth"
        );
        probe.wait_for_d1(1);
        assert_eq!(
            probe.d1_requests(),
            1,
            "DPA positive control must reach D1 exactly once"
        );
        assert_eq!(
            probe.stripe_requests(),
            0,
            "DPA positive control must not call Stripe"
        );

        for (case, presented) in [
            ("wrong", WRONG_KEY_64),
            ("shared-mismatch", OTHER_KEY_64),
            ("empty", ""),
        ] {
            probe.reset();
            let response = tier_select::router(tier_state.clone())
                .oneshot(tier_request(presented)?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "tier {case} auth must return 401"
            );
            assert_no_effects(&probe, "tier-select", case);

            probe.reset();
            let response = dpa_accept::router(dpa_state.clone())
                .oneshot(dpa_request(presented)?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "DPA {case} auth must return 401"
            );
            assert_no_effects(&probe, "dpa-accept", case);
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    drop(runtime);
    clear_auth_env();
    result
}
