//! Shared test fixtures (RSA keygen, deterministic clock + JTI minter,
//! pre-populated registry).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panics surface as test failures"
)]
#![allow(missing_docs, reason = "test fixtures: documented in module rustdoc")]
#![allow(dead_code, reason = "shared fixtures not used by every test binary")]

use std::sync::{Mutex, OnceLock};

use corelink_dpa_acceptance::service::{Clock, DpaAcceptanceService, JtiMinter};
use corelink_dpa_acceptance::{
    InMemoryDpaAcceptanceStore, InMemoryDpaAuditSink, InMemoryNotificationSink, IpHashSalt,
    Jurisdiction, LocaleBcp47, LocaleNoticeRegistry, RsaPrivateKeyPem, RsaPublicKeyPem, SignupId,
    TenantCtx, TenantId,
};

use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

#[derive(Debug)]
pub struct FixedClock {
    pub now_ms: i64,
}

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.now_ms
    }
}

#[derive(Debug, Default)]
pub struct CountingJtiMinter {
    counter: Mutex<u64>,
}

impl JtiMinter for CountingJtiMinter {
    fn mint(&self) -> String {
        let mut g = self.counter.lock().expect("jti counter");
        *g += 1;
        format!("jti-{:08}", *g)
    }
}

#[derive(Debug)]
pub struct Keys {
    pub private: RsaPrivateKeyPem,
    pub public: RsaPublicKeyPem,
}

#[allow(clippy::expect_used)]
pub fn gen_keys() -> Keys {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public = RsaPublicKey::from(&private);
    let private_pem = private
        .to_pkcs1_pem(LineEnding::LF)
        .expect("priv pem")
        .to_string();
    let public_pem = public
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pub pem");
    Keys {
        private: RsaPrivateKeyPem(private_pem),
        public: RsaPublicKeyPem(public_pem),
    }
}

/// Return the immutable RSA fixture used by service builders.
///
/// Property cases must exercise the service invariants, not pay for a fresh
/// 2048-bit keypair.  Keep the PEM strings owned by each returned [`Keys`]
/// value so every service owns its signing material while the expensive
/// generation happens once per test binary.  [`gen_keys`] remains fresh for
/// tests that intentionally need a foreign key.
fn fixture_keys() -> Keys {
    static PEM: OnceLock<(String, String)> = OnceLock::new();
    let (private_pem, public_pem) = PEM
        .get_or_init(|| {
            let keys = gen_keys();
            (keys.private.0, keys.public.0)
        })
        .clone();
    Keys {
        private: RsaPrivateKeyPem(private_pem),
        public: RsaPublicKeyPem(public_pem),
    }
}

pub fn registry_three_locales() -> LocaleNoticeRegistry {
    let mut r = LocaleNoticeRegistry::new();
    r.register(LocaleBcp47::EnUs, "DPA v1.0.0 (en-US) — canonical text.");
    r.register(LocaleBcp47::PtBr, "DPA v1.0.0 (pt-BR) — texto canônico.");
    r.register(LocaleBcp47::Es419, "DPA v1.0.0 (es-419) — texto canónico.");
    r
}

pub type TestService = DpaAcceptanceService<
    InMemoryDpaAcceptanceStore,
    InMemoryDpaAuditSink,
    InMemoryNotificationSink,
    CountingJtiMinter,
    FixedClock,
>;

pub fn build_service(now_ms: i64) -> (TestService, RsaPublicKeyPem) {
    let keys = fixture_keys();
    let svc = DpaAcceptanceService::new(
        InMemoryDpaAcceptanceStore::new(),
        InMemoryDpaAuditSink::new(),
        InMemoryNotificationSink::new(),
        CountingJtiMinter::default(),
        FixedClock { now_ms },
        registry_three_locales(),
        keys.private,
        "kid-test-01",
        IpHashSalt::new(Some(&[0x51; 32])).expect("valid test salt"),
    );
    (svc, keys.public)
}

pub fn ctx(signup: &str, locale: LocaleBcp47) -> TenantCtx {
    TenantCtx {
        tenant_id: TenantId(format!("tenant-{}", signup)),
        signup_id: SignupId(signup.to_owned()),
        jurisdiction: match locale {
            LocaleBcp47::EnUs => Jurisdiction::Us,
            LocaleBcp47::PtBr => Jurisdiction::Br,
            LocaleBcp47::Es419 => Jurisdiction::Latam,
            _ => Jurisdiction::Us,
        },
        client_ip: "203.0.113.1".to_owned(),
        resolved_locale: locale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn fixture_is_rsa_2048_and_pem_shaped() {
        let keys = fixture_keys();
        assert!(keys
            .private
            .0
            .starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(keys.public.0.starts_with("-----BEGIN PUBLIC KEY-----"));

        let private = RsaPrivateKey::from_pkcs1_pem(&keys.private.0).expect("private PEM");
        let public = RsaPublicKey::from_public_key_pem(&keys.public.0).expect("public PEM");
        assert_eq!(private.size() * 8, 2048);
        assert_eq!(public.size() * 8, 2048);
        assert_eq!(private.n(), public.n());
    }
}
