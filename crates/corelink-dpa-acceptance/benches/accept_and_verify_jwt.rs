//! Criterion benchmark — DPA acceptance pipeline (RS256 sign on accept) +
//! RS256 receipt verify.
//!
//! # Target
//!
//! - `dpa/accept_rs256_sign`: p99 < 50 ms (dominated by RS256 sign on 2048-bit
//!   key). Production fan-out adds D1 insert + email send.
//! - `dpa/verify_receipt_rs256`: p99 < 5 ms (RS256 verify is 10-20x cheaper
//!   than sign).
//!
//! RSA keypair is generated once at bench startup (NOT inside the benched
//! closure) so we measure the sign/verify path, not keygen.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    clippy::unwrap_used,
    reason = "bench harness; macros generate items we do not own"
)]

use std::sync::Mutex;

use corelink_dpa_acceptance::{
    service::{Clock, DpaAcceptanceService, JtiMinter},
    verify_receipt, ConsentProofPayload, DpaAcceptanceRequest, InMemoryDpaAcceptanceStore,
    InMemoryDpaAuditSink, InMemoryNotificationSink, IpHashSalt, Jurisdiction, LocaleBcp47,
    LocaleNoticeRegistry, RsaPrivateKeyPem, RsaPublicKeyPem, SignupId, TenantCtx, TenantId,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    pkcs8::EncodePublicKey,
    RsaPrivateKey, RsaPublicKey,
};
use std::hint::black_box;

#[derive(Debug)]
struct FixedClock(i64);
impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

#[derive(Debug, Default)]
struct CountingJti(Mutex<u64>);
impl JtiMinter for CountingJti {
    fn mint(&self) -> String {
        let mut g = self.0.lock().expect("jti counter");
        *g = g.saturating_add(1);
        format!("jti-{:016}", *g)
    }
}

fn gen_keys() -> (RsaPrivateKeyPem, RsaPublicKeyPem) {
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
    (RsaPrivateKeyPem(private_pem), RsaPublicKeyPem(public_pem))
}

fn registry() -> LocaleNoticeRegistry {
    let mut r = LocaleNoticeRegistry::new();
    r.register(LocaleBcp47::EnUs, "DPA v1.0.0 (en-US) — canonical text.");
    r.register(LocaleBcp47::PtBr, "DPA v1.0.0 (pt-BR) — texto canônico.");
    r.register(LocaleBcp47::Es419, "DPA v1.0.0 (es-419) — texto canónico.");
    r
}

type BenchService = DpaAcceptanceService<
    InMemoryDpaAcceptanceStore,
    InMemoryDpaAuditSink,
    InMemoryNotificationSink,
    CountingJti,
    FixedClock,
>;

fn build_service(now_ms: i64, private: RsaPrivateKeyPem) -> BenchService {
    DpaAcceptanceService::new(
        InMemoryDpaAcceptanceStore::new(),
        InMemoryDpaAuditSink::new(),
        InMemoryNotificationSink::new(),
        CountingJti::default(),
        FixedClock(now_ms),
        registry(),
        private,
        "kid-bench-01",
        IpHashSalt::new(Some(&[0x52; 32])).expect("valid benchmark salt"),
    )
}

fn build_request(seq: u64) -> (TenantCtx, DpaAcceptanceRequest) {
    let r = registry();
    let req = DpaAcceptanceRequest {
        proof: ConsentProofPayload {
            notice_text_hash: r.hash_for(LocaleBcp47::EnUs).expect("hash"),
            notice_version: "1.0.0".into(),
            dpa_version: "1.0.0".into(),
            locale: LocaleBcp47::EnUs,
            wording_id: "11111111-1111-7111-8111-111111111111".into(),
            ui_capture_ts: 1_699_999_999_000,
            submission_ts: 0,
        },
    };
    let ctx = TenantCtx {
        tenant_id: TenantId(format!("tenant-bench-{seq}")),
        signup_id: SignupId(format!("signup-bench-{seq}")),
        jurisdiction: Jurisdiction::Us,
        client_ip: "203.0.113.1".to_owned(),
        resolved_locale: LocaleBcp47::EnUs,
    };
    (ctx, req)
}

fn bench_accept(c: &mut Criterion) {
    let (private, _public) = gen_keys();
    c.bench_function("dpa/accept_rs256_sign", |b| {
        let mut seq: u64 = 0;
        b.iter(|| {
            // Fresh service per iter so idempotency cache misses + the
            // sign + persist path executes end-to-end.
            seq = seq.saturating_add(1);
            let svc = build_service(1_700_000_000_000, private.clone());
            let (ctx, req) = build_request(seq);
            let receipt = svc.accept(black_box(&ctx), black_box(req)).expect("accept");
            black_box(receipt);
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let (private, public) = gen_keys();
    let svc = build_service(1_700_000_000_000, private);
    let (ctx, req) = build_request(0);
    let receipt = svc.accept(&ctx, req).expect("seed receipt");
    c.bench_function("dpa/verify_receipt_rs256", |b| {
        b.iter(|| {
            let claims = verify_receipt(
                black_box(&public),
                Some("kid-bench-01"),
                black_box(&receipt.jwt_receipt),
            )
            .expect("verify");
            black_box(claims);
        });
    });
}

criterion_group!(benches, bench_accept, bench_verify);
criterion_main!(benches);
