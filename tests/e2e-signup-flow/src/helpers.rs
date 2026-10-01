//! Shared test fixtures for the R3-1 E2E harness.
//!
//! See the crate-level rustdoc for the full pipeline. The helpers
//! exported here are the only API surface the integration tests rely
//! on; keeping them centralised avoids re-deriving the same wiring (RSA
//! keygen, Stripe webhook secret, deterministic JTI minter, etc.) per
//! test binary.
//!
//! Charter notes:
//! - All identifiers (tenant slug, idempotency key, correlation id, JTI)
//!   are derived from the tenant name passed to [`make_test_tenant`] so
//!   the harness is deterministic across runs.
//! - `#[non_exhaustive]` types from the consumed crates are constructed
//!   exclusively through the canonical constructors (never brace-init
//!   across the crate boundary).

#![allow(
    clippy::expect_used,
    reason = "test harness construction may panic on infrastructure-level failures (RSA keygen)"
)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use corelink_dpa_acceptance::service::{Clock, DpaAcceptanceService, JtiMinter};
use corelink_dpa_acceptance::{
    ConsentProofPayload, DpaAcceptanceRequest, InMemoryDpaAcceptanceStore, InMemoryDpaAuditSink,
    InMemoryNotificationSink, IpHashSalt, Jurisdiction, LocaleBcp47, LocaleNoticeRegistry,
    RsaPrivateKeyPem, RsaPublicKeyPem, SignupId as DpaSignupId, TenantCtx as DpaTenantCtx,
    TenantId as DpaTenantId,
};
use corelink_signup::orchestrator::InMemoryProvisionRecord;
use corelink_signup::{
    Bcp47Locale, CorrelationId, IdempotencyKey, InMemoryAtomicSignupStore, InMemoryBillingClient,
    InMemorySignupAuditSink, PatHash, ShownOnceToken, SignupAuditEventType, SignupOrchestrator,
    SignupOutcome, SignupRequest, SignupResponse, TenantId as SignupTenantId, UserEmailHash,
};
use corelink_tier_selection::{
    InMemoryDpaGate, InMemoryStripeClient, InMemoryTierSelectionAuditSink, StripeClient,
    TenantCtx as TierTenantCtx, TenantId as TierTenantId, TierSelectionAuditEventType,
    TierSelectionLedger,
};

use crate::r2::InMemoryR2Client;
use crate::{TEST_DPA_NOTICE_EN, TEST_DPA_VERSION};

/// Canonical e2e audit event family discriminator. Pinned by
/// [`verify_audit_chain`] so the test asserts the ordering of the
/// three sub-crate audit chains explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpectedAuditEvent {
    /// `corelink.signup.started`.
    SignupStarted,
    /// `corelink.signup.completed`.
    SignupCompleted,
    /// `corelink.signup.deferred`.
    SignupDeferred,
    /// `corelink.signup.failed`.
    SignupFailed,
    /// `dpa.accepted` (per `corelink-dpa-acceptance`).
    DpaAccepted,
    /// `tier.attempted` (per `corelink-tier-selection`).
    TierAttempted,
    /// `tier.activated.free`.
    TierActivatedFree,
    /// `tier.stripe.checkout.created`.
    TierStripeCheckoutCreated,
    /// `tier.dpa.first.violation`.
    TierDpaFirstViolation,
}

/// Bundle of in-memory ledgers + the R2 stub returned by
/// [`setup_test_ledgers`].
#[derive(Debug)]
pub struct TestEnv {
    /// Signup orchestrator (in-memory store + billing + audit).
    pub signup: SignupOrchestrator<
        InMemorySignupAuditSink,
        InMemoryAtomicSignupStore,
        InMemoryBillingClient,
        InMemoryProvisionRecord,
    >,
    /// Clone of the signup audit sink (orchestrator does not expose
    /// its sink accessor; we keep an external handle for inspection).
    pub signup_audit: InMemorySignupAuditSink,
    /// Clone of the signup atomic store (mirror of the D1 transaction
    /// log; used by tests to assert atomic counter invariants).
    pub signup_store: InMemoryAtomicSignupStore,
    /// DPA acceptance service.
    pub dpa: DpaAcceptanceService<
        InMemoryDpaAcceptanceStore,
        InMemoryDpaAuditSink,
        InMemoryNotificationSink,
        CountingJtiMinter,
        FixedClock,
    >,
    /// Public RSA key used to verify the JWT receipt (matches the DPA
    /// service's signing key family).
    pub dpa_public_key: RsaPublicKeyPem,
    /// Tier-selection ledger.
    pub tier: TierSelectionLedger,
    /// DPA acceptance gate handle shared with the tier ledger (so the
    /// happy path can flip the gate to `accepted` after DPA submission).
    pub dpa_gate: Arc<InMemoryDpaGate>,
    /// In-memory Stripe client (the tier ledger's Stripe collaborator).
    pub stripe: Arc<InMemoryStripeClient>,
    /// Tier-selection audit sink handle (for ordering assertions).
    pub tier_audit: InMemoryTierSelectionAuditSink,
    /// R2 CAS stub.
    pub r2: InMemoryR2Client,
    /// Pinned `now_ms` clock (deterministic across all sub-services).
    pub now_ms: u64,
}

/// Per-test deterministic clock.
#[derive(Debug)]
pub struct FixedClock {
    now_ms: i64,
}

impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.now_ms
    }
}

/// Counting JTI minter (deterministic).
#[derive(Debug, Default)]
pub struct CountingJtiMinter {
    counter: Mutex<u64>,
}

impl JtiMinter for CountingJtiMinter {
    fn mint(&self) -> String {
        let mut g = match self.counter.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = g.saturating_add(1);
        format!("jti-{:08}", *g)
    }
}

/// Construct the canonical e2e test bundle. All four ledgers share the
/// same `now_ms` clock and the same DPA gate so the tier ledger
/// observes DPA acceptance the moment the DPA service records it.
#[must_use]
pub fn setup_test_ledgers() -> TestEnv {
    let now_ms: u64 = 1_700_000_000_000;

    // ---- Signup orchestrator ----
    let signup_audit = InMemorySignupAuditSink::new();
    let signup_store = InMemoryAtomicSignupStore::new();
    let signup = SignupOrchestrator::new(
        signup_audit.clone(),
        signup_store.clone(),
        InMemoryBillingClient::new(),
        InMemoryProvisionRecord::new(),
    );

    // ---- DPA acceptance service ----
    let mut registry = LocaleNoticeRegistry::new();
    registry.register(LocaleBcp47::EnUs, TEST_DPA_NOTICE_EN);
    registry.register(
        LocaleBcp47::PtBr,
        "DPA v1.0.0 (pt-BR) — texto canônico e2e.",
    );
    registry.register(
        LocaleBcp47::Es419,
        "DPA v1.0.0 (es-419) — texto canónico e2e.",
    );

    let Keys { private, public } = gen_keys();

    let dpa = DpaAcceptanceService::new(
        InMemoryDpaAcceptanceStore::new(),
        InMemoryDpaAuditSink::new(),
        InMemoryNotificationSink::new(),
        CountingJtiMinter::default(),
        FixedClock {
            now_ms: now_ms as i64,
        },
        registry,
        private,
        "kid-e2e-test-01",
        IpHashSalt::new(Some(&[0x53; 32])).expect("valid e2e salt"),
    );

    // ---- Tier-selection ledger ----
    let dpa_gate = Arc::new(InMemoryDpaGate::new());
    let stripe = Arc::new(InMemoryStripeClient::new());
    let tier_audit = InMemoryTierSelectionAuditSink::new();
    let tier = TierSelectionLedger::new(
        dpa_gate.clone() as Arc<dyn corelink_tier_selection::DpaAcceptanceGate>,
        stripe.clone() as Arc<dyn StripeClient>,
        Arc::new(tier_audit.clone()),
        TEST_DPA_VERSION,
        "https://app.corelink.example/billing/success",
        "https://app.corelink.example/billing/cancel",
    );

    TestEnv {
        signup,
        signup_audit,
        signup_store,
        dpa,
        dpa_public_key: public,
        tier,
        dpa_gate,
        stripe,
        tier_audit,
        r2: InMemoryR2Client::new(),
        now_ms,
    }
}

/// Canonical per-test tenant fixture returned by [`make_test_tenant`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TenantBundle {
    /// Logical tenant slug (also seeded into all derived identifiers).
    pub name: String,
    /// Deterministic signup payload.
    pub signup_request: SignupRequest,
    /// `corelink_locale` cookie locale (canonical en-US for the harness;
    /// tests can clone + override).
    pub locale_bcp47: LocaleBcp47,
}

/// Build a [`TenantBundle`] whose identifiers (idempotency key,
/// correlation id, Clerk event id, email hash) are deterministic
/// functions of `name`.
#[must_use]
pub fn make_test_tenant(name: &str) -> TenantBundle {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b":corelink-e2e-v1");
    let email_hash = hex::encode(h.finalize());
    let idem = format!("idem-{name}");
    let clerk_evt = format!("evt_e2e_{name}");
    TenantBundle {
        name: name.to_string(),
        signup_request: SignupRequest::new(
            clerk_evt.clone(),
            UserEmailHash::new(email_hash),
            Bcp47Locale::new("en-US"),
            IdempotencyKey::new(idem),
            CorrelationId::new(clerk_evt),
        ),
        locale_bcp47: LocaleBcp47::EnUs,
    }
}

/// Outcome captured after the orchestrator + DPA + tier pipeline ran.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProvisionedTenant {
    /// Tenant id minted by the signup orchestrator.
    pub tenant_id: SignupTenantId,
    /// First PAT hash issued at signup.
    pub first_pat_hash: PatHash,
    /// Shown-once reveal token issued at signup.
    pub shown_once_token: ShownOnceToken,
    /// Raw signup response (for additional assertions in callers).
    pub signup_response: SignupResponse,
}

impl ProvisionedTenant {
    /// Extract the tenant + PAT triplet from a `SignupOutcome::Provisioned`
    /// response.
    ///
    /// # Errors
    ///
    /// Returns the unhappy outcome verbatim if it is not `Provisioned`
    /// so callers can pattern-match on the variant they actually got.
    #[allow(clippy::result_large_err)] // test-only harness; SignupOutcome is the canonical surface
    pub fn from_response(resp: SignupResponse) -> Result<Self, SignupOutcome> {
        match resp.outcome.clone() {
            SignupOutcome::Provisioned {
                tenant_id,
                first_pat_hash,
                shown_once_token,
                ..
            } => Ok(Self {
                tenant_id,
                first_pat_hash,
                shown_once_token,
                signup_response: resp,
            }),
            other => Err(other),
        }
    }
}

/// Verify that the signup audit chain contains, in order, the events
/// listed in `expected`. The function is **subset-ordered**: events
/// MAY appear with additional events in between (e.g. `tier_attempted`
/// between `signup.started` and `signup.completed`); duplicates are
/// allowed; the relative order MUST be respected.
///
/// # Errors
///
/// Returns a human-readable error string describing the first mismatch.
pub fn verify_audit_chain(env: &TestEnv, expected: &[ExpectedAuditEvent]) -> Result<(), String> {
    let mut emitted: Vec<ExpectedAuditEvent> = Vec::new();

    // Signup audit chain.
    for rec in env.signup_audit.snapshot() {
        emitted.push(match rec.event_type {
            SignupAuditEventType::Started => ExpectedAuditEvent::SignupStarted,
            SignupAuditEventType::Completed => ExpectedAuditEvent::SignupCompleted,
            SignupAuditEventType::Deferred => ExpectedAuditEvent::SignupDeferred,
            SignupAuditEventType::Failed => ExpectedAuditEvent::SignupFailed,
            _ => continue,
        });
    }

    // DPA audit chain — translate the `dpa.accepted` event only.
    for ev in env.dpa.audit_sink().snapshot() {
        if matches!(ev, corelink_dpa_acceptance::DpaAuditEvent::Accepted { .. }) {
            emitted.push(ExpectedAuditEvent::DpaAccepted);
        }
    }

    // Tier-selection audit chain.
    for ev in env.tier_audit.snapshot_event_types() {
        emitted.push(match ev {
            TierSelectionAuditEventType::TierSelectAttempted => ExpectedAuditEvent::TierAttempted,
            TierSelectionAuditEventType::TierActivatedFree => ExpectedAuditEvent::TierActivatedFree,
            TierSelectionAuditEventType::StripeCheckoutSessionCreated => {
                ExpectedAuditEvent::TierStripeCheckoutCreated
            }
            TierSelectionAuditEventType::DpaFirstViolationAttempt => {
                ExpectedAuditEvent::TierDpaFirstViolation
            }
            _ => continue,
        });
    }

    // Subset-ordered match.
    let mut cursor = 0usize;
    let mut matched: HashSet<usize> = HashSet::new();
    for (idx, want) in expected.iter().enumerate() {
        let mut found = false;
        while cursor < emitted.len() {
            let got = emitted.get(cursor).copied();
            cursor = cursor.saturating_add(1);
            if got == Some(*want) {
                matched.insert(idx);
                found = true;
                break;
            }
        }
        if !found {
            return Err(format!(
                "audit chain missing expected event {want:?} at position {idx}; \
                 emitted = {emitted:?}"
            ));
        }
    }
    Ok(())
}

// -------------------------------------------------------------------
// Internal helpers: bridge identifier types across the three crates
// (signup vs DPA vs tier all carry their own `TenantId` newtype but
// the e2e harness uses the signup tenant id as the canonical key).
// -------------------------------------------------------------------

/// Build the [`DpaTenantCtx`] for the DPA `accept` call given a
/// freshly-provisioned signup tenant.
#[must_use]
pub fn dpa_ctx_for(prov: &ProvisionedTenant, signup_id_str: &str) -> DpaTenantCtx {
    DpaTenantCtx {
        tenant_id: DpaTenantId(prov.tenant_id.as_str().to_string()),
        signup_id: DpaSignupId(signup_id_str.to_string()),
        jurisdiction: Jurisdiction::Us,
        client_ip: "203.0.113.7".to_string(),
        resolved_locale: LocaleBcp47::EnUs,
    }
}

/// Build a canonical DPA acceptance request matching the registry
/// notice text for `locale`.
#[must_use]
pub fn dpa_request_for(_env: &TestEnv, locale: LocaleBcp47) -> DpaAcceptanceRequest {
    let hash = match locale {
        LocaleBcp47::EnUs => corelink_dpa_acceptance::notice_text_hash(TEST_DPA_NOTICE_EN),
        LocaleBcp47::PtBr => {
            corelink_dpa_acceptance::notice_text_hash("DPA v1.0.0 (pt-BR) — texto canônico e2e.")
        }
        LocaleBcp47::Es419 => {
            corelink_dpa_acceptance::notice_text_hash("DPA v1.0.0 (es-419) — texto canónico e2e.")
        }
        _ => corelink_dpa_acceptance::notice_text_hash(TEST_DPA_NOTICE_EN),
    };
    DpaAcceptanceRequest {
        proof: ConsentProofPayload {
            notice_text_hash: hash,
            notice_version: TEST_DPA_VERSION.to_string(),
            dpa_version: TEST_DPA_VERSION.to_string(),
            locale,
            wording_id: "11111111-1111-7111-8111-111111111111".to_string(),
            ui_capture_ts: 1_699_999_999_000,
            submission_ts: 0,
        },
    }
}

/// Build a [`TierTenantCtx`] mirroring the signup tenant.
#[must_use]
pub fn tier_ctx_for(prov: &ProvisionedTenant, now_ms: u64) -> TierTenantCtx {
    TierTenantCtx::new(
        TierTenantId::new(prov.tenant_id.as_str()),
        now_ms,
        format!("corr-{}", prov.tenant_id),
    )
}

// -------------------------------------------------------------------
// RSA fixture + signup audit accessor.
// -------------------------------------------------------------------

/// PEM-encoded RSA key pair used by the DPA receipt JWT.
#[derive(Debug)]
pub struct Keys {
    /// Private key (PKCS#1 PEM).
    pub private: RsaPrivateKeyPem,
    /// Public key (SPKI PEM).
    pub public: RsaPublicKeyPem,
}

/// Generate a fresh 2048-bit RSA key pair for the harness.
///
/// The `jsonwebtoken` crate rejects RSA keys smaller than 2048-bit
/// (`JwtSign("RSA key invalid: TooSmall")`), so the harness uses
/// 2048-bit keys. Debug-mode keygen takes 30-60s on commodity
/// hardware; per-process [`Keys::shared`] caches the key pair so
/// every test in the binary shares it (one keygen per `cargo test`
/// binary, not per `#[test]`).
#[must_use]
pub fn gen_keys() -> Keys {
    Keys::shared()
}

fn gen_keys_inner() -> Keys {
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
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

impl Keys {
    /// Return a per-process cached key pair so tests share a single
    /// expensive keygen.
    #[must_use]
    pub fn shared() -> Self {
        use std::sync::OnceLock;
        static CACHE: OnceLock<(String, String)> = OnceLock::new();
        let (priv_pem, pub_pem) = CACHE
            .get_or_init(|| {
                let k = gen_keys_inner();
                (k.private.0, k.public.0)
            })
            .clone();
        Keys {
            private: RsaPrivateKeyPem(priv_pem),
            public: RsaPublicKeyPem(pub_pem),
        }
    }
}

// -------------------------------------------------------------------
// Test-only audit accessors — bolt-on to keep the harness ergonomic
// without modifying the production orchestrator surface.
// -------------------------------------------------------------------

/// Tier-selection audit snapshot extension — surfaces the event-type
/// sequence from the in-memory sink.
pub trait TierAuditSnapshotExt {
    /// Snapshot the canonical event-type sequence.
    fn snapshot_event_types(&self) -> Vec<TierSelectionAuditEventType>;
}

impl TierAuditSnapshotExt for InMemoryTierSelectionAuditSink {
    fn snapshot_event_types(&self) -> Vec<TierSelectionAuditEventType> {
        self.snapshot().into_iter().map(|r| r.event_type).collect()
    }
}
