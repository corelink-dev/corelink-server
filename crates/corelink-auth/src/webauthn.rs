//! `corelink-webauthn` — WebAuthn Level 3 admin primitives (WI-S03-006).
//!
//! Implements the canonical surface that `auth_model.md §1.6 +
//! security_model.md §CTRL-AUTH-010 + invariant_registry.md
//! INV-AUTH-WEBAUTHN-*` enforce on every admin step-up and recovery
//! flow. The crate is **HIGH_RISK** (FF-HR-002 / FF-HR-005 / FF-HR-009)
//! and is the first line of defence against:
//!
//! - origin spoofing (`evil.example.com.attacker.com`),
//! - RP-ID confusion,
//! - challenge replay,
//! - user-verification (UV) downgrade in admin step-up,
//! - sign-count regression (cloned-authenticator signal),
//! - AAGUID denylist evasion,
//! - magic-link recovery (Lote 10.3-tris explicitly rejected — only
//!   the 6-digit OTP path is canonical).
//!
//! # Architectural split
//!
//! | Layer | What this crate ships | What is deferred |
//! |---|---|---|
//! | Trait surface | [`WebAuthnEngine`] / [`ChallengeStore`] / [`CredentialStore`] / [`RecoveryOtpStore`] | — |
//! | In-memory implementations | [`InMemoryEngine`] / [`InMemoryChallengeStore`] / [`InMemoryCredentialStore`] / [`InMemoryRecoveryOtpStore`] | — |
//! | Production engine | (stub returning [`WebAuthnError::EngineNotConfigured`]) | `webauthn-rs = 0.5` shim wired alongside staging Cloudflare + real authenticators (charter trait-abstraction-defer pattern; see WI-S03-006 §6.2) |
//! | Recovery OTP | Argon2id PHC mint / verify, single-use guard, rate limit | Email-channel delivery (Clerk SSO; lives in S-19 onboarding) |
//!
//! The trait abstraction lets every property test, adversarial test,
//! and sprint-close audit run host-side without browser / authenticator
//! emulation. The Cloudflare integration shim is a separate WI per
//! charter §inflection (real CF account credentials).
//!
//! # Canonical invariants enforced
//!
//! 1. [`RpId::new`] rejects subdomains and shapes that are not
//!    eTLD+1 (mitigates RP-ID confusion attacks). Codex round-1 P0
//!    surface: an attacker registering `attacker.com` as RP-ID would
//!    be silently accepted by a weak validator.
//! 2. [`OriginAllowlist::contains`] is **exact match** — no prefix /
//!    regex / suffix matching (mitigates `evil.example.com.attacker.com`).
//! 3. [`Ceremony::Authentication`] in admin step-up demands
//!    [`AuthenticatorFlags::user_verification`] = true. UP alone is
//!    insufficient.
//! 4. [`Credential::sign_count`] is monotonic; regressions raise
//!    [`SignCountSeverity::Sev2InvestigationRequired`] on first event
//!    (W3C-compliant per Lote 10.3-tris P0-R5-002b — passkey
//!    `sign_count = 0` always is exempt).
//! 5. [`AaguidPolicy`] explicitly enforces allowlist + denylist; an
//!    AAGUID missing from allowlist is rejected even if not on the
//!    denylist (closed-default).
//! 6. Challenge TTL ≤ 300 s (replay surface bound); recovery OTP TTL
//!    ≤ 600 s.
//! 7. Recovery OTP is **single-use**: the
//!    [`RecoveryOtpStore::verify_and_consume`] call is guarded by a
//!    SQL-equivalent `UPDATE … WHERE consumed_at IS NULL` semantic.
//! 8. **Magic-link recovery is rejected at the type level**:
//!    [`RecoveryChannel`] enum has no `MagicLink` variant; an attempt
//!    to add one would be a compile error in every existing call site.
//!
//! # Forbidden surface
//!
//! - **No `unsafe`** anywhere in the crate.
//! - **No `unwrap` / `expect` / `panic` / direct `[i]` indexing** in
//!   library code (all crate-strict clippy lints are `deny`).
//! - **No `webauthn-rs` runtime dependency at SEAL** — the production
//!   shim is gated behind a `feature = "host-server"` that is
//!   unimplemented in this Lote so the no-default-features build stays
//!   `wasm32-unknown-unknown`-clean for downstream Worker callers
//!   (matches the pattern set by `corelink-pat` and `corelink-clerk`).
//!
//! # Quickstart — passkey enrolment + admin step-up
//!
//! ```rust
//! use corelink_auth::webauthn::{
//!     AaguidPolicy, AuthenticatorAttachment, AuthenticatorFlags, Ceremony, CredentialId,
//!     EngineConfig, InMemoryEngine, Origin, OriginAllowlist, RegistrationResponse,
//!     AuthenticationResponse, RpId, ChallengeTtl, UserAccountId, Aaguid, WebAuthnEngine,
//!     SignCount, EngineClock, FixedClock, COSE_ALG_ES256,
//! };
//! use std::time::Duration;
//! use uuid::Uuid;
//!
//! # fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = EngineConfig::builder(RpId::new("example.com")?, "CoreLink")
//!     .origins(OriginAllowlist::from_strings([
//!         "https://app.example.com",
//!         "https://admin.example.com",
//!     ])?)
//!     .aaguids(AaguidPolicy::builder()
//!         .allow(Aaguid::yubikey_5())
//!         .allow(Aaguid::touch_id())
//!         .deny(Aaguid::yubikey_4_deprecated())
//!         .build())
//!     .challenge_ttl(ChallengeTtl::default())
//!     .build()?;
//! let clock = FixedClock::epoch();
//! let engine = InMemoryEngine::new(cfg, clock);
//! let user = UserAccountId(Uuid::nil());
//!
//! let challenge = engine.start_registration(user, AuthenticatorAttachment::Platform)?;
//! let response = RegistrationResponse::synthetic_for_test(
//!     challenge.id().clone(), Aaguid::touch_id(), CredentialId::synthetic([1u8; 32].to_vec()),
//!     COSE_ALG_ES256, AuthenticatorFlags::up_uv(), 0, Origin::parse("https://app.example.com")?,
//! );
//! let cred_id = engine.finish_registration(challenge.id(), response)?;
//!
//! let auth_challenge = engine.start_authentication(user, Ceremony::AdminStepUp)?;
//! let auth_response = AuthenticationResponse::synthetic_for_test(
//!     auth_challenge.id().clone(), cred_id.clone(), AuthenticatorFlags::up_uv(), SignCount::new(1),
//!     Origin::parse("https://admin.example.com")?,
//! );
//! let outcome = engine.finish_authentication(auth_challenge.id(), auth_response)?;
//! assert!(outcome.is_authenticated());
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

pub mod aaguid;
pub mod challenge;
pub mod clock;
pub mod cose;
pub mod credential;
pub mod engine;
pub mod error;
pub mod flags;
pub mod metrics;
pub mod origin;
pub mod recovery;
pub mod sign_count;
pub mod step_up;
pub mod store;
pub mod types;

pub use aaguid::{Aaguid, AaguidPolicy, AaguidPolicyBuilder};
pub use challenge::{
    AuthenticationChallenge, ChallengeBytes, ChallengeId, ChallengeTtl, RegistrationChallenge,
    CHALLENGE_BYTE_LEN,
};
pub use clock::{EngineClock, FixedClock};
pub use cose::{
    cose_algorithm_label, parse_cose_algorithm, CoseAlgorithm, COSE_ALG_EDDSA, COSE_ALG_ES256,
    COSE_ALG_RS256,
};
pub use credential::{Credential, CredentialId, RegistrationResponse};
pub use engine::{
    AuthenticationOutcome, AuthenticationResponse, Ceremony, EngineConfig, EngineConfigBuilder,
    InMemoryEngine, ProductionEngineNotConfigured, WebAuthnEngine,
};
pub use error::WebAuthnError;
pub use flags::AuthenticatorFlags;
pub use metrics::{CeremonyResult, MetricsObserver, MetricsRecorder, NoopMetrics};
pub use origin::{Origin, OriginAllowlist, RpId};
pub use recovery::{
    RecoveryChannel, RecoveryOtp, RecoveryOtpHash, RecoveryOtpId, RecoveryOtpRecord,
    RecoveryOtpVerifyOutcome, RecoveryRateLimit, RECOVERY_OTP_DIGITS, RECOVERY_OTP_TTL_DEFAULT,
};
pub use sign_count::{SignCount, SignCountAssessment, SignCountSeverity};
pub use step_up::{StepUpToken, StepUpTokenId, STEP_UP_TTL_DEFAULT};
pub use store::{
    AuthenticatorAttachment, ChallengeStore, CredentialStore, InMemoryChallengeStore,
    InMemoryCredentialStore, InMemoryRecoveryOtpStore, RecoveryOtpStore,
};
pub use types::UserAccountId;

/// Crate canonical version string, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
