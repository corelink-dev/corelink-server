//! Property tests pinning the load-bearing invariants of
//! `corelink-quota-cas` at 10k iterations per check (PR-gate; nightly
//! 100k via `PROPTEST_CASES` env var override).
//!
//! Coverage map (mirrors WI-S08-003 §6.1.12):
//!
//! - `prop_cas_no_double_spend` — concurrent (sequential under
//!   per-instance `Mutex` envelope; mirrors DO actor model) acquires
//!   never exceed `bytes_quota`. Race-aware strict-< predicate
//!   pinning.
//! - `prop_cas_race_detected_retry_succeeds` — when a mid-flight
//!   version bump fires the `VersionMismatch` arm, the orchestrator
//!   retries and the second attempt succeeds (canonical happy path
//!   under contention).
//! - `prop_retry_after_days_until_month_reset` — formula correctness:
//!   last second of month → 1s; first second of month → ~31d; never
//!   below floor; never above 31d.
//! - `prop_tenant_isolation` — tenant A's CAS state is invisible to
//!   tenant B (architectural impossibility per per-tenant key).
//! - `prop_audit_emit_per_decision_arm` — every Allow / Deny429 /
//!   RaceDetected decision emits exactly one canonical audit record
//!   per arm.
//! - `prop_idempotent_zero_byte_check` — `request_bytes == 0` is
//!   read-path passthrough; no state mutation; no Commit audit;
//!   cas_version unchanged.
//! - `prop_cas_decision_budget_and_correctness` — deterministic decision,
//!   state, audit, and bounded-attempt invariants over generated inputs.
//! - `real_latency_probe_under_5ms_p99` — an explicitly ignored, opt-in
//!   wall-clock probe for the production SLO (never part of general CI).
//! - `prop_overshoot_does_not_panic` — extreme inputs never panic
//!   the orchestrator (saturating arithmetic via checked_add).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "test code: panics surface as test failures by design"
)]

use std::io::Write as _;
use std::sync::Arc;

use corelink_billing::quota::cas::{
    canonical_audit_event_strings, canonical_metric_names, days_until_month_reset_secs,
    next_month_first_utc_midnight_secs, AtomicCasState, AtomicQuotaChecker, AtomicTenantBytesState,
    InMemoryAtomicCasState, InMemoryAtomicQuotaChecker, InMemoryQuotaCasAuditSink,
    InMemoryQuotaCasMetrics, QuotaCasDecision, QuotaCasEventType, QuotaCasMetricKind,
    QuotaCasResultLabel, MAX_CAS_AUDIT_EVENTS_PER_ATTEMPT, MAX_CAS_AUDIT_EVENTS_PER_DECISION,
    MAX_SECS_PER_MONTH, MIGRATION_0012_QUOTA_CAS_ATTEMPTS, RETRY_AFTER_MIN_SECS,
};
use corelink_eviction::EvictionRegion;
use proptest::prelude::*;
use uuid::Uuid;

fn proptest_cases() -> u32 {
    proptest_cases_or(10_000)
}

/// Parameterized variant — returns env override if set, else `default`.
/// Used by per-block `#![proptest_config(...)]` to keep the env-override
/// contract uniform across callsites with distinct case counts.
fn proptest_cases_or(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

type CheckerType = InMemoryAtomicQuotaChecker<
    InMemoryAtomicCasState,
    InMemoryQuotaCasAuditSink,
    InMemoryQuotaCasMetrics,
>;

type Fixture = (
    CheckerType,
    Arc<InMemoryAtomicCasState>,
    Arc<InMemoryQuotaCasAuditSink>,
    Arc<InMemoryQuotaCasMetrics>,
);

fn checker_fixture(used: u64, quota: u64) -> Fixture {
    let state = Arc::new(InMemoryAtomicCasState::new());
    state
        .seed_row(AtomicTenantBytesState {
            tenant_id: Uuid::from_u128(0xa),
            region: EvictionRegion::Sam,
            bytes_used: used,
            bytes_quota: quota,
            cas_version: 0,
        })
        .unwrap();
    let audit = Arc::new(InMemoryQuotaCasAuditSink::new());
    let metrics = Arc::new(InMemoryQuotaCasMetrics::new());
    let checker = InMemoryAtomicQuotaChecker::with_defaults(
        Arc::clone(&state),
        Arc::clone(&audit),
        Arc::clone(&metrics),
    );
    (checker, state, audit, metrics)
}

// ---- Sanity: artifact + canonical lists pinned ----------------------

#[test]
fn migration_0012_is_embedded() {
    assert!(!MIGRATION_0012_QUOTA_CAS_ATTEMPTS.is_empty());
    assert!(MIGRATION_0012_QUOTA_CAS_ATTEMPTS.contains("CREATE TABLE"));
    assert!(MIGRATION_0012_QUOTA_CAS_ATTEMPTS.contains("quota_cas_attempts"));
}

#[test]
fn canonical_audit_event_strings_pinned_count_six() {
    let s = canonical_audit_event_strings();
    assert_eq!(s.len(), 6);
}

#[test]
fn canonical_metric_names_pinned_count_five() {
    let s = canonical_metric_names();
    assert_eq!(s.len(), 5);
}

// ---- prop_cas_no_double_spend --------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Sequential acquires under per-instance Mutex envelope MUST never
    /// exceed bytes_quota. Mirrors DO actor model serialisation.
    #[test]
    fn prop_cas_no_double_spend(
        // Sample (quota, frac, request, n_calls) and derive used from frac so
        // `used < quota` is structurally guaranteed.
        quota in 1_000u64..1_000_000,
        frac in 0u32..900,                 // permille of quota in [0, 0.9].
        request_bytes in 1u64..10_000,
        n_calls in 1usize..50,
    ) {
        let used = (quota / 1_000).saturating_mul(frac as u64);
        let (checker, state, _a, _m) = checker_fixture(used, quota);
        let mut total_committed: u64 = used;
        for _ in 0..n_calls {
            let out = checker.try_acquire(
                Uuid::from_u128(0xa),
                EvictionRegion::Sam,
                request_bytes,
                1_000,
                1,
            );
            match out {
                Ok(o) => match o.decision {
                    QuotaCasDecision::Allow { bytes_used_after, .. } => {
                        total_committed = bytes_used_after;
                    }
                    QuotaCasDecision::Deny429 { .. } => {
                        // Subsequent calls would also deny — break.
                        break;
                    }
                    _ => break,
                },
                Err(_) => break,
            }
        }
        // Critical invariant: total_committed never exceeded quota.
        let row = state
            .lookup(Uuid::from_u128(0xa), EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        prop_assert!(
            row.bytes_used < quota || row.bytes_used == used,
            "bytes_used {} >= quota {} after {} calls",
            row.bytes_used,
            quota,
            n_calls
        );
        // Sanity: total_committed matches state row.
        prop_assert_eq!(row.bytes_used, total_committed);
    }
}

// ---- prop_retry_after_days_until_month_reset ----------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_retry_after_days_until_month_reset(
        // Random Unix epoch second within reasonable range
        // (1970..2100 ≈ [0, 4_000_000_000_000]).
        now_secs in 1i64..4_000_000_000,
    ) {
        let secs = days_until_month_reset_secs(now_secs);
        prop_assert!(secs >= RETRY_AFTER_MIN_SECS);
        prop_assert!(secs <= MAX_SECS_PER_MONTH);
        // Stronger: the next 1st-UTC-midnight is strictly after now.
        let next = next_month_first_utc_midnight_secs(now_secs);
        prop_assert!(next > now_secs);
    }
}

// ---- prop_tenant_isolation ----------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_tenant_isolation(
        used_a in 0u64..50,                 // < min(quota_a) = 100, so always < quota.
        quota_a in 100u64..1_000,
        used_b in 0u64..50,                 // < min(quota_b) = 100.
        quota_b in 100u64..1_000,
        request_a in 1u64..50,
        request_b in 1u64..50,
    ) {
        let state = Arc::new(InMemoryAtomicCasState::new());
        let ten_a = Uuid::from_u128(0xa);
        let ten_b = Uuid::from_u128(0xb);
        state.seed_row(AtomicTenantBytesState {
            tenant_id: ten_a,
            region: EvictionRegion::Sam,
            bytes_used: used_a,
            bytes_quota: quota_a,
            cas_version: 0,
        }).unwrap();
        state.seed_row(AtomicTenantBytesState {
            tenant_id: ten_b,
            region: EvictionRegion::Sam,
            bytes_used: used_b,
            bytes_quota: quota_b,
            cas_version: 0,
        }).unwrap();
        let audit = Arc::new(InMemoryQuotaCasAuditSink::new());
        let metrics = Arc::new(InMemoryQuotaCasMetrics::new());
        let checker = InMemoryAtomicQuotaChecker::with_defaults(
            Arc::clone(&state),
            Arc::clone(&audit),
            Arc::clone(&metrics),
        );
        // Tenant A acquire.
        let _ = checker.try_acquire(ten_a, EvictionRegion::Sam, request_a, 1_000, 1);
        // Tenant B's state must be UNCHANGED.
        let row_b = state
            .lookup(ten_b, EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        prop_assert_eq!(row_b.bytes_used, used_b);
        prop_assert_eq!(row_b.cas_version, 0);
        // Tenant B acquire.
        let _ = checker.try_acquire(ten_b, EvictionRegion::Sam, request_b, 1_000, 1);
        // Tenant A's state should now be either initial (if A denied)
        // or used_a + request_a (if A allowed); never depends on B.
        let row_a = state
            .lookup(ten_a, EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        prop_assert!(
            row_a.bytes_used == used_a || row_a.bytes_used == used_a + request_a
        );
    }
}

// ---- prop_idempotent_zero_byte_check ------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_idempotent_zero_byte_check(
        quota in 1u64..1_000,
        frac in 0u32..1_000,
        n_calls in 1u32..32,
    ) {
        let used = (quota.saturating_mul(frac as u64)) / 1_000;
        let (checker, state, audit, _m) = checker_fixture(used, quota);
        for _ in 0..n_calls {
            let out = checker.try_acquire(
                Uuid::from_u128(0xa),
                EvictionRegion::Sam,
                0,
                1_000,
                1,
            ).unwrap();
            // Always Allow; bytes_used unchanged.
            let is_allow = matches!(out.decision, QuotaCasDecision::Allow { .. });
            prop_assert!(is_allow);
        }
        // State is byte-exact unchanged (cas_version still 0; bytes_used == used).
        let row = state
            .lookup(Uuid::from_u128(0xa), EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        prop_assert_eq!(row.bytes_used, used);
        prop_assert_eq!(row.cas_version, 0);
        // No CommitSucceeded audit (zero-byte path emits CheckPassed only).
        prop_assert_eq!(
            audit.snapshot_of(QuotaCasEventType::CasCommitSucceeded).len(),
            0
        );
        prop_assert_eq!(
            audit.snapshot_of(QuotaCasEventType::CasCheckPassed).len(),
            n_calls as usize
        );
    }
}

// ---- prop_audit_emit_per_decision_arm -----------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_audit_emit_per_decision_arm(
        used in 0u64..200,
        quota in 100u64..200,
        request_bytes in 1u64..200,
    ) {
        let (checker, _s, audit, metrics) = checker_fixture(used, quota);
        let out = checker.try_acquire(
            Uuid::from_u128(0xa),
            EvictionRegion::Sam,
            request_bytes,
            1_000,
            1,
        ).unwrap();
        match out.decision {
            QuotaCasDecision::Allow { .. } => {
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasCheckPassed).len(),
                    1
                );
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasCommitSucceeded).len(),
                    1
                );
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasDenied429HardBlock).len(),
                    0
                );
                prop_assert_eq!(
                    metrics.check_total_for_label(QuotaCasResultLabel::Allow),
                    1
                );
            }
            QuotaCasDecision::Deny429 { .. } => {
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasDenied429HardBlock).len(),
                    1
                );
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasRetryAfterEmitted).len(),
                    1
                );
                prop_assert_eq!(
                    audit.snapshot_of(QuotaCasEventType::CasCommitSucceeded).len(),
                    0
                );
                prop_assert_eq!(
                    metrics.counter_for_tenant(
                        QuotaCasMetricKind::DenialsTotal,
                        Uuid::from_u128(0xa)
                    ),
                    1
                );
            }
            _ => {
                prop_assert!(false, "unexpected decision arm");
            }
        }
    }
}

// ---- prop_overshoot_does_not_panic ------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_overshoot_does_not_panic(
        used in 0u64..u64::MAX / 2,
        quota in 1u64..u64::MAX,
        request_bytes in 1u64..u64::MAX / 2,
    ) {
        let (checker, _s, _a, _m) = checker_fixture(used, quota);
        // The orchestrator MUST NOT panic on any input combination
        // (saturating arithmetic via checked_add for overflow; defensive
        // ceiling computation).
        let _ = checker.try_acquire(
            Uuid::from_u128(0xa),
            EvictionRegion::Sam,
            request_bytes,
            1_000,
            1_700_000_000,
        );
    }
}

// ---- prop_cas_race_detected_retry_succeeds ------------------------

/// One-shot version-bumping AtomicCasState wrapper: bumps the inner
/// version on the first try_commit_delta call, then defers to the
/// inner. Mirrors a mid-flight concurrent commit_reservation.
#[derive(Debug)]
struct OneShotRaceState {
    inner: Arc<InMemoryAtomicCasState>,
    bumped: std::sync::Mutex<bool>,
}

impl AtomicCasState for OneShotRaceState {
    fn lookup(
        &self,
        tenant_id: Uuid,
        region: EvictionRegion,
    ) -> Result<Option<AtomicTenantBytesState>, corelink_billing::quota::cas::AtomicCasStateError>
    {
        self.inner.lookup(tenant_id, region)
    }
    fn try_commit_delta(
        &self,
        tenant_id: Uuid,
        region: EvictionRegion,
        expected_version: u64,
        delta_bytes: u64,
    ) -> Result<AtomicTenantBytesState, corelink_billing::quota::cas::AtomicCasStateError> {
        let mut g = self.bumped.lock().unwrap();
        if !*g {
            *g = true;
            drop(g);
            let cur = self.inner.lookup(tenant_id, region)?.ok_or(
                corelink_billing::quota::cas::AtomicCasStateError::Missing {
                    tenant_id,
                    region: region.as_str(),
                },
            )?;
            self.inner.seed_row(AtomicTenantBytesState {
                cas_version: cur.cas_version.saturating_add(1),
                ..cur
            })?;
        }
        self.inner
            .try_commit_delta(tenant_id, region, expected_version, delta_bytes)
    }
    fn seed_row(
        &self,
        state: AtomicTenantBytesState,
    ) -> Result<(), corelink_billing::quota::cas::AtomicCasStateError> {
        self.inner.seed_row(state)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    #[test]
    fn prop_cas_race_detected_retry_succeeds(
        quota in 1_000u64..100_000,
        frac in 0u32..900,
        request_bytes in 1u64..50,
    ) {
        let used = (quota / 1_000).saturating_mul(frac as u64);
        let inner = Arc::new(InMemoryAtomicCasState::new());
        inner.seed_row(AtomicTenantBytesState {
            tenant_id: Uuid::from_u128(0xa),
            region: EvictionRegion::Sam,
            bytes_used: used,
            bytes_quota: quota,
            cas_version: 0,
        }).unwrap();
        let race_state = Arc::new(OneShotRaceState {
            inner: Arc::clone(&inner),
            bumped: std::sync::Mutex::new(false),
        });
        let audit = Arc::new(InMemoryQuotaCasAuditSink::new());
        let metrics = Arc::new(InMemoryQuotaCasMetrics::new());
        let checker = InMemoryAtomicQuotaChecker::with_defaults(
            Arc::clone(&race_state),
            Arc::clone(&audit),
            Arc::clone(&metrics),
        );
        let out = checker.try_acquire(
            Uuid::from_u128(0xa),
            EvictionRegion::Sam,
            request_bytes,
            1_000,
            1,
        ).unwrap();
        // Should succeed on attempt 2 (after the OneShot bump).
        let is_allow = matches!(out.decision, QuotaCasDecision::Allow { .. });
        prop_assert!(is_allow);
        prop_assert_eq!(out.cas_attempts, 2);
        prop_assert_eq!(
            audit.snapshot_of(QuotaCasEventType::CasRaceDetected).len(),
            1
        );
        prop_assert_eq!(
            metrics.counter_total(QuotaCasMetricKind::RaceDetectedTotal),
            1
        );
    }
}

// ---- deterministic decision budget + correctness ------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases_or(1_000)))]

    /// The production contract is bounded work and correct state transition,
    /// not an environment-sensitive wall-clock sample. Each non-racing
    /// decision emits exactly two audit records and stays within the bounded
    /// retry/audit budget even when inputs vary adversarially.
    #[test]
    fn prop_cas_decision_budget_and_correctness(
        used in 0u64..2_000,
        quota in 1_000u64..2_000,
        request_bytes in 1u64..50,
    ) {
        prop_assume!(used < quota);
        let (checker, state, audit, metrics) = checker_fixture(used, quota);
        let would_use = used.checked_add(request_bytes).unwrap();
        let should_allow = would_use < quota;
        let outcome = checker.try_acquire(
            Uuid::from_u128(0xa),
            EvictionRegion::Sam,
            request_bytes,
            1_000,
            1,
        ).unwrap();
        prop_assert!(outcome.cas_attempts >= 1);
        prop_assert!(outcome.cas_attempts <= checker.config().max_cas_attempts());
        prop_assert!((audit.len() as u32) <= MAX_CAS_AUDIT_EVENTS_PER_DECISION);
        prop_assert_eq!(audit.len() as u32, MAX_CAS_AUDIT_EVENTS_PER_ATTEMPT);
        prop_assert_eq!(metrics.counter_total(QuotaCasMetricKind::CheckTotal), 1);
        let row = state
            .lookup(Uuid::from_u128(0xa), EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        if should_allow {
            let is_allow = matches!(outcome.decision, QuotaCasDecision::Allow { .. });
            prop_assert!(is_allow);
            prop_assert_eq!(row.bytes_used, would_use);
            prop_assert_eq!(row.cas_version, 1);
            prop_assert_eq!(
                audit.snapshot_of(QuotaCasEventType::CasCheckPassed).len(),
                1
            );
            prop_assert_eq!(
                audit.snapshot_of(QuotaCasEventType::CasCommitSucceeded).len(),
                1
            );
        } else {
            let is_deny = matches!(outcome.decision, QuotaCasDecision::Deny429 { .. });
            prop_assert!(is_deny);
            prop_assert_eq!(row.bytes_used, used);
            prop_assert_eq!(row.cas_version, 0);
            prop_assert_eq!(
                audit.snapshot_of(QuotaCasEventType::CasDenied429HardBlock).len(),
                1
            );
            prop_assert_eq!(
                audit.snapshot_of(QuotaCasEventType::CasRetryAfterEmitted).len(),
                1
            );
        }
    }
}

// ---- isolated real latency measurement ---------------------------

/// Real wall-clock probe of the isolated in-memory fixture against the WI §22
/// budget. It does not claim production latency. It is ignored so a loaded
/// developer host or shared CI runner cannot turn an opt-in measurement into
/// a false general-CI failure. Run explicitly with:
/// `cargo test -p corelink-billing --test quota_cas_prop_quota_cas
/// real_latency_probe_under_5ms_p99 -- --ignored --nocapture`.
#[test]
#[ignore = "opt-in real latency measurement; excluded from general CI"]
fn real_latency_probe_under_5ms_p99() {
    let (checker, _state, _audit, _metrics) = checker_fixture(0, 2_000);
    let mut samples = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        let started = std::time::Instant::now();
        checker
            .try_acquire(Uuid::from_u128(0xa), EvictionRegion::Sam, 1, 1_000, 1)
            .expect("latency probe fixture must remain valid");
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    // Nearest-rank p99 uses rank ceil(0.99 * N), with ranks starting at one.
    // Keep the inclusive 5 ms boundary on that exact order statistic.
    #[expect(
        clippy::manual_div_ceil,
        reason = "scripts/verify_b251_quota_cas_budget.py pins this exact nearest-rank expression"
    )]
    let p99_rank = (samples.len() * 99 + 99) / 100;
    let p99 = samples[p99_rank - 1];
    writeln!(
        std::io::stderr().lock(),
        concat!(
            "B251_LATENCY_PROBE_JSON=",
            "{{\"sample_count\":1000,\"p99_us\":{},\"limit_us\":5000,",
            "\"fixture\":\"InMemoryAtomicQuotaChecker\",",
            "\"production_latency_measured\":false}}"
        ),
        p99
    )
    .expect("latency probe result must be writable");
    assert!(p99 <= 5_000, "quota CAS p99 exceeded 5ms: {p99}us");
}

// ---- prop_retry_after_canonical_at_boundary -----------------------

#[test]
fn retry_after_at_canonical_boundary_cases() {
    // Test boundary cases per WI §1 invariant 8.
    use corelink_billing::quota::cas::retry_after::compose_utc;

    // Last second of December → 1 second.
    let dec_31 = compose_utc(2026, 12, 31, 23, 59, 59);
    assert_eq!(days_until_month_reset_secs(dec_31), 1);

    // First second of January → ~31 days − 1s.
    let jan_1 = compose_utc(2026, 1, 1, 0, 0, 1);
    assert_eq!(days_until_month_reset_secs(jan_1), 31 * 86_400 - 1);

    // Feb 28 non-leap year → 1 day.
    let feb_28_nonleap = compose_utc(2027, 2, 28, 0, 0, 0);
    assert_eq!(days_until_month_reset_secs(feb_28_nonleap), 86_400);

    // Feb 29 leap year → 1 day.
    let feb_29_leap = compose_utc(2028, 2, 29, 0, 0, 0);
    assert_eq!(days_until_month_reset_secs(feb_29_leap), 86_400);
}
