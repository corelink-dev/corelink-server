//! Shared D02/D03 provenance operation. The hosted collector copies this
//! source into the immutable D02 checkout and the protected-main checkout,
//! then hashes the actual checker outcomes and state snapshots.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    reason = "test fixture: the stderr markers are the B-251 collector's protocol, and \
              `hex` indexes a 16-entry table with a nibble"
)]

use std::sync::Arc;

use corelink_billing::quota::cas::{
    AtomicCasState, AtomicQuotaChecker, AtomicTenantBytesState, InMemoryAtomicCasState,
    InMemoryAtomicQuotaChecker, InMemoryQuotaCasAuditSink, InMemoryQuotaCasMetrics,
    QuotaCasDecision,
};
use corelink_eviction::EvictionRegion;
use uuid::Uuid;

const OPERATION_SEED_HEX: &str = "b2510025d002d003";

#[test]
fn operation_emits_transcript() {
    let seed = u64::from_str_radix(OPERATION_SEED_HEX, 16).unwrap();
    let mut state_rng = seed;
    let mut transcript = String::new();
    let mut failures = String::new();
    for ordinal in 0..1_000u32 {
        let used = next(&mut state_rng) % 900;
        let quota = 1_000 + (next(&mut state_rng) % 1_000);
        let request = 1 + (next(&mut state_rng) % 49);
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
        let outcome =
            checker.try_acquire(Uuid::from_u128(0xa), EvictionRegion::Sam, request, 1_000, 1);
        let row = state
            .lookup(Uuid::from_u128(0xa), EvictionRegion::Sam)
            .unwrap()
            .unwrap();
        match outcome {
            Ok(outcome) => {
                let decision = match outcome.decision {
                    QuotaCasDecision::Allow {
                        bytes_used_after,
                        cas_version_after,
                        ..
                    } => format!("allow:{bytes_used_after}:{cas_version_after}"),
                    QuotaCasDecision::Deny429 { would_use, .. } => format!("deny:{would_use}"),
                    _ => "unknown-decision".to_owned(),
                };
                transcript.push_str(&format!(
                    "{ordinal}:{used}:{quota}:{request}:{decision}:{}:{}:{}\n",
                    row.bytes_used, row.cas_version, outcome.cas_attempts
                ));
            }
            Err(error) => {
                failures.push_str(&format!("{ordinal}:{used}:{quota}:{request}:{error:?}\n"));
                transcript.push_str(&format!(
                    "{ordinal}:{used}:{quota}:{request}:error:{}:{}\n",
                    row.bytes_used, row.cas_version
                ));
            }
        }
    }
    eprintln!("B251_OPERATION_COUNT=1000");
    eprintln!("B251_OPERATION_FAILURES_HEX={}", hex(failures.as_bytes()));
    eprintln!(
        "B251_OPERATION_TRANSCRIPT_HEX={}",
        hex(transcript.as_bytes())
    );
}

fn next(state: &mut u64) -> u64 {
    // SplitMix64: stable across toolchains and independent of proptest internals.
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
