//! Happy-path 1 — Access (LGPD Art. 18 II / GDPR Art. 15 read).
//!
//! Customer submits an Access DSR (read-only; no MFA gate) → API
//! returns `RequestAccepted` with JWT receipt + canonical SLA deadline
//! → status endpoint reports `Pending`. The audit chain contains
//! `request_received → request_accepted → receipt_issued → status_polled`
//! in canonical order.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests are allowed to use these primitives"
)]

use corelink_dsr::{DsrDecision, DsrEndpoint, DsrJurisdiction, DsrRequestKind, DsrStatus};
use e2e_dsr::{
    canonical_dsr_for, make_test_tenant, poll_dsr_status, setup_test_env, verify_audit_chain,
    ExpectedDsrAuditEvent,
};

#[test]
fn access_request_happy_path() {
    let env = setup_test_env();
    let tenant = make_test_tenant("acme-co");

    let request = canonical_dsr_for(
        &tenant,
        DsrRequestKind::Access,
        DsrJurisdiction::Gdpr,
        env.now_ms,
    );

    let decision = match env.dsr.submit(&request) {
        Ok(d) => d,
        Err(e) => panic!("dsr submit failed: {e:?}"),
    };

    match decision {
        DsrDecision::RequestAccepted {
            ref receipt,
            sla_deadline_ms,
        } => {
            // Receipt is a non-empty compact-form JWT.
            assert!(
                receipt.is_non_empty(),
                "expected non-empty JWT receipt token"
            );
            assert!(
                receipt.as_str().split('.').count() == 3,
                "expected canonical 3-segment compact JWT, got {} segments",
                receipt.as_str().split('.').count()
            );
            // SLA deadline = submitted + 30 days for GDPR.
            let expected = env.now_ms.saturating_add(30 * 86_400_000);
            assert_eq!(sla_deadline_ms, expected, "GDPR SLA mismatch");
        }
        other => panic!(
            "expected RequestAccepted; got decision variant {}",
            other.as_str()
        ),
    }

    // Status endpoint reports Pending.
    let status = poll_dsr_status(&env, &tenant, request.request_id);
    assert_eq!(status, Some(DsrStatus::Pending));

    // Audit chain: 1 received + 1 accepted + 1 receipt_issued + 1 status_polled.
    assert_eq!(env.dsr_store.len(), 1, "single ticket stored");
    assert_eq!(env.dsr_audit.len(), 4, "audit chain length");
    if let Err(msg) = verify_audit_chain(
        &env,
        &[
            ExpectedDsrAuditEvent::RequestReceived,
            ExpectedDsrAuditEvent::RequestAccepted,
            ExpectedDsrAuditEvent::ReceiptIssued,
            ExpectedDsrAuditEvent::StatusPolled,
        ],
    ) {
        panic!("audit chain ordering: {msg}");
    }

    // No MFA gate for the Access arm.
    assert_eq!(env.dsr_mfa.verified_count(), 0);
    assert_eq!(env.dsr_mfa.rejected_count(), 0);
}
