---
id: "ISSUE-2161-STAGING-TEARDOWN-ATTRIBUTION"
type: "architecture"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-09-25"
updated: "2026-10-01"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
tags: ["architecture", "staging", "load-test", "teardown", "issue-2161"]
---

# Issue 2161: staging teardown attribution contract

`0147_staging_load_test_run_ownership.sql` is the frozen server-side
prerequisite for `POST /_internal/load-test/teardown`. It deliberately does
not mount that route or claim a runtime deletion receipt.

The exact identity is `(run_id, scenario)`: a canonical positive numeric
GitHub run ID, one of `signup`, `webhook`, `dsr`, `cas`, `byok`,
`endurance-2h`, or `b103-cargo-write`, and a lowercase 40-hex deployment SHA. The ledger accepts
only `target_environment = 'staging'`.

The resource classes are closed until this contract is amended and reviewed:

| Ledger class | Current persistent surface | Receipt treatment |
| --- | --- | --- |
| `cas_reference` | `blob_meta` and the corresponding R2 CAS object | Delete only a run-owned reference; retain the physical object while shared. |
| `webhook_inbox` | `stripe_webhook_events_processed`, `stripe_webhook_event_inbox` | Disposable only with a fresh run-unique synthetic event ID. |
| `webhook_effect` | `stripe_webhook_event_effects` and effects keyed by that event | Disposable only with the same exact ledger identity. |
| `billing_audit` | `stripe_billing_audit_events` | Retained and counted. |
| `dsr_artifact` | synthetic DSR ticket/job artifacts | Classify per adapter before registration; no inferred deletion. |
| `dsr_obligation` | `dsr_requested`, `dsr_erasure_log` | Retained and counted. |
| `audit_evidence` | `audit_outbox`, sealed audit ledger/head/archive evidence | Retained and counted. |
| `signup_artifact` | signup orchestration durable rows | Classify per adapter before registration. |
| `byok_artifact` | BYOK control-plane durable rows | Classify per adapter before registration. |

Each persistent write must register a nonsecret opaque handle and a
receipt-only SHA-256 reference in the same durable unit as the write (or use
a durable intent plus reconciliation when R2 prevents one transaction).
`cas_reference` records a run-owned reference, never ownership of a shared
CAS object. The CAS adapter removes the physical object only after its shared
reference count reaches zero.

Before a future teardown starts, every applicable resource class must have a
complete, bounded scan whose observed count equals the registered ledger rows.
An incomplete scan, unknown class, duplicate opaque handle, missing row, or
count mismatch fails closed. `dsr_obligation`, `audit_evidence`, and
`billing_audit` are retained-only and must transition to `preserved`; they are
included in the redacted receipt and never deletion candidates.

The only disposable state path is `registered → delete_started → deleted`
(or `quarantined`); retrying a terminal state is idempotent. A run follows
`open → sealed → teardown_started → reconciled` (or `failed`). The endpoint
must authenticate a staging-only principal and exact allowlisted identity,
then bind its redacted receipt to the sealed deployment SHA, scans, preserved
and deleted counts, and post-delete readback. It must not issue a receipt on
any failure.
