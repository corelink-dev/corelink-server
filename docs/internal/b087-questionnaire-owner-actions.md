# B-087 questionnaire reconciliation — owner packet

Engineering has reconciled the bounded procurement population in:

- `marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md`
- `marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md`

`scripts/verify_b087_questionnaires.py` is the semantic guard for the named rows.
It is intentionally compatible with B-156: B-156 remains the canonical inventory
of published `BYOK`, `Buck2`, and `pentest` mentions. This guard does not create a
second census; it checks only the procurement rows whose answer depends on the
shipped posture, with a closed population and mutation tests.

## Exact conflict map

| Surface | Engineering answer | Residue / owner action |
|---|---|---|
| BYOK rows (CAIQ CEK/BCR/DSP; SIG N/K) | The Dockerfile production build links no KMS provider: `CORELINK_BYOK_PROVIDER_FEATURE` is empty (#1648), and selecting `byok-aws-real` is a deliberate image change made together with KMS provisioning. The B-083 receipt has no protected test tenant, image digest, CMK access, activation, CAS/AC round-trip, revocation or p99 drill. Activation therefore returns `501 byok_not_available` on every request. | Legal must review the executed SLA's five-minute BYOK kill-switch promise. The residency amendment is a pending legal-review template, not an executed promise; reconcile it before any execution. This change amends neither instrument. |
| WORM / Object Lock (CAIQ LOG-03; SIG LOG-03) | R2 audit storage is tamper-evident, not proven immutable. The 2026-08-25 Object Lock probe returned `NotImplemented`; the latest 2026-09-09 probe was `INDETERMINATE` because credentials were rejected before capability testing. No WORM retention is evidenced in this deployment. | Legal must review the executed DPA's `immutable R2 with Object Lock` language. This change leaves the DPA untouched. |
| SAST, fuzz, and supply-chain rows | Answers now distinguish PR dependency gates, nightly CodeQL, dispatch-only Semgrep/fuzz, unsigned SBOM/provenance, checksums, and preserved signed-commit controls. | No owner action is implied by the wording; future capability claims require a new evidence review. |
| Synthetic paging (CAIQ SEF-03; SIG J.4) | Production has no synthetic cron; PagerDuty rotation is not repository-verifiable. | Operations should provide a PagerDuty schedule export before any 24×7 rotation claim is reused. |
| Superseded questionnaire copies | Current files are truthful and guarded. | Sales/Legal decide whether any prospect who received a superseded copy needs notification; no notification is claimed here. |

This packet records decisions still outside the engineering-closeable portion;
it is not evidence that an owner, customer, prospect, or regulator was contacted.

## Version and status crosswalk

This is a repository snapshot for the owner review. A versioned file proves
what text is present in this checkout; it does not prove that a customer
received it, accepted it, or was notified of a later change.

| Surface | Repository record | Status proved here | What remains external |
|---|---|---|---|
| DPA | [`legal/dpa/v1.0.0.en-US.md`](../../legal/dpa/v1.0.0.en-US.md) (`notice_version: 1.0.0`, effective `2026-05-14`) | Approved repository template; contains the historical Object Lock and BYOK language named above | Legal must reconcile any executed customer copy and record the disposition; no amendment is inferred |
| Customer DPA reference claim | [`docs/customer/dpa-onboarding.md`](../customer/dpa-onboarding.md) (version `1.1.0`, distribution `post-NDA enterprise customers`) | The FAQ says CoreLink “has executed its DPA with a lighthouse enterprise customer”; this page does not identify the executed copy or cite an execution receipt | Legal/owner must reconcile the statement against an authoritative executed-copy reference and confirm the wording for its stated distribution; this packet does not verify a customer, signature, execution, or receipt |
| SLA | [`legal/sla/v1.0.0.md`](../../legal/sla/v1.0.0.md) (`sla_version: 1.0.0`, effective `2026-05-14`) | Approved repository version; contains the historical Enterprise BYOK and credit language named above | Legal/Finance must decide treatment of executed instruments and record the disposition |
| Residency amendment | [`legal/dpa-residency-amendment.md`](../../legal/dpa-residency-amendment.md) (`version: 1.0.0`) | `PENDING_LEGAL_REVIEW`; not an effective amendment | Legal must approve, version, execute, and identify affected customers if applicable |
| Correction drafts | [`docs/internal/legal-drafts/2026-09-08-dpa-v1.0.1-draft.md`](legal-drafts/2026-09-08-dpa-v1.0.1-draft.md), [`docs/internal/legal-drafts/2026-09-08-sla-v1.0.1-draft.md`](legal-drafts/2026-09-08-sla-v1.0.1-draft.md) | `DRAFT — NOT EFFECTIVE`; `effective_date: null`; `supersedes: null` | Counsel/Finance approval, final identifier, effective date, signed artifact, and notice decision |
| Questionnaire copies | [`CAIQ-V4-pre-filled.md`](../../marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md) (`1.0.0`, `DRAFT`) and [`SIG-LITE-2026-pre-filled.md`](../../marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md) (`1.1.0`, `DRAFT`) | Current bounded answer banks; both front matters say `supersedes: null` and `superseded_by: null`. These source versions do not establish which copies circulated or whether either superseded a sent copy. | Sales/Legal must identify the recipient population and source versions from CRM/mail records and decide whether notice is required |
| Response-pack scaffolding | [`VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md`](../../marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md) (`1.1.0`, `DRAFT`) and [`EVIDENCE-PACK-INDEX.md`](../../marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md) (`1.1.0`, `DRAFT`) | Reusable scaffolding; both front matters say `supersedes: null` and `superseded_by: null` | Sales/Legal must map any sent copy to a recipient and source version; repository presence is not delivery evidence |
| Public legal claims | [`docs/internal/2026-08-24-published-claims-audit.md`](../../docs/internal/2026-08-24-published-claims-audit.md) and public Trust Center sources such as [`compliance.mdx`](../../apps/docs/docs/trust/compliance.mdx) | Audit records unresolved public DPA/BYOK/Object Lock and operational claims; public pages do not provide customer receipt data | Legal/owner must decide the effective wording and any customer notice; no public-page text is treated as approval or receipt |

No recipient or supersession ledger is present in this repository. The absence
of that ledger is a blocker to claiming that a prior copy was superseded for a
particular recipient, or that any notification was sent or received.

The customer DPA reference claim above is a repository statement requiring
Legal/owner reconciliation; it is not an executed instrument or evidence of a
customer identity, signature, or receipt. The recipient population for any
questionnaire copies remains external to this repository.

## Evidence handoff locations

Owners must attach the three independent records below without placing secrets,
contract bytes, or recipient PII in this repository:

- `reports/owner-actions/b170-legal-contract-review.md` — Legal's disposition
  of the executed DPA/SLA claims and the pending residency template before execution.
- `reports/owner-actions/b170-pagerduty-export.json` — Operations' redacted
  schedule/rotation export, including export time and account/workspace.
- `reports/owner-actions/b170-recipient-notification-decision.md` — Sales/Legal
  decision and, if applicable, redacted notification evidence for superseded
  copies.

Each record must include the decision owner, decision timestamp, exact source
version(s), and a redacted receipt or authority reference where an external act
is claimed. A decision record may explicitly say “no action required”; it must
not say approved, sent, delivered, or received without that supporting receipt.

Unsigned working templates are available under
`docs/internal/b170-owner-artifact-templates/` for the Legal disposition, PagerDuty
export receipt, and Sales/Legal notification decision. They are scaffolding only;
they are not the three canonical records and do not alter the open state.

The B-170 guard treats missing records as `open` and turns red when all three
appear, forcing content review before the backlog item can be closed.

## Proposed follow-up item (ID allocated by the canonical backlog owner)

Use the next dense backlog identifier; do not allocate one in this change:

```backlog-proposal
id: B-<next-dense-id>
repo: corelink-server
owner: owner
status: open
title: reconcile executed legal claims and external questionnaire recipients
scope: review the executed DPA Object Lock and SLA BYOK five-minute promises, reconcile the pending residency template before execution, obtain the PagerDuty rotation export, and decide whether recipients of superseded questionnaire copies require notice
evidence: owner/legal decision record; owner/ops PagerDuty export; owner/sales notification decision
non-claim: no contract amendment, export, notification, or customer/regulator contact is asserted until its owner records evidence
verify: manual — owner evidence is external to this repository
```
