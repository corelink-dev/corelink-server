# Vendor Legal-Review Record — Clerk, Inc.

> STATUS: TEMPLATE — formal Legal review pending; dated public-source assessment below is not a completed review.

| Field | Value |
|---|---|
| Vendor | Clerk, Inc. |
| Sub-processor id | `clerk` |
| Review date | `TBD (formal Legal review not completed)` |
| Public-source assessment date | 2026-09-22 (does not replace the formal review) |
| Reviewer | `TBD (named Legal Counsel / Privacy Officer)`; no formal reviewer or decision is recorded. |
| Terms reference | <https://clerk.com/legal/standard-terms> |
| DPA reference | <https://clerk.com/legal/dpa> |
| DPA status | Re-chartered by the owner (#2593): the vendor's standard online terms and DPA, accepted at account signup; no countersigned copy and no recorded acceptance date. The repository disclosure's earlier contract-date value had no supporting record and has been removed. |
| SCC / transfer mechanism | Repository disclosure states EU SCC Module 3 and UK IDTA; the applicable executed terms were not rechecked. |
| Schrems II TIA | Evidence insufficient — repository disclosure states a TIA is completed, but the dated assessment is not in this packet. |
| Data categories processed | account_pii |
| Data residency / region | Multi-region (tenant-pinned per tenant.primary_region) |
| Sub-processor flow-down | Evidence insufficient — DPA describes subprocessor obligations; no CoreLink-applicable roster or flow-down evidence was checked. |
| Certifications verified | Not verified for CoreLink — register lists SOC 2 Type II; the current report, period, service scope, and exceptions were not retrieved. |
| Review outcome | `TBD (formal Legal outcome pending)`; public-source assessment: **Evidence insufficient — not approved**. |
| Human decision | Pending formal human review; no approval decision is recorded. |
| Signer | `TBD (named human signer pending)`; no signature is recorded. |
| Conditions / follow-ups | VP-Sec and Legal/Privacy must obtain current customer/account evidence, complete the refresh fields, decide, and record the named reviewer and signer. |
| Next review due | `2026-08-15` (formal due date; overdue 38 calendar days at assessment capture; not reset). |

## Public-source assessment (2026-09-22)

**Public statements observed.** Clerk publishes a DPA and subprocessor directory. The DPA says the customer authorizes current listed subprocessors as of the DPA effective date, and Clerk provides 15 days’ notice of proposed changes. It allows storage/processing where Clerk or its subprocessors maintain facilities, subject to the DPA.

| Refresh item | Current public evidence and remaining gap |
|---|---|
| Scope | Public terms describe Clerk generally. CoreLink-enabled features, fields, retention settings, and account data flows have not been reconciled. |
| Subprocessors | The DPA links Clerk’s list and describes advance notice. A dated list as of CoreLink’s effective date and later change disposition were not captured. |
| Residency | The repository disclosure states multi-region tenant-pinned processing. Actual tenant configuration, replica placement, and transfer assessment were not verified. |
| Security changes / current assurance | The DPA describes security measures and refers to current independent reports under conditions; no current CoreLink-accessible report, period, scope, or exceptions were reviewed. |
| DPA changes | No comparison against the executed CoreLink DPA version was possible; the public DPA page does not verify CoreLink’s effective version. |
| Renewal date | CoreLink order form, renewal date, and notice window remain unverified. |
| Human decision / signer | No human approval or signature is recorded. Evidence is insufficient; the outcome remains not approved and pending Legal review. |

### Official vendor sources consulted on 2026-09-22

- [Clerk Data Processing Agreement](https://clerk.com/legal/dpa)
- [Clerk Subprocessors](https://clerk.com/legal/subprocessors)
- [Clerk legal resources](https://clerk.com/legal)

## Formal review cadence

The source register records the last formal review as **2026-05-15** and the formal next-review due date as **2026-08-15**. On the assessment capture date, 2026-09-22, the recorded due date is **38 calendar days overdue**. This public-source assessment does not satisfy the formal review, alter its due date, or start a new cadence. The register’s quarterly cadence, 90-day threshold, and explicit scheduled date are left as recorded; no replacement due date is inferred.

Public vendor material does not establish CoreLink’s executed terms, account settings, customer-restricted reports, applicable subprocessor snapshot, current data flow, completed transfer assessment, renewal terms, human disposition, or Drata workspace export. Any assertions in repository registers or commitments remain repository-recorded assertions until the underlying dated evidence is examined by the accountable reviewers.

*This file remains a template and is not a signed legal review. Referenced by `legal/sub-processors.md` and/or `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`; existence is enforced by `scripts/validate_sub_processors.py`.*
