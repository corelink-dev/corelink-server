# Vendor Legal-Review Record — Stripe, Inc.

> STATUS: TEMPLATE — formal Legal review pending; dated public-source assessment below is not a completed review.

| Field | Value |
|---|---|
| Vendor | Stripe, Inc. |
| Sub-processor id | `stripe` |
| Review date | `TBD (formal Legal review not completed)` |
| Public-source assessment date | 2026-09-22 (does not replace the formal review) |
| Reviewer | `TBD (named Legal Counsel / Privacy Officer)`; no formal reviewer or decision is recorded. |
| Terms reference | <https://stripe.com/legal/ssa> |
| DPA reference | <https://stripe.com/legal/dpa> |
| DPA status | Re-chartered by the owner (#2593): the vendor's standard online terms and DPA, accepted at account signup; no countersigned copy and no recorded acceptance date. The repository disclosure's earlier contract-date value had no supporting record and has been removed. |
| SCC / transfer mechanism | Repository disclosure states EU SCC Module 3 and UK IDTA; account entity and applicable executed terms were not rechecked. |
| Schrems II TIA | Evidence insufficient — repository disclosure states a TIA is completed, but the dated assessment is not in this packet. |
| Data categories processed | billing_data; payment_information |
| Data residency / region | US and EU |
| Sub-processor flow-down | Evidence insufficient — DPA describes subprocessor obligations; no account-applicable roster snapshot or change disposition was captured. |
| Certifications verified | Not verified for CoreLink — register lists PCI-DSS L1, SOC 2 Type II, ISO 27001; current account-relevant reports and scope were not retrieved. |
| Review outcome | `TBD (formal Legal outcome pending)`; public-source assessment: **Evidence insufficient — not approved**. |
| Human decision | Pending formal human review; no approval decision is recorded. |
| Signer | `TBD (named human signer pending)`; no signature is recorded. |
| Conditions / follow-ups | VP-Sec and Legal/Privacy must obtain current customer/account evidence, complete the refresh fields, decide, and record the named reviewer and signer. |
| Next review due | `2026-08-15` (formal due date; overdue 38 calendar days at assessment capture; not reset). |

## Public-source assessment (2026-09-22)

**Public statements observed.** Stripe’s DPA page says the DPA is part of its Services Agreement and lists 2025-11-18 as its last update. It distinguishes processing roles, links a dynamic service-provider/subprocessor list, and says a subscribed customer can receive notice of list changes.

| Refresh item | Current public evidence and remaining gap |
|---|---|
| Scope | Public terms describe Stripe processing generally. CoreLink account region, enabled products, actual payment fields, and processor/controller roles have not been reconciled to the account. |
| Subprocessors | The DPA links a dynamic list. No dated CoreLink-applicable roster or history/change notice comparison was captured. |
| Residency | The DPA describes global processing/transfers. The CoreLink account entity, actual processing locations, and transfer assessment remain unverified. |
| Security changes / current assurance | The DPA describes security measures and annual SOC reporting; no current customer report, period, account/service scope, or exceptions were retrieved. |
| DPA changes | The public DPA is marked last updated 2025-11-18. Without the agreement/version in force for CoreLink and its prior version, applicable changes cannot be determined. |
| Renewal date | CoreLink Services Agreement, account region, renewal date, and notice window remain unverified. |
| Human decision / signer | No human approval or signature is recorded. Evidence is insufficient; the outcome remains not approved and pending Legal review. |

### Official vendor sources consulted on 2026-09-22

- [Stripe Data Processing Agreement, last updated 2025-11-18](https://stripe.com/legal/dpa)
- [Stripe Service Providers, Sub-processors & Affiliates](https://stripe.com/legal/service-providers)
- [Stripe DPA FAQ](https://stripe.com/legal/dpa/faqs)

## Formal review cadence

The source register records the last formal review as **2026-05-15** and the formal next-review due date as **2026-08-15**. On the assessment capture date, 2026-09-22, the recorded due date is **38 calendar days overdue**. This public-source assessment does not satisfy the formal review, alter its due date, or start a new cadence. The register’s quarterly cadence, 90-day threshold, and explicit scheduled date are left as recorded; no replacement due date is inferred.

Public vendor material does not establish CoreLink’s executed terms, account settings, customer-restricted reports, applicable subprocessor snapshot, current data flow, completed transfer assessment, renewal terms, human disposition, or Drata workspace export. Any assertions in repository registers or commitments remain repository-recorded assertions until the underlying dated evidence is examined by the accountable reviewers.

*This file remains a template and is not a signed legal review. Referenced by `legal/sub-processors.md` and/or `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`; existence is enforced by `scripts/validate_sub_processors.py`.*
