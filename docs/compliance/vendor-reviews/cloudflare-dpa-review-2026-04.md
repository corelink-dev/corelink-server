# Vendor Legal-Review Record — Cloudflare, Inc.

> STATUS: TEMPLATE — formal Legal review pending; dated public-source assessment below is not a completed review.

| Field | Value |
|---|---|
| Vendor | Cloudflare, Inc. |
| Sub-processor id | `cloudflare` |
| Review date | `TBD (formal Legal review not completed)` |
| Public-source assessment date | 2026-09-22 (does not replace the formal review) |
| Reviewer | `TBD (named Legal Counsel / Privacy Officer)`; no formal reviewer or decision is recorded. |
| Terms reference | <https://www.cloudflare.com/terms/> |
| DPA reference | <https://www.cloudflare.com/cloudflare-customer-dpa/> |
| DPA status | Re-chartered by the owner (#2593): the vendor's standard online terms and DPA, accepted at account signup; no countersigned copy and no recorded acceptance date. The repository disclosure's earlier contract-date value had no supporting record and has been removed. |
| SCC / transfer mechanism | Repository disclosure states EU SCC Module 3 and UK IDTA; the applicable executed terms were not rechecked. |
| Schrems II TIA | Evidence insufficient — repository disclosure states a TIA is completed, but the dated TIA record is not in this packet. |
| Data categories processed | account_metadata; blob_content; audit_logs; telemetry |
| Data residency / region | R2/DO tenant-pinned per tenant.primary_region; D1 control-plane metadata global under SCC/TIA safeguards |
| Sub-processor flow-down | Evidence insufficient — public DPA describes subprocessor obligations; executed flow-down evidence and CoreLink change disposition were not checked. |
| Certifications verified | Not verified for CoreLink — register lists SOC 2 Type II, ISO 27001, ISO 27018, PCI-DSS L1, and HIPAA-compliant infrastructure; current applicable reports were not retrieved. |
| Review outcome | `TBD (formal Legal outcome pending)`; public-source assessment: **Evidence insufficient — not approved**. |
| Human decision | Pending formal human review; no approval decision is recorded. |
| Signer | `TBD (named human signer pending)`; no signature is recorded. |
| Conditions / follow-ups | VP-Sec and Legal/Privacy must obtain current customer/account evidence, complete the refresh fields, decide, and record the named reviewer and signer. |
| Next review due | `2026-08-15` (formal due date; overdue 38 calendar days at assessment capture; not reset). |

## Public-source assessment (2026-09-22)

**Public statements observed.** Cloudflare publishes DPA v6.4, effective 2026-04-03. It says customer acceptance/signature or another agreement date sets the DPA effective date. The DPA says subprocessor additions/replacements are listed at least 30 days before processing. Customer audit evidence is provided through a report no older than 13 months.

| Refresh item | Current public evidence and remaining gap |
|---|---|
| Scope | Public sources describe Cloudflare platform services. The current CoreLink account service inventory and in-scope feature set have not been reconciled. |
| Subprocessors | The DPA links a public list and describes advance notice. No dated CoreLink-applicable snapshot or comparison since the last review was captured. |
| Residency | The repository disclosure states tenant-pinned R2/DO and globally located D1 metadata under SCC/TIA safeguards. Account configuration and the underlying transfer assessment were not independently reviewed. |
| Security changes / current assurance | Public security/compliance material exists; the current customer-specific report, coverage period, service applicability, and exceptions remain unverified. |
| DPA changes | Public DPA version 6.4 is effective 2026-04-03. Whether it changed terms applicable to CoreLink cannot be determined without the executed prior and current copies. |
| Renewal date | CoreLink order form, renewal date, and notice window remain unverified. |
| Human decision / signer | No human approval or signature is recorded. Evidence is insufficient; the outcome remains not approved and pending Legal review. |

### Official vendor sources consulted on 2026-09-22

- [Cloudflare Customer Data Processing Addendum, v6.4 effective 2026-04-03](https://www.cloudflare.com/cloudflare-customer-dpa/)
- [Cloudflare subprocessor list referenced by the DPA](https://www.cloudflare.com/gdpr/subprocessors/)
- [Cloudflare compliance documentation access](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/compliance-docs/)

## Formal review cadence

The source register records the last formal review as **2026-05-15** and the formal next-review due date as **2026-08-15**. On the assessment capture date, 2026-09-22, the recorded due date is **38 calendar days overdue**. This public-source assessment does not satisfy the formal review, alter its due date, or start a new cadence. The register’s quarterly cadence, 90-day threshold, and explicit scheduled date are left as recorded; no replacement due date is inferred.

Public vendor material does not establish CoreLink’s executed terms, account settings, customer-restricted reports, applicable subprocessor snapshot, current data flow, completed transfer assessment, renewal terms, human disposition, or Drata workspace export. Any assertions in repository registers or commitments remain repository-recorded assertions until the underlying dated evidence is examined by the accountable reviewers.

*This file remains a template and is not a signed legal review. Referenced by `legal/sub-processors.md` and/or `legal/dpa/SUB-PROCESSOR-COMMITMENTS.md`; existence is enforced by `scripts/validate_sub_processors.py`.*
