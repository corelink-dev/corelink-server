---
document_type: "sub_processor_commitments"
version: "1.1.0"
# v1.1.0 takes effect when it is published; no separate effective date is
# recorded, so none is stated. v1.0.0 was effective 2026-05-14.
effective_date: null
previous_version: "1.0.0"
previous_effective_date: "2026-05-14"
legal_basis: "GDPR Art. 28(2); LGPD Art. 39 (operador)"
wi_origin: "WI-S20-005"
recharter: "B-316 owner re-charter, 2026-10-01 (#2593)"
canonical_compliance_matrix: "specs/03_architecture/compliance_matrix.md"
related_documents:
  - "legal/sub-processors.md"
  - "legal/dpa/v1.0.0.en-US.md"
  - "legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md"
---

# CoreLink Sub-Processor Commitments

> Version 1.1.0 · takes effect on publication (no separate effective date is
> recorded) · v1.0.0 was effective 2026-05-14 · Origin WI-S20-005 · Canonical
> reference `specs/03_architecture/compliance_matrix.md`.

This document is the authoritative list of CoreLink sub-processors that
receive personal data, with the data-protection commitments flowed down
from CoreLink's DPA (`legal/dpa/v1.0.0.*.md`) and the EU SCCs Module 3
(`legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md`). The operational registry
(YAML, versioned by `legal/sub-processors.md`) is the system of record for
discovery and notification; this document is the legal commitment view.

Customer notification of any addition, replacement, or scope expansion is
provided at least **30 calendar days** in advance per DPA §3.1.

**Contract basis (owner re-charter, 2026-10-01).** CoreLink is a single-owner
company with no separate legal department. Each sub-processor below is engaged
on that vendor's own standard online terms and data processing agreement,
linked in its section, which the owner accepted online when the account was
created. There is no countersigned copy and no separate named Legal/Privacy
reviewer; the owner is the reviewer. The online acceptance dates were not
recorded, so none are stated. Version 1.0.0 showed `2026-04-23` as the
contract date for Cloudflare, Clerk and Stripe; no acceptance record supports
that value, so it is not carried forward.

---

## 1. Active sub-processors (approved launch set)

### 1.1 Cloudflare, Inc.

| Field | Value |
|---|---|
| Role | Infrastructure provider — Workers, R2, D1, KV, Durable Objects, Pages, Email Routing. |
| Data categories | Account metadata; blob content (encrypted); audit logs; telemetry. |
| Region | R2 objects and jurisdictional Durable Object state are tenant-pinned per `INV-DATA-RESIDENCY` (WNAM / ENAM / WEUR / APAC). The D1 control plane is one shared global database; its primary is currently reported in ENAM with no D1 jurisdiction and automatic read replication. `SAM` is not provisioned and is not promised. |
| Terms reference | <https://www.cloudflare.com/terms/> |
| DPA reference | <https://www.cloudflare.com/cloudflare-customer-dpa/> |
| SCCs / transfer mechanism | The repository disclosure describes the shared D1 control plane under SCC/TIA safeguards. This prelaunch record does not establish an executed transfer mechanism or counsel approval. |
| Schrems II TIA | None recorded; this record does not represent one as completed or approved. |
| Vendor review evidence | `docs/compliance/vendor-reviews/cloudflare-dpa-review-2026-04.md` |
| Contract basis | Cloudflare's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.2 Clerk, Inc.

| Field | Value |
|---|---|
| Role | Authentication, identity provider, JWT issuer. |
| Data categories | Account personal data (email, name, credentials, session tokens). |
| Region | Multi-region (tenant-pinned per `tenant.primary_region`). |
| Terms reference | <https://clerk.com/legal/standard-terms> |
| DPA reference | <https://clerk.com/legal/dpa> |
| SCCs / transfer mechanism | As set out in Clerk's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/clerk-dpa-review-2026-04.md` |
| Contract basis | Clerk's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.3 Resend, Inc.

| Field | Value |
|---|---|
| Role | Transactional email and newsletter-audience delivery. |
| Data categories | Recipient email address; message content and delivery metadata. |
| Region | United States. |
| Terms reference | <https://resend.com/legal/terms-of-service> |
| DPA reference | <https://resend.com/legal/dpa> |
| SCCs / transfer mechanism | As set out in Resend's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/resend-dpa-review-2026-09.md` |
| Contract basis | Resend's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.4 Stripe, Inc.

| Field | Value |
|---|---|
| Role | Payment processing and subscription billing. |
| Data categories | Billing data; payment information (payment method tokens; card data never touches CoreLink). |
| Region | US and EU. |
| Terms reference | <https://stripe.com/legal/ssa> |
| DPA reference | <https://stripe.com/legal/dpa> |
| SCCs / transfer mechanism | As set out in Stripe's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/stripe-dpa-review-2026-04.md` |
| Contract basis | Stripe's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.5 GitHub, Inc.

| Field | Value |
|---|---|
| Role | Source code repository and CI/CD pipeline. |
| Data categories | Source code; CI artifacts. |
| Region | United States. |
| Terms reference | <https://docs.github.com/en/site-policy/github-terms/github-terms-of-service> |
| DPA reference | <https://github.com/customer-terms/github-data-protection-agreement> |
| SCCs / transfer mechanism | As set out in GitHub's Data Protection Agreement. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/github-dpa-review-2026-04.md` |
| Contract basis | GitHub's standard online terms and Data Protection Agreement, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.6 Functional Software, Inc. (Sentry)

| Field | Value |
|---|---|
| Role | Application error monitoring (admin-ui server/edge/client and the docs-site build loader). |
| Data categories | Scrubbed diagnostic telemetry (exception and breadcrumb events). |
| Region | United States. |
| Terms reference | <https://sentry.io/terms/> |
| DPA reference | <https://sentry.io/legal/dpa/> |
| SCCs / transfer mechanism | As set out in Sentry's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/sentry-dpa-review-2026-09.md` |
| Contract basis | Sentry's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.7 Plausible Insights OÜ (Plausible Analytics)

| Field | Value |
|---|---|
| Role | Cookieless web analytics for the docs-site marketing funnel. |
| Data categories | Visitor pageview telemetry. |
| Region | European Union. |
| Terms reference | <https://plausible.io/terms> |
| DPA reference | <https://plausible.io/dpa> |
| SCCs / transfer mechanism | As set out in Plausible's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/plausible-dpa-review-2026-09.md` |
| Contract basis | Plausible's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

### 1.8 Better Stack, Inc. (BetterStack / Statuspage)

| Field | Value |
|---|---|
| Role | Uptime/status monitoring — synthetic HTTP-health probes against CoreLink's own public endpoints, and public status page hosting. |
| Data categories | Synthetic probe telemetry; no customer personal data is sent. |
| Region | European Union. |
| Terms reference | <https://betterstack.com/terms> |
| DPA reference | <https://betterstack.com/dpa> |
| SCCs / transfer mechanism | As set out in Better Stack's DPA. |
| Schrems II TIA | None recorded; CoreLink has not recorded a separate transfer impact assessment for this vendor. |
| Vendor review evidence | `docs/compliance/vendor-reviews/betterstack-dpa-review-2026-09.md` |
| Contract basis | Better Stack's standard online terms and DPA, accepted online at account signup. No countersigned copy. |
| Online acceptance date | Not recorded. |

---

## 2. Flow-down obligations

Each sub-processor is contractually bound to materially equivalent
protections to those Processor owes Controller under the DPA, including:

1. **Documented instructions** only (GDPR Art. 28(3)(a); LGPD Art. 39).
2. **Confidentiality** of authorised personnel (GDPR Art. 28(3)(b)).
3. **Security measures** appropriate to risk (GDPR Art. 32; LGPD Art. 46).
4. **No engagement of further sub-processors** without advance written
   notice and a right to object.
5. **Assistance with data-subject rights** (GDPR Arts. 12–22; LGPD Art. 18).
6. **Personal-data breach notification** without undue delay so Processor
   can meet the 72-hour Controller-notification SLA.
7. **Return or deletion** of personal data on termination.
8. **Audit rights** (documentary by default; on-site as required by law).
9. **International transfers** governed by EU SCCs Module 3 (or local
   equivalents) and EDPB Recommendations 01/2020 supplementary measures.

These obligations are those in each vendor's own standard DPA, linked in §1.
CoreLink has no separate Legal Counsel; the owner reviews the vendor terms at
onboarding and records the contract basis in
`docs/compliance/vendor-reviews/*.md`.

---

## 3. Schrems II supplementary measures (applied across sub-processors)

1. **Technical.** Encryption in transit uses TLS 1.2 as the minimum; TLS 1.3 is
   negotiated where supported. Data at rest is encrypted by the storage
   provider; R2 objects and Durable Object state are tenant-pinned. BYOK,
   per-tenant key separation and cryptographic erasure are designs that are
   not enabled today and are not relied on here.
2. **Organisational.** The owner reviews each vendor's published terms, DPA and
   security documentation at onboarding and when the vendor announces a
   change. No continuous vendor-monitoring tool, transparency report or
   warrant canary is in place.
3. **Contractual.** The transfer terms (including SCCs where they apply) and
   the flow-down audit, breach-notification and DSR-cooperation clauses are
   those incorporated in each vendor's own DPA, linked in §1; this file and
   `legal/sub-processors.md` record which vendors they cover.

---

## 4. Process changes and updates

| Action | Notice period | Where tracked |
|---|---|---|
| Add new sub-processor | 30 days written notice | `legal/sub-processors.md` + this document update + customer notification |
| Replace existing sub-processor | 30 days written notice | same |
| Scope expansion (new data categories) | 30 days written notice | same |
| Termination of sub-processor relationship | post-event notification within 30 days | same |

Changes to this document are reviewed by the owner in a pull request. The
`.github/workflows/legal-changes-review.yml` workflow that used to gate them is
currently disabled; `scripts/verify_b316_pending_vendor_reviews.py` checks that
this document agrees with every published sub-processor list.

---

## 5. Compliance mapping

| Framework | This document section |
|---|---|
| GDPR Art. 28(2) (sub-processor engagement) | §§1, 2, 4 |
| GDPR Art. 28(4) (flow-down) | §2 |
| GDPR Art. 32 (TOMs) | §3 |
| GDPR Art. 46 + EDPB 01/2020 | §3 |
| LGPD Art. 39 (operador) | §§1, 2 |
| EU SCCs Module 3 | §§1, 2, 3 |
| SOC 2 CC9.2 (vendor management) | §§1, 4 |

Canonical control IDs catalogued in
`specs/03_architecture/compliance_matrix.md`.

---

*End of sub-processor commitments v1.1.0.*
