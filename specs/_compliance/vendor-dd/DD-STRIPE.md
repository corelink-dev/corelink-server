---
id: "DD-STRIPE-2026-05-15"
type: "vendor_due_diligence"
doc_status: "ACTIVE"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
sprint: "R5-3"
parent_wi: "WI-R5-3-GAP-14-VENDOR-RISK"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
inherits_from: ["VENDOR-RISK-REGISTER-2026-05-15", "VENDOR-RISK-METHODOLOGY-2026-05-15"]
tags: ["soc2", "cc9.2", "vendor-dd", "critical", "stripe", "pci-dss", "gap-14"]
---

# Vendor DD — Stripe, Inc.

> **doc_status:** ACTIVE · Register row: 2 · Category: **Critical** · Residual risk: **4.0** (Inherent 16 × CEF 0.25).
>
> Stripe is the sole payment-processing pathway and the LLC formation counsel (Stripe Atlas). Stripe outage = billing freeze.

---

## 1. Vendor profile

| Field | Value |
|---|---|
| Legal entity | Stripe, Inc. (Delaware) + Stripe Payments Europe, Ltd. (Ireland, for EEA acquiring) |
| HQ | 354 Oyster Point Blvd, South San Francisco, CA 94080, USA |
| Public ticker | Private (late-stage) |
| Atlas relationship | HuGR Labs, Inc. formation via Stripe Atlas (`legal/incorporation-package.md`) |
| Contract effective | Not recorded — standard online terms and DPA accepted at account signup (owner statement, #2593 re-charter); no acceptance record is held |
| Account ID | (Atlas application; live + test keys per `secrets-checklist.md` rows 1-3) |
| Primary contact | Stripe Atlas success team + dedicated success manager (recorded in `legal/vendor-contacts.md`) |

## 2. Service scope

- Payment processing (cards: Visa, Mastercard, AmEx, Discover; SEPA; iDEAL; Pix planned via Stripe Brazil)
- Subscription billing (Stripe Billing) — all 5 canonical plans (free / solo / team / business / enterprise)
- Webhook event delivery → `apps/server` Stripe webhook handler
- Tax computation (Stripe Tax — VAT, GST, US sales tax)
- Stripe Atlas legal templates (MSA, ToS, Privacy Policy starting points)

## 3. Data sharing

| Data category | Direction | Encryption at rest | Encryption in transit | Key holder |
|---|---|---|---|---|
| Payment card primary account number (PAN) | Customer browser → Stripe (CoreLink **never touches PAN**; tokenized via Stripe.js / Elements) | Stripe (PCI-DSS L1) | TLS 1.3 | Stripe |
| Customer billing address / email | CoreLink → Stripe Customer object | Stripe-managed | TLS 1.3 | Stripe |
| Subscription metadata + invoice line items | CoreLink ↔ Stripe Billing | Stripe-managed | TLS 1.3 | Stripe |
| Webhook signing secret | Stripe → CoreLink (one-time at endpoint creation) | `cf-wrangler` secret store | TLS 1.3 | CoreLink |
| Tax jurisdiction inferred from IP | (Stripe-side computation only) | Stripe-managed | TLS 1.3 | Stripe |

**Cardholder data scope:** CoreLink is **PCI-DSS SAQ A** eligible because PAN never traverses CoreLink infrastructure (Stripe.js redirects + Elements iframe pattern). This is the principal control that keeps CoreLink out of full PCI scope.

## 4. Regulatory and attestation scope

| Framework | Status | Evidence path |
|---|---|---|
| PCI-DSS Level 1 | Attested (Service Provider) | Stripe Trust Center + AoC available on request |
| SOC 2 Type II | Attested | Drata vendor module pulls report annually |
| ISO 27001 | Certified | Stripe Trust Center |
| GDPR | Processor; SCCs Module 2 | https://stripe.com/legal/dpa |
| LGPD | Processor; Brazilian acquiring via Stripe Brazil | DPA |
| State money-transmission licensing | Held in all required US states | Stripe Atlas materials |

## 5. Contractual posture

| Document | Signed | Notes |
|---|---|---|
| Stripe Services Agreement (SSA) | Not recorded (accepted online) | https://stripe.com/legal/ssa |
| DPA | Not recorded (accepted online with the terms) | https://stripe.com/legal/dpa |
| Stripe Connected Account Agreement | N/A (CoreLink is direct merchant; not Connect platform yet) | — |
| BAA | Not signed | No PHI in scope |

## 6. Control mapping

| CoreLink CTRL | Dependency on Stripe |
|---|---|
| CTRL-BILLING-001..006 | All billing-ledger sources of truth come from Stripe webhooks |
| CTRL-AUDIT-003 | Webhook DLQ + replay log invariant (`INV-WEBHOOK-DLQ-IDEMPOTENT-001`) |
| CTRL-PRIV-018 | Customer billing data deletion via Stripe Customer object purge on DSR-erasure |
| CTRL-COMPL-002 | Stripe Atlas counsel provides MSA/ToS templates for customer-facing legal |

## 7. Risk assessment narrative

**Inherent risk (16 = 4 × 4):** Impact 4 (billing freeze + cash-flow stop, but customer data plane unaffected); Likelihood 4 (Stripe has had material public incidents — most recently 2023 Stripe Billing API degradation; still mature but non-zero).

**Residual risk (4.0):** CEF 0.25 — strong attestation portfolio (PCI-DSS L1 + SOC 2 Type II + ISO 27001), CoreLink keeps PAN out of scope (PCI SAQ A), webhook idempotency invariant + 24h DLQ replay buffer compensates for short outages. CEF stops at 0.25 (not 0.10) because **there is no realistic second payment processor failover** — Stripe is single-vendor by design and a switch would be a quarter-long project.

**Top risks monitored:**

1. Stripe API outage > 24h → billing automation backlog exceeds DLQ window. Mitigation: manual invoicing path documented in `legal/billing-fallback-playbook.md`.
2. Webhook signing secret rotation breakage. Mitigation: dual-secret transition window per `RB-WEBHOOK-DLQ-REPLAY.md`.
3. Stripe Atlas legal template drift vs CoreLink's commercial terms. Mitigation: annual legal review against template diffs.
4. Regulatory blocking of Stripe in a specific jurisdiction (e.g., Brazil licensing change). Mitigation: Pix-direct integration plan as fallback for BR (S22 roadmap).

## 8. Escalation contacts

| Role | Contact | SLA |
|---|---|---|
| Stripe support — P1 | Stripe Dashboard support → "Live mode urgent" + email support+priority@stripe.com | 1h business hours; 4h off-hours |
| Atlas success | atlas@stripe.com | 1 business day |
| Security / abuse | security@stripe.com | 24h |
| Compliance / DPA | privacy@stripe.com | 5 business days |
| Breach notification | privacy@stripe.com + legal@stripe.com → notify security@hugr.dev | Per DPA |

## 9. Termination / exit plan

If Stripe terminates CoreLink or exits the market:

1. **Day 0..3:** snapshot all Stripe Customer + Subscription + Invoice objects via Stripe API export (`stripe-cli` bulk export).
2. **Day 3..30:** stand up alternate processor (candidate: Adyen for enterprise tier + Mercado Pago for LATAM); migrate active subscriptions via off-session re-authorization where supported, manual re-collection where not (PSD2-aware flow).
3. **Day 30..60:** complete migration; revoke Stripe webhook endpoints; close out outstanding invoices; reconcile billing ledger.
4. **Cash flow:** Stripe payout schedule is rolling 2-day; worst case 7 days of receivables stuck in Stripe balance at termination. Mitigation: maintain ≥ 30 days operating cash unrelated to Stripe payouts.

**RTO:** ≤ 60 days (worst case) for full billing migration. **RPO:** 1 hour (webhook backlog).

## 10. Review history

| Review date | Reviewer | Type | Residual | Notes |
|---|---|---|---|---|
| 2026-05-15 | Gustavo Schneiter (VP-Sec) | Baseline | 4.0 | Initial DD; closes GAP-14. |

Next quarterly review: **2026-08-15**.
