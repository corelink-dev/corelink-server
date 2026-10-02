---
id: "DD-CLOUDFLARE-2026-05-15"
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
tags: ["soc2", "cc9.2", "vendor-dd", "critical", "cloudflare", "gap-14"]
---

# Vendor DD — Cloudflare, Inc.

> **doc_status:** ACTIVE · Register row: 1 · Category: **Critical** · Residual risk: **5.0** (Inherent 20 × CEF 0.25).
>
> Cloudflare runs the **entire CoreLink data plane and control-plane runtime** (Workers, R2, D1, Durable Objects, KV, Pages, Email). Loss of Cloudflare is a CoreLink existential event.

---

## 1. Vendor profile

| Field | Value |
|---|---|
| Legal entity | Cloudflare, Inc. |
| HQ | 101 Townsend Street, San Francisco, CA 94107, USA |
| Public ticker | NYSE: NET |
| Primary jurisdiction | United States (Delaware C-corp) + EU subsidiary (Cloudflare Germany GmbH for EU customer DPA) |
| CoreLink account ID | (see `docs/internal/secrets-checklist.md` row 49 placeholder; real value lives in `gha-secret`) |
| Contract effective | Not recorded — standard online terms and DPA accepted at account signup (owner statement, #2593 re-charter); no acceptance record is held |
| Annual contract value | (commercial-sensitive; redacted in this register) |
| Account executive (primary) | (recorded in `legal/vendor-contacts.md`) |
| Technical account manager | (recorded in `legal/vendor-contacts.md`) |

## 2. Service scope

Services consumed:

- **Cloudflare Workers** — `apps/server` runtime; primary execution surface
- **R2 object storage** — encrypted-blob storage (BYOK envelopes); customer payload data plane
- **D1** — control-plane SQLite-on-the-edge (account, tenant, billing-ledger snapshots, dsr_tickets, audit-log shards)
- **Durable Objects** — strongly-consistent per-tenant coordination (rate-limits, locks, webhook DLQ state)
- **KV** — cache layer for hot config + token-derivation lookups
- **Pages** — `apps/admin-ui` static hosting + `/privacy/sub-processors` public surface
- **Cloudflare Email Routing** — outbound transactional egress (mirrored to SendGrid for redundancy)
- **Custom domains** — api.hugr.dev, admin.hugr.dev, docs.hugr.dev, status.hugr.dev

Regions configured: `wnam` (us-east) primary + `enam` + `eeur` + `apac` per-tenant pinned via `tenant.primary_region`.

## 3. Data sharing

| Data category | Direction | Encryption at rest | Encryption in transit | Key holder |
|---|---|---|---|---|
| Customer encrypted blobs | CoreLink → R2 | AES-256 + envelope encrypted with customer CMK (AWS / GCP / Azure / Vault) | TLS 1.3 | Customer (CoreLink never holds the unwrapping KEK) |
| Account / tenant metadata | CoreLink → D1 | AES-256 (CF-managed) | TLS 1.3 | Cloudflare |
| Audit-log shards | CoreLink → D1 | AES-256 (CF-managed) | TLS 1.3 | Cloudflare |
| Operational telemetry | CoreLink → Logpush → Grafana Cloud | AES-256 in flight + at rest at Grafana | TLS 1.3 | Grafana / Cloudflare |
| Customer plaintext content | (never) | — | — | — |

The architectural invariant **INV-DATA-CRYPTO-001 (BYOK envelope encryption end-to-end)** ensures Cloudflare cannot read customer payload bytes even if R2 keys are compromised.

## 4. Regulatory and attestation scope

| Framework | Status | Cadence | Evidence path |
|---|---|---|---|
| SOC 2 Type II | Attested (current report ≤ 12 months) | Annual | Drata vendor module → Cloudflare → "SOC 2 Type II 2025 Report" |
| ISO 27001 | Certified | 3-year cycle (surveillance annually) | Cloudflare Trust Hub |
| ISO 27017 (cloud security) | Certified | Annual | Cloudflare Trust Hub |
| ISO 27018 (cloud privacy) | Certified | Annual | Cloudflare Trust Hub |
| PCI-DSS Level 1 | Attested | Annual | Cloudflare Trust Hub |
| FedRAMP Moderate | Authorized (Cloudflare for Government) — Workers + R2 partial | Continuous monitoring | Cloudflare FedRAMP package |
| HIPAA | Self-attested infrastructure compliance; BAA available on request (not signed today — no PHI in scope) | N/A | Cloudflare HIPAA position paper |
| GDPR | Processor; SCCs Module 2 baked into DPA; EU Subsidiary signs DPAs for EEA customers | N/A | https://www.cloudflare.com/cloudflare-customer-dpa/ |
| LGPD | Processor; Brazilian data residency available via São Paulo region | N/A | DPA |

## 5. Contractual posture

| Document | Signed | Version | Notes |
|---|---|---|---|
| Terms | Not recorded (accepted online) | https://www.cloudflare.com/terms/ | Cloudflare's standard self-serve terms; no negotiated MSA is recorded |
| DPA | Not recorded (accepted online with the terms) | https://www.cloudflare.com/cloudflare-customer-dpa/ | SCCs Module 2; sub-processor list at cloudflare.com/gdpr/subprocessors |
| SLA | Not recorded | Standard terms only | No negotiated SLA or service-credit schedule is recorded |
| BAA | Not signed | N/A | Available on request; no PHI in scope today |

Sub-processor change notification: **30-day prior notice** to enterprise customers (CoreLink subscribed to security@hugr.dev channel).

## 6. Control mapping (which CoreLink CTRLs depend on Cloudflare)

| CoreLink CTRL | Dependency on Cloudflare |
|---|---|
| CTRL-CRYPTO-002 / CRYPTO-003 | R2 + Workers crypto primitives (envelope encryption) |
| CTRL-DATA-001..006 | D1 / R2 / DO storage durability and access-control |
| CTRL-ACCESS-001..003 | Workers + KV-backed token-derivation lookups |
| CTRL-AUDIT-001..005 | D1 audit-log shards + Logpush for log integrity |
| CTRL-GC-001 / GC-002 | Workers quota and rate-limit enforcement |
| CTRL-PRIV-014..016 | DSR-erasure flows execute against R2 + D1 |
| CTRL-AVAIL-001..003 | Multi-region failover via tenant-pinned region routing |

If Cloudflare suffers a multi-region SEV-1, **24 CoreLink CTRLs degrade simultaneously**. This drives Critical category + quarterly review cadence.

## 7. Risk assessment narrative

**Inherent risk (20 = 5 × 4):** Impact 5 (catastrophic — multi-tenant data plane); Likelihood 4 (Cloudflare has a non-zero recurrence of multi-hour global incidents, e.g., 2020 BGP / 2022 control-plane events). Despite mature engineering, the dependency surface is exceptionally large.

**Residual risk (5.0):** CEF 0.25 because (a) Cloudflare carries SOC 2 Type II + ISO 27001 ≤ 12 months old, (b) CoreLink has documented compensating controls (BYOK envelope encryption — Cloudflare cannot read plaintext; multi-region routing; chaos-drill-tested fallback), but (c) failover is to **other Cloudflare regions**, not to a non-Cloudflare provider, so CEF cannot reach 0.10. Data at rest at Cloudflare is encrypted with Cloudflare-managed keys for metadata and customer-managed keys for content — partial alignment with the 0.10 condition but not full.

**Top risk drivers monitored continuously:**

1. Cloudflare global control-plane outage → CoreLink is fully blind (no admin operations).
2. Cloudflare BGP route leak → traffic blackhole.
3. Workers platform deprecation event → mass-migration required.
4. R2 silent data corruption → mitigated by cross-region replication invariant + BLAKE3 content addressing (`INV-CACHE-001`).
5. KMS-side Cloudflare key compromise → mitigated by BYOK envelope: customer keys are external to Cloudflare.

## 8. Escalation contacts

| Role | Contact path | SLA |
|---|---|---|
| Enterprise support — P1 incident | Cloudflare support portal `Priority: P1` + dedicated TAM Slack channel | 15-minute initial response |
| Account executive | (per `legal/vendor-contacts.md`) | Same business day |
| Security / abuse | abuse@cloudflare.com + security@cloudflare.com | 24h |
| Legal / privacy | privacy@cloudflare.com | 5 business days |
| Breach notification (per DPA) | privacy@cloudflare.com + CoreLink's security@hugr.dev on file | Per DPA Art. 33 timelines |

## 9. Termination / exit plan

If Cloudflare exits the market, is acquired into incompatible terms, or terminates CoreLink:

1. **Day 0..7:** trigger Cloudflare-exit war room. Snapshot full R2 / D1 state to cold backup (AWS S3 + GCS dual destinations).
2. **Day 7..30:** stand up alternate edge runtime (candidate stack: AWS Lambda@Edge + S3 + RDS; or Fastly Compute@Edge + Postgres) per `specs/_disaster-recovery/cloudflare-exit-cold-plan.md` (drafted — pending sprint S22 walkthrough).
3. **Day 30..60:** progressive customer migration; bilateral DPA amendments; communicate sub-processor change with full 30-day notice (Art. 28.2).
4. **Day 60..90:** decommission Cloudflare account.

**RTO worst case:** 30 days (data preserved via cross-cloud backups; service degraded). **RPO:** 1 hour (R2 cross-region replication + D1 hourly snapshots).

## 10. Review history

| Review date | Reviewer | Type | Residual | Notes |
|---|---|---|---|---|
| 2026-05-15 | Gustavo Schneiter (VP-Sec) | Baseline | 5.0 | Initial DD; closes GAP-14. |

Next quarterly review: **2026-08-15**.
