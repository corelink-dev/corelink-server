---
id: "DPIA-REVIEW-PROCESS"
type: "process"
doc_status: "FROZEN"
version: "1.0.0"
created: "2026-05-13"
updated: "2026-05-13"
owner: "Privacy Officer"
tags: ["dpia", "review-process", "quarterly", "gdpr-art-35", "lgpd-art-38"]
---

# Quarterly Privacy Officer DPIA Review Process

> **Owner:** Privacy Officer (interim: Gustavo Schneiter; hire target: post-Series A)
> **Frequency:** Quarterly (Q1: March, Q2: June, Q3: September, Q4: December)
> **SLA:** Review completed within 30 days of quarter start. Missed review → SEV-3 alert.

---

## 1. Overview

This document describes the **Standard Operating Procedure (SOP)** for the quarterly DPIA review cycle mandated by GDPR Art. 35 + LGPD Art. 38 + ANPD Res. CD/ANPD nº 4/2023 §4 (DPIAs must be updated when processing changes materially).

DPIAs are living documents. The quarterly review ensures that:
1. Existing DPIAs remain accurate as features evolve.
2. New features with PII impact have received a DPIA before going to production.
3. Risk assessments reflect current threat landscape and regulatory changes.
4. Sub-processor DPAs and SCCs remain valid (esp. for cross-border transfers post-Schrems II).

---

## 2. DPIA Register

The current DPIA register is maintained in `legal/dpia/`. Active DPIAs:

| DPIA ID | Feature | Sprint | Last reviewed | Status |
|---|---|---|---|---|
| DPIA-S07-001 | CAS deduplication — cross-tenant inference | S-07 | 2026-05-13 | DRAFT (pending sign-off) |
| DPIA-S09-001 | Telemetry aggregation — legitimate interest | S-09 | 2026-05-13 | DRAFT (pending sign-off) |
| DPIA-S10-001 | Billing data cross-border (Stripe US) | S-10 | 2026-05-13 | DRAFT (pending sign-off) |

> **To add a new DPIA:** create `legal/dpia/<feature-slug>.md` using `specs/_templates/dpia.md` and add a row to this register.

---

## 3. Quarterly Review Procedure

### Step 1: Identify DPIAs requiring review

At the start of each quarter, Privacy Officer reviews this register and identifies DPIAs where:
- (a) It has been ≥ 90 days since last review, OR
- (b) A change-triggered event occurred (PR detected by `scripts/validate_dpia.py`), OR
- (c) A sub-processor DPA/SCC has changed (any vendor in `legal/sub-processors.md`), OR
- (d) A supervisory authority (ANPD/DPC/ICO) has issued new guidance relevant to the DPIA scope.

### Step 2: Review each DPIA

For each DPIA identified in Step 1, Privacy Officer:

1. **Re-reads the current DPIA document** (`legal/dpia/<slug>.md`).
2. **Checks for material changes** in the underlying feature (git log for relevant crates/migration files).
3. **Checks sub-processor status:**
   - Stripe: verify DPF certification at `dataprivacyframework.gov`; verify DPA status at `stripe.com/legal/dpa`.
   - Cloudflare: verify DPA at `cloudflare.com/gdpr/`.
   - Every other vendor in `legal/sub-processors.md`: re-read the terms and DPA linked there.
4. **Checks regulatory landscape:**
   - Any new ANPD resolution impacting DPIA requirements?
   - Any CJEU/EDPB ruling impacting SCCs or cross-border transfer instruments?
5. **Updates risk register** (§3 of DPIA) if threat landscape or mitigations have changed.
6. **Updates residual risk assessment** (§5 of DPIA) if mitigations have improved or degraded.
7. **Updates the DPIA changelog** (§6 of DPIA) with version bump + date + summary.
8. **Updates the register table above** with new "last reviewed" date.

### Step 3: Identify missing DPIAs (retroactive review)

Privacy Officer reviews the git log for PRs that:
- Added new data categories to `data_model.md`
- Added new sub-processors to `sub-processors.md`
- Added new purpose values to ConsentPurpose enum
- Modified erasure worker backends (WI-S11-002)
- Modified billing data schema

Cross-check against DPIA register. If a PR changed PII handling without a corresponding DPIA, create a retroactive DPIA within 30 days and document the gap in the EVT-045 evidence.

### Step 4: Update EVT-045 quarterly summary

After completing all DPIA reviews, Privacy Officer:
1. Creates quarterly summary commit: `legal/dpia/quarterly-review-YYYY-QX.md` with list of DPIAs reviewed, changes made, and any new DPIAs created.
2. Uploads summary to R2 `evidence-legal/dpia-quarterly-review-YYYY-QX.md` (retain 7y).
3. Records `EVT-045` audit event in the CoreLink audit log.
4. Increments Prometheus counter: `corelink_dpia_quarterly_review_completion_total{quarter="YYYY-QX"}`.

### Step 5: Escalation on missed review

If the quarterly review is not completed within 30 days of quarter start:
- SEV-3 alert fires (PagerDuty → Privacy Officer + Engineering Lead).
- Privacy Officer documents reason for delay in the quarterly summary.
- Escalate to DPO if delay exceeds 60 days.
- Record gap in EVT-045 evidence.

---

## 4. Change-Triggered DPIA Review

The CI hook (`scripts/validate_dpia.py`) detects PII-impacting PRs and fails CI if no DPIA exists for the feature. When triggered:

1. **Engineer creates or updates DPIA** using `specs/_templates/dpia.md` at `legal/dpia/<feature-slug>.md`.
2. **Privacy Officer reviews** the DPIA within 5 business days (DPIA blocks PR merge via required reviewer).
3. **If override needed:** PR comment `[dpia: skip; rationale: <X>]` requires Privacy Officer GitHub approval + written rationale. CI re-fails without Privacy Officer approval.
4. **DPIA committed** in same PR as the PII-impacting change (or separate PR if retroactive).
5. **EVT-045 evidence uploaded** upon Privacy Officer sign-off.

---

## 5. LIA Review Schedule

LIA documents (`legal/lia/`) require annual review AND change-triggered review:

| LIA ID | Feature | Next review | Reviewer |
|---|---|---|---|
| LIA-S09-001 | Telemetry aggregation | 2027-05-13 | Privacy Officer |

LIA review procedure mirrors DPIA review steps 2–4 above, with specific attention to:
- Whether the legitimate interest is still compelling and current.
- Whether less intrusive alternatives are now available.
- Whether the balance test still holds (new threats to fundamental rights? new regulatory guidance?).

---

## 6. Regulatory Monitoring Checklist

Quarterly, Privacy Officer checks:

| Regulatory body | What to check | Frequency |
|---|---|---|
| ANPD (Brazil) | New resolutions or guidance on RIPD/DPIA | Quarterly |
| EDPB | New guidelines on DPIA, SCCs, legitimate interest | Quarterly |
| CJEU | Court rulings on cross-border data transfers | Quarterly |
| ICO (UK) | LIA guidance updates | Annual |
| US DPF | Stripe DPF certification status | Quarterly |
| Cloudflare | DPA updates; BCR status | Quarterly |
| Stripe | DPA updates; government access transparency report | Quarterly |

---

## 7. Metrics

| Metric | Description | Threshold |
|---|---|---|
| `corelink_dpia_quarterly_review_completion_total` | Counter incremented on each completed quarterly review cycle | Must reach 1 per quarter |
| `corelink_dpia_pr_coverage_total{outcome='enforced'}` | Counter per PR where DPIA hook triggered | 100% coverage of PII-impacting PRs |
| `corelink_dpia_pr_coverage_total{outcome='skipped_with_rationale'}` | Counter per valid override | ≤ 5% of PRs |
| `corelink_dpia_pr_coverage_total{outcome='skipped_missing_rationale'}` | Counter per invalid override (should be 0) | Must be 0 |

---

*SOP version 1.0.0 — WI-S11-008 — GDPR Art. 35 + LGPD Art. 38 quarterly Privacy Officer review.*
