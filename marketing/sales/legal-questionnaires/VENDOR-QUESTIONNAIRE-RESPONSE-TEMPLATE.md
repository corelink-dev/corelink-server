---
id: "SALES-VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.1.0"
created: "2026-05-15"
updated: "2026-08-02"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
reviewers: []
supersedes: null
superseded_by: null
parent: "R-PREP-SALES-ENABLEMENT"
tags: ["sales", "legal", "questionnaire", "vendor-review", "template", "procurement", "r-prep", "ga"]
---

# Generic Vendor Questionnaire Response — Template

> **Audience:** CoreLink CS / SE responding to a *custom* vendor security / privacy / procurement questionnaire (i.e. anything that is **not** SIG Lite or CAIQ — typical examples: bank-specific RFP, healthcare-vendor onboarding form, Fortune 500 procurement portal, EU public-sector tender).
>
> **What this template gives you:** a four-part response structure (cover letter + answer key + evidence index + DPA reference) that frames every custom question in our canonical posture, points to the right artifact, and avoids ad-hoc claims.
>
> **Companion docs:**
> - `SIG-LITE-2026-pre-filled.md` — start there if the form is SIG-like (`Y/P/N` columns, 14 categories A–N).
> - `CAIQ-V4-pre-filled.md` — start there if the form references CCM, CSA, STAR, or CAIQ control IDs.
> - `EVIDENCE-PACK-INDEX.md` — what-artifact-answers-which-question-family.
> - `RESPONSE-SLA-POLICY.md` — turnaround commitments.

---

## When to use this template (decision tree)

```
Custom vendor questionnaire received
            │
            ▼
  Does it match SIG Lite layout?
            │
   yes ────►  Use SIG-LITE-2026-pre-filled.md and map cells
            │
   no  ────►  Does it match CAIQ / CCM v4 layout?
            │
   yes ────►  Use CAIQ-V4-pre-filled.md and map cells
            │
   no  ────►  Use this template (custom-form path)
```

If the custom form contains **only ~5–20 questions**, fold the answer key directly into the cover letter. If it contains **20+ questions**, use the full four-part structure.

---

## Part 1 — Cover letter

Save as `<prospect>-corelink-response-cover-letter-YYYY-MM-DD.pdf`. Sign as Founder + DPO (or VP-Sec where DPO sign is excessive for scope).

### Template

> **Subject:** CoreLink response to `<Prospect Org>` vendor-review questionnaire — `<YYYY-MM-DD>`
>
> Dear `<Prospect Procurement Contact>`,
>
> Thank you for evaluating CoreLink as a vendor for `<engagement scope>`. Attached is our full response, comprising:
>
> 1. This cover letter.
> 2. Answer key — `<form-name>` populated cell-by-cell (`<filename>`).
> 3. Evidence index — concrete artifact references per question family (`<filename>`).
> 4. CoreLink standard DPA `v1.0.0` (English EU+UK locale; PT-BR + ES-LATAM available on request).
>
> **About our compliance posture (read before the answer key):**
>
> - **SOC 2 Type I:** target Q4-2026 fieldwork with Schellman & Co.; report Q1-2027. Today: 83.7% weighted internal readiness, 96.4% green on Drata continuous compliance. The full Type-I-readiness rollup (`SOC2-EVIDENCE-ROLLUP-2026-05-15`) is shareable under NDA.
> - **ISO 27001:2022:** certification target Q1-2027 with Schellman (Stage 1 Q4-2026 stacked with SOC 2). Today: 98.9% in-scope Annex A coverage on internal crosswalk. NDA-gated crosswalk pack available.
> - **PCI DSS:** SAQ-A self-attested 2026-05-15. CoreLink itself is not in your PCI CDE — Stripe (PCI L1 Service Provider) handles all cardholder data; CoreLink stores only opaque Stripe tokens.
> - **LGPD / GDPR:** compliant as processor (joint controller for limited service-telemetry); DPO appointed 2026-05-15 (`dpo@humangr.com`); SCC Modules 2/3 in the DPA. **EU data residency is live** — EU (`weur`) tenants' data stays in physically-EU R2 buckets (via the `lhr` cluster). US (`enam`) is the default region. Brazil/`sam` and APAC residency are on the roadmap (Enterprise-on-request, not GA; Cloudflare R2 has no South-America region today, so BR physical residency is not yet possible).
> - **HIPAA:** **out of scope by design.** CoreLink is a build-artefact cache and does not sign BAAs. The substrate (Cloudflare / AWS / GCP / Azure) is HIPAA-aligned, but the CoreLink product surface is not engineered for PHI.
> - **FedRAMP:** **not pursued.** NIST 800-53 Rev 5 Moderate crosswalk at 87% (informational only — not a substitute for ATO). Documented rationale: `specs/_compliance/FEDRAMP-NOT-IN-SCOPE-RATIONALE.md`.
>
> **About this response:**
>
> Every answer below is sourced to a concrete artifact in our repository (`HuGR-dev/corelink-server` (private)) at commit `<SHA>`. We have populated `Yes / Partial / Compensating Control / N/A / No` per question with explicit rationale; *no claim of capability is made without evidence on file*. Where remediation is in flight, the gap is identified with an ID and ETA (e.g. `GAP-02 → D+30`).
>
> If any answer is materially insufficient for your evaluation, we welcome a follow-up call. Our DPO + Security Lead can walk auditors through the full evidence rollup under NDA.
>
> Best regards,
>
> Gustavo Schneiter — Founder, DPO
> `gustavo@humangr.com` · `dpo@humangr.com`
> CoreLink (HuGR Labs)
>
> Encl: (1) Answer key — `<form-name>` populated · (2) Evidence index · (3) DPA `v1.0.0`
>
> ---
>
> *Routing:* please send all follow-up correspondence to `trust@humangr.com` (procurement-routing alias). Privacy / DSR questions go to `privacy@humangr.com`. Security-vulnerability reports go to `security@humangr.com`. We commit to acknowledgement within 1 business day.

---

## Part 2 — Answer key

Fill the prospect's form cell-by-cell. For each question, populate four columns at minimum:

| # | Prospect's question text | A | CoreLink answer | Evidence pointer |
|---|---|---|---|---|

Where:

- **A** (status): `Y` / `P` / `CC` / `N/A` / `N` per the legend below.
- **CoreLink answer**: 1–4 sentences, direct, no marketing varnish. Cite the canonical phrasing in our public Trust Center where possible.
- **Evidence pointer**: relative path within `HuGR-dev/corelink-server` (private) repository at commit `<SHA>` *OR* URL within the Trust Center *OR* "Available under NDA at `trust@humangr.com`" — never silence.

### Legend (consistent across all CoreLink responses)

- **Y** = Yes — implemented and evidenced.
- **P** = Partial — control exists, evidence gap with stated ETA + GAP ID.
- **CC** = Compensating Control — primary control N/A; equivalent control documented.
- **N/A** = Not applicable; scoping reason stated.
- **N** = No (with rationale).

### Answer-block canonical phrasings — copy / paste pool

These are the 12 highest-frequency answer blocks. Lift them verbatim when the prospect's question matches the topic; paraphrase only if the question is materially narrower.

#### 1. SOC 2 status

> **A:** SOC 2 Type I target Q4-2026 fieldwork; report Q1-2027. Type II target Q3-2027. Auditor: Schellman & Co. Continuous compliance via Drata: 96.4% green dashboard, 90.7% strict auto-collection of evidence. Internal readiness scorecard 83.7% (113/135 weighted criterion-points). Full Type-I-readiness rollup (`SOC2-EVIDENCE-ROLLUP-2026-05-15.md`) shareable under NDA. **No Type I report yet issued.**

#### 2. ISO 27001 status

> **A:** ISO/IEC 27001:2022 certification target Q1-2027 (Stage 1 audit Q4-2026 stacked with SOC 2 Type I; Stage 2 + certificate issuance Q1-2027). Today: 98.9% in-scope Annex A coverage on internal crosswalk; 91% overlap with SOC 2 evidence collection in Drata. NDA-gated crosswalk pack at `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md` available via `trust@humangr.com`.

#### 3. PCI DSS status

> **A:** PCI DSS SAQ-A compliant (self-attested 2026-05-15; validity through 2027-05-14). CoreLink is not in your PCI CDE — Stripe (PCI Level 1 Service Provider, SAQ-D-SP) tokenizes all card data via Stripe Elements; CoreLink stores only opaque Stripe identifiers (`cus_…`, `sub_…`, `pm_…`, `in_…`). Boundary diagram + signed SAQ-A available via `trust@humangr.com`.

#### 4. LGPD (Brazil) compliance

> **A:** LGPD-compliant as processor (joint controller for limited service-telemetry). DPO appointed 2026-05-15 (`dpo@humangr.com`). Brazilian-tenant data is stored in the **US (ENAM)** region under SCCs + supplementary measures for cross-border transfer. In-country Brazilian residency (`sam` São Paulo) is on the roadmap — note **Cloudflare R2 has no South-America region**, so BR physical residency is not yet technically possible (Enterprise-on-request once the substrate supports it, not GA). 72h ANPD notification commitment. DSR turnaround: 5-business-day acknowledgement / 15-business-day resolution (Art. 18).

#### 5. GDPR compliance

> **A:** CoreLink's prelaunch materials distinguish tenant-pinned R2/DO state from a shared global D1 control plane. EU (`weur`) CAS/AC blobs use physically-EU R2 buckets through London/`lhr`; that statement does not cover D1. D1's primary is currently reported in ENAM with no D1 jurisdiction. Counsel has not yet approved effective customer-facing transfer terms for this D1 posture, so this template makes no executed SCC, BYOK, or crypto-erase claim.

#### 6. HIPAA

> **A:** Out of scope by design. CoreLink is a build-artefact cache; it does not handle PHI. We do **not** sign Business Associate Agreements. The underlying infrastructure (Cloudflare / AWS / GCP / Azure) is HIPAA-aligned at the substrate level, but CoreLink's product surface is not engineered, scoped, or tested for PHI. If your build artefacts contain PHI, that is likely an upstream tagging bug — please raise a SEV-2 with your account team.

#### 7. FedRAMP

> **A:** Not pursued today. NIST 800-53 Rev 5 Moderate crosswalk at 87% (informational only — not a substitute for ATO). Rationale documented at `specs/_compliance/FEDRAMP-NOT-IN-SCOPE-RATIONALE.md`. Sponsorship-path documented. CSA STAR Level 1 / CAIQ self-assessment available on request via `trust@humangr.com`.

#### 8. Encryption at rest + in transit

> **A:** At rest: AES-256-GCM on Cloudflare R2 / D1 / KV / DO. Optional BYOK envelope encryption per blob (KMS providers: AWS KMS at GA; GCP Cloud KMS, Azure Key Vault, HashiCorp Vault on the roadmap). In transit: TLS 1.2 minimum (TLS 1.3 negotiated with every client that supports it; the 1.2 floor is deliberate so `native-tls`/SecureTransport clients such as `sccache` connect, per ADR-0072); HSTS `max-age=63072000; includeSubDomains; preload`; AEAD-only ciphers (AES-256-GCM, ChaCha20-Poly1305); mTLS edge-to-origin. FIPS endpoint posture per `compliance/byok-fips-matrix.md`.

#### 9. Tenant isolation

> **A:** Cross-tenant blast radius is **zero**. Tenant-scoped R2 prefixes, Durable Object instances, and Clerk namespaces isolate tenant access. The D1 control plane is one shared global database, not a per-tenant database; its primary is currently reported in ENAM with no D1 jurisdiction. `INV-TenantIsolation` is TLA+ model-checked and CI-gated. A request that reaches a region or tenant other than the binding is refused at the boundary — not load-balanced, not falling back.

#### 10. Data residency

> **A:** CoreLink serves tenant-pinned R2/DO state through a **US (ENAM)** default path and a **physically-EU (WEUR)** path. EU (`weur`) CAS and AC blobs are stored in physically-EU Cloudflare R2 buckets (`corelink-cas-eu` / `corelink-ac-eu`, both EEUR) via London/`lhr`; this is an R2 residency statement. The D1 control plane is one shared global database, with its primary currently reported in ENAM and no D1 jurisdiction. The prelaunch DPA/TIA text does not establish an approved transfer basis or executed customer terms for that D1 posture. Other jurisdictions (`sam` São Paulo, `oce` Sydney, `apc` Tokyo/Singapore, `mea` Dubai) are roadmap items, not GA.

#### 11. Breach notification

> **A:** 72h to ANPD (LGPD Art. 33); 72h to EU supervisory authority (GDPR Art. 33); without-undue-delay to high-risk affected data subjects (GDPR Art. 34); **24h to affected enterprise tenant** (DPA §7). 4h internal escalation to DPO + Security Lead. Status page within 5 min for SEV1; email to affected tenants within 30 min.

#### 12. Sub-processor management

> **A:** 6 active sub-processors (full list at `apps/docs/docs/trust/subprocessors.mdx`; auto-generated from internal vendor risk register `specs/_compliance/VENDOR-RISK-REGISTER.md`). 30 calendar days advance notice on additions or replacements per DPA §6 + GDPR Art. 28 §2 + LGPD Art. 27 §4º. Notification channels: tenant-registered distribution email + status page + RSS (post-GA). Customer has right to object per DPA §6.4.

---

## Part 3 — Evidence index

Attach `EVIDENCE-PACK-INDEX.md` (companion doc) as a separate file. It maps question families → canonical artifact → access path (public / NDA-gated). For custom-form responses, also include:

- A per-question-cluster mini-index inside the answer key showing the artifact-pointer count (e.g. "Encryption: 4 artifacts attached, see Evidence Index §2.4").
- Cross-references between prospect's question IDs and the canonical phrasing block (see Part 2 §"Copy / paste pool").

---

## Part 4 — DPA reference

Always attach the CoreLink standard DPA `legal/dpa/v1.0.0`. If the prospect provides their own DPA template:

1. **Do not silently redline.** Their template is a starting point; their procurement / Legal owns the deviation register.
2. **Map their clauses to our standard DPA sections.** Send back a clause-by-clause map.
3. **Where their template is incompatible with our posture, state it explicitly** (e.g. unlimited indemnity, BAA clauses for HIPAA scope we don't sign, in-country data-residency clauses we cannot meet today — EU residency is live (data stays in the EU), but Brazil/`sam` and APAC physical residency are roadmap, not GA). Counter-proposal language inline.
4. **Engage external counsel for deviations beyond ±15% of our standard.** Escalation path: Founder → external counsel (`legal/legal-externo-engagement-contract.md`) → Schellman pre-audit review.

Standard DPA sections (per `legal/dpa/v1.0.0`):

| § | Topic | Our standard |
|---|---|---|
| 1 | Definitions | Aligned with GDPR Art. 4 + LGPD Art. 5 |
| 2 | Scope + roles | Processor (joint controller for service-telemetry) |
| 3 | Records of processing | Linked to `LGPD-ROPA-2026-05-15.md` |
| 4 | Security of processing | Linked to `security_model.md` CTRL catalog |
| 5 | DSR support | 5-day acknowledge / 15-day resolve |
| 6 | Sub-processors | 30-day advance notice + objection right |
| 7 | Breach notification | 24h to enterprise tenant; 72h to authority |
| 8 | Right to audit | Reasonable-notice + cost responsibility |
| 9 | International transfers | SCC Modules 2/3 + supplementary measures |
| 10 | Termination + data return | Verifiable erasure on termination |

---

## Pre-flight checklist (before sending response)

- [ ] Countersigned NDA on file with Legal.
- [ ] Cover letter signed by Founder + DPO (or VP-Sec).
- [ ] Answer key populated cell-by-cell — **no empty cells**, no "TBD".
- [ ] Every `Y` answer has at least one evidence pointer.
- [ ] Every `P` answer has GAP ID + ETA.
- [ ] Every `CC` answer has the equivalent control documented.
- [ ] Every `N/A` answer has a scoping rationale.
- [ ] Every `N` answer has a rationale (rare; usually limited to HIPAA / FedRAMP).
- [ ] Evidence Index attached.
- [ ] DPA `v1.0.0` attached.
- [ ] Commit SHA at top of cover letter.
- [ ] Watermarked with prospect name + date.
- [ ] Sent via `trust@humangr.com` (procurement-routing alias) — never personal email.
- [ ] Logged in CRM with response timestamp + form-name + version + commit SHA.
- [ ] Calendar invite sent for follow-up Q&A call within 5 business days of submission.

---

## Common custom-form patterns (worked examples)

### Pattern A — Financial-services vendor onboarding (~60 questions)

Typical themes: SOC 2, FFIEC, GLBA, PCI DSS, GDPR/CCPA, vendor risk management, cyber insurance, BCP, exit clauses.

**CoreLink response posture:**
- Lead with PCI DSS SAQ-A + Stripe inheritance.
- For FFIEC-aligned questions: map to SOC 2 evidence rollup + ISO 27001 crosswalk; acknowledge no native FFIEC framework.
- For cyber-insurance questions: state "Q3-2026 broker engagement; ≥ $5M aggregate target". Do not overstate.
- Attach: SIG-LITE-2026-pre-filled.md as exhibit (most FS forms ask SIG Lite anyway).

### Pattern B — Healthcare vendor onboarding (~80 questions)

Typical themes: HIPAA BAA, HITRUST CSF, PHI handling, Privacy Rule, Security Rule.

**CoreLink response posture:**
- Lead with the HIPAA out-of-scope answer (canonical phrasing #6).
- Most form sections become **N/A** with scoping rationale.
- If prospect insists, decline scope rather than soften the answer. PHI in a build-artefact cache is a tagging bug, not a vendor capability.

### Pattern C — EU public-sector tender (~120 questions)

Typical themes: GDPR Art. 28 sub-processor controls, Schrems II SCC, data residency, exit / portability.

**CoreLink response posture:**
- Lead with GDPR + Schrems II (canonical phrasing #5).
- Heavy attach: `legal/dpa/v1.0.0`, SCCs, GDPR-DPIA library.
- For data-residency: EU (`weur`) CAS/AC data uses physically-EU R2 buckets (EEUR) via `lhr`. The shared global D1 control plane is separately disclosed with a primary currently reported in ENAM and no D1 jurisdiction; do not claim EU-wide residency or an approved transfer basis for D1 before counsel signs off.
- For portability (Art. 20): cite CAIQ IPY domain answers + REAPI v2 export.

### Pattern D — Fortune 500 procurement portal (~30–200 questions; vendor-specific)

Typical themes: highly variable — combination of SIG, CAIQ, custom risk-rating, ESG, supply chain.

**CoreLink response posture:**
- Triage form by domain — for each domain, identify which canonical phrasing block applies.
- For ESG / DEI / supply-chain questions outside CoreLink's standard scope: provide what's true (e.g. OSS license allowlist for supply chain; remote-first org for DEI) and decline to overstate.
- If form requests **certified** answers (auditor-attested per question), state turnaround for SOC 2 letter (T+0 if already issued; otherwise NDA-gated readiness rollup).

---

## Escalation path

| Situation | Escalate to |
|---|---|
| Question asks for a certification we don't hold | DPO (Gustavo Schneiter, `dpo@humangr.com`) — write the "not yet, here's the roadmap" answer; never embellish. |
| Prospect wants to redline DPA beyond ±15% | External counsel per `legal/legal-externo-engagement-contract.md`. |
| Prospect wants a custom security commitment beyond DPA | Founder + Security Lead — write into SOW addendum, not into questionnaire. |
| Prospect requests on-site audit | DPO + Security Lead; route via `trust@humangr.com`. Cite DPA §8 right-to-audit terms. |
| Prospect requests pentest results we don't have | "No external pentest has been commissioned and no report or availability date exists. `CAP-GA-002` remains a hard pre-GA gate; do not promise an NDA report or later cadence. Internal adversarial-review and cargo-fuzz evidence can be discussed under NDA." |
| Prospect insists on HIPAA BAA | Founder + Legal; if PHI is truly in scope, *decline the engagement*. CoreLink is not a HIPAA-aligned product. |
| Prospect insists on FedRAMP | Founder; explain the 12–18 month 3PAO engagement requirement and ask whether SOC 2 + ISO 27001 satisfy their actual ATO requirement. Most do. |

---

## Related

- `marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md` — SIG Lite path.
- `marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md` — CAIQ v4 path.
- `marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md` — evidence pack.
- `marketing/sales/legal-questionnaires/RESPONSE-SLA-POLICY.md` — turnaround commitments.
- `marketing/sales/FAQ-MASTER.md` §Compliance — canonical phrasing per topic.
- `marketing/sales/OBJECTION-HANDLING.md` — push-back patterns.
- `apps/docs/docs/trust/` — public trust center.
- `legal/dpa/v1.0.0` — standard DPA (EN-EU+UK).
- `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` — enterprise-tier engagement playbook.

## Contact

| What you need | Where to send it |
|---|---|
| Vendor-questionnaire response (countersigned NDA on file) | `trust@humangr.com` |
| DPA redline / legal | `legal@humangr.com` |
| Privacy / DSR | `privacy@humangr.com` |
| Security vulnerability report | `security@humangr.com` |
