---
id: "SALES-EVIDENCE-PACK-INDEX"
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
tags: ["sales", "legal", "questionnaire", "evidence-pack", "procurement", "auditor", "r-prep", "ga"]
---

# Evidence Pack Index — Which artifact answers which question family

> **Audience:** auditor or procurement reviewer with countersigned NDA on file via `trust@humangr.com`. This is the one-page wayfinder for the evidence bundle attached to any CoreLink SIG / CAIQ / custom-form response.
>
> **Source of truth:** `HuGR-dev/corelink-server` at commit `<SHA>` (cited per response) — a **private** repository. All paths below are repo-relative unless they start with `https://`.
>
> **⛔ CoreLink is not open source.** There is no public source repository. No row in this index may invite an auditor to "go read the code" — the platform source is private and is shared only under NDA. The only artifacts anyone can fetch without auth are release **binaries and checksums** (see PUBLIC-REPO). Verified 2026-08-02: `HumanGuardrail/corelink` and `HuGR-Labs/corelink` both return **HTTP 404** — that repo has never existed in either org, so this is not org-rename drift.
>
> **Access model:**
> - **PUBLIC** = visible on `apps/docs/docs/` or on the live docs site `https://humangr.com/corelink/docs/` (the old dotted `docs.corelink.` hostname is NXDOMAIN; `corelink-docs.humangr.com` 301s to the same live base).
> - **PUBLIC-REPO** = a **release artifact** (binary, checksum) downloadable without auth from `HuGR-Labs/corelink-cli` (HTTP 200) or `HuGR-Labs/clw-releases` (HTTP 200). Both publish **build outputs only — no source**.
> - **NDA** = shareable with countersigned NDA on file via `trust@humangr.com`. Turnaround: 1 business day.
> - **AUDITOR-ONLY** = shared with engaged 3PAO / external auditor only; not distributed even with NDA.

---

## How to use this index

1. Identify the question family (e.g. "encryption at rest", "BYOK", "GDPR breach", "SOC 2 controls").
2. Look up the family in the §1 master table to get the **canonical artifact path** and access tier.
3. Pull the artifact into the response bundle (folder `<prospect>-evidence-pack-YYYY-MM-DD/`).
4. Cite the artifact in the answer-key "Evidence" column.

If a question family is not listed here, escalate to DPO before answering — it likely means the prospect is asking outside our standard scope (HIPAA, FedRAMP, scope creep) and the answer should be one of the canonical declines in the vendor-questionnaire template.

---

## 1. Master index — question family × canonical artifact

| # | Question family | Canonical artifact (path) | Access |
|---|---|---|---|
| 1 | **SOC 2 — overall status** | `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md` | NDA |
| 2 | SOC 2 — gap register | `specs/_compliance/SOC2-GAP-ANALYSIS.md` | NDA |
| 3 | SOC 2 — roadmap | `specs/_compliance/SOC2-ROADMAP.md` | NDA |
| 4 | SOC 2 — auditor walkthrough | `specs/_compliance/AUDITOR-WALKTHROUGH-SCRIPT.md` | AUDITOR-ONLY |
| 5 | SOC 2 — Drata coverage | `specs/_compliance/DRATA-INTEGRATION-COVERAGE.md` | NDA |
| 6 | SOC 2 — weekly digest cadence | `specs/_compliance/weekly-digests/` | NDA |
| 7 | **ISO 27001:2022 — crosswalk** | `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md` | NDA |
| 8 | ISO 27001 — gap analysis | `specs/_compliance/ISO27001-GAP-ANALYSIS.md` | NDA |
| 9 | ISO 27001 — roadmap | `specs/_compliance/ISO27001-ROADMAP.md` | NDA |
| 10 | ISO 27001 — public summary | `apps/docs/docs/trust/iso27001.mdx` | PUBLIC |
| 11 | **PCI DSS — SAQ-A** | `specs/_compliance/PCI-DSS-SAQ-A-2026-05-15.md` | NDA |
| 12 | PCI DSS — boundary diagram | `specs/_compliance/PCI-DSS-BOUNDARY-DIAGRAM.md` | NDA |
| 13 | PCI DSS — annual recertify | `specs/_compliance/PCI-DSS-ANNUAL-RECERTIFY.md` | NDA |
| 14 | PCI DSS — public summary | `apps/docs/docs/trust/pci-dss.mdx` | PUBLIC |
| 15 | **GDPR — full audit** | `specs/_compliance/GDPR-FULL-AUDIT-2026-05-15.md` | NDA |
| 16 | GDPR — SCC execution | `specs/_compliance/GDPR-SCC-EXECUTION-2026-05-15.md` | NDA |
| 17 | GDPR — DPIA library | `specs/_compliance/GDPR-DPIA-LIBRARY.md` | NDA |
| 18 | GDPR — DPIA validator | `scripts/validate_dpia.py` | NDA |
| 19 | **LGPD — full audit** | `specs/_compliance/LGPD-FULL-AUDIT-2026-05-15.md` | NDA |
| 20 | LGPD — residency attestation (ROADMAP — in-jurisdiction residency not yet GA; data currently US/ENAM) | `specs/_compliance/LGPD-RESIDENCY-ATTESTATION-2026-05-15.md` | NDA |
| 21 | LGPD — ROPA | `specs/_compliance/LGPD-ROPA-2026-05-15.md` | NDA |
| 22 | LGPD — residency verifier (fails-loud today: in-jurisdiction residency not yet provisioned; ROADMAP) | `scripts/verify-lgpd-residency.py` | NDA |
| 23 | LGPD — DPO monthly checklist | `specs/_compliance/LGPD-DPO-MONTHLY-CHECKLIST.md` | NDA |
| 24 | **DPO — appointment** | `specs/_compliance/DPO-APPOINTMENT-2026-05-15.md` | NDA |
| 25 | DPO — responsibilities matrix | `specs/_compliance/DPO-RESPONSIBILITIES-MATRIX.md` | NDA |
| 26 | DPO — handoff plan | `specs/_compliance/DPO-HANDOFF-PLAN.md` | NDA |
| 27 | **FedRAMP — Moderate crosswalk** | `specs/_compliance/FEDRAMP-MODERATE-CROSSWALK-2026-05-15.md` | NDA |
| 28 | FedRAMP — not-in-scope rationale | `specs/_compliance/FEDRAMP-NOT-IN-SCOPE-RATIONALE.md` | PUBLIC (excerpt at `apps/docs/docs/trust/fedramp-info.mdx`) |
| 29 | **Encryption at rest + in transit** | `apps/docs/docs/trust/data-handling.mdx#encryption` | PUBLIC |
| 30 | BYOK — FIPS attestation matrix | `specs/_compliance/BYOK-FIPS-ATTESTATION-MATRIX.md` | NDA |
| 31 | BYOK — vendor letters | `specs/_compliance/fips-attestation-letters/` | NDA |
| 32 | BYOK — RFI questionnaire | `specs/_compliance/FIPS-RFI-QUESTIONNAIRE.md` | NDA |
| 33 | BYOK — endpoint verifier | `scripts/verify-fips-endpoints.py` | NDA |
| 34 | BYOK — renewal runbook | `specs/_runbooks/RB-FIPS-ATTESTATION-RENEWAL.md` | NDA |
| 35 | BYOK — public explainer | `apps/docs/docs/security/byok` | PUBLIC |
| 36 | BYOK — provider matrix | `compliance/byok-fips-matrix.md` | NDA |
| 37 | **Tenant isolation** | `specs/03_architecture/invariant_registry.md` (search `INV-TenantIsolation`) | NDA |
| 38 | Tenant isolation — public explainer | `apps/docs/docs/trust/index.mdx` §Posture-at-a-glance | PUBLIC |
| 39 | **Data residency** (US/ENAM default + physically-EU/WEUR live for EU tenants; Brazil/`sam` + APAC are ROADMAP) | `apps/docs/docs/trust/data-handling.mdx#residency` | PUBLIC |
| 40 | Residency — invariant (enforced for the live regions: `weur`→`lhr` guard refuses cross-region access; further regions ship under the same invariant) | `INV-REGION-NO-CROSS-LEAK` (in `specs/03_architecture/invariant_registry.md`) | NDA |
| 41 | LGPD residency — verifier (Brazil-specific; fails-loud today — Cloudflare R2 has no South-America region, so BR physical residency is ROADMAP) | `scripts/verify-lgpd-residency.py` | NDA |
| 42 | Residency — attestation API (ROADMAP — signed per-tenant residency-proof not live today) | `GET /v1/tenant/me/residency-proof` | PUBLIC |
| 43 | **Audit chain — Merkle proofs** | `apps/docs/docs/security/audit-chain` | PUBLIC |
| 44 | Audit chain — append-only invariant | `INV-AUDIT-APPEND-ONLY`, `INV-OBS-AUDIT-CHAIN-INTEGRITY` | NDA |
| 45 | Audit chain — retention | 7-year retention per `data-handling.mdx#retention` | PUBLIC |
| 46 | **Incident response — playbook** | `specs/_compliance/IR-TABLETOP-PLAYBOOK.md` | NDA |
| 47 | IR — 2026 tabletop schedule | `specs/_compliance/IR-TABLETOP-SCHEDULE-2026.md` | NDA |
| 48 | IR — scenarios library | `specs/_compliance/ir-scenarios/` | NDA |
| 49 | IR — breach notif runbook | `specs/05_quality/runbooks/RB-BREACH-NOTIF.md` | NDA |
| 50 | IR — public summary | `apps/docs/docs/trust/incident-response.mdx` | PUBLIC |
| 51 | IR — crisis comms templates | `marketing/launch/CRISIS-COMMS-TEMPLATES.md` | NDA |
| 52 | **Sub-processors — public list** | `apps/docs/docs/trust/subprocessors.mdx` | PUBLIC |
| 53 | Sub-processors — full register | `specs/_compliance/VENDOR-RISK-REGISTER.md` | NDA |
| 54 | Sub-processors — methodology | `specs/_compliance/VENDOR-RISK-METHODOLOGY.md` | NDA |
| 55 | Sub-processors — DD files | `specs/_compliance/vendor-dd/` | NDA |
| 56 | Sub-processors — quarterly review runbook | `specs/_runbooks/RB-VENDOR-RISK-QUARTERLY-REVIEW.md` | NDA |
| 57 | Sub-processors — legal listing | `legal/sub-processors.md` | NDA |
| 58 | Sub-processors — change notice runbook | `specs/_runbooks/RB-SUBPROCESSOR-CHANGE.md` | NDA |
| 59 | **BCP / DR — cadence** | `specs/_compliance/BCP-DR-DRILL-CADENCE.md` | NDA |
| 60 | DR — cold restore spec | `specs/_compliance/COLD-RESTORE-DRILL-SPEC.md` | NDA |
| 61 | DR — cold restore runbook | `specs/_runbooks/RB-COLD-RESTORE-FROM-ZERO.md` | NDA |
| 62 | DR — active failover spec | `specs/_compliance/ACTIVE-FAILOVER-DRILL-SPEC.md` | NDA |
| 63 | DR — active failover runbook | `specs/_runbooks/RB-ACTIVE-FAILOVER.md` | NDA |
| 64 | DR — chaos drill summary | `specs/_audits/sealed/2026-05-14-region-outage-chaos-s14.md` | NDA |
| 65 | DR — drill evidence | `specs/_compliance/drill-evidence/` | NDA |
| 66 | **Vulnerability mgmt — static analysis** | `specs/_audits/sealed/2026-05-15-static-analysis-baseline.md` | NDA |
| 67 | Vuln — triage runbook | `specs/_runbooks/RB-STATIC-ANALYSIS-TRIAGE.md` | NDA |
| 68 | Vuln — cargo-fuzz summary | `specs/_audits/sealed/2026-05-14-cargo-fuzz-summary-s15.md` | NDA |
| 69 | Vuln — Dependency-Track | ADR-0024 (`specs/03_architecture/adrs/`) | NDA |
| 70 | **Supply chain — SBOM** (a real CycloneDX 1.6 SBOM exists, but **no public SBOM does** — see the caveat below before answering) | `.sbom/cyclonedx-rust.json` (413 components) + `.sbom/cyclonedx-npm-admin-ui.json` (50) + `.sbom/cyclonedx-npm-docs.json` (25) — generated 2026-05-28, committed `1ed22958` | NDA |
| 71 | Supply chain — Rekor / Sigstore / Cosign (**NOT LIVE — do not offer this to an auditor**; see the caveat below) | *No signature artifact exists.* Integrity evidence we can actually point at: `https://github.com/HuGR-Labs/corelink-cli/releases/download/v0.1.1/checksums.txt` + per-binary `.sha256` | PUBLIC-REPO (checksums only) |
| 72 | Supply chain — license allowlist | `LICENSE-APACHE-2.0` + `LICENSE-MIT` + OSS matrix commit `44cdf15` + `.github/workflows/license-policy.yml` + `scripts/license-audit.sh` | NDA |
| 73 | **Secrets management** | `docs/internal/secrets-checklist.md` (108-row matrix) | NDA |
| 74 | Secrets — drift validator | `scripts/validate_secrets_matrix.py` | NDA |
| 75 | Secrets — drift gate | `.github/workflows/secrets-drift.yml` | NDA |
| 76 | Secrets — triage runbook | `specs/_runbooks/RB-SECRETS-DRIFT.md` | NDA |
| 77 | Secrets — DEBT-001 closure | Commit `52624e7` (2026-05-15) | NDA |
| 78 | **GA gate — go/no-go** | `specs/_compliance/GA-GATE-CRITERIA.md` | NDA |
| 79 | GA gate — template | `specs/_compliance/GA-GATE-GO-NOGO-TEMPLATE.md` | NDA |
| 80 | **DPA — standard** | `legal/dpa/v1.0.0` (EN-EU+UK) | NDA (signed copy with each tenant) |
| 81 | DPA — PT-BR locale | `legal/dpa/v1.0.0/pt-BR` | NDA |
| 82 | DPA — ES-LATAM locale | `legal/dpa/v1.0.0/es-LATAM` | NDA |
| 83 | LIA — template | `legal/lia/` | NDA |
| 84 | Breach notification template | `legal/breach-notification/` | NDA |
| 85 | **VDP / responsible disclosure** | `apps/docs/docs/security/policy` | PUBLIC |
| 86 | Security contact card | `/.well-known/security.txt` | PUBLIC |
| 87 | PGP key | `/.well-known/security-pgp.asc` | PUBLIC |
| 88 | **SLO catalog** | `specs/03_architecture/slo_catalog.md` | NDA |
| 89 | SLO — public summary | **not published** — `/slo` 404s on the live docs site and no source page exists; use row 88 | NDA |
| 90 | Status page | `https://hugrl.betteruptime.com` | PUBLIC |
| 91 | **Trust Center — index** | `apps/docs/docs/trust/index.mdx` | PUBLIC |
| 92 | Trust Center — compliance | `apps/docs/docs/trust/compliance.mdx` | PUBLIC |
| 93 | Trust Center — data handling | `apps/docs/docs/trust/data-handling.mdx` | PUBLIC |
| 94 | Trust Center — sub-processors | `apps/docs/docs/trust/subprocessors.mdx` | PUBLIC |
| 95 | Trust Center — incident response | `apps/docs/docs/trust/incident-response.mdx` | PUBLIC |
| 96 | Trust Center — FedRAMP info | `apps/docs/docs/trust/fedramp-info.mdx` | PUBLIC |
| 97 | Trust Center — PCI DSS | `apps/docs/docs/trust/pci-dss.mdx` | PUBLIC |
| 98 | Trust Center — ISO 27001 | `apps/docs/docs/trust/iso27001.mdx` | PUBLIC |
| 99 | **FAQ — sales canonical** | `marketing/sales/FAQ-MASTER.md` | NDA (internal sales reference) |
| 100 | Lighthouse playbook — enterprise | `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md` | NDA (per engagement) |

### 1.1 Supply-chain caveat — what rows 70–72 can and cannot promise

Measured 2026-08-02. Answer supply-chain questions from this block, not from memory.

- **SBOM — exists, is NOT public, is NOT per-release (row 70).** A CycloneDX 1.6 SBOM is committed
  at `.sbom/` (488 components across the Rust workspace, admin-ui and docs) and ships under NDA.
  It is *not* attached to any release: `.github/workflows/sbom.yml` has **12 runs, 0 green** —
  including the single `release`-triggered run (`26659689412`, 2026-05-29, failed), and
  `.github/workflows/sbom-consolidated.yml` has **never run**. The `.sbom/` snapshot is therefore
  hand-refreshed (last touched by commit `1ed22958`, 2026-05-27) and may lag the shipped build —
  state its generation date when you hand it over.
- **Cosign / Rekor / Sigstore — does not exist (row 71).** No CoreLink artifact carries a Cosign
  signature and no Rekor transparency entry has ever been created.
  `.github/workflows/cosign-sign.yml` has **0 runs ever**: it triggers on a `v*` tag and no `v*`
  tag has ever been pushed (the 52 tags in the repo are `cli-v*` / `*-sealed` and do not match).
  Signing of the CLI is still an explicit placeholder — `.github/workflows/release-cli.yml:247`
  is `"[TODO v2] cosign sign (placeholder)"`, which echoes *"cosign keyless signing not yet
  wired"*. SLSA provenance is in the same state: `.github/workflows/release-slsa3.yml` has 1 run,
  failed. **Never offer signatures, Rekor entries or SLSA attestation as available evidence.**
  What we *can* substantiate today is per-binary SHA-256 integrity (row 71, PUBLIC-REPO).
- **License allowlist — real and enforced (row 72).** `.github/workflows/license-policy.yml` is
  green on 28 runs; `LICENSE-APACHE-2.0`, `LICENSE-MIT` and the OSS matrix (commit `44cdf15`)
  are in-tree. NDA-gated only because the source tree is private.

If a questionnaire asks for a signed SBOM or a transparency-log entry, the honest answer is
**"not today"** plus the roadmap item — not a pointer to an artifact that was never produced.

---

## 2. Evidence-pack assembly by response type

### 2.1 SIG Lite response pack (standard bundle)

Include in order:

1. Cover letter (Founder + DPO signature).
2. `SIG-LITE-2026-pre-filled.md` populated and watermarked.
3. `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md` (master rollup).
4. `specs/_compliance/VENDOR-RISK-REGISTER.md` (sub-processor list).
5. `apps/docs/docs/trust/` snapshot (compliance + data-handling + sub-processors + incident-response).
6. `legal/dpa/v1.0.0`.
7. This Evidence Pack Index.

### 2.2 CAIQ v4 response pack

Include in order:

1. Cover letter.
2. `CAIQ-V4-pre-filled.md` populated and watermarked.
3. `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`.
4. `specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md`.
5. `apps/docs/docs/trust/iso27001.mdx` (public crosswalk).
6. `compliance/byok-fips-matrix.md` + `specs/_compliance/BYOK-FIPS-ATTESTATION-MATRIX.md` (CEK domain).
7. `legal/dpa/v1.0.0`.
8. This Evidence Pack Index.

### 2.3 Custom-form / vendor questionnaire response pack

Per `VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md` part 1–4. Mandatory items:

1. Cover letter (per template).
2. Answer key (per template).
3. This Evidence Pack Index.
4. `legal/dpa/v1.0.0`.

Conditional items (include if relevant to the form's topic-mix):

- SOC 2 rollup if any audit / compliance questions → add §1 item 1.
- ISO crosswalk if any ISO / Annex A questions → add §1 item 7.
- PCI SAQ-A if any payment / cardholder data questions → add §1 item 11.
- BYOK matrix + FIPS letters if any cryptography / KMS questions → add §1 items 30–36.
- IR playbook + breach notif runbook if any incident questions → add §1 items 46–51.
- Sub-processor full register if any third-party / supply-chain questions → add §1 items 53–58.
- BCP / DR cadence if any continuity questions → add §1 items 59–65.

### 2.4 Auditor / 3PAO walkthrough pack (separate from procurement responses)

For engaged auditors only — different access tier:

1. `specs/_compliance/AUDITOR-WALKTHROUGH-SCRIPT.md` — step-by-step.
2. All §1 NDA items above.
3. AUDITOR-ONLY: `specs/_audits/sealed/2026-05-14-soc2-readiness-score.md` (internal scorecard).
4. AUDITOR-ONLY: full vendor DD files at `specs/_compliance/vendor-dd/`.
5. AUDITOR-ONLY: ir-scenarios at `specs/_compliance/ir-scenarios/`.
6. AUDITOR-ONLY: drill-evidence at `specs/_compliance/drill-evidence/`.

---

## 3. Watermarking + bundle hygiene

Every artifact in a customer-bound pack **must** be watermarked:

```
CONFIDENTIAL — <Prospect Org> — <YYYY-MM-DD> — CoreLink (HuGR Labs)
Pursuant to NDA dated <NDA date>. Not for redistribution.
Source commit: <SHA> · `HuGR-dev/corelink-server` (private)
```

Bundle naming:

```
<prospect>-corelink-evidence-pack-<YYYY-MM-DD>-<commit-short-SHA>.zip
```

Hash the ZIP (`shasum -a 256`) and send the digest alongside the bundle, out-of-band, so the receiver can verify integrity. **Do not promise a Cosign signature** — no CoreLink release-signing key is in service today (§1.1, row 71).

---

## 4. Quick lookup — "which artifact for which CCM v4 domain"

| CCM v4 domain | Primary evidence artifact |
|---|---|
| A&A | SOC 2 rollup + Drata coverage |
| AIS | security_model.md + static-analysis baseline |
| BCR | BCP-DR-DRILL-CADENCE + chaos summary + active-failover spec |
| CCC | branch protection + canonical-consistency validator — Rekor / signed-deploy NOT live, see §1.1 |
| CEK | BYOK FIPS matrix + provider attestation letters + key flow |
| DCS | Inherited from sub-processors (CF / AWS / GCP / Azure SOC 2 Type II) |
| DSP | LGPD ROPA + GDPR DPIA library + data-handling.mdx |
| GRC | SOC 2 rollup + vendor risk methodology + weekly compliance digest |
| HRS | DPO appointment + competence matrix (GAP-05) + Code of Conduct |
| IAM | auth_model.md + Clerk SSO + INV-TenantIsolation + PAT-DUAL-APPROVAL |
| IPY | REAPI v2 docs + admin API export + audit-chain Merkle proofs |
| IVS | Cloudflare substrate (US/ENAM default + physically-EU/WEUR region live; further regions on roadmap) + immutable Workers |
| LOG | INV-AUDIT-APPEND-ONLY + R2 Object Lock + Prometheus catalog |
| SEF | IR-TABLETOP-PLAYBOOK + RB-BREACH-NOTIF + DPA §7 |
| STA | VENDOR-RISK-REGISTER + sub-processors.mdx + SBOM (`.sbom/`, NDA) — SLSA / Sigstore NOT live, see §1.1 |
| TVM | static-analysis baseline + Dependency-Track + VDP |
| UEM | Remote-first org + WebAuthn-bound prod access + GAP-ISO-07 (T+3m) |

---

## 5. Quick lookup — "which artifact for which SIG Lite category"

| SIG Lite category | Primary evidence artifact |
|---|---|
| A — Risk Management | VENDOR-RISK-METHODOLOGY + 33-GAP SOC 2 register |
| B — Security Policy | security_model.md + compliance_matrix.md |
| C — Org Security | DPO appointment + 13-role sign-off |
| D — Asset Management | Drata inventory + ROPA + GAP-ISO-01 (T+1m) |
| E — HR Security | Drata employee attestations + GAP-05 (T+3m) |
| F — Physical | Inherited (sub-processor SOC 2 Type II) |
| G — Comms+Ops | 60+ runbooks + SLO catalog + chaos drills |
| H — Access Control | INV-TenantIsolation + WebAuthn + PAT-DUAL-APPROVAL |
| I — System Acq+Dev | static-analysis baseline + SBOM (`.sbom/`, NDA) — SLSA NOT live, see §1.1 |
| J — Incident Mgmt | IR-TABLETOP-PLAYBOOK + 72h breach commitment |
| K — Compliance | SOC 2 rollup + ISO crosswalk + PCI SAQ-A + LGPD/GDPR audits |
| L — Endpoint Security | GAP-ISO-06 + GAP-ISO-07 (T+1m–T+3m) |
| M — Data Privacy | LGPD-ROPA + GDPR DPIA library + verifiable erasure |
| N — Cloud Hosting | Cloudflare / AWS / GCP / Azure SOC 2 Type II + BYOK matrix |

---

## 6. Maintenance

This index is updated whenever:

- A new compliance artifact lands in `specs/_compliance/` (add a row).
- An artifact moves from NDA → PUBLIC (update access column).
- A GAP closes (update referenced rows).
- A new audit framework is added (add a section to §2).
- The commit SHA reference snapshot rolls forward (per-response in cover letter; this index stays version-agnostic).

Next scheduled refresh: 2026-08-15 (Q3 quarterly review window, stacked with vendor-risk register refresh).

---

## Related

- `marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md`
- `marketing/sales/legal-questionnaires/CAIQ-V4-pre-filled.md`
- `marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md`
- `marketing/sales/legal-questionnaires/RESPONSE-SLA-POLICY.md`
- `specs/_compliance/AUDITOR-WALKTHROUGH-SCRIPT.md`
- `specs/_compliance/SOC2-EVIDENCE-ROLLUP-2026-05-15.md`
- `apps/docs/docs/trust/index.mdx`
- `marketing/lighthouse-kit/CUSTOMER-PLAYBOOK.md`

## Contact

| What you need | Where to send it |
|---|---|
| Evidence pack request (countersigned NDA on file) | `trust@humangr.com` |
| Auditor / 3PAO walkthrough | `trust@humangr.com` — cc Founder + DPO |
| Privacy / DSR | `privacy@humangr.com` |
| Security vulnerability report | `security@humangr.com` |
