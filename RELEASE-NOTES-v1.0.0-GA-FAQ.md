---
version: "1.0.0"
release_codename: "GA"
release_date: "TBD (pending framework-v1-0-0-ga tag)"
doc_status: "DRAFT"
audience: "customers / prospects / sales / CS"
publication_gate: "framework-v1-0-0-ga tag + Owner approval (ADR-0034b 2-key)"
owner: "Gustavo Schneiter"
final_approver: "Gustavo Schneiter"
parent: "RELEASE-NOTES-v1.0.0-GA.md"
companion_docs:
  - "RELEASE-NOTES-v1.0.0-GA.md"
  - "CHANGELOG.md"
  - "docs/release-notes/v1.0.0-GA-marketing-summary.md"
  - "specs/_audits/sealed/2026-05-16-release-notes-editorial-polish.md"
---

# CoreLink v1.0.0 GA — Customer FAQ (DRAFT)

> **DRAFT.** Pre-answers to the 8 most likely customer questions ahead
> of v1.0.0 GA. All answers are honest about the *current* engineering
> state; nothing here overclaims a vendor attestation that has not
> closed. Publication is gated on the `framework-v1-0-0-ga` tag and
> the Owner + on-call SRE 2-key approval recorded in
> `specs/_audits/sealed/2026-05-16-ga-readiness-final.md` §13.

---

## Q1. What does CoreLink cost?

| Tier | Audience | Storage | Pricing model |
|---|---|---|---|
| **Solo** | Individual engineers, side projects | 50 GB | Free with metered overage |
| **Team** | ≤ 25 engineers | 1 TB | Per-seat monthly |
| **Business** | 26 – 250 engineers | 10 TB | Per-seat monthly + usage |
| **Enterprise** | > 250 engineers / regulated | Custom | Annual contract; BYOK required; dedicated CSM |

Interactive pricing calculator at `humangr.com/corelink/docs/pricing`. Final
pricing for any tier change is gated on Finance + Legal + Security
review per the S-18 cross-functional anti-scope gate (§10).

---

## Q2. What SLA does CoreLink commit to?

- **Business tier:** 99.9 % monthly uptime against the customer-facing
  read + write API (`p99 < 100 ms` cache hit; `p99 < 250 ms` cache miss
  + R2 backfill). Business-hours support; 4-hour P1 response.
- **Enterprise tier:** **99.95 %** monthly uptime; 24 / 7 P1 response
  with a **5-minute** PagerDuty acknowledgement SLA; contractual SLA
  credits via the DPA addendum.
- **All tiers** inherit the **4-burn-rate SLO alerting** stack (5 min,
  30 min, 1 h, 6 h windows) and the customer-facing per-tenant SLO
  dashboard.

SLA terms live in `legal/SLA-v1.md`; contractual SLA-credits formula
in the Enterprise DPA addendum.

---

## Q3. Where is my data stored? (Data residency)

CoreLink operates **4 production regions** at GA:

- **WNAM** — `us-west` (Cloudflare R2 + D1 + Durable Objects).
- **ENAM** — `us-east`.
- **WEUR** — `eu-west` (GDPR-resident).
- **SAM** — `sa-east` (LGPD-resident).

**Tenant `primary_region`** is pinned at signup from the rendered-locale
cookie (`corelink_locale`) and is **never silently changed**. Hot-blob
cross-region replication (the top 1 % of objects by traffic) is
**opt-in per tenant** for read-failover, and respects the same
residency boundaries (no EU-resident tenant data replicates to a
non-EU region without explicit DPA addendum signature).

Cross-border transfer mechanisms:

- **EU → US:** SCCs (Standard Contractual Clauses) executed; Schrems II
  TIA (Transfer Impact Assessment) on file, available on request to
  `trust@humangr.com` (DPA on file required).
- **MX:** LFPDPPP-aligned engineering-side; attorney sign-off pending
  (DEBT-025, hard-cap 2026-10-01 — see Q5).

---

## Q4. Do you support BYOK (Bring Your Own Key)?

**Yes.** CoreLink ships a 4-provider BYOK matrix at GA:

| Provider | FIPS level |
|---|---|
| AWS KMS | FIPS 140-3 L1 |
| GCP KMS | FIPS 140-2 L1 |
| Azure Key Vault Premium | FIPS 140-2 L2 |
| HashiCorp Vault Enterprise | FIPS 140-3 L1 |

**Encryption envelope.** Per-blob **AES-256-GCM** (FIPS 197 + FIPS
140-3 approved) with 96-bit random nonces and **CSPRNG-derived DEKs**
(via `getrandom::getrandom` — never deterministic from blob hash, which
would propagate compromise across blobs).

**Kill switch.** Customer-controlled revocation with **≤ 6 min p99**
end-to-end propagation SLA (60 s detection + 5 min DEK cache TTL hard
ceiling). Dry-run runbook: `RB-BYOK-REVOKE`.

**FIPS attestations.** 3 of 4 provider rows attested in
`compliance/byok-fips-matrix.md` at GA. The **AWS KMS row** is
engineering-CLOSED (wave-28 AWS Artifact fetch automation
SEAL'd — DEBT-003); the operator downloads the PDF at T-7d from AWS
Artifact and commits it under `evidence/aws-artifact/`.

BYOK is **available** on Business tier (optional add-on) and
**required** on Enterprise tier.

---

## Q5. What's the status of the external penetration test?

**Honest answer:** the pentest is contracted but **not yet complete**.
No customer-facing security claim in this release depends on a closed
external pentest.

**What is sealed today:**

- **Engagement scope** — `specs/_audits/sealed/2026-05-16-pre-ga-pentest-scope.md`
  v1.0 (502 lines; 6 attacker models; 41 attack chains; ASVS v4.0.3
  self-assessment; STRIDE + LINDDUN matrices). Wave-25 SEAL.
- **Vendor shortlist** — Bishop Fox, NCC Group, Trail of Bits.
- **RFP send ceremony** — executed wave-28 (`f3d44dc`);
  DEBT-026 register row **engineering-CLOSED**; vendor 30-day
  selection clock running.
- **Pentest finding absorption framework** — wave-28
  (`bb2da85`); 7-state machine
  (`RECEIVED → TRIAGED → IN_FIX → FIXED → RETEST_SUBMITTED →
  RETEST_PASSED → ABSORBED`) with CVSS / P-tier coherence enforced;
  48 test cases passing.

**Earliest retest letter** target: **2026-07-29** (vendor-paced).
HIGH / CRITICAL findings gate any `GA-Full` / `v1.1.0` promotion. The
vendor exec-summary will be published on the security & compliance
page once the retest clears HIGH / CRITICAL.

---

## Q6. Are you SOC 2 / ISO 27001 certified?

| Framework | Status at GA |
|---|---|
| **SOC 2 Type I** | **Ready** — auditor engagement scheduled per `SOC2-ROADMAP.md`; continuous evidence collection via Drata. |
| **SOC 2 Type II** | **In flight** — T+12m operating-effectiveness window opens at T-0. |
| **ISO 27001** | **Stage-1 eligible** at GA; Stage-2 at T+6m per `ISO27001-INTERNAL-AUDIT-PROGRAM.md`. |
| **GDPR** | **Compliant** — full DPIA library + SCCs executed (`GDPR-FULL-AUDIT-2026-05-15.md`). |
| **LGPD** (Brazil) | **Compliant** — DPO appointed; ROPA published (`LGPD-FULL-AUDIT-2026-05-15.md`). |
| **LFPDPPP** (Mexico) | Engineering-side **ready** (DEBT-025 wave-28); attorney sign-off pending (T+21d from attorney engagement; hard-cap pre-MX-tenant 2026-10-01). |
| **PCI DSS (SAQ-A)** | **Eligible** — Stripe-tokenised; no PAN in the CoreLink boundary. |
| **CCPA** | **Compliant** — inherits from the GDPR pipeline. |
| **FedRAMP Moderate** | **Not in scope at GA** — documented rationale in `FEDRAMP-NOT-IN-SCOPE-RATIONALE.md`. |

**Note on framing.** "Ready" / "Eligible" means engineering-side
controls are wired and an external auditor can engage. It does *not*
mean an attestation has been issued. We will publish each attestation
report on the trust center as it closes.

---

## Q7. How do I migrate from BuildBuddy / EngFlow / Bazel Remote Cache / Buildless / NativeLink?

**Short answer:** change the `--remote_cache` URL and the credential
helper. Your `BUILD` / `MODULE.bazel` / `.buckconfig` files do not
change.

CoreLink speaks the **REAPI v2** wire (`bazelbuild/remote-apis` v2.12.0).
If your build already uses any REAPI-v2-compatible remote cache, the
migration is:

```bash
# Bazel (stock HTTP remote cache; the tenant comes from the PAT)
build --remote_cache=https://corelink-api.humangr.com/bazel/cache
build --credential_helper=corelink-api.humangr.com=%workspace%/.bazel/corelink-credential-helper.sh

# Buck2: not supported today. Buck2 speaks REAPI over gRPC only, and
# CoreLink serves no gRPC ingress (see the "Migrate from a Bazel remote
# cache" guide on the docs site).
```

**Migration assist:**

- Side-by-side cache-hit-rate dashboards for the first 30 days.
- Dual-write mode for the migration window (writes go to both caches;
  reads prefer CoreLink, fall back to the legacy cache).
- A migration guide
  (`humangr.com/corelink/docs/how-to/migrate/from-bazel-remote-cache`,
  covering `bazel-remote` and BuildBuddy) walking through flag-by-flag
  config translation.

**Action Cache (AC)** is fully supported — same wire, plus
**HKDF-keyed MAC signatures** and **RFC 6962-style domain separation**
for dedup-safe action results.

---

## Q8. Is the price list final? Can I lock pricing for 12 months?

**Pricing is published** on `humangr.com/corelink/docs/pricing` with a
**12-month price lock** available on annual contracts (Business and
Enterprise tiers). Solo and Team monthly customers receive **90-day
written notice** before any price change, per the published terms.

**Pricing calculator** at `humangr.com/corelink/docs/pricing` (wave-29
stream #7 — SSR-rendered, 4-tier comparison, internal cost-worksheet).

**Volume + commit discounts** available on Business tier (≥ 250 seats
or ≥ 5 TB cache utilisation 12-month average) and Enterprise tier
(custom).

Any pricing change requires the **S-18 cross-functional anti-scope
gate** (Finance + Legal + Security review) before publication — see
`specs/_canonical/S-18-CROSS-FUNCTIONAL.md`.

---

## Cross-references

- `RELEASE-NOTES-v1.0.0-GA.md` — full customer-facing release notes.
- `CHANGELOG.md` — technical changelog.
- `docs/release-notes/v1.0.0-GA-marketing-summary.md` — 1-page exec
  summary.
- `specs/_audits/sealed/2026-05-16-release-notes-editorial-polish.md` —
  this FAQ's editorial polish audit (wave-30 stream #10).
- `specs/_audits/sealed/2026-05-16-final-cutover-readiness.md` — CONDITIONAL
  GO verdict + 7-DEFER counter + 10-row Owner pre-condition checklist.
- `specs/_audits/sealed/2026-05-16-prod-deploy-dressrun.md` — production-tier
  dress-run 9.36 / 10 PROCEED.

---

**End of CoreLink v1.0.0 GA Customer FAQ (DRAFT).**
Publication gated on the `framework-v1-0-0-ga` tag and Owner approval.
