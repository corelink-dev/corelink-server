---
version: "1.4.0"
last_updated: "2026-10-02"
notification_required: true
# Approved launch set (B-316 / #2593 owner re-charter, 2026-10-01): exactly these
# eight vendors. Each is engaged on its own standard online terms and DPA, linked
# below. No online-acceptance date is recorded for any of them, so every
# contract_signed_at is null; a date may only be added from an acceptance record.
sub_processors:
  - id: "cloudflare"
    name: "Cloudflare, Inc."
    role: "Infrastructure provider (Workers, R2, KV, DO, D1, Pages, Email)"
    data_categories_processed:
      - "account_metadata"
      - "blob_content"
      - "audit_logs"
      - "telemetry"
    region: "R2/DO tenant-pinned per tenant.primary_region; D1 control-plane metadata global under SCC/TIA safeguards"
    certifications:
      - "SOC 2 Type II"
      - "ISO 27001"
      - "ISO 27018"
      - "PCI-DSS Level 1"
      - "HIPAA-compliant infra"
    terms_url: "https://www.cloudflare.com/terms/"
    dpa_url: "https://www.cloudflare.com/cloudflare-customer-dpa/"
    primary_jurisdiction: "United States (EU offices)"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/cloudflare-dpa-review-2026-04.md"

  - id: "clerk"
    name: "Clerk, Inc."
    role: "Authentication, identity provider, JWT issuer"
    data_categories_processed:
      - "account_pii"
    region: "Multi-region (tenant-pinned per tenant.primary_region)"
    certifications:
      - "SOC 2 Type II"
      - "GDPR processor"
    terms_url: "https://clerk.com/legal/standard-terms"
    dpa_url: "https://clerk.com/legal/dpa"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/clerk-dpa-review-2026-04.md"

  - id: "resend"
    name: "Resend, Inc."
    role: "Transactional email + newsletter-audience delivery"
    data_categories_processed:
      - "recipient_email_pii"
    region: "United States"
    certifications: []
    terms_url: "https://resend.com/legal/terms-of-service"
    dpa_url: "https://resend.com/legal/dpa"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/resend-dpa-review-2026-09.md"

  - id: "stripe"
    name: "Stripe, Inc."
    role: "Payment processing and subscription billing"
    data_categories_processed:
      - "billing_data"
      - "payment_information"
    region: "US and EU"
    certifications:
      - "PCI-DSS Level 1"
      - "SOC 2 Type II"
      - "ISO 27001"
    terms_url: "https://stripe.com/legal/ssa"
    dpa_url: "https://stripe.com/legal/dpa"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/stripe-dpa-review-2026-04.md"

  - id: "github"
    name: "GitHub, Inc."
    role: "Source code repository and CI/CD pipeline"
    data_categories_processed:
      - "source_code"
      - "ci_artifacts"
    region: "United States"
    certifications:
      - "SOC 2 Type II"
      - "ISO 27001"
    terms_url: "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service"
    dpa_url: "https://github.com/customer-terms/github-data-protection-agreement"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/github-dpa-review-2026-04.md"

  - id: "sentry"
    name: "Functional Software, Inc. (Sentry)"
    role: "Application error monitoring (admin-ui server/edge/client + docs-site build loader)"
    data_categories_processed:
      - "telemetry"
    region: "United States"
    certifications: []
    terms_url: "https://sentry.io/terms/"
    dpa_url: "https://sentry.io/legal/dpa/"
    primary_jurisdiction: "United States"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/sentry-dpa-review-2026-09.md"

  - id: "plausible"
    name: "Plausible Insights OÜ (Plausible Analytics)"
    role: "Cookieless web analytics for the docs-site marketing funnel"
    data_categories_processed:
      - "telemetry"
    region: "European Union"
    certifications: []
    terms_url: "https://plausible.io/terms"
    dpa_url: "https://plausible.io/dpa"
    primary_jurisdiction: "Estonia (EU)"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/plausible-dpa-review-2026-09.md"

  - id: "betterstack"
    name: "Better Stack, Inc. (BetterStack / Statuspage)"
    role: "Uptime/status monitoring — synthetic HTTP-health probes against CoreLink's own public endpoints + public status page hosting"
    data_categories_processed:
      - "telemetry"
    region: "European Union"
    certifications: []
    terms_url: "https://betterstack.com/terms"
    dpa_url: "https://betterstack.com/dpa"
    primary_jurisdiction: "European Union"
    contract_signed_at: null
    legal_review_evidence: "docs/compliance/vendor-reviews/betterstack-dpa-review-2026-09.md"
---

# CoreLink — Sub-Processors Register

CoreLink processa dados pessoais via os seguintes sub-processadores conforme
**GDPR Art. 28.2** + **LGPD Art. 39** + **CTRL-PRIV-021**.

Lista completa abaixo. Versão e data de última atualização no frontmatter YAML acima.

> **Source of truth (single chain).** This file is the **authoritative
> contractual sub-processor disclosure** referenced by the DPA (`legal/dpa/v1.0.0`
> §3). The customer-facing public page
> (`apps/docs/docs/trust/subprocessors.mdx`) is **not** generated from this
> file directly — it is auto-generated by `scripts/gen-public-subprocessors.py`
> from the internal **Vendor Risk Register**
> (`specs/_compliance/VENDOR-RISK-REGISTER.md`), of which the active
> customer-data sub-processors below are a subset. The register and this
> contractual list MUST stay consistent; the drift gate runs in
> `.github/workflows/subprocessors-sync.yml`. Any change to the active set
> is made in **both** the register and this file in the same PR (see
> *Change Process* below). `scripts/verify_b316_pending_vendor_reviews.py`
> checks that this file, the register, the commitments document and every
> published sub-processor list name the same vendors with the same terms and
> DPA links.

## Right to Object

Per **GDPR Art. 28.2.b** + **LGPD Art. 39**, customers podem objetar a mudanças via:

- **Email**: privacy@hugr.dev
- **API**: `POST /v1/privacy/sub-processor-objection`
- **DPA escalation**: Privacy Officer + Legal review ≤ 14 dias úteis → accept-or-terminate decision.

Rate limit: 5 objections/day/subject (anti-DoS; S-08 inheritance).

## Sub-Processors

Active sub-processors (8) — the approved launch set, matching
`apps/docs/docs/trust/subprocessors.mdx`'s "Active sub-processors" table,
`apps/admin-ui/src/content/sub-processors.json`, and the active subset of
`specs/_compliance/VENDOR-RISK-REGISTER.md` §2:

| ID | Nome | Função | Região | Terms | DPA |
|---|---|---|---|---|---|
| cloudflare | Cloudflare, Inc. | Infrastructure (Workers, R2, KV, DO, D1, Pages, Email) | R2/DO tenant-pinned; D1 control-plane metadata global under SCC/TIA safeguards | [Terms](https://www.cloudflare.com/terms/) | [DPA](https://www.cloudflare.com/cloudflare-customer-dpa/) |
| clerk | Clerk, Inc. | Authentication, identity provider, JWT issuer | Multi-region (tenant-pinned) | [Terms](https://clerk.com/legal/standard-terms) | [DPA](https://clerk.com/legal/dpa) |
| resend | Resend, Inc. | Transactional email + newsletter-audience delivery (recipient email is PII) | United States | [Terms](https://resend.com/legal/terms-of-service) | [DPA](https://resend.com/legal/dpa) |
| stripe | Stripe, Inc. | Payment processing and billing | US and EU | [Terms](https://stripe.com/legal/ssa) | [DPA](https://stripe.com/legal/dpa) |
| github | GitHub, Inc. | Source code repository and CI/CD | United States | [Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) | [DPA](https://github.com/customer-terms/github-data-protection-agreement) |
| sentry | Functional Software, Inc. (Sentry) | Application error monitoring — scrubbed diagnostic telemetry (admin-ui + docs-site) | United States | [Terms](https://sentry.io/terms/) | [DPA](https://sentry.io/legal/dpa/) |
| plausible | Plausible Insights OÜ (Plausible Analytics) | Cookieless web analytics for the docs-site marketing funnel | European Union | [Terms](https://plausible.io/terms) | [DPA](https://plausible.io/dpa) |
| betterstack | Better Stack, Inc. (BetterStack / Statuspage) | Uptime/status monitoring — synthetic probes + public status page (no customer data) | European Union | [Terms](https://betterstack.com/terms) | [DPA](https://betterstack.com/dpa) |

### Contract basis (owner re-charter, 2026-10-01)

CoreLink is a single-owner company with no separate legal department. On
2026-10-01 the owner re-chartered B-316 (#2593): each sub-processor above is
engaged on **that vendor's own standard online terms and data processing
agreement**, linked in the table, which the owner accepted online when the
account was created. There is no countersigned copy and no separate named
Legal/Privacy reviewer; the owner is the reviewer.

**Acceptance dates are not recorded**, so `contract_signed_at` is `null` for
every vendor. Earlier versions of this file showed `2026-04-23` for five
vendors; that value is the date the repository's specifications were created,
it was applied identically to vendors CoreLink never used, and no acceptance
record supports it, so it has been removed rather than carried forward. A date
may be added only from an acceptance record (for example a vendor dashboard or
the acceptance email).

## Contracted-but-not-active / integration built, not enabled

The vendors below have a real client integration in the codebase (and, for
Grafana, a prior contractual review) but are **not** currently
sub-processors — no production credential is deployed for them, or no code
path invokes the client, so no customer data is flowing today. Kept here
rather than deleted so the disclosure stays truthful if one is switched on
later; mirrors `apps/docs/docs/trust/subprocessors.mdx`'s
"Contracted-but-not-active" table and `specs/_compliance/VENDOR-RISK-REGISTER.md`
§4b.

| Vendor | Integration | Why not active today |
|---|---|---|
| Grafana Labs | `grafana_cloud` OTel exporter variant (`crates/corelink-container/src/routes/otel_layer.rs:158-248`) | `CORELINK_GRAFANA_API_KEY` is deployed on no Worker; the exporter falls back to `disabled`. |
| Drata, Inc. | `crates/corelink-ops/src/drata/` client | `DRATA_API_KEY` is deployed on none of 10 production Workers and is not a GitHub Actions secret. |
| Slack Technologies, LLC (Salesforce) | Security-webhook delivery in `.github/workflows/pentest-findings-sync.yml` | `SLACK_SECURITY_WEBHOOK` is unset everywhere; the workflow skips the delivery step. |
| HubSpot, Inc. | `crates/corelink-enterprise-inquiry/src/hubspot.rs` | `HUBSPOT_PRIVATE_APP_TOKEN` is unset; the client is not mounted as a route or a dependency of `corelink-container`. |
| Twilio, Inc. (SendGrid + Twilio SMS) | None found | `SENDGRID_API_KEY` is unset everywhere and there is no code consumer at all; the live transactional-email path is Resend (above), not Twilio/SendGrid. |

## Non-customer-data (supply-chain only — not counted as a sub-processor)

| Vendor | Role | Why it is not a customer-data sub-processor |
|---|---|---|
| The Linux Foundation (Sigstore) | Release signing + Rekor transparency for **CoreLink's own build artifacts** (the former OCI lane was removed; release-chain use remains separately gated) | Current release-SLSA, CAS, and TSA paths send only CoreLink-owned artifact/signing metadata; no customer-data path is wired. The separate transparency-log seam is not a live transport; any future pseudonymous-tenant use requires a new Legal/DPO review. Sigstore is not a customer-data sub-processor in the current register; the separate GDPR transfer table remains subject to Legal/DPO review. |

## Notification Policy

**All 5 canonical plans** (free/solo/team/business/enterprise) receive mandatory
sub-processor change notifications. This notification is based on **legal_obligation**
basis (privacy_model.md §5.6.1) — NOT opt-out-able via consent_revoke.

This corrects any prior tier-gated approach per **ADR-S11-008 v2** (Lote 10.11.0-bis):
GDPR Art. 28.2 + LGPD Art. 39 establish sub-processor transparency as a universal
right, NOT a premium feature.

## Change Process

1. Privacy Officer drafts the change in a single PR that updates **both** the
   internal source of truth `specs/_compliance/VENDOR-RISK-REGISTER.md` **and**
   this contractual disclosure file, keeping the two consistent.
2. Legal review per DPA + GDPR Art. 28.2 implications.
3. The sub-processors sync pipeline (`.github/workflows/subprocessors-sync.yml`)
   regenerates the public page from the register
   (`scripts/gen-public-subprocessors.py` → `apps/docs/docs/trust/subprocessors.mdx`)
   and the change-notify hook (`scripts/subprocessor-change-notify.py`):
   - Auto-generates the public `/trust/subprocessors` page (drift-gated; the PR
     fails if the page is stale relative to the register).
   - Emits `dev.hugr.corelink.sub_processor.{published|changed}.v1` CloudEvent.
   - Seeds `sub_processor_broadcast_log` D1 table.
4. 30-day advance notice email broadcast to all subscribed customers (DKIM signed).
5. Customer may object via `POST /v1/privacy/sub-processor-objection`.
6. Privacy Officer + Legal review ≤ 14 days → accept-or-terminate decision.

**Note**: 30d countdown = calendar days (not business days), per EDPB 7/2020 §125 industry standard.
