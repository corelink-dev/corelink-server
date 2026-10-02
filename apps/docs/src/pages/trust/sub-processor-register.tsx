/**
 * Sub-processor register — public list at `/trust/sub-processor-register`.
 *
 * Wave-29 stream-8 deliverable, paired with the existing
 * `docs/trust/subprocessors.mdx` MDX page at `/trust/subprocessors`.
 *
 * Source of truth: `specs/_compliance/VENDOR-RISK-REGISTER.md` (full
 * 22-vendor register; only the 9 vendors that process customer personal
 * data on CoreLink's behalf appear in the public "Active sub-processors"
 * table).
 *
 * Refresh cadence: monthly (calendar reminder + drift-gate CI in
 * `.github/workflows/subprocessors-sync.yml` once wired post-GA). Until
 * the auto-generator (`scripts/gen-public-subprocessors.py`) ships, this
 * page is the hand-maintained mirror of the MDX page, structured for
 * easier React-side filtering by region and data class.
 *
 * 30-day notice mechanism: see DPA §6 / LGPD Art. 27 §4º / GDPR Art. 28 §2.
 */

import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import Translate from "@docusaurus/Translate";
import type { ReactElement } from "react";

const LAST_REFRESHED = "2026-08-24";

interface SubProcessor {
  readonly num: number;
  readonly vendor: string;
  readonly service: string;
  readonly dataClasses: readonly string[];
  readonly regions: string;
  readonly dpaHref: string;
  readonly dpaLabel: string;
}

const ACTIVE_SUB_PROCESSORS: readonly SubProcessor[] = [
  {
    num: 1,
    vendor: "Cloudflare, Inc.",
    service: "Workers / R2 / D1 / DO / KV / Pages / Email",
    dataClasses: ["metadata", "encrypted-blobs", "audit-logs", "telemetry"],
    regions: "R2/DO tenant-pinned; D1 control-plane metadata global under SCC/TIA safeguards",
    dpaHref: "https://www.cloudflare.com/cloudflare-customer-dpa/",
    dpaLabel: "Cloudflare DPA",
  },
  {
    num: 2,
    vendor: "Stripe, Inc.",
    service: "Payment processing + subscription billing + Stripe Atlas counsel",
    dataClasses: ["payment", "pii"],
    regions: "Multi-region (per tenant primary_region pin)",
    dpaHref: "https://stripe.com/legal/dpa",
    dpaLabel: "Stripe DPA",
  },
  {
    num: 3,
    vendor: "Clerk, Inc.",
    service: "Authentication + identity provider + JWT issuer",
    dataClasses: ["pii"],
    regions: "Multi-region (per tenant primary_region pin)",
    dpaHref: "mailto:privacy@humangr.com?subject=Clerk%20DPA%20request",
    dpaLabel: "Clerk DPA (on request)",
  },
  {
    num: 4,
    vendor: "PagerDuty, Inc.",
    service: "Incident management + on-call alerting (prod + synthetic-drill routes)",
    dataClasses: ["audit-logs", "metadata"],
    regions: "US / EU (selectable)",
    dpaHref: "https://www.pagerduty.com/security/",
    dpaLabel: "PagerDuty trust portal",
  },
  {
    num: 5,
    vendor: "GitHub, Inc. (Microsoft Enterprise)",
    service: "Source code repository + CI/CD pipeline + Actions secrets store",
    dataClasses: ["source code", "ci artifacts", "audit-logs"],
    regions: "US / EU (selectable)",
    dpaHref: "https://github.com/security",
    dpaLabel: "GitHub trust portal",
  },
  {
    num: 6,
    vendor: "Resend, Inc.",
    service: "Transactional email + newsletter-audience delivery",
    dataClasses: ["pii (recipient email address)"],
    regions: "Multi-region (per tenant primary_region pin)",
    dpaHref: "https://resend.com/legal/dpa",
    dpaLabel: "Resend DPA",
  },
  {
    num: 7,
    vendor: "Functional Software, Inc. (Sentry)",
    service: "Application error monitoring (admin-ui server/edge/client + docs-site build loader)",
    dataClasses: ["telemetry (scrubbed diagnostic events)"],
    regions: "US / EU (selectable)",
    dpaHref: "https://sentry.io/legal/dpa/",
    dpaLabel: "Sentry DPA",
  },
  {
    num: 8,
    vendor: "Plausible Insights OÜ (Plausible Analytics)",
    service: "Cookieless web analytics for the docs-site marketing funnel",
    dataClasses: ["telemetry (page-view aggregates only)"],
    regions: "US / EU (selectable)",
    dpaHref: "https://plausible.io/dpa",
    dpaLabel: "Plausible DPA",
  },
  {
    num: 9,
    vendor: "Better Stack, Inc. (BetterStack / Statuspage)",
    service:
      "Uptime and status monitoring: synthetic HTTP probes against CoreLink's own public endpoints, and the hosted status page",
    dataClasses: ["telemetry (probe results only; no customer data is sent)"],
    regions: "US / EU",
    dpaHref: "https://betterstack.com/privacy",
    dpaLabel: "Better Stack privacy policy",
  },
];

function SubProcessorRow({ sp }: { readonly sp: SubProcessor }): ReactElement {
  return (
    <tr>
      <td>{sp.num}</td>
      <td>
        <strong>{sp.vendor}</strong>
      </td>
      <td>{sp.service}</td>
      <td>
        {sp.dataClasses.map((c) => (
          <code
            key={`${sp.num}-${c}`}
            style={{
              display: "inline-block",
              marginRight: "0.25rem",
              padding: "0.05rem 0.35rem",
              background: "var(--ifm-color-emphasis-100)",
              borderRadius: "3px",
              fontSize: "0.8rem",
            }}
          >
            {c}
          </code>
        ))}
      </td>
      <td>{sp.regions}</td>
      <td>
        <a href={sp.dpaHref} rel="noopener noreferrer" target="_blank">
          {sp.dpaLabel}
        </a>
      </td>
    </tr>
  );
}

export default function SubProcessorRegister(): ReactElement {
  return (
    <Layout
      title="Sub-processor register"
      description="CoreLink public sub-processor register — 8 active vendors that process customer personal data on CoreLink's behalf. 30-day advance-notice mechanism per GDPR Art. 28 / LGPD Art. 27 §4º."
    >
      <main className="container margin-top--lg margin-bottom--xl" style={{ maxWidth: "1100px" }}>
        <header>
          <h1>
            <Translate
              id="trust.subprocessor.title"
              description="Sub-processor register page title"
            >
              Sub-processor register
            </Translate>
          </h1>
          <p className="u-muted">
            <Translate
              id="trust.subprocessor.subhead"
              description="Sub-processor register subheadline"
            >
              Public list of CoreLink sub-processors — the third parties that
              process customer personal data on our behalf. Maintained per
              GDPR Art. 28 §2 and LGPD Art. 39 + Art. 27 §4º.
            </Translate>
          </p>
          <p>
            <strong>
              <Translate
                id="trust.subprocessor.refreshed"
                description="Last refreshed label"
              >
                Last refreshed:
              </Translate>
            </strong>{" "}
            <code>{LAST_REFRESHED}</code>.{" "}
            <Translate
              id="trust.subprocessor.cadence"
              description="Refresh cadence note"
            >
              Refresh cadence: monthly, plus immediate update on any
              addition or replacement.
            </Translate>{" "}
            <Translate
              id="trust.subprocessor.source"
              description="Source-of-truth pointer"
            >
              Source of truth:
            </Translate>{" "}
            VENDOR-RISK-REGISTER.md{" "}
            <Translate
              id="trust.subprocessor.source.full"
              description="Source of truth size context"
            >
              (full 22-vendor register; only the 9 vendors that process
              customer personal data on CoreLink's behalf appear below).
              Available on request from trust@humangr.com.
            </Translate>
          </p>
        </header>

        <section aria-labelledby="notice-heading" style={{ marginTop: "1.5rem" }}>
          <h2 id="notice-heading">
            <Translate
              id="trust.subprocessor.notice.title"
              description="Notice section title"
            >
              30-day advance-notice mechanism
            </Translate>
          </h2>
          <p>
            <Translate
              id="trust.subprocessor.notice.body"
              description="Notice section body"
            >
              Per our DPA §6 and LGPD Art. 27 §4º + GDPR Art. 28 §2, we will
              give at least 30 calendar days' written notice before adding
              or replacing a sub-processor that processes customer personal
              data. Subscribe via tenant email digest, the status page, or
              the post-GA RSS feed.
            </Translate>
          </p>
          <ul>
            <li>
              <strong>Email digest</strong> — configure{" "}
              <code>subprocessor-changes@</code> in tenant settings.
            </li>
            <li>
              <strong>Status page</strong> —{" "}
              <a
                href="https://hugrl.betteruptime.com"
                rel="noopener noreferrer"
                target="_blank"
              >
                hugrl.betteruptime.com
              </a>{" "}
              carries service state only — subscriptions are switched off
              there, so it is not a sub-processor notification channel.
            </li>
            <li>
              <strong>RSS feed</strong> — not available; no sub-processor
              feed has been published.
            </li>
          </ul>
        </section>

        <section aria-labelledby="active-heading" style={{ marginTop: "2rem" }}>
          <h2 id="active-heading">
            <Translate
              id="trust.subprocessor.active.title"
              description="Active sub-processors section title"
              values={{ count: ACTIVE_SUB_PROCESSORS.length }}
            >
              {"Active sub-processors ({count})"}
            </Translate>
          </h2>
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Vendor</th>
                  <th>Service to CoreLink</th>
                  <th>Customer-data class</th>
                  <th>Region(s)</th>
                  <th>DPA</th>
                </tr>
              </thead>
              <tbody>
                {ACTIVE_SUB_PROCESSORS.map((sp) => (
                  <SubProcessorRow key={sp.num} sp={sp} />
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section style={{ marginTop: "2rem" }}>
          <h2>
            <Translate
              id="trust.subprocessor.related.title"
              description="Related section title"
            >
              Related
            </Translate>
          </h2>
          <ul>
            <li>
              <Link to="/trust">Trust Center</Link>
            </li>
            <li>
              <Link to="/trust/subprocessors">
                Long-form sub-processors page (DPA matrix + BYOK custodians + internal LLM tooling)
              </Link>
            </li>
            <li>
              <Link to="/trust/data-handling">Data handling</Link>
            </li>
            <li>
              <Link to="/trust/incident-response">Incident response</Link>
            </li>
          </ul>
        </section>
      </main>
    </Layout>
  );
}
