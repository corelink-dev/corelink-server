/**
 * Public sub-processors page — Phase 0 §A `LEGAL-FOOTER-WIRE` deliverable,
 * reconciled 2026-05-27 against actual first-party wiring evidence.
 *
 * Source of truth: `apps/admin-ui/src/content/sub-processors.json` — the
 * table below is rendered from it, so this page, the admin-ui page and the
 * trust register cannot list different vendors or links. Each vendor is
 * engaged on its own standard terms and DPA (B-316 owner re-charter, #2593);
 * no acceptance dates are shown because none were recorded.
 * Audit cross-reference: `specs/_audits/2026-05-27-sub-processors-finalization.md`
 *
 * Vendor inventory verified by grep against:
 *   Cloudflare  — wrangler.toml (5 locations)
 *   Clerk       — apps/admin-ui/middleware.ts + sign-up page
 *   Stripe      — apps/admin-ui/src/app/api/checkout/session/route.ts
 *   Resend      — apps/admin-ui/src/app/api/newsletter/subscribe/route.ts
 *               + apps/analytics-worker/wrangler.toml (weekly digest)
 *   Sentry      — apps/admin-ui/sentry.{server,client,edge}.config.ts
 *   Plausible   — apps/docs/docusaurus.config.ts
 *   BetterStack — apps/docs/src/components/StatusPill/StatusPill.tsx
 *   GitHub      — .github/workflows/ (5+ workflow files)
 *   PostHog     — NOT wired; removed from active list.
 */

import Layout from "@theme/Layout";
import type { ReactElement } from "react";

import subProcessorsData from "../../../../admin-ui/src/content/sub-processors.json";

import styles from "./legal.module.css";

const PRIVACY_EMAIL = "privacy@humangr.com";

interface SubProcessor {
  id: string;
  name: string;
  role: string;
  region: string;
  certifications: string[];
  terms_url: string;
  dpa_url: string;
}

interface SubProcessorList {
  version: string;
  items: SubProcessor[];
}

const subProcessors: SubProcessorList =
  subProcessorsData as SubProcessorList;

// A vendor page that could not be confirmed is published as the literal
// "link pending" (never a guessed URL); render it as text, not a link.
function VendorLink({
  href,
  label,
}: {
  readonly href: string;
  readonly label: string;
}): ReactElement {
  if (!href.startsWith("https://")) return <span>{href}</span>;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  );
}

export default function SubProcessorsPage(): ReactElement {
  const { version, items } = subProcessors;

  return (
    <Layout
      title="Sub-processors"
      description="CoreLink sub-processors: third-party service providers that process customer personal data on behalf of HuGR Labs, with regions, certifications, and links to each vendor's terms and DPA."
    >
      <main className={styles.page}>
        <header className={styles.header}>
          <h1>Sub-processors</h1>
          <p className={styles.meta}>
            Version <code>{version}</code> &middot; Last updated{" "}
            <time dateTime={version}>{version}</time> &middot; Source:{" "}
            <code>apps/admin-ui/src/content/sub-processors.json</code>
          </p>
        </header>

        {/* ── Notification commitment ── */}
        <section className={styles.section}>
          <p>
            HuGR Labs will notify customers at least{" "}
            <strong>30 days before any new sub-processor</strong> begins
            processing customer personal data, and before any existing
            sub-processor materially changes its processing role, region, or
            own sub-processor list. Notices are sent by email to the account
            owner of record. To have them sent to an additional address
            (security team, DPO, procurement), email{" "}
            <a href={`mailto:${PRIVACY_EMAIL}`}>{PRIVACY_EMAIL}</a> with
            subject &ldquo;Sub-processor notice subscription&rdquo; and include
            your tenant identifier. There is no notice setting in the product
            and no automated notice delivery yet; each notice is sent
            individually.
          </p>
          <p>
            CoreLink&rsquo;s own data processing agreement with its customers
            is a separate document; request a copy at{" "}
            <a href="mailto:legal@humangr.com">legal@humangr.com</a>.
          </p>
        </section>

        {/* ── Active sub-processor table ── */}
        <section className={styles.section}>
          <h2>Active sub-processors</h2>
          <p>
            These providers are currently wired and may process customer
            personal data on behalf of HuGR Labs. Each is engaged on its own
            standard terms and data processing agreement (DPA), linked in the
            table; HuGR Labs accepted them online when it created each account.
            The acceptance dates were not recorded, so none are shown.
          </p>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col">Sub-processor</th>
                <th scope="col">Service</th>
                <th scope="col">Region</th>
                <th scope="col">Certifications</th>
                <th scope="col">Terms</th>
                <th scope="col">DPA</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>
                    <strong>{item.name}</strong>
                  </td>
                  <td>{item.role}</td>
                  <td>{item.region}</td>
                  <td>{item.certifications.join(" · ")}</td>
                  <td>
                    <VendorLink href={item.terms_url} label="Terms" />
                  </td>
                  <td>
                    <VendorLink href={item.dpa_url} label="DPA" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* ── Transfer mechanisms ── */}
        <section className={styles.section}>
          <h2>Transfer mechanisms in force</h2>
          <p>
            Every cross-border transfer of personal data is supported by one of
            the mechanisms below, documented per-vendor in the CoreLink Records
            of Processing Activities (ROPA):
          </p>
          <ul>
            <li>
              <strong>EU–US Data Privacy Framework (DPF):</strong> active for
              Cloudflare, Clerk, Stripe (US entity), and GitHub. Adequacy
              decision of 10 July 2023 (Commission Implementing Decision (EU)
              2023/1795). DPF withdrawal triggers automatic SCC fallback already
              contractually in place.
            </li>
            <li>
              <strong>Standard Contractual Clauses (SCC):</strong> EU
              Commission Implementing Decision 2021/914, Modules 2 and 3,
              backstops every US-bound transfer, as incorporated in each
              vendor&rsquo;s DPA linked above. HuGR Labs has not recorded a
              separate Schrems II Transfer Impact Assessment per vendor.
            </li>
            <li>
              <strong>UK International Data Transfer Addendum:</strong> ICO
              Addendum (in force from 21 March 2022) layers onto EU SCCs for
              UK-originated transfers.
            </li>
            <li>
              <strong>LGPD transfer mechanism (Art. 33):</strong> ANPD
              Resolução CD/ANPD nº 19/2024 SCCs, executed as an integrated
              annex to the CoreLink DPA.
            </li>
          </ul>
        </section>

        {/* ── Change notification policy ── */}
        <section className={styles.section}>
          <h2>Change notification policy</h2>
          <p>
            CoreLink commits to a <strong>30-day prior notice</strong> before
            any new sub-processor begins processing customer personal data, and
            before a sub-processor materially changes its processing role,
            region, or sub-sub-processor list (GDPR Art. 28(2) compliant, per
            DPA §16). Notices are sent by email to the account owner of record
            and to any additional address registered by writing to{" "}
            <a href={`mailto:${PRIVACY_EMAIL}`}>{PRIVACY_EMAIL}</a>.
          </p>
          <p>
            You have the right to object to a new sub-processor on reasonable
            grounds. If unresolved within 30 days, you may terminate the
            affected portion of the Service with a pro-rated refund of
            pre-paid unused fees (Terms §10).
          </p>
        </section>

        {/* ── Audit and assistance rights ── */}
        <section className={styles.section}>
          <h2>Audit, assistance, and documentation rights</h2>
          <p>
            On reasonable written notice and subject to confidentiality
            commitments, CoreLink will make available (a) the third-party
            audit reports each active sub-processor publishes or shares with
            its customers, (b) the vendor DPA that applies to each
            sub-processor (linked above), (c) relevant ROPA sections, and (d)
            annual pen-test executive summaries. CoreLink also provides assistance with
            controller-side DPIA (GDPR Art. 35) and ANPD Relatório de Impacto
            (LGPD Art. 38) obligations.
          </p>
        </section>

        <p className={styles.footnote}>
          See also:{" "}
          <a href="/legal/privacy">Privacy Notice</a> &middot;{" "}
          <a href="/legal/terms">Terms of Service</a> &middot;{" "}
          <a href="mailto:legal@humangr.com">
            Data Processing Addendum (on request)
          </a>
          {" "}&middot;{" "}
          <a href={`mailto:${PRIVACY_EMAIL}`}>
            Ask for prior versions of this list
          </a>
        </p>
      </main>
    </Layout>
  );
}
