/**
 * Sub-processor register — public list at `/trust/sub-processor-register`.
 *
 * Wave-29 stream-8 deliverable, paired with the generated
 * `docs/trust/subprocessors.mdx` MDX page at `/trust/subprocessors`.
 *
 * Rows are rendered from `apps/admin-ui/src/content/sub-processors.json`, the
 * same data the `/legal/sub-processors` page and the admin-ui page render, so
 * the three cannot list different vendors or links. Each vendor is engaged on
 * its own standard terms and DPA (B-316 owner re-charter, #2593); no
 * acceptance dates are shown because none were recorded.
 * `scripts/verify_b316_pending_vendor_reviews.py` checks that the JSON, the
 * generated MDX page, `legal/sub-processors.md` and
 * `specs/_compliance/VENDOR-RISK-REGISTER.md` agree.
 *
 * 30-day notice mechanism: see DPA §6 / LGPD Art. 27 §4º / GDPR Art. 28 §2.
 */

import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import Translate from "@docusaurus/Translate";
import type { ReactElement } from "react";

import subProcessorsData from "../../../../admin-ui/src/content/sub-processors.json";

interface SubProcessor {
  readonly id: string;
  readonly name: string;
  readonly role: string;
  readonly region: string;
  readonly certifications: readonly string[];
  readonly terms_url: string;
  readonly dpa_url: string;
}

interface SubProcessorList {
  readonly version: string;
  readonly items: readonly SubProcessor[];
}

const { version: LAST_REFRESHED, items: ACTIVE_SUB_PROCESSORS } =
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

function SubProcessorRow({
  sp,
  num,
}: {
  readonly sp: SubProcessor;
  readonly num: number;
}): ReactElement {
  return (
    <tr>
      <td>{num}</td>
      <td>
        <strong>{sp.name}</strong>
      </td>
      <td>{sp.role}</td>
      <td>{sp.region}</td>
      <td>
        <VendorLink href={sp.terms_url} label="Terms" />
      </td>
      <td>
        <VendorLink href={sp.dpa_url} label="DPA" />
      </td>
    </tr>
  );
}

export default function SubProcessorRegister(): ReactElement {
  return (
    <Layout
      title="Sub-processor register"
      description="CoreLink public sub-processor register — the vendors that process customer personal data on CoreLink's behalf, with links to each vendor's terms and DPA. 30-day advance-notice mechanism per GDPR Art. 28 / LGPD Art. 27 §4º."
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
            Each sub-processor below is engaged on its own standard terms and
            data processing agreement (DPA), linked in the table. CoreLink
            accepted them online when it created each account; the acceptance
            dates were not recorded, so none are shown.
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
              (the full vendor register is internal; only the vendors that
              process customer personal data on CoreLink's behalf appear
              below, each with links to its own terms and DPA). Available on
              request from trust@humangr.com.
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
              data.
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
                  <th>Region(s)</th>
                  <th>Terms</th>
                  <th>DPA</th>
                </tr>
              </thead>
              <tbody>
                {ACTIVE_SUB_PROCESSORS.map((sp, index) => (
                  <SubProcessorRow key={sp.id} sp={sp} num={index + 1} />
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
