/**
 * Trust Center — five-quadrant deep-dive at `/trust/center`.
 *
 * Wave-29 stream-8 deliverable, relocated from `/trust` to `/trust/center`
 * in the Phase-0 launch-readiness sweep (2026-05-27). The shorter `/trust`
 * route now serves the charter-aligned security-controls summary
 * (`src/pages/trust.tsx`) that auditors and procurement linked from
 * outbound RFP responses tend to expect on first hit. This quadrant page
 * remains the canonical detailed entry, linked from `/trust` and from the
 * security / procurement footer columns.
 *
 * Legacy long-form trust page lives at `/trust/overview`
 * (`docs/trust/index.mdx`) for procurement / DPO single-page printable.
 *
 * Honest pre-GA framing rules (CRITICAL — see consolidation audit
 * `specs/_audits/sealed/2026-05-16-trust-center-consolidation.md` §C2):
 *
 *   - LIVE-ATTESTATION → the artefact exists, is current, and is binding
 *     on CoreLink (e.g. SAQ-A self-attestation, LGPD ROPA, sub-processor
 *     register, status page, security.txt).
 *   - IN-AUDIT → independent verification is engaged but not yet complete
 *     (e.g. SOC 2 Type I report being drafted, ISO 27001 Stage-1 prep).
 *   - PRE-GA-BLOCKER → a hard launch condition with no supporting evidence
 *     yet. The external pentest belongs here: no firm is engaged and no RFP
 *     has been sent, while CAP-GA-002 remains a hard pre-GA gate.
 *   - POST-GA → roadmap item not yet started or only internally scoped
 *     (e.g. SOC 2 Type II 6-month observation window, ISO 27001 Stage-2
 *     surveillance audit, FedRAMP sponsorship path).
 *
 * Per `docs/internal/security-readiness.md` §3 and the wave-25 pre-GA
 * security attestation (`specs/_audits/sealed/2026-05-16-pre-ga-security-attestation.md`),
 * we MUST NOT claim certifications not yet achieved. SOC 2 Type II is
 * IN-AUDIT (window started 2026-05-15), not "certified".
 *
 * Component design:
 *   - Five quadrants: Compliance, Security, Privacy, Reliability, Operations.
 *   - Each quadrant: 3–5 cards linking to existing trust pages (Docusaurus
 *     docs at `/trust/<slug>` or React pages at `/trust/<slug>`).
 *   - Status badges (LIVE / IN-AUDIT / POST-GA / PRE-GA-BLOCKER) on every
 *     compliance claim.
 *   - Footer: security@humangr.com contact + report-security policy link.
 *
 * i18n: copy is wrapped in `<Translate>` so the 4 locales (en-US default,
 * pt-BR, es-419, de) pick up `i18n/<locale>/code.json` overrides.
 */

import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import Translate from "@docusaurus/Translate";
import type { ReactElement, ReactNode } from "react";

type ClaimStatus = "LIVE" | "IN-AUDIT" | "POST-GA" | "PRE-GA-BLOCKER";

interface TrustCard {
  readonly title: string;
  readonly href: string;
  readonly status: ClaimStatus;
  readonly summary: string;
}

interface TrustQuadrant {
  readonly id: string;
  readonly title: string;
  readonly intro: string;
  readonly cards: readonly TrustCard[];
}

const STATUS_LABELS: Record<ClaimStatus, string> = {
  LIVE: "LIVE-ATTESTATION",
  "IN-AUDIT": "IN-AUDIT",
  "POST-GA": "POST-GA",
  "PRE-GA-BLOCKER": "PRE-GA BLOCKER",
};

const STATUS_COLORS: Record<ClaimStatus, { bg: string; fg: string; border: string }> = {
  LIVE: { bg: "#dcfce7", fg: "#14532d", border: "#16a34a" },
  "IN-AUDIT": { bg: "#fef3c7", fg: "#7c2d12", border: "#b45309" },
  "POST-GA": { bg: "#e0e7ff", fg: "#1e3a8a", border: "#3730a3" },
  "PRE-GA-BLOCKER": { bg: "#fee2e2", fg: "#7f1d1d", border: "#b91c1c" },
};

const QUADRANTS: readonly TrustQuadrant[] = [
  {
    id: "compliance",
    title: "Compliance",
    intro:
      "Frameworks we are evaluated against and the attestation evidence we can hand to your auditor today.",
    cards: [
      {
        title: "SOC 2 Type I + Type II",
        href: "/trust/compliance#soc-2",
        status: "IN-AUDIT",
        summary:
          "Type I observation window opened 2026-05-15 with Drata; Type II requires 6-month continuous-operation evidence. We do not claim 'SOC 2 certified' pre-GA.",
      },
      {
        title: "ISO 27001:2022",
        href: "/trust/iso27001",
        status: "IN-AUDIT",
        summary:
          "Annex A coverage 98.9% (SoA 2026-05-15); Stage-1 prep in flight, Stage-2 certifier audit target Q1-2027.",
      },
      {
        title: "PCI DSS — SAQ-A",
        href: "/trust/pci-dss",
        status: "LIVE",
        summary:
          "Self-attested SAQ-A 2026-05-15. CoreLink never sees card data (Stripe Elements tokenizes in-browser).",
      },
      {
        title: "FedRAMP Moderate posture",
        href: "/trust/fedramp-info",
        status: "POST-GA",
        summary:
          "Not pursued today. ~85% Moderate baseline already covered by SOC 2 + ISO 27001 crosswalk. Sponsorship path documented for federal customers.",
      },
      {
        title: "GDPR, LGPD, CCPA",
        href: "/trust/compliance#privacy-frameworks",
        status: "LIVE",
        summary:
          "GDPR Art. 28 + 32 DPA available; LGPD ROPA + residency attestation 2026-05-15; CCPA disclosures live.",
      },
    ],
  },
  {
    id: "security",
    title: "Security",
    intro:
      "How we protect customer data in flight, at rest, and across the supply chain.",
    cards: [
      {
        title: "Encryption — TLS 1.2+ and AES-256-GCM",
        href: "/trust/data-handling#encryption",
        status: "LIVE",
        summary:
          "All customer payloads encrypted in transit (TLS 1.2 floor, 1.3 negotiated) and at rest (AES-256-GCM via Cloudflare R2 platform encryption).",
      },
      {
        title: "BYOK envelope encryption",
        href: "/security/byok",
        status: "POST-GA",
        summary:
          "The shipping production build links no real KMS provider: it resolves to an in-memory placeholder (doc-marked not for production), and the activation endpoint fails closed rather than flip a tenant to BYOK on it. Four-provider wiring (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault) is designed but not yet built into the production binary.",
      },
      {
        title: "Audit chain — hash-chained events",
        href: "/security/audit-chain",
        status: "POST-GA",
        summary:
          "Each audit event is BLAKE3 hash-linked to the previous one with a verifiable inclusion proof, and that primitive is live. The durable side is not: the wired sink is in-memory (lost on process restart, not shared across containers), and R2 persistence, the scheduled verify cron, SIEM fan-out, and 7-year Object Lock retention are all deferred.",
      },
      {
        title: "Vulnerability disclosure (VDP)",
        href: "/security/policy",
        status: "LIVE",
        summary:
          "Coordinated VDP with safe-harbor, 90-day disclosure window, severity matrix, and PGP-encrypted intake — see report-security policy.",
      },
      {
        title: "External pentest — hard pre-GA blocker",
        href: "/trust/compliance#pentest",
        status: "PRE-GA-BLOCKER",
        summary:
          "No external penetration test has been commissioned and no RFP has been sent — every vendor in reports/pentest-rfp-tracker.json is NOT_CONTACTED. CAP-GA-002 requires an external report and retest with no outstanding HIGH or CRITICAL findings before GA. Assurance today is internal: TLA+ invariants gated in CI, CodeQL / cargo-audit / semgrep / trivy scanning, sealed cargo-fuzz summaries, and internal adversarial review waves.",
      },
    ],
  },
  {
    id: "privacy",
    title: "Privacy",
    intro:
      "Who we share data with, where it lives, and how data-subject rights are honoured.",
    cards: [
      {
        title: "Sub-processor register",
        href: "/trust/sub-processor-register",
        status: "LIVE",
        summary:
          "Public list with links to each vendor's terms and DPA; 30-day advance-notice mechanism per DPA §6 / LGPD Art. 27 §4º / GDPR Art. 28 §2.",
      },
      {
        title: "Data residency — BR / US / EU",
        href: "/trust/data-handling#residency",
        status: "LIVE",
        summary:
          "Per-tenant primary-region pin; LGPD residency attestation 2026-05-15.",
      },
      {
        title: "GDPR SCCs + Art. 28 DPA",
        href: "/trust/compliance#gdpr",
        status: "LIVE",
        summary:
          "Customer DPA v1.0.0 offered at sign-up; each sub-processor is engaged on its own DPA, linked from the sub-processor list. No separate transfer impact assessment is recorded.",
      },
      {
        title: "DPO appointment + contact",
        href: "/trust/data-handling#dpo",
        status: "LIVE",
        summary:
          "DPO appointed 2026-05-15 per LGPD Art. 41 + GDPR Art. 37; privacy@humangr.com for all data-subject requests.",
      },
      {
        title: "Data Subject Access Request (DSAR) flow",
        href: "/trust/data-handling#dsar",
        status: "LIVE",
        summary:
          "30-day response SLA per GDPR Art. 12 + LGPD Art. 19; tenant-admin self-service export + delete endpoints.",
      },
    ],
  },
  {
    id: "reliability",
    title: "Reliability",
    intro:
      "How we measure, expose, and protect uptime — and what we owe you when it slips.",
    cards: [
      {
        title: "Status page + uptime history",
        href: "https://hugrl.betteruptime.com",
        status: "LIVE",
        summary:
          "RSS / email / SMS / webhook subscription. Live incident timeline, scheduled maintenance, and sub-processor change broadcasts.",
      },
      {
        title: "Service-Level Agreement (SLA)",
        href: "/legal/terms",
        status: "LIVE",
        summary:
          "99.95% monthly uptime (Pro+); service-credit schedule; reporting cadence; root-cause publication commitment.",
      },
      {
        title: "Incident response — 72h breach SLA",
        href: "/trust/incident-response",
        status: "LIVE",
        summary:
          "Severity matrix, on-call rotation, customer-notification commitments, and tabletop cadence (quarterly).",
      },
      {
        title: "Incident history + postmortems",
        href: "/trust/incident-history",
        status: "POST-GA",
        summary:
          "Public postmortem corpus — pre-populated with the wave-24 cold-restore drill and the wave-25 failover drill once redacted. Real-incident wire T+30d post-GA.",
      },
      {
        title: "BCP / DR — drill cadence",
        href: "/trust/compliance#bcp-dr",
        status: "LIVE",
        summary:
          "Cold-restore + active failover drills on a quarterly cadence; evidence stored in `specs/_compliance/drill-evidence/`.",
      },
    ],
  },
  {
    id: "operations",
    title: "Operations",
    intro:
      "How we run the service day-to-day, and how you stay informed.",
    cards: [
      {
        title: "Pre-GA security attestation pack",
        href: "mailto:trust@humangr.com",
        status: "LIVE",
        summary:
          "Day-1 evidence pack for pentest vendors + GA sign-off — consolidated security posture across 8 waves of adversarial review. Available on request from trust@humangr.com.",
      },
      {
        title: "RFC 9116 security.txt",
        href: "/.well-known/security.txt",
        status: "LIVE",
        summary:
          "Canonical machine-readable security-contact card with PGP fingerprint, disclosure policy URL, and preferred languages.",
      },
      {
        title: "Pre-sales legal toolkit",
        href: "/trust/overview#pre-sales",
        status: "LIVE",
        summary:
          "SIG Lite (5 BDs), CAIQ v4 (7 BDs), and custom vendor questionnaires (3–10 BDs depending on size) under NDA.",
      },
      {
        title: "Customer audit-log export",
        href: "/security/audit-chain#export",
        status: "POST-GA",
        summary:
          "The export route and its audit sink are wired to in-memory implementations today: exported data is lost on process restart and is not shared across containers. The durable, R2-backed exporter tenant admins would use for a self-service CSV / NDJSON / Parquet export is not yet wired.",
      },
      {
        title: "Trust Center deep-dive overview",
        href: "/trust/overview",
        status: "LIVE",
        summary:
          "Long-form deep-dive page (legacy `docs/trust/index.mdx`, now at `/trust/overview`) — kept for auditors who want a single-page printable.",
      },
    ],
  },
];

function StatusBadge({ status }: { readonly status: ClaimStatus }): ReactElement {
  const { bg, fg, border } = STATUS_COLORS[status];
  return (
    <span
      aria-label={`Compliance claim status: ${STATUS_LABELS[status]}`}
      style={{
        display: "inline-block",
        padding: "0.125rem 0.5rem",
        background: bg,
        color: fg,
        border: `1px solid ${border}`,
        borderRadius: "4px",
        fontSize: "0.75rem",
        fontWeight: 700,
        letterSpacing: "0.02em",
        textTransform: "uppercase",
      }}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}

function QuadrantCard({ card }: { readonly card: TrustCard }): ReactElement {
  const external = card.href.startsWith("http") || card.href.startsWith("/.well-known");
  const cardBody = (
    <>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "0.75rem",
          marginBottom: "0.25rem",
        }}
      >
        <h3 style={{ margin: 0, fontSize: "1rem" }}>{card.title}</h3>
        <StatusBadge status={card.status} />
      </div>
      <p>{card.summary}</p>
    </>
  );
  if (external) {
    return (
      <a
        className="u-card"
        href={card.href}
        rel="noopener noreferrer"
        target={card.href.startsWith("http") ? "_blank" : undefined}
      >
        {cardBody}
      </a>
    );
  }
  return (
    <Link className="u-card" to={card.href}>
      {cardBody}
    </Link>
  );
}

function Quadrant({ quadrant }: { readonly quadrant: TrustQuadrant }): ReactElement {
  return (
    <section aria-labelledby={`q-${quadrant.id}`} style={{ marginTop: "2rem" }}>
      <h2 id={`q-${quadrant.id}`} style={{ marginBottom: "0.25rem" }}>
        {quadrant.title}
      </h2>
      <p className="u-muted" style={{ marginTop: 0 }}>
        {quadrant.intro}
      </p>
      <div className="u-grid u-grid-3" style={{ marginTop: "1rem" }}>
        {quadrant.cards.map((card) => (
          <QuadrantCard key={`${quadrant.id}-${card.href}`} card={card} />
        ))}
      </div>
    </section>
  );
}

function LegendItem({
  status,
  description,
}: {
  readonly status: ClaimStatus;
  readonly description: ReactNode;
}): ReactElement {
  return (
    <li style={{ marginBottom: "0.5rem" }}>
      <StatusBadge status={status} />{" "}
      <span style={{ marginLeft: "0.5rem" }}>{description}</span>
    </li>
  );
}

export default function TrustCenter(): ReactElement {
  return (
    <Layout
      title="Trust Center"
      description="CoreLink Trust Center — compliance posture, security controls, privacy commitments, reliability evidence, and operational transparency in one consolidated page."
    >
      <main
        className="container margin-top--lg margin-bottom--xl"
        style={{ maxWidth: "1100px" }}
      >
        <header>
          <h1 style={{ marginBottom: "0.5rem" }}>
            <Translate
              id="trust.landing.headline"
              description="Trust Center landing page headline"
            >
              Security, compliance, and operational transparency
            </Translate>
          </h1>
          <p className="u-muted" style={{ fontSize: "1.1rem", maxWidth: "780px" }}>
            <Translate
              id="trust.landing.subhead"
              description="Trust Center landing page subheadline"
            >
              CoreLink is a multi-tenant content-addressable cache that sees
              customer build artefacts, signed audit events, and (optionally)
              customer-managed key material. This page is the single public
              entry into how we secure that surface — compliance posture,
              security controls, privacy commitments, reliability evidence,
              and the operational mechanics that hold the whole stack
              together.
            </Translate>
          </p>
        </header>

        <aside
          role="note"
          aria-labelledby="legend-heading"
          style={{
            marginTop: "1.5rem",
            padding: "1rem 1.25rem",
            border: "1px solid var(--ifm-color-emphasis-300)",
            borderRadius: "8px",
            background: "var(--ifm-background-surface-color)",
          }}
        >
          <h2 id="legend-heading" style={{ fontSize: "1rem", margin: 0 }}>
            <Translate
              id="trust.landing.legend.title"
              description="Status badge legend section title"
            >
              How to read this page
            </Translate>
          </h2>
          <p style={{ marginTop: "0.5rem", marginBottom: "0.75rem" }}>
            <Translate
              id="trust.landing.legend.intro"
              description="Status badge legend intro paragraph"
            >
              Every compliance claim below is tagged with one of four
              honesty badges. We do not claim certifications we have not yet
              achieved. SOC 2 Type II is IN-AUDIT (observation window opened
              2026-05-15), not "certified".
            </Translate>
          </p>
          <ul style={{ margin: 0, paddingLeft: "1rem", listStyle: "none" }}>
            <LegendItem
              status="LIVE"
              description={
                <Translate
                  id="trust.landing.legend.live"
                  description="LIVE-ATTESTATION badge meaning"
                >
                  The artefact exists, is current, and is contractually
                  binding on CoreLink (e.g. SAQ-A self-attestation, LGPD
                  ROPA, sub-processor register, status page, security.txt).
                </Translate>
              }
            />
            <LegendItem
              status="PRE-GA-BLOCKER"
              description={
                <Translate
                  id="trust.landing.legend.pregaBlocker"
                  description="PRE-GA-BLOCKER badge meaning"
                >
                  A hard pre-GA condition lacks its required evidence. GA
                  remains blocked until CAP-GA-002 has an external report and
                  retest with no outstanding HIGH or CRITICAL findings.
                </Translate>
              }
            />
            <LegendItem
              status="IN-AUDIT"
              description={
                <Translate
                  id="trust.landing.legend.inaudit"
                  description="IN-AUDIT badge meaning"
                >
                  Independent verification is engaged but not yet complete
                  (e.g. SOC 2 Type I report being drafted, ISO 27001 Stage-1
                  prep).
                </Translate>
              }
            />
            <LegendItem
              status="POST-GA"
              description={
                <Translate
                  id="trust.landing.legend.postga"
                  description="POST-GA badge meaning"
                >
                  Roadmap item not yet started or only internally scoped
                  (e.g. SOC 2 Type II 6-month observation window,
                  ISO 27001 Stage-2 surveillance audit, FedRAMP sponsorship
                  path).
                </Translate>
              }
            />
          </ul>
        </aside>

        {QUADRANTS.map((q) => (
          <Quadrant key={q.id} quadrant={q} />
        ))}

        <footer
          style={{
            marginTop: "3rem",
            padding: "1.5rem",
            border: "1px solid var(--ifm-color-emphasis-300)",
            borderRadius: "8px",
            background: "var(--ifm-background-surface-color)",
          }}
        >
          <h2 style={{ marginTop: 0 }}>
            <Translate
              id="trust.landing.contact.title"
              description="Contact section title"
            >
              Talk to us
            </Translate>
          </h2>
          <p>
            <Translate
              id="trust.landing.contact.body"
              description="Contact section body"
            >
              For procurement, compliance, or vendor-risk questions, email
            </Translate>{" "}
            <a href="mailto:security@humangr.com">security@humangr.com</a>.{" "}
            <Translate
              id="trust.landing.contact.privacy"
              description="Contact privacy line"
            >
              For data-subject access requests and DPA / SCC execution, email
            </Translate>{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>.
          </p>
          <p>
            <Translate
              id="trust.landing.contact.disclosure"
              description="Security disclosure pointer"
            >
              To report a security vulnerability, please follow our
            </Translate>{" "}
            <Link to="/security/policy">
              <Translate
                id="trust.landing.contact.disclosure.linktext"
                description="Security disclosure link text"
              >
                coordinated disclosure policy
              </Translate>
            </Link>{" "}
            <Translate
              id="trust.landing.contact.disclosure.suffix"
              description="Security disclosure suffix"
            >
              (PGP-encrypted intake, 90-day disclosure window, safe-harbor).
            </Translate>
          </p>
        </footer>
      </main>
    </Layout>
  );
}
