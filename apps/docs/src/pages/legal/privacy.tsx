/**
 * Public privacy page — Phase 0 §A `LEGAL-FOOTER-WIRE` deliverable.
 *
 * Mirrors the canonical content from `apps/admin-ui/src/content/privacy-notice.en.md`
 * (the single source of truth for end-user-facing privacy text) and adds a
 * controller-of-record block summarising the GDPR/LGPD regimes that govern
 * CoreLink processing. Deep technical detail (article-by-article DSR table,
 * 12-backend erasure pipeline, SCC/DPF transfer mechanisms) lives in the
 * Diátaxis explainers at `/explanation/privacy/gdpr` and
 * `/explanation/privacy/lgpd-full` — this public page links out rather than
 * duplicating, keeping the legal surface short enough for a non-specialist
 * reader to absorb in under two minutes.
 *
 * Charter note: shipped with the `subject to final legal review prior to GA`
 * banner per `specs/_audits/2026-05-27-phase-0-execution-plan.md` §2.A
 * hard-pause trigger (c). Termageddon ($119/yr, Phase 1) supersedes this
 * page when first enterprise contract negotiates.
 */

import Layout from "@theme/Layout";
import type { ReactElement } from "react";

import styles from "./legal.module.css";

const EFFECTIVE_DATE = "2026-05-27";
const VERSION = "1.0.0";

export default function PrivacyPage(): ReactElement {
  return (
    <Layout
      title="Privacy"
      description="CoreLink privacy notice: how CoreLink (HuGR Labs) collects, processes, and protects personal data under GDPR, LGPD, and US-state privacy statutes (CCPA/CPRA, VCDPA)."
    >
      <main className={styles.page}>
        <header className={styles.header}>
          <h1>Privacy Notice</h1>
          <p className={styles.meta}>
            Version {VERSION} · Effective {EFFECTIVE_DATE} · Maintained by HuGR
            Labs Privacy Team
          </p>
        </header>

        <p className={styles.draftNote} role="status">
          <strong>Subject to final legal review prior to GA.</strong> This
          notice is in force for the current pre-GA period and accurately
          describes how CoreLink processes data today. A counter-signed
          Termageddon-managed update lands before the first enterprise
          contract is executed; substantive changes will be announced at least
          30 days in advance via the in-app banner and the administrator email
          on file.
        </p>

        <p>
          CoreLink (&ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;) is
          a product operated by HuGR Labs. We process personal data on behalf
          of our customers (&ldquo;controllers&rdquo;) as a data{" "}
          <strong>processor</strong> under the EU General Data Protection
          Regulation (Regulation 2016/679 — GDPR), the Brazilian Lei Geral de
          Proteção de Dados (Lei 13.709/2018 — LGPD), and applicable
          state-level US privacy statutes (CCPA/CPRA, VCDPA, CPA, CTDPA,
          UCPA). This notice describes the categories of personal data we
          collect when you visit our public surfaces (this site, our marketing
          pages, the support portal) or use the CoreLink Admin UI as an end
          user of a customer tenant.
        </p>

        <section className={styles.section}>
          <h2>1. Controller of record</h2>
          <table className={styles.table}>
            <tbody>
              <tr>
                <th scope="row">Legal entity (current)</th>
                <td>HuGR Labs — sole-proprietorship of Gustavo Schneiter</td>
              </tr>
              <tr>
                <th scope="row">Legal entity (post-incorporation)</th>
                <td>
                  CoreLink, Inc. — Delaware C-corp, Stripe Atlas filing in
                  flight; the corporate successor inherits this notice with no
                  break in the data-protection chain.
                </td>
              </tr>
              <tr>
                <th scope="row">Privacy contact</th>
                <td>
                  <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>{" "}
                  (interim Data Protection Officer:{" "}
                  <a href="mailto:gustavo@humangr.com">gustavo@humangr.com</a>)
                </td>
              </tr>
              <tr>
                <th scope="row">EU representative (Art. 27)</th>
                <td>
                  Appointment in flight; published here before the first
                  EU-established Lighthouse customer goes live.
                </td>
              </tr>
              <tr>
                <th scope="row">Brazilian DPO (LGPD Art. 41)</th>
                <td>
                  Gustavo Schneiter (interim) —{" "}
                  <a href="mailto:dpo@humangr.com">dpo@humangr.com</a>
                </td>
              </tr>
            </tbody>
          </table>
        </section>

        <section className={styles.section}>
          <h2>2. Categories of personal data</h2>
          <ul>
            <li>
              <strong>Identity data:</strong> name, email address, organization
              affiliation, locale preference.
            </li>
            <li>
              <strong>Authentication data:</strong> hashed session tokens,
              OAuth/OIDC subject identifiers from your identity provider, MFA
              enrollment status.
            </li>
            <li>
              <strong>Usage telemetry:</strong> API endpoint, latency, response
              status, anonymized IP-network prefix (truncated to /24 for IPv4,
              /48 for IPv6).
            </li>
            <li>
              <strong>Support context:</strong> information you voluntarily
              disclose in support tickets.
            </li>
            <li>
              <strong>Customer tenant content (controller-owned):</strong> the
              blobs your tenant uploads to the content-addressable cache. We
              store the bytes, a content-addressable hash, and minimal
              metadata; we do <strong>not</strong> inspect the content. Where
              your blobs embed third-party personal data, you remain the
              controller and we act as your processor under our DPA.
            </li>
          </ul>
        </section>

        <section className={styles.section}>
          <h2>3. Purposes and legal bases</h2>
          <p>
            We process the categories above to (a) provide the Service under
            our contract with you or your organization (GDPR Art. 6(1)(b)
            / LGPD Art. 7-V); (b) comply with legal obligations such as
            financial-record retention and audit-log preservation (Art. 6(1)(c)
            / Art. 7-II); and (c) pursue our legitimate interest in
            maintaining product reliability and security (Art. 6(1)(f)
            / Art. 7-IX). Where consent is required, we collect it via the
            cookie banner and the Consent Management UI; consent can be
            withdrawn at any time with the same friction as granting.
          </p>
        </section>

        <section className={styles.section}>
          <h2>4. Retention</h2>
          <p>
            Personal data is retained only as long as needed for the purposes
            above. Default retention windows:
          </p>
          <ul>
            <li>Authentication logs — 90 days.</li>
            <li>
              Audit trail — 7 years (SOC 2 / SOX baseline; mandatory for
              processor-side accountability).
            </li>
            <li>Support tickets — 3 years from closure.</li>
            <li>
              Customer tenant content — for the duration of the tenant&rsquo;s
              subscription plus 30 calendar days of grace, after which a
              tombstone replay erases CAS, AC, audit-PII, and KV bindings.
            </li>
          </ul>
        </section>

        <section className={styles.section}>
          <h2>5. Your rights</h2>
          <p>
            You may exercise the rights of access, rectification, deletion,
            restriction, objection, and portability granted by GDPR Articles
            15–22, LGPD Articles 18–22, and analogous US-state statutes via
            the Data-Subject Request (DSR) flow in your account, or by
            emailing{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>. We
            respond within 30 calendar days (45 under CCPA, with one 45-day
            extension permitted under Cal. Civ. Code §1798.130; 15 working
            days under LGPD Art. 19(1)(II) for access requests where a
            simplified form is sufficient).
          </p>
          <p>
            Internally, DSRs are orchestrated by the{" "}
            <code>corelink_privacy::dsr</code> module: a request lands at
            the <code>POST /v1/privacy/dsr</code> endpoint of the Admin UI
            or the public Privacy Console, is authenticated against the
            Clerk session, escalates to a WebAuthn step-up for the three
            destructive verbs (erasure, restriction, objection), and is
            then dispatched to the rights orchestrator. The orchestrator
            evaluates a canonical list of 12 backend kinds
            (<code>BackendKind</code>), of which 4 have a real, shipped
            adapter and actually hold tenant data today — R2 CAS
            (content-addressable blobs), R2 Action Cache, D1 (metadata),
            and Stripe (billing PII, pseudonymized rather than deleted).
            The remaining 8 canonical kinds resolve to a truthful
            <code>not_applicable</code> outcome rather than a masked
            no-op, because no durable subject data exists there in the
            shipped system. The orchestrator signs an Ed25519 completion
            attestation over all 12 per-backend outcomes (consumed
            unchanged from{" "}
            <code>corelink_crypto::ed25519::attestation</code>). The signed
            report is delivered to you alongside a Markdown-formatted
            human summary.
          </p>
          <p>
            The full article-by-article SLA table, the WebAuthn step-up
            policy for destructive requests, and the backend-by-backend
            erasure detail live in the GDPR-rights and LGPD-rights
            explainers, which are still pending Legal and DPO sign-off and
            are therefore not published on this site yet. Until they are,
            request them from{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>.
          </p>
        </section>

        <section className={styles.section}>
          <h2>6. LGPD-specific provisions (Brazilian data subjects)</h2>
          <p>
            HuGR Labs is currently established in São Paulo, Brazil; the
            founder is a Brazilian national resident in Brazil. Processing
            of personal data of subjects located in Brazil is therefore
            governed by the LGPD (Lei 13.709/2018, in force since 18
            September 2020 and enforceable since 1 August 2021) regardless
            of the data subject&rsquo;s residency status. In addition to the
            rights enumerated above, the following LGPD-specific
            provisions apply:
          </p>
          <ul>
            <li>
              <strong>Legal basis (Art. 7):</strong> we rely primarily on
              Art. 7-V (execution of a contract or preliminary procedures
              relating to a contract to which the data subject is a party)
              and Art. 7-IX (legitimate interest, balanced against the
              fundamental rights and freedoms of the data subject and
              documented in a per-purpose LIA). Sensitive data (Art. 11)
              is not knowingly processed by CoreLink&rsquo;s telemetry
              path; if a controller chooses to upload sensitive payloads
              into the cache, the controller bears the Art. 11(1) legal
              basis and we act as processor under Art. 39.
            </li>
            <li>
              <strong>International transfers (Art. 33):</strong> transfers
              from Brazil are executed under the Brazilian standard
              contractual clauses published by ANPD via Resolução CD/ANPD
              nº 19/2024 (in force 23 August 2024), executed alongside the
              EU SCCs as a single integrated annex to the DPA. The Art. 33
              transparency obligation is met by the Sub-processors page
              and the per-vendor transfer-mechanism table.
            </li>
            <li>
              <strong>DPIA / Relatório de Impacto (Art. 38):</strong> the
              Authority may require a Data Protection Impact Assessment;
              CoreLink maintains an internal DPIA covering the cache
              ingest, authentication, and DSR-orchestration pipelines and
              will produce it to ANPD on request. The DPIA is reviewed at
              least annually and on each material change to processing.
            </li>
            <li>
              <strong>ANPD complaints (Art. 18 §1):</strong> Brazilian data
              subjects may submit complaints directly to the Autoridade
              Nacional de Proteção de Dados via{" "}
              <a
                href="https://www.gov.br/anpd/pt-br/canais_atendimento"
                rel="noopener noreferrer"
                target="_blank"
              >
                gov.br/anpd
              </a>
              . We will cooperate fully with any ANPD enquiry.
            </li>
            <li>
              <strong>DPO (Encarregado, Art. 41):</strong> Gustavo
              Schneiter holds the interim DPO appointment; the appointment
              is registered with ANPD and published at{" "}
              <a href="mailto:dpo@humangr.com">dpo@humangr.com</a>. A
              fractional senior privacy counsel is being engaged to assume
              the role before GA.
            </li>
            <li>
              <strong>Sandbox / Children (Art. 14):</strong> CoreLink is
              not directed at children and we do not knowingly process
              personal data of subjects under 18; the Service is targeted
              at developers and engineering organizations.
            </li>
          </ul>
        </section>

        <section className={styles.section}>
          <h2>7. Data residency, pseudonymization, and security</h2>
          <p>
            CoreLink supports per-tenant data-residency pinning from a
            closed set of macro regions. Four are currently provisioned
            with a jurisdiction-correct storage bucket and enforced at
            the request ingress by the <code>corelink_privacy::residency</code>{" "}
            module: <code>wnam</code> and <code>enam</code> (North
            America), <code>weur</code> (European Union — served from
            London), and <code>apac</code> (Asia-Pacific — served from
            Tokyo, provisioned 2026-08-17). A tenant pinned to one
            provisioned region cannot cross into another region's storage
            even if the originating client is elsewhere. Two further
            macro codes, <code>sam</code> (South America) and{" "}
            <code>afr</code> (Africa), exist in the region enum but have
            no provisioned storage bucket; signup rejects them today, so
            no tenant can be pinned there. Residency choices are recorded
            in the immutable ledger and surfaced in the Admin UI privacy
            console.
          </p>
          <p>
            Analytics and operational metrics are pseudonymized at source
            by <code>corelink_privacy::pseudonymize</code>: every subject
            identifier is keyed-HMAC-SHA-256 against a per-tenant secret
            held only inside the Worker isolate, with a{" "}
            <code>subtle::ConstantTimeEq</code> tag compare to defend
            against timing-side-channel correlation attacks. The
            pseudonymization key never leaves the isolate and is rotated
            on tenant lifecycle events; recovering the original subject
            identifier from a stored pseudonym requires possession of the
            tenant secret, which CoreLink does not have for customer
            Bring-Your-Own-Key tenants.
          </p>
          <p>
            All personal data is encrypted in transit (TLS 1.2 minimum,
            with TLS 1.3 negotiated by every client that supports it; HSTS
            preload on every public surface, certificate transparency
            monitored by Cloudflare). Data at rest is encrypted by the
            underlying Cloudflare R2 / D1 / KV / Durable-Object substrates
            with AES-256-GCM; Enterprise tenants may additionally opt into
            BYOK envelope encryption on top, where the data key is sealed
            by a customer-controlled key in Cloudflare&rsquo;s Key
            Management Service.
          </p>
        </section>

        <section className={styles.section}>
          <h2>8. Consent management</h2>
          <p>
            The Admin UI presents choices for optional analytics and
            marketing. Plausible loads there only when the analytics
            preference in your browser allows it. The public documentation
            site uses Plausible separately, as described below. For
            questions about consent or to request withdrawal, contact{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>.
          </p>
        </section>

        <section className={styles.section}>
          <h2>9. International transfers</h2>
          <p>
            CoreLink processes data on Cloudflare&rsquo;s network: R2 objects
            and Durable Object state follow the tenant&rsquo;s region, and the
            D1 control-plane database is shared and global. The other
            recipients are the sub-processors on the{" "}
            <a href="/legal/sub-processors">Sub-processors page</a>. Transfers
            from the EU/EEA to the US rely on the transfer terms in each
            recipient&rsquo;s own data processing agreement, such as the EU-US
            Data Privacy Framework (DPF) or Standard Contractual Clauses
            (Commission Implementing Decision 2021/914). CoreLink has not
            recorded a separate Schrems II Transfer Impact Assessment; ask{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a> for
            the current transfer details.
          </p>
        </section>

        <section className={styles.section}>
          <h2>10. Sub-processors</h2>
          <p>
            The current list of sub-processors and their regions is published
            on the <a href="/legal/sub-processors">Sub-processors page</a>.
            Material changes are announced at least 30 days in advance by
            email to the account owner of record.
          </p>
        </section>

        <section className={styles.section}>
          <h2>11. Cookies and analytics</h2>
          <p>
            The public documentation site loads a Plausible analytics
            script on its pages. The Admin UI's analytics preference does
            not control this documentation-site script. In the Admin UI,
            Plausible loads only when that preference allows it, as
            described above. We do not run cross-site tracking, ad
            networks, or browser fingerprinting.
          </p>
        </section>

        <section className={styles.section}>
          <h2>12. Breach notification</h2>
          <p>
            We notify affected controllers without undue delay, and in any
            case within <strong>72 hours</strong> of becoming aware of a
            personal data breach (GDPR Art. 33 / LGPD Art. 48). Our internal
            timeline targets supervisory-authority notification within 48
            hours — beating the statutory cap by 24 hours. Affected data
            subjects receive notice when the breach is likely to result in
            high risk to their rights and freedoms.
          </p>
        </section>

        <section className={styles.section}>
          <h2>13. Contact and complaints</h2>
          <p>
            Data Protection contact —{" "}
            <a href="mailto:privacy@humangr.com">privacy@humangr.com</a>.
            Postal address forthcoming with the Stripe Atlas Delaware
            registration. You have the right to lodge a complaint with your
            local supervisory authority (ANPD in Brazil; your member-state
            DPA in the EU/EEA; the relevant state attorney general in the US)
            and to seek a judicial remedy.
          </p>
        </section>

        <p className={styles.footnote}>
          See also: <a href="/legal/terms">Terms of Service</a> ·{" "}
          <a href="/legal/sub-processors">Sub-processors</a> ·{" "}
          <a href="mailto:legal@humangr.com">
            Data Processing Addendum (on request)
          </a>
        </p>
      </main>
    </Layout>
  );
}
