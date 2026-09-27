/**
 * Public terms-of-service page — Phase 0 §A `LEGAL-FOOTER-WIRE` deliverable.
 *
 * Authored from the Common Paper Cloud Service Agreement (CSA) template per
 * `specs/_audits/2026-05-27-legal-ops-setup.md` §1.2, adapted to CoreLink's
 * single-product surface and stripped to a plain-language T&C suitable for
 * self-service signup. Covers the seven CSA core sections: service
 * description, plan/payment, acceptable-use policy, warranties &
 * disclaimers, liability cap, governing law (Delaware, post-Atlas filing),
 * and termination.
 *
 * Charter note: shipped with the `subject to final legal review prior to GA`
 * banner per Phase 0 execution-plan §2.A hard-pause trigger (c). The
 * Common Paper Standard Service Agreement (master) supersedes this page when
 * a paid enterprise contract is negotiated; this page applies to
 * self-service Free and Pro tier users only.
 */

import Layout from "@theme/Layout";
import type { ReactElement } from "react";

import styles from "./legal.module.css";

const EFFECTIVE_DATE = "2026-05-27";
const VERSION = "1.0.0";

export default function TermsPage(): ReactElement {
  return (
    <Layout
      title="Terms of Service"
      description="CoreLink Terms of Service: the agreement governing self-service Free and Pro use of the CoreLink multi-tenant content-addressable cache by HuGR Labs."
    >
      <main className={styles.page}>
        <header className={styles.header}>
          <h1>Terms of Service</h1>
          <p className={styles.meta}>
            Version {VERSION} · Effective {EFFECTIVE_DATE} · Based on the
            Common Paper Cloud Service Agreement template
          </p>
        </header>

        <p className={styles.draftNote} role="status">
          <strong>Subject to final legal review prior to GA.</strong> These
          terms govern self-service Free and Pro use of CoreLink during the
          pre-GA period. Enterprise customers execute a separate Master
          Subscription Agreement and a counter-signed Data Processing
          Addendum; nothing in this page reduces commitments made in a
          signed Order Form.
        </p>

        <p>
          These Terms of Service (&ldquo;Terms&rdquo;) form a binding
          agreement between you (or the organization you represent) and HuGR
          Labs (operating the CoreLink service; together with its corporate
          successor CoreLink, Inc., &ldquo;CoreLink&rdquo;, &ldquo;we&rdquo;,
          &ldquo;us&rdquo;). By creating an account, clicking
          &ldquo;agree&rdquo;, or using any CoreLink surface, you accept
          these Terms. If you do not have authority to bind your organization,
          do not accept these Terms.
        </p>

        <section className={styles.section}>
          <h2>1. The Service</h2>
          <p>
            CoreLink provides a multi-tenant, content-addressable cache
            running on Cloudflare&rsquo;s global edge. Subject to these Terms,
            we grant you a non-exclusive, non-transferable, revocable right to
            use the Service for your internal business purposes during your
            subscription term. The Service includes the API, the command-line
            tool, the Admin UI, and the documentation surfaces (this site,{" "}
            <a href="https://humangr.com/corelink/docs">
              humangr.com/corelink/docs
            </a>
            , and{" "}
            <a href="https://humangr.com/corelink">
              humangr.com/corelink
            </a>
            ).
          </p>
          <p>
            We may modify the Service over time. We will not materially reduce
            the core functionality of a paid tier during your billing period
            without giving you 30 days&rsquo; notice and a pro-rated refund
            for the unused portion if you choose to terminate as a result.
          </p>
        </section>

        <section className={styles.section}>
          <h2>2. Account and access</h2>
          <p>
            You must be at least 18 years old and authorized by your
            organization to bind it to these Terms. You are responsible for
            (a) safeguarding your credentials and personal access tokens;
            (b) all activity that happens under your account; and (c) keeping
            your contact email current so we can reach you for security
            notices and breach disclosures. We use Clerk as our identity
            provider; their authentication terms apply to the sign-in flow
            (see <a href="/legal/sub-processors">Sub-processors</a>).
          </p>
        </section>

        <section className={styles.section}>
          <h2>3. Plans, fees, and payment</h2>
          <p>
            CoreLink offers six tiers: Free (10 GB cache, no card required),
            Solo ($15/month), Starter ($35/month), Pro ($50/month), Max
            ($149/month) — all paid via Stripe Checkout — and Enterprise
            (custom-contract). Paid-tier fees are charged monthly in advance and
            are non-refundable except where required by law or where we
            materially reduce the Service per §1. Overage above your plan
            allowance is metered at the rate card published on{" "}
            <a href="/pricing">humangr.com/corelink/docs/pricing</a> and is
            invoiced at the close of each billing cycle.
          </p>
          <p>
            Past-due amounts accrue interest at the lesser of 1.5% per month
            or the maximum allowed by law. We may suspend access to paid
            features for accounts more than 14 days past due after providing
            7 days&rsquo; notice; underlying tenant content remains
            recoverable for at least 30 days after suspension.
          </p>
          <p>
            Stripe processes all card payments. CoreLink never sees card
            data. See Stripe&rsquo;s{" "}
            <a
              href="https://stripe.com/legal/consumer"
              rel="noopener noreferrer"
              target="_blank"
            >
              Services Terms
            </a>{" "}
            for the payment relationship between you and Stripe.
          </p>
        </section>

        <section className={styles.section}>
          <h2>4. Acceptable use</h2>
          <p>You agree not to:</p>
          <ul>
            <li>
              Reverse-engineer, decompile, or otherwise attempt to derive the
              source code of the Service except as expressly permitted by
              applicable law.
            </li>
            <li>
              Use the Service to violate any applicable law, infringe any
              third party&rsquo;s rights, or transmit malicious code,
              unlawful content, or material that is harmful to children.
            </li>
            <li>
              Interfere with the Service&rsquo;s integrity, security,
              availability, or performance — including denial-of-service
              attempts, rate-limit evasion, or unauthorized scanning beyond
              the published security-research scope.
            </li>
            <li>
              Use the cache to serve cleartext credentials, encryption keys,
              cardholder data, or content subject to ITAR/EAR export controls
              outside your authorized jurisdictions.
            </li>
            <li>
              Resell, sublicense, or expose the Service to third parties as a
              hosted product without our prior written consent.
            </li>
          </ul>
          <p>
            We may suspend any account engaging in conduct that materially
            threatens the Service or other tenants; we will give notice and an
            opportunity to cure where the threat permits.
          </p>
        </section>

        <section className={styles.section}>
          <h2>5. Customer content and license</h2>
          <p>
            You retain all ownership of the content you upload to the cache
            (&ldquo;Customer Content&rdquo;). You grant us a worldwide,
            non-exclusive, royalty-free license to host, store, replicate,
            transmit, and process Customer Content solely as needed to
            provide the Service to you. We do not inspect Customer Content
            beyond cryptographic hashing and metadata required for cache
            operation. The detailed data-handling terms — including
            sub-processor list, transfer mechanisms, retention windows, and
            erasure procedures — are governed by the{" "}
            <a href="/legal/privacy">Privacy Notice</a> and the Data
            Processing Addendum. The DPA is not published on this site;
            request a counter-signed copy at{" "}
            <a href="mailto:legal@humangr.com">legal@humangr.com</a>.
          </p>
        </section>

        <section className={styles.section}>
          <h2>6. Confidentiality</h2>
          <p>
            Each party will protect the other&rsquo;s Confidential
            Information with the same degree of care it uses for its own
            (and at minimum, reasonable care). Confidential Information does
            not include information that is publicly known through no fault
            of the receiving party, was already known to the receiving party
            without confidentiality obligation, or was independently
            developed without use of the disclosing party&rsquo;s information.
          </p>
        </section>

        <section className={styles.section}>
          <h2>7. Warranties and disclaimers</h2>
          <p>
            We warrant that we will provide the Service with reasonable skill
            and care and in substantial conformance with the published
            documentation. <strong>Except for the warranty above</strong>, the
            Service is provided <strong>&ldquo;AS IS&rdquo;</strong> and we
            disclaim all other warranties — express, implied, statutory, or
            otherwise — including implied warranties of merchantability,
            fitness for a particular purpose, and non-infringement, to the
            maximum extent permitted by law.
          </p>
        </section>

        <section className={styles.section}>
          <h2>8. Limitation of liability</h2>
          <p>
            <strong>
              To the maximum extent permitted by law, neither party will be
              liable for any indirect, incidental, special, consequential,
              cover, or punitive damages
            </strong>
            , or for lost profits, lost revenues, lost data, or business
            interruption, arising out of or related to the Service, even if
            advised of the possibility of such damages.
          </p>
          <p>
            <strong>
              Each party&rsquo;s aggregate liability arising out of or
              related to these Terms will not exceed the greater of (a) the
              fees you paid us in the 12 months preceding the event giving
              rise to the claim, or (b) US$100.
            </strong>{" "}
            The cap does not apply to (i) a party&rsquo;s indemnification
            obligations, (ii) breach of confidentiality, (iii) gross
            negligence or willful misconduct, or (iv) amounts you owe us in
            fees.
          </p>
        </section>

        <section className={styles.section}>
          <h2>9. Indemnification</h2>
          <p>
            You will defend, indemnify, and hold us harmless from any
            third-party claim arising out of your Customer Content, your
            breach of §4 (Acceptable Use), or your violation of applicable
            law. We will defend, indemnify, and hold you harmless from any
            third-party claim that your authorized use of the Service
            infringes a US-issued patent, copyright, or trademark, subject to
            the limitation in §8 and provided you (a) give us prompt notice,
            (b) grant us sole control of the defense, and (c) reasonably
            cooperate.
          </p>
        </section>

        <section className={styles.section}>
          <h2>10. Term and termination</h2>
          <p>
            These Terms apply for as long as you use the Service. You may
            terminate at any time by closing your account from the Admin UI;
            Pro-tier termination takes effect at the end of the current
            billing period (no pro-rated refund except where required by law
            or §1). We may terminate or suspend immediately for material
            breach of §4 or unpaid fees more than 30 days past due, after
            giving notice and an opportunity to cure where the threat
            permits. On termination, your tenant content is recoverable for
            30 calendar days, then erased per the Privacy Notice §4.
          </p>
        </section>

        <section className={styles.section}>
          <h2>11. Changes to these Terms</h2>
          <p>
            We may update these Terms from time to time. Material changes
            will be announced at least 30 days in advance via in-app banner
            and the administrator email on file. Continued use of the Service
            after the effective date constitutes acceptance; if you do not
            accept, you may terminate per §10 without penalty during the
            30-day notice window.
          </p>
        </section>

        <section className={styles.section}>
          <h2>12. Governing law and disputes</h2>
          <p>
            These Terms are governed by the laws of the State of Delaware,
            USA (effective on completion of the in-flight Stripe Atlas
            Delaware C-corp filing), excluding its conflict-of-laws rules.
            Before the corporate succession completes, these Terms are
            governed by the laws of the State of São Paulo, Brazil, where
            HuGR Labs is currently established. Disputes are resolved in the
            state or federal courts located in Wilmington, Delaware (or, in
            the interim period, in São Paulo) and each party submits to
            those courts&rsquo; personal jurisdiction. Nothing in this
            section limits either party from seeking injunctive relief in any
            court of competent jurisdiction for misuse of intellectual
            property or Confidential Information.
          </p>
        </section>

        <section className={styles.section}>
          <h2>13. Miscellaneous</h2>
          <p>
            These Terms, together with the{" "}
            <a href="/legal/privacy">Privacy Notice</a>, the Data Processing
            Addendum, and any executed Order Form, constitute the entire agreement
            between the parties and supersede any prior agreement on the
            subject. If any provision is held unenforceable, the remainder
            stays in effect. Neither party&rsquo;s failure to enforce a right
            is a waiver. You may not assign these Terms without our prior
            written consent (except to a successor in a merger or sale of
            substantially all assets); we may assign these Terms in
            connection with our corporate succession from HuGR Labs to
            CoreLink, Inc.
          </p>
        </section>

        <section className={styles.section}>
          <h2>14. Service availability and credits</h2>
          <p>
            No SLA service-credit program is currently active or effective for
            any tier. These Terms do not promise service-credit eligibility,
            an invoice adjustment, or automatic issuance. Any later service-
            credit policy must appear in a separately approved, dated SLA
            version after legal and release review; this section does not
            activate that policy.
          </p>
        </section>

        <section className={styles.section}>
          <h2>15. Export control and sanctions</h2>
          <p>
            The Service may be subject to US Export Administration
            Regulations (EAR) and Office of Foreign Assets Control (OFAC)
            sanctions; you may not access the Service from, or use it to
            transfer data to, any jurisdiction or party subject to a
            comprehensive US embargo, nor in violation of any applicable
            export-control regulation of your home jurisdiction.
            Sanctions screening on signup is performed by Clerk (account
            holder) and Stripe (payment counterparty); CoreLink reserves
            the right to suspend or terminate accounts flagged by either
            screen.
          </p>
        </section>

        <section className={styles.section}>
          <h2>16. Beta features</h2>
          <p>
            We may make pre-release features available to you under labels
            such as &ldquo;preview&rdquo;, &ldquo;beta&rdquo;,
            &ldquo;experimental&rdquo;, or &ldquo;developer preview&rdquo;.
            Beta features are provided &ldquo;AS IS&rdquo;, are excluded
            from the warranty in §7 and the availability commitment in §14,
            may be modified or withdrawn at any time, and may be subject to
            additional terms presented at the time of enrolment. You bear
            sole responsibility for evaluating whether a beta feature is
            fit for your use case.
          </p>
        </section>

        <section className={styles.section}>
          <h2>17. Contact</h2>
          <p>
            Questions about these Terms? Email{" "}
            <a href="mailto:legal@humangr.com">legal@humangr.com</a>. For
            privacy-specific questions, see the{" "}
            <a href="/legal/privacy">Privacy Notice</a> §10.
          </p>
        </section>

        <p className={styles.footnote}>
          See also: <a href="/legal/privacy">Privacy Notice</a> ·{" "}
          <a href="/legal/sub-processors">Sub-processors</a> ·{" "}
          <a href="mailto:legal@humangr.com">
            Data Processing Addendum (on request)
          </a>
        </p>
      </main>
    </Layout>
  );
}
