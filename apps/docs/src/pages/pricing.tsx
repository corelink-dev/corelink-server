/**
 * Public pricing page — Phase 0.E launch shape.
 *
 * 6 tiers (Free / Solo / Starter / Pro / Max / Enterprise) per
 * pricing-benchmarks §5 + ROADMAP-TO-LAUNCH.md §3
 * + phase-0-execution-plan.md §2.E. Prices are concrete launch prices
 * (no longer provisional). CTAs route to real surfaces:
 *
 *   Free        → https://humangr.com/corelink/sign-up
 *   Paid tiers  → https://humangr.com/corelink/en/upgrade?plan=<tier>
 *   Enterprise  → mailto:sales@humangr.com
 *
 * The `/upgrade?plan=pro` route in `apps/admin-ui` triggers the
 * Stripe Checkout Session created by Phase 0.C
 * (`BILLINGSTEP-DELETE-WIRE-CHECKOUT`); if the user is not signed in
 * Clerk routes through `/sign-up?intent=pro&redirect=/upgrade?plan=pro`.
 */

import Layout from "@theme/Layout";
import { useState } from "react";
import type { ReactElement } from "react";

import {
  CANONICAL_TIERS,
  TIER_RATE_CARD,
  applyPeriodDiscount,
  formatRetention,
  formatUsd,
} from "../lib/pricing";
import type { BillingPeriod, TierId, TierShape } from "../lib/pricing";

import styles from "./pricing.module.css";

const APP_BASE = "https://humangr.com/corelink";
const SIGNUP_URL = `${APP_BASE}/sign-up`;
const UPGRADE_PRO_URL = `${APP_BASE}/en/upgrade?plan=pro`;
const SALES_MAILTO = "mailto:sales@humangr.com?subject=CoreLink%20Enterprise%20inquiry";

interface TierCta {
  readonly label: string;
  readonly href: string;
  readonly rel?: string;
}

function ctaForTier(tier: TierId): TierCta {
  switch (tier) {
    case "free":
      return { label: "Start free", href: SIGNUP_URL };
    case "solo":
      return { label: "Upgrade to Solo", href: `${APP_BASE}/upgrade?plan=solo` };
    case "starter":
      return { label: "Upgrade to Starter", href: `${APP_BASE}/upgrade?plan=starter` };
    case "pro":
      // Admin-ui handles the auth check: if not signed in Clerk
      // intercepts and routes to `/sign-up?redirect=/upgrade?plan=pro`.
      // If signed in it POSTs to /api/checkout/session and 303s into
      // Stripe Checkout (wired by Phase 0.C). Same flow for every paid
      // SKU via `/upgrade?plan=<tier>`.
      return { label: "Upgrade to Pro", href: UPGRADE_PRO_URL };
    case "max":
      return { label: "Upgrade to Max", href: `${APP_BASE}/upgrade?plan=max` };
    case "enterprise":
      return { label: "Contact sales", href: SALES_MAILTO };
  }
}

function tierHeadlinePrice(card: TierShape, period: BillingPeriod): string {
  if (card.usdMonthlyBase === null) {
    return "Custom";
  }
  if (card.usdMonthlyBase === 0) {
    return "$0";
  }
  const effective = applyPeriodDiscount(card.usdMonthlyBase, period);
  return `${formatUsd(effective)}/mo`;
}

function tierSubprice(card: TierShape, period: BillingPeriod): string {
  if (card.usdMonthlyBase === null) {
    return "Custom contract";
  }
  if (card.usdMonthlyBase === 0) {
    return "Free forever — no card";
  }
  if (period === "annual" && card.usdAnnualList !== null) {
    return `${formatUsd(card.usdAnnualList)}/year — 2 months free`;
  }
  return "billed monthly";
}

function CheckOrDash({ included }: { included: boolean }): ReactElement {
  return included ? (
    <span className={styles.checkmark} aria-label="Included">
      {"✓"}
    </span>
  ) : (
    <span className={styles.dash} aria-label="Not included">
      {"—"}
    </span>
  );
}

export default function Pricing(): ReactElement {
  const [period, setPeriod] = useState<BillingPeriod>("monthly");

  return (
    <Layout
      title="Pricing"
      description="CoreLink plans: Free, Solo ($15/mo), Starter ($35/mo), Pro ($50/mo or $500/yr), Max ($149/mo), Enterprise. Six tiers, flat numbers, no per-seat."
    >
      <main className={styles.page}>
        <header className={styles.header}>
          <h1>Pricing</h1>
          <p>
            Six tiers, from Free to Enterprise. Flat numbers ($50/mo on
            Pro). No per-seat, no per-build, no surprise bills.
          </p>
        </header>

        <div className={styles.periodToggle} role="group" aria-label="Billing period">
          <button
            type="button"
            aria-pressed={period === "monthly"}
            onClick={() => setPeriod("monthly")}
          >
            Monthly
          </button>
          <button
            type="button"
            aria-pressed={period === "annual"}
            onClick={() => setPeriod("annual")}
          >
            Annual (2 months free)
          </button>
        </div>

        <section aria-label="Tier headline cards" className={styles.tierGrid}>
          {CANONICAL_TIERS.map((tierId) => {
            const card = TIER_RATE_CARD[tierId];
            const cta = ctaForTier(tierId);
            return (
              <article
                key={tierId}
                className={
                  tierId === "pro"
                    ? `${styles.tierCard} ${styles.tierCardFeatured}`
                    : styles.tierCard
                }
              >
                {tierId === "pro" ? (
                  <span className={styles.recommendedBadge}>Most popular</span>
                ) : null}
                <h3>{card.label}</h3>
                <p className={styles.tierTagline}>{card.tagline}</p>
                <div className={styles.tierPrice}>
                  {tierHeadlinePrice(card, period)}
                </div>
                <div className={styles.tierSubprice}>
                  {tierSubprice(card, period)}
                </div>
                <ul className={styles.tierFeatures}>
                  <li>
                    <strong>{card.includedCasGb.toLocaleString("en-US")} GB</strong>{" "}
                    cache storage
                  </li>
                  <li>
                    <strong>
                      {card.includedRequests.toLocaleString("en-US")}
                    </strong>{" "}
                    cache requests / mo
                  </li>
                  <li>
                    {card.includedWorkspaces === null
                      ? "Unlimited workspaces"
                      : `${card.includedWorkspaces} workspace${card.includedWorkspaces === 1 ? "" : "s"}`}
                  </li>
                  <li>
                    <strong>{card.retentionDays}-day</strong> cache retention
                  </li>
                  <li>
                    {card.hardCap
                      ? "Storage hard-caps at 100% — no surprise bills"
                      : "Custom capacity"}
                  </li>
                  <li>{card.support}</li>
                </ul>
                <a
                  className={styles.cta}
                  href={cta.href}
                  rel={cta.rel}
                  data-tier={tierId}
                >
                  {cta.label}
                </a>
              </article>
            );
          })}
        </section>

        <h2>Feature comparison</h2>
        <p>
          Every numeric quota below is the included allowance for the plan.
          CAS storage is the axis CoreLink meters today: a tenant that
          reaches 100% of its storage quota gets{" "}
          <code>429 Quota Exceeded</code> with an upgrade hint instead of
          silently billing overage. Cache-request-count enforcement is not
          live yet, so the request figure below is the allowance, not an
          enforced cap.
        </p>

        <table className={styles.compareTable}>
          <thead>
            <tr>
              <th scope="col">Capability</th>
              {CANONICAL_TIERS.map((t) => (
                <th key={t} scope="col">
                  {TIER_RATE_CARD[t].label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">Price</th>
              {CANONICAL_TIERS.map((t) => {
                const c = TIER_RATE_CARD[t];
                return (
                  <td key={t}>
                    {c.usdMonthlyBase === null
                      ? "Custom"
                      : c.usdMonthlyBase === 0
                        ? "$0"
                        : `$${c.usdMonthlyBase}/mo`}
                  </td>
                );
              })}
            </tr>
            <tr>
              <th scope="row">CAS storage included</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  {TIER_RATE_CARD[t].includedCasGb.toLocaleString("en-US")} GB
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">Cache requests / mo</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  {TIER_RATE_CARD[t].includedRequests.toLocaleString("en-US")}
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">Workspaces</th>
              {CANONICAL_TIERS.map((t) => {
                const w = TIER_RATE_CARD[t].includedWorkspaces;
                return <td key={t}>{w === null ? "Unlimited" : w}</td>;
              })}
            </tr>
            <tr>
              <th scope="row">Cache retention</th>
              {CANONICAL_TIERS.map((t) => {
                const c = TIER_RATE_CARD[t];
                return (
                  <td key={t}>
                    {c.retentionOverrideCapDays === null
                      ? `${c.retentionDays} days`
                      : `${c.retentionDays} days (up to ${c.retentionOverrideCapDays} by contract)`}
                  </td>
                );
              })}
            </tr>
            <tr>
              <th scope="row">BYOK (R2 + KMS)</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  <CheckOrDash included={TIER_RATE_CARD[t].byok} />
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">SSO / SAML</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  <CheckOrDash included={TIER_RATE_CARD[t].sso} />
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">DPA + MSA</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  <CheckOrDash included={TIER_RATE_CARD[t].dpa} />
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">Audit log export</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>
                  <CheckOrDash included={TIER_RATE_CARD[t].auditLogExport} />
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">Support</th>
              {CANONICAL_TIERS.map((t) => (
                <td key={t}>{TIER_RATE_CARD[t].support}</td>
              ))}
            </tr>
          </tbody>
        </table>

        <p>
          Need to size for your team? See the{" "}
          <a href="/pricing/calculator">interactive calculator</a> — plug in
          your storage and request volume to find the smallest tier that fits.
        </p>
      </main>
    </Layout>
  );
}
