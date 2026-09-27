/**
 * Pricing data model for the public pricing page + calculator.
 *
 * 6-tier launch ladder (FROZEN taxonomy contract, 2026-06-09): the
 * public surface lists all six customer-facing tiers in canonical
 * order, the four paid tiers self-serve via Stripe Checkout and
 * Enterprise routes through the inquiry form:
 *
 *     Free $0  →  Solo $15  →  Starter $35  →  Pro $50  →  Max $149
 *               →  Enterprise (contact us)
 *
 * Pricing is the launch rate card, signed off by Gustavo Schneiter
 * (sole-founder authority). Pro is the recommended / anchor SKU.
 *
 * Quota policy at v0.1 is **hard cap** on every priced tier (no silent
 * overage billing — buyer hits 100% → 429 + upgrade CTA). Overage axes
 * exist as data so the calculator can render "you would exceed this
 * tier" warnings, but every overage USD rate is `0` (hard cap), which
 * the page renders as "Hard cap — upgrade to continue" rather than a
 * misleading "$0/GB overage".
 *
 * NO BACKEND CALLS — all formulas are pure functions so the calculator
 * is fully client-side.
 */

/**
 * Launch tier taxonomy — the six canonical customer-facing tiers
 * (FROZEN). Wire strings are snake_case. Runner SKUs are a separate
 * entitlement axis and are intentionally excluded. The internal billing model in
 * `crates/corelink-tier-selection/src/tier.rs` is the matching
 * authority; this is the public surface.
 */
export type TierId =
  | "free"
  | "solo"
  | "starter"
  | "pro"
  | "max"
  | "enterprise";

export const CANONICAL_TIERS: readonly TierId[] = [
  "free",
  "solo",
  "starter",
  "pro",
  "max",
  "enterprise",
] as const;

/**
 * Billing period. Annual is sold as "2 months free" (~17% off) on the
 * Pro base; Plausible / BetterStack convention.
 */
export type BillingPeriod = "monthly" | "annual";

/**
 * "2 months free" = pay for 10 months out of 12 → 1 - 10/12 ≈ 16.67%.
 * Applied uniformly to every paid tier's monthly base for the annual
 * list price (e.g. Pro $50/mo → $500/yr vs. $50 × 12).
 */
export const ANNUAL_DISCOUNT_RATE = 1 - 10 / 12;

/**
 * Single tier's published shape. Concrete launch pricing per
 * `specs/_audits/2026-05-27-pricing-benchmarks.md` §5.
 */
export interface TierShape {
  readonly id: TierId;
  readonly label: string;
  /** Short marketing tagline rendered under the tier name. */
  readonly tagline: string;
  /** Included CAS storage (GB-month). */
  readonly includedCasGb: number;
  /** Included cache requests / month. */
  readonly includedRequests: number;
  /** Included workspaces (Free: 1; higher tiers unlimited → `null`). */
  readonly includedWorkspaces: number | null;
  /** True if BYOK (bring-your-own-R2 + bring-your-own-KMS) is offered. */
  readonly byok: boolean;
  /** True if SSO/SAML (Clerk org-mode) is offered. */
  readonly sso: boolean;
  /** Future SLA-credit eligibility only; does not mean a program or issuance is active. */
  readonly slaCredits: boolean;
  /** True if DPA + custom MSA are offered. */
  readonly dpa: boolean;
  /** True if audit log export (beyond 90-day in-app retention). */
  readonly auditLogExport: boolean;
  /**
   * Cache retention promise (days): how long cached artifacts are
   * retained before tier-TTL eviction. This is a published product
   * promise — it mirrors, and MUST stay consistent with, the canonical
   * TTL ladder in `crates/corelink-eviction/src/tier.rs` composed with
   * the billing→operational tier mapping
   * (`crates/corelink-ratelimit/src/tier.rs::tier_for_billing_label`,
   * PROPOSAL-2026-06-10-ADMIN-PILOT-TENANT-RATE-MAPPING §3.3/§3.5,
   * ratified 2026-06-10).
   */
  readonly retentionDays: number;
  /**
   * Contract-negotiated retention override hard cap (days). `null` for
   * every self-serve tier (no override offered); Enterprise only:
   * 730 d (CAP-EVICT-002 boundary — 730 is the CAP, the default stays
   * 365 d).
   */
  readonly retentionOverrideCapDays: number | null;
  /** Support channel description. */
  readonly support: string;
  /** Per-tier base monthly fee (USD). `null` for contact-sales. */
  readonly usdMonthlyBase: number | null;
  /** Annual list price (USD/year). `null` for Free or contact-sales. */
  readonly usdAnnualList: number | null;
  /**
   * Overage USD rate per GB of CAS storage beyond `includedCasGb`.
   * `0` = hard cap (writes return 429; no silent overage). The page
   * renders this honestly as "Hard cap — upgrade to continue".
   */
  readonly usdPerCasGbOverage: number;
  /**
   * Overage USD rate per cache request beyond `includedRequests`.
   * `0` = hard cap.
   */
  readonly usdPerRequestOverage: number;
  /** True ⇒ quota is enforced as a hard cap (429 over quota). */
  readonly hardCap: boolean;
}

/**
 * Launch rate card per pricing-benchmarks §5. Magnitudes are the
 * **published v0.1 prices**, not placeholders.
 */
export const TIER_RATE_CARD: Readonly<Record<TierId, TierShape>> = {
  free: {
    id: "free",
    label: "Free",
    tagline: "For personal projects and evaluation. No credit card.",
    includedCasGb: 10,
    includedRequests: 500_000,
    includedWorkspaces: 1,
    byok: false,
    sso: false,
    slaCredits: false,
    dpa: false,
    auditLogExport: false,
    retentionDays: 7,
    retentionOverrideCapDays: null,
    support: "Community (GitHub Discussions)",
    usdMonthlyBase: 0,
    usdAnnualList: 0,
    usdPerCasGbOverage: 0,
    usdPerRequestOverage: 0,
    hardCap: true,
  },
  solo: {
    id: "solo",
    label: "Solo",
    tagline: "For the solo developer shipping real work.",
    includedCasGb: 50,
    includedRequests: 2_000_000,
    includedWorkspaces: null, // unlimited
    byok: false,
    sso: false,
    slaCredits: false,
    dpa: false,
    auditLogExport: false,
    retentionDays: 30,
    retentionOverrideCapDays: null,
    support: "Email (best-effort response target)",
    usdMonthlyBase: 15,
    usdAnnualList: 150,
    usdPerCasGbOverage: 0, // hard cap at v0.1; metered overage deferred to v0.2.
    usdPerRequestOverage: 0,
    hardCap: true,
  },
  starter: {
    id: "starter",
    label: "Starter",
    tagline: "For a small team getting onto a shared cache.",
    includedCasGb: 150,
    includedRequests: 6_000_000,
    includedWorkspaces: null, // unlimited
    byok: false,
    sso: false,
    slaCredits: false,
    dpa: false,
    auditLogExport: false,
    retentionDays: 90,
    retentionOverrideCapDays: null,
    support: "Email (2 business-day response target)",
    usdMonthlyBase: 35,
    usdAnnualList: 350,
    usdPerCasGbOverage: 0, // hard cap at v0.1; metered overage deferred to v0.2.
    usdPerRequestOverage: 0,
    hardCap: true,
  },
  pro: {
    id: "pro",
    label: "Pro",
    tagline: "For teams shipping production builds. Best value.",
    includedCasGb: 500,
    includedRequests: 20_000_000,
    includedWorkspaces: null, // unlimited
    byok: false,
    sso: false,
    slaCredits: false,
    dpa: false,
    auditLogExport: false,
    retentionDays: 365,
    retentionOverrideCapDays: null,
    support: "Email (1 business-day response target)",
    usdMonthlyBase: 50,
    usdAnnualList: 500,
    usdPerCasGbOverage: 0, // hard cap at v0.1; metered overage deferred to v0.2.
    usdPerRequestOverage: 0,
    hardCap: true,
  },
  max: {
    id: "max",
    label: "Max",
    tagline: "For scaling teams pushing serious build volume.",
    includedCasGb: 2_000,
    includedRequests: 80_000_000,
    includedWorkspaces: null, // unlimited
    byok: false,
    sso: false,
    slaCredits: false,
    dpa: false,
    auditLogExport: false,
    retentionDays: 365,
    retentionOverrideCapDays: null,
    support: "Priority email (1 business-day response target)",
    usdMonthlyBase: 149,
    usdAnnualList: 1_490,
    usdPerCasGbOverage: 0, // hard cap at v0.1; metered overage deferred to v0.2.
    usdPerRequestOverage: 0,
    hardCap: true,
  },
  enterprise: {
    id: "enterprise",
    label: "Enterprise",
    tagline: "BYOK, dedicated tenant, 99.9% SLA, SSO, DPA.",
    // Indicative anchors (range $500–$5,000/mo per §5); rendered as
    // "Custom" — no specific dollar number shown until a contract.
    includedCasGb: 10_000,
    includedRequests: 1_000_000_000,
    includedWorkspaces: null,
    byok: true,
    sso: true,
    // Enterprise eligibility is reserved for a gated future SLA; credits remain inactive.
    slaCredits: true,
    dpa: true,
    auditLogExport: true,
    retentionDays: 365,
    retentionOverrideCapDays: 730, // default 365 d; up to 730 d by contract (CAP-EVICT-002)
    support: "Dedicated channel + custom SLA",
    usdMonthlyBase: null,
    usdAnnualList: null,
    usdPerCasGbOverage: 0,
    usdPerRequestOverage: 0,
    hardCap: false,
  },
};

/**
 * Buyer inputs for the calculator. All values are non-negative; the
 * pure formula functions clamp at zero defensively.
 */
export interface UsageInputs {
  readonly casGbStored: number;
  readonly requestsPerMonth: number;
}

export const DEFAULT_USAGE: UsageInputs = {
  casGbStored: 50,
  requestsPerMonth: 2_000_000,
};

/**
 * Per-tier estimate for the calculator. `monthlyTotal` is `null` for
 * Enterprise (contact sales — no $0 anchor).
 */
export interface TierCostEstimate {
  readonly tier: TierId;
  readonly label: string;
  /** True if the usage profile fits within included quotas. */
  readonly fitsWithoutOverage: boolean;
  /** USD/month at the selected billing period, or null for contact-sales. */
  readonly monthlyTotal: number | null;
  /** USD/month effective price under annual billing, or null. */
  readonly annualizedMonthlyTotal: number | null;
  readonly breakdown: {
    readonly base: number | null;
    /**
     * `null` ⇒ exceeding the included quota is a hard-cap event (writes
     * return 429; no overage charge possible). Otherwise: USD overage
     * for the GB above the included quota.
     */
    readonly casOverage: number | null;
    readonly requestOverage: number | null;
  };
}

const clampNonNegative = (n: number): number =>
  n < 0 || !Number.isFinite(n) ? 0 : n;

/**
 * Apply the period discount to the monthly base. Annual = "2 months
 * free" (~16.67% off) per Pro's $500/yr list vs. $50 × 12.
 */
export function applyPeriodDiscount(
  monthlyBase: number,
  period: BillingPeriod,
): number {
  if (period === "annual") {
    return monthlyBase * (1 - ANNUAL_DISCOUNT_RATE);
  }
  return monthlyBase;
}

/**
 * Pure formula: per-tier monthly cost given a usage profile and
 * billing period. Enterprise returns `monthlyTotal: null`.
 */
export function estimateTier(
  tier: TierId,
  usage: UsageInputs,
  period: BillingPeriod = "monthly",
): TierCostEstimate {
  const card = TIER_RATE_CARD[tier];
  const gbStored = clampNonNegative(usage.casGbStored);
  const requests = clampNonNegative(usage.requestsPerMonth);

  const casExceeded = Math.max(0, gbStored - card.includedCasGb);
  const reqExceeded = Math.max(0, requests - card.includedRequests);
  const fitsWithoutOverage = casExceeded === 0 && reqExceeded === 0;

  // Enterprise: contact-sales, never anchor a number.
  if (card.usdMonthlyBase === null) {
    return {
      tier,
      label: card.label,
      fitsWithoutOverage: true, // contact sales never rejects a customer
      monthlyTotal: null,
      annualizedMonthlyTotal: null,
      breakdown: { base: null, casOverage: null, requestOverage: null },
    };
  }

  // Hard-cap tiers (every priced tier at v0.1): overage is structurally
  // disallowed. Surface `null` so the UI renders "Hard cap" instead
  // of a misleading "$0 overage".
  const casOverageCost = card.hardCap
    ? null
    : casExceeded * card.usdPerCasGbOverage;
  const reqOverageCost = card.hardCap
    ? null
    : reqExceeded * card.usdPerRequestOverage;

  const overageSum =
    (casOverageCost ?? 0) + (reqOverageCost ?? 0);

  const monthlyBase = card.usdMonthlyBase;
  const annualBase = applyPeriodDiscount(monthlyBase, "annual");
  const monthlyTotal = monthlyBase + overageSum;
  const annualizedMonthlyTotal = annualBase + overageSum;

  return {
    tier,
    label: card.label,
    fitsWithoutOverage,
    monthlyTotal: period === "annual" ? annualizedMonthlyTotal : monthlyTotal,
    annualizedMonthlyTotal,
    breakdown: {
      base: period === "annual" ? annualBase : monthlyBase,
      casOverage: casOverageCost,
      requestOverage: reqOverageCost,
    },
  };
}

/**
 * Estimate every tier in canonical order. Useful for side-by-side
 * comparison rendering in the calculator.
 */
export function estimateAllTiers(
  usage: UsageInputs,
  period: BillingPeriod = "monthly",
): readonly TierCostEstimate[] {
  return CANONICAL_TIERS.map((t) => estimateTier(t, usage, period));
}

/**
 * Pick the smallest tier (by canonical order) whose included quotas
 * fully cover the usage profile. Returns `null` if usage exceeds even
 * Max — caller should route to Enterprise contact-sales.
 */
export function recommendTier(usage: UsageInputs): TierId | null {
  for (const tier of ["free", "solo", "starter", "pro", "max"] as const) {
    const est = estimateTier(tier, usage, "monthly");
    if (est.fitsWithoutOverage) {
      return tier;
    }
  }
  return null;
}

/**
 * Headroom under the recommended tier — how much more storage or
 * requests can the buyer absorb before hitting the next tier. `null`
 * when no quantifiable tier fits (route to Enterprise).
 */
export interface BreakEvenHeadroom {
  readonly recommended: TierId;
  readonly headroomCasGb: number;
  readonly headroomRequests: number;
}

export function computeBreakEven(usage: UsageInputs): BreakEvenHeadroom | null {
  const rec = recommendTier(usage);
  if (rec === null) {
    return null;
  }
  const card = TIER_RATE_CARD[rec];
  return {
    recommended: rec,
    headroomCasGb: Math.max(0, card.includedCasGb - usage.casGbStored),
    headroomRequests: Math.max(
      0,
      card.includedRequests - usage.requestsPerMonth,
    ),
  };
}

/**
 * Render a tier's cache-retention promise. Self-serve tiers show the
 * flat promise ("90-day cache retention"); Enterprise appends the
 * contract-negotiable override cap ("365-day cache retention — up to
 * 730 days by contract").
 */
export function formatRetention(card: TierShape): string {
  const base = `${card.retentionDays}-day cache retention`;
  if (card.retentionOverrideCapDays === null) {
    return base;
  }
  return `${base} — up to ${card.retentionOverrideCapDays} days by contract`;
}

/**
 * Format a USD amount. `null` ⇒ "Contact us" (no $0 anchor for
 * Enterprise). Negative inputs clamp to 0.
 */
export function formatUsd(amount: number | null): string {
  if (amount === null) {
    return "Contact us";
  }
  const clamped = clampNonNegative(amount);
  if (clamped > 0 && clamped < 10) {
    return `$${clamped.toFixed(2)}`;
  }
  return `$${Math.round(clamped).toLocaleString("en-US")}`;
}
