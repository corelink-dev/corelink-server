/**
 * B-089 automatic SLA credits.
 *
 * There are deliberately three durable boundaries here:
 *
 *  1. `sla_monthly_observations` is the append-only hand-off from the
 *     provider-operated SLO reporter.  `publishClosedSlaMeasurements` is the
 *     only producer for the settlement table and will not publish a month
 *     before its UTC close plus the report cutoff.
 *  2. `sla_credit_ledger` is the money-path idempotency boundary.  A tenant
 *     and UTC service month can produce at most one credit and one Stripe
 *     idempotency key.
 *  3. `sla_credit_outbox` and `sla_credit_reconciliation` make the gap after
 *     an external Stripe call durable.  If the Worker dies after Stripe has
 *     accepted an idempotent request but before D1 is updated, the next lease
 *     retries the same request and then records/reconciles the same provider
 *     object.
 *
 * The financial gate is checked in both the sweep and the provider.  The
 * repository and migrations may therefore be deployed while B-089 is parked;
 * no Stripe mutation happens until owner proof flips the explicit flag.
 */

import { constantTimeEqual } from "./github_provision.js";

export type CreditFailureKind = "transient" | "permanent";
export type SlaTier = "free" | "solo" | "starter" | "pro" | "max" | "enterprise";

export interface SlaMonthlyMeasurement {
  tenant_id: string;
  service_period: string; // canonical UTC YYYY-MM
  tier: string;
  monthly_fee_minor: number;
  currency: string;
  availability_percent: number;
  latency_excess_percent?: number | null;
  latency_sustained_minutes?: number | null;
  dsr_breach_days?: number | null;
  billing_drift_percent?: number | null;
  billing_drift_sustained_hours?: number | null;
  force_majeure: boolean;
  eligible_at_ms: number;
}

/** Immutable source row emitted by the provider-operated SLO report writer. */
export interface SlaMonthlyObservation extends SlaMonthlyMeasurement {
  observed_at_ms: number;
}

export interface CreditDecision {
  eligible: boolean;
  reason: string;
  credit_percent: number;
  amount_minor: number;
  catastrophic: boolean;
}

const CONTRACT_TIERS: Record<string, { target: number }> = {
  enterprise: { target: 99.95 },
};
const DAY_MS = 24 * 60 * 60 * 1000;
/** §7 says the report is published within ten business days of close. */
export const SLA_REPORT_CUTOFF_BUSINESS_DAYS = 10;
export const MAX_SWEEP_ROWS = 100;
const RETRY_BASE_MS = 60_000;
const RETRY_MAX_MS = DAY_MS;
const LEASE_MS = 5 * 60_000;

function finiteMs(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/** Rejects values such as 2026-00, 2026-13, and non-zero-padded months. */
export function parseUtcMonth(period: string): { year: number; month: number; start_ms: number; end_ms: number } | null {
  const match = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(period);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  // Date.UTC treats 0..99 as 1900..1999.  Those years are not valid for the
  // current product and rejecting them also prevents a surprising boundary.
  if (!Number.isSafeInteger(year) || year < 1970 || year > 9998) return null;
  const start_ms = Date.UTC(year, month - 1, 1);
  const end_ms = Date.UTC(year + (month === 12 ? 1 : 0), month === 12 ? 0 : month, 1);
  if (!finiteMs(start_ms) || !finiteMs(end_ms)) return null;
  return { year, month, start_ms, end_ms };
}

/** Returns the previous UTC calendar month, independent of local timezone. */
export function previousUtcMonth(now_ms: number): string {
  if (!finiteMs(now_ms)) throw new Error("now_ms must be a non-negative safe integer");
  const d = new Date(now_ms);
  const year = d.getUTCFullYear();
  const month = d.getUTCMonth();
  const previous = month === 0 ? `${year - 1}` : `${year}`;
  const number = month === 0 ? 12 : month;
  return `${previous}-${String(number).padStart(2, "0")}`;
}

/** Add business days using UTC weekdays (Saturday/Sunday are not counted). */
export function monthlyCutoffAtMs(service_period: string): number {
  const parsed = parseUtcMonth(service_period);
  if (!parsed) throw new Error("invalid UTC service period");
  let cursor = parsed.end_ms;
  let added = 0;
  while (added < SLA_REPORT_CUTOFF_BUSINESS_DAYS) {
    cursor += DAY_MS;
    const weekday = new Date(cursor).getUTCDay();
    if (weekday !== 0 && weekday !== 6) added += 1;
  }
  return cursor;
}

function canonicalCurrency(currency: string): string | null {
  const canonical = currency.trim().toUpperCase();
  return /^[A-Z]{3}$/.test(canonical) ? canonical : null;
}

function amountFor(fee_minor: number, percent: number): number | null {
  if (!Number.isSafeInteger(fee_minor) || fee_minor < 0 || !Number.isSafeInteger(percent) || percent < 0 || percent > 100) return null;
  // BigInt prevents an unsafe intermediate when a custom enterprise fee is
  // close to MAX_SAFE_INTEGER.  Conversion is allowed only after the exact
  // amount is known to fit the D1 INTEGER/Stripe integer contract.
  const amount = (BigInt(fee_minor) * BigInt(percent)) / 100n;
  return amount <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(amount) : null;
}

function availabilityCredit(target: number, achieved: number): { percent: number; catastrophic: boolean } {
  if (!Number.isFinite(achieved) || achieved < 0 || achieved > 100) return { percent: 0, catastrophic: false };
  const gap = target - achieved;
  if (gap <= 0) return { percent: 0, catastrophic: false };
  // The absolute <95% carve-out is part of the catastrophic definition even
  // when the tier target is less than five points above the observation.
  if (gap > 5 || achieved < 95) return { percent: 100, catastrophic: true };
  if (gap <= 0.5) return { percent: 5, catastrophic: false };
  if (gap <= 1) return { percent: 10, catastrophic: false };
  if (gap <= 2.5) return { percent: 25, catastrophic: false };
  return { percent: 50, catastrophic: false };
}

/** Calculate executed SLA v1.0.0 §4 without I/O. */
export function evaluateSlaCredit(measurement: SlaMonthlyMeasurement): CreditDecision {
  const tier = measurement.tier.trim().toLowerCase();
  const contract = CONTRACT_TIERS[tier];
  if (!contract) {
    return { eligible: false, reason: tier === "free" ? "free_tier_excluded" : "tier_not_in_executed_sla", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }
  const period = parseUtcMonth(measurement.service_period);
  const currency = canonicalCurrency(measurement.currency);
  if (!period || !finiteMs(measurement.eligible_at_ms) || !Number.isSafeInteger(measurement.monthly_fee_minor) || measurement.monthly_fee_minor < 0 || !currency) {
    return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }
  if (measurement.force_majeure) {
    return { eligible: false, reason: "force_majeure_excluded", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }
  const optionalMetrics = [
    measurement.latency_excess_percent,
    measurement.latency_sustained_minutes,
    measurement.dsr_breach_days,
    measurement.billing_drift_percent,
    measurement.billing_drift_sustained_hours,
  ];
  if (optionalMetrics.some((value) => value != null && (!Number.isFinite(value) || value < 0))) {
    return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }
  if (!Number.isFinite(measurement.availability_percent) || measurement.availability_percent < 0 || measurement.availability_percent > 100) {
    return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }

  const availability = availabilityCredit(contract.target, measurement.availability_percent);
  let percent = availability.percent;
  const latencyExcess = measurement.latency_excess_percent ?? 0;
  if (!Number.isFinite(latencyExcess) || latencyExcess < 0) {
    return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  }
  if (latencyExcess > 0 && (measurement.latency_sustained_minutes ?? 0) >= 60) {
    percent += latencyExcess <= 25 ? 5 : latencyExcess <= 50 ? 10 : 25;
  }
  const dsrDays = measurement.dsr_breach_days ?? 0;
  if (!Number.isFinite(dsrDays) || dsrDays < 0) return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  if (dsrDays >= 45) percent += 25;
  else if (dsrDays >= 30) percent += 5;
  const billingDrift = measurement.billing_drift_percent ?? 0;
  if (!Number.isFinite(billingDrift) || billingDrift < 0) return { eligible: false, reason: "invalid_measurement", credit_percent: 0, amount_minor: 0, catastrophic: false };
  if (billingDrift >= 0.1 && (measurement.billing_drift_sustained_hours ?? 0) > 24) percent += 10;

  percent = Math.min(100, percent);
  const amount = amountFor(measurement.monthly_fee_minor, percent);
  if (amount === null) return { eligible: false, reason: "invalid_fee_or_currency", credit_percent: 0, amount_minor: 0, catastrophic: availability.catastrophic };
  if (amount <= 0) return { eligible: false, reason: "no_breach", credit_percent: 0, amount_minor: 0, catastrophic: availability.catastrophic };
  return { eligible: true, reason: "eligible", credit_percent: percent, amount_minor: amount, catastrophic: availability.catastrophic };
}

export interface SlaCreditRequest {
  credit_id: string;
  tenant_id: string;
  stripe_customer_id: string;
  amount_minor: number;
  currency: string;
  service_period: string;
  credit_percent: number;
  idempotency_key: string;
  catastrophic: boolean;
}

export interface ProviderFailure { kind: CreditFailureKind; reason: string }
export type ProviderResult = { provider_ref: string } | { failure: ProviderFailure };
export interface ProviderReconciliation { ok: boolean; failure?: ProviderFailure }

export interface SlaCreditProvider {
  applyCredit(request: SlaCreditRequest): Promise<ProviderResult>;
  /** Optional means the provider cannot synchronously verify the object. */
  reconcileCredit?(request: SlaCreditRequest, provider_ref: string): Promise<ProviderReconciliation>;
}

/** Stripe pending invoice item, which is applied to the next invoice. */
export class StripeInvoiceItemProvider implements SlaCreditProvider {
  constructor(
    private readonly secretKey: string,
    private readonly apiBase = "https://api.stripe.com",
    private readonly enabled = false,
  ) {}

  async applyCredit(request: SlaCreditRequest): Promise<ProviderResult> {
    if (!this.enabled) return { failure: { kind: "permanent", reason: "provider_disabled" } };
    if (!Number.isSafeInteger(request.amount_minor) || request.amount_minor <= 0 || !Number.isSafeInteger(request.credit_percent) || request.credit_percent < 1 || request.credit_percent > 100) return { failure: { kind: "permanent", reason: "invalid_amount" } };
    const currency = canonicalCurrency(request.currency);
    if (!currency || !parseUtcMonth(request.service_period)) return { failure: { kind: "permanent", reason: "invalid_request" } };
    const body = new URLSearchParams({
      customer: request.stripe_customer_id,
      amount: String(-request.amount_minor),
      currency: currency.toLowerCase(),
      description: `CoreLink SLA service credit ${request.service_period}`,
      "metadata[credit_id]": request.credit_id,
      "metadata[service_period]": request.service_period,
      "metadata[credit_percent]": String(request.credit_percent),
    });
    try {
      const response = await fetch(`${this.apiBase.replace(/\/$/, "")}/v1/invoiceitems`, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.secretKey}`, "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": request.idempotency_key },
        body,
      });
      if (response.ok) {
        const value = (await response.json()) as { id?: unknown };
        return typeof value.id === "string" && value.id.length > 0 ? { provider_ref: value.id } : { failure: { kind: "permanent", reason: "stripe_response_missing_id" } };
      }
      const reason = `stripe_http_${response.status}`;
      return { failure: { kind: response.status === 408 || response.status === 409 || response.status === 429 || response.status >= 500 ? "transient" : "permanent", reason } };
    } catch (error) {
      return { failure: { kind: "transient", reason: error instanceof Error ? error.message.slice(0, 240) : "stripe_transport_error" } };
    }
  }

  async reconcileCredit(request: SlaCreditRequest, provider_ref: string): Promise<ProviderReconciliation> {
    if (!this.enabled) return { ok: false, failure: { kind: "permanent", reason: "provider_disabled" } };
    try {
      const response = await fetch(`${this.apiBase.replace(/\/$/, "")}/v1/invoiceitems/${encodeURIComponent(provider_ref)}`, {
        headers: { Authorization: `Bearer ${this.secretKey}` },
      });
      if (!response.ok) {
        const reason = `stripe_reconcile_http_${response.status}`;
        return { ok: false, failure: { kind: response.status === 408 || response.status === 409 || response.status === 429 || response.status >= 500 ? "transient" : "permanent", reason } };
      }
      const value = (await response.json()) as Record<string, unknown>;
      const amount = value.amount;
      const customer = value.customer;
      const metadata = value.metadata;
      const metadataRecord = metadata && typeof metadata === "object" ? metadata as Record<string, unknown> : null;
      const responseCurrency = typeof value.currency === "string" ? value.currency.toUpperCase() : null;
      if (
        amount !== -request.amount_minor ||
        customer !== request.stripe_customer_id ||
        responseCurrency !== canonicalCurrency(request.currency) ||
        !metadataRecord ||
        metadataRecord.credit_id !== request.credit_id ||
        metadataRecord.service_period !== request.service_period ||
        metadataRecord.credit_percent !== String(request.credit_percent)
      ) {
        return { ok: false, failure: { kind: "permanent", reason: "stripe_reconcile_mismatch" } };
      }
      return { ok: true };
    } catch (error) {
      return { ok: false, failure: { kind: "transient", reason: error instanceof Error ? error.message.slice(0, 240) : "stripe_reconcile_transport_error" } };
    }
  }
}

export interface D1RunResult { meta?: { changes?: number } }
export interface D1QueryResult<T = Record<string, unknown>> { results?: T[] }
export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<D1RunResult>;
  all<T = Record<string, unknown>>(): Promise<D1QueryResult<T>>;
}
export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatement;
  /** D1 batch is one transaction; it is required for the money state machine. */
  batch?(statements: D1PreparedStatement[]): Promise<D1RunResult[]>;
}

export interface SlaCreditCronEnv {
  BILLING_DB?: D1DatabaseLike;
  SLA_CREDITS_ENABLED?: string;
  SLA_OBSERVATIONS_ENABLED?: string;
  SLA_OBSERVATION_INGEST_KEY?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_API_BASE?: string;
}

export interface SlaCreditSweepResult {
  ok: boolean;
  skipped: boolean;
  measured: number;
  produced: number;
  created: number;
  applied: number;
  failed: number;
  blocked: number;
  reconciled: number;
}

export const SLA_CREDIT_INSERT_SQL = `INSERT OR IGNORE INTO sla_credit_ledger
  (credit_id, tenant_id, service_period, credit_percent, amount_minor, currency,
   stripe_customer_id, status, idempotency_key, catastrophic, attempts,
   next_attempt_at_ms, created_at_ms, updated_at_ms)
  VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 0, ?, ?, ?)`;

const INSERT_OUTBOX_SQL = `INSERT OR IGNORE INTO sla_credit_outbox
  (credit_id, idempotency_key, payload_json, status, attempts, created_at_ms, updated_at_ms)
  VALUES (?, ?, ?, 'pending', 0, ?, ?)`;

function idFor(tenant: string, period: string): string { return `sla_credit:${tenant}:${period}`; }
function backoff(attempt: number): number { return Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(Math.max(attempt, 0), 10)); }
function enabled(env: SlaCreditCronEnv): boolean { return env.SLA_CREDITS_ENABLED?.trim().toLowerCase() === "true"; }
function observationIngestEnabled(env: SlaCreditCronEnv): boolean {
  return enabled(env) && env.SLA_OBSERVATIONS_ENABLED?.trim().toLowerCase() === "true";
}
function asMeasurement(row: Record<string, unknown>): SlaMonthlyMeasurement {
  return {
    tenant_id: String(row.tenant_id), service_period: String(row.service_period), tier: String(row.tier),
    monthly_fee_minor: Number(row.monthly_fee_minor), currency: String(row.currency), availability_percent: Number(row.availability_percent),
    latency_excess_percent: row.latency_excess_percent == null ? null : Number(row.latency_excess_percent), latency_sustained_minutes: row.latency_sustained_minutes == null ? null : Number(row.latency_sustained_minutes),
    dsr_breach_days: row.dsr_breach_days == null ? null : Number(row.dsr_breach_days), billing_drift_percent: row.billing_drift_percent == null ? null : Number(row.billing_drift_percent),
    billing_drift_sustained_hours: row.billing_drift_sustained_hours == null ? null : Number(row.billing_drift_sustained_hours), force_majeure: row.force_majeure === true || row.force_majeure === 1,
    eligible_at_ms: Number(row.eligible_at_ms),
  };
}

async function atomic(db: D1DatabaseLike, statements: D1PreparedStatement[]): Promise<D1RunResult[]> {
  if (!db.batch) throw new Error("B-089 requires D1 batch transactions");
  return db.batch(statements);
}

/** Persist the provider-operated observation without allowing a non-UTC key. */
export async function recordCanonicalSlaObservation(db: D1DatabaseLike, observation: SlaMonthlyObservation): Promise<void> {
  const period = parseUtcMonth(observation.service_period);
  if (!period || !finiteMs(observation.observed_at_ms) || observation.observed_at_ms < period.end_ms) throw new Error("SLA observation must be a closed UTC month");
  const cutoff = monthlyCutoffAtMs(observation.service_period);
  if (!Number.isSafeInteger(observation.monthly_fee_minor) || observation.monthly_fee_minor < 0 || !canonicalCurrency(observation.currency)) throw new Error("SLA observation has invalid currency or fee");
  await db.prepare(`INSERT OR IGNORE INTO sla_monthly_observations
    (tenant_id, service_period, tier, monthly_fee_minor, currency, availability_percent,
     latency_excess_percent, latency_sustained_minutes, dsr_breach_days,
     billing_drift_percent, billing_drift_sustained_hours, force_majeure,
     cutoff_at_ms, observed_at_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    observation.tenant_id, observation.service_period, observation.tier.trim().toLowerCase(), observation.monthly_fee_minor,
    canonicalCurrency(observation.currency), observation.availability_percent, observation.latency_excess_percent ?? null,
    observation.latency_sustained_minutes ?? null, observation.dsr_breach_days ?? null, observation.billing_drift_percent ?? null,
    observation.billing_drift_sustained_hours ?? null, observation.force_majeure ? 1 : 0, cutoff, observation.observed_at_ms,
  ).run();
}

/**
 * Move closed/cutoff observations into the immutable settlement table.  The
 * query has no OFFSET: published rows leave the candidate set, so 100 ancient
 * rows cannot starve newer tenants or months.
 */
export async function publishClosedSlaMeasurements(db: D1DatabaseLike, nowMs: number): Promise<number> {
  const source = await db.prepare(`SELECT * FROM sla_monthly_observations
    WHERE published_at_ms IS NULL AND cutoff_at_ms <= ?
    ORDER BY service_period ASC, tenant_id ASC LIMIT ?`).bind(nowMs, MAX_SWEEP_ROWS).all<Record<string, unknown>>();
  let produced = 0;
  for (const row of source.results ?? []) {
    const period = String(row.service_period);
    const parsed = parseUtcMonth(period);
    if (!parsed || monthlyCutoffAtMs(period) > nowMs) continue;
    const statements = [
      db.prepare(`INSERT OR IGNORE INTO sla_monthly_measurements
        (tenant_id, service_period, tier, monthly_fee_minor, currency, availability_percent,
         latency_excess_percent, latency_sustained_minutes, dsr_breach_days,
         billing_drift_percent, billing_drift_sustained_hours, force_majeure,
         eligible_at_ms, state, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`)
        .bind(row.tenant_id, period, row.tier, row.monthly_fee_minor, canonicalCurrency(String(row.currency)), row.availability_percent,
          row.latency_excess_percent ?? null, row.latency_sustained_minutes ?? null, row.dsr_breach_days ?? null,
          row.billing_drift_percent ?? null, row.billing_drift_sustained_hours ?? null, row.force_majeure ? 1 : 0, Number(row.cutoff_at_ms)),
      db.prepare("UPDATE sla_monthly_observations SET published_at_ms = ? WHERE tenant_id = ? AND service_period = ? AND published_at_ms IS NULL")
        .bind(nowMs, row.tenant_id, period),
    ];
    const result = await atomic(db, statements);
    produced += Number(result[0]?.meta?.changes ?? 0);
  }
  return produced;
}

async function audit(db: D1DatabaseLike, creditId: string, type: string, detail: string, nowMs: number): Promise<D1PreparedStatement> {
  return db.prepare("INSERT INTO sla_credit_audit_events (credit_id, event_type, detail, created_at_ms) VALUES (?, ?, ?, ?)").bind(creditId, type, detail.slice(0, 500), nowMs);
}

async function markMeasurement(db: D1DatabaseLike, measurement: SlaMonthlyMeasurement, state: string, reason: string, nowMs: number, decision?: CreditDecision): Promise<number> {
  const creditId = idFor(measurement.tenant_id, measurement.service_period);
  const currency = canonicalCurrency(measurement.currency) ?? measurement.currency.trim().toUpperCase();
  const statements: D1PreparedStatement[] = [];
  if (decision?.eligible) {
    statements.push(db.prepare(SLA_CREDIT_INSERT_SQL).bind(creditId, measurement.tenant_id, measurement.service_period, decision.credit_percent, decision.amount_minor, currency, null, `sla-credit:${creditId}`, decision.catastrophic ? 1 : 0, nowMs, nowMs, nowMs));
  }
  statements.push(db.prepare(`UPDATE sla_monthly_measurements SET state = ?, decision_reason = ?, evaluated_at_ms = ?, credit_percent = ?, amount_minor = ? WHERE tenant_id = ? AND service_period = ? AND state = 'pending'`)
    .bind(state, reason, nowMs, decision?.eligible ? decision.credit_percent : 0, decision?.eligible ? decision.amount_minor : 0, measurement.tenant_id, measurement.service_period));
  if (decision?.eligible) statements.push(await audit(db, creditId, "created", `${decision.credit_percent}%:${decision.amount_minor}`, nowMs));
  const result = await atomic(db, statements);
  return decision?.eligible ? Number(result[0]?.meta?.changes ?? 0) : 0;
}

async function retryMapping(db: D1DatabaseLike, creditId: string, attempts: number, nowMs: number): Promise<void> {
  const nextAttempt = Math.min(10, Math.max(0, Number.isSafeInteger(attempts) ? attempts : 0) + 1);
  await atomic(db, [
    db.prepare(`UPDATE sla_credit_ledger SET status = 'failed', failure_kind = 'transient', failure_reason = ?, next_attempt_at_ms = ?, lease_until_ms = NULL, attempts = attempts + 1, updated_at_ms = ? WHERE credit_id = ? AND status IN ('pending', 'processing', 'failed')`)
      .bind("tenant_mapping_pending", nowMs + backoff(nextAttempt), nowMs, creditId),
    await audit(db, creditId, "retry", "tenant_mapping_pending", nowMs),
  ]);
}

function requestFromRow(row: Record<string, unknown>, customerId: string): SlaCreditRequest {
  return {
    credit_id: String(row.credit_id), tenant_id: String(row.tenant_id), stripe_customer_id: customerId,
    amount_minor: Number(row.amount_minor), currency: String(row.currency), service_period: String(row.service_period),
    credit_percent: Number(row.credit_percent), idempotency_key: String(row.idempotency_key), catastrophic: row.catastrophic === true || row.catastrophic === 1,
  };
}

/**
 * The outbox body is the durable source of truth after a provider call. A
 * mapping lookup may change while a lease is being recovered; accepting a
 * newly mapped customer in that case would turn crash recovery into a second,
 * different money operation. Malformed or mismatched payloads are rejected so
 * the normal mapping-change guard can block them for review.
 */
function requestFromOutbox(raw: unknown, row: Record<string, unknown>): SlaCreditRequest | null {
  if (typeof raw !== "string") return null;
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (!value || typeof value !== "object") return null;
    const currency = typeof value.currency === "string" ? canonicalCurrency(value.currency) : null;
    const request: SlaCreditRequest = {
      credit_id: String(value.credit_id ?? ""),
      tenant_id: String(value.tenant_id ?? ""),
      stripe_customer_id: String(value.stripe_customer_id ?? ""),
      amount_minor: Number(value.amount_minor),
      currency: currency ?? "",
      service_period: String(value.service_period ?? ""),
      credit_percent: Number(value.credit_percent),
      idempotency_key: String(value.idempotency_key ?? ""),
      catastrophic: value.catastrophic === true || value.catastrophic === 1,
    };
    if (
      request.credit_id !== String(row.credit_id) ||
      request.tenant_id !== String(row.tenant_id) ||
      request.idempotency_key !== String(row.idempotency_key) ||
      !request.stripe_customer_id ||
      !currency ||
      !parseUtcMonth(request.service_period) ||
      !Number.isSafeInteger(request.amount_minor) || request.amount_minor <= 0 ||
      !Number.isSafeInteger(request.credit_percent) || request.credit_percent < 1 || request.credit_percent > 100
    ) return null;
    if (
      request.amount_minor !== Number(row.amount_minor) ||
      request.credit_percent !== Number(row.credit_percent) ||
      currency !== canonicalCurrency(String(row.currency))
    ) return null;
    return request;
  } catch {
    return null;
  }
}

/** Authenticated production hand-off from the provider-operated SLO reporter. */
export async function handleSlaObservationIngest(request: Request, env: SlaCreditCronEnv): Promise<Response> {
  if (request.method !== "POST") return Response.json({ error: "method_not_allowed" }, { status: 405 });
  if (!observationIngestEnabled(env)) return Response.json({ error: "sla_observation_ingest_disabled" }, { status: 503 });
  const expected = env.SLA_OBSERVATION_INGEST_KEY?.trim();
  if (!expected || expected.length < 32) return Response.json({ error: "unavailable" }, { status: 503 });
  const presented = request.headers.get("x-corelink-sla-observation-key") ?? "";
  if (!constantTimeEqual(presented, expected)) return Response.json({ error: "unauthorized" }, { status: 401 });
  const db = env.BILLING_DB;
  if (!db) return Response.json({ error: "billing_db_unbound" }, { status: 503 });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return Response.json({ error: "invalid_observation" }, { status: 400 });
  const observation = body as SlaMonthlyObservation;
  if (
    typeof observation.tenant_id !== "string" || !observation.tenant_id.trim() ||
    typeof observation.service_period !== "string" || typeof observation.tier !== "string" ||
    typeof observation.currency !== "string" || typeof observation.force_majeure !== "boolean" ||
    typeof observation.availability_percent !== "number" || typeof observation.monthly_fee_minor !== "number" ||
    typeof observation.observed_at_ms !== "number"
  ) return Response.json({ error: "invalid_observation" }, { status: 400 });
  try {
    await recordCanonicalSlaObservation(db, observation);
  } catch {
    return Response.json({ error: "invalid_observation" }, { status: 400 });
  }
  return Response.json({ accepted: true, service_period: observation.service_period });
}

/** Settle a bounded batch. Due rows are leased, so an old transient row cannot monopolise every tick. */
export async function runSlaCreditSweep(env: SlaCreditCronEnv, nowMs: number, provider?: SlaCreditProvider): Promise<SlaCreditSweepResult> {
  const result: SlaCreditSweepResult = { ok: true, skipped: false, measured: 0, produced: 0, created: 0, applied: 0, failed: 0, blocked: 0, reconciled: 0 };
  const db = env.BILLING_DB;
  if (!db) return { ...result, skipped: true };
  try {
    result.produced = await publishClosedSlaMeasurements(db, nowMs);
    const measurements = await db.prepare(`SELECT * FROM sla_monthly_measurements
      WHERE state = 'pending' AND eligible_at_ms <= ?
      ORDER BY eligible_at_ms ASC, tenant_id ASC LIMIT ?`).bind(nowMs, MAX_SWEEP_ROWS).all<Record<string, unknown>>();
    for (const row of measurements.results ?? []) {
      result.measured += 1;
      const measurement = asMeasurement(row);
      const decision = evaluateSlaCredit(measurement);
      const created = await markMeasurement(db, measurement, decision.eligible ? "evaluated" : "ineligible", decision.reason, nowMs, decision);
      result.created += created;
    }

    // The gate is inside the sweep, not merely in providerFromEnv.  A caller
    // cannot smuggle an enabled fake/provider into a disabled production env.
    if (!enabled(env) || !provider) {
      result.skipped = true;
      return result;
    }
    const due = await db.prepare(`SELECT * FROM sla_credit_ledger
      WHERE (status IN ('pending', 'failed') AND next_attempt_at_ms <= ?)
         OR (status = 'processing' AND lease_until_ms <= ?)
      ORDER BY next_attempt_at_ms ASC, credit_id ASC LIMIT ?`).bind(nowMs, nowMs, MAX_SWEEP_ROWS).all<Record<string, unknown>>();
    for (const row of due.results ?? []) {
      const creditId = String(row.credit_id);
      const attempts = Number(row.attempts) || 0;
      const outbox = await db.prepare("SELECT payload_json, provider_ref FROM sla_credit_outbox WHERE credit_id = ? LIMIT 1").bind(creditId).all<{ payload_json?: unknown; provider_ref?: string | null }>();
      const outboxRow = outbox.results?.[0];
      const recoveredRequest = outboxRow ? requestFromOutbox(outboxRow.payload_json, row) : null;
      const recoveredProviderRef = recoveredRequest && typeof outboxRow?.provider_ref === "string" ? outboxRow.provider_ref.trim() : "";
      const mapping = await db.prepare("SELECT stripe_customer_id FROM tenant_billing WHERE tenant_id = ? LIMIT 1").bind(row.tenant_id).all<{ stripe_customer_id?: string | null }>();
      const customerId = mapping.results?.[0]?.stripe_customer_id?.trim() ?? "";
      const oldCustomer = typeof row.stripe_customer_id === "string" ? row.stripe_customer_id.trim() : "";
      const requestCustomer = recoveredRequest?.stripe_customer_id ?? customerId;
      if (!requestCustomer) {
        await retryMapping(db, creditId, attempts, nowMs);
        result.failed += 1;
        continue;
      }
      if (!recoveredRequest && oldCustomer && oldCustomer !== customerId) {
        await atomic(db, [
          db.prepare("UPDATE sla_credit_ledger SET status = 'blocked', failure_kind = 'permanent', failure_reason = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ?").bind("tenant_mapping_changed", nowMs, creditId),
          await audit(db, creditId, "blocked", "tenant_mapping_changed", nowMs),
        ]);
        result.blocked += 1;
        continue;
      }
      const request = recoveredRequest ?? requestFromRow(row, requestCustomer);
      const payload = JSON.stringify(request);
      const claimed = await atomic(db, [
        db.prepare(`UPDATE sla_credit_ledger SET status = 'processing', stripe_customer_id = ?, lease_until_ms = ?, attempts = attempts + 1, updated_at_ms = ? WHERE credit_id = ? AND ((status IN ('pending', 'failed') AND next_attempt_at_ms <= ?) OR (status = 'processing' AND lease_until_ms <= ?))`).bind(request.stripe_customer_id, nowMs + LEASE_MS, nowMs, creditId, nowMs, nowMs),
        db.prepare(INSERT_OUTBOX_SQL).bind(creditId, request.idempotency_key, payload, nowMs, nowMs),
      ]);
      if (Number(claimed[0]?.meta?.changes ?? 0) !== 1) continue;

      let alreadyReconciled = false;
      let recoveredReconciliationFailure: ProviderFailure | undefined;
      let applied: ProviderResult;
      if (recoveredProviderRef && provider.reconcileCredit) {
        const recovered = await provider.reconcileCredit(request, recoveredProviderRef);
        applied = recovered.ok
          ? { provider_ref: recoveredProviderRef }
          : { provider_ref: recoveredProviderRef };
        if (!recovered.ok) recoveredReconciliationFailure = recovered.failure ?? { kind: "transient", reason: "provider_recovery_reconcile_failed" };
        alreadyReconciled = recovered.ok;
      } else {
        // No provider reference means the worker may have died before D1 saw
        // an accepted object. Replaying the exact outbox body/key is the
        // provider's idempotent recovery path.
        applied = await provider.applyCredit(request);
      }
      if (!("provider_ref" in applied)) {
        if (applied.failure.kind === "transient") {
          await atomic(db, [
            db.prepare("UPDATE sla_credit_ledger SET status = 'failed', failure_kind = ?, failure_reason = ?, next_attempt_at_ms = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ? AND status = 'processing'").bind(applied.failure.kind, applied.failure.reason, nowMs + backoff(attempts + 1), nowMs, creditId),
            db.prepare("UPDATE sla_credit_outbox SET status = 'failed', last_error = ?, updated_at_ms = ? WHERE credit_id = ?").bind(applied.failure.reason, nowMs, creditId),
            await audit(db, creditId, "retry", applied.failure.reason, nowMs),
          ]);
          result.failed += 1;
        } else {
          await atomic(db, [
            db.prepare("UPDATE sla_credit_ledger SET status = 'blocked', failure_kind = ?, failure_reason = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ? AND status = 'processing'").bind(applied.failure.kind, applied.failure.reason, nowMs, creditId),
            db.prepare("UPDATE sla_credit_outbox SET status = 'blocked', last_error = ?, updated_at_ms = ? WHERE credit_id = ?").bind(applied.failure.reason, nowMs, creditId),
            await audit(db, creditId, "blocked", applied.failure.reason, nowMs),
          ]);
          result.blocked += 1;
        }
        continue;
      }

      const reconciliation = recoveredReconciliationFailure
        ? { ok: false, failure: recoveredReconciliationFailure }
        : alreadyReconciled
          ? { ok: true }
          : provider.reconcileCredit
            ? await provider.reconcileCredit(request, applied.provider_ref)
            : { ok: true };
      if (!reconciliation.ok) {
        const failure = reconciliation.failure ?? { kind: "transient" as const, reason: "stripe_reconcile_failed" };
        if (failure.kind === "transient") {
          await atomic(db, [
            db.prepare("UPDATE sla_credit_ledger SET status = 'failed', provider_ref = ?, failure_kind = ?, failure_reason = ?, next_attempt_at_ms = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ? AND status = 'processing'").bind(applied.provider_ref, failure.kind, failure.reason, nowMs + backoff(attempts + 1), nowMs, creditId),
            db.prepare("UPDATE sla_credit_outbox SET status = 'sent', provider_ref = ?, last_error = ?, updated_at_ms = ? WHERE credit_id = ?").bind(applied.provider_ref, failure.reason, nowMs, creditId),
            db.prepare("INSERT INTO sla_credit_reconciliation (credit_id, provider_ref, status, next_attempt_at_ms, last_error, updated_at_ms) VALUES (?, ?, 'pending', ?, ?, ?) ON CONFLICT(credit_id) DO UPDATE SET provider_ref = excluded.provider_ref, status = 'pending', next_attempt_at_ms = excluded.next_attempt_at_ms, last_error = excluded.last_error, updated_at_ms = excluded.updated_at_ms").bind(creditId, applied.provider_ref, nowMs + backoff(attempts + 1), failure.reason, nowMs),
            await audit(db, creditId, "retry", failure.reason, nowMs),
          ]);
          result.failed += 1;
        } else {
          await atomic(db, [
            db.prepare("UPDATE sla_credit_ledger SET status = 'blocked', provider_ref = ?, failure_kind = 'permanent', failure_reason = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ? AND status = 'processing'").bind(applied.provider_ref, failure.reason, nowMs, creditId),
            db.prepare("UPDATE sla_credit_outbox SET status = 'needs_review', provider_ref = ?, last_error = ?, updated_at_ms = ? WHERE credit_id = ?").bind(applied.provider_ref, failure.reason, nowMs, creditId),
            db.prepare("INSERT INTO sla_credit_reconciliation (credit_id, provider_ref, status, next_attempt_at_ms, last_error, updated_at_ms) VALUES (?, ?, 'mismatch', ?, ?, ?) ON CONFLICT(credit_id) DO UPDATE SET provider_ref = excluded.provider_ref, status = 'mismatch', last_error = excluded.last_error, updated_at_ms = excluded.updated_at_ms").bind(creditId, applied.provider_ref, nowMs, failure.reason, nowMs),
            await audit(db, creditId, "blocked", failure.reason, nowMs),
          ]);
          result.blocked += 1;
        }
        continue;
      }
      await atomic(db, [
        db.prepare("UPDATE sla_credit_ledger SET status = 'applied', provider_ref = ?, applied_at_ms = ?, lease_until_ms = NULL, updated_at_ms = ? WHERE credit_id = ? AND status = 'processing'").bind(applied.provider_ref, nowMs, nowMs, creditId),
        db.prepare("UPDATE sla_credit_outbox SET status = 'sent', provider_ref = ?, updated_at_ms = ? WHERE credit_id = ?").bind(applied.provider_ref, nowMs, creditId),
        db.prepare("INSERT INTO sla_credit_reconciliation (credit_id, provider_ref, status, next_attempt_at_ms, updated_at_ms) VALUES (?, ?, 'reconciled', ?, ?) ON CONFLICT(credit_id) DO UPDATE SET provider_ref = excluded.provider_ref, status = 'reconciled', next_attempt_at_ms = excluded.next_attempt_at_ms, updated_at_ms = excluded.updated_at_ms").bind(creditId, applied.provider_ref, nowMs, nowMs),
        await audit(db, creditId, "applied", applied.provider_ref, nowMs),
      ]);
      result.applied += 1;
      result.reconciled += 1;
    }
  } catch (error) {
    result.ok = false;
    console.error(`[sla-credit-cron] sweep failed: ${error instanceof Error ? error.message.slice(0, 240) : "unknown"}`);
  }
  return result;
}

export function providerFromEnv(env: SlaCreditCronEnv): SlaCreditProvider | undefined {
  if (!enabled(env)) return undefined;
  const key = env.STRIPE_SECRET_KEY?.trim();
  return key ? new StripeInvoiceItemProvider(key, env.STRIPE_API_BASE, true) : undefined;
}
