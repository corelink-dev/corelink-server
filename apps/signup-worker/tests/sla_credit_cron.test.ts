import { afterEach, describe, expect, it, vi } from "vitest";
import {
  StripeInvoiceItemProvider,
  evaluateSlaCredit,
  handleSlaObservationIngest,
  monthlyCutoffAtMs,
  parseUtcMonth,
  providerFromEnv,
  runSlaCreditSweep,
  type D1DatabaseLike,
  type D1PreparedStatement,
  type SlaMonthlyMeasurement,
  type SlaCreditRequest,
} from "../src/webhooks/sla_credit_cron.js";

type Row = Record<string, unknown>;

function baseMeasurement(overrides: Partial<SlaMonthlyMeasurement> = {}): SlaMonthlyMeasurement {
  return {
    tenant_id: "tenant-1",
    service_period: "2026-08",
    tier: "enterprise",
    monthly_fee_minor: 5_000,
    currency: "USD",
    availability_percent: 99.4,
    latency_excess_percent: 0,
    latency_sustained_minutes: 0,
    dsr_breach_days: 0,
    billing_drift_percent: 0,
    billing_drift_sustained_hours: 0,
    force_majeure: false,
    eligible_at_ms: 0,
    ...overrides,
  };
}

/** Small D1 double that records the SQL boundaries the adversarial cases care about. */
class MemoryDb implements D1DatabaseLike {
  measurements: Row[];
  ledger = new Map<string, Row>();
  outbox = new Map<string, Row>();
  recon = new Map<string, Row>();
  audits: Row[] = [];
  observations: Row[] = [];
  customer: string | null = "cus_test";
  missingTenants = new Set<string>();
  constructor(measurements: Row[]) { this.measurements = measurements; }

  prepare(sql: string): D1PreparedStatement {
    let args: unknown[] = [];
    const statement = {
      bind: (...values: unknown[]) => { args = values; return statement; },
      all: async <T = Row>() => {
        if (sql.includes("sla_credit_outbox") && sql.includes("SELECT")) {
          const row = this.outbox.get(String(args[0]));
          return { results: row ? [row] as T[] : [] as T[] };
        }
        if (sql.includes("sla_monthly_observations")) return { results: this.observations.filter((row) => row.published_at_ms == null) as T[] };
        if (sql.includes("sla_monthly_measurements")) {
          return { results: this.measurements.filter((row) => row.state === "pending" && Number(row.eligible_at_ms) <= Number(args[0])).slice(0, 100) as T[] };
        }
        if (sql.includes("tenant_billing")) return { results: this.customer && !this.missingTenants.has(String(args[0])) ? [{ stripe_customer_id: this.customer }] as T[] : [] as T[] };
        if (sql.includes("FROM sla_credit_ledger")) {
          const now = Number(args[0]);
          return { results: [...this.ledger.values()].filter((row) =>
            ((row.status === "pending" || row.status === "failed") && Number(row.next_attempt_at_ms) <= now) ||
            (row.status === "processing" && Number(row.lease_until_ms) <= Number(args[1]))).sort((a, b) => Number(a.next_attempt_at_ms) - Number(b.next_attempt_at_ms)).slice(0, 100) as T[] };
        }
        return { results: [] as T[] };
      },
      run: async () => this.run(sql, args),
    };
    return statement;
  }

  async batch(statements: D1PreparedStatement[]) {
    const results: { meta: { changes: number } }[] = [];
    for (const statement of statements) results.push(await statement.run() as { meta: { changes: number } });
    return results;
  }

  private async run(sql: string, args: unknown[]): Promise<{ meta: { changes: number } }> {
    if (sql.includes("INSERT OR IGNORE INTO sla_credit_ledger")) {
      const id = String(args[0]);
      if (this.ledger.has(id)) return { meta: { changes: 0 } };
      this.ledger.set(id, {
        credit_id: id, tenant_id: args[1], service_period: args[2], credit_percent: args[3], amount_minor: args[4], currency: args[5],
        stripe_customer_id: args[6], status: "pending", idempotency_key: args[7], catastrophic: args[8], attempts: 0,
        next_attempt_at_ms: args[9], created_at_ms: args[10], updated_at_ms: args[11],
      });
      return { meta: { changes: 1 } };
    }
    if (sql.includes("INSERT OR IGNORE INTO sla_monthly_observations")) {
      this.observations.push({ tenant_id: args[0], service_period: args[1], tier: args[2], monthly_fee_minor: args[3], currency: args[4], observed_at_ms: args[13] });
      return { meta: { changes: 1 } };
    }
    if (sql.includes("UPDATE sla_monthly_measurements")) {
      const row = this.measurements.find((item) => item.tenant_id === args[5] && item.service_period === args[6] && item.state === "pending");
      if (!row) return { meta: { changes: 0 } };
      row.state = args[0]; row.decision_reason = args[1]; row.evaluated_at_ms = args[2]; row.credit_percent = args[3]; row.amount_minor = args[4];
      return { meta: { changes: 1 } };
    }
    if (sql.includes("INSERT INTO sla_credit_audit_events")) {
      this.audits.push({ credit_id: args[0], event_type: args[1], detail: args[2] });
      return { meta: { changes: 1 } };
    }
    if (sql.includes("INSERT OR IGNORE INTO sla_credit_outbox")) {
      const id = String(args[0]);
      if (this.outbox.has(id)) return { meta: { changes: 0 } };
      this.outbox.set(id, { credit_id: id, idempotency_key: args[1], payload_json: args[2], status: "pending" });
      return { meta: { changes: 1 } };
    }
    if (sql.startsWith("UPDATE sla_credit_ledger SET status = 'processing'")) {
      const row = this.ledger.get(String(args[3]));
      if (!row || !((row.status === "pending" || row.status === "failed") && Number(row.next_attempt_at_ms) <= Number(args[4]))) return { meta: { changes: 0 } };
      row.status = "processing"; row.stripe_customer_id = args[0]; row.lease_until_ms = args[1]; row.attempts = Number(row.attempts) + 1;
      return { meta: { changes: 1 } };
    }
    if (sql.startsWith("UPDATE sla_credit_ledger SET status = 'failed', failure_kind = 'transient'")) {
      const row = this.ledger.get(String(args[3]));
      if (row) { row.status = "failed"; row.failure_reason = "tenant_mapping_pending"; row.next_attempt_at_ms = args[1]; row.attempts = Number(row.attempts) + 1; }
      return { meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET status = 'applied'")) {
      const row = this.ledger.get(String(args[3]));
      if (row) { row.status = "applied"; row.provider_ref = args[0]; }
      return { meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET status = 'failed'")) {
      const hasProviderRef = sql.includes("provider_ref = ?");
      const row = this.ledger.get(String(args[args.length - 1]));
      if (row) { row.status = "failed"; row.next_attempt_at_ms = args[hasProviderRef ? 3 : 2]; if (hasProviderRef) row.provider_ref = args[0]; }
      return { meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("SET status = 'blocked'")) {
      const id = String(args[args.length - 1]);
      const row = this.ledger.get(id);
      if (row) { row.status = "blocked"; if (sql.includes("provider_ref = ?")) row.provider_ref = args[0]; }
      return { meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("UPDATE sla_credit_outbox")) {
      const row = this.outbox.get(String(args[args.length - 1]));
      if (row) { row.status = sql.includes("needs_review") ? "needs_review" : sql.includes("failed") ? "failed" : "sent"; row.provider_ref = args[0]; }
      return { meta: { changes: row ? 1 : 0 } };
    }
    if (sql.includes("INSERT INTO sla_credit_reconciliation")) {
      this.recon.set(String(args[0]), { credit_id: args[0], provider_ref: args[1], status: sql.includes("'reconciled'") ? "reconciled" : sql.includes("'mismatch'") ? "mismatch" : "pending", next_attempt_at_ms: args[2], last_error: args[3] });
      return { meta: { changes: 1 } };
    }
    return { meta: { changes: 1 } };
  }
}

function measurementRow(overrides: Partial<SlaMonthlyMeasurement> = {}): Row {
  const measurement = baseMeasurement(overrides);
  return { ...measurement, eligible_at_ms: measurement.eligible_at_ms, state: "pending" };
}

describe("B-089 strict policy boundaries", () => {
  it("uses UTC months and a cutoff after the closed month, not local time", () => {
    expect(parseUtcMonth("2026-02")?.start_ms).toBe(Date.UTC(2026, 1, 1));
    expect(parseUtcMonth("2026-2")).toBeNull();
    expect(parseUtcMonth("2026-13")).toBeNull();
    expect(monthlyCutoffAtMs("2026-08")).toBeGreaterThan(Date.UTC(2026, 8, 1));
  });

  it("rejects unsafe integer fees and never creates an unsafe amount", () => {
    expect(evaluateSlaCredit(baseMeasurement({ monthly_fee_minor: Number.MAX_SAFE_INTEGER + 1 })).reason).toBe("invalid_measurement");
    expect(evaluateSlaCredit(baseMeasurement({ monthly_fee_minor: 1, availability_percent: 99.95 })).eligible).toBe(false);
    expect(evaluateSlaCredit(baseMeasurement({ currency: "usd", availability_percent: 99.49 })).amount_minor).toBe(250);
  });

  it("caps stacked credits and marks an absolute <95% result catastrophic", () => {
    const result = evaluateSlaCredit(baseMeasurement({ availability_percent: 94.99, latency_excess_percent: 80, latency_sustained_minutes: 60, dsr_breach_days: 45, billing_drift_percent: 0.2, billing_drift_sustained_hours: 25 }));
    expect(result).toMatchObject({ eligible: true, credit_percent: 100, amount_minor: 5_000, catastrophic: true });
  });

  it("excludes all five non-Enterprise launch tiers before credit calculation", () => {
    for (const tier of ["free", "solo", "starter", "pro", "max"]) {
      const decision = evaluateSlaCredit(baseMeasurement({ tier, availability_percent: 90 }));
      expect(decision).toMatchObject({ eligible: false, credit_percent: 0, amount_minor: 0,
        reason: tier === "free" ? "free_tier_excluded" : "tier_not_in_executed_sla" });
    }
    expect(evaluateSlaCredit(baseMeasurement({ tier: " ENTERPRISE ", availability_percent: 99.49 })))
      .toMatchObject({ eligible: true, credit_percent: 5, amount_minor: 250 });
  });
});

describe("B-089 gates, retries, and transaction boundaries", () => {
  it("never creates a ledger, outbox, or provider call for the five excluded tiers", async () => {
    for (const tier of ["free", "solo", "starter", "pro", "max"]) {
      const db = new MemoryDb([measurementRow({ tier, availability_percent: 90 })]);
      const applyCredit = vi.fn(async () => ({ provider_ref: "ii_forbidden" }));
      const result = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, { applyCredit });
      expect(result).toMatchObject({ measured: 1, created: 0, applied: 0, blocked: 0 });
      expect(db.measurements[0]).toMatchObject({ state: "ineligible", credit_percent: 0, amount_minor: 0,
        decision_reason: tier === "free" ? "free_tier_excluded" : "tier_not_in_executed_sla" });
      expect(db.ledger.size).toBe(0);
      expect(db.outbox.size).toBe(0);
      expect(applyCredit).not.toHaveBeenCalled();
    }
  });
  it("does not let a supplied provider bypass the in-sweep financial gate", async () => {
    const db = new MemoryDb([measurementRow()]);
    let calls = 0;
    const provider = { applyCredit: async () => { calls += 1; return { provider_ref: "ii_test" }; } };
    const result = await runSlaCreditSweep({ BILLING_DB: db }, 0, provider);
    expect(result.applied).toBe(0);
    expect(calls).toBe(0);
    expect([...db.ledger.values()][0]?.status).toBe("pending");
  });

  it("retries a missing tenant mapping instead of permanently blocking the credit", async () => {
    const db = new MemoryDb([measurementRow()]);
    db.customer = null;
    const provider = { applyCredit: async () => ({ provider_ref: "ii_test" }) };
    const first = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, provider);
    expect(first.failed).toBe(1);
    expect([...db.ledger.values()][0]?.status).toBe("failed");
    db.customer = "cus_late";
    const second = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 120_000, provider);
    expect(second.applied).toBe(1);
    expect([...db.ledger.values()][0]?.stripe_customer_id).toBe("cus_late");
    // One mapping retry plus one provider lease claim are both durable
    // attempts; the mapping retry must not remain an invisible loop.
    expect([...db.ledger.values()][0]?.attempts).toBe(2);
    expect([...db.ledger.values()][0]?.next_attempt_at_ms).toBe(120_000);
  });

  it("does not let a due population of mapping misses starve the next ready tenant", async () => {
    const rows = Array.from({ length: 101 }, (_, index) => measurementRow({ tenant_id: `missing-${index}` }));
    rows[100] = measurementRow({ tenant_id: "ready-after-misses" });
    const db = new MemoryDb(rows);
    for (let index = 0; index < 100; index += 1) db.missingTenants.add(`missing-${index}`);
    const provider = { applyCredit: vi.fn(async () => ({ provider_ref: "ii_ready" })) };
    const first = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, provider);
    expect(first.failed).toBe(100);
    expect([...db.ledger.values()].filter((row) => row.attempts === 1)).toHaveLength(100);
    const second = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, provider);
    expect(second.applied).toBe(1);
    expect(db.ledger.get("sla_credit:ready-after-misses:2026-08")?.status).toBe("applied");
  });

  it("does not starve a newer row behind a bounded batch of ineligible rows", async () => {
    const rows = Array.from({ length: 101 }, (_, index) => measurementRow({ tenant_id: `t-${index}`, availability_percent: 99.95 }));
    rows[100] = measurementRow({ tenant_id: "newer", availability_percent: 99.4 });
    const db = new MemoryDb(rows);
    const first = await runSlaCreditSweep({ BILLING_DB: db }, 0);
    expect(first.measured).toBe(100);
    const second = await runSlaCreditSweep({ BILLING_DB: db }, 0);
    expect(second.measured).toBe(1);
    expect(db.ledger.has("sla_credit:newer:2026-08")).toBe(true);
  });

  it("records outbox and reconciliation state in the same post-provider batch", async () => {
    const db = new MemoryDb([measurementRow()]);
    const provider = { applyCredit: async (request: { idempotency_key: string }) => ({ provider_ref: `ref:${request.idempotency_key}` }) };
    const result = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, provider);
    expect(result).toMatchObject({ created: 1, applied: 1, reconciled: 1 });
    expect(db.outbox.get("sla_credit:tenant-1:2026-08")?.status).toBe("sent");
    expect(db.recon.get("sla_credit:tenant-1:2026-08")?.status).toBe("reconciled");
    expect(db.audits.map((row) => row.event_type)).toEqual(["created", "applied"]);
  });

  it("recovers an accepted provider object from the outbox across a mapping change", async () => {
    const db = new MemoryDb([]);
    db.customer = "cus_new";
    const request: SlaCreditRequest = {
      credit_id: "sla_credit:tenant-crash:2026-08",
      tenant_id: "tenant-crash",
      stripe_customer_id: "cus_old",
      amount_minor: 250,
      currency: "USD",
      service_period: "2026-08",
      credit_percent: 5,
      idempotency_key: "sla-credit:sla_credit:tenant-crash:2026-08",
      catastrophic: false,
    };
    db.ledger.set(request.credit_id, {
      ...request, status: "failed", attempts: 1, next_attempt_at_ms: 0, lease_until_ms: null,
      created_at_ms: 0, updated_at_ms: 0,
    });
    db.outbox.set(request.credit_id, { credit_id: request.credit_id, idempotency_key: request.idempotency_key, payload_json: JSON.stringify(request), provider_ref: "ii_accepted", status: "sent" });
    const apply = vi.fn(async () => ({ provider_ref: "ii_duplicate" }));
    const reconcile = vi.fn(async (recovered: SlaCreditRequest, providerRef: string) => {
      expect(recovered.stripe_customer_id).toBe("cus_old");
      expect(providerRef).toBe("ii_accepted");
      return { ok: true } as const;
    });
    const result = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, { applyCredit: apply, reconcileCredit: reconcile });
    expect(result).toMatchObject({ applied: 1, blocked: 0, reconciled: 1 });
    expect(apply).not.toHaveBeenCalled();
    expect(reconcile).toHaveBeenCalledOnce();
    expect(db.ledger.get(request.credit_id)?.status).toBe("applied");
  });

  it("persists a transient recovery-reconcile failure instead of orphaning the provider object", async () => {
    const db = new MemoryDb([]);
    db.customer = "cus_new";
    const request: SlaCreditRequest = {
      credit_id: "sla_credit:tenant-recovery-transient:2026-08", tenant_id: "tenant-recovery-transient",
      stripe_customer_id: "cus_old", amount_minor: 250, currency: "USD", service_period: "2026-08",
      credit_percent: 5, idempotency_key: "sla-credit:sla_credit:tenant-recovery-transient:2026-08", catastrophic: false,
    };
    db.ledger.set(request.credit_id, { ...request, status: "failed", attempts: 1, next_attempt_at_ms: 0, lease_until_ms: null, created_at_ms: 0, updated_at_ms: 0 });
    db.outbox.set(request.credit_id, { credit_id: request.credit_id, idempotency_key: request.idempotency_key, payload_json: JSON.stringify(request), provider_ref: "ii_transient", status: "sent" });
    const result = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, {
      applyCredit: vi.fn(async () => ({ provider_ref: "ii_duplicate" })),
      reconcileCredit: async () => ({ ok: false, failure: { kind: "transient", reason: "stripe_reconcile_http_503" } }),
    });
    expect(result).toMatchObject({ applied: 0, failed: 1, blocked: 0 });
    expect(db.ledger.get(request.credit_id)).toMatchObject({ status: "failed", provider_ref: "ii_transient" });
    expect(db.outbox.get(request.credit_id)).toMatchObject({ status: "sent", provider_ref: "ii_transient" });
    expect(db.recon.get(request.credit_id)).toMatchObject({ status: "pending", provider_ref: "ii_transient", last_error: "stripe_reconcile_http_503" });
  });

  it("marks a permanent recovery mismatch needs-review with durable reconciliation evidence", async () => {
    const db = new MemoryDb([]);
    db.customer = "cus_new";
    const request: SlaCreditRequest = {
      credit_id: "sla_credit:tenant-recovery-mismatch:2026-08", tenant_id: "tenant-recovery-mismatch",
      stripe_customer_id: "cus_old", amount_minor: 250, currency: "USD", service_period: "2026-08",
      credit_percent: 5, idempotency_key: "sla-credit:sla_credit:tenant-recovery-mismatch:2026-08", catastrophic: false,
    };
    db.ledger.set(request.credit_id, { ...request, status: "failed", attempts: 1, next_attempt_at_ms: 0, lease_until_ms: null, created_at_ms: 0, updated_at_ms: 0 });
    db.outbox.set(request.credit_id, { credit_id: request.credit_id, idempotency_key: request.idempotency_key, payload_json: JSON.stringify(request), provider_ref: "ii_mismatch", status: "sent" });
    const result = await runSlaCreditSweep({ BILLING_DB: db, SLA_CREDITS_ENABLED: "true" }, 0, {
      applyCredit: vi.fn(async () => ({ provider_ref: "ii_duplicate" })),
      reconcileCredit: async () => ({ ok: false, failure: { kind: "permanent", reason: "stripe_reconcile_mismatch" } }),
    });
    expect(result).toMatchObject({ applied: 0, failed: 0, blocked: 1 });
    expect(db.ledger.get(request.credit_id)).toMatchObject({ status: "blocked", provider_ref: "ii_mismatch" });
    expect(db.outbox.get(request.credit_id)).toMatchObject({ status: "needs_review", provider_ref: "ii_mismatch" });
    expect(db.recon.get(request.credit_id)).toMatchObject({ status: "mismatch", provider_ref: "ii_mismatch", last_error: "stripe_reconcile_mismatch" });
  });
});

describe("Stripe provider gate and reconciliation", () => {
  afterEach(() => vi.restoreAllMocks());

  it("does not call Stripe unless the provider was constructed enabled", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const request = { credit_id: "c", tenant_id: "t", stripe_customer_id: "cus", amount_minor: 100, currency: "USD", service_period: "2026-08", credit_percent: 1, idempotency_key: "k", catastrophic: false };
    await expect(new StripeInvoiceItemProvider("sk_test").applyCredit(request)).resolves.toEqual({ failure: { kind: "permanent", reason: "provider_disabled" } });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the stable idempotency key and verifies the created invoice item", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "ii_test" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ amount: -100, currency: "usd", customer: "cus", metadata: { credit_id: "c", service_period: "2026-08", credit_percent: "1" } }), { status: 200 }));
    const provider = new StripeInvoiceItemProvider("sk_test", "https://stripe.test/", true);
    const request = { credit_id: "c", tenant_id: "t", stripe_customer_id: "cus", amount_minor: 100, currency: "USD", service_period: "2026-08", credit_percent: 1, idempotency_key: "stable", catastrophic: false };
    await expect(provider.applyCredit(request)).resolves.toEqual({ provider_ref: "ii_test" });
    await expect(provider.reconcileCredit(request, "ii_test")).resolves.toEqual({ ok: true });
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).headers).toMatchObject({ "Idempotency-Key": "stable" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects a provider object whose currency, service period, or percentage drifts", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify({ amount: -100, currency: "eur", customer: "cus", metadata: { credit_id: "c", service_period: "2026-09", credit_percent: "2" } }), { status: 200 }));
    const provider = new StripeInvoiceItemProvider("sk_test", "https://stripe.test/", true);
    const request = { credit_id: "c", tenant_id: "t", stripe_customer_id: "cus", amount_minor: 100, currency: "USD", service_period: "2026-08", credit_percent: 1, idempotency_key: "stable", catastrophic: false };
    await expect(provider.reconcileCredit(request, "ii_test")).resolves.toEqual({ ok: false, failure: { kind: "permanent", reason: "stripe_reconcile_mismatch" } });
  });

  it("requires both the parked gate and the Stripe secret", () => {
    expect(providerFromEnv({ STRIPE_SECRET_KEY: "sk_test" })).toBeUndefined();
    expect(providerFromEnv({ SLA_CREDITS_ENABLED: "true" })).toBeUndefined();
    expect(providerFromEnv({ SLA_CREDITS_ENABLED: "true", STRIPE_SECRET_KEY: "sk_test" })).toBeDefined();
  });
});

describe("B-089 canonical observation producer", () => {
  const key = "observation-ingest-key-012345678901234567890";
  const body = {
    tenant_id: "tenant-producer",
    service_period: "2026-08",
    tier: "pro",
    monthly_fee_minor: 5_000,
    currency: "usd",
    availability_percent: 99.4,
    force_majeure: false,
    eligible_at_ms: 0,
    observed_at_ms: Date.UTC(2026, 8, 1),
  };

  it("is an authenticated, gated production caller of the canonical writer", async () => {
    const db = new MemoryDb([]);
    const env = { BILLING_DB: db, SLA_CREDITS_ENABLED: "true", SLA_OBSERVATIONS_ENABLED: "true", SLA_OBSERVATION_INGEST_KEY: key };
    await expect(handleSlaObservationIngest(new Request("https://worker.test/internal/sla/monthly-observation", { method: "POST", body: JSON.stringify(body) }), env)).resolves.toMatchObject({ status: 401 });
    const response = await handleSlaObservationIngest(new Request("https://worker.test/internal/sla/monthly-observation", { method: "POST", headers: { "x-corelink-sla-observation-key": key, "content-type": "application/json" }, body: JSON.stringify(body) }), env);
    expect(response.status).toBe(200);
    expect(db.observations).toHaveLength(1);
  });

  it("stays parked even when a caller supplies a valid observation body", async () => {
    const db = new MemoryDb([]);
    const response = await handleSlaObservationIngest(new Request("https://worker.test/internal/sla/monthly-observation", { method: "POST", headers: { "x-corelink-sla-observation-key": key }, body: JSON.stringify(body) }), { BILLING_DB: db, SLA_CREDITS_ENABLED: "false", SLA_OBSERVATIONS_ENABLED: "true", SLA_OBSERVATION_INGEST_KEY: key });
    expect(response.status).toBe(503);
    expect(db.observations).toHaveLength(0);
  });
});
