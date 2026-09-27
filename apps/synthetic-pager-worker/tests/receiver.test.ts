import { afterEach, describe, expect, it, vi } from "vitest";
import handler, { runDeferredDeliveries } from "../src/index.js";
import {
  buildPagerDutyEvent,
  parseSyntheticPageEnvelope,
  validateReceiverEnvironment,
  type ReceiverEnv,
} from "../src/contract.js";

const drillId = "SP-1785765600000";
const correlation = `PAT-CORRELATION-ID-001:${drillId}`;
const deferredDrillId = "SP-1787580000000";
const deferredCorrelation = `PAT-CORRELATION-ID-001:${deferredDrillId}`;
const immediateEnvelope = {
  drill: "synthetic_page",
  cron: "0 14 * * 1",
  scheduled_at_ms: 1_785_765_600_000,
  synthetic_page: {
    service: "synthetic-drill",
    event_action: "trigger",
    severity: "info",
    synthetic_severity: "sev2_synthetic",
    region: "americas",
    rotation_week: 0,
    emit_at_ms: 1_785_765_600_000,
    delivery_mode: "immediate",
    provider_mode: "pagerduty",
    worker_revision: "",
    serving_sha: "",
    dedup_key: drillId,
    correlation_id: correlation,
  },
} as const;
const deferredEnvelope = {
  ...immediateEnvelope,
  scheduled_at_ms: 1_787_580_000_000,
  synthetic_page: {
    ...immediateEnvelope.synthetic_page,
    region: "boundary_handoff",
    rotation_week: 3,
    emit_at_ms: 1_788_134_340_000,
    delivery_mode: "deferred",
    dedup_key: deferredDrillId,
    correlation_id: deferredCorrelation,
  },
} as const;

function fakeDb(options: { row?: unknown; persistedOutcome?: string; rows?: unknown[]; failBatch?: boolean; failBatchAt?: number; providerReceipt?: unknown; providerAudit?: boolean } = {}) {
  const calls: string[] = [];
  let batchNumber = 0;
  const run = vi.fn().mockResolvedValue({ success: true });
  const batch = vi.fn().mockImplementation(async () => {
    batchNumber += 1;
    calls.push("batch");
    if (options.failBatch || options.failBatchAt === batchNumber) throw new Error("storage unavailable");
    for (const row of options.rows ?? []) {
      if (typeof row === "object" && row !== null && "delivery_mode" in row && "delivered_at_ms" in row) {
        (row as { delivered_at_ms: number | null }).delivered_at_ms = 1_788_134_340_000;
      }
    }
    return [];
  });
  const prepare = vi.fn().mockImplementation((sql: string) => {
    calls.push(`prepare:${sql.slice(0, 24)}`);
    return {
      bind: vi.fn().mockImplementation(() => ({
        all: vi.fn().mockResolvedValue({
          results: (options.rows ?? []).filter((row) =>
            typeof row === "object" && row !== null && "delivery_mode" in row && "delivered_at_ms" in row
              ? (row as { delivery_mode: string; delivered_at_ms: number | null }).delivery_mode === "deferred" &&
                (row as { delivered_at_ms: number | null }).delivered_at_ms === null
              : true,
          ),
        }),
        first: vi.fn().mockImplementation(async () =>
          sql.includes("SELECT outcome FROM synthetic_page_drills_b072")
            ? options.persistedOutcome === undefined ? null : { outcome: options.persistedOutcome }
            : sql.includes("FROM synthetic_page_provider_receipts") ? options.providerReceipt ?? null
            : sql.includes("FROM synthetic_page_provider_audit_events") ? options.providerAudit ? { present: 1 } : null
            : options.row ?? null),
        run,
      })),
    };
  });
  return { db: { prepare, batch } as unknown as D1Database, prepare, batch, run, calls };
}

function env(overrides: Partial<ReceiverEnv> = {}, dbOptions: Parameters<typeof fakeDb>[0] = {}) {
  const database = fakeDb(dbOptions);
  return {
    value: {
      ENVIRONMENT: "staging",
      SYNTHETIC_DRILL_ENABLED: "true",
      PAGERDUTY_EVENTS_URL: "https://events.pagerduty.com/v2/enqueue",
      PAGERDUTY_SERVICE: "synthetic-drill",
      PAGERDUTY_SYNTHETIC_ROUTING_KEY: "test-routing-key",
      PAGERDUTY_WEBHOOK_SECRET: "webhook-secret",
      CONFIG_DB: database.db,
      ...overrides,
  } satisfies ReceiverEnv,
    database,
  };
}

function request(body: unknown, path = "/v1/drills/synthetic_page"): Request {
  const dedupKey = (body as { synthetic_page: { dedup_key: string } }).synthetic_page.dedup_key;
  return new Request(`https://synthetic.example${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-corelink-scheduled-drill-id": dedupKey,
    },
    body: JSON.stringify(body),
  });
}

const workerFetch = handler.fetch!;
const workerScheduled = handler.scheduled!;
async function invoke(requestValue: Request, environment: ReceiverEnv): Promise<Response> {
  return workerFetch(requestValue as Parameters<typeof workerFetch>[0], environment, {} as ExecutionContext);
}

async function signature(body: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
  return `v1=${[...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

afterEach(() => vi.unstubAllGlobals());

describe("synthetic receiver contract", () => {
  it("uses one canonical drill id for PagerDuty dedup and correlation", () => {
    const page = parseSyntheticPageEnvelope(immediateEnvelope)!.synthetic_page;
    expect(page.dedup_key).toBe(drillId);
    expect(buildPagerDutyEvent(page, "routing-key")).toMatchObject({
      event_action: "trigger",
      dedup_key: drillId,
      payload: { custom_details: { correlation_id: correlation } },
    });
    expect(parseSyntheticPageEnvelope({
      ...immediateEnvelope,
      synthetic_page: { ...immediateEnvelope.synthetic_page, correlation_id: "wrong" },
    })).toBeNull();
    expect(parseSyntheticPageEnvelope({
      ...immediateEnvelope,
      scheduled_at_ms: immediateEnvelope.scheduled_at_ms + 1,
    })).toBeNull();
    expect(parseSyntheticPageEnvelope({
      ...immediateEnvelope,
      synthetic_page: { ...immediateEnvelope.synthetic_page, region: "emea" },
    })).toBeNull();
    expect(parseSyntheticPageEnvelope({
      ...deferredEnvelope,
      synthetic_page: { ...deferredEnvelope.synthetic_page, emit_at_ms: deferredEnvelope.synthetic_page.emit_at_ms + 1 },
    })).toBeNull();
  });

  it.each(["prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd"])(
    "rejects %s before any external delivery",
    (environment) => {
      expect(validateReceiverEnvironment(env({ ENVIRONMENT: environment }).value)).toContain("production");
    },
  );

  it("commits D1 and audit before PagerDuty fetch", async () => {
    const receiver = env();
    const order: string[] = [];
    const pagerDutyFetch = vi.fn<typeof fetch>().mockImplementation(async () => {
      order.push("pagerduty");
      return new Response(null, { status: 202 });
    });
    receiver.database.batch.mockImplementation(async () => {
      order.push("d1");
      return [];
    });
    vi.stubGlobal("fetch", pagerDutyFetch);
    expect((await invoke(request(immediateEnvelope), receiver.value)).status).toBe(202);
    expect(order).toEqual(["d1", "pagerduty", "d1"]);
    expect(receiver.database.batch).toHaveBeenCalledTimes(2);
  });

  it("does not record a delivery receipt when PagerDuty rejects the event", async () => {
    const receiver = env();
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 503 })));
    expect((await invoke(request(immediateEnvelope), receiver.value)).status).toBe(502);
    expect(receiver.database.batch).toHaveBeenCalledOnce();
  });

  it("returns retryable 503 when PagerDuty accepted but its durable receipt failed", async () => {
    const receiver = env({}, { failBatchAt: 2 });
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 202 })));
    const response = await invoke(request(immediateEnvelope), receiver.value);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "delivery_receipt_unavailable" });
    expect(receiver.database.batch).toHaveBeenCalledTimes(2);
  });

  it("suppresses PagerDuty when D1 storage fails", async () => {
    const receiver = env({}, { failBatch: true });
    const pagerDutyFetch = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", pagerDutyFetch);
    expect((await invoke(request(immediateEnvelope), receiver.value)).status).toBe(503);
    expect(pagerDutyFetch).not.toHaveBeenCalled();
  });

  it("persists the deferred handoff and returns 202 without dropping it", async () => {
    const receiver = env();
    const pagerDutyFetch = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", pagerDutyFetch);
    const response = await invoke(request(deferredEnvelope), receiver.value);
    expect(response.status).toBe(202);
    expect(JSON.parse(await response.text())).toMatchObject({ deferred: true, dedup_key: deferredDrillId });
    expect(receiver.database.batch).toHaveBeenCalledOnce();
    expect(pagerDutyFetch).not.toHaveBeenCalled();
  });

  it("records an explicit provider-deferred terminal receipt without PagerDuty credentials", async () => {
    const receipt = {
      drill_id: deferredDrillId,
      scheduled_at_ms: deferredEnvelope.scheduled_at_ms,
      correlation_id: deferredCorrelation,
      provider_mode: "provider_deferred",
      outcome: "provider_deferred",
      scheduler_worker_revision: "cf-scheduler-version-7",
      serving_sha: "0123456789abcdef0123456789abcdef01234567",
      receiver_worker_revision: "cf-receiver-version-9",
      receiver_result: "persisted_provider_deferred",
    };
    const receiver = env({
      SYNTHETIC_DRILL_PROVIDER_MODE: "provider_deferred",
      PAGERDUTY_EVENTS_URL: undefined,
      PAGERDUTY_SERVICE: undefined,
      PAGERDUTY_SYNTHETIC_ROUTING_KEY: undefined,
      PAGERDUTY_WEBHOOK_SECRET: undefined,
      CF_VERSION_METADATA: { id: "cf-receiver-version-9" },
    }, { providerReceipt: receipt, providerAudit: true });
    const pagerDutyFetch = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", pagerDutyFetch);
    const requestEnvelope = {
      ...deferredEnvelope,
      synthetic_page: { ...deferredEnvelope.synthetic_page,
        provider_mode: "provider_deferred" as const,
        worker_revision: "cf-scheduler-version-7",
        serving_sha: "0123456789abcdef0123456789abcdef01234567" },
    };
    const response = await invoke(request(requestEnvelope), receiver.value);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ terminal: true, outcome: "provider_deferred",
      receiver_result: "persisted_provider_deferred", drill_id: deferredDrillId,
      correlation_id: deferredCorrelation, serving_sha: receipt.serving_sha });
    expect(pagerDutyFetch).not.toHaveBeenCalled();
    expect(receiver.database.batch).toHaveBeenCalledTimes(2);
    expect(receiver.database.prepare.mock.calls.some(([sql]) => String(sql).includes("synthetic_page_provider_audit_events"))).toBe(true);
  });

  it("rejects missing correlation/provenance and unexpected provider fields", () => {
    const providerEnvelope = { ...deferredEnvelope, synthetic_page: { ...deferredEnvelope.synthetic_page,
      provider_mode: "provider_deferred" as const, worker_revision: "cf-scheduler-version-7",
      serving_sha: "0123456789abcdef0123456789abcdef01234567" } };
    expect(parseSyntheticPageEnvelope({ ...providerEnvelope, synthetic_page: {
      ...providerEnvelope.synthetic_page, correlation_id: "forged" } })).toBeNull();
    expect(parseSyntheticPageEnvelope({ ...providerEnvelope, synthetic_page: {
      ...providerEnvelope.synthetic_page, worker_revision: "" } })).toBeNull();
    expect(parseSyntheticPageEnvelope({ ...providerEnvelope, synthetic_page: {
      ...providerEnvelope.synthetic_page, serving_sha: "unknown" } })).toBeNull();
    expect(parseSyntheticPageEnvelope({ ...providerEnvelope, synthetic_page: {
      ...providerEnvelope.synthetic_page, terminal: true } })).toBeNull();
  });

  it("rejects a provider mode that differs from receiver configuration", async () => {
    const receiver = env();
    const fetchStub = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchStub);
    const response = await invoke(request({ ...deferredEnvelope, synthetic_page: {
      ...deferredEnvelope.synthetic_page, provider_mode: "provider_deferred" as const,
      worker_revision: "cf-scheduler-version-7", serving_sha: "0123456789abcdef0123456789abcdef01234567" } }), receiver.value);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "provider_mode_mismatch" });
    expect(receiver.database.batch).not.toHaveBeenCalled();
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it("does not persist terminal work when the receiver revision is unavailable", async () => {
    const receiver = env({ SYNTHETIC_DRILL_PROVIDER_MODE: "provider_deferred",
      PAGERDUTY_EVENTS_URL: undefined, PAGERDUTY_SERVICE: undefined,
      PAGERDUTY_SYNTHETIC_ROUTING_KEY: undefined, PAGERDUTY_WEBHOOK_SECRET: undefined,
      CF_VERSION_METADATA: undefined });
    const response = await invoke(request({ ...deferredEnvelope, synthetic_page: {
      ...deferredEnvelope.synthetic_page, provider_mode: "provider_deferred" as const,
      worker_revision: "cf-scheduler-version-7", serving_sha: "0123456789abcdef0123456789abcdef01234567" } }), receiver.value);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "provider_deferred_provenance_unavailable" });
    expect(receiver.database.batch).not.toHaveBeenCalled();
  });

  it("fails closed when provider-deferred provenance does not match the stored receipt", async () => {
    const receiver = env({
      SYNTHETIC_DRILL_PROVIDER_MODE: "provider_deferred",
      PAGERDUTY_EVENTS_URL: undefined,
      PAGERDUTY_SERVICE: undefined,
      PAGERDUTY_SYNTHETIC_ROUTING_KEY: undefined,
      PAGERDUTY_WEBHOOK_SECRET: undefined,
      CF_VERSION_METADATA: { id: "cf-receiver-version-9" },
    }, { providerReceipt: { drill_id: deferredDrillId, scheduled_at_ms: deferredEnvelope.scheduled_at_ms,
      correlation_id: "wrong-correlation", provider_mode: "provider_deferred", outcome: "provider_deferred",
      scheduler_worker_revision: "cf-scheduler-version-7", serving_sha: "0123456789abcdef0123456789abcdef01234567",
      receiver_worker_revision: "cf-receiver-version-9", receiver_result: "persisted_provider_deferred" }, providerAudit: true });
    const requestEnvelope = { ...deferredEnvelope, synthetic_page: { ...deferredEnvelope.synthetic_page,
      provider_mode: "provider_deferred" as const, worker_revision: "cf-scheduler-version-7",
      serving_sha: "0123456789abcdef0123456789abcdef01234567" } };
    const response = await invoke(request(requestEnvelope), receiver.value);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: "provider_deferred_replay_mismatch" });
  });

  it("executes deferred delivery and retries with identical dedup/correlation", async () => {
    const receiver = env({}, {
      rows: [{
        drill_id: deferredDrillId,
        region: "boundary_handoff",
        emit_ts_ms: 1_788_134_340_000,
        scheduled_at_ms: 1_787_580_000_000,
        correlation_id: deferredCorrelation,
        delivery_mode: "deferred",
        delivered_at_ms: null,
      }],
    });
    const pagerDutyFetch = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    const controller = { cron: "59 23 * * 1", scheduledTime: 1_788_134_340_000, noRetry: vi.fn() } as ScheduledController;
    const acceptedAt = 1_788_134_345_000;
    await expect(runDeferredDeliveries(controller, receiver.value, pagerDutyFetch)).rejects.toThrow("PagerDuty delivery failed");
    await expect(runDeferredDeliveries(controller, receiver.value, pagerDutyFetch, () => acceptedAt)).resolves.toBeUndefined();
    await expect(runDeferredDeliveries(controller, receiver.value, pagerDutyFetch, () => acceptedAt + 1)).resolves.toBeUndefined();
    expect(pagerDutyFetch).toHaveBeenCalledTimes(2);
    expect(pagerDutyFetch.mock.calls[0]?.[1]?.body).toBe(pagerDutyFetch.mock.calls[1]?.[1]?.body);
    expect(receiver.database.batch).toHaveBeenCalledOnce();
    expect(receiver.database.calls).toContain("batch");
  });

  it("never runs the deferred PagerDuty sweep in provider-deferred mode", async () => {
    const receiver = env({ SYNTHETIC_DRILL_PROVIDER_MODE: "provider_deferred",
      PAGERDUTY_SYNTHETIC_ROUTING_KEY: undefined }, { rows: [{ drill_id: deferredDrillId,
      region: "boundary_handoff", emit_ts_ms: 1_788_134_340_000, scheduled_at_ms: 1_787_580_000_000,
      correlation_id: deferredCorrelation, delivery_mode: "deferred", delivered_at_ms: null }] });
    const pagerDutyFetch = vi.fn<typeof fetch>();
    await expect(runDeferredDeliveries({ cron: "59 23 * * 1", scheduledTime: 1_788_134_340_000 } as ScheduledController,
      receiver.value, pagerDutyFetch)).resolves.toBeUndefined();
    expect(receiver.database.prepare).not.toHaveBeenCalled();
    expect(pagerDutyFetch).not.toHaveBeenCalled();
  });

  it("rejects an unknown receiver cron without enumerating durable rows", async () => {
    const receiver = env();
    const controller = { cron: "0 0 * * *", scheduledTime: 1_788_134_340_000, noRetry: vi.fn() } as ScheduledController;
    await expect(workerScheduled(controller, receiver.value, {} as ExecutionContext)).rejects.toThrow(
      "unknown deferred delivery cron",
    );
    expect(controller.noRetry).toHaveBeenCalledOnce();
    expect(receiver.database.prepare).not.toHaveBeenCalled();
  });

  it("requires an authenticated PagerDuty acknowledgment and records MTTA", async () => {
    const body = JSON.stringify({
      id: "pd-ack-001",
      event_type: "incident.acknowledged",
      occurred_at: "2026-09-08T14:01:00.000Z",
      data: { incident: { incident_key: drillId, assignments: [{ assignee: { summary: "eng-001" } }] } },
    });
    const receiver = env({}, {
      row: { drill_id: drillId, emit_ts_ms: 1_785_765_600_000, outcome: "unacked", correlation_id: correlation, delivered_at_ms: 1_785_765_600_100 },
      persistedOutcome: "acked",
    });
    const bad = await invoke(new Request("https://synthetic.example/v1/webhooks/pagerduty", { method: "POST", body }), receiver.value);
    expect(bad.status).toBe(401);
    const good = await invoke(new Request("https://synthetic.example/v1/webhooks/pagerduty", {
      method: "POST",
      headers: { "x-pagerduty-signature": await signature(body, "webhook-secret") },
      body,
    }), receiver.value);
    expect(good.status).toBe(202);
    expect(receiver.database.batch).toHaveBeenCalledOnce();
    expect(receiver.database.prepare).toHaveBeenCalledTimes(4);
  });

  it("records an authenticated escalation as terminal escalation, not an ack", async () => {
    const body = JSON.stringify({
      id: "pd-escalation-001",
      event_type: "incident.escalated",
      occurred_at: "2026-09-08T14:02:00.000Z",
      data: { incident: { incident_key: drillId, service: { summary: "synthetic-drill" } } },
    });
    const receiver = env({}, {
      row: { drill_id: drillId, emit_ts_ms: 1_785_765_600_000, outcome: "unacked", correlation_id: correlation, delivered_at_ms: 1_785_765_600_100 },
      persistedOutcome: "escalated",
    });
    const response = await invoke(new Request("https://synthetic.example/v1/webhooks/pagerduty", {
      method: "POST",
      headers: { "x-pagerduty-signature": await signature(body, "webhook-secret") },
      body,
    }), receiver.value);
    expect(response.status).toBe(202);
    expect(JSON.parse(await response.text())).toMatchObject({ outcome: "escalated", drill_id: drillId });
    expect(receiver.database.batch).toHaveBeenCalledOnce();
  });

  it("returns the persisted terminal outcome when competing webhook events race", async () => {
    const body = JSON.stringify({
      id: "pd-ack-lost-race",
      event_type: "incident.acknowledged",
      occurred_at: "2026-09-08T14:01:00.000Z",
      data: { incident: { incident_key: drillId } },
    });
    const receiver = env({}, {
      row: { drill_id: drillId, emit_ts_ms: 1_785_765_600_000, outcome: "unacked", correlation_id: correlation, delivered_at_ms: 1_785_765_600_100 },
      persistedOutcome: "escalated",
    });
    const response = await invoke(new Request("https://synthetic.example/v1/webhooks/pagerduty", {
      method: "POST",
      headers: { "x-pagerduty-signature": await signature(body, "webhook-secret") },
      body,
    }), receiver.value);
    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({ outcome: "escalated", drill_id: drillId });
    const batchStatements = receiver.database.batch.mock.calls[0]?.[0] as unknown[];
    expect(batchStatements).toHaveLength(2);
  });

  it("retries a signed outcome until the delivery receipt is durable", async () => {
    const body = JSON.stringify({
      id: "pd-ack-before-receipt",
      event_type: "incident.acknowledged",
      occurred_at: "2026-09-08T14:01:00.000Z",
      data: { incident: { incident_key: drillId } },
    });
    const receiver = env({}, {
      row: { drill_id: drillId, emit_ts_ms: 1_785_765_600_000, outcome: "unacked", correlation_id: correlation, delivered_at_ms: null },
    });
    const response = await invoke(new Request("https://synthetic.example/v1/webhooks/pagerduty", {
      method: "POST",
      headers: { "x-pagerduty-signature": await signature(body, "webhook-secret") },
      body,
    }), receiver.value);
    expect(response.status).toBe(503);
    expect(receiver.database.batch).not.toHaveBeenCalled();
  });
});
