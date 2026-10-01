/**
 * Unit tests for worker/src/durable_object.ts — DO state machine, lifecycle
 * events, health probe, constant-time comparison, per-tenant pinning.
 *
 * Tests run in Node.js environment (no cloudflare:test / workerd runtime).
 * We test the DO class directly by constructing it with mock DurableObjectState.
 *
 * Charter invariants verified:
 *   - Telemetry fires BEFORE container action (audit-before-mutation)
 *   - Body bytes NEVER in error response (INV-NO-BODY-IN-LOGS)
 *   - Constant-time comparison (timingSafeEqual) correctness
 *   - Per-tenant isolation (DO IDs derived from tenant path)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CoreLinkServer, timingSafeEqual, STAGING_D1_HTTP_OPERATION_KEY, STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY } from "../src/durable_object.js";
import { STAGING_D1_PROBE_WINDOW } from "../src/staging_runtime_d1_probe.js";
import { V8_PROBE_NAME, V8_PROBE_RELEASE, V8_PROBE_NONCE, V8_PROBE_RETIRED_KEY, V8_CLEANUP_RECEIPT_KEY } from "../src/staging_d1_probe_v8_cleanup.js";
import { V9_PROBE_NAME, V9_PROBE_RELEASE, V9_PROBE_NONCE, V9_PROBE_RETIRED_KEY } from "../src/staging_d1_probe_v9_cleanup.js";
import { OLD_PROBE_NAME, OLD_PROBE_RELEASE, V5_PROBE_NAME, V5_PROBE_RELEASE } from "../src/staging_d1_probe_retirement.js";
import { createHttpLifetime, httpDeadlineContext, STAGING_D1_HTTP_LIFETIME_KEY } from "../src/staging_d1_http_lifetime.js";
import { isStagingD1HttpStatus } from "../src/staging_d1_http_contract.js";
import cleanupWindow from "../src/staging_d1_probe_cleanup_window.json";
import type { Env } from "../src/index.js";

// ──────────────────────────────────────────────────────────────────────────────
// Mock helpers
// ──────────────────────────────────────────────────────────────────────────────

/** Create a mock DurableObjectState. Container is always undefined (no CF runtime). */
function makeMockState(idStr = "test-do-id"): DurableObjectState {
  const storage = new Map<string, unknown>();
  let alarmTime: number | null = null;

  return {
    id: {
      toString: () => idStr,
      name: idStr,
      equals: (other: DurableObjectId) => other.toString() === idStr,
    } as DurableObjectId,
    storage: {
      get: async (key: string) => storage.get(key),
      put: async (key: string, val: unknown) => { storage.set(key, val); },
      delete: async (key: string) => storage.delete(key),
      list: async () => new Map(storage),
      getAlarm: async () => alarmTime,
      setAlarm: async (time: number) => { alarmTime = time; },
      deleteAlarm: async () => { alarmTime = null; },
      transaction: async (fn: (txn: DurableObjectTransaction) => Promise<unknown>) => fn({
        get: async (key: string) => storage.get(key),
        put: async (key: string, value: unknown) => { storage.set(key, value); },
        delete: async (key: string) => storage.delete(key),
      } as unknown as DurableObjectTransaction),
      deleteAll: async () => { storage.clear(); },
    } as unknown as DurableObjectStorage,
    container: undefined, // No container in Node.js test environment
    waitUntil: (_p: Promise<unknown>) => {},
    blockConcurrencyWhile: async <T>(fn: () => Promise<T>): Promise<T> => fn(),
    acceptWebSocket: () => {},
    getWebSockets: () => [],
    setWebSocketAutoResponse: () => {},
    getWebSocketAutoResponse: () => null,
    getWebSocketAutoResponseTimestamp: () => null,
    setHibernatableWebSocketEventTimeout: () => {},
    getHibernatableWebSocketEventTimeout: () => null,
    getTags: () => [],
    abort: () => {},
    props: {},
    facets: {} as DurableObjectFacets,
  } as unknown as DurableObjectState;
}

function makeEnv(): Env {
  return {
    CORELINK_SERVER: {} as DurableObjectNamespace,
    ENVIRONMENT: "test",
    PAGERDUTY_ROUTING_KEY: "",
  };
}

describe("durable authenticated HTTP native coordinator", () => {
  const release = "a".repeat(40), at = STAGING_D1_PROBE_WINDOW.starts_ms + 120_000;
  const native = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
    probe_nonce: STAGING_D1_PROBE_WINDOW.nonce, worker_release: release, scheduled_time_ms: at,
    parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
    probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true };
  const v8Receipt = { contract: "corelink-staging-v8-cleanup-v1", old_release: V8_PROBE_RELEASE,
    old_nonce: V8_PROBE_NONCE, worker_release: release, prior_execution: "unknown",
    prior_admission_present: true, container_stopped: true, alarm_absent: true, tables_absent: true, completed_at_ms: at };
  const v9Receipt = { ...v8Receipt, contract: "corelink-staging-v9-cleanup-v1", old_release: V9_PROBE_RELEASE, old_nonce: V9_PROBE_NONCE };
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(at); });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
  const flush = async () => { for (let n = 0; n < 1000; n++) await Promise.resolve(); };

  async function fixture() {
    const name = `_staging_d1_binding_probe_v2:${STAGING_D1_PROBE_WINDOW.nonce}:${release}`;
    const state = makeMockState(name), order: string[] = [];
    let initialized!: Promise<unknown>;
    state.blockConcurrencyWhile = <T>(fn: () => Promise<T>) => { const result = fn(); initialized = result; return result; };
    const v8 = vi.fn(async () => {
      expect(await state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "running");
      expect(await state.storage.get("staging-d1-binding-probe-admission-v1")).toBeUndefined();
      order.push("v8"); return v8Receipt;
    });
    const v9 = vi.fn(async () => { order.push("v9"); return v9Receipt; });
    const old = vi.fn(async () => { order.push("old"); return {
      old_probe_release: OLD_PROBE_RELEASE, old_probe_retired: true, old_probe_tables_absent: true }; });
    const v5 = vi.fn(async () => { order.push("v5"); return {
      v5_probe_release: V5_PROBE_RELEASE, v5_probe_retired: true, v5_probe_tables_absent: true }; });
    const sql = vi.fn(() => ({ bind() { return this; }, all: async () => {
      order.push("v4"); return { success: true, results: [] }; } }));
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd", D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com", CONFIG_DB: { prepare: sql },
      CORELINK_SERVER: { idFromName: (id: string) => ({ toString: () => id }), get: (id: DurableObjectId) => {
        if (id.toString() === V8_PROBE_NAME) return { cleanupV8StagingD1RuntimeProbe: v8 };
        if (id.toString() === V9_PROBE_NAME) return { cleanupV9StagingD1RuntimeProbe: v9 };
        if (id.toString() === OLD_PROBE_NAME) return { retireStagingD1RuntimeProbe: old };
        if (id.toString() === V5_PROBE_NAME) return { retireStagingD1RuntimeProbe: v5 };
        throw new Error("unexpected fixture namespace");
      } },
    } as unknown as Env;
    const port = vi.fn(async (_request: Request) => { order.push("native"); return Response.json(native); });
    const container = { running: false, getTcpPort: () => ({ fetch: port }), signal: vi.fn(),
      destroy: vi.fn(async () => { order.push("stop"); container.running = false; }) };
    Object.assign(state, { container });
    const do_ = new CoreLinkServer(state, env, Date.now); await initialized;
    const start = vi.spyOn(do_ as unknown as { startHttpProbeContainer: () => Promise<{ ok: true }> }, "startHttpProbeContainer")
      .mockImplementation(async () => { container.running = true; return { ok: true }; });
    return { do_, state, env, order, v8, v9, old, v5, sql, port, container, start };
  }

  it("claims before all cleanup, executes whole order, and persists exact stopped proof", async () => {
    const h = await fixture();
    const result = await h.do_.executeStagingD1HttpProof(at);
    expect(h.order).toEqual(["v8", "v9", "v4", "old", "v5", "native", "stop"]);
    expect(isStagingD1HttpStatus(result, release, Date.now())).toBe(true);
    expect(result.status).toBe("complete"); expect(result.rollback_safe).toBe(true);
    expect(Object.keys(result)).toHaveLength(9);
    expect(Object.keys(result.native_receipt as object)).toHaveLength(20);
    expect(Object.keys(result.v8_cleanup as object)).toHaveLength(10);
    expect(Object.keys(result.v9_cleanup as object)).toHaveLength(10);
    const request = h.port.mock.calls[0]![0];
    expect(request.method).toBe("POST");
    expect(request.headers.has("authorization")).toBe(false);
    expect(request.headers.has("x-corelink-internal-auth")).toBe(false);
    expect(h.old).toHaveBeenCalledWith(at, at + 600_000);
    expect(await h.do_.readStagingD1HttpProof()).toEqual(result);
    expect((await h.do_.fetch(new Request("https://test/_internal/staging/d1-binding-runtime-probe", { method: "POST" }))).status).toBe(404);
    await expect(h.do_.executeStagingD1HttpProof(at)).rejects.toThrow();
    expect(h.v8).toHaveBeenCalledOnce();
    expect(await h.state.storage.get("staging-d1-binding-probe-receipt-v1")).toEqual(native);
  });

  it.each(["v8", "v9", "old", "v5"] as const)("persists UNKNOWN and never admits native work after %s failure", async phase => {
    const h = await fixture(); h[phase].mockRejectedValue(new Error("private-provider-sentinel"));
    const result = await h.do_.executeStagingD1HttpProof(at);
    expect(result.status).toBe("unknown"); expect(result.rollback_safe).toBe(false);
    expect(JSON.stringify(result)).not.toContain("private-provider-sentinel");
    expect(h.start).not.toHaveBeenCalled(); expect(h.container.destroy).not.toHaveBeenCalled();
    expect(await h.state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "unknown");
    await expect(h.do_.executeStagingD1HttpProof(at)).rejects.toThrow();
  });

  it("records UNKNOWN before waiting for an uncancellable cleanup; late resolution never admits", async () => {
    const h = await fixture(); let finish!: (receipt: typeof v8Receipt) => void;
    h.v8.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const result = h.do_.executeStagingD1HttpProof(at); await flush();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(await h.state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "unknown");
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
    expect(h.v9).not.toHaveBeenCalled(); expect(h.container.destroy).not.toHaveBeenCalled();
    finish(v8Receipt); expect((await result).status).toBe("unknown");
    expect(h.v9).not.toHaveBeenCalled(); expect(h.start).not.toHaveBeenCalled();
    expect(await h.state.storage.get("staging-d1-binding-probe-admission-v1")).toBeUndefined();
  });

  it("never cleans during pending native fetch and never completes after late native success", async () => {
    const h = await fixture(); let finish!: (response: Response) => void;
    h.port.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const result = h.do_.executeStagingD1HttpProof(at); await flush();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(h.container.destroy).not.toHaveBeenCalled();
    expect(await h.state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "unknown");
    finish(Response.json(native)); expect((await result).status).toBe("unknown");
    expect(h.container.destroy).toHaveBeenCalledOnce();
    expect(await h.state.storage.get("staging-d1-binding-probe-receipt-v1")).toBeUndefined();
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
  });

  it("does not make an unresolved native operation safe after both budgets expire", async () => {
    const h = await fixture(); h.port.mockImplementation(() => new Promise(() => {}));
    const result = h.do_.executeStagingD1HttpProof(at); await flush();
    await vi.advanceTimersByTimeAsync(1_200_000);
    expect((await result).status).toBe("unknown");
    expect(h.container.destroy).not.toHaveBeenCalled();
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
  });

  it.each(["extra", "stopped", "alarm"])("rejects incomplete final proof: %s", async failure => {
    const h = await fixture();
    if (failure === "extra") h.port.mockResolvedValue(Response.json({ ...native, private: "sentinel" }));
    if (failure === "stopped") h.container.destroy.mockResolvedValue(undefined);
    if (failure === "alarm") vi.spyOn(h.state.storage, "getAlarm").mockResolvedValueOnce(at + 1_200_000).mockResolvedValue(at);
    const result = await h.do_.executeStagingD1HttpProof(at);
    expect(result.status).toBe("unknown"); expect(result.rollback_safe).toBe(false);
    expect(result.native_receipt).toBeNull();
    expect(await h.state.storage.get("staging-d1-binding-probe-receipt-v1")).toBeUndefined();
  });

  it("rehydrates a running claim as UNKNOWN, preserves all native keys, and read cannot replay", async () => {
    const h = await fixture();
    const keys = ["staging-d1-binding-probe-admission-v1", "staging-d1-binding-probe-state-v1", "staging-d1-binding-probe-receipt-v1"];
    for (const key of keys) await h.state.storage.put(key, { preserved: key });
    await h.state.storage.put(STAGING_D1_HTTP_OPERATION_KEY, { status: "running" });
    let ready!: Promise<unknown>;
    h.state.blockConcurrencyWhile = <T>(fn: () => Promise<T>) => { const result = fn(); ready = result; return result; };
    const restored = new CoreLinkServer(h.state, h.env, Date.now); await ready;
    expect((await restored.readStagingD1HttpProof()).status).toBe("unknown");
    await expect(restored.executeStagingD1HttpProof(at)).rejects.toThrow();
    await expect(restored.admitStagingD1RuntimeProbe(at)).rejects.toThrow();
    expect(h.v8).not.toHaveBeenCalled();
    for (const key of keys) expect(await h.state.storage.get(key)).toEqual({ preserved: key });
  });

  it.each([undefined, {}, { operation_started_ms: at, completion_deadline_ms: Infinity },
    { operation_started_ms: at, completion_deadline_ms: at },
    { operation_started_ms: at, completion_deadline_ms: at + 1_200_001 },
    { operation_started_ms: at, completion_deadline_ms: at + 600_000, extra: true }])(
    "orphaned COMPLETE with absent/malformed/out-of-budget deadline is never safe", async deadline => {
      const h = await fixture(); await h.do_.executeStagingD1HttpProof(at);
      if (deadline === undefined) await h.state.storage.delete(STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY);
      else await h.state.storage.put(STAGING_D1_HTTP_COMPLETION_DEADLINE_KEY, deadline);
      expect((await h.do_.readStagingD1HttpProof()).status).toBe("unknown");
      expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
    });

  it("a commit delayed after callback return cannot resurrect COMPLETE after timeout and eviction", async () => {
    const h = await fixture();
    let commit!: () => void, committed!: Promise<void>;
    vi.spyOn(h.state.storage, "transaction").mockImplementation(async callback => {
      const staged = new Map<string, unknown>();
      const result = await callback({
        get: async (key: string) => staged.has(key) ? staged.get(key) : h.state.storage.get(key),
        put: async (key: string, value: unknown) => { staged.set(key, value); },
      } as unknown as DurableObjectTransaction);
      // The callback (including its final deadline check) already returned.
      if ((staged.get(STAGING_D1_HTTP_OPERATION_KEY) as { status?: string } | undefined)?.status === "complete") {
        let finish!: () => void;
        committed = new Promise<void>(resolve => { finish = resolve; });
        await new Promise<void>(resolve => { commit = resolve; });
        for (const [key, value] of staged) await h.state.storage.put(key, value);
        finish();
      } else for (const [key, value] of staged) await h.state.storage.put(key, value);
      return result;
    });
    const execution = h.do_.executeStagingD1HttpProof(at);
    const rejected = expect(execution).rejects.toThrow("status unavailable");
    await flush();
    expect(commit).toBeTypeOf("function");
    await vi.advanceTimersByTimeAsync(600_000); await rejected;
    expect(await h.state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "unknown");
    commit(); await committed;
    expect(await h.state.storage.get(STAGING_D1_HTTP_OPERATION_KEY)).toHaveProperty("status", "complete");
    let ready!: Promise<unknown>;
    h.state.blockConcurrencyWhile = <T>(fn: () => Promise<T>) => { const result = fn(); ready = result; return result; };
    const restored = new CoreLinkServer(h.state, h.env, Date.now); await ready;
    const status = await restored.readStagingD1HttpProof();
    expect(status.status).toBe("unknown"); expect(status.rollback_safe).toBe(false);
    await expect(restored.executeStagingD1HttpProof(at + 600_000)).rejects.toThrow();
  });

  it.each(["set", "readback", "record"])("no cleanup or admission before lifetime arming: %s", async failure => {
    const h = await fixture();
    if (failure === "set") vi.spyOn(h.state.storage, "setAlarm").mockRejectedValue(new Error("sentinel"));
    if (failure === "readback") vi.spyOn(h.state.storage, "getAlarm").mockResolvedValue(null);
    if (failure === "record") {
      const get = h.state.storage.get.bind(h.state.storage);
      vi.spyOn(h.state.storage, "get").mockImplementation(((key: string) => key === STAGING_D1_HTTP_LIFETIME_KEY
        ? Promise.resolve(undefined) : get(key)) as typeof h.state.storage.get);
    }
    await expect(h.do_.executeStagingD1HttpProof(at)).rejects.toThrow("claim rejected");
    expect(h.v8).not.toHaveBeenCalled(); expect(h.start).not.toHaveBeenCalled(); expect(h.sql).not.toHaveBeenCalled();
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
    await expect(h.do_.executeStagingD1HttpProof(at)).rejects.toThrow();
  });

  it("arms the immutable lifetime before v8 and status reads cannot renew it", async () => {
    const h = await fixture(); h.v8.mockImplementation(() => new Promise(() => {}));
    const execution = h.do_.executeStagingD1HttpProof(at); await flush();
    expect(await h.state.storage.get(STAGING_D1_HTTP_LIFETIME_KEY)).toEqual(createHttpLifetime(release, at));
    expect(await h.state.storage.getAlarm()).toBe(at + 1_200_000);
    vi.setSystemTime(at + 100_000); await h.do_.readStagingD1HttpProof(); await h.do_.alarm();
    expect(await h.state.storage.getAlarm()).toBe(at + 1_200_000);
    await vi.advanceTimersByTimeAsync(1_200_000); expect((await execution).status).toBe("unknown");
  });

  it.each([false, true])("expiry stop remains independent of unresolved native fetch; stopped=%s", async stopped => {
    const h = await fixture(); h.port.mockImplementation(() => new Promise(() => {}));
    h.container.signal.mockImplementation(() => { if (stopped) h.container.running = false; });
    const execution = h.do_.executeStagingD1HttpProof(at); await flush();
    await vi.advanceTimersByTimeAsync(1_199_999); await h.do_.alarm();
    expect(h.container.signal).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1); expect((await execution).status).toBe("unknown");
    const sqlCalls = h.sql.mock.calls.length;
    await h.do_.alarm(); await h.do_.alarm();
    expect(h.container.signal).toHaveBeenCalledExactlyOnceWith(9);
    expect(h.container.destroy).not.toHaveBeenCalled(); expect(h.sql).toHaveBeenCalledTimes(sqlCalls);
    expect(await h.state.storage.get(STAGING_D1_HTTP_LIFETIME_KEY)).toMatchObject({ state: stopped ? "stopped" : "unproven" });
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
    await expect(h.do_.executeStagingD1HttpProof(at)).rejects.toThrow();
  });

  it("expiry never submits another stop while normal destroy is unresolved", async () => {
    const h = await fixture(); h.container.destroy.mockImplementation(() => new Promise(() => {}));
    const execution = h.do_.executeStagingD1HttpProof(at); const failure = expect(execution).rejects.toThrow(); await flush();
    expect(h.container.destroy).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1_200_000); await failure; await h.do_.alarm();
    expect(h.container.destroy).toHaveBeenCalledOnce(); expect(h.container.signal).not.toHaveBeenCalled();
    expect((await h.do_.readStagingD1HttpProof()).rollback_safe).toBe(false);
  });

  it("eviction keeps original expiry; lost signal and malformed records cannot imply stop", async () => {
    const h = await fixture();
    await h.state.storage.put(STAGING_D1_HTTP_OPERATION_KEY, { status: "unknown" });
    await h.state.storage.put(STAGING_D1_HTTP_LIFETIME_KEY, { ...createHttpLifetime(release, at),
      state: "stop_attempted", stop_attempted_at_ms: at + 1_200_000 });
    h.container.running = true; vi.setSystemTime(at + 1_200_001);
    let ready!: Promise<unknown>;
    h.state.blockConcurrencyWhile = <T>(fn: () => Promise<T>) => { const result = fn(); ready = result; return result; };
    const restored = new CoreLinkServer(h.state, h.env, Date.now); await ready; await restored.alarm();
    expect(h.container.signal).not.toHaveBeenCalled();
    expect((await restored.readStagingD1HttpProof()).rollback_safe).toBe(false);
    await h.state.storage.put(STAGING_D1_HTTP_LIFETIME_KEY, { ...createHttpLifetime(release, at), worker_release: "b".repeat(40) });
    await restored.alarm(); expect(h.container.signal).not.toHaveBeenCalled(); expect(h.v8).not.toHaveBeenCalled();
  });

  it("actual private startup installs the immutable loopback context and never renews its alarm", async () => {
    const h = await fixture(); h.start.mockRestore();
    const binding = { fetch: vi.fn() }, exports = vi.fn(() => binding);
    Object.assign(h.state, { exports: { StagingD1BindingProxy: exports } });
    const start = vi.fn((_options: unknown) => { h.container.running = true; });
    Object.assign(h.container, { start, interceptOutboundHttp: vi.fn(async () => {}), setInactivityTimeout: vi.fn() });
    const setAlarm = vi.spyOn(h.state.storage, "setAlarm");
    await h.do_.executeStagingD1HttpProof(at);
    expect(exports).toHaveBeenCalledExactlyOnceWith({ props: httpDeadlineContext(createHttpLifetime(release, at)) });
    expect(start).toHaveBeenCalledOnce();
    const options = start.mock.calls[0]?.[0] as unknown as { entrypoint: string[]; env: Record<string, string> };
    expect(options.entrypoint).toEqual(["/usr/local/bin/corelink-staging-probe-supervisor"]);
    expect(options.env["CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS"]).toBe(String(at + 600_000));
    expect(setAlarm.mock.calls.every(([value]) => value === at + 1_200_000)).toBe(true);
  });

  it("restores the v9 retired fence before fetch, alarm, or native admission", async () => {
    const h = await fixture(); await h.state.storage.put(V9_PROBE_RETIRED_KEY, { old_release: V9_PROBE_RELEASE });
    let ready!: Promise<unknown>;
    h.state.blockConcurrencyWhile = <T>(fn: () => Promise<T>) => { const result = fn(); ready = result; return result; };
    const restored = new CoreLinkServer(h.state, h.env, Date.now); await ready;
    expect((await restored.fetch(new Request("https://test/"))).status).toBe(410);
    expect((await restored.fetch(new Request("https://test/_internal/staging/d1-binding-runtime-probe", { method: "POST" }))).status).toBe(404);
    await expect(restored.executeStagingD1HttpProof(at)).rejects.toThrow();
    await restored.alarm(); expect(h.start).not.toHaveBeenCalled();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Idempotent-start guard (multi-region cold-start thrash fix, 2026-08-18)
// ──────────────────────────────────────────────────────────────────────────────

describe("startContainer already-running race handling", () => {
  function makeDO(opts: {
    startThrows: string;
    healthStatus: number;
    running: boolean;
  }): { do_: CoreLinkServer; destroySpy: ReturnType<typeof vi.fn> } {
    const state = makeMockState();
    const destroySpy = vi.fn();
    (state as unknown as { container: unknown }).container = {
      running: opts.running,
      start: () => {
        throw new Error(opts.startThrows);
      },
      destroy: destroySpy,
      getTcpPort: () => ({
        fetch: async () => new Response("x", { status: opts.healthStatus }),
      }),
      setInactivityTimeout: async () => {},
      monitor: () => new Promise<void>(() => {}),
    };
    const do_ = new CoreLinkServer(state, makeEnv());
    (do_ as unknown as { lifecycleState: Record<string, unknown> }).lifecycleState = {
      containerStatus: "stopped",
      tenantId: "t",
      coldStartCount: 0,
    };
    return { do_, destroySpy };
  }

  it("serves (health-gates), does NOT destroy, when start() throws 'already running'", async () => {
    // The cold-region thrash: CF's start() flips running true then (or a prior
    // request's start already did) throws "already running". The container IS
    // up — destroying it re-opens the thrash. Health-gate + serve instead.
    const { do_, destroySpy } = makeDO({
      startThrows: "start() cannot be called on a container that is already running.",
      healthStatus: 200,
      running: true,
    });
    const res = await (
      do_ as unknown as {
        startContainer: (r: string) => Promise<{ ok: boolean; reason?: string }>;
      }
    ).startContainer("req-already-running");
    expect(res.ok).toBe(true);
    expect(destroySpy).not.toHaveBeenCalled();
  });

  it("still DESTROYS + reports container_start_threw on a genuine (non-already-running) throw", async () => {
    const { do_, destroySpy } = makeDO({
      startThrows: "container start threw for real",
      healthStatus: 500,
      running: true,
    });
    const res = await (
      do_ as unknown as {
        startContainer: (r: string) => Promise<{ ok: boolean; reason?: string }>;
      }
    ).startContainer("req-real-throw");
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("container_start_threw");
    expect(destroySpy).toHaveBeenCalled();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Constant-time comparison
// ──────────────────────────────────────────────────────────────────────────────

describe("timingSafeEqual", () => {
  it("returns true for equal strings", async () => {
    expect(await timingSafeEqual("hello", "hello")).toBe(true);
  });

  it("returns false for different strings", async () => {
    expect(await timingSafeEqual("hello", "world")).toBe(false);
  });

  it("returns false for strings of different lengths", async () => {
    expect(await timingSafeEqual("short", "longer-string")).toBe(false);
  });

  it("returns false for empty vs non-empty", async () => {
    expect(await timingSafeEqual("", "x")).toBe(false);
  });

  it("returns true for equal empty strings", async () => {
    expect(await timingSafeEqual("", "")).toBe(true);
  });

  it("returns false for single-char difference", async () => {
    const a = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01";
    const b = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0X";
    expect(await timingSafeEqual(a, b)).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO constructor and init
// ──────────────────────────────────────────────────────────────────────────────

describe("CoreLinkServer constructor", () => {
  it("can be instantiated without throwing", () => {
    const state = makeMockState();
    const env = makeEnv();
    expect(() => new CoreLinkServer(state, env)).not.toThrow();
  });

  it("restores lifecycle state from storage on wakeup", async () => {
    const state = makeMockState();
    // Pre-populate storage with a lifecycle state
    await state.storage.put("lifecycle", {
      containerStatus: "stopped",
      lastHealthCheckMs: 12345,
      coldStartCount: 3,
      tenantId: "test-tenant",
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    // Wait for blockConcurrencyWhile to complete
    await new Promise<void>((r) => setTimeout(r, 10));
    // Verify DO was created; we can't inspect private state directly but
    // indirectly verify by requesting health
    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    expect(resp.status).not.toBe(500); // Not an unhandled error
  });
});

describe("staging D1 runtime probe exposure", () => {
  it("reads only an immutable receipt after the v6 entry cutoff without touching lifecycle state", async () => {
    const window = STAGING_D1_PROBE_WINDOW;
    const release = "c".repeat(40);
    const name = `_staging_d1_binding_probe_v2:${window.nonce}:${release}`;
    const state = makeMockState(name);
    const namespace = {
      idFromName: vi.fn((id: string) => ({ toString: () => id })),
      get: vi.fn(() => { throw new Error("receipt read must not fetch or start a Container"); }),
    };
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      CORELINK_SERVER: namespace,
    } as unknown as Env;
    const receipt = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
      probe_nonce: window.nonce, worker_release: release, scheduled_time_ms: window.starts_ms + 120_000,
      parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
      probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true };
    await state.storage.put("staging-d1-binding-probe-receipt-v1", receipt);
    const do_ = new CoreLinkServer(state, env, () => window.last_entry_ms + 60_000);
    const before = await state.storage.list();
    await expect(do_.readStagingD1RuntimeProbeReceipt(window.last_entry_ms + 60_000)).resolves.toEqual(receipt);
    expect(await state.storage.list()).toEqual(before);
    expect(namespace.idFromName).toHaveBeenCalledWith(name);
    expect(namespace.get).not.toHaveBeenCalled();
  });

  it("accepts only fresh stored receipts and rejects expiry before accessing a Container", async () => {
    const window = STAGING_D1_PROBE_WINDOW;
    const release = "a".repeat(40);
    const scheduledTime = window.starts_ms + 120_000;
    const probeName = `_staging_d1_binding_probe_v2:${window.nonce}:${release}`;
    const namespace = {
      idFromName: vi.fn((name: string) => ({ toString: () => name })),
      get: vi.fn(() => { throw new Error("receipt read must not fetch or start a Container"); }),
    };
    const state = makeMockState(probeName);
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
      CORELINK_SERVER: namespace,
    } as unknown as Env;
    const receipt = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
      probe_nonce: window.nonce, worker_release: release, scheduled_time_ms: scheduledTime,
      parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
      probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true,
    };
    for (const stored of [receipt, { ...receipt, probe_nonce: "old" },
      { ...receipt, worker_release: "b".repeat(40) }, { ...receipt, scheduled_time_ms: window.starts_ms - 60000 }]) {
      await state.storage.put("staging-d1-binding-probe-receipt-v1", stored);
      const do_ = new CoreLinkServer(state, env, () => scheduledTime + 5000);
      if (stored === receipt) await expect(do_.readStagingD1RuntimeProbeReceipt(scheduledTime)).resolves.toEqual(receipt);
      else await expect(do_.readStagingD1RuntimeProbeReceipt(scheduledTime)).rejects.toThrow("stored receipt rejected");
      const expired = new CoreLinkServer(state, env, () => window.expires_ms);
      await expect(expired.readStagingD1RuntimeProbeReceipt(scheduledTime)).rejects.toThrow("guard rejected");
    }
    expect(namespace.get).not.toHaveBeenCalled();
  });

  it("rejects the native probe path through ordinary Durable Object fetch", async () => {
    const state = makeMockState("public-probe-path-test");
    const do_ = new CoreLinkServer(state, makeEnv());
    const response = await do_.fetch(new Request(
      "https://worker.invalid/_internal/staging/d1-binding-runtime-probe",
      { method: "POST", body: "{}" },
    ));
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("not_found");
  });

  it("emits native_complete only after the validated receipt and stopped state persist", async () => {
    const window = STAGING_D1_PROBE_WINDOW, release = "a".repeat(40), scheduledTime = window.starts_ms;
    const state = makeMockState(`_staging_d1_binding_probe_v2:${window.nonce}:${release}`);
    const receipt = { contract: "corelink-staging-d1-binding-runtime-v1", outcome: "pass",
      probe_nonce: window.nonce, worker_release: release, scheduled_time_ms: scheduledTime,
      parameterized_select: true, failed_batch_observed: true, rollback_absence_verified: true,
      probe_table_dropped: true, d1_binding_intercepted: true, authorization_absent: true, cf_api_token_absent: true };
    const container = { running: true, destroy: vi.fn(async () => { container.running = false; }),
      getTcpPort: () => ({ fetch: vi.fn(async () => Response.json(receipt)) }) };
    Object.assign(state, { container });
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
      CORELINK_SERVER: { idFromName: (id: string) => ({ toString: () => id }) },
    } as unknown as Env;
    const do_ = new CoreLinkServer(state, env, () => scheduledTime + 5000);
    const admission = { contract: "corelink-staging-d1-probe-admission-v1" as const,
      probe_nonce: window.nonce, worker_release: release, scheduled_time_ms: scheduledTime };
    await state.storage.put("staging-d1-binding-probe-admission-v1", admission);
    vi.spyOn(do_ as unknown as { ensureContainerRunning: (...args: unknown[]) => Promise<unknown> }, "ensureContainerRunning").mockResolvedValue({ ok: true });
    const put = vi.spyOn(state.storage, "put");
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    await expect(do_.runStagingD1RuntimeProbe(admission)).resolves.toEqual(receipt);
    expect(container.running).toBe(false);
    expect(await state.storage.get("staging-d1-binding-probe-state-v1")).toBe("complete");
    expect(info.mock.calls.map(call => call[0])).toEqual([
      `[staging_d1_runtime_probe] phase=native_start release=${release}`,
      `[staging_d1_runtime_probe] phase=native_complete release=${release}`,
    ]);
    expect(info.mock.invocationCallOrder[1]).toBeGreaterThan(put.mock.invocationCallOrder.at(-1)!);
    info.mockRestore();
  });

  it("rejects first admission after latest entry and rejects a foreign admission", async () => {
    const window = STAGING_D1_PROBE_WINDOW;
    const release = "e".repeat(40);
    const name = `_staging_d1_binding_probe_v2:${window.nonce}:${release}`;
    const state = makeMockState(name);
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_API_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
      CORELINK_SERVER: { idFromName: (id: string) => ({ toString: () => id }) },
    } as unknown as Env;
    const afterCutoff = new CoreLinkServer(state, env, () => window.last_entry_ms + 1);
    await expect(afterCutoff.admitStagingD1RuntimeProbe(window.last_entry_ms)).rejects.toThrow();
    const candidate = new CoreLinkServer(state, env, () => window.last_entry_ms);
    const currentNonce = window.nonce;
    try {
      for (const nonce of ["issue-1700-recovery-20261001-v10", "issue-1700-recovery-20261001-v11"]) {
        window.nonce = nonce;
        await expect(candidate.admitStagingD1RuntimeProbe(window.last_entry_ms)).rejects.toThrow("HTTP admission required");
        expect(await state.storage.get("staging-d1-binding-probe-admission-v1")).toBeUndefined();
      }
    } finally {
      window.nonce = currentNonce;
    }
    expect(await state.storage.get("staging-d1-binding-probe-admission-v1")).toBeUndefined();
    const otherRelease = { contract: "corelink-staging-d1-probe-admission-v1" as const,
      probe_nonce: window.nonce, worker_release: "f".repeat(40), scheduled_time_ms: window.last_entry_ms };
    await expect(candidate.runStagingD1RuntimeProbe(otherRelease)).rejects.toThrow("guard rejected");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO health probe
// ──────────────────────────────────────────────────────────────────────────────

describe("DO /_do/health", () => {
  it("returns 503 when container is not running (no container binding in test)", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    // Container is undefined in test, so status is not 'running' → 503
    expect(resp.status).toBe(503);
  });

  it("health probe returns JSON with container_status field", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    const body = await resp.json() as Record<string, unknown>;
    expect(body["container_status"]).toBeDefined();
    expect(["stopped", "starting", "running", "degraded"]).toContain(body["container_status"]);
  });

  it("health probe sets X-Request-Id", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(
      new Request("http://localhost/_do/health", {
        headers: { "x-request-id": "health-probe-test" },
      }),
    );
    expect(resp.headers.get("x-request-id")).toBe("health-probe-test");
  });

  it("health probe generates x-request-id if not provided", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    expect(resp.headers.get("x-request-id")).not.toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO D1 placement instrument (/_do/health → d1_probe)
//
// The instrument exists to answer ONE question: is this DO co-located with the
// ENAM D1 primary? These tests pin the property that makes the answer
// trustworthy — a read that never happened, or that threw, can NEVER surface as
// a fast number or as a missing field.
// ──────────────────────────────────────────────────────────────────────────────

/** Build a D1-ish binding double. `withSession` is omitted when `sessions` is false. */
function makeD1Double(opts: {
  sessions: boolean;
  primaryDelayMs?: number;
  replicaDelayMs?: number;
  throwOn?: "primary" | "replica" | "both";
  withSessionThrows?: boolean;
}): unknown {
  const handle = (kind: "primary" | "replica", delayMs: number) => ({
    prepare: (_q: string) => ({
      all: async () => {
        await new Promise<void>((r) => setTimeout(r, delayMs));
        if (opts.throwOn === kind || opts.throwOn === "both") {
          throw new Error(`${kind} read exploded`);
        }
        return {
          results: [{ "1": 1 }],
          meta: {
            served_by_region: kind === "primary" ? "ENAM" : "WNAM",
            served_by_primary: kind === "primary",
            served_by_colo: kind === "primary" ? "MIA" : "SJC",
          },
        };
      },
    }),
  });

  const primary = handle("primary", opts.primaryDelayMs ?? 0);
  if (!opts.sessions) return primary;
  return {
    ...primary,
    withSession: (_c: string) => {
      if (opts.withSessionThrows === true) throw new Error("no sessions here");
      return handle("replica", opts.replicaDelayMs ?? 0);
    },
  };
}

function envWithD1(db: unknown): Env {
  return { ...makeEnv(), CONFIG_DB: db } as unknown as Env;
}

async function healthBody(env: Env, path = "http://localhost/_do/health"): Promise<Record<string, unknown>> {
  const state = makeMockState();
  const do_ = new CoreLinkServer(state, env);
  await new Promise<void>((r) => setTimeout(r, 5));
  const resp = await do_.fetch(new Request(path));
  return (await resp.json()) as Record<string, unknown>;
}

describe("DO /_do/health d1_probe (placement instrument)", () => {
  it("measures BOTH paths and reports D1's served_by provenance", async () => {
    const body = await healthBody(envWithD1(makeD1Double({ sessions: true })));
    const probe = body["d1_probe"] as Record<string, unknown>;
    expect(probe["binding_bound"]).toBe(true);
    expect(probe["sessions_api_available"]).toBe(true);

    const primary = probe["primary"] as Record<string, unknown>;
    const replica = probe["replica"] as Record<string, unknown>;
    expect(primary["available"]).toBe(true);
    expect(primary["ok"]).toBe(true);
    expect((primary["samples_ms"] as number[]).length).toBe(3);
    expect(typeof primary["min_ms"]).toBe("number");
    expect(primary["error"]).toBeNull();
    // The provenance is what distinguishes "the replica path really hit a
    // replica" from "the Sessions API quietly served the primary".
    expect(primary["served_by_primary"]).toBe(true);
    expect(primary["served_by_region"]).toBe("ENAM");
    expect(replica["served_by_primary"]).toBe(false);
    expect(replica["ok"]).toBe(true);
    // The warm-up is REPORTED, not hidden — it is the honest cold number.
    expect(typeof probe["warmup_ms"]).toBe("number");
  });

  it("degrades to primary-only (never throws) when the Sessions API is absent", async () => {
    const body = await healthBody(envWithD1(makeD1Double({ sessions: false })));
    const probe = body["d1_probe"] as Record<string, unknown>;
    expect(probe["sessions_api_available"]).toBe(false);
    const replica = probe["replica"] as Record<string, unknown>;
    // "unavailable, fell back" — NOT silently reported as equal to the primary.
    expect(replica["available"]).toBe(false);
    expect(replica["error"]).toContain("withSession");
    expect(replica["min_ms"]).toBeNull();
    expect((probe["primary"] as Record<string, unknown>)["ok"]).toBe(true);
    // The health probe itself must be unaffected.
    expect(body["container_status"]).toBeDefined();
  });

  it("a read that THROWS is an explicit error — never a fast number, never a missing field", async () => {
    const body = await healthBody(envWithD1(makeD1Double({ sessions: true, throwOn: "primary" })));
    const probe = body["d1_probe"] as Record<string, unknown>;
    const primary = probe["primary"] as Record<string, unknown>;
    expect(primary["available"]).toBe(true); // it WAS attempted…
    expect(primary["ok"]).toBe(false); // …and it failed.
    expect(primary["min_ms"]).toBeNull();
    expect(primary["samples_ms"]).toEqual([]);
    expect(typeof primary["error"]).toBe("string");
    expect(primary["error"]).toContain("exploded");
  });

  it("reports an unbound CONFIG_DB as unavailable on both paths, not as zero", async () => {
    // makeEnv() has no CONFIG_DB at all — the pre-existing test double.
    const body = await healthBody(makeEnv());
    const probe = body["d1_probe"] as Record<string, unknown>;
    expect(probe["binding_bound"]).toBe(false);
    for (const path of ["primary", "replica"]) {
      const p = probe[path] as Record<string, unknown>;
      expect(p["available"]).toBe(false);
      expect(p["min_ms"]).toBeNull();
      expect(p["error"]).toContain("CONFIG_DB");
    }
  });

  it("a throwing withSession is reported, not propagated", async () => {
    const body = await healthBody(
      envWithD1(makeD1Double({ sessions: true, withSessionThrows: true })),
    );
    const probe = body["d1_probe"] as Record<string, unknown>;
    const replica = probe["replica"] as Record<string, unknown>;
    expect(replica["available"]).toBe(false);
    expect(replica["error"]).toContain("no sessions here");
    expect((probe["primary"] as Record<string, unknown>)["ok"]).toBe(true);
  });

  it("makes no external colo request unless ?colo=1 is passed", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    try {
      const body = await healthBody(envWithD1(makeD1Double({ sessions: true })));
      const probe = body["d1_probe"] as Record<string, unknown>;
      expect(probe["do_colo"]).toBeNull();
      expect(probe["do_colo_error"]).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("?colo=1 resolves the DO colo, and a failing trace is an error field", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("fl=1\ncolo=IAD\n", { status: 200 }));
    try {
      const body = await healthBody(
        envWithD1(makeD1Double({ sessions: true })),
        "http://localhost/_do/health?colo=1",
      );
      expect((body["d1_probe"] as Record<string, unknown>)["do_colo"]).toBe("IAD");
    } finally {
      fetchSpy.mockRestore();
    }

    const failSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("trace down"));
    try {
      const body = await healthBody(
        envWithD1(makeD1Double({ sessions: true })),
        "http://localhost/_do/health?colo=1",
      );
      const probe = body["d1_probe"] as Record<string, unknown>;
      expect(probe["do_colo"]).toBeNull();
      expect(probe["do_colo_error"]).toContain("trace down");
    } finally {
      failSpy.mockRestore();
    }
  });

  it("the D1 reads run ONLY on /_do/health — /_do/stop never touches D1", async () => {
    let reads = 0;
    const db = {
      prepare: (_q: string) => ({
        all: async () => {
          reads += 1;
          return { results: [], meta: {} };
        },
      }),
    };
    const state = makeMockState();
    const do_ = new CoreLinkServer(state, envWithD1(db));
    await new Promise<void>((r) => setTimeout(r, 5));
    await do_.fetch(new Request("http://localhost/_do/stop"));
    expect(reads).toBe(0);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO stop endpoint
// ──────────────────────────────────────────────────────────────────────────────

describe("DO /_do/stop", () => {
  it("returns 200 with stopped:true", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/stop"));
    expect(resp.status).toBe(200);
    const body = await resp.json() as { stopped: boolean };
    expect(body.stopped).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO container unavailable path (no container binding in test)
// ──────────────────────────────────────────────────────────────────────────────

describe("DO request forwarding without container", () => {
  it("returns 503 CONTAINER_UNAVAILABLE when container binding is absent", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(
      new Request("http://localhost/v2/myrepo/blobs/sha256:abc", {
        headers: { "x-request-id": "test-req-001" },
      }),
    );
    expect(resp.status).toBe(503);
    const body = await resp.json() as { error: string };
    expect(body.error).toBe("CONTAINER_UNAVAILABLE");
  });

  it("503 response body does NOT contain request body (INV-NO-BODY-IN-LOGS)", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const sensitiveBody = "sensitive-data-that-must-not-leak=true";
    const resp = await do_.fetch(
      new Request("http://localhost/api/v2/t/blobs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-request-id": "no-leak-test",
        },
        body: sensitiveBody,
      }),
    );
    const text = await resp.text();
    expect(text).not.toContain("sensitive-data");
    expect(text).not.toContain("must-not-leak");
  });

  it("returns X-Request-Id on 503 response", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(
      new Request("http://localhost/api/v2/t/path", {
        headers: { "x-request-id": "503-test" },
      }),
    );
    expect(resp.headers.get("x-request-id")).toBe("503-test");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO lifecycle state persistence
// ──────────────────────────────────────────────────────────────────────────────

describe("DO lifecycle state persistence", () => {
  it("persists lifecycle state on stop", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await do_.fetch(new Request("http://localhost/_do/stop"));

    // Verify state was written to storage
    const stored = await state.storage.get("lifecycle") as Record<string, unknown> | undefined;
    expect(stored).toBeDefined();
    expect(stored?.["containerStatus"]).toBe("stopped");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO alarm
// ──────────────────────────────────────────────────────────────────────────────

describe("DO alarm", () => {
  it("alarm() runs without throwing when container is stopped", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await expect(do_.alarm()).resolves.not.toThrow();
  });

  it("alarm() runs without throwing when lifecycle state is 'starting'", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "starting",
      lastHealthCheckMs: 0,
      coldStartCount: 0,
      tenantId: null,
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await expect(do_.alarm()).resolves.not.toThrow();
  });

  it("alarm() runs without throwing when lifecycle state is 'degraded'", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "degraded",
      lastHealthCheckMs: 0,
      coldStartCount: 1,
      tenantId: "tenant-a",
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await expect(do_.alarm()).resolves.not.toThrow();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO ensureContainerRunning state machine
// ──────────────────────────────────────────────────────────────────────────────

describe("DO ensureContainerRunning state machine", () => {
  it("returns 503 for 'stopped' state (no container binding)", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "stopped",
      lastHealthCheckMs: 0,
      coldStartCount: 0,
      tenantId: null,
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/v2/repo/blobs/sha256:abc"));
    expect(resp.status).toBe(503);
  });

  it("returns 503 for 'degraded' state (no container binding)", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "degraded",
      lastHealthCheckMs: 0,
      coldStartCount: 2,
      tenantId: "my-tenant",
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/v2/repo/blobs/sha256:abc"));
    expect(resp.status).toBe(503);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO multiple requests handling
// ──────────────────────────────────────────────────────────────────────────────

describe("DO multiple concurrent request paths", () => {
  it("handles multiple sequential fetch calls without throwing", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const reqs = [
      do_.fetch(new Request("http://localhost/_do/health")),
      do_.fetch(new Request("http://localhost/api/v2/t/p")),
      do_.fetch(new Request("http://localhost/_do/health")),
    ];
    const responses = await Promise.all(reqs);
    for (const resp of responses) {
      expect([200, 503]).toContain(resp.status);
    }
  });

  it("stop then health returns 503 (container stopped)", async () => {
    const state = makeMockState();
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await do_.fetch(new Request("http://localhost/_do/stop"));
    const healthResp = await do_.fetch(new Request("http://localhost/_do/health"));
    expect(healthResp.status).toBe(503);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO tenantId handling
// ──────────────────────────────────────────────────────────────────────────────

describe("DO tenantId in persisted state", () => {
  it("reads tenantId from storage if present", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "stopped",
      lastHealthCheckMs: Date.now() - 1000,
      coldStartCount: 1,
      tenantId: "my-test-tenant",
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    // Health probe runs fine with tenantId set
    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    expect([200, 503]).toContain(resp.status);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO response bodies are sanitized
// ──────────────────────────────────────────────────────────────────────────────

describe("DO response sanitization", () => {
  it("stop endpoint returns sanitized JSON (no raw tenant id in body)", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "stopped",
      lastHealthCheckMs: 0,
      coldStartCount: 0,
      tenantId: "SUPERSECRET_TENANT_ID",
    });
    const env = makeEnv();
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/stop"));
    const text = await resp.text();
    // The tenant id MUST NOT appear verbatim in response (INV-NO-PII-IN-LOGS)
    expect(text).not.toContain("SUPERSECRET_TENANT_ID");
  });

  it("health probe body does not contain sensitive data", async () => {
    const state = makeMockState();
    const env = makeEnv();
    // Inject secret-looking data as DO id (should only appear as hash)
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/health"));
    const body = await resp.json() as Record<string, unknown>;
    // Verify only expected fields are present
    const allowedFields = new Set([
      "status", "container_status", "container_running",
      "cold_start_count", "last_health_check_ms", "request_id",
      // D1 placement instrument: timings + D1's own served_by_* provenance +
      // bounded error strings from a `SELECT 1`. No tenant id, no binding value,
      // no body bytes ever enter it.
      "d1_probe",
    ]);
    for (const key of Object.keys(body)) {
      expect(allowedFields.has(key), `unexpected field: ${key}`).toBe(true);
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// DO PagerDuty telemetry path (non-empty routingKey exercises emitLifecycleEvent body)
// ──────────────────────────────────────────────────────────────────────────────

describe("DO PagerDuty telemetry emit", () => {
  it("stop with non-empty PAGERDUTY_ROUTING_KEY exercises emitLifecycleEvent body (fetch stubbed to 200)", async () => {
    // Stub fetch so the PD call returns 200 immediately — exercises lines 160-186
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ status: "success" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
    );
    try {
      const state = makeMockState();
      const env: Env & { PAGERDUTY_ROUTING_KEY?: string } = {
        CORELINK_SERVER: {} as DurableObjectNamespace,
        ENVIRONMENT: "test",
        PAGERDUTY_ROUTING_KEY: "test-fake-routing-key-00000000000000",
      };
      const do_ = new CoreLinkServer(state, env);
      await new Promise<void>((r) => setTimeout(r, 5));

      // Should return 200 — PD emit is fire-and-forget
      const resp = await do_.fetch(new Request("http://localhost/_do/stop"));
      expect(resp.status).toBe(200);
      const body = await resp.json() as { stopped: boolean };
      expect(body.stopped).toBe(true);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("emitLifecycleEvent catch block is exercised when fetch throws (lines 187-188)", async () => {
    // Patch global fetch to throw for PD endpoint, verifying the catch block is exercised.
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("pagerduty.com")) {
        throw new Error("simulated PagerDuty network error");
      }
      throw new Error("unexpected fetch call in test");
    });

    try {
      const state = makeMockState();
      const env: Env & { PAGERDUTY_ROUTING_KEY?: string } = {
        CORELINK_SERVER: {} as DurableObjectNamespace,
        ENVIRONMENT: "test",
        PAGERDUTY_ROUTING_KEY: "non-empty-routing-key-for-throw-test",
      };
      const do_ = new CoreLinkServer(state, env);
      await new Promise<void>((r) => setTimeout(r, 5));

      // The stop endpoint emits a PD event; fetch throws → catch block runs → DO still returns 200
      const resp = await do_.fetch(new Request("http://localhost/_do/stop"));
      expect(resp.status).toBe(200);
      const body = await resp.json() as { stopped: boolean };
      expect(body.stopped).toBe(true);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("emitLifecycleEvent skips body when routingKey is empty string", async () => {
    // Verify the guard at routingKey.length === 0 (already covered by default tests,
    // this ensures the empty-key fast-path stays covered after refactors)
    const state = makeMockState();
    const env = makeEnv(); // PAGERDUTY_ROUTING_KEY = "" via module augmentation default
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    const resp = await do_.fetch(new Request("http://localhost/_do/stop"));
    expect(resp.status).toBe(200);
  });

  it("stop with non-empty PD key still persists lifecycle state as 'stopped'", async () => {
    const state = makeMockState();
    await state.storage.put("lifecycle", {
      containerStatus: "running",
      lastHealthCheckMs: Date.now() - 1000,
      coldStartCount: 2,
      tenantId: "tenant-pd-test",
    });
    const env: Env & { PAGERDUTY_ROUTING_KEY?: string } = {
      CORELINK_SERVER: {} as DurableObjectNamespace,
      ENVIRONMENT: "test",
      PAGERDUTY_ROUTING_KEY: "fake-key-for-coverage",
    };
    const do_ = new CoreLinkServer(state, env);
    await new Promise<void>((r) => setTimeout(r, 5));

    await do_.fetch(new Request("http://localhost/_do/stop"));

    const stored = await state.storage.get("lifecycle") as Record<string, unknown> | undefined;
    expect(stored?.["containerStatus"]).toBe("stopped");
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Adversarial attacks — 5 required by WP-1.1 DOD §7
// ──────────────────────────────────────────────────────────────────────────────
// B-126 M3 split population: durable_object_part2.test.ts

describe("exact old probe retirement fence", () => {
  const oldName = "_staging_d1_binding_probe_v2:issue-1700-recovery-20260929:0f785fb9b096afe01247f1057d46377b9f604f13";
  const retiredKey = "staging-d1-binding-probe-retired-v1";
  const v5Name = "_staging_d1_binding_probe_v2:issue-1700-recovery-20260930-v5:cc32b3d819181bf9175e795868f66212aa5456c1";
  const v5RetiredKey = "staging-d1-binding-probe-retired-v5";
  const time = STAGING_D1_PROBE_WINDOW.starts_ms + 60000;
  const oldProbeAdmission = { contract: "corelink-staging-d1-probe-admission-v1" as const,
    probe_nonce: STAGING_D1_PROBE_WINDOW.nonce, worker_release: "a".repeat(40), scheduled_time_ms: time };
  function fixture(id = oldName) {
    const state = makeMockState(id);
    Object.assign(state, { container: { running: false, destroy: vi.fn().mockResolvedValue(undefined) } });
    const sql = vi.fn(() => ({ bind() { return this; }, all: async () => ({ success: true, results: [] }) }));
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: "a".repeat(40),
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd", D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      CONFIG_DB: { prepare: sql }, CORELINK_SERVER: { idFromName: (name: string) => ({ toString: () => name }) } } as unknown as Env;
    const do_ = new CoreLinkServer(state, env, () => time);
    return { do_, state, env, sql };
  }
  it("preserves claim/receipt, fences fetch/probe/alarm and is idempotent", async () => {
    const { do_, state, sql } = fixture();
    await state.storage.put("staging-d1-binding-probe-state-v1", "unknown");
    await state.storage.put("staging-d1-binding-probe-receipt-v1", { preserved: true });
    const result = await do_.retireStagingD1RuntimeProbe(time);
    expect(result.old_probe_retired).toBe(true);
    expect(result.old_probe_tables_absent).toBe(true);
    expect(await state.storage.get("staging-d1-binding-probe-state-v1")).toBe("unknown");
    expect(await state.storage.get("staging-d1-binding-probe-receipt-v1")).toEqual({ preserved: true });
    expect(await state.storage.get(retiredKey)).toBeDefined();
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    await expect(do_.runStagingD1RuntimeProbe(oldProbeAdmission)).rejects.toThrow();
    const calls = sql.mock.calls.length;
    await do_.alarm();
    expect(sql.mock.calls.length).toBe(calls); // no generic tenant cleanup
    await expect(do_.retireStagingD1RuntimeProbe(time)).resolves.toEqual(result);
  });
  it("retires the exact v5 DO independently while preserving its unknown claim and receipt", async () => {
    const { do_, state, sql } = fixture(v5Name);
    await state.storage.put("staging-d1-binding-probe-state-v1", "unknown");
    await state.storage.put("staging-d1-binding-probe-receipt-v1", { execution: "unknown" });
    const result = await do_.retireStagingD1RuntimeProbe(time);
    expect(result).toEqual({ v5_probe_release: "cc32b3d819181bf9175e795868f66212aa5456c1",
      v5_probe_retired: true, v5_probe_tables_absent: true });
    expect(await state.storage.get("staging-d1-binding-probe-state-v1")).toBe("unknown");
    expect(await state.storage.get("staging-d1-binding-probe-receipt-v1")).toEqual({ execution: "unknown" });
    expect(await state.storage.get(v5RetiredKey)).toBeDefined();
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    expect(sql).toHaveBeenCalled();
  });
  it.each(["wrong-id", "production", "account", "database", "expired"])("rejects %s before marker/SQL", async kind => {
    const { do_, state, env, sql } = fixture(kind === "wrong-id" ? "tenant" : oldName);
    if (kind === "production") env.ENVIRONMENT = "production";
    if (kind === "account") env.CLOUDFLARE_ACCOUNT_ID = "wrong";
    if (kind === "database") env.D1_DATABASE_ID = "wrong";
    await expect(do_.retireStagingD1RuntimeProbe(kind === "expired" ? STAGING_D1_PROBE_WINDOW.expires_ms : time)).rejects.toThrow();
    expect(await state.storage.get(retiredKey)).toBeUndefined();
    expect(sql).not.toHaveBeenCalled();
  });
  it("refuses active work and concurrent retirement without cleaning", async () => {
    const { do_, state, sql } = fixture();
    await Promise.resolve(); await Promise.resolve();
    let finish!: () => void;
    const active = (do_ as unknown as { withProbeActivity: (f: () => Promise<void>) => Promise<void> })
      .withProbeActivity(() => new Promise<void>(resolve => { finish = resolve; }));
    await expect(do_.retireStagingD1RuntimeProbe(time)).rejects.toThrow("busy");
    expect(sql).not.toHaveBeenCalled();
    expect(await state.storage.get(retiredKey)).toBeUndefined();
    finish(); await active;
    const retirement = do_.retireStagingD1RuntimeProbe(time);
    await expect(do_.retireStagingD1RuntimeProbe(time)).rejects.toThrow("busy");
    await retirement;
  });
  it("rehydrates retirement and fences requests while Container stop is pending", async () => {
    const { do_, state, env, sql } = fixture();
    await Promise.resolve(); await Promise.resolve();
    let stopped!: () => void;
    const container = { running: true, destroy: vi.fn(() => new Promise<void>(resolve => {
      stopped = () => { container.running = false; resolve(); };
    })) };
    Object.assign(state, { container });
    const pending = do_.retireStagingD1RuntimeProbe(time);
    while (!container.destroy.mock.calls.length) await Promise.resolve();
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    await expect(do_.runStagingD1RuntimeProbe(oldProbeAdmission)).rejects.toThrow();
    await do_.alarm();
    expect(sql).not.toHaveBeenCalled();
    stopped(); await pending;
    const restored = new CoreLinkServer(state, env, () => time);
    await Promise.resolve(); await Promise.resolve();
    expect((await restored.fetch(new Request("https://test/"))).status).toBe(410);
    await expect(restored.runStagingD1RuntimeProbe(oldProbeAdmission)).rejects.toThrow();
    const calls = sql.mock.calls.length;
    await restored.alarm();
    expect(sql.mock.calls.length).toBe(calls);
  });
  it("missing old Container binding is unknown, never stopped proof", async () => {
    const { do_, state, sql } = fixture();
    Object.assign(state, { container: undefined });
    await expect(do_.retireStagingD1RuntimeProbe(time)).rejects.toThrow("binding unavailable");
    expect(sql).not.toHaveBeenCalled();
  });
  it("never queries D1 if exact old Container cannot prove stopped", async () => {
    const { do_, state, sql } = fixture();
    Object.assign(state, { container: { running: true, destroy: vi.fn().mockResolvedValue(undefined) } });
    await expect(do_.retireStagingD1RuntimeProbe(time)).rejects.toThrow("stop unproven");
    expect(sql).not.toHaveBeenCalled();
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
  });
});

describe("exact v8 cleanup fence and live proof", () => {
  const release = "a".repeat(40);
  const time = cleanupWindow.starts_ms;
  const admissionKey = "staging-d1-binding-probe-admission-v1";
  const claimKey = "staging-d1-binding-probe-state-v1";
  const receiptKey = "staging-d1-binding-probe-receipt-v1";
  const admission = { contract: "corelink-staging-d1-probe-admission-v1" as const,
    probe_nonce: V8_PROBE_NONCE, worker_release: V8_PROBE_RELEASE,
    scheduled_time_ms: Date.parse("2026-10-01T07:26:00Z") };
  const completion = { contract: "corelink-staging-v8-cleanup-v1", old_release: V8_PROBE_RELEASE,
    old_nonce: V8_PROBE_NONCE, worker_release: release, prior_execution: "unknown",
    prior_admission_present: true, container_stopped: true, alarm_absent: true,
    tables_absent: true, completed_at_ms: time };

  async function fixture(id = V8_PROBE_NAME, now: () => number = () => time) {
    const state = makeMockState(id);
    let ready!: Promise<unknown>;
    Object.assign(state, { blockConcurrencyWhile: (fn: () => Promise<unknown>) => (ready = fn()) });
    const container = { running: false, destroy: vi.fn().mockResolvedValue(undefined) };
    Object.assign(state, { container });
    const catalog = vi.fn().mockResolvedValue({ success: true, results: [] });
    const sql = vi.fn((_query: string) => ({ bind() { return this; }, all: catalog }));
    const env = { ...makeEnv(), ENVIRONMENT: "staging", SENTRY_RELEASE: release,
      CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
      D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
      R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
      CONFIG_DB: { prepare: sql },
      CORELINK_SERVER: { idFromName: (name: string) => ({ toString: () => name }) },
    } as unknown as Env;
    const do_ = new CoreLinkServer(state, env, now);
    await ready;
    return { do_, state, container, env, sql, catalog };
  }
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it("v9 cleanup uses its separate fence and preserves historical admission/state/receipt", async () => {
    const current = STAGING_D1_PROBE_WINDOW.starts_ms + 120_000;
    const { do_, state, container, sql } = await fixture(V9_PROBE_NAME, () => current);
    const prior = { contract: "corelink-staging-d1-probe-admission-v1", probe_nonce: V9_PROBE_NONCE,
      worker_release: V9_PROBE_RELEASE, scheduled_time_ms: Date.parse("2026-10-01T12:36:00Z") };
    await state.storage.put(admissionKey, prior);
    await state.storage.put(claimKey, "unknown");
    await state.storage.put(receiptKey, { prior_execution: "unknown" });
    const result = await do_.cleanupV9StagingD1RuntimeProbe(current, release);
    expect(result).toEqual({ contract: "corelink-staging-v9-cleanup-v1", old_release: V9_PROBE_RELEASE,
      old_nonce: V9_PROBE_NONCE, worker_release: release, prior_execution: "unknown",
      prior_admission_present: true, container_stopped: true, alarm_absent: true, tables_absent: true, completed_at_ms: current });
    expect(await state.storage.get(V9_PROBE_RETIRED_KEY)).toBeDefined();
    expect(await state.storage.get(V8_PROBE_RETIRED_KEY)).toBeUndefined();
    expect(await state.storage.get(admissionKey)).toEqual(prior);
    expect(await state.storage.get(claimKey)).toBe("unknown");
    expect(await state.storage.get(receiptKey)).toEqual({ prior_execution: "unknown" });
    expect(container.running).toBe(false); expect(sql).toHaveBeenCalledTimes(2);
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    expect((await do_.fetch(new Request("https://test/_internal/staging/d1-binding-runtime-probe", { method: "POST" }))).status).toBe(404);
  });

  it("preserves all three historical keys and only writes the exact completion after live proof", async () => {
    const { do_, state, sql, container } = await fixture();
    const historical = { [admissionKey]: admission, [claimKey]: "unknown", [receiptKey]: { execution: "unknown" } };
    for (const [key, value] of Object.entries(historical)) await state.storage.put(key, value);
    const put = vi.spyOn(state.storage, "put");
    // The historical object is already ineligible for native replay before its marker exists.
    await expect(do_.admitStagingD1RuntimeProbe(time)).rejects.toThrow();
    await expect(do_.runStagingD1RuntimeProbe(admission)).rejects.toThrow("old probe cannot be replayed");
    const result = await do_.cleanupV8StagingD1RuntimeProbe(time, release);
    expect(result).toEqual(completion);
    expect(Object.keys(result)).toHaveLength(10);
    expect(await state.storage.get(V8_CLEANUP_RECEIPT_KEY)).toEqual(completion);
    for (const [key, value] of Object.entries(historical)) {
      expect(await state.storage.get(key)).toEqual(value);
      expect(put.mock.calls.some(call => call[0] === key)).toBe(false);
    }
    expect(sql).toHaveBeenCalledTimes(2);
    expect(container.destroy).not.toHaveBeenCalled();
    expect(put.mock.calls.at(-1)).toEqual([V8_CLEANUP_RECEIPT_KEY, completion]);
    expect(put.mock.invocationCallOrder.at(-1)).toBeGreaterThan(sql.mock.invocationCallOrder.at(-1)!);
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    await expect(do_.admitStagingD1RuntimeProbe(time)).rejects.toThrow();
    await expect(do_.runStagingD1RuntimeProbe(admission)).rejects.toThrow("old probe cannot be replayed");
    await do_.alarm();
    expect(sql).toHaveBeenCalledTimes(2);
  });

  it("refuses an active old call before any marker or SQL and permits cleanup after quiescence", async () => {
    const { do_, state, sql } = await fixture();
    let finish!: () => void;
    const active = (do_ as unknown as { withProbeActivity: (f: () => Promise<void>) => Promise<void> })
      .withProbeActivity(() => new Promise<void>(resolve => { finish = resolve; }));
    await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).rejects.toThrow("busy");
    expect(sql).not.toHaveBeenCalled();
    expect(await state.storage.get(V8_PROBE_RETIRED_KEY)).toBeUndefined();
    finish(); await active;
    await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).resolves.toMatchObject({ tables_absent: true });
    expect(sql).toHaveBeenCalledTimes(2);
  });

  it("fences incoming work synchronously and withholds SQL and completion while destroy is pending", async () => {
    const { do_, state, container, sql } = await fixture();
    let stop!: () => void;
    container.running = true;
    container.destroy.mockImplementation(() => new Promise<void>(resolve => {
      stop = () => { container.running = false; resolve(); };
    }));
    const pending = do_.cleanupV8StagingD1RuntimeProbe(time, release);
    await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).rejects.toThrow("busy");
    expect((await do_.fetch(new Request("https://test/"))).status).toBe(410);
    for (let i = 0; i < 40 && !container.destroy.mock.calls.length; i++) await Promise.resolve();
    expect(container.destroy).toHaveBeenCalledOnce();
    expect(await state.storage.get(V8_PROBE_RETIRED_KEY)).toEqual({ old_release: V8_PROBE_RELEASE, destroy_attempted: true });
    expect(await state.storage.get(V8_CLEANUP_RECEIPT_KEY)).toBeUndefined();
    await do_.alarm();
    expect(sql).not.toHaveBeenCalled();
    stop();
    await expect(pending).resolves.toMatchObject({ container_stopped: true, prior_admission_present: false });
  });

  it.each(["destroy-error", "timeout", "still-running", "missing-container", "alarm"])(
    "cannot prove completion or touch D1 after %s", async failure => {
      vi.useFakeTimers(); vi.setSystemTime(time);
      const { do_, state, container, sql } = await fixture(V8_PROBE_NAME, Date.now);
      if (failure === "missing-container") Object.assign(state, { container: undefined });
      else if (failure === "alarm") vi.spyOn(state.storage, "getAlarm").mockResolvedValue(time);
      else {
        container.running = true;
        if (failure === "destroy-error") container.destroy.mockRejectedValue(new Error("private-destroy-error"));
        if (failure === "timeout") container.destroy.mockImplementation(() => new Promise<void>(() => {}));
      }
      const pending = do_.cleanupV8StagingD1RuntimeProbe(time, release);
      const rejected = expect(pending).rejects.toThrow();
      if (failure === "timeout") await vi.advanceTimersByTimeAsync(60_000);
      await rejected;
      expect(sql).not.toHaveBeenCalled();
      expect(await state.storage.get(V8_PROBE_RETIRED_KEY)).toBeDefined();
      expect(await state.storage.get(V8_CLEANUP_RECEIPT_KEY)).toBeUndefined();
      if (["destroy-error", "timeout", "still-running"].includes(failure)) {
        await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).rejects.toThrow();
        expect(container.destroy).toHaveBeenCalledOnce();
        expect(sql).not.toHaveBeenCalled();
      }
    });

  it.each(["wrong-id", "production", "account", "database", "r2", "malformed-release", "old-release", "wrong-release",
    "start-minus-one", "expiry", "expiry-plus-one", "future", "fractional", "off-cadence"])(
    "rejects %s before marker or SQL", async failure => {
      let now = time;
      const { do_, state, env, sql, container } = await fixture(failure === "wrong-id" ? "tenant" : V8_PROBE_NAME, () => now);
      let scheduled = time;
      let expectedRelease = release;
      if (failure === "production") env.ENVIRONMENT = "production";
      if (failure === "account") env.CLOUDFLARE_ACCOUNT_ID = "wrong";
      if (failure === "database") env.D1_DATABASE_ID = "wrong";
      if (failure === "r2") env.R2_S3_ENDPOINT = "https://wrong.invalid";
      if (failure === "malformed-release") env.SENTRY_RELEASE = expectedRelease = "malformed";
      if (failure === "old-release") env.SENTRY_RELEASE = expectedRelease = V8_PROBE_RELEASE;
      if (failure === "wrong-release") expectedRelease = "b".repeat(40);
      if (failure === "start-minus-one") scheduled = now = time - 1;
      if (failure === "expiry") now = cleanupWindow.expires_ms;
      if (failure === "expiry-plus-one") now = cleanupWindow.expires_ms + 1;
      if (failure === "future") scheduled += 120_000;
      if (failure === "fractional") scheduled += 0.5;
      if (failure === "off-cadence") scheduled = now = time + 1;
      await expect(do_.cleanupV8StagingD1RuntimeProbe(scheduled, expectedRelease)).rejects.toThrow("guard rejected");
      expect(await state.storage.get(V8_PROBE_RETIRED_KEY)).toBeUndefined();
      expect(sql).not.toHaveBeenCalled();
      expect(container.destroy).not.toHaveBeenCalled();
    });

  it("accepts the last instant of cleanup without relaxing native admission or expiry", async () => {
    const now = cleanupWindow.expires_ms - 1;
    const scheduled = Math.floor(now / 120_000) * 120_000;
    const { do_, state, env } = await fixture(V8_PROBE_NAME, () => now);
    await expect(do_.cleanupV8StagingD1RuntimeProbe(scheduled, release)).resolves.toMatchObject({ completed_at_ms: now });
    const freshState = makeMockState(`_staging_d1_binding_probe_v2:${STAGING_D1_PROBE_WINDOW.nonce}:${release}`);
    const fresh = new CoreLinkServer(freshState, env, () => now);
    await expect(fresh.admitStagingD1RuntimeProbe(scheduled)).rejects.toThrow();
    await expect(do_.runStagingD1RuntimeProbe(admission)).rejects.toThrow("old probe cannot be replayed");
    const expired = new CoreLinkServer(state, env, () => cleanupWindow.expires_ms);
    await expect(expired.cleanupV8StagingD1RuntimeProbe(scheduled, release)).rejects.toThrow("guard rejected");
    const expiredNative = new CoreLinkServer(freshState, env, () => STAGING_D1_PROBE_WINDOW.expires_ms);
    await expect(expiredNative.runStagingD1RuntimeProbe({ ...admission,
      probe_nonce: STAGING_D1_PROBE_WINDOW.nonce, worker_release: release,
      scheduled_time_ms: STAGING_D1_PROBE_WINDOW.starts_ms,
    })).rejects.toThrow("guard rejected");
  });

  it.each(["valid", "running", "alarm", "catalog"])("revalidates stored retirement and completion against current %s state", async current => {
    const { do_, state, container, catalog, sql } = await fixture();
    await state.storage.put(V8_PROBE_RETIRED_KEY, { old_release: V8_PROBE_RELEASE, destroy_attempted: true });
    await state.storage.put(V8_CLEANUP_RECEIPT_KEY, completion);
    await state.storage.put(admissionKey, admission);
    if (current === "running") container.running = true;
    if (current === "alarm") vi.spyOn(state.storage, "getAlarm").mockResolvedValue(time);
    if (current === "catalog") catalog.mockResolvedValue({ success: false, results: [] });
    const put = vi.spyOn(state.storage, "put");
    if (current === "valid") {
      await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).resolves.toEqual(completion);
      expect(sql).toHaveBeenCalledTimes(2);
      expect(put.mock.calls.some(call => call[0] === V8_CLEANUP_RECEIPT_KEY)).toBe(true);
    } else {
      await expect(do_.cleanupV8StagingD1RuntimeProbe(time, release)).rejects.toThrow();
      expect(put.mock.calls.some(call => call[0] === V8_CLEANUP_RECEIPT_KEY)).toBe(false);
      if (current !== "catalog") expect(sql).not.toHaveBeenCalled();
    }
    expect(container.destroy).not.toHaveBeenCalled();
    expect(await state.storage.get(V8_CLEANUP_RECEIPT_KEY)).toEqual(completion);
  });
});
