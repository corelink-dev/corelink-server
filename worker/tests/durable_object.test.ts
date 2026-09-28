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

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CoreLinkServer, timingSafeEqual } from "../src/durable_object.js";
import type { Env } from "../src/index.js";

// ──────────────────────────────────────────────────────────────────────────────
// Mock helpers
// ──────────────────────────────────────────────────────────────────────────────

/** Create a mock DurableObjectState. Container is always undefined (no CF runtime). */
function makeMockState(idStr = "test-do-id"): DurableObjectState {
  const storage = new Map<string, unknown>();
  const alarmTime: number | null = null;

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
      setAlarm: async (_time: number) => {},
      deleteAlarm: async () => {},
      transaction: async (fn: (txn: DurableObjectTransaction) => Promise<void>) => fn({} as DurableObjectTransaction),
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
