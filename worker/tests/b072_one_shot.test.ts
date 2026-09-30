import { describe, expect, it, vi } from "vitest";
import type { D1Database, ScheduledController } from "@cloudflare/workers-types";
import workerHandler from "../src/index.js";
import type { Env } from "../src/index.js";
import { B072_MAX_WINDOW_MS, B072_MIN_PROPAGATION_MS } from "../src/b072_one_shot.js";

const scheduledAt = 1_785_765_600_000;
const sha = "0123456789abcdef0123456789abcdef01234567";
const receiverVersion = "cf-receiver-one-shot-v9";
const drillId = `SP-${scheduledAt}`;
const correlationId = `PAT-CORRELATION-ID-001:${drillId}`;

function scheduledCtx(): ExecutionContext {
  return {
    waitUntil: (_promise: Promise<unknown>) => undefined,
    passThroughOnException: () => undefined,
  } as unknown as ExecutionContext;
}

function authorization(overrides: Record<string, unknown> = {}) {
  const authorizedAt = scheduledAt - 30 * 60_000;
  return {
    issue_id: 1652,
    serving_sha: sha,
    approval_nonce: "a".repeat(48),
    receiver_worker_revision: receiverVersion,
    approved_reviewer: "independent-reviewer",
    approved_run_id: 123456,
    authorized_at_ms: authorizedAt,
    starts_at_ms: authorizedAt + B072_MIN_PROPAGATION_MS,
    ends_at_ms: scheduledAt + B072_MAX_WINDOW_MS - 10 * 60_000,
    ...overrides,
  };
}

function fakeDatabase(options: { auth?: unknown; claimChanges?: number; readError?: boolean; claimError?: boolean } = {}) {
  const state = { claimed: false };
  const prepare = vi.fn((_sql: string) => {
    const run = vi.fn(async () => {
      if (options.claimError) throw new Error("write unavailable");
      if (state.claimed) return { success: true, meta: { changes: 0 } };
      const changes = options.claimChanges ?? 1;
      if (changes === 1) state.claimed = true;
      return { success: true, meta: { changes } };
    });
    return {
      first: vi.fn(async () => {
        if (options.readError) throw new Error("read unavailable");
        return options.auth === undefined ? authorization() : options.auth;
      }),
      bind: vi.fn(() => ({ run })),
    };
  });
  return { db: { prepare } as unknown as D1Database, prepare, state };
}

function controller(scheduledTime = scheduledAt) {
  const noRetry = vi.fn();
  return { value: { cron: "* * * * *", scheduledTime, noRetry } as unknown as ScheduledController, noRetry };
}

function stagingEnv(fetch: typeof globalThis.fetch, db = fakeDatabase()) {
  return {
    ENVIRONMENT: "staging",
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
    SYNTHETIC_DRILL_PROVIDER_MODE: "provider_deferred",
    SENTRY_RELEASE: sha,
    CONFIG_DB: db.db,
    SCHEDULED_DRILL_DELIVERY: { fetch },
  } as unknown as Env;
}

function terminalResponse(overrides: Record<string, unknown> = {}) {
  return new Response(JSON.stringify({
    terminal: true,
    outcome: "provider_deferred",
    receiver_result: "persisted_provider_deferred",
    drill_id: drillId,
    correlation_id: correlationId,
    scheduled_at_ms: scheduledAt,
    worker_revision: sha,
    serving_sha: sha,
    receiver_worker_revision: receiverVersion,
    ...overrides,
  }), { status: 200, headers: { "content-type": "application/json" } });
}

function terminalAt(at: number) {
  const id = `SP-${at}`;
  return new Response(JSON.stringify({ terminal: true, outcome: "provider_deferred",
    receiver_result: "persisted_provider_deferred", drill_id: id,
    correlation_id: `PAT-CORRELATION-ID-001:${id}`, scheduled_at_ms: at,
    worker_revision: sha, serving_sha: sha, receiver_worker_revision: receiverVersion }),
  { status: 200, headers: { "content-type": "application/json" } });
}

describe("B-072 durable one-shot scheduler fence", () => {
  it("claims before one synthetic provider-deferred service-binding POST", async () => {
    const db = fakeDatabase();
    const post = vi.fn<typeof fetch>().mockResolvedValue(terminalResponse());
    const tick = controller();
    const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);

    await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, db), scheduledCtx())).resolves.toBeUndefined();

    expect(db.prepare).toHaveBeenCalledTimes(2);
    expect(String(db.prepare.mock.calls[1]?.[0])).toContain("INSERT OR IGNORE INTO b072_one_shot_claim");
    expect(String(db.prepare.mock.calls[1]?.[0])).toContain("b072_one_shot_activation");
    expect(String(db.prepare.mock.calls[1]?.[0])).toContain("b072_one_shot_revocation");
    expect(post).toHaveBeenCalledOnce();
    const [, init] = post.mock.calls[0] ?? [];
    const payload = JSON.parse(String((init as RequestInit).body));
    expect(payload).toMatchObject({ cron: "* * * * *", scheduled_at_ms: scheduledAt,
      synthetic_page: { provider_mode: "provider_deferred", dedup_key: drillId, correlation_id: correlationId,
        serving_sha: sha, worker_revision: sha } });
    expect(tick.noRetry).not.toHaveBeenCalled();
    now.mockRestore();
  });

  it.each([
    ["account", { CLOUDFLARE_ACCOUNT_ID: "wrong" }],
    ["D1", { D1_DATABASE_ID: "wrong" }],
    ["provider mode", { SYNTHETIC_DRILL_PROVIDER_MODE: "pagerduty" }],
    ["serving SHA", { SENTRY_RELEASE: "bad" }],
  ])("does not POST when the staging %s guard is wrong", async (_label, override) => {
    const post = vi.fn<typeof fetch>();
    const tick = controller();
    const env = { ...stagingEnv(post), ...override } as unknown as Env;
    await expect(workerHandler.scheduled!(tick.value, env, scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
    expect(post).not.toHaveBeenCalled();
    expect(tick.noRetry).toHaveBeenCalledOnce();
  });

  it.each([
    ["absent", null],
    ["wrong serving SHA", authorization({ serving_sha: "f".repeat(40) })],
    ["malformed nonce", authorization({ approval_nonce: "not-a-nonce" })],
    ["wrong issue", authorization({ issue_id: 1700 })],
    ["too-short propagation", authorization({ starts_at_ms: authorization().starts_at_ms - 1 })],
    ["oversized window", authorization({ ends_at_ms: scheduledAt + B072_MAX_WINDOW_MS + 1 })],
  ])("fails closed for %s authorization without POST", async (_label, auth) => {
    const post = vi.fn<typeof fetch>();
    const db = fakeDatabase({ auth });
    const tick = controller();
    const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
    await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, db), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
    expect(post).not.toHaveBeenCalled();
    expect(tick.noRetry).toHaveBeenCalledOnce();
    now.mockRestore();
  });

  it("rejects both window boundaries and delayed schedule delivery", async () => {
    for (const [nowValue, tickTime] of [
      [scheduledAt, authorization().starts_at_ms - 60_000],
      [authorization().ends_at_ms, scheduledAt],
      [scheduledAt, authorization().ends_at_ms],
    ]) {
      const post = vi.fn<typeof fetch>();
      const tick = controller(tickTime);
      const now = vi.spyOn(Date, "now").mockReturnValue(nowValue);
      await expect(workerHandler.scheduled!(tick.value, stagingEnv(post), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
      expect(post).not.toHaveBeenCalled();
      expect(tick.noRetry).toHaveBeenCalledOnce();
      now.mockRestore();
    }
  });

  it("accepts both authorization window start boundaries inclusively", async () => {
    const startsAt = authorization().starts_at_ms;
    const db = fakeDatabase();
    const post = vi.fn<typeof fetch>().mockResolvedValue(terminalAt(startsAt));
    const tick = controller(startsAt);
    const now = vi.spyOn(Date, "now").mockReturnValue(startsAt);
    await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, db), scheduledCtx())).resolves.toBeUndefined();
    expect(post).toHaveBeenCalledOnce();
    expect(tick.noRetry).not.toHaveBeenCalled();
    now.mockRestore();
  });

  it("rejects pre-activation, revoked, duplicate and concurrent claims", async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const post = vi.fn<typeof fetch>();
      const db = fakeDatabase({ claimChanges: 0 });
      const tick = controller();
      const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
      await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, db), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
      expect(post).not.toHaveBeenCalled();
      expect(tick.noRetry).toHaveBeenCalledOnce();
      now.mockRestore();
    }
  });

  it("consumes claim on receiver exception, 5xx, or non-exact terminal receipt", async () => {
    const invalid = terminalResponse({ serving_sha: "f".repeat(40) });
    const outcomes: Array<() => Promise<Response>> = [
      async () => { throw new Error("lost response"); },
      async () => new Response("{}", { status: 503 }),
      async () => invalid,
    ];
    for (const fetch of outcomes) {
      const db = fakeDatabase();
      const post = vi.fn<typeof globalThis.fetch>().mockImplementation(fetch);
      const tick = controller();
      const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
      await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, db), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
      expect(post).toHaveBeenCalledOnce();
      expect(tick.noRetry).toHaveBeenCalledOnce();
      const later = controller();
      await expect(workerHandler.scheduled!(later.value, stagingEnv(post, db), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
      expect(post).toHaveBeenCalledOnce();
      now.mockRestore();
    }
  });

  it.each([
    ["missing terminal", { terminal: undefined }],
    ["wrong drill", { drill_id: "SP-1785765600001" }],
    ["wrong correlation", { correlation_id: "stale" }],
    ["wrong scheduled time", { scheduled_at_ms: scheduledAt - 60_000 }],
    ["wrong outcome", { outcome: "accepted" }],
    ["wrong receiver result", { receiver_result: "persisted" }],
    ["wrong receiver revision", { receiver_worker_revision: "stale-receiver" }],
    ["missing SHA", { serving_sha: undefined }],
  ])("rejects terminal receipt with %s", async (_label, fields) => {
    const post = vi.fn<typeof fetch>().mockResolvedValue(terminalResponse(fields));
    const tick = controller();
    const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
    await expect(workerHandler.scheduled!(tick.value, stagingEnv(post), scheduledCtx())).rejects.toThrow("B-072 one-shot rejected");
    expect(post).toHaveBeenCalledOnce();
    expect(tick.noRetry).toHaveBeenCalledOnce();
    now.mockRestore();
  });

  it("uses staging noRetry on D1 failures and leaves weekly dev retry behavior alone", async () => {
    const post = vi.fn<typeof fetch>();
    const tick = controller();
    const now = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
    await expect(workerHandler.scheduled!(tick.value, stagingEnv(post, fakeDatabase({ readError: true })), scheduledCtx()))
      .rejects.toThrow("B-072 one-shot rejected");
    expect(tick.noRetry).toHaveBeenCalledOnce();
    expect(post).not.toHaveBeenCalled();
    now.mockRestore();

    const claimFailure = controller();
    const claimPost = vi.fn<typeof fetch>();
    const claimNow = vi.spyOn(Date, "now").mockReturnValue(scheduledAt);
    await expect(workerHandler.scheduled!(claimFailure.value,
      stagingEnv(claimPost, fakeDatabase({ claimError: true })), scheduledCtx()))
      .rejects.toThrow("B-072 one-shot rejected");
    expect(claimFailure.noRetry).toHaveBeenCalledOnce();
    expect(claimPost).not.toHaveBeenCalled();
    claimNow.mockRestore();

    const weekly = controller();
    (weekly.value as unknown as { cron: string }).cron = "0 14 * * 1";
    const weeklyPost = vi.fn<typeof fetch>().mockRejectedValue(new Error("transport"));
    await expect(workerHandler.scheduled!(weekly.value, { ENVIRONMENT: "dev", SCHEDULED_DRILL_DELIVERY: { fetch: weeklyPost } } as Env,
      scheduledCtx())).rejects.toThrow("scheduled drill delivery failed");
    expect(weekly.noRetry).not.toHaveBeenCalled();
  });
});
