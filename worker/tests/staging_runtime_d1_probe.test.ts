import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScheduledController } from "@cloudflare/workers-types";
import { runScheduled, STAGING_D1_RUNTIME_PROBE_CRON, STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS } from "../src/index_schedule.js";
import { STAGING_D1_PROBE_WINDOW } from "../src/staging_runtime_d1_probe.js";
import type { Env } from "../src/index_common.js";

const RELEASE = "0123456789abcdef0123456789abcdef01234567";
const SCHEDULED_TIME = Date.parse("2026-09-30T18:01:00Z");
const RECEIPT = {
  contract: "corelink-staging-d1-binding-runtime-v1",
  outcome: "pass",
  probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
  worker_release: RELEASE,
  scheduled_time_ms: SCHEDULED_TIME,
  parameterized_select: true,
  failed_batch_observed: true,
  rollback_absence_verified: true,
  probe_table_dropped: true,
  d1_binding_intercepted: true,
  authorization_absent: true,
  cf_api_token_absent: true,
} as const;

function controller(cron = STAGING_D1_RUNTIME_PROBE_CRON): ScheduledController & { noRetry: ReturnType<typeof vi.fn> } {
  return { cron, scheduledTime: SCHEDULED_TIME, noRetry: vi.fn() } as unknown as ScheduledController & { noRetry: ReturnType<typeof vi.fn> };
}

function controllerAt(scheduledTime: number): ScheduledController & { noRetry: ReturnType<typeof vi.fn> } {
  return { cron: STAGING_D1_RUNTIME_PROBE_CRON, scheduledTime, noRetry: vi.fn() } as unknown as ScheduledController & { noRetry: ReturnType<typeof vi.fn> };
}

function env(stub: { runStagingD1RuntimeProbe: ReturnType<typeof vi.fn> }): Env {
  const retired = { retireStagingD1RuntimeProbe: vi.fn().mockResolvedValue({
    old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true }) };
  return {
    ENVIRONMENT: "staging",
    SENTRY_RELEASE: RELEASE,
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
    CONFIG_DB: { prepare: vi.fn(() => ({ bind: vi.fn(function (this: unknown) { return this; }),
      all: vi.fn().mockResolvedValue({ success: true, results: [] }) })) },
    R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
    CORELINK_SERVER: {
      idFromName: vi.fn((name: string) => ({ name })),
      get: vi.fn((id: { name: string }) => id.name.includes("recovery-20260929:") ? retired : stub),
    },
  } as unknown as Env;
}

afterEach(() => vi.useRealTimers());

describe("temporary staging native D1 runtime Cron", () => {
  it("calls only the fixed release-specific DO RPC and emits no synthetic drill", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-30T18:01:05Z"));
    const stub = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const target = env(stub);
    const controllerValue = controller();

    await expect(runScheduled(controllerValue, target)).resolves.toBeUndefined();

    expect(target.CORELINK_SERVER.idFromName).toHaveBeenCalledWith(`_staging_d1_binding_probe_v2:${STAGING_D1_PROBE_WINDOW.nonce}:${RELEASE}`);
    expect(target.CORELINK_SERVER.get).toHaveBeenCalledTimes(2);
    expect(stub.runStagingD1RuntimeProbe).toHaveBeenCalledWith(SCHEDULED_TIME);
    expect(controllerValue.noRetry).not.toHaveBeenCalled();
  });

  it("accepts the same stored release receipt on a later minute for tail recovery", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-30T18:02:05Z"));
    const stub = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const later = controllerAt(Date.parse("2026-09-30T18:02:00Z"));
    await expect(runScheduled(later, env(stub))).resolves.toBeUndefined();
    expect(stub.runStagingD1RuntimeProbe).toHaveBeenCalledWith(later.scheduledTime);
  });

  it("rejects wrong target and expired time before calling the DO", async () => {
    vi.useFakeTimers();
    const stub = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const target = env(stub);
    vi.setSystemTime(new Date(STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS - 1));
    await expect(runScheduled(controller(), target)).resolves.toBeUndefined();
    expect(stub.runStagingD1RuntimeProbe).toHaveBeenCalledOnce();

    stub.runStagingD1RuntimeProbe.mockClear();
    const badTarget = { ...target, ENVIRONMENT: "production" } as Env;
    const before = controller();
    vi.setSystemTime(new Date("2026-09-30T18:01:05Z"));
    await expect(runScheduled(before, badTarget)).rejects.toThrow("staging D1 runtime probe guard rejected");
    expect(before.noRetry).toHaveBeenCalledOnce();
    expect(stub.runStagingD1RuntimeProbe).not.toHaveBeenCalled();

    const expired = controller();
    vi.setSystemTime(new Date(STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS));
    await expect(runScheduled(expired, target)).rejects.toThrow("staging D1 runtime probe guard rejected");
    expect(expired.noRetry).toHaveBeenCalledOnce();
    expect(stub.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
  });

  it("rejects malformed or incomplete receipts without logging their body", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-30T18:01:05Z"));
    const stub = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue({ ...RECEIPT, rollback_absence_verified: false }) };
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(runScheduled(controller(), env(stub))).rejects.toThrow("staging D1 runtime probe failed");
    expect(error).toHaveBeenCalledWith("[staging_d1_runtime_probe] failed reason=probe_failed");
    expect(error.mock.calls.flat().join(" ")).not.toContain(JSON.stringify(stub.runStagingD1RuntimeProbe.mock.results));
  });
});


it("rejects previous-window nonce and previous-release receipts", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(SCHEDULED_TIME + 5000);
  for (const receipt of [
    { ...RECEIPT, probe_nonce: "old-probe" },
    { ...RECEIPT, worker_release: "a".repeat(40) },
    { ...RECEIPT, scheduled_time_ms: STAGING_D1_PROBE_WINDOW.starts_ms - 60000 },
  ]) {
    const stub = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(receipt) };
    await expect(runScheduled(controller(), env(stub))).rejects.toThrow("staging D1 runtime probe failed");
  }
});

it("does not enter fresh probe when retirement fails or returns incomplete proof", async () => {
  vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
  for (const result of [undefined, { old_probe_release: "wrong", old_probe_retired: true, old_probe_tables_absent: true },
    { old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: false }]) {
    const fresh = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const target = env(fresh);
    const retire = result === undefined ? vi.fn().mockRejectedValue(new Error("retirement failed")) : vi.fn().mockResolvedValue(result);
    vi.mocked(target.CORELINK_SERVER.get).mockImplementation(() => ({ retireStagingD1RuntimeProbe: retire }) as never);
    await expect(runScheduled(controller(), target)).rejects.toThrow();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
  }
});
