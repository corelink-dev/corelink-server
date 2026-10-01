import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScheduledController } from "@cloudflare/workers-types";
import { runScheduled, STAGING_D1_RUNTIME_PROBE_CRON, STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS } from "../src/index_schedule.js";
import { recordStagingD1ProbePhase, runStagingD1BindingRuntimeProbe, STAGING_D1_PROBE_WINDOW } from "../src/staging_runtime_d1_probe.js";
import { B072_ONE_SHOT_CRON } from "../src/b072_one_shot.js";
import { V5_PROBE_RELEASE } from "../src/staging_d1_probe_retirement.js";
import { V8_PROBE_NAME, V8_PROBE_RELEASE, V8_PROBE_NONCE } from "../src/staging_d1_probe_v8_cleanup.js";
import cleanupWindow from "../src/staging_d1_probe_cleanup_window.json";
import type { Env } from "../src/index_common.js";

const RELEASE = "0123456789abcdef0123456789abcdef01234567";
const SCHEDULED_TIME = STAGING_D1_PROBE_WINDOW.starts_ms;
const CLEANUP_RECEIPT = {
  contract: "corelink-staging-v8-cleanup-v1", old_release: V8_PROBE_RELEASE,
  old_nonce: V8_PROBE_NONCE, worker_release: RELEASE, prior_execution: "unknown",
  prior_admission_present: true, container_stopped: true, alarm_absent: true,
  tables_absent: true, completed_at_ms: SCHEDULED_TIME,
} as const;
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

function env(stub: { runStagingD1RuntimeProbe: ReturnType<typeof vi.fn>; readStagingD1RuntimeProbeReceipt?: ReturnType<typeof vi.fn>; admitStagingD1RuntimeProbe?: ReturnType<typeof vi.fn> },
  cleanup = vi.fn().mockResolvedValue(CLEANUP_RECEIPT)): Env {
  const retired = { retireStagingD1RuntimeProbe: vi.fn().mockResolvedValue({
    old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true }) };
  const retiredV5 = { retireStagingD1RuntimeProbe: vi.fn().mockResolvedValue({
    v5_probe_release: V5_PROBE_RELEASE, v5_probe_retired: true, v5_probe_tables_absent: true }) };
  return {
    ENVIRONMENT: "staging",
    SENTRY_RELEASE: RELEASE,
    CLOUDFLARE_ACCOUNT_ID: "6a1fc1c626fc2628823e60b9db01f5cd",
    D1_DATABASE_ID: "d72a6b39-6a48-4338-bfda-1111dda98604",
    CONFIG_DB: { prepare: vi.fn(() => ({ bind: vi.fn(function (this: unknown) { return this; }),
      all: vi.fn().mockResolvedValue({ success: true, results: [] }) })) },
    R2_S3_ENDPOINT: "https://6a1fc1c626fc2628823e60b9db01f5cd.r2.cloudflarestorage.com",
    CORELINK_SERVER: {
      idFromName: vi.fn((name: string) => ({ name, toString: () => name })),
      get: vi.fn((id: { name: string }) => id.name.includes("recovery-20260929:") ? retired :
        id.name.includes("issue-1700-recovery-20260930-v5:") ? retiredV5 :
        id.name === V8_PROBE_NAME ? { cleanupV8StagingD1RuntimeProbe: cleanup } : {
        ...stub,
        readStagingD1RuntimeProbeReceipt: stub.readStagingD1RuntimeProbeReceipt ?? vi.fn().mockResolvedValue(undefined),
        admitStagingD1RuntimeProbe: stub.admitStagingD1RuntimeProbe ?? vi.fn().mockImplementation(async (scheduledTime: number) => ({
          status: "admitted", admission: { contract: "corelink-staging-d1-probe-admission-v1",
            probe_nonce: STAGING_D1_PROBE_WINDOW.nonce, worker_release: RELEASE, scheduled_time_ms: scheduledTime },
        })),
      }),
    },
  } as unknown as Env;
}

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe("native Cron is a read-only receipt carrier", () => {
  it.each([SCHEDULED_TIME, STAGING_D1_PROBE_WINDOW.last_entry_ms + 60_000])(
    "reads the fixed namespace without cleanup, admission or native work at %s", async scheduledTime => {
      vi.useFakeTimers(); vi.setSystemTime(scheduledTime + 5000);
      const fresh = { runStagingD1RuntimeProbe: vi.fn(), admitStagingD1RuntimeProbe: vi.fn(),
        readStagingD1RuntimeProbeReceipt: vi.fn().mockResolvedValue(RECEIPT) };
      const cleanup = vi.fn(), target = env(fresh, cleanup), tick = controllerAt(scheduledTime);
      const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
      await runScheduled(tick, target);
      expect(tick.noRetry).toHaveBeenCalledOnce();
      expect(target.CORELINK_SERVER.get).toHaveBeenCalledOnce();
      expect(fresh.readStagingD1RuntimeProbeReceipt).toHaveBeenCalledWith(scheduledTime);
      expect(cleanup).not.toHaveBeenCalled();
      expect(fresh.admitStagingD1RuntimeProbe).not.toHaveBeenCalled();
      expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
      expect(JSON.stringify(info.mock.calls)).not.toContain("authenticated_http");
    });
  it("does not substitute an execution when there is no stored receipt", async () => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME);
    const fresh = { runStagingD1RuntimeProbe: vi.fn() }, cleanup = vi.fn();
    const target = env(fresh, cleanup), tick = controller();
    await runScheduled(tick, target);
    expect(tick.noRetry).toHaveBeenCalledOnce();
    expect(cleanup).not.toHaveBeenCalled();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
  });
  it("rejects a wrong target and expired timestamp before querying a DO", async () => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME);
    const target = env({ runStagingD1RuntimeProbe: vi.fn() });
    await expect(runScheduled(controller(), { ...target, ENVIRONMENT: "production" })).rejects.toThrow("guard rejected");
    await expect(runScheduled(controllerAt(STAGING_D1_RUNTIME_PROBE_EXPIRES_AT_MS), target)).rejects.toThrow("read target rejected");
    expect(target.CORELINK_SERVER.get).not.toHaveBeenCalled();
  });
  it("does not reinterpret the separate B072 cadence as native admission", async () => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME);
    expect(B072_ONE_SHOT_CRON).not.toBe(STAGING_D1_RUNTIME_PROBE_CRON);
    const target = env({ runStagingD1RuntimeProbe: vi.fn() });
    await expect(runScheduled(controller(B072_ONE_SHOT_CRON), target)).rejects.toThrow();
    expect(target.CORELINK_SERVER.get).not.toHaveBeenCalled();
  });
});

describe("v8 cleanup gates v9 probe admission", () => {
  it("waits for cleanup and logs its separate receipt before accessing the new object", async () => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
    let finish!: (value: typeof CLEANUP_RECEIPT) => void;
    const cleanup = vi.fn(() => new Promise<typeof CLEANUP_RECEIPT>(resolve => { finish = resolve; }));
    const fresh = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const target = env(fresh, cleanup);
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const pending = runStagingD1BindingRuntimeProbe(target, SCHEDULED_TIME);
    await Promise.resolve();
    expect(cleanup).toHaveBeenCalledWith(SCHEDULED_TIME, RELEASE);
    expect(target.CORELINK_SERVER.get).toHaveBeenCalledOnce();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
    expect(info).not.toHaveBeenCalled();
    finish(CLEANUP_RECEIPT);
    const result = await pending;
    expect(result).not.toHaveProperty("v8_cleanup");
    expect(result).not.toHaveProperty("prior_admission_present");
    expect(Object.keys(result)).toHaveLength(20);
    expect(info).toHaveBeenCalledExactlyOnceWith(`[staging_d1_runtime_probe] v8_cleanup=${JSON.stringify(CLEANUP_RECEIPT)}`);
    expect(info.mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(target.CORELINK_SERVER.get).mock.invocationCallOrder[1]!);
  });

  it.each([
    undefined, null, {}, { ...CLEANUP_RECEIPT, extra: true },
    { ...CLEANUP_RECEIPT, old_release: RELEASE }, { ...CLEANUP_RECEIPT, old_nonce: "v9" },
    { ...CLEANUP_RECEIPT, worker_release: "f".repeat(40) },
    { ...CLEANUP_RECEIPT, prior_execution: "complete" },
    { ...CLEANUP_RECEIPT, prior_admission_present: "true" },
    { ...CLEANUP_RECEIPT, container_stopped: false }, { ...CLEANUP_RECEIPT, alarm_absent: false },
    { ...CLEANUP_RECEIPT, tables_absent: false },
    { ...CLEANUP_RECEIPT, completed_at_ms: cleanupWindow.starts_ms - 1 },
    { ...CLEANUP_RECEIPT, completed_at_ms: SCHEDULED_TIME + 5001 },
  ])("rejects invalid cleanup proof before new admission: %j", async receipt => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
    const fresh = { runStagingD1RuntimeProbe: vi.fn(), admitStagingD1RuntimeProbe: vi.fn() };
    const target = env(fresh, vi.fn().mockResolvedValue(receipt));
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    await expect(runStagingD1BindingRuntimeProbe(target, SCHEDULED_TIME)).rejects.toThrow("cleanup receipt rejected");
    expect(target.CORELINK_SERVER.idFromName).toHaveBeenCalledExactlyOnceWith(V8_PROBE_NAME);
    expect(fresh.admitStagingD1RuntimeProbe).not.toHaveBeenCalled();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
    expect(info).not.toHaveBeenCalled();
  });

  it.each(["rpc-error", "timeout"])("denies new admission after cleanup %s", async failure => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
    const cleanup = failure === "rpc-error"
      ? vi.fn().mockRejectedValue(new Error("private-provider-error"))
      : vi.fn(() => new Promise<never>(() => {}));
    const fresh = { runStagingD1RuntimeProbe: vi.fn(), admitStagingD1RuntimeProbe: vi.fn() };
    const target = env(fresh, cleanup);
    const pending = runStagingD1BindingRuntimeProbe(target, SCHEDULED_TIME);
    const rejected = expect(pending).rejects.toThrow("v8 cleanup operation failed or deadline exceeded");
    if (failure === "timeout") await vi.advanceTimersByTimeAsync(60_000);
    await rejected;
    expect(target.CORELINK_SERVER.get).toHaveBeenCalledOnce();
    expect(fresh.admitStagingD1RuntimeProbe).not.toHaveBeenCalled();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
  });

  it("still requires cleanup before returning an existing new-release receipt", async () => {
    vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
    const fresh = { runStagingD1RuntimeProbe: vi.fn(),
      readStagingD1RuntimeProbeReceipt: vi.fn().mockResolvedValue(RECEIPT) };
    const cleanup = vi.fn().mockRejectedValue(new Error("unproven"));
    await expect(runStagingD1BindingRuntimeProbe(env(fresh, cleanup), SCHEDULED_TIME)).rejects.toThrow();
    expect(fresh.readStagingD1RuntimeProbeReceipt).not.toHaveBeenCalled();
  });
});

it("phase diagnostics contain only frozen enums and a valid staging release", () => {
  const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
  const target = env({ runStagingD1RuntimeProbe: vi.fn() });
  for (const phase of ["scheduled_entry", "native_start", "native_complete", "native_error"] as const) {
    recordStagingD1ProbePhase(target, phase);
  }
  recordStagingD1ProbePhase(target, "private-error-sentinel" as never);
  recordStagingD1ProbePhase({ ...target, SENTRY_RELEASE: "private-release-sentinel" }, "native_error");
  recordStagingD1ProbePhase({ ...target, ENVIRONMENT: "production" }, "native_start");
  expect(info.mock.calls.map(call => call[0])).toEqual(
    ["scheduled_entry", "native_start", "native_complete", "native_error"].map(phase =>
      `[staging_d1_runtime_probe] phase=${phase} release=${RELEASE}`));
  info.mockRestore();
});

it("does not enter the fresh DO when exact v5 retirement proof is incomplete", async () => {
  vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
  const fresh = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
  const target = env(fresh);
  vi.mocked(target.CORELINK_SERVER.get).mockImplementation((id) => {
    if (id.name === V8_PROBE_NAME) return ({ cleanupV8StagingD1RuntimeProbe: vi.fn().mockResolvedValue(CLEANUP_RECEIPT) } as never);
    if (id.name.includes("recovery-20260929:")) return ({ retireStagingD1RuntimeProbe: vi.fn().mockResolvedValue({
      old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: true }) } as never);
    if (id.name.includes("issue-1700-recovery-20260930-v5:")) return ({ retireStagingD1RuntimeProbe: vi.fn().mockResolvedValue({
      v5_probe_release: V5_PROBE_RELEASE, v5_probe_retired: true, v5_probe_tables_absent: false }) } as never);
    return ({ readStagingD1RuntimeProbeReceipt: vi.fn().mockResolvedValue(undefined),
      admitStagingD1RuntimeProbe: vi.fn().mockResolvedValue({ status: "admitted", admission: {
        contract: "corelink-staging-d1-probe-admission-v1", probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
        worker_release: RELEASE, scheduled_time_ms: SCHEDULED_TIME,
      } }), runStagingD1RuntimeProbe: fresh.runStagingD1RuntimeProbe } as never);
  });
  await expect(runStagingD1BindingRuntimeProbe(target, SCHEDULED_TIME)).rejects.toThrow();
  expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
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
    await expect(runStagingD1BindingRuntimeProbe(env(stub), SCHEDULED_TIME)).rejects.toThrow();
  }
});

it("does not enter fresh probe when either exact historical retirement fails or is incomplete", async () => {
  vi.useFakeTimers(); vi.setSystemTime(SCHEDULED_TIME + 5000);
  for (const result of [undefined, { old_probe_release: "wrong", old_probe_retired: true, old_probe_tables_absent: true },
    { old_probe_release: "0f785fb9b096afe01247f1057d46377b9f604f13", old_probe_retired: true, old_probe_tables_absent: false }]) {
    const fresh = { runStagingD1RuntimeProbe: vi.fn().mockResolvedValue(RECEIPT) };
    const target = env(fresh);
    const retire = result === undefined ? vi.fn().mockRejectedValue(new Error("retirement failed")) : vi.fn().mockResolvedValue(result);
    const retireV5 = vi.fn().mockResolvedValue({ v5_probe_release: V5_PROBE_RELEASE, v5_probe_retired: true, v5_probe_tables_absent: true });
    vi.mocked(target.CORELINK_SERVER.get).mockImplementation((id) => id.name === V8_PROBE_NAME
      ? ({ cleanupV8StagingD1RuntimeProbe: vi.fn().mockResolvedValue(CLEANUP_RECEIPT) } as never)
      : id.name.includes("recovery-20260929:")
      ? ({ retireStagingD1RuntimeProbe: retire } as never)
      : id.name.includes("issue-1700-recovery-20260930-v5:") ? ({ retireStagingD1RuntimeProbe: retireV5 } as never)
      : ({ readStagingD1RuntimeProbeReceipt: vi.fn().mockResolvedValue(undefined),
        admitStagingD1RuntimeProbe: vi.fn().mockResolvedValue({ status: "admitted", admission: {
          contract: "corelink-staging-d1-probe-admission-v1", probe_nonce: STAGING_D1_PROBE_WINDOW.nonce,
          worker_release: RELEASE, scheduled_time_ms: SCHEDULED_TIME,
        } }), runStagingD1RuntimeProbe: fresh.runStagingD1RuntimeProbe } as never));
    await expect(runStagingD1BindingRuntimeProbe(target, SCHEDULED_TIME)).rejects.toThrow();
    expect(fresh.runStagingD1RuntimeProbe).not.toHaveBeenCalled();
  }
});
