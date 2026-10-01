import { assertV4FailedProbeCatalogAbsent, OLD_PROBE_NAME, OLD_PROBE_RELEASE, V5_PROBE_NAME, V5_PROBE_RELEASE, type OldProbeRetirement } from "./staging_d1_probe_retirement.js";
import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
export const STAGING_D1_PROBE_WINDOW = window;
export const STAGING_D1_PROBE_LAST_ENTRY_MS = window.last_entry_ms;
import type { Env } from "./index_common.js";
import { isV8CleanupReceipt, withinV8CleanupDeadline, V8_PROBE_NAME, type V8CleanupReceipt } from "./staging_d1_probe_v8_cleanup.js";
import cleanupWindow from "./staging_d1_probe_cleanup_window.json";
import { isV9CleanupReceipt, V9_PROBE_NAME, type V9CleanupReceipt } from "./staging_d1_probe_v9_cleanup.js";
import { isStagingD1HttpNativeReceipt } from "./staging_d1_http_contract.js";
import type { StagingD1HttpLifecycle } from "./staging_d1_http_lifecycle.js";

export const STAGING_D1_RUNTIME_PROBE_DO_PREFIX = `_staging_d1_binding_probe_v2:${window.nonce}:`;
export const STAGING_D1_RUNTIME_PROBE_PATH = "/_internal/staging/d1-binding-runtime-probe";

/** Fixed stage evidence only; never provider errors, request data, or receipt payloads. */
export function recordStagingD1ProbePhase(env: Env,
  phase: "scheduled_entry" | "native_start" | "native_complete" | "native_error"): void {
  const release = env.SENTRY_RELEASE ?? "";
  if (env.ENVIRONMENT === "staging" && /^[0-9a-f]{40}$/.test(release) &&
      ["scheduled_entry", "native_start", "native_complete", "native_error"].includes(phase)) {
    console.info(`[staging_d1_runtime_probe] phase=${phase} release=${release}`);
  }
}

export interface StagingD1RuntimeProbeReceipt {
  readonly contract: "corelink-staging-d1-binding-runtime-v1";
  readonly probe_nonce: string;
  readonly outcome: "pass";
  readonly worker_release: string;
  readonly scheduled_time_ms: number;
  readonly parameterized_select: true;
  readonly failed_batch_observed: true;
  readonly rollback_absence_verified: true;
  readonly probe_table_dropped: true;
  readonly d1_binding_intercepted: true;
  readonly authorization_absent: true;
  readonly cf_api_token_absent: true;
}

export interface StagingD1RuntimeProbeAdmission {
  readonly contract: "corelink-staging-d1-probe-admission-v1";
  readonly probe_nonce: string;
  readonly worker_release: string;
  readonly scheduled_time_ms: number;
}

export type StagingD1RuntimeProbeAdmissionResult =
  | { readonly status: "admitted"; readonly admission: StagingD1RuntimeProbeAdmission }
  | { readonly status: "already_admitted" }
  | { readonly status: "complete"; readonly receipt: StagingD1RuntimeProbeReceipt };

interface StagingD1RuntimeProbeStub {
  cleanupV9StagingD1RuntimeProbe(scheduledTime: number, expectedRelease: string): Promise<V9CleanupReceipt>;
  cleanupV8StagingD1RuntimeProbe(scheduledTime: number, expectedRelease: string): Promise<V8CleanupReceipt>;
  admitStagingD1RuntimeProbe(scheduledTime: number): Promise<StagingD1RuntimeProbeAdmissionResult>;
  retireStagingD1RuntimeProbe(scheduledTime: number, deadlineMs?: number): Promise<OldProbeRetirement>;
  readStagingD1RuntimeProbeReceipt(scheduledTime: number): Promise<StagingD1RuntimeProbeReceipt | undefined>;
  runStagingD1RuntimeProbe(admission: StagingD1RuntimeProbeAdmission): Promise<StagingD1RuntimeProbeReceipt>;
}

const NATIVE_KEYS = ["contract", "probe_nonce", "outcome", "worker_release", "scheduled_time_ms",
  "parameterized_select", "failed_batch_observed", "rollback_absence_verified", "probe_table_dropped",
  "d1_binding_intercepted", "authorization_absent", "cf_api_token_absent"] as const;

function exactNativeReceipt(value: unknown, release: string, scheduledTime: number): value is StagingD1RuntimeProbeReceipt {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return Object.keys(r).length === NATIVE_KEYS.length && NATIVE_KEYS.every(key => Object.hasOwn(r, key)) &&
    /^[0-9a-f]{40}$/.test(release) && r["contract"] === "corelink-staging-d1-binding-runtime-v1" &&
    r["probe_nonce"] === window.nonce && r["outcome"] === "pass" && r["worker_release"] === release &&
    r["scheduled_time_ms"] === scheduledTime && Number.isSafeInteger(scheduledTime) &&
    scheduledTime % 120_000 === 0 && scheduledTime >= window.starts_ms && scheduledTime <= window.last_entry_ms &&
    NATIVE_KEYS.slice(5).every(key => r[key] === true);
}

/** The HTTP coordinator has durably claimed before this function is entered. */
export async function runStagingD1HttpSequence(env: Env, scheduledTime: number, life: StagingD1HttpLifecycle,
  local: {
    admit(): Promise<StagingD1RuntimeProbeAdmissionResult>;
    run(admission: StagingD1RuntimeProbeAdmission): Promise<StagingD1RuntimeProbeReceipt>;
  }): Promise<{ native: ReturnType<typeof withRetirementProof>; v8: V8CleanupReceipt; v9: V9CleanupReceipt }> {
  const release = env.SENTRY_RELEASE ?? "";
  const stub = (name: string) => env.CORELINK_SERVER.get(env.CORELINK_SERVER.idFromName(name)) as unknown as StagingD1RuntimeProbeStub;
  const v8 = await life.run(() => stub(V8_PROBE_NAME).cleanupV8StagingD1RuntimeProbe(scheduledTime, release));
  if (!isV8CleanupReceipt(v8, release, Date.now())) throw new Error("http proof v8 rejected");
  const v9 = await life.run(() => stub(V9_PROBE_NAME).cleanupV9StagingD1RuntimeProbe(scheduledTime, release));
  if (!isV9CleanupReceipt(v9, release, Date.now())) throw new Error("http proof v9 rejected");
  const admission = await life.run(() => local.admit());
  if (admission.status !== "admitted") throw new Error("http proof admission rejected");
  await life.run(() => assertV4FailedProbeCatalogAbsent(env.CONFIG_DB));
  const old = await life.run(() => stub(OLD_PROBE_NAME).retireStagingD1RuntimeProbe(scheduledTime, life.executeDeadline));
  if (old.old_probe_release !== OLD_PROBE_RELEASE || old.old_probe_retired !== true || old.old_probe_tables_absent !== true) {
    throw new Error("http proof retirement rejected");
  }
  const v5 = await life.run(() => stub(V5_PROBE_NAME).retireStagingD1RuntimeProbe(scheduledTime, life.executeDeadline));
  if (v5.v5_probe_release !== V5_PROBE_RELEASE || v5.v5_probe_retired !== true || v5.v5_probe_tables_absent !== true) {
    throw new Error("http proof retirement rejected");
  }
  life.check();
  const receipt = await local.run(admission.admission);
  life.check();
  if (!exactNativeReceipt(receipt, release, scheduledTime)) throw new Error("http proof native rejected");
  const native = withRetirementProof(receipt);
  if (!isStagingD1HttpNativeReceipt(native, release, Date.now())) throw new Error("http proof native rejected");
  return { native, v8, v9 };
}

type RetirementProof = {
  readonly old_probe_release: typeof OLD_PROBE_RELEASE; readonly old_probe_retired: true; readonly old_probe_tables_absent: true;
  readonly v5_probe_release: typeof V5_PROBE_RELEASE; readonly v5_probe_retired: true; readonly v5_probe_tables_absent: true;
  readonly v5_prior_execution: "unknown";
};
function withRetirementProof(receipt: StagingD1RuntimeProbeReceipt): StagingD1RuntimeProbeReceipt & RetirementProof & { readonly v4_probe_catalog_absent: true } {
  return { ...receipt, v4_probe_catalog_absent: true as const,
    old_probe_release: OLD_PROBE_RELEASE, old_probe_retired: true as const,
    old_probe_tables_absent: true as const, v5_probe_release: V5_PROBE_RELEASE,
    v5_probe_retired: true as const, v5_probe_tables_absent: true as const,
    v5_prior_execution: "unknown" as const };
}

function releaseStub(env: Env, release: string): StagingD1RuntimeProbeStub {
  const id = env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`);
  return env.CORELINK_SERVER.get(id) as unknown as StagingD1RuntimeProbeStub;
}

/** Read only the already persisted receipt after the one-shot entry lease closes. */
export async function readStagingD1BindingRuntimeProbeReceipt(
  env: Env,
  scheduledTime: number,
): Promise<ReturnType<typeof withRetirementProof> | undefined> {
  const release = env.SENTRY_RELEASE ?? "";
  if (env.ENVIRONMENT !== "staging" || !/^[0-9a-f]{40}$/.test(release) ||
      !Number.isSafeInteger(scheduledTime) || scheduledTime < window.starts_ms ||
      scheduledTime >= window.expires_ms) throw new Error("staging runtime receipt read target rejected");
  const receipt = await releaseStub(env, release).readStagingD1RuntimeProbeReceipt(scheduledTime);
  if (receipt === undefined) return undefined;
  if (receipt.probe_nonce !== window.nonce || receipt.scheduled_time_ms > scheduledTime ||
      receipt.worker_release !== release) throw new Error("staging runtime stored receipt rejected");
  return withRetirementProof(receipt);
}

/** Call a dedicated per-release DO through its non-HTTP RPC method. */
export async function runStagingD1BindingRuntimeProbe(
  env: Env,
  scheduledTime: number,
): Promise<StagingD1RuntimeProbeReceipt & RetirementProof & { readonly v4_probe_catalog_absent: true }> {
  const release = env.SENTRY_RELEASE ?? "";
  if (
    env.ENVIRONMENT !== "staging" ||
    !/^[0-9a-f]{40}$/.test(release) ||
    !Number.isSafeInteger(scheduledTime)
  ) {
    throw new Error("staging runtime probe target rejected");
  }
  if (scheduledTime > window.last_entry_ms || Date.now() > window.last_entry_ms) {
    throw new Error("staging runtime probe entry lease closed");
  }
  const v8 = env.CORELINK_SERVER.get(env.CORELINK_SERVER.idFromName(V8_PROBE_NAME)) as unknown as StagingD1RuntimeProbeStub;
  const cleanup = await withinV8CleanupDeadline(
    () => v8.cleanupV8StagingD1RuntimeProbe(scheduledTime, release), Date.now,
    Math.min(Date.now() + 60_000, cleanupWindow.expires_ms),
  );
  if (!isV8CleanupReceipt(cleanup, release, Date.now())) throw new Error("v8 cleanup receipt rejected");
  console.info(`[staging_d1_runtime_probe] v8_cleanup=${JSON.stringify(cleanup)}`);
  const stub = releaseStub(env, release);
  const stored = await stub.readStagingD1RuntimeProbeReceipt(scheduledTime);
  if (stored !== undefined) {
    if (stored.probe_nonce !== window.nonce || stored.scheduled_time_ms > scheduledTime ||
        stored.worker_release !== release) throw new Error("staging runtime stored receipt rejected");
    return withRetirementProof(stored);
  }
  const admission = await stub.admitStagingD1RuntimeProbe(scheduledTime);
  if (admission.status === "complete") return withRetirementProof(admission.receipt);
  if (admission.status !== "admitted") throw new Error("staging runtime probe already admitted");
  await assertV4FailedProbeCatalogAbsent(env.CONFIG_DB);
  const oldId = env.CORELINK_SERVER.idFromName(OLD_PROBE_NAME);
  const oldStub = env.CORELINK_SERVER.get(oldId) as unknown as StagingD1RuntimeProbeStub;
  const retired = await oldStub.retireStagingD1RuntimeProbe(scheduledTime);
  if (retired.old_probe_release !== OLD_PROBE_RELEASE || retired.old_probe_retired !== true ||
      retired.old_probe_tables_absent !== true) throw new Error("old probe retirement rejected");
  const v5Id = env.CORELINK_SERVER.idFromName(V5_PROBE_NAME);
  const v5Stub = env.CORELINK_SERVER.get(v5Id) as unknown as StagingD1RuntimeProbeStub;
  const v5Retired = await v5Stub.retireStagingD1RuntimeProbe(scheduledTime);
  if (v5Retired.v5_probe_release !== V5_PROBE_RELEASE || v5Retired.v5_probe_retired !== true ||
      v5Retired.v5_probe_tables_absent !== true) throw new Error("v5 probe retirement rejected");
  const receipt = await stub.runStagingD1RuntimeProbe(admission.admission);
  // Cloudflare runs this cron every two minutes. Once the dedicated DO has emitted
  // its release-bound receipt, later ticks return that same receipt so a tail
  // can recover it; the first scheduled timestamp remains the proof timestamp.
  if (
    receipt.probe_nonce !== window.nonce ||
    receipt.scheduled_time_ms < window.starts_ms ||
    receipt.scheduled_time_ms >= window.expires_ms ||
    receipt.contract !== "corelink-staging-d1-binding-runtime-v1" ||
    receipt.outcome !== "pass" ||
    receipt.worker_release !== release ||
    !Number.isSafeInteger(receipt.scheduled_time_ms) ||
    receipt.scheduled_time_ms > scheduledTime ||
    receipt.parameterized_select !== true ||
    receipt.failed_batch_observed !== true ||
    receipt.rollback_absence_verified !== true ||
    receipt.probe_table_dropped !== true ||
    receipt.d1_binding_intercepted !== true ||
    receipt.authorization_absent !== true ||
    receipt.cf_api_token_absent !== true
  ) {
    throw new Error("staging runtime probe receipt rejected");
  }
  return withRetirementProof(receipt);
}
