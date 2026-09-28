import type { Env } from "./index_common.js";

export const STAGING_D1_RUNTIME_PROBE_DO_PREFIX = "_staging_d1_binding_probe_v1:";
export const STAGING_D1_RUNTIME_PROBE_PATH = "/_internal/staging/d1-binding-runtime-probe";

export interface StagingD1RuntimeProbeReceipt {
  readonly contract: "corelink-staging-d1-binding-runtime-v1";
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

interface StagingD1RuntimeProbeStub {
  runStagingD1RuntimeProbe(scheduledTime: number): Promise<StagingD1RuntimeProbeReceipt>;
}

/** Call a dedicated per-release DO through its non-HTTP RPC method. */
export async function runStagingD1BindingRuntimeProbe(
  env: Env,
  scheduledTime: number,
): Promise<StagingD1RuntimeProbeReceipt> {
  const release = env.SENTRY_RELEASE ?? "";
  if (
    env.ENVIRONMENT !== "staging" ||
    !/^[0-9a-f]{40}$/.test(release) ||
    !Number.isSafeInteger(scheduledTime)
  ) {
    throw new Error("staging runtime probe target rejected");
  }
  const id = env.CORELINK_SERVER.idFromName(`${STAGING_D1_RUNTIME_PROBE_DO_PREFIX}${release}`);
  const stub = env.CORELINK_SERVER.get(id) as unknown as StagingD1RuntimeProbeStub;
  const receipt = await stub.runStagingD1RuntimeProbe(scheduledTime);
  // Cloudflare runs this cron every minute. Once the dedicated DO has emitted
  // its release-bound receipt, later ticks return that same receipt so a tail
  // can recover it; the first scheduled timestamp remains the proof timestamp.
  if (
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
  return receipt;
}
