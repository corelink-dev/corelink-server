import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
import { OLD_PROBE_RELEASE, V5_PROBE_RELEASE } from "./staging_d1_probe_retirement.js";
import { isV8CleanupReceipt } from "./staging_d1_probe_v8_cleanup.js";
import { isV9CleanupReceipt } from "./staging_d1_probe_v9_cleanup.js";

/** HTTP delivery does not establish Cron or Tail execution. */
export const STAGING_D1_HTTP_CONTRACT = "corelink-staging-d1-http-proof-v1";
export const STAGING_D1_HTTP_EXECUTE_MS = 600_000;
export const STAGING_D1_HTTP_CLEANUP_MS = 600_000;

export type StagingD1HttpStatus = {
  contract: typeof STAGING_D1_HTTP_CONTRACT;
  carrier: "authenticated_http";
  worker_release: string;
  probe_nonce: string;
  status: "not_started" | "running" | "unknown" | "complete";
  rollback_safe: boolean;
  native_receipt: unknown | null;
  v8_cleanup: unknown | null;
  v9_cleanup: unknown | null;
};

const NATIVE_TRUE_KEYS = [
  "parameterized_select", "failed_batch_observed", "rollback_absence_verified",
  "probe_table_dropped", "d1_binding_intercepted", "authorization_absent",
  "cf_api_token_absent", "v4_probe_catalog_absent", "old_probe_retired",
  "old_probe_tables_absent", "v5_probe_retired", "v5_probe_tables_absent",
] as const;

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

/** The original twenty-key native receipt stays independent of its carrier. */
export function isStagingD1HttpNativeReceipt(value: unknown, release: string, now: number): boolean {
  if (!exactKeys(value, ["contract", "probe_nonce", "outcome", "worker_release", "scheduled_time_ms",
    "old_probe_release", "v5_probe_release", "v5_prior_execution", ...NATIVE_TRUE_KEYS])) return false;
  const at = value["scheduled_time_ms"];
  return value["contract"] === "corelink-staging-d1-binding-runtime-v1" &&
    value["probe_nonce"] === window.nonce && value["outcome"] === "pass" &&
    value["worker_release"] === release && typeof at === "number" && Number.isSafeInteger(at) &&
    at % 120_000 === 0 && at >= window.starts_ms && at <= window.last_entry_ms && at <= now &&
    value["old_probe_release"] === OLD_PROBE_RELEASE && value["v5_probe_release"] === V5_PROBE_RELEASE &&
    value["v5_prior_execution"] === "unknown" && NATIVE_TRUE_KEYS.every(key => value[key] === true);
}

/** Never serialize unvalidated RPC values or free-form provider errors. */
export function isStagingD1HttpStatus(value: unknown, release: string, now: number): value is StagingD1HttpStatus {
  if (!exactKeys(value, ["contract", "carrier", "worker_release", "probe_nonce", "status",
    "rollback_safe", "native_receipt", "v8_cleanup", "v9_cleanup"]) ||
    !/^[0-9a-f]{40}$/.test(release) || !Number.isSafeInteger(now) ||
    value["contract"] !== STAGING_D1_HTTP_CONTRACT || value["carrier"] !== "authenticated_http" ||
    value["worker_release"] !== release || value["probe_nonce"] !== window.nonce) return false;
  const v8 = value["v8_cleanup"];
  const v9 = value["v9_cleanup"];
  if ((v8 !== null && !isV8CleanupReceipt(v8, release, now)) ||
      (v9 !== null && !isV9CleanupReceipt(v9, release, now))) return false;
  if (value["status"] === "complete") return value["rollback_safe"] === true && v8 !== null && v9 !== null &&
    isStagingD1HttpNativeReceipt(value["native_receipt"], release, now);
  if (!["not_started", "running", "unknown"].includes(value["status"] as string) ||
      value["rollback_safe"] !== false || value["native_receipt"] !== null) return false;
  return value["status"] !== "not_started" || (v8 === null && v9 === null);
}
