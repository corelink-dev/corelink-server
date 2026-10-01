import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";

export const STAGING_D1_HTTP_LIFETIME_KEY = "staging-d1-http-lifetime-v1";
export const STAGING_D1_HTTP_DEADLINE_CONTRACT = "corelink-staging-http-deadline-v1";
export interface StagingD1HttpDeadline {
  readonly contract: typeof STAGING_D1_HTTP_DEADLINE_CONTRACT;
  readonly worker_release: string;
  readonly probe_nonce: string;
  readonly operation_started_ms: number;
  readonly execute_deadline_ms: number;
  readonly kill_at_ms: number;
}
export interface StagingD1HttpLifetime extends StagingD1HttpDeadline {
  readonly state: "armed" | "stop_attempted" | "stopped" | "unproven";
  readonly stop_attempted_at_ms: number | null;
  readonly stopped_at_ms: number | null;
}
const CONTEXT_KEYS = ["contract", "worker_release", "probe_nonce", "operation_started_ms", "execute_deadline_ms", "kill_at_ms"];
const LIFETIME_KEYS = [...CONTEXT_KEYS, "state", "stop_attempted_at_ms", "stopped_at_ms"];
function exact(value: unknown, keys: string[]): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
export function isStagingD1HttpDeadline(value: unknown, release: string): value is StagingD1HttpDeadline {
  if (!exact(value, CONTEXT_KEYS)) return false;
  const start = value["operation_started_ms"];
  return value["contract"] === STAGING_D1_HTTP_DEADLINE_CONTRACT && /^[0-9a-f]{40}$/.test(release) &&
    value["worker_release"] === release && value["probe_nonce"] === window.nonce &&
    typeof start === "number" && Number.isSafeInteger(start) && start >= window.starts_ms && start <= window.last_entry_ms &&
    value["execute_deadline_ms"] === Math.min(start + 600_000, window.expires_ms) &&
    value["kill_at_ms"] === Math.min(start + 1_200_000, window.expires_ms);
}
export function httpDeadlineContext(value: StagingD1HttpLifetime): StagingD1HttpDeadline {
  return { contract: value.contract, worker_release: value.worker_release, probe_nonce: value.probe_nonce,
    operation_started_ms: value.operation_started_ms, execute_deadline_ms: value.execute_deadline_ms, kill_at_ms: value.kill_at_ms };
}
export function isStagingD1HttpLifetime(value: unknown, release: string): value is StagingD1HttpLifetime {
  if (!exact(value, LIFETIME_KEYS)) return false;
  const record = value as unknown as StagingD1HttpLifetime;
  if (!isStagingD1HttpDeadline(httpDeadlineContext(record), release)) return false;
  const attempt = record.stop_attempted_at_ms, stopped = record.stopped_at_ms;
  const time = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= record.kill_at_ms;
  if (record.state === "armed") return attempt === null && stopped === null;
  if (record.state === "stop_attempted" || record.state === "unproven") return time(attempt) && stopped === null;
  return record.state === "stopped" && time(attempt) && time(stopped) && stopped >= attempt;
}
export function createHttpLifetime(release: string, start: number): StagingD1HttpLifetime {
  const value: StagingD1HttpLifetime = { contract: STAGING_D1_HTTP_DEADLINE_CONTRACT, worker_release: release,
    probe_nonce: window.nonce, operation_started_ms: start, execute_deadline_ms: Math.min(start + 600_000, window.expires_ms),
    kill_at_ms: Math.min(start + 1_200_000, window.expires_ms), state: "armed", stop_attempted_at_ms: null, stopped_at_ms: null };
  if (!isStagingD1HttpLifetime(value, release)) throw new Error("HTTP lifetime rejected");
  return value;
}
export function checkHttpExecutionDeadline(context: StagingD1HttpDeadline, now = Date.now()): void {
  if (!Number.isSafeInteger(now) || now < context.operation_started_ms || now >= context.execute_deadline_ms) {
    throw new Error("HTTP execution deadline");
  }
}
