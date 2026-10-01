import type { D1Database } from "@cloudflare/workers-types";
import window from "./staging_d1_probe_cleanup_window.json";

export const V8_PROBE_RELEASE = "7d18bcfc450db97b1b987923050b92971da530a8";
export const V8_PROBE_NONCE = "issue-1700-recovery-20261001-v8";
export const V8_PROBE_NAME = `_staging_d1_binding_probe_v2:${V8_PROBE_NONCE}:${V8_PROBE_RELEASE}`;
export const V8_PROBE_RETIRED_KEY = "staging-d1-binding-probe-retired-v8";
export const V8_CLEANUP_RECEIPT_KEY = "staging-d1-binding-probe-cleanup-v8";

// SQLite PRAGMA table-valued functions support correlated joins:
// https://www.sqlite.org/pragma.html#pragma_functions
// Count one overflow table, inspect at most 128, and match identifier case as
// SQLite does. An external ON DELETE CASCADE reference must forbid DROP too.
export const PROBE_FOREIGN_KEY_CHECK_SQL = `WITH table_names AS (
  SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 129
), bounded_names AS (
  SELECT name FROM table_names LIMIT 128
)
SELECT (SELECT COUNT(*) FROM table_names) AS table_count,
  EXISTS(SELECT 1 FROM pragma_foreign_key_list(?1, 'main') LIMIT 1) AS outgoing,
  EXISTS(SELECT 1 FROM bounded_names AS names
    JOIN pragma_foreign_key_list(names.name, 'main') AS fk
    WHERE fk."table" = ?1 COLLATE NOCASE LIMIT 1) AS incoming`;

const TABLE_PREFIX = `corelink_staging_d1_probe_${V8_PROBE_RELEASE.slice(0, 16)}_`;
// Immutable host invocation bounds, not the wider v8 admission window.
const RUN_START_MS = 1790839493000; // 2026-10-01T07:24:53Z
const RUN_END_MS = 1790840995000; // 2026-10-01T07:49:55Z
const MAX_OPERATION_MS = 60_000;
const DEADLINE_ERROR = "v8 cleanup operation failed or deadline exceeded";
const RECEIPT_KEYS = [
  "contract", "old_release", "old_nonce", "worker_release", "prior_execution",
  "prior_admission_present", "container_stopped", "alarm_absent", "tables_absent",
  "completed_at_ms",
];

export interface V8CleanupReceipt {
  contract: "corelink-staging-v8-cleanup-v1";
  old_release: typeof V8_PROBE_RELEASE;
  old_nonce: typeof V8_PROBE_NONCE;
  worker_release: string;
  prior_execution: "unknown";
  prior_admission_present: boolean;
  container_stopped: true;
  alarm_absent: true;
  tables_absent: true;
  completed_at_ms: number;
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

export function probeForeignKeysClear(value: unknown): boolean {
  return hasExactKeys(value, ["table_count", "outgoing", "incoming"]) &&
    typeof value["table_count"] === "number" && Number.isSafeInteger(value["table_count"]) &&
    value["table_count"] >= 0 && value["table_count"] <= 128 &&
    value["outgoing"] === 0 && value["incoming"] === 0;
}

export function isV8CleanupReceipt(value: unknown, release: string, now: number): value is V8CleanupReceipt {
  if (!hasExactKeys(value, RECEIPT_KEYS)) return false;
  const completed = value["completed_at_ms"];
  return typeof release === "string" && /^[0-9a-f]{40}$/.test(release) && release !== V8_PROBE_RELEASE &&
    Number.isSafeInteger(now) && now >= window.starts_ms && now < window.expires_ms &&
    value["contract"] === "corelink-staging-v8-cleanup-v1" &&
    value["old_release"] === V8_PROBE_RELEASE && value["old_nonce"] === V8_PROBE_NONCE &&
    value["worker_release"] === release && value["prior_execution"] === "unknown" &&
    typeof value["prior_admission_present"] === "boolean" &&
    value["container_stopped"] === true && value["alarm_absent"] === true && value["tables_absent"] === true &&
    typeof completed === "number" && Number.isSafeInteger(completed) &&
    completed >= window.starts_ms && completed <= now;
}

function remainingMs(now: () => number, deadlineMs: number): number {
  const current = now();
  if (!Number.isSafeInteger(current) || !Number.isSafeInteger(deadlineMs) ||
      current < window.starts_ms || current >= window.expires_ms || deadlineMs <= current ||
      deadlineMs - current > MAX_OPERATION_MS) throw new Error(DEADLINE_ERROR);
  return Math.min(deadlineMs, window.expires_ms) - current;
}

/** A timeout rejects proof; it does not cancel an already submitted provider call. */
export async function withinV8CleanupDeadline<T>(
  operation: () => Promise<T>, now: () => number, deadlineMs: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const remaining = remainingMs(now, deadlineMs);
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(DEADLINE_ERROR)), remaining);
    });
    const result = await Promise.race([
      timeout,
      Promise.resolve().then(() => {
        remainingMs(now, deadlineMs);
        return operation();
      }),
    ]);
    remainingMs(now, deadlineMs);
    return result;
  } catch {
    // Do not expose provider messages, query payloads, or row values.
    throw new Error(DEADLINE_ERROR);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function admissionTime(admission: unknown): number | undefined {
  if (admission === undefined) return undefined;
  if (!hasExactKeys(admission, ["contract", "probe_nonce", "worker_release", "scheduled_time_ms"])) {
    throw new Error("v8 cleanup admission rejected");
  }
  const scheduled = admission["scheduled_time_ms"];
  if (admission["contract"] !== "corelink-staging-d1-probe-admission-v1" ||
      admission["probe_nonce"] !== V8_PROBE_NONCE || admission["worker_release"] !== V8_PROBE_RELEASE ||
      typeof scheduled !== "number" || !Number.isSafeInteger(scheduled) || scheduled % 120_000 !== 0 ||
      scheduled < RUN_START_MS || scheduled > RUN_END_MS) throw new Error("v8 cleanup admission rejected");
  return scheduled;
}

/** Caller must first fence the exact v8 object and prove Container/alarm stopped. */
export async function cleanV8ProbeTables(
  db: D1Database, admission: unknown, now: () => number, deadlineMs: number,
): Promise<void> {
  const scheduled = admissionTime(admission);
  const table = scheduled === undefined ? undefined : `${TABLE_PREFIX}${scheduled}`;
  const inventory = async (): Promise<unknown[]> => {
    const result = await withinV8CleanupDeadline(() => db.prepare(
      "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name GLOB ?1 OR tbl_name GLOB ?1 LIMIT 3",
    ).bind(`${TABLE_PREFIX}*`).all<unknown>(), now, deadlineMs);
    if (!result || result.success !== true || !Array.isArray(result.results) || result.results.length > 2) {
      throw new Error("v8 cleanup catalog rejected");
    }
    return result.results;
  };
  const objects = await inventory();
  const seen = new Set<string>();
  for (const object of objects) {
    if (table === undefined || !hasExactKeys(object, ["type", "name", "tbl_name", "sql"]) ||
        object["tbl_name"] !== table || typeof object["type"] !== "string" || seen.has(object["type"])) {
      throw new Error("v8 cleanup catalog ownership rejected");
    }
    const type = object["type"];
    if (type === "table" && object["name"] === table &&
        object["sql"] === `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)`) {
      seen.add(type);
    } else if (type === "index" && object["name"] === `sqlite_autoindex_${table}_1` && object["sql"] === null) {
      seen.add(type);
    } else {
      throw new Error("v8 cleanup catalog ownership rejected");
    }
  }
  if (objects.length !== 0) {
    if (table === undefined || !seen.has("table")) throw new Error("v8 cleanup catalog ownership rejected");
    const foreign = await withinV8CleanupDeadline(
      () => db.prepare(PROBE_FOREIGN_KEY_CHECK_SQL).bind(table).first(), now, deadlineMs,
    );
    if (!probeForeignKeysClear(foreign)) {
      throw new Error("v8 cleanup foreign key rejected");
    }
    const rows = await withinV8CleanupDeadline(() => db.prepare(
      `SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN probe_id = ?1 AND value IN (?2, ?3) THEN 0 ELSE 1 END), 0) AS invalid FROM (SELECT probe_id, value FROM "${table}" LIMIT 2)`,
    ).bind(`${V8_PROBE_RELEASE}:${scheduled}`, "probe", "intentional-failure")
      .first<{ total: number; invalid: number }>(), now, deadlineMs);
    if (!hasExactKeys(rows, ["total", "invalid"]) || typeof rows["total"] !== "number" ||
        !Number.isSafeInteger(rows["total"]) || rows["total"] < 0 || rows["total"] > 1 || rows["invalid"] !== 0) {
      throw new Error("v8 cleanup rows rejected");
    }
    const dropped = await withinV8CleanupDeadline(
      () => db.prepare(`DROP TABLE "${table}"`).run(), now, deadlineMs,
    );
    if (!dropped || dropped.success !== true) throw new Error("v8 cleanup drop failed");
  }
  if ((await inventory()).length !== 0) throw new Error("v8 cleanup readback failed");
}
