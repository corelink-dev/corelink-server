import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
import type { D1Database } from "@cloudflare/workers-types";

export const OLD_PROBE_RELEASE = "0f785fb9b096afe01247f1057d46377b9f604f13";
export const OLD_PROBE_NAME = `_staging_d1_binding_probe_v2:issue-1700-recovery-20260929:${OLD_PROBE_RELEASE}`;
export const OLD_PROBE_RETIRED_KEY = "staging-d1-binding-probe-retired-v1";
export const V5_PROBE_RELEASE = "cc32b3d819181bf9175e795868f66212aa5456c1";
export const V5_PROBE_NONCE = "issue-1700-recovery-20260930-v5";
export const V5_PROBE_NAME = `_staging_d1_binding_probe_v2:${V5_PROBE_NONCE}:${V5_PROBE_RELEASE}`;
export const V5_PROBE_RETIRED_KEY = "staging-d1-binding-probe-retired-v5";
export const V5_PROBE_RUN_BOUNDS = { start: 1790791200000, end: 1790812740000 };
// Immutable bounds of the only host invocation of this candidate. The first
// possible cron is ceil(start / minute), the last is floor(end / minute).
export const OLD_PROBE_RUN_BOUNDS = { start: 1790727123000, end: 1790728458000 };
export const OLD_TABLE_PREFIX = `corelink_staging_d1_probe_${OLD_PROBE_RELEASE.slice(0, 16)}_`;
export const OLD_PROBE_TABLES = new Map<string, number>();
for (let at = Math.ceil(OLD_PROBE_RUN_BOUNDS.start / 60000) * 60000;
     at <= Math.floor(OLD_PROBE_RUN_BOUNDS.end / 60000) * 60000; at += 60000) {
  OLD_PROBE_TABLES.set(`${OLD_TABLE_PREFIX}${at}`, at);
}
export const V5_TABLE_PREFIX = `corelink_staging_d1_probe_${V5_PROBE_RELEASE.slice(0, 16)}_`;
export const V5_PROBE_TABLES = new Map<string, number>();
for (let at = Math.ceil(V5_PROBE_RUN_BOUNDS.start / 60000) * 60000;
     at <= Math.floor(V5_PROBE_RUN_BOUNDS.end / 60000) * 60000; at += 60000) {
  V5_PROBE_TABLES.set(`${V5_TABLE_PREFIX}${at}`, at);
}

// The failed v4 schedule readback showed empty schedules/tails, not a completed
// runtime receipt. Prove its exact release-derived D1 namespace is absent; do
// not drop it or infer anything about DO state from this catalog check.
export const V4_FAILED_PROBE_RELEASE = "9d8fdbfa04dd16d4099056de6e16ea8343ebba46";
export const V4_FAILED_PROBE_TABLE_PREFIX = `corelink_staging_d1_probe_${V4_FAILED_PROBE_RELEASE.slice(0, 16)}_`;
export async function assertV4FailedProbeCatalogAbsent(db: D1Database): Promise<void> {
  const result = await db.prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name GLOB ?1 OR tbl_name GLOB ?1 LIMIT 1")
    .bind(`${V4_FAILED_PROBE_TABLE_PREFIX}*`).all();
  if (!result.success || !Array.isArray(result.results) || result.results.length !== 0) {
    throw new Error("v4 failed probe catalog absence unproven");
  }
}

export interface OldProbeRetirement {
  old_probe_release?: typeof OLD_PROBE_RELEASE;
  old_probe_retired?: true;
  old_probe_tables_absent?: true;
  v5_probe_release?: typeof V5_PROBE_RELEASE;
  v5_probe_retired?: true;
  v5_probe_tables_absent?: true;
}

/** Only called after the exact old DO's Container is stopped and entry is fenced. */
export async function cleanOldProbeTables(db: D1Database, now: () => number = Date.now): Promise<void> {
  return cleanProbeTables(db, OLD_PROBE_RELEASE, OLD_TABLE_PREFIX, OLD_PROBE_TABLES, now);
}

/** Exact v5 namespace cleanup; unknown prior execution is not an absence claim. */
export async function cleanV5ProbeTables(db: D1Database, now: () => number = Date.now): Promise<void> {
  return cleanProbeTables(db, V5_PROBE_RELEASE, V5_TABLE_PREFIX, V5_PROBE_TABLES, now);
}

async function cleanProbeTables(db: D1Database, release: string, prefix: string,
  allowedTables: ReadonlyMap<string, number>, now: () => number): Promise<void> {
  const inventory = async () => {
    const result = await db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name GLOB ?1 OR tbl_name GLOB ?1 LIMIT 129")
      .bind(`${prefix}*`).all<{ type: string; name: string; tbl_name: string; sql: string | null }>();
    if (!result.success || !Array.isArray(result.results) || result.results.length > 128) throw new Error("old probe catalog rejected");
    return result.results;
  };
  const objects = await inventory();
  const tables = objects.filter((object) => object.type === "table");
  for (const object of objects) {
    const table = object.type === "table" ? object.name : object.tbl_name;
    if (!allowedTables.has(table) || object.tbl_name !== table ||
        (object.type !== "table" && !(object.type === "index" && object.name === `sqlite_autoindex_${table}_1` && object.sql === null))) {
      throw new Error("old probe catalog ownership rejected");
    }
    if (object.type === "table" && object.sql !== `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)`) {
      throw new Error("old probe schema rejected");
    }
  }
  // Validate every object and row before the first DROP. Never return row data.
  for (const { name } of tables) {
    const foreign = await db.prepare(`PRAGMA foreign_key_list("${name}")`).all();
    if (!foreign.success || foreign.results.length !== 0) throw new Error("old probe foreign key rejected");
    const rows = await db.prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN probe_id = ?1 AND value IN (?2, ?3) THEN 0 ELSE 1 END), 0) AS invalid FROM "${name}"`)
      .bind(`${release}:${allowedTables.get(name)}`, "probe", "intentional-failure").first<{ total: number; invalid: number }>();
    if (!rows || !Number.isInteger(rows.total) || rows.total < 0 || rows.total > 1 || rows.invalid !== 0) {
      throw new Error("old probe rows rejected");
    }
  }
  for (const { name } of tables) {
    if (now() < window.starts_ms || now() >= window.expires_ms) throw new Error("old probe cleanup window rejected");
    const result = await db.prepare(`DROP TABLE "${name}"`).run();
    if (!result.success) throw new Error("old probe cleanup failed");
  }
  if ((await inventory()).length !== 0) throw new Error("old probe cleanup readback failed");
}
