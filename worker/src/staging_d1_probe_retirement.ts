import window from "../../crates/corelink-container/src/routes/staging_d1_probe_window.json";
import type { D1Database } from "@cloudflare/workers-types";

export const OLD_PROBE_RELEASE = "0f785fb9b096afe01247f1057d46377b9f604f13";
export const OLD_PROBE_NAME = `_staging_d1_binding_probe_v2:issue-1700-recovery-20260929:${OLD_PROBE_RELEASE}`;
export const OLD_PROBE_RETIRED_KEY = "staging-d1-binding-probe-retired-v1";
// Immutable bounds of the only host invocation of this candidate. The first
// possible cron is ceil(start / minute), the last is floor(end / minute).
export const OLD_PROBE_RUN_BOUNDS = { start: 1790727123000, end: 1790728458000 };
export const OLD_TABLE_PREFIX = `corelink_staging_d1_probe_${OLD_PROBE_RELEASE.slice(0, 16)}_`;
export const OLD_PROBE_TABLES = new Map<string, number>();
for (let at = Math.ceil(OLD_PROBE_RUN_BOUNDS.start / 60000) * 60000;
     at <= Math.floor(OLD_PROBE_RUN_BOUNDS.end / 60000) * 60000; at += 60000) {
  OLD_PROBE_TABLES.set(`${OLD_TABLE_PREFIX}${at}`, at);
}

export interface OldProbeRetirement {
  old_probe_release: typeof OLD_PROBE_RELEASE;
  old_probe_retired: true;
  old_probe_tables_absent: true;
}

/** Only called after the exact old DO's Container is stopped and entry is fenced. */
export async function cleanOldProbeTables(db: D1Database, now: () => number = Date.now): Promise<void> {
  const inventory = async () => {
    const result = await db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name GLOB ?1 OR tbl_name GLOB ?1 LIMIT 129")
      .bind(`${OLD_TABLE_PREFIX}*`).all<{ type: string; name: string; tbl_name: string; sql: string | null }>();
    if (!result.success || !Array.isArray(result.results) || result.results.length > 128) throw new Error("old probe catalog rejected");
    return result.results;
  };
  const objects = await inventory();
  const tables = objects.filter((object) => object.type === "table");
  for (const object of objects) {
    const table = object.type === "table" ? object.name : object.tbl_name;
    if (!OLD_PROBE_TABLES.has(table) || object.tbl_name !== table ||
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
      .bind(`${OLD_PROBE_RELEASE}:${OLD_PROBE_TABLES.get(name)}`, "probe", "intentional-failure").first<{ total: number; invalid: number }>();
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
