import { describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";
import { cleanOldProbeTables, OLD_PROBE_TABLES, OLD_TABLE_PREFIX, OLD_PROBE_RUN_BOUNDS } from "../src/staging_d1_probe_retirement.js";

const table = [...OLD_PROBE_TABLES.keys()][0]!;
const schema = { type: "table", name: table, tbl_name: table,
  sql: `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)` };
function database(options: { objects?: object[]; foreign?: object[]; rows?: object; dropFails?: boolean; retained?: boolean } = {}) {
  let objects = options.objects ?? [schema, { type: "index", name: `sqlite_autoindex_${table}_1`, tbl_name: table, sql: null }];
  const drops: string[] = [];
  const prepare = vi.fn((sql: string) => ({
    bind: vi.fn(function (this: unknown) { return this; }),
    all: async () => ({ success: true, results: sql.startsWith("SELECT type") ? objects : options.foreign ?? [] }),
    first: async () => options.rows ?? { total: 0, invalid: 0 },
    run: async () => { drops.push(sql); if (!options.retained) objects = []; return { success: !options.dropFails }; },
  }));
  return { db: { prepare } as unknown as D1Database, drops, prepare };
}

describe("exact old staging probe SQL retirement", () => {
  it("derives each scheduled minute from immutable host bounds", () => {
    const times = [...OLD_PROBE_TABLES.values()];
    expect(times[0]).toBe(Math.ceil(OLD_PROBE_RUN_BOUNDS.start / 60000) * 60000);
    expect(times.at(-1)).toBe(Math.floor(OLD_PROBE_RUN_BOUNDS.end / 60000) * 60000);
    expect(times.every(t => t % 60000 === 0 && t >= OLD_PROBE_RUN_BOUNDS.start && t <= OLD_PROBE_RUN_BOUNDS.end)).toBe(true);
  });
  it("drops only validated owned tables and proves absence", async () => {
    const { db, drops, prepare } = database();
    await cleanOldProbeTables(db, () => 1790776860000);
    expect(drops).toEqual([`DROP TABLE "${table}"`]);
    expect(prepare.mock.calls.filter(([sql]) => sql.startsWith("SELECT type"))).toHaveLength(2);
  });
  it("empty inventory is idempotent without any DROP", async () => {
    const { db, drops } = database({ objects: [] });
    await cleanOldProbeTables(db, () => 1790776860000);
    expect(drops).toEqual([]);
  });
  it.each([
    [schema, { ...schema, name: `${OLD_TABLE_PREFIX}1790727123000`, tbl_name: `${OLD_TABLE_PREFIX}1790727123000` }],
    [schema, { ...schema, name: `${OLD_TABLE_PREFIX}1790726400000`, tbl_name: `${OLD_TABLE_PREFIX}1790726400000` }],
    [schema, { type: "trigger", name: "other", tbl_name: table, sql: "payload" }],
    [{ ...schema, sql: schema.sql + " STRICT" }],
    [schema, { type: "index", name: "user_index", tbl_name: table, sql: "payload" }],
    Array.from({ length: 129 }, () => schema),
  ])("rejects whole inventory before any DROP", async (...objects) => {
    const { db, drops } = database({ objects });
    await expect(cleanOldProbeTables(db, () => 1790776860000)).rejects.toThrow();
    expect(drops).toEqual([]);
  });
  it.each([{ foreign: [{}] }, { rows: { total: 1, invalid: 1 } }, { rows: { total: 2, invalid: 0 } }])("rejects FK or unowned rows without output/destruction", async options => {
    const { db, drops } = database(options);
    await expect(cleanOldProbeTables(db, () => 1790776860000)).rejects.toThrow();
    expect(drops).toEqual([]);
  });
  it("hard expiry prevents DROP even after inventory validation", async () => {
    const { db, drops } = database();
    await expect(cleanOldProbeTables(db, () => 1790798400000)).rejects.toThrow("window rejected");
    expect(drops).toEqual([]);
  });
  it.each([{ dropFails: true }, { retained: true }])("cleanup uncertainty cannot pass", async options => {
    await expect(cleanOldProbeTables(database(options).db, () => 1790776860000)).rejects.toThrow();
  });
});
