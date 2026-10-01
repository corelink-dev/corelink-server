import { describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";
import { assertV4FailedProbeCatalogAbsent, cleanOldProbeTables, cleanV5ProbeTables, OLD_PROBE_TABLES, OLD_TABLE_PREFIX, OLD_PROBE_RUN_BOUNDS, V4_FAILED_PROBE_TABLE_PREFIX, V5_PROBE_RELEASE, V5_PROBE_RUN_BOUNDS, V5_PROBE_TABLES, V5_TABLE_PREFIX } from "../src/staging_d1_probe_retirement.js";

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
  it("bounds v5 retirement to the historical release and its minute schedule", async () => {
    const times = [...V5_PROBE_TABLES.values()];
    expect(V5_PROBE_RELEASE).toBe("cc32b3d819181bf9175e795868f66212aa5456c1");
    expect(V5_TABLE_PREFIX).toBe("corelink_staging_d1_probe_cc32b3d819181bf9_");
    expect(times[0]).toBe(Math.ceil(V5_PROBE_RUN_BOUNDS.start / 60000) * 60000);
    expect(times.at(-1)).toBe(Math.floor(V5_PROBE_RUN_BOUNDS.end / 60000) * 60000);
    expect(times.every(t => t % 60000 === 0 && t >= V5_PROBE_RUN_BOUNDS.start && t <= V5_PROBE_RUN_BOUNDS.end)).toBe(true);
    const name = [...V5_PROBE_TABLES.keys()][0]!;
    const object = { type: "table", name, tbl_name: name,
      sql: `CREATE TABLE ${name} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)` };
    const inventory = [object, { type: "index", name: `sqlite_autoindex_${name}_1`, tbl_name: name, sql: null }];
    const drops: string[] = [];
    const db = { prepare(sql: string) { return {
      bind() { return this; },
      all: async () => ({ success: true, results: sql.startsWith("SELECT type") ? inventory : [] }),
      first: async () => ({ total: 1, invalid: 0 }),
      run: async () => { drops.push(sql); inventory.splice(0); return { success: true }; },
    }; } } as unknown as D1Database;
    await cleanV5ProbeTables(db, () => 1790809200000);
    expect(drops).toEqual([`DROP TABLE "${name}"`]);
  });
  it("fails closed on an unexpected v5 namespace object without dropping anything", async () => {
    const rogue = { type: "table", name: `${V5_TABLE_PREFIX}1790800000000`, tbl_name: `${V5_TABLE_PREFIX}1790800000000`, sql: "rogue" };
    const drops: string[] = [];
    const db = { prepare(sql: string) { return {
      bind() { return this; },
      all: async () => ({ success: true, results: sql.startsWith("SELECT type") ? [rogue] : [] }),
      first: async () => ({ total: 0, invalid: 0 }),
      run: async () => { drops.push(sql); return { success: true }; },
    }; } } as unknown as D1Database;
    await expect(cleanV5ProbeTables(db, () => 1790809200000)).rejects.toThrow("ownership rejected");
    expect(drops).toEqual([]);
  });
  it("proves only the exact failed-v4 D1 namespace absent and never deletes it", async () => {
    const { db, drops, prepare } = database({ objects: [] });
    await assertV4FailedProbeCatalogAbsent(db);
    expect(prepare.mock.calls[0]?.[0]).toContain("LIMIT 1");
    expect(V4_FAILED_PROBE_TABLE_PREFIX).toBe("corelink_staging_d1_probe_9d8fdbfa04dd16d4_");
    expect(drops).toEqual([]);
    const present = database({ objects: [schema] });
    await expect(assertV4FailedProbeCatalogAbsent(present.db)).rejects.toThrow("absence unproven");
    expect(present.drops).toEqual([]);
  });
  it("derives each scheduled minute from immutable host bounds", () => {
    const times = [...OLD_PROBE_TABLES.values()];
    expect(times[0]).toBe(Math.ceil(OLD_PROBE_RUN_BOUNDS.start / 60000) * 60000);
    expect(times.at(-1)).toBe(Math.floor(OLD_PROBE_RUN_BOUNDS.end / 60000) * 60000);
    expect(times.every(t => t % 60000 === 0 && t >= OLD_PROBE_RUN_BOUNDS.start && t <= OLD_PROBE_RUN_BOUNDS.end)).toBe(true);
  });
  it("drops only validated owned tables and proves absence", async () => {
    const { db, drops, prepare } = database();
    await cleanOldProbeTables(db, () => 1790791260000);
    expect(drops).toEqual([`DROP TABLE "${table}"`]);
    expect(prepare.mock.calls.filter(([sql]) => sql.startsWith("SELECT type"))).toHaveLength(2);
  });
  it("empty inventory is idempotent without any DROP", async () => {
    const { db, drops } = database({ objects: [] });
    await cleanOldProbeTables(db, () => 1790791260000);
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
    await expect(cleanOldProbeTables(db, () => 1790791260000)).rejects.toThrow();
    expect(drops).toEqual([]);
  });
  it.each([{ foreign: [{}] }, { rows: { total: 1, invalid: 1 } }, { rows: { total: 2, invalid: 0 } }])("rejects FK or unowned rows without output/destruction", async options => {
    const { db, drops } = database(options);
    await expect(cleanOldProbeTables(db, () => 1790791260000)).rejects.toThrow();
    expect(drops).toEqual([]);
  });
  it("hard expiry prevents DROP even after inventory validation", async () => {
    const { db, drops } = database();
    await expect(cleanOldProbeTables(db, () => 1790812740000)).rejects.toThrow("window rejected");
    expect(drops).toEqual([]);
  });
  it.each([{ dropFails: true }, { retained: true }])("cleanup uncertainty cannot pass", async options => {
    await expect(cleanOldProbeTables(database(options).db, () => 1790791260000)).rejects.toThrow();
  });
});
