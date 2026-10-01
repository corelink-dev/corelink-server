import { describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";
import { STAGING_D1_PROBE_WINDOW } from "../src/staging_runtime_d1_probe.js";
import { assertV4FailedProbeCatalogAbsent, cleanOldProbeTables, cleanV5ProbeTables, OLD_PROBE_TABLES, OLD_TABLE_PREFIX, OLD_PROBE_RUN_BOUNDS, V4_FAILED_PROBE_TABLE_PREFIX, V5_PROBE_RELEASE, V5_PROBE_RUN_BOUNDS, V5_PROBE_TABLES, V5_TABLE_PREFIX } from "../src/staging_d1_probe_retirement.js";
import { PROBE_FOREIGN_KEY_CHECK_SQL } from "../src/staging_d1_probe_v8_cleanup.js";
import { StagingD1HttpLifecycle } from "../src/staging_d1_http_lifecycle.js";

const table = [...OLD_PROBE_TABLES.keys()][0]!;
const schema = { type: "table", name: table, tbl_name: table,
  sql: `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)` };
async function atProbeTime<T>(time: number, action: () => Promise<T>): Promise<T> {
  vi.useFakeTimers();
  vi.setSystemTime(time);
  try { return await action(); } finally { vi.useRealTimers(); }
}

function database(options: { objects?: object[]; foreign?: object[]; incoming?: number; tableCount?: number; rows?: object; dropFails?: boolean; retained?: boolean } = {}, ownedTable = table) {
  const ownedSchema = { type: "table", name: ownedTable, tbl_name: ownedTable,
    sql: `CREATE TABLE ${ownedTable} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)` };
  let objects = options.objects ?? [ownedSchema, { type: "index", name: `sqlite_autoindex_${ownedTable}_1`, tbl_name: ownedTable, sql: null }];
  const drops: string[] = [];
  const prepare = vi.fn((sql: string) => ({
    bind: vi.fn(function (this: unknown) { return this; }),
    all: async () => ({ success: true, results: sql.startsWith("SELECT type") ? objects : options.foreign ?? [] }),
    first: async () => sql === PROBE_FOREIGN_KEY_CHECK_SQL
      ? { table_count: options.tableCount ?? 1, outgoing: options.foreign?.length ? 1 : 0, incoming: options.incoming ?? 0 }
      : options.rows ?? { total: 0, invalid: 0 },
    run: async () => { drops.push(sql); if (!options.retained) objects = []; return { success: !options.dropFails }; },
  }));
  return { db: { prepare } as unknown as D1Database, drops, prepare };
}

describe("exact old staging probe SQL retirement", () => {
  it.each([cleanOldProbeTables, cleanV5ProbeTables])("stops every later SQL statement after a bounded catalog call times out", async clean => {
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, async () => {
      let finish!: (value: { success: true; results: object[] }) => void;
      const prepare = vi.fn(() => ({ bind() { return this; }, all: () => new Promise(resolve => { finish = resolve; }) }));
      const life = new StagingD1HttpLifecycle(Date.now, STAGING_D1_PROBE_WINDOW.expires_ms);
      const pending = clean({ prepare } as unknown as D1Database, Date.now, operation => life.run(operation));
      const failed = expect(pending).rejects.toThrow("execution stopped");
      await vi.advanceTimersByTimeAsync(600_000); await failed;
      finish({ success: true, results: [] });
      await Promise.resolve(); await Promise.resolve();
      expect(prepare).toHaveBeenCalledOnce();
    });
  });

  it.each([cleanOldProbeTables, cleanV5ProbeTables])("rechecks the cumulative budget before DROP", async clean => {
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, async () => {
      const owned = clean === cleanOldProbeTables ? table : [...V5_PROBE_TABLES.keys()][0]!;
      const h = database({}, owned);
      const life = new StagingD1HttpLifecycle(Date.now, STAGING_D1_PROBE_WINDOW.expires_ms);
      let calls = 0;
      await expect(clean(h.db, Date.now, operation => {
        if (++calls === 4) vi.setSystemTime(life.executeDeadline);
        return life.run(operation);
      })).rejects.toThrow("execution stopped");
      expect(h.drops).toEqual([]);
      expect(h.prepare.mock.calls).toHaveLength(3);
    });
  });
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
      first: async () => sql === PROBE_FOREIGN_KEY_CHECK_SQL
        ? { table_count: 1, outgoing: 0, incoming: 0 } : { total: 1, invalid: 0 },
      run: async () => { drops.push(sql); inventory.splice(0); return { success: true }; },
    }; } } as unknown as D1Database;
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => cleanV5ProbeTables(db));
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
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => expect(cleanV5ProbeTables(db)).rejects.toThrow("ownership rejected"));
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
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => cleanOldProbeTables(db));
    expect(drops).toEqual([`DROP TABLE "${table}"`]);
    expect(prepare.mock.calls.filter(([sql]) => sql.startsWith("SELECT type"))).toHaveLength(2);
  });
  it("empty inventory is idempotent without any DROP", async () => {
    const { db, drops } = database({ objects: [] });
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => cleanOldProbeTables(db));
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
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => expect(cleanOldProbeTables(db)).rejects.toThrow());
    expect(drops).toEqual([]);
  });
  it.each([{ foreign: [{}] }, { rows: { total: 1, invalid: 1 } }, { rows: { total: 2, invalid: 0 } }])("rejects FK or unowned rows without output/destruction", async options => {
    const { db, drops } = database(options);
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => expect(cleanOldProbeTables(db)).rejects.toThrow());
    expect(drops).toEqual([]);
  });
  it.each([
    ["v3", cleanOldProbeTables, table],
    ["v5", cleanV5ProbeTables, [...V5_PROBE_TABLES.keys()][0]!],
  ] as const)("%s refuses inbound references and unbounded catalog before DROP", async (_label, clean, ownedTable) => {
    for (const options of [{ incoming: 1 }, { tableCount: 129 }]) {
      const { db, drops, prepare } = database(options, ownedTable);
      await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => expect(clean(db)).rejects.toThrow("foreign key rejected"));
      expect(drops).toEqual([]);
      expect(prepare).toHaveBeenCalledWith(PROBE_FOREIGN_KEY_CHECK_SQL);
    }
  });
  it.each([
    ["v3", cleanOldProbeTables, table],
    ["v5", cleanV5ProbeTables, [...V5_PROBE_TABLES.keys()][0]!],
  ] as const)("hard v6 expiry prevents %s cleanup even after inventory validation", async (_label, clean, ownedTable) => {
    const { db, drops } = database({}, ownedTable);
    await atProbeTime(STAGING_D1_PROBE_WINDOW.expires_ms - 1, () => clean(db));
    expect(drops).toEqual([`DROP TABLE "${ownedTable}"`]);
  });
  it.each([
    ["v3", cleanOldProbeTables, table],
    ["v5", cleanV5ProbeTables, [...V5_PROBE_TABLES.keys()][0]!],
  ] as const)("exact v6 expiry prevents %s cleanup before any DROP", async (_label, clean, ownedTable) => {
    const { db, drops } = database({}, ownedTable);
    await atProbeTime(STAGING_D1_PROBE_WINDOW.expires_ms, () => expect(clean(db)).rejects.toThrow("window rejected"));
    expect(drops).toEqual([]);
  });
  it.each([{ dropFails: true }, { retained: true }])("cleanup uncertainty cannot pass", async options => {
    await atProbeTime(STAGING_D1_PROBE_WINDOW.starts_ms, () => expect(cleanOldProbeTables(database(options).db)).rejects.toThrow());
  });
});
