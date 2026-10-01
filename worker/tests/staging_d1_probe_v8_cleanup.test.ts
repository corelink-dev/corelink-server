import { describe, expect, it, vi } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import window from "../src/staging_d1_probe_cleanup_window.json";
import {
  cleanV8ProbeTables, isV8CleanupReceipt, withinV8CleanupDeadline,
  V8_CLEANUP_RECEIPT_KEY, V8_PROBE_NAME, V8_PROBE_NONCE, V8_PROBE_RELEASE,
  V8_PROBE_RETIRED_KEY, PROBE_FOREIGN_KEY_CHECK_SQL, probeForeignKeysClear, type V8CleanupReceipt,
} from "../src/staging_d1_probe_v8_cleanup.js";

const RELEASE = "a".repeat(40);
const NOW = window.starts_ms + 1000;
const DEADLINE = NOW + 60_000;
const FIRST_TICK = 1790839560000; // 07:26 UTC
const LAST_TICK = 1790840880000; // 07:48 UTC
const PREFIX = "corelink_staging_d1_probe_7d18bcfc450db97b_";
const DEADLINE_ERROR = "v8 cleanup operation failed or deadline exceeded";

function admission(time = FIRST_TICK) {
  return { contract: "corelink-staging-d1-probe-admission-v1", probe_nonce: V8_PROBE_NONCE,
    worker_release: V8_PROBE_RELEASE, scheduled_time_ms: time };
}

function receipt(): V8CleanupReceipt {
  return { contract: "corelink-staging-v8-cleanup-v1", old_release: V8_PROBE_RELEASE,
    old_nonce: V8_PROBE_NONCE, worker_release: RELEASE, prior_execution: "unknown",
    prior_admission_present: true, container_stopped: true, alarm_absent: true,
    tables_absent: true, completed_at_ms: NOW };
}

function catalog(time = FIRST_TICK) {
  const table = `${PREFIX}${time}`;
  return [
    { type: "table", name: table, tbl_name: table,
      sql: `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL)` },
    { type: "index", name: `sqlite_autoindex_${table}_1`, tbl_name: table, sql: null },
  ];
}

function database(options: {
  objects?: unknown[]; foreign?: unknown; rows?: unknown; dropFails?: boolean;
  retained?: boolean; inventoryFails?: boolean; foreignFails?: boolean;
  throwProvider?: boolean; onRows?: () => void;
} = {}) {
  let objects = options.objects ?? catalog();
  const drops: string[] = [];
  const bound: unknown[][] = [];
  const prepare = vi.fn((sql: string) => ({
    bind(...args: unknown[]) { bound.push(args); return this; },
    all: async () => {
      if (options.throwProvider) throw new Error("provider-secret-sentinel");
      return { success: !options.inventoryFails, results: objects };
    },
    first: async () => {
      if (sql === PROBE_FOREIGN_KEY_CHECK_SQL) {
        return options.foreignFails ? null : options.foreign ?? { table_count: 1, outgoing: 0, incoming: 0 };
      }
      options.onRows?.();
      return options.rows ?? { total: 0, invalid: 0 };
    },
    run: async () => {
      drops.push(sql);
      if (!options.retained && !options.dropFails) objects = [];
      return { success: !options.dropFails };
    },
  }));
  return { db: { prepare } as unknown as D1Database, prepare, drops, bound };
}

// Execute the exported production SQL against real SQLite; return only selected
// catalog metadata and aggregates, never the external fixture's row payload.
function sqliteQuery(path: string, sql: string, args: unknown[] = [], script = false): Record<string, unknown>[] {
  const python = `import json, sqlite3, sys
request = json.load(sys.stdin)
with sqlite3.connect(request["path"]) as connection:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    if request["script"]:
        connection.executescript(request["sql"])
        result = []
    else:
        cursor = connection.execute(request["sql"], request["args"])
        result = [dict(row) for row in cursor.fetchall()] if cursor.description else []
    print(json.dumps(result))
`;
  return JSON.parse(execFileSync("python3", ["-c", python], {
    input: JSON.stringify({ path, sql, args, script }), encoding: "utf8", timeout: 5000, maxBuffer: 65536,
  }));
}

async function withSqlite(action: (path: string) => Promise<void>): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), "v8-cleanup-sqlite-"));
  try { await action(join(directory, "fixture.sqlite")); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}

describe("shared bounded foreign-key oracle", () => {
  it.each([0, 128])("accepts exact zero-FK aggregates within the table bound", table_count => {
    expect(probeForeignKeysClear({ table_count, outgoing: 0, incoming: 0 })).toBe(true);
  });

  it.each([
    null, {}, [], { table_count: 129, outgoing: 0, incoming: 0 },
    { table_count: -1, outgoing: 0, incoming: 0 }, { table_count: 1.5, outgoing: 0, incoming: 0 },
    { table_count: 1, outgoing: 1, incoming: 0 }, { table_count: 1, outgoing: 0, incoming: 1 },
    { table_count: 1, outgoing: "0", incoming: 0 }, { table_count: 1, outgoing: 0, incoming: false },
    { table_count: 1, outgoing: 0, incoming: 0, payload: "sentinel" },
  ].map(value => ({ value })))("rejects ambiguous, overflowing or referenced catalogs", ({ value }) => {
    expect(probeForeignKeysClear(value)).toBe(false);
  });

  it.each([false, true])("preserves an unrelated CASCADE child's row before rejecting DROP (uppercase=%s)", async uppercase => {
    await withSqlite(async path => {
      const table = `${PREFIX}${FIRST_TICK}`;
      const reference = uppercase ? table.toUpperCase() : table;
      sqliteQuery(path, `CREATE TABLE ${table} (probe_id TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE unrelated_child (probe_id TEXT REFERENCES "${reference}"(probe_id) ON DELETE CASCADE, payload TEXT);`, [], true);
      sqliteQuery(path, `INSERT INTO "${table}" VALUES (?1, ?2)`, [`${V8_PROBE_RELEASE}:${FIRST_TICK}`, "probe"]);
      sqliteQuery(path, "INSERT INTO unrelated_child VALUES (?1, ?2)", [`${V8_PROBE_RELEASE}:${FIRST_TICK}`, "external-fixture-row"]);
      expect(sqliteQuery(path, PROBE_FOREIGN_KEY_CHECK_SQL, [table])).toEqual([
        { table_count: 2, outgoing: 0, incoming: 1 },
      ]);
      const prepare = vi.fn((sql: string) => {
        let bound: unknown[] = [];
        return {
          bind(...args: unknown[]) { bound = args; return this; },
          all: async () => ({ success: true, results: sqliteQuery(path, sql, bound) }),
          first: async () => sqliteQuery(path, sql, bound)[0] ?? null,
          run: async () => { sqliteQuery(path, sql, bound); return { success: true }; },
        };
      });
      await expect(cleanV8ProbeTables({ prepare } as unknown as D1Database, admission(), () => NOW, DEADLINE))
        .rejects.toThrow("v8 cleanup foreign key rejected");
      expect(prepare).toHaveBeenCalledTimes(2);
      expect(sqliteQuery(path, "SELECT COUNT(*) AS preserved FROM unrelated_child WHERE payload = ?1", ["external-fixture-row"]))
        .toEqual([{ preserved: 1 }]);
      // Negative control confirms this fixture really would cascade on DROP.
      sqliteQuery(path, `DROP TABLE "${table}"`);
      expect(sqliteQuery(path, "SELECT COUNT(*) AS remaining FROM unrelated_child")).toEqual([{ remaining: 0 }]);
    });
  });

  it("finds outgoing references and rejects table-catalog overflow in real SQLite", async () => {
    await withSqlite(async path => {
      sqliteQuery(path, "CREATE TABLE external_parent(id INTEGER PRIMARY KEY); CREATE TABLE outgoing_probe(id INTEGER REFERENCES external_parent(id));", [], true);
      expect(sqliteQuery(path, PROBE_FOREIGN_KEY_CHECK_SQL, ["outgoing_probe"])).toEqual([
        { table_count: 2, outgoing: 1, incoming: 0 },
      ]);
      sqliteQuery(path, Array.from({ length: 126 }, (_value, index) => `CREATE TABLE unrelated_${index}(id INTEGER);`).join("\n"), [], true);
      const bounded = sqliteQuery(path, PROBE_FOREIGN_KEY_CHECK_SQL, ["unrelated_0"])[0];
      expect(bounded).toEqual({ table_count: 128, outgoing: 0, incoming: 0 });
      expect(probeForeignKeysClear(bounded)).toBe(true);
      sqliteQuery(path, "CREATE TABLE overflow_table(id INTEGER)");
      const overflow = sqliteQuery(path, PROBE_FOREIGN_KEY_CHECK_SQL, ["unrelated_0"])[0];
      expect(overflow).toEqual({ table_count: 129, outgoing: 0, incoming: 0 });
      expect(probeForeignKeysClear(overflow)).toBe(false);
    });
  });
});

describe("fixed v8 cleanup receipt", () => {
  it("pins the exact namespace and emits no historical payload fields", () => {
    expect(V8_PROBE_NAME).toBe("_staging_d1_binding_probe_v2:issue-1700-recovery-20261001-v8:7d18bcfc450db97b1b987923050b92971da530a8");
    expect(V8_PROBE_RETIRED_KEY).toBe("staging-d1-binding-probe-retired-v8");
    expect(V8_CLEANUP_RECEIPT_KEY).toBe("staging-d1-binding-probe-cleanup-v8");
    expect(isV8CleanupReceipt(receipt(), RELEASE, NOW)).toBe(true);
    expect(isV8CleanupReceipt({ ...receipt(), prior_admission_present: false }, RELEASE, NOW)).toBe(true);
    expect(Object.keys(receipt()).sort()).toEqual([
      "alarm_absent", "completed_at_ms", "container_stopped", "contract", "old_nonce",
      "old_release", "prior_admission_present", "prior_execution", "tables_absent", "worker_release",
    ]);
    expect(isV8CleanupReceipt({ ...receipt(), payload: "secret-sentinel" }, RELEASE, NOW)).toBe(false);
    expect(isV8CleanupReceipt({ ...receipt(), [Symbol("secret-sentinel")]: true }, RELEASE, NOW)).toBe(false);
    for (const key of Object.keys(receipt())) {
      const incomplete = { ...receipt() } as Record<string, unknown>;
      delete incomplete[key];
      expect(isV8CleanupReceipt(incomplete, RELEASE, NOW)).toBe(false);
    }
  });

  it.each([
    { old_release: RELEASE }, { old_nonce: "wrong" }, { worker_release: "b".repeat(40) },
    { contract: "other" }, { prior_execution: "never_ran" }, { prior_admission_present: 1 },
    { container_stopped: false }, { alarm_absent: false }, { tables_absent: false },
    { completed_at_ms: window.starts_ms - 1 }, { completed_at_ms: NOW + 1 },
    { completed_at_ms: NOW + 0.5 }, { completed_at_ms: Number.NaN },
  ])("rejects mismatched or unproven receipt fields", fields => {
    expect(isV8CleanupReceipt({ ...receipt(), ...fields }, RELEASE, NOW)).toBe(false);
  });

  it.each([V8_PROBE_RELEASE, "A".repeat(40), "a".repeat(39), "a".repeat(41), "payload-sentinel"])(
    "requires a different valid cleanup release", release => {
      expect(isV8CleanupReceipt({ ...receipt(), worker_release: release }, release, NOW)).toBe(false);
    },
  );

  it("checks inclusive completion bounds and exclusive cleanup expiry", () => {
    const earliest = { ...receipt(), completed_at_ms: window.starts_ms };
    expect(isV8CleanupReceipt(earliest, RELEASE, window.starts_ms)).toBe(true);
    expect(isV8CleanupReceipt(earliest, RELEASE, window.starts_ms - 1)).toBe(false);
    expect(isV8CleanupReceipt(earliest, RELEASE, window.expires_ms - 1)).toBe(true);
    expect(isV8CleanupReceipt(earliest, RELEASE, window.expires_ms)).toBe(false);
    expect(isV8CleanupReceipt(earliest, RELEASE, window.expires_ms + 1)).toBe(false);
  });
});

describe("one exact admitted v8 table", () => {
  it.each([FIRST_TICK, LAST_TICK])("validates the complete catalog and uses five statements at most", async time => {
    const { db, drops, prepare, bound } = database({ objects: catalog(time), rows: { total: 1, invalid: 0 } });
    await cleanV8ProbeTables(db, admission(time), () => NOW, DEADLINE);
    expect(drops).toEqual([`DROP TABLE "${PREFIX}${time}"`]);
    expect(prepare).toHaveBeenCalledTimes(5);
    expect(prepare.mock.calls[0]?.[0]).toContain("LIMIT 3");
    expect(prepare.mock.calls[2]?.[0]).toContain("LIMIT 2");
    expect(bound).toEqual([[`${PREFIX}*`], [`${PREFIX}${time}`], [`${V8_PROBE_RELEASE}:${time}`, "probe", "intentional-failure"], [`${PREFIX}*`]]);
  });

  it("requires an empty catalog without admission and performs no drop", async () => {
    const empty = database({ objects: [] });
    await cleanV8ProbeTables(empty.db, undefined, () => NOW, DEADLINE);
    expect(empty.prepare).toHaveBeenCalledTimes(2);
    expect(empty.drops).toEqual([]);
    const occupied = database();
    await expect(cleanV8ProbeTables(occupied.db, undefined, () => NOW, DEADLINE)).rejects.toThrow("ownership rejected");
    expect(occupied.prepare).toHaveBeenCalledTimes(1);
    expect(occupied.drops).toEqual([]);
  });

  it.each([
    null, [], {}, { ...admission(), extra: "secret-sentinel" },
    { ...admission(), contract: "other" }, { ...admission(), probe_nonce: "wrong" },
    { ...admission(), worker_release: RELEASE },
    ...[FIRST_TICK - 1, FIRST_TICK + 1, LAST_TICK - 1, LAST_TICK + 1,
      FIRST_TICK - 120_000, LAST_TICK + 120_000, FIRST_TICK + 60_000,
      1790839493000 - 1, 1790840995000 + 1, Number.NaN]
      .map(scheduled_time_ms => ({ ...admission(), scheduled_time_ms })),
  ].map(value => ({ value })))("rejects malformed, foreign, or out-of-interval admission before SQL", async ({ value }) => {
    const { db, prepare } = database();
    await expect(cleanV8ProbeTables(db, value, () => NOW, DEADLINE)).rejects.toThrow("admission rejected");
    expect(prepare).not.toHaveBeenCalled();
  });

  it.each([
    [null], ["payload-sentinel"], [catalog()[1]],
    [catalog()[0], catalog()[0]], [...catalog(), catalog()[0]],
    [{ ...catalog()[0], sql: "CREATE TABLE unrelated(payload TEXT)" }],
    [{ ...catalog()[0], payload: "secret-sentinel" }],
    [{ ...catalog()[0], type: "trigger" }],
    [catalog()[0], { ...catalog()[1], name: "user_index", sql: "payload-sentinel" }],
    catalog(FIRST_TICK + 120_000),
    [{ ...catalog()[0], name: "unrelated", tbl_name: "unrelated" }],
  ])("rejects any unknown, duplicate, or unowned catalog object before deletion", async (...objects) => {
    const { db, prepare, drops } = database({ objects });
    await expect(cleanV8ProbeTables(db, admission(), () => NOW, DEADLINE)).rejects.toThrow();
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(drops).toEqual([]);
  });

  it.each([
    { foreign: [{}] }, { foreignFails: true }, { inventoryFails: true },
    { foreign: { table_count: 2, outgoing: 1, incoming: 0 } },
    { foreign: { table_count: 2, outgoing: 0, incoming: 1 } },
    { foreign: { table_count: 129, outgoing: 0, incoming: 0 } },
    { rows: { total: 1, invalid: 1 } }, { rows: { total: 2, invalid: 0 } },
    { rows: { total: -1, invalid: 0 } }, { rows: { total: 0.5, invalid: 0 } },
    { rows: { total: 0, invalid: "0" } }, { rows: { total: 0, invalid: 0, payload: "sentinel" } },
  ])("requires no foreign keys and at most one exactly owned row", async options => {
    const { db, drops } = database(options);
    await expect(cleanV8ProbeTables(db, admission(), () => NOW, DEADLINE)).rejects.toThrow();
    expect(drops).toEqual([]);
  });

  it.each([{ dropFails: true }, { retained: true }])("never accepts failed drop or nonempty readback", async options => {
    const { db, drops, prepare } = database(options);
    await expect(cleanV8ProbeTables(db, admission(), () => NOW, DEADLINE)).rejects.toThrow();
    expect(drops).toHaveLength(1);
    expect(prepare.mock.calls.length).toBeLessThanOrEqual(5);
  });

  it("sanitizes provider exceptions and stops before subsequent statements", async () => {
    const { db, prepare } = database({ throwProvider: true });
    await expect(cleanV8ProbeTables(db, admission(), () => NOW, DEADLINE)).rejects.toThrow(DEADLINE_ERROR);
    expect(prepare).toHaveBeenCalledTimes(1);
  });

  it("rechecks the absolute deadline after awaited validation before DROP", async () => {
    let current = NOW;
    const { db, drops, prepare } = database({ onRows: () => { current = DEADLINE; } });
    await expect(cleanV8ProbeTables(db, admission(), () => current, DEADLINE)).rejects.toThrow(DEADLINE_ERROR);
    expect(prepare).toHaveBeenCalledTimes(3);
    expect(drops).toEqual([]);
  });
});

describe("bounded cleanup awaits", () => {
  it.each([
    [window.starts_ms - 1, window.starts_ms + 60_000], [window.expires_ms, window.expires_ms + 1],
    [NOW, NOW], [NOW, NOW - 1], [NOW, NOW + 60_001], [NOW, NOW + 0.5],
    [NOW, Number.NaN], [Number.NaN, DEADLINE],
  ])("rejects invalid time or budget before calling the operation", async (now, deadline) => {
    const operation = vi.fn(async () => true);
    await expect(withinV8CleanupDeadline(operation, () => now, deadline)).rejects.toThrow(DEADLINE_ERROR);
    expect(operation).not.toHaveBeenCalled();
  });

  it("clears successful and rejected operation timers", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    try {
      await expect(withinV8CleanupDeadline(async () => true, Date.now, DEADLINE)).resolves.toBe(true);
      expect(vi.getTimerCount()).toBe(0);
      await expect(withinV8CleanupDeadline(async () => { throw new Error("secret-sentinel"); }, Date.now, DEADLINE))
        .rejects.toThrow(DEADLINE_ERROR);
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });

  it.each([NOW, window.expires_ms - 1])("times out pending work at the earliest deadline and never continues SQL", async current => {
    vi.useFakeTimers();
    vi.setSystemTime(current);
    try {
      let finish!: (value: unknown) => void;
      const pending = new Promise(resolve => { finish = resolve; });
      const prepare = vi.fn(() => ({ bind() { return this; }, all: () => pending }));
      const db = { prepare } as unknown as D1Database;
      const rejected = expect(cleanV8ProbeTables(db, admission(), Date.now, current + 60_000))
        .rejects.toThrow(DEADLINE_ERROR);
      await vi.advanceTimersByTimeAsync(Math.min(60_000, window.expires_ms - current));
      await rejected;
      expect(vi.getTimerCount()).toBe(0);
      finish({ success: true, results: catalog() });
      await Promise.resolve();
      expect(prepare).toHaveBeenCalledTimes(1);
    } finally { vi.useRealTimers(); }
  });
});
