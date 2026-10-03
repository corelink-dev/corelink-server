import { DatabaseSync } from "node:sqlite";
import { SCHEMA_OBJECTS_SQL, TARGET } from "../../scripts/deploy-route.mjs";

// Wrangler 4.141's migrations table (getCreateMigrationsTableQuery in its dist).
export const WRANGLER_MIGRATIONS_TABLE_SQL = `CREATE TABLE IF NOT EXISTS "d1_migrations"(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT UNIQUE,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);`;

// What the route's schema query returns from the receiver D1, built by real
// SQLite rather than written by hand: the reserved D1 table, then (when a
// migration is given) Wrangler's migrations table, the migration and its ledger
// row, then any extra SQL a test adds. SQLite's own objects (autoindexes,
// sqlite_sequence) appear exactly as they would on D1.
export function d1SchemaRows({ migration = null, extraSql = "" } = {}) {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID;");
    if (migration !== null) {
      db.exec(WRANGLER_MIGRATIONS_TABLE_SQL);
      db.exec(migration);
      db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").run(TARGET.migration);
    }
    if (extraSql) db.exec(extraSql);
    return db.prepare(SCHEMA_OBJECTS_SQL).all().map((row) => ({ type: row.type, name: row.name, tbl_name: row.tbl_name, sql: row.sql }));
  } finally {
    db.close();
  }
}
