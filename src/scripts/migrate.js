import "dotenv/config";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getPool } from "../db.js";

const directory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../api/db/migrations");
const pool = getPool();
let client;

try {
  client = await pool.connect();
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const files = (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort();
  for (const name of files) {
    const sql = await readFile(path.join(directory, name), "utf8");
    await client.query("BEGIN");
    try {
      await client.query("SELECT pg_advisory_xact_lock(81420318)");
      const applied = await client.query("SELECT 1 FROM schema_migrations WHERE name = $1", [name]);
      if (applied.rowCount) {
        await client.query("COMMIT");
        continue;
      }

      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
      await client.query("COMMIT");
      console.info(`Applied migration ${name}`);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
} catch (error) {
  const errorCode = error && typeof error === "object" && "code" in error
    ? error.code
    : undefined;
  console.error(
    "Database migration failed.",
    errorCode ? `Error code: ${errorCode}` : "Check database connectivity and migration files."
  );
  process.exitCode = 1;
} finally {
  client?.release();
  await pool.end();
}
