import "dotenv/config";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "../db.js";

const directory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../db/migrations");
const client = await pool.connect();

try {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const files = (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort();
  for (const name of files) {
    const { rowCount } = await client.query("SELECT 1 FROM schema_migrations WHERE name = $1", [name]);
    if (rowCount) continue;

    const sql = await readFile(path.join(directory, name), "utf8");
    await client.query("BEGIN");
    try {
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
  console.error("Database migration failed:", error);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
