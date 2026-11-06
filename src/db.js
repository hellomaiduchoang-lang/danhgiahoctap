import pg from "pg";

const { Pool } = pg;
let pool;

export function getPool() {
  if (!process.env.DATABASE_URL) {
    const error = new Error("DATABASE_URL chưa được cấu hình; hãy đặt URL PostgreSQL trước khi dùng API xác thực.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }

  if (!pool) {
    const databaseUrl = process.env.DATABASE_URL;
    const database = new URL(databaseUrl);
    const isLocalDatabase =
      database.hostname === "localhost" ||
      database.hostname === "127.0.0.1";

    pool = new Pool({
      connectionString: databaseUrl,
      ssl: isLocalDatabase
        ? false
        : { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000
    });
    pool.on("error", () => {
      console.error("Unexpected PostgreSQL pool error.");
    });
  }
  return pool;
}

export async function closePool() {
  if (!pool) return;
  await pool.end();
  pool = undefined;
}
