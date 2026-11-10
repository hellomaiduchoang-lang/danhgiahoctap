import pg from "pg";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required.");
}

const databaseUrl = process.env.DATABASE_URL;
const databaseHost = new URL(databaseUrl).hostname;
const isLocalDatabase =
  databaseHost === "localhost" ||
  databaseHost === "127.0.0.1";

export const pool = new Pool({
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
