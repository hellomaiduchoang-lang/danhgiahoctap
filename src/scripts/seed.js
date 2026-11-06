import "dotenv/config";
import bcrypt from "bcryptjs";
import { getPool } from "../db.js";

const username = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD || "";
if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
  throw new Error("ADMIN_USERNAME must be 3–32 lowercase letters, numbers, dots, underscores, or hyphens.");
}
if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
  throw new Error("ADMIN_PASSWORD must be 12–72 UTF-8 bytes.");
}

const pool = getPool();
let client;
let transactionStarted = false;

try {
  client = await pool.connect();
  const passwordHash = await bcrypt.hash(password, 12);
  await client.query("BEGIN");
  transactionStarted = true;
  await client.query("SELECT pg_advisory_xact_lock(81420317)");
  const result = await client.query(
    `INSERT INTO users (username, password_hash, full_name, is_admin, is_super_admin, is_active)
     VALUES ($1, $2, 'ClassTrack Admin', TRUE, TRUE, TRUE)
     ON CONFLICT (username) DO UPDATE
     SET password_hash = EXCLUDED.password_hash,
         is_admin = TRUE,
         is_super_admin = TRUE,
         is_active = TRUE
     RETURNING (xmax = 0) AS created`,
    [username, passwordHash]
  );
  await client.query("COMMIT");
  transactionStarted = false;
  console.info(`Super Admin account ${result.rows[0].created ? "created" : "updated"}.`);
} catch (error) {
  if (client && transactionStarted) {
    await client.query("ROLLBACK");
  }
  const errorCode = error && typeof error === "object" && "code" in error
    ? error.code
    : undefined;
  console.error(
    "Database seed failed.",
    errorCode ? `Error code: ${errorCode}` : "Check database connectivity and configured admin settings."
  );
  process.exitCode = 1;
} finally {
  client?.release();
  await pool.end();
}
