import "dotenv/config";
import bcrypt from "bcryptjs";
import { pool } from "../db.js";

const username = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();
const fullName = String(process.env.ADMIN_FULL_NAME || "").trim();
const password = process.env.ADMIN_PASSWORD || "";

if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
  throw new Error("ADMIN_USERNAME must be 3–32 characters using lowercase letters, numbers, dots, underscores, or hyphens.");
}
if (!fullName || fullName.length > 120) throw new Error("Set ADMIN_FULL_NAME (1–120 characters).");
if (password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
  throw new Error("ADMIN_PASSWORD must be 12–72 UTF-8 bytes.");
}

const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT pg_advisory_xact_lock(81420317)");
  const existing = await client.query("SELECT 1 FROM users WHERE is_super_admin = TRUE LIMIT 1");
  if (existing.rowCount) throw new Error("A Super Admin already exists; refusing to create another bootstrap account.");

  const passwordHash = await bcrypt.hash(password, 12);
  await client.query(
    `INSERT INTO users (username, password_hash, full_name, is_admin, is_super_admin)
     VALUES ($1, $2, $3, TRUE, TRUE)`,
    [username, passwordHash, fullName]
  );
  await client.query("COMMIT");
  console.info(`Created initial Super Admin account: ${username}`);
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  client.release();
  await pool.end();
}
