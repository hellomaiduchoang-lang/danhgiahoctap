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
const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT pg_advisory_xact_lock(81420317)");

  const existingAdmin = await client.query(
    "SELECT id, username, is_super_admin FROM users WHERE username = $1",
    [username]
  );
  if (existingAdmin.rowCount) {
    if (!existingAdmin.rows[0].is_super_admin) {
      throw new Error(`Username "${username}" already belongs to a non-Super Admin account.`);
    }
    await client.query("COMMIT");
    console.info(`Super Admin account already exists: ${username}`);
  } else {
    const existingSuperAdmin = await client.query(
      "SELECT username FROM users WHERE is_super_admin = TRUE LIMIT 1"
    );
    if (existingSuperAdmin.rowCount) {
      throw new Error(`A Super Admin already exists (${existingSuperAdmin.rows[0].username}); refusing to create another.`);
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await client.query(
      `INSERT INTO users (username, password_hash, full_name, is_admin, is_super_admin)
       VALUES ($1, $2, $3, TRUE, TRUE)`,
      [username, passwordHash, "ClassTrack Admin"]
    );
    await client.query("COMMIT");
    console.info(`Created initial Super Admin account: ${username}`);
  }
} catch (error) {
  await client.query("ROLLBACK");
  console.error("Database seed failed:", error);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
