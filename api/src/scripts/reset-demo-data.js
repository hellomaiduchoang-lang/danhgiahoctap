import "dotenv/config";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const resetApproval = "YES_I_HAVE_A_BACKUP";
const resetLockId = 81420321;
const resetTables = [
  "admin_permissions",
  "audit_logs",
  "auth_sessions",
  "class_forum_posts",
  "class_groups",
  "class_member_roles",
  "class_members",
  "class_weekly_point_periods",
  "class_weekly_point_scores",
  "classes",
  "conduct_categories",
  "conduct_records",
  "evidence_files",
  "group_members",
  "member_permissions",
  "role_requests",
  "users"
];

const countQueries = [
  ["users", "SELECT COUNT(*)::bigint AS count FROM users WHERE is_admin = FALSE AND is_super_admin = FALSE"],
  ["teachers", "SELECT COUNT(*)::bigint AS count FROM users WHERE is_teacher = TRUE AND is_admin = FALSE AND is_super_admin = FALSE"],
  ["students", `SELECT COUNT(DISTINCT users.id)::bigint AS count
                FROM users
                JOIN class_members ON class_members.user_id = users.id
                JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
                JOIN roles ON roles.id = class_member_roles.role_id
                WHERE roles.name = 'ROLE_STUDENT'
                  AND users.is_admin = FALSE
                  AND users.is_super_admin = FALSE`],
  ["classes", "SELECT COUNT(*)::bigint AS count FROM classes"],
  ["class_members", "SELECT COUNT(*)::bigint AS count FROM class_members"],
  ["class_member_roles", "SELECT COUNT(*)::bigint AS count FROM class_member_roles"],
  ["member_permissions", "SELECT COUNT(*)::bigint AS count FROM member_permissions"],
  ["role_requests", "SELECT COUNT(*)::bigint AS count FROM role_requests"],
  ["class_groups", "SELECT COUNT(*)::bigint AS count FROM class_groups"],
  ["group_members", "SELECT COUNT(*)::bigint AS count FROM group_members"],
  ["conduct_categories", "SELECT COUNT(*)::bigint AS count FROM conduct_categories"],
  ["conduct_records", "SELECT COUNT(*)::bigint AS count FROM conduct_records"],
  ["evidence_files", "SELECT COUNT(*)::bigint AS count FROM evidence_files"],
  ["class_forum_posts", "SELECT COUNT(*)::bigint AS count FROM class_forum_posts"],
  ["class_weekly_point_scores", "SELECT COUNT(*)::bigint AS count FROM class_weekly_point_scores"],
  ["class_weekly_point_periods", "SELECT COUNT(*)::bigint AS count FROM class_weekly_point_periods"],
  ["auth_sessions", "SELECT COUNT(*)::bigint AS count FROM auth_sessions"],
  ["audit_logs", "SELECT COUNT(*)::bigint AS count FROM audit_logs"],
  ["admin_permissions", `SELECT COUNT(*)::bigint AS count
                         FROM admin_permissions
                         WHERE user_id IN (
                           SELECT id FROM users
                           WHERE is_admin = FALSE AND is_super_admin = FALSE
                         )`]
];

const deleteStatements = [
  ["audit_logs", "DELETE FROM audit_logs"],
  ["auth_sessions", "DELETE FROM auth_sessions"],
  ["admin_permissions", `DELETE FROM admin_permissions
                         WHERE user_id IN (
                           SELECT id FROM users
                           WHERE is_admin = FALSE AND is_super_admin = FALSE
                         )`],
  ["evidence_files", "DELETE FROM evidence_files"],
  ["class_weekly_point_scores", "DELETE FROM class_weekly_point_scores"],
  ["class_forum_posts", "DELETE FROM class_forum_posts"],
  ["conduct_records", "DELETE FROM conduct_records"],
  ["group_members", "DELETE FROM group_members"],
  ["class_member_roles", "DELETE FROM class_member_roles"],
  ["member_permissions", "DELETE FROM member_permissions"],
  ["role_requests", "DELETE FROM role_requests"],
  ["class_weekly_point_periods", "DELETE FROM class_weekly_point_periods"],
  ["class_groups", "DELETE FROM class_groups"],
  ["conduct_categories", "DELETE FROM conduct_categories"],
  ["class_members", "DELETE FROM class_members"],
  ["classes", "DELETE FROM classes"],
  ["users", `DELETE FROM users
             WHERE is_admin = FALSE
               AND is_super_admin = FALSE`]
];

export class ResetSafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = "ResetSafetyError";
  }
}

function countValue(result) {
  return Number(result.rows[0]?.count || 0);
}

async function getCounts(client) {
  const counts = {};
  for (const [table, sql] of countQueries) {
    counts[table] = countValue(await client.query(sql));
  }
  return counts;
}

function logCounts(logger, heading, counts) {
  logger.info(heading);
  for (const [table, count] of Object.entries(counts)) {
    logger.info(`  ${table}: ${count}`);
  }
}

export async function resetDemoData(client, { dryRun, logger = console }) {
  let transactionStarted = false;
  try {
    await client.query(dryRun ? "BEGIN READ ONLY" : "BEGIN");
    transactionStarted = true;

    if (!dryRun) {
      await client.query("SELECT pg_advisory_xact_lock($1)", [resetLockId]);
      await client.query(`LOCK TABLE ${resetTables.join(", ")} IN ACCESS EXCLUSIVE MODE`);
    }

    const counts = await getCounts(client);
    logger.info(`Mode: ${dryRun ? "DRY RUN (no data will be changed)" : "RESET DEMO DATA"}`);
    logCounts(logger, "Planned record counts:", counts);

    if (dryRun) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      logger.info("DRY RUN complete. No database rows were changed.");
      return { dryRun: true, counts, deletedCounts: null };
    }

    const deletedCounts = {};
    for (const [table, sql] of deleteStatements) {
      const result = await client.query(`${sql} RETURNING 1`);
      deletedCounts[table] = result.rowCount;
    }

    if (deletedCounts.users !== counts.users) {
      throw new ResetSafetyError(
        `Expected to delete ${counts.users} non-admin accounts, but deleted ${deletedCounts.users}.`
      );
    }

    await client.query("COMMIT");
    transactionStarted = false;
    logCounts(logger, "Deleted record counts:", deletedCounts);
    logger.info("Demo data reset completed. Admin and Super Admin accounts were retained.");
    return { dryRun: false, counts, deletedCounts };
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK");
    }
    throw error;
  }
}

export function readResetOptions(env = process.env) {
  const dryRunValue = env.DRY_RUN ?? "true";
  if (dryRunValue !== "true" && dryRunValue !== "false") {
    throw new ResetSafetyError("DRY_RUN must be exactly true or false.");
  }
  const dryRun = dryRunValue === "true";
  if (!dryRun && env.ALLOW_RESET !== resetApproval) {
    throw new ResetSafetyError("Destructive reset requires ALLOW_RESET=YES_I_HAVE_A_BACKUP.");
  }
  return { dryRun };
}

async function main() {
  let pool;
  let client;
  try {
    const options = readResetOptions();
    ({ pool } = await import("../db.js"));
    client = await pool.connect();
    await resetDemoData(client, options);
  } catch (error) {
    const message = error instanceof ResetSafetyError
      ? error.message
      : "Database reset failed; the transaction was rolled back.";
    console.error(message);
    if (!(error instanceof ResetSafetyError) && error?.code) {
      console.error(`Database error code: ${error.code}`);
    }
    process.exitCode = 1;
  } finally {
    client?.release();
    await pool?.end();
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath && pathToFileURL(invokedPath).href === import.meta.url) {
  await main();
}
