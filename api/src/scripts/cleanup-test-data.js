import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const cleanupApproval = "YES_I_HAVE_A_BACKUP";
const destructiveCleanupLockId = 81420320;
const allowedUserForeignKeys = new Set([
  "admin_permissions.granted_by_user_id:SET NULL",
  "admin_permissions.user_id:CASCADE",
  "audit_logs.actor_user_id:SET NULL",
  "auth_sessions.user_id:CASCADE",
  "class_members.user_id:CASCADE"
]);

export class CleanupSafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = "CleanupSafetyError";
  }
}

function quoteIdentifier(identifier) {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function countFrom(result) {
  return Number(result.rows[0]?.count || 0);
}

async function getUserForeignKeys(client) {
  const userRelation = await client.query(
    `SELECT namespaces.nspname AS schema_name
     FROM pg_class AS relations
     JOIN pg_namespace AS namespaces ON namespaces.oid = relations.relnamespace
     WHERE relations.oid = to_regclass('users')`
  );
  const schemaName = userRelation.rows[0]?.schema_name;
  if (!schemaName) throw new CleanupSafetyError("Could not resolve the users table.");

  const result = await client.query(
    `SELECT child_namespace.nspname AS schema_name,
            child_table.relname AS table_name,
            child_column.attname AS column_name,
            CASE constraint_info.confdeltype
              WHEN 'c' THEN 'CASCADE'
              WHEN 'n' THEN 'SET NULL'
              WHEN 'r' THEN 'RESTRICT'
              WHEN 'a' THEN 'NO ACTION'
              WHEN 'd' THEN 'SET DEFAULT'
            END AS delete_action
     FROM pg_constraint AS constraint_info
     JOIN pg_class AS child_table ON child_table.oid = constraint_info.conrelid
     JOIN pg_namespace AS child_namespace ON child_namespace.oid = child_table.relnamespace
     JOIN LATERAL unnest(constraint_info.conkey) AS child_key(attnum) ON TRUE
     JOIN pg_attribute AS child_column
       ON child_column.attrelid = child_table.oid
      AND child_column.attnum = child_key.attnum
     WHERE constraint_info.contype = 'f'
       AND constraint_info.confrelid = to_regclass('users')
     ORDER BY child_namespace.nspname, child_table.relname, child_column.attname`
  );

  const actual = new Set(result.rows.map((row) =>
    `${row.schema_name}.${row.table_name}.${row.column_name}:${row.delete_action}`
  ));
  const expected = new Set([...allowedUserForeignKeys].map((foreignKey) =>
    `${schemaName}.${foreignKey}`
  ));
  const unknown = [...actual].filter((foreignKey) => !expected.has(foreignKey));
  const missing = [...expected].filter((foreignKey) => !actual.has(foreignKey));
  if (unknown.length || missing.length) {
    const details = [
      ...unknown.map((foreignKey) => `unreviewed ${foreignKey}`),
      ...missing.map((foreignKey) => `expected ${foreignKey} was not found`)
    ];
    throw new CleanupSafetyError(`User foreign-key schema check failed: ${details.join("; ")}.`);
  }

  return schemaName;
}

export async function cleanupNonAdminUsers(client, { dryRun, logger = console }) {
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;
    await client.query("SELECT pg_advisory_xact_lock($1)", [destructiveCleanupLockId]);

    const schemaName = await getUserForeignKeys(client);
    const table = (name) => `${quoteIdentifier(schemaName)}.${quoteIdentifier(name)}`;
    const candidates = await client.query(
      `SELECT id, username
       FROM ${table("users")}
       WHERE is_admin = FALSE AND is_super_admin = FALSE
       ORDER BY username, id
       FOR UPDATE`
    );
    const userIds = candidates.rows.map((user) => user.id);
    const userIdParameters = [userIds];

    const sessionCountResult = await client.query(
      `SELECT COUNT(*)::int AS count FROM ${table("auth_sessions")} WHERE user_id = ANY($1::uuid[])`,
      userIdParameters
    );
    const permissionCountResult = await client.query(
      `SELECT COUNT(*)::int AS count FROM ${table("admin_permissions")} WHERE user_id = ANY($1::uuid[])`,
      userIdParameters
    );
    const membershipCountResult = await client.query(
      `SELECT COUNT(*)::int AS count FROM ${table("class_members")} WHERE user_id = ANY($1::uuid[])`,
      userIdParameters
    );
    const auditCountResult = await client.query(
      `SELECT COUNT(*)::int AS count FROM ${table("audit_logs")} WHERE actor_user_id = ANY($1::uuid[])`,
      userIdParameters
    );
    const membershipsByUser = await client.query(
      `SELECT users.username, COUNT(class_members.id)::int AS membership_count
       FROM ${table("users")} AS users
       JOIN ${table("class_members")} AS class_members ON class_members.user_id = users.id
       WHERE users.id = ANY($1::uuid[])
       GROUP BY users.username
       ORDER BY users.username`,
      userIdParameters
    );

    const counts = {
      auth_sessions: countFrom(sessionCountResult),
      admin_permissions: countFrom(permissionCountResult),
      class_members: countFrom(membershipCountResult),
      audit_logs_retained: countFrom(auditCountResult),
      users: candidates.rowCount
    };

    logger.info(`Mode: ${dryRun ? "DRY RUN (no rows will be deleted)" : "DESTRUCTIVE CLEANUP"}`);
    logger.info(`Non-admin accounts selected (${candidates.rowCount}):`);
    if (candidates.rowCount) {
      for (const user of candidates.rows) logger.info(`  ${user.username}`);
    } else {
      logger.info("  (none)");
    }
    logger.info("Planned delete counts if all safety checks pass:");
    logger.info(`  auth_sessions: ${counts.auth_sessions}`);
    logger.info(`  admin_permissions: ${counts.admin_permissions}`);
    logger.info(`  users: ${counts.users}`);
    logger.info(`  class_members: 0 (never deleted; found ${counts.class_members})`);
    logger.info(`  audit_logs: 0 deleted (${counts.audit_logs_retained} retained; actor reference becomes NULL through the existing foreign key)`);

    if (counts.class_members) {
      const blockingUsers = membershipsByUser.rows
        .map((row) => `${row.username} (${row.membership_count} class_members)`)
        .join(", ");
      throw new CleanupSafetyError(
        `Cleanup stopped: related class/learning data exists for ${blockingUsers}. No rows were deleted.`
      );
    }

    if (dryRun) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      logger.info("DRY RUN complete. No rows were deleted.");
      return { dryRun: true, counts };
    }

    let deletedSessions = 0;
    let deletedPermissions = 0;
    let deletedUsers = 0;
    if (userIds.length) {
      const sessions = await client.query(
        `DELETE FROM ${table("auth_sessions")} WHERE user_id = ANY($1::uuid[]) RETURNING user_id`,
        userIdParameters
      );
      deletedSessions = sessions.rowCount;

      const permissions = await client.query(
        `DELETE FROM ${table("admin_permissions")} WHERE user_id = ANY($1::uuid[]) RETURNING user_id`,
        userIdParameters
      );
      deletedPermissions = permissions.rowCount;

      const users = await client.query(
        `DELETE FROM ${table("users")}
         WHERE id = ANY($1::uuid[])
           AND is_admin = FALSE
           AND is_super_admin = FALSE
         RETURNING id`,
        userIdParameters
      );
      deletedUsers = users.rowCount;
      if (deletedUsers !== userIds.length) {
        throw new CleanupSafetyError(
          `Expected to delete ${userIds.length} non-admin users, but deleted ${deletedUsers}. The transaction will be rolled back.`
        );
      }
    }

    await client.query("COMMIT");
    transactionStarted = false;

    const deletedCounts = {
      auth_sessions: deletedSessions,
      admin_permissions: deletedPermissions,
      class_members: 0,
      audit_logs: 0,
      users: deletedUsers
    };
    logger.info("Deleted row counts:");
    for (const [tableName, count] of Object.entries(deletedCounts)) {
      logger.info(`  ${tableName}: ${count}`);
    }
    logger.info(`Preserved audit_logs rows whose actor reference was cleared by the foreign key: ${counts.audit_logs_retained}`);
    return { dryRun: false, deletedCounts };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch {
        logger.error("Cleanup transaction rollback failed.");
      }
    }
    throw error;
  }
}

async function main() {
  if (process.env.ALLOW_DESTRUCTIVE_CLEANUP !== cleanupApproval) {
    console.error("Cleanup refused. Set ALLOW_DESTRUCTIVE_CLEANUP=YES_I_HAVE_A_BACKUP to run this script.");
    process.exitCode = 1;
    return;
  }

  const dryRunSetting = process.env.DRY_RUN;
  if (dryRunSetting !== undefined && dryRunSetting !== "true" && dryRunSetting !== "false") {
    console.error("Cleanup refused. DRY_RUN must be exactly true or false.");
    process.exitCode = 1;
    return;
  }
  const dryRun = dryRunSetting !== "false";

  let pool;
  let client;
  try {
    ({ pool } = await import("../db.js"));
    client = await pool.connect();
    await cleanupNonAdminUsers(client, { dryRun });
  } catch (error) {
    if (error instanceof CleanupSafetyError) {
      console.error(error.message);
    } else {
      const errorCode = error && typeof error === "object" && "code" in error ? error.code : undefined;
      console.error(
        "Cleanup failed.",
        errorCode ? `Database error code: ${errorCode}` : "Check database connectivity and schema configuration."
      );
    }
    process.exitCode = 1;
  } finally {
    client?.release();
    await pool?.end();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
