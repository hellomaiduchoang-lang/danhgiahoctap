import "dotenv/config";
import path from "node:path";
import { pathToFileURL } from "node:url";

const deleteApproval = "I_HAVE_A_BACKUP";
const deleteLockTables = [
  "users",
  "class_members",
  "auth_sessions",
  "audit_logs",
  "admin_permissions"
];

const accountCountsSql = `
  SELECT
    (SELECT COUNT(*)::bigint
     FROM class_members
     WHERE user_id = users.id) AS class_memberships,
    (SELECT COUNT(DISTINCT class_id)::bigint
     FROM class_members
     WHERE user_id = users.id) AS classes,
    (SELECT COUNT(*)::bigint
     FROM class_member_roles
     WHERE class_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR granted_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS class_member_roles,
    (SELECT COUNT(*)::bigint
     FROM member_permissions
     WHERE class_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR granted_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS member_permissions,
    (SELECT COUNT(*)::bigint
     FROM role_requests
     WHERE requested_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR reviewed_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS role_requests,
    (SELECT COUNT(*)::bigint
     FROM class_groups
     WHERE leader_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS class_groups,
    (SELECT COUNT(*)::bigint
     FROM group_members
     WHERE class_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS group_members,
    (SELECT COUNT(*)::bigint
     FROM conduct_records
     WHERE student_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR recorder_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS conduct_records,
    (SELECT COALESCE(SUM(points), 0)::bigint
     FROM conduct_records
     WHERE student_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR recorder_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS points,
    (SELECT COUNT(*)::bigint
     FROM conduct_records
     WHERE (student_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
         OR recorder_member_id IN (SELECT id FROM class_members WHERE user_id = users.id))
       AND BTRIM(description) <> '') AS comments,
    (SELECT COUNT(*)::bigint
     FROM evidence_files
     WHERE uploaded_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
        OR EXISTS (
          SELECT 1
          FROM conduct_records
          WHERE conduct_records.class_id = evidence_files.class_id
            AND conduct_records.id = evidence_files.conduct_record_id
            AND (conduct_records.student_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)
              OR conduct_records.recorder_member_id IN (SELECT id FROM class_members WHERE user_id = users.id))
        )) AS evidence_files,
    (SELECT COUNT(*)::bigint
     FROM class_forum_posts
     WHERE author_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS class_forum_posts,
    (SELECT COUNT(*)::bigint
     FROM class_weekly_point_periods
     WHERE reset_by_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS class_weekly_point_periods,
    (SELECT COUNT(*)::bigint
     FROM class_weekly_point_scores
     WHERE class_member_id IN (SELECT id FROM class_members WHERE user_id = users.id)) AS class_weekly_point_scores,
    (SELECT COUNT(*)::bigint
     FROM audit_logs
     WHERE actor_user_id = users.id
        OR (target_type = 'user' AND target_id = users.id::text)) AS audit_logs,
    (SELECT COUNT(*)::bigint
     FROM admin_permissions
     WHERE user_id = users.id OR granted_by_user_id = users.id) AS admin_permissions,
    (SELECT COUNT(*)::bigint
     FROM auth_sessions
     WHERE user_id = users.id) AS auth_sessions
  FROM users
  WHERE users.id = $1
`;

const historyCountKeys = [
  "class_member_roles",
  "member_permissions",
  "role_requests",
  "class_groups",
  "group_members",
  "conduct_records",
  "points",
  "comments",
  "evidence_files",
  "class_forum_posts",
  "class_weekly_point_periods",
  "class_weekly_point_scores",
  "audit_logs",
  "admin_permissions"
];

export class DeleteTestAccountsSafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = "DeleteTestAccountsSafetyError";
  }
}

function toCounts(row) {
  return Object.fromEntries(
    Object.entries(row).map(([key, value]) => [key, Number(value || 0)])
  );
}

function blockersFor(account, counts) {
  const blockers = [];
  if (account.is_admin) blockers.push("protected Admin account");
  if (account.is_super_admin) blockers.push("protected Super Admin account");
  if (counts.class_memberships) {
    blockers.push(`belongs to ${counts.class_memberships} class membership(s) across ${counts.classes} class(es)`);
  }
  for (const key of historyCountKeys) {
    if (counts[key]) blockers.push(`has ${counts[key]} related ${key} record(s)`);
  }
  return blockers;
}

function logAccountReport(logger, accountReport) {
  logger.info(`Account ${accountReport.username}: ${accountReport.status}`);
  if (accountReport.blockers.length) {
    for (const blocker of accountReport.blockers) logger.info(`  Kept: ${blocker}`);
  }
  for (const [table, count] of Object.entries(accountReport.counts)) {
    if (count) logger.info(`  ${table}: ${count}`);
  }
}

export function readDeleteOptions(env = process.env) {
  const rawUsernames = env.TEST_USERNAMES;
  if (typeof rawUsernames !== "string" || !rawUsernames.trim()) {
    throw new DeleteTestAccountsSafetyError("Set TEST_USERNAMES to a comma-separated allowlist.");
  }
  const usernames = rawUsernames.split(",").map((username) => username.trim().toLowerCase());
  if (usernames.some((username) => !/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username))) {
    throw new DeleteTestAccountsSafetyError("TEST_USERNAMES contains an invalid username.");
  }
  const uniqueUsernames = [...new Set(usernames)];

  const dryRunValue = env.DRY_RUN ?? "true";
  if (dryRunValue !== "true" && dryRunValue !== "false") {
    throw new DeleteTestAccountsSafetyError("DRY_RUN must be exactly true or false.");
  }
  const dryRun = dryRunValue === "true";
  if (!dryRun && env.ALLOW_DELETE_TEST_ACCOUNTS !== deleteApproval) {
    throw new DeleteTestAccountsSafetyError(
      "Deletion requires ALLOW_DELETE_TEST_ACCOUNTS=I_HAVE_A_BACKUP."
    );
  }
  return { usernames: uniqueUsernames, dryRun };
}

export async function deleteTestAccounts(client, { usernames, dryRun, logger = console }) {
  let transactionStarted = false;
  try {
    await client.query(dryRun ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" : "BEGIN");
    transactionStarted = true;

    if (!dryRun) {
      await client.query(
        `LOCK TABLE ${deleteLockTables.join(", ")} IN SHARE ROW EXCLUSIVE MODE`
      );
    }

    const accountsResult = await client.query(
      `SELECT id, username, is_admin, is_super_admin
       FROM users
       WHERE username = ANY($1::text[])
       ORDER BY username${dryRun ? "" : " FOR UPDATE"}`,
      [usernames]
    );
    const accountsByUsername = new Map(accountsResult.rows.map((account) => [account.username, account]));
    const reports = [];

    for (const username of usernames) {
      const account = accountsByUsername.get(username);
      if (!account) {
        reports.push({
          username,
          status: "not found",
          blockers: [],
          counts: {}
        });
        continue;
      }

      const countResult = await client.query(accountCountsSql, [account.id]);
      if (!countResult.rowCount) {
        throw new DeleteTestAccountsSafetyError("Unable to inspect all requested account relations.");
      }
      const counts = toCounts(countResult.rows[0]);
      const blockers = blockersFor(account, counts);
      reports.push({
        username,
        status: blockers.length ? "kept" : dryRun ? "would delete" : "eligible for deletion",
        blockers,
        counts
      });
    }

    const deletableReports = reports.filter((report) =>
      accountsByUsername.has(report.username) && report.blockers.length === 0
    );
    const deletableAccounts = deletableReports
      .map((report) => accountsByUsername.get(report.username));
    const accountIds = deletableAccounts.map((account) => account.id);
    const plannedCounts = {
      auth_sessions: deletableReports.reduce((total, report) => total + report.counts.auth_sessions, 0),
      users: deletableAccounts.length
    };

    logger.info(`Mode: ${dryRun ? "DRY RUN (no data will be changed)" : "DELETE ALLOWLISTED TEST ACCOUNTS"}`);
    for (const report of reports) logAccountReport(logger, report);
    logger.info("Planned deletions:");
    for (const [table, count] of Object.entries(plannedCounts)) logger.info(`  ${table}: ${count}`);

    if (dryRun) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      logger.info("DRY RUN complete. No database rows were changed.");
      return { dryRun: true, reports, plannedCounts, deletedCounts: null };
    }

    const deletedCounts = { auth_sessions: 0, users: 0 };
    if (accountIds.length) {
      const sessions = await client.query(
        "DELETE FROM auth_sessions WHERE user_id = ANY($1::uuid[]) RETURNING 1",
        [accountIds]
      );
      deletedCounts.auth_sessions = sessions.rowCount;
      if (deletedCounts.auth_sessions !== plannedCounts.auth_sessions) {
        throw new DeleteTestAccountsSafetyError("Session counts changed during deletion; no changes were committed.");
      }

      const users = await client.query(
        `DELETE FROM users
         WHERE id = ANY($1::uuid[])
           AND is_admin = FALSE
           AND is_super_admin = FALSE
           AND NOT EXISTS (SELECT 1 FROM class_members WHERE class_members.user_id = users.id)
           AND NOT EXISTS (
             SELECT 1 FROM audit_logs
             WHERE audit_logs.actor_user_id = users.id
                OR (audit_logs.target_type = 'user' AND audit_logs.target_id = users.id::text)
           )
           AND NOT EXISTS (
             SELECT 1 FROM admin_permissions
             WHERE admin_permissions.user_id = users.id
                OR admin_permissions.granted_by_user_id = users.id
           )
         RETURNING id`,
        [accountIds]
      );
      deletedCounts.users = users.rowCount;
      if (deletedCounts.users !== plannedCounts.users) {
        throw new DeleteTestAccountsSafetyError("Account eligibility changed during deletion; no changes were committed.");
      }
    }

    await client.query("COMMIT");
    transactionStarted = false;
    for (const report of deletableReports) report.status = "deleted";
    logger.info("Deleted record counts:");
    for (const [table, count] of Object.entries(deletedCounts)) logger.info(`  ${table}: ${count}`);
    for (const report of deletableReports) logger.info(`Account ${report.username}: deleted`);
    logger.info("Deletion completed. Admin and Super Admin accounts were retained.");
    return { dryRun: false, reports, plannedCounts, deletedCounts };
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    throw error;
  }
}

async function main() {
  let pool;
  let client;
  try {
    const options = readDeleteOptions();
    ({ pool } = await import("../db.js"));
    client = await pool.connect();
    await deleteTestAccounts(client, options);
  } catch (error) {
    const message = error instanceof DeleteTestAccountsSafetyError
      ? error.message
      : "Failed to inspect or delete allowlisted accounts; no changes were committed.";
    console.error(message);
    if (!(error instanceof DeleteTestAccountsSafetyError) && error?.code) {
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
