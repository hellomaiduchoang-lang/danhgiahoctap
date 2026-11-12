import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  deleteTestAccounts,
  DeleteTestAccountsSafetyError,
  readDeleteOptions
} from "../src/scripts/delete-test-accounts.js";

const scriptPath = fileURLToPath(new URL("../src/scripts/delete-test-accounts.js", import.meta.url));
const apiDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const accountIds = {
  eligible: "00000000-0000-4000-8000-000000000001",
  member: "00000000-0000-4000-8000-000000000002",
  admin: "00000000-0000-4000-8000-000000000003",
  superAdmin: "00000000-0000-4000-8000-000000000004"
};

function counts(overrides = {}) {
  return {
    class_memberships: 0,
    classes: 0,
    class_member_roles: 0,
    member_permissions: 0,
    role_requests: 0,
    class_groups: 0,
    group_members: 0,
    conduct_records: 0,
    points: 0,
    comments: 0,
    evidence_files: 0,
    class_forum_posts: 0,
    class_weekly_point_periods: 0,
    class_weekly_point_scores: 0,
    audit_logs: 0,
    admin_permissions: 0,
    auth_sessions: 0,
    ...overrides
  };
}

function createAccounts() {
  return [
    { id: accountIds.eligible, username: "hs_test_01", is_admin: false, is_super_admin: false },
    { id: accountIds.member, username: "hs_test_02", is_admin: false, is_super_admin: false },
    { id: accountIds.admin, username: "gv_test_01", is_admin: true, is_super_admin: false },
    { id: accountIds.superAdmin, username: "super_test_01", is_admin: false, is_super_admin: true }
  ];
}

function installClient({ accountCounts = {}, failOnDelete } = {}) {
  const statements = [];
  const accounts = createAccounts();
  const client = {
    async query(sql, params = []) {
      statements.push({ sql, params });
      if (sql.includes("FROM users") && sql.includes("username = ANY")) {
        return {
          rows: accounts.filter((account) => params[0].includes(account.username)),
          rowCount: accounts.filter((account) => params[0].includes(account.username)).length
        };
      }
      if (sql === "\n  SELECT" || sql.includes("AS class_memberships")) {
        return { rows: [counts(accountCounts[params[0]] || {})], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM")) {
        const table = sql.match(/DELETE FROM ([a-z_]+)/)?.[1];
        if (table === failOnDelete) {
          const error = new Error("database detail must not be logged");
          error.code = "23503";
          throw error;
        }
        if (table === "auth_sessions") return { rows: [], rowCount: counts(accountCounts[accountIds.eligible] || {}).auth_sessions };
        if (table === "users") return { rows: [{ id: accountIds.eligible }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  };
  return { client, statements };
}

function createLogger() {
  const messages = [];
  return { messages, info: (message) => messages.push(message) };
}

test("delete options default to dry-run and require an allowlist and explicit approval", () => {
  assert.deepEqual(readDeleteOptions({ TEST_USERNAMES: "hs_test_01, hs_test_02" }), {
    usernames: ["hs_test_01", "hs_test_02"],
    dryRun: true
  });
  assert.deepEqual(readDeleteOptions({
    TEST_USERNAMES: " HS_TEST_01,hs_test_01 ",
    DRY_RUN: "false",
    ALLOW_DELETE_TEST_ACCOUNTS: "I_HAVE_A_BACKUP"
  }), {
    usernames: ["hs_test_01"],
    dryRun: false
  });
  assert.throws(() => readDeleteOptions({}), /TEST_USERNAMES/);
  assert.throws(() => readDeleteOptions({ TEST_USERNAMES: "hs_test_01," }), /invalid username/);
  assert.throws(() => readDeleteOptions({ TEST_USERNAMES: "hs_test_01", DRY_RUN: "yes" }), /DRY_RUN/);
  assert.throws(
    () => readDeleteOptions({ TEST_USERNAMES: "hs_test_01", DRY_RUN: "false" }),
    /ALLOW_DELETE_TEST_ACCOUNTS=I_HAVE_A_BACKUP/
  );
});

test("unapproved destructive execution stops before loading database configuration", () => {
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: apiDirectory,
    env: {
      ...process.env,
      TEST_USERNAMES: "hs_test_01",
      DRY_RUN: "false",
      ALLOW_DELETE_TEST_ACCOUNTS: "",
      DATABASE_URL: "",
      SESSION_SECRET: "must-not-be-printed"
    },
    encoding: "utf8"
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 1);
  assert.match(output, /ALLOW_DELETE_TEST_ACCOUNTS=I_HAVE_A_BACKUP/);
  assert.doesNotMatch(output, /DATABASE_URL|must-not-be-printed|SESSION_SECRET|password_hash|token/i);
});

test("dry-run reports related data and keeps associated or privileged accounts", async () => {
  const { client, statements } = installClient({
    accountCounts: {
      [accountIds.eligible]: { auth_sessions: 2 },
      [accountIds.member]: {
        class_memberships: 2,
        classes: 2,
        conduct_records: 3,
        points: 8,
        comments: 1,
        audit_logs: 1
      }
    }
  });
  const logger = createLogger();
  const result = await deleteTestAccounts(client, {
    usernames: ["hs_test_01", "hs_test_02", "gv_test_01", "super_test_01", "missing_test"],
    dryRun: true,
    logger
  });

  assert.equal(result.dryRun, true);
  assert.deepEqual(result.plannedCounts, { auth_sessions: 2, users: 1 });
  assert.deepEqual(result.reports.map(({ username, status }) => [username, status]), [
    ["hs_test_01", "would delete"],
    ["hs_test_02", "kept"],
    ["gv_test_01", "kept"],
    ["super_test_01", "kept"],
    ["missing_test", "not found"]
  ]);
  assert.deepEqual(result.reports[1].counts.conduct_records, 3);
  assert.deepEqual(result.reports[1].counts.classes, 2);
  assert.equal(statements[0].sql, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM")), false);
  assert.ok(logger.messages.some((message) => message.includes("Kept: protected Admin account")));
  assert.ok(logger.messages.some((message) => message.includes("Kept: protected Super Admin account")));
  assert.ok(logger.messages.some((message) => message.includes("has 3 related conduct_records")));
  assert.equal(logger.messages.some((message) => /password_hash|DATABASE_URL|SESSION_SECRET|must-not-be-printed/.test(message)), false);
});

test("real deletion revokes sessions before deleting only eligible allowlisted users", async () => {
  const { client, statements } = installClient({ accountCounts: { [accountIds.eligible]: { auth_sessions: 2 } } });
  const result = await deleteTestAccounts(client, {
    usernames: ["hs_test_01"],
    dryRun: false,
    logger: createLogger()
  });
  const sessionDeleteIndex = statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM auth_sessions"));
  const userDeleteIndex = statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM users"));

  assert.deepEqual(result.plannedCounts, { auth_sessions: 2, users: 1 });
  assert.deepEqual(result.deletedCounts, { auth_sessions: 2, users: 1 });
  assert.equal(result.reports[0].status, "deleted");
  assert.ok(statements.some(({ sql }) => sql.startsWith("LOCK TABLE users, class_members, auth_sessions, audit_logs, admin_permissions")));
  assert.ok(sessionDeleteIndex >= 0);
  assert.ok(userDeleteIndex > sessionDeleteIndex);
  assert.deepEqual(statements[userDeleteIndex].params, [[accountIds.eligible]]);
  assert.match(statements[userDeleteIndex].sql, /is_admin = FALSE/);
  assert.match(statements[userDeleteIndex].sql, /is_super_admin = FALSE/);
  assert.match(statements[userDeleteIndex].sql, /NOT EXISTS \(SELECT 1 FROM class_members/);
  assert.match(statements[userDeleteIndex].sql, /NOT EXISTS \([\s\S]*FROM audit_logs/);
  assert.equal(statements.at(-1).sql, "COMMIT");
});

test("deletion failures roll back without exposing database error details", async () => {
  const { client, statements } = installClient({
    accountCounts: { [accountIds.eligible]: { auth_sessions: 2 } },
    failOnDelete: "users"
  });
  const logger = createLogger();
  await assert.rejects(
    deleteTestAccounts(client, { usernames: ["hs_test_01"], dryRun: false, logger }),
    (error) => error.code === "23503" && error.message === "database detail must not be logged"
  );
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql === "COMMIT"), false);
  assert.equal(logger.messages.some((message) => message.includes("database detail must not be logged")), false);
});

test("failed account deletion rolls back if the account became ineligible", async () => {
  const { client, statements } = installClient({ accountCounts: { [accountIds.eligible]: { auth_sessions: 2 } } });
  const originalQuery = client.query;
  client.query = async (sql, params = []) => {
    if (sql.startsWith("DELETE FROM users")) return { rows: [], rowCount: 0 };
    return originalQuery(sql, params);
  };
  await assert.rejects(
    deleteTestAccounts(client, { usernames: ["hs_test_01"], dryRun: false, logger: createLogger() }),
    DeleteTestAccountsSafetyError
  );
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql === "COMMIT"), false);
});
