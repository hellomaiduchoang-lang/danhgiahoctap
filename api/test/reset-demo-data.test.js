import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readResetOptions, resetDemoData, ResetSafetyError } from "../src/scripts/reset-demo-data.js";

const scriptPath = fileURLToPath(new URL("../src/scripts/reset-demo-data.js", import.meta.url));
const apiDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const plannedCounts = {
  users: 4,
  teachers: 1,
  students: 3,
  classes: 2,
  class_members: 5,
  class_member_roles: 5,
  member_permissions: 1,
  role_requests: 1,
  class_groups: 1,
  group_members: 2,
  conduct_categories: 2,
  conduct_records: 4,
  evidence_files: 1,
  class_forum_posts: 1,
  class_weekly_point_scores: 2,
  class_weekly_point_periods: 1,
  auth_sessions: 6,
  audit_logs: 8,
  admin_permissions: 1
};

function installClient({ failOnDelete } = {}) {
  const statements = [];
  const client = {
    async query(sql, params = []) {
      statements.push({ sql, params });
      if (sql.startsWith("SELECT COUNT")) {
        let table;
        if (sql.includes("FROM users") && sql.includes("is_teacher = TRUE")) table = "teachers";
        else if (sql.includes("FROM users") && sql.includes("JOIN class_members")) table = "students";
        else if (sql.includes("FROM admin_permissions")) table = "admin_permissions";
        else table = sql.match(/FROM ([a-z_]+)/)?.[1];
        return { rows: [{ count: plannedCounts[table] || 0 }], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM")) {
        const table = sql.match(/DELETE FROM ([a-z_]+)/)?.[1];
        if (table === failOnDelete) {
          const error = new Error("constraint detail should not be printed");
          error.code = "23503";
          throw error;
        }
        return { rows: [], rowCount: table === "users" ? plannedCounts.users : plannedCounts[table] || 0 };
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

test("reset defaults to dry run and rejects invalid or unapproved destructive options", () => {
  assert.deepEqual(readResetOptions({}), { dryRun: true });
  assert.deepEqual(readResetOptions({ DRY_RUN: "true" }), { dryRun: true });
  assert.throws(() => readResetOptions({ DRY_RUN: "yes" }), /DRY_RUN must be exactly true or false/);
  assert.throws(
    () => readResetOptions({ DRY_RUN: "false", ALLOW_RESET: "no" }),
    /ALLOW_RESET=YES_I_HAVE_A_BACKUP/
  );
  assert.deepEqual(readResetOptions({
    DRY_RUN: "false",
    ALLOW_RESET: "YES_I_HAVE_A_BACKUP"
  }), { dryRun: false });
});

test("reset refuses destructive mode before loading database configuration without approval", () => {
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: apiDirectory,
    env: {
      ...process.env,
      DRY_RUN: "false",
      ALLOW_RESET: "",
      DATABASE_URL: ""
    },
    encoding: "utf8"
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 1);
  assert.match(output, /ALLOW_RESET=YES_I_HAVE_A_BACKUP/);
  assert.doesNotMatch(output, /DATABASE_URL|password_hash|SESSION_SECRET|cookie|token/i);
});

test("DRY_RUN counts planned deletions and rolls back without deleting data", async () => {
  const { client, statements } = installClient();
  const logger = createLogger();
  const result = await resetDemoData(client, { dryRun: true, logger });

  assert.equal(result.dryRun, true);
  assert.deepEqual(result.counts, plannedCounts);
  assert.equal(statements[0].sql, "BEGIN READ ONLY");
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM")), false);
  assert.equal(logger.messages.some((message) => message.includes("password_hash")), false);
});

test("destructive reset deletes known tables in foreign-key order and keeps admin accounts", async () => {
  const { client, statements } = installClient();
  const result = await resetDemoData(client, { dryRun: false, logger: createLogger() });
  const deletes = statements.filter(({ sql }) => sql.startsWith("DELETE FROM"));
  const deletedTables = deletes.map(({ sql }) => sql.match(/DELETE FROM ([a-z_]+)/)[1]);

  assert.equal(result.dryRun, false);
  assert.deepEqual(deletedTables, [
    "audit_logs",
    "auth_sessions",
    "admin_permissions",
    "evidence_files",
    "class_weekly_point_scores",
    "class_forum_posts",
    "conduct_records",
    "group_members",
    "class_member_roles",
    "member_permissions",
    "role_requests",
    "class_weekly_point_periods",
    "class_groups",
    "conduct_categories",
    "class_members",
    "classes",
    "users"
  ]);
  assert.match(deletes.at(-1).sql, /is_admin = FALSE/);
  assert.match(deletes.at(-1).sql, /is_super_admin = FALSE/);
  assert.equal(statements.at(-1).sql, "COMMIT");
  assert.equal(result.deletedCounts.users, plannedCounts.users);
});

test("any deletion failure rolls back the complete reset", async () => {
  const { client, statements } = installClient({ failOnDelete: "conduct_records" });

  await assert.rejects(
    resetDemoData(client, { dryRun: false, logger: createLogger() }),
    (error) => error.code === "23503" && !(error instanceof ResetSafetyError)
  );
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql === "COMMIT"), false);
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM classes")), false);
});
