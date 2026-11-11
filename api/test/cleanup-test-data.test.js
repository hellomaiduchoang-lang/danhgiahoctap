import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cleanupNonAdminUsers } from "../src/scripts/cleanup-test-data.js";

const scriptPath = fileURLToPath(new URL("../src/scripts/cleanup-test-data.js", import.meta.url));
const apiDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const userIds = [
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002"
];
const foreignKeys = [
  ["auth_sessions", "user_id", "CASCADE"],
  ["class_members", "user_id", "CASCADE"],
  ["audit_logs", "actor_user_id", "SET NULL"],
  ["admin_permissions", "user_id", "CASCADE"],
  ["admin_permissions", "granted_by_user_id", "SET NULL"]
].map(([table_name, column_name, delete_action]) => ({
  schema_name: "public",
  table_name,
  column_name,
  delete_action
}));

function installClient({ memberships = 0, unknownForeignKey = false } = {}) {
  const statements = [];
  const users = userIds.map((id, index) => ({ id, username: `test.user${index + 1}` }));
  const client = {
    async query(sql, params = []) {
      statements.push({ sql, params });
      if (sql === "SELECT pg_advisory_xact_lock($1)") return { rows: [], rowCount: 1 };
      if (sql.includes("FROM pg_constraint")) {
        return {
          rows: unknownForeignKey
            ? [...foreignKeys, {
              schema_name: "public",
              table_name: "unknown_user_data",
              column_name: "user_id",
              delete_action: "CASCADE"
            }]
            : foreignKeys,
          rowCount: foreignKeys.length + Number(unknownForeignKey)
        };
      }
      if (sql.includes("to_regclass('users')")) return { rows: [{ schema_name: "public" }], rowCount: 1 };
      if (sql.includes("FOR UPDATE")) return { rows: users, rowCount: users.length };
      if (sql.includes("COUNT(*)::int AS count")) {
        if (sql.includes('"auth_sessions"')) return { rows: [{ count: 3 }], rowCount: 1 };
        if (sql.includes('"admin_permissions"')) return { rows: [{ count: 1 }], rowCount: 1 };
        if (sql.includes('"class_members"')) return { rows: [{ count: memberships }], rowCount: 1 };
        if (sql.includes('"audit_logs"')) return { rows: [{ count: 4 }], rowCount: 1 };
      }
      if (sql.includes("GROUP BY users.username")) {
        return {
          rows: memberships ? [{ username: "test.user1", membership_count: memberships }] : [],
          rowCount: memberships ? 1 : 0
        };
      }
      if (sql.startsWith('DELETE FROM "public"."auth_sessions"')) return { rows: [], rowCount: 3 };
      if (sql.startsWith('DELETE FROM "public"."admin_permissions"')) return { rows: [], rowCount: 1 };
      if (sql.startsWith('DELETE FROM "public"."users"')) return { rows: users.map(({ id }) => ({ id })), rowCount: users.length };
      return { rows: [], rowCount: 1 };
    }
  };
  return { client, statements };
}

function createLogger() {
  const messages = [];
  return {
    messages,
    info: (message) => messages.push(message),
    error: (message) => messages.push(message)
  };
}

test("cleanup refuses to start without the exact backup approval and never loads database configuration", () => {
  const env = { ...process.env, DRY_RUN: "true" };
  delete env.ALLOW_DESTRUCTIVE_CLEANUP;
  delete env.DATABASE_URL;
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: apiDirectory,
    env,
    encoding: "utf8"
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 1);
  assert.match(output, /ALLOW_DESTRUCTIVE_CLEANUP=YES_I_HAVE_A_BACKUP/);
  assert.doesNotMatch(output, /DATABASE_URL|password_hash|session token/i);
});

test("cleanup refuses non-boolean DRY_RUN settings before loading database configuration", () => {
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: apiDirectory,
    env: {
      ...process.env,
      ALLOW_DESTRUCTIVE_CLEANUP: "YES_I_HAVE_A_BACKUP",
      DRY_RUN: "yes",
      DATABASE_URL: ""
    },
    encoding: "utf8"
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 1);
  assert.match(output, /DRY_RUN must be exactly true or false/);
  assert.doesNotMatch(output, /DATABASE_URL|password_hash|session token/i);
});

test("DRY_RUN reports candidate users and counts, then rolls back without deleting rows", async () => {
  const { client, statements } = installClient();
  const logger = createLogger();
  const result = await cleanupNonAdminUsers(client, { dryRun: true, logger });

  assert.equal(result.dryRun, true);
  assert.deepEqual(result.counts, {
    auth_sessions: 3,
    admin_permissions: 1,
    class_members: 0,
    audit_logs_retained: 4,
    users: 2
  });
  assert.equal(logger.messages.includes("  test.user1"), true);
  assert.equal(logger.messages.includes("  test.user2"), true);
  assert.equal(statements.at(-1).sql, "ROLLBACK");
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM")), false);
});

test("cleanup deletes only safe non-admin account relations in foreign-key order", async () => {
  const { client, statements } = installClient();
  const logger = createLogger();
  const result = await cleanupNonAdminUsers(client, { dryRun: false, logger });
  const deleteStatements = statements.filter(({ sql }) => sql.startsWith("DELETE FROM"));

  assert.deepEqual(result.deletedCounts, {
    auth_sessions: 3,
    admin_permissions: 1,
    class_members: 0,
    audit_logs: 0,
    users: 2
  });
  assert.match(deleteStatements[0].sql, /auth_sessions/);
  assert.match(deleteStatements[1].sql, /admin_permissions/);
  assert.match(deleteStatements[2].sql, /users/);
  assert.match(deleteStatements[2].sql, /is_admin = FALSE/);
  assert.match(deleteStatements[2].sql, /is_super_admin = FALSE/);
  assert.equal(statements.at(-1).sql, "COMMIT");
  assert.match(logger.messages.at(-1), /4/);
});

test("cleanup stops and rolls back when class membership indicates related learning data", async () => {
  const { client, statements } = installClient({ memberships: 2 });
  const logger = createLogger();

  await assert.rejects(
    cleanupNonAdminUsers(client, { dryRun: false, logger }),
    /related class\/learning data exists for test\.user1 \(2 class_members\)/
  );
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM")), false);
  assert.equal(statements.at(-1).sql, "ROLLBACK");
});

test("cleanup stops and rolls back when the database has an unreviewed user foreign key", async () => {
  const { client, statements } = installClient({ unknownForeignKey: true });

  await assert.rejects(
    cleanupNonAdminUsers(client, { dryRun: false, logger: createLogger() }),
    /unreviewed public\.unknown_user_data\.user_id:CASCADE/
  );
  assert.equal(statements.some(({ sql }) => sql.startsWith("DELETE FROM")), false);
  assert.equal(statements.at(-1).sql, "ROLLBACK");
});
