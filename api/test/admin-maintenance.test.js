import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

const superAdminId = "00000000-0000-4000-8000-000000000001";
const accountIds = [
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003"
];
const adminCookie = `classtrack_session=${"f".repeat(64)}`;

async function withServer(handler) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  try {
    await handler(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
}

function installDatabaseMock({ user, clientQuery = async () => ({ rows: [], rowCount: 0 }) }) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  let connectionCount = 0;
  pool.query = async (sql, params = []) => {
    statements.push({ sql, params, type: "pool" });
    if (sql.includes("FROM auth_sessions")) return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    return { rows: [], rowCount: 0 };
  };
  pool.connect = async () => {
    connectionCount++;
    return {
      query: async (sql, params = []) => {
        statements.push({ sql, params, type: "client" });
        return clientQuery(sql, params);
      },
      release() {}
    };
  };
  return {
    statements,
    connectionCount: () => connectionCount,
    restore() {
      if (hadOwnQuery) pool.query = originalQuery;
      else delete pool.query;
      if (hadOwnConnect) pool.connect = originalConnect;
      else delete pool.connect;
    }
  };
}

function authenticatedUser({ isAdmin = true, isSuperAdmin = false } = {}) {
  return {
    id: superAdminId,
    username: isSuperAdmin ? "superadmin" : "admin",
    fullName: "Test Admin",
    isAdmin,
    isSuperAdmin,
    isTeacher: false,
    mustChangePassword: false,
    adminPermissions: []
  };
}

async function postDisableNonAdmins(origin, { cookie = adminCookie, confirmText = "DISABLE ALL NON-ADMINS" } = {}) {
  return fetch(`${origin}/api/admin/maintenance/disable-non-admins`, {
    method: "POST",
    headers: {
      ...(cookie ? { Cookie: cookie } : {}),
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ confirmText })
  });
}

test("disable-non-admins requires authentication and Super Admin", async () => {
  for (const { user, cookie, expectedStatus } of [
    { user: null, cookie: null, expectedStatus: 401 },
    { user: authenticatedUser(), cookie: adminCookie, expectedStatus: 403 }
  ]) {
    const database = installDatabaseMock({ user });
    try {
      await withServer(async (origin) => {
        const response = await postDisableNonAdmins(origin, { cookie });
        assert.equal(response.status, expectedStatus);
        assert.equal(database.connectionCount(), 0);
      });
    } finally {
      database.restore();
    }
  }
});

test("disable-non-admins requires the exact confirmation before opening a transaction", async () => {
  const database = installDatabaseMock({ user: authenticatedUser({ isSuperAdmin: true }) });
  try {
    await withServer(async (origin) => {
      const response = await postDisableNonAdmins(origin, { confirmText: "disable all non-admins" });
      assert.equal(response.status, 400);
      assert.equal(database.connectionCount(), 0);
    });
  } finally {
    database.restore();
  }
});

test("disable-non-admins is transactional, preserves admin and learning data, and audits the result", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: true }),
    clientQuery: async (sql, params = []) => {
      if (sql.startsWith("SELECT id FROM users")) return { rows: accountIds.map((id) => ({ id })), rowCount: accountIds.length };
      if (sql.startsWith("UPDATE users SET is_active")) {
        assert.deepEqual(params, [accountIds]);
        return { rows: [{ id: accountIds[0] }], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM auth_sessions")) {
        assert.deepEqual(params, [accountIds]);
        return { rows: [], rowCount: 2 };
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postDisableNonAdmins(origin);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { disabledCount: 1 });
      const statements = database.statements.filter(({ type }) => type === "client").map(({ sql }) => sql);
      assert.equal(statements[0], "BEGIN");
      assert.equal(statements.at(-1), "COMMIT");
      assert.equal(statements.some((sql) => sql.startsWith("DELETE FROM auth_sessions")), true);
      assert.equal(statements.some((sql) => sql.startsWith("INSERT INTO audit_logs")), true);
      assert.equal(statements.some((sql) => /DELETE\s+FROM\s+(users|class_members|classes|conduct_records|class_weekly_point_scores|class_forum_posts)/i.test(sql)), false);
      assert.equal(statements.some((sql) => /password_hash|token_hash/i.test(sql)), false);
      const accountQuery = database.statements.find(({ sql }) => sql.startsWith("SELECT id FROM users"));
      assert.match(accountQuery.sql, /is_admin = FALSE AND is_super_admin = FALSE/);
    });
  } finally {
    database.restore();
  }
});

test("disable-non-admins rolls back if the transaction fails", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: true }),
    clientQuery: async (sql) => {
      if (sql.startsWith("INSERT INTO audit_logs")) throw new Error("audit insert failed");
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postDisableNonAdmins(origin);
      assert.equal(response.status, 500);
      const statements = database.statements.filter(({ type }) => type === "client").map(({ sql }) => sql);
      assert.equal(statements[0], "BEGIN");
      assert.equal(statements.at(-1), "ROLLBACK");
    });
  } finally {
    database.restore();
  }
});
