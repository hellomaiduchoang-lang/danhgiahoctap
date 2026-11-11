import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

const adminId = "00000000-0000-4000-8000-000000000001";
const targetId = "00000000-0000-4000-8000-000000000002";
const adminCookie = `classtrack_session=${"d".repeat(64)}`;

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

function installDatabaseMock({
  user,
  clientQuery = async () => ({ rows: [], rowCount: 0 })
}) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  let connectionCount = 0;
  pool.query = async (sql, params = []) => {
    statements.push({ sql, params, type: "pool" });
    if (sql.includes("FROM auth_sessions")) {
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    }
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

function authenticatedUser({
  id = adminId,
  isAdmin = true,
  isSuperAdmin = false,
  adminPermissions = ["accounts:manage"]
} = {}) {
  return {
    id,
    username: isAdmin || isSuperAdmin ? "admin" : "teacher",
    fullName: "Test User",
    isAdmin,
    isSuperAdmin,
    isTeacher: !isAdmin && !isSuperAdmin,
    mustChangePassword: false,
    adminPermissions
  };
}

function targetAccount({
  id = targetId,
  isAdmin = false,
  isSuperAdmin = false,
  isActive = true
} = {}) {
  return { id, username: "student.test", is_admin: isAdmin, is_super_admin: isSuperAdmin, is_active: isActive };
}

async function patchStatus(origin, userId = targetId, body = {
  isActive: false,
  confirmText: "DISABLE ACCOUNT"
}, cookie = adminCookie) {
  return fetch(`${origin}/api/admin/users/${userId}/status`, {
    method: "PATCH",
    headers: {
      ...(cookie ? { Cookie: cookie } : {}),
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
}

test("account status endpoint returns 401 without a session", async () => {
  const database = installDatabaseMock({});
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, targetId, { isActive: false, confirmText: "DISABLE ACCOUNT" }, null);
      assert.equal(response.status, 401);
      assert.equal(database.connectionCount(), 0);
    });
  } finally {
    database.restore();
  }
});

test("teachers and admins without accounts:manage receive 403", async () => {
  for (const user of [
    authenticatedUser({ isAdmin: false, isSuperAdmin: false, adminPermissions: [] }),
    authenticatedUser({ isAdmin: true, isSuperAdmin: false, adminPermissions: [] })
  ]) {
    const database = installDatabaseMock({ user });
    try {
      await withServer(async (origin) => {
        const response = await patchStatus(origin);
        assert.equal(response.status, 403);
        assert.equal(database.connectionCount(), 0);
      });
    } finally {
      database.restore();
    }
  }
});

test("invalid user ID or confirmation returns 400", async () => {
  const database = installDatabaseMock({ user: authenticatedUser() });
  try {
    await withServer(async (origin) => {
      const invalidId = await patchStatus(origin, "student.test");
      assert.equal(invalidId.status, 400);
      const invalidConfirmation = await patchStatus(origin, targetId, {
        isActive: false,
        confirmText: "disable account"
      });
      assert.equal(invalidConfirmation.status, 400);
      assert.equal(database.connectionCount(), 0);
    });
  } finally {
    database.restore();
  }
});

test("disabling an account requires only the exact DISABLE ACCOUNT confirmation", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql, params = []) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        assert.deepEqual(params, [targetId]);
        return { rows: [targetAccount()], rowCount: 1 };
      }
      if (sql.startsWith("UPDATE users SET is_active")) {
        assert.deepEqual(params, [targetId, false]);
        return { rows: [{ id: targetId, username: "student.test", is_active: false }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, targetId, {
        isActive: false,
        confirmText: "DISABLE ACCOUNT"
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { userId: targetId, isActive: false, revokedSessions: 1 });
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
    });
  } finally {
    database.restore();
  }
});

test("account status endpoint returns 404 for an unknown account", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql) => sql.includes("FROM users WHERE id = $1 FOR UPDATE")
      ? { rows: [], rowCount: 0 }
      : { rows: [], rowCount: 0 }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin);
      assert.equal(response.status, 404);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), true);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("UPDATE users")), false);
    });
  } finally {
    database.restore();
  }
});

test("deactivation requires a typed confirmation before disabling the current account", async () => {
  const database = installDatabaseMock({ user: authenticatedUser() });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, adminId, { isActive: false });
      assert.equal(response.status, 400);
      assert.equal(database.connectionCount(), 0);
    });
  } finally {
    database.restore();
  }
});

test("only Super Admin can change a Super Admin account status", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql) => sql.includes("FROM users WHERE id = $1 FOR UPDATE")
      ? { rows: [targetAccount({ isAdmin: true, isSuperAdmin: true })], rowCount: 1 }
      : { rows: [], rowCount: 0 }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin);
      assert.equal(response.status, 403);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("UPDATE users")), false);
    });
  } finally {
    database.restore();
  }
});

test("the last active Super Admin cannot be deactivated", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: true }),
    clientQuery: async (sql) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [targetAccount({ id: adminId, isAdmin: true, isSuperAdmin: true })], rowCount: 1 };
      }
      if (sql.includes("COUNT(*)::INT AS count FROM users WHERE is_super_admin")) {
        return { rows: [{ count: 1 }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, adminId);
      assert.equal(response.status, 409);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("UPDATE users")), false);
    });
  } finally {
    database.restore();
  }
});

test("deactivation updates is_active, revokes sessions, and writes audit in one transaction", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql, params = []) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [targetAccount()], rowCount: 1 };
      }
      if (sql.startsWith("UPDATE users SET is_active")) {
        assert.equal(params[0], targetId);
        assert.equal(params[1], false);
        return { rows: [{ id: targetId, username: "student.test", is_active: false }], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM auth_sessions")) return { rows: [], rowCount: 2 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin);
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.deepEqual(body, { userId: targetId, isActive: false, revokedSessions: 2 });
      assert.equal(JSON.stringify(body).includes("password"), false);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO audit_logs")), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM class_members")), false);
    });
  } finally {
    database.restore();
  }
});

test("a confirmed current Admin may disable their own account when another active Admin remains", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql, params = []) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [targetAccount({ id: adminId, isAdmin: true })], rowCount: 1 };
      }
      if (sql.startsWith("UPDATE users SET is_active")) {
        assert.equal(params[0], adminId);
        return { rows: [{ id: adminId, username: "admin", is_active: false }], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM auth_sessions")) return { rows: [], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, adminId);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { userId: adminId, isActive: false, revokedSessions: 1 });
    });
  } finally {
    database.restore();
  }
});

test("a confirmed request restores an account without deleting class or learning records", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: true }),
    clientQuery: async (sql, params = []) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [targetAccount({ isActive: false })], rowCount: 1 };
      }
      if (sql.startsWith("UPDATE users SET is_active")) {
        assert.equal(params[1], true);
        return { rows: [{ id: targetId, username: "student.test", is_active: true }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin, targetId, {
        isActive: true,
        confirmText: "ENABLE ACCOUNT"
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { userId: targetId, isActive: true, revokedSessions: 0 });
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM auth_sessions")), false);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM class_members")), false);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM conduct_records")), false);
    });
  } finally {
    database.restore();
  }
});

test("predictable database constraints return 409 and roll back", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql) => {
      if (sql.includes("FROM users WHERE id = $1 FOR UPDATE")) {
        return { rows: [targetAccount()], rowCount: 1 };
      }
      if (sql.startsWith("UPDATE users")) {
        const error = new Error("constraint");
        error.code = "23514";
        throw error;
      }
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await patchStatus(origin);
      assert.equal(response.status, 409);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal((await response.json()).error.includes("constraint"), false);
    });
  } finally {
    database.restore();
  }
});
