import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

const adminId = "00000000-0000-4000-8000-000000000001";
const classId = "00000000-0000-4000-8000-000000000010";
const adminCookie = `classtrack_session=${"e".repeat(64)}`;

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

function installDatabaseMock({ user, poolQuery, clientQuery = async () => ({ rows: [], rowCount: 0 }) }) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  pool.query = async (sql, params = []) => {
    statements.push({ sql, params, type: "pool" });
    if (sql.includes("FROM auth_sessions")) return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    return poolQuery(sql, params);
  };
  pool.connect = async () => ({
    query: async (sql, params = []) => {
      statements.push({ sql, params, type: "client" });
      return clientQuery(sql, params);
    },
    release() {}
  });
  return {
    statements,
    restore() {
      if (hadOwnQuery) pool.query = originalQuery;
      else delete pool.query;
      if (hadOwnConnect) pool.connect = originalConnect;
      else delete pool.connect;
    }
  };
}

function adminUser() {
  return {
    id: adminId,
    username: "admin",
    fullName: "Admin",
    isAdmin: true,
    isSuperAdmin: false,
    isTeacher: false,
    mustChangePassword: false,
    adminPermissions: ["accounts:manage"]
  };
}

test("GET /api/admin/users filters and paginates without exposing secrets", async () => {
  const database = installDatabaseMock({
    user: adminUser(),
    poolQuery: async (sql) => {
      if (sql.includes("COUNT(*)::INT AS total")) return { rows: [{ total: 61 }], rowCount: 1 };
      return {
        rows: [{
          id: "00000000-0000-4000-8000-000000000002",
          username: "student.ada",
          fullName: "Ada Student",
          isActive: false,
          isAdmin: false,
          isSuperAdmin: false,
          type: "teacher",
          createdAt: "2026-01-01T00:00:00.000Z",
          classCount: 2,
          relatedRecordCount: 3
        }],
        rowCount: 1
      };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(
        `${origin}/api/admin/users?search=ada&role=teacher&status=inactive&classId=${classId}&from=2026-01-01&to=2026-01-31&page=2&pageSize=50`,
        { headers: { Cookie: adminCookie } }
      );
      assert.equal(response.status, 200);
      const result = await response.json();
      assert.equal(result.total, 61);
      assert.equal(result.page, 2);
      assert.equal(result.pageSize, 50);
      assert.equal(result.totalPages, 2);
      assert.equal(result.users.length, 1);
      assert.equal(JSON.stringify(result).includes("password_hash"), false);
      const count = database.statements.find(({ sql }) => sql.includes("COUNT(*)::INT AS total"));
      assert.match(count.sql, /users\.username ILIKE \$1/);
      assert.equal(count.params.includes("%ada%"), true);
      assert.equal(count.params.includes(classId), true);
      const pageQuery = database.statements.find(({ sql }) => sql.includes("FROM users") && sql.includes("LIMIT"));
      assert.equal(pageQuery.params.at(-2), 50);
      assert.equal(pageQuery.params.at(-1), 50);
    });
  } finally {
    database.restore();
  }
});

test("GET /api/admin/users rejects page sizes above 100", async () => {
  const database = installDatabaseMock({
    user: adminUser(),
    poolQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/users?pageSize=101`, {
        headers: { Cookie: adminCookie }
      });
      assert.equal(response.status, 400);
      assert.equal(database.statements.some(({ sql }) => sql.includes("COUNT(*)::INT AS total")), false);
    });
  } finally {
    database.restore();
  }
});

test("Admin class status changes are transactional and preserve related data", async () => {
  const database = installDatabaseMock({
    user: adminUser(),
    poolQuery: async () => ({ rows: [], rowCount: 0 }),
    clientQuery: async (sql, params = []) => {
      if (sql.startsWith("UPDATE classes SET is_active")) {
        assert.deepEqual(params, [classId, false]);
        return {
          rows: [{ id: classId, class_code: "C-01", class_name: "Test", is_active: false }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}/status`, {
        method: "PATCH",
        headers: { Cookie: adminCookie, "Content-Type": "application/json" },
        body: JSON.stringify({ isActive: false, confirmText: "DISABLE CLASS" })
      });
      assert.equal(response.status, 200);
      assert.equal((await response.json()).class.is_active, false);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), true);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE ")), false);
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO audit_logs")), true);
    });
  } finally {
    database.restore();
  }
});
