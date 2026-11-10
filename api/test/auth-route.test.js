import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "postgresql://test:test@127.0.0.1:5432/test";
}

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

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
  let released = false;

  pool.query = async () => ({ rows: user ? [user] : [], rowCount: user ? 1 : 0 });
  pool.connect = async () => ({
    query: clientQuery,
    release: () => { released = true; }
  });

  return {
    wasReleased: () => released,
    restore() {
      if (hadOwnQuery) pool.query = originalQuery;
      else delete pool.query;
      if (hadOwnConnect) pool.connect = originalConnect;
      else delete pool.connect;
    }
  };
}

function authenticatedUser(overrides = {}) {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    username: "admin",
    isAdmin: true,
    isSuperAdmin: true,
    adminPermissions: [],
    mustChangePassword: false,
    ...overrides
  };
}

const adminCookie = `classtrack_session=${"a".repeat(64)}`;

test("POST /api/auth/login parses JSON and reaches the login handler", async () => {
  const server = app.listen(0, "127.0.0.1");

  try {
    await new Promise((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ab", password: "invalid" })
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      error: "Tên đăng nhập hoặc mật khẩu không hợp lệ.",
      code: "BAD_REQUEST"
    });

    const getResponse = await fetch(`http://127.0.0.1:${address.port}/api/auth/login`);
    assert.equal(getResponse.status, 404);
    assert.deepEqual(await getResponse.json(), {
      error: "API route not found.",
      code: "NOT_FOUND"
    });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("POST /api/admin/teachers creates hashed teacher accounts and returns frontend format", async () => {
  const userInserts = [];
  const queries = [];
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: false, adminPermissions: ["teachers:manage"] }),
    clientQuery: async (sql, params = []) => {
      queries.push(sql);
      if (sql.includes("INSERT INTO users")) {
        userInserts.push(params);
        return { rows: [{ id: `00000000-0000-4000-8000-${String(userInserts.length).padStart(12, "0")}` }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/teachers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ teachers: ["Nguyễn Minh An", "Trần Thị Bình"] })
      });

      assert.equal(response.status, 201);
      const result = await response.json();
      assert.deepEqual(result.accounts.map(({ fullName }) => fullName), ["Nguyễn Minh An", "Trần Thị Bình"]);
      assert.equal(result.accounts.length, 2);
      for (let index = 0; index < result.accounts.length; index++) {
        const account = result.accounts[index];
        const [username, passwordHash, fullName] = userInserts[index];
        assert.equal(account.username, username);
        assert.equal(account.fullName, fullName);
        assert.match(account.username, /^gv\.[a-z0-9.]+\.[a-f0-9]{16}$/);
        assert.equal(await bcrypt.compare(account.password, passwordHash), true);
        assert.equal(passwordHash.includes(account.password), false);
      }
      assert.ok(queries.includes("BEGIN"));
      assert.ok(queries.includes("COMMIT"));
      assert.ok(queries.some((sql) => sql.includes("INSERT INTO audit_logs")));
      assert.equal(database.wasReleased(), true);
    });
  } finally {
    database.restore();
  }
});

test("POST /api/admin/teachers rejects unauthenticated and unauthorized users", async () => {
  const database = installDatabaseMock({
    user: authenticatedUser({ isAdmin: false, isSuperAdmin: false, adminPermissions: [] })
  });

  try {
    await withServer(async (origin) => {
      const unauthenticated = await fetch(`${origin}/api/admin/teachers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ teachers: ["Nguyễn Minh An"] })
      });
      assert.equal(unauthenticated.status, 401);

      const unauthorized = await fetch(`${origin}/api/admin/teachers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ teachers: ["Nguyễn Minh An"] })
      });
      assert.equal(unauthorized.status, 403);
    });
  } finally {
    database.restore();
  }
});

test("POST /api/admin/teachers validates the frontend body", async () => {
  const database = installDatabaseMock({ user: authenticatedUser() });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/teachers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ teachers: ["", "A".repeat(121)] })
      });
      assert.equal(response.status, 400);
    });
  } finally {
    database.restore();
  }
});
