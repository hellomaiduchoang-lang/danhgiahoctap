import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

const classId = "00000000-0000-4000-8000-000000000010";
const studentMemberId = "00000000-0000-4000-8000-000000000020";
const categoryId = "00000000-0000-4000-8000-000000000030";
const recordId = "00000000-0000-4000-8000-000000000040";
const sessionCookie = `classtrack_session=${"e".repeat(64)}`;

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
  user = teacher(),
  access = { member_id: "00000000-0000-4000-8000-000000000011", roles: ["ROLE_TEACHER"], permissions: ["classes:read", "conduct:create", "conduct:view_all"] },
  poolQuery = async () => ({ rows: [], rowCount: 0 }),
  clientQuery = async () => ({ rows: [], rowCount: 0 })
} = {}) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  pool.query = async (sql, params = []) => {
    statements.push({ sql, params, type: "pool" });
    if (sql.includes("FROM auth_sessions")) return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    if (sql.includes("FROM class_members") && sql.includes("WHERE class_members.user_id")) {
      return { rows: access ? [access] : [], rowCount: access ? 1 : 0 };
    }
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

function teacher() {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    username: "teacher",
    fullName: "Test Teacher",
    isAdmin: false,
    isSuperAdmin: false,
    isTeacher: true,
    mustChangePassword: false,
    adminPermissions: []
  };
}

function admin() {
  return {
    ...teacher(),
    username: "admin",
    isAdmin: true,
    isTeacher: false
  };
}

function requestHeaders() {
  return { Cookie: sessionCookie, "Content-Type": "application/json" };
}

function pointBody(overrides = {}) {
  return {
    studentId: "HS001",
    categoryId,
    description: "Test point record",
    date: "2026-11-13",
    source: "Teacher",
    evidenceName: "",
    weekNumber: 46,
    schoolYear: "2026-2027",
    ...overrides
  };
}

async function postRecord(origin, body, headers = requestHeaders()) {
  return fetch(`${origin}/api/classes/${classId}/conduct-records`, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });
}

test("conduct score entry saves a valid week and school year", async () => {
  const database = installDatabaseMock({
    clientQuery: async (sql) => {
      if (sql.includes("FROM conduct_categories")) {
        return { rows: [{ id: categoryId, name: "Chăm học", kind: "positive", points: 2 }], rowCount: 1 };
      }
      if (sql.includes("FROM class_members") && sql.includes("users.student_number")) {
        return { rows: [{ id: studentMemberId }], rowCount: 1 };
      }
      if (sql.includes("SELECT 1 FROM conduct_records")) return { rows: [], rowCount: 0 };
      if (sql.includes("INSERT INTO conduct_records")) return { rows: [{ id: recordId }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postRecord(origin, pointBody());
      assert.equal(response.status, 201);
      assert.deepEqual(await response.json(), {
        id: recordId, status: "pending", weekNumber: 46, schoolYear: "2026-2027"
      });
      const insert = database.statements.find(({ sql }) => sql.includes("INSERT INTO conduct_records"));
      assert.match(insert.sql, /week_number, school_year/);
      assert.equal(insert.params[12], 46);
      assert.equal(insert.params[13], "2026-2027");
    });
  } finally {
    database.restore();
  }
});

test("conduct score entry rejects a missing week and out-of-range weeks", async () => {
  const database = installDatabaseMock();
  try {
    await withServer(async (origin) => {
      for (const body of [
        pointBody({ weekNumber: undefined }),
        pointBody({ weekNumber: 0 }),
        pointBody({ weekNumber: 54 })
      ]) {
        const response = await postRecord(origin, body);
        assert.equal(response.status, 400);
      }
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("conduct score entry rejects a duplicate student, class, week, and school year", async () => {
  const database = installDatabaseMock({
    clientQuery: async (sql) => {
      if (sql.includes("FROM conduct_categories")) {
        return { rows: [{ id: categoryId, name: "Chăm học", kind: "positive", points: 2 }], rowCount: 1 };
      }
      if (sql.includes("FROM class_members") && sql.includes("users.student_number")) {
        return { rows: [{ id: studentMemberId }], rowCount: 1 };
      }
      if (sql.includes("SELECT 1 FROM conduct_records")) return { rows: [{ "?column?": 1 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postRecord(origin, pointBody());
      assert.equal(response.status, 409);
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO conduct_records")), false);
    });
  } finally {
    database.restore();
  }
});

test("teachers cannot enter scores for a class they are not assigned to", async () => {
  const database = installDatabaseMock({
    access: null,
    poolQuery: async (sql) => sql.includes("FROM classes WHERE id = $1 AND is_active = TRUE")
      ? { rows: [{ "?column?": 1 }], rowCount: 1 }
      : { rows: [], rowCount: 0 }
  });
  try {
    await withServer(async (origin) => {
      const response = await postRecord(origin, pointBody());
      assert.equal(response.status, 403);
    });
  } finally {
    database.restore();
  }
});

test("conduct records can be filtered by week", async () => {
  let conductQuery;
  const database = installDatabaseMock({
    poolQuery: async (sql, params) => {
      if (sql.includes("FROM conduct_records") && sql.includes("ORDER BY conduct_records.record_date")) {
        conductQuery = { sql, params };
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/${classId}/conduct-records?weekNumber=12`, {
        headers: { Cookie: sessionCookie }
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { incidents: [] });
      assert.match(conductQuery.sql, /conduct_records\.week_number = \$2/);
      assert.deepEqual(conductQuery.params, [classId, 12]);
    });
  } finally {
    database.restore();
  }
});

test("conduct score entry requires authentication", async () => {
  const database = installDatabaseMock({ user: null });
  try {
    await withServer(async (origin) => {
      const response = await postRecord(origin, pointBody(), { "Content-Type": "application/json" });
      assert.equal(response.status, 401);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("Admin can filter conduct records by class, week, school year, and student", async () => {
  let conductQuery;
  const database = installDatabaseMock({
    user: admin(),
    poolQuery: async (sql, params) => {
      if (sql.includes("FROM conduct_records") && sql.includes("ORDER BY conduct_records.record_date")) {
        conductQuery = { sql, params };
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const query = new URLSearchParams({
        classId, weekNumber: "12", schoolYear: "2026-2027", studentId: "HS001"
      });
      const response = await fetch(`${origin}/api/admin/conduct-records?${query}`, {
        headers: { Cookie: sessionCookie }
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { records: [] });
      assert.match(conductQuery.sql, /conduct_records\.class_id = \$1/);
      assert.match(conductQuery.sql, /conduct_records\.week_number = \$2/);
      assert.match(conductQuery.sql, /conduct_records\.school_year = \$3/);
      assert.match(conductQuery.sql, /student\.student_number = \$4/);
      assert.deepEqual(conductQuery.params, [classId, 12, "2026-2027", "HS001"]);
    });
  } finally {
    database.restore();
  }
});

test("Admin can edit a complete conduct score record", async () => {
  const database = installDatabaseMock({
    user: admin(),
    clientQuery: async (sql) => {
      if (sql.includes("SELECT class_id, category_id, title, kind, points FROM conduct_records")) {
        return { rows: [{ class_id: classId, category_id: categoryId, title: "Chăm học", kind: "positive", points: 2 }], rowCount: 1 };
      }
      if (sql.includes("FROM class_members") && sql.includes("users.student_number")) {
        return { rows: [{ id: studentMemberId }], rowCount: 1 };
      }
      if (sql.includes("FROM conduct_categories")) {
        return { rows: [{ id: categoryId, name: "Chăm học", kind: "positive", points: 2 }], rowCount: 1 };
      }
      if (sql.includes("SELECT 1 FROM conduct_records")) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/conduct-records/${recordId}`, {
        method: "PUT",
        headers: requestHeaders(),
        body: JSON.stringify({
          ...pointBody(),
          status: "verified"
        })
      });
      const body = await response.json();
      assert.equal(response.status, 200, `${JSON.stringify(body)} ${JSON.stringify(database.statements.map(({ sql }) => sql))}`);
      assert.deepEqual(body, {
        id: recordId, status: "verified", weekNumber: 46, schoolYear: "2026-2027"
      });
      assert.ok(database.statements.some(({ sql }) => sql.includes("UPDATE conduct_records")));
      assert.ok(database.statements.some(({ sql, params }) =>
        sql.includes("INSERT INTO audit_logs") && params.includes("conduct.admin_updated")));
    });
  } finally {
    database.restore();
  }
});
