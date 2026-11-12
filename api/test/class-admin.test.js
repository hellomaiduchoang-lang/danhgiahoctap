import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");

const classId = "00000000-0000-4000-8000-000000000010";
const adminCookie = `classtrack_session=${"c".repeat(64)}`;

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

function installDatabaseMock({ user, poolQuery = async () => ({ rows: [], rowCount: 0 }), clientQuery = async () => ({ rows: [], rowCount: 0 }) }) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  pool.query = async (sql, params = []) => {
    statements.push({ sql, params, type: "pool" });
    if (sql.includes("FROM auth_sessions")) {
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
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

function account({ isAdmin, isSuperAdmin = false } = {}) {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    username: isAdmin ? "admin" : "teacher",
    fullName: isAdmin ? "Class Admin" : "Class Teacher",
    isAdmin,
    isSuperAdmin,
    isTeacher: !isAdmin && !isSuperAdmin,
    mustChangePassword: false,
    adminPermissions: []
  };
}

function classRecord() {
  return {
    id: classId,
    class_code: "TEST-01",
    class_name: "Test Class",
    academic_year: "2026-2027"
  };
}

function relatedCounts() {
  return {
    memberships: 3,
    students: 2,
    teachers: 1,
    shared_users: 1,
    accounts_to_delete: 2,
    teachers_to_delete: 1,
    students_to_delete: 1,
    member_roles: 3,
    member_permissions: 0,
    role_requests: 1,
    groups: 1,
    group_members: 2,
    conduct_categories: 2,
    conduct_records: 4,
    positive_records: 2,
    violations: 2,
    positive_points: 10,
    negative_points: 3,
    evidence_files: 1,
    forum_posts: 1,
    weekly_periods: 1,
    weekly_scores: 2,
    retained_audit_logs: 5
  };
}

function requestHeaders(cookie) {
  return cookie ? { Cookie: cookie } : {};
}

test("class admin endpoints reject unauthenticated callers", async () => {
  const database = installDatabaseMock({});
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes`);
      assert.equal(response.status, 401);
      const deleteResponse = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "DELETE CLASS" })
      });
      assert.equal(deleteResponse.status, 401);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("class admin endpoints reject teachers", async () => {
  const database = installDatabaseMock({ user: account({ isAdmin: false }) });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}/preview`, {
        headers: requestHeaders(adminCookie)
      });
      assert.equal(response.status, 403);
      const deleteResponse = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "DELETE CLASS" })
      });
      assert.equal(deleteResponse.status, 403);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("Admin class list returns class identifiers and member counts", async () => {
  const classes = [{
    id: classId,
    class_code: "TEST-01",
    class_name: "Test Class",
    student_count: 2,
    teacher_count: 1
  }];
  const database = installDatabaseMock({
    user: account({ isAdmin: false, isSuperAdmin: true }),
    poolQuery: async (sql) => sql.includes("AS teacher_count")
      ? { rows: classes, rowCount: 1 }
      : { rows: [], rowCount: 0 }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes`, {
        headers: requestHeaders(adminCookie)
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { classes });
    });
  } finally {
    database.restore();
  }
});

test("Admin class detail includes assigned teachers and status without sensitive user fields", async () => {
  const detail = {
    id: classId,
    class_code: "TEST-01",
    class_name: "Test Class",
    academic_year: "2026-2027",
    is_active: true,
    teachers: [{ id: "00000000-0000-4000-8000-000000000030", username: "teacher.one", fullName: "Teacher One" }],
    studentCount: 2
  };
  const database = installDatabaseMock({
    user: account({ isAdmin: true }),
    poolQuery: async (sql) => sql.includes("jsonb_build_object")
      ? { rows: [detail], rowCount: 1 }
      : { rows: [], rowCount: 0 }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        headers: requestHeaders(adminCookie)
      });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.deepEqual(body.class, detail);
      assert.equal(JSON.stringify(body).includes("password_hash"), false);
    });
  } finally {
    database.restore();
  }
});

test("ordinary Admin cannot permanently delete a class", async () => {
  const database = installDatabaseMock({ user: account({ isAdmin: true }) });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmClassCode: "TEST-01", confirmText: "DELETE CLASS" })
      });
      assert.equal(response.status, 403);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("Admin can preview class data without deleting anything", async () => {
  const database = installDatabaseMock({
    user: account({ isAdmin: true }),
    poolQuery: async (sql) => {
      if (sql.includes("FROM classes WHERE id = $1")) return { rows: [classRecord()], rowCount: 1 };
      if (sql.includes("AS retained_audit_logs")) return { rows: [relatedCounts()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}/deletion-preview`, {
        headers: requestHeaders(adminCookie)
      });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.deepEqual(body.class, classRecord());
      assert.equal(body.relatedCounts.students, 2);
      assert.equal(body.relatedCounts.violations, 2);
      assert.equal(body.relatedCounts.weekly_scores, 2);
      assert.equal(body.relatedCounts.accounts_to_delete, 2);
      assert.equal(body.relatedCounts.shared_users, 1);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE ")), false);
    });
  } finally {
    database.restore();
  }
});

test("class deletion requires only the exact DELETE CLASS confirmation", async () => {
  const database = installDatabaseMock({
    user: account({ isAdmin: true, isSuperAdmin: true }),
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "delete class" })
      });
      assert.equal(response.status, 400);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE ")), false);
    });
  } finally {
    database.restore();
  }
});

test("Super Admin can delete a class without a class code and only remove accounts exclusive to it", async () => {
  const orphanStudentId = "00000000-0000-4000-8000-000000000040";
  const database = installDatabaseMock({
    user: account({ isAdmin: false, isSuperAdmin: true }),
    clientQuery: async (sql) => {
      if (sql.includes("FROM classes WHERE id = $1 FOR UPDATE")) return { rows: [{ ...classRecord(), class_code: null }], rowCount: 1 };
      if (sql.includes("SELECT class_members.id FROM class_members")) return { rows: [], rowCount: 3 };
      if (sql.includes("SELECT DISTINCT users.id")) {
        assert.match(sql, /users\.is_admin = FALSE/);
        assert.match(sql, /users\.is_super_admin = FALSE/);
        assert.match(sql, /other_memberships\.class_id <> \$1/);
        return { rows: [{ id: orphanStudentId }], rowCount: 1 };
      }
      if (sql.includes("AS count")) return { rows: [{ count: 2 }], rowCount: 1 };
      if (sql.startsWith("DELETE FROM users")) {
        assert.deepEqual(sql && database.statements.at(-1).params, [[orphanStudentId]]);
        return { rows: [{ id: orphanStudentId }], rowCount: 1 };
      }
      if (sql.startsWith("DELETE FROM classes")) return { rows: [{ id: classId }], rowCount: 1 };
      if (sql.startsWith("DELETE ")) return { rows: [], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "DELETE CLASS" })
      });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.deepEqual(body.deletedClass, {
        id: classId,
        class_code: null,
        class_name: "Test Class"
      });
      assert.equal(body.deletedAccounts, 1);
      assert.equal(body.keptSharedUsers, 2);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
      const auditStatements = database.statements.filter(({ sql }) => sql.includes("INSERT INTO audit_logs"));
      assert.equal(auditStatements.length, 2);
      assert.ok(database.statements.findIndex(({ sql }) => sql.includes("INSERT INTO audit_logs")) <
        database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM conduct_records")));
      assert.ok(database.statements.findLastIndex(({ sql }) => sql.includes("INSERT INTO audit_logs")) >
        database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM classes")));
      const userDelete = database.statements.find(({ sql }) => sql.startsWith("DELETE FROM users"));
      assert.match(userDelete.sql, /is_admin = FALSE/);
      assert.match(userDelete.sql, /is_super_admin = FALSE/);
      assert.equal(database.statements.find(({ sql }) => sql.includes("DELETE FROM auth_sessions")).params[0][0], orphanStudentId);
      assert.ok(database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM class_members")) >
        database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM conduct_records")));
      assert.ok(database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM classes")) >
        database.statements.findIndex(({ sql }) => sql.startsWith("DELETE FROM users")));
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM audit_logs")), false);
    });
  } finally {
    database.restore();
  }
});

test("class deletion rolls back when a relation delete fails", async () => {
  const database = installDatabaseMock({
    user: account({ isAdmin: true, isSuperAdmin: true }),
    clientQuery: async (sql) => {
      if (sql.includes("FROM classes WHERE id = $1 FOR UPDATE")) return { rows: [classRecord()], rowCount: 1 };
      if (sql.includes("SELECT DISTINCT users.id")) return { rows: [], rowCount: 0 };
      if (sql.includes("AS count")) return { rows: [{ count: 0 }], rowCount: 1 };
      if (sql.includes("DELETE FROM conduct_records")) {
        const error = new Error("relation delete failed");
        error.code = "XX000";
        throw error;
      }
      if (sql.startsWith("DELETE ")) return { rows: [], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "DELETE CLASS" })
      });
      assert.equal(response.status, 500);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("DELETE FROM classes")), false);
    });
  } finally {
    database.restore();
  }
});

test("class deletion returns 409 and rolls back when a foreign key prevents safe deletion", async () => {
  const database = installDatabaseMock({
    user: account({ isAdmin: false, isSuperAdmin: true }),
    clientQuery: async (sql) => {
      if (sql.includes("FROM classes WHERE id = $1 FOR UPDATE")) return { rows: [classRecord()], rowCount: 1 };
      if (sql.startsWith("DELETE FROM conduct_records")) {
        const error = new Error("foreign key constraint");
        error.code = "23503";
        throw error;
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/admin/classes/${classId}`, {
        method: "DELETE",
        headers: { ...requestHeaders(adminCookie), "Content-Type": "application/json" },
        body: JSON.stringify({ confirmText: "DELETE CLASS" })
      });
      assert.equal(response.status, 409);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), false);
    });
  } finally {
    database.restore();
  }
});
