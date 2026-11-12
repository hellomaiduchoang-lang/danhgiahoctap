import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import * as XLSX from "@e965/xlsx";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = "postgres://localhost/classtrack_test";

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");
const teacherCookie = `classtrack_session=${"b".repeat(64)}`;
const teacherId = "00000000-0000-4000-8000-000000000001";
const classId = "00000000-0000-4000-8000-000000000010";
const studentMemberId = "00000000-0000-4000-8000-000000000020";

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

function installDatabaseMock({ poolQuery, clientQuery }) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  const statements = [];
  pool.query = async (sql, params) => {
    statements.push({ sql, params, type: "pool" });
    return poolQuery(sql, params);
  };
  pool.connect = async () => ({
    query: async (sql, params) => {
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

function authenticatedTeacherQuery(sql) {
  if (sql.includes("FROM auth_sessions")) {
    return {
      rows: [{
        id: teacherId,
        username: "teacher",
        isAdmin: false,
        isSuperAdmin: false,
        isTeacher: true,
        mustChangePassword: false,
        adminPermissions: []
      }],
      rowCount: 1
    };
  }
  return { rows: [], rowCount: 0 };
}

function spreadsheetBuffer(records, bookType = "xlsx") {
  const workbook = XLSX.utils.book_new();
  const sheet = XLSX.utils.aoa_to_sheet([
    ["username", "full_name", "student_code", "class_code", "password"],
    ...records
  ]);
  XLSX.utils.book_append_sheet(workbook, sheet, "Students");
  return XLSX.write(workbook, { type: "buffer", bookType });
}

async function postImport(origin, buffer, filename = "students.xlsx", cookie = teacherCookie) {
  const form = new FormData();
  form.append("file", new Blob([buffer]), filename);
  return fetch(`${origin}/api/teacher/students/import`, {
    method: "POST",
    headers: cookie ? { Cookie: cookie } : {},
    body: form
  });
}

function classLookup(roles = ["ROLE_TEACHER"], permissions = ["students:list"]) {
  return {
    id: classId,
    classCode: "C-01",
    teacherMemberId: "00000000-0000-4000-8000-000000000030",
    roles,
    permissions
  };
}

test("Excel import creates a student with a bcrypt hash and no password in the report", async () => {
  const password = "Strong-password-123";
  const database = installDatabaseMock({
    poolQuery: async (sql, params = []) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql, params = []) => {
      if (sql.includes("INSERT INTO users")) {
        assert.equal(params[0], "student.one");
        assert.equal(params[3], "HS100");
        assert.notEqual(params[1], password);
        assert.equal(await bcrypt.compare(password, params[1]), true);
        assert.match(sql, /TRUE,\s*FALSE,\s*FALSE,\s*FALSE,\s*TRUE/);
        return { rows: [{ id: "00000000-0000-4000-8000-000000000040" }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_members")) return { rows: [{ id: studentMemberId }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_member_roles")) return { rows: [{ id: 1 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        [" Student.One ", "Nguyễn Văn An", " hs100 ", "C-01", password]
      ]));
      assert.equal(response.status, 200);
      const report = await response.json();
      assert.deepEqual(report, { created: 1, skipped: 0, failed: 0, errors: [] });
      assert.equal(JSON.stringify(report).includes(password), false);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO audit_logs")), true);
    });
  } finally {
    database.restore();
  }
});

test("Excel import accepts legacy XLS workbooks", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql.includes("INSERT INTO users")) return { rows: [{ id: "00000000-0000-4000-8000-000000000044" }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_members")) return { rows: [{ id: studentMemberId }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_member_roles")) return { rows: [{ id: 1 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["xls.student", "Lê Văn Nam", "HS109", "C-01", "Some-password"]
      ], "xls"), "students.xls");
      assert.equal(response.status, 200);
      assert.equal((await response.json()).created, 1);
    });
  } finally {
    database.restore();
  }
});

test("Excel import skips a username or student-code collision in the database", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql, params = []) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      if (sql.includes("SELECT username, student_number")) {
        assert.match(sql, /UPPER\(student_number\) = ANY/);
        assert.deepEqual(params[1], ["HS102"]);
        return { rows: [{ username: "existing.other", student_number: "hs102" }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async () => ({ rows: [], rowCount: 1 })
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["new.student", "Trần Thị Bình", " hs102 ", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 200);
      const report = await response.json();
      assert.equal(report.created, 0);
      assert.equal(report.skipped, 1);
      assert.equal(report.errors[0].code, "DUPLICATE_IN_DATABASE");
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO users")), false);
    });
  } finally {
    database.restore();
  }
});

test("Excel import reports a duplicate detected during INSERT instead of failing the request", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql.includes("INSERT INTO users")) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["raced.student", "Raced Student", "HS105", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), {
        created: 0,
        skipped: 1,
        failed: 0,
        errors: [{
          row: 2,
          field: "username",
          code: "DUPLICATE_IN_DATABASE",
          message: "Tên đăng nhập hoặc mã học sinh đã tồn tại."
        }]
      });
    });
  } finally {
    database.restore();
  }
});

test("Excel import skips duplicate usernames or student codes within the file", async () => {
  let insertedUsers = 0;
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql.includes("SELECT username, student_number")) return { rows: [], rowCount: 0 };
      if (sql.includes("INSERT INTO users")) {
        insertedUsers++;
        return { rows: [{ id: "00000000-0000-4000-8000-000000000043" }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_members")) return { rows: [{ id: studentMemberId }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_member_roles")) return { rows: [{ id: 1 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["duplicate.user", "Nguyễn Văn An", "HS106", "C-01", "Some-password"],
        [" DUPLICATE.USER ", "Trần Thị Bình", "HS107", "C-01", "Some-password"],
        ["other.user", "Lê Văn Nam", " hs106 ", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 200);
      const report = await response.json();
      assert.equal(report.created, 1);
      assert.equal(report.skipped, 2);
      assert.deepEqual(report.errors.map((error) => error.code), ["DUPLICATE_IN_FILE", "DUPLICATE_IN_FILE"]);
      assert.equal(insertedUsers, 1);
    });
  } finally {
    database.restore();
  }
});

test("Excel import rejects malformed or unsupported files", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });

  try {
    await withServer(async (origin) => {
      const malformed = await postImport(origin, Buffer.from("not an Excel workbook"));
      assert.equal(malformed.status, 400);
      const unsupported = await postImport(origin, Buffer.from("anything"), "students.csv");
      assert.equal(unsupported.status, 400);
    });
  } finally {
    database.restore();
  }
});

test("Excel import rejects missing and privileged headers before inserting users", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      for (const headers of [
        ["username", "full_name", "student_code", "class_code"],
        ["username", "full_name", "student_code", "class_code", "password", "is_teacher"]
      ]) {
        const workbook = XLSX.utils.book_new();
        const sheet = XLSX.utils.aoa_to_sheet([headers, ["student", "Student", "HS201", "C-01", "Secret"]]);
        XLSX.utils.book_append_sheet(workbook, sheet, "Students");
        const response = await postImport(origin, XLSX.write(workbook, { type: "buffer", bookType: "xlsx" }));
        assert.equal(response.status, 400);
        assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO users")), false);
      }
    });
  } finally {
    database.restore();
  }
});

test("Excel import returns 401 without an authenticated session", async () => {
  const database = installDatabaseMock({
    poolQuery: async () => ({ rows: [], rowCount: 0 }),
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([]), "students.xlsx", null);
      assert.equal(response.status, 401);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("Excel import reports invalid rows individually and continues with valid rows", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql.includes("INSERT INTO users")) return { rows: [{ id: "00000000-0000-4000-8000-000000000045" }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_members")) return { rows: [{ id: studentMemberId }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_member_roles")) return { rows: [{ id: 1 }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["valid.student", "Valid Student", "HS301", "C-01", "Some-password"],
        ["INVALID USERNAME", "Invalid Student", "HS302", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 200);
      const report = await response.json();
      assert.equal(report.created, 1);
      assert.equal(report.failed, 1);
      assert.equal(report.errors[0].row, 3);
      assert.equal(report.errors[0].field, "username");
    });
  } finally {
    database.restore();
  }
});

test("Excel import rolls back the complete file if a related insert fails", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup()], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql.includes("INSERT INTO users")) return { rows: [{ id: "00000000-0000-4000-8000-000000000046" }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_members")) return { rows: [{ id: studentMemberId }], rowCount: 1 };
      if (sql.includes("INSERT INTO class_member_roles")) {
        const error = new Error("role configuration failed");
        error.code = "XX000";
        throw error;
      }
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["first.student", "First Student", "HS401", "C-01", "Some-password"],
        ["second.student", "Second Student", "HS402", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 500);
      const body = await response.json();
      assert.equal(body.error, "An unexpected server error occurred.");
      assert.equal(JSON.stringify(body).includes("role configuration failed"), false);
      assert.equal(database.statements.filter(({ sql }) => sql === "BEGIN").length, 1);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), false);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
    });
  } finally {
    database.restore();
  }
});

test("Excel import enforces the 5 MB and 500-row limits", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      const tooLarge = await postImport(origin, Buffer.alloc(5 * 1024 * 1024 + 1), "large.xlsx");
      assert.equal(tooLarge.status, 413);
      const tooManyRows = await postImport(origin, spreadsheetBuffer(
        Array.from({ length: 501 }, (_, index) => [`student${index}`, `Student ${index}`, `HS${index}`, "C-01", "Some-password"])
      ));
      assert.equal(tooManyRows.status, 400);
      assert.match((await tooManyRows.json()).error, /500/);
    });
  } finally {
    database.restore();
  }
});

test("Excel import refuses rows for a class the teacher does not manage", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      const auth = authenticatedTeacherQuery(sql);
      if (sql.includes("FROM auth_sessions")) return auth;
      if (sql.includes("FROM classes")) return { rows: [classLookup([], [])], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async () => ({ rows: [], rowCount: 0 })
  });
  try {
    await withServer(async (origin) => {
      const response = await postImport(origin, spreadsheetBuffer([
        ["student.two", "Lê Văn Nam", "HS103", "C-01", "Some-password"]
      ]));
      assert.equal(response.status, 403);
      const body = await response.json();
      assert.equal(body.report.created, 0);
      assert.equal(body.report.failed, 1);
      assert.equal(database.statements.some(({ sql }) => sql === "BEGIN"), false);
    });
  } finally {
    database.restore();
  }
});

test("student deactivation is forbidden without students:delete permission", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async (sql) => {
      if (sql.includes("SELECT class_members.id AS")) {
        return {
          rows: [{
            memberId: studentMemberId,
            classId,
            userId: "00000000-0000-4000-8000-000000000041",
            fullName: "Nguyễn Văn An",
            studentNumber: "HS104"
          }],
          rowCount: 1
        };
      }
      if (sql.includes("AS can_delete")) return { rows: [{ is_teacher: true, can_delete: false }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/teacher/students/${studentMemberId}`, {
        method: "DELETE",
        headers: { Cookie: teacherCookie }
      });
      assert.equal(response.status, 403);
      assert.equal(database.statements.some(({ sql }) => sql.startsWith("UPDATE users SET is_active")), false);
      assert.equal(database.statements.some(({ sql }) => sql === "ROLLBACK"), true);
    });
  } finally {
    database.restore();
  }
});

test("student deactivation returns 404 for an unknown class membership", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async (sql) => {
      if (sql.includes("SELECT class_members.id AS")) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 0 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/teacher/students/${studentMemberId}`, {
        method: "DELETE",
        headers: { Cookie: teacherCookie }
      });
      assert.equal(response.status, 404);
    });
  } finally {
    database.restore();
  }
});

test("student deactivation only disables the account and writes an audit entry", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => authenticatedTeacherQuery(sql),
    clientQuery: async (sql) => {
      if (sql.includes("SELECT class_members.id AS")) {
        return {
          rows: [{
            memberId: studentMemberId,
            classId,
            userId: "00000000-0000-4000-8000-000000000042",
            fullName: "Phạm Thị Hoa",
            studentNumber: "HS105"
          }],
          rowCount: 1
        };
      }
      if (sql.includes("AS can_delete")) return { rows: [{ is_teacher: true, can_delete: true }], rowCount: 1 };
      if (sql.startsWith("UPDATE users SET is_active")) return { rows: [{ id: "user-id" }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }
  });
  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/teacher/students/${studentMemberId}`, {
        method: "DELETE",
        headers: { Cookie: teacherCookie }
      });
      assert.equal(response.status, 204);
      const updates = database.statements.filter(({ sql }) => sql.startsWith("UPDATE "));
      assert.deepEqual(updates.map(({ sql }) => sql), [
        "UPDATE users SET is_active = FALSE WHERE id = $1 AND is_active = TRUE RETURNING id"
      ]);
      assert.equal(database.statements.some(({ sql }) => sql.includes("INSERT INTO audit_logs")), true);
      assert.equal(database.statements.some(({ sql }) => sql === "COMMIT"), true);
    });
  } finally {
    database.restore();
  }
});
