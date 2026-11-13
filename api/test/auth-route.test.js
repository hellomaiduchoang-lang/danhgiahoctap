import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

process.env.NODE_ENV = "test";
process.env.APP_ORIGIN = "http://127.0.0.1:3000";
process.env.FRONTEND_ORIGIN = "https://hellomaiduchoang-lang.github.io";
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "postgresql://test:test@127.0.0.1:5432/test";
}

const { pool } = await import("../src/db.js");
const { app } = await import("../src/server.js");
const { clearSessionCookie, setSessionCookie } = await import("../src/auth.js");
const githubPagesOrigin = "https://hellomaiduchoang-lang.github.io";

function frontendFunction(html, name) {
  const declaration = new RegExp(`(?:async\\s+)?function ${name}\\(`).exec(html);
  assert.ok(declaration, `Missing ${name} in frontend`);
  const start = declaration.index;
  const boundary = /\r?\n      (?:async )?function |\r?\n      (?:const|let) /g;
  boundary.lastIndex = start + 1;
  const match = boundary.exec(html);
  return html.slice(start, match ? match.index : html.length);
}

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
  poolQuery = async () => ({ rows: user ? [user] : [], rowCount: user ? 1 : 0 }),
  clientQuery = async () => ({ rows: [], rowCount: 0 })
}) {
  const hadOwnQuery = Object.hasOwn(pool, "query");
  const hadOwnConnect = Object.hasOwn(pool, "connect");
  const originalQuery = pool.query;
  const originalConnect = pool.connect;
  let released = false;

  pool.query = poolQuery;
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

test("session cookies allow secure cross-site use in production", () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const headers = new Map();
  const response = { setHeader: (name, value) => headers.set(name, value) };
  process.env.NODE_ENV = "production";

  try {
    setSessionCookie(response, "session-token");
    const cookie = headers.get("Set-Cookie");
    assert.match(cookie, /; Secure/);
    assert.match(cookie, /; SameSite=None/);
    assert.match(cookie, /; HttpOnly/);

    clearSessionCookie(response);
    const clearedCookie = headers.get("Set-Cookie");
    assert.match(clearedCookie, /; Secure/);
    assert.match(clearedCookie, /; SameSite=None/);
    assert.match(clearedCookie, /; Max-Age=0/);
  } finally {
    process.env.NODE_ENV = originalNodeEnv;
  }
});

test("deployed frontend sends credentialed requests to the Render API", async () => {
  for (const file of ["../../public/index.html", "../public/index.html"]) {
    const html = await readFile(new URL(file, import.meta.url), "utf8");
    assert.match(html, /https:\/\/classtrack-nobf\.onrender\.com/);
    assert.match(html, /credentials:\s*"include"/);
    assert.match(html, /\/api\/classes\/\$\{encodeURIComponent\(activeClass\.id\)\}\/students/);
    assert.match(html, /body:\s*\{\s*fullName:\s*document\.getElementById\("new-student-name"\)\.value\s*\}/);
    assert.match(html, /timeoutMs:\s*120000/);
    assert.match(html, /\/api\/admin\/users\/\$\{encodeURIComponent\(account\.id\)\}\/status/);
    assert.match(html, /DISABLE ACCOUNT/);
    assert.match(html, /ENABLE ACCOUNT/);
    assert.doesNotMatch(html, /admin-account-confirm-username/);
    assert.match(html, /data-account-action="\$\{account\.isActive \? "disable" : "enable"\}"/);
    assert.match(html, /formData\.append\("file", file\)/);
    assert.match(html, /apiRequest\("\/api\/teacher\/students\/import"/);
    assert.match(html, /credentials:\s*"include"/);
    assert.match(html, /headers:\s*options\.body && !isFormData \? \{\s*"Content-Type":\s*"application\/json"\s*\} : undefined/);
    assert.match(html, /rememberCreatedStudentCredentials\(report\.credentials\)/);
    assert.match(html, /rememberCreatedStudentCredentials\(result\.credentials\)/);
    assert.match(html, /result\.credentials\.length !== 1/);
    assert.match(html, /result\.credentials\.length !== rows\.length/);
    assert.match(html, /function downloadStudentAccounts\(\)/);
    assert.match(html, /Tải CSV tài khoản/);
    assert.match(html, /document\.body\.appendChild\(link\);\s*link\.click\(\);\s*link\.remove\(\)/);
    assert.match(html, /rows\.length > 50/);
    assert.match(html, /Mỗi lần chỉ có thể tạo tối đa 50 tài khoản học sinh/);
    assert.match(html, /Đã tạo \$\{result\.credentials\.length\} tài khoản, nhưng chưa thể làm mới danh sách/);
    assert.match(html, /Đã nhập tài khoản, nhưng chưa thể làm mới danh sách/);
    assert.match(html, /temporary_password/);
    assert.match(html, /Hãy tạo hoặc import tài khoản học sinh trước khi tải file\./);
    assert.match(html, /Mật khẩu tạm của phiên trước không thể khôi phục\./);
    assert.match(html, /Mật khẩu tạm chỉ hiển thị trong lần tạo tài khoản này\. Nếu mất file, hãy dùng chức năng đặt lại mật khẩu\./);
    assert.doesNotMatch(html, /Bạn có muốn xóa mật khẩu tạm khỏi bộ nhớ trình duyệt không\?/);
    assert.match(html, /sessionStorage\.setItem\(studentCredentialsSessionMarker, "true"\)/);
    assert.match(html, /let currentCreatedStudentCredentials = \[\]/);
    assert.doesNotMatch(html, /sessionStorage\.setItem\([^,]+,\s*JSON\.stringify\(currentCreatedStudentCredentials/);
    assert.match(html, /currentCreatedStudentCredentials\.length === 0/);
    assert.match(html, /id="student-credentials-reset"/);
    assert.match(html, /Lỗi cấu hình API: phản hồi tạo tài khoản thiếu credentials hợp lệ/);
    assert.match(html, /classroom\.class_name\} · ID: \$\{classroom\.id\}/);
    assert.match(html, /\/api\/admin\/classes\/\$\{encodeURIComponent\(classId\)\}\/deletion-preview/);
    assert.match(html, /counts\.students_to_delete/);
    assert.match(html, /counts\.teachers_to_delete/);
    assert.match(html, /counts\.conduct_records/);
    assert.match(html, /counts\.points/);
    assert.match(html, /counts\.incidents/);
    assert.match(html, /counts\.comments/);
    assert.match(html, /counts\.violations/);
    assert.match(html, /counts\.weekly_scores/);
    assert.match(html, /id="admin-class-delete-submit" type="submit" disabled/);
    assert.match(html, /value !== "DELETE CLASS"/);
    assert.match(html, /confirmText !== "DELETE CLASS"/);
    assert.match(html, /Bước xác nhận cuối:/);
    assert.match(html, /body:\s*\{\s*confirmText\s*\}/);
    assert.match(html, /400: "Nội dung xác nhận hoặc thông tin lớp không hợp lệ\."/);
    assert.match(html, /401: "Phiên đăng nhập đã hết hạn\. Hãy đăng nhập lại\."/);
    assert.match(html, /403: "Chỉ Super Admin mới được xóa vĩnh viễn lớp\."/);
    assert.match(html, /404: "Không tìm thấy lớp để xóa\."/);
    assert.match(html, /409: "Không thể xóa an toàn do dữ liệu liên quan\."/);
    assert.match(html, /500: "Máy chủ gặp lỗi khi xóa lớp; thao tác đã được hoàn tác\."/);
    assert.doesNotMatch(html, /admin-class-confirm-code|confirmClassCode/);
    assert.doesNotMatch(html, /classroom\.class_code \? "" : "disabled/);
    assert.match(html, /Tài khoản thuộc lớp khác cùng Admin\/Super Admin được giữ nguyên/);
    const statusHandlerStart = html.indexOf('document.getElementById("admin-account-status-form").addEventListener("submit"');
    const statusHandlerEnd = html.indexOf('document.getElementById("admin-permissions-form").addEventListener("submit"', statusHandlerStart);
    const statusHandler = html.slice(statusHandlerStart, statusHandlerEnd);
    assert.match(statusHandler, /\/api\/admin\/users\/\$\{encodeURIComponent\(account\.id\)\}\/status/);
    assert.match(statusHandler, /method:\s*"PATCH",\s*body:\s*\{\s*isActive,\s*confirmText\s*\}/);
    assert.equal((statusHandler.match(/await loadAdminAccounts\(\)/g) || []).length, 1);
    assert.equal((statusHandler.match(/await loadAdminAudit\(\)/g) || []).length, 1);
    assert.match(statusHandler, /showToast\(isActive \? "Đã khôi phục tài khoản\." : "Đã vô hiệu hóa tài khoản"\)/);
    assert.doesNotMatch(statusHandler, /revoke-sessions/);
    const createFormStart = html.indexOf('document.getElementById("student-account-form").addEventListener("submit"');
    const bulkFormStart = html.indexOf('document.getElementById("bulk-student-form").addEventListener("submit"', createFormStart);
    const createFormHandler = html.slice(createFormStart, bulkFormStart);
    assert.ok(createFormHandler.indexOf("rememberCreatedStudentCredentials(result.credentials)") <
      createFormHandler.indexOf("await loadClassData()"));
    assert.match(createFormHandler, /Đã tạo tài khoản, nhưng chưa thể làm mới danh sách/);
  }
});

test("teacher student credentials stay in memory and download from the stored response", async () => {
  for (const file of ["../../public/index.html", "../public/index.html"]) {
    const html = await readFile(new URL(file, import.meta.url), "utf8");
    const elements = {
      "export-students": { disabled: true },
      "student-account-export-status": { textContent: "" },
      "download-student-accounts": { hidden: true, disabled: true, textContent: "" },
      "bulk-student-status": { textContent: "" },
      "student-credentials-lost-notice": { hidden: true },
      "student-credentials-reset": { hidden: true },
      "student-credentials-login-notice": { hidden: true }
    };
    const storedValues = new Map();
    const toastMessages = [];
    const link = {
      click() { this.clicked = true; },
      remove() { this.removed = true; }
    };
    let downloadedBlob;
    const context = {
      currentCreatedStudentCredentials: [],
      lostStudentCredentialsFromPreviousLoad: false,
      studentCredentialsSessionMarker: "credentials-marker",
      hasAdminPermission: () => false,
      sessionStorage: {
        setItem(key, value) { storedValues.set(key, value); },
        removeItem(key) { storedValues.delete(key); }
      },
      document: {
        getElementById(id) { return elements[id] || null; },
        createElement() { return link; },
        body: { appendChild() {} }
      },
      URL: {
        createObjectURL(blob) { downloadedBlob = blob; return "blob:test"; },
        revokeObjectURL() {}
      },
      Blob,
      window: { setTimeout() {} },
      showToast(message) { toastMessages.push(message); }
    };

    vm.runInNewContext([
      frontendFunction(html, "csvCell"),
      frontendFunction(html, "rememberCreatedStudentCredentials"),
      frontendFunction(html, "updateStudentAccountExport"),
      frontendFunction(html, "downloadStudentAccounts")
    ].join("\n"), context);

    vm.runInNewContext("updateStudentAccountExport()", context);
    assert.equal(elements["export-students"].disabled, true);
    assert.equal(elements["download-student-accounts"].disabled, true);
    assert.throws(
      () => vm.runInNewContext("rememberCreatedStudentCredentials(undefined)", context),
      /Lỗi cấu hình API/
    );
    const credentials = [{
      username: "hs100",
      full_name: "Nguyễn Văn An",
      student_code: "HS100",
      temporary_password: "one-time-password"
    }];
    assert.equal(
      vm.runInNewContext(`rememberCreatedStudentCredentials(${JSON.stringify(credentials)})`, context),
      1
    );
    assert.equal(elements["export-students"].disabled, false);
    assert.equal(elements["download-student-accounts"].disabled, false);
    assert.equal(elements["download-student-accounts"].hidden, false);
    assert.equal(storedValues.get("credentials-marker"), "true");

    const loadClassData = frontendFunction(html, "loadClassData");
    const loadAdminAccounts = frontendFunction(html, "loadAdminAccounts");
    assert.doesNotMatch(loadClassData, /clearGeneratedStudentCredentials|clearGeneratedAccounts/);
    assert.doesNotMatch(loadAdminAccounts, /clearGeneratedStudentCredentials|clearGeneratedAccounts/);

    vm.runInNewContext("downloadStudentAccounts()", context);
    assert.equal(link.clicked, true);
    assert.equal(link.removed, true);
    assert.equal(link.download, "tai-khoan-hoc-sinh.csv");
    assert.match(await downloadedBlob.text(), /hs100/);
    assert.match(await downloadedBlob.text(), /one-time-password/);
    assert.equal(context.currentCreatedStudentCredentials.length, 1);
    assert.match(toastMessages.at(-1), /Mật khẩu tạm chỉ hiển thị trong lần tạo tài khoản này/);
  }
});

test("bulk student creation returns downloadable credentials for every created account", async () => {
  const memberId = "00000000-0000-4000-8000-000000000020";
  const memberships = [];
  const userInserts = [];
  const auditStatements = [];
  let nextCode = 51;
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return {
          rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })],
          rowCount: 1
        };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: memberId,
            roles: ["ROLE_TEACHER"],
            permissions: ["students:list"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql, params = []) => {
      if (sql.includes("nextval('student_account_code_seq')")) {
        return { rows: [{ code: nextCode++ }], rowCount: 1 };
      }
      if (sql.includes("SELECT 1 FROM users WHERE username")) return { rows: [], rowCount: 0 };
      if (sql.includes("INSERT INTO users")) {
        userInserts.push(params);
        return { rows: [{ id: `00000000-0000-4000-8000-${String(userInserts.length).padStart(12, "0")}` }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_members")) {
        memberships.push(params);
        return { rows: [{ id: `00000000-0000-4000-8000-${String(memberships.length + 100).padStart(12, "0")}` }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_member_roles")) return { rows: [], rowCount: 1 };
      if (sql.includes("INSERT INTO audit_logs")) auditStatements.push({ sql, params });
      return { rows: [], rowCount: 1 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students/bulk`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ students: ["Nguyễn Văn An", "Trần Thị Bình"] })
      });

      assert.equal(response.status, 201);
      const body = await response.json();
      assert.deepEqual(body.credentials.map(({ username, full_name, student_code }) => ({
        username, full_name, student_code
      })), [
        { username: "hs051", full_name: "Nguyễn Văn An", student_code: "HS051" },
        { username: "hs052", full_name: "Trần Thị Bình", student_code: "HS052" }
      ]);
      assert.equal(userInserts.length, 2);
      assert.equal(memberships.length, 2);
      for (const [index, account] of body.credentials.entries()) {
        assert.equal(await bcrypt.compare(account.temporary_password, userInserts[index][1]), true);
        assert.notEqual(userInserts[index][1], account.temporary_password);
      }
      assert.equal(JSON.stringify(auditStatements).includes(body.credentials[0].temporary_password), false);
      assert.equal(JSON.stringify(body).includes("password_hash"), false);
      assert.equal(JSON.stringify(body).includes("DATABASE_URL"), false);
    });
  } finally {
    database.restore();
  }
});

test("bulk student creation rejects more than 50 names before opening a transaction", async () => {
  let transactionStarted = false;
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return {
          rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })],
          rowCount: 1
        };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: "00000000-0000-4000-8000-000000000020",
            roles: ["ROLE_TEACHER"],
            permissions: ["students:list"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      if (sql === "BEGIN") transactionStarted = true;
      return { rows: [], rowCount: 0 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students/bulk`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ students: Array.from({ length: 51 }, (_, index) => `Student ${index + 1}`) })
      });
      assert.equal(response.status, 400);
      assert.match((await response.json()).error, /1 đến 50/);
      assert.equal(transactionStarted, false);
    });
  } finally {
    database.restore();
  }
});

test("account cleanup UI is restricted to Super Admin and sends the exact confirmation", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  assert.match(html, /id="admin-account-maintenance"[^>]*hidden/);
  assert.match(html, /admin-account-maintenance"\)\.hidden = !currentUser\.isSuperAdmin/);
  assert.match(html, /DISABLE ALL NON-ADMINS/);
  assert.match(html, /\/api\/admin\/maintenance\/disable-non-admins/);
  assert.match(html, /method:\s*"POST",\s*body:\s*\{\s*confirmText:\s*confirmation\s*\}/);
  assert.match(html, /Dữ liệu học sinh, giáo viên, lớp, điểm, vi phạm và nhận xét không bị xóa/);
});

test("CORS allows credentialed requests only from the configured frontend origin", async () => {
  await withServer(async (origin) => {
    const allowed = await fetch(`${origin}/health`, {
      headers: { Origin: githubPagesOrigin }
    });
    assert.equal(allowed.headers.get("access-control-allow-origin"), githubPagesOrigin);
    assert.equal(allowed.headers.get("access-control-allow-credentials"), "true");

    const preflight = await fetch(`${origin}/api/admin/teachers`, {
      method: "OPTIONS",
      headers: {
        Origin: githubPagesOrigin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"
      }
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), githubPagesOrigin);
    assert.equal(preflight.headers.get("access-control-allow-credentials"), "true");

    const untrusted = await fetch(`${origin}/health`, {
      headers: { Origin: "https://attacker.example" }
    });
    assert.equal(untrusted.headers.get("access-control-allow-origin"), null);

    const rejectedPreflight = await fetch(`${origin}/api/admin/teachers`, {
      method: "OPTIONS",
      headers: {
        Origin: "https://attacker.example",
        "Access-Control-Request-Method": "POST"
      }
    });
    assert.equal(rejectedPreflight.status, 403);
  });
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
      const teacherInsert = queries.find((sql) => sql.includes("INSERT INTO users"));
      assert.match(teacherInsert, /is_active,\s*is_teacher/);
      assert.match(teacherInsert, /is_admin,\s*is_super_admin,\s*must_change_password/);
      assert.match(teacherInsert, /TRUE,\s*TRUE,\s*FALSE,\s*FALSE,\s*TRUE/);
      assert.equal(database.wasReleased(), true);
    });
  } finally {
    database.restore();
  }
});

test("a created teacher can log in, and the response never includes the password hash", async () => {
  let createdUser;
  const database = installDatabaseMock({
    user: authenticatedUser({ isSuperAdmin: false, adminPermissions: ["teachers:manage"] }),
    poolQuery: async (sql, params = []) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser()], rowCount: 1 };
      }
      if (sql.includes("FROM users WHERE users.username")) {
        return {
          rows: createdUser && createdUser.username === params[0] ? [createdUser] : [],
          rowCount: createdUser && createdUser.username === params[0] ? 1 : 0
        };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql, params = []) => {
      if (sql.includes("INSERT INTO users")) {
        const [username, password_hash, full_name] = params;
        createdUser = {
          id: "00000000-0000-4000-8000-000000000123",
          username,
          password_hash,
          full_name,
          is_active: true,
          is_teacher: true,
          is_admin: false,
          is_super_admin: false,
          must_change_password: true,
          password_reset_expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
          admin_permissions: []
        };
        return { rows: [{ id: createdUser.id }], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  });

  try {
    await withServer(async (origin) => {
      const createResponse = await fetch(`${origin}/api/admin/teachers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ teachers: ["  Nguyễn Giáo Viên  "] })
      });
      assert.equal(createResponse.status, 201);
      const { accounts } = await createResponse.json();
      assert.equal(accounts.length, 1);
      assert.equal(accounts[0].fullName, "Nguyễn Giáo Viên");
      assert.ok(accounts[0].username.length <= 32);
      assert.equal(createdUser.full_name, "Nguyễn Giáo Viên");
      assert.equal(createdUser.is_active, true);
      assert.equal(createdUser.is_teacher, true);
      assert.equal(createdUser.is_admin, false);
      assert.equal(createdUser.is_super_admin, false);
      assert.equal(createdUser.must_change_password, true);
      assert.equal(await bcrypt.compare(accounts[0].password, createdUser.password_hash), true);
      assert.notEqual(createdUser.password_hash, accounts[0].password);
      assert.equal(typeof createdUser.password_hash, "string");

      const loginResponse = await fetch(`${origin}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: `  ${accounts[0].username.toUpperCase()}  `,
          password: accounts[0].password
        })
      });
      assert.equal(loginResponse.status, 200);
      const loginBody = await loginResponse.json();
      assert.equal(loginBody.user.username, createdUser.username);
      assert.equal(loginBody.user.mustChangePassword, true);
      assert.equal(JSON.stringify(loginBody).includes(createdUser.password_hash), false);
      assert.match(loginResponse.headers.get("set-cookie"), /classtrack_session=/);
    });
  } finally {
    database.restore();
  }
});

test("teacher login rejects an incorrect password", async () => {
  const passwordHash = await bcrypt.hash("teacher-correct-password", 4);
  const database = installDatabaseMock({
    poolQuery: async (sql, params = []) => {
      if (sql.includes("FROM users WHERE users.username")) {
        const user = params[0] === "teacher.test"
          ? {
              username: "teacher.test",
              password_hash: passwordHash,
              must_change_password: false,
              admin_permissions: []
            }
          : null;
        return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
      }
      return { rows: [], rowCount: 0 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "teacher.test", password: "wrong-password" })
      });
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), {
        error: "Tên đăng nhập hoặc mật khẩu không chính xác.",
        code: "UNAUTHORIZED"
      });
    });
  } finally {
    database.restore();
  }
});

test("teacher username collisions return 409 and roll back the batch", async () => {
  let insertAttempts = 0;
  const queries = [];
  const database = installDatabaseMock({
    user: authenticatedUser(),
    clientQuery: async (sql) => {
      queries.push(sql);
      if (sql.includes("INSERT INTO users")) {
        insertAttempts++;
        return { rows: [], rowCount: 0 };
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
        body: JSON.stringify({ teachers: ["Giáo Viên Trùng"] })
      });
      assert.equal(response.status, 409);
      assert.equal(insertAttempts, 5);
      assert.ok(queries.includes("ROLLBACK"));
      assert.equal((await response.json()).accounts, undefined);
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
        headers: {
          "Content-Type": "application/json",
          Origin: githubPagesOrigin
        },
        body: JSON.stringify({ teachers: ["Nguyễn Minh An"] })
      });
      assert.equal(unauthenticated.status, 401);
      assert.equal(unauthenticated.headers.get("access-control-allow-origin"), githubPagesOrigin);
      assert.equal(unauthenticated.headers.get("access-control-allow-credentials"), "true");

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

test("POST /api/classes/:classId/students creates a class student from the frontend body", async () => {
  const studentId = "00000000-0000-4000-8000-000000000123";
  const membershipId = "00000000-0000-4000-8000-000000000456";
  const userInserts = [];
  const queries = [];
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })], rowCount: 1 };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: "00000000-0000-4000-8000-000000000789",
            roles: ["ROLE_TEACHER"],
            permissions: ["students:list"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql, params = []) => {
      queries.push(sql);
      if (sql.includes("nextval('student_account_code_seq')")) {
        return { rows: [{ code: 42 }], rowCount: 1 };
      }
      if (sql.includes("SELECT 1 FROM users WHERE username")) {
        return { rows: [], rowCount: 0 };
      }
      if (sql.includes("INSERT INTO users")) {
        userInserts.push(params);
        return { rows: [{ id: studentId }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_members")) {
        return { rows: [{ id: membershipId }], rowCount: 1 };
      }
      if (sql.includes("INSERT INTO class_member_roles")) {
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: adminCookie
        },
        body: JSON.stringify({ fullName: "  Nguyễn Văn An  " })
      });

      assert.equal(response.status, 201);
      const body = await response.json();
      const { credentials } = body;
      assert.deepEqual(Object.keys(body), [
        "username", "full_name", "student_code", "temporary_password", "credentials"
      ]);
      assert.deepEqual(Object.keys(credentials[0]), [
        "username", "full_name", "student_code", "temporary_password"
      ]);
      const account = credentials[0];
      assert.deepEqual({
        username: body.username,
        full_name: body.full_name,
        student_code: body.student_code,
        temporary_password: body.temporary_password
      }, account);
      const [username, passwordHash, fullName, studentNumber] = userInserts[0];
      assert.equal(account.student_code, "HS042");
      assert.equal(account.username, "hs042");
      assert.equal(account.full_name, "Nguyễn Văn An");
      assert.equal(username, "hs042");
      assert.equal(studentNumber, "HS042");
      assert.equal(fullName, "Nguyễn Văn An");
      assert.equal(await bcrypt.compare(account.temporary_password, passwordHash), true);
      assert.notEqual(passwordHash, account.temporary_password);
      assert.equal(JSON.stringify(credentials).includes(passwordHash), false);
      assert.match(queries.find((sql) => sql.includes("INSERT INTO users")), /is_active,\s*is_teacher/);
      assert.match(queries.find((sql) => sql.includes("INSERT INTO users")), /is_admin,\s*is_super_admin,\s*must_change_password/);
      assert.ok(queries.includes("BEGIN"));
      assert.ok(queries.includes("COMMIT"));
    });
  } finally {
    database.restore();
  }
});

test("student creation rejects invalid names and class IDs", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })], rowCount: 1 };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: "00000000-0000-4000-8000-000000000789",
            roles: ["ROLE_TEACHER"],
            permissions: ["students:list"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  });

  try {
    await withServer(async (origin) => {
      const invalidName = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminCookie },
        body: JSON.stringify({ fullName: "   " })
      });
      assert.equal(invalidName.status, 400);

      const invalidClassId = await fetch(`${origin}/api/classes/not-a-uuid/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminCookie },
        body: JSON.stringify({ fullName: "Nguyễn Văn An" })
      });
      assert.equal(invalidClassId.status, 400);
    });
  } finally {
    database.restore();
  }
});

test("student creation returns 409 and rolls back on a username or student code collision", async () => {
  const queries = [];
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })], rowCount: 1 };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: "00000000-0000-4000-8000-000000000789",
            roles: ["ROLE_TEACHER"],
            permissions: ["students:list"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    },
    clientQuery: async (sql) => {
      queries.push(sql);
      if (sql.includes("nextval('student_account_code_seq')")) return { rows: [{ code: 42 }], rowCount: 1 };
      if (sql.includes("SELECT 1 FROM users WHERE username")) return { rows: [], rowCount: 0 };
      if (sql.includes("INSERT INTO users")) {
        const error = new Error("duplicate key");
        error.code = "23505";
        throw error;
      }
      return { rows: [], rowCount: 1 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminCookie },
        body: JSON.stringify({ fullName: "Nguyễn Văn An" })
      });
      assert.equal(response.status, 409);
      assert.deepEqual(await response.json(), {
        error: "Tên đăng nhập hoặc mã học sinh đã được sử dụng.",
        code: "CONFLICT"
      });
      assert.ok(queries.includes("ROLLBACK"));
    });
  } finally {
    database.restore();
  }
});

test("student creation requires an authenticated teacher with students:list permission", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })], rowCount: 1 };
      }
      if (sql.includes("FROM class_members")) {
        return {
          rows: [{
            member_id: "00000000-0000-4000-8000-000000000789",
            roles: ["ROLE_TEACHER"],
            permissions: ["classes:read"]
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  });

  try {
    await withServer(async (origin) => {
      const unauthenticated = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fullName: "Nguyễn Văn An" })
      });
      assert.equal(unauthenticated.status, 401);

      const missingPermission = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminCookie },
        body: JSON.stringify({ fullName: "Nguyễn Văn An" })
      });
      assert.equal(missingPermission.status, 403);
    });
  } finally {
    database.restore();
  }
});

test("student creation returns 404 if class membership is missing", async () => {
  const database = installDatabaseMock({
    poolQuery: async (sql) => {
      if (sql.includes("FROM auth_sessions")) {
        return { rows: [authenticatedUser({ isAdmin: false, isSuperAdmin: false, isTeacher: true })], rowCount: 1 };
      }
      if (sql.includes("FROM class_members")) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 0 };
    }
  });

  try {
    await withServer(async (origin) => {
      const response = await fetch(`${origin}/api/classes/00000000-0000-4000-8000-000000000010/students`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminCookie },
        body: JSON.stringify({ fullName: "Nguyễn Văn An" })
      });
      assert.equal(response.status, 404);
    });
  } finally {
    database.restore();
  }
});
