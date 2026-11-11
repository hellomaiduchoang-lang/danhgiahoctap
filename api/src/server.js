import "dotenv/config";
import express from "express";
import bcrypt from "bcryptjs";
import multer from "multer";
import * as XLSX from "@e965/xlsx";
import { randomBytes } from "node:crypto";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "./db.js";
import { conductVisibility } from "./authorization.js";
import { isAllowedFrontendOrigin } from "./origins.js";
import {
  authenticate,
  classPermission,
  clearSessionCookie,
  login,
  loadClassAccess,
  requireAuthentication,
  revokeSession,
  setSessionCookie
} from "./auth.js";

const app = express();
export { app };
const port = Number(process.env.PORT || 3000);
const host = "0.0.0.0";
const configuredPublicOrigin = process.env.APP_ORIGIN || process.env.RENDER_EXTERNAL_URL;
if (process.env.NODE_ENV === "production" && !configuredPublicOrigin) {
  throw new Error("Set APP_ORIGIN to the public HTTPS origin of this deployment.");
}
const appOrigin = new URL(configuredPublicOrigin || `http://127.0.0.1:${port}`).origin;
const frontendOrigins = new Set();
for (const value of (process.env.FRONTEND_ORIGIN || "").split(",")) {
  const candidate = value.trim();
  if (!candidate) continue;
  try {
    const origin = new URL(candidate);
    if (origin.origin !== candidate || !["http:", "https:"].includes(origin.protocol)) {
      throw new Error("Expected an origin without a path.");
    }
    frontendOrigins.add(origin.origin);
  }
  catch { throw new Error(`Invalid frontend origin in FRONTEND_ORIGIN: ${candidate}`); }
}
if (process.env.NODE_ENV === "production" && frontendOrigins.size === 0) {
  throw new Error("Set FRONTEND_ORIGIN to the exact public frontend origin.");
}
if (process.env.NODE_ENV !== "production") {
  frontendOrigins.add(`http://localhost:${port}`);
  frontendOrigins.add(`http://127.0.0.1:${port}`);
  frontendOrigins.add("http://localhost:8000");
  frontendOrigins.add("http://127.0.0.1:8000");
}
const trustedMutationOrigins = new Set([...frontendOrigins, appOrigin]);
const isDevelopment = process.env.NODE_ENV !== "production";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const publicDirectory = path.join(root, "public");
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_STUDENT_IMPORT_SIZE = 5 * 1024 * 1024;
const studentImportUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_STUDENT_IMPORT_SIZE, files: 1, fields: 0, parts: 1 }
});

app.disable("x-powered-by");
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: [
        "'self'",
        ...frontendOrigins,
        ...(isDevelopment ? ["http://localhost:*", "http://127.0.0.1:*"] : [])
      ],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use((request, response, next) => {
  const origin = request.get("origin");
  if (origin && isAllowedFrontendOrigin(origin, frontendOrigins, isDevelopment)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    response.setHeader("Access-Control-Max-Age", "600");
    response.append("Vary", "Origin");
  }
  if (request.method === "OPTIONS") {
    if (!origin || !isAllowedFrontendOrigin(origin, frontendOrigins, isDevelopment)) {
      return response.status(403).json({ error: "Request origin is not allowed.", code: "ORIGIN_NOT_ALLOWED" });
    }
    return response.status(204).end();
  }
  next();
});
app.use((request, response, next) => {
  const originalJson = response.json.bind(response);
  response.json = (body) => {
    if (response.statusCode >= 400 && body && typeof body === "object" && !Array.isArray(body) && !body.code) {
      const codeByStatus = { 400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND", 409: "CONFLICT", 422: "UNPROCESSABLE_ENTITY", 429: "RATE_LIMITED" };
      body = { ...body, code: codeByStatus[response.statusCode] || "REQUEST_FAILED" };
    }
    return originalJson(body);
  };
  next();
});
app.use(express.json({ limit: "2mb" }));
app.get("/health", (_request, response) => {
  response.json({ ok: true });
});
app.use("/api", authenticate);
app.use("/api", (_request, response, next) => {
  response.setHeader("Cache-Control", "no-store");
  next();
});
app.use("/api", (request, response, next) => {
  if (!request.user?.mustChangePassword || ["/session", "/account/password", "/auth/logout"].includes(request.path)) return next();
  return response.status(403).json({ error: "Bạn cần đổi mật khẩu tạm trước khi tiếp tục." });
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Try again later." }
});

function requireSameOrigin(request, response, next) {
  const origin = request.get("origin");
  if (!origin) {
    const fetchSite = request.get("sec-fetch-site");
    const referer = request.get("referer");
    if (fetchSite === "cross-site" || (referer && (() => {
      try { return !isAllowedFrontendOrigin(new URL(referer).origin, frontendOrigins, isDevelopment); }
      catch { return true; }
    })())) {
      return response.status(403).json({ error: "Request origin is not allowed." });
    }
    return next();
  }
  if (!isAllowedFrontendOrigin(origin, trustedMutationOrigins, isDevelopment)) {
    return response.status(403).json({ error: "Request origin is not allowed." });
  }
  return next();
}

function asyncRoute(handler) {
  return (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
}

function requireClassTeacher(request, response, next) {
  if (!request.classAccess?.roles.has("ROLE_TEACHER")) {
    return response.status(403).json({ error: "Only a teacher in this class can manage class roles and groups." });
  }
  return next();
}

function requireTeacherAccount(request, response, next) {
  if (!request.user?.isTeacher || request.user.isAdmin) {
    return response.status(403).json({ error: "Chỉ giáo viên mới được thực hiện thao tác này." });
  }
  return next();
}

function parseStudentImportFile(request, response, next) {
  studentImportUpload.single("file")(request, response, (error) => {
    if (!error) return next();
    if (error instanceof multer.MulterError) {
      const tooLarge = error.code === "LIMIT_FILE_SIZE";
      return response.status(tooLarge ? 413 : 400).json({
        error: tooLarge ? "Tệp Excel không được vượt quá 5 MB." : "Chỉ được tải lên một tệp trong trường file."
      });
    }
    return next(error);
  });
}

function requireAdminPermission(permission) {
  return (request, response, next) => {
    if (!request.user?.isAdmin && !request.user?.isSuperAdmin) {
      return response.status(403).json({ error: "Chỉ tài khoản quản trị mới được thực hiện thao tác này." });
    }
    if (request.user.isSuperAdmin || request.user.adminPermissions?.includes(permission)) return next();
    return response.status(403).json({ error: "Tài khoản quản trị chưa được cấp quyền cho thao tác này." });
  };
}

function requireAdminAccount(request, response, next) {
  if (!request.user?.isAdmin && !request.user?.isSuperAdmin) {
    return response.status(403).json({ error: "Chỉ Admin hoặc Super Admin mới được quản lý lớp." });
  }
  return next();
}

function requireSuperAdmin(request, response, next) {
  if (!request.user?.isSuperAdmin) return response.status(403).json({ error: "Chỉ Super Admin mới được quản lý quyền quản trị cấp cao." });
  return next();
}

function audit(client, { classId, actorUserId, action, targetType, targetId, details = {} }) {
  return client.query(
    `INSERT INTO audit_logs (class_id, actor_user_id, action, target_type, target_id, details)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [classId, actorUserId, action, targetType, targetId, details]
  );
}

async function nextStudentIdentity(client) {
  while (true) {
    const result = await client.query("SELECT nextval('student_account_code_seq') AS code");
    const studentNumber = `HS${String(result.rows[0].code).padStart(3, "0")}`;
    const username = studentNumber.toLowerCase();
    const conflict = await client.query(
      "SELECT 1 FROM users WHERE username = $1 OR student_number = $2 LIMIT 1",
      [username, studentNumber]
    );
    if (!conflict.rowCount) return { studentNumber, username };
  }
}

app.get("/api/health", asyncRoute(async (_request, response) => {
  await pool.query("SELECT 1");
  response.json({ status: "ok" });
}));

app.put("/api/account/avatar", requireAuthentication, requireSameOrigin, asyncRoute(async (request, response) => {
  const dataUrl = request.body?.dataUrl;
  if (typeof dataUrl !== "string") {
    return response.status(400).json({ error: "Vui lòng chọn ảnh đại diện PNG, JPEG hoặc WebP." });
  }
  const match = dataUrl.match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!match) return response.status(400).json({ error: "Ảnh phải có định dạng PNG, JPEG hoặc WebP." });
  const bytes = Buffer.from(match[2], "base64");
  if (!bytes.length || bytes.length > 1024 * 1024 || bytes.toString("base64") !== match[2]) {
    return response.status(400).json({ error: "Ảnh đại diện phải nhỏ hơn hoặc bằng 1 MB." });
  }
  await pool.query("UPDATE users SET avatar_data = $1 WHERE id = $2", [dataUrl, request.user.id]);
  response.json({ avatarData: dataUrl });
}));

app.patch("/api/account/password", requireAuthentication, requireSameOrigin, asyncRoute(async (request, response) => {
  const { currentPassword, newPassword } = request.body || {};
  if (typeof currentPassword !== "string" || typeof newPassword !== "string" ||
      newPassword.length < 8 || Buffer.byteLength(newPassword, "utf8") > 72) {
    return response.status(400).json({ error: "Mật khẩu mới cần có ít nhất 8 ký tự và tối đa 72 byte." });
  }
  const result = await pool.query("SELECT password_hash FROM users WHERE id = $1 AND is_active = TRUE", [request.user.id]);
  if (!result.rows[0]?.password_hash || !(await bcrypt.compare(currentPassword, result.rows[0].password_hash))) {
    return response.status(400).json({ error: "Mật khẩu hiện tại không chính xác." });
  }
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await pool.query("UPDATE users SET password_hash = $1, must_change_password = FALSE, password_reset_expires_at = NULL WHERE id = $2", [passwordHash, request.user.id]);
  response.json({ message: "Đã đổi mật khẩu." });
}));

app.post("/api/auth/login", requireSameOrigin, loginLimiter, asyncRoute(async (request, response) => {
  const submittedLogin = typeof request.body?.username === "string"
    ? request.body.username
    : typeof request.body?.email === "string" ? request.body.email : "";
  const username = submittedLogin.trim().toLowerCase().split("@")[0];
  const password = typeof request.body?.password === "string" ? request.body.password : "";
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username) || !password || Buffer.byteLength(password, "utf8") > 72) {
    return response.status(400).json({ error: "Tên đăng nhập hoặc mật khẩu không hợp lệ." });
  }
  const result = await login(username, password);
  if (!result) {
    return response.status(401).json({ error: "Tên đăng nhập hoặc mật khẩu không chính xác." });
  }
  setSessionCookie(response, result.token);
  response.json({ user: result.user });
}));

app.post(
  "/api/teacher/students/import",
  requireAuthentication,
  requireSameOrigin,
  requireTeacherAccount,
  parseStudentImportFile,
  asyncRoute(async (request, response) => {
    const report = { created: 0, skipped: 0, failed: 0, errors: [] };
    const file = request.file;
    if (!file) return response.status(400).json({ error: "Hãy chọn tệp Excel trong trường file." });
    if (![".xlsx", ".xls"].includes(path.extname(file.originalname).toLowerCase())) {
      return response.status(400).json({ error: "Chỉ chấp nhận tệp .xlsx hoặc .xls." });
    }

    let rows;
    try {
      const workbook = XLSX.read(file.buffer, { type: "buffer", dense: true, cellDates: false });
      const firstSheet = workbook.SheetNames[0];
      if (!firstSheet) return response.status(400).json({ error: "Tệp Excel không có trang tính." });
      const worksheet = workbook.Sheets[firstSheet];
      const range = XLSX.utils.decode_range(worksheet["!ref"] || "A1:A1");
      if (range.e.r > 500) return response.status(400).json({ error: "Tệp Excel chỉ được có tối đa 500 dòng dữ liệu." });
      rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, raw: false, defval: "", blankrows: true });
    } catch {
      return response.status(400).json({ error: "Tệp Excel không hợp lệ hoặc không thể đọc." });
    }

    const requiredColumns = ["username", "full_name", "student_code", "class_code", "password"];
    const headers = (Array.isArray(rows[0]) ? rows[0] : []).map((value) =>
      String(value ?? "").replace(/^\uFEFF/, "").trim().toLowerCase()
    );
    const privilegedColumns = ["is_admin", "is_teacher", "is_super_admin"];
    const suppliedPrivilegedColumns = headers.filter((header) => privilegedColumns.includes(header));
    if (suppliedPrivilegedColumns.length) {
      return response.status(400).json({
        error: "Tệp không được chứa các cột phân quyền tài khoản.",
        report
      });
    }
    const unknownColumns = [...new Set(headers.filter((header) =>
      header && !["username", "full_name", "student_code", "class_code", "password"].includes(header)
    ))];
    if (unknownColumns.length || new Set(headers.filter(Boolean)).size !== headers.filter(Boolean).length) {
      return response.status(400).json({
        error: "Tệp có tên cột không được hỗ trợ hoặc bị lặp.",
        report
      });
    }
    const columnIndexes = Object.fromEntries(requiredColumns.map((column) => [column, headers.indexOf(column)]));
    const missingColumns = requiredColumns.filter((column) => columnIndexes[column] < 0);
    if (missingColumns.length) {
      return response.status(400).json({
        error: `Thiếu cột bắt buộc: ${missingColumns.join(", ")}.`,
        report
      });
    }

    const inputRows = rows.slice(1)
      .map((cells, index) => ({ row: index + 2, cells: Array.isArray(cells) ? cells : [] }))
      .filter(({ cells }) => cells.some((value) => String(value ?? "").trim() !== ""));
    if (inputRows.length > 500) {
      return response.status(400).json({ error: "Tệp Excel chỉ được có tối đa 500 dòng dữ liệu." });
    }
    if (!inputRows.length) return response.status(400).json({ error: "Tệp Excel không có dòng dữ liệu." });

    const validRows = [];
    for (const { row, cells } of inputRows) {
      const student = {
        row,
        username: String(cells[columnIndexes.username] ?? "").trim().toLowerCase(),
        fullName: String(cells[columnIndexes.full_name] ?? "").trim(),
        studentCode: String(cells[columnIndexes.student_code] ?? "").trim(),
        classCode: String(cells[columnIndexes.class_code] ?? "").trim(),
        password: String(cells[columnIndexes.password] ?? "")
      };
      const rowErrors = [];
      if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(student.username)) {
        rowErrors.push(["username", "Tên đăng nhập phải dài 3–32 ký tự và chỉ gồm chữ thường, số, dấu chấm, gạch dưới hoặc gạch ngang."]);
      }
      if (!student.fullName || student.fullName.length > 120) {
        rowErrors.push(["full_name", "Họ tên là bắt buộc và không được vượt quá 120 ký tự."]);
      }
      if (!student.studentCode || student.studentCode.length > 32) {
        rowErrors.push(["student_code", "Mã học sinh là bắt buộc và không được vượt quá 32 ký tự."]);
      }
      if (!student.classCode || student.classCode.length > 64) {
        rowErrors.push(["class_code", "Mã lớp là bắt buộc và không được vượt quá 64 ký tự."]);
      }
      if (!student.password || Buffer.byteLength(student.password, "utf8") > 72) {
        rowErrors.push(["password", "Mật khẩu là bắt buộc và không được vượt quá 72 byte."]);
      }
      if (rowErrors.length) {
        report.failed++;
        for (const [field, message] of rowErrors) {
          report.errors.push({ row, field, code: "INVALID_VALUE", message });
        }
      } else {
        validRows.push(student);
      }
    }

    const seenUsernames = new Set();
    const seenStudentCodes = new Set();
    const uniqueRows = [];
    for (const student of validRows) {
      if (seenUsernames.has(student.username) || seenStudentCodes.has(student.studentCode)) {
        report.skipped++;
        report.errors.push({
          row: student.row,
          field: seenUsernames.has(student.username) ? "username" : "student_code",
          code: "DUPLICATE_IN_FILE",
          message: "Tên đăng nhập hoặc mã học sinh đã xuất hiện trong tệp."
        });
        continue;
      }
      seenUsernames.add(student.username);
      seenStudentCodes.add(student.studentCode);
      uniqueRows.push(student);
    }

    if (!uniqueRows.length) return response.json(report);

    const classCodes = [...new Set(uniqueRows.map((student) => student.classCode.toLowerCase()))];
    const classResult = await pool.query(
      `SELECT classes.id, classes.class_code AS "classCode",
              (SELECT class_members.id
               FROM class_members
               WHERE class_members.class_id = classes.id
                 AND class_members.user_id = $2
                 AND class_members.is_active = TRUE
               LIMIT 1) AS "teacherMemberId",
              ARRAY(
                SELECT roles.name
                FROM class_members
                JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
                JOIN roles ON roles.id = class_member_roles.role_id
                WHERE class_members.class_id = classes.id
                  AND class_members.user_id = $2
                  AND class_members.is_active = TRUE
              ) AS roles,
              ARRAY(
                SELECT permissions.name
                FROM class_members
                JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
                JOIN role_permissions ON role_permissions.role_id = class_member_roles.role_id
                JOIN permissions ON permissions.id = role_permissions.permission_id
                WHERE class_members.class_id = classes.id
                  AND class_members.user_id = $2
                  AND class_members.is_active = TRUE
                UNION
                SELECT permissions.name
                FROM class_members
                JOIN member_permissions ON member_permissions.class_member_id = class_members.id
                JOIN permissions ON permissions.id = member_permissions.permission_id
                WHERE class_members.class_id = classes.id
                  AND class_members.user_id = $2
                  AND class_members.is_active = TRUE
              ) AS permissions
       FROM classes
       WHERE classes.is_active = TRUE
         AND LOWER(BTRIM(classes.class_code)) = ANY($1::text[])`,
      [classCodes, request.user.id]
    );
    const classesByCode = new Map(classResult.rows.map((row) => [row.classCode.toLowerCase(), row]));
    const readyRows = [];
    for (const student of uniqueRows) {
      const classroom = classesByCode.get(student.classCode.toLowerCase());
      if (!classroom) {
        report.failed++;
        report.errors.push({
          row: student.row,
          field: "class_code",
          code: "CLASS_NOT_FOUND",
          message: "Không tìm thấy mã lớp trong hệ thống."
        });
        continue;
      }
      student.classroom = classroom;
      readyRows.push(student);
    }

    const unauthorizedRows = readyRows.filter(({ classroom }) =>
      !classroom.roles.includes("ROLE_TEACHER") ||
      !classroom.permissions.includes("students:list")
    );
    if (unauthorizedRows.length) {
      const unauthorizedSet = new Set(unauthorizedRows);
      for (const student of readyRows) {
        report.failed++;
        report.errors.push({
          row: student.row,
          field: "class_code",
          code: unauthorizedSet.has(student) ? "CLASS_FORBIDDEN" : "IMPORT_ABORTED",
          message: unauthorizedSet.has(student)
            ? "Bạn không được phân công phụ trách lớp này."
            : "Không nhập dòng này vì tệp có mã lớp ngoài phạm vi phụ trách."
        });
      }
      return response.status(403).json({
        error: "Chỉ được nhập học sinh vào lớp do giáo viên hiện tại phụ trách.",
        report
      });
    }

    if (!readyRows.length) return response.status(400).json({ error: "Không có dòng nào hợp lệ để nhập.", report });

    const existing = await pool.query(
      `SELECT username, student_number
       FROM users
       WHERE username = ANY($1::text[]) OR student_number = ANY($2::text[])`,
      [readyRows.map(({ username }) => username), readyRows.map(({ studentCode }) => studentCode)]
    );
    const existingUsernames = new Set(existing.rows.map((row) => row.username));
    const existingStudentCodes = new Set(existing.rows.map((row) => row.student_number));
    const insertRows = [];
    for (const student of readyRows) {
      if (existingUsernames.has(student.username) || existingStudentCodes.has(student.studentCode)) {
        report.skipped++;
        report.errors.push({
          row: student.row,
          field: existingUsernames.has(student.username) ? "username" : "student_code",
          code: "DUPLICATE_IN_DATABASE",
          message: "Tên đăng nhập hoặc mã học sinh đã tồn tại."
        });
        continue;
      }
      student.passwordHash = await bcrypt.hash(student.password, 12);
      insertRows.push(student);
    }

    if (!insertRows.length) return response.json(report);

    const client = await pool.connect();
    try {
      for (let offset = 0; offset < insertRows.length; offset += 50) {
        const batch = insertRows.slice(offset, offset + 50);
        const batchErrors = [];
        let batchCreated = 0;
        let batchSkipped = 0;
        await client.query("BEGIN");
        try {
          for (const student of batch) {
            const insertedUser = await client.query(
              `INSERT INTO users (
                 username, password_hash, full_name, student_number, is_active, is_teacher,
                 is_admin, is_super_admin, must_change_password, password_reset_expires_at
               )
               VALUES ($1, $2, $3, $4, TRUE, FALSE, FALSE, FALSE, TRUE, NOW() + INTERVAL '24 hours')
               ON CONFLICT DO NOTHING
               RETURNING id`,
              [student.username, student.passwordHash, student.fullName, student.studentCode]
            );
            if (!insertedUser.rowCount) {
              batchSkipped++;
              batchErrors.push({
                row: student.row,
                field: "username",
                code: "DUPLICATE_IN_DATABASE",
                message: "Tên đăng nhập hoặc mã học sinh đã tồn tại."
              });
              continue;
            }

            const membership = await client.query(
              "INSERT INTO class_members (class_id, user_id) VALUES ($1, $2) RETURNING id",
              [student.classroom.id, insertedUser.rows[0].id]
            );
            const assignedRole = await client.query(
              `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
               SELECT $1, $2, roles.id, $3 FROM roles WHERE roles.name = 'ROLE_STUDENT'`,
              [student.classroom.id, membership.rows[0].id, student.classroom.teacherMemberId]
            );
            if (assignedRole.rowCount !== 1) {
              const error = new Error("Student role is not configured.");
              error.code = "STUDENT_ROLE_NOT_CONFIGURED";
              throw error;
            }
            await audit(client, {
              classId: student.classroom.id,
              actorUserId: request.user.id,
              action: "IMPORT_STUDENTS",
              targetType: "user",
              targetId: insertedUser.rows[0].id,
              details: {
                username: student.username,
                studentNumber: student.studentCode,
                classCode: student.classroom.classCode,
                ip: request.ip
              }
            });
            batchCreated++;
          }
          await client.query("COMMIT");
          report.created += batchCreated;
          report.skipped += batchSkipped;
          report.errors.push(...batchErrors);
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        }
      }
    } finally {
      client.release();
    }
    response.json(report);
  })
);

app.post("/api/classes/:classId/students", requireAuthentication, requireSameOrigin, classPermission("students:list"), asyncRoute(async (request, response) => {
  if (!request.classAccess.roles.has("ROLE_TEACHER")) {
    return response.status(403).json({ error: "Chỉ giáo viên của lớp mới được tạo tài khoản học sinh." });
  }
  const fullName = typeof request.body?.fullName === "string" ? request.body.fullName.trim() : "";
  if (typeof fullName !== "string" || !fullName.trim() || fullName.trim().length > 120) {
    return response.status(400).json({ error: "Vui lòng nhập họ tên học sinh (tối đa 120 ký tự)." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { studentNumber, username } = await nextStudentIdentity(client);
    const password = `Ct-${randomBytes(9).toString("base64url")}`;
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await client.query(
      `INSERT INTO users (
         username, password_hash, full_name, student_number, is_active, is_teacher,
         is_admin, is_super_admin, must_change_password, password_reset_expires_at
       )
       VALUES ($1, $2, $3, $4, TRUE, FALSE, FALSE, FALSE, TRUE, NOW() + INTERVAL '24 hours')
       RETURNING id`,
      [username.trim().toLowerCase(), passwordHash, fullName, studentNumber]
    );
    const membership = await client.query(
      "INSERT INTO class_members (class_id, user_id) VALUES ($1, $2) RETURNING id",
      [request.params.classId, user.rows[0].id]
    );
    const assignedRole = await client.query(
      `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
       SELECT $1, $2, roles.id, $3 FROM roles WHERE roles.name = 'ROLE_STUDENT'`,
      [request.params.classId, membership.rows[0].id, request.classAccess.memberId]
    );
    if (assignedRole.rowCount !== 1) {
      const error = new Error("Student role is not configured.");
      error.code = "STUDENT_ROLE_NOT_CONFIGURED";
      throw error;
    }
    await audit(client, { classId: request.params.classId, actorUserId: request.user.id,
      action: "student.account_created", targetType: "user", targetId: user.rows[0].id,
      details: { username } });
    await client.query("COMMIT");
    response.status(201).json({ account: { id: studentNumber, studentNumber, username, fullName, password } });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return response.status(409).json({ error: "Tên đăng nhập hoặc mã học sinh đã được sử dụng." });
    if (error.code === "23503") return response.status(404).json({ error: "Không tìm thấy lớp hoặc thành viên liên quan." });
    throw error;
  } finally {
    client.release();
  }
}));

app.post("/api/classes/:classId/students/bulk", requireAuthentication, requireSameOrigin, classPermission("students:list"), asyncRoute(async (request, response) => {
  if (!request.classAccess.roles.has("ROLE_TEACHER")) {
    return response.status(403).json({ error: "Chỉ giáo viên của lớp mới được tạo tài khoản học sinh." });
  }
  const entries = request.body?.students;
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 50) {
    return response.status(400).json({ error: "Hãy nhập từ 1 đến 50 học sinh mỗi lần." });
  }
  const studentsToCreate = [];
  for (const entry of entries) {
    const fullName = typeof entry === "string" ? entry.trim() : typeof entry?.fullName === "string" ? entry.fullName.trim() : "";
    if (!fullName || fullName.length > 120) {
      return response.status(400).json({ error: "Mỗi dòng cần có họ tên học sinh (tối đa 120 ký tự)." });
    }
    studentsToCreate.push({ fullName, password: `Ct-${randomBytes(9).toString("base64url")}` });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const student of studentsToCreate) {
      Object.assign(student, await nextStudentIdentity(client));
      const passwordHash = await bcrypt.hash(student.password, 12);
      const user = await client.query(
        `INSERT INTO users (
           username, password_hash, full_name, student_number, is_active, is_teacher,
           is_admin, is_super_admin, must_change_password, password_reset_expires_at
         )
         VALUES ($1, $2, $3, $4, TRUE, FALSE, FALSE, FALSE, TRUE, NOW() + INTERVAL '24 hours')
         RETURNING id`,
        [student.username, passwordHash, student.fullName, student.studentNumber]
      );
      const membership = await client.query(
        "INSERT INTO class_members (class_id, user_id) VALUES ($1, $2) RETURNING id",
        [request.params.classId, user.rows[0].id]
      );
      const assignedRole = await client.query(
        `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
         SELECT $1, $2, roles.id, $3 FROM roles WHERE roles.name = 'ROLE_STUDENT'`,
        [request.params.classId, membership.rows[0].id, request.classAccess.memberId]
      );
      if (assignedRole.rowCount !== 1) {
        const error = new Error("Student role is not configured.");
        error.code = "STUDENT_ROLE_NOT_CONFIGURED";
        throw error;
      }
      await audit(client, {
        classId: request.params.classId,
        actorUserId: request.user.id,
        action: "student.account_created",
        targetType: "user",
        targetId: user.rows[0].id,
        details: { username: student.username }
      });
    }
    await client.query("COMMIT");
    response.status(201).json({ accounts: studentsToCreate.map(({ studentNumber, username, fullName, password }) => ({ studentNumber, username, fullName, password })) });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return response.status(409).json({ error: "Có mã học sinh hoặc tên đăng nhập đã tồn tại. Chưa tài khoản nào được tạo; hãy sửa danh sách rồi thử lại." });
    if (error.code === "23503") return response.status(404).json({ error: "Không tìm thấy lớp hoặc thành viên liên quan. Chưa tài khoản nào được tạo." });
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/admin/teachers", requireAuthentication, requireAdminPermission("teachers:manage"), asyncRoute(async (_request, response) => {
  const result = await pool.query(
    `SELECT id, username, full_name AS "fullName", is_active AS "isActive", created_at AS "createdAt"
     FROM users
     WHERE is_teacher = TRUE AND is_admin = FALSE
     ORDER BY full_name, username`
  );
  response.json({ teachers: result.rows });
}));

app.post(
  "/api/admin/teachers",
  requireAuthentication,
  requireSameOrigin,
  requireAdminPermission("teachers:manage"),
  asyncRoute(async (request, response) => {
    const names = request.body?.teachers;
    if (!Array.isArray(names) || names.length < 1 || names.length > 50 ||
        names.some((name) => typeof name !== "string" || !name.trim() || name.trim().length > 120)) {
      return response.status(400).json({ error: "Nhập từ 1 đến 50 họ tên giáo viên, mỗi tên tối đa 120 ký tự." });
    }
    const normalizedNames = names.map((name) => name.trim());
    let client;
    const accounts = [];
    try {
      client = await pool.connect();
      await client.query("BEGIN");
      for (const fullName of normalizedNames) {
        const stem = fullName.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
          .replace(/[^a-z0-9]+/g, ".").replace(/^\.|\.$/g, "").slice(0, 12) || "giao.vien";
        const password = `Ct-${randomBytes(9).toString("base64url")}`;
        const passwordHash = await bcrypt.hash(password, 12);
        let username;
        let teacherId;

        for (let attempt = 0; attempt < 5; attempt++) {
          username = `gv.${stem}.${randomBytes(8).toString("hex")}`.trim().toLowerCase();
          const inserted = await client.query(
            `INSERT INTO users (
               username, password_hash, full_name, is_active, is_teacher,
               is_admin, is_super_admin, must_change_password, password_reset_expires_at
             )
             VALUES ($1, $2, $3, TRUE, TRUE, FALSE, FALSE, TRUE, NOW() + INTERVAL '24 hours')
             ON CONFLICT (username) DO NOTHING
             RETURNING id`,
            [username, passwordHash, fullName]
          );
          teacherId = inserted.rows[0]?.id;
          if (teacherId) break;
        }

        if (!teacherId) {
          const error = new Error("Could not generate a unique teacher username.");
          error.code = "TEACHER_USERNAME_COLLISION";
          throw error;
        }

        await client.query(
          `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
           VALUES ($1, 'CREATE_USER', 'user', $2, $3::jsonb)`,
          [request.user.id, teacherId, JSON.stringify({ username, fullName, role: "teacher", ip: request.ip })]
        );
        accounts.push({ fullName, username, password });
      }
      await client.query("COMMIT");
    } catch (error) {
      if (client) await client.query("ROLLBACK");
      if (error.code === "TEACHER_USERNAME_COLLISION" || error.code === "23505") {
        return response.status(409).json({ error: "Tên đăng nhập đã được sử dụng. Chưa tài khoản nào được tạo; vui lòng thử lại." });
      }
      throw error;
    } finally {
      client?.release();
    }
    response.status(201).json({ accounts });
  })
);

app.post("/api/admin/admins", requireAuthentication, requireSameOrigin, asyncRoute(async (request, response) => {
  if (!request.user.isAdmin || (!request.user.isSuperAdmin && !request.user.adminPermissions?.includes("admins:manage"))) {
    return response.status(403).json({ error: "Tài khoản quản trị chưa được cấp quyền tạo admin." });
  }
  const { fullName, username: rawUsername, password } = request.body || {};
  const username = typeof rawUsername === "string" ? rawUsername.trim().toLowerCase() : "";
  if (typeof fullName !== "string" || !fullName.trim() || fullName.trim().length > 120 ||
      !/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username) ||
      typeof password !== "string" || password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
    return response.status(400).json({ error: "Thông tin tài khoản quản trị không hợp lệ." });
  }
  const client = await pool.connect();
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    await client.query("BEGIN");
    const created = await client.query(
      "INSERT INTO users (username, password_hash, full_name, is_admin) VALUES ($1, $2, $3, TRUE) RETURNING id",
      [username, passwordHash, fullName.trim()]
    );
    await client.query(
      `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
       VALUES ($1, 'CREATE_USER', 'user', $2, $3::jsonb)`,
      [request.user.id, created.rows[0].id, JSON.stringify({ username, fullName: fullName.trim(), role: "admin", ip: request.ip })]
    );
    await client.query("COMMIT");
    response.status(201).json({ username, fullName: fullName.trim() });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return response.status(409).json({ error: "Tên đăng nhập đã được sử dụng." });
    throw error;
  } finally { client.release(); }
}));

app.get(
  ["/api/admin/users", "/api/admin/accounts"],
  requireAuthentication,
  requireAdminPermission("accounts:manage"),
  asyncRoute(async (request, response) => {
  const query = typeof (request.query.search ?? request.query.q) === "string"
    ? (request.query.search ?? request.query.q).trim().slice(0, 120)
    : "";
  const type = typeof (request.query.role ?? request.query.type) === "string"
    ? request.query.role ?? request.query.type
    : "";
  const status = typeof request.query.status === "string" ? request.query.status : "";
  const page = request.query.page === undefined ? 1 : Number(request.query.page);
  const pageSize = request.query.pageSize === undefined ? 25 : Number(request.query.pageSize);
  const classId = typeof request.query.classId === "string" ? request.query.classId : "";
  const parseDateFilter = (value) => {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
    const date = new Date(`${value}T00:00:00.000Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value ? value : null;
  };
  const from = request.query.from ? parseDateFilter(request.query.from) : null;
  const to = request.query.to ? parseDateFilter(request.query.to) : null;
  if ((request.query.from && !from) || (request.query.to && !to)) {
    return response.status(400).json({ error: "Ngày lọc tài khoản không hợp lệ." });
  }
  if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    return response.status(400).json({ error: "Thông tin phân trang không hợp lệ; pageSize tối đa là 100." });
  }
  if (type && !["student", "teacher", "admin", "super_admin"].includes(type)) {
    return response.status(400).json({ error: "Loại tài khoản lọc không hợp lệ." });
  }
  if (status && !["active", "inactive", "locked"].includes(status)) {
    return response.status(400).json({ error: "Trạng thái tài khoản lọc không hợp lệ." });
  }
  if (classId && !UUID_PATTERN.test(classId)) {
    return response.status(400).json({ error: "Mã lớp không hợp lệ." });
  }

  const conditions = [];
  const parameters = [];
  const bind = (value) => {
    parameters.push(value);
    return `$${parameters.length}`;
  };
  if (query) {
    const value = bind(`%${query}%`);
    conditions.push(`(users.username ILIKE ${value} OR users.full_name ILIKE ${value})`);
  }
  if (type) {
    const value = bind(type);
    conditions.push(`CASE WHEN users.is_super_admin THEN 'super_admin'
                          WHEN users.is_admin THEN 'admin'
                          WHEN users.is_teacher THEN 'teacher'
                          WHEN users.student_number IS NOT NULL THEN 'student'
                          ELSE 'user' END = ${value}`);
  }
  if (status) conditions.push(`users.is_active = ${bind(status === "active")}`);
  if (classId) {
    const value = bind(classId);
    conditions.push(`EXISTS (SELECT 1 FROM class_members cm WHERE cm.user_id = users.id AND cm.class_id = ${value})`);
  }
  if (from) conditions.push(`users.created_at >= ${bind(from)}::date`);
  if (to) conditions.push(`users.created_at < ${bind(to)}::date + INTERVAL '1 day'`);
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const countResult = await pool.query(`SELECT COUNT(*)::INT AS total FROM users ${whereClause}`, parameters);
  const total = countResult.rows[0].total;
  const offset = (page - 1) * pageSize;
  if (!Number.isSafeInteger(offset)) {
    return response.status(400).json({ error: "Số trang vượt quá giới hạn." });
  }
  const limitPlaceholder = bind(pageSize);
  const offsetPlaceholder = bind(offset);
  const result = await pool.query(
    `SELECT users.id, users.username, users.full_name AS "fullName",
            users.is_active AS "isActive", users.must_change_password AS "mustChangePassword",
            users.is_admin AS "isAdmin", users.is_super_admin AS "isSuperAdmin",
            ARRAY(SELECT admin_permissions.permission_name FROM admin_permissions WHERE admin_permissions.user_id = users.id) AS "adminPermissions",
            users.created_at AS "createdAt",
            (SELECT COUNT(DISTINCT cm.class_id)::INT FROM class_members cm WHERE cm.user_id = users.id) AS "classCount",
            (SELECT COUNT(DISTINCT cr.id)::INT FROM conduct_records cr
             JOIN class_members cm ON cm.id IN (cr.student_member_id, cr.recorder_member_id)
             WHERE cm.user_id = users.id) AS "relatedRecordCount",
            CASE WHEN users.is_super_admin THEN 'super_admin'
                 WHEN users.is_admin THEN 'admin'
                 WHEN users.is_teacher THEN 'teacher'
                 WHEN users.student_number IS NOT NULL THEN 'student'
                 ELSE 'user' END AS type
     FROM users
     ${whereClause}
     ORDER BY users.created_at DESC, users.id
     LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder}`,
    parameters
  );
  response.json({
    users: result.rows,
    accounts: result.rows,
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize)
  });
}));

const updateAdminUserStatus = asyncRoute(async (request, response) => {
  const userId = request.params.userId || request.params.accountId;
  const isActive = request.body?.isActive;
  const expectedConfirmation = isActive === false ? "DISABLE ACCOUNT" : "ENABLE ACCOUNT";
  if (!UUID_PATTERN.test(userId) || typeof isActive !== "boolean" ||
      request.body?.confirmText !== expectedConfirmation) {
    return response.status(400).json({ error: "Mã tài khoản hoặc nội dung xác nhận trạng thái không hợp lệ." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(7319, 1)");
    const target = await client.query(
      `SELECT id, username, is_admin, is_super_admin, is_active
       FROM users WHERE id = $1 FOR UPDATE`,
      [userId]
    );
    if (!target.rowCount) {
      await client.query("ROLLBACK");
      return response.status(404).json({ error: "Không tìm thấy tài khoản." });
    }

    const account = target.rows[0];
    if (account.is_super_admin && !request.user.isSuperAdmin) {
      await client.query("ROLLBACK");
      return response.status(403).json({ error: "Chỉ Super Admin mới được thay đổi trạng thái tài khoản Super Admin." });
    }
    if (!isActive && account.is_super_admin) {
      const activeSuperAdmins = await client.query(
        "SELECT COUNT(*)::INT AS count FROM users WHERE is_super_admin = TRUE AND is_active = TRUE"
      );
      if (activeSuperAdmins.rows[0].count <= 1) {
        await client.query("ROLLBACK");
        return response.status(409).json({ error: "Không thể vô hiệu hóa Super Admin đang hoạt động cuối cùng." });
      }
    }

    const updated = await client.query(
      "UPDATE users SET is_active = $2 WHERE id = $1 RETURNING id, username, is_active",
      [userId, isActive]
    );
    let revokedSessions = 0;
    if (!isActive) {
      const sessions = await client.query("DELETE FROM auth_sessions WHERE user_id = $1", [userId]);
      revokedSessions = sessions.rowCount;
    }
    await client.query(
      `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
       VALUES ($1, $2, 'user', $3, $4::jsonb)`,
      [request.user.id, isActive ? "ENABLE_USER" : "DISABLE_USER", userId,
        JSON.stringify({
          username: updated.rows[0].username,
          isActive,
          revokedSessions,
          ip: request.ip
        })]
    );
    await client.query("COMMIT");
    response.json({ userId: updated.rows[0].id, isActive: updated.rows[0].is_active, revokedSessions });
  } catch (error) {
    await client.query("ROLLBACK");
    if (["23503", "23505", "23514", "23P01"].includes(error.code)) {
      return response.status(409).json({ error: "Không thể thay đổi trạng thái tài khoản do ràng buộc dữ liệu." });
    }
    throw error;
  } finally {
    client.release();
  }
});

app.patch(
  ["/api/admin/users/:userId/status", "/api/admin/accounts/:accountId/status"],
  requireAuthentication,
  requireSameOrigin,
  requireAdminPermission("accounts:manage"),
  updateAdminUserStatus
);

app.post(
  "/api/admin/maintenance/disable-non-admins",
  requireAuthentication,
  requireSameOrigin,
  requireSuperAdmin,
  asyncRoute(async (request, response) => {
    if (request.body?.confirmText !== "DISABLE ALL NON-ADMINS") {
      return response.status(400).json({ error: "Cần nhập chính xác DISABLE ALL NON-ADMINS để xác nhận." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const accounts = await client.query(
        "SELECT id FROM users WHERE is_admin = FALSE AND is_super_admin = FALSE FOR UPDATE"
      );
      const accountIds = accounts.rows.map((account) => account.id);
      let disabledCount = 0;
      let revokedSessionCount = 0;

      if (accountIds.length) {
        const disabled = await client.query(
          "UPDATE users SET is_active = FALSE WHERE id = ANY($1::uuid[]) AND is_active = TRUE RETURNING id",
          [accountIds]
        );
        disabledCount = disabled.rowCount;
        const sessions = await client.query(
          "DELETE FROM auth_sessions WHERE user_id = ANY($1::uuid[])",
          [accountIds]
        );
        revokedSessionCount = sessions.rowCount;
      }

      await audit(client, {
        actorUserId: request.user.id,
        action: "admin.maintenance_disabled_non_admins",
        targetType: "user",
        targetId: "all_non_admins",
        details: { disabledCount, revokedSessionCount, ip: request.ip }
      });
      await client.query("COMMIT");
      response.json({ disabledCount });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  })
);

app.post("/api/admin/accounts/:accountId/password-reset", requireAuthentication, requireSameOrigin,
  requireAdminPermission("accounts:manage"), asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.accountId)) return response.status(400).json({ error: "Mã tài khoản không hợp lệ." });
    if (request.params.accountId === request.user.id) return response.status(400).json({ error: "Hãy đổi mật khẩu của chính bạn trong phần Cá nhân." });
    const target = await pool.query("SELECT username, is_super_admin FROM users WHERE id = $1", [request.params.accountId]);
    if (!target.rowCount) return response.status(404).json({ error: "Không tìm thấy tài khoản." });
    if (target.rows[0].is_super_admin && !request.user.isSuperAdmin) {
      return response.status(403).json({ error: "Chỉ Super Admin mới được hỗ trợ đặt lại mật khẩu Super Admin." });
    }
    const temporaryPassword = `Ct-${randomBytes(12).toString("base64url")}`;
    const passwordHash = await bcrypt.hash(temporaryPassword, 12);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "UPDATE users SET password_hash = $2, must_change_password = TRUE, password_reset_expires_at = NOW() + INTERVAL '24 hours' WHERE id = $1",
        [request.params.accountId, passwordHash]
      );
      await client.query("DELETE FROM auth_sessions WHERE user_id = $1", [request.params.accountId]);
      await client.query(
        `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
         VALUES ($1, 'RESET_PASSWORD', 'user', $2, $3::jsonb)`,
        [request.user.id, request.params.accountId, JSON.stringify({ username: target.rows[0].username, sessionsRevoked: true, ip: request.ip })]
      );
      await client.query("COMMIT");
      response.json({ username: target.rows[0].username, temporaryPassword });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.post("/api/admin/accounts/:accountId/revoke-sessions", requireAuthentication, requireSameOrigin,
  requireAdminPermission("accounts:manage"), asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.accountId)) return response.status(400).json({ error: "Mã tài khoản không hợp lệ." });
    if (request.params.accountId === request.user.id) return response.status(400).json({ error: "Dùng nút đăng xuất để kết thúc phiên hiện tại." });
    const target = await pool.query("SELECT username, is_super_admin FROM users WHERE id = $1", [request.params.accountId]);
    if (!target.rowCount) return response.status(404).json({ error: "Không tìm thấy tài khoản." });
    if (target.rows[0].is_super_admin && !request.user.isSuperAdmin) return response.status(403).json({ error: "Chỉ Super Admin mới được thu hồi phiên của Super Admin." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const deleted = await client.query("DELETE FROM auth_sessions WHERE user_id = $1", [request.params.accountId]);
      await client.query(
        `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
         VALUES ($1, 'admin.sessions_revoked', 'user', $2, $3::jsonb)`,
        [request.user.id, request.params.accountId, JSON.stringify({ username: target.rows[0].username, sessionCount: deleted.rowCount })]
      );
      await client.query("COMMIT");
      response.json({ revokedCount: deleted.rowCount });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.put("/api/admin/accounts/:accountId/admin-permissions", requireAuthentication, requireSameOrigin, requireSuperAdmin,
  asyncRoute(async (request, response) => {
    const permissionNames = ["accounts:manage", "teachers:manage", "admins:manage", "audit:view", "reports:view"];
    const permissions = request.body?.permissions;
    if (!UUID_PATTERN.test(request.params.accountId) || !Array.isArray(permissions) ||
        permissions.some((permission) => !permissionNames.includes(permission)) || new Set(permissions).size !== permissions.length) {
      return response.status(400).json({ error: "Danh sách quyền admin không hợp lệ." });
    }
    if (request.params.accountId === request.user.id) return response.status(400).json({ error: "Không thể tự cấp hoặc thu hồi quyền của chính mình." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const target = await client.query("SELECT is_admin, is_super_admin FROM users WHERE id = $1 FOR UPDATE", [request.params.accountId]);
      if (!target.rowCount || !target.rows[0].is_admin) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy tài khoản admin thường." });
      }
      if (target.rows[0].is_super_admin) {
        await client.query("ROLLBACK");
        return response.status(400).json({ error: "Quyền chi tiết không áp dụng cho Super Admin." });
      }
      const before = await client.query("SELECT permission_name FROM admin_permissions WHERE user_id = $1", [request.params.accountId]);
      await client.query("DELETE FROM admin_permissions WHERE user_id = $1", [request.params.accountId]);
      for (const permission of permissions) {
        await client.query("INSERT INTO admin_permissions (user_id, permission_name, granted_by_user_id) VALUES ($1, $2, $3)",
          [request.params.accountId, permission, request.user.id]);
      }
      await client.query(
        `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
         VALUES ($1, 'admin.permissions_changed', 'user', $2, $3::jsonb)`,
        [request.user.id, request.params.accountId, JSON.stringify({ before: before.rows.map((row) => row.permission_name), after: permissions })]
      );
      await client.query("COMMIT");
      response.json({ permissions });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.patch("/api/admin/accounts/:accountId/super-admin", requireAuthentication, requireSameOrigin, requireSuperAdmin,
  asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.accountId) || typeof request.body?.isSuperAdmin !== "boolean") {
      return response.status(400).json({ error: "Thông tin vai trò Super Admin không hợp lệ." });
    }
    if (request.params.accountId === request.user.id) return response.status(400).json({ error: "Không thể tự thay đổi vai trò Super Admin." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const target = await client.query("SELECT is_admin, is_super_admin, username FROM users WHERE id = $1 FOR UPDATE", [request.params.accountId]);
      if (!target.rowCount || !target.rows[0].is_admin) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Chỉ tài khoản admin mới có thể nhận vai trò Super Admin." });
      }
      if (!request.body.isSuperAdmin && target.rows[0].is_super_admin) {
        const remaining = await client.query("SELECT COUNT(*)::int AS count FROM users WHERE is_super_admin AND is_active AND id <> $1", [request.params.accountId]);
        if (!remaining.rows[0].count) {
          await client.query("ROLLBACK");
          return response.status(400).json({ error: "Hệ thống phải luôn còn ít nhất một Super Admin đang hoạt động." });
        }
      }
      await client.query("UPDATE users SET is_super_admin = $2 WHERE id = $1", [request.params.accountId, request.body.isSuperAdmin]);
      if (request.body.isSuperAdmin) await client.query("DELETE FROM admin_permissions WHERE user_id = $1", [request.params.accountId]);
      await client.query("DELETE FROM auth_sessions WHERE user_id = $1", [request.params.accountId]);
      await client.query(
        `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details)
         VALUES ($1, 'admin.super_admin_changed', 'user', $2, $3::jsonb)`,
        [request.user.id, request.params.accountId, JSON.stringify({ username: target.rows[0].username, isSuperAdmin: request.body.isSuperAdmin })]
      );
      await client.query("COMMIT");
      response.json({ isSuperAdmin: request.body.isSuperAdmin });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.get("/api/admin/audit", requireAuthentication, requireAdminPermission("audit:view"), asyncRoute(async (_request, response) => {
  const result = await pool.query(
    `SELECT audit_logs.id, audit_logs.action, audit_logs.target_type AS "targetType",
            audit_logs.target_id AS "targetId", audit_logs.details,
            audit_logs.created_at AS "createdAt", actor.username AS "actorUsername", actor.full_name AS "actorName"
     FROM audit_logs LEFT JOIN users AS actor ON actor.id = audit_logs.actor_user_id
     WHERE audit_logs.action LIKE 'admin.%' OR audit_logs.action IN (
       'CREATE_USER', 'DISABLE_USER', 'ENABLE_USER', 'RESET_PASSWORD',
       'CREATE_CLASS', 'DISABLE_CLASS', 'DELETE_CLASS', 'IMPORT_STUDENTS',
       'class.leadership_updated', 'class.group_saved', 'class.group_member_moved',
       'student.removed_from_class', 'conduct.weekly_scores_archived'
     )
     ORDER BY audit_logs.created_at DESC LIMIT 250`
  );
  response.json({ events: result.rows });
}));

app.get("/api/admin/overview", requireAuthentication, asyncRoute(async (request, response) => {
  if ((!request.user.isAdmin && !request.user.isSuperAdmin) ||
      (!request.user.isSuperAdmin && !request.user.adminPermissions?.includes("reports:view"))) {
    return response.status(403).json({ error: "Tài khoản quản trị chưa được cấp quyền xem thống kê hệ thống." });
  }
  const result = await pool.query(
    `SELECT
       (SELECT COUNT(*) FROM users)::INT AS "accountCount",
       (SELECT COUNT(*) FROM users WHERE student_number IS NOT NULL)::INT AS "studentCount",
       (SELECT COUNT(*) FROM users WHERE is_teacher = TRUE AND is_admin = FALSE)::INT AS "teacherCount",
       (SELECT COUNT(*) FROM classes)::INT AS "classCount",
       (SELECT COUNT(*) FROM users WHERE is_active = TRUE)::INT AS "activeAccountCount",
       (SELECT COUNT(*) FROM users WHERE is_active = FALSE)::INT AS "inactiveAccountCount",
       (SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '7 days')::INT AS "createdLast7Days",
       (SELECT COUNT(*)::INT FROM audit_logs
        WHERE created_at >= NOW() - INTERVAL '7 days'
          AND (action ILIKE '%fail%' OR action ILIKE '%suspicious%' OR action ILIKE '%error%')) AS "abnormalActivityCount",
       (SELECT COALESCE(SUM(points), 0)::INT FROM conduct_records
        WHERE kind = 'positive'
          AND record_date >= DATE_TRUNC('month', CURRENT_DATE)::DATE
          AND record_date < (DATE_TRUNC('month', CURRENT_DATE) + INTERVAL '1 month')::DATE) AS "positivePoints",
       (SELECT COALESCE(SUM(points), 0)::INT FROM conduct_records
        WHERE kind = 'negative'
          AND record_date >= DATE_TRUNC('month', CURRENT_DATE)::DATE
          AND record_date < (DATE_TRUNC('month', CURRENT_DATE) + INTERVAL '1 month')::DATE) AS "negativePoints",
       (SELECT COUNT(*)::INT FROM conduct_records WHERE status = 'pending') AS "pendingRecords"`
  );
  response.json({ overview: result.rows[0] });
}));

app.get("/api/session", requireAuthentication, asyncRoute(async (request, response) => {
  const result = await pool.query(
    `SELECT classes.id, classes.name,
            classes.class_code AS "classCode",
            classes.academic_year AS "academicYear",
            ARRAY(SELECT roles.name FROM class_member_roles
                  JOIN roles ON roles.id = class_member_roles.role_id
                  WHERE class_member_roles.class_member_id = class_members.id) AS roles,
            ARRAY(
              SELECT permissions.name
              FROM role_permissions
              JOIN permissions ON permissions.id = role_permissions.permission_id
              WHERE role_permissions.role_id IN (
                SELECT class_member_roles.role_id FROM class_member_roles
                WHERE class_member_roles.class_member_id = class_members.id
              )
              UNION
              SELECT permissions.name
              FROM member_permissions
              JOIN permissions ON permissions.id = member_permissions.permission_id
              WHERE member_permissions.class_member_id = class_members.id
            ) AS permissions
     FROM class_members
     JOIN classes ON classes.id = class_members.class_id
     WHERE class_members.user_id = $1 AND class_members.is_active = TRUE
       AND classes.is_active = TRUE
     ORDER BY classes.name`,
    [request.user.id]
  );
  response.json({ user: request.user, classes: result.rows });
}));

app.post("/api/auth/logout", requireSameOrigin, requireAuthentication, asyncRoute(async (request, response) => {
  await revokeSession(request);
  clearSessionCookie(response);
  response.status(204).end();
}));

app.get("/api/classes", requireAuthentication, asyncRoute(async (request, response) => {
  const result = await pool.query(
    `SELECT classes.id, classes.name,
            classes.class_code AS "classCode",
            classes.academic_year AS "academicYear",
            ARRAY(SELECT roles.name FROM class_member_roles
                  JOIN roles ON roles.id = class_member_roles.role_id
                  WHERE class_member_roles.class_member_id = class_members.id) AS roles,
            ARRAY(
              SELECT permissions.name
              FROM role_permissions
              JOIN permissions ON permissions.id = role_permissions.permission_id
              WHERE role_permissions.role_id IN (
                SELECT class_member_roles.role_id FROM class_member_roles
                WHERE class_member_roles.class_member_id = class_members.id
              )
              UNION
              SELECT permissions.name
              FROM member_permissions
              JOIN permissions ON permissions.id = member_permissions.permission_id
              WHERE member_permissions.class_member_id = class_members.id
            ) AS permissions
     FROM class_members
     JOIN classes ON classes.id = class_members.class_id
     WHERE class_members.user_id = $1 AND class_members.is_active = TRUE
       AND classes.is_active = TRUE
     ORDER BY classes.name`,
    [request.user.id]
  );
  response.json({ classes: result.rows });
}));

app.post("/api/classes", requireAuthentication, requireSameOrigin, asyncRoute(async (request, response) => {
  if (request.user.isAdmin || !request.user.isTeacher) {
    return response.status(403).json({ error: "Chỉ giáo viên mới được tạo lớp." });
  }
  const { name: rawName, academicYear: rawAcademicYear } = request.body || {};
  const name = typeof rawName === "string" ? rawName.trim() : "";
  const academicYear = typeof rawAcademicYear === "string" ? rawAcademicYear.trim() : "";
  if (!name || name.length > 80 || !academicYear || academicYear.length > 20) {
    return response.status(400).json({ error: "Hãy nhập tên lớp và năm học hợp lệ." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const classResult = await client.query(
      "INSERT INTO classes (name, academic_year) VALUES ($1, $2) RETURNING id, name, academic_year AS \"academicYear\"",
      [name, academicYear]
    );
    const classId = classResult.rows[0].id;
    const membership = await client.query(
      "INSERT INTO class_members (class_id, user_id) VALUES ($1, $2) RETURNING id",
      [classId, request.user.id]
    );
    await client.query(
      `INSERT INTO class_member_roles (class_id, class_member_id, role_id)
       SELECT $1, $2, id FROM roles WHERE name = 'ROLE_TEACHER'`,
      [classId, membership.rows[0].id]
    );
    await audit(client, {
      classId,
      actorUserId: request.user.id,
      action: "CREATE_CLASS",
      targetType: "class",
      targetId: classId,
      details: { name, academicYear, ip: request.ip }
    });
    await client.query("COMMIT");
    response.status(201).json({ class: classResult.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return response.status(409).json({ error: "Lớp này đã tồn tại trong năm học đã chọn." });
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/admin/classes", requireAuthentication, requireAdminAccount, asyncRoute(async (_request, response) => {
  const result = await pool.query(
    `SELECT classes.id,
            classes.class_code,
            classes.name AS class_name,
            classes.is_active,
            ARRAY(
              SELECT DISTINCT users.full_name
              FROM class_members
              JOIN users ON users.id = class_members.user_id
              JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
              JOIN roles ON roles.id = class_member_roles.role_id
              WHERE class_members.class_id = classes.id
                AND class_members.is_active = TRUE
                AND users.is_active = TRUE
                AND roles.name = 'ROLE_TEACHER'
              ORDER BY users.full_name
            ) AS teachers,
            (
              SELECT COUNT(DISTINCT class_members.user_id)::INT
              FROM class_members
              JOIN users ON users.id = class_members.user_id
              JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
              JOIN roles ON roles.id = class_member_roles.role_id
              WHERE class_members.class_id = classes.id
                AND class_members.is_active = TRUE
                AND users.is_active = TRUE
                AND roles.name = 'ROLE_STUDENT'
            ) AS student_count,
            (
              SELECT COUNT(DISTINCT class_members.user_id)::INT
              FROM class_members
              JOIN users ON users.id = class_members.user_id
              JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
              JOIN roles ON roles.id = class_member_roles.role_id
              WHERE class_members.class_id = classes.id
                AND class_members.is_active = TRUE
                AND users.is_active = TRUE
                AND roles.name = 'ROLE_TEACHER'
            ) AS teacher_count
     FROM classes
     ORDER BY classes.name, classes.academic_year, classes.id`
  );
  response.json({ classes: result.rows });
}));

app.get("/api/admin/classes/:classId", requireAuthentication, requireAdminAccount, asyncRoute(async (request, response) => {
  if (!UUID_PATTERN.test(request.params.classId)) {
    return response.status(400).json({ error: "Mã lớp không hợp lệ." });
  }
  const result = await pool.query(
    `SELECT classes.id, classes.class_code, classes.name AS class_name,
            classes.academic_year, classes.is_active, classes.created_at AS "createdAt",
            ARRAY(
              SELECT jsonb_build_object('id', users.id, 'username', users.username, 'fullName', users.full_name)
              FROM class_members
              JOIN users ON users.id = class_members.user_id
              JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
              JOIN roles ON roles.id = class_member_roles.role_id
              WHERE class_members.class_id = classes.id
                AND class_members.is_active = TRUE
                AND users.is_active = TRUE
                AND roles.name = 'ROLE_TEACHER'
              GROUP BY users.id, users.username, users.full_name
              ORDER BY users.full_name
            ) AS teachers,
            (SELECT COUNT(DISTINCT cm.user_id)::INT FROM class_members cm
             JOIN class_member_roles cmr ON cmr.class_member_id = cm.id
             JOIN roles r ON r.id = cmr.role_id
             WHERE cm.class_id = classes.id AND cm.is_active AND r.name = 'ROLE_STUDENT') AS "studentCount"
     FROM classes WHERE classes.id = $1`,
    [request.params.classId]
  );
  if (!result.rowCount) return response.status(404).json({ error: "Không tìm thấy lớp." });
  response.json({ class: result.rows[0] });
}));

app.get(["/api/admin/classes/:classId/preview", "/api/admin/classes/:classId/deletion-preview"], requireAuthentication, requireAdminAccount,
  asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.classId)) {
      return response.status(400).json({ error: "Mã lớp không hợp lệ." });
    }
    const classResult = await pool.query(
      `SELECT id, class_code, name AS class_name, academic_year, is_active
       FROM classes WHERE id = $1`,
      [request.params.classId]
    );
    if (!classResult.rowCount) return response.status(404).json({ error: "Không tìm thấy lớp." });

    const countsResult = await pool.query(
      `SELECT
         (SELECT COUNT(*)::INT FROM class_members WHERE class_id = $1) AS memberships,
         (SELECT COUNT(DISTINCT class_members.user_id)::INT
          FROM class_members
          JOIN users ON users.id = class_members.user_id
          JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
          JOIN roles ON roles.id = class_member_roles.role_id
          WHERE class_members.class_id = $1 AND class_members.is_active = TRUE
            AND users.is_active = TRUE AND roles.name = 'ROLE_STUDENT') AS students,
         (SELECT COUNT(DISTINCT class_members.user_id)::INT
          FROM class_members
          JOIN users ON users.id = class_members.user_id
          JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
          JOIN roles ON roles.id = class_member_roles.role_id
          WHERE class_members.class_id = $1 AND class_members.is_active = TRUE
            AND users.is_active = TRUE AND roles.name = 'ROLE_TEACHER') AS teachers,
         (SELECT COUNT(*)::INT FROM class_member_roles WHERE class_id = $1) AS member_roles,
         (SELECT COUNT(*)::INT FROM member_permissions WHERE class_id = $1) AS member_permissions,
         (SELECT COUNT(*)::INT FROM role_requests WHERE class_id = $1) AS role_requests,
         (SELECT COUNT(*)::INT FROM class_groups WHERE class_id = $1) AS groups,
         (SELECT COUNT(*)::INT FROM group_members WHERE class_id = $1) AS group_members,
         (SELECT COUNT(*)::INT FROM conduct_categories WHERE class_id = $1) AS conduct_categories,
         (SELECT COUNT(*)::INT FROM conduct_records WHERE class_id = $1) AS conduct_records,
         (SELECT COUNT(*)::INT FROM conduct_records WHERE class_id = $1 AND kind = 'positive') AS positive_records,
         (SELECT COUNT(*)::INT FROM conduct_records WHERE class_id = $1 AND kind = 'negative') AS violations,
         (SELECT COALESCE(SUM(points), 0)::INT FROM conduct_records WHERE class_id = $1 AND kind = 'positive') AS positive_points,
         (SELECT COALESCE(SUM(points), 0)::INT FROM conduct_records WHERE class_id = $1 AND kind = 'negative') AS negative_points,
         (SELECT COUNT(*)::INT FROM evidence_files WHERE class_id = $1) AS evidence_files,
         (SELECT COUNT(*)::INT FROM class_forum_posts WHERE class_id = $1) AS forum_posts,
         (SELECT COUNT(*)::INT FROM class_weekly_point_periods WHERE class_id = $1) AS weekly_periods,
         (SELECT COUNT(*)::INT FROM class_weekly_point_scores WHERE class_id = $1) AS weekly_scores,
         (SELECT COUNT(*)::INT FROM audit_logs WHERE class_id = $1) AS retained_audit_logs`,
      [request.params.classId]
    );
    response.json({
      class: classResult.rows[0],
      relatedCounts: countsResult.rows[0]
    });
  }));

app.patch("/api/admin/classes/:classId/status", requireAuthentication, requireSameOrigin, requireAdminAccount,
  asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.classId) || typeof request.body?.isActive !== "boolean") {
      return response.status(400).json({ error: "Thông tin trạng thái lớp không hợp lệ." });
    }
    const expectedConfirmation = request.body.isActive ? "ENABLE CLASS" : "DISABLE CLASS";
    if (request.body.confirmText !== expectedConfirmation) {
      return response.status(400).json({ error: `Cần xác nhận bằng nội dung ${expectedConfirmation}.` });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        `UPDATE classes SET is_active = $2
         WHERE id = $1
         RETURNING id, class_code, name AS class_name, is_active`,
        [request.params.classId, request.body.isActive]
      );
      if (!updated.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy lớp." });
      }
      await audit(client, {
        classId: updated.rows[0].id,
        actorUserId: request.user.id,
        action: request.body.isActive ? "ENABLE_CLASS" : "DISABLE_CLASS",
        targetType: "class",
        targetId: updated.rows[0].id,
        details: { classCode: updated.rows[0].class_code, name: updated.rows[0].class_name, ip: request.ip }
      });
      await client.query("COMMIT");
      response.json({ class: updated.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

app.delete("/api/admin/classes/:classId", requireAuthentication, requireSameOrigin, requireSuperAdmin,
  asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.classId)) {
      return response.status(400).json({ error: "Mã lớp không hợp lệ." });
    }
    if (typeof request.body?.confirmClassCode !== "string" ||
        typeof request.body?.confirmText !== "string" ||
        request.body.confirmText !== "DELETE CLASS") {
      return response.status(400).json({ error: "Cần nhập đúng mã lớp và nội dung xác nhận DELETE CLASS." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const classResult = await client.query(
        `SELECT id, class_code, name AS class_name
         FROM classes WHERE id = $1 FOR UPDATE`,
        [request.params.classId]
      );
      if (!classResult.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy lớp." });
      }
      const classInfo = classResult.rows[0];
      if (!classInfo.class_code || request.body.confirmClassCode !== classInfo.class_code) {
        await client.query("ROLLBACK");
        return response.status(409).json({ error: "Mã xác nhận không khớp chính xác với mã lớp." });
      }

      await client.query(
        `SELECT class_members.id
         FROM class_members
         JOIN users ON users.id = class_members.user_id
         WHERE class_members.class_id = $1
         FOR UPDATE OF class_members, users`,
        [request.params.classId]
      );
      const orphanStudentResult = await client.query(
        `SELECT DISTINCT users.id
         FROM class_members
         JOIN users ON users.id = class_members.user_id
         JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
         JOIN roles ON roles.id = class_member_roles.role_id
         WHERE class_members.class_id = $1
           AND roles.name = 'ROLE_STUDENT'
           AND users.student_number IS NOT NULL
           AND users.is_teacher = FALSE
           AND users.is_admin = FALSE
           AND users.is_super_admin = FALSE
           AND NOT EXISTS (
             SELECT 1 FROM class_members AS other_memberships
             WHERE other_memberships.user_id = users.id
               AND other_memberships.class_id <> $1
           )`,
        [request.params.classId]
      );
      const orphanStudentIds = orphanStudentResult.rows.map((row) => row.id);
      const sharedUsersResult = await client.query(
        `SELECT COUNT(DISTINCT class_members.user_id)::INT AS count
         FROM class_members
         WHERE class_members.class_id = $1
           AND EXISTS (
             SELECT 1 FROM class_members AS other_memberships
             WHERE other_memberships.user_id = class_members.user_id
               AND other_memberships.class_id <> $1
           )`,
        [request.params.classId]
      );
      const keptSharedUsers = sharedUsersResult.rows[0]?.count || 0;
      const deletedRelations = {};
      const relationDeletes = [
        ["evidence_files", "DELETE FROM evidence_files WHERE class_id = $1"],
        ["weekly_scores", "DELETE FROM class_weekly_point_scores WHERE class_id = $1"],
        ["weekly_periods", "DELETE FROM class_weekly_point_periods WHERE class_id = $1"],
        ["conduct_records", "DELETE FROM conduct_records WHERE class_id = $1"],
        ["forum_posts", "DELETE FROM class_forum_posts WHERE class_id = $1"],
        ["group_members", "DELETE FROM group_members WHERE class_id = $1"],
        ["role_requests", "DELETE FROM role_requests WHERE class_id = $1"],
        ["member_permissions", "DELETE FROM member_permissions WHERE class_id = $1"],
        ["member_roles", "DELETE FROM class_member_roles WHERE class_id = $1"],
        ["groups", "DELETE FROM class_groups WHERE class_id = $1"],
        ["conduct_categories", "DELETE FROM conduct_categories WHERE class_id = $1"]
      ];
      for (const [relation, sql] of relationDeletes) {
        const result = await client.query(sql, [request.params.classId]);
        deletedRelations[relation] = result.rowCount;
      }

      const memberships = await client.query(
        "DELETE FROM class_members WHERE class_id = $1",
        [request.params.classId]
      );
      deletedRelations.class_members = memberships.rowCount;

      let deletedStudents = 0;
      if (orphanStudentIds.length) {
        const sessions = await client.query(
          "DELETE FROM auth_sessions WHERE user_id = ANY($1::uuid[])",
          [orphanStudentIds]
        );
        deletedRelations.auth_sessions = sessions.rowCount;
        const students = await client.query(
          `DELETE FROM users
           WHERE id = ANY($1::uuid[])
             AND is_teacher = FALSE
             AND is_admin = FALSE
             AND is_super_admin = FALSE
           RETURNING id`,
          [orphanStudentIds]
        );
        deletedStudents = students.rowCount;
      } else {
        deletedRelations.auth_sessions = 0;
      }

      await audit(client, {
        classId: request.params.classId,
        actorUserId: request.user.id,
        action: "DELETE_CLASS",
        targetType: "class",
        targetId: request.params.classId,
        details: {
          classCode: classInfo.class_code,
          className: classInfo.class_name,
          deletedRelations,
          deletedStudents,
          keptSharedUsers,
          ip: request.ip
        }
      });
      const deletedClassResult = await client.query(
        "DELETE FROM classes WHERE id = $1 RETURNING id",
        [request.params.classId]
      );
      if (!deletedClassResult.rowCount) {
        const error = new Error("Class disappeared during deletion.");
        error.code = "CLASS_DELETE_RACE";
        throw error;
      }
      await client.query("COMMIT");
      response.json({
        deletedClass: {
          id: classInfo.id,
          class_code: classInfo.class_code,
          class_name: classInfo.class_name
        },
        deletedRelations,
        deletedStudents,
        keptSharedUsers
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

app.get("/api/classes/:classId/students", requireAuthentication, classPermission("classes:read"), asyncRoute(async (request, response) => {
  if (request.user.isAdmin) return response.status(403).json({ error: "Tài khoản quản trị chỉ được xem số liệu tổng hợp, không xem danh sách học sinh." });
  const { permissions, memberId, roles } = request.classAccess;
  let scope = "";
  if (!permissions.has("students:list")) {
    if (permissions.has("conduct:view_group") && roles.has("ROLE_GROUP_LEADER")) {
      scope = `AND class_members.id IN (
        SELECT group_members.class_member_id
        FROM group_members
        WHERE group_members.class_id = class_members.class_id
          AND group_members.group_id IN (
            SELECT class_groups.id FROM class_groups
            WHERE class_groups.class_id = class_members.class_id
              AND class_groups.leader_member_id = $2
          )
      )`;
    } else if (permissions.has("conduct:view_own")) {
      scope = "AND class_members.id = $2";
    } else {
      return response.status(403).json({ error: "You do not have permission to view this class roster." });
    }
  }
  const result = await pool.query(
    `SELECT users.student_number AS id,
            ${roles.has("ROLE_TEACHER") ? "users.username," : ""}
            class_members.id AS "memberId", users.full_name AS name, users.avatar_color AS color,
            users.avatar_data AS "avatarData",
            classes.name AS "className"
     FROM class_members
     JOIN users ON users.id = class_members.user_id
     JOIN classes ON classes.id = class_members.class_id
     WHERE class_members.class_id = $1
       AND class_members.is_active = TRUE
       AND users.is_active = TRUE
       ${scope}
       AND EXISTS (
         SELECT 1 FROM class_member_roles
         JOIN roles ON roles.id = class_member_roles.role_id
         WHERE class_member_roles.class_member_id = class_members.id
           AND roles.name = 'ROLE_STUDENT'
       )
     ORDER BY users.full_name`,
    scope ? [request.params.classId, memberId] : [request.params.classId]
  );
  response.json({ students: result.rows });
}));

app.delete(
  "/api/teacher/students/:studentId",
  requireAuthentication,
  requireSameOrigin,
  requireTeacherAccount,
  asyncRoute(async (request, response) => {
    if (!UUID_PATTERN.test(request.params.studentId)) {
      return response.status(400).json({ error: "Mã học sinh không hợp lệ." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const studentResult = await client.query(
        `SELECT class_members.id AS "memberId", class_members.class_id AS "classId",
                class_members.user_id AS "userId", users.full_name AS "fullName",
                users.student_number AS "studentNumber"
         FROM class_members
         JOIN users ON users.id = class_members.user_id
         WHERE class_members.id = $1
           AND class_members.is_active = TRUE
           AND users.is_active = TRUE
           AND EXISTS (
             SELECT 1
             FROM class_member_roles
             JOIN roles ON roles.id = class_member_roles.role_id
             WHERE class_member_roles.class_member_id = class_members.id
               AND roles.name = 'ROLE_STUDENT'
           )
         FOR UPDATE OF class_members, users`,
        [request.params.studentId]
      );
      if (!studentResult.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy học sinh đang hoạt động." });
      }
      const student = studentResult.rows[0];
      const accessResult = await client.query(
        `SELECT
           EXISTS (
             SELECT 1
             FROM class_members
             JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
             JOIN roles ON roles.id = class_member_roles.role_id
             WHERE class_members.user_id = $1
               AND class_members.class_id = $2
               AND class_members.is_active = TRUE
               AND roles.name = 'ROLE_TEACHER'
           ) AS is_teacher,
           EXISTS (
             SELECT 1
             FROM class_members
             JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
             JOIN roles ON roles.id = class_member_roles.role_id
             JOIN role_permissions ON role_permissions.role_id = roles.id
             JOIN permissions ON permissions.id = role_permissions.permission_id
             WHERE class_members.user_id = $1
               AND class_members.class_id = $2
               AND class_members.is_active = TRUE
               AND roles.name = 'ROLE_TEACHER'
               AND permissions.name = 'students:delete'
             UNION
             SELECT 1
             FROM class_members
             JOIN member_permissions ON member_permissions.class_member_id = class_members.id
             JOIN permissions ON permissions.id = member_permissions.permission_id
             WHERE class_members.user_id = $1
               AND class_members.class_id = $2
               AND class_members.is_active = TRUE
               AND permissions.name = 'students:delete'
           ) AS can_delete`,
        [request.user.id, student.classId]
      );
      const access = accessResult.rows[0];
      if (!access?.is_teacher || !access.can_delete) {
        await client.query("ROLLBACK");
        return response.status(403).json({ error: "Bạn không có quyền vô hiệu hóa học sinh trong lớp này." });
      }

      const deactivated = await client.query(
        "UPDATE users SET is_active = FALSE WHERE id = $1 AND is_active = TRUE RETURNING id",
        [student.userId]
      );
      if (!deactivated.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy học sinh đang hoạt động." });
      }
      await audit(client, {
        classId: student.classId,
        actorUserId: request.user.id,
        action: "teacher.student_deactivated",
        targetType: "user",
        targetId: student.userId,
        details: { studentNumber: student.studentNumber, fullName: student.fullName }
      });
      await client.query("COMMIT");
      response.status(204).end();
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  })
);

app.delete("/api/classes/:classId/students/:studentNumber", requireAuthentication, requireSameOrigin,
  classPermission("students:list"), requireClassTeacher, asyncRoute(async (request, response) => {
    const studentNumber = typeof request.params.studentNumber === "string" ? request.params.studentNumber.trim() : "";
    if (!studentNumber || studentNumber.length > 32) return response.status(400).json({ error: "Mã học sinh không hợp lệ." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [request.params.classId]);
      const student = await client.query(
        `SELECT class_members.id, class_members.user_id, users.full_name, users.student_number
         FROM class_members JOIN users ON users.id = class_members.user_id
         WHERE class_members.class_id = $1 AND users.student_number = $2 AND class_members.is_active = TRUE
           AND EXISTS (SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
                       WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT')
         FOR UPDATE OF class_members`,
        [request.params.classId, studentNumber]
      );
      if (!student.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy học sinh đang hoạt động trong lớp." });
      }
      const member = student.rows[0];
      await client.query("UPDATE class_members SET is_active = FALSE WHERE id = $1", [member.id]);
      await client.query("DELETE FROM group_members WHERE class_id = $1 AND class_member_id = $2", [request.params.classId, member.id]);
      await client.query("UPDATE class_groups SET leader_member_id = NULL WHERE class_id = $1 AND leader_member_id = $2", [request.params.classId, member.id]);
      await client.query("DELETE FROM member_permissions WHERE class_id = $1 AND class_member_id = $2", [request.params.classId, member.id]);
      await client.query("DELETE FROM class_member_roles WHERE class_id = $1 AND class_member_id = $2", [request.params.classId, member.id]);
      await client.query("DELETE FROM role_requests WHERE class_id = $1 AND requested_by_member_id = $2 AND status = 'pending'", [request.params.classId, member.id]);
      await client.query(
        `INSERT INTO audit_logs (class_id, actor_user_id, action, target_type, target_id, details)
         VALUES ($1, $2, 'student.removed_from_class', 'class_member', $3, $4::jsonb)`,
        [request.params.classId, request.user.id, member.id, JSON.stringify({ studentNumber: member.student_number, fullName: member.full_name })]
      );
      await client.query("COMMIT");
      response.json({ removed: true, studentNumber: member.student_number });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.get("/api/classes/:classId/conduct-records", requireAuthentication, classPermission("classes:read"), asyncRoute(async (request, response) => {
  if (request.user.isAdmin) return response.status(403).json({ error: "Admin chỉ được xem điểm rèn luyện tổng hợp toàn hệ thống." });
  const { memberId } = request.classAccess;
  const scope = conductVisibility(request.classAccess);
  if (scope === null) {
    return response.status(403).json({ error: "You do not have permission to view conduct records." });
  }

  const result = await pool.query(
    `SELECT conduct_records.id, users.student_number AS "studentId",
            conduct_records.title, conduct_records.description, conduct_records.kind,
            conduct_records.points, conduct_records.record_date::TEXT AS date,
            conduct_records.source, conduct_records.evidence_name AS evidence, conduct_records.status,
            recorder.full_name AS recorder, conduct_records.created_at::TEXT AS "createdAt",
            FLOOR(EXTRACT(EPOCH FROM conduct_records.created_at) * 1000000)::BIGINT AS "createdAtUs"
     FROM conduct_records
     JOIN class_members AS student_member ON student_member.id = conduct_records.student_member_id
     JOIN users ON users.id = student_member.user_id
     JOIN class_members AS recorder_member ON recorder_member.id = conduct_records.recorder_member_id
     JOIN users AS recorder ON recorder.id = recorder_member.user_id
     WHERE conduct_records.class_id = $1 ${scope}
     ORDER BY conduct_records.record_date DESC, conduct_records.created_at DESC`,
    scope.includes("$2") ? [request.params.classId, memberId] : [request.params.classId]
  );
  response.json({ incidents: result.rows });
}));

app.get("/api/classes/:classId/conduct-categories", requireAuthentication, classPermission("classes:read"), asyncRoute(async (request, response) => {
  const result = await pool.query(
    `SELECT id, name, kind, points FROM conduct_categories
     WHERE class_id = $1 ORDER BY kind, name`,
    [request.params.classId]);
  response.json({ categories: result.rows });
}));

app.post("/api/classes/:classId/conduct-categories", requireAuthentication, requireSameOrigin,
  classPermission("roles:manage"), requireClassTeacher, asyncRoute(async (request, response) => {
    const { name, kind, points } = request.body || {};
    if (typeof name !== "string" || !name.trim() || name.trim().length > 80 ||
        !["positive", "negative"].includes(kind) || !Number.isInteger(points) || points < 1 || points > 100) {
      return response.status(400).json({ error: "Conduct category details are invalid." });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `INSERT INTO conduct_categories (class_id, name, kind, points)
         VALUES ($1, $2, $3, $4) RETURNING id, name, kind, points`,
        [request.params.classId, name.trim(), kind, points]);
      await audit(client, { classId: request.params.classId, actorUserId: request.user.id,
        action: "conduct.category_created", targetType: "conduct_category", targetId: result.rows[0].id,
        details: { name: name.trim(), kind, points } });
      await client.query("COMMIT");
      response.status(201).json({ category: result.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return response.status(409).json({ error: "A category with that name and type already exists in this class." });
      throw error;
    } finally { client.release(); }
  }));

app.post("/api/classes/:classId/conduct-records", requireAuthentication, requireSameOrigin, classPermission("conduct:create"), asyncRoute(async (request, response) => {
  const { studentId, categoryId, description = "", date, source = "", evidenceName = "" } = request.body || {};
  if (
    typeof studentId !== "string" || !UUID_PATTERN.test(categoryId || "") ||
    studentId.length > 32 ||
    typeof description !== "string" || description.length > 500 ||
    typeof date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
    Number.isNaN(Date.parse(`${date}T00:00:00.000Z`)) ||
    new Date(`${date}T00:00:00.000Z`).toISOString().slice(0, 10) !== date ||
    typeof source !== "string" || source.length > 80 ||
    typeof evidenceName !== "string" || evidenceName.length > 255
  ) {
    return response.status(400).json({ error: "Conduct record data is invalid." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const category = await client.query(
      `SELECT id, name, kind, points FROM conduct_categories
       WHERE id = $1 AND class_id = $2`,
      [categoryId, request.params.classId]);
    if (!category.rowCount) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: "Choose a point category configured for this class." });
    }
    const student = await client.query(
      `SELECT class_members.id
       FROM class_members
       JOIN users ON users.id = class_members.user_id
       JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
       JOIN roles ON roles.id = class_member_roles.role_id
       WHERE class_members.class_id = $1 AND users.student_number = $2
         AND roles.name = 'ROLE_STUDENT' AND class_members.is_active = TRUE`,
      [request.params.classId, studentId]
    );
    if (!student.rowCount) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: "Student is not a member of this class." });
    }

    const isGroupManager = request.classAccess.roles.has("ROLE_GROUP_LEADER") &&
      !request.classAccess.roles.has("ROLE_CLASS_LEADER") &&
      !request.classAccess.roles.has("ROLE_CLASS_DEPUTY") &&
      !request.classAccess.roles.has("ROLE_TEACHER");
    if (isGroupManager) {
      const inSameGroup = await client.query(
        `SELECT 1 FROM group_members AS student_group
         JOIN class_groups ON class_groups.id = student_group.group_id AND class_groups.class_id = student_group.class_id
         WHERE student_group.class_id = $1 AND student_group.class_member_id = $2
           AND class_groups.leader_member_id = $3 LIMIT 1`,
        [request.params.classId, student.rows[0].id, request.classAccess.memberId]);
      if (!inSameGroup.rowCount) {
        await client.query("ROLLBACK");
        return response.status(403).json({ error: "Group leaders can only record points for students in their own group." });
      }
    }

    const inserted = await client.query(
      `INSERT INTO conduct_records
        (class_id, student_member_id, recorder_member_id, category_id, title, description, kind, points, record_date, source, evidence_name, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING id`,
      [
        request.params.classId, student.rows[0].id, request.classAccess.memberId, category.rows[0].id,
        category.rows[0].name, description.trim(), category.rows[0].kind, category.rows[0].points,
        date, source.trim(), evidenceName.trim(), isGroupManager ? "verified" : "pending"
      ]
    );
    await audit(client, {
      classId: request.params.classId,
      actorUserId: request.user.id,
      action: "conduct.created",
      targetType: "conduct_record",
      targetId: inserted.rows[0].id,
      details: { studentId, categoryId: category.rows[0].id, kind: category.rows[0].kind, points: category.rows[0].points }
    });
    await client.query("COMMIT");
    response.status(201).json({ id: inserted.rows[0].id, status: isGroupManager ? "verified" : "pending" });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/classes/:classId/weekly-scores", requireAuthentication,
  classPermission("classes:read"), asyncRoute(async (request, response) => {
    if (request.user.isAdmin) return response.status(403).json({ error: "Admin không được xem hồ sơ điểm của học sinh." });
    const state = await pool.query(
      `SELECT COALESCE(
                (SELECT archived_at::DATE FROM class_weekly_point_periods
                 WHERE class_id = $1 ORDER BY week_end DESC, archived_at DESC LIMIT 1),
                DATE_TRUNC('week', CURRENT_DATE)::DATE
              )::TEXT AS "currentWeekStart",
              (SELECT FLOOR(EXTRACT(EPOCH FROM archived_at) * 1000000)::BIGINT
               FROM class_weekly_point_periods WHERE class_id = $1
               ORDER BY week_end DESC, archived_at DESC LIMIT 1) AS "currentPeriodStartedAtUs",
              COALESCE((SELECT week_end >= CURRENT_DATE FROM class_weekly_point_periods
                        WHERE class_id = $1 ORDER BY week_end DESC, archived_at DESC LIMIT 1), FALSE) AS "resetToday"`,
      [request.params.classId]
    );
    const teacher = request.classAccess.roles.has("ROLE_TEACHER");
    const history = await pool.query(
      `SELECT periods.id, periods.academic_year AS "academicYear",
              periods.week_start::TEXT AS "weekStart", periods.week_end::TEXT AS "weekEnd",
              scores.student_number AS "studentNumber", scores.full_name AS "fullName",
              scores.positive_points AS "positivePoints", scores.negative_points AS "negativePoints",
              scores.total_points AS "totalPoints"
       FROM class_weekly_point_scores AS scores
       JOIN class_weekly_point_periods AS periods ON periods.id = scores.period_id
       WHERE scores.class_id = $1 ${teacher ? "" : "AND scores.class_member_id = $2"}
       ORDER BY periods.week_start DESC, periods.archived_at DESC, scores.full_name`,
      teacher ? [request.params.classId] : [request.params.classId, request.classAccess.memberId]
    );
    response.json({ ...state.rows[0], canReset: !state.rows[0].resetToday, history: history.rows });
  }));

app.post("/api/classes/:classId/weekly-score-reset", requireAuthentication, requireSameOrigin,
  classPermission("classes:read"), asyncRoute(async (request, response) => {
    if (!request.classAccess.roles.has("ROLE_GROUP_LEADER")) {
      return response.status(403).json({ error: "Chỉ tổ trưởng hoặc nhóm trưởng mới được reset tuần điểm." });
    }
    const managedGroups = await pool.query(
      "SELECT 1 FROM class_groups WHERE class_id = $1 AND leader_member_id = $2 LIMIT 1",
      [request.params.classId, request.classAccess.memberId]
    );
    if (!managedGroups.rowCount) {
      return response.status(403).json({ error: "Bạn chưa được phân công quản lý tổ hoặc nhóm trong lớp này." });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const classResult = await client.query(
        `SELECT academic_year FROM classes WHERE id = $1 FOR UPDATE`,
        [request.params.classId]
      );
      if (!classResult.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Class not found." });
      }
      const period = await client.query(
        `SELECT COALESCE(
                  (SELECT archived_at::DATE FROM class_weekly_point_periods
                   WHERE class_id = $1 ORDER BY week_end DESC, archived_at DESC LIMIT 1),
                  DATE_TRUNC('week', CURRENT_DATE)::DATE
                ) AS week_start,
                (SELECT archived_at FROM class_weekly_point_periods WHERE class_id = $1
                 ORDER BY week_end DESC, archived_at DESC LIMIT 1) AS previous_archive_at,
                CURRENT_DATE AS week_end,
                COALESCE((SELECT week_end >= CURRENT_DATE FROM class_weekly_point_periods
                          WHERE class_id = $1 ORDER BY week_end DESC, archived_at DESC LIMIT 1), FALSE) AS reset_today`,
        [request.params.classId]
      );
      const { week_start: weekStart, week_end: weekEnd, previous_archive_at: previousArchiveAt, reset_today: resetToday } = period.rows[0];
      if (resetToday) {
        await client.query("ROLLBACK");
        return response.status(409).json({ error: "Tuần điểm đã được chốt hôm nay." });
      }
      const savedPeriod = await client.query(
        `INSERT INTO class_weekly_point_periods
           (class_id, academic_year, week_start, week_end, period_started_at, reset_by_member_id)
         VALUES ($1, $2, $3, $4, COALESCE($5::TIMESTAMPTZ, $3::DATE::TIMESTAMPTZ), $6)
         RETURNING id, week_start::TEXT AS "weekStart", week_end::TEXT AS "weekEnd"`,
        [request.params.classId, classResult.rows[0].academic_year, weekStart, weekEnd, previousArchiveAt, request.classAccess.memberId]
      );
      await client.query(
        `WITH roster AS (
           SELECT class_members.id, users.student_number, users.full_name
           FROM class_members JOIN users ON users.id = class_members.user_id
           WHERE class_members.class_id = $1 AND class_members.is_active = TRUE
             AND EXISTS (
               SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
               WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT'
             )
         ), weekly_totals AS (
           SELECT student_member_id,
                  COALESCE(SUM(points) FILTER (WHERE kind = 'positive'), 0)::INTEGER AS positive_points,
                  COALESCE(SUM(points) FILTER (WHERE kind = 'negative'), 0)::INTEGER AS negative_points
           FROM conduct_records
           WHERE class_id = $1 AND status = 'verified' AND record_date <= $3::DATE
             AND created_at > COALESCE($5::TIMESTAMPTZ, $2::DATE::TIMESTAMPTZ)
             AND created_at <= NOW()
           GROUP BY student_member_id
         )
         INSERT INTO class_weekly_point_scores
           (period_id, class_id, class_member_id, student_number, full_name,
            positive_points, negative_points, total_points)
         SELECT $4, $1, roster.id, roster.student_number, roster.full_name,
                COALESCE(weekly_totals.positive_points, 0), COALESCE(weekly_totals.negative_points, 0),
                COALESCE(weekly_totals.positive_points, 0) - COALESCE(weekly_totals.negative_points, 0)
         FROM roster LEFT JOIN weekly_totals ON weekly_totals.student_member_id = roster.id`,
        [request.params.classId, weekStart, weekEnd, savedPeriod.rows[0].id, previousArchiveAt]
      );
      const archived = await client.query(
        `SELECT COUNT(*)::INTEGER AS count FROM class_weekly_point_scores WHERE period_id = $1`,
        [savedPeriod.rows[0].id]
      );
      await audit(client, {
        classId: request.params.classId,
        actorUserId: request.user.id,
        action: "conduct.weekly_scores_archived",
        targetType: "class_weekly_point_period",
        targetId: savedPeriod.rows[0].id,
        details: { weekStart: savedPeriod.rows[0].weekStart, weekEnd: savedPeriod.rows[0].weekEnd, studentCount: archived.rows[0].count }
      });
      await client.query("COMMIT");
      response.status(201).json({ ...savedPeriod.rows[0], nextWeekStart: new Date(`${savedPeriod.rows[0].weekEnd}T00:00:00Z`).toISOString().slice(0, 10), studentCount: archived.rows[0].count });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.get("/api/classes/:classId/forum", requireAuthentication, classPermission("classes:read"), asyncRoute(async (request, response) => {
  const result = await pool.query(
    `SELECT class_forum_posts.id, class_forum_posts.week_start::TEXT AS "weekStart",
            class_forum_posts.week_end::TEXT AS "weekEnd", class_forum_posts.title,
            class_forum_posts.message, class_forum_posts.score_snapshot AS "scoreSnapshot",
            class_forum_posts.created_at::TEXT AS "createdAt", users.full_name AS "authorName",
            class_groups.name AS "groupName"
     FROM class_forum_posts
     JOIN class_members ON class_members.id = class_forum_posts.author_member_id
     JOIN users ON users.id = class_members.user_id
     LEFT JOIN class_groups ON class_groups.id = class_forum_posts.group_id
     WHERE class_forum_posts.class_id = $1
     ORDER BY class_forum_posts.week_start DESC, class_forum_posts.created_at DESC`,
    [request.params.classId]
  );
  response.json({ posts: result.rows });
}));

app.get("/api/classes/:classId/forum/managed-groups", requireAuthentication,
  classPermission("classes:read"), asyncRoute(async (request, response) => {
    if (!request.classAccess.roles.has("ROLE_GROUP_LEADER")) {
      return response.status(403).json({ error: "Only group leaders can publish a group weekly summary." });
    }
    const result = await pool.query(
      `SELECT id, name FROM class_groups
       WHERE class_id = $1 AND leader_member_id = $2
       ORDER BY name`,
      [request.params.classId, request.classAccess.memberId]);
    response.json({ groups: result.rows });
  }));

app.post("/api/classes/:classId/forum/weekly-summary", requireAuthentication, requireSameOrigin,
  classPermission("classes:read"), asyncRoute(async (request, response) => {
    if (!request.classAccess.roles.has("ROLE_GROUP_LEADER")) {
      return response.status(403).json({ error: "Only group leaders can publish a group weekly summary." });
    }
    const { groupId, weekStart, weekEnd, message = "" } = request.body || {};
    const validDate = (value) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
      !Number.isNaN(Date.parse(`${value}T00:00:00.000Z`)) &&
      new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
    if (!UUID_PATTERN.test(groupId || "") || !validDate(weekStart) || !validDate(weekEnd) ||
        Date.parse(`${weekEnd}T00:00:00.000Z`) < Date.parse(`${weekStart}T00:00:00.000Z`) ||
        (Date.parse(`${weekEnd}T00:00:00.000Z`) - Date.parse(`${weekStart}T00:00:00.000Z`)) / 86400000 > 6 ||
        typeof message !== "string" || message.length > 2000) {
      return response.status(400).json({ error: "Week dates or the message are invalid. Choose a range of up to seven days." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const group = await client.query(
        `SELECT id, name FROM class_groups
         WHERE id = $1 AND class_id = $2 AND leader_member_id = $3
         FOR UPDATE`,
        [groupId, request.params.classId, request.classAccess.memberId]);
      if (!group.rowCount) {
        await client.query("ROLLBACK");
        return response.status(403).json({ error: "You can only publish a summary for a group you lead." });
      }
      const totals = await client.query(
        `WITH roster AS (
           SELECT class_members.id, users.student_number, users.full_name
           FROM class_members JOIN users ON users.id = class_members.user_id
           JOIN group_members ON group_members.class_member_id = class_members.id AND group_members.class_id = $1
           WHERE class_members.class_id = $1 AND group_members.group_id = $4 AND class_members.is_active = TRUE
             AND EXISTS (SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
                         WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT')
         ), weekly_totals AS (
           SELECT conduct_records.student_member_id,
                  COALESCE(SUM(conduct_records.points) FILTER (WHERE conduct_records.kind = 'positive'), 0)::INTEGER AS positive_points,
                  COALESCE(SUM(conduct_records.points) FILTER (WHERE conduct_records.kind = 'negative'), 0)::INTEGER AS negative_points
           FROM conduct_records
           WHERE conduct_records.class_id = $1 AND conduct_records.status = 'verified'
             AND conduct_records.record_date BETWEEN $2::DATE AND $3::DATE
           GROUP BY conduct_records.student_member_id
         )
         SELECT COALESCE(JSON_AGG(JSON_BUILD_OBJECT(
                  'memberId', roster.id,
                  'studentNumber', roster.student_number,
                  'fullName', roster.full_name,
                  'positivePoints', COALESCE(weekly_totals.positive_points, 0),
                  'negativePoints', COALESCE(weekly_totals.negative_points, 0),
                  'totalPoints', COALESCE(weekly_totals.positive_points, 0) - COALESCE(weekly_totals.negative_points, 0)
                ) ORDER BY COALESCE(weekly_totals.positive_points, 0) - COALESCE(weekly_totals.negative_points, 0) DESC, roster.full_name), '[]'::JSON) AS snapshot
         FROM roster LEFT JOIN weekly_totals ON weekly_totals.student_member_id = roster.id`,
        [request.params.classId, weekStart, weekEnd, groupId]);
      const title = `Tổng kết ${group.rows[0].name} tuần ${weekStart} – ${weekEnd}`;
      const inserted = await client.query(
        `INSERT INTO class_forum_posts
          (class_id, group_id, author_member_id, week_start, week_end, title, message, score_snapshot)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::JSONB)
         ON CONFLICT (class_id, group_id, week_start) WHERE group_id IS NOT NULL DO UPDATE SET
           author_member_id = EXCLUDED.author_member_id,
           week_end = EXCLUDED.week_end,
           title = EXCLUDED.title,
           message = EXCLUDED.message,
           score_snapshot = EXCLUDED.score_snapshot,
           created_at = NOW()
         RETURNING id`,
        [request.params.classId, groupId, request.classAccess.memberId, weekStart, weekEnd, title, message.trim(), JSON.stringify(totals.rows[0].snapshot)]);
      await audit(client, { classId: request.params.classId, actorUserId: request.user.id,
        action: "forum.weekly_summary_saved", targetType: "class_forum_post", targetId: inserted.rows[0].id,
        details: { weekStart, weekEnd, studentCount: totals.rows[0].snapshot.length } });
      await client.query("COMMIT");
      response.status(201).json({ id: inserted.rows[0].id, title });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.patch("/api/classes/:classId/conduct-records/:recordId/verify", requireAuthentication, requireSameOrigin, classPermission("conduct:verify"), asyncRoute(async (request, response) => {
  if (!UUID_PATTERN.test(request.params.recordId)) {
    return response.status(400).json({ error: "Conduct record ID is invalid." });
  }
  const status = request.body?.status;
  if (!["pending", "verified"].includes(status)) {
    return response.status(400).json({ error: "Status must be pending or verified." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE conduct_records
       SET status = $3
       WHERE id = $1 AND class_id = $2
       RETURNING id`,
      [request.params.recordId, request.params.classId, status]
    );
    if (!updated.rowCount) {
      await client.query("ROLLBACK");
      return response.status(404).json({ error: "Conduct record not found." });
    }
    await audit(client, {
      classId: request.params.classId,
      actorUserId: request.user.id,
      action: status === "verified" ? "conduct.verified" : "conduct.reopened",
      targetType: "conduct_record",
      targetId: updated.rows[0].id
    });
    await client.query("COMMIT");
    response.json({ id: updated.rows[0].id, status });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/classes/:classId/leadership", requireAuthentication, classPermission("roles:manage"), requireClassTeacher, asyncRoute(async (request, response) => {
  const [studentResult, groupResult] = await Promise.all([
    pool.query(
      `SELECT class_members.id AS "memberId", users.student_number AS "studentNumber", users.full_name AS "fullName",
              ARRAY(SELECT group_members.group_id FROM group_members
                   WHERE group_members.class_id = class_members.class_id
                     AND group_members.class_member_id = class_members.id) AS "groupIds",
              ARRAY(SELECT roles.name FROM class_member_roles
                   JOIN roles ON roles.id = class_member_roles.role_id
                   WHERE class_member_roles.class_member_id = class_members.id) AS roles
       FROM class_members JOIN users ON users.id = class_members.user_id
       WHERE class_members.class_id = $1 AND class_members.is_active = TRUE
         AND EXISTS (SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
                     WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT')
       ORDER BY users.full_name`, [request.params.classId]),
    pool.query(
      `SELECT class_groups.id, class_groups.name, class_groups.leader_member_id AS "leaderMemberId",
              COALESCE(JSON_AGG(JSON_BUILD_OBJECT('memberId', class_members.id, 'studentNumber', users.student_number, 'fullName', users.full_name))
                FILTER (WHERE class_members.id IS NOT NULL), '[]'::json) AS members
       FROM class_groups
       LEFT JOIN group_members ON group_members.group_id = class_groups.id AND group_members.class_id = class_groups.class_id
       LEFT JOIN class_members ON class_members.id = group_members.class_member_id AND class_members.is_active = TRUE
       LEFT JOIN users ON users.id = class_members.user_id
       WHERE class_groups.class_id = $1
       GROUP BY class_groups.id ORDER BY class_groups.name`, [request.params.classId])
  ]);
  response.json({
    students: studentResult.rows,
    groups: groupResult.rows
  });
}));

app.put("/api/classes/:classId/leadership", requireAuthentication, requireSameOrigin, classPermission("roles:manage"), requireClassTeacher, asyncRoute(async (request, response) => {
  const assignments = request.body?.assignments;
  const allowedRoles = ["ROLE_CLASS_LEADER", "ROLE_CLASS_DEPUTY"];
  if (!Array.isArray(assignments) || assignments.length !== allowedRoles.length ||
      assignments.some((entry) => !allowedRoles.includes(entry?.role) || (entry.memberId && !UUID_PATTERN.test(entry.memberId))) ||
      new Set(assignments.map((entry) => entry.role)).size !== allowedRoles.length) {
    return response.status(400).json({ error: "Leadership assignments are invalid." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [request.params.classId]);
    for (const assignment of assignments) {
      if (assignment.memberId) {
        const target = await client.query(
          `SELECT 1 FROM class_members JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
           JOIN roles ON roles.id = class_member_roles.role_id
           WHERE class_members.id = $1 AND class_members.class_id = $2 AND class_members.is_active = TRUE AND roles.name = 'ROLE_STUDENT'`,
          [assignment.memberId, request.params.classId]);
        if (!target.rowCount) {
          await client.query("ROLLBACK");
          return response.status(400).json({ error: "Leadership must be assigned to an active student in this class." });
        }
      }
      const role = await client.query("SELECT id FROM roles WHERE name = $1", [assignment.role]);
      await client.query("DELETE FROM class_member_roles WHERE class_id = $1 AND role_id = $2", [request.params.classId, role.rows[0].id]);
      if (assignment.memberId) {
        await client.query(
          `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
           VALUES ($1, $2, $3, $4)`,
          [request.params.classId, assignment.memberId, role.rows[0].id, request.classAccess.memberId]);
      }
    }
    await audit(client, { classId: request.params.classId, actorUserId: request.user.id,
      action: "class.leadership_updated", targetType: "class", targetId: request.params.classId,
      details: { assignments } });
    await client.query("COMMIT");
    response.json({ saved: true });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}));

app.post("/api/classes/:classId/groups", requireAuthentication, requireSameOrigin, classPermission("roles:manage"), requireClassTeacher, asyncRoute(async (request, response) => {
  const { name, memberIds, leaderMemberId, groupId } = request.body || {};
  if (typeof name !== "string" || !name.trim() || name.trim().length > 80 || !Array.isArray(memberIds) ||
      memberIds.length < 1 || memberIds.length > 50 || memberIds.some((id) => !UUID_PATTERN.test(id)) ||
      new Set(memberIds).size !== memberIds.length || !UUID_PATTERN.test(leaderMemberId || "") || !memberIds.includes(leaderMemberId) ||
      (groupId !== undefined && !UUID_PATTERN.test(groupId))) {
    return response.status(400).json({ error: "Group details are invalid. Select a name, members and a leader from those members." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [request.params.classId]);
    const validMembers = await client.query(
      `SELECT class_members.id FROM class_members
       WHERE class_members.class_id = $1 AND class_members.is_active = TRUE AND class_members.id = ANY($2::uuid[])
         AND EXISTS (SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
                     WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT')`,
      [request.params.classId, memberIds]);
    if (validMembers.rowCount !== memberIds.length) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: "Every group member must be an active student in this class." });
    }
    const group = groupId
      ? await client.query(
        `UPDATE class_groups SET name = $3, leader_member_id = $4
         WHERE class_id = $1 AND id = $2 RETURNING id`,
        [request.params.classId, groupId, name.trim(), leaderMemberId])
      : await client.query(
        `INSERT INTO class_groups (class_id, name, leader_member_id) VALUES ($1, $2, $3)
         ON CONFLICT (class_id, name) DO UPDATE SET leader_member_id = EXCLUDED.leader_member_id
         RETURNING id`,
        [request.params.classId, name.trim(), leaderMemberId]);
    if (!group.rowCount) {
      await client.query("ROLLBACK");
      return response.status(404).json({ error: "Không tìm thấy tổ/nhóm cần chỉnh sửa trong lớp này." });
    }
    await client.query(
      `UPDATE class_groups SET leader_member_id = NULL
       WHERE class_id = $1 AND id <> $2 AND leader_member_id = ANY($3::uuid[])`,
      [request.params.classId, group.rows[0].id, memberIds]);
    const groupLeaderRole = await client.query("SELECT id FROM roles WHERE name = 'ROLE_GROUP_LEADER'");
    await client.query(
      `DELETE FROM class_member_roles
       WHERE class_id = $1 AND class_member_id = ANY($2::uuid[]) AND role_id = $3`,
      [request.params.classId, memberIds, groupLeaderRole.rows[0].id]);
    await client.query(
      "DELETE FROM group_members WHERE class_id = $1 AND group_id <> $2 AND class_member_id = ANY($3::uuid[])",
      [request.params.classId, group.rows[0].id, memberIds]);
    await client.query("DELETE FROM group_members WHERE class_id = $1 AND group_id = $2",
      [request.params.classId, group.rows[0].id]);
    for (const memberId of memberIds) {
      await client.query("INSERT INTO group_members (group_id, class_id, class_member_id) VALUES ($1, $2, $3)",
        [group.rows[0].id, request.params.classId, memberId]);
    }
    await client.query(
      `DELETE FROM class_member_roles AS assigned
       WHERE assigned.class_id = $1 AND assigned.role_id = $2
         AND NOT EXISTS (SELECT 1 FROM class_groups WHERE class_groups.class_id = $1
                         AND class_groups.leader_member_id = assigned.class_member_id)`,
      [request.params.classId, groupLeaderRole.rows[0].id]);
    await client.query(
      `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
       VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
      [request.params.classId, leaderMemberId, groupLeaderRole.rows[0].id, request.classAccess.memberId]);
    await audit(client, { classId: request.params.classId, actorUserId: request.user.id,
      action: "class.group_saved", targetType: "class_group", targetId: group.rows[0].id,
      details: { name: name.trim(), memberCount: memberIds.length, leaderMemberId } });
    await client.query("COMMIT");
    response.status(201).json({ id: group.rows[0].id, name: name.trim() });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return response.status(409).json({ error: "A group with that name already exists in this class." });
    throw error;
  } finally { client.release(); }
}));

app.patch("/api/classes/:classId/group-members/:memberId", requireAuthentication, requireSameOrigin,
  classPermission("roles:manage"), requireClassTeacher, asyncRoute(async (request, response) => {
    const targetGroupId = request.body?.groupId;
    if (!UUID_PATTERN.test(request.params.memberId) ||
        (targetGroupId !== null && !UUID_PATTERN.test(targetGroupId || ""))) {
      return response.status(400).json({ error: "Thông tin chuyển tổ không hợp lệ." });
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [request.params.classId]);
      const student = await client.query(
        `SELECT class_members.id, users.full_name
         FROM class_members JOIN users ON users.id = class_members.user_id
         WHERE class_members.id = $1 AND class_members.class_id = $2 AND class_members.is_active = TRUE
           AND EXISTS (SELECT 1 FROM class_member_roles JOIN roles ON roles.id = class_member_roles.role_id
                       WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_STUDENT')
         FOR UPDATE OF class_members`,
        [request.params.memberId, request.params.classId]
      );
      if (!student.rowCount) {
        await client.query("ROLLBACK");
        return response.status(404).json({ error: "Không tìm thấy học sinh đang hoạt động trong lớp." });
      }
      if (targetGroupId) {
        const targetGroup = await client.query("SELECT id FROM class_groups WHERE id = $1 AND class_id = $2", [targetGroupId, request.params.classId]);
        if (!targetGroup.rowCount) {
          await client.query("ROLLBACK");
          return response.status(404).json({ error: "Không tìm thấy tổ/nhóm đích trong lớp này." });
        }
      }
      const previousGroups = await client.query(
        "SELECT group_id FROM group_members WHERE class_id = $1 AND class_member_id = $2",
        [request.params.classId, request.params.memberId]
      );
      await client.query(
        `UPDATE class_groups SET leader_member_id = NULL
         WHERE class_id = $1 AND leader_member_id = $2 AND ($3::uuid IS NULL OR id <> $3)`,
        [request.params.classId, request.params.memberId, targetGroupId]
      );
      await client.query("DELETE FROM group_members WHERE class_id = $1 AND class_member_id = $2", [request.params.classId, request.params.memberId]);
      if (targetGroupId) {
        await client.query("INSERT INTO group_members (group_id, class_id, class_member_id) VALUES ($1, $2, $3)",
          [targetGroupId, request.params.classId, request.params.memberId]);
      }
      await client.query(
        `DELETE FROM class_member_roles AS assigned USING roles
         WHERE assigned.class_id = $1 AND assigned.class_member_id = $2
           AND assigned.role_id = roles.id AND roles.name = 'ROLE_GROUP_LEADER'
           AND NOT EXISTS (SELECT 1 FROM class_groups WHERE class_groups.class_id = $1
                           AND class_groups.leader_member_id = assigned.class_member_id)`,
        [request.params.classId, request.params.memberId]
      );
      await client.query(
        `INSERT INTO audit_logs (class_id, actor_user_id, action, target_type, target_id, details)
         VALUES ($1, $2, 'class.group_member_moved', 'class_member', $3, $4::jsonb)`,
        [request.params.classId, request.user.id, request.params.memberId,
          JSON.stringify({ fullName: student.rows[0].full_name, fromGroupIds: previousGroups.rows.map((row) => row.group_id), toGroupId: targetGroupId })]
      );
      await client.query("COMMIT");
      response.json({ memberId: request.params.memberId, groupId: targetGroupId });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }));

app.post("/api/classes/:classId/role-requests", requireAuthentication, requireSameOrigin, asyncRoute(async (request, response) => {
  if (!UUID_PATTERN.test(request.params.classId)) {
    return response.status(400).json({ error: "Class ID is invalid." });
  }
  const access = await loadClassAccess(request.user.id, request.params.classId);
  if (!access) {
    return response.status(404).json({ error: "Class not found." });
  }
  if (access.roles.has("ROLE_TEACHER")) {
    return response.status(403).json({ error: "Teachers cannot request an additional class leadership role." });
  }
  const { role, reason = "" } = request.body || {};
  if (!["ROLE_CLASS_LEADER", "ROLE_CLASS_DEPUTY", "ROLE_GROUP_LEADER"].includes(role) ||
      typeof reason !== "string" || reason.length > 500) {
    return response.status(400).json({ error: "Role request data is invalid." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const roleResult = await client.query("SELECT id FROM roles WHERE name = $1", [role]);
    const alreadyAssigned = await client.query(
      "SELECT 1 FROM class_member_roles WHERE class_id = $1 AND class_member_id = $2 AND role_id = $3",
      [request.params.classId, access.memberId, roleResult.rows[0].id]
    );
    if (alreadyAssigned.rowCount) {
      await client.query("ROLLBACK");
      return response.status(409).json({ error: "This role is already assigned in this class." });
    }
    const result = await client.query(
      `INSERT INTO role_requests (class_id, requested_by_member_id, requested_role_id, reason)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (class_id, requested_by_member_id, requested_role_id) WHERE status = 'pending'
       DO NOTHING
       RETURNING id`,
      [request.params.classId, access.memberId, roleResult.rows[0].id, reason.trim()]
    );
    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return response.status(409).json({ error: "A request for this role is already pending." });
    }
    await audit(client, {
      classId: request.params.classId,
      actorUserId: request.user.id,
      action: "role.requested",
      targetType: "role_request",
      targetId: result.rows[0].id
    });
    await client.query("COMMIT");
    response.status(201).json({ id: result.rows[0].id, status: "pending" });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/classes/:classId/role-requests", requireAuthentication, classPermission("roles:manage"), asyncRoute(async (request, response) => {
  const result = await pool.query(
    `SELECT role_requests.id, role_requests.reason, role_requests.status,
            role_requests.created_at AS "createdAt", users.full_name AS "requesterName",
            roles.name AS "requestedRole"
     FROM role_requests
     JOIN class_members ON class_members.id = role_requests.requested_by_member_id
     JOIN users ON users.id = class_members.user_id
     JOIN roles ON roles.id = role_requests.requested_role_id
     WHERE role_requests.class_id = $1
     ORDER BY (role_requests.status = 'pending') DESC, role_requests.created_at DESC`,
    [request.params.classId]
  );
  response.json({ requests: result.rows });
}));

app.patch("/api/classes/:classId/role-requests/:requestId", requireAuthentication, requireSameOrigin, classPermission("roles:manage"), asyncRoute(async (request, response) => {
  if (!UUID_PATTERN.test(request.params.requestId)) {
    return response.status(400).json({ error: "Role request ID is invalid." });
  }
  const decision = request.body?.decision;
  if (!["approved", "rejected"].includes(decision)) {
    return response.status(400).json({ error: "Decision must be approved or rejected." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const pending = await client.query(
      `SELECT role_requests.id, role_requests.requested_by_member_id, role_requests.requested_role_id
       FROM role_requests
       WHERE role_requests.id = $1 AND role_requests.class_id = $2 AND role_requests.status = 'pending'
       FOR UPDATE`,
      [request.params.requestId, request.params.classId]
    );
    if (!pending.rowCount) {
      await client.query("ROLLBACK");
      return response.status(404).json({ error: "Pending role request not found." });
    }
    const roleRequest = pending.rows[0];
    if (roleRequest.requested_by_member_id === request.classAccess.memberId) {
      await client.query("ROLLBACK");
      return response.status(403).json({ error: "A requester cannot review their own role request." });
    }
    if (decision === "approved") {
      const requestedRole = await client.query("SELECT name FROM roles WHERE id = $1", [roleRequest.requested_role_id]);
      if (["ROLE_CLASS_LEADER", "ROLE_CLASS_DEPUTY"].includes(requestedRole.rows[0]?.name)) {
        await client.query(
          "DELETE FROM class_member_roles WHERE class_id = $1 AND role_id = $2",
          [request.params.classId, roleRequest.requested_role_id]);
      }
      await client.query(
        `INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING`,
        [request.params.classId, roleRequest.requested_by_member_id, roleRequest.requested_role_id, request.classAccess.memberId]
      );
    }
    await client.query(
      `UPDATE role_requests
       SET status = $2, reviewed_by_member_id = $3, reviewed_at = NOW()
       WHERE id = $1`,
      [roleRequest.id, decision, request.classAccess.memberId]
    );
    await audit(client, {
      classId: request.params.classId,
      actorUserId: request.user.id,
      action: `role_request.${decision}`,
      targetType: "role_request",
      targetId: roleRequest.id
    });
    await client.query("COMMIT");
    response.json({ id: roleRequest.id, status: decision });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.get("/api/classes/:classId/permissions", requireAuthentication, classPermission("permissions:manage"), asyncRoute(async (_request, response) => {
  const result = await pool.query(
    "SELECT name FROM permissions WHERE name NOT IN ('roles:manage', 'permissions:manage') ORDER BY name"
  );
  response.json({ permissions: result.rows.map((row) => row.name) });
}));

app.put("/api/classes/:classId/members/:memberId/permissions", requireAuthentication, requireSameOrigin, classPermission("permissions:manage"), asyncRoute(async (request, response) => {
  if (!UUID_PATTERN.test(request.params.memberId)) {
    return response.status(400).json({ error: "Member ID is invalid." });
  }
  const permissions = request.body?.permissions;
  if (!Array.isArray(permissions) || permissions.length > 20 ||
      permissions.some((permission) => typeof permission !== "string") ||
      new Set(permissions).size !== permissions.length) {
    return response.status(400).json({ error: "Permissions must be a unique list of valid permission names." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const member = await client.query(
      `SELECT class_members.id
       FROM class_members
       WHERE class_members.id = $1 AND class_members.class_id = $2 AND class_members.is_active = TRUE
         AND NOT EXISTS (
           SELECT 1 FROM class_member_roles
           JOIN roles ON roles.id = class_member_roles.role_id
           WHERE class_member_roles.class_member_id = class_members.id AND roles.name = 'ROLE_TEACHER'
         )`,
      [request.params.memberId, request.params.classId]
    );
    if (!member.rowCount) {
      await client.query("ROLLBACK");
      return response.status(404).json({ error: "Member not found or cannot be delegated permissions." });
    }
    const allowed = await client.query(
      `SELECT name FROM permissions
       WHERE name = ANY($1::TEXT[])
         AND name NOT IN ('roles:manage', 'permissions:manage')`,
      [permissions]
    );
    if (allowed.rowCount !== permissions.length) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: "One or more permissions cannot be delegated." });
    }

    await client.query(
      "DELETE FROM member_permissions WHERE class_id = $1 AND class_member_id = $2",
      [request.params.classId, request.params.memberId]
    );
    if (permissions.length) {
      await client.query(
        `INSERT INTO member_permissions (class_id, class_member_id, permission_id, granted_by_member_id)
         SELECT $1, $2, id, $3 FROM permissions WHERE name = ANY($4::TEXT[])`,
        [request.params.classId, request.params.memberId, request.classAccess.memberId, permissions]
      );
    }
    await audit(client, {
      classId: request.params.classId,
      actorUserId: request.user.id,
      action: "member.permissions_updated",
      targetType: "class_member",
      targetId: request.params.memberId,
      details: { permissions }
    });
    await client.query("COMMIT");
    response.json({ memberId: request.params.memberId, permissions });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.use("/api", (_request, response) => {
  response.status(404).json({ error: "API route not found." });
});

app.get(["/", "/index.html"], (_request, response) => {
  response.setHeader("Cache-Control", "no-cache, must-revalidate");
  response.sendFile(path.join(publicDirectory, "index.html"));
});
app.use(express.static(publicDirectory, { index: false }));

app.use((error, _request, response, _next) => {
  const errorCode = error && typeof error === "object" && "code" in error
    ? error.code
    : undefined;
  console.error(
    "Request failed.",
    errorCode ? `Error code: ${errorCode}` : "Unexpected server error."
  );
  if (response.headersSent) return;
  const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500 ? error.status : 500;
  const codeByStatus = { 400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND", 409: "CONFLICT", 413: "PAYLOAD_TOO_LARGE", 422: "UNPROCESSABLE_ENTITY", 429: "RATE_LIMITED" };
  response.status(status).json({
    error: status === 500 ? "An unexpected server error occurred." : "Request could not be processed.",
    code: codeByStatus[status] || "INTERNAL_SERVER_ERROR"
  });
});

const isMainModule = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMainModule) {
  const server = app.listen(port, host, () => {
    console.info(`ClassTrack listening on ${host}:${port} (${appOrigin})`);
  });
  server.on("error", (error) => {
    if (error.code === "EADDRINUSE") {
      console.error(`Port ${port} is already in use. Stop the other process or configure a different PORT before starting ClassTrack.`);
    } else {
      console.error("ClassTrack failed to bind its network address:", error);
    }
    process.exitCode = 1;
  });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    });
  }
}
