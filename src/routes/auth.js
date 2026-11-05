import { createHash, randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import express from "express";
import { getPool } from "../db.js";

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = "classtrack_session";
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const router = express.Router();

function asyncRoute(handler) {
  return (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
}

function tokenHash(token) {
  return createHash("sha256").update(token).digest();
}

function readSessionToken(request) {
  const cookieHeader = request.headers.cookie || "";
  for (const entry of cookieHeader.split(";")) {
    const separator = entry.indexOf("=");
    if (separator < 0 || entry.slice(0, separator).trim() !== COOKIE_NAME) continue;
    const token = entry.slice(separator + 1).trim();
    return /^[a-f0-9]{64}$/.test(token) ? token : null;
  }
  return null;
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${token}; HttpOnly${secure}; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  );
}

function clearSessionCookie(response) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function sameOrigin(request, response, next) {
  const origin = request.get("origin");
  if (!origin) {
    if (request.get("sec-fetch-site") === "cross-site") {
      return response.status(403).json({ error: "Yêu cầu không được phép từ nguồn khác." });
    }
    return next();
  }

  const forwardedProtocol = request.get("x-forwarded-proto")?.split(",")[0].trim();
  const protocol = forwardedProtocol || request.protocol;
  if (origin !== `${protocol}://${request.get("host")}`) {
    return response.status(403).json({ error: "Yêu cầu không được phép từ nguồn khác." });
  }
  return next();
}

async function findUserBySession(request) {
  const token = readSessionToken(request);
  if (!token) return null;

  const result = await getPool().query(
    `SELECT users.id,
            users.username,
            users.full_name AS "fullName",
            users.is_admin AS "isAdmin",
            users.is_super_admin AS "isSuperAdmin",
            users.must_change_password AS "mustChangePassword",
            users.password_reset_expires_at AS "passwordResetExpiresAt",
            users.student_number AS "studentNumber",
            users.avatar_data AS "avatarData",
            users.is_teacher AS "isTeacher",
            ARRAY(
              SELECT admin_permissions.permission_name
              FROM admin_permissions
              WHERE admin_permissions.user_id = users.id
            ) AS "adminPermissions"
     FROM auth_sessions
     JOIN users ON users.id = auth_sessions.user_id
     WHERE auth_sessions.token_hash = $1
       AND auth_sessions.expires_at > NOW()
       AND users.is_active = TRUE`,
    [tokenHash(token)]
  );
  const user = result.rows[0];
  if (user?.mustChangePassword &&
      (!user.passwordResetExpiresAt || new Date(user.passwordResetExpiresAt) <= new Date())) {
    return null;
  }
  if (user) delete user.passwordResetExpiresAt;
  return user || null;
}

router.use((_request, response, next) => {
  response.setHeader("Cache-Control", "no-store");
  next();
});

router.post("/login", sameOrigin, asyncRoute(async (request, response) => {
  const submittedLogin = typeof request.body?.username === "string" ? request.body.username : "";
  const username = submittedLogin.trim().toLowerCase();
  const password = typeof request.body?.password === "string" ? request.body.password : "";
  if (!USERNAME_PATTERN.test(username) || !password || Buffer.byteLength(password, "utf8") > 72) {
    return response.status(400).json({ error: "Tên đăng nhập hoặc mật khẩu không hợp lệ." });
  }

  const result = await getPool().query(
    `SELECT users.id, users.username, users.full_name, users.password_hash, users.avatar_data,
            users.is_admin, users.is_super_admin, users.is_teacher, users.must_change_password,
            users.password_reset_expires_at,
            ARRAY(
              SELECT admin_permissions.permission_name
              FROM admin_permissions
              WHERE admin_permissions.user_id = users.id
            ) AS admin_permissions
     FROM users
     WHERE users.username = $1 AND users.is_active = TRUE`,
    [username]
  );
  const user = result.rows[0];
  if (!user?.password_hash || !(await bcrypt.compare(password, user.password_hash)) ||
      (user.must_change_password &&
        (!user.password_reset_expires_at || new Date(user.password_reset_expires_at) <= new Date()))) {
    return response.status(401).json({ error: "Tên đăng nhập hoặc mật khẩu không chính xác." });
  }

  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  const pool = getPool();
  await pool.query("DELETE FROM auth_sessions WHERE expires_at <= NOW()");
  await pool.query(
    "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [tokenHash(token), user.id, expiresAt]
  );

  setSessionCookie(response, token);
  return response.json({
    user: {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      avatarData: user.avatar_data,
      isAdmin: user.is_admin,
      isSuperAdmin: user.is_super_admin,
      adminPermissions: user.admin_permissions,
      mustChangePassword: user.must_change_password,
      isTeacher: user.is_teacher
    }
  });
}));

router.post("/logout", sameOrigin, asyncRoute(async (request, response) => {
  const token = readSessionToken(request);
  if (token) {
    await getPool().query("DELETE FROM auth_sessions WHERE token_hash = $1", [tokenHash(token)]);
  }
  clearSessionCookie(response);
  return response.status(204).end();
}));

export async function getSession(request, response, next) {
  response.setHeader("Cache-Control", "no-store");
  try {
    const user = await findUserBySession(request);
    if (!user) return response.status(401).json({ error: "Authentication required." });

    const result = await getPool().query(
      `SELECT classes.id, classes.name,
              classes.academic_year AS "academicYear",
              ARRAY(
                SELECT roles.name
                FROM class_member_roles
                JOIN roles ON roles.id = class_member_roles.role_id
                WHERE class_member_roles.class_member_id = class_members.id
              ) AS roles,
              ARRAY(
                SELECT permissions.name
                FROM role_permissions
                JOIN permissions ON permissions.id = role_permissions.permission_id
                WHERE role_permissions.role_id IN (
                  SELECT class_member_roles.role_id
                  FROM class_member_roles
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
       ORDER BY classes.name`,
      [user.id]
    );
    return response.json({ user, classes: result.rows });
  } catch (error) {
    return next(error);
  }
}

export const authRouter = router;
