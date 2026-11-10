import { createHash, randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import { pool } from "./db.js";

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = process.env.NODE_ENV === "production" ? "__Host-classtrack_session" : "classtrack_session";

function tokenHash(token) {
  return createHash("sha256").update(token).digest();
}

function readCookie(request, name) {
  const cookieHeader = request.headers.cookie || "";
  for (const entry of cookieHeader.split(";")) {
    const separator = entry.indexOf("=");
    if (separator < 0) continue;
    if (entry.slice(0, separator).trim() === name) {
      return entry.slice(separator + 1).trim();
    }
  }
  return null;
}

export function setSessionCookie(response, token) {
  const isProduction = process.env.NODE_ENV === "production";
  const secure = isProduction ? "; Secure" : "";
  const sameSite = isProduction ? "None" : "Lax";
  response.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secure}`
  );
}

export function clearSessionCookie(response) {
  const isProduction = process.env.NODE_ENV === "production";
  const secure = isProduction ? "; Secure" : "";
  const sameSite = isProduction ? "None" : "Lax";
  response.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=0${secure}`);
}

export async function login(username, password) {
  if (Buffer.byteLength(password, "utf8") > 72) {
    return null;
  }
  const normalizedUsername = typeof username === "string" ? username.trim().toLowerCase() : "";
  const result = await pool.query(
    `SELECT users.id, users.username, users.full_name, users.password_hash, users.avatar_data,
            users.is_admin, users.is_super_admin, users.is_teacher, users.must_change_password,
            users.password_reset_expires_at,
            ARRAY(SELECT admin_permissions.permission_name FROM admin_permissions WHERE admin_permissions.user_id = users.id) AS admin_permissions
     FROM users WHERE users.username = $1 AND users.is_active = TRUE`,
    [normalizedUsername]
  );
  const user = result.rows[0];
  if (!user?.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
    return null;
  }
  if (user.must_change_password && (!user.password_reset_expires_at || new Date(user.password_reset_expires_at) <= new Date())) {
    return null;
  }

  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await pool.query("DELETE FROM auth_sessions WHERE expires_at <= NOW()");
  await pool.query(
    "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [tokenHash(token), user.id, expiresAt]
  );
  return { token, user: { id: user.id, username: user.username, fullName: user.full_name, avatarData: user.avatar_data,
    isAdmin: user.is_admin, isSuperAdmin: user.is_super_admin, adminPermissions: user.admin_permissions,
    mustChangePassword: user.must_change_password, isTeacher: user.is_teacher } };
}

export async function authenticate(request, _response, next) {
  try {
    const token = readCookie(request, COOKIE_NAME);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) {
      request.user = null;
      return next();
    }
    const result = await pool.query(
      `SELECT users.id, users.username, users.full_name AS "fullName", users.is_admin AS "isAdmin",
      users.is_super_admin AS "isSuperAdmin", users.must_change_password AS "mustChangePassword",
      ARRAY(SELECT admin_permissions.permission_name FROM admin_permissions WHERE admin_permissions.user_id = users.id) AS "adminPermissions",
      users.student_number AS "studentNumber", users.avatar_data AS "avatarData", users.is_teacher AS "isTeacher"
       FROM auth_sessions
       JOIN users ON users.id = auth_sessions.user_id
       WHERE auth_sessions.token_hash = $1
         AND auth_sessions.expires_at > NOW()
         AND users.is_active = TRUE`,
      [tokenHash(token)]
    );
    request.user = result.rows[0] || null;
    return next();
  } catch (error) {
    return next(error);
  }
}

export function requireAuthentication(request, response, next) {
  if (!request.user) {
    return response.status(401).json({ error: "Authentication required." });
  }
  return next();
}

export async function revokeSession(request) {
  const token = readCookie(request, COOKIE_NAME);
  if (token && /^[a-f0-9]{64}$/.test(token)) {
    await pool.query("DELETE FROM auth_sessions WHERE token_hash = $1", [tokenHash(token)]);
  }
}

export async function loadClassAccess(userId, classId) {
  const result = await pool.query(
    `SELECT class_members.id AS member_id,
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
     WHERE class_members.user_id = $1
       AND class_members.class_id = $2
       AND class_members.is_active = TRUE`,
    [userId, classId]
  );
  const access = result.rows[0];
  return access
    ? { memberId: access.member_id, roles: new Set(access.roles), permissions: new Set(access.permissions) }
    : null;
}

export async function requireClassPermission(request, response, next, permission) {
  try {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.classId)) {
      return response.status(400).json({ error: "Class ID is invalid." });
    }
    const access = await loadClassAccess(request.user.id, request.params.classId);
    if (!access) {
      return response.status(404).json({ error: "Class not found." });
    }
    if (!access.permissions.has(permission)) {
      return response.status(403).json({ error: "You do not have permission for this class action." });
    }
    request.classAccess = access;
    return next();
  } catch (error) {
    return next(error);
  }
}

export function classPermission(permission) {
  return (request, response, next) => {
    requireClassPermission(request, response, next, permission);
  };
}
