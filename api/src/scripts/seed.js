import "dotenv/config";
import bcrypt from "bcryptjs";
import { pool } from "../db.js";

const username = (process.env.BOOTSTRAP_TEACHER_USERNAME || process.env.BOOTSTRAP_TEACHER_EMAIL || "teacher").trim().toLowerCase().split("@")[0];
const password = process.env.BOOTSTRAP_TEACHER_PASSWORD;
if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username) || !password || password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
  throw new Error("Set BOOTSTRAP_TEACHER_USERNAME and a BOOTSTRAP_TEACHER_PASSWORD between 12 and 72 UTF-8 bytes.");
}

const client = await pool.connect();
const students = [
  ["HS001", "Nguyễn Minh Anh", "#f6d7cc"],
  ["HS002", "Trần Hoàng Nam", "#cfe9dd"],
  ["HS003", "Lê Khánh Linh", "#ded8f5"],
  ["HS004", "Phạm Gia Bảo", "#f3e4bc"],
  ["HS005", "Đỗ Hà My", "#cce4f5"],
  ["HS006", "Vũ Đức Minh", "#f2d4df"]
];
const incidents = [
  ["EVT01", "HS003", "Tích cực phát biểu xây dựng bài", "Chủ động đóng góp ý kiến trong giờ Ngữ văn.", "positive", 2, "2026-10-21", "GVCN", "verified", ""],
  ["EVT02", "HS001", "Hỗ trợ bạn học tập", "Hướng dẫn bạn hoàn thành bài tập nhóm.", "positive", 3, "2026-10-20", "Giáo viên bộ môn", "verified", "nhom-hoc-tap.jpg"],
  ["EVT03", "HS004", "Đi học muộn", "Vào lớp sau khi tiết học bắt đầu.", "negative", 2, "2026-10-20", "Sổ đầu bài", "pending", ""],
  ["EVT04", "HS002", "Hoàn thành tốt nhiệm vụ trực nhật", "Khu vực lớp học sạch sẽ, đúng phân công.", "positive", 2, "2026-10-18", "GVCN", "verified", ""],
  ["EVT05", "HS006", "Chưa chuẩn bị bài", "Chưa hoàn thành phần bài tập được giao.", "negative", 1, "2026-10-17", "Giáo viên bộ môn", "pending", ""],
  ["EVT06", "HS005", "Đạt giải khuyến khích văn nghệ", "Tham gia hội diễn văn nghệ cấp trường.", "positive", 5, "2026-10-15", "Ban tổ chức", "verified", "ket-qua-hoi-dien.pdf"],
  ["EVT07", "HS001", "Giữ gìn vệ sinh lớp học", "Chủ động nhặt rác và sắp xếp bàn ghế.", "positive", 1, "2026-10-12", "GVCN", "verified", ""]
];

try {
  await client.query("BEGIN");
  const passwordHash = await bcrypt.hash(password, 12);
  const classResult = await client.query(
    `INSERT INTO classes (name, school_name, academic_year)
     VALUES ('10A1', 'THPT Nguyễn Du', '2025-2026')
     ON CONFLICT (name, academic_year) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
  );
  const classId = classResult.rows[0].id;
  const teacherRole = await client.query("SELECT id FROM roles WHERE name = 'ROLE_TEACHER'");
  const insertedTeacher = await client.query(
    `INSERT INTO users (username, password_hash, full_name)
     VALUES ($1, $2, 'Nguyễn Minh Lan')
     ON CONFLICT (username) DO NOTHING
     RETURNING id`,
    [username, passwordHash]
  );
  let teacherId = insertedTeacher.rows[0]?.id;
  if (!teacherId) {
    const existingTeacher = await client.query(
      `SELECT users.id
       FROM users
       JOIN class_members ON class_members.user_id = users.id
       JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
       JOIN roles ON roles.id = class_member_roles.role_id
       WHERE users.username = $1 AND class_members.class_id = $2
         AND roles.name = 'ROLE_TEACHER'`,
      [username, classId]
    );
    teacherId = existingTeacher.rows[0]?.id;
    if (!teacherId) {
      throw new Error("The bootstrap username already belongs to an account that is not a teacher of class 10A1.");
    }
    await client.query(
      "UPDATE users SET password_hash = $2, is_active = TRUE WHERE id = $1",
      [teacherId, passwordHash]
    );
  }
  await client.query("UPDATE users SET is_admin = TRUE, is_super_admin = TRUE, is_teacher = TRUE, must_change_password = FALSE WHERE id = $1", [teacherId]);
  const teacherMember = await client.query(
    `INSERT INTO class_members (class_id, user_id)
     VALUES ($1, $2)
     ON CONFLICT (class_id, user_id) DO UPDATE SET is_active = TRUE
     RETURNING id`,
    [classId, teacherId]
  );
  await client.query(
    "INSERT INTO class_member_roles (class_id, class_member_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    [classId, teacherMember.rows[0].id, teacherRole.rows[0].id]
  );

  const memberIds = new Map();
  const studentRole = await client.query("SELECT id FROM roles WHERE name = 'ROLE_STUDENT'");
  for (const [studentNumber, fullName, avatarColor] of students) {
    const userResult = await client.query(
      `INSERT INTO users (username, full_name, student_number, avatar_color)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (student_number) DO UPDATE SET full_name = EXCLUDED.full_name, avatar_color = EXCLUDED.avatar_color
       RETURNING id`,
      [studentNumber.toLowerCase(), fullName, studentNumber, avatarColor]
    );
    const memberResult = await client.query(
      `INSERT INTO class_members (class_id, user_id)
       VALUES ($1, $2)
       ON CONFLICT (class_id, user_id) DO UPDATE SET is_active = TRUE
       RETURNING id`,
      [classId, userResult.rows[0].id]
    );
    memberIds.set(studentNumber, memberResult.rows[0].id);
    await client.query(
      "INSERT INTO class_member_roles (class_id, class_member_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
      [classId, memberResult.rows[0].id, studentRole.rows[0].id]
    );
  }

  const groupLeaderRole = await client.query("SELECT id FROM roles WHERE name = 'ROLE_GROUP_LEADER'");
  await client.query(
    "INSERT INTO class_member_roles (class_id, class_member_id, role_id, granted_by_member_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    [classId, memberIds.get("HS001"), groupLeaderRole.rows[0].id, teacherMember.rows[0].id]
  );
  const groupResult = await client.query(
    `INSERT INTO class_groups (class_id, name)
     VALUES ($1, 'Tổ 1')
     ON CONFLICT (class_id, name) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
    [classId]
  );
  for (const [studentNumber] of students.slice(0, 3)) {
    await client.query(
      `INSERT INTO group_members (group_id, class_id, class_member_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (group_id, class_member_id) DO NOTHING`,
      [groupResult.rows[0].id, classId, memberIds.get(studentNumber)]
    );
  }

  for (const [key, studentNumber, title, description, kind, points, recordDate, source, status, evidenceName] of incidents) {
    await client.query(
      `INSERT INTO conduct_records
        (class_id, student_member_id, recorder_member_id, title, description, kind, points, record_date, source, status, idempotency_key, evidence_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (class_id, idempotency_key) DO NOTHING`,
      [classId, memberIds.get(studentNumber), teacherMember.rows[0].id, title, description, kind, points, recordDate, source, status, key, evidenceName]
    );
  }

  await client.query("COMMIT");
  console.info(`Seeded ClassTrack demo class 10A1. Teacher login: ${username}`);
} catch (error) {
  await client.query("ROLLBACK");
  console.error("Database seed failed:", error);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
