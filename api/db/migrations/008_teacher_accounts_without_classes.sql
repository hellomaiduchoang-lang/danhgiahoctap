ALTER TABLE users ADD COLUMN is_teacher BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET is_teacher = TRUE
WHERE EXISTS (
  SELECT 1
  FROM class_members
  JOIN class_member_roles ON class_member_roles.class_member_id = class_members.id
  JOIN roles ON roles.id = class_member_roles.role_id
  WHERE class_members.user_id = users.id
    AND roles.name = 'ROLE_TEACHER'
);
