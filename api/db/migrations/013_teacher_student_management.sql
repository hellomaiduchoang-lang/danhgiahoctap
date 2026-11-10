ALTER TABLE classes ADD COLUMN class_code TEXT;

ALTER TABLE classes
  ADD CONSTRAINT classes_class_code_trim_check
  CHECK (class_code IS NULL OR (class_code = BTRIM(class_code) AND class_code <> ''));

CREATE UNIQUE INDEX classes_class_code_unique_idx
  ON classes (LOWER(BTRIM(class_code)))
  WHERE class_code IS NOT NULL;

INSERT INTO permissions (name)
VALUES ('students:delete')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles
CROSS JOIN permissions
WHERE roles.name = 'ROLE_TEACHER'
  AND permissions.name = 'students:delete'
ON CONFLICT DO NOTHING;
