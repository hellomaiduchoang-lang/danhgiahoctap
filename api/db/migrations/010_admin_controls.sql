ALTER TABLE users
  ADD COLUMN is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- The first existing administrator becomes the initial Super Admin.
UPDATE users
SET is_super_admin = TRUE
WHERE id = (
  SELECT id FROM users
  WHERE is_admin = TRUE AND is_active = TRUE
  ORDER BY created_at, id
  LIMIT 1
);

CREATE TABLE admin_permissions (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission_name TEXT NOT NULL CHECK (permission_name IN (
    'accounts:manage',
    'teachers:manage',
    'admins:manage',
    'audit:view',
    'reports:view'
  )),
  granted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, permission_name)
);

CREATE INDEX admin_permissions_user_idx ON admin_permissions (user_id);
CREATE INDEX audit_logs_created_at_idx ON audit_logs (created_at DESC);
