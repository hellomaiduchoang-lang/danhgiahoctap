CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  full_name TEXT NOT NULL,
  student_number TEXT UNIQUE,
  avatar_color TEXT NOT NULL DEFAULT '#e3e8f5',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (email = LOWER(email))
);

CREATE TABLE classes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  school_name TEXT NOT NULL DEFAULT '',
  academic_year TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (name, academic_year)
);

CREATE TABLE roles (
  id SMALLSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE CHECK (name IN (
    'ROLE_TEACHER',
    'ROLE_CLASS_LEADER',
    'ROLE_CLASS_DEPUTY',
    'ROLE_GROUP_LEADER',
    'ROLE_STUDENT'
  ))
);

CREATE TABLE permissions (
  id SMALLSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE role_permissions (
  role_id SMALLINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id SMALLINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE class_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (class_id, user_id),
  UNIQUE (class_id, id)
);

CREATE TABLE class_member_roles (
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  class_member_id UUID NOT NULL,
  role_id SMALLINT NOT NULL REFERENCES roles(id),
  granted_by_member_id UUID,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (class_member_id, role_id),
  FOREIGN KEY (class_id, class_member_id) REFERENCES class_members(class_id, id) ON DELETE CASCADE,
  FOREIGN KEY (class_id, granted_by_member_id) REFERENCES class_members(class_id, id)
);

CREATE TABLE member_permissions (
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  class_member_id UUID NOT NULL,
  permission_id SMALLINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  granted_by_member_id UUID NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (class_member_id, permission_id),
  FOREIGN KEY (class_id, class_member_id) REFERENCES class_members(class_id, id) ON DELETE CASCADE,
  FOREIGN KEY (class_id, granted_by_member_id) REFERENCES class_members(class_id, id)
);

CREATE TABLE role_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  requested_by_member_id UUID NOT NULL,
  requested_role_id SMALLINT NOT NULL REFERENCES roles(id),
  reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by_member_id UUID,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (class_id, requested_by_member_id) REFERENCES class_members(class_id, id),
  FOREIGN KEY (class_id, reviewed_by_member_id) REFERENCES class_members(class_id, id)
);

CREATE UNIQUE INDEX role_requests_pending_unique_idx
  ON role_requests (class_id, requested_by_member_id, requested_role_id)
  WHERE status = 'pending';

CREATE TABLE class_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (class_id, name),
  UNIQUE (id, class_id)
);

CREATE TABLE group_members (
  group_id UUID NOT NULL,
  class_id UUID NOT NULL,
  class_member_id UUID NOT NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (group_id, class_member_id),
  FOREIGN KEY (group_id, class_id) REFERENCES class_groups(id, class_id) ON DELETE CASCADE,
  FOREIGN KEY (class_id, class_member_id) REFERENCES class_members(class_id, id) ON DELETE CASCADE
);

CREATE TABLE conduct_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('positive', 'negative')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (class_id, name, kind),
  UNIQUE (class_id, id)
);

CREATE TABLE conduct_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  student_member_id UUID NOT NULL,
  recorder_member_id UUID NOT NULL,
  category_id UUID,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
  description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
  kind TEXT NOT NULL CHECK (kind IN ('positive', 'negative')),
  points INTEGER NOT NULL CHECK (points BETWEEN 1 AND 100),
  record_date DATE NOT NULL,
  source TEXT NOT NULL DEFAULT '' CHECK (length(source) <= 80),
  evidence_name TEXT NOT NULL DEFAULT '' CHECK (length(evidence_name) <= 255),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idempotency_key TEXT,
  FOREIGN KEY (class_id, student_member_id) REFERENCES class_members(class_id, id),
  FOREIGN KEY (class_id, recorder_member_id) REFERENCES class_members(class_id, id),
  UNIQUE (class_id, idempotency_key),
  UNIQUE (class_id, id),
  FOREIGN KEY (class_id, category_id) REFERENCES conduct_categories(class_id, id)
);

CREATE TABLE evidence_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  conduct_record_id UUID NOT NULL,
  original_name TEXT NOT NULL,
  storage_key TEXT NOT NULL UNIQUE,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
  uploaded_by_member_id UUID NOT NULL REFERENCES class_members(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (class_id, conduct_record_id) REFERENCES conduct_records(class_id, id) ON DELETE CASCADE,
  FOREIGN KEY (class_id, uploaded_by_member_id) REFERENCES class_members(class_id, id)
);

CREATE TABLE auth_sessions (
  token_hash BYTEA PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX auth_sessions_expiry_idx ON auth_sessions (expires_at);
CREATE INDEX class_members_user_idx ON class_members (user_id, is_active);
CREATE INDEX group_members_class_member_idx ON group_members (class_id, class_member_id);
CREATE INDEX conduct_records_class_date_idx ON conduct_records (class_id, record_date DESC);
CREATE INDEX conduct_records_student_idx ON conduct_records (student_member_id, record_date DESC);
CREATE INDEX evidence_files_class_idx ON evidence_files (class_id, conduct_record_id);

CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  class_id UUID REFERENCES classes(id) ON DELETE SET NULL,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (name) VALUES
  ('ROLE_TEACHER'),
  ('ROLE_CLASS_LEADER'),
  ('ROLE_CLASS_DEPUTY'),
  ('ROLE_GROUP_LEADER'),
  ('ROLE_STUDENT');

INSERT INTO permissions (name) VALUES
  ('classes:read'),
  ('students:list'),
  ('conduct:view_all'),
  ('conduct:view_group'),
  ('conduct:view_own'),
  ('conduct:create'),
  ('conduct:verify'),
  ('roles:manage'),
  ('permissions:manage');

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles CROSS JOIN permissions
WHERE roles.name = 'ROLE_TEACHER';

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles JOIN permissions ON permissions.name IN ('classes:read', 'conduct:view_own')
WHERE roles.name = 'ROLE_STUDENT';

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles JOIN permissions ON permissions.name IN ('classes:read', 'students:list')
WHERE roles.name = 'ROLE_CLASS_LEADER';

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles JOIN permissions ON permissions.name = 'classes:read'
WHERE roles.name IN ('ROLE_CLASS_DEPUTY', 'ROLE_GROUP_LEADER');

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles JOIN permissions ON permissions.name = 'conduct:view_group'
WHERE roles.name = 'ROLE_GROUP_LEADER';
