ALTER TABLE classes
  ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX classes_is_active_idx ON classes (is_active);
