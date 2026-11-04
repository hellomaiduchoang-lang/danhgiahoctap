ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET username = CASE
  WHEN student_number IS NOT NULL THEN LOWER(student_number)
  ELSE LOWER(SPLIT_PART(email, '@', 1))
END;

UPDATE users AS target
SET username = target.username || '-' || LEFT(REPLACE(target.id::TEXT, '-', ''), 8)
WHERE EXISTS (
  SELECT 1 FROM users AS other
  WHERE other.username = target.username AND other.id < target.id
);

ALTER TABLE users ALTER COLUMN username SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_username_unique UNIQUE (username);
ALTER TABLE users DROP CONSTRAINT users_email_check;
ALTER TABLE users DROP COLUMN email;
