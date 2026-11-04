ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ;
