ALTER TABLE users
ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users
    ADD CONSTRAINT users_role_check
    CHECK (role IN ('researcher', 'triager', 'admin'));
  END IF;
END $$;

ALTER TABLE findings
ADD COLUMN IF NOT EXISTS ai_summary TEXT,
ADD COLUMN IF NOT EXISTS ai_recommendation TEXT,
ADD COLUMN IF NOT EXISTS ai_priority TEXT,
ADD COLUMN IF NOT EXISTS ai_confidence NUMERIC(3,2) NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS reviewed_by BIGINT REFERENCES users(id),
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);