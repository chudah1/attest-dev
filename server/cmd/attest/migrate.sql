-- Idempotent migrations for existing databases.
-- Each block silently skips if the column already exists.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS require_idp BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS idp_issuer_url TEXT;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS idp_client_id TEXT;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS org_id TEXT;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS idp_issuer TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_req TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_issuer TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_subject TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_org_tid ON audit_log (org_id, att_tid, id);
