-- Idempotent migrations for existing databases.
-- Each block silently skips if the column already exists.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS require_idp BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS idp_issuer_url TEXT;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS idp_client_id TEXT;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS intent_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS agent_checksum TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS idp_issuer TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS hitl_req TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS hitl_issuer TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS hitl_subject TEXT;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS org_id TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS idp_issuer TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS idp_subject TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_req TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_issuer TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hitl_subject TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_org_tid ON audit_log (org_id, att_tid, id);

CREATE TABLE IF NOT EXISTS org_action_policies (
    org_id TEXT NOT NULL REFERENCES organizations(id),
    action_type TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, action_type)
);

CREATE TABLE IF NOT EXISTS action_requests (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    att_tid TEXT NOT NULL,
    action_family TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_system TEXT NOT NULL,
    target_object TEXT NOT NULL,
    action_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    display_payload JSONB,
    payload_hash TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    sponsor_user_id TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_level TEXT,
    policy_version TEXT,
    policy_reason TEXT,
    approval_id TEXT REFERENCES approvals(id),
    grant_jti TEXT REFERENCES credentials(jti),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_action_requests_org_created ON action_requests (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_requests_org_status ON action_requests (org_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_requests_tid ON action_requests (att_tid);

CREATE TABLE IF NOT EXISTS execution_receipts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    action_request_id TEXT NOT NULL UNIQUE REFERENCES action_requests(id),
    grant_jti TEXT NOT NULL REFERENCES credentials(jti),
    outcome TEXT NOT NULL,
    provider_ref TEXT,
    response_payload JSONB,
    payload_hash TEXT NOT NULL,
    approved_by TEXT,
    executed_at TIMESTAMPTZ NOT NULL,
    signed_packet_hash TEXT NOT NULL,
    signature_algorithm TEXT,
    signature_kid TEXT,
    packet_signature TEXT
);

CREATE INDEX IF NOT EXISTS idx_execution_receipts_org_executed ON execution_receipts (org_id, executed_at DESC);
