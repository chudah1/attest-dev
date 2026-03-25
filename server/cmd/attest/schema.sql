-- Attest database schema
-- Run once against a fresh PostgreSQL database.

-- ── organisations ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
    id             TEXT        PRIMARY KEY,          -- UUID
    name           TEXT        NOT NULL,
    status         TEXT        NOT NULL DEFAULT 'active',
    require_idp    BOOLEAN     NOT NULL DEFAULT FALSE,
    idp_issuer_url TEXT,
    idp_client_id  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── api_keys ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT        PRIMARY KEY,          -- UUID
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    key_hash    TEXT        NOT NULL UNIQUE,      -- SHA-256 hex of the raw key
    name        TEXT        NOT NULL DEFAULT 'default',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys (org_id);

-- ── org_keys ──────────────────────────────────────────────────────────────────
-- Stores RSA key pairs per org. Multiple rows per org are allowed (rotation).
-- The active key has retired_at IS NULL.

CREATE TABLE IF NOT EXISTS org_keys (
    id          TEXT        PRIMARY KEY,          -- UUID, used as JWT kid
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    private_key BYTEA       NOT NULL,             -- PKCS1 DER; encrypt at rest in production
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_org_keys_org ON org_keys (org_id) WHERE retired_at IS NULL;

-- ── credentials ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credentials (
    jti         TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    att_tid     TEXT        NOT NULL,
    att_pid     TEXT,                        -- parent jti; NULL for root
    att_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    depth       INTEGER     NOT NULL DEFAULT 0,
    scope       TEXT[]      NOT NULL,
    chain       TEXT[]      NOT NULL,        -- ordered ancestor jti list
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

-- GIN index enables fast ancestor lookup: chain @> ARRAY['<jti>']
CREATE INDEX IF NOT EXISTS idx_credentials_chain ON credentials USING GIN (chain);
CREATE INDEX IF NOT EXISTS idx_credentials_tid   ON credentials (att_tid);
CREATE INDEX IF NOT EXISTS idx_credentials_uid   ON credentials (att_uid);

-- ── revocations ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revocations (
    jti         TEXT        PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT        NOT NULL         -- agent or user ID that triggered revocation
);

CREATE INDEX IF NOT EXISTS idx_revocations_at ON revocations (revoked_at);

-- ── approvals ──────────────────────────────────────────────────────────────────
-- Stores pending requests from an agent for a human to approve

CREATE TABLE IF NOT EXISTS approvals (
    id             TEXT        PRIMARY KEY,     -- The Approval Challenge ID (e.g. uuid)
    org_id         TEXT        NOT NULL REFERENCES organizations(id),
    agent_id       TEXT        NOT NULL,        -- The sub-agent requesting approval
    att_tid        TEXT        NOT NULL,        -- Task tree ID
    parent_token   TEXT        NOT NULL,        -- The credential of the agent asking
    intent         TEXT        NOT NULL,        -- Description of the action needing approval
    requested_scope TEXT[]     NOT NULL,        -- The specific scope required (e.g., finance:transfer)
    status         TEXT        NOT NULL DEFAULT 'pending', -- pending, approved, rejected
    approved_by    TEXT,                        -- The IdP Subject who approved it
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals (agent_id) WHERE status = 'pending';

-- ── audit_log ─────────────────────────────────────────────────────────────────
-- Append-only. Each row chains to the previous via prev_hash / entry_hash.

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    prev_hash   TEXT        NOT NULL,        -- entry_hash of previous row for this tid
    entry_hash  TEXT        NOT NULL,        -- SHA-256(prev_hash || event_type || jti || created_at)
    event_type  TEXT        NOT NULL,        -- issued | delegated | verified | revoked | expired | hitl_granted
    jti         TEXT        NOT NULL,
    att_tid     TEXT        NOT NULL,
    att_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    scope       JSONB       NOT NULL DEFAULT '[]',
    meta        JSONB,
    idp_issuer  TEXT,                        -- Okta/Entra issuer (Root credential identity)
    idp_subject TEXT,                        -- Okta/Entra unique user subject (Root credential identity)
    hitl_req    TEXT,                        -- The approval challenge ID
    hitl_issuer TEXT,                        -- The IdP issuer of the human who approved mid-chain
    hitl_subject TEXT,                       -- The subject of the human who approved mid-chain
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_org_tid ON audit_log (org_id, att_tid, id);
CREATE INDEX IF NOT EXISTS idx_audit_tid ON audit_log (att_tid, id);
CREATE INDEX IF NOT EXISTS idx_audit_jti ON audit_log (jti);

-- Prevent UPDATE and DELETE on audit_log to keep it append-only.
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;

-- ── migrations ──────────────────────────────────────────────────────────────
-- Idempotent ALTER statements to upgrade existing databases.
-- Each uses DO $$ to silently skip if the column/table already exists.

DO $$ BEGIN
    ALTER TABLE organizations ADD COLUMN require_idp BOOLEAN NOT NULL DEFAULT FALSE;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE organizations ADD COLUMN idp_issuer_url TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE organizations ADD COLUMN idp_client_id TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE credentials ADD COLUMN org_id TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN org_id TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN idp_issuer TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN idp_subject TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN hitl_req TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN hitl_issuer TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE audit_log ADD COLUMN hitl_subject TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;
