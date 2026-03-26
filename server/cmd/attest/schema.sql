-- Attest database schema
-- Run once against a fresh PostgreSQL database.

-- ── organisations ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
    id             TEXT        PRIMARY KEY,
    name           TEXT        NOT NULL,
    status         TEXT        NOT NULL DEFAULT 'active',
    require_idp    BOOLEAN     NOT NULL DEFAULT FALSE,
    idp_issuer_url TEXT,
    idp_client_id  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── api_keys ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    key_hash    TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL DEFAULT 'default',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys (org_id);

-- ── org_keys ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS org_keys (
    id          TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    private_key BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_org_keys_org ON org_keys (org_id) WHERE retired_at IS NULL;

-- ── credentials ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credentials (
    jti         TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES organizations(id),
    att_tid     TEXT        NOT NULL,
    att_pid     TEXT,
    att_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    depth       INTEGER     NOT NULL DEFAULT 0,
    scope       TEXT[]      NOT NULL,
    chain       TEXT[]      NOT NULL,
    intent_hash TEXT        NOT NULL DEFAULT '',
    agent_checksum TEXT,
    idp_issuer  TEXT,
    idp_subject TEXT,
    hitl_req    TEXT,
    hitl_issuer TEXT,
    hitl_subject TEXT,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_chain ON credentials USING GIN (chain);
CREATE INDEX IF NOT EXISTS idx_credentials_tid   ON credentials (att_tid);
CREATE INDEX IF NOT EXISTS idx_credentials_uid   ON credentials (att_uid);

-- ── revocations ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revocations (
    jti         TEXT        PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_at ON revocations (revoked_at);

-- ── approvals ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT        PRIMARY KEY,
    org_id          TEXT        NOT NULL REFERENCES organizations(id),
    agent_id        TEXT        NOT NULL,
    att_tid         TEXT        NOT NULL,
    parent_token    TEXT        NOT NULL,
    intent          TEXT        NOT NULL,
    requested_scope TEXT[]      NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    approved_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals (agent_id) WHERE status = 'pending';

-- ── audit_log ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGSERIAL   PRIMARY KEY,
    org_id       TEXT        NOT NULL REFERENCES organizations(id),
    prev_hash    TEXT        NOT NULL,
    entry_hash   TEXT        NOT NULL,
    event_type   TEXT        NOT NULL,
    jti          TEXT        NOT NULL,
    att_tid      TEXT        NOT NULL,
    att_uid      TEXT        NOT NULL,
    agent_id     TEXT        NOT NULL,
    scope        JSONB       NOT NULL DEFAULT '[]',
    meta         JSONB,
    idp_issuer   TEXT,
    idp_subject  TEXT,
    hitl_req     TEXT,
    hitl_issuer  TEXT,
    hitl_subject TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tid ON audit_log (att_tid, id);
CREATE INDEX IF NOT EXISTS idx_audit_jti ON audit_log (jti);

CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;
