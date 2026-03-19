-- Warrant database schema
-- Run once against a fresh PostgreSQL database.

-- ── credentials ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credentials (
    jti         TEXT        PRIMARY KEY,
    wrt_tid     TEXT        NOT NULL,
    wrt_pid     TEXT,                        -- parent jti; NULL for root
    wrt_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    depth       INTEGER     NOT NULL DEFAULT 0,
    scope       TEXT[]      NOT NULL,
    chain       TEXT[]      NOT NULL,        -- ordered ancestor jti list
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

-- GIN index enables fast ancestor lookup: chain @> ARRAY['<jti>']
CREATE INDEX IF NOT EXISTS idx_credentials_chain ON credentials USING GIN (chain);
CREATE INDEX IF NOT EXISTS idx_credentials_tid   ON credentials (wrt_tid);
CREATE INDEX IF NOT EXISTS idx_credentials_uid   ON credentials (wrt_uid);

-- ── revocations ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revocations (
    jti         TEXT        PRIMARY KEY,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT        NOT NULL         -- agent or user ID that triggered revocation
);

CREATE INDEX IF NOT EXISTS idx_revocations_at ON revocations (revoked_at);

-- ── audit_log ─────────────────────────────────────────────────────────────────
-- Append-only. Each row chains to the previous via prev_hash / entry_hash.

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    prev_hash   TEXT        NOT NULL,        -- entry_hash of previous row for this tid
    entry_hash  TEXT        NOT NULL,        -- SHA-256(prev_hash || event_type || jti || created_at)
    event_type  TEXT        NOT NULL,        -- issued | delegated | verified | revoked | expired
    jti         TEXT        NOT NULL,
    wrt_tid     TEXT        NOT NULL,
    wrt_uid     TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    scope       JSONB       NOT NULL DEFAULT '[]',
    meta        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tid ON audit_log (wrt_tid, id);
CREATE INDEX IF NOT EXISTS idx_audit_jti ON audit_log (jti);

-- Prevent UPDATE and DELETE on audit_log to keep it append-only.
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;
