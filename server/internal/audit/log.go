package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/attest-dev/attest/pkg/attest"
)

// Log is an append-only audit log with cryptographic hash chaining.
// Each entry records the SHA-256 of the previous entry's hash, forming a
// tamper-evident chain for the given task tree.
type Log struct {
	db *pgxpool.Pool
}

// NewLog constructs a Log backed by the given connection pool.
func NewLog(db *pgxpool.Pool) *Log {
	return &Log{db: db}
}

// Append writes an AuditEvent to the log.
// It fetches the most recent entry_hash for the same att_tid and chains from it.
// If this is the first event for the task, prev_hash is all-zeros.
func (l *Log) Append(ctx context.Context, orgID string, event attest.AuditEvent) error {
	event.OrgID = orgID
	scopeJSON, err := json.Marshal(event.Scope)
	if err != nil {
		return fmt.Errorf("marshal scope: %w", err)
	}

	metaJSON, err := json.Marshal(event.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	// Use a serializable transaction so concurrent appends for the same
	// att_tid don't fork the hash chain.
	tx, err := l.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Use a transactional advisory lock to strictly serialize appends for the same
	// att_tid. This prevents phantom-read forks where concurrent appends see
	// the same prev_hash. The lock is released automatically when `tx` commits.
	_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('audit_log'::text), hashtext($1::text))", event.TaskID)
	if err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}

	// Fetch the latest row to chain from.
	var prevHash string
	err = tx.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log
		WHERE att_tid = $1 AND org_id = $2
		ORDER BY id DESC
		LIMIT 1
	`, event.TaskID, orgID).Scan(&prevHash)
	if err != nil {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()

	raw := prevHash + string(event.EventType) + event.JTI + now.Format(time.RFC3339Nano)
	h := sha256.Sum256([]byte(raw))
	entryHash := hex.EncodeToString(h[:])

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_log
			(org_id, prev_hash, entry_hash, event_type, jti, att_tid, att_uid, agent_id, scope, meta, idp_issuer, idp_subject, hitl_req, hitl_issuer, hitl_subject, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`, event.OrgID, prevHash, entryHash, string(event.EventType), event.JTI, event.TaskID,
		event.UserID, event.AgentID, scopeJSON, metaJSON, event.IDPIssuer, event.IDPSubject,
		event.HITLRequestID, event.HITLIssuer, event.HITLSubject, now)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}

	return tx.Commit(ctx)
}

// Query returns all audit events for a given task ID in insertion order.
func (l *Log) Query(ctx context.Context, orgID string, taskID string) ([]attest.AuditEvent, error) {
	rows, err := l.db.Query(ctx, `
		SELECT id, org_id, prev_hash, entry_hash, event_type, jti, att_tid, att_uid, agent_id, scope, meta, idp_issuer, idp_subject, hitl_req, hitl_issuer, hitl_subject, created_at
		FROM audit_log
		WHERE org_id = $1 AND att_tid = $2
		ORDER BY id ASC
	`, orgID, taskID)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var events []attest.AuditEvent
	for rows.Next() {
		var e attest.AuditEvent
		var scopeJSON, metaJSON []byte
		var evType string

		err := rows.Scan(
			&e.ID, &e.OrgID, &e.PrevHash, &e.EntryHash, &evType,
			&e.JTI, &e.TaskID, &e.UserID, &e.AgentID,
			&scopeJSON, &metaJSON, &e.IDPIssuer, &e.IDPSubject,
			&e.HITLRequestID, &e.HITLIssuer, &e.HITLSubject, &e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}

		e.EventType = attest.EventType(evType)

		if err := json.Unmarshal(scopeJSON, &e.Scope); err != nil {
			return nil, fmt.Errorf("unmarshal scope: %w", err)
		}
		if len(metaJSON) > 0 && string(metaJSON) != "null" {
			if err := json.Unmarshal(metaJSON, &e.Meta); err != nil {
				return nil, fmt.Errorf("unmarshal meta: %w", err)
			}
		}

		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit rows: %w", err)
	}

	return events, nil
}
