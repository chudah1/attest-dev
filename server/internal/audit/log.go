package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/warrant-dev/warrant/pkg/warrant"
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
// It fetches the most recent entry_hash for the same wrt_tid and chains from it.
// If this is the first event for the task, prev_hash is all-zeros.
func (l *Log) Append(ctx context.Context, event warrant.AuditEvent) error {
	// Fetch the latest entry_hash for this task (for chaining).
	var prevHash string
	err := l.db.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log
		WHERE wrt_tid = $1
		ORDER BY id DESC
		LIMIT 1
	`, event.TaskID).Scan(&prevHash)
	if err != nil {
		// No previous entry — use genesis hash.
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	scopeJSON, err := json.Marshal(event.Scope)
	if err != nil {
		return fmt.Errorf("marshal scope: %w", err)
	}

	metaJSON, err := json.Marshal(event.Meta)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}

	now := time.Now().UTC()

	// Compute entry hash: SHA-256(prevHash + eventType + jti + timestamp).
	raw := prevHash + string(event.EventType) + event.JTI + now.Format(time.RFC3339Nano)
	h := sha256.Sum256([]byte(raw))
	entryHash := hex.EncodeToString(h[:])

	_, err = l.db.Exec(ctx, `
		INSERT INTO audit_log
			(prev_hash, entry_hash, event_type, jti, wrt_tid, wrt_uid, agent_id, scope, meta, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, prevHash, entryHash, string(event.EventType), event.JTI, event.TaskID,
		event.UserID, event.AgentID, scopeJSON, metaJSON, now)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}

	return nil
}

// Query returns all audit events for a given task ID in insertion order.
func (l *Log) Query(ctx context.Context, taskID string) ([]warrant.AuditEvent, error) {
	rows, err := l.db.Query(ctx, `
		SELECT id, prev_hash, entry_hash, event_type, jti, wrt_tid, wrt_uid, agent_id, scope, meta, created_at
		FROM audit_log
		WHERE wrt_tid = $1
		ORDER BY id ASC
	`, taskID)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var events []warrant.AuditEvent
	for rows.Next() {
		var e warrant.AuditEvent
		var scopeJSON, metaJSON []byte
		var evType string

		err := rows.Scan(
			&e.ID, &e.PrevHash, &e.EntryHash, &evType,
			&e.JTI, &e.TaskID, &e.UserID, &e.AgentID,
			&scopeJSON, &metaJSON, &e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}

		e.EventType = warrant.EventType(evType)

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
