package revocation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists revoked JTIs and supports descendant cascade via the chain column.
type Store struct {
	db *pgxpool.Pool
}

// NewStore constructs a Store backed by the given connection pool.
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Revoke marks jti as revoked and cascades to every credential whose
// att_chain contains jti (i.e. every descendant in the delegation tree).
func (s *Store) Revoke(ctx context.Context, orgID, jti, revokedBy string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	now := time.Now().UTC()

	// Collect the target jti plus all descendants (credentials whose chain
	// contains this jti). The GIN index on chain makes this efficient.
	rows, err := tx.Query(ctx, `
		SELECT jti FROM credentials
		WHERE org_id = $1 AND (jti = $2 OR chain @> ARRAY[$2]::text[])
	`, orgID, jti)
	if err != nil {
		return fmt.Errorf("query descendants: %w", err)
	}
	defer rows.Close()

	var jtis []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return fmt.Errorf("scan jti: %w", err)
		}
		jtis = append(jtis, j)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rows: %w", err)
	}

	// Insert into revocations, ignoring duplicates.
	for _, j := range jtis {
		_, err := tx.Exec(ctx, `
			INSERT INTO revocations (jti, revoked_at, revoked_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (jti) DO NOTHING
		`, j, now, revokedBy)
		if err != nil {
			return fmt.Errorf("insert revocation for %s: %w", j, err)
		}
	}

	return tx.Commit(ctx)
}

// TrackCredential inserts the credential into the credentials table so that
// cascade revocation can discover descendants via the chain column.
func (s *Store) TrackCredential(ctx context.Context, orgID string, claims *attest.Claims) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO credentials (jti, org_id, att_tid, att_pid, att_uid, agent_id, depth, scope, chain, issued_at, expires_at, intent_hash, agent_checksum, idp_issuer, idp_subject, hitl_req, hitl_issuer, hitl_subject)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULLIF($13, ''), $14, $15, $16, $17, $18)
		ON CONFLICT (jti) DO NOTHING
	`, claims.ID, orgID, claims.TaskID, claims.ParentID, claims.UserID,
		strings.TrimPrefix(claims.Subject, "agent:"), claims.Depth,
		claims.Scope, claims.Chain,
		claims.IssuedAt.Time, claims.ExpiresAt.Time, claims.IntentHash, claims.AgentChecksum,
		claims.IDPIssuer, claims.IDPSubject, claims.HITLRequestID, claims.HITLIssuer, claims.HITLSubject)
	if err != nil {
		return fmt.Errorf("track credential database error: %w", err)
	}
	return nil
}

// ListTaskCredentials returns all credentials for a task tree.
func (s *Store) ListTaskCredentials(ctx context.Context, orgID, taskID string) ([]attest.CredentialRecord, error) {
	rows, err := s.db.Query(ctx, `
		SELECT jti, org_id, att_tid, att_pid, att_uid, agent_id, depth, scope, chain, issued_at, expires_at,
		       intent_hash, agent_checksum, idp_issuer, idp_subject, hitl_req, hitl_issuer, hitl_subject
		FROM credentials
		WHERE org_id = $1 AND att_tid = $2
		ORDER BY depth ASC, issued_at ASC, jti ASC
	`, orgID, taskID)
	if err != nil {
		return nil, fmt.Errorf("list task credentials: %w", err)
	}
	defer rows.Close()

	var out []attest.CredentialRecord
	for rows.Next() {
		var c attest.CredentialRecord
		if err := rows.Scan(
			&c.JTI, &c.OrgID, &c.TaskID, &c.ParentID, &c.UserID, &c.AgentID, &c.Depth,
			&c.Scope, &c.Chain, &c.IssuedAt, &c.ExpiresAt,
			&c.IntentHash, &c.AgentChecksum, &c.IDPIssuer, &c.IDPSubject,
			&c.HITLRequestID, &c.HITLIssuer, &c.HITLSubject,
		); err != nil {
			return nil, fmt.Errorf("scan task credential: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task credentials: %w", err)
	}

	return out, nil
}

// IsRevoked reports whether jti appears in the revocations table.
// If orgID is non-empty, enforce tenant isolation via a JOIN on credentials.
// If orgID is empty (public verifier endpoint), do a global lookup.
func (s *Store) IsRevoked(ctx context.Context, orgID string, jti string) (bool, error) {
	var exists bool
	var err error
	if orgID != "" {
		err = s.db.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM revocations r
				JOIN credentials c ON c.jti = r.jti
				WHERE r.jti = $1 AND c.org_id = $2
			)
		`, jti, orgID).Scan(&exists)
	} else {
		err = s.db.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM revocations WHERE jti = $1)
		`, jti).Scan(&exists)
	}
	if err != nil {
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return exists, nil
}
