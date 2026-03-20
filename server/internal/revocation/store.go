package revocation

import (
	"context"
	"fmt"
	"time"

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
func (s *Store) Revoke(ctx context.Context, jti, revokedBy string) error {
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
		WHERE jti = $1 OR chain @> ARRAY[$1]::text[]
	`, jti)
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

// TrackCredential is a no-op for the Postgres Store — descendants are
// discovered at revocation time via the credentials table.
func (s *Store) TrackCredential(_ string, _ []string) {}

// IsRevoked reports whether jti appears in the revocations table.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM revocations WHERE jti = $1)
	`, jti).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return exists, nil
}
