package approval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production implementation backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore returns a PostgresStore using the given connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) RequestApproval(ctx context.Context, req ApprovalRequest) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO approvals (id, org_id, agent_id, att_tid, parent_token, intent, requested_scope, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
	`, req.ID, req.OrgID, req.AgentID, req.TaskID, req.ParentToken, req.Intent, req.RequestedScope, now)
	if err != nil {
		return fmt.Errorf("insert approval: %w", err)
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	return s.getByID(ctx, orgID, id, false)
}

func (s *PostgresStore) GetPending(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	return s.getByID(ctx, orgID, id, true)
}

func (s *PostgresStore) getByID(ctx context.Context, orgID, id string, pendingOnly bool) (*ApprovalRequest, error) {
	query := `SELECT id, org_id, agent_id, att_tid, parent_token, intent, requested_scope, status, approved_by, created_at, resolved_at
		FROM approvals WHERE id = $1 AND org_id = $2`

	var req ApprovalRequest
	err := s.pool.QueryRow(ctx, query, id, orgID).Scan(
		&req.ID, &req.OrgID, &req.AgentID, &req.TaskID, &req.ParentToken, &req.Intent,
		&req.RequestedScope, &req.Status, &req.ApprovedBy, &req.CreatedAt, &req.ResolvedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get approval: %w", err)
	}

	if req.Status == StatusPending && time.Since(req.CreatedAt) > 15*time.Minute {
		req.Status = StatusExpired
	}

	if pendingOnly && req.Status != StatusPending {
		return nil, ErrNotFound
	}

	return &req, nil
}

func (s *PostgresStore) Resolve(ctx context.Context, orgID, id string, status Status, approvedBy string) error {
	now := time.Now().UTC()
	expireThreshold := now.Add(-15 * time.Minute)

	// Update only if pending and not expired
	tag, err := s.pool.Exec(ctx, `
		UPDATE approvals
		SET status = $1, approved_by = $2, resolved_at = $3
		WHERE id = $4 AND org_id = $5 AND status = 'pending' AND created_at >= $6
	`, string(status), approvedBy, now, id, orgID, expireThreshold)
	if err != nil {
		return fmt.Errorf("resolve approval: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
