package approval

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("approval request not found or already resolved")

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

type ApprovalRequest struct {
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	TaskID         string     `json:"att_tid"`
	ParentToken    string     `json:"parent_token"`
	Intent         string     `json:"intent"`
	RequestedScope []string   `json:"requested_scope"`
	Status         Status     `json:"status"`
	ApprovedBy     *string    `json:"approved_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

// Store provides persistence for approval requests.
type Store interface {
	RequestApproval(ctx context.Context, req ApprovalRequest) error
	GetPending(ctx context.Context, id string) (*ApprovalRequest, error)
	Get(ctx context.Context, id string) (*ApprovalRequest, error)
	Resolve(ctx context.Context, id string, status Status, approvedBy string) error
}
