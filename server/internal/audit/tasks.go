package audit

import (
	"time"

	"github.com/attest-dev/attest/pkg/attest"
)

// TaskListQuery controls org-scoped task discovery.
type TaskListQuery struct {
	UserID string
	AgentID string
	Status string
	Limit int
}

// TaskSummary is the dashboard-friendly view of a task tree.
type TaskSummary struct {
	TaskID          string           `json:"att_tid"`
	UserID          string           `json:"att_uid"`
	RootAgentID     string           `json:"root_agent_id"`
	EventCount      int              `json:"event_count"`
	CredentialCount int              `json:"credential_count"`
	CreatedAt       time.Time        `json:"created_at"`
	LastEventAt     time.Time        `json:"last_event_at"`
	LastEventType   attest.EventType `json:"last_event_type"`
	Revoked         bool             `json:"revoked"`
}
