package attest

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	MaxDelegationDepth = 10
	MaxTTLSeconds      = 86400

	EventIssued    EventType = "issued"
	EventDelegated EventType = "delegated"
	EventVerified  EventType = "verified"
	EventRevoked   EventType = "revoked"
	EventExpired   EventType = "expired"
)

type EventType string

// Claims extends jwt.RegisteredClaims with Attest-specific fields (att_*).
type Claims struct {
	jwt.RegisteredClaims

	// att_tid: task tree ID shared across the entire delegation chain
	TaskID string `json:"att_tid"`

	// att_pid: jti of the parent credential (empty for root)
	ParentID string `json:"att_pid,omitempty"`

	// att_depth: delegation depth (0 = root)
	Depth int `json:"att_depth"`

	// att_scope: list of "resource:action" permission entries
	Scope []string `json:"att_scope"`

	// att_intent: SHA-256 hex of the original instruction
	IntentHash string `json:"att_intent"`

	// att_chain: ordered jti ancestry from root to this credential
	Chain []string `json:"att_chain"`

	// att_uid: original human principal who initiated the task
	UserID string `json:"att_uid"`
}

// IssueParams carries the inputs needed to issue a root credential.
type IssueParams struct {
	AgentID     string   `json:"agent_id"`
	UserID      string   `json:"user_id"`
	Scope       []string `json:"scope"`
	Instruction string   `json:"instruction"`
	TTLSeconds  int64    `json:"ttl_seconds,omitempty"`
}

// DelegateParams carries the inputs needed to delegate to a child agent.
type DelegateParams struct {
	ParentToken string   `json:"parent_token"`
	ChildAgent  string   `json:"child_agent"`
	ChildScope  []string `json:"child_scope"`
	TTLSeconds  int64    `json:"ttl_seconds,omitempty"`
}

// VerifyResult is returned by token verification.
type VerifyResult struct {
	Valid    bool     `json:"valid"`
	Claims   *Claims  `json:"claims,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// AuditEvent is a single immutable entry in the audit log.
type AuditEvent struct {
	ID        int64             `json:"id,omitempty"`
	PrevHash  string            `json:"prev_hash"`
	EntryHash string            `json:"entry_hash"`
	EventType EventType         `json:"event_type"`
	JTI       string            `json:"jti"`
	TaskID    string            `json:"att_tid"`
	UserID    string            `json:"att_uid"`
	AgentID   string            `json:"agent_id"`
	Scope     []string          `json:"scope"`
	Meta      map[string]string `json:"meta,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}
