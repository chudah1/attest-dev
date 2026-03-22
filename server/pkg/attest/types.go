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
	EventAction    EventType = "action"
	EventLifecycle EventType = "lifecycle"
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

	// att_ack: SHA-256 checksum of the agent's system prompt + tool configuration
	AgentChecksum string `json:"att_ack,omitempty"`

	// att_idp_iss: The verified identity provider issuer URL
	IDPIssuer *string `json:"att_idp_iss,omitempty"`

	// att_idp_sub: The verified identity provider subject (user ID)
	IDPSubject *string `json:"att_idp_sub,omitempty"`

	// att_hitl_req: The approval challenge/request ID
	HITLRequestID *string `json:"att_hitl_req,omitempty"`

	// att_hitl_uid: The verified IdP subject of the human who approved mid-chain
	HITLSubject *string `json:"att_hitl_uid,omitempty"`

	// att_hitl_iss: The verified IdP issuer of the human who approved mid-chain
	HITLIssuer *string `json:"att_hitl_iss,omitempty"`
}

// IssueParams carries the inputs needed to issue a root credential.
type IssueParams struct {
	AgentID       string   `json:"agent_id"`
	UserID        string   `json:"user_id"`
	Scope         []string `json:"scope"`
	Instruction   string   `json:"instruction"`
	TTLSeconds         int64    `json:"ttl_seconds,omitempty"`
	AgentChecksum      string   `json:"agent_checksum,omitempty"`
	IDToken            string   `json:"id_token,omitempty"`
	VerifiedIDPIssuer  *string  `json:"-"`
	VerifiedIDPSubject *string  `json:"-"`
}

// DelegateParams carries the inputs needed to delegate to a child agent.
type DelegateParams struct {
	ParentToken string   `json:"parent_token"`
	ChildAgent  string   `json:"child_agent"`
	ChildScope  []string `json:"child_scope"`
	TTLSeconds  int64    `json:"ttl_seconds,omitempty"`

	// HITL fields injected by the server post-verification during an approval.
	VerifiedHITLRequestID *string `json:"-"`
	VerifiedHITLSubject   *string `json:"-"`
	VerifiedHITLIssuer    *string `json:"-"`
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
	Scope      []string          `json:"scope"`
	Meta       map[string]string `json:"meta,omitempty"`
	IDPIssuer  *string           `json:"idp_issuer,omitempty"`
	IDPSubject *string           `json:"idp_subject,omitempty"`
	HITLRequestID *string        `json:"hitl_req,omitempty"`
	HITLSubject   *string        `json:"hitl_subject,omitempty"`
	HITLIssuer    *string        `json:"hitl_issuer,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}
