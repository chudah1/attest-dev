package attest

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	MaxDelegationDepth = 10
	DefaultTTLSeconds  = 3600
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
	AgentID            string   `json:"agent_id"`
	UserID             string   `json:"user_id"`
	Scope              []string `json:"scope"`
	Instruction        string   `json:"instruction"`
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
	ID            int64             `json:"id,omitempty"`
	PrevHash      string            `json:"prev_hash"`
	EntryHash     string            `json:"entry_hash"`
	EventType     EventType         `json:"event_type"`
	JTI           string            `json:"jti"`
	OrgID         string            `json:"org_id"`
	TaskID        string            `json:"att_tid"`
	UserID        string            `json:"att_uid"`
	AgentID       string            `json:"agent_id"`
	Scope         []string          `json:"scope"`
	Meta          map[string]string `json:"meta,omitempty"`
	IDPIssuer     *string           `json:"idp_issuer,omitempty"`
	IDPSubject    *string           `json:"idp_subject,omitempty"`
	HITLRequestID *string           `json:"hitl_req,omitempty"`
	HITLSubject   *string           `json:"hitl_subject,omitempty"`
	HITLIssuer    *string           `json:"hitl_issuer,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

// CredentialRecord is the persisted view of a credential used for
// evidence/export flows and cascade revocation introspection.
type CredentialRecord struct {
	JTI           string    `json:"jti"`
	OrgID         string    `json:"org_id,omitempty"`
	TaskID        string    `json:"att_tid"`
	ParentID      string    `json:"att_pid,omitempty"`
	UserID        string    `json:"att_uid"`
	AgentID       string    `json:"agent_id"`
	Depth         int       `json:"att_depth"`
	Scope         []string  `json:"att_scope"`
	Chain         []string  `json:"att_chain"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	IntentHash    string    `json:"att_intent,omitempty"`
	AgentChecksum string    `json:"att_ack,omitempty"`
	IDPIssuer     *string   `json:"att_idp_iss,omitempty"`
	IDPSubject    *string   `json:"att_idp_sub,omitempty"`
	HITLRequestID *string   `json:"att_hitl_req,omitempty"`
	HITLSubject   *string   `json:"att_hitl_uid,omitempty"`
	HITLIssuer    *string   `json:"att_hitl_iss,omitempty"`
}

type EvidencePacket struct {
	PacketType    string               `json:"packet_type"`
	SchemaVersion string               `json:"schema_version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Org           EvidenceOrg          `json:"org"`
	Task          EvidenceTask         `json:"task"`
	Identity      EvidenceIdentity     `json:"identity"`
	Credentials   []EvidenceCredential `json:"credentials"`
	Events        []AuditEvent         `json:"events"`
	Integrity     EvidenceIntegrity    `json:"integrity"`
	Summary       EvidenceSummary      `json:"summary"`
}

type EvidenceOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type EvidenceTask struct {
	TaskID          string `json:"att_tid"`
	RootJTI         string `json:"root_jti"`
	RootAgentID     string `json:"root_agent_id"`
	UserID          string `json:"att_uid"`
	InstructionHash string `json:"instruction_hash,omitempty"`
	DepthMax        int    `json:"depth_max"`
	CredentialCount int    `json:"credential_count"`
	EventCount      int    `json:"event_count"`
	Revoked         bool   `json:"revoked"`
}

type EvidenceIdentity struct {
	UserID     string            `json:"user_id"`
	IDPIssuer  *string           `json:"idp_issuer,omitempty"`
	IDPSubject *string           `json:"idp_subject,omitempty"`
	Approval   *EvidenceApproval `json:"approval,omitempty"`
}

type EvidenceApproval struct {
	Present   bool    `json:"present"`
	RequestID *string `json:"request_id,omitempty"`
	Issuer    *string `json:"issuer,omitempty"`
	Subject   *string `json:"subject,omitempty"`
}

type EvidenceCredential struct {
	JTI           string    `json:"jti"`
	ParentJTI     string    `json:"parent_jti,omitempty"`
	AgentID       string    `json:"agent_id"`
	Scope         []string  `json:"scope"`
	Depth         int       `json:"depth"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Chain         []string  `json:"chain"`
	IntentHash    string    `json:"intent_hash,omitempty"`
	AgentChecksum string    `json:"agent_checksum,omitempty"`
	IDPIssuer     *string   `json:"idp_issuer,omitempty"`
	IDPSubject    *string   `json:"idp_subject,omitempty"`
	HITLRequestID *string   `json:"hitl_request_id,omitempty"`
	HITLSubject   *string   `json:"hitl_subject,omitempty"`
	HITLIssuer    *string   `json:"hitl_issuer,omitempty"`
}

type EvidenceIntegrity struct {
	AuditChainValid bool     `json:"audit_chain_valid"`
	HashAlgorithm   string   `json:"hash_algorithm"`
	PacketHash      string   `json:"packet_hash"`
	Notes           []string `json:"notes"`
}

type EvidenceSummary struct {
	Result          string `json:"result"`
	ScopeViolations int    `json:"scope_violations"`
	Approvals       int    `json:"approvals"`
	Revocations     int    `json:"revocations"`
}
