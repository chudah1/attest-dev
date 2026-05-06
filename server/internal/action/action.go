package action

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/internal/token"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/google/uuid"
)

var (
	ErrNotFound          = errors.New("action not found")
	ErrInvalidTransition = errors.New("invalid action status transition")
	ErrInvalidGrant      = errors.New("invalid execution grant")
)

type ActionPolicyConfig struct {
	AutoApproveThresholdCents int64 `json:"auto_approve_threshold_cents"`
	ApprovalThresholdCents    int64 `json:"approval_threshold_cents"`
}

func defaultRefundPolicyConfig() ActionPolicyConfig {
	return ActionPolicyConfig{
		AutoApproveThresholdCents: 5000,
		ApprovalThresholdCents:    500000,
	}
}

type PolicyDecision struct {
	Status        attest.ActionStatus
	RiskLevel     attest.RiskLevel
	PolicyVersion string
	PolicyReason  string
}

type NormalizedAction struct {
	ActionFamily   string
	ActionType     string
	TargetSystem   string
	TargetObject   string
	ActionPayload  map[string]any
	DisplayPayload map[string]any
}

type Handler interface {
	ActionType() string
	ActionFamily() string
	PolicyVersion() string
	Validate(targetSystem, targetObject string, actionPayload map[string]any, displayPayload map[string]any) (*NormalizedAction, error)
	EvaluatePolicy(config ActionPolicyConfig, normalized *NormalizedAction) PolicyDecision
	GrantScope(normalized *NormalizedAction) []string
}

type ListParams struct {
	Status string `json:"status,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

type ExecuteParams struct {
	Outcome         attest.ExecutionOutcome `json:"outcome"`
	ProviderRef     *string                 `json:"provider_ref,omitempty"`
	ResponsePayload map[string]any          `json:"response_payload,omitempty"`
}

type CreateActionParams struct {
	ActionType     string         `json:"action_type"`
	TargetSystem   string         `json:"target_system"`
	TargetObject   string         `json:"target_object"`
	ActionPayload  map[string]any `json:"action_payload"`
	DisplayPayload map[string]any `json:"display_payload,omitempty"`
	AgentID        string         `json:"agent_id"`
	SponsorUserID  string         `json:"sponsor_user_id"`
	TaskID         string         `json:"att_tid,omitempty"`
}

type Store interface {
	GetPolicyConfig(ctx context.Context, orgID, actionType string) (ActionPolicyConfig, error)
	UpsertPolicyConfig(ctx context.Context, orgID, actionType string, config ActionPolicyConfig) error
	CreateAction(ctx context.Context, req *attest.ActionRequest) error
	MarkActionApproved(ctx context.Context, orgID, id string, grantJTI string) error
	MarkActionDenied(ctx context.Context, orgID, id string) error
	MarkActionExecuted(ctx context.Context, orgID, id string, status attest.ActionStatus) error
	GetAction(ctx context.Context, orgID, id string) (*attest.ActionRequest, error)
	ListActions(ctx context.Context, orgID string, params ListParams) ([]attest.ActionRequest, error)
	CreateReceipt(ctx context.Context, receipt *attest.ExecutionReceipt) error
	GetReceipt(ctx context.Context, orgID, actionID string) (*attest.ExecutionReceipt, error)
	LoadApproval(ctx context.Context, orgID string, id *string) (*attest.ActionApprovalState, error)
	HydrateAction(ctx context.Context, req *attest.ActionRequest, approvals approval.Store, revStore revocation.Revoker) error
}

type Service struct {
	store     Store
	issuer    *token.Issuer
	orgStore  org.Store
	revStore  revocation.Revoker
	auditLog  audit.Logger
	approvals approval.Store
	handlers  map[string]Handler
}

func NewService(store Store, issuer *token.Issuer, orgStore org.Store, revStore revocation.Revoker, auditLog audit.Logger, approvals approval.Store) *Service {
	return &Service{
		store:     store,
		issuer:    issuer,
		orgStore:  orgStore,
		revStore:  revStore,
		auditLog:  auditLog,
		approvals: approvals,
		handlers: map[string]Handler{
			"refund": &RefundHandler{actionType: "refund"},
			"credit": &RefundHandler{actionType: "credit"},
		},
	}
}

func actionID(prefix string) string {
	return prefix + "_" + uuid.NewString()
}

func canonicalHash(v any) (string, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	h := attestHash(b)
	return h, nil
}

func canonicalJSON(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		return marshalCanonicalMap(t)
	case []any:
		parts := make([][]byte, 0, len(t))
		for _, item := range t {
			b, err := canonicalJSON(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, b)
		}
		return []byte("[" + joinJSON(parts) + "]"), nil
	case string, bool, nil, float64, float32, int, int32, int64, uint, uint64, uint32:
		return json.Marshal(t)
	default:
		return json.Marshal(t)
	}
}

func marshalCanonicalMap(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		keyJSON, _ := json.Marshal(key)
		sb.Write(keyJSON)
		sb.WriteByte(':')
		valueJSON, err := canonicalJSON(m[key])
		if err != nil {
			return nil, err
		}
		sb.Write(valueJSON)
	}
	sb.WriteByte('}')
	return []byte(sb.String()), nil
}

func joinJSON(parts [][]byte) string {
	var sb strings.Builder
	for i, part := range parts {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.Write(part)
	}
	return sb.String()
}

func attestHash(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
