package action

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/internal/token"
	"github.com/attest-dev/attest/pkg/attest"
)

type memoryActionStore struct {
	cfgs     map[string]ActionPolicyConfig
	actions  map[string]*attest.ActionRequest
	receipts map[string]*attest.ExecutionReceipt
}

func newMemoryActionStore() *memoryActionStore {
	return &memoryActionStore{
		cfgs:     make(map[string]ActionPolicyConfig),
		actions:  make(map[string]*attest.ActionRequest),
		receipts: make(map[string]*attest.ExecutionReceipt),
	}
}

func (m *memoryActionStore) policyKey(orgID, actionType string) string {
	return orgID + ":" + actionType
}

func (m *memoryActionStore) GetPolicyConfig(_ context.Context, orgID, actionType string) (ActionPolicyConfig, error) {
	if cfg, ok := m.cfgs[m.policyKey(orgID, actionType)]; ok {
		return cfg, nil
	}
	return defaultRefundPolicyConfig(), nil
}

func (m *memoryActionStore) UpsertPolicyConfig(_ context.Context, orgID, actionType string, config ActionPolicyConfig) error {
	m.cfgs[m.policyKey(orgID, actionType)] = config
	return nil
}

func (m *memoryActionStore) CreateAction(_ context.Context, req *attest.ActionRequest) error {
	cp := *req
	cp.ActionPayload = cloneMap(req.ActionPayload)
	cp.DisplayPayload = cloneMap(req.DisplayPayload)
	m.actions[req.ID] = &cp
	return nil
}

func (m *memoryActionStore) MarkActionApproved(_ context.Context, orgID, id string, grantJTI string) error {
	req, ok := m.actions[id]
	if !ok || req.OrgID != orgID || req.Status != attest.ActionStatusPendingApproval {
		return ErrInvalidTransition
	}
	req.Status = attest.ActionStatusApproved
	req.GrantJTI = &grantJTI
	return nil
}

func (m *memoryActionStore) MarkActionDenied(_ context.Context, orgID, id string) error {
	req, ok := m.actions[id]
	if !ok || req.OrgID != orgID || req.Status != attest.ActionStatusPendingApproval {
		return ErrInvalidTransition
	}
	req.Status = attest.ActionStatusDenied
	return nil
}

func (m *memoryActionStore) MarkActionExecuted(_ context.Context, orgID, id string, status attest.ActionStatus) error {
	req, ok := m.actions[id]
	if !ok || req.OrgID != orgID || req.Status != attest.ActionStatusApproved {
		return ErrInvalidTransition
	}
	req.Status = status
	return nil
}

func (m *memoryActionStore) GetAction(_ context.Context, orgID, id string) (*attest.ActionRequest, error) {
	req, ok := m.actions[id]
	if !ok || req.OrgID != orgID {
		return nil, ErrNotFound
	}
	cp := *req
	cp.ActionPayload = cloneMap(req.ActionPayload)
	cp.DisplayPayload = cloneMap(req.DisplayPayload)
	return &cp, nil
}

func (m *memoryActionStore) ListActions(_ context.Context, orgID string, params ListParams) ([]attest.ActionRequest, error) {
	out := make([]attest.ActionRequest, 0, len(m.actions))
	for _, req := range m.actions {
		if req.OrgID != orgID {
			continue
		}
		if params.Status != "" && string(req.Status) != params.Status {
			continue
		}
		cp := *req
		cp.ActionPayload = cloneMap(req.ActionPayload)
		cp.DisplayPayload = cloneMap(req.DisplayPayload)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if params.Offset > 0 && params.Offset < len(out) {
		out = out[params.Offset:]
	} else if params.Offset >= len(out) {
		out = nil
	}
	if params.Limit > 0 && len(out) > params.Limit {
		out = out[:params.Limit]
	}
	return out, nil
}

func (m *memoryActionStore) CreateReceipt(_ context.Context, receipt *attest.ExecutionReceipt) error {
	cp := *receipt
	cp.ResponsePayload = cloneMap(receipt.ResponsePayload)
	cp.DisplayPayload = cloneMap(receipt.DisplayPayload)
	m.receipts[receipt.ActionRequestID] = &cp
	return nil
}

func (m *memoryActionStore) GetReceipt(_ context.Context, orgID, actionID string) (*attest.ExecutionReceipt, error) {
	receipt, ok := m.receipts[actionID]
	if !ok || receipt.OrgID != orgID {
		return nil, ErrNotFound
	}
	cp := *receipt
	cp.ResponsePayload = cloneMap(receipt.ResponsePayload)
	cp.DisplayPayload = cloneMap(receipt.DisplayPayload)
	return &cp, nil
}

func (m *memoryActionStore) LoadApproval(ctx context.Context, orgID string, id *string) (*attest.ActionApprovalState, error) {
	_ = ctx
	_ = orgID
	_ = id
	return nil, nil
}

func (m *memoryActionStore) HydrateAction(ctx context.Context, req *attest.ActionRequest, approvals approval.Store, revStore revocation.Revoker) error {
	if req == nil {
		return nil
	}
	if req.ApprovalID != nil {
		state, err := approvals.Get(ctx, req.OrgID, *req.ApprovalID)
		if err == nil && state != nil {
			req.Approval = &attest.ActionApprovalState{
				ID:         state.ID,
				Status:     string(state.Status),
				ApprovedBy: cloneStringPtr(state.ApprovedBy),
				CreatedAt:  state.CreatedAt,
				ResolvedAt: cloneTimePtr(state.ResolvedAt),
			}
		}
	}
	if req.GrantJTI != nil {
		cred, err := revStore.GetCredential(ctx, req.OrgID, *req.GrantJTI)
		if err == nil && cred != nil {
			req.Grant = &attest.ExecutionGrant{
				JTI:       cred.JTI,
				Scope:     append([]string(nil), cred.Scope...),
				ExpiresAt: cred.ExpiresAt,
			}
		}
	}
	if receipt, err := m.GetReceipt(ctx, req.OrgID, req.ID); err == nil {
		req.Receipt = receipt
	}
	return nil
}

func TestServiceCreateAutoApprovedAction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	o, _, _, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}

	store := newMemoryActionStore()
	revStore := revocation.NewMemoryStore()
	approvalStore := approval.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(store, token.NewIssuer("https://attest.test"), orgStore, revStore, auditLog, approvalStore)

	result, err := svc.Create(ctx, o, CreateActionParams{
		ActionType:   "refund",
		TargetSystem: "stripe",
		TargetObject: "order_123",
		ActionPayload: map[string]any{
			"amount_cents": 4799,
			"currency":     "USD",
			"reason":       "damaged_item",
		},
		AgentID:       "support-bot",
		SponsorUserID: "alice@acme.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if result.Action.Status != attest.ActionStatusApproved {
		t.Fatalf("Status = %q, want approved", result.Action.Status)
	}
	if result.Action.TaskID == "" {
		t.Fatal("TaskID is empty")
	}
	if result.Grant == nil || result.Action.Grant == nil {
		t.Fatal("expected execution grant on auto-approved action")
	}
	if _, err := revStore.GetCredential(ctx, o.ID, result.Grant.JTI); err != nil {
		t.Fatalf("GetCredential(grant) error = %v", err)
	}
}

func TestServiceApprovalAndExecutionFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	o, _, _, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}

	store := newMemoryActionStore()
	revStore := revocation.NewMemoryStore()
	approvalStore := approval.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(store, token.NewIssuer("https://attest.test"), orgStore, revStore, auditLog, approvalStore)

	result, err := svc.Create(ctx, o, CreateActionParams{
		ActionType:   "refund",
		TargetSystem: "stripe",
		TargetObject: "order_9100",
		ActionPayload: map[string]any{
			"amount_cents": 250000,
			"currency":     "USD",
			"reason":       "service_failure",
		},
		AgentID:       "support-bot",
		SponsorUserID: "alice@acme.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Action.Status != attest.ActionStatusPendingApproval {
		t.Fatalf("Status = %q, want pending_approval", result.Action.Status)
	}
	if result.Action.ApprovalID == nil {
		t.Fatal("ApprovalID is nil")
	}

	approved, err := svc.Approve(ctx, o, result.Action.ID, "approver-123", "issuer-1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.Status != attest.ActionStatusApproved {
		t.Fatalf("approved status = %q, want approved", approved.Status)
	}
	if approved.Grant == nil || approved.Grant.Token == "" {
		t.Fatal("expected grant token after approval")
	}

	receipt, err := svc.Execute(ctx, o, result.Action.ID, ExecuteParams{
		Outcome:         attest.ExecutionOutcomeSuccess,
		ResponsePayload: map[string]any{"status": "succeeded"},
		ProviderRef:     strPtr("re_123"),
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if receipt.Outcome != attest.ExecutionOutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", receipt.Outcome)
	}
	if receipt.SignedPacketHash == "" {
		t.Fatal("SignedPacketHash is empty")
	}

	got, err := svc.Get(ctx, o.ID, result.Action.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != attest.ActionStatusExecuted {
		t.Fatalf("stored status = %q, want executed", got.Status)
	}
	if got.Receipt == nil {
		t.Fatal("expected stored receipt after execution")
	}
	if got.Approval == nil || got.Approval.ApprovedBy == nil || *got.Approval.ApprovedBy != "approver-123" {
		t.Fatal("expected approval attribution on stored action")
	}
}

func strPtr(v string) *string {
	return &v
}

func setupServiceAndAutoApprove(t *testing.T) (*Service, *org.Org, *CreateResult, revocation.Revoker) {
	t.Helper()
	ctx := context.Background()
	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	o, _, _, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}
	store := newMemoryActionStore()
	revStore := revocation.NewMemoryStore()
	approvalStore := approval.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(store, token.NewIssuer("https://attest.test"), orgStore, revStore, auditLog, approvalStore)

	result, err := svc.Create(ctx, o, CreateActionParams{
		ActionType:   "refund",
		TargetSystem: "stripe",
		TargetObject: "order_small",
		ActionPayload: map[string]any{
			"amount_cents": 2000,
			"currency":     "USD",
			"reason":       "duplicate_charge",
		},
		AgentID:       "support-bot",
		SponsorUserID: "alice@acme.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Action.Status != attest.ActionStatusApproved {
		t.Fatalf("expected auto-approved, got %q", result.Action.Status)
	}
	return svc, o, result, revStore
}

func TestServiceDoubleExecutionRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, o, result, _ := setupServiceAndAutoApprove(t)

	_, err := svc.Execute(ctx, o, result.Action.ID, ExecuteParams{
		Outcome:         attest.ExecutionOutcomeSuccess,
		ResponsePayload: map[string]any{"status": "ok"},
	})
	if err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}

	_, err = svc.Execute(ctx, o, result.Action.ID, ExecuteParams{
		Outcome:         attest.ExecutionOutcomeSuccess,
		ResponsePayload: map[string]any{"status": "ok"},
	})
	if err == nil {
		t.Fatal("second Execute() should fail, got nil error")
	}
}

type expiredRevStore struct {
	revocation.Revoker
}

func (e *expiredRevStore) GetCredential(ctx context.Context, orgID, jti string) (*attest.CredentialRecord, error) {
	cred, err := e.Revoker.GetCredential(ctx, orgID, jti)
	if err != nil {
		return nil, err
	}
	cred.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
	return cred, nil
}

func TestServiceExpiredGrantRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	o, _, _, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}
	store := newMemoryActionStore()
	realRevStore := revocation.NewMemoryStore()
	approvalStore := approval.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(store, token.NewIssuer("https://attest.test"), orgStore, realRevStore, auditLog, approvalStore)

	result, err := svc.Create(ctx, o, CreateActionParams{
		ActionType:   "refund",
		TargetSystem: "stripe",
		TargetObject: "order_expired",
		ActionPayload: map[string]any{
			"amount_cents": 2000,
			"currency":     "USD",
			"reason":       "test",
		},
		AgentID:       "bot",
		SponsorUserID: "alice@acme.com",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Swap in the expired wrapper so Execute sees an expired credential
	svc.revStore = &expiredRevStore{Revoker: realRevStore}

	_, err = svc.Execute(ctx, o, result.Action.ID, ExecuteParams{
		Outcome: attest.ExecutionOutcomeSuccess,
	})
	if err == nil {
		t.Fatal("Execute() with expired grant should fail, got nil error")
	}
}

func TestServiceRevokedGrantRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, o, result, revStore := setupServiceAndAutoApprove(t)

	if err := revStore.Revoke(ctx, o.ID, result.Grant.JTI, "admin@acme.com"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	_, err := svc.Execute(ctx, o, result.Action.ID, ExecuteParams{
		Outcome: attest.ExecutionOutcomeSuccess,
	})
	if err == nil {
		t.Fatal("Execute() with revoked grant should fail, got nil error")
	}
}

func TestCreditHandlerPolicyVersion(t *testing.T) {
	t.Parallel()
	handler := &RefundHandler{actionType: "credit"}
	if handler.PolicyVersion() != "credit-v1" {
		t.Fatalf("PolicyVersion() = %q, want credit-v1", handler.PolicyVersion())
	}
	if handler.ActionFamily() != "finance" {
		t.Fatalf("ActionFamily() = %q, want finance", handler.ActionFamily())
	}
}

func TestServiceUpsertPolicyConfigValidatesThresholds(t *testing.T) {
	t.Parallel()

	svc := &Service{store: newMemoryActionStore()}
	err := svc.UpsertPolicyConfig(context.Background(), "org_1", "refund", ActionPolicyConfig{
		AutoApproveThresholdCents: 1000,
		ApprovalThresholdCents:    500,
	})
	if err == nil {
		t.Fatal("UpsertPolicyConfig() error = nil, want validation error")
	}
}

func TestCloneTimePtr(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	cloned := cloneTimePtr(&now)
	if cloned == nil || !cloned.Equal(now) {
		t.Fatal("cloneTimePtr() did not preserve time value")
	}
}

func TestServiceListFiltersAndPagination(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	o, _, _, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateOrg() error = %v", err)
	}

	store := newMemoryActionStore()
	revStore := revocation.NewMemoryStore()
	approvalStore := approval.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(store, token.NewIssuer("https://attest.test"), orgStore, revStore, auditLog, approvalStore)

	create := func(amount int64) {
		t.Helper()
		if _, err := svc.Create(ctx, o, CreateActionParams{
			ActionType:   "refund",
			TargetSystem: "stripe",
			TargetObject: "order",
			ActionPayload: map[string]any{
				"amount_cents": amount,
				"currency":     "USD",
				"reason":       "test",
			},
			AgentID:       "support-bot",
			SponsorUserID: "alice@acme.com",
		}); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	create(1000)   // approved
	create(250000) // pending_approval
	create(300000) // pending_approval

	filtered, err := svc.List(ctx, o.ID, ListParams{Status: string(attest.ActionStatusPendingApproval), Limit: 10})
	if err != nil {
		t.Fatalf("List(filtered) error = %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2", len(filtered))
	}
	for _, item := range filtered {
		if item.Status != attest.ActionStatusPendingApproval {
			t.Fatalf("filtered item status = %q, want pending_approval", item.Status)
		}
	}

	paged, err := svc.List(ctx, o.ID, ListParams{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("List(paged) error = %v", err)
	}
	if len(paged) != 1 {
		t.Fatalf("len(paged) = %d, want 1", len(paged))
	}
}
