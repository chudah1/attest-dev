package action

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
)

type CreateResult struct {
	Action *attest.ActionRequest
	Grant  *attest.ExecutionGrant
}

func (s *Service) UpsertPolicyConfig(ctx context.Context, orgID, actionType string, config ActionPolicyConfig) error {
	if actionType == "" {
		return fmt.Errorf("action_type is required")
	}
	if config.AutoApproveThresholdCents < 0 {
		return fmt.Errorf("auto_approve_threshold_cents must be non-negative")
	}
	if config.ApprovalThresholdCents < config.AutoApproveThresholdCents {
		return fmt.Errorf("approval_threshold_cents must be greater than or equal to auto_approve_threshold_cents")
	}
	return s.store.UpsertPolicyConfig(ctx, orgID, actionType, config)
}

func (s *Service) PolicyConfig(ctx context.Context, orgID, actionType string) (ActionPolicyConfig, error) {
	if actionType == "" {
		return ActionPolicyConfig{}, fmt.Errorf("action_type is required")
	}
	return s.store.GetPolicyConfig(ctx, orgID, actionType)
}

func (s *Service) Create(ctx context.Context, o *org.Org, params CreateActionParams) (*CreateResult, error) {
	req := &attest.ActionRequest{
		ID:             actionID("act"),
		OrgID:          o.ID,
		TaskID:         params.TaskID,
		ActionType:     params.ActionType,
		TargetSystem:   params.TargetSystem,
		TargetObject:   params.TargetObject,
		ActionPayload:  cloneMap(params.ActionPayload),
		DisplayPayload: cloneMap(params.DisplayPayload),
		AgentID:        params.AgentID,
		SponsorUserID:  params.SponsorUserID,
		Status:         attest.ActionStatusPendingPolicy,
		CreatedAt:      time.Now().UTC(),
	}

	handler, ok := s.handlers[params.ActionType]
	if !ok {
		req.Status = attest.ActionStatusDenied
		req.ActionFamily = "unknown"
		req.PolicyVersion = "system"
		req.PolicyReason = "unsupported_action_type"
		if err := s.store.CreateAction(ctx, req); err != nil {
			return nil, err
		}
		_ = s.logActionEvent(ctx, o.ID, req, "action_requested", map[string]string{"decision": string(req.Status), "reason": req.PolicyReason})
		return &CreateResult{Action: req}, nil
	}

	normalized, err := handler.Validate(params.TargetSystem, params.TargetObject, params.ActionPayload, params.DisplayPayload)
	if err != nil {
		req.Status = attest.ActionStatusDenied
		req.ActionFamily = handler.ActionFamily()
		req.PolicyVersion = handler.PolicyVersion()
		req.PolicyReason = "invalid_payload"
		if err := s.store.CreateAction(ctx, req); err != nil {
			return nil, err
		}
		_ = s.logActionEvent(ctx, o.ID, req, "action_requested", map[string]string{"decision": string(req.Status), "reason": req.PolicyReason})
		return &CreateResult{Action: req}, nil
	}

	req.ActionFamily = normalized.ActionFamily
	req.ActionPayload = normalized.ActionPayload
	req.DisplayPayload = normalized.DisplayPayload
	hash, err := canonicalHash(req.ActionPayload)
	if err != nil {
		return nil, err
	}
	req.PayloadHash = hash
	if req.TaskID == "" {
		rootToken, rootClaims, err := s.issueSyntheticRoot(ctx, o.ID, params.AgentID, params.SponsorUserID, handler.GrantScope(normalized), syntheticInstruction(req))
		if err != nil {
			return nil, err
		}
		req.TaskID = rootClaims.TaskID
		_ = rootToken
	}

	cfg, err := s.store.GetPolicyConfig(ctx, o.ID, params.ActionType)
	if err != nil {
		return nil, err
	}
	decision := handler.EvaluatePolicy(cfg, normalized)
	req.Status = decision.Status
	req.RiskLevel = decision.RiskLevel
	req.PolicyVersion = decision.PolicyVersion
	req.PolicyReason = decision.PolicyReason

	var grant *attest.ExecutionGrant
	var approvalID *string
	var grantJTI *string
	parentToken, parentClaims, err := s.prepareGrantParent(ctx, o.ID, req, handler.GrantScope(normalized), syntheticInstruction(req))
	if err != nil {
		return nil, err
	}

	switch decision.Status {
	case attest.ActionStatusApproved:
		grant, err = s.issueGrant(ctx, o.ID, parentClaims, handler.GrantScope(normalized), params.AgentID)
		if err != nil {
			return nil, err
		}
		grantJTI = &grant.JTI
	case attest.ActionStatusPendingApproval:
		id := actionID("hitl")
		approvalID = &id
		intent := fmt.Sprintf("%s %s on %s", strings.ToUpper(req.ActionType), params.TargetObject, params.TargetSystem)
		if err := s.approvals.RequestApproval(ctx, approval.ApprovalRequest{
			ID:             id,
			OrgID:          o.ID,
			AgentID:        params.AgentID,
			TaskID:         req.TaskID,
			ParentToken:    parentToken,
			Intent:         intent,
			RequestedScope: handler.GrantScope(normalized),
		}); err != nil {
			return nil, err
		}
	}

	req.ApprovalID = approvalID
	req.GrantJTI = grantJTI
	req.Grant = grant
	if approvalID != nil {
		req.Approval = &attest.ActionApprovalState{ID: *approvalID, Status: string(approval.StatusPending), CreatedAt: time.Now().UTC()}
	}
	if err := s.store.CreateAction(ctx, req); err != nil {
		return nil, err
	}
	_ = s.logActionEvent(ctx, o.ID, req, "action_requested", map[string]string{
		"decision":   string(req.Status),
		"risk_level": string(req.RiskLevel),
		"reason":     req.PolicyReason,
	})
	return &CreateResult{Action: req, Grant: grant}, nil
}

func (s *Service) Get(ctx context.Context, orgID, id string) (*attest.ActionRequest, error) {
	req, err := s.store.GetAction(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.HydrateAction(ctx, req, s.approvals, s.revStore); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Service) List(ctx context.Context, orgID string, params ListParams) ([]attest.ActionRequest, error) {
	if params.Limit <= 0 || params.Limit > 100 {
		params.Limit = 50
	}
	items, err := s.store.ListActions(ctx, orgID, params)
	if err != nil {
		return nil, err
	}
	for i := range items {
		_ = s.store.HydrateAction(ctx, &items[i], s.approvals, s.revStore)
	}
	return items, nil
}

func (s *Service) Approve(ctx context.Context, o *org.Org, id string, approvedBy, approvedIssuer string) (*attest.ActionRequest, error) {
	req, err := s.store.GetAction(ctx, o.ID, id)
	if err != nil {
		return nil, err
	}
	if req.Status != attest.ActionStatusPendingApproval || req.ApprovalID == nil {
		return nil, ErrInvalidTransition
	}

	pending, err := s.approvals.GetPending(ctx, o.ID, *req.ApprovalID)
	if err != nil {
		return nil, err
	}
	if err := s.approvals.Resolve(ctx, o.ID, *req.ApprovalID, approval.StatusApproved, approvedBy); err != nil {
		return nil, err
	}

	parentClaims, err := s.verifyStoredParent(ctx, o.ID, pending.ParentToken)
	if err != nil {
		return nil, err
	}
	orgKey, err := s.orgStore.GetSigningKey(ctx, o.ID)
	if err != nil {
		return nil, err
	}
	childToken, childClaims, err := s.issuer.DelegateVerified(orgKey.PrivateKey, orgKey.KeyID, parentClaims, attest.DelegateParams{
		ParentToken:           pending.ParentToken,
		ChildAgent:            req.AgentID,
		ChildScope:            []string{req.ActionType + ":execute"},
		TTLSeconds:            60,
		VerifiedHITLRequestID: req.ApprovalID,
		VerifiedHITLSubject:   &approvedBy,
		VerifiedHITLIssuer:    &approvedIssuer,
	})
	if err != nil {
		return nil, err
	}
	if err := s.revStore.TrackCredential(ctx, o.ID, childClaims); err != nil {
		return nil, err
	}
	if err := s.store.MarkActionApproved(ctx, o.ID, id, childClaims.ID); err != nil {
		return nil, err
	}
	req.Status = attest.ActionStatusApproved
	req.GrantJTI = &childClaims.ID
	req.Grant = &attest.ExecutionGrant{
		JTI:       childClaims.ID,
		Token:     childToken,
		Scope:     append([]string(nil), childClaims.Scope...),
		ExpiresAt: childClaims.ExpiresAt.Time,
	}
	now := time.Now().UTC()
	req.Approval = &attest.ActionApprovalState{
		ID:         *req.ApprovalID,
		Status:     string(approval.StatusApproved),
		ApprovedBy: &approvedBy,
		CreatedAt:  pending.CreatedAt,
		ResolvedAt: &now,
	}
	_ = s.logActionEvent(ctx, o.ID, req, "action_approved", map[string]string{"approval_id": *req.ApprovalID, "approved_by": approvedBy})
	return req, nil
}

func (s *Service) Deny(ctx context.Context, o *org.Org, id string) (*attest.ActionRequest, error) {
	req, err := s.store.GetAction(ctx, o.ID, id)
	if err != nil {
		return nil, err
	}
	if req.Status != attest.ActionStatusPendingApproval || req.ApprovalID == nil {
		return nil, ErrInvalidTransition
	}
	if err := s.approvals.Resolve(ctx, o.ID, *req.ApprovalID, approval.StatusRejected, ""); err != nil {
		return nil, err
	}
	if err := s.store.MarkActionDenied(ctx, o.ID, id); err != nil {
		return nil, err
	}
	req.Status = attest.ActionStatusDenied
	_ = s.logActionEvent(ctx, o.ID, req, "action_denied", map[string]string{"approval_id": *req.ApprovalID})
	return req, nil
}

func (s *Service) Execute(ctx context.Context, o *org.Org, id string, params ExecuteParams) (*attest.ExecutionReceipt, error) {
	req, err := s.Get(ctx, o.ID, id)
	if err != nil {
		return nil, err
	}
	if req.Status != attest.ActionStatusApproved || req.GrantJTI == nil || req.Grant == nil {
		return nil, ErrInvalidTransition
	}
	cred, err := s.revStore.GetCredential(ctx, o.ID, *req.GrantJTI)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if cred.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrInvalidGrant
	}
	if revoked, _ := s.revStore.IsRevoked(ctx, o.ID, cred.JTI); revoked {
		return nil, ErrInvalidGrant
	}
	hash, err := canonicalHash(req.ActionPayload)
	if err != nil {
		return nil, err
	}
	receipt := &attest.ExecutionReceipt{
		ID:              actionID("rcpt"),
		OrgID:           o.ID,
		ActionRequestID: req.ID,
		TaskID:          req.TaskID,
		ActionFamily:    req.ActionFamily,
		ActionType:      req.ActionType,
		TargetSystem:    req.TargetSystem,
		TargetObject:    req.TargetObject,
		SponsorUserID:   req.SponsorUserID,
		AgentID:         req.AgentID,
		GrantJTI:        cred.JTI,
		Outcome:         params.Outcome,
		ProviderRef:     params.ProviderRef,
		ResponsePayload: cloneMap(params.ResponsePayload),
		PayloadHash:     hash,
		PolicyVersion:   req.PolicyVersion,
		PolicyReason:    req.PolicyReason,
		ExecutedAt:      time.Now().UTC(),
		ApprovedBy:      approvalActor(req.Approval),
		DisplayPayload:  cloneMap(req.DisplayPayload),
		Approval:        req.Approval,
	}
	if err := s.signReceipt(ctx, o.ID, receipt); err != nil {
		return nil, err
	}
	if err := s.store.CreateReceipt(ctx, receipt); err != nil {
		return nil, err
	}
	nextStatus := attest.ActionStatusExecuted
	if params.Outcome == attest.ExecutionOutcomeFailure {
		nextStatus = attest.ActionStatusFailed
	}
	if err := s.store.MarkActionExecuted(ctx, o.ID, id, nextStatus); err != nil {
		return nil, err
	}
	req.Status = nextStatus
	_ = s.logActionEvent(ctx, o.ID, req, "action_executed", map[string]string{"outcome": string(params.Outcome), "receipt_id": receipt.ID})
	return receipt, nil
}

func (s *Service) Receipt(ctx context.Context, orgID, id string) (*attest.ExecutionReceipt, error) {
	req, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if req.Receipt == nil {
		return nil, ErrNotFound
	}
	req.Receipt.TaskID = req.TaskID
	req.Receipt.ActionFamily = req.ActionFamily
	req.Receipt.ActionType = req.ActionType
	req.Receipt.TargetSystem = req.TargetSystem
	req.Receipt.TargetObject = req.TargetObject
	req.Receipt.SponsorUserID = req.SponsorUserID
	req.Receipt.AgentID = req.AgentID
	req.Receipt.PolicyVersion = req.PolicyVersion
	req.Receipt.PolicyReason = req.PolicyReason
	req.Receipt.DisplayPayload = cloneMap(req.DisplayPayload)
	req.Receipt.Approval = req.Approval
	return req.Receipt, nil
}

func (s *Service) issueSyntheticRoot(ctx context.Context, orgID, agentID, sponsorUserID string, scope []string, instruction string) (string, *attest.Claims, error) {
	orgKey, err := s.orgStore.GetSigningKey(ctx, orgID)
	if err != nil {
		return "", nil, err
	}
	tokenString, claims, err := s.issuer.Issue(orgKey.PrivateKey, orgKey.KeyID, attest.IssueParams{
		AgentID:     agentID,
		UserID:      sponsorUserID,
		Scope:       scope,
		Instruction: instruction,
		TTLSeconds:  300,
	})
	if err != nil {
		return "", nil, err
	}
	if err := s.revStore.TrackCredential(ctx, orgID, claims); err != nil {
		return "", nil, err
	}
	return tokenString, claims, nil
}

func (s *Service) prepareGrantParent(ctx context.Context, orgID string, req *attest.ActionRequest, desiredScope []string, instruction string) (string, *attest.Claims, error) {
	if req.TaskID == "" {
		return s.issueSyntheticRoot(ctx, orgID, req.AgentID, req.SponsorUserID, desiredScope, instruction)
	}
	creds, err := s.revStore.ListTaskCredentials(ctx, orgID, req.TaskID)
	if err != nil {
		return "", nil, err
	}
	var chosen *attest.CredentialRecord
	for i := len(creds) - 1; i >= 0; i-- {
		cred := creds[i]
		if cred.UserID == req.SponsorUserID && attest.IsSubset(cred.Scope, desiredScope) {
			if chosen == nil || cred.AgentID == req.AgentID {
				copyCred := cred
				chosen = &copyCred
				if cred.AgentID == req.AgentID {
					break
				}
			}
		}
	}
	if chosen == nil {
		return s.issueSyntheticRoot(ctx, orgID, req.AgentID, req.SponsorUserID, desiredScope, instruction)
	}
	orgKey, err := s.orgStore.GetSigningKey(ctx, orgID)
	if err != nil {
		return "", nil, err
	}
	claims := credentialRecordToClaims(chosen)
	tokenString, err := s.issuer.SignClaims(orgKey.PrivateKey, orgKey.KeyID, claims)
	if err != nil {
		return "", nil, err
	}
	return tokenString, claims, nil
}

func (s *Service) issueGrant(ctx context.Context, orgID string, parentClaims *attest.Claims, scope []string, agentID string) (*attest.ExecutionGrant, error) {
	orgKey, err := s.orgStore.GetSigningKey(ctx, orgID)
	if err != nil {
		return nil, err
	}
	tokenString, claims, err := s.issuer.DelegateVerified(orgKey.PrivateKey, orgKey.KeyID, parentClaims, attest.DelegateParams{
		ChildAgent: agentID,
		ChildScope: scope,
		TTLSeconds: 60,
	})
	if err != nil {
		return nil, err
	}
	if err := s.revStore.TrackCredential(ctx, orgID, claims); err != nil {
		return nil, err
	}
	return &attest.ExecutionGrant{
		JTI:       claims.ID,
		Token:     tokenString,
		Scope:     append([]string(nil), claims.Scope...),
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

func credentialRecordToClaims(cred *attest.CredentialRecord) *attest.Claims {
	return &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent:" + cred.AgentID,
			IssuedAt:  jwt.NewNumericDate(cred.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(cred.ExpiresAt),
			ID:        cred.JTI,
		},
		TaskID:        cred.TaskID,
		ParentID:      cred.ParentID,
		Depth:         cred.Depth,
		Scope:         append([]string(nil), cred.Scope...),
		IntentHash:    cred.IntentHash,
		Chain:         append([]string(nil), cred.Chain...),
		UserID:        cred.UserID,
		AgentChecksum: cred.AgentChecksum,
		IDPIssuer:     cloneStringPtr(cred.IDPIssuer),
		IDPSubject:    cloneStringPtr(cred.IDPSubject),
		HITLRequestID: cloneStringPtr(cred.HITLRequestID),
		HITLSubject:   cloneStringPtr(cred.HITLSubject),
		HITLIssuer:    cloneStringPtr(cred.HITLIssuer),
	}
}

func syntheticInstruction(req *attest.ActionRequest) string {
	return fmt.Sprintf("Execute %s on %s in %s for %s", req.ActionType, req.TargetObject, req.TargetSystem, req.SponsorUserID)
}

func (s *Service) verifyStoredParent(ctx context.Context, orgID, tokenString string) (*attest.Claims, error) {
	orgKeys, err := s.orgStore.ListSigningKeys(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, key := range orgKeys {
		result, err := s.issuer.Verify(tokenString, &key.PrivateKey.PublicKey)
		if err == nil && result != nil && result.Valid {
			return result.Claims, nil
		}
	}
	return nil, ErrInvalidGrant
}

func (s *Service) signReceipt(ctx context.Context, orgID string, receipt *attest.ExecutionReceipt) error {
	orgKey, err := s.orgStore.GetSigningKey(ctx, orgID)
	if err != nil {
		return err
	}
	packet := map[string]any{
		"receipt_id":        receipt.ID,
		"action_request_id": receipt.ActionRequestID,
		"grant_jti":         receipt.GrantJTI,
		"outcome":           receipt.Outcome,
		"provider_ref":      receipt.ProviderRef,
		"payload_hash":      receipt.PayloadHash,
		"executed_at":       receipt.ExecutedAt.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalJSON(packet)
	if err != nil {
		return err
	}
	hash := crypto.SHA256.New()
	_, _ = hash.Write(canonical)
	digest := hash.Sum(nil)
	receipt.SignedPacketHash = fmt.Sprintf("%x", digest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, orgKey.PrivateKey, crypto.SHA256, digest)
	if err != nil {
		return fmt.Errorf("sign receipt: %w", err)
	}
	receipt.SignatureAlgorithm = "RS256"
	receipt.SignatureKID = orgKey.KeyID
	receipt.PacketSignature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

func (s *Service) logActionEvent(ctx context.Context, orgID string, req *attest.ActionRequest, eventType string, meta map[string]string) error {
	jti := req.ID
	if req.GrantJTI != nil && *req.GrantJTI != "" {
		jti = *req.GrantJTI
	}
	return s.auditLog.Append(ctx, orgID, attest.AuditEvent{
		EventType: attest.EventType(eventType),
		JTI:       jti,
		TaskID:    req.TaskID,
		UserID:    req.SponsorUserID,
		AgentID:   req.AgentID,
		Scope:     nil,
		Meta: mergeMeta(meta, map[string]string{
			"action_request_id": req.ID,
			"action_type":       req.ActionType,
			"action_family":     req.ActionFamily,
			"target_system":     req.TargetSystem,
			"target_object":     req.TargetObject,
		}),
	})
}

func mergeMeta(parts ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, part := range parts {
		for k, v := range part {
			if v != "" {
				out[k] = v
			}
		}
	}
	return out
}

func normalizedFamily(normalized *NormalizedAction, handler Handler) string {
	if normalized != nil && normalized.ActionFamily != "" {
		return normalized.ActionFamily
	}
	if handler != nil {
		return handler.ActionFamily()
	}
	return ""
}

func approvalActor(state *attest.ActionApprovalState) *string {
	if state == nil {
		return nil
	}
	return cloneStringPtr(state.ApprovedBy)
}

func timePtr(v time.Time) *time.Time {
	return &v
}
