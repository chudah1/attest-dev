package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	db *pgxpool.Pool
}

func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) GetPolicyConfig(ctx context.Context, orgID, actionType string) (ActionPolicyConfig, error) {
	row := s.db.QueryRow(ctx, `SELECT config FROM org_action_policies WHERE org_id = $1 AND action_type = $2`, orgID, actionType)
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return defaultRefundPolicyConfig(), nil
		}
		return ActionPolicyConfig{}, fmt.Errorf("get policy config: %w", err)
	}
	cfg := defaultRefundPolicyConfig()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ActionPolicyConfig{}, fmt.Errorf("decode policy config: %w", err)
	}
	return cfg, nil
}

func (s *PostgresStore) UpsertPolicyConfig(ctx context.Context, orgID, actionType string, config ActionPolicyConfig) error {
	raw, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal policy config: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO org_action_policies (org_id, action_type, config, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (org_id, action_type)
		DO UPDATE SET config = EXCLUDED.config, updated_at = EXCLUDED.updated_at
	`, orgID, actionType, raw)
	if err != nil {
		return fmt.Errorf("upsert policy config: %w", err)
	}
	return nil
}

func (s *PostgresStore) CreateAction(ctx context.Context, req *attest.ActionRequest) error {
	actionJSON, err := json.Marshal(req.ActionPayload)
	if err != nil {
		return fmt.Errorf("marshal action payload: %w", err)
	}
	displayJSON, err := json.Marshal(req.DisplayPayload)
	if err != nil {
		return fmt.Errorf("marshal display payload: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO action_requests (
			id, org_id, att_tid, action_family, action_type, target_system, target_object,
			action_payload, display_payload, payload_hash, agent_id, sponsor_user_id,
			status, risk_level, policy_version, policy_reason, approval_id, grant_jti, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19
		)
	`, req.ID, req.OrgID, req.TaskID, req.ActionFamily, req.ActionType, req.TargetSystem, req.TargetObject,
		actionJSON, displayJSON, req.PayloadHash, req.AgentID, req.SponsorUserID,
		req.Status, string(req.RiskLevel), req.PolicyVersion, req.PolicyReason, req.ApprovalID, req.GrantJTI, req.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert action request: %w", err)
	}
	return nil
}

func (s *PostgresStore) MarkActionApproved(ctx context.Context, orgID, id string, grantJTI string) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE action_requests
		SET status = $1, grant_jti = $2
		WHERE id = $3 AND org_id = $4 AND status = $5
	`, attest.ActionStatusApproved, grantJTI, id, orgID, attest.ActionStatusPendingApproval)
	if err != nil {
		return fmt.Errorf("mark action approved: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *PostgresStore) MarkActionDenied(ctx context.Context, orgID, id string) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE action_requests
		SET status = $1
		WHERE id = $2 AND org_id = $3 AND status = $4
	`, attest.ActionStatusDenied, id, orgID, attest.ActionStatusPendingApproval)
	if err != nil {
		return fmt.Errorf("mark action denied: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *PostgresStore) MarkActionExecuted(ctx context.Context, orgID, id string, status attest.ActionStatus) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE action_requests
		SET status = $1
		WHERE id = $2 AND org_id = $3 AND status = $4
	`, status, id, orgID, attest.ActionStatusApproved)
	if err != nil {
		return fmt.Errorf("mark action executed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *PostgresStore) GetAction(ctx context.Context, orgID, id string) (*attest.ActionRequest, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, org_id, att_tid, action_family, action_type, target_system, target_object,
		       action_payload, display_payload, payload_hash, agent_id, sponsor_user_id,
		       status, COALESCE(risk_level, ''), COALESCE(policy_version, ''), COALESCE(policy_reason, ''),
		       approval_id, grant_jti, created_at
		FROM action_requests
		WHERE id = $1 AND org_id = $2
	`, id, orgID)
	var req attest.ActionRequest
	var actionJSON, displayJSON []byte
	var risk, status string
	if err := row.Scan(
		&req.ID, &req.OrgID, &req.TaskID, &req.ActionFamily, &req.ActionType, &req.TargetSystem, &req.TargetObject,
		&actionJSON, &displayJSON, &req.PayloadHash, &req.AgentID, &req.SponsorUserID,
		&status, &risk, &req.PolicyVersion, &req.PolicyReason,
		&req.ApprovalID, &req.GrantJTI, &req.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get action request: %w", err)
	}
	req.Status = attest.ActionStatus(status)
	req.RiskLevel = attest.RiskLevel(risk)
	if len(actionJSON) > 0 && string(actionJSON) != "null" {
		if err := json.Unmarshal(actionJSON, &req.ActionPayload); err != nil {
			return nil, fmt.Errorf("decode action payload: %w", err)
		}
	}
	if len(displayJSON) > 0 && string(displayJSON) != "null" {
		if err := json.Unmarshal(displayJSON, &req.DisplayPayload); err != nil {
			return nil, fmt.Errorf("decode display payload: %w", err)
		}
	}
	return &req, nil
}

func (s *PostgresStore) ListActions(ctx context.Context, orgID string, params ListParams) ([]attest.ActionRequest, error) {
	query := `
		SELECT id, org_id, att_tid, action_family, action_type, target_system, target_object,
		       action_payload, display_payload, payload_hash, agent_id, sponsor_user_id,
		       status, COALESCE(risk_level, ''), COALESCE(policy_version, ''), COALESCE(policy_reason, ''),
		       approval_id, grant_jti, created_at
		FROM action_requests
		WHERE org_id = $1`
	args := []any{orgID}
	argIdx := 2
	if params.Status != "" {
		query += fmt.Sprintf(` AND status = $%d`, argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	query += ` ORDER BY created_at DESC`
	query += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list action requests: %w", err)
	}
	defer rows.Close()
	var out []attest.ActionRequest
	for rows.Next() {
		var item attest.ActionRequest
		var actionJSON, displayJSON []byte
		var risk, status string
		if err := rows.Scan(
			&item.ID, &item.OrgID, &item.TaskID, &item.ActionFamily, &item.ActionType, &item.TargetSystem, &item.TargetObject,
			&actionJSON, &displayJSON, &item.PayloadHash, &item.AgentID, &item.SponsorUserID,
			&status, &risk, &item.PolicyVersion, &item.PolicyReason,
			&item.ApprovalID, &item.GrantJTI, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan action request: %w", err)
		}
		item.Status = attest.ActionStatus(status)
		item.RiskLevel = attest.RiskLevel(risk)
		_ = json.Unmarshal(actionJSON, &item.ActionPayload)
		_ = json.Unmarshal(displayJSON, &item.DisplayPayload)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateReceipt(ctx context.Context, receipt *attest.ExecutionReceipt) error {
	responseJSON, err := json.Marshal(receipt.ResponsePayload)
	if err != nil {
		return fmt.Errorf("marshal response payload: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO execution_receipts (
			id, org_id, action_request_id, grant_jti, outcome, provider_ref, response_payload,
			payload_hash, approved_by, executed_at, signed_packet_hash, signature_algorithm,
			signature_kid, packet_signature
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14
		)
	`, receipt.ID, receipt.OrgID, receipt.ActionRequestID, receipt.GrantJTI, string(receipt.Outcome), receipt.ProviderRef, responseJSON,
		receipt.PayloadHash, receipt.ApprovedBy, receipt.ExecutedAt, receipt.SignedPacketHash, receipt.SignatureAlgorithm,
		receipt.SignatureKID, receipt.PacketSignature)
	if err != nil {
		return fmt.Errorf("insert execution receipt: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetReceipt(ctx context.Context, orgID, actionID string) (*attest.ExecutionReceipt, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, org_id, action_request_id, grant_jti, outcome, provider_ref, response_payload,
		       payload_hash, approved_by, executed_at, signed_packet_hash, signature_algorithm,
		       signature_kid, packet_signature
		FROM execution_receipts
		WHERE org_id = $1 AND action_request_id = $2
	`, orgID, actionID)
	var receipt attest.ExecutionReceipt
	var outcome string
	var responseJSON []byte
	if err := row.Scan(
		&receipt.ID, &receipt.OrgID, &receipt.ActionRequestID, &receipt.GrantJTI, &outcome, &receipt.ProviderRef, &responseJSON,
		&receipt.PayloadHash, &receipt.ApprovedBy, &receipt.ExecutedAt, &receipt.SignedPacketHash, &receipt.SignatureAlgorithm,
		&receipt.SignatureKID, &receipt.PacketSignature,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get execution receipt: %w", err)
	}
	receipt.Outcome = attest.ExecutionOutcome(outcome)
	if len(responseJSON) > 0 && string(responseJSON) != "null" {
		_ = json.Unmarshal(responseJSON, &receipt.ResponsePayload)
	}
	return &receipt, nil
}

func (s *PostgresStore) LoadApproval(ctx context.Context, orgID string, id *string) (*attest.ActionApprovalState, error) {
	if id == nil || *id == "" {
		return nil, nil
	}
	row := s.db.QueryRow(ctx, `
		SELECT id, status, approved_by, created_at, resolved_at
		FROM approvals
		WHERE org_id = $1 AND id = $2
	`, orgID, *id)
	var out attest.ActionApprovalState
	if err := row.Scan(&out.ID, &out.Status, &out.ApprovedBy, &out.CreatedAt, &out.ResolvedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get approval state: %w", err)
	}
	return &out, nil
}

func (s *PostgresStore) HydrateAction(ctx context.Context, req *attest.ActionRequest, approvals approval.Store, revStore revocation.Revoker) error {
	if req == nil {
		return nil
	}
	if req.ApprovalID != nil {
		state, err := s.LoadApproval(ctx, req.OrgID, req.ApprovalID)
		if err != nil {
			return err
		}
		req.Approval = state
	}
	if req.GrantJTI != nil && *req.GrantJTI != "" {
		cred, err := revStore.GetCredential(ctx, req.OrgID, *req.GrantJTI)
		if err == nil && cred != nil {
			req.Grant = &attest.ExecutionGrant{
				JTI:       cred.JTI,
				Scope:     append([]string(nil), cred.Scope...),
				ExpiresAt: cred.ExpiresAt,
			}
		}
	}
	receipt, err := s.GetReceipt(ctx, req.OrgID, req.ID)
	if err == nil && receipt != nil {
		req.Receipt = receipt
	}
	return nil
}

func (s *PostgresStore) UpdateActionTaskID(ctx context.Context, orgID, id, taskID string) error {
	_, err := s.db.Exec(ctx, `UPDATE action_requests SET att_tid = $1 WHERE id = $2 AND org_id = $3`, taskID, id, orgID)
	if err != nil {
		return fmt.Errorf("update action task id: %w", err)
	}
	return nil
}
