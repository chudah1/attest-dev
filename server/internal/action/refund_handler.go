package action

import (
	"fmt"

	"github.com/attest-dev/attest/pkg/attest"
)

type RefundHandler struct {
	actionType string
}

func (h *RefundHandler) ActionType() string {
	return h.actionType
}

func (h *RefundHandler) ActionFamily() string {
	return "finance"
}

func (h *RefundHandler) PolicyVersion() string {
	return h.actionType + "-v1"
}

func (h *RefundHandler) Validate(targetSystem, targetObject string, actionPayload map[string]any, displayPayload map[string]any) (*NormalizedAction, error) {
	amount, ok := parseAmountCents(actionPayload["amount_cents"])
	if !ok || amount <= 0 {
		return nil, fmt.Errorf("invalid_payload")
	}
	currency, ok := actionPayload["currency"].(string)
	if !ok || currency == "" {
		return nil, fmt.Errorf("invalid_payload")
	}
	reason, ok := actionPayload["reason"].(string)
	if !ok || reason == "" {
		return nil, fmt.Errorf("invalid_payload")
	}

	normalizedPayload := map[string]any{
		"amount_cents": amount,
		"currency":     currency,
		"reason":       reason,
	}
	normalizedDisplay := cloneMap(displayPayload)
	if len(normalizedDisplay) == 0 {
		normalizedDisplay = map[string]any{
			"amount_cents": amount,
			"currency":     currency,
			"reason":       reason,
		}
	}

	return &NormalizedAction{
		ActionFamily:   "finance",
		ActionType:     h.actionType,
		TargetSystem:   targetSystem,
		TargetObject:   targetObject,
		ActionPayload:  normalizedPayload,
		DisplayPayload: normalizedDisplay,
	}, nil
}

func (h *RefundHandler) EvaluatePolicy(config ActionPolicyConfig, normalized *NormalizedAction) PolicyDecision {
	amount, _ := normalized.ActionPayload["amount_cents"].(int64)
	if amount <= config.AutoApproveThresholdCents {
		return PolicyDecision{
			Status:        attest.ActionStatusApproved,
			RiskLevel:     attest.RiskLow,
			PolicyVersion: h.PolicyVersion(),
			PolicyReason:  "amount_below_auto_threshold",
		}
	}

	risk := attest.RiskMedium
	reason := "amount_requires_approval"
	if amount > config.ApprovalThresholdCents {
		risk = attest.RiskHigh
		reason = "amount_above_approval_threshold"
	}
	return PolicyDecision{
		Status:        attest.ActionStatusPendingApproval,
		RiskLevel:     risk,
		PolicyVersion: h.PolicyVersion(),
		PolicyReason:  reason,
	}
}

func (h *RefundHandler) GrantScope(_ *NormalizedAction) []string {
	return []string{h.actionType + ":execute"}
}

func parseAmountCents(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	default:
		return 0, false
	}
}
