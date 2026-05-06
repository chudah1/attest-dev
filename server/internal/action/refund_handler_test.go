package action

import (
	"testing"

	"github.com/attest-dev/attest/pkg/attest"
)

func TestRefundHandlerValidateNormalizesPayload(t *testing.T) {
	t.Parallel()

	handler := &RefundHandler{actionType: "refund"}
	normalized, err := handler.Validate(
		"stripe",
		"order_123",
		map[string]any{
			"amount_cents": float64(4799),
			"currency":     "USD",
			"reason":       "damaged_item",
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if normalized.ActionFamily != "finance" {
		t.Fatalf("ActionFamily = %q, want finance", normalized.ActionFamily)
	}
	if got := normalized.ActionPayload["amount_cents"]; got != int64(4799) {
		t.Fatalf("amount_cents = %#v, want 4799", got)
	}
	if got := normalized.DisplayPayload["currency"]; got != "USD" {
		t.Fatalf("display currency = %#v, want USD", got)
	}
}

func TestRefundHandlerValidateRejectsInvalidPayload(t *testing.T) {
	t.Parallel()

	handler := &RefundHandler{actionType: "refund"}
	_, err := handler.Validate("stripe", "order_123", map[string]any{
		"currency": "USD",
		"reason":   "damaged_item",
	}, nil)
	if err == nil {
		t.Fatal("Validate() error = nil, want invalid payload error")
	}
}

func TestRefundHandlerEvaluatePolicy(t *testing.T) {
	t.Parallel()

	handler := &RefundHandler{actionType: "refund"}
	config := ActionPolicyConfig{
		AutoApproveThresholdCents: 5000,
		ApprovalThresholdCents:    500000,
	}

	tests := []struct {
		name       string
		amount     int64
		wantStatus attest.ActionStatus
		wantRisk   attest.RiskLevel
		wantReason string
	}{
		{
			name:       "auto approved",
			amount:     4799,
			wantStatus: attest.ActionStatusApproved,
			wantRisk:   attest.RiskLow,
			wantReason: "amount_below_auto_threshold",
		},
		{
			name:       "approval required",
			amount:     150000,
			wantStatus: attest.ActionStatusPendingApproval,
			wantRisk:   attest.RiskMedium,
			wantReason: "amount_requires_approval",
		},
		{
			name:       "high risk approval required",
			amount:     700000,
			wantStatus: attest.ActionStatusPendingApproval,
			wantRisk:   attest.RiskHigh,
			wantReason: "amount_above_approval_threshold",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decision := handler.EvaluatePolicy(config, &NormalizedAction{
				ActionPayload: map[string]any{"amount_cents": tc.amount},
			})
			if decision.Status != tc.wantStatus {
				t.Fatalf("Status = %q, want %q", decision.Status, tc.wantStatus)
			}
			if decision.RiskLevel != tc.wantRisk {
				t.Fatalf("RiskLevel = %q, want %q", decision.RiskLevel, tc.wantRisk)
			}
			if decision.PolicyReason != tc.wantReason {
				t.Fatalf("PolicyReason = %q, want %q", decision.PolicyReason, tc.wantReason)
			}
			if decision.PolicyVersion != "refund-v1" {
				t.Fatalf("PolicyVersion = %q, want refund-v1", decision.PolicyVersion)
			}
		})
	}
}
