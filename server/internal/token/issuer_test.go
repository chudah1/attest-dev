package token

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/attest-dev/attest/pkg/attest"
)

const testKID = "test-key-id"

func newTestIssuer(t *testing.T) (*Issuer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewIssuer("https://attest.test"), key
}

func TestIssue_HappyPath(t *testing.T) {
	iss, key := newTestIssuer(t)

	tok, claims, err := iss.Issue(key, testKID, attest.IssueParams{
		AgentID:     "orchestrator-v1",
		UserID:      "usr_test",
		Scope:       []string{"research:read", "gmail:send"},
		Instruction: "do the thing",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token string")
	}
	if claims.Depth != 0 {
		t.Errorf("depth = %d, want 0", claims.Depth)
	}
	if len(claims.Chain) != 1 || claims.Chain[0] != claims.ID {
		t.Errorf("chain = %v, want [%s]", claims.Chain, claims.ID)
	}
	if claims.IntentHash == "" {
		t.Error("intent hash should not be empty")
	}

	result, err := iss.Verify(tok, &key.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Errorf("verify invalid: %v", result.Warnings)
	}
}

func TestIssue_MissingAgentID(t *testing.T) {
	iss, key := newTestIssuer(t)
	_, _, err := iss.Issue(key, testKID, attest.IssueParams{
		UserID:      "usr_test",
		Scope:       []string{"gmail:send"},
		Instruction: "do the thing",
	})
	if err == nil {
		t.Fatal("expected error for missing agent_id")
	}
}

func TestIssue_InvalidScope(t *testing.T) {
	iss, key := newTestIssuer(t)
	_, _, err := iss.Issue(key, testKID, attest.IssueParams{
		AgentID:     "agent",
		UserID:      "usr",
		Scope:       []string{"notvalid"},
		Instruction: "do the thing",
	})
	if err == nil {
		t.Fatal("expected error for invalid scope entry")
	}
}

func TestDelegate_HappyPath(t *testing.T) {
	iss, key := newTestIssuer(t)

	rootTok, rootClaims, _ := iss.Issue(key, testKID, attest.IssueParams{
		AgentID:     "orchestrator-v1",
		UserID:      "usr_test",
		Scope:       []string{"research:read", "gmail:send"},
		Instruction: "do the thing",
	})

	childTok, childClaims, err := iss.Delegate(key, testKID, attest.DelegateParams{
		ParentToken: rootTok,
		ChildAgent:  "email-agent-v1",
		ChildScope:  []string{"gmail:send"},
	})

	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	if childClaims.Depth != 1 {
		t.Errorf("child depth = %d, want 1", childClaims.Depth)
	}
	if childClaims.TaskID != rootClaims.TaskID {
		t.Error("task ID should be propagated")
	}
	if childClaims.IntentHash != rootClaims.IntentHash {
		t.Error("intent hash should be propagated")
	}
	if len(childClaims.Chain) != 2 {
		t.Errorf("chain length = %d, want 2", len(childClaims.Chain))
	}
	if childClaims.Chain[0] != rootClaims.ID {
		t.Error("chain[0] should be root jti")
	}
	if childClaims.Chain[1] != childClaims.ID {
		t.Error("chain tail should be child jti")
	}

	result, err := iss.Verify(childTok, &key.PublicKey)
	if err != nil {
		t.Fatalf("verify child: %v", err)
	}
	if !result.Valid {
		t.Errorf("child verify invalid: %v", result.Warnings)
	}
}

func TestDelegate_ScopeViolation(t *testing.T) {
	iss, key := newTestIssuer(t)

	rootTok, _, _ := iss.Issue(key, testKID, attest.IssueParams{
		AgentID:     "orchestrator-v1",
		UserID:      "usr_test",
		Scope:       []string{"gmail:send"},
		Instruction: "do the thing",
	})

	_, _, err := iss.Delegate(key, testKID, attest.DelegateParams{
		ParentToken: rootTok,
		ChildAgent:  "bad-agent",
		ChildScope:  []string{"database:delete"},
	})

	if err == nil {
		t.Fatal("expected scope violation error")
	}
	if !strings.Contains(err.Error(), "subset") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDelegate_DepthLimit(t *testing.T) {
	iss, key := newTestIssuer(t)

	tok, _, _ := iss.Issue(key, testKID, attest.IssueParams{
		AgentID:     "agent-0",
		UserID:      "usr_test",
		Scope:       []string{"*:*"},
		Instruction: "do the thing",
	})

	var err error
	for i := 0; i < attest.MaxDelegationDepth; i++ {
		tok, _, err = iss.Delegate(key, testKID, attest.DelegateParams{
			ParentToken: tok,
			ChildAgent:  "agent",
			ChildScope:  []string{"*:*"},
		})
		if err != nil {
			t.Fatalf("delegate at depth %d: %v", i+1, err)
		}
	}

	_, _, err = iss.Delegate(key, testKID, attest.DelegateParams{
		ParentToken: tok,
		ChildAgent:  "too-deep",
		ChildScope:  []string{"*:*"},
	})
	if err == nil {
		t.Fatal("expected depth limit error")
	}
}
