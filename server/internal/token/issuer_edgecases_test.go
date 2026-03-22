package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
)

// TestGenerateTestKey creates a test RSA key pair for signing.
func TestGenerateTestKeyHelper(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

// TestIssue_IntentHashConsistency tests that intent hash is consistent for same instruction.
func TestIssue_IntentHashConsistency(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	params := attest.IssueParams{
		AgentID:     "agent-123",
		UserID:      "user-456",
		Scope:       []string{"read:documents"},
		Instruction: "analyze_documents",
		TTLSeconds:  3600,
	}

	_, claims1, _ := iss.Issue(key, "key-id-1", params)

	// Same params should produce same intent hash
	_, claims2, _ := iss.Issue(key, "key-id-1", params)

	if claims1.IntentHash != claims2.IntentHash {
		t.Errorf("Expected same intent hash for same instruction, got %s vs %s",
			claims1.IntentHash, claims2.IntentHash)
	}

	// Different instruction should produce different hash
	params.Instruction = "different_instruction"
	_, claims3, _ := iss.Issue(key, "key-id-1", params)

	if claims1.IntentHash == claims3.IntentHash {
		t.Error("Expected different intent hash for different instruction")
	}
}

// TestIssue_ValidScopes tests various valid scope formats.
func TestIssue_ValidScopes(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name   string
		scopes []string
	}{
		{"simple scope", []string{"read:documents"}},
		{"wildcard resource", []string{"*:read"}},
		{"wildcard action", []string{"documents:*"}},
		{"multiple scopes", []string{"read:documents", "write:notes", "delete:drafts"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := attest.IssueParams{
				AgentID:     "agent",
				UserID:      "user",
				Scope:       tt.scopes,
				Instruction: "test",
			}

			_, _, err := iss.Issue(key, "kid", params)
			if err != nil {
				t.Errorf("Unexpected error for scopes %v: %v", tt.scopes, err)
			}
		})
	}
}

// TestDelegate_TTLCalculation tests that child expiry is minimum of requested and parent expiry.
func TestDelegate_TTLCalculation(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Issue root with 1 hour TTL
	issueParams := attest.IssueParams{
		AgentID:     "parent-agent",
		UserID:      "user-456",
		Scope:       []string{"read:documents", "write:notes"},
		Instruction: "parent_task",
		TTLSeconds:  3600, // 1 hour
	}

	parentToken, parentClaims, _ := iss.Issue(key, "key-id-1", issueParams)
	parentExpiry := parentClaims.ExpiresAt.Time

	// Delegate with shorter TTL (30 min) - should use 30 min
	delegateParams := attest.DelegateParams{
		ParentToken: parentToken,
		ChildAgent:  "child-agent",
		ChildScope:  []string{"read:documents"},
		TTLSeconds:  1800, // 30 min
	}

	_, childClaims1, _ := iss.Delegate(key, "key-id-1", delegateParams)
	childExpiry1 := childClaims1.ExpiresAt.Time

	// Should be approximately 30 minutes from now
	expectedMaxExpiry := time.Now().Add(1800 * time.Second)
	if childExpiry1.After(expectedMaxExpiry.Add(5 * time.Second)) {
		t.Errorf("Child expiry %v should be before %v", childExpiry1, expectedMaxExpiry)
	}

	// Delegate with longer TTL (2 hours) - should use parent expiry (1 hour)
	delegateParams.TTLSeconds = 7200 // 2 hours
	_, childClaims2, _ := iss.Delegate(key, "key-id-1", delegateParams)
	childExpiry2 := childClaims2.ExpiresAt.Time

	// Child expiry should match parent expiry (within a few seconds)
	if childExpiry2.After(parentExpiry.Add(5*time.Second)) || childExpiry2.Before(parentExpiry.Add(-5*time.Second)) {
		t.Errorf("Child expiry %v should be close to parent expiry %v", childExpiry2, parentExpiry)
	}
}

// TestVerify_ChainIntegrity tests validation of chain integrity warnings.
func TestVerify_ChainIntegrity(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	now := time.Now()
	claims := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.test",
			Subject:   "agent:agent-123",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			ID:        "jti-123",
		},
		TaskID: "tid-456",
		Depth:  2,
		Scope:  []string{"read:documents"},
		Chain:  []string{"root-jti", "parent-jti"}, // Missing current jti
		UserID: "user-456",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token, _ := tok.SignedString(key)

	result, _ := iss.Verify(token, &key.PublicKey)
	// Should have warnings but still parse
	if len(result.Warnings) == 0 {
		t.Error("Expected warnings for chain integrity issue")
	}
}

// TestIssue_ScopeNormalization tests that scopes are properly normalized.
func TestIssue_ScopeNormalization(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	params := attest.IssueParams{
		AgentID:     "agent",
		UserID:      "user",
		Scope:       []string{"research:read", "gmail:send"},
		Instruction: "test",
	}

	_, claims, _ := iss.Issue(key, "kid", params)

	// Verify scope is stored
	if len(claims.Scope) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(claims.Scope))
	}
}

// TestDelegate_AncestryChain tests that delegation maintains proper ancestry chain.
func TestDelegate_AncestryChain(t *testing.T) {
	iss := NewIssuer("https://issuer.test")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a chain: root → level1 → level2
	rootTok, rootClaims, _ := iss.Issue(key, "kid", attest.IssueParams{
		AgentID:     "agent-0",
		UserID:      "user",
		Scope:       []string{"*:*"},
		Instruction: "root",
	})

	level1Tok, level1Claims, _ := iss.Delegate(key, "kid", attest.DelegateParams{
		ParentToken: rootTok,
		ChildAgent:  "agent-1",
		ChildScope:  []string{"*:*"},
	})

	_, level2Claims, _ := iss.Delegate(key, "kid", attest.DelegateParams{
		ParentToken: level1Tok,
		ChildAgent:  "agent-2",
		ChildScope:  []string{"*:*"},
	})

	// Verify chain structure
	if len(level2Claims.Chain) != 3 {
		t.Errorf("Expected chain length 3, got %d", len(level2Claims.Chain))
	}

	if level2Claims.Chain[0] != rootClaims.ID {
		t.Error("First element should be root jti")
	}

	if level2Claims.Chain[1] != level1Claims.ID {
		t.Error("Second element should be level1 jti")
	}

	if level2Claims.Chain[2] != level2Claims.ID {
		t.Error("Third element should be level2 jti")
	}

	if level2Claims.Depth != 2 {
		t.Errorf("Expected depth 2, got %d", level2Claims.Depth)
	}
}
