package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/pkg/attest"
)

// TestCompleteFlow tests the full credential lifecycle:
// Issue → Delegate → Audit → Revoke → Cascade
func TestCompleteFlow(t *testing.T) {
	ctx := context.Background()

	// Initialize components
	iss := NewIssuer("https://issuer.example.com")
	revStore := revocation.NewMemoryStore()
	auditLog := audit.NewMemoryLog()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// ========== STEP 1: Issue Root Credential ==========
	issueParams := attest.IssueParams{
		AgentID:     "orchestrator-v1",
		UserID:      "user-admin",
		Scope:       []string{"research:read", "gmail:send", "database:delete"},
		Instruction: "analyze_email_and_update_db",
		TTLSeconds:  3600,
	}

	rootToken, rootClaims, err := iss.Issue(key, "kid-1", issueParams)
	if err != nil {
		t.Fatalf("Failed to issue root credential: %v", err)
	}

	if rootClaims.Depth != 0 {
		t.Errorf("Root credential should have depth 0, got %d", rootClaims.Depth)
	}

	// Track the credential for revocation
	revStore.TrackCredential(rootClaims.ID, rootClaims.Chain)

	// Log the issuance
	auditLog.Append(ctx, attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       rootClaims.ID,
		TaskID:    rootClaims.TaskID,
		UserID:    rootClaims.UserID,
		AgentID:   issueParams.AgentID,
		Scope:     rootClaims.Scope,
	})

	t.Logf("✓ Step 1: Root token issued (JTI=%s)", rootClaims.ID[:8])

	// ========== STEP 2: Delegate to Child Agent ==========
	delegateParams := attest.DelegateParams{
		ParentToken: rootToken,
		ChildAgent:  "email-agent-v1",
		ChildScope:  []string{"gmail:send"}, // Narrower scope
		TTLSeconds:  1800,
	}

	childToken, childClaims, err := iss.Delegate(key, "kid-1", delegateParams)
	if err != nil {
		t.Fatalf("Failed to delegate: %v", err)
	}

	if childClaims.Depth != 1 {
		t.Errorf("Child should have depth 1, got %d", childClaims.Depth)
	}

	if childClaims.TaskID != rootClaims.TaskID {
		t.Error("TaskID should be inherited")
	}

	if len(childClaims.Chain) != 2 || childClaims.Chain[0] != rootClaims.ID {
		t.Error("Child chain should contain root JTI")
	}

	// Track and log delegation
	revStore.TrackCredential(childClaims.ID, childClaims.Chain)
	auditLog.Append(ctx, attest.AuditEvent{
		EventType: attest.EventDelegated,
		JTI:       childClaims.ID,
		TaskID:    childClaims.TaskID,
		UserID:    childClaims.UserID,
		AgentID:   delegateParams.ChildAgent,
		Scope:     childClaims.Scope,
	})

	t.Logf("✓ Step 2: Child token delegated (JTI=%s, Depth=%d)", childClaims.ID[:8], childClaims.Depth)

	// ========== STEP 3: Verify Tokens ==========
	rootResult, _ := iss.Verify(rootToken, &key.PublicKey)
	if !rootResult.Valid {
		t.Error("Root token should be valid")
	}

	childResult, _ := iss.Verify(childToken, &key.PublicKey)
	if !childResult.Valid {
		t.Error("Child token should be valid")
	}

	// Verify neither are revoked yet
	rootRevoked, _ := revStore.IsRevoked(ctx, rootClaims.ID)
	childRevoked, _ := revStore.IsRevoked(ctx, childClaims.ID)

	if rootRevoked || childRevoked {
		t.Error("Tokens should not be revoked yet")
	}

	t.Log("✓ Step 3: Both tokens verified successfully")

	// ========== STEP 4: Revoke Parent (Cascade) ==========
	err = revStore.Revoke(ctx, rootClaims.ID, "admin-user")
	if err != nil {
		t.Fatalf("Failed to revoke: %v", err)
	}

	// Log the revocation event
	auditLog.Append(ctx, attest.AuditEvent{
		EventType: attest.EventRevoked,
		JTI:       rootClaims.ID,
		TaskID:    rootClaims.TaskID,
		UserID:    rootClaims.UserID,
		AgentID:   "system",
		Scope:     rootClaims.Scope,
		Meta: map[string]string{
			"revoked_by": "admin-user",
		},
	})

	// Verify cascade: both parent and child should now be revoked
	rootRevoked, _ = revStore.IsRevoked(ctx, rootClaims.ID)
	childRevoked, _ = revStore.IsRevoked(ctx, childClaims.ID)

	if !rootRevoked {
		t.Error("Parent should be revoked")
	}
	if !childRevoked {
		t.Error("Child should be revoked (cascade)")
	}

	t.Log("✓ Step 4: Parent revoked, child revoked via cascade")

	// ========== STEP 5: Verify Full Audit Trail ==========
	events, err := auditLog.Query(ctx, rootClaims.TaskID)
	if err != nil {
		t.Fatalf("Failed to query audit log: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 audit events, got %d", len(events))
	}

	// Verify event sequence
	if events[0].EventType != attest.EventIssued {
		t.Error("Event 1 should be EventIssued")
	}
	if events[1].EventType != attest.EventDelegated {
		t.Error("Event 2 should be EventDelegated")
	}
	if events[2].EventType != attest.EventRevoked {
		t.Error("Event 3 should be EventRevoked")
	}

	// Verify hash chaining
	if events[1].PrevHash != events[0].EntryHash {
		t.Error("Event 2 should chain from Event 1")
	}
	if events[2].PrevHash != events[1].EntryHash {
		t.Error("Event 3 should chain from Event 2")
	}

	t.Log("✓ Step 5: Audit trail complete and properly chained")
}

// TestMultipleDelegationLevels tests deep delegation chains
func TestMultipleDelegationLevels(t *testing.T) {
	ctx := context.Background()

	iss := NewIssuer("https://issuer.example.com")
	revStore := revocation.NewMemoryStore()
	auditLog := audit.NewMemoryLog()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Issue root
	rootParams := attest.IssueParams{
		AgentID:     "root-orchestrator",
		UserID:      "admin",
		Scope:       []string{"*:*"},
		Instruction: "orchestrate_workflow",
		TTLSeconds:  86400,
	}

	rootToken, rootClaims, _ := iss.Issue(key, "kid", rootParams)
	revStore.TrackCredential(rootClaims.ID, rootClaims.Chain)
	auditLog.Append(ctx, attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       rootClaims.ID,
		TaskID:    rootClaims.TaskID,
		UserID:    rootClaims.UserID,
		AgentID:   rootParams.AgentID,
		Scope:     rootClaims.Scope,
	})

	currentToken := rootToken
	var jtis []string
	jtis = append(jtis, rootClaims.ID)

	// Create 3 levels of delegation
	for level := 1; level <= 3; level++ {
		agentName := "agent-level-" + string(rune('0'+level))

		delegateParams := attest.DelegateParams{
			ParentToken: currentToken,
			ChildAgent:  agentName,
			ChildScope:  []string{"*:read"},
		}

		newToken, newClaims, err := iss.Delegate(key, "kid", delegateParams)
		if err != nil {
			t.Fatalf("Level %d delegation failed: %v", level, err)
		}

		// Verify depth
		if newClaims.Depth != level {
			t.Errorf("Level %d should have depth %d, got %d", level, level, newClaims.Depth)
		}

		// Verify chain grows
		if len(newClaims.Chain) != level+1 {
			t.Errorf("Level %d should have chain length %d, got %d", level, level+1, len(newClaims.Chain))
		}

		revStore.TrackCredential(newClaims.ID, newClaims.Chain)
		auditLog.Append(ctx, attest.AuditEvent{
			EventType: attest.EventDelegated,
			JTI:       newClaims.ID,
			TaskID:    newClaims.TaskID,
			UserID:    newClaims.UserID,
			AgentID:   agentName,
			Scope:     newClaims.Scope,
		})

		jtis = append(jtis, newClaims.ID)
		currentToken = newToken
	}

	// Revoke at root
	revStore.Revoke(ctx, rootClaims.ID, "admin")

	// Verify all 4 credentials are revoked (cascade)
	for i, jti := range jtis {
		revoked, _ := revStore.IsRevoked(ctx, jti)
		if !revoked {
			t.Errorf("Level %d should be revoked", i)
		}
	}

	// Verify audit log has 4 events
	events, _ := auditLog.Query(ctx, rootClaims.TaskID)
	if len(events) != 4 {
		t.Fatalf("Expected 4 audit events, got %d", len(events))
	}

	t.Logf("✓ 3-level delegation chain with cascade revocation working")
	t.Logf("✓ %d credentials revoked in cascade", len(jtis))
	t.Logf("✓ Audit trail captured all %d events", len(events))
}
