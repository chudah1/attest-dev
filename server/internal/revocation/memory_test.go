package revocation

import (
	"context"
	"testing"

	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
)

func makeClaims(jti string, chain []string) *attest.Claims {
	return &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{ID: jti},
		Chain:            chain,
	}
}

// TestMemoryStore_BasicRevocation tests basic revocation tracking.
func TestMemoryStore_BasicRevocation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.TrackCredential(ctx, "test-org", makeClaims("jti-1", []string{"jti-1"}))

	// Initially not revoked
	revoked, err := store.IsRevoked(ctx, "test-org", "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Expected jti-1 not to be revoked initially")
	}

	// Revoke it
	err = store.Revoke(ctx, "test-org", "jti-1", "admin")
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Now should be revoked
	revoked, err = store.IsRevoked(ctx, "test-org", "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !revoked {
		t.Error("Expected jti-1 to be revoked")
	}
}

// TestMemoryStore_CascadeRevocation tests revoking parent revokes descendants.
func TestMemoryStore_CascadeRevocation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Build a chain: root → parent → child
	store.TrackCredential(ctx, "test-org", makeClaims("root", []string{"root"}))
	store.TrackCredential(ctx, "test-org", makeClaims("parent", []string{"root", "parent"}))
	store.TrackCredential(ctx, "test-org", makeClaims("child", []string{"root", "parent", "child"}))
	store.TrackCredential(ctx, "test-org", makeClaims("sibling", []string{"root", "sibling"}))

	// Revoke the parent
	err := store.Revoke(ctx, "test-org", "parent", "admin")
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Verify revocation cascade
	tests := []struct {
		jti      string
		expected bool
	}{
		{"root", false},    // ancestor not revoked
		{"parent", true},   // target revoked
		{"child", true},    // descendant revoked
		{"sibling", false}, // different branch not revoked
	}

	for _, tt := range tests {
		revoked, _ := store.IsRevoked(ctx, "test-org", tt.jti)
		if revoked != tt.expected {
			t.Errorf("jti=%s: expected %v, got %v", tt.jti, tt.expected, revoked)
		}
	}
}

// TestMemoryStore_NonExistent tests checking non-existent JTI.
func TestMemoryStore_NonExistent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	revoked, err := store.IsRevoked(ctx, "test-org", "never-tracked")
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Expected non-existent JTI to not be revoked")
	}
}
