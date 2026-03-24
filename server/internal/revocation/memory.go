package revocation

import (
	"context"
	"sync"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
)

// memEntry records when and by whom a JTI was revoked.
type memEntry struct {
	revokedAt time.Time
	revokedBy string
}

// MemoryStore is a thread-safe, in-process revocation store for dev/test use.
// It supports cascade revocation via TrackCredential: callers register each
// issued/delegated credential's chain, and Revoke propagates to all
// descendants without needing a database.
type MemoryStore struct {
	mu         sync.RWMutex
	revoked    map[string]memEntry // jti → revocation record
	chains     map[string][]string // jti → att_chain of that credential
	orgByJTI   map[string]string   // jti → org_id
}

// NewMemoryStore returns a ready-to-use in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		revoked:  make(map[string]memEntry),
		chains:   make(map[string][]string),
		orgByJTI: make(map[string]string),
	}
}

// TrackCredential registers a credential so its chain is available for
// cascade revocation. Call this immediately after issuing or delegating.
func (m *MemoryStore) TrackCredential(_ context.Context, orgID string, claims *attest.Claims) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(claims.Chain))
	copy(cp, claims.Chain)
	m.chains[claims.ID] = cp
	m.orgByJTI[claims.ID] = orgID
	return nil
}

// Revoke marks jti and all descendants (credentials whose chain contains jti)
// as revoked. Cascade is derived from the chains registered via TrackCredential.
func (m *MemoryStore) Revoke(_ context.Context, orgID, jti, revokedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	entry := memEntry{revokedAt: now, revokedBy: revokedBy}

	// Only revoke if the credential belongs to this org.
	if owner, ok := m.orgByJTI[jti]; ok && owner != orgID {
		return nil
	}
	m.revoked[jti] = entry

	// Cascade: any credential whose recorded chain contains jti is a descendant,
	// but only within the same org.
	for credJTI, chain := range m.chains {
		if m.orgByJTI[credJTI] != orgID {
			continue
		}
		for _, ancestor := range chain {
			if ancestor == jti {
				m.revoked[credJTI] = entry
				break
			}
		}
	}

	return nil
}

// IsRevoked reports whether jti has been revoked.
// If orgID is empty (public endpoint), skip the org ownership check.
func (m *MemoryStore) IsRevoked(_ context.Context, orgID, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if orgID != "" {
		if owner, ok := m.orgByJTI[jti]; ok && owner != orgID {
			return false, nil
		}
	}

	_, ok := m.revoked[jti]
	return ok, nil
}
