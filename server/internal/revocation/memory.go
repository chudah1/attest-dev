package revocation

import (
	"context"
	"sync"
	"time"
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
	chains     map[string][]string // jti → wrt_chain of that credential
}

// NewMemoryStore returns a ready-to-use in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		revoked: make(map[string]memEntry),
		chains:  make(map[string][]string),
	}
}

// TrackCredential registers a credential so its chain is available for
// cascade revocation. Call this immediately after issuing or delegating.
func (m *MemoryStore) TrackCredential(jti string, chain []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(chain))
	copy(cp, chain)
	m.chains[jti] = cp
}

// Revoke marks jti and all descendants (credentials whose chain contains jti)
// as revoked. Cascade is derived from the chains registered via TrackCredential.
func (m *MemoryStore) Revoke(_ context.Context, jti, revokedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	entry := memEntry{revokedAt: now, revokedBy: revokedBy}

	// Always revoke the target itself.
	m.revoked[jti] = entry

	// Cascade: any credential whose recorded chain contains jti is a descendant.
	for credJTI, chain := range m.chains {
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
func (m *MemoryStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.revoked[jti]
	return ok, nil
}
