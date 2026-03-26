package revocation

import (
	"context"
	"sort"
	"strings"
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
	mu       sync.RWMutex
	revoked  map[string]memEntry                // jti → revocation record
	chains   map[string][]string                // jti → att_chain of that credential
	orgByJTI map[string]string                  // jti → org_id
	creds    map[string]attest.CredentialRecord // jti -> credential snapshot
}

// NewMemoryStore returns a ready-to-use in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		revoked:  make(map[string]memEntry),
		chains:   make(map[string][]string),
		orgByJTI: make(map[string]string),
		creds:    make(map[string]attest.CredentialRecord),
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
	issuedAt := time.Time{}
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	expiresAt := time.Time{}
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	m.creds[claims.ID] = attest.CredentialRecord{
		JTI:           claims.ID,
		OrgID:         orgID,
		TaskID:        claims.TaskID,
		ParentID:      claims.ParentID,
		UserID:        claims.UserID,
		AgentID:       strings.TrimPrefix(claims.Subject, "agent:"),
		Depth:         claims.Depth,
		Scope:         append([]string(nil), claims.Scope...),
		Chain:         cp,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		IntentHash:    claims.IntentHash,
		AgentChecksum: claims.AgentChecksum,
		IDPIssuer:     cloneStringPtr(claims.IDPIssuer),
		IDPSubject:    cloneStringPtr(claims.IDPSubject),
		HITLRequestID: cloneStringPtr(claims.HITLRequestID),
		HITLSubject:   cloneStringPtr(claims.HITLSubject),
		HITLIssuer:    cloneStringPtr(claims.HITLIssuer),
	}
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

// ListTaskCredentials returns all credentials for a task tree.
func (m *MemoryStore) ListTaskCredentials(_ context.Context, orgID, taskID string) ([]attest.CredentialRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]attest.CredentialRecord, 0)
	for _, cred := range m.creds {
		if cred.OrgID == orgID && cred.TaskID == taskID {
			out = append(out, cred)
		}
	}

	// Keep deterministic ancestry-friendly ordering.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		if !out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].IssuedAt.Before(out[j].IssuedAt)
		}
		return out[i].JTI < out[j].JTI
	})
	return out, nil
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
