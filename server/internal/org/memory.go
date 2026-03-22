package org

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

const devOrgID = "dev-org"
const devOrgName = "Dev Org"
const devAPIKey = "dev"

// apiKeyEntry stores the internal record for a MemoryStore API key.
type apiKeyEntry struct {
	orgID     string
	keyID     string
	name      string
	createdAt time.Time
	revokedAt *time.Time
}

// MemoryStore is a thread-safe in-process implementation for dev/test use.
// On startup it creates a single "dev" organisation whose API key is the
// literal string "dev", matching the existing single-tenant behaviour.
type MemoryStore struct {
	mu         sync.RWMutex
	orgs       map[string]*Org           // org id → org
	keys       map[string][]*OrgKey      // org id → signing keys (last is active)
	apiKeys    map[string]*apiKeyEntry   // SHA-256(raw key) → entry
	orgAPIKeys map[string][]*APIKey      // org id → api key metadata list
}

// NewMemoryStore returns a MemoryStore pre-seeded with the "dev" organisation.
func NewMemoryStore() (*MemoryStore, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate dev rsa key: %w", err)
	}

	devKeyID := uuid.NewString()
	devAPIKeyID := uuid.NewString()
	now := time.Now().UTC()

	devOrgKey := &OrgKey{
		KeyID:      devKeyID,
		OrgID:      devOrgID,
		PrivateKey: privateKey,
		CreatedAt:  now,
	}

	devAPIKeyMeta := &APIKey{
		ID:        devAPIKeyID,
		OrgID:     devOrgID,
		Name:      "default",
		CreatedAt: now,
	}

	s := &MemoryStore{
		orgs: map[string]*Org{
			devOrgID: {
				ID:        devOrgID,
				Name:      devOrgName,
				Status:    "active",
				CreatedAt: now,
			},
		},
		keys: map[string][]*OrgKey{
			devOrgID: {devOrgKey},
		},
		apiKeys: map[string]*apiKeyEntry{
			hashKey(devAPIKey): {
				orgID:     devOrgID,
				keyID:     devAPIKeyID,
				name:      "default",
				createdAt: now,
			},
		},
		orgAPIKeys: map[string][]*APIKey{
			devOrgID: {devAPIKeyMeta},
		},
	}
	return s, nil
}

func (s *MemoryStore) CreateOrg(_ context.Context, name string) (*Org, string, *APIKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate rsa key: %w", err)
	}

	now := time.Now().UTC()
	org := &Org{
		ID:        uuid.NewString(),
		Name:      name,
		Status:    "active",
		CreatedAt: now,
	}
	orgKey := &OrgKey{
		KeyID:      uuid.NewString(),
		OrgID:      org.ID,
		PrivateKey: privateKey,
		CreatedAt:  now,
	}
	rawKey := generateAPIKey()
	apiKeyID := uuid.NewString()
	apiKey := &APIKey{
		ID:        apiKeyID,
		OrgID:     org.ID,
		Name:      "default",
		CreatedAt: now,
	}

	s.mu.Lock()
	s.orgs[org.ID] = org
	s.keys[org.ID] = []*OrgKey{orgKey}
	s.apiKeys[hashKey(rawKey)] = &apiKeyEntry{
		orgID:     org.ID,
		keyID:     apiKeyID,
		name:      "default",
		createdAt: now,
	}
	s.orgAPIKeys[org.ID] = []*APIKey{apiKey}
	s.mu.Unlock()

	return org, rawKey, apiKey, nil
}

func (s *MemoryStore) ResolveAPIKey(_ context.Context, rawKey string) (*Org, *APIKey, error) {
	h := hashKey(rawKey)

	s.mu.RLock()
	entry, ok := s.apiKeys[h]
	s.mu.RUnlock()

	if !ok || entry.revokedAt != nil {
		return nil, nil, ErrInvalidKey
	}

	s.mu.RLock()
	org := s.orgs[entry.orgID]
	s.mu.RUnlock()

	if org == nil || org.Status != "active" {
		return nil, nil, ErrInvalidKey
	}

	ak := &APIKey{
		ID:        entry.keyID,
		OrgID:     entry.orgID,
		Name:      entry.name,
		CreatedAt: entry.createdAt,
	}
	return org, ak, nil
}

func (s *MemoryStore) GetSigningKey(_ context.Context, orgID string) (*OrgKey, error) {
	s.mu.RLock()
	ks := s.keys[orgID]
	s.mu.RUnlock()
	if len(ks) == 0 {
		return nil, fmt.Errorf("no signing key for org %q", orgID)
	}
	return ks[len(ks)-1], nil
}

func (s *MemoryStore) CreateAPIKey(_ context.Context, orgID, name string) (*APIKey, string, error) {
	rawKey := generateAPIKey()
	now := time.Now().UTC()
	apiKeyID := uuid.NewString()

	ak := &APIKey{
		ID:        apiKeyID,
		OrgID:     orgID,
		Name:      name,
		CreatedAt: now,
	}

	s.mu.Lock()
	s.apiKeys[hashKey(rawKey)] = &apiKeyEntry{
		orgID:     orgID,
		keyID:     apiKeyID,
		name:      name,
		createdAt: now,
	}
	s.orgAPIKeys[orgID] = append([]*APIKey{ak}, s.orgAPIKeys[orgID]...)
	s.mu.Unlock()

	return ak, rawKey, nil
}

func (s *MemoryStore) ListAPIKeys(_ context.Context, orgID string) ([]*APIKey, error) {
	s.mu.RLock()
	list := s.orgAPIKeys[orgID]
	out := make([]*APIKey, len(list))
	copy(out, list)
	s.mu.RUnlock()
	return out, nil
}

func (s *MemoryStore) RevokeAPIKey(_ context.Context, orgID, keyID string) error {
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the entry in apiKeys map.
	for h, entry := range s.apiKeys {
		if entry.orgID == orgID && entry.keyID == keyID {
			if entry.revokedAt != nil {
				return ErrNotFound // already revoked
			}
			entry.revokedAt = &now
			s.apiKeys[h] = entry

			// Update metadata in orgAPIKeys.
			for _, ak := range s.orgAPIKeys[orgID] {
				if ak.ID == keyID {
					ak.RevokedAt = &now
					break
				}
			}
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) RotateSigningKey(_ context.Context, orgID string) (*OrgKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	now := time.Now().UTC()
	newKey := &OrgKey{
		KeyID:      uuid.NewString(),
		OrgID:      orgID,
		PrivateKey: privateKey,
		CreatedAt:  now,
	}

	s.mu.Lock()
	s.keys[orgID] = append(s.keys[orgID], newKey)
	s.mu.Unlock()

	return newKey, nil
}

// generateAPIKey returns a new random API key in the form att_live_<64 hex chars>.
func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "att_live_" + hex.EncodeToString(b)
}

// hashKey returns the SHA-256 hex digest of a raw API key string.
func hashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
