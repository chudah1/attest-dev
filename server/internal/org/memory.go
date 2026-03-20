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

// MemoryStore is a thread-safe in-process implementation for dev/test use.
// On startup it creates a single "dev" organisation whose API key is the
// literal string "dev", matching the existing single-tenant behaviour.
type MemoryStore struct {
	mu      sync.RWMutex
	orgs    map[string]*Org          // org id → org
	keys    map[string]*OrgKey       // org id → active signing key
	apiKeys map[string]string        // SHA-256(raw key) → org id
}

// NewMemoryStore returns a MemoryStore pre-seeded with the "dev" organisation.
func NewMemoryStore() (*MemoryStore, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate dev rsa key: %w", err)
	}

	devKeyID := uuid.NewString()
	now := time.Now().UTC()

	s := &MemoryStore{
		orgs: map[string]*Org{
			devOrgID: {
				ID:        devOrgID,
				Name:      devOrgName,
				Status:    "active",
				CreatedAt: now,
			},
		},
		keys: map[string]*OrgKey{
			devOrgID: {
				KeyID:      devKeyID,
				OrgID:      devOrgID,
				PrivateKey: privateKey,
				CreatedAt:  now,
			},
		},
		apiKeys: map[string]string{
			hashKey(devAPIKey): devOrgID,
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
	apiKey := &APIKey{
		ID:        uuid.NewString(),
		OrgID:     org.ID,
		Name:      "default",
		CreatedAt: now,
	}

	s.mu.Lock()
	s.orgs[org.ID] = org
	s.keys[org.ID] = orgKey
	s.apiKeys[hashKey(rawKey)] = org.ID
	s.mu.Unlock()

	return org, rawKey, apiKey, nil
}

func (s *MemoryStore) ResolveAPIKey(_ context.Context, rawKey string) (*Org, error) {
	h := hashKey(rawKey)
	s.mu.RLock()
	orgID, ok := s.apiKeys[h]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrInvalidKey
	}
	s.mu.RLock()
	org := s.orgs[orgID]
	s.mu.RUnlock()
	if org == nil || org.Status != "active" {
		return nil, ErrInvalidKey
	}
	return org, nil
}

func (s *MemoryStore) GetSigningKey(_ context.Context, orgID string) (*OrgKey, error) {
	s.mu.RLock()
	k := s.keys[orgID]
	s.mu.RUnlock()
	if k == nil {
		return nil, fmt.Errorf("no signing key for org %q", orgID)
	}
	return k, nil
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
