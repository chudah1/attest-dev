package org

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const devOrgID = "dev-org"
const devOrgName = "Dev Org"
const devAPIKey = "dev"

// apiKeyEntry stores the internal record for a MemoryStore API key.
type apiKeyEntry struct {
	orgID        string
	keyID        string
	name         string
	createdAt    time.Time
	revokedAt    *time.Time
	hashedSecret string
}

// MemoryStore is a thread-safe in-process implementation for dev/test use.
// On startup it creates a single "dev" organisation whose API key is the
// literal string "dev", matching the existing single-tenant behaviour.
type MemoryStore struct {
	mu         sync.RWMutex
	orgs       map[string]*Org         // org id → org
	keys       map[string][]*OrgKey    // org id → signing keys (last is active)
	apiKeys    map[string]*apiKeyEntry // SHA-256(raw key) → entry
	orgAPIKeys map[string][]*APIKey    // org id → api key metadata list
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

	hashedDevAPIKeySecret, _ := hashKey("dev-secret")

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
			devAPIKey: { // The literal "dev" key for legacy compatibility
				orgID:        devOrgID,
				keyID:        "dev-key-id", // A placeholder ID for the literal "dev" key
				name:         "dev-default",
				createdAt:    now,
				hashedSecret: hashedDevAPIKeySecret,
			},
			devAPIKeyID: { // The actual dev API key with a secret
				orgID:        devOrgID,
				keyID:        devAPIKeyID,
				name:         "default",
				createdAt:    now,
				hashedSecret: hashedDevAPIKeySecret, // Using the same hashed secret for simplicity
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
	secret := generateAPIKeySecret()
	apiKeyID := uuid.NewString()
	rawKey := "att_live_" + apiKeyID + "." + secret

	hashedSecret, err := hashKey(secret)
	if err != nil {
		return nil, "", nil, fmt.Errorf("hash key: %w", err)
	}

	apiKey := &APIKey{
		ID:        apiKeyID,
		OrgID:     org.ID,
		Name:      "default",
		CreatedAt: now,
	}

	s.mu.Lock()
	s.orgs[org.ID] = org
	s.keys[org.ID] = []*OrgKey{orgKey}
	s.apiKeys[apiKeyID] = &apiKeyEntry{ // Store by keyID
		orgID:        org.ID,
		keyID:        apiKeyID,
		name:         "default",
		createdAt:    now,
		hashedSecret: hashedSecret,
	}
	s.orgAPIKeys[org.ID] = []*APIKey{apiKey}
	s.mu.Unlock()

	return org, rawKey, apiKey, nil
}

func (s *MemoryStore) ResolveAPIKey(_ context.Context, rawKey string) (*Org, *APIKey, error) {
	// Dev key bypass for the literal "dev" string.
	// This is for legacy compatibility and testing convenience.
	if rawKey == devAPIKey {
		s.mu.RLock()
		org := s.orgs[devOrgID]
		s.mu.RUnlock()
		if org == nil {
			return nil, nil, ErrInvalidKey
		}
		// For the "dev" key, we return a hardcoded APIKey metadata.
		// The actual dev API key (att_live_dev-key-id.dev-secret) is handled below.
		ak := &APIKey{
			ID:        "dev-key-id",
			OrgID:     devOrgID,
			Name:      "dev-default",
			CreatedAt: org.CreatedAt,
		}
		return org, ak, nil
	}

	parts := strings.Split(rawKey, ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "att_live_") {
		return nil, nil, ErrInvalidKey
	}
	keyID := strings.TrimPrefix(parts[0], "att_live_")
	secret := parts[1]

	s.mu.RLock()
	entry, ok := s.apiKeys[keyID]
	s.mu.RUnlock()

	if !ok || entry.revokedAt != nil {
		return nil, nil, ErrInvalidKey
	}

	// Compare the provided secret with the stored bcrypt hash.
	if err := bcrypt.CompareHashAndPassword([]byte(entry.hashedSecret), []byte(secret)); err != nil {
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

func (s *MemoryStore) UpdateOrg(_ context.Context, orgID string, requireIDP bool, issuerURL, clientID *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	o, ok := s.orgs[orgID]
	if !ok {
		return ErrNotFound
	}

	o.RequireIDP = requireIDP
	o.IDPIssuerURL = issuerURL
	o.IDPClientID = clientID
	return nil
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

func (s *MemoryStore) ListSigningKeys(_ context.Context, orgID string) ([]*OrgKey, error) {
	s.mu.RLock()
	ks := s.keys[orgID]
	s.mu.RUnlock()
	if len(ks) == 0 {
		return nil, fmt.Errorf("no signing key for org %q", orgID)
	}

	out := make([]*OrgKey, 0, len(ks))
	for i := len(ks) - 1; i >= 0; i-- {
		out = append(out, ks[i])
	}
	return out, nil
}

func (s *MemoryStore) CreateAPIKey(_ context.Context, orgID, name string) (*APIKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	org := s.orgs[orgID]
	if org == nil {
		return nil, "", ErrNotFound
	}

	secret := generateAPIKeySecret()
	now := time.Now().UTC()
	apiKeyID := uuid.NewString()

	hashedSecret, err := hashKey(secret)
	if err != nil {
		return nil, "", fmt.Errorf("hash key: %w", err)
	}

	s.apiKeys[apiKeyID] = &apiKeyEntry{ // Store by keyID
		orgID:        orgID,
		keyID:        apiKeyID,
		name:         name,
		createdAt:    now,
		hashedSecret: hashedSecret,
	}

	apiKey := &APIKey{
		ID:        apiKeyID,
		OrgID:     orgID,
		Name:      name,
		CreatedAt: now,
	}

	s.orgAPIKeys[orgID] = append(s.orgAPIKeys[orgID], apiKey)

	rawKey := "att_live_" + apiKeyID + "." + secret
	return apiKey, rawKey, nil
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

// generateAPIKeySecret returns a new random API key secret (32 bytes hex length = 64).
func generateAPIKeySecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// hashKey returns the bcrypt hash of a raw API key secret string.
func hashKey(secret string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}
