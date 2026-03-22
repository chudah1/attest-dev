// Package org manages organisations, API keys, and per-org RSA signing keys.
package org

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"
)

// ErrInvalidKey is returned when an API key cannot be resolved.
var ErrInvalidKey = errors.New("invalid or revoked api key")

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// Org represents a tenant organisation.
type Org struct {
	ID        string
	Name      string
	Status    string
	CreatedAt time.Time
}

// APIKey holds metadata for an issued API key (never the raw value).
type APIKey struct {
	ID        string
	OrgID     string
	Name      string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// OrgKey holds the active RSA key pair for an org.
// The KeyID is used as the JWT `kid` header and in the JWKS response.
type OrgKey struct {
	KeyID      string
	OrgID      string
	PrivateKey *rsa.PrivateKey
	CreatedAt  time.Time
}

// Store abstracts org, API key, and signing key persistence.
// Both the Postgres and in-memory implementations satisfy this interface.
type Store interface {
	// CreateOrg creates a new organisation, generates its first RSA-2048 key
	// pair, and issues an initial API key. Returns the org, the raw API key
	// string (shown once — never stored in plaintext), and the key metadata.
	CreateOrg(ctx context.Context, name string) (*Org, string, *APIKey, error)

	// ResolveAPIKey looks up an organisation by raw API key.
	// Returns the org and the resolved APIKey metadata (including ID).
	// Returns ErrInvalidKey if the key does not exist or has been revoked.
	ResolveAPIKey(ctx context.Context, rawKey string) (*Org, *APIKey, error)

	// GetSigningKey returns the active RSA key pair for the given org.
	GetSigningKey(ctx context.Context, orgID string) (*OrgKey, error)

	// CreateAPIKey generates a new API key for the org and returns the
	// key metadata and the raw key string (shown once).
	CreateAPIKey(ctx context.Context, orgID, name string) (*APIKey, string, error)

	// ListAPIKeys returns all API keys for the org, ordered newest first.
	ListAPIKeys(ctx context.Context, orgID string) ([]*APIKey, error)

	// RevokeAPIKey marks the given key as revoked.
	// Returns ErrNotFound if the key does not exist for this org.
	RevokeAPIKey(ctx context.Context, orgID, keyID string) error

	// RotateSigningKey generates a new RSA-2048 signing key for the org,
	// retires the previous one, and returns the new key.
	RotateSigningKey(ctx context.Context, orgID string) (*OrgKey, error)
}
