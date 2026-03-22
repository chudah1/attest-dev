package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrProviderUnavailable indicates the IdP's discovery endpoint could not be reached.
var ErrProviderUnavailable = errors.New("identity provider unavailable")

// VerifiedClaims holds the extracted claims from a validated OIDC identity token.
type VerifiedClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// Manager handles caching of OIDC providers to prevent hitting /.well-known endpoints on every request.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]*cachedProvider
}

type cachedProvider struct {
	provider *oidc.Provider
	expires  time.Time
}

// NewManager creates a new OIDC Provider manager.
func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]*cachedProvider),
	}
}

// VerifyToken validates an OIDC token against the specified issuer and expected client ID.
func (m *Manager) VerifyToken(ctx context.Context, issuerURL, clientID, rawToken string) (*VerifiedClaims, error) {
	m.mu.RLock()
	cp, exists := m.providers[issuerURL]
	m.mu.RUnlock()

	// If missing or expired (cache for 1 hour), acquire write lock and double-check.
	if !exists || time.Now().After(cp.expires) {
		m.mu.Lock()
		cp, exists = m.providers[issuerURL]
		if !exists || time.Now().After(cp.expires) {
			p, err := oidc.NewProvider(ctx, issuerURL)
			if err != nil {
				m.mu.Unlock()
				return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
			}
			cp = &cachedProvider{
				provider: p,
				expires:  time.Now().Add(1 * time.Hour),
			}
			m.providers[issuerURL] = cp
		}
		m.mu.Unlock()
	}

	verifier := cp.provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify token signature: %w", err)
	}

	var claims VerifiedClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse token claims: %w", err)
	}

	return &claims, nil
}
