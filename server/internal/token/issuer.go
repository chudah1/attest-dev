package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/warrant-dev/warrant/pkg/warrant"
)

// Issuer signs and verifies Warrant credentials using RS256.
type Issuer struct {
	privateKey *rsa.PrivateKey
	issuerURI  string
}

// NewIssuer constructs an Issuer with the given RSA key pair and issuer URI.
func NewIssuer(privateKey *rsa.PrivateKey, issuerURI string) *Issuer {
	return &Issuer{privateKey: privateKey, issuerURI: issuerURI}
}

// Issue creates a root credential (depth 0) from the supplied parameters.
func (is *Issuer) Issue(p warrant.IssueParams) (string, *warrant.Claims, error) {
	if p.AgentID == "" {
		return "", nil, errors.New("agent_id is required")
	}
	if p.UserID == "" {
		return "", nil, errors.New("user_id is required")
	}
	if len(p.Scope) == 0 {
		return "", nil, errors.New("scope must not be empty")
	}
	for _, s := range p.Scope {
		if _, ok := warrant.ParseScope(s); !ok {
			return "", nil, fmt.Errorf("invalid scope entry: %q", s)
		}
	}
	if p.Instruction == "" {
		return "", nil, errors.New("instruction is required")
	}

	ttl := p.TTLSeconds
	if ttl <= 0 || ttl > warrant.MaxTTLSeconds {
		ttl = warrant.MaxTTLSeconds
	}

	now := time.Now().UTC()
	jti := uuid.NewString()
	tid := uuid.NewString()

	h := sha256.Sum256([]byte(p.Instruction))
	intentHash := hex.EncodeToString(h[:])

	claims := &warrant.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.issuerURI,
			Subject:   "agent:" + p.AgentID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			ID:        jti,
		},
		TaskID:     tid,
		Depth:      0,
		Scope:      warrant.NormaliseScope(p.Scope),
		IntentHash: intentHash,
		Chain:      []string{jti},
		UserID:     p.UserID,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(is.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("signing: %w", err)
	}
	return signed, claims, nil
}

// Delegate issues a child credential by narrowing scope from the parent.
func (is *Issuer) Delegate(p warrant.DelegateParams, pubKey *rsa.PublicKey) (string, *warrant.Claims, error) {
	if p.ParentToken == "" {
		return "", nil, errors.New("parent_token is required")
	}
	if p.ChildAgent == "" {
		return "", nil, errors.New("child_agent is required")
	}
	if len(p.ChildScope) == 0 {
		return "", nil, errors.New("child_scope must not be empty")
	}

	// Verify parent token signature and expiry.
	parentClaims := &warrant.Claims{}
	_, err := jwt.ParseWithClaims(p.ParentToken, parentClaims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("invalid parent token: %w", err)
	}

	childScope := warrant.NormaliseScope(p.ChildScope)
	if !warrant.IsSubset(parentClaims.Scope, childScope) {
		return "", nil, errors.New("child scope is not a subset of parent scope")
	}
	if parentClaims.Depth >= warrant.MaxDelegationDepth {
		return "", nil, fmt.Errorf("delegation depth limit (%d) reached", warrant.MaxDelegationDepth)
	}

	now := time.Now().UTC()
	jti := uuid.NewString()

	// exp = min(requested TTL, parent expiry)
	parentExp := parentClaims.ExpiresAt.Time
	exp := parentExp
	if p.TTLSeconds > 0 {
		requested := now.Add(time.Duration(p.TTLSeconds) * time.Second)
		if requested.Before(parentExp) {
			exp = requested
		}
	}

	claims := &warrant.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.issuerURI,
			Subject:   "agent:" + p.ChildAgent,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
		TaskID:     parentClaims.TaskID,
		ParentID:   parentClaims.ID,
		Depth:      parentClaims.Depth + 1,
		Scope:      childScope,
		IntentHash: parentClaims.IntentHash,
		Chain:      append(append([]string{}, parentClaims.Chain...), jti),
		UserID:     parentClaims.UserID,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(is.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("signing: %w", err)
	}
	return signed, claims, nil
}

// Verify checks signature, expiry, chain length, and chain tail consistency.
func (is *Issuer) Verify(tokenString string, pubKey *rsa.PublicKey) (*warrant.VerifyResult, error) {
	claims := &warrant.Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return &warrant.VerifyResult{Valid: false}, fmt.Errorf("token verification failed: %w", err)
	}

	var warnings []string

	// Chain length must equal depth + 1 (root has depth 0, chain=[jti]).
	expectedLen := claims.Depth + 1
	if len(claims.Chain) != expectedLen {
		warnings = append(warnings, fmt.Sprintf(
			"chain length %d does not match depth %d (expected %d)",
			len(claims.Chain), claims.Depth, expectedLen,
		))
	}

	// Chain tail must match jti.
	if len(claims.Chain) > 0 && claims.Chain[len(claims.Chain)-1] != claims.ID {
		warnings = append(warnings, "chain tail does not match jti")
	}

	return &warrant.VerifyResult{
		Valid:    len(warnings) == 0,
		Claims:  claims,
		Warnings: warnings,
	}, nil
}
