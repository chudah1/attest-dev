package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer signs and verifies Attest credentials using RS256.
// It is stateless with respect to keys — the signing key is passed at call
// time so the same Issuer instance works for all organisations.
type Issuer struct {
	issuerURI string
}

// NewIssuer constructs an Issuer for the given issuer URI.
func NewIssuer(issuerURI string) *Issuer {
	return &Issuer{issuerURI: issuerURI}
}

// Issue creates a root credential (depth 0) signed with key.
func (is *Issuer) Issue(key *rsa.PrivateKey, kid string, p attest.IssueParams) (string, *attest.Claims, error) {
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
		if _, ok := attest.ParseScope(s); !ok {
			return "", nil, fmt.Errorf("invalid scope entry: %q", s)
		}
	}
	if p.Instruction == "" {
		return "", nil, errors.New("instruction is required")
	}

	ttl := p.TTLSeconds
	if ttl < 0 {
		return "", nil, errors.New("ttl_seconds must not be negative")
	}
	if ttl == 0 {
		ttl = attest.DefaultTTLSeconds
	} else if ttl > attest.MaxTTLSeconds {
		ttl = attest.MaxTTLSeconds
	}

	now := time.Now().UTC()
	jti := uuid.NewString()
	tid := uuid.NewString()

	h := sha256.Sum256([]byte(p.Instruction))
	intentHash := hex.EncodeToString(h[:])

	claims := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.issuerURI,
			Subject:   "agent:" + p.AgentID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			ID:        jti,
		},
		TaskID:        tid,
		Depth:         0,
		Scope:         attest.NormaliseScope(p.Scope),
		IntentHash:    intentHash,
		Chain:         []string{jti},
		UserID:        p.UserID,
		AgentChecksum: p.AgentChecksum,
		IDPIssuer:     p.VerifiedIDPIssuer,
		IDPSubject:    p.VerifiedIDPSubject,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", nil, fmt.Errorf("signing: %w", err)
	}
	return signed, claims, nil
}

// Delegate issues a child credential by narrowing scope from the parent.
// The parent token is verified against the org's public key (derived from key).
func (is *Issuer) Delegate(key *rsa.PrivateKey, kid string, p attest.DelegateParams) (string, *attest.Claims, error) {
	if p.ParentToken == "" {
		return "", nil, errors.New("parent_token is required")
	}
	if p.ChildAgent == "" {
		return "", nil, errors.New("child_agent is required")
	}
	if len(p.ChildScope) == 0 {
		return "", nil, errors.New("child_scope must not be empty")
	}

	pubKey := &key.PublicKey

	// Verify parent token signature and expiry.
	parentClaims := &attest.Claims{}
	_, err := jwt.ParseWithClaims(p.ParentToken, parentClaims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("invalid parent token: %w", err)
	}

	return is.DelegateVerified(key, kid, parentClaims, p)
}

// DelegateVerified issues a child credential from already-verified parent claims.
func (is *Issuer) DelegateVerified(key *rsa.PrivateKey, kid string, parentClaims *attest.Claims, p attest.DelegateParams) (string, *attest.Claims, error) {
	if parentClaims == nil {
		return "", nil, errors.New("parent claims are required")
	}

	childScope := attest.NormaliseScope(p.ChildScope)
	if !attest.IsSubset(parentClaims.Scope, childScope) {
		return "", nil, errors.New("child scope is not a subset of parent scope")
	}
	if parentClaims.Depth >= attest.MaxDelegationDepth {
		return "", nil, fmt.Errorf("delegation depth limit (%d) reached", attest.MaxDelegationDepth)
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
	} else {
		defaultExp := now.Add(time.Duration(attest.DefaultTTLSeconds) * time.Second)
		if defaultExp.Before(parentExp) {
			exp = defaultExp
		}
	}

	hitlReq := parentClaims.HITLRequestID
	if p.VerifiedHITLRequestID != nil {
		hitlReq = p.VerifiedHITLRequestID
	}
	hitlSub := parentClaims.HITLSubject
	if p.VerifiedHITLSubject != nil {
		hitlSub = p.VerifiedHITLSubject
	}
	hitlIss := parentClaims.HITLIssuer
	if p.VerifiedHITLIssuer != nil {
		hitlIss = p.VerifiedHITLIssuer
	}

	claims := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.issuerURI,
			Subject:   "agent:" + p.ChildAgent,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
		TaskID:        parentClaims.TaskID,
		ParentID:      parentClaims.ID,
		Depth:         parentClaims.Depth + 1,
		Scope:         childScope,
		IntentHash:    parentClaims.IntentHash,
		Chain:         append(append([]string{}, parentClaims.Chain...), jti),
		UserID:        parentClaims.UserID,
		AgentChecksum: parentClaims.AgentChecksum,
		IDPIssuer:     parentClaims.IDPIssuer,
		IDPSubject:    parentClaims.IDPSubject,
		HITLRequestID: hitlReq,
		HITLSubject:   hitlSub,
		HITLIssuer:    hitlIss,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", nil, fmt.Errorf("signing: %w", err)
	}
	return signed, claims, nil
}

// Verify checks signature, expiry, chain length, and chain tail consistency.
func (is *Issuer) Verify(tokenString string, pubKey *rsa.PublicKey) (*attest.VerifyResult, error) {
	claims := &attest.Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return &attest.VerifyResult{Valid: false}, fmt.Errorf("token verification failed: %w", err)
	}

	var warnings []string

	expectedLen := claims.Depth + 1
	if len(claims.Chain) != expectedLen {
		warnings = append(warnings, fmt.Sprintf(
			"chain length %d does not match depth %d (expected %d)",
			len(claims.Chain), claims.Depth, expectedLen,
		))
	}

	if len(claims.Chain) > 0 && claims.Chain[len(claims.Chain)-1] != claims.ID {
		warnings = append(warnings, "chain tail does not match jti")
	}

	return &attest.VerifyResult{
		Valid:    len(warnings) == 0,
		Claims:   claims,
		Warnings: warnings,
	}, nil
}
