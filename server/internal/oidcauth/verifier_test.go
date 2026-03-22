package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// encodeBase64URL encodes bytes as unpadded base64url.
func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func setupMockIdP(t *testing.T) (*httptest.Server, *rsa.PrivateKey, string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keyID := "test-key-id"

	mux := http.NewServeMux()
	
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                             serverURL,
			"jwks_uri":                           serverURL + "/keys",
			"response_types_supported":           []string{"id_token"},
			"subject_types_supported":            []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := &privKey.PublicKey
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": keyID,
					"n":   encodeBase64URL(pub.N.Bytes()),
					"e":   encodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		})
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	return server, privKey, keyID
}

func TestVerifyToken_Success(t *testing.T) {
	server, privKey, kid := setupMockIdP(t)
	defer server.Close()

	clientID := "test-client-id"
	subject := "user_12345"
	email := "test@example.com"

	// Create a valid JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   server.URL,
		"sub":   subject,
		"aud":   clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": email,
	})
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	manager := NewManager()
	ctx := context.Background()

	claims, err := manager.VerifyToken(ctx, server.URL, clientID, tokenString)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if claims.Issuer != server.URL {
		t.Errorf("expected issuer %q, got %q", server.URL, claims.Issuer)
	}
	if claims.Subject != subject {
		t.Errorf("expected subject %q, got %q", subject, claims.Subject)
	}
	if claims.Email != email {
		t.Errorf("expected email %q, got %q", email, claims.Email)
	}
}

func TestVerifyToken_InvalidSignature(t *testing.T) {
	server, _, kid := setupMockIdP(t)
	defer server.Close()

	// Generate a DIFFERENT private key
	badPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	clientID := "test-client-id"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": server.URL,
		"sub": "user_123",
		"aud": clientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = kid
	tokenString, _ := token.SignedString(badPrivKey)

	manager := NewManager()
	ctx := context.Background()

	_, err := manager.VerifyToken(ctx, server.URL, clientID, tokenString)
	if err == nil {
		t.Fatal("expected signature validation error, got nil")
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	server, privKey, kid := setupMockIdP(t)
	defer server.Close()

	clientID := "test-client-id"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": server.URL,
		"sub": "user_123",
		"aud": clientID,
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
	})
	token.Header["kid"] = kid
	tokenString, _ := token.SignedString(privKey)

	manager := NewManager()
	ctx := context.Background()

	_, err := manager.VerifyToken(ctx, server.URL, clientID, tokenString)
	if err == nil {
		t.Fatal("expected expiration error, got nil")
	}
}
