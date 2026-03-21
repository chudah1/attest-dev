package main

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/internal/token"
	"github.com/attest-dev/attest/pkg/attest"
)

type orgCtxKey struct{}

type handlers struct {
	issuer   *token.Issuer
	orgStore org.Store
	revStore revocation.Revoker
	auditLog audit.Logger
}

// authMiddleware resolves the Bearer API key to an org and injects it into context.
func (h *handlers) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		rawKey := strings.TrimPrefix(authHeader, "Bearer ")
		o, err := h.orgStore.ResolveAPIKey(r.Context(), rawKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		ctx := context.WithValue(r.Context(), orgCtxKey{}, o)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func orgFromCtx(ctx context.Context) *org.Org {
	o, _ := ctx.Value(orgCtxKey{}).(*org.Org)
	return o
}

// corsMiddleware allows browser requests from the dashboard.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GET /v1/org
func (h *handlers) getOrg(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	writeJSON(w, http.StatusOK, o)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// POST /v1/orgs — create a new organisation (unauthenticated signup).
func (h *handlers) signup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	o, rawKey, apiKey, err := h.orgStore.CreateOrg(r.Context(), body.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create org: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"org":     o,
		"api_key": rawKey,
		"key_id":  apiKey.ID,
	})
}

// POST /v1/credentials
func (h *handlers) issueCredential(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	var p attest.IssueParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	orgKey, err := h.orgStore.GetSigningKey(r.Context(), o.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get signing key: "+err.Error())
		return
	}

	tok, claims, err := h.issuer.Issue(orgKey.PrivateKey, orgKey.KeyID, p)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	h.revStore.TrackCredential(claims.ID, claims.Chain)

	_ = h.auditLog.Append(r.Context(), attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       claims.ID,
		TaskID:    claims.TaskID,
		UserID:    claims.UserID,
		AgentID:   p.AgentID,
		Scope:     claims.Scope,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  tok,
		"claims": claims,
	})
}

// POST /v1/credentials/delegate
func (h *handlers) delegateCredential(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	var p attest.DelegateParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	orgKey, err := h.orgStore.GetSigningKey(r.Context(), o.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get signing key: "+err.Error())
		return
	}

	tok, claims, err := h.issuer.Delegate(orgKey.PrivateKey, orgKey.KeyID, p)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	h.revStore.TrackCredential(claims.ID, claims.Chain)

	_ = h.auditLog.Append(r.Context(), attest.AuditEvent{
		EventType: attest.EventDelegated,
		JTI:       claims.ID,
		TaskID:    claims.TaskID,
		UserID:    claims.UserID,
		AgentID:   p.ChildAgent,
		Scope:     claims.Scope,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  tok,
		"claims": claims,
	})
}

// DELETE /v1/credentials/{jti}
func (h *handlers) revokeCredential(w http.ResponseWriter, r *http.Request) {
	jti := chi.URLParam(r, "jti")
	if jti == "" {
		writeError(w, http.StatusBadRequest, "jti path parameter required")
		return
	}

	var body struct {
		RevokedBy string `json:"revoked_by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.RevokedBy == "" {
		body.RevokedBy = "unknown"
	}

	if err := h.revStore.Revoke(r.Context(), jti, body.RevokedBy); err != nil {
		writeError(w, http.StatusInternalServerError, "revocation failed: "+err.Error())
		return
	}

	_ = h.auditLog.Append(r.Context(), attest.AuditEvent{
		EventType: attest.EventRevoked,
		JTI:       jti,
		Meta:      map[string]string{"revoked_by": body.RevokedBy},
	})

	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/revoked/{jti}
func (h *handlers) checkRevocation(w http.ResponseWriter, r *http.Request) {
	jti := chi.URLParam(r, "jti")
	revoked, err := h.revStore.IsRevoked(r.Context(), jti)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": revoked})
}

// GET /v1/tasks/{tid}/audit
func (h *handlers) getAuditLog(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")
	events, err := h.auditLog.Query(r.Context(), tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []attest.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// GET /orgs/{orgID}/jwks.json — public, returns the org's active RSA public key as JWKS.
func (h *handlers) jwks(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	orgKey, err := h.orgStore.GetSigningKey(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "org not found")
		return
	}

	pub := &orgKey.PrivateKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": orgKey.KeyID,
				"n":   encodeBase64URL(nBytes),
				"e":   encodeBase64URL(eBytes),
			},
		},
	})
}

// GET /health
func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// encodeBase64URL encodes bytes as unpadded base64url (RFC 7518 §2).
func encodeBase64URL(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		remaining := len(b) - i
		var b0, b1, b2 byte
		b0 = b[i]
		if remaining > 1 {
			b1 = b[i+1]
		}
		if remaining > 2 {
			b2 = b[i+2]
		}
		out = append(out,
			alphabet[b0>>2],
			alphabet[(b0&0x03)<<4|b1>>4],
		)
		if remaining > 1 {
			out = append(out, alphabet[(b1&0x0f)<<2|b2>>6])
		}
		if remaining > 2 {
			out = append(out, alphabet[b2&0x3f])
		}
	}
	return string(out)
}
