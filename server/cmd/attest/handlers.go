package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/evidence"
	"github.com/attest-dev/attest/internal/oidcauth"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/internal/token"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type orgCtxKey struct{}
type apiKeyIDCtxKey struct{}

type handlers struct {
	issuer      *token.Issuer
	orgStore    org.Store
	revStore    revocation.Revoker
	auditLog    audit.Logger
	evidenceSvc *evidence.Service
	oidcManager *oidcauth.Manager
	appStore    approval.Store
}

func keyIDFromToken(token string) string {
	parser := new(jwt.Parser)
	parsed, _, err := parser.ParseUnverified(token, &attest.Claims{})
	if err != nil || parsed == nil {
		return ""
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

func reorderOrgKeysByKID(keys []*org.OrgKey, kid string) []*org.OrgKey {
	if kid == "" || len(keys) < 2 {
		return keys
	}

	out := make([]*org.OrgKey, 0, len(keys))
	for _, key := range keys {
		if key.KeyID == kid {
			out = append(out, key)
		}
	}
	for _, key := range keys {
		if key.KeyID != kid {
			out = append(out, key)
		}
	}
	return out
}

func (h *handlers) verifyTokenForOrg(ctx context.Context, orgID, rawToken string) (*attest.VerifyResult, error) {
	orgKeys, err := h.orgStore.ListSigningKeys(ctx, orgID)
	if err != nil {
		return nil, err
	}

	kid := keyIDFromToken(rawToken)
	for _, orgKey := range reorderOrgKeysByKID(orgKeys, kid) {
		result, err := h.issuer.Verify(rawToken, &orgKey.PrivateKey.PublicKey)
		if err == nil && result != nil && result.Valid {
			return result, nil
		}
	}

	return nil, errors.New("token verification failed")
}

// authMiddleware resolves the Bearer API key to an org and injects both the
// org and the resolved API key ID into context.
func (h *handlers) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		rawKey := strings.TrimPrefix(authHeader, "Bearer ")
		o, ak, err := h.orgStore.ResolveAPIKey(r.Context(), rawKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		ctx := context.WithValue(r.Context(), orgCtxKey{}, o)
		ctx = context.WithValue(ctx, apiKeyIDCtxKey{}, ak.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func orgFromCtx(ctx context.Context) *org.Org {
	o, _ := ctx.Value(orgCtxKey{}).(*org.Org)
	return o
}

func apiKeyIDFromCtx(ctx context.Context) string {
	id, _ := ctx.Value(apiKeyIDCtxKey{}).(string)
	return id
}

// corsMiddleware allows browser requests from the dashboard.
func corsMiddleware(next http.Handler) http.Handler {
	allowed := os.Getenv("CORS_ORIGIN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost" || strings.HasPrefix(origin, "http://localhost:") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else if allowed != "" && origin == allowed {
			w.Header().Set("Access-Control-Allow-Origin", allowed)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
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

// PATCH /v1/org
func (h *handlers) updateOrg(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	var body struct {
		RequireIDP   *bool   `json:"require_idp"`
		IDPIssuerURL *string `json:"idp_issuer_url"`
		IDPClientID  *string `json:"idp_client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Use existing values if not provided in the patch request.
	requireIDP := o.RequireIDP
	if body.RequireIDP != nil {
		requireIDP = *body.RequireIDP
	}
	issuerURL := o.IDPIssuerURL
	if body.IDPIssuerURL != nil {
		if *body.IDPIssuerURL == "" {
			issuerURL = nil
		} else {
			issuerURL = body.IDPIssuerURL
		}
	}
	clientID := o.IDPClientID
	if body.IDPClientID != nil {
		if *body.IDPClientID == "" {
			clientID = nil
		} else {
			clientID = body.IDPClientID
		}
	}

	if requireIDP && (issuerURL == nil || clientID == nil) {
		writeError(w, http.StatusBadRequest, "require_idp requires both idp_issuer_url and idp_client_id to be set")
		return
	}

	if err := h.orgStore.UpdateOrg(r.Context(), o.ID, requireIDP, issuerURL, clientID); err != nil {
		writeInternalError(w, "update org", err)
		return
	}

	o.RequireIDP = requireIDP
	o.IDPIssuerURL = issuerURL
	o.IDPClientID = clientID

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

func writeInternalError(w http.ResponseWriter, msg string, err error) {
	slog.Error(msg, "err", err)
	writeError(w, http.StatusInternalServerError, msg)
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
		writeInternalError(w, "create org", err)
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

	if o.RequireIDP && p.IDToken == "" {
		writeError(w, http.StatusUnauthorized, "strict mode enabled: id_token required")
		return
	}

	if p.IDToken != "" {
		if o.IDPIssuerURL == nil || o.IDPClientID == nil {
			writeError(w, http.StatusPreconditionFailed, "org missing idp configuration")
			return
		}

		claims, err := h.oidcManager.VerifyToken(r.Context(), *o.IDPIssuerURL, *o.IDPClientID, p.IDToken)
		if err != nil {
			if errors.Is(err, oidcauth.ErrProviderUnavailable) {
				writeError(w, http.StatusBadGateway, "identity provider unreachable: "+err.Error())
			} else {
				writeError(w, http.StatusUnauthorized, "invalid id_token: "+err.Error())
			}
			return
		}

		p.VerifiedIDPIssuer = &claims.Issuer
		p.VerifiedIDPSubject = &claims.Subject
	}

	orgKey, err := h.orgStore.GetSigningKey(r.Context(), o.ID)
	if err != nil {
		writeInternalError(w, "get signing key", err)
		return
	}

	tok, claims, err := h.issuer.Issue(orgKey.PrivateKey, orgKey.KeyID, p)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.revStore.TrackCredential(r.Context(), o.ID, claims); err != nil {
		writeInternalError(w, "track credential", err)
		return
	}

	if err := h.auditLog.Append(r.Context(), o.ID, attest.AuditEvent{
		EventType:     attest.EventIssued,
		JTI:           claims.ID,
		TaskID:        claims.TaskID,
		UserID:        claims.UserID,
		AgentID:       p.AgentID,
		Scope:         claims.Scope,
		IDPIssuer:     claims.IDPIssuer,
		IDPSubject:    claims.IDPSubject,
		HITLRequestID: claims.HITLRequestID,
		HITLSubject:   claims.HITLSubject,
		HITLIssuer:    claims.HITLIssuer,
	}); err != nil {
		http.Error(w, `{"error":"audit log unavailable"}`, http.StatusInternalServerError)
		return
	}

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

	parentResult, err := h.verifyTokenForOrg(r.Context(), o.ID, p.ParentToken)
	if err != nil || parentResult == nil || !parentResult.Valid {
		writeError(w, http.StatusUnprocessableEntity, "invalid parent token")
		return
	}

	orgKey, err := h.orgStore.GetSigningKey(r.Context(), o.ID)
	if err != nil {
		writeInternalError(w, "get signing key", err)
		return
	}

	tok, claims, err := h.issuer.DelegateVerified(orgKey.PrivateKey, orgKey.KeyID, parentResult.Claims, p)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.revStore.TrackCredential(r.Context(), o.ID, claims); err != nil {
		writeInternalError(w, "track credential", err)
		return
	}

	if err := h.auditLog.Append(r.Context(), o.ID, attest.AuditEvent{
		EventType:     attest.EventDelegated,
		JTI:           claims.ID,
		TaskID:        claims.TaskID,
		UserID:        claims.UserID,
		AgentID:       p.ChildAgent,
		Scope:         claims.Scope,
		IDPIssuer:     claims.IDPIssuer,
		IDPSubject:    claims.IDPSubject,
		HITLRequestID: claims.HITLRequestID,
		HITLSubject:   claims.HITLSubject,
		HITLIssuer:    claims.HITLIssuer,
	}); err != nil {
		http.Error(w, `{"error":"audit log unavailable"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  tok,
		"claims": claims,
	})
}

// DELETE /v1/credentials/{jti}
func (h *handlers) revokeCredential(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
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

	cred, err := h.revStore.GetCredential(r.Context(), o.ID, jti)
	if err != nil {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}

	if err := h.revStore.Revoke(r.Context(), o.ID, jti, body.RevokedBy); err != nil {
		writeInternalError(w, "revocation failed", err)
		return
	}

	if err := h.auditLog.Append(r.Context(), o.ID, attest.AuditEvent{
		EventType: attest.EventRevoked,
		JTI:       jti,
		TaskID:    cred.TaskID,
		UserID:    cred.UserID,
		AgentID:   cred.AgentID,
		Scope:     append([]string(nil), cred.Scope...),
		Meta:      map[string]string{"revoked_by": body.RevokedBy},
	}); err != nil {
		http.Error(w, `{"error":"audit log unavailable"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/revoked/{jti}
func (h *handlers) checkRevocation(w http.ResponseWriter, r *http.Request) {
	// This is a public endpoint (no authMiddleware). orgFromCtx will return nil.
	// Since JTIs are high-entropy UUIDs (122 bits), they act as capability URLs.
	jti := chi.URLParam(r, "jti")
	// Pass an empty string for orgID. The store must implement a global lookup for this public endpoint.
	revoked, err := h.revStore.IsRevoked(r.Context(), "", jti)
	if err != nil {
		writeInternalError(w, "check revocation", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": revoked})
}

// GET /v1/tasks/{tid}/audit
func (h *handlers) getAuditLog(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	tid := chi.URLParam(r, "tid")
	events, err := h.auditLog.Query(r.Context(), o.ID, tid)
	if err != nil {
		writeInternalError(w, "query audit log", err)
		return
	}
	if events == nil {
		events = []attest.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *handlers) buildSignedTaskEvidence(ctx context.Context, o *org.Org, tid string) (*attest.EvidencePacket, error) {
	packet, err := h.evidenceSvc.BuildTaskEvidence(ctx, o.ID, o.Name, tid)
	if err != nil {
		return nil, err
	}

	orgKey, err := h.orgStore.GetSigningKey(ctx, o.ID)
	if err != nil {
		return nil, err
	}
	if err := evidence.SignPacket(packet, orgKey.PrivateKey, orgKey.KeyID); err != nil {
		return nil, err
	}

	return packet, nil
}

// GET /v1/tasks/{tid}/evidence
func (h *handlers) getTaskEvidence(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	tid := chi.URLParam(r, "tid")
	packet, err := h.buildSignedTaskEvidence(r.Context(), o, tid)
	if err != nil {
		writeInternalError(w, "build task evidence", err)
		return
	}
	writeJSON(w, http.StatusOK, packet)
}

// GET /v1/tasks/{tid}/report
func (h *handlers) getTaskReport(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	tid := chi.URLParam(r, "tid")
	packet, err := h.buildSignedTaskEvidence(r.Context(), o, tid)
	if err != nil {
		writeInternalError(w, "build task evidence", err)
		return
	}

	reportHTML, err := evidence.RenderTaskReport(packet, evidence.ReportOptions{
		Template: evidence.ReportTemplate(r.URL.Query().Get("template")),
	})
	if err != nil {
		writeInternalError(w, "render task report", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(reportHTML)
}

// GET /orgs/{orgID}/jwks.json — public, returns the org's current and historical
// RSA public keys as JWKS so previously signed artifacts remain verifiable.
func (h *handlers) jwks(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	orgKeys, err := h.orgStore.ListSigningKeys(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "org not found")
		return
	}

	keys := make([]map[string]any, 0, len(orgKeys))
	for _, orgKey := range orgKeys {
		pub := &orgKey.PrivateKey.PublicKey
		nBytes := pub.N.Bytes()
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": orgKey.KeyID,
			"n":   encodeBase64URL(nBytes),
			"e":   encodeBase64URL(eBytes),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": keys,
	})
}

// GET /health
func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /v1/org/keys — list all API keys for the authenticated org.
func (h *handlers) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	keys, err := h.orgStore.ListAPIKeys(r.Context(), o.ID)
	if err != nil {
		writeInternalError(w, "list api keys", err)
		return
	}
	if keys == nil {
		keys = []*org.APIKey{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// POST /v1/org/keys — create a new API key for the authenticated org.
func (h *handlers) createAPIKey(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	ak, rawKey, err := h.orgStore.CreateAPIKey(r.Context(), o.ID, body.Name)
	if err != nil {
		writeInternalError(w, "create api key", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"api_key": rawKey,
		"key_id":  ak.ID,
	})
}

// DELETE /v1/org/keys/{keyID} — revoke a specific API key.
func (h *handlers) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	keyID := chi.URLParam(r, "keyID")

	// Prevent revoking the key currently used to authenticate this request.
	if keyID == apiKeyIDFromCtx(r.Context()) {
		writeError(w, http.StatusBadRequest, "cannot revoke the key used to authenticate this request")
		return
	}

	if err := h.orgStore.RevokeAPIKey(r.Context(), o.ID, keyID); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			writeError(w, http.StatusNotFound, "api key not found")
			return
		}
		writeInternalError(w, "revoke api key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/org/keys/rotate — rotate the org's RSA signing key.
func (h *handlers) rotateKey(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	newKey, err := h.orgStore.RotateSigningKey(r.Context(), o.ID)
	if err != nil {
		writeInternalError(w, "rotate signing key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"kid": newKey.KeyID})
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

// POST /v1/approvals — called by the Agent/SDK to request human approval.
func (h *handlers) requestApproval(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	_ = o // ensure org is authenticated

	var body struct {
		AgentID        string   `json:"agent_id"`
		TaskID         string   `json:"att_tid"`
		ParentToken    string   `json:"parent_token"`
		Intent         string   `json:"intent"`
		RequestedScope []string `json:"requested_scope"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Basic validation
	if body.AgentID == "" || body.TaskID == "" || len(body.RequestedScope) == 0 {
		writeError(w, http.StatusBadRequest, "missing required fields (agent_id, att_tid, requested_scope)")
		return
	}
	if len(body.Intent) > 2000 {
		writeError(w, http.StatusBadRequest, "intent exceeds maximum length of 2000 characters")
		return
	}
	if len(body.RequestedScope) > 50 {
		writeError(w, http.StatusBadRequest, "requested_scope contains too many items (max 50)")
		return
	}
	for _, s := range body.RequestedScope {
		if len(s) > 200 {
			writeError(w, http.StatusBadRequest, "a scope item exceeds maximum length of 200 characters")
			return
		}
	}

	challengeID := "hitl_" + uuid.NewString()

	req := approval.ApprovalRequest{
		ID:             challengeID,
		OrgID:          o.ID,
		AgentID:        body.AgentID,
		TaskID:         body.TaskID,
		ParentToken:    body.ParentToken,
		Intent:         body.Intent,
		RequestedScope: body.RequestedScope,
	}

	if err := h.appStore.RequestApproval(r.Context(), req); err != nil {
		writeInternalError(w, "failed to store approval request", err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"challenge_id": challengeID,
		"status":       "pending",
	})
}

// GET /v1/approvals/{id} — called by the Agent/SDK to poll approval status.
func (h *handlers) getApproval(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	challengeID := chi.URLParam(r, "id")
	if challengeID == "" {
		writeError(w, http.StatusBadRequest, "challenge id required")
		return
	}

	req, err := h.appStore.Get(r.Context(), o.ID, challengeID)
	if err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval request not found")
			return
		}
		writeInternalError(w, "failed to fetch approval", err)
		return
	}

	// Don't expose the parent_token in the polling response.
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              req.ID,
		"agent_id":        req.AgentID,
		"att_tid":         req.TaskID,
		"intent":          req.Intent,
		"requested_scope": req.RequestedScope,
		"status":          req.Status,
		"approved_by":     req.ApprovedBy,
		"created_at":      req.CreatedAt,
		"resolved_at":     req.ResolvedAt,
	})
}

// POST /v1/approvals/{id}/deny — called by Dashboard/Slack to reject an approval.
func (h *handlers) denyApproval(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	challengeID := chi.URLParam(r, "id")
	if challengeID == "" {
		writeError(w, http.StatusBadRequest, "challenge id required")
		return
	}

	// Verify the approval belongs to this org before resolving.
	if _, err := h.appStore.Get(r.Context(), o.ID, challengeID); err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval request not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to fetch approval")
		return
	}

	if err := h.appStore.Resolve(r.Context(), o.ID, challengeID, approval.StatusRejected, ""); err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval request not found or not pending")
			return
		}
		writeInternalError(w, "failed to deny approval", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":     challengeID,
		"status": string(approval.StatusRejected),
	})
}

// POST /v1/approvals/{id}/grant — called by Dashboard/Slack when the human approves via IdP token.
func (h *handlers) grantApproval(w http.ResponseWriter, r *http.Request) {
	o := orgFromCtx(r.Context())
	challengeID := chi.URLParam(r, "id")

	if challengeID == "" {
		writeError(w, http.StatusBadRequest, "challenge id required")
		return
	}

	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	var verifiedSubject, verifiedIssuer string

	if o.IDPIssuerURL != nil && o.IDPClientID != nil {
		if body.IDToken == "" {
			writeError(w, http.StatusBadRequest, "id_token is required when IdP is configured")
			return
		}
		verifiedClaims, err := h.oidcManager.VerifyToken(r.Context(), *o.IDPIssuerURL, *o.IDPClientID, body.IDToken)
		if err != nil {
			if errors.Is(err, oidcauth.ErrProviderUnavailable) {
				writeError(w, http.StatusBadGateway, "identity provider unreachable")
			} else {
				writeError(w, http.StatusUnauthorized, "invalid id_token")
			}
			return
		}
		verifiedSubject = verifiedClaims.Subject
		verifiedIssuer = verifiedClaims.Issuer
	} else {
		// Fallback for local dev environments where IdP isn't configured
		verifiedSubject = "dev_approver_1"
		verifiedIssuer = "local_dashboard_session"
	}

	// Fetch the pending request (scoped to this org)
	pending, err := h.appStore.GetPending(r.Context(), o.ID, challengeID)
	if err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval request not found or not pending")
			return
		}
		writeInternalError(w, "failed to fetch approval", err)
		return
	}

	// Pre-check: verify the parent token hasn't expired while waiting for approval.
	orgKey, err := h.orgStore.GetSigningKey(r.Context(), o.ID)
	if err != nil {
		writeInternalError(w, "get signing key", err)
		return
	}

	parentResult, err := h.verifyTokenForOrg(r.Context(), o.ID, pending.ParentToken)
	if err != nil || !parentResult.Valid {
		// Parent token expired or invalid — reject the approval automatically.
		_ = h.appStore.Resolve(r.Context(), o.ID, challengeID, approval.StatusRejected, "system:parent_expired")
		writeError(w, http.StatusGone, "parent token expired while waiting for approval")
		return
	}

	// Check there's enough remaining TTL to be useful (at least 30 seconds).
	if parentResult.Claims.ExpiresAt != nil && time.Until(parentResult.Claims.ExpiresAt.Time) < 30*time.Second {
		_ = h.appStore.Resolve(r.Context(), o.ID, challengeID, approval.StatusRejected, "system:parent_expiring")
		writeError(w, http.StatusGone, "parent token expires in less than 30 seconds, approval too late")
		return
	}

	// Mark it resolved.
	if err := h.appStore.Resolve(r.Context(), o.ID, challengeID, approval.StatusApproved, verifiedSubject); err != nil {
		writeInternalError(w, "failed to update approval status", err)
		return
	}

	dp := attest.DelegateParams{
		ParentToken: pending.ParentToken,
		ChildAgent:  pending.AgentID,
		ChildScope:  pending.RequestedScope,
	}

	// Inject the human signature bounds
	dp.VerifiedHITLRequestID = &challengeID
	dp.VerifiedHITLSubject = &verifiedSubject
	dp.VerifiedHITLIssuer = &verifiedIssuer

	tok, claims, err := h.issuer.DelegateVerified(orgKey.PrivateKey, orgKey.KeyID, parentResult.Claims, dp)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "failed to issue hitl credential: "+err.Error())
		return
	}

	if err := h.revStore.TrackCredential(r.Context(), o.ID, claims); err != nil {
		writeInternalError(w, "track credential", err)
		return
	}

	if err := h.auditLog.Append(r.Context(), o.ID, attest.AuditEvent{
		EventType:     "hitl_granted",
		JTI:           claims.ID,
		TaskID:        claims.TaskID,
		UserID:        claims.UserID,
		AgentID:       pending.AgentID,
		Scope:         claims.Scope,
		IDPIssuer:     claims.IDPIssuer,
		IDPSubject:    claims.IDPSubject,
		HITLRequestID: claims.HITLRequestID,
		HITLSubject:   claims.HITLSubject,
		HITLIssuer:    claims.HITLIssuer,
	}); err != nil {
		http.Error(w, `{"error":"audit log unavailable"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":  tok,
		"claims": claims,
	})
}

// verifyCred validates a token against the org's signing key and writes an error if invalid.
// Also checks the revocation store — revoked credentials are rejected.
// Returns the verified claims, or nil if the response was already written.
func (h *handlers) verifyCred(w http.ResponseWriter, r *http.Request, token string) *attest.Claims {
	o := orgFromCtx(r.Context())
	result, err := h.verifyTokenForOrg(r.Context(), o.ID, token)
	if err != nil || result == nil || !result.Valid {
		writeError(w, http.StatusUnauthorized, "invalid or expired credential")
		return nil
	}
	// Reject revoked credentials.
	if revoked, _ := h.revStore.IsRevoked(r.Context(), o.ID, result.Claims.ID); revoked {
		writeError(w, http.StatusUnauthorized, "credential has been revoked")
		return nil
	}
	return result.Claims
}

// appendAudit writes an audit event derived from verified claims.
func (h *handlers) appendAudit(w http.ResponseWriter, r *http.Request, eventType attest.EventType, claims *attest.Claims, meta map[string]string) bool {
	o := orgFromCtx(r.Context())
	// Strip the "agent:" prefix so the stored agent_id is the bare identifier.
	agentID := strings.TrimPrefix(claims.Subject, "agent:")
	if err := h.auditLog.Append(r.Context(), o.ID, attest.AuditEvent{
		EventType:     eventType,
		JTI:           claims.ID,
		TaskID:        claims.TaskID,
		UserID:        claims.UserID,
		AgentID:       agentID,
		Scope:         claims.Scope,
		Meta:          meta,
		IDPIssuer:     claims.IDPIssuer,
		IDPSubject:    claims.IDPSubject,
		HITLRequestID: claims.HITLRequestID,
		HITLSubject:   claims.HITLSubject,
		HITLIssuer:    claims.HITLIssuer,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit log unavailable")
		return false
	}
	return true
}

// POST /v1/audit/report — agents/gateways report action outcomes against a credential.
func (h *handlers) reportAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token   string            `json:"token"`
		Tool    string            `json:"tool"`
		Outcome string            `json:"outcome"`
		Meta    map[string]string `json:"meta,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.Token == "" || body.Tool == "" || body.Outcome == "" {
		writeError(w, http.StatusBadRequest, "token, tool, and outcome are required")
		return
	}
	validOutcomes := map[string]bool{"success": true, "failure": true, "error": true, "skipped": true}
	if !validOutcomes[body.Outcome] {
		writeError(w, http.StatusBadRequest, "outcome must be one of: success, failure, error, skipped")
		return
	}

	claims := h.verifyCred(w, r, body.Token)
	if claims == nil {
		return
	}

	meta := body.Meta
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["tool"] = body.Tool
	meta["outcome"] = body.Outcome

	if h.appendAudit(w, r, attest.EventAction, claims, meta) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// POST /v1/audit/status — agents report lifecycle events (started, completed, failed).
func (h *handlers) reportStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token  string            `json:"token"`
		Status string            `json:"status"`
		Meta   map[string]string `json:"meta,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.Token == "" || body.Status == "" {
		writeError(w, http.StatusBadRequest, "token and status are required")
		return
	}

	validStatuses := map[string]bool{"started": true, "completed": true, "failed": true}
	if !validStatuses[body.Status] {
		writeError(w, http.StatusBadRequest, "status must be one of: started, completed, failed")
		return
	}

	claims := h.verifyCred(w, r, body.Token)
	if claims == nil {
		return
	}

	meta := body.Meta
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["status"] = body.Status

	if h.appendAudit(w, r, attest.EventLifecycle, claims, meta) {
		w.WriteHeader(http.StatusNoContent)
	}
}
