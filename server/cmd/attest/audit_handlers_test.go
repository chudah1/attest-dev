package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/attest-dev/attest/internal/approval"
	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/evidence"
	"github.com/attest-dev/attest/internal/oidcauth"
	"github.com/attest-dev/attest/internal/org"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/internal/token"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/go-chi/chi/v5"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// testEnv is a complete in-memory server fixture for handler unit tests.
type testEnv struct {
	h       *handlers
	issuer  *token.Issuer
	orgID   string
	apiKey  string
	sigKey  *rsa.PrivateKey
	reverts []func()
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	orgStore, err := org.NewMemoryStore()
	if err != nil {
		t.Fatalf("new org store: %v", err)
	}
	iss := token.NewIssuer("https://attest.test")

	// CreateOrg returns (org, rawAPIKey, apiKeyMeta, err)
	o, rawKey, _, err := orgStore.CreateOrg(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	// Retrieve the auto-generated signing key so we can sign test tokens.
	orgKey, err := orgStore.GetSigningKey(context.Background(), o.ID)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}

	revStore := revocation.NewMemoryStore()
	auditLog := audit.NewMemoryLog()

	h := &handlers{
		issuer:      iss,
		orgStore:    orgStore,
		revStore:    revStore,
		auditLog:    auditLog,
		evidenceSvc: evidence.NewService(auditLog, revStore),
		oidcManager: oidcauth.NewManager(),
		appStore:    approval.NewMemoryStore(),
	}

	return &testEnv{
		h:      h,
		issuer: iss,
		orgID:  o.ID,
		apiKey: rawKey,
		sigKey: orgKey.PrivateKey,
	}
}

// issueToken mints a fresh root credential using the test env's signing key.
func (e *testEnv) issueToken(t *testing.T, scope []string) (tokenStr string, jti string) {
	t.Helper()
	_, claims, err := e.issuer.Issue(e.sigKey, "kid-test", attest.IssueParams{
		AgentID:     "test-agent",
		UserID:      "test-user",
		Scope:       scope,
		Instruction: "test instruction",
		TTLSeconds:  3600,
	})
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	// track in rev store so revocation tests work
	e.h.revStore.TrackCredential(context.Background(), e.orgID, claims)

	// Re-issue through issuer to get the real signed token string.
	tok, _, err := e.issuer.Issue(e.sigKey, "kid-test", attest.IssueParams{
		AgentID:     "test-agent",
		UserID:      "test-user",
		Scope:       scope,
		Instruction: "test instruction",
		TTLSeconds:  3600,
	})
	if err != nil {
		t.Fatalf("issueToken (string): %v", err)
	}
	// We need the jti of the *second* call — track it too.
	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	e.h.revStore.TrackCredential(context.Background(), e.orgID, result.Claims)
	return tok, result.Claims.ID
}

// makeRequest builds and executes an HTTP request through the Chi router.
func (e *testEnv) makeRequest(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", e.apiKey))

	rr := httptest.NewRecorder()

	// Build a minimal Chi router with auth middleware
	r := chi.NewRouter()
	r.Use(e.h.authMiddleware)
	r.Route("/v1", func(r chi.Router) {
		r.Post("/audit/report", e.h.reportAction)
		r.Post("/audit/status", e.h.reportStatus)
		r.Delete("/credentials/{jti}", e.h.revokeCredential)
		r.Get("/revoked/{jti}", e.h.checkRevocation)
		r.Get("/tasks/{tid}/report", e.h.getTaskReport)
	})

	r.ServeHTTP(rr, req)
	return rr
}

// ─── reportAction tests ───────────────────────────────────────────────────────

func TestReportAction_HappyPath(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "success",
		"meta":    map[string]string{"file": "/tmp/notes.txt"},
	})

	if rr.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

func TestReportAction_InvalidOutcome(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "banana", // not a valid enum value
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid outcome, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "outcome must be one of") {
		t.Errorf("expected enum error message, got: %s", rr.Body.String())
	}
}

func TestReportAction_MissingFields(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	cases := []map[string]any{
		{"token": tok, "tool": "read_file"},         // missing outcome
		{"token": tok, "outcome": "success"},        // missing tool
		{"tool": "read_file", "outcome": "success"}, // missing token
	}
	for _, body := range cases {
		rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body=%v: want 400, got %d", body, rr.Code)
		}
	}
}

func TestReportAction_RevokedCredential(t *testing.T) {
	e := newTestEnv(t)
	tok, jti := e.issueToken(t, []string{"files:read"})

	// Revoke the credential first.
	revRR := e.makeRequest(t, http.MethodDelete, "/v1/credentials/"+jti, map[string]string{"revoked_by": "test"})
	if revRR.Code != http.StatusNoContent {
		t.Fatalf("revoke failed: %d — %s", revRR.Code, revRR.Body.String())
	}

	// Attempt to report action with the now-revoked token.
	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "success",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("revoked credential should return 401, got %d — %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "revoked") {
		t.Errorf("expected revocation message, got: %s", rr.Body.String())
	}
}

func TestReportAction_InvalidToken(t *testing.T) {
	e := newTestEnv(t)

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   "not.a.jwt",
		"tool":    "read_file",
		"outcome": "success",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("invalid token should return 401, got %d", rr.Code)
	}
}

func TestReportAction_AgentIDStrippedOfPrefix(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	// Parse the token to get the task ID for log querying.
	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "success",
	})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — %s", rr.Code, rr.Body.String())
	}

	// Check the audit log entry has a bare agent ID (no "agent:" prefix).
	events, err := e.h.auditLog.Query(context.Background(), e.orgID, taskID)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	lastEvent := events[len(events)-1]
	if strings.HasPrefix(lastEvent.AgentID, "agent:") {
		t.Errorf("AgentID should NOT have 'agent:' prefix, got: %s", lastEvent.AgentID)
	}
}

func TestGetTaskReport_HTML(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rrAction := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "success",
	})
	if rrAction.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from audit report, got %d — %s", rrAction.Code, rrAction.Body.String())
	}

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/report", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from task report, got %d — %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected text/html content type, got %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "Agent Authorization Evidence Report") {
		t.Fatalf("expected report heading in body")
	}
	if !strings.Contains(rr.Body.String(), taskID) {
		t.Fatalf("expected task id in report body")
	}
}

func TestGetTaskReport_TemplateQuery(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/report?template=soc2", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from task report, got %d — %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "SOC 2 Control Evidence") {
		t.Fatalf("expected soc2 template content in body")
	}
}

// ─── reportStatus tests ───────────────────────────────────────────────────────

func TestReportStatus_HappyPath(t *testing.T) {
	statuses := []string{"started", "completed", "failed"}
	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			e := newTestEnv(t)
			tok, _ := e.issueToken(t, []string{"files:read"})

			rr := e.makeRequest(t, http.MethodPost, "/v1/audit/status", map[string]any{
				"token":  tok,
				"status": status,
			})

			if rr.Code != http.StatusNoContent {
				t.Errorf("status=%s: want 204, got %d — %s", status, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestReportStatus_InvalidStatus(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/status", map[string]any{
		"token":  tok,
		"status": "running", // not a valid value
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid status, got %d", rr.Code)
	}
}

func TestReportStatus_MissingFields(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	cases := []map[string]any{
		{"token": tok},        // missing status
		{"status": "started"}, // missing token
	}
	for _, body := range cases {
		rr := e.makeRequest(t, http.MethodPost, "/v1/audit/status", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body=%v: want 400, got %d", body, rr.Code)
		}
	}
}

func TestReportStatus_RevokedCredential(t *testing.T) {
	e := newTestEnv(t)
	tok, jti := e.issueToken(t, []string{"files:read"})

	// Revoke first.
	revRR := e.makeRequest(t, http.MethodDelete, "/v1/credentials/"+jti, map[string]string{"revoked_by": "test"})
	if revRR.Code != http.StatusNoContent {
		t.Fatalf("revoke failed: %d", revRR.Code)
	}

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/status", map[string]any{
		"token":  tok,
		"status": "completed",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("revoked credential should return 401, got %d", rr.Code)
	}
}

func TestReportStatus_WithMeta(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/status", map[string]any{
		"token":  tok,
		"status": "failed",
		"meta":   map[string]string{"error": "context deadline exceeded", "retries": "3"},
	})

	if rr.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d — %s", rr.Code, rr.Body.String())
	}
}
