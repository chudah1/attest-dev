package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		r.Post("/credentials/delegate", e.h.delegateCredential)
		r.Post("/audit/report", e.h.reportAction)
		r.Post("/audit/status", e.h.reportStatus)
		r.Delete("/credentials/{jti}", e.h.revokeCredential)
		r.Get("/revoked/{jti}", e.h.checkRevocation)
		r.Get("/tasks", e.h.listTasks)
		r.Get("/tasks/{tid}/evidence", e.h.getTaskEvidence)
		r.Get("/tasks/{tid}/report", e.h.getTaskReport)
	})

	r.ServeHTTP(rr, req)
	return rr
}

func (e *testEnv) makePublicRequest(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Get("/orgs/{orgID}/jwks.json", e.h.jwks)
	r.ServeHTTP(rr, req)
	return rr
}

func jwksPublicKeyForKID(t *testing.T, body []byte, kid string) *rsa.PublicKey {
	t.Helper()

	var payload struct {
		Keys []struct {
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	for _, key := range payload.Keys {
		if key.KID != kid {
			continue
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			t.Fatalf("decode jwks modulus: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			t.Fatalf("decode jwks exponent: %v", err)
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}

	t.Fatalf("jwks missing kid %q", kid)
	return nil
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
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

func TestReportAction_HistoricalSigningKeyStillAccepted(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	if _, err := e.h.orgStore.RotateSigningKey(context.Background(), e.orgID); err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}

	rr := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   tok,
		"tool":    "read_file",
		"outcome": "success",
	})

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 with historical signing key, got %d — %s", rr.Code, rr.Body.String())
	}
}

func TestDelegateCredential_HistoricalParentKeyStillAccepted(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read", "email:send"})

	if _, err := e.h.orgStore.RotateSigningKey(context.Background(), e.orgID); err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}

	rr := e.makeRequest(t, http.MethodPost, "/v1/credentials/delegate", map[string]any{
		"parent_token": tok,
		"child_agent":  "email-agent-v1",
		"child_scope":  []string{"email:send"},
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 with historical parent token, got %d — %s", rr.Code, rr.Body.String())
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

func TestGetTaskEvidence_SignedPacket(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/evidence", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from task evidence, got %d — %s", rr.Code, rr.Body.String())
	}

	var packet attest.EvidencePacket
	if err := json.Unmarshal(rr.Body.Bytes(), &packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	if packet.Integrity.SignatureAlgorithm != "RS256" {
		t.Fatalf("expected RS256 signature algorithm, got %q", packet.Integrity.SignatureAlgorithm)
	}
	if packet.Integrity.SignatureKID == "" {
		t.Fatalf("expected signature kid")
	}
	if packet.Integrity.PacketSignature == "" {
		t.Fatalf("expected packet signature")
	}
}

func TestGetTaskEvidence_VerifiesAgainstPublicJWKS(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rrEvidence := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/evidence", nil)
	if rrEvidence.Code != http.StatusOK {
		t.Fatalf("expected 200 from task evidence, got %d — %s", rrEvidence.Code, rrEvidence.Body.String())
	}

	var packet attest.EvidencePacket
	if err := json.Unmarshal(rrEvidence.Body.Bytes(), &packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}

	rrJWKS := e.makePublicRequest(t, http.MethodGet, "/orgs/"+e.orgID+"/jwks.json")
	if rrJWKS.Code != http.StatusOK {
		t.Fatalf("expected 200 from jwks, got %d — %s", rrJWKS.Code, rrJWKS.Body.String())
	}

	pub := jwksPublicKeyForKID(t, rrJWKS.Body.Bytes(), packet.Integrity.SignatureKID)
	sig, err := base64.RawURLEncoding.DecodeString(packet.Integrity.PacketSignature)
	if err != nil {
		t.Fatalf("decode packet signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, mustDecodeHex(t, packet.Integrity.PacketHash), sig); err != nil {
		t.Fatalf("verify packet signature: %v", err)
	}
}

func TestJWKS_IncludesHistoricalKeysAfterRotation(t *testing.T) {
	e := newTestEnv(t)

	initialKey, err := e.h.orgStore.GetSigningKey(context.Background(), e.orgID)
	if err != nil {
		t.Fatalf("get initial signing key: %v", err)
	}
	rotatedKey, err := e.h.orgStore.RotateSigningKey(context.Background(), e.orgID)
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}

	rr := e.makePublicRequest(t, http.MethodGet, "/orgs/"+e.orgID+"/jwks.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from jwks, got %d — %s", rr.Code, rr.Body.String())
	}

	var payload struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(payload.Keys) != 2 {
		t.Fatalf("expected 2 jwks keys after rotation, got %d", len(payload.Keys))
	}

	found := map[string]bool{}
	for _, key := range payload.Keys {
		found[key.KID] = true
	}
	if !found[initialKey.KeyID] {
		t.Fatalf("expected jwks to include original key id %q", initialKey.KeyID)
	}
	if !found[rotatedKey.KeyID] {
		t.Fatalf("expected jwks to include rotated key id %q", rotatedKey.KeyID)
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

func TestGetTaskReport_PrintMode(t *testing.T) {
	e := newTestEnv(t)
	tok, _ := e.issueToken(t, []string{"files:read"})

	result, _ := e.issuer.Verify(tok, &e.sigKey.PublicKey)
	taskID := result.Claims.TaskID

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/report?mode=print", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from print task report, got %d — %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Print-friendly report") {
		t.Fatalf("expected print banner content in report body")
	}
	if !strings.Contains(body, "window.print()") {
		t.Fatalf("expected print script in report body")
	}
}

func TestGetTaskReport_MatchesEvidencePacket(t *testing.T) {
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

	rrEvidenceA := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/evidence", nil)
	if rrEvidenceA.Code != http.StatusOK {
		t.Fatalf("expected 200 from task evidence A, got %d — %s", rrEvidenceA.Code, rrEvidenceA.Body.String())
	}
	rrEvidenceB := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/evidence", nil)
	if rrEvidenceB.Code != http.StatusOK {
		t.Fatalf("expected 200 from task evidence B, got %d — %s", rrEvidenceB.Code, rrEvidenceB.Body.String())
	}

	var packetA attest.EvidencePacket
	if err := json.Unmarshal(rrEvidenceA.Body.Bytes(), &packetA); err != nil {
		t.Fatalf("decode packet A: %v", err)
	}
	var packetB attest.EvidencePacket
	if err := json.Unmarshal(rrEvidenceB.Body.Bytes(), &packetB); err != nil {
		t.Fatalf("decode packet B: %v", err)
	}

	if packetA.Integrity.PacketHash != packetB.Integrity.PacketHash {
		t.Fatalf("expected stable packet hash across repeated evidence requests")
	}
	if !packetA.GeneratedAt.Equal(packetB.GeneratedAt) {
		t.Fatalf("expected stable generated_at across repeated evidence requests")
	}
	if packetA.Integrity.PacketSignature != packetB.Integrity.PacketSignature {
		t.Fatalf("expected stable packet signature across repeated evidence requests")
	}

	rrReport := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/report", nil)
	if rrReport.Code != http.StatusOK {
		t.Fatalf("expected 200 from task report, got %d — %s", rrReport.Code, rrReport.Body.String())
	}

	reportBody := rrReport.Body.String()
	if !strings.Contains(reportBody, packetA.Integrity.PacketHash) {
		t.Fatalf("expected report to contain evidence packet hash")
	}
	if !strings.Contains(reportBody, packetA.GeneratedAt.UTC().Format(time.RFC3339)) {
		t.Fatalf("expected report to contain evidence generated_at timestamp")
	}
}

func TestListTasks_ReturnsRecentTaskSummaries(t *testing.T) {
	e := newTestEnv(t)

	appendIssued := func(taskID, jti, userID, agentID string, createdOffset time.Duration) {
		t.Helper()
		if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
			EventType: attest.EventIssued,
			JTI:       jti,
			TaskID:    taskID,
			UserID:    userID,
			AgentID:   agentID,
			Scope:     []string{"files:read"},
		}); err != nil {
			t.Fatalf("append issued event: %v", err)
		}
	}

	appendAction := func(taskID, jti, userID, agentID, outcome string) {
		t.Helper()
		if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
			EventType: attest.EventAction,
			JTI:       jti,
			TaskID:    taskID,
			UserID:    userID,
			AgentID:   agentID,
			Scope:     []string{"files:read"},
			Meta:      map[string]string{"outcome": outcome},
		}); err != nil {
			t.Fatalf("append action event: %v", err)
		}
	}

	appendRevoked := func(taskID, jti, userID, agentID string) {
		t.Helper()
		if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
			EventType: attest.EventRevoked,
			JTI:       jti,
			TaskID:    taskID,
			UserID:    userID,
			AgentID:   agentID,
			Scope:     []string{"files:read"},
		}); err != nil {
			t.Fatalf("append revoked event: %v", err)
		}
	}

	appendIssued("task-active", "jti-active-root", "alice", "planner", 0)
	appendAction("task-active", "jti-active-root", "alice", "executor", "success")
	appendIssued("task-revoked", "jti-revoked-root", "bob", "planner", 0)
	appendRevoked("task-revoked", "jti-revoked-root", "bob", "planner")

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks?limit=10", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tasks []audit.TaskSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &tasks); err != nil {
		t.Fatalf("decode task summaries: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}

	var sawActive, sawRevoked bool
	for _, task := range tasks {
		switch task.TaskID {
		case "task-active":
			sawActive = true
			if task.UserID != "alice" {
				t.Fatalf("expected alice, got %q", task.UserID)
			}
			if task.RootAgentID != "planner" {
				t.Fatalf("expected planner, got %q", task.RootAgentID)
			}
			if task.Revoked {
				t.Fatalf("expected active task to not be revoked")
			}
		case "task-revoked":
			sawRevoked = true
			if !task.Revoked {
				t.Fatalf("expected revoked task to be flagged revoked")
			}
		}
	}
	if !sawActive || !sawRevoked {
		t.Fatalf("missing expected tasks in response: %+v", tasks)
	}
}

func TestListTasks_FiltersByStatusAndUser(t *testing.T) {
	e := newTestEnv(t)

	if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "jti-active",
		TaskID:    "task-active",
		UserID:    "alice",
		AgentID:   "planner",
		Scope:     []string{"files:read"},
	}); err != nil {
		t.Fatalf("append active event: %v", err)
	}
	if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "jti-revoked",
		TaskID:    "task-revoked",
		UserID:    "bob",
		AgentID:   "reviewer",
		Scope:     []string{"files:read"},
	}); err != nil {
		t.Fatalf("append revoked issued event: %v", err)
	}
	if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
		EventType: attest.EventRevoked,
		JTI:       "jti-revoked",
		TaskID:    "task-revoked",
		UserID:    "bob",
		AgentID:   "reviewer",
		Scope:     []string{"files:read"},
	}); err != nil {
		t.Fatalf("append revoked event: %v", err)
	}

	rr := e.makeRequest(t, http.MethodGet, "/v1/tasks?status=revoked&user_id=bob", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tasks []audit.TaskSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &tasks); err != nil {
		t.Fatalf("decode task summaries: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].TaskID != "task-revoked" {
		t.Fatalf("expected revoked task, got %q", tasks[0].TaskID)
	}
}

func TestTaskEvidence_TrustLoopReflectsDelegationRuntimeAndRevocation(t *testing.T) {
	e := newTestEnv(t)
	rootToken, rootJTI := e.issueToken(t, []string{"files:read", "email:send"})

	rootResult, _ := e.issuer.Verify(rootToken, &e.sigKey.PublicKey)
	taskID := rootResult.Claims.TaskID

	if err := e.h.auditLog.Append(context.Background(), e.orgID, attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       rootJTI,
		TaskID:    taskID,
		UserID:    rootResult.Claims.UserID,
		AgentID:   "test-agent",
		Scope:     append([]string(nil), rootResult.Claims.Scope...),
	}); err != nil {
		t.Fatalf("append issued event: %v", err)
	}

	rrDelegate := e.makeRequest(t, http.MethodPost, "/v1/credentials/delegate", map[string]any{
		"parent_token": rootToken,
		"child_agent":  "email-agent-v1",
		"child_scope":  []string{"email:send"},
	})
	if rrDelegate.Code != http.StatusCreated {
		t.Fatalf("expected 201 from delegate, got %d — %s", rrDelegate.Code, rrDelegate.Body.String())
	}

	var delegated struct {
		Token  string        `json:"token"`
		Claims attest.Claims `json:"claims"`
	}
	if err := json.Unmarshal(rrDelegate.Body.Bytes(), &delegated); err != nil {
		t.Fatalf("decode delegate response: %v", err)
	}
	if delegated.Token == "" {
		t.Fatalf("expected delegated token")
	}

	rrStatus := e.makeRequest(t, http.MethodPost, "/v1/audit/status", map[string]any{
		"token":  delegated.Token,
		"status": "started",
	})
	if rrStatus.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from audit status, got %d — %s", rrStatus.Code, rrStatus.Body.String())
	}

	rrAction := e.makeRequest(t, http.MethodPost, "/v1/audit/report", map[string]any{
		"token":   delegated.Token,
		"tool":    "send_email",
		"outcome": "success",
		"meta": map[string]string{
			"channel": "customer",
		},
	})
	if rrAction.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from audit report, got %d — %s", rrAction.Code, rrAction.Body.String())
	}

	rrRevoke := e.makeRequest(t, http.MethodDelete, "/v1/credentials/"+rootJTI, map[string]string{
		"revoked_by": "security-review",
	})
	if rrRevoke.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from revoke, got %d — %s", rrRevoke.Code, rrRevoke.Body.String())
	}

	rrEvidence := e.makeRequest(t, http.MethodGet, "/v1/tasks/"+taskID+"/evidence", nil)
	if rrEvidence.Code != http.StatusOK {
		t.Fatalf("expected 200 from task evidence, got %d — %s", rrEvidence.Code, rrEvidence.Body.String())
	}

	var packet attest.EvidencePacket
	if err := json.Unmarshal(rrEvidence.Body.Bytes(), &packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}

	if packet.Task.CredentialCount != 2 {
		t.Fatalf("expected 2 credentials, got %d", packet.Task.CredentialCount)
	}
	if packet.Task.EventCount != 5 {
		t.Fatalf("expected 5 task events, got %d", packet.Task.EventCount)
	}
	if !packet.Task.Revoked {
		t.Fatalf("expected task to be marked revoked")
	}
	if packet.Summary.Result != "revoked" {
		t.Fatalf("expected revoked summary result, got %q", packet.Summary.Result)
	}
	if packet.Summary.Revocations != 1 {
		t.Fatalf("expected 1 revocation, got %d", packet.Summary.Revocations)
	}
	if !packet.Integrity.AuditChainValid {
		t.Fatalf("expected valid audit chain")
	}

	eventTypes := make([]attest.EventType, 0, len(packet.Events))
	sawRevokedEvent := false
	for _, event := range packet.Events {
		eventTypes = append(eventTypes, event.EventType)
		if event.EventType == attest.EventRevoked {
			sawRevokedEvent = true
			if event.TaskID != taskID {
				t.Fatalf("expected revoked event task id %q, got %q", taskID, event.TaskID)
			}
			if event.Meta["revoked_by"] != "security-review" {
				t.Fatalf("expected revoked_by metadata to be preserved")
			}
		}
	}
	if !sawRevokedEvent {
		t.Fatalf("expected revoked event in evidence packet")
	}

	expectedOrder := []attest.EventType{
		attest.EventIssued,
		attest.EventDelegated,
		attest.EventLifecycle,
		attest.EventAction,
		attest.EventRevoked,
	}
	if len(eventTypes) != len(expectedOrder) {
		t.Fatalf("unexpected event count in task evidence: %v", eventTypes)
	}
	for i, want := range expectedOrder {
		if eventTypes[i] != want {
			t.Fatalf("unexpected event order at %d: got %q want %q", i, eventTypes[i], want)
		}
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
