package evidence

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
)

func TestBuildTaskEvidence(t *testing.T) {
	ctx := context.Background()
	revStore := revocation.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(auditLog, revStore)

	root := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "root-jti",
			Subject:   "agent:orchestrator-v1",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		},
		TaskID:     "tid_123",
		Depth:      0,
		Scope:      []string{"research:read", "email:send"},
		IntentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Chain:      []string{"root-jti"},
		UserID:     "usr_alice",
	}
	child := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "child-jti",
			Subject:   "agent:email-agent-v1",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
		},
		TaskID:     "tid_123",
		ParentID:   "root-jti",
		Depth:      1,
		Scope:      []string{"email:send"},
		IntentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Chain:      []string{"root-jti", "child-jti"},
		UserID:     "usr_alice",
	}

	if err := revStore.TrackCredential(ctx, "org_123", root); err != nil {
		t.Fatalf("track root: %v", err)
	}
	if err := revStore.TrackCredential(ctx, "org_123", child); err != nil {
		t.Fatalf("track child: %v", err)
	}

	if err := auditLog.Append(ctx, "org_123", attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "root-jti",
		TaskID:    "tid_123",
		UserID:    "usr_alice",
		AgentID:   "orchestrator-v1",
		Scope:     []string{"research:read", "email:send"},
	}); err != nil {
		t.Fatalf("append issued event: %v", err)
	}
	if err := auditLog.Append(ctx, "org_123", attest.AuditEvent{
		EventType: attest.EventDelegated,
		JTI:       "child-jti",
		TaskID:    "tid_123",
		UserID:    "usr_alice",
		AgentID:   "email-agent-v1",
		Scope:     []string{"email:send"},
	}); err != nil {
		t.Fatalf("append delegated event: %v", err)
	}

	packet, err := svc.BuildTaskEvidence(ctx, "org_123", "Acme", "tid_123")
	if err != nil {
		t.Fatalf("build evidence: %v", err)
	}

	if packet.PacketType != "attest.evidence_packet" {
		t.Fatalf("unexpected packet type: %s", packet.PacketType)
	}
	if packet.Task.RootJTI != "root-jti" {
		t.Fatalf("unexpected root jti: %s", packet.Task.RootJTI)
	}
	if packet.Task.CredentialCount != 2 {
		t.Fatalf("unexpected credential count: %d", packet.Task.CredentialCount)
	}
	if !packet.Integrity.AuditChainValid {
		t.Fatalf("expected valid audit chain")
	}
	if packet.Integrity.PacketHash == "" {
		t.Fatalf("expected packet hash")
	}
	if len(packet.Events) != 2 {
		t.Fatalf("unexpected event count: %d", len(packet.Events))
	}
}

func TestRenderTaskReport(t *testing.T) {
	packet := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		Org: attest.EvidenceOrg{
			ID:   "org_123",
			Name: "Acme",
		},
		Task: attest.EvidenceTask{
			TaskID:          "tid_123",
			RootJTI:         "root-jti",
			RootAgentID:     "orchestrator-v1",
			UserID:          "usr_alice",
			InstructionHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DepthMax:        1,
			CredentialCount: 2,
			EventCount:      2,
		},
		Identity: attest.EvidenceIdentity{
			UserID: "usr_alice",
		},
		Credentials: []attest.EvidenceCredential{
			{
				JTI:       "root-jti",
				AgentID:   "orchestrator-v1",
				Scope:     []string{"research:read", "email:send"},
				Depth:     0,
				IssuedAt:  time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(time.Hour),
				Chain:     []string{"root-jti"},
			},
		},
		Events: []attest.AuditEvent{
			{
				EventType: attest.EventIssued,
				JTI:       "root-jti",
				AgentID:   "orchestrator-v1",
				Scope:     []string{"research:read", "email:send"},
				EntryHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				CreatedAt: time.Now().UTC(),
			},
		},
		Integrity: attest.EvidenceIntegrity{
			AuditChainValid: true,
			HashAlgorithm:   "sha256",
			PacketHash:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		Summary: attest.EvidenceSummary{
			Result: "active",
		},
	}

	reportHTML, err := RenderTaskReport(packet, ReportOptions{})
	if err != nil {
		t.Fatalf("render report: %v", err)
	}

	body := string(reportHTML)
	if !strings.Contains(body, "Agent Authorization Evidence Report") {
		t.Fatalf("expected report heading")
	}
	if !strings.Contains(body, "tid_123") {
		t.Fatalf("expected task id in report")
	}
	if !strings.Contains(body, "root-jti") {
		t.Fatalf("expected credential in report")
	}
}

func TestRenderTaskReport_SOC2Template(t *testing.T) {
	packet := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		Org:           attest.EvidenceOrg{ID: "org_123", Name: "Acme"},
		Task: attest.EvidenceTask{
			TaskID:          "tid_123",
			RootJTI:         "root-jti",
			RootAgentID:     "orchestrator-v1",
			UserID:          "usr_alice",
			InstructionHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DepthMax:        2,
			CredentialCount: 3,
			EventCount:      4,
		},
		Identity: attest.EvidenceIdentity{UserID: "usr_alice"},
		Integrity: attest.EvidenceIntegrity{
			AuditChainValid: true,
			HashAlgorithm:   "sha256",
			PacketHash:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		Summary: attest.EvidenceSummary{
			Result:          "active",
			Approvals:       1,
			ScopeViolations: 0,
			Revocations:     0,
		},
	}

	reportHTML, err := RenderTaskReport(packet, ReportOptions{Template: ReportTemplateSOC2})
	if err != nil {
		t.Fatalf("render soc2 report: %v", err)
	}

	body := string(reportHTML)
	if !strings.Contains(body, "SOC 2 Control Evidence") {
		t.Fatalf("expected soc2 eyebrow")
	}
	if !strings.Contains(body, "Control Summary") {
		t.Fatalf("expected soc2 summary title")
	}
	if !strings.Contains(body, "For control testing") {
		t.Fatalf("expected soc2 copy")
	}
}
