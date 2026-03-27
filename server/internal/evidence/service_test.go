package evidence

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/pkg/attest"
	"github.com/golang-jwt/jwt/v5"
)

type fixtureJWKS struct {
	Keys []fixtureJWK `json:"keys"`
}

type fixtureJWK struct {
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func loadFixturePacket(t *testing.T) *attest.EvidencePacket {
	t.Helper()

	path := filepath.Join("..", "..", "..", "testdata", "evidence", "packet.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read packet fixture: %v", err)
	}

	var packet attest.EvidencePacket
	if err := json.Unmarshal(raw, &packet); err != nil {
		t.Fatalf("unmarshal packet fixture: %v", err)
	}
	return &packet
}

func loadFixtureJWKS(t *testing.T) fixtureJWKS {
	t.Helper()

	path := filepath.Join("..", "..", "..", "testdata", "evidence", "jwks.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read jwks fixture: %v", err)
	}

	var jwks fixtureJWKS
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatalf("unmarshal jwks fixture: %v", err)
	}
	return jwks
}

func fixtureRSAPublicKey(t *testing.T, jwks fixtureJWKS, kid string) *rsa.PublicKey {
	t.Helper()

	for _, key := range jwks.Keys {
		if key.KID != kid {
			continue
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			t.Fatalf("decode modulus: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			t.Fatalf("decode exponent: %v", err)
		}

		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		return &rsa.PublicKey{N: n, E: e}
	}

	t.Fatalf("kid %q not found in fixture jwks", kid)
	return nil
}

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

func TestBuildTaskEvidence_HashStableAcrossRepeatedBuilds(t *testing.T) {
	ctx := context.Background()
	revStore := revocation.NewMemoryStore()
	auditLog := audit.NewMemoryLog()
	svc := NewService(auditLog, revStore)

	issuedAt := time.Unix(100, 0).UTC()
	root := &attest.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "root-jti",
			Subject:   "agent:orchestrator-v1",
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(time.Hour)),
		},
		TaskID:     "tid_stable",
		Depth:      0,
		Scope:      []string{"files:read"},
		IntentHash: strings.Repeat("a", 64),
		Chain:      []string{"root-jti"},
		UserID:     "usr_alice",
	}

	if err := revStore.TrackCredential(ctx, "org_123", root); err != nil {
		t.Fatalf("track root: %v", err)
	}
	if err := auditLog.Append(ctx, "org_123", attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "root-jti",
		TaskID:    "tid_stable",
		UserID:    "usr_alice",
		AgentID:   "orchestrator-v1",
		Scope:     []string{"files:read"},
	}); err != nil {
		t.Fatalf("append issued event: %v", err)
	}

	packetA, err := svc.BuildTaskEvidence(ctx, "org_123", "Acme", "tid_stable")
	if err != nil {
		t.Fatalf("build evidence A: %v", err)
	}
	packetB, err := svc.BuildTaskEvidence(ctx, "org_123", "Acme", "tid_stable")
	if err != nil {
		t.Fatalf("build evidence B: %v", err)
	}

	if packetA.Integrity.PacketHash != packetB.Integrity.PacketHash {
		t.Fatalf("expected stable packet hash across repeated builds")
	}
	if !packetA.GeneratedAt.Equal(packetB.GeneratedAt) {
		t.Fatalf("expected stable generated_at across repeated builds")
	}
}

func TestSignPacket(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	packet := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		Integrity: attest.EvidenceIntegrity{
			HashAlgorithm: "sha256",
			PacketHash:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
	}

	if err := SignPacket(packet, key, "kid-123"); err != nil {
		t.Fatalf("sign packet: %v", err)
	}
	if packet.Integrity.SignatureAlgorithm != "RS256" {
		t.Fatalf("unexpected signature algorithm: %s", packet.Integrity.SignatureAlgorithm)
	}
	if packet.Integrity.SignatureKID != "kid-123" {
		t.Fatalf("unexpected signature kid: %s", packet.Integrity.SignatureKID)
	}
	if packet.Integrity.PacketSignature == "" {
		t.Fatalf("expected packet signature")
	}
	if _, err := base64.RawURLEncoding.DecodeString(packet.Integrity.PacketSignature); err != nil {
		t.Fatalf("expected base64url signature: %v", err)
	}
}

func TestHashPacket_IncludesGeneratedAt(t *testing.T) {
	packetA := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Unix(100, 0).UTC(),
		Integrity: attest.EvidenceIntegrity{
			HashAlgorithm: "sha256",
		},
	}
	packetB := &attest.EvidencePacket{
		PacketType:    packetA.PacketType,
		SchemaVersion: packetA.SchemaVersion,
		GeneratedAt:   time.Unix(101, 0).UTC(),
		Integrity: attest.EvidenceIntegrity{
			HashAlgorithm: "sha256",
		},
	}

	hashA, err := hashPacket(packetA)
	if err != nil {
		t.Fatalf("hash packet A: %v", err)
	}
	hashB, err := hashPacket(packetB)
	if err != nil {
		t.Fatalf("hash packet B: %v", err)
	}
	if hashA == hashB {
		t.Fatalf("expected generated_at to affect packet hash")
	}
}

func TestSignPacket_CoversGeneratedAt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	packet := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Unix(100, 0).UTC(),
		Integrity: attest.EvidenceIntegrity{
			HashAlgorithm: "sha256",
		},
	}

	hash, err := hashPacket(packet)
	if err != nil {
		t.Fatalf("hash packet: %v", err)
	}
	packet.Integrity.PacketHash = hash
	if err := SignPacket(packet, key, "kid-123"); err != nil {
		t.Fatalf("sign packet: %v", err)
	}

	originalSignature := packet.Integrity.PacketSignature
	packet.GeneratedAt = time.Unix(101, 0).UTC()
	nextHash, err := hashPacket(packet)
	if err != nil {
		t.Fatalf("rehash packet: %v", err)
	}
	if nextHash == packet.Integrity.PacketHash {
		t.Fatalf("expected packet hash to change after generated_at changes")
	}
	if packet.Integrity.PacketSignature != originalSignature {
		t.Fatalf("expected signature field to remain unchanged until explicitly re-signed")
	}
}

func TestHashPacket_ExcludesSignatureMetadata(t *testing.T) {
	packetA := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Unix(100, 0).UTC(),
		Integrity: attest.EvidenceIntegrity{
			HashAlgorithm:      "sha256",
			SignatureAlgorithm: "RS256",
			SignatureKID:       "kid-a",
			PacketSignature:    "aaa",
		},
	}
	packetB := &attest.EvidencePacket{}
	raw, err := json.Marshal(packetA)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	if err := json.Unmarshal(raw, packetB); err != nil {
		t.Fatalf("unmarshal packet: %v", err)
	}
	packetB.Integrity.SignatureAlgorithm = "RS256"
	packetB.Integrity.SignatureKID = "kid-b"
	packetB.Integrity.PacketSignature = "bbb"

	hashA, err := hashPacket(packetA)
	if err != nil {
		t.Fatalf("hash packet A: %v", err)
	}
	hashB, err := hashPacket(packetB)
	if err != nil {
		t.Fatalf("hash packet B: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("expected signature metadata to be excluded from packet hash")
	}
}

func TestHashPacket_MatchesFixturePacketHash(t *testing.T) {
	packet := loadFixturePacket(t)

	hash, err := hashPacket(packet)
	if err != nil {
		t.Fatalf("hash packet: %v", err)
	}
	if hash != packet.Integrity.PacketHash {
		t.Fatalf("expected fixture packet hash %s, got %s", packet.Integrity.PacketHash, hash)
	}
}

func TestFixturePacketSignatureVerifies(t *testing.T) {
	packet := loadFixturePacket(t)
	jwks := loadFixtureJWKS(t)
	pub := fixtureRSAPublicKey(t, jwks, packet.Integrity.SignatureKID)

	sig, err := base64.RawURLEncoding.DecodeString(packet.Integrity.PacketSignature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, mustDecodeHex(t, packet.Integrity.PacketHash), sig); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return out
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
			AuditChainValid:    true,
			HashAlgorithm:      "sha256",
			PacketHash:         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			SignatureAlgorithm: "RS256",
			SignatureKID:       "kid-123",
			PacketSignature:    "c2lnbmVkLXBheWxvYWQ",
		},
		Summary: attest.EvidenceSummary{
			Result: "active",
		},
	}

	reportHTML, err := RenderTaskReport(packet, ReportOptions{BaseURL: "https://api.attestdev.com"})
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
	if !strings.Contains(body, "https://api.attestdev.com/orgs/org_123/jwks.json") {
		t.Fatalf("expected jwks url in report")
	}
	if !strings.Contains(body, "verifyEvidencePacket") {
		t.Fatalf("expected verification snippet in report")
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
			AuditChainValid:    true,
			HashAlgorithm:      "sha256",
			PacketHash:         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			SignatureAlgorithm: "RS256",
			SignatureKID:       "kid-123",
			PacketSignature:    "c2lnbmVkLXBheWxvYWQ",
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
