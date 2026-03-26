package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/attest-dev/attest/internal/audit"
	"github.com/attest-dev/attest/internal/revocation"
	"github.com/attest-dev/attest/pkg/attest"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Service assembles task-tree evidence packets from stored credentials and
// append-only audit events.
type Service struct {
	auditLog audit.Logger
	revStore revocation.Revoker
}

func NewService(auditLog audit.Logger, revStore revocation.Revoker) *Service {
	return &Service{
		auditLog: auditLog,
		revStore: revStore,
	}
}

func (s *Service) BuildTaskEvidence(ctx context.Context, orgID, orgName, taskID string) (*attest.EvidencePacket, error) {
	creds, err := s.revStore.ListTaskCredentials(ctx, orgID, taskID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	events, err := s.auditLog.Query(ctx, orgID, taskID)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	if creds == nil {
		creds = []attest.CredentialRecord{}
	}
	if events == nil {
		events = []attest.AuditEvent{}
	}

	packet := &attest.EvidencePacket{
		PacketType:    "attest.evidence_packet",
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		Org: attest.EvidenceOrg{
			ID:   orgID,
			Name: orgName,
		},
		Events: events,
	}

	root := findRootCredential(creds)
	if root != nil {
		packet.Task.TaskID = taskID
		packet.Task.RootJTI = root.JTI
		packet.Task.RootAgentID = root.AgentID
		packet.Task.UserID = root.UserID
		packet.Task.InstructionHash = root.IntentHash
		packet.Identity.UserID = root.UserID
		packet.Identity.IDPIssuer = cloneStringPtr(root.IDPIssuer)
		packet.Identity.IDPSubject = cloneStringPtr(root.IDPSubject)
	}

	packet.Credentials = make([]attest.EvidenceCredential, 0, len(creds))
	maxDepth := 0
	for _, cred := range creds {
		if cred.Depth > maxDepth {
			maxDepth = cred.Depth
		}
		packet.Credentials = append(packet.Credentials, attest.EvidenceCredential{
			JTI:           cred.JTI,
			ParentJTI:     cred.ParentID,
			AgentID:       cred.AgentID,
			Scope:         append([]string(nil), cred.Scope...),
			Depth:         cred.Depth,
			IssuedAt:      cred.IssuedAt,
			ExpiresAt:     cred.ExpiresAt,
			Chain:         append([]string(nil), cred.Chain...),
			IntentHash:    cred.IntentHash,
			AgentChecksum: cred.AgentChecksum,
			IDPIssuer:     cloneStringPtr(cred.IDPIssuer),
			IDPSubject:    cloneStringPtr(cred.IDPSubject),
			HITLRequestID: cloneStringPtr(cred.HITLRequestID),
			HITLSubject:   cloneStringPtr(cred.HITLSubject),
			HITLIssuer:    cloneStringPtr(cred.HITLIssuer),
		})
		if packet.Identity.Approval == nil && cred.HITLRequestID != nil {
			packet.Identity.Approval = &attest.EvidenceApproval{
				Present:   true,
				RequestID: cloneStringPtr(cred.HITLRequestID),
				Issuer:    cloneStringPtr(cred.HITLIssuer),
				Subject:   cloneStringPtr(cred.HITLSubject),
			}
		}
	}

	if packet.Task.TaskID == "" {
		packet.Task.TaskID = taskID
	}
	packet.Task.DepthMax = maxDepth
	packet.Task.CredentialCount = len(creds)
	packet.Task.EventCount = len(events)

	notes := make([]string, 0)
	auditChainValid := validateAuditChain(events, &notes)
	validateCredentials(taskID, creds, &notes)

	summary := buildSummary(events, creds)
	packet.Task.Revoked = summary.Revocations > 0
	packet.Summary = summary
	packet.Integrity = attest.EvidenceIntegrity{
		AuditChainValid: auditChainValid,
		HashAlgorithm:   "sha256",
		Notes:           notes,
	}

	hash, err := hashPacket(packet)
	if err != nil {
		return nil, fmt.Errorf("hash packet: %w", err)
	}
	packet.Integrity.PacketHash = hash

	return packet, nil
}

func findRootCredential(creds []attest.CredentialRecord) *attest.CredentialRecord {
	for i := range creds {
		if creds[i].Depth == 0 || creds[i].ParentID == "" {
			return &creds[i]
		}
	}
	return nil
}

func validateAuditChain(events []attest.AuditEvent, notes *[]string) bool {
	if len(events) == 0 {
		*notes = append(*notes, "no audit events found for task")
		return true
	}

	for i, event := range events {
		if i == 0 {
			if event.PrevHash != genesisHash {
				*notes = append(*notes, "first audit event does not use the genesis previous hash")
				return false
			}
			continue
		}
		if event.PrevHash != events[i-1].EntryHash {
			*notes = append(*notes, fmt.Sprintf("audit chain break between event %d and %d", events[i-1].ID, event.ID))
			return false
		}
	}
	return true
}

func validateCredentials(taskID string, creds []attest.CredentialRecord, notes *[]string) {
	rootCount := 0
	var expectedIntent string
	for _, cred := range creds {
		if cred.Depth == 0 || cred.ParentID == "" {
			rootCount++
		}
		if cred.TaskID != taskID {
			*notes = append(*notes, fmt.Sprintf("credential %s belongs to unexpected task id %s", cred.JTI, cred.TaskID))
		}
		if len(cred.Chain) != cred.Depth+1 {
			*notes = append(*notes, fmt.Sprintf("credential %s has invalid chain length for depth", cred.JTI))
		}
		if len(cred.Chain) > 0 && cred.Chain[len(cred.Chain)-1] != cred.JTI {
			*notes = append(*notes, fmt.Sprintf("credential %s chain tail does not match jti", cred.JTI))
		}
		if cred.IntentHash != "" {
			if expectedIntent == "" {
				expectedIntent = cred.IntentHash
			} else if expectedIntent != cred.IntentHash {
				*notes = append(*notes, "credentials in task do not share a single intent hash")
			}
		}
	}
	if rootCount == 0 {
		*notes = append(*notes, "no root credential found for task")
	}
	if rootCount > 1 {
		*notes = append(*notes, "multiple root credentials found for task")
	}
}

func buildSummary(events []attest.AuditEvent, creds []attest.CredentialRecord) attest.EvidenceSummary {
	summary := attest.EvidenceSummary{
		Result: "active",
	}

	hasExpired := false
	now := time.Now().UTC()
	for _, cred := range creds {
		if cred.ExpiresAt.Before(now) {
			hasExpired = true
		}
	}

	for _, event := range events {
		switch event.EventType {
		case attest.EventRevoked:
			summary.Revocations++
		case attest.EventDelegated:
			if summary.Result == "active" {
				summary.Result = "active"
			}
		}

		if event.HITLRequestID != nil {
			summary.Approvals++
		}
		if isScopeViolation(event) {
			summary.ScopeViolations++
		}
	}

	switch {
	case summary.Revocations > 0:
		summary.Result = "revoked"
	case hasExpired:
		summary.Result = "expired"
	default:
		summary.Result = "active"
	}

	return summary
}

func isScopeViolation(event attest.AuditEvent) bool {
	if strings.EqualFold(event.Meta["reason"], "scope_violation") {
		return true
	}
	if strings.EqualFold(event.Meta["status"], "scope_violation") {
		return true
	}
	if strings.Contains(strings.ToLower(event.Meta["detail"]), "scope_violation") {
		return true
	}
	return false
}

func hashPacket(packet *attest.EvidencePacket) (string, error) {
	clone := *packet
	clone.GeneratedAt = time.Time{}
	clone.Integrity.PacketHash = ""

	b, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
