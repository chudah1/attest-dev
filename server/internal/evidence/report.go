package evidence

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
)

//go:embed templates/report.html.tmpl
var reportTemplateSource string

type ReportTemplate string

const (
	ReportTemplateAudit    ReportTemplate = "audit"
	ReportTemplateSOC2     ReportTemplate = "soc2"
	ReportTemplateIncident ReportTemplate = "incident"
)

type ReportOptions struct {
	Template ReportTemplate
	BaseURL  string
}

type reportProfile struct {
	ID                    ReportTemplate
	PageTitle             string
	Eyebrow               string
	HeroTitle             string
	Lede                  string
	ExecutiveSummaryTitle string
	ExecutiveSummaryBody  string
	ChainIntro            string
	TimelineIntro         string
	Footer                string
}

type reportViewData struct {
	Profile      reportProfile
	Packet       *attest.EvidencePacket
	Verification reportVerification
}

type reportVerification struct {
	JWKSURL       string
	TypeScriptCLI string
	PythonCLI     string
}

var reportTemplate = template.Must(template.New("evidence_report").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format(time.RFC3339)
	},
	"join": func(items []string) string {
		if len(items) == 0 {
			return "—"
		}
		return strings.Join(items, ", ")
	},
	"shortHash": func(v string) string {
		if v == "" {
			return "—"
		}
		if len(v) <= 18 {
			return v
		}
		return v[:10] + "..." + v[len(v)-6:]
	},
	"eventClass": func(v attest.EventType) string {
		switch v {
		case attest.EventIssued:
			return "issued"
		case attest.EventDelegated:
			return "delegated"
		case attest.EventRevoked:
			return "revoked"
		case attest.EventAction:
			return "action"
		case attest.EventLifecycle:
			return "lifecycle"
		default:
			return "neutral"
		}
	},
}).Parse(reportTemplateSource))

var reportProfiles = map[ReportTemplate]reportProfile{
	ReportTemplateAudit: {
		ID:                    ReportTemplateAudit,
		PageTitle:             "Attest Evidence Report",
		Eyebrow:               "Agent Authorization Evidence Report",
		HeroTitle:             "Who authorized what, through which chain, and with what outcome.",
		Lede:                  "This report is rendered directly from an Attest evidence packet. It summarizes the delegated authority chain, runtime events, revocation state, and packet integrity for offline review.",
		ExecutiveSummaryTitle: "Executive Summary",
		ExecutiveSummaryBody:  "The task tree originated from user %s and reached a maximum delegation depth of %d. Attest recorded %d approval-linked event(s), %d scope violation(s), and %d revocation event(s).",
		ChainIntro:            "Each row represents a credential in the task tree, including parent linkage, delegated scope, and any approval metadata persisted at issuance time.",
		TimelineIntro:         "The append-only event log below is the human-readable view of the packet event stream. Reviewers can use it to confirm issuance, delegation, action, lifecycle, and revocation activity.",
		Footer:                "This report is an Attest rendering of the underlying evidence packet. The JSON packet remains the canonical export artifact for downstream verification and compliance storage.",
	},
	ReportTemplateSOC2: {
		ID:                    ReportTemplateSOC2,
		PageTitle:             "Attest SOC 2 Evidence Report",
		Eyebrow:               "SOC 2 Control Evidence",
		HeroTitle:             "Control-ready evidence for delegated agent authority.",
		Lede:                  "This rendering packages the Attest evidence packet for audit and SOC 2 review. It emphasizes chain-of-authority, runtime proof, and integrity signals that support control testing.",
		ExecutiveSummaryTitle: "Control Summary",
		ExecutiveSummaryBody:  "For control testing, this task was initiated by %s, reached a delegation depth of %d, and produced %d approval-linked event(s), %d scope violation(s), and %d revocation event(s).",
		ChainIntro:            "Use this credential table to confirm least-privilege delegation, bounded ancestry, and credential lifetime controls.",
		TimelineIntro:         "Use this timeline to confirm the sequence of issued credentials and runtime actions against the control narrative for the task.",
		Footer:                "This SOC 2-oriented rendering is derived from the canonical Attest evidence packet and is intended to support auditor review, not replace the source packet.",
	},
	ReportTemplateIncident: {
		ID:                    ReportTemplateIncident,
		PageTitle:             "Attest Incident Review Report",
		Eyebrow:               "Incident Review Packet",
		HeroTitle:             "Reconstruct the delegated chain behind a specific agent action.",
		Lede:                  "This incident-oriented view packages the Attest evidence packet for fast review. It foregrounds the human origin, authority chain, runtime event order, and integrity result for the task.",
		ExecutiveSummaryTitle: "Incident Summary",
		ExecutiveSummaryBody:  "This task traces back to %s, reached delegation depth %d, and currently reflects %d approval-linked event(s), %d scope violation(s), and %d revocation event(s) relevant to incident review.",
		ChainIntro:            "Review this chain to determine which credential held authority at each step and whether delegation narrowed as expected.",
		TimelineIntro:         "Review the event order below to reconstruct what happened, when it happened, and which credential was active at the time.",
		Footer:                "This incident review rendering is generated from the Attest evidence packet. Preserve the packet hash and JSON export alongside any investigative notes.",
	},
}

func normalizeReportTemplate(name string) ReportTemplate {
	switch ReportTemplate(strings.ToLower(strings.TrimSpace(name))) {
	case ReportTemplateSOC2:
		return ReportTemplateSOC2
	case ReportTemplateIncident:
		return ReportTemplateIncident
	default:
		return ReportTemplateAudit
	}
}

func resolveReportProfile(name string) reportProfile {
	key := normalizeReportTemplate(name)
	profile, ok := reportProfiles[key]
	if !ok {
		return reportProfiles[ReportTemplateAudit]
	}
	return profile
}

func buildReportViewData(packet *attest.EvidencePacket, opts ReportOptions) reportViewData {
	profile := resolveReportProfile(string(opts.Template))
	profile.ExecutiveSummaryBody = fmt.Sprintf(
		profile.ExecutiveSummaryBody,
		packet.Identity.UserID,
		packet.Task.DepthMax,
		packet.Summary.Approvals,
		packet.Summary.ScopeViolations,
		packet.Summary.Revocations,
	)

	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.attestdev.com"
	}

	jwksURL := fmt.Sprintf("%s/orgs/%s/jwks.json", baseURL, packet.Org.ID)
	packetRef := "packet.json"

	return reportViewData{
		Profile: profile,
		Packet:  packet,
		Verification: reportVerification{
			JWKSURL:       jwksURL,
			TypeScriptCLI: fmt.Sprintf("import { verifyEvidencePacket, loadJWKS } from '@attest-dev/sdk';\n\nconst packet = JSON.parse(await Bun.file('%s').text());\nconst jwks = await loadJWKS('%s');\nconst result = await verifyEvidencePacket(packet, jwks);\nconsole.log(result.valid);", packetRef, jwksURL),
			PythonCLI:     fmt.Sprintf("from attest import verify_evidence_packet, load_jwks\nimport json\n\nwith open('%s') as f:\n    packet = json.load(f)\n\njwks = load_jwks('%s')\nresult = verify_evidence_packet(packet, jwks)\nprint(result.valid)", packetRef, jwksURL),
		},
	}
}

// RenderTaskReport converts a canonical evidence packet into a human-readable
// HTML report for compliance and audit workflows.
func RenderTaskReport(packet *attest.EvidencePacket, opts ReportOptions) ([]byte, error) {
	if packet == nil {
		return nil, fmt.Errorf("nil evidence packet")
	}

	view := buildReportViewData(packet, opts)

	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, view); err != nil {
		return nil, fmt.Errorf("execute report template: %w", err)
	}
	return out.Bytes(), nil
}
