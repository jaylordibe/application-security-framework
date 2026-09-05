package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

// SARIF 2.1.0 output.
//
// A caveat worth stating plainly, because it is easy to imply otherwise: SARIF
// was designed for static analysis, where every result has a file and a line.
// Runtime findings have neither. The document below is valid against the OASIS
// 2.1.0 schema and uses the operation's URL as the artifact location, which the
// specification permits. GitHub code scanning, however, expects a
// repository-relative path, so it will ingest this file but will not link
// results to source. Only source-derived findings can do that, and Assay has
// none yet.

// sarifVersion is pinned. Emitting a different version silently would break
// every consumer's parser.
const sarifVersion = "2.1.0"

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifText           `json:"shortDescription"`
	FullDescription      sarifText           `json:"fullDescription"`
	Help                 sarifText           `json:"help"`
	DefaultConfiguration sarifRuleConfig     `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string    `json:"ruleId"`
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
	Kind    string    `json:"kind,omitempty"`
	// PartialFingerprints give a result a stable identity across runs.
	// Retrofitting these later would change the identity of every existing
	// alert for every consumer, so they are emitted from the first release.
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Locations           []sarifLocation   `json:"locations"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	LogicalLocations []sarifLogical        `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	StartTimeUTC               string              `json:"startTimeUtc,omitempty"`
	EndTimeUTC                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// severityToLevel maps our severity onto SARIF's smaller vocabulary. The
// original severity is preserved in properties, because the mapping loses
// information and a consumer may want the real value.
func severityToLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "none"
	}
}

// confidenceToPrecision maps confidence onto SARIF's precision property.
func confidenceToPrecision(c string) string {
	switch c {
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// WriteSARIF renders the document as SARIF 2.1.0.
//
// Suspected findings are emitted with kind "open" rather than "fail": SARIF has
// a vocabulary for "this needs a human decision", and using it is more honest
// than presenting an unverified hypothesis as a failure.
func WriteSARIF(w io.Writer, doc Document) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(doc.Findings))

	for _, f := range doc.Findings {
		if _, ok := rules[f.CheckID]; !ok {
			tags := append([]string{}, f.CWE...)
			tags = append(tags, f.OWASP...)
			rules[f.CheckID] = sarifRule{
				ID:               f.CheckID,
				Name:             f.CheckID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Expected},
				Help:             sarifText{Text: helpText(f)},
				DefaultConfiguration: sarifRuleConfig{
					Level: severityToLevel(f.Severity),
				},
				Properties: sarifRuleProperties{
					Tags:      tags,
					Precision: confidenceToPrecision(f.Confidence),
				},
			}
		}

		kind := "fail"
		if f.State != "confirmed" {
			kind = "open"
		}

		results = append(results, sarifResult{
			RuleID:  f.CheckID,
			Level:   severityToLevel(f.Severity),
			Kind:    kind,
			Message: sarifText{Text: f.Title + ". " + f.Actual},
			PartialFingerprints: map[string]string{
				"assayFindingId/v1": fingerprint(f.CheckID + "\x00" + f.OperationID),
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifact{URI: artifactURI(doc, f)},
				},
				LogicalLocations: []sarifLogical{{
					Name:               f.OperationID,
					FullyQualifiedName: f.OperationID,
					Kind:               "function",
				}},
			}},
			Properties: map[string]any{
				"state":                   f.State,
				"severity":                f.Severity,
				"confidence":              f.Confidence,
				"identityId":              f.IdentityID,
				"verificationPerformed":   f.Verification.Performed,
				"verificationUnavailable": f.Verification.Unavailable,
			},
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, id := range sortedKeys(rules) {
		ruleList = append(ruleList, rules[id])
	}

	notifications := make([]sarifNotification, 0, len(doc.ToolFailures))
	for _, f := range doc.ToolFailures {
		notifications = append(notifications, sarifNotification{
			Level:   "error",
			Message: sarifText{Text: f},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "assay",
				Version:        doc.Tool.Version,
				InformationURI: "https://github.com/jaylordibe/application-security-framework",
				Rules:          ruleList,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				// An assessment that executed no checks did not succeed, whatever
				// its exit status. Saying otherwise here would let a SARIF
				// consumer draw exactly the wrong conclusion.
				ExecutionSuccessful:        doc.Assurance.ExecutedChecks > 0,
				StartTimeUTC:               doc.Run.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
				EndTimeUTC:                 doc.Run.FinishedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
				ToolExecutionNotifications: notifications,
			}},
			// Coverage has no home in SARIF's vocabulary, so it travels in
			// properties rather than being dropped.
			Properties: map[string]any{
				"assaySchemaVersion":  doc.SchemaVersion,
				"assurance":           doc.Assurance,
				"classesNotAssessed":  doc.ClassesNotAssessed,
				"coverage":            doc.Coverage,
				"surfaceCompleteness": doc.Assurance.SurfaceCompleteness,
			},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// artifactURI locates a finding. Runtime findings have no source file, so the
// operation's URL is used, which the SARIF specification permits.
func artifactURI(doc Document, f Finding) string {
	target := strings.TrimRight(doc.Run.Target, "/")
	if i := strings.IndexByte(f.OperationID, ' '); i >= 0 {
		return target + f.OperationID[i+1:]
	}
	return target
}

func helpText(f Finding) string {
	var b strings.Builder
	b.WriteString(f.Expected)
	if f.Remediation != "" {
		b.WriteString("\n\nRemediation: ")
		b.WriteString(f.Remediation)
	}
	if len(f.Verification.Unavailable) > 0 {
		b.WriteString("\n\nNot established by this run: ")
		b.WriteString(strings.Join(f.Verification.Unavailable, "; "))
	}
	return b.String()
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func sortedKeys(m map[string]sarifRule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
