// Package report renders an assessment result into published formats.
//
// This package owns the wire schema. The domain model deliberately carries no
// struct tags, so renaming an internal field is never a breaking change to
// anything a consumer parses. Everything published passes through the DTOs here.
package report

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/model"
)

// SchemaVersion identifies the output contract. It is the first field of every
// document so a consumer can dispatch on it before parsing anything else.
//
// Consumers must treat an unrecognised blocked cause, outcome or finding state
// as blocked rather than as success. Within a major version, fields are added
// but never removed or repurposed.
const SchemaVersion = "assay.report/v1alpha1"

// Document is the JSON report.
type Document struct {
	SchemaVersion string `json:"schemaVersion"`
	Tool          Tool   `json:"tool"`
	Run           Run    `json:"run"`

	// Assurance is deliberately the first substantive section. A reader who
	// stops after one paragraph must not come away believing more than the
	// evidence supports.
	Assurance Assurance `json:"assurance"`

	Surface  Surface         `json:"surface"`
	Findings []Finding       `json:"findings"`
	Coverage []CoverageEntry `json:"coverage"`

	ToolFailures       []string `json:"toolFailures"`
	OutOfScopeHosts    []string `json:"outOfScopeHosts"`
	ClassesNotAssessed []string `json:"classesNotAssessed"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Run describes the assessment.
type Run struct {
	ID                     string      `json:"id"`
	Target                 string      `json:"target"`
	TargetName             string      `json:"targetName,omitempty"`
	Profile                string      `json:"profile"`
	StartedAt              time.Time   `json:"startedAt"`
	FinishedAt             time.Time   `json:"finishedAt"`
	Scope                  []string    `json:"scope"`
	AllowsPrivateAddresses bool        `json:"allowsPrivateAddresses"`
	Environment            Environment `json:"environment"`
}

// Environment records stated deviations from production, as facts rather than a
// score. A numeric "fidelity percentage" would invent precision nobody has.
type Environment struct {
	Name        string   `json:"name,omitempty"`
	Differences []string `json:"differences,omitempty"`
}

// Assurance states plainly what this run does and does not support.
type Assurance struct {
	// Statement is the sentence that must survive being quoted alone.
	Statement string `json:"statement"`
	// SurfaceCompleteness explains the limits of the denominator.
	SurfaceCompleteness string `json:"surfaceCompleteness"`
	// ExecutedChecks, BlockedChecks and UntestedSurface summarise the ledger.
	ExecutedChecks  int `json:"executedChecks"`
	BlockedChecks   int `json:"blockedChecks"`
	UntestedSurface int `json:"untestedSurface"`
	// ConfirmedFindings and SuspectedFindings are counted separately, because
	// conflating them is how a suspicion becomes a claim.
	ConfirmedFindings int `json:"confirmedFindings"`
	SuspectedFindings int `json:"suspectedFindings"`
}

// Surface describes what was discovered and how much it can be trusted.
type Surface struct {
	SpecDerived    bool     `json:"specDerived"`
	Source         Source   `json:"source"`
	Title          string   `json:"title,omitempty"`
	SpecVersion    string   `json:"specVersion,omitempty"`
	OperationCount int      `json:"operationCount"`
	Oracle         Oracle   `json:"oracle"`
	ExternalRefs   []string `json:"refusedExternalReferences,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// Source records where a fact came from.
type Source struct {
	Kind       string    `json:"kind"`
	Ref        string    `json:"ref,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
}

// Oracle grades the expectation source.
type Oracle struct {
	Level      string `json:"level"`
	Provenance string `json:"provenance"`
	Detail     string `json:"detail"`
	Protected  int    `json:"protectedOperations"`
	Public     int    `json:"publicOperations"`
	Unstated   int    `json:"unstatedOperations"`
}

// Finding is a published finding.
type Finding struct {
	ID           string       `json:"id"`
	CheckID      string       `json:"checkId"`
	Title        string       `json:"title"`
	State        string       `json:"state"`
	Severity     string       `json:"severity"`
	Confidence   string       `json:"confidence"`
	CWE          []string     `json:"cwe,omitempty"`
	OWASP        []string     `json:"owasp,omitempty"`
	OperationID  string       `json:"operationId,omitempty"`
	IdentityID   string       `json:"identityId,omitempty"`
	Expected     string       `json:"expected"`
	Actual       string       `json:"actual"`
	EvidenceRefs []string     `json:"evidenceRefs,omitempty"`
	Verification Verification `json:"verification"`
	Remediation  string       `json:"remediation,omitempty"`
	Reproduction []string     `json:"reproduction,omitempty"`
}

// Verification explains how far a hypothesis was tested.
type Verification struct {
	Strategy    string             `json:"strategy"`
	Performed   bool               `json:"performed"`
	Result      string             `json:"result,omitempty"`
	Steps       []VerificationStep `json:"steps,omitempty"`
	Unavailable []string           `json:"unavailable,omitempty"`
}

// VerificationStep is one discriminator and its result.
type VerificationStep struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// CoverageEntry is one ledger row.
type CoverageEntry struct {
	Dimension    string   `json:"dimension"`
	Subject      string   `json:"subject"`
	CheckID      string   `json:"checkId,omitempty"`
	IdentityID   string   `json:"identityId,omitempty"`
	Disposition  string   `json:"disposition"`
	Cause        string   `json:"cause,omitempty"`
	Detail       string   `json:"detail,omitempty"`
	EvidenceRefs []string `json:"evidenceRefs,omitempty"`
}

// Build maps an engine result onto the published schema.
func Build(res engine.Result, version string) Document {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "assay", Version: version},
		Run: Run{
			ID:                     res.RunID,
			Target:                 res.Target,
			TargetName:             res.TargetName,
			Profile:                string(res.Profile),
			StartedAt:              res.StartedAt,
			FinishedAt:             res.FinishedAt,
			Scope:                  nonNil(res.ScopeEntries),
			AllowsPrivateAddresses: res.AllowPrivate,
			Environment: Environment{
				Name:        res.Environment.Name,
				Differences: res.Environment.Differences,
			},
		},
		Surface: Surface{
			SpecDerived: res.Surface.SpecDerived,
			Source: Source{
				Kind:       string(res.Surface.SpecSource.Kind),
				Ref:        res.Surface.SpecSource.Ref,
				ObservedAt: res.Surface.SpecSource.ObservedAt,
			},
			Title:          res.Surface.SpecTitle,
			SpecVersion:    res.Surface.SpecVersion,
			OperationCount: len(res.Surface.Operations),
			Oracle: Oracle{
				Level:      string(res.Surface.Fidelity.Level),
				Provenance: string(res.Surface.Fidelity.Provenance),
				Detail:     res.Surface.Fidelity.Detail,
				Protected:  res.Surface.Fidelity.Protected,
				Public:     res.Surface.Fidelity.Public,
				Unstated:   res.Surface.Fidelity.Silent,
			},
			ExternalRefs: res.Surface.ExternalRefs,
			Warnings:     res.Surface.Warnings,
		},
		Findings:           make([]Finding, 0, len(res.Findings)),
		Coverage:           make([]CoverageEntry, 0, len(res.Coverage)),
		ToolFailures:       nonNil(res.ToolFailures),
		OutOfScopeHosts:    nonNil(res.OutOfScopeHosts),
		ClassesNotAssessed: nonNil(res.ClassesNotAssessed),
	}

	for _, f := range res.Findings {
		doc.Findings = append(doc.Findings, Finding{
			ID:           f.ID,
			CheckID:      f.CheckID,
			Title:        f.Title,
			State:        string(f.State),
			Severity:     string(f.Severity),
			Confidence:   string(f.Confidence),
			CWE:          f.CWE,
			OWASP:        f.OWASP,
			OperationID:  f.OperationID,
			IdentityID:   f.IdentityID,
			Expected:     f.Expected,
			Actual:       f.Actual,
			EvidenceRefs: f.EvidenceRefs,
			Verification: Verification{
				Strategy:    f.Verification.Strategy,
				Performed:   f.Verification.Performed,
				Result:      f.Verification.Result,
				Steps:       toSteps(f.Verification.Steps),
				Unavailable: f.Verification.Unavailable,
			},
			Remediation:  f.Remediation,
			Reproduction: f.Reproduction,
		})
	}

	for _, e := range res.Coverage {
		doc.Coverage = append(doc.Coverage, CoverageEntry{
			Dimension:    e.Dimension,
			Subject:      e.Subject,
			CheckID:      e.CheckID,
			IdentityID:   e.IdentityID,
			Disposition:  string(e.Disposition),
			Cause:        string(e.Cause),
			Detail:       e.Detail,
			EvidenceRefs: e.EvidenceRefs,
		})
	}

	doc.Assurance = buildAssurance(res)
	return doc
}

func toSteps(in []model.VerificationStep) []VerificationStep {
	if len(in) == 0 {
		return nil
	}
	out := make([]VerificationStep, 0, len(in))
	for _, s := range in {
		out = append(out, VerificationStep{Name: s.Name, Passed: s.Passed, Detail: s.Detail})
	}
	return out
}

// buildAssurance writes the sentence that must survive being quoted alone.
func buildAssurance(res engine.Result) Assurance {
	a := Assurance{
		ExecutedChecks: res.ExecutedCount(),
		BlockedChecks:  res.BlockedCount(),
	}
	for _, e := range res.Coverage {
		if e.Disposition == model.DispositionUntested {
			a.UntestedSurface++
		}
	}
	for _, f := range res.Findings {
		switch f.State {
		case model.StateConfirmed:
			a.ConfirmedFindings++
		case model.StateSuspected:
			a.SuspectedFindings++
		}
	}

	if res.Surface.SpecDerived {
		a.SurfaceCompleteness = "This ledger enumerates only the operations declared in the " +
			"specification Assay was given. Routes that exist but are not documented were not " +
			"discovered, are not counted here, and were not tested. Coverage is therefore relative " +
			"to the specification, not to the application."
	} else {
		a.SurfaceCompleteness = "No specification was available, so no attack surface was enumerated."
	}

	switch {
	case a.ExecutedChecks == 0:
		a.Statement = "This assessment executed no checks. It establishes nothing about the " +
			"security of the target. See the coverage ledger for why each planned item did not run."
	default:
		a.Statement = "This assessment ran a limited set of checks against a specification-derived " +
			"attack surface. It does not establish that the target is secure. Absence of findings " +
			"here means only that these checks, against these operations, produced none — see " +
			"classesNotAssessed for weakness classes nothing in this run examined."
	}
	return a
}

// nonNil ensures slices marshal as [] rather than null, so consumers need no
// null handling.
func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// WriteJSON renders the document.
func WriteJSON(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Target-controlled strings are already sanitized upstream; escaping HTML
	// here is belt and braces for anything that reaches a browser.
	enc.SetEscapeHTML(true)
	return enc.Encode(doc)
}

// Summary renders a short human-readable result for a terminal.
func Summary(doc Document) string {
	var b strings.Builder
	b.WriteString("Assay assessment " + doc.Run.ID + "\n")
	b.WriteString("  target:   " + doc.Run.Target + "\n")
	b.WriteString("  profile:  " + doc.Run.Profile + "\n")
	b.WriteString("  surface:  " + strconv.Itoa(doc.Surface.OperationCount) + " operations from " +
		doc.Surface.Source.Kind + "\n")
	b.WriteString("  oracle:   " + doc.Surface.Oracle.Level + " (" + doc.Surface.Oracle.Provenance + ")\n")
	b.WriteString("\n")
	b.WriteString("  executed: " + strconv.Itoa(doc.Assurance.ExecutedChecks) + "\n")
	b.WriteString("  blocked:  " + strconv.Itoa(doc.Assurance.BlockedChecks) + "\n")
	b.WriteString("  untested: " + strconv.Itoa(doc.Assurance.UntestedSurface) + "\n")
	b.WriteString("  findings: " + strconv.Itoa(doc.Assurance.ConfirmedFindings) + " confirmed, " +
		strconv.Itoa(doc.Assurance.SuspectedFindings) + " suspected\n")
	b.WriteString("\n")
	b.WriteString(wrap(doc.Assurance.Statement, 76, "  "))
	return b.String()
}

// wrap breaks text to a display width for terminal output.
//
// Widths are counted in runes, not bytes: the assurance statement contains
// em-dashes, and byte arithmetic would wrap it short.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := indent
	lineWidth := utf8.RuneCountInString(indent)
	indentWidth := lineWidth
	for _, w := range words {
		wordWidth := utf8.RuneCountInString(w)
		if lineWidth+wordWidth+1 > width && lineWidth > indentWidth {
			b.WriteString(line + "\n")
			line, lineWidth = indent, indentWidth
		}
		if lineWidth > indentWidth {
			line += " "
			lineWidth++
		}
		line += w
		lineWidth += wordWidth
	}
	b.WriteString(line + "\n")
	return b.String()
}
