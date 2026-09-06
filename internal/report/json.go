// Package report renders an assessment result into published formats.
//
// This package owns the wire schema. The domain model deliberately carries no
// struct tags, so renaming an internal field is never a breaking change to
// anything a consumer parses. Everything published passes through the DTOs here.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jaylordibe/application-security-framework/internal/adapter"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// SchemaVersion identifies the output contract. It is the first field of every
// document so a consumer can dispatch on it before parsing anything else.
//
// Consumers must treat an unrecognised blocked cause, outcome or finding state
// as blocked rather than as success. Within a major version, fields are added
// but never removed or repurposed.
const SchemaVersion = "appsec.report/v1alpha1"

// Document is the JSON report.
type Document struct {
	SchemaVersion string `json:"schemaVersion"`
	Tool          Tool   `json:"tool"`
	Run           Run    `json:"run"`

	// Assurance is deliberately the first substantive section. A reader who
	// stops after one paragraph must not come away believing more than the
	// evidence supports.
	Assurance Assurance `json:"assurance"`

	Surface Surface `json:"surface"`
	// Identities records what was known about each configured principal. It
	// carries no credential, no credential length and no fingerprint: an
	// identity's id is publishable, and its material never is.
	Identities []Identity `json:"identities"`
	// Ownership accounts for the cross-owner boundaries this run exercised and
	// states plainly what they do not cover.
	Ownership Ownership `json:"ownership"`
	// Adapters records what framework adapters contributed and what they could
	// not determine. It carries source locations, never source contents.
	Adapters AdapterAccount `json:"adapters"`
	// Engines records what each external scanning engine did, and what it did
	// not. An engine that failed assessed nothing, and that must not read the
	// same as an engine that found nothing.
	Engines  EngineAccount   `json:"engines"`
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
	// AuthenticatedControl states what the run could establish about identities,
	// because whether an authenticated baseline existed bounds how far any
	// authorization conclusion in this report can go.
	AuthenticatedControl string `json:"authenticatedControl"`
}

// Identity is a configured principal and what was established about it.
type Identity struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	// Scheme is the authentication mechanism, e.g. bearer.
	Scheme string `json:"scheme,omitempty"`
	// CredentialSource names where the credential was read from, by location.
	// A location is not a secret; the value it points at is, and is absent.
	CredentialSource string `json:"credentialSource,omitempty"`
	// Usable reports whether a credential was resolved at all.
	Usable bool `json:"usable"`
	// Problem explains an unusable identity or a failed canary.
	Problem string `json:"problem,omitempty"`
	// LivenessMonitored reports whether a canary is configured. Without one an
	// expiry during the run could not have been detected, which bounds every
	// conclusion drawn from this identity.
	LivenessMonitored bool     `json:"livenessMonitored"`
	Liveness          string   `json:"liveness"`
	LastGoodAt        string   `json:"lastGoodAt,omitempty"`
	FirstBadAt        string   `json:"firstBadAt,omitempty"`
	CanaryProbes      int      `json:"canaryProbes"`
	Warnings          []string `json:"warnings,omitempty"`
}

// Ownership is the cross-owner account.
//
// It carries no percentage. The number of ownership boundaries an application
// has is unknown and unknowable from a specification, so a percentage would need
// a denominator nobody has. What can be stated truthfully is which boundaries
// were exercised.
type Ownership struct {
	// Statement says in words what the numbers do and do not mean.
	Statement string `json:"statement"`
	// BoundariesVerified counts cross-owner units that reached a conclusion.
	BoundariesVerified int `json:"boundariesVerified"`
	BoundariesBlocked  int `json:"boundariesBlocked"`
	BoundariesUntested int `json:"boundariesUntested"`
	// Findings counts cross-owner findings.
	Findings int `json:"findings"`
	// Tested lists each exercised tuple, so a reader can see the actual extent
	// rather than inferring it from a count.
	Tested []string `json:"tested"`
}

// AdapterAccount is the framework-adapter section of a report.
//
// It exists so a reader can tell how a security expectation was arrived at. A
// static inference drawn from route files and a runtime answer from the
// framework itself are not the same claim, and neither is evidence that a
// control actually works — that is what the runtime checks establish.
type AdapterAccount struct {
	// Statement says in words what adapter facts do and do not mean.
	Statement string `json:"statement"`
	// Corroborated, Added and Conflicting count how adapter facts related to
	// what the specification already said.
	Corroborated int `json:"corroborated"`
	Added        int `json:"added"`
	Conflicting  int `json:"conflicting"`
	Undetermined int `json:"undetermined"`
	// Conflicts describe each disagreement between sources, in full. A
	// disagreement between two of the application's own artefacts is a finding
	// about the application, not a detail to summarise away.
	Conflicts []AdapterConflict `json:"conflicts,omitempty"`
	// Failures name adapters that produced nothing usable.
	Failures []string `json:"failures,omitempty"`
	// Limitations are what the adapters said they could not determine.
	Limitations []string `json:"limitations,omitempty"`
	// UnmatchedOperations are routes an adapter reported that the specification
	// does not contain. They are recorded and not tested.
	UnmatchedOperations []string `json:"operationsOutsideSpecification,omitempty"`
}

// AdapterConflict is one disagreement between sources about one operation.
type AdapterConflict struct {
	OperationID string `json:"operationId"`
	Kind        string `json:"kind"`
	Adapter     string `json:"adapter"`
	// Provenance is the grade the adapter's extraction method earns.
	Provenance string `json:"provenance"`
	Detail     string `json:"detail"`
	// Source locates the application code behind the adapter's claim.
	Source string `json:"source,omitempty"`
}

// EngineAccount is the external-engine section of a report.
type EngineAccount struct {
	// Statement says in words what engine results do and do not mean.
	Statement string `json:"statement"`
	// Runs describes each engine that was enabled.
	Runs []EngineRun `json:"runs,omitempty"`
	// Failures name engines that produced nothing usable.
	Failures []string `json:"failures,omitempty"`
	// Limitations are what the engines could not do.
	Limitations []string `json:"limitations,omitempty"`
}

// EngineRun is one external engine's execution record.
type EngineRun struct {
	Engine  string `json:"engine"`
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	// ExecutablePath says which program ran, rather than which name was on
	// PATH.
	ExecutablePath string `json:"executablePath,omitempty"`
	// ProvenanceVerified is false for anything a user installed. AppSec
	// Framework cannot establish that a binary is a genuine upstream build and
	// does not imply a chain of custody it has not checked.
	ProvenanceVerified bool `json:"provenanceVerified"`
	// RuleSource identifies the templates or rules that ran, which is what
	// makes a result reproducible.
	RuleSource string `json:"ruleSource,omitempty"`
	// Arguments is the redacted argument vector.
	Arguments []string `json:"arguments,omitempty"`
	Cause     string   `json:"cause,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	// Observations counts what it contributed.
	Observations int   `json:"observations"`
	DurationMS   int64 `json:"durationMs"`
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
	ID          string   `json:"id"`
	CheckID     string   `json:"checkId"`
	Title       string   `json:"title"`
	State       string   `json:"state"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	OperationID string   `json:"operationId,omitempty"`
	IdentityID  string   `json:"identityId,omitempty"`
	ResourceID  string   `json:"resourceId,omitempty"`
	OwnerID     string   `json:"ownerIdentityId,omitempty"`
	// External carries the engine's own account of an imported observation.
	// Its severity and confidence are the engine's scales, not AppSec's.
	External     *ExternalSource `json:"externalSource,omitempty"`
	Expected     string          `json:"expected"`
	Actual       string          `json:"actual"`
	EvidenceRefs []string        `json:"evidenceRefs,omitempty"`
	Verification Verification    `json:"verification"`
	Remediation  string          `json:"remediation,omitempty"`
	Reproduction []string        `json:"reproduction,omitempty"`
}

// ExternalSource is an imported result's provenance.
type ExternalSource struct {
	Engine         string `json:"engine"`
	EngineVersion  string `json:"engineVersion,omitempty"`
	ExecutablePath string `json:"executablePath,omitempty"`
	RunID          string `json:"runId,omitempty"`
	RuleID         string `json:"ruleId"`
	RuleName       string `json:"ruleName,omitempty"`
	// Severity and Confidence are the engine's own values, unconverted. AppSec
	// Framework's severity for these findings is "unassessed", which is the
	// truthful answer: it has not judged them.
	Severity       string   `json:"sourceSeverity,omitempty"`
	Confidence     string   `json:"sourceConfidence,omitempty"`
	Location       string   `json:"location,omitempty"`
	Parameter      string   `json:"parameter,omitempty"`
	References     []string `json:"references,omitempty"`
	RuleProvenance string   `json:"ruleProvenance,omitempty"`
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
	ResourceID   string   `json:"resourceId,omitempty"`
	OwnerID      string   `json:"ownerIdentityId,omitempty"`
	Disposition  string   `json:"disposition"`
	Cause        string   `json:"cause,omitempty"`
	Detail       string   `json:"detail,omitempty"`
	EvidenceRefs []string `json:"evidenceRefs,omitempty"`
}

// Build maps an engine result onto the published schema.
func Build(res engine.Result, version string) Document {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "application-security-framework", Version: version},
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
		Identities:         make([]Identity, 0, len(res.Identities)),
		Coverage:           make([]CoverageEntry, 0, len(res.Coverage)),
		ToolFailures:       nonNil(res.ToolFailures),
		OutOfScopeHosts:    nonNil(res.OutOfScopeHosts),
		ClassesNotAssessed: nonNil(res.ClassesNotAssessed),
	}

	for _, st := range res.Identities {
		doc.Identities = append(doc.Identities, Identity{
			ID:                st.ID,
			Label:             st.Label,
			Scheme:            string(st.Scheme),
			CredentialSource:  st.Source,
			Usable:            st.Usable,
			Problem:           st.Problem,
			LivenessMonitored: st.Monitored,
			Liveness:          string(st.Liveness),
			LastGoodAt:        timeOrEmpty(st.LastGood),
			FirstBadAt:        timeOrEmpty(st.FirstBad),
			CanaryProbes:      st.Probes,
			Warnings:          st.Warnings,
		})
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
			ResourceID:   f.ResourceID,
			OwnerID:      f.OwnerIdentityID,
			External:     externalSource(f.External),
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
			ResourceID:   e.ResourceID,
			OwnerID:      e.OwnerIdentityID,
			Disposition:  string(e.Disposition),
			Cause:        string(e.Cause),
			Detail:       e.Detail,
			EvidenceRefs: e.EvidenceRefs,
		})
	}

	doc.Adapters = buildAdapterAccount(res.Surface)
	doc.Engines = buildEngineAccount(res.Engines)
	doc.Ownership = Ownership{
		Statement:          res.Ownership.Statement,
		BoundariesVerified: res.Ownership.Verified,
		BoundariesBlocked:  res.Ownership.Blocked,
		BoundariesUntested: res.Ownership.Untested,
		Findings:           res.Ownership.Findings,
		Tested:             nonNil(res.Ownership.Boundaries),
	}
	doc.Assurance = buildAssurance(res)
	return doc
}

// timeOrEmpty renders a timestamp, or nothing when it was never set. A zero
// time rendered as "0001-01-01T00:00:00Z" reads as a real observation.
func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
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
		// Count untested assessment work only, on the same rule as the executed
		// and blocked counts: an identity row is a precondition, not surface.
		if e.Disposition == model.DispositionUntested && engine.IsAssessmentWork(e.Dimension) {
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
			"specification AppSec Framework was given. Routes that exist but are not documented were not " +
			"discovered, are not counted here, and were not tested. Coverage is therefore relative " +
			"to the specification, not to the application."
	} else {
		a.SurfaceCompleteness = "No specification was available, so no attack surface was enumerated."
	}

	a.AuthenticatedControl = authenticatedControlStatement(res)

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

// buildAdapterAccount summarises what adapters contributed.
func buildAdapterAccount(s engine.Surface) AdapterAccount {
	a := AdapterAccount{
		Failures:            nonNil(s.AdapterFailures),
		Limitations:         nonNil(s.AdapterLimitations),
		UnmatchedOperations: nonNil(s.AdapterUnmatched),
	}
	for _, m := range s.AdapterMerges {
		switch m.Agreement {
		case adapter.AgreementCorroborated:
			a.Corroborated++
		case adapter.AgreementNew:
			a.Added++
		case adapter.AgreementUnknown:
			a.Undetermined++
		case adapter.AgreementConflict:
			a.Conflicting++
			c := AdapterConflict{
				OperationID: m.OperationID,
				Kind:        string(m.Kind),
				Adapter:     m.Adapter,
				Provenance:  string(m.Provenance),
				Detail:      m.Detail,
			}
			if m.Evidence.File != "" {
				c.Source = m.Evidence.File
				if m.Evidence.Line > 0 {
					c.Source = fmt.Sprintf("%s:%d", m.Evidence.File, m.Evidence.Line)
				}
			}
			a.Conflicts = append(a.Conflicts, c)
		}
	}

	switch {
	case len(s.AdapterMerges) == 0 && len(s.AdapterFailures) == 0:
		a.Statement = "No framework adapter ran, so every expectation in this report comes from " +
			"the specification or from configuration."
	case len(s.AdapterFailures) > 0 && len(s.AdapterMerges) == 0:
		a.Statement = "Every configured framework adapter failed, so no framework-derived " +
			"expectation was added. This does not mean the application has no authorization " +
			"controls; it means none were read."
	case a.Conflicting > 0:
		a.Statement = fmt.Sprintf("A framework adapter and the specification disagree about %d "+
			"operation(s). Neither is used as an oracle for those, because choosing between two "+
			"of the application's own artefacts with no evidence would be a guess. Adapter facts "+
			"are expectations about what should happen, never evidence that a control works.",
			a.Conflicting)
	default:
		a.Statement = "Framework adapters contributed expectations about what the application " +
			"should enforce. An adapter fact is an expectation, not evidence: whether a control " +
			"actually works is established by the runtime checks, not by reading source."
	}
	return a
}

// externalSource maps imported provenance onto the wire format.
func externalSource(e *model.ExternalSource) *ExternalSource {
	if e == nil {
		return nil
	}
	return &ExternalSource{
		Engine: e.Engine, EngineVersion: e.EngineVersion, ExecutablePath: e.ExecutablePath,
		RunID: e.RunID, RuleID: e.RuleID, RuleName: e.RuleName,
		Severity: e.Severity, Confidence: e.Confidence,
		Location: e.Location, Parameter: e.Parameter,
		References: e.References, RuleProvenance: e.RuleProvenance,
	}
}

// buildEngineAccount summarises what the external engines did.
func buildEngineAccount(c scanner.Collection) EngineAccount {
	a := EngineAccount{
		Statement:   c.Statement(),
		Failures:    nonNil(c.Failures),
		Limitations: nonNil(c.Limitations),
	}
	for _, o := range c.Outcomes {
		a.Runs = append(a.Runs, EngineRun{
			Engine:             o.Engine,
			Status:             string(o.Status),
			Version:            o.Provenance.Version,
			ExecutablePath:     o.Provenance.ExecutablePath,
			ProvenanceVerified: o.Provenance.Verified,
			RuleSource:         o.Provenance.RuleSource,
			Arguments:          o.Provenance.Arguments,
			Cause:              string(o.Cause),
			Detail:             o.Detail,
			Observations:       len(o.Observations),
			DurationMS:         o.Duration.Milliseconds(),
		})
	}
	return a
}

// authenticatedControlStatement says what the run could establish about the
// identities it was given.
//
// This sentence exists because "no confirmed findings" means something very
// different depending on whether an authenticated baseline was available. A
// reader who does not know which case they are in cannot interpret the rest of
// the report.
func authenticatedControlStatement(res engine.Result) string {
	if len(res.Identities) == 0 {
		return "No identity was configured, so no authenticated control request was made. " +
			"No finding can reach confirmed without one, and every authorization conclusion here " +
			"rests on unauthenticated observation alone."
	}
	var usable, monitored, bad int
	for _, st := range res.Identities {
		if st.Usable {
			usable++
		}
		if st.Monitored {
			monitored++
		}
		if st.Liveness == identity.LivenessBad {
			bad++
		}
	}
	switch {
	case usable == 0:
		return "An identity was configured but no credential could be resolved, so no " +
			"authenticated control request was made. Authorization conclusions here rest on " +
			"unauthenticated observation alone; see the identity rows in the coverage ledger."
	case bad > 0:
		return "An identity was rejected by the target during this run. Results that depended on " +
			"it are withdrawn and marked blocked, and any finding it corroborated is reported as " +
			"suspected rather than confirmed."
	case monitored == 0:
		return "An authenticated control request was available, but no liveness canary is " +
			"configured, so a credential expiring during the run could not have been detected. " +
			"Confirmed findings here were each corroborated by a control request that succeeded " +
			"at the moment it ran."
	default:
		return "An authenticated control request was available and its identity was confirmed " +
			"live by a canary, so an anonymous response could be compared against what a " +
			"legitimate caller receives."
	}
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
	b.WriteString("AppSec Framework assessment " + doc.Run.ID + "\n")
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

	// Ownership is stated in the terminal, not only in the JSON.
	//
	// A cross-owner finding is the most quotable thing this tool produces, and
	// the extent behind it is the least visible: one boundary, on one resource,
	// between one pair of identities. An operator who sees "2 confirmed" and
	// never sees how narrow the test was will generalise it, and the report will
	// have let them.
	if o := doc.Ownership; o.BoundariesVerified+o.BoundariesBlocked+o.BoundariesUntested > 0 {
		b.WriteString("\n")
		b.WriteString("  ownership boundaries checked: " + strconv.Itoa(o.BoundariesVerified))
		if o.BoundariesBlocked > 0 {
			b.WriteString(", blocked " + strconv.Itoa(o.BoundariesBlocked))
		}
		if o.BoundariesUntested > 0 {
			b.WriteString(", untested " + strconv.Itoa(o.BoundariesUntested))
		}
		b.WriteString("\n")
		for _, t := range o.Tested {
			b.WriteString("    - " + t + "\n")
		}
		b.WriteString(wrap(o.Statement, 76, "  "))
	}

	// External engine results are stated in the terminal too.
	//
	// They are neither confirmed nor suspected — an imported alert is observed
	// — so without this an operator whose Nuclei reported twelve criticals
	// reads "findings: 0 confirmed, 0 suspected" and concludes the engine found
	// nothing. The count is deliberately not folded into the findings line:
	// these are another tool's claims, and merging them would be exactly the
	// promotion this project refuses to do.
	var ran []EngineRun
	for _, r := range doc.Engines.Runs {
		// An engine nobody enabled is not a result. Listing it would pad the
		// summary with work that was never planned.
		if r.Status != string(scanner.StatusSkipped) {
			ran = append(ran, r)
		}
	}
	if len(ran) > 0 {
		b.WriteString("\n")
		for _, r := range ran {
			line := "  engine " + r.Engine + ": " + r.Status
			if r.Version != "" {
				line += " (" + r.Version + ")"
			}
			switch {
			case r.Status == string(scanner.StatusBlocked):
				// The detail already names what was lost.
			case r.Observations == 1:
				line += ", 1 observation"
			default:
				line += ", " + strconv.Itoa(r.Observations) + " observations"
			}
			b.WriteString(line + "\n")
		}
		if n := observedCount(doc.Findings); n > 0 {
			sentence := strconv.Itoa(n) + " external results are recorded as observed. They are " +
				"another tool's claims, unverified by AppSec Framework, and are not counted as " +
				"confirmed or suspected findings."
			if n == 1 {
				sentence = "1 external result is recorded as observed. It is another tool's " +
					"claim, unverified by AppSec Framework, and is not counted as a confirmed " +
					"or suspected finding."
			}
			b.WriteString(wrap(sentence, 76, "  "))
		}
	}

	b.WriteString("\n")
	b.WriteString(wrap(doc.Assurance.Statement, 76, "  "))
	return b.String()
}

// observedCount counts findings imported from an external engine.
func observedCount(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.State == string(model.StateObserved) {
			n++
		}
	}
	return n
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
