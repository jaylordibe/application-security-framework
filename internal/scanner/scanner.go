// Package scanner runs external scanning engines and normalizes what they find.
//
// AppSec Framework does not reimplement Nuclei's template engine, ZAP's active
// scanner or Semgrep's dataflow analysis. Those are mature, specialised and
// maintained by people who do nothing else. What this project owns is the part
// nobody else does: supervising them safely, keeping them inside the
// authorization boundary, preserving where every result came from, and being
// honest about what did not run.
//
// The rule that governs everything here: **an external alert is an observation,
// not a finding.** Nuclei saying "critical" is a statement about a template's
// category. ZAP saying "high confidence" is a statement about ZAP's matcher.
// Neither is evidence that this application is exploitable, and neither may
// promote itself. Only AppSec's own deterministic verification can do that, and
// where AppSec has no verification for a class, `observed` is the honest and
// final state (ADR-0005).
package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/proc"
)

// Budgets. Generous for a real scan, bounded against a hostile or broken tool.
const (
	// MaxStdout bounds a structured result document.
	MaxStdout int64 = 64 << 20 // 64 MiB
	// MaxStderr bounds diagnostics.
	MaxStderr int64 = 256 << 10
	// MaxObservations bounds how many results one engine may contribute.
	MaxObservations = 10000
	// MaxStringBytes bounds any single imported string. Engine output is
	// attacker-influenced — a target chooses what appears in a matched response
	// — and it reaches terminals, reports and SARIF viewers.
	MaxStringBytes = 4096
	// DefaultTimeout bounds one engine run.
	DefaultTimeout = 10 * time.Minute
	// DefaultVersionTimeout bounds the version probe, which must be quick.
	DefaultVersionTimeout = 20 * time.Second
)

// Capability is a weakness class an engine can look for.
//
// These are the strings the coverage account already uses, so that an engine
// claiming a capability removes exactly the entry it earns from
// classesNotAssessed and nothing more.
type Capability string

// Meta identifies an engine.
type Meta struct {
	// ID is the engine's identifier, e.g. "nuclei".
	ID string
	// Title is a human name for reports.
	Title string
	// Capabilities are the weakness classes this engine can cover *when it runs
	// with the right configuration*. Claiming one is not the same as having
	// covered it; see Normalized.Covered.
	Capabilities []Capability
	// Unlocks describes, for `doctor`, what installing this engine would buy.
	Unlocks string
	// InstallHint tells an operator how to get it, without AppSec fetching
	// anything itself.
	InstallHint string
}

// Availability is what was learned about an engine without scanning.
type Availability struct {
	// Present is true when the executable was found and answered a version
	// probe.
	Present bool
	// Path is the resolved executable, recorded so a report says which program
	// ran rather than which name was on PATH.
	Path string
	// Version is what the tool reported about itself.
	//
	// It is the tool's own claim and nothing more. AppSec cannot establish that
	// a binary named `nuclei` is ProjectDiscovery's Nuclei, and does not
	// pretend to: see Provenance.
	Version string
	// Problem explains an engine that is not usable.
	Problem string
	// Warnings are non-fatal observations about the installation.
	Warnings []string
}

// Target is what an engine is pointed at.
type Target struct {
	// BaseURL is the authorized origin. For a runtime engine this is the only
	// host it may contact.
	BaseURL string
	// SourceRoot is an application checkout, for engines that read code.
	SourceRoot string
	// SpecPath is an OpenAPI document on disk, for engines that can import one.
	SpecPath string
	// Profile is the effective assessment safety profile.
	Profile model.Profile
}

// Provenance records what actually ran, so a result can be reproduced and so a
// report never overstates what AppSec knows about the tool.
type Provenance struct {
	// Engine, Version and ExecutablePath describe the program.
	Engine         string
	Version        string
	ExecutablePath string
	// Arguments is the argument vector, already redacted for display. It is
	// recorded because "which flags ran" is the difference between a scan that
	// covered a class and one that did not.
	Arguments []string
	// RuleSource describes where templates or rules came from, and whether they
	// were pinned. Without it, a result is not reproducible: the same command
	// against a corpus that changed overnight is a different scan.
	RuleSource string
	// Verified reports whether AppSec could establish that this executable is
	// what it claims to be. It is false for anything a user installed, and the
	// report says so rather than implying a provenance chain that does not
	// exist.
	Verified bool
}

// Observation is one normalized external result.
//
// It is deliberately not called a finding. A finding is something AppSec has an
// opinion about; this is something another tool said.
type Observation struct {
	// RuleID and RuleName identify what fired.
	RuleID   string
	RuleName string
	// Location is a URL, or a file and line for a source scanner.
	Location string
	// Parameter names the implicated input, when the engine says.
	Parameter string
	// SourceSeverity and SourceConfidence are the engine's own values, kept
	// verbatim and never converted.
	SourceSeverity   string
	SourceConfidence string
	// References are the engine's classifications: CWE, CVE, WASC.
	References []string
	// Detail is a short operator-facing description.
	Detail string
	// Evidence is the engine's supporting excerpt, sanitized and bounded. It
	// may be empty: some engines return matched response bytes, which is
	// exactly where a reflected credential would appear.
	Evidence string
}

// Normalized is everything one engine run produced.
type Normalized struct {
	Observations []Observation
	// Covered are the capabilities this run *actually exercised*. An engine
	// that started but ran no relevant rules covers nothing, and saying
	// otherwise would let launching a process count as assessing a class.
	Covered []Capability
	// Limitations are what the engine could not do, in its own terms.
	Limitations []string
	// Partial marks a result that is incomplete but retained.
	Partial bool
}

// Invocation is what an engine asks to have run.
//
// EnvNames is separate from Spec.Env on purpose. An engine declares which
// variables it needs; the runner decides what it actually gets, applying the
// forbidden list that keeps this tool's own credentials out. Letting an engine
// build its own environment would put that enforcement in three places and make
// it optional in all of them.
type Invocation struct {
	Spec       proc.Spec
	EnvNames   []string
	Provenance Provenance
}

// Workspace is a temporary directory for one engine run.
type Workspace struct {
	// Dir is the working directory, created empty and removed afterwards.
	Dir string
	// OutputPath is a path inside Dir an engine may write results to, for tools
	// that will not write structured output to stdout.
	OutputPath string
}

// Engine is one external scanning tool.
//
// The interface is small on purpose. Supervision, budgets, environment
// construction, failure accounting and provenance all belong to this package,
// identically for every engine; what differs between Nuclei, ZAP and Semgrep is
// only how to ask them a question and how to read the answer.
type Engine interface {
	// Meta identifies the engine.
	Meta() Meta
	// Detect resolves the executable and asks it for its version. It must not
	// scan anything.
	Detect(ctx context.Context, s Settings) Availability
	// RequiredProfile is the safety profile a run needs. An engine that sends
	// attack traffic must require more than one that reads files.
	RequiredProfile(s Settings) model.Profile
	// Invocation builds the argument vector and provenance for a run. It never
	// builds a shell string.
	Invocation(t Target, s Settings, w Workspace, a Availability) (Invocation, error)
	// Normalize turns captured output into observations.
	//
	// It is given the settings as well as the output because what a run covered
	// depends on what it was asked to do: a ZAP passive scan and a ZAP active
	// scan produce the same report shape and assess entirely different things.
	Normalize(stdout []byte, w Workspace, p Provenance, s Settings) (Normalized, error)
}

// Settings is an engine's operator configuration.
//
// It is deliberately not a generic command specification. There is no
// `command`, no `args` and no `env` an operator can set freely: that would make
// AppSec a shell runner wearing a security tool's name, and every hardening in
// this package would become optional.
type Settings struct {
	// Enabled turns the engine on. Engines are off by default.
	Enabled bool
	// Executable is an explicit path. Empty means look the engine's own binary
	// name up on PATH.
	Executable string
	// RuleSource is a template or rule directory the operator supplies.
	RuleSource string
	// TimeoutSeconds bounds the run. Zero uses DefaultTimeout.
	TimeoutSeconds int
	// PassEnv names environment variables to forward. The environment is
	// otherwise built from nothing.
	PassEnv []string
	// Severity optionally narrows which severities an engine reports.
	Severity []string
	// Extra carries a small set of engine-specific, validated options. It is
	// never a passthrough for arbitrary flags.
	Extra map[string]string
}

// Timeout returns the effective run timeout.
func (s Settings) Timeout() time.Duration {
	if s.TimeoutSeconds > 0 {
		return time.Duration(s.TimeoutSeconds) * time.Second
	}
	return DefaultTimeout
}

// Status is how an engine run ended.
type Status string

const (
	// StatusCompleted means the engine ran to completion and its output parsed.
	StatusCompleted Status = "completed"
	// StatusPartial means it produced usable but incomplete results.
	StatusPartial Status = "partial"
	// StatusBlocked means it produced nothing usable.
	StatusBlocked Status = "blocked"
	// StatusSkipped means it was not run, because it was not enabled or the
	// profile did not permit it.
	StatusSkipped Status = "skipped"
)

// Outcome is one engine's contribution to an assessment.
type Outcome struct {
	Engine     string
	Status     Status
	Provenance Provenance
	// Observations are what the engine reported, normalized.
	Observations []Observation
	// Covered are the capabilities actually exercised.
	Covered []Capability
	// Cause and Detail explain a blocked or partial run in ledger terms.
	Cause  model.BlockedCause
	Detail string
	// Limitations are what the engine or this integration could not do.
	Limitations []string
	// Stderr is the engine's diagnostics, sanitized and bounded.
	Stderr string
	// Duration is how long the run took.
	Duration time.Duration
}

// Failed reports whether this engine contributed nothing usable.
func (o Outcome) Failed() bool { return o.Status == StatusBlocked }

// sanitize bounds and cleans an engine-supplied string.
func sanitize(s string) string { return proc.Sanitize(s, MaxStringBytes) }

// sanitizeAll cleans a slice, dropping empties and bounding its length.
func sanitizeAll(in []string, max int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if c := sanitize(s); c != "" {
			out = append(out, c)
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// ToFinding converts an observation into a finding in the observed state.
//
// The state is not a parameter. Every path into the finding model from an
// external engine arrives here, and it always produces `observed` — there is no
// argument that could make it produce anything else. If AppSec later gains
// deterministic verification for a class, that verification promotes the
// finding afterwards, from evidence it gathered itself.
func ToFinding(o Observation, p Provenance, runID string) model.Finding {
	title := o.RuleName
	if title == "" {
		title = o.RuleID
	}
	if title == "" {
		title = p.Engine + " observation"
	}

	actual := o.Detail
	if actual == "" {
		actual = fmt.Sprintf("%s reported %q at %s", p.Engine, o.RuleID, o.Location)
	}
	if o.SourceSeverity != "" {
		actual += fmt.Sprintf(". %s rates this %s in its own scale, which AppSec Framework has "+
			"not translated: it is the engine's judgement of the rule, not an assessment of this "+
			"application's exposure", p.Engine, o.SourceSeverity)
	}

	// A stable identity, so the same alert keeps it across runs and consumers
	// can deduplicate. The location is part of it because one rule firing at
	// two places is two findings, not one seen twice.
	id := p.Engine + ":" + o.RuleID
	if o.Location != "" {
		id += ":" + o.Location
	}

	return model.Finding{
		ID:      id,
		CheckID: p.Engine + ":" + o.RuleID,
		Title:   title,
		// Observed, always. An external alert is something another tool said.
		State: model.StateObserved,
		// AppSec has formed no view, and says so rather than borrowing the
		// engine's scale.
		Severity:   model.SeverityUnassessed,
		Confidence: model.ConfidenceLow,
		CWE:        cweRefs(o.References),
		Expected:   "no result from an external engine is, by itself, evidence that this application is exploitable",
		Actual:     actual,
		External: &model.ExternalSource{
			Engine:         p.Engine,
			EngineVersion:  p.Version,
			ExecutablePath: p.ExecutablePath,
			RunID:          runID,
			RuleID:         o.RuleID,
			RuleName:       o.RuleName,
			Severity:       o.SourceSeverity,
			Confidence:     o.SourceConfidence,
			Location:       o.Location,
			Parameter:      o.Parameter,
			References:     o.References,
			RuleProvenance: p.RuleSource,
		},
		Verification: model.VerificationRecord{
			Strategy:  "external-engine-import",
			Performed: false,
			Result: "imported from " + p.Engine + " and not verified by AppSec Framework. It stays " +
				"observed: this project does not promote another tool's alert on that tool's own " +
				"confidence, and has no deterministic verification for this weakness class",
			Unavailable: []string{
				"appsec-verification: AppSec Framework has no deterministic check for this class, " +
					"so it cannot establish whether the reported condition is exploitable here",
			},
		},
		Remediation: "Triage this against the engine's own documentation for " + o.RuleID +
			". It has not been confirmed by AppSec Framework.",
	}
}

// cweRefs extracts CWE identifiers from an engine's references.
func cweRefs(refs []string) []string {
	var out []string
	for _, r := range refs {
		if strings.HasPrefix(strings.ToUpper(r), "CWE-") {
			out = append(out, strings.ToUpper(r))
		}
	}
	sort.Strings(out)
	return out
}
