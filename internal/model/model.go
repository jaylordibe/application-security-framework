// Package model contains the framework-neutral, normalized application-security
// model.
//
// Two rules govern this package, both enforced by review:
//
//   - It imports nothing outside the standard library.
//   - It carries no struct tags. The model is not the wire format. Package
//     report owns the versioned output DTOs and the mapping onto them, so that
//     renaming a field here is never a breaking change to published output.
//
// Concrete types are preferred to interfaces; polymorphism is introduced only
// where a second implementation actually exists (ADR-0009).
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Provenance records how a fact or expectation was obtained. It never upgrades
// itself: an inferred expectation that is contradicted becomes a rejected
// hypothesis, not a finding.
type Provenance string

const (
	// ProvenanceDeclared means the operator or the application stated it.
	ProvenanceDeclared Provenance = "declared"
	// ProvenanceInferred means analysis derived it. This is a hypothesis.
	ProvenanceInferred Provenance = "inferred"
	// ProvenanceObserved means it was seen at runtime.
	ProvenanceObserved Provenance = "observed"
	// ProvenanceVerified means it was deterministically confirmed.
	ProvenanceVerified Provenance = "verified"
)

// Valid reports whether p is a known provenance value.
func (p Provenance) Valid() bool {
	switch p {
	case ProvenanceDeclared, ProvenanceInferred, ProvenanceObserved, ProvenanceVerified:
		return true
	}
	return false
}

// SourceKind identifies the class of artefact a fact came from.
type SourceKind string

const (
	SourceOpenAPIFile SourceKind = "openapi-file"
	SourceOpenAPIURL  SourceKind = "openapi-url"
	SourceConfig      SourceKind = "config"
	SourceRuntime     SourceKind = "runtime"
	SourceAdapter     SourceKind = "adapter"
)

// Source records where a single fact came from, so a report can explain why
// Assay believes something.
type Source struct {
	Kind SourceKind
	// Ref is a path or URL. It is redacted before it is stored.
	Ref        string
	ObservedAt time.Time
}

// Profile is an assessment safety profile. Profiles are strictly ordered and
// never escalate implicitly (threat model T-12).
type Profile string

const (
	// ProfileDiscovery permits low-risk reconnaissance only.
	ProfileDiscovery Profile = "discovery"
	// ProfileVerification permits real techniques with controlled impact. It is
	// the default for authorized local and staging environments.
	ProfileVerification Profile = "verification"
	// ProfileIntrusive permits potentially state-changing or disruptive tests
	// and requires explicit authorization.
	ProfileIntrusive Profile = "intrusive"
)

func (p Profile) rank() (int, bool) {
	switch p {
	case ProfileDiscovery:
		return 1, true
	case ProfileVerification:
		return 2, true
	case ProfileIntrusive:
		return 3, true
	}
	return 0, false
}

// Valid reports whether p is a known profile.
func (p Profile) Valid() bool {
	_, ok := p.rank()
	return ok
}

// Permits reports whether effective profile p allows work requiring `required`.
// An unknown profile on either side permits nothing, so malformed input fails
// closed rather than open.
func (p Profile) Permits(required Profile) bool {
	have, okHave := p.rank()
	need, okNeed := required.rank()
	if !okHave || !okNeed {
		return false
	}
	return have >= need
}

// SafeMethods are HTTP methods defined as neither state-changing nor
// destructive. Everything else is treated as potentially state-changing.
func SafeMethods() []string { return []string{"GET", "HEAD", "OPTIONS"} }

// IsSafeMethod reports whether an HTTP method is read-only by definition.
func IsSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// RequiredProfileForMethod computes the safety profile required to exercise an
// HTTP method.
//
// This is deliberately a property of the (check, operation) pair rather than of
// the check alone. A check that iterates every operation in a specification
// would otherwise send an unauthenticated DELETE under the discovery profile —
// and if the endpoint really is missing authentication, which is exactly what
// is being hunted, it would destroy data while proving it.
func RequiredProfileForMethod(method string) Profile {
	if IsSafeMethod(method) {
		return ProfileVerification
	}
	return ProfileIntrusive
}

// GateProfile decides whether work requiring `required` may run under the
// effective profile, and if not, why. Centralised so that the gate cannot be
// implemented twice with different semantics.
func GateProfile(effective, required Profile) (bool, BlockedCause) {
	if !effective.Valid() || !required.Valid() {
		return false, CauseSafetyPolicy
	}
	if effective.Permits(required) {
		return true, CauseNone
	}
	return false, CauseSafetyPolicy
}

// Outcome is the classification of an observed response into an access-control
// result. Indeterminate is first-class and is never silently a pass (ADR-0004).
type Outcome string

const (
	OutcomeAllowed       Outcome = "allowed"
	OutcomeDenied        Outcome = "denied"
	OutcomeNotFound      Outcome = "not_found"
	OutcomeError         Outcome = "error"
	OutcomeRateLimited   Outcome = "rate_limited"
	OutcomeIndeterminate Outcome = "indeterminate"
)

// Valid reports whether o is a known outcome.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeAllowed, OutcomeDenied, OutcomeNotFound, OutcomeError,
		OutcomeRateLimited, OutcomeIndeterminate:
		return true
	}
	return false
}

// Parameter is a single input to an operation.
type Parameter struct {
	Name     string
	In       string // path, query, header, cookie, body
	Required bool
}

// SecurityRequirement is one declared authentication requirement. Schemes are
// ANDed together; a list of requirements is ORed.
//
// An empty Schemes slice is meaningful: in OpenAPI, an empty requirement object
// inside the list means authentication is OPTIONAL for that operation.
type SecurityRequirement struct {
	Schemes []string
}

// Operation is one callable unit of attack surface.
type Operation struct {
	ID           string
	Method       string
	PathTemplate string
	BaseURL      string
	Parameters   []Parameter
	// Security holds declared security requirements.
	//
	// nil          — the specification said nothing (unstated).
	// []           — explicitly declared public (security: []).
	// [{}, {...}]  — contains an empty member, so authentication is optional.
	Security   []SecurityRequirement
	Deprecated bool
	Summary    string
	Sources    []Source
}

// DeclaresAuthRequired reports whether the operation's own specification states
// that authentication is required.
//
// It returns false when the specification is silent (nil), when the operation is
// explicitly public (empty list), and when any member is empty — because an
// empty member makes authentication optional, so an unauthenticated success is
// correct behaviour rather than a vulnerability.
func (o Operation) DeclaresAuthRequired() bool {
	if len(o.Security) == 0 {
		return false
	}
	for _, req := range o.Security {
		if len(req.Schemes) == 0 {
			// Optional authentication. Not a requirement.
			return false
		}
	}
	return true
}

// DeclaresPublic reports whether the specification explicitly declared the
// operation as requiring no authentication.
func (o Operation) DeclaresPublic() bool {
	return o.Security != nil && len(o.Security) == 0
}

// RequiredPathParams returns the names of path parameters that must be given a
// value before the operation can be exercised meaningfully.
//
// An operation with unfilled required path parameters cannot be tested: probing
// /users/{id} with a literal "{id}" or an invented identifier exercises a
// resource that does not exist, and the resulting 404 says nothing about
// authorization.
func (o Operation) RequiredPathParams() []string {
	var out []string
	for _, p := range o.Parameters {
		if strings.EqualFold(p.In, "path") {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Identity is an actor Assay may act as. Identities are never invented; they
// come from configuration only.
type Identity struct {
	ID string
	// Anonymous marks the identity that presents no credentials.
	Anonymous bool
	// Description is operator-supplied.
	Description string
}

// AnonymousIdentity is the always-available identity that presents no
// credentials. It needs no configuration and no secrets.
func AnonymousIdentity() Identity {
	return Identity{ID: "anonymous", Anonymous: true, Description: "no credentials presented"}
}

// Severity states how damaging a finding would be if real. Independent of
// Confidence (ADR-0006).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank orders severities so a policy threshold can be compared.
func (s Severity) severityRank() (int, bool) {
	switch s {
	case SeverityInfo:
		return 1, true
	case SeverityLow:
		return 2, true
	case SeverityMedium:
		return 3, true
	case SeverityHigh:
		return 4, true
	case SeverityCritical:
		return 5, true
	}
	return 0, false
}

// AtLeast reports whether s is at least as severe as threshold. An unknown value
// on either side reports false, so a malformed threshold cannot fail a build for
// the wrong reason.
func (s Severity) AtLeast(threshold Severity) bool {
	have, okHave := s.severityRank()
	need, okNeed := threshold.severityRank()
	if !okHave || !okNeed {
		return false
	}
	return have >= need
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Confidence states how certain we are that a finding is real. It is a function
// of evidence quality and verification state only — never of a model's
// confidence language, and never of how many tools agreed (ADR-0006).
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Valid reports whether c is a known confidence.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}

// FindingState is the lifecycle state of a finding within a single assessment.
// REMEDIATED and VERIFIED_FIXED are deliberately absent: they are conclusions
// from comparing two assessments, not states within one (ADR-0006).
type FindingState string

const (
	StateObserved  FindingState = "observed"
	StateSuspected FindingState = "suspected"
	StateConfirmed FindingState = "confirmed"
	StateRejected  FindingState = "rejected"
	StateBlocked   FindingState = "blocked"
)

// Valid reports whether s is a known finding state.
func (s FindingState) Valid() bool {
	switch s {
	case StateObserved, StateSuspected, StateConfirmed, StateRejected, StateBlocked:
		return true
	}
	return false
}

// VerificationRecord describes what was done to test a hypothesis, including
// which corroborating evidence sources were wanted but unavailable.
type VerificationRecord struct {
	Strategy string
	// Steps records each verification step and its result, so a reviewer can
	// audit why a confidence level was assigned.
	Steps []VerificationStep
	// Performed is false when verification was blocked entirely.
	Performed bool
	Result    string
	// Unavailable names evidence sources that were wanted but not obtainable.
	// Their absence caps confidence; it never silently raises it.
	Unavailable []string
}

// VerificationStep is one discriminator applied while verifying a hypothesis.
type VerificationStep struct {
	Name string
	// Passed is true when the step supported the hypothesis.
	Passed bool
	Detail string
}

// Finding is a difference between an expectation and an observed outcome.
type Finding struct {
	ID          string
	CheckID     string
	Title       string
	State       FindingState
	Severity    Severity
	Confidence  Confidence
	CWE         []string
	OWASP       []string
	OperationID string
	IdentityID  string
	Expected    string
	Actual      string
	// EvidenceRefs reference stored evidence rather than embedding copies.
	EvidenceRefs []string
	Verification VerificationRecord
	Remediation  string
	Reproduction []string
}

// Disposition is what happened to one unit of intended work.
//
// The value is "executed" rather than "tested" on purpose: a check ran, which is
// a far weaker statement than "this operation was tested for security".
type Disposition string

const (
	// DispositionExecuted means the check ran and produced a usable outcome.
	DispositionExecuted Disposition = "executed"
	// DispositionBlocked means work was planned but could not run.
	DispositionBlocked Disposition = "blocked"
	// DispositionUntested means the surface exists but no work was planned.
	DispositionUntested Disposition = "untested"
)

// BlockedCause is the machine-readable reason a unit of work did not run.
// Reporting "blocked" without a cause would be as useless as reporting nothing.
//
// Consumers must treat an unrecognised cause as blocked rather than as success.
type BlockedCause string

const (
	CauseNone                  BlockedCause = ""
	CauseMissingIdentity       BlockedCause = "missing_identity"
	CauseMissingResource       BlockedCause = "missing_resource"
	CauseAuthenticationFailed  BlockedCause = "authentication_failed"
	CauseEngineUnavailable     BlockedCause = "engine_unavailable"
	CauseUnsupportedProtocol   BlockedCause = "unsupported_protocol"
	CauseEnvironmentMismatch   BlockedCause = "environment_mismatch"
	CauseInsufficientPrivilege BlockedCause = "insufficient_privilege"
	CauseSafetyPolicy          BlockedCause = "safety_policy"
	CauseIndeterminateOutcome  BlockedCause = "indeterminate_outcome"
	CauseTransportError        BlockedCause = "transport_error"
	CauseOutOfScope            BlockedCause = "out_of_scope"
	CauseNoOracle              BlockedCause = "no_oracle"
	CauseRateLimited           BlockedCause = "rate_limited"
	CauseAmbiguousDenial       BlockedCause = "ambiguous_denial"
	CauseCancelled             BlockedCause = "cancelled"
)

// Valid reports whether c is a known blocked cause.
func (c BlockedCause) Valid() bool {
	switch c {
	case CauseNone, CauseMissingIdentity, CauseMissingResource, CauseAuthenticationFailed,
		CauseEngineUnavailable, CauseUnsupportedProtocol, CauseEnvironmentMismatch,
		CauseInsufficientPrivilege, CauseSafetyPolicy, CauseIndeterminateOutcome,
		CauseTransportError, CauseOutOfScope, CauseNoOracle, CauseRateLimited,
		CauseAmbiguousDenial, CauseCancelled:
		return true
	}
	return false
}

// CoverageEntry is one unit of intended work and its disposition.
//
// Entries are keyed by (subject, check) rather than by subject alone. A row
// saying "operation executed" without naming the check would imply the operation
// was tested for security generally, when in fact one check for one weakness
// class ran against it.
type CoverageEntry struct {
	// Dimension names what is covered, e.g. "operation".
	Dimension string
	// Subject identifies the thing covered within that dimension.
	Subject     string
	CheckID     string
	IdentityID  string
	Disposition Disposition
	// Cause is required when Disposition is blocked.
	Cause  BlockedCause
	Detail string
	// EvidenceRefs reference the stored exchanges behind this row. A blocked row
	// with evidence is far more actionable than one without: it shows what the
	// target actually returned when the check gave up.
	EvidenceRefs []string
}

// Key returns the ledger key for an entry.
func (e CoverageEntry) Key() string {
	return strings.Join([]string{e.Dimension, e.Subject, e.CheckID, e.IdentityID}, "\x00")
}

// CapturedRequest is a request as it was sent, after redaction. It lives in
// model rather than in the HTTP package so that classification and reporting can
// name it without depending on the transport.
type CapturedRequest struct {
	Method string
	URL    string
	Header map[string][]string
	Body   []byte
	// BodyTruncated is true when the body exceeded the capture limit.
	BodyTruncated bool
}

// CapturedResponse is a response as it was received, after redaction.
type CapturedResponse struct {
	Status        int
	Proto         string
	Header        map[string][]string
	Body          []byte
	BodyTruncated bool
	// Elapsed is how long the exchange took.
	Elapsed time.Duration
	// RemoteAddr is the address actually connected to, recorded so that a report
	// can show which address a hostname resolved to at the time.
	RemoteAddr string
}

// HeaderValue returns the first value of a header, matched case-insensitively.
func (r CapturedResponse) HeaderValue(name string) string {
	for k, v := range r.Header {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// HasHeader reports whether a header is present, matched case-insensitively.
func (r CapturedResponse) HasHeader(name string) bool {
	for k, v := range r.Header {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return true
		}
	}
	return false
}

// Exchange is a request/response pair, or a request and the error it produced.
type Exchange struct {
	Request  CapturedRequest
	Response *CapturedResponse
	// Err is a redacted error string. It is never a raw error, because Go's
	// url.Error renders the full URL including its query string.
	Err string
}

// OperationID builds a stable identifier for an operation, derived from method
// and path only so that it survives unrelated specification changes.
func OperationID(method, pathTemplate string) string {
	return fmt.Sprintf("%s %s", strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(pathTemplate))
}

// SortOperations orders operations deterministically so reports and evaluation
// fixtures are reproducible.
func SortOperations(ops []Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].PathTemplate != ops[j].PathTemplate {
			return ops[i].PathTemplate < ops[j].PathTemplate
		}
		return ops[i].Method < ops[j].Method
	})
}
