// Package adapter defines the contract between AppSec Framework and framework
// adapters, and consumes their output as untrusted input.
//
// An adapter observes an application's own source or runtime and reports
// normalized security facts. The core never learns what a Laravel middleware
// group or a NestJS guard is: adapters translate those into facts this package
// defines, and the core reasons only about the facts (ADR-0002).
//
// Everything here treats adapter output as hostile. An adapter runs against a
// repository that may be attacker-controlled, may itself be a third-party
// binary, and produces JSON that reaches the oracle. The rule that follows from
// that is simple and absolute: malformed, oversized, unknown-version or
// self-contradictory output must never make an assessment look better than one
// with no adapter at all.
package adapter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// ContractVersion is the adapter contract this build speaks.
//
// It is the *contract* version, not the adapter's own version. An adapter may
// ship any version it likes; what the core must agree with it about is the
// meaning of the document.
const ContractVersion = "appsec.adapter/v1alpha1"

// contractPrefix is the family every supported version belongs to.
const contractPrefix = "appsec.adapter/"

// Budgets bound what an adapter may produce.
//
// These are deliberately generous rather than tight. A real application has
// hundreds of operations, and a limit that breaks on a normal codebase teaches
// operators to disable the check. They exist to stop unbounded consumption, not
// to police size.
const (
	// MaxDocumentBytes bounds one adapter document.
	MaxDocumentBytes = 16 << 20 // 16 MiB
	// MaxFacts bounds how many facts one adapter may report.
	MaxFacts = 20000
	// MaxLimitations bounds the self-reported limitation list.
	MaxLimitations = 500
	// MaxStringBytes bounds any single string in the document. Adapter strings
	// reach reports, terminals and future AI consumers; an unbounded one is a
	// flooding primitive and an injection surface.
	MaxStringBytes = 4096
	// MaxPathSegments bounds an operation path's depth.
	MaxPathSegments = 64
)

// ExtractionMethod is how an adapter learned what it reports.
//
// The adapter states the method; the *core* decides how much that is worth.
// This split is deliberate: letting an adapter name its own confidence would
// make provenance spoofing a one-line change in an untrusted component, and
// provenance is what stops a guess being treated as a fact.
type ExtractionMethod string

const (
	// MethodFrameworkNative means the framework itself was asked — an artisan
	// command, a runtime metadata dump. Highest fidelity, and it executes the
	// target application's code.
	MethodFrameworkNative ExtractionMethod = "framework-native"
	// MethodStaticAST means the application's own language parsed it without
	// executing it.
	MethodStaticAST ExtractionMethod = "static-ast"
	// MethodStaticLexical means tolerant pattern extraction over source text.
	// Cheapest and broadest, and the least able to resolve anything dynamic.
	MethodStaticLexical ExtractionMethod = "static-lexical"
)

// Valid reports whether m is a known extraction method.
func (m ExtractionMethod) Valid() bool {
	switch m {
	case MethodFrameworkNative, MethodStaticAST, MethodStaticLexical:
		return true
	}
	return false
}

// ExecutesTargetCode reports whether this method runs code from the inspected
// repository.
//
// Asking a framework to describe itself means booting it, which runs service
// providers, module initialisers, decorators and whatever else the repository
// author put in that path. That is sometimes worth doing and must never happen
// by accident, so it is a property of the method rather than a footnote.
func (m ExtractionMethod) ExecutesTargetCode() bool {
	return m == MethodFrameworkNative
}

// Provenance maps an extraction method onto the model's grading.
//
// The mapping lives here, in the core, and is not negotiable by the adapter.
// Framework-native introspection is the application describing itself, which is
// a declaration. Everything static is an inference drawn from the outside, no
// matter how confident the adapter feels about it.
//
// Note what is absent: no method maps to ProvenanceObserved or
// ProvenanceVerified. Those describe what a request actually did, and no amount
// of reading source establishes them (ADR-0014).
func (m ExtractionMethod) Provenance() model.Provenance {
	if m == MethodFrameworkNative {
		return model.ProvenanceDeclared
	}
	return model.ProvenanceInferred
}

// Kind is the category of a normalized fact.
//
// The set is small on purpose. This is not an application AST: it is the subset
// of what a framework knows that can change what AppSec tests or how much it
// trusts an expectation.
type Kind string

const (
	// KindAuthentication states whether an operation requires a caller to be
	// authenticated.
	KindAuthentication Kind = "operation.authentication"
	// KindAuthorization states whether an operation applies an authorization
	// control beyond authentication.
	KindAuthorization Kind = "operation.authorization"
	// KindOwnership states whether an operation is scoped to the calling
	// identity's own records.
	KindOwnership Kind = "operation.ownership"
)

// Valid reports whether k is a known fact kind.
func (k Kind) Valid() bool {
	switch k {
	case KindAuthentication, KindAuthorization, KindOwnership:
		return true
	}
	return false
}

// Value is a fact's assertion. Values are namespaced by kind.
type Value string

const (
	// AuthenticationRequired means the framework applies an authentication
	// control to this operation.
	AuthenticationRequired Value = "required"
	// AuthenticationPublic means the framework applies none.
	AuthenticationPublic Value = "public"

	// AuthorizationPresent means a control beyond authentication applies.
	AuthorizationPresent Value = "present"
	// AuthorizationAbsent means none was found.
	AuthorizationAbsent Value = "absent"

	// OwnershipScoped means the operation is restricted to records belonging to
	// the caller.
	OwnershipScoped Value = "owner-scoped"
	// OwnershipUnscoped means it is not.
	OwnershipUnscoped Value = "not-owner-scoped"

	// ValueUnknown is available to every kind and is the honest answer whenever
	// an adapter met something it could not resolve.
	//
	// It exists so that "I looked and could not tell" is expressible. Without
	// it, an adapter meeting a dynamic construct has only the choice between
	// silence, which reads as absence, and a guess.
	ValueUnknown Value = "unknown"
)

// validValues lists what each kind may assert.
var validValues = map[Kind]map[Value]bool{
	KindAuthentication: {AuthenticationRequired: true, AuthenticationPublic: true, ValueUnknown: true},
	KindAuthorization:  {AuthorizationPresent: true, AuthorizationAbsent: true, ValueUnknown: true},
	KindOwnership:      {OwnershipScoped: true, OwnershipUnscoped: true, ValueUnknown: true},
}

// OperationRef identifies the operation a fact is about.
//
// It is a method and a path template, which is what every HTTP framework and
// every specification agrees on. Deliberately not a controller name, a class, a
// handler or a route name: those exist in one ecosystem and not another, and
// the whole point of this contract is that the core cannot tell which ecosystem
// it is talking to.
type OperationRef struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// ID renders the operation identifier the rest of the system uses.
func (o OperationRef) ID() string { return model.OperationID(o.Method, o.Path) }

// Evidence points at where in the application a fact came from.
//
// It carries a location, never source contents. A developer needs to know which
// file and line to look at; a report that quotes the surrounding code would
// copy an application's source into an artefact that gets attached to tickets.
type Evidence struct {
	// File is a path relative to the inspected root.
	File string `json:"file,omitempty"`
	// Line is 1-indexed, zero when unknown.
	Line int `json:"line,omitempty"`
	// Detail explains the reasoning in one operator-facing sentence.
	Detail string `json:"detail,omitempty"`
}

// Fact is one normalized security fact.
type Fact struct {
	Kind      Kind         `json:"kind"`
	Operation OperationRef `json:"operation"`
	Value     Value        `json:"value"`
	// Control is an opaque label for the authorization control found, such as a
	// permission name. It is never interpreted, only reported: the core has no
	// idea what any application's permissions mean and must not pretend to.
	Control  string   `json:"control,omitempty"`
	Evidence Evidence `json:"evidence,omitempty"`
}

// key identifies the subject a fact asserts about, for duplicate and conflict
// detection within one document.
func (f Fact) key() string { return string(f.Kind) + "\x00" + f.Operation.ID() }

// AdapterInfo identifies the adapter that produced a document.
type AdapterInfo struct {
	// Name is the adapter's identifier, e.g. "laravel".
	Name string `json:"name"`
	// Version is the adapter's own version, for the operator's benefit.
	Version string `json:"version"`
	// ExtractionMethod is how it learned what it reports. The core maps this
	// onto provenance; the adapter cannot state provenance directly.
	ExtractionMethod ExtractionMethod `json:"extractionMethod"`
}

// TargetInfo describes what was inspected. Best-effort and never trusted for
// anything security-relevant.
type TargetInfo struct {
	Framework        string `json:"framework,omitempty"`
	FrameworkVersion string `json:"frameworkVersion,omitempty"`
}

// Document is one adapter's output.
type Document struct {
	ContractVersion string      `json:"contractVersion"`
	Adapter         AdapterInfo `json:"adapter"`
	Target          TargetInfo  `json:"target,omitempty"`
	Facts           []Fact      `json:"facts"`
	// Limitations are what the adapter could not determine, in its own words.
	//
	// This field is why the contract can be honest. Without it, a fact's absence
	// is ambiguous between "the framework applies no control here" and "I could
	// not read this construct", and those two must never be confused: the first
	// is a finding waiting to happen and the second is a gap in the tool.
	Limitations []string `json:"limitations,omitempty"`
}

// SupportedContractVersions are the document versions this build understands.
var SupportedContractVersions = []string{ContractVersion}

// VersionSupport classifies a contract version string.
type VersionSupport int

const (
	// VersionUnparseable means the string is not a contract version at all.
	VersionUnparseable VersionSupport = iota
	// VersionSupported means this build understands the document.
	VersionSupported
	// VersionUnknown means it is a well-formed contract version this build does
	// not know. It is refused rather than parsed hopefully: a future version may
	// give an existing field a new meaning, and guessing would let a document
	// mean something other than what it says.
	VersionUnknown
)

// ClassifyVersion decides whether a document's contract version can be used.
func ClassifyVersion(v string) VersionSupport {
	if v == "" || !strings.HasPrefix(v, contractPrefix) {
		return VersionUnparseable
	}
	suffix := strings.TrimPrefix(v, contractPrefix)
	if suffix == "" || strings.ContainsAny(suffix, "/ \t\r\n") {
		return VersionUnparseable
	}
	for _, s := range SupportedContractVersions {
		if v == s {
			return VersionSupported
		}
	}
	return VersionUnknown
}

// SortFacts orders facts deterministically so two runs over one repository
// produce identical documents and evidence hashes.
func SortFacts(facts []Fact) {
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Operation.ID() != facts[j].Operation.ID() {
			return facts[i].Operation.ID() < facts[j].Operation.ID()
		}
		if facts[i].Kind != facts[j].Kind {
			return facts[i].Kind < facts[j].Kind
		}
		return facts[i].Value < facts[j].Value
	})
}

// Describe renders an adapter for an operator-facing message.
func (a AdapterInfo) Describe() string {
	return fmt.Sprintf("%s %s (%s)", a.Name, a.Version, a.ExtractionMethod)
}
