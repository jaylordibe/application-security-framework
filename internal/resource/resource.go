// Package resource models concrete resources known to belong to an identity,
// and binds their values into an operation's parameters.
//
// A fixture is the smallest thing that makes a cross-owner test meaningful: a
// resource the assessment knows exists, knows who owns it, and knows how to
// address. Without one, probing /api/orders/{orderId} means inventing an
// identifier and reading a 404 that says nothing about authorization.
//
// The model is deliberately framework-neutral. It carries no notion of a
// primary key, a foreign key, a tenant column or an ORM relation, because the
// two reference applications disagree about all of them: one expresses
// ownership as a membership row with no owner column anywhere, the other has no
// tenancy at all. What a fixture holds instead is the set of values needed to
// fill an operation's declared parameters, which is the only thing every
// application has in common.
package resource

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// Expectation states what should happen when a non-owner addresses this
// resource.
//
// It is required rather than defaulted. Assuming that every resource with an
// owner is private would report every deliberately shared document — a public
// profile, a team-visible record, a published article — as a broken access
// control. The operator states the boundary; AppSec Framework tests it.
type Expectation string

const (
	// CrossOwnerDenied means a non-owner must not be able to reach the
	// resource. This is the boundary a BOLA check tests.
	CrossOwnerDenied Expectation = "denied"
	// CrossOwnerAllowed means non-owners are legitimately permitted. The probe
	// still runs and is still recorded, but a success is correct behaviour and
	// is never a finding.
	CrossOwnerAllowed Expectation = "allowed"
)

// Valid reports whether e is a known expectation.
func (e Expectation) Valid() bool {
	return e == CrossOwnerDenied || e == CrossOwnerAllowed
}

// Provenance records how a fixture came to be known.
//
// Ownership is never inferred. A value that merely appeared in a response is
// not evidence that the responding identity owns it — a list endpoint returns
// other people's identifiers all the time — so there is no provenance value for
// "seen in a response".
type Provenance string

const (
	// ProvenanceConfigured means the operator declared the fixture.
	ProvenanceConfigured Provenance = "configured"
	// ProvenanceAPICreated means AppSec Framework created the resource through
	// the application's own API as the owning identity.
	//
	// Declared but not produced in M2: creating a resource needs setup
	// orchestration this milestone deliberately does not build. The constant
	// exists so that the report schema does not have to change when it does.
	ProvenanceAPICreated Provenance = "api-created"
)

// idPattern constrains a fixture id so it is safe in a ledger key, a report and
// a filename without escaping. It matches the identity id rule deliberately:
// two different rules for two kinds of name is a bug waiting to happen.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// paramNamePattern constrains a parameter name to what OpenAPI templates use.
var paramNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// MaxValueBytes bounds one parameter value. An identifier is short; anything
// larger is a misconfiguration, and an unbounded value would let a
// configuration file build a multi-megabyte URL.
const MaxValueBytes = 512

// Mutation describes a state-changing attempt against a resource.
//
// Values are explicit field/value pairs sent as a JSON object. This is
// deliberately not a payload language: a generic mutation DSL would need
// templating, generators and type coercion, all of which is a large attack
// surface pointed at somebody's real data for no gain over naming the two
// fields you want to change.
type Mutation struct {
	Values map[string]any
}

// Fixture is one resource known to belong to one identity.
type Fixture struct {
	ID string
	// Type is a logical label such as "order". It is descriptive only; nothing
	// branches on it.
	Type string
	// Owner is the identity id that owns this resource.
	Owner string
	// CrossOwnerAccess states the expected behaviour for a non-owner.
	CrossOwnerAccess Expectation
	// Values fill an operation's declared parameters, keyed by parameter name.
	Values map[string]string
	// Operations optionally narrows which operation ids this fixture applies
	// to. Empty means every operation whose required path parameters this
	// fixture can fill.
	Operations []string
	// NonOwners optionally narrows which identities act as the non-owner. Empty
	// means every configured identity except the owner.
	NonOwners []string
	// Mutation enables cross-owner mutation testing. Nil means read-only
	// testing, which is the default: a mutation attempt against somebody's real
	// resource has to be asked for.
	Mutation *Mutation
	// Provenance records how the fixture was obtained.
	Provenance Provenance
}

// Validate checks one fixture, returning operator-facing problems.
//
// knownIdentities is the set of configured identity ids, so that a fixture
// referring to an identity that does not exist fails at load rather than
// producing a mysterious blocked row much later.
func (f Fixture) Validate(path string, knownIdentities map[string]bool) []string {
	var problems []string

	switch {
	case f.ID == "":
		problems = append(problems, path+".id is required")
	case !idPattern.MatchString(f.ID):
		problems = append(problems, fmt.Sprintf("%s.id %q must be 1-64 characters of lowercase "+
			"letters, digits, hyphen or underscore, starting with a letter or digit", path, f.ID))
	}

	switch {
	case f.Owner == "":
		problems = append(problems, path+".owner is required; a resource with no owner cannot "+
			"establish a cross-owner boundary")
	case !knownIdentities[f.Owner]:
		problems = append(problems, fmt.Sprintf("%s.owner %q is not a configured identity", path, f.Owner))
	}

	if !f.CrossOwnerAccess.Valid() {
		problems = append(problems, fmt.Sprintf("%s.crossOwnerAccess %q is not one of denied, allowed. "+
			"It is required: whether non-owners may reach this resource is a statement about your "+
			"application that AppSec Framework must not guess", path, f.CrossOwnerAccess))
	}

	if len(f.Values) == 0 {
		problems = append(problems, path+".values is required; without parameter values the "+
			"resource cannot be addressed")
	}
	for name, v := range f.Values {
		problems = append(problems, validateValue(path, name, v)...)
	}

	for i, id := range f.NonOwners {
		switch {
		case !knownIdentities[id]:
			problems = append(problems, fmt.Sprintf("%s.nonOwners[%d] %q is not a configured identity",
				path, i, id))
		case id == f.Owner:
			problems = append(problems, fmt.Sprintf("%s.nonOwners[%d] %q is the owner; a resource's "+
				"owner cannot be its own non-owner", path, i, id))
		}
	}

	if f.Mutation != nil && len(f.Mutation.Values) == 0 {
		problems = append(problems, path+".mutation.values is required when mutation is configured; "+
			"an empty body proves nothing about whether a write was authorized")
	}

	sort.Strings(problems)
	return problems
}

// validateValue rejects a parameter value that could change a URL's meaning.
//
// Fixture values are untrusted input in the sense that matters: they are typed
// by a human, arrive through a pull request, and are interpolated into a URL. A
// value containing a slash, a control character or a URL delimiter must be
// refused at load rather than escaped and hoped about, because the failure mode
// is contacting a host nobody authorized.
func validateValue(path, name, v string) []string {
	var problems []string
	if !paramNamePattern.MatchString(name) {
		problems = append(problems, fmt.Sprintf("%s.values has parameter name %q, which is not a "+
			"valid OpenAPI parameter name", path, name))
	}
	if v == "" {
		problems = append(problems, fmt.Sprintf("%s.values.%s is empty", path, name))
		return problems
	}
	if len(v) > MaxValueBytes {
		problems = append(problems, fmt.Sprintf("%s.values.%s exceeds %d bytes", path, name, MaxValueBytes))
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			problems = append(problems, fmt.Sprintf("%s.values.%s contains a control character", path, name))
			break
		}
	}
	// A path parameter fills exactly one path segment. Anything that could end
	// the segment, start a query or fragment, or introduce an authority is
	// refused outright rather than encoded, so that the intent is unambiguous.
	for _, bad := range []struct {
		s    string
		what string
	}{
		{"/", "a path separator"},
		{"\\", "a backslash"},
		{"?", "a query delimiter"},
		{"#", "a fragment delimiter"},
		{"..", "a parent-directory reference"},
		{"%", "a percent sign, which would be double-encoded"},
		{"@", "an authority delimiter"},
	} {
		if strings.Contains(v, bad.s) {
			problems = append(problems, fmt.Sprintf("%s.values.%s contains %s (%q); a parameter value "+
				"fills one path segment and must not be able to change the shape of the URL",
				path, name, bad.what, bad.s))
		}
	}
	return problems
}

// ValidateAll checks a whole set, including cross-fixture rules.
func ValidateAll(fixtures []Fixture, knownIdentities map[string]bool) []string {
	var problems []string
	seen := map[string]int{}
	for i, f := range fixtures {
		path := fmt.Sprintf("resources[%d]", i)
		problems = append(problems, f.Validate(path, knownIdentities)...)
		if f.ID == "" {
			continue
		}
		if first, dup := seen[f.ID]; dup {
			problems = append(problems, fmt.Sprintf("%s.id %q duplicates resources[%d].id; fixture ids "+
				"key the coverage ledger and must be unique", path, f.ID, first))
			continue
		}
		seen[f.ID] = i
	}
	sort.Strings(problems)
	return problems
}

// Binding is the result of filling an operation's parameters from a fixture.
type Binding struct {
	// URL is the concrete, safely encoded address of the resource.
	URL string
	// Bound names the parameters that were filled, sorted, for the record.
	Bound []string
}

// ErrUnfillable reports that a fixture cannot address an operation.
type ErrUnfillable struct {
	Missing []string
}

func (e *ErrUnfillable) Error() string {
	return "the fixture supplies no value for path parameter(s) " + strings.Join(e.Missing, ", ")
}

// Bind fills an operation's declared path parameters from a fixture and returns
// the concrete URL.
//
// It works from the parsed parameter list rather than by substituting into the
// template textually. A generic string replacement would happily rewrite any
// {braced} text it found, including a literal brace in a path, and would give
// no way to tell a filled operation from an unfilled one.
//
// Every value is percent-encoded for a path segment, and the finished URL is
// re-parsed and checked against the operation's own origin. Encoding alone is
// not enough: the point of the check is that no fixture value can move the
// request to a different host, which is the failure that would turn an
// assessment into an attack on a third party.
func Bind(op model.Operation, values map[string]string) (Binding, error) {
	base, err := url.Parse(strings.TrimRight(op.BaseURL, "/"))
	if err != nil {
		return Binding{}, fmt.Errorf("the operation's base URL is not parseable: %w", err)
	}

	required := op.RequiredPathParams()
	var missing []string
	for _, name := range required {
		if v, ok := values[name]; !ok || v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Binding{}, &ErrUnfillable{Missing: missing}
	}

	// Fill segment by segment. A template segment is exactly "{name}"; anything
	// else is a literal and is left alone.
	template := "/" + strings.TrimLeft(op.PathTemplate, "/")
	segments := strings.Split(template, "/")
	var bound []string
	for i, seg := range segments {
		name, ok := templateName(seg)
		if !ok {
			continue
		}
		v, have := values[name]
		if !have || v == "" {
			// Not required, and not supplied. An unfilled template segment
			// would be sent literally as "{name}", which addresses nothing.
			return Binding{}, &ErrUnfillable{Missing: []string{name}}
		}
		if problems := validateValue("fixture", name, v); len(problems) > 0 {
			return Binding{}, fmt.Errorf("%s", problems[0])
		}
		segments[i] = url.PathEscape(v)
		bound = append(bound, name)
	}
	sort.Strings(bound)

	filled := strings.Join(segments, "/")
	full := base.String() + filled

	// Re-parse and verify the origin is unchanged. This is the backstop that
	// makes the encoding above a control rather than a hope.
	parsed, err := url.Parse(full)
	if err != nil {
		return Binding{}, fmt.Errorf("the bound URL is not parseable: %w", err)
	}
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host {
		return Binding{}, fmt.Errorf("binding changed the origin from %s://%s to %s://%s, which is "+
			"refused", base.Scheme, base.Host, parsed.Scheme, parsed.Host)
	}
	if parsed.User != nil {
		return Binding{}, fmt.Errorf("binding introduced userinfo into the URL, which is refused")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return Binding{}, fmt.Errorf("binding introduced a query or fragment into the path, which is refused")
	}
	if !strings.HasPrefix(parsed.EscapedPath(), base.EscapedPath()) {
		return Binding{}, fmt.Errorf("binding escaped the operation's base path, which is refused")
	}

	return Binding{URL: full, Bound: bound}, nil
}

// templateName returns the parameter name of a "{name}" segment.
func templateName(segment string) (string, bool) {
	if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' {
		return "", false
	}
	name := segment[1 : len(segment)-1]
	if name == "" {
		return "", false
	}
	return name, true
}

// AppliesTo reports whether a fixture is intended for an operation.
func (f Fixture) AppliesTo(op model.Operation) bool {
	if len(f.Operations) == 0 {
		return true
	}
	for _, id := range f.Operations {
		if id == op.ID {
			return true
		}
	}
	return false
}

// SortFixtures orders fixtures deterministically so runs are reproducible.
func SortFixtures(fs []Fixture) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
}
