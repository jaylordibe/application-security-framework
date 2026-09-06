// Package config loads and validates appsec.yaml.
//
// Configuration is trusted in the sense that the operator wrote it, but it is
// validated strictly anyway: a trusted author still makes mistakes, and a
// configuration file may arrive through a pull request.
//
// Three YAML behaviours are deliberately not enabled. The decoder is never given
// ReferenceFiles or ReferenceDirs, which would let a configuration file pull
// anchor definitions from arbitrary filesystem paths. Input is size-capped, and
// alias expansion is bounded, because alias/merge expansion is a classic
// exponential-blowup denial of service (threat model T-04).
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/resource"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// MaxConfigBytes bounds a configuration file.
const MaxConfigBytes = 1 << 20 // 1 MiB

// CurrentAPIVersion is the only configuration version this build understands.
//
// It is required from day one. Adding a version field later, after strict
// decoding has already rejected unknown fields, would make every existing
// configuration invalid.
const CurrentAPIVersion = "appsec/v1alpha1"

// Config is the parsed appsec.yaml.
type Config struct {
	APIVersion  string      `yaml:"apiVersion"`
	Target      Target      `yaml:"target"`
	Scope       Scope       `yaml:"scope"`
	Assessment  Assessment  `yaml:"assessment"`
	Identities  []Identity  `yaml:"identities"`
	Resources   []Resource  `yaml:"resources"`
	Discovery   Discovery   `yaml:"discovery"`
	Outcome     Outcome     `yaml:"outcome"`
	Environment Environment `yaml:"environment"`
	Policy      Policy      `yaml:"policy"`
	Output      Output      `yaml:"output"`
}

// Policy decides when a run fails the build.
//
// Without this the exit code is decorative: the only shipped check produces
// suspected findings, so gating solely on confirmed ones would exit 0 on a real
// authentication bypass and quietly green-light a pipeline.
type Policy struct {
	// FailOnConfirmed is the lowest severity of a CONFIRMED finding that fails
	// the run. Empty disables the rule.
	FailOnConfirmed string `yaml:"failOnConfirmed"`
	// FailOnSuspected is the lowest severity of a SUSPECTED finding that fails
	// the run. Suspected findings are unverified by definition, so the default is
	// deliberately high rather than off: an unverified high-severity finding is
	// worth a human looking at it.
	FailOnSuspected string `yaml:"failOnSuspected"`
}

// Target names the application under assessment.
type Target struct {
	// BaseURL is the root of the application, e.g. http://localhost:3000.
	BaseURL string `yaml:"baseURL"`
	// Name is a label used in reports.
	Name string `yaml:"name"`
}

// Scope is the network authorization boundary.
type Scope struct {
	// Include lists additional allowed endpoints. The target's own origin is
	// always included.
	Include []ScopeEntry `yaml:"include"`
	// AllowPrivateAddresses permits loopback and RFC1918 addresses. Assessing a
	// local application requires this, and requiring it to be stated makes the
	// decision deliberate rather than accidental.
	AllowPrivateAddresses bool `yaml:"allowPrivateAddresses"`
}

// ScopeEntry is one allowlist grant.
type ScopeEntry struct {
	Scheme     string `yaml:"scheme"`
	Host       string `yaml:"host"`
	Ports      []int  `yaml:"ports"`
	PathPrefix string `yaml:"pathPrefix"`
}

// Assessment controls safety and pacing.
type Assessment struct {
	// Profile is the effective safety profile. It never escalates implicitly.
	Profile string `yaml:"profile"`
	// AuthorizeIntrusive must be true for the intrusive profile to be accepted.
	// A profile alone is not authorization.
	AuthorizeIntrusive bool `yaml:"authorizeIntrusive"`
	// Concurrency bounds simultaneous requests to the target.
	Concurrency int `yaml:"concurrency"`
	// RequestsPerSecond bounds request rate. Assessment tooling that hammers a
	// target gets itself blocked, and every later response then classifies as a
	// denial, producing a false clean report.
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	// TimeoutSeconds bounds a single request.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// ExcludeOperations lists operation ids that must never be exercised.
	ExcludeOperations []string `yaml:"excludeOperations"`
	// ExcludeAuthEndpoints skips operations whose path looks like
	// authentication. Sweeping unauthenticated requests across login routes can
	// trip account lockout on real accounts and poison the rest of the run.
	ExcludeAuthEndpoints *bool `yaml:"excludeAuthEndpoints"`
}

// Identity is one security principal AppSec Framework may act as.
//
// The credential itself is deliberately absent from this struct. Only a
// reference to where the material lives is configurable, so that a credential
// cannot be committed to a repository, reviewed in a pull request, or copied
// into a CI log by the ordinary act of sharing a configuration file.
type Identity struct {
	// ID is a stable, short name used in the ledger and in reports.
	ID string `yaml:"id"`
	// Label is a human-readable description.
	Label string `yaml:"label"`
	// Authentication says how to authenticate as this identity.
	Authentication Authentication `yaml:"authentication"`
	// Liveness configures a canary that establishes whether the identity is
	// still usable. Optional, and strongly recommended: without one, a
	// credential expiring mid-run cannot be detected.
	Liveness *LivenessProbe `yaml:"liveness"`
}

// Authentication is a supported authentication mechanism and its credential
// reference.
type Authentication struct {
	// Type is bearer or apiKey.
	Type string `yaml:"type"`
	// Header is the field name for the apiKey type.
	Header string `yaml:"header"`
	// ValuePrefix is prepended to the credential for the apiKey type.
	ValuePrefix string `yaml:"valuePrefix"`
	// Credential references where the secret is read from.
	Credential Credential `yaml:"credential"`
}

// Credential references a secret without containing one.
type Credential struct {
	// Env names an environment variable.
	Env string `yaml:"env"`
	// File names a file whose contents are the credential.
	File string `yaml:"file"`
}

// LivenessProbe is a safe, authentication-requiring operation used to establish
// whether an identity still authenticates.
type LivenessProbe struct {
	Method string `yaml:"method"`
	// Path is resolved against target.baseURL and is subject to the scope
	// policy like every other request.
	Path string `yaml:"path"`
	// ExpectStatus lists statuses meaning the identity is still good. Empty
	// means any 2xx.
	ExpectStatus []int `yaml:"expectStatus"`
}

// Resource is one concrete resource known to belong to an identity.
//
// A fixture is what makes a cross-owner test mean anything: without one, asking
// for /api/orders/{orderId} means inventing an identifier and reading a 404 that
// says nothing about authorization.
type Resource struct {
	// ID is a stable, short name used in the ledger and in reports.
	ID string `yaml:"id"`
	// Type is a logical label such as "order". Descriptive only.
	Type string `yaml:"type"`
	// Owner is the identity id that owns this resource.
	Owner string `yaml:"owner"`
	// CrossOwnerAccess is "denied" or "allowed". Required: whether non-owners
	// may reach this resource is a statement about the application that AppSec
	// Framework must not guess. Assuming every owned resource is private would
	// report every deliberately shared record as a broken access control.
	CrossOwnerAccess string `yaml:"crossOwnerAccess"`
	// Values fill an operation's declared parameters, keyed by parameter name.
	Values map[string]string `yaml:"values"`
	// Operations optionally narrows which operation ids this fixture applies to.
	Operations []string `yaml:"operations"`
	// NonOwners optionally narrows which identities probe this fixture. Empty
	// means every configured identity except the owner.
	NonOwners []string `yaml:"nonOwners"`
	// Mutation enables cross-owner write testing. Absent means read-only.
	Mutation *ResourceMutation `yaml:"mutation"`
}

// ResourceMutation holds the explicit values a cross-owner write attempts.
//
// Deliberately not a payload language. A generic mutation DSL would need
// templating, generators and coercion, all pointed at somebody's real data, for
// no gain over naming the two fields you want to change.
type ResourceMutation struct {
	Values map[string]any `yaml:"values"`
}

// Discovery configures how the attack surface is learned.
type Discovery struct {
	// OpenAPIFile is a path to a specification on disk.
	OpenAPIFile string `yaml:"openAPIFile"`
	// OpenAPIURL is a specification served by the target.
	OpenAPIURL string `yaml:"openAPIURL"`
	// ProbeWellKnownPaths permits fetching the usual specification locations on
	// the target's own origin when neither of the above is set.
	ProbeWellKnownPaths *bool `yaml:"probeWellKnownPaths"`
}

// Outcome supplies application-specific signals for classifying responses.
//
// These come from the operator only. A hostile target that could define its own
// oracle could map "allowed" to "denied" and suppress every finding.
type Outcome struct {
	// ErrorCodePointer is a JSON pointer to a stable error-code field, e.g.
	// "/errorCode". Real applications frequently return 200 or 400 with a
	// machine-readable code that is far more reliable than the status.
	ErrorCodePointer string `yaml:"errorCodePointer"`
	// DeniedCodes map error-code values to a denial outcome.
	DeniedCodes []string `yaml:"deniedCodes"`
	// NotFoundCodes map error-code values to a not-found outcome.
	NotFoundCodes []string `yaml:"notFoundCodes"`
}

// Environment records how the assessed environment differs from production.
// These are facts stated by the operator, not a score.
type Environment struct {
	Name string `yaml:"name"`
	// Differences lists production-equivalence deviations, e.g.
	// "rateLimiting: relaxed".
	Differences []string `yaml:"differences"`
}

// Output controls where results are written.
type Output struct {
	// Dir is the run directory root.
	Dir string `yaml:"dir"`
}

// Default returns a configuration with safe defaults applied.
func Default() Config {
	probe := true
	excludeAuth := true
	return Config{
		APIVersion: CurrentAPIVersion,
		Assessment: Assessment{
			Profile:              string(model.ProfileVerification),
			Concurrency:          4,
			RequestsPerSecond:    10,
			TimeoutSeconds:       20,
			ExcludeAuthEndpoints: &excludeAuth,
		},
		Discovery: Discovery{ProbeWellKnownPaths: &probe},
		Policy: Policy{
			FailOnConfirmed: string(model.SeverityLow),
			FailOnSuspected: string(model.SeverityHigh),
		},
		Output: Output{Dir: ".appsec"},
	}
}

// Load reads and validates a configuration file.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if info.Size() > MaxConfigBytes {
		return Config{}, fmt.Errorf("config: file is %d bytes, limit is %d", info.Size(), MaxConfigBytes)
	}
	return Parse(io.LimitReader(f, MaxConfigBytes+1), path)
}

// Parse decodes and validates configuration from a reader.
func Parse(r io.Reader, name string) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config: input exceeds %d bytes", MaxConfigBytes)
	}

	cfg := Default()
	// Strict decoding rejects unknown fields, so a typo becomes a loud error
	// rather than a silently ignored setting. ReferenceFiles and ReferenceDirs
	// are deliberately absent.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)), yaml.Strict())
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: %s:\n%s", name, yaml.FormatError(err, false, true))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", name, err)
	}
	return cfg, nil
}

// Validate applies semantic rules that a schema cannot express.
func (c *Config) Validate() error {
	var problems []string

	if c.APIVersion == "" {
		c.APIVersion = CurrentAPIVersion
	}
	if c.APIVersion != CurrentAPIVersion {
		problems = append(problems, fmt.Sprintf(
			"apiVersion %q is not supported by this build (expected %q)", c.APIVersion, CurrentAPIVersion))
	}

	if c.Target.BaseURL == "" {
		problems = append(problems, "target.baseURL is required")
	} else if u, err := url.Parse(c.Target.BaseURL); err != nil {
		problems = append(problems, "target.baseURL is not a valid URL")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		problems = append(problems, fmt.Sprintf("target.baseURL scheme %q is not supported (use http or https)", u.Scheme))
	} else if u.Host == "" {
		problems = append(problems, "target.baseURL must include a host")
	} else if u.User != nil {
		problems = append(problems, "target.baseURL must not embed credentials; put them in an identity instead")
	}

	profile := model.Profile(c.Assessment.Profile)
	if !profile.Valid() {
		problems = append(problems, fmt.Sprintf(
			"assessment.profile %q is not one of discovery, verification, intrusive", c.Assessment.Profile))
	} else if profile == model.ProfileIntrusive && !c.Assessment.AuthorizeIntrusive {
		problems = append(problems, "assessment.profile is intrusive but assessment.authorizeIntrusive is not set; "+
			"intrusive testing can change or destroy data and must be authorized explicitly")
	}

	if c.Assessment.Concurrency < 1 || c.Assessment.Concurrency > 64 {
		problems = append(problems, "assessment.concurrency must be between 1 and 64")
	}
	if c.Assessment.RequestsPerSecond <= 0 || c.Assessment.RequestsPerSecond > 1000 {
		problems = append(problems, "assessment.requestsPerSecond must be greater than 0 and at most 1000")
	}
	if c.Assessment.TimeoutSeconds < 1 || c.Assessment.TimeoutSeconds > 300 {
		problems = append(problems, "assessment.timeoutSeconds must be between 1 and 300")
	}

	if c.Discovery.OpenAPIFile != "" && c.Discovery.OpenAPIURL != "" {
		problems = append(problems, "discovery.openAPIFile and discovery.openAPIURL are mutually exclusive")
	}
	if c.Discovery.OpenAPIURL != "" {
		if u, err := url.Parse(c.Discovery.OpenAPIURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			problems = append(problems, "discovery.openAPIURL must be an http or https URL")
		}
	}

	if c.Outcome.ErrorCodePointer != "" && !strings.HasPrefix(c.Outcome.ErrorCodePointer, "/") {
		problems = append(problems, `outcome.errorCodePointer must be a JSON pointer beginning with "/"`)
	}

	for i, e := range c.Scope.Include {
		if e.Host == "" {
			problems = append(problems, fmt.Sprintf("scope.include[%d].host is required", i))
		}
		if e.Scheme != "" && e.Scheme != "http" && e.Scheme != "https" {
			problems = append(problems, fmt.Sprintf("scope.include[%d].scheme %q is not http or https", i, e.Scheme))
		}
		for _, p := range e.Ports {
			if p < 1 || p > 65535 {
				problems = append(problems, fmt.Sprintf("scope.include[%d] port %d is out of range", i, p))
			}
		}
	}

	for name, v := range map[string]string{
		"policy.failOnConfirmed": c.Policy.FailOnConfirmed,
		"policy.failOnSuspected": c.Policy.FailOnSuspected,
	} {
		if v != "" && !model.Severity(v).Valid() {
			problems = append(problems, fmt.Sprintf(
				"%s %q is not one of info, low, medium, high, critical (or empty to disable)", name, v))
		}
	}

	if c.Output.Dir == "" {
		problems = append(problems, "output.dir is required")
	}

	// Identity rules live in the identity package beside the types they
	// constrain, so that the validation a credential must pass cannot drift
	// away from the code that resolves it.
	problems = append(problems, identity.ValidateAll(c.IdentityModels())...)

	known := map[string]bool{}
	for _, i := range c.Identities {
		if i.ID != "" {
			known[i.ID] = true
		}
	}
	problems = append(problems, resource.ValidateAll(c.ResourceFixtures(), known)...)

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  - "))
	}
	return nil
}

// IdentityModels maps the configured identities onto the identity package's
// types.
//
// The mapping is explicit rather than a shared struct because the two have
// different jobs: the config type is the YAML wire format and must keep its
// tags and its pointer-for-optional fields, while the identity type is the
// domain model and carries none.
func (c Config) IdentityModels() []identity.Identity {
	out := make([]identity.Identity, 0, len(c.Identities))
	for _, i := range c.Identities {
		id := identity.Identity{
			ID:    i.ID,
			Label: i.Label,
			Auth: identity.Authentication{
				Scheme:      identity.Scheme(i.Authentication.Type),
				Header:      i.Authentication.Header,
				ValuePrefix: i.Authentication.ValuePrefix,
				Credential: identity.CredentialSource{
					Env:  i.Authentication.Credential.Env,
					File: i.Authentication.Credential.File,
				},
			},
		}
		if i.Liveness != nil {
			id.Live = identity.Liveness{
				Method:       i.Liveness.Method,
				Path:         i.Liveness.Path,
				ExpectStatus: i.Liveness.ExpectStatus,
			}
		}
		out = append(out, id)
	}
	return out
}

// ResourceFixtures maps the configured resources onto the resource package's
// types.
func (c Config) ResourceFixtures() []resource.Fixture {
	out := make([]resource.Fixture, 0, len(c.Resources))
	for _, r := range c.Resources {
		f := resource.Fixture{
			ID:               r.ID,
			Type:             r.Type,
			Owner:            r.Owner,
			CrossOwnerAccess: resource.Expectation(r.CrossOwnerAccess),
			Values:           r.Values,
			Operations:       r.Operations,
			NonOwners:        r.NonOwners,
			// Everything configurable is, by definition, configured. Resources
			// created through the application's own API would carry
			// ProvenanceAPICreated, and M2 does not create any.
			Provenance: resource.ProvenanceConfigured,
		}
		if r.Mutation != nil {
			f.Mutation = &resource.Mutation{Values: r.Mutation.Values}
		}
		out = append(out, f)
	}
	return out
}

// Profile returns the validated profile.
func (c Config) Profile() model.Profile { return model.Profile(c.Assessment.Profile) }

// ShouldExcludeAuthEndpoints reports the effective setting.
func (c Config) ShouldExcludeAuthEndpoints() bool {
	if c.Assessment.ExcludeAuthEndpoints == nil {
		return true
	}
	return *c.Assessment.ExcludeAuthEndpoints
}

// ShouldProbeWellKnownPaths reports the effective setting.
func (c Config) ShouldProbeWellKnownPaths() bool {
	if c.Discovery.ProbeWellKnownPaths == nil {
		return true
	}
	return *c.Discovery.ProbeWellKnownPaths
}

// ScopePolicy builds the network authorization boundary.
//
// The target's own origin is always included: the URL the operator typed is the
// authorization they gave. Everything else must be granted explicitly.
func (c Config) ScopePolicy() (*scope.Policy, error) {
	u, err := url.Parse(c.Target.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("config: target.baseURL: %w", err)
	}
	entries := []scope.Entry{targetEntry(u)}
	for _, e := range c.Scope.Include {
		entries = append(entries, scope.Entry{
			Scheme:     e.Scheme,
			Host:       e.Host,
			Ports:      e.Ports,
			PathPrefix: e.PathPrefix,
		})
	}
	return scope.New(entries, c.Scope.AllowPrivateAddresses)
}

// targetEntry grants exactly the target's scheme, host and port.
func targetEntry(u *url.URL) scope.Entry {
	e := scope.Entry{Scheme: u.Scheme, Host: u.Hostname()}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			e.Ports = []int{n}
		}
	}
	return e
}
