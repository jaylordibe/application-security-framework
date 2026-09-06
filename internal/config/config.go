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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/jaylordibe/application-security-framework/internal/adapter"
	"github.com/jaylordibe/application-security-framework/internal/discovery"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/resource"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// adapterNamePattern constrains an adapter name to a plain identifier.
var adapterNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// envPattern constrains an environment variable name to the POSIX shape.
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// engineSeverityPattern constrains a severity filter to a plain word, so an
// operator-supplied value reaching an argument vector cannot look like a flag.
var engineSeverityPattern = regexp.MustCompile(`^[a-z]{1,16}$`)

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
	Adapters    Adapters    `yaml:"adapters"`
	Engines     Engines     `yaml:"engines"`
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

// Adapters configures framework adapters.
//
// Adapters are opt-in and are never discovered from a target repository. A
// manifest sitting in a checkout must not be able to cause a program to run
// (ADR-0002).
type Adapters struct {
	// SourceRoot is the application source to inspect. Required when any
	// adapter is configured.
	SourceRoot string `yaml:"sourceRoot"`
	// Trust authorises adapters that execute the inspected application's own
	// code. "none" (the default) permits only adapters that do not.
	//
	// This is a separate decision from configuring an adapter because
	// framework-native introspection is not passive: asking Laravel to list its
	// routes boots the framework and runs every service provider, and importing
	// a NestJS module executes it. Neither should happen because somebody added
	// a line naming an executable.
	Trust string `yaml:"trust"`
	// Use lists the adapters to run.
	Use []AdapterUse `yaml:"use"`
}

// AdapterUse is one configured adapter.
type AdapterUse struct {
	// Name must match the name the adapter reports, so a document cannot be
	// attributed to an adapter that did not produce it.
	Name string `yaml:"name"`
	// Path is the adapter executable. It is executed directly with an explicit
	// argument vector and never through a shell.
	Path string `yaml:"path"`
	// Args are extra arguments passed after --source-root.
	Args []string `yaml:"args"`
	// TimeoutSeconds bounds this adapter. Zero uses the default.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// PassEnv names environment variables to forward. The adapter's environment
	// is otherwise built from nothing: a CI environment holds cloud
	// credentials, registry tokens and this tool's own identity credentials,
	// and none of that belongs in a third-party binary run against an untrusted
	// repository.
	PassEnv []string `yaml:"passEnv"`
}

// Engines configures external scanning engines.
//
// Each engine is a named, known integration rather than a command an operator
// composes. There is deliberately no `command`, `args` or `env` here: those
// would make AppSec Framework a general process runner, and the argument-vector
// construction, minimal environment and profile gating that make an engine safe
// to run would all become optional.
type Engines struct {
	// SourceRoot is an application checkout, for engines that read code.
	SourceRoot string `yaml:"sourceRoot"`
	Nuclei     Engine `yaml:"nuclei"`
	ZAP        Engine `yaml:"zap"`
	SAST       Engine `yaml:"sast"`
}

// Engine is one external engine's settings.
type Engine struct {
	// Enabled turns the engine on. Engines are off by default: none runs
	// because it happens to be installed.
	Enabled bool `yaml:"enabled"`
	// Executable is an explicit path. Empty means look the engine's own binary
	// name up on PATH.
	Executable string `yaml:"executable"`
	// Templates or Rules is the corpus the engine runs. It must be a local
	// path: AppSec Framework ships none and fetches none, because a corpus that
	// changes between runs makes results incomparable and an unrecorded corpus
	// is an unrecorded dependency.
	Templates string `yaml:"templates"`
	Rules     string `yaml:"rules"`
	// Mode narrows what an engine may do, for engines that have modes. ZAP's
	// "active" mode sends attack payloads and requires the intrusive profile.
	Mode string `yaml:"mode"`
	// Severity optionally narrows which severities an engine reports.
	Severity []string `yaml:"severity"`
	// RateLimit bounds requests per second, for engines that send traffic.
	RateLimit int `yaml:"rateLimit"`
	// TimeoutSeconds bounds the run.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// PassEnv names environment variables to forward. The engine's environment
	// is otherwise built from nothing, and this tool's identity credentials can
	// never be forwarded whatever is named here.
	PassEnv []string `yaml:"passEnv"`
	// AllowUnsignedTemplates lets Nuclei execute templates that carry no
	// signature.
	//
	// It exists because refusing them outright would rule out every template an
	// operator writes themselves, and defaults to false because a template is
	// executable security logic that runs against the operator's own target.
	// Turning it on is a statement that this directory is trusted, and the
	// provenance of every resulting observation records that nothing else
	// established it.
	AllowUnsignedTemplates bool `yaml:"allowUnsignedTemplates"`
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
	// Surface configures discovery of paths the specification does not
	// describe.
	Surface SurfaceDiscovery `yaml:"surface"`
}

// SurfaceDiscovery configures the discovery of undocumented surface.
//
// There is deliberately no depth, no seed list, no wordlist and no include
// pattern here. Each of those is a knob a crawler needs and this is not one: it
// makes a single non-recursive pass over artefacts the application publishes
// about itself. A configuration that could express "crawl three levels deep"
// would mean the code behind it could too.
type SurfaceDiscovery struct {
	// Enabled turns discovery on. It defaults to on, because the alternative is
	// a coverage ledger that silently measures only the surface the application
	// chose to document.
	Enabled *bool `yaml:"enabled"`
	// LinkHeaders, Robots, JavaScript and WellKnown enable individual sources.
	// Each defaults to on when discovery is enabled; they exist so an operator
	// whose target dislikes one of them can turn just that one off.
	LinkHeaders *bool `yaml:"linkHeaders"`
	Robots      *bool `yaml:"robots"`
	JavaScript  *bool `yaml:"javascript"`
	WellKnown   *bool `yaml:"wellKnown"`

	// MaxRequests, MaxScripts, MaxBytes and MaxCandidates bound what a target
	// can make discovery do. Zero means the built-in default.
	MaxRequests   int   `yaml:"maxRequests"`
	MaxScripts    int   `yaml:"maxScripts"`
	MaxBytes      int64 `yaml:"maxBytes"`
	MaxCandidates int   `yaml:"maxCandidates"`

	// AssessAdapterDiscovered permits assessing operations a framework adapter
	// found that the specification does not document.
	//
	// It is separate from the sources above and defaults to on, because it is
	// the one case where discovered surface is genuinely testable: the adapter
	// read the application's routing table, so the method is known and the
	// authentication expectation comes from the same source that would have
	// supplied it had the route been documented. Nothing is invented. It is
	// still a switch, because it means requests to routes the operator may not
	// have known were there.
	AssessAdapterDiscovered *bool `yaml:"assessAdapterDiscovered"`
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
	problems = append(problems, c.validateAdapters()...)
	problems = append(problems, c.validateEngines()...)

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

// validateAdapters checks the adapter configuration.
func (c Config) validateAdapters() []string {
	var problems []string
	if len(c.Adapters.Use) == 0 {
		if c.Adapters.SourceRoot != "" || c.Adapters.Trust != "" {
			problems = append(problems, "adapters.sourceRoot and adapters.trust have no effect "+
				"without adapters.use")
		}
		return problems
	}
	if c.Adapters.SourceRoot == "" {
		problems = append(problems, "adapters.sourceRoot is required when an adapter is configured; "+
			"an adapter must be told what to inspect rather than discovering it")
	}
	if t := c.Adapters.Trust; t != "" && !adapter.TrustMode(t).Valid() {
		problems = append(problems, fmt.Sprintf("adapters.trust %q is not one of none, %s",
			t, adapter.TrustExecuteTargetCode))
	}
	seen := map[string]int{}
	for i, a := range c.Adapters.Use {
		path := fmt.Sprintf("adapters.use[%d]", i)
		switch {
		case a.Name == "":
			problems = append(problems, path+".name is required")
		case !adapterNamePattern.MatchString(a.Name):
			problems = append(problems, fmt.Sprintf("%s.name %q must be lowercase letters, digits, "+
				"hyphen or underscore", path, a.Name))
		default:
			if first, dup := seen[a.Name]; dup {
				problems = append(problems, fmt.Sprintf("%s.name %q duplicates adapters.use[%d]",
					path, a.Name, first))
			}
			seen[a.Name] = i
		}
		if a.Path == "" {
			problems = append(problems, path+".path is required; an adapter is executed by explicit "+
				"path and is never searched for")
		}
		if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 900 {
			problems = append(problems, path+".timeoutSeconds must be between 0 and 900")
		}
		for j, e := range a.PassEnv {
			if !envPattern.MatchString(e) {
				problems = append(problems, fmt.Sprintf("%s.passEnv[%d] %q is not a valid environment "+
					"variable name", path, j, e))
			}
		}
	}
	return problems
}

// validateEngines checks the external engine configuration.
func (c Config) validateEngines() []string {
	var problems []string
	named := map[string]Engine{
		"nuclei": c.Engines.Nuclei, "zap": c.Engines.ZAP, "sast": c.Engines.SAST,
	}
	for _, name := range []string{"nuclei", "sast", "zap"} {
		e := named[name]
		path := "engines." + name
		if !e.Enabled {
			continue
		}
		if e.TimeoutSeconds < 0 || e.TimeoutSeconds > 7200 {
			problems = append(problems, path+".timeoutSeconds must be between 0 and 7200")
		}
		if e.RateLimit < 0 || e.RateLimit > 1000 {
			problems = append(problems, path+".rateLimit must be between 0 and 1000")
		}
		for i, v := range e.PassEnv {
			if !envPattern.MatchString(v) {
				problems = append(problems, fmt.Sprintf("%s.passEnv[%d] %q is not a valid "+
					"environment variable name", path, i, v))
			}
		}
		for i, v := range e.Severity {
			if !engineSeverityPattern.MatchString(v) {
				problems = append(problems, fmt.Sprintf("%s.severity[%d] %q is not a plain "+
					"severity name", path, i, v))
			}
		}
		switch name {
		case "nuclei":
			if e.Templates == "" {
				problems = append(problems, path+".templates is required when nuclei is enabled; "+
					"AppSec Framework will not let it fetch templates for itself, because a scan "+
					"against a corpus that changed overnight is not reproducible")
			}
		case "sast":
			if e.Rules == "" {
				problems = append(problems, path+".rules is required when sast is enabled; AppSec "+
					"Framework ships no rules and will not pull them from a registry")
			}
			if c.Engines.SourceRoot == "" {
				problems = append(problems, "engines.sourceRoot is required when sast is enabled; "+
					"a static analyser needs an application checkout to read")
			}
		case "zap":
			if e.Mode != "" && e.Mode != "passive" && e.Mode != "active" {
				problems = append(problems, path+`.mode must be "passive" or "active"`)
			}
			if e.Mode == "active" && c.Profile() != model.ProfileIntrusive {
				problems = append(problems, "engines.zap.mode is active, which sends attack "+
					"payloads and requires assessment.profile: intrusive")
			}
		}
	}
	return problems
}

// EngineSettings maps a configured engine onto the scanner package's settings.
func (e Engine) EngineSettings() scanner.Settings {
	s := scanner.Settings{
		Enabled:        e.Enabled,
		Executable:     e.Executable,
		TimeoutSeconds: e.TimeoutSeconds,
		PassEnv:        e.PassEnv,
		Severity:       e.Severity,
		Extra:          map[string]string{},
	}
	// One of the two corpus fields, whichever the engine uses.
	s.RuleSource = e.Templates
	if s.RuleSource == "" {
		s.RuleSource = e.Rules
	}
	if e.Mode != "" {
		s.Extra["mode"] = e.Mode
	}
	if e.RateLimit > 0 {
		s.Extra["rateLimit"] = strconv.Itoa(e.RateLimit)
	}
	if e.AllowUnsignedTemplates {
		s.Extra["allowUnsignedTemplates"] = "true"
	}
	return s
}

// AdapterTrust returns the effective trust mode.
func (c Config) AdapterTrust() adapter.TrustMode {
	if c.Adapters.Trust == "" {
		return adapter.TrustNone
	}
	return adapter.TrustMode(c.Adapters.Trust)
}

// AdapterSpecs maps the configured adapters onto execution specs.
func (c Config) AdapterSpecs() []adapter.Spec {
	out := make([]adapter.Spec, 0, len(c.Adapters.Use))
	for _, a := range c.Adapters.Use {
		out = append(out, adapter.Spec{
			Name:       a.Name,
			Path:       a.Path,
			Args:       a.Args,
			SourceRoot: c.Adapters.SourceRoot,
			Timeout:    time.Duration(a.TimeoutSeconds) * time.Second,
			PassEnv:    a.PassEnv,
		})
	}
	return out
}

// CredentialEnvNames returns the environment variables holding this tool's own
// identity credentials, so they can be kept out of every adapter.
func (c Config) CredentialEnvNames() []string {
	var out []string
	for _, i := range c.Identities {
		if e := i.Authentication.Credential.Env; e != "" {
			out = append(out, e)
		}
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
// SurfaceDiscoveryEnabled reports whether undocumented-surface discovery runs.
func (c Config) SurfaceDiscoveryEnabled() bool {
	return boolOr(c.Discovery.Surface.Enabled, true)
}

// AssessAdapterDiscovered reports whether adapter-found operations that the
// specification omits are assessed.
func (c Config) AssessAdapterDiscovered() bool {
	return boolOr(c.Discovery.Surface.AssessAdapterDiscovered, true)
}

// DiscoverySources maps the configuration onto the discovery package's source
// selection.
func (c Config) DiscoverySources() discovery.Sources {
	if !c.SurfaceDiscoveryEnabled() {
		return discovery.Sources{}
	}
	s := c.Discovery.Surface
	return discovery.Sources{
		LinkHeaders: boolOr(s.LinkHeaders, true),
		Robots:      boolOr(s.Robots, true),
		JavaScript:  boolOr(s.JavaScript, true),
		WellKnown:   boolOr(s.WellKnown, true),
	}
}

// DiscoveryLimits maps the configuration onto the discovery package's budgets.
// Unset fields keep the built-in defaults rather than becoming zero, which would
// disable discovery by accident.
func (c Config) DiscoveryLimits() discovery.Limits {
	s := c.Discovery.Surface
	l := discovery.DefaultLimits()
	if s.MaxRequests > 0 {
		l.MaxRequests = s.MaxRequests
	}
	if s.MaxScripts > 0 {
		l.MaxScripts = s.MaxScripts
	}
	if s.MaxBytes > 0 {
		l.MaxBytes = s.MaxBytes
	}
	if s.MaxCandidates > 0 {
		l.MaxCandidates = s.MaxCandidates
	}
	return l
}

// boolOr resolves an optional boolean against its default.
func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

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
