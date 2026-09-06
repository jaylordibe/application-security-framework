package identity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Scheme is how a credential is presented to the target.
//
// The set is deliberately tiny. OAuth2 flows, OIDC, browser login, cookie
// session establishment and refresh rotation are all out of scope for M1: each
// needs multi-step state, and a half-implemented login flow that silently falls
// back to anonymous is precisely the false-assurance failure this project
// exists to prevent.
type Scheme string

const (
	// SchemeBearer sends Authorization: Bearer <credential>.
	SchemeBearer Scheme = "bearer"
	// SchemeAPIKey sends <header>: <valuePrefix><credential>.
	SchemeAPIKey Scheme = "apiKey"
)

// Valid reports whether s is a supported scheme.
func (s Scheme) Valid() bool { return s == SchemeBearer || s == SchemeAPIKey }

// AnonymousID is the reserved id of the always-available identity that presents
// no credentials. It may not be configured.
const AnonymousID = "anonymous"

// MaxCredentialBytes bounds a credential read from a file. A credential is a
// token, not a payload; anything larger is a misconfiguration such as a path
// pointing at a log or a keyring database.
const MaxCredentialBytes = 64 << 10

// idPattern constrains an identity id to something safe to place in a report, a
// ledger key and a filename without escaping.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// envPattern constrains an environment variable name to the POSIX shape.
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tokenPattern is an RFC 9110 field-name: 1*tchar.
//
// Validating this is not cosmetic. An unvalidated header name reaches
// http.Header.Add, and a name containing a colon, CR or LF is the classic
// request-splitting primitive. Go's net/http does reject some of this, but a
// security tool must not depend on a downstream library's validation for a
// control it can enforce itself.
var tokenPattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// forbiddenHeaders may not carry a credential.
//
// Host, Content-Length, Transfer-Encoding, Connection and Upgrade control the
// message framing and the connection; setting them from configuration would let
// a credential header corrupt the request or, in the case of Host, redirect it
// past the scope gate that was evaluated against the URL. User-Agent is refused
// because being identifiable is a deliberate safety property (threat model
// T-14), not an operator preference.
var forbiddenHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"transfer-encoding": true,
	"connection":        true,
	"upgrade":           true,
	"user-agent":        true,
}

// CredentialSource says where a credential is read from.
//
// Exactly one field must be set. Both options keep the secret out of the
// repository: a value written directly into appsec.yaml would be committed,
// reviewed, copied into CI logs and mirrored into every fork, so it is not
// offered at all rather than offered with a warning.
type CredentialSource struct {
	// Env names an environment variable holding the credential.
	Env string
	// File names a file whose entire contents are the credential. Leading and
	// trailing whitespace is trimmed, because a file written with a here-doc or
	// an editor almost always ends in a newline that is not part of the token.
	File string
}

// Describe renders the source for an operator, naming the location but never
// reading it.
func (s CredentialSource) Describe() string {
	switch {
	case s.Env != "":
		return "environment variable " + s.Env
	case s.File != "":
		return "file " + s.File
	default:
		return "no credential source"
	}
}

// Validate checks the source's shape.
func (s CredentialSource) Validate(path string) []string {
	var problems []string
	switch {
	case s.Env != "" && s.File != "":
		problems = append(problems, path+": set exactly one of env or file, not both")
	case s.Env == "" && s.File == "":
		problems = append(problems, path+": one of env or file is required; a credential is never "+
			"written directly into the configuration file")
	case s.Env != "" && !envPattern.MatchString(s.Env):
		problems = append(problems, fmt.Sprintf("%s.env %q is not a valid environment variable name", path, s.Env))
	}
	return problems
}

// Resolve reads the credential.
//
// The returned error names the location and never the value, so that a
// resolution failure can be printed, logged and stored without becoming the
// leak it is reporting.
func (s CredentialSource) Resolve() (Secret, error) {
	switch {
	case s.Env != "":
		v, ok := os.LookupEnv(s.Env)
		if !ok {
			return Secret{}, fmt.Errorf("environment variable %s is not set", s.Env)
		}
		if strings.TrimSpace(v) == "" {
			return Secret{}, fmt.Errorf("environment variable %s is set but empty", s.Env)
		}
		return NewSecret(v), nil
	case s.File != "":
		f, err := os.Open(s.File)
		if err != nil {
			// os.Open's error text is the path and the errno, neither of which
			// is the credential.
			return Secret{}, fmt.Errorf("cannot read credential file: %w", err)
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(io.LimitReader(f, MaxCredentialBytes+1))
		if err != nil {
			return Secret{}, fmt.Errorf("cannot read credential file %s: %w", s.File, err)
		}
		if len(b) > MaxCredentialBytes {
			return Secret{}, fmt.Errorf("credential file %s exceeds %d bytes; a credential is a token, "+
				"not a payload", s.File, MaxCredentialBytes)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return Secret{}, fmt.Errorf("credential file %s is empty", s.File)
		}
		return NewSecret(v), nil
	default:
		return Secret{}, errors.New("no credential source is configured")
	}
}

// Authentication describes how to authenticate as an identity.
type Authentication struct {
	Scheme Scheme
	// Header is the field name for the apiKey scheme.
	Header string
	// ValuePrefix is prepended to the credential for the apiKey scheme, for
	// applications expecting e.g. "Token <key>" in a custom header.
	ValuePrefix string
	Credential  CredentialSource
}

// Liveness configures the canary that establishes whether an identity is still
// usable.
//
// The operation is supplied by the operator rather than guessed. Probing /me,
// /profile or /whoami on the assumption that they exist would produce a 404 on
// most applications, which is indistinguishable from an expired credential —
// the canary would then report the identity dead and block the entire run.
type Liveness struct {
	Method string
	// Path is resolved against the target's base URL and is subject to the same
	// scope policy as every other request.
	Path string
	// ExpectStatus lists statuses that mean the identity is still good. Empty
	// means any 2xx.
	ExpectStatus []int
}

// Configured reports whether a canary was supplied.
func (l Liveness) Configured() bool { return l.Path != "" }

// Accepts reports whether a status means the identity is still usable.
func (l Liveness) Accepts(status int) bool {
	if len(l.ExpectStatus) == 0 {
		return status >= 200 && status <= 299
	}
	for _, s := range l.ExpectStatus {
		if s == status {
			return true
		}
	}
	return false
}

// Identity is a security principal AppSec Framework may act as.
//
// It holds no credential. Auth.Credential is a reference to where the material
// lives; the material itself appears only in a Resolved, which is built at run
// start and never serialised.
type Identity struct {
	ID    string
	Label string
	Auth  Authentication
	// Live configures the liveness canary. Optional.
	Live Liveness
}

// Validate checks one identity's shape, returning operator-facing problems.
func (i Identity) Validate(path string) []string {
	var problems []string

	switch {
	case i.ID == "":
		problems = append(problems, path+".id is required")
	case i.ID == AnonymousID:
		problems = append(problems, fmt.Sprintf("%s.id %q is reserved for the built-in identity that "+
			"presents no credentials", path, AnonymousID))
	case !idPattern.MatchString(i.ID):
		problems = append(problems, fmt.Sprintf("%s.id %q must be 1-64 characters of lowercase letters, "+
			"digits, hyphen or underscore, starting with a letter or digit", path, i.ID))
	}

	if !i.Auth.Scheme.Valid() {
		problems = append(problems, fmt.Sprintf("%s.authentication.type %q is not one of bearer, apiKey",
			path, i.Auth.Scheme))
	}

	switch i.Auth.Scheme {
	case SchemeAPIKey:
		switch {
		case i.Auth.Header == "":
			problems = append(problems, path+".authentication.header is required for the apiKey scheme")
		case !tokenPattern.MatchString(i.Auth.Header):
			problems = append(problems, fmt.Sprintf("%s.authentication.header %q is not a valid HTTP header "+
				"name; a header name may contain only token characters", path, i.Auth.Header))
		case forbiddenHeaders[strings.ToLower(i.Auth.Header)]:
			problems = append(problems, fmt.Sprintf("%s.authentication.header %q may not carry a credential; "+
				"it controls the message framing, the connection or the tool's identifiability",
				path, i.Auth.Header))
		}
		if strings.ContainsAny(i.Auth.ValuePrefix, "\r\n\x00") {
			problems = append(problems, path+".authentication.valuePrefix may not contain control characters")
		}
	case SchemeBearer:
		if i.Auth.Header != "" {
			problems = append(problems, path+".authentication.header applies only to the apiKey scheme")
		}
		if i.Auth.ValuePrefix != "" {
			problems = append(problems, path+".authentication.valuePrefix applies only to the apiKey scheme")
		}
	}

	problems = append(problems, i.Auth.Credential.Validate(path+".authentication.credential")...)

	if i.Live.Configured() {
		if !strings.HasPrefix(i.Live.Path, "/") {
			problems = append(problems, fmt.Sprintf("%s.liveness.path %q must begin with /", path, i.Live.Path))
		}
		if i.Live.Method != "" && !tokenPattern.MatchString(i.Live.Method) {
			problems = append(problems, fmt.Sprintf("%s.liveness.method %q is not a valid HTTP method",
				path, i.Live.Method))
		}
		if i.Live.Method != "" && !isSafeCanaryMethod(i.Live.Method) {
			problems = append(problems, fmt.Sprintf("%s.liveness.method %q may change state; a canary runs "+
				"repeatedly and must be a safe method (GET, HEAD or OPTIONS)", path, i.Live.Method))
		}
		for _, s := range i.Live.ExpectStatus {
			if s < 100 || s > 599 {
				problems = append(problems, fmt.Sprintf("%s.liveness.expectStatus %d is not an HTTP status", path, s))
			}
		}
	}
	return problems
}

// isSafeCanaryMethod reports whether a method may be used for a repeated probe.
func isSafeCanaryMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// ValidateAll checks a whole set, including cross-identity rules.
func ValidateAll(ids []Identity) []string {
	var problems []string
	seen := map[string]int{}
	for i, id := range ids {
		path := fmt.Sprintf("identities[%d]", i)
		problems = append(problems, id.Validate(path)...)
		if id.ID == "" {
			continue
		}
		if first, dup := seen[id.ID]; dup {
			problems = append(problems, fmt.Sprintf("%s.id %q duplicates identities[%d].id; identity ids "+
				"key the coverage ledger and must be unique", path, id.ID, first))
			continue
		}
		seen[id.ID] = i
	}
	sort.Strings(problems)
	return problems
}
