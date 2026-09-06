package identity

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/redact"
)

// Liveness is what is known about whether an identity can still authenticate.
//
// Three states, because two would force a lie. "Unknown" is not a synonym for
// "good": before the first canary, and for an identity with no canary
// configured, the honest answer is that nobody has checked.
type LivenessState string

const (
	// LivenessUnknown means no canary has reported yet.
	LivenessUnknown LivenessState = "unknown"
	// LivenessGood means a canary succeeded and the identity authenticated.
	LivenessGood LivenessState = "good"
	// LivenessBad means a canary ran and the identity failed to authenticate.
	LivenessBad LivenessState = "bad"
)

// Status is a snapshot of an identity for reporting. It deliberately contains
// no credential, no credential length and no credential fingerprint.
type Status struct {
	ID     string
	Label  string
	Scheme Scheme
	// Source describes where the credential came from, by location only.
	Source string
	// Usable is false when the credential could not be resolved at all.
	Usable bool
	// Problem explains why the identity is unusable, or why a canary failed.
	Problem string
	// Monitored reports whether a liveness canary is configured.
	Monitored bool
	Liveness  LivenessState
	// LastGood is the most recent time a canary confirmed the identity.
	LastGood time.Time
	// FirstBad is the first time a canary reported the identity invalid. The
	// interval (LastGood, FirstBad] is the window in which the credential's
	// validity is unknown, because a canary observes expiry only when it next
	// runs, not when it happens.
	FirstBad time.Time
	// Probes counts canary probes performed.
	Probes int
	// Warnings are non-fatal observations about how the credential is stored.
	Warnings []string
}

// UncertaintyWindow reports the interval in which authenticated results cannot
// be trusted, and whether one exists.
//
// A result whose authenticated request completed at or before LastGood is
// backed by a credential a canary confirmed afterwards. A result after LastGood,
// once FirstBad is known, may have been produced by a credential that had
// already expired.
func (s Status) UncertaintyWindow() (from time.Time, to time.Time, ok bool) {
	if s.Liveness != LivenessBad || s.FirstBad.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return s.LastGood, s.FirstBad, true
}

// Control issues authenticated requests as one identity and tracks whether that
// identity is still usable.
//
// Concurrency: a Control is safe for use by many goroutines. It holds no
// per-request state, and Headers returns a freshly allocated map on every call,
// so two identities executing concurrently cannot contaminate one another's
// requests. The underlying httpx.Client is shared deliberately — it is
// stateless per request and carries the scope policy that must apply to
// authenticated traffic exactly as it applies to anonymous traffic.
type Control struct {
	id     Identity
	secret Secret
	// baseURL is the target root the canary path resolves against.
	baseURL string
	client  *httpx.Client

	mu       sync.Mutex
	state    LivenessState
	lastGood time.Time
	firstBad time.Time
	probes   int
	problem  string
	warnings []string
	// probing serialises canary probes so that a burst of suspicious responses
	// produces one probe rather than one per goroutine.
	probing bool
}

// ID returns the identity id.
func (c *Control) ID() string { return c.id.ID }

// Status returns a snapshot for reporting.
func (c *Control) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := make([]string, len(c.warnings))
	copy(w, c.warnings)
	return Status{
		ID:        c.id.ID,
		Label:     c.id.Label,
		Scheme:    c.id.Auth.Scheme,
		Source:    c.id.Auth.Credential.Describe(),
		Usable:    !c.secret.Empty(),
		Problem:   c.problem,
		Monitored: c.id.Live.Configured(),
		Liveness:  c.state,
		LastGood:  c.lastGood,
		FirstBad:  c.firstBad,
		Probes:    c.probes,
		Warnings:  w,
	}
}

// Headers returns a freshly allocated header map carrying this identity's
// credential.
//
// A new map every call is not defensive style, it is the isolation guarantee:
// returning a shared map would let one goroutine's request mutate another's, and
// would let a credential outlive the request it was built for.
func (c *Control) Headers() map[string][]string {
	h := make(map[string][]string, 1)
	switch c.id.Auth.Scheme {
	case SchemeBearer:
		h["Authorization"] = []string{"Bearer " + c.secret.Expose()}
	case SchemeAPIKey:
		h[c.id.Auth.Header] = []string{c.id.Auth.ValuePrefix + c.secret.Expose()}
	}
	return h
}

// Usable reports whether an authenticated request may be attempted, and why not
// when it may not.
//
// A known-bad identity is refused rather than retried. Continuing to send a
// credential a canary has already rejected produces a sweep of denials that
// look exactly like a correctly protected application.
func (c *Control) Usable() (bool, model.BlockedCause, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.secret.Empty() {
		detail := "the credential for identity " + c.id.ID + " could not be resolved"
		if c.problem != "" {
			detail += ": " + c.problem
		}
		return false, model.CauseMissingIdentity, detail
	}
	if c.state == LivenessBad {
		detail := "identity " + c.id.ID + " is no longer accepted by the target"
		if c.problem != "" {
			detail += ": " + c.problem
		}
		return false, model.CauseAuthenticationFailed, detail
	}
	return true, model.CauseNone, ""
}

// Do issues an authenticated request.
//
// Scope is enforced by the shared client exactly as it is for anonymous
// traffic: the URL gate runs before resolution and the address gate runs at
// dial time, so an authenticated request can no more reach an unauthorized host
// than an anonymous one can. Redirects are not followed, so a credential is
// never replayed to a Location the target chose.
func (c *Control) Do(ctx context.Context, method, url string, extra map[string][]string) (model.Exchange, error) {
	return c.DoWithBody(ctx, method, url, extra, nil)
}

// DoWithBody is Do with a request body, for the state-changing requests a
// cross-owner write check makes.
//
// The header map is rebuilt from scratch on every call and the caller's map is
// copied rather than adopted, so no request can observe or alter another's
// headers. That is the isolation guarantee two identities running concurrently
// depend on.
func (c *Control) DoWithBody(
	ctx context.Context,
	method, url string,
	extra map[string][]string,
	body []byte,
) (model.Exchange, error) {
	header := make(map[string][]string, len(extra)+2)
	for k, v := range extra {
		cp := make([]string, len(v))
		copy(cp, v)
		header[k] = cp
	}
	for k, v := range c.Headers() {
		header[k] = v
	}
	return c.client.Do(ctx, httpx.Request{Method: method, URL: url, Header: header, Body: body})
}

// NoteSuspicious reports that an authenticated request produced a result
// consistent with an invalid credential, and triggers a canary probe.
//
// This is event-driven rather than periodic on purpose. A timer probes when
// nothing has happened and stays silent when everything has; probing at the
// moment a credential first looks wrong finds the expiry with the smallest
// possible uncertainty window, which is exactly the interval that later has to
// be treated as untrusted.
func (c *Control) NoteSuspicious(ctx context.Context) {
	if !c.id.Live.Configured() {
		// Nothing can be established without a canary. The caller still records
		// the failed control; it simply cannot be attributed to expiry.
		return
	}
	c.mu.Lock()
	if c.probing || c.state == LivenessBad {
		c.mu.Unlock()
		return
	}
	c.probing = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.probing = false
		c.mu.Unlock()
	}()
	c.probe(ctx)
}

// Probe runs the liveness canary now and returns the resulting state.
func (c *Control) Probe(ctx context.Context) LivenessState {
	if !c.id.Live.Configured() {
		return LivenessUnknown
	}
	c.mu.Lock()
	if c.probing {
		state := c.state
		c.mu.Unlock()
		return state
	}
	c.probing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.probing = false
		c.mu.Unlock()
	}()
	return c.probe(ctx)
}

// probe performs the canary request and records what it learned.
func (c *Control) probe(ctx context.Context) LivenessState {
	if c.secret.Empty() {
		return LivenessUnknown
	}
	method := strings.ToUpper(strings.TrimSpace(c.id.Live.Method))
	if method == "" {
		method = http.MethodGet
	}
	url := strings.TrimRight(c.baseURL, "/") + "/" + strings.TrimLeft(c.id.Live.Path, "/")

	ex, err := c.Do(ctx, method, url, map[string][]string{
		"Accept":        {"application/json, */*"},
		"Cache-Control": {"no-cache"},
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	c.probes++

	switch {
	case err != nil || ex.Response == nil:
		// A transport failure says nothing about the credential. Recording it as
		// bad would block every authenticated control because the network
		// hiccuped, which is a worse error than the one it prevents.
		c.problem = "the liveness canary could not be completed: " + ex.Err
		if c.state == LivenessGood {
			// Keep the last good observation; the identity is not known bad.
			return c.state
		}
		c.state = LivenessUnknown
		return c.state
	case c.id.Live.Accepts(ex.Response.Status):
		c.state = LivenessGood
		c.lastGood = time.Now()
		c.problem = ""
		return c.state
	default:
		c.state = LivenessBad
		if c.firstBad.IsZero() {
			c.firstBad = time.Now()
		}
		c.problem = fmt.Sprintf("the liveness canary %s %s returned %d, which is not an accepted status",
			method, c.id.Live.Path, ex.Response.Status)
		return c.state
	}
}

// Set is the resolved identities for one run.
//
// It is a concrete type rather than an interface. There is one implementation
// and no prospect of a second, and ADR-0009 is explicit that an interface with
// one implementation is indirection rather than abstraction.
type Set struct {
	controls []*Control
	byID     map[string]*Control
}

// Controls returns every configured identity's control, in configuration order.
func (s *Set) Controls() []*Control {
	if s == nil {
		return nil
	}
	out := make([]*Control, len(s.controls))
	copy(out, s.controls)
	return out
}

// Len reports how many identities are configured.
//
// Len and ByID have no caller in the M1 flow, which uses Primary alone. They
// exist because Set is the seam M2 selects identities through, and a container
// that cannot be counted or addressed by id would have to be reshaped there.
// Both are covered by tests so they cannot rot before that caller arrives.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.controls)
}

// Primary returns the identity used as the authenticated control.
//
// M1 uses exactly one. The type carries a slice so that M2 can add a second
// without reshaping every caller, but choosing between identities is a
// cross-identity decision and belongs to M2, not here.
func (s *Set) Primary() *Control {
	if s == nil || len(s.controls) == 0 {
		return nil
	}
	return s.controls[0]
}

// ByID returns one identity's control.
func (s *Set) ByID(id string) (*Control, bool) {
	if s == nil {
		return nil, false
	}
	c, ok := s.byID[id]
	return c, ok
}

// Statuses returns a snapshot of every identity.
func (s *Set) Statuses() []Status {
	if s == nil {
		return nil
	}
	out := make([]Status, 0, len(s.controls))
	for _, c := range s.controls {
		out = append(out, c.Status())
	}
	return out
}

// Resolve reads every identity's credential and builds its control.
//
// Credentials are registered with the redactor before the first request is
// possible, so a value cannot reach evidence even if the very first exchange
// carries it. An identity whose credential cannot be resolved is still returned:
// it is unusable, and the run must be able to say so in the ledger rather than
// quietly proceeding anonymously.
func Resolve(ids []Identity, baseURL string, client *httpx.Client, red *redact.Redactor) *Set {
	set := &Set{byID: make(map[string]*Control, len(ids))}
	for _, id := range ids {
		c := &Control{
			id:      id,
			baseURL: baseURL,
			client:  client,
			state:   LivenessUnknown,
		}

		if id.Auth.Scheme == SchemeAPIKey && id.Auth.Header != "" {
			// Register the header name before anything can be captured, so a
			// bespoke credential header is replaced by name and not only by
			// value.
			red.RegisterSensitiveHeader(id.Auth.Header)
		}

		secret, err := id.Auth.Credential.Resolve()
		if err != nil {
			c.problem = err.Error()
		} else {
			c.secret = secret
			// Register before first use. The value, and the exact string that
			// will travel on the wire, are both registered: a target that
			// reflects "Bearer <token>" back in a body must not defeat
			// redaction by including the scheme.
			red.Register(secret.Expose(), redact.Placeholder)
			switch id.Auth.Scheme {
			case SchemeBearer:
				red.Register("Bearer "+secret.Expose(), redact.Placeholder)
			case SchemeAPIKey:
				if id.Auth.ValuePrefix != "" {
					red.Register(id.Auth.ValuePrefix+secret.Expose(), redact.Placeholder)
				}
			}
			c.warnings = append(c.warnings, credentialWarnings(id.Auth.Credential)...)
		}

		set.controls = append(set.controls, c)
		set.byID[id.ID] = c
	}
	return set
}

// credentialWarnings reports non-fatal concerns about how a credential is
// stored. They are warnings rather than refusals because the operator, not this
// tool, owns the filesystem: refusing to run because a CI system mounted a
// secret group-readable would be an obstruction, while saying nothing would let
// a genuinely world-readable credential pass unremarked.
func credentialWarnings(src CredentialSource) []string {
	if src.File == "" {
		return nil
	}
	info, err := os.Stat(src.File)
	if err != nil {
		return nil
	}
	if !permissionsEnforced() {
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return []string{fmt.Sprintf("credential file %s is mode %o and is readable by users other than "+
			"its owner", src.File, perm)}
	}
	return nil
}

// permissionsEnforced reports whether this platform honours POSIX file modes.
// On Windows os.Chmod only toggles a read-only attribute, so a mode check there
// would report a problem that does not exist and one that does, at random.
func permissionsEnforced() bool { return runtime.GOOS != "windows" }
