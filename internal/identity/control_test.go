package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// clientFor builds a scope-enforced client pointed at a test server, so control
// behaviour is exercised through the same transport a real run uses.
func clientFor(t *testing.T, srv *httptest.Server) (*httpx.Client, *redact.Redactor) {
	t.Helper()
	var port int
	parts := strings.Split(srv.URL, ":")
	if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}
	pol, err := scope.New([]scope.Entry{
		{Host: "127.0.0.1", Ports: []int{port}},
		{Host: "localhost", Ports: []int{port}},
	}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	red := redact.New()
	c, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	t.Cleanup(c.Close)
	return c, red
}

func TestHeadersCarryTheCredential(t *testing.T) {
	tests := []struct {
		name       string
		auth       Authentication
		wantHeader string
		wantValue  string
	}{
		{
			name:       "bearer",
			auth:       Authentication{Scheme: SchemeBearer},
			wantHeader: "Authorization",
			wantValue:  "Bearer s3cr3t",
		},
		{
			name:       "api key",
			auth:       Authentication{Scheme: SchemeAPIKey, Header: "X-API-Key"},
			wantHeader: "X-API-Key",
			wantValue:  "s3cr3t",
		},
		{
			name:       "api key with prefix",
			auth:       Authentication{Scheme: SchemeAPIKey, Header: "X-API-Key", ValuePrefix: "Token "},
			wantHeader: "X-API-Key",
			wantValue:  "Token s3cr3t",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Control{id: Identity{ID: "admin", Auth: tc.auth}, secret: NewSecret("s3cr3t")}
			h := c.Headers()
			got, ok := h[tc.wantHeader]
			if !ok {
				t.Fatalf("header %s absent from %v", tc.wantHeader, keysOf(h))
			}
			if len(got) != 1 || got[0] != tc.wantValue {
				t.Errorf("header value = %v, want %q", got, tc.wantValue)
			}
		})
	}
}

func keysOf(h map[string][]string) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// Headers must hand back a fresh map every time. A shared map would let one
// request's mutation reach another goroutine's request, which for a credential
// header means one identity acting as another.
func TestHeadersAreNotShared(t *testing.T) {
	c := &Control{
		id:     Identity{ID: "admin", Auth: Authentication{Scheme: SchemeBearer}},
		secret: NewSecret("s3cr3t"),
	}
	first := c.Headers()
	first["Authorization"] = []string{"Bearer tampered"}
	first["X-Injected"] = []string{"1"}

	second := c.Headers()
	if second["Authorization"][0] != "Bearer s3cr3t" {
		t.Errorf("a mutation of one header map reached the next: %v", second["Authorization"])
	}
	if _, injected := second["X-Injected"]; injected {
		t.Error("a key added to one header map appeared in the next")
	}
}

// Two identities running concurrently must never present one another's
// credential. This is the contamination the -race build is watching for, and
// the assertion that the wire carried the right token is what proves it.
func TestConcurrentIdentitiesDoNotContaminate(t *testing.T) {
	var mismatches int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + strings.TrimPrefix(r.URL.Path, "/")
		if r.Header.Get("Authorization") != want {
			atomic.AddInt64(&mismatches, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client, red := clientFor(t, srv)

	var ids []Identity
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("id%d", i)
		t.Setenv("APPSEC_TEST_"+strings.ToUpper(name), name)
		ids = append(ids, Identity{
			ID: name,
			Auth: Authentication{
				Scheme:     SchemeBearer,
				Credential: CredentialSource{Env: "APPSEC_TEST_" + strings.ToUpper(name)},
			},
		})
	}
	set := Resolve(ids, srv.URL, client, red)

	var wg sync.WaitGroup
	for _, c := range set.Controls() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(c *Control) {
				defer wg.Done()
				_, _ = c.Do(context.Background(), http.MethodGet, srv.URL+"/"+c.ID(), nil)
			}(c)
		}
	}
	wg.Wait()

	if n := atomic.LoadInt64(&mismatches); n != 0 {
		t.Fatalf("%d requests carried the wrong identity's credential", n)
	}
}

// A credential must be registered with the redactor before any request can be
// made, or the very first exchange writes it to disk.
func TestResolveRegistersCredentialsWithTheRedactor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	const secret = "APPSEC_M1_SECRET_MUST_NEVER_PERSIST_7f91"
	t.Setenv("APPSEC_TEST_REG", secret)
	Resolve([]Identity{{
		ID:   "admin",
		Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_REG"}},
	}}, srv.URL, client, red)

	// The bare value, the on-the-wire form, and a body that echoes either.
	for _, probe := range []string{secret, "Bearer " + secret, `{"echo":"` + secret + `"}`} {
		if got := red.String(probe); strings.Contains(got, secret) {
			t.Errorf("redactor did not learn the credential: %q", got)
		}
	}
}

// A bespoke API-key header must be redacted by name, not only by value, so that
// a target echoing a prefix cannot leave part of it readable.
func TestResolveRegistersCustomCredentialHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_KEY", "abcdefghijklmnop")
	Resolve([]Identity{{
		ID: "svc",
		Auth: Authentication{
			Scheme: SchemeAPIKey, Header: "X-Custom-Auth",
			Credential: CredentialSource{Env: "APPSEC_TEST_KEY"},
		},
	}}, srv.URL, client, red)

	out := red.Header(map[string][]string{"X-Custom-Auth": {"abcdefghijklmnop"}})
	if out["X-Custom-Auth"][0] != redact.Placeholder {
		t.Errorf("custom credential header was not redacted: %v", out)
	}
}

// An identity whose credential is missing must be usable-false with a cause the
// ledger can record, never silently anonymous.
func TestUnresolvableIdentityIsBlockedNotAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	set := Resolve([]Identity{{
		ID:   "admin",
		Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_DEFINITELY_UNSET"}},
	}}, srv.URL, client, red)

	c := set.Primary()
	ok, cause, why := c.Usable()
	if ok {
		t.Fatal("an identity with no credential reported itself usable")
	}
	if cause != "missing_identity" {
		t.Errorf("cause = %q, want missing_identity", cause)
	}
	if !strings.Contains(why, "APPSEC_DEFINITELY_UNSET") {
		t.Errorf("the reason does not name the credential source: %q", why)
	}
	if st := c.Status(); st.Usable {
		t.Error("status reports an unusable identity as usable")
	}
}

func TestLivenessTransitions(t *testing.T) {
	var status atomic.Int64
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_LIVE", "live-token")
	set := Resolve([]Identity{{
		ID: "admin",
		Auth: Authentication{
			Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_LIVE"},
		},
		Live: Liveness{Path: "/api/me"},
	}}, srv.URL, client, red)
	c := set.Primary()

	if got := c.Status().Liveness; got != LivenessUnknown {
		t.Errorf("before any probe liveness = %s, want unknown", got)
	}

	if got := c.Probe(context.Background()); got != LivenessGood {
		t.Fatalf("probe against a 200 = %s, want good", got)
	}
	good := c.Status()
	if good.LastGood.IsZero() {
		t.Error("a good probe did not record when it happened")
	}
	if _, _, uncertain := good.UncertaintyWindow(); uncertain {
		t.Error("a live identity reported an uncertainty window")
	}

	// The credential expires.
	status.Store(401)
	if got := c.Probe(context.Background()); got != LivenessBad {
		t.Fatalf("probe against a 401 = %s, want bad", got)
	}
	bad := c.Status()
	if bad.FirstBad.IsZero() {
		t.Fatal("a bad probe did not record when the identity was first seen invalid")
	}
	from, to, uncertain := bad.UncertaintyWindow()
	if !uncertain {
		t.Fatal("an expired identity reported no uncertainty window")
	}
	if !from.Equal(good.LastGood) || !to.Equal(bad.FirstBad) {
		t.Errorf("window = (%v, %v], want (%v, %v]", from, to, good.LastGood, bad.FirstBad)
	}

	// A known-bad identity is refused rather than retried: continuing to send a
	// rejected credential produces denials that look like a protected app.
	ok, cause, _ := c.Usable()
	if ok {
		t.Error("a known-bad identity reported itself usable")
	}
	if cause != "authentication_failed" {
		t.Errorf("cause = %q, want authentication_failed", cause)
	}
}

// A transport failure says nothing about a credential. Treating it as expiry
// would block a whole run because the network stuttered.
func TestTransportFailureDoesNotDeclareTheIdentityDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_DOWN", "token")
	set := Resolve([]Identity{{
		ID: "admin",
		Auth: Authentication{
			Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_DOWN"},
		},
		Live: Liveness{Path: "/api/me"},
	}}, srv.URL, client, red)
	c := set.Primary()

	if got := c.Probe(context.Background()); got != LivenessGood {
		t.Fatalf("first probe = %s, want good", got)
	}
	srv.Close() // the target goes away

	if got := c.Probe(context.Background()); got == LivenessBad {
		t.Error("a transport failure was reported as an invalid credential")
	}
	if ok, _, _ := c.Usable(); !ok {
		t.Error("a transport failure made a previously good identity unusable")
	}
}

// An identity with no canary cannot be probed, and probing must not invent a
// verdict for one.
func TestUnmonitoredIdentityStaysUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_NOCANARY", "token")
	set := Resolve([]Identity{{
		ID:   "admin",
		Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_NOCANARY"}},
	}}, srv.URL, client, red)
	c := set.Primary()

	if got := c.Probe(context.Background()); got != LivenessUnknown {
		t.Errorf("probe without a canary = %s, want unknown", got)
	}
	st := c.Status()
	if st.Monitored {
		t.Error("an identity with no canary reported itself monitored")
	}
	if st.Probes != 0 {
		t.Errorf("probes = %d, want 0; nothing should have been sent", st.Probes)
	}
	if ok, _, _ := c.Usable(); !ok {
		t.Error("an unmonitored identity was refused; unknown is not bad")
	}
}

// A burst of suspicious responses must produce one canary probe, not one per
// goroutine.
func TestNoteSuspiciousProbesOnce(t *testing.T) {
	var probes int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/me" {
			atomic.AddInt64(&probes, 1)
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_BURST", "token")
	set := Resolve([]Identity{{
		ID: "admin",
		Auth: Authentication{
			Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_BURST"},
		},
		Live: Liveness{Path: "/api/me"},
	}}, srv.URL, client, red)
	c := set.Primary()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.NoteSuspicious(context.Background())
		}()
	}
	wg.Wait()

	if n := atomic.LoadInt64(&probes); n == 0 {
		t.Fatal("a suspicious authenticated response triggered no canary probe")
	} else if n > 5 {
		t.Errorf("%d canary probes for one burst; probes are not being coalesced", n)
	}
	if c.Status().Liveness != LivenessBad {
		t.Error("the canary observed a 401 but did not mark the identity bad")
	}
}

// Cancellation must stop a probe rather than hanging the run.
func TestProbeRespectsCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	t.Setenv("APPSEC_TEST_CANCEL", "token")
	set := Resolve([]Identity{{
		ID: "admin",
		Auth: Authentication{
			Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_CANCEL"},
		},
		Live: Liveness{Path: "/api/me"},
	}}, srv.URL, client, red)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := set.Primary().Probe(ctx); got == LivenessGood {
		t.Error("a cancelled probe reported the identity good")
	}
}

func TestSetAccessors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	client, red := clientFor(t, srv)

	var empty *Set
	if empty.Len() != 0 || empty.Primary() != nil || empty.Controls() != nil || empty.Statuses() != nil {
		t.Error("a nil Set must behave as an empty one; the no-identity path runs through it")
	}

	t.Setenv("APPSEC_TEST_A", "a-token")
	t.Setenv("APPSEC_TEST_B", "b-token")
	set := Resolve([]Identity{
		{ID: "first", Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_A"}}},
		{ID: "second", Auth: Authentication{Scheme: SchemeBearer, Credential: CredentialSource{Env: "APPSEC_TEST_B"}}},
	}, srv.URL, client, red)

	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	if set.Primary().ID() != "first" {
		t.Errorf("Primary = %s, want the first configured identity", set.Primary().ID())
	}
	if _, ok := set.ByID("second"); !ok {
		t.Error("ByID could not find a configured identity")
	}
	if _, ok := set.ByID("absent"); ok {
		t.Error("ByID invented an identity")
	}
	if len(set.Statuses()) != 2 {
		t.Error("Statuses did not report every identity")
	}
}
