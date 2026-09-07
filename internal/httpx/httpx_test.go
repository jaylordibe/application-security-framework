package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// loopbackPolicy allows loopback because httptest binds there. The
// default-denies behaviour is asserted in the scope package, so permitting it
// here cannot hide a permissive default.
func loopbackPolicy(t *testing.T, ports ...int) *scope.Policy {
	t.Helper()
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	entries := []scope.Entry{
		{Host: "127.0.0.1", Ports: ports},
		{Host: "localhost", Ports: ports},
		{Host: "::1", Ports: ports},
	}
	p, err := scope.New(entries, true)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return p
}

func newClient(t *testing.T, p *scope.Policy, mutate func(*Options)) *Client {
	t.Helper()
	opts := Options{Policy: p, Redactor: redact.New(), Timeout: 5 * time.Second}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	var p int
	if _, err := fmt.Sscanf(portStr, "%d", &p); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return p
}

func TestNewRequiresPolicyAndRedactor(t *testing.T) {
	if _, err := New(Options{Redactor: redact.New()}); err == nil {
		t.Error("client built without a scope policy")
	}
	if _, err := New(Options{Policy: loopbackPolicy(t)}); err == nil {
		t.Error("client built without a redactor")
	}
}

// The URL gate must refuse before anything is dialled. The sentinel dial fails
// the test if it is ever called, which asserts that no packet was sent — a
// stronger claim than merely "an error was returned".
func TestOutOfScopeURLSendsNoPacket(t *testing.T) {
	var dialed atomic.Bool
	c := newClient(t, loopbackPolicy(t), func(o *Options) {
		o.Dial = func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("dial must not happen")
		}
		o.Resolver = func(context.Context, string) ([]netip.Addr, error) {
			t.Error("resolver called for an out-of-scope host; DNS must not be emitted")
			return nil, errors.New("no dns")
		}
	})
	_, err := c.Do(context.Background(), Request{Method: "GET", URL: "https://evil.example/x"})
	var oos *ErrOutOfScope
	if !errors.As(err, &oos) {
		t.Fatalf("error = %v, want ErrOutOfScope", err)
	}
	if dialed.Load() {
		t.Fatal("a connection was attempted to an out-of-scope host")
	}
}

// The regression test for DNS rebinding: the name passes the URL gate, then
// resolves to a forbidden address. Refusing requires evaluating the resolved
// address, which is why the check lives in the dialer.
func TestRebindingResolverIsRefused(t *testing.T) {
	var calls atomic.Int32
	var dialed atomic.Bool
	pol, err := scope.New([]scope.Entry{{Host: "rebind.test", Ports: []int{80}}}, true)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	c := newClient(t, pol, func(o *Options) {
		o.Resolver = func(context.Context, string) ([]netip.Addr, error) {
			// First lookup benign, second points at instance metadata.
			if calls.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		o.Dial = func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed.Store(true)
			if strings.HasPrefix(addr, "169.254.169.254") {
				t.Errorf("dialled forbidden address %s", addr)
			}
			return nil, errors.New("stub dial")
		}
	})

	// The second request must be refused on the resolved address.
	_, _ = c.Do(context.Background(), Request{Method: "GET", URL: "http://rebind.test/"})
	_, err = c.Do(context.Background(), Request{Method: "GET", URL: "http://rebind.test/"})
	var oos *ErrOutOfScope
	if !errors.As(err, &oos) {
		t.Fatalf("second request error = %v, want ErrOutOfScope", err)
	}
}

// If any resolved address is forbidden, the whole dial is refused. A rebinding
// target returns both a permitted and a forbidden address; picking the permitted
// one would let the attack succeed on a retry.
func TestAnyForbiddenAddressRefusesTheDial(t *testing.T) {
	pol, err := scope.New([]scope.Entry{{Host: "mixed.test", Ports: []int{80}}}, true)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	c := newClient(t, pol, func(o *Options) {
		o.Resolver = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("169.254.169.254"),
			}, nil
		}
		o.Dial = func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial attempted despite a forbidden address in the answer")
			return nil, errors.New("stub")
		}
	})
	_, err = c.Do(context.Background(), Request{Method: "GET", URL: "http://mixed.test/"})
	if err == nil {
		t.Fatal("mixed resolution accepted")
	}
}

// Redirects must never be followed. The second server's counter proves it.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/next", http.StatusFound)
	}))
	defer first.Close()

	c := newClient(t, loopbackPolicy(t, portOf(t, first.URL), portOf(t, second.URL)), nil)
	ex, err := c.Do(context.Background(), Request{Method: "GET", URL: first.URL + "/start"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if ex.Response == nil || ex.Response.Status != http.StatusFound {
		t.Fatalf("status = %v, want 302 captured as evidence", ex.Response)
	}
	if got := secondHits.Load(); got != 0 {
		t.Fatalf("redirect target was contacted %d times; redirects must not be followed", got)
	}
	if loc := RedirectLocation(first.URL+"/start", ex.Response); loc == "" {
		t.Error("redirect location not exposed for scope re-evaluation")
	}
}

// A hostile target can stream a body forever. Capture must stop at the limit
// and record that it did, rather than exhausting memory or implying the body was
// complete. Content-Length is never trusted: the read is bounded regardless.
func TestBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		chunk := strings.Repeat("A", 4096)
		for i := 0; i < 1024; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	const limit = 8192
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
		o.MaxBodyBytes = limit
	})
	ex, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if int64(len(ex.Response.Body)) > limit {
		t.Fatalf("body length %d exceeds limit %d", len(ex.Response.Body), limit)
	}
	if !ex.Response.BodyTruncated {
		t.Error("truncation not recorded; a report would imply the body was complete")
	}
}

func TestSensitiveHeadersAreRedactedInEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=super-secret-value-1234567890; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), nil)
	ex, err := c.Do(context.Background(), Request{
		Method: "GET",
		URL:    srv.URL + "/",
		Header: map[string][]string{"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.abcdefgh.signature"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := ex.Request.Header["Authorization"][0]; got != redact.Placeholder {
		t.Errorf("request Authorization = %q, want redacted", got)
	}
	for k, v := range ex.Response.Header {
		if strings.EqualFold(k, "Set-Cookie") && v[0] != redact.Placeholder {
			t.Errorf("response Set-Cookie = %q, want redacted", v[0])
		}
	}
}

// Query-string secrets must not survive into evidence, because Go's url.Error
// renders the full URL on any transport failure.
func TestQuerySecretsRedactedInCapturedURL(t *testing.T) {
	c := newClient(t, loopbackPolicy(t), nil)
	ex, _ := c.Do(context.Background(), Request{
		Method: "GET",
		URL:    "https://evil.example/x?api_key=abcdef0123456789&safe=yes",
	})
	if strings.Contains(ex.Request.URL, "abcdef0123456789") {
		t.Fatalf("captured URL leaked a secret: %s", ex.Request.URL)
	}
	if !strings.Contains(ex.Request.URL, "safe=yes") {
		t.Errorf("non-sensitive query parameter was lost: %s", ex.Request.URL)
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/"}); err == nil {
		t.Fatal("cancelled request returned no error")
	}
}

// Found during the product validation gate, running against a real NestJS
// application: "localhost" resolves to ::1 and 127.0.0.1, the server bound IPv4
// only, and the client dialled ::1, got connection-refused and aborted the whole
// assessment. curl succeeds against the same target because it falls back.
func TestDialFallsBackToTheNextAuthorizedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("reached"))
	}))
	defer srv.Close()

	_, port, err := scope.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	policy, err := scope.New([]scope.Entry{{Host: "dual.test", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatal(err)
	}

	// The name resolves to a loopback address nothing listens on, then to the
	// one the server is actually bound to.
	var dialled []string
	c, err := New(Options{
		Policy:   policy,
		Redactor: redact.New(),
		Timeout:  10 * time.Second,
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("127.0.0.1"),
			}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			if strings.HasPrefix(addr, "[::1]") {
				return nil, errors.New("connect: connection refused")
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ex, err := c.Do(context.Background(), Request{
		Method: "GET", URL: fmt.Sprintf("http://dual.test:%d/", port),
	})
	if err != nil {
		t.Fatalf("a target listening on only one of its addresses was unreachable: %v", err)
	}
	if ex.Response == nil || ex.Response.Status != 200 {
		t.Fatalf("response = %+v", ex.Response)
	}
	if len(dialled) != 2 {
		t.Errorf("dialled %v, want the refused address then the working one", dialled)
	}
}

// Falling back must not become a way to reach an address scope refused. A single
// denied address still refuses the whole request, before any dial.
func TestFallbackNeverReachesAnUnauthorizedAddress(t *testing.T) {
	policy, err := scope.New([]scope.Entry{{Host: "mixed.test", Ports: []int{80}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	var dialled []string
	c, err := New(Options{
		Policy:   policy,
		Redactor: redact.New(),
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("169.254.169.254"), // cloud metadata
			}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			return nil, errors.New("refused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Do(context.Background(), Request{Method: "GET", URL: "http://mixed.test/"}); err == nil {
		t.Fatal("a host resolving to cloud metadata was contacted")
	}
	if len(dialled) != 0 {
		t.Errorf("dialled %v; one denied address must refuse the request before any dial", dialled)
	}
}
