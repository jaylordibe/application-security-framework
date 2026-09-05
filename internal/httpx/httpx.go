// Package httpx is the only way Assay reaches the network.
//
// It enforces the scope policy at two independent points, because neither is
// sufficient alone:
//
//  1. Before every request, on the URL. This runs before name resolution, so an
//     out-of-scope host generates no DNS traffic.
//  2. At dial time, on every resolved IP address, connecting only to an address
//     that was checked.
//
// The second gate is what closes the DNS-rebinding window: checking a hostname
// and then handing it to the standard dialer lets the name be resolved again,
// and the address connected to need not be the address that was checked.
//
// Three defaults that would silently defeat those gates are overridden:
//
//   - Proxy is nil. http.Transport defaults to ProxyFromEnvironment, and when
//     HTTP_PROXY is set the dialer is handed the proxy's address while the real
//     target travels inside CONNECT — so IP checking never happens at all. CI
//     runners frequently set these variables.
//   - Keep-alives are disabled. Transport reuses pooled connections without
//     calling the dialer, which would make "scope is checked per request" false
//     for every request after the first.
//   - FallbackDelay is negative, disabling Happy Eyeballs. Dual-stack racing can
//     connect to an address other than the one evaluated.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// ErrBodyTooLarge is returned when a response body exceeds the capture limit.
var ErrBodyTooLarge = errors.New("httpx: response body exceeded limit")

// ErrOutOfScope is returned when the scope policy refuses a request.
type ErrOutOfScope struct {
	Target string
	Reason string
}

func (e *ErrOutOfScope) Error() string {
	return fmt.Sprintf("httpx: out of scope: %s: %s", e.Target, e.Reason)
}

// Resolver looks up the addresses for a host. It is injectable so that scope
// behaviour — including DNS rebinding — can be tested without real DNS.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DialFunc opens a connection to a literal address. It is injectable so that a
// test can assert that no packet was sent.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Options configures a Client.
type Options struct {
	Policy   *scope.Policy
	Redactor *redact.Redactor
	// Timeout bounds a single request, including body capture.
	Timeout time.Duration
	// MaxBodyBytes bounds how much of a response body is read. A hostile target
	// can otherwise stream forever, or lie in Content-Length.
	MaxBodyBytes int64
	// MaxResponseHeaderBytes bounds response headers.
	MaxResponseHeaderBytes int64
	// UserAgent identifies Assay. Being identifiable is deliberate: an
	// assessment tool that disguises itself is harder to authorize and harder to
	// stop.
	UserAgent string
	// Resolver and Dial default to the standard library when nil.
	Resolver Resolver
	Dial     DialFunc
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
	// RequestsPerSecond paces outbound requests. Zero means unpaced.
	//
	// Pacing belongs here rather than in the assessment loop: a single check
	// issues several requests, so limiting once per check would exceed the
	// configured rate by that factor. Getting rate limited matters because every
	// subsequent response then classifies as a denial, which reads as a clean
	// report.
	RequestsPerSecond float64
}

// Client performs scope-enforced HTTP requests and captures redacted evidence.
type Client struct {
	opts     Options
	policy   *scope.Policy
	red      *redact.Redactor
	resolver Resolver
	dial     DialFunc
	hc       *http.Client
	now      func() time.Time
	limiter  *limiter
}

// Defaults applied when Options leaves a field zero.
const (
	DefaultTimeout                = 20 * time.Second
	DefaultMaxBodyBytes           = 1 << 20 // 1 MiB
	DefaultMaxResponseHeaderBytes = 1 << 18 // 256 KiB
	DefaultUserAgent              = "Assay (+https://github.com/jaylordibe/application-security-framework)"
)

// New builds a Client. It returns an error rather than falling back to an
// unrestricted client if no policy is supplied, because a client without a
// policy is exactly the failure this package exists to prevent.
func New(opts Options) (*Client, error) {
	if opts.Policy == nil {
		return nil, errors.New("httpx: a scope policy is required")
	}
	if opts.Redactor == nil {
		return nil, errors.New("httpx: a redactor is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.MaxResponseHeaderBytes <= 0 {
		opts.MaxResponseHeaderBytes = DefaultMaxResponseHeaderBytes
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	c := &Client{
		opts:    opts,
		policy:  opts.Policy,
		red:     opts.Redactor,
		now:     opts.Now,
		limiter: newLimiter(opts.RequestsPerSecond),
	}
	c.resolver = opts.Resolver
	if c.resolver == nil {
		c.resolver = defaultResolver
	}
	c.dial = opts.Dial
	if c.dial == nil {
		c.dial = defaultDial
	}

	transport := &http.Transport{
		// Never inherit proxy settings from the environment: a proxy would be
		// handed the connection and our IP checks would never run.
		Proxy: nil,
		// One dial per request keeps the URL gate and the address gate 1:1.
		DisableKeepAlives:      true,
		DialContext:            c.dialContext,
		MaxResponseHeaderBytes: opts.MaxResponseHeaderBytes,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  opts.Timeout,
		ExpectContinueTimeout:  1 * time.Second,
		ForceAttemptHTTP2:      false,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}

	c.hc = &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		// Redirects are never followed automatically. A redirect is evidence,
		// and its target must pass scope evaluation as a fresh request.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

// defaultResolver resolves a host to netip addresses using the standard
// resolver.
func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// defaultDial opens a TCP connection with Happy Eyeballs disabled, so the
// address dialled is the address that was evaluated.
func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		// Negative disables the dual-stack fallback race.
		FallbackDelay: -1,
	}
	return d.DialContext(ctx, network, addr)
}

// dialContext resolves, evaluates and connects.
//
// The address handed to us is the URL's host and port. We resolve it ourselves,
// require every resolved address to be permitted, and then connect to a literal
// IP so that no second resolution can occur. Requiring *all* addresses to pass —
// rather than picking the first that does — is deliberate: a rebinding target
// returns both a permitted and a forbidden address, and choosing the permitted
// one would let the attack proceed on a retry.
func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := scope.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("httpx: cannot parse dial address: %w", err)
	}

	var addrs []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{literal}
	} else {
		resolved, rerr := c.resolver(ctx, host)
		if rerr != nil {
			return nil, fmt.Errorf("httpx: cannot resolve host: %w", rerr)
		}
		if len(resolved) == 0 {
			return nil, fmt.Errorf("httpx: host resolved to no addresses")
		}
		addrs = resolved
	}

	for _, a := range addrs {
		if d := c.policy.CheckAddr(a); !d.Allowed {
			return nil, &ErrOutOfScope{Target: a.String(), Reason: d.Reason}
		}
	}

	chosen := addrs[0].WithZone("")
	if chosen.Is4In6() {
		chosen = chosen.Unmap()
	}
	dialAddr := net.JoinHostPort(chosen.String(), fmt.Sprintf("%d", port))

	conn, err := c.dial(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}

	// Verify that the connection actually landed on the evaluated address. An
	// address we cannot verify is refused rather than accepted, so the check
	// fails closed.
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = conn.Close()
		return nil, &ErrOutOfScope{
			Target: dialAddr,
			Reason: "the connection's remote address could not be verified",
		}
	}
	got, _ := netip.AddrFromSlice(ra.IP)
	got = got.Unmap().WithZone("")
	if !got.IsValid() || got != chosen {
		_ = conn.Close()
		return nil, &ErrOutOfScope{
			Target: got.String(),
			Reason: "connection landed on an address that was not evaluated",
		}
	}
	return conn, nil
}

// limiter paces outbound requests.
type limiter struct {
	ticker *time.Ticker
	done   chan struct{}
}

// newLimiter returns a limiter, or nil when pacing is disabled.
func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / rps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &limiter{ticker: time.NewTicker(interval), done: make(chan struct{})}
}

func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return nil
	case <-l.ticker.C:
		return nil
	}
}

// Close stops pacing and releases anything waiting on it. Stopping a ticker does
// not close its channel, so a waiter would otherwise block forever.
func (c *Client) Close() {
	if c.limiter == nil {
		return
	}
	c.limiter.ticker.Stop()
	select {
	case <-c.limiter.done:
	default:
		close(c.limiter.done)
	}
}

// Request describes an exchange to perform.
type Request struct {
	Method string
	URL    string
	Header map[string][]string
	Body   []byte
}

// Do performs a request and returns a redacted exchange.
//
// A transport failure is returned inside the exchange, not only as an error, so
// that a caller can record what was attempted. The error is also returned so a
// caller cannot mistake a failure for a response.
func (c *Client) Do(ctx context.Context, r Request) (model.Exchange, error) {
	captured := model.CapturedRequest{
		Method: strings.ToUpper(r.Method),
		URL:    c.red.URL(r.URL),
		Header: c.red.Header(r.Header),
	}
	if len(r.Body) > 0 {
		captured.Body = c.red.Bytes(r.Body)
	}

	// Pace before doing anything else, so the limit covers every request the
	// assessment makes rather than every check.
	if err := c.limiter.wait(ctx); err != nil {
		return model.Exchange{Request: captured, Err: c.red.Error(err)}, err
	}

	// Gate one: the URL, before any resolution.
	if d := c.policy.CheckURL(r.URL); !d.Allowed {
		err := &ErrOutOfScope{Target: c.red.URL(r.URL), Reason: d.Reason}
		return model.Exchange{Request: captured, Err: c.red.Error(err)}, err
	}

	req, err := http.NewRequestWithContext(ctx, captured.Method, r.URL, bodyReader(r.Body))
	if err != nil {
		return model.Exchange{Request: captured, Err: c.red.Error(err)}, err
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}

	start := c.now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return model.Exchange{Request: captured, Err: c.red.Error(err)}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, truncated, readErr := readBounded(resp.Body, c.opts.MaxBodyBytes)
	if readErr != nil && !errors.Is(readErr, ErrBodyTooLarge) {
		ex := model.Exchange{Request: captured, Err: c.red.Error(readErr)}
		return ex, readErr
	}

	captureResp := &model.CapturedResponse{
		Status:        resp.StatusCode,
		Proto:         resp.Proto,
		Header:        c.red.Header(resp.Header),
		Body:          c.red.Bytes(body),
		BodyTruncated: truncated,
		Elapsed:       c.now().Sub(start),
	}
	return model.Exchange{Request: captured, Response: captureResp}, nil
}

// bodyReader avoids sending a non-nil reader for an empty body, which would set
// Content-Length: 0 on requests that should have no body at all.
func bodyReader(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return strings.NewReader(string(b))
}

// truncationTail is discarded from a truncated body.
//
// Redaction runs after capture, so a secret straddling the cut would survive as
// a prefix that no longer matches any pattern — a JWT sliced mid-signature is
// still fully readable base64. Dropping a tail from an already-truncated body
// costs nothing (the body is incomplete regardless) and closes that boundary.
const truncationTail = 4096

// readBounded reads at most limit bytes and reports whether more remained.
//
// It reads limit+1 bytes so that "exactly at the limit" is distinguishable from
// "truncated", and it never trusts Content-Length.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return buf, false, err
	}
	if int64(len(buf)) <= limit {
		return buf, false, nil
	}
	cut := limit
	if cut > truncationTail {
		cut -= truncationTail
	}
	return buf[:cut], true, nil
}

// RedirectLocation returns the redirect target of a response resolved against
// the request URL, or "" if the response is not a redirect.
//
// Callers must re-evaluate the returned URL against scope before following it;
// nothing here follows anything.
func RedirectLocation(requestURL string, resp *model.CapturedResponse) string {
	if resp == nil || resp.Status < 300 || resp.Status > 399 {
		return ""
	}
	loc := resp.HeaderValue("Location")
	if loc == "" {
		return ""
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}
