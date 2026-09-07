// Package scope decides whether AppSec Framework is permitted to contact a given endpoint.
//
// Scope is an allowlist: nothing is reachable unless the configuration grants
// it. There is no deny-list to bypass, because allowlists fail closed and
// deny-lists fail open (ADR-0008).
//
// A scanner that sends a request to a host it was not authorized to test is an
// attack tool. This package is therefore the single authorization boundary for
// network access, and every decision it makes is explainable.
package scope

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// Decision is the result of evaluating a candidate endpoint.
type Decision struct {
	// Allowed reports whether the request may be sent.
	Allowed bool
	// Reason explains the decision in operator-facing language. It is always
	// populated, including on success, so a report can show why a host was
	// contacted.
	Reason string
}

// Entry is one allowlist grant. Host matching is exact or single-label wildcard;
// there is no regular-expression matching, because a scope that is hard to
// reason about is a scope that will be got wrong.
type Entry struct {
	// Scheme is "http" or "https". Empty means both.
	Scheme string
	// Host is a hostname, an IP literal, or a "*.example.com" wildcard.
	Host string
	// Ports is the set of permitted ports. Empty means the scheme default only.
	Ports []int
	// PathPrefix optionally confines the grant to a path subtree.
	PathPrefix string
}

// Policy is the effective scope for an assessment.
type Policy struct {
	entries []Entry
	// allowPrivate permits loopback, private and link-local addresses. Local
	// assessment is the normal case, so this is expected to be set — but it is
	// set deliberately rather than by accident.
	allowPrivate bool
	// mu guards recorded. CheckURL is called from every assessment goroutine, so
	// an unsynchronised map here is a concurrent-write crash, not a data-quality
	// problem.
	mu sync.Mutex
	// recorded holds out-of-scope hosts seen during the run. They are recorded
	// and never contacted.
	recorded map[string]struct{}
}

// deniedPrefixes are never permitted, even when private addresses are allowed.
//
// Cloud instance metadata is the reason this list exists: no legitimate
// assessment target is the metadata service, and reaching it turns AppSec Framework into
// an credential-exfiltration tool for whoever controls the target.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS/Azure/GCP IMDS
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS over IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud metadata
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local incl. IMDS range
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64: embeds IPv4, incl. IMDS
	netip.MustParsePrefix("64:ff9b:1::/48"),     // NAT64 local-use
	netip.MustParsePrefix("2002::/16"),          // 6to4: embeds IPv4
	netip.MustParsePrefix("2001::/32"),          // Teredo: embeds IPv4
	netip.MustParsePrefix("0.0.0.0/8"),          // "this host"; routes to loopback
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT
	netip.MustParsePrefix("224.0.0.0/4"),        // IPv4 multicast
	netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
}

// privatePrefixes require allowPrivate to be set.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), // unique local
}

// New builds a Policy. It returns an error if any entry is unusable, because a
// scope that silently drops a malformed entry is a scope that grants less than
// the operator believes — or, worse, one they stop reading.
func New(entries []Entry, allowPrivate bool) (*Policy, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("scope: at least one allowlist entry is required")
	}
	normalized := make([]Entry, 0, len(entries))
	for i, e := range entries {
		host, err := normalizeHost(e.Host)
		if err != nil {
			return nil, fmt.Errorf("scope: entry %d: %w", i, err)
		}
		if e.Scheme != "" && e.Scheme != "http" && e.Scheme != "https" {
			return nil, fmt.Errorf("scope: entry %d: unsupported scheme %q", i, e.Scheme)
		}
		for _, p := range e.Ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("scope: entry %d: port %d out of range", i, p)
			}
		}
		e.Host = host
		normalized = append(normalized, e)
	}
	return &Policy{entries: normalized, allowPrivate: allowPrivate, recorded: map[string]struct{}{}}, nil
}

// AllowsPrivate reports whether private and loopback addresses are permitted.
func (p *Policy) AllowsPrivate() bool { return p.allowPrivate }

// Entries returns the allowlist, for reporting the effective scope.
func (p *Policy) Entries() []Entry {
	out := make([]Entry, len(p.entries))
	copy(out, p.entries)
	return out
}

// CheckURL evaluates a candidate URL against the allowlist.
//
// This is the hostname-level gate and it runs BEFORE any name resolution, so
// that an out-of-scope host generates no DNS traffic. Resolving a hostname in
// order to reject it would itself be an out-of-band callback to
// attacker-controlled infrastructure, contradicting the promise that
// out-of-scope hosts are recorded and never contacted.
func (p *Policy) CheckURL(raw string) Decision {
	u, err := url.Parse(raw)
	if err != nil {
		return Decision{false, "url is not parseable"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Decision{false, fmt.Sprintf("scheme %q is not supported", u.Scheme)}
	}
	if u.User != nil {
		// Credentials in a URL would be sent to whatever host follows, and are a
		// common way to disguise a target. Refuse rather than strip.
		return Decision{false, "url contains embedded credentials"}
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return Decision{false, "host is not usable: " + err.Error()}
	}
	port, err := effectivePort(u)
	if err != nil {
		return Decision{false, err.Error()}
	}

	// Why an entry did not match is tracked, so a refusal can say what actually
	// failed. Reporting "host is not in scope" when the host matched and the
	// port did not sends an operator looking in the wrong place entirely — and
	// scope refusals are the messages people hit first, on their own machine,
	// against a target they can see is running.
	var hostMatched bool
	for _, e := range p.entries {
		if !hostMatches(e.Host, host) {
			continue
		}
		hostMatched = true
		if e.Scheme != "" && e.Scheme != u.Scheme {
			continue
		}
		if !portMatches(e, u.Scheme, port) {
			continue
		}
		if e.PathPrefix != "" && !strings.HasPrefix(pathOrRoot(u), e.PathPrefix) {
			continue
		}
		return Decision{true, fmt.Sprintf("matched scope entry %s", e.String())}
	}
	p.record(host)
	if hostMatched {
		return Decision{false, fmt.Sprintf(
			"%s://%s:%d is not in scope: the host is allowed but this scheme, port or path is "+
				"not. In scope: %s", u.Scheme, host, port, strings.Join(p.EntryStrings(), ", "))}
	}
	return Decision{false, fmt.Sprintf("host %q is not in scope. In scope: %s",
		host, strings.Join(p.EntryStrings(), ", "))}
}

// CheckAddr evaluates a resolved IP address.
//
// This is the second gate. It exists because a hostname that passes CheckURL can
// still resolve to an address we must never contact — that is the whole of DNS
// rebinding, and of a target pointing its own DNS at instance metadata.
func (p *Policy) CheckAddr(addr netip.Addr) Decision {
	if !addr.IsValid() {
		return Decision{false, "address is not valid"}
	}
	// Unwrap IPv4-mapped IPv6 first, so ::ffff:169.254.169.254 is evaluated as
	// the IPv4 address it actually reaches.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	// Zone identifiers (fe80::1%eth0) are stripped for comparison.
	addr = addr.WithZone("")

	for _, pre := range deniedPrefixes {
		if prefixContains(pre, addr) {
			return Decision{false, fmt.Sprintf("address %s is in denied range %s", addr, pre)}
		}
	}
	if !p.allowPrivate {
		for _, pre := range privatePrefixes {
			if prefixContains(pre, addr) {
				return Decision{false, fmt.Sprintf(
					"address %s is private (%s); set scope.allowPrivateAddresses to assess a local target", addr, pre)}
			}
		}
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return Decision{false, fmt.Sprintf("address %s is private or loopback", addr)}
		}
	}
	return Decision{true, fmt.Sprintf("address %s permitted", addr)}
}

// prefixContains compares only addresses of the same family, so that an IPv4
// prefix never accidentally matches an IPv6 address.
func prefixContains(pre netip.Prefix, addr netip.Addr) bool {
	if pre.Addr().Is4() != addr.Is4() {
		return false
	}
	return pre.Contains(addr)
}

// record notes an out-of-scope host so a report can list what was discovered but
// deliberately not contacted.
func (p *Policy) record(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recorded == nil {
		p.recorded = map[string]struct{}{}
	}
	p.recorded[host] = struct{}{}
}

// OutOfScopeHosts returns hosts that were seen and not contacted.
func (p *Policy) OutOfScopeHosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.recorded))
	for h := range p.recorded {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// String renders an entry for reporting.
func (e Entry) String() string {
	var b strings.Builder
	if e.Scheme != "" {
		b.WriteString(e.Scheme)
		b.WriteString("://")
	}
	b.WriteString(e.Host)
	if len(e.Ports) > 0 {
		b.WriteString(":")
		parts := make([]string, 0, len(e.Ports))
		for _, p := range e.Ports {
			parts = append(parts, strconv.Itoa(p))
		}
		b.WriteString(strings.Join(parts, ","))
	}
	if e.PathPrefix != "" {
		b.WriteString(e.PathPrefix)
	}
	return b.String()
}

// normalizeHost lowercases, strips a trailing dot, and converts an
// internationalised name to its ASCII form, so that visually distinct spellings
// of the same host cannot slip past an exact comparison.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", fmt.Errorf("host is empty")
	}
	// An IPv6 literal may arrive bracketed.
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "*.") {
		rest, err := idna.Lookup.ToASCII(h[2:])
		if err != nil {
			return "", fmt.Errorf("wildcard host %q is not a valid name: %w", h, err)
		}
		return "*." + rest, nil
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.WithZone("").String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("host %q is not a valid name: %w", h, err)
	}
	return ascii, nil
}

// hostMatches compares a normalized allowlist host against a normalized
// candidate. A wildcard matches exactly one additional label, so *.example.com
// matches api.example.com but not a.b.example.com and not example.com itself.
func hostMatches(entry, candidate string) bool {
	if entry == candidate {
		return true
	}
	if !strings.HasPrefix(entry, "*.") {
		return false
	}
	suffix := entry[2:]
	if !strings.HasSuffix(candidate, "."+suffix) {
		return false
	}
	label := strings.TrimSuffix(candidate, "."+suffix)
	return label != "" && !strings.Contains(label, ".")
}

// effectivePort resolves the port for a URL, defaulting by scheme.
func effectivePort(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %q is not valid", p)
		}
		return n, nil
	}
	if u.Scheme == "https" {
		return 443, nil
	}
	return 80, nil
}

// portMatches applies an entry's port set, defaulting to the scheme's default
// port only. An entry for https://api.example.com must not authorize
// http://api.example.com:9200, which could be an internal service on the same
// host.
func portMatches(e Entry, scheme string, port int) bool {
	if len(e.Ports) == 0 {
		if scheme == "https" {
			return port == 443
		}
		return port == 80
	}
	for _, p := range e.Ports {
		if p == port {
			return true
		}
	}
	return false
}

func pathOrRoot(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// SplitHostPort is a convenience wrapper used by the dialer, which receives an
// "addr" string rather than a URL.
func SplitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("port %q is not numeric", p)
	}
	return h, n, nil
}

// EntryStrings renders the effective scope for reporting.
func (p *Policy) EntryStrings() []string {
	out := make([]string, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e.String())
	}
	return out
}
