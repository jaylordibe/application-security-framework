package scope

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func mustPolicy(t *testing.T, entries []Entry, allowPrivate bool) *Policy {
	t.Helper()
	p, err := New(entries, allowPrivate)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// The default must deny loopback. Tests that need loopback opt in explicitly;
// without this test, a permissive default could ship because every other test
// demanded it.
func TestDefaultDeniesLoopback(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "localhost", Ports: []int{3000}}}, false)
	if d := p.CheckAddr(netip.MustParseAddr("127.0.0.1")); d.Allowed {
		t.Fatalf("loopback allowed by default: %s", d.Reason)
	}
	if d := p.CheckAddr(netip.MustParseAddr("::1")); d.Allowed {
		t.Fatalf("IPv6 loopback allowed by default: %s", d.Reason)
	}
}

func TestAllowPrivatePermitsLoopback(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "localhost", Ports: []int{3000}}}, true)
	if d := p.CheckAddr(netip.MustParseAddr("127.0.0.1")); !d.Allowed {
		t.Fatalf("loopback denied with allowPrivate: %s", d.Reason)
	}
}

// Metadata must stay denied even when the operator allows private addresses,
// which is the normal configuration for local assessment.
func TestMetadataDeniedEvenWithPrivateAllowed(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "example.test"}}, true)
	for _, addr := range []string{
		"169.254.169.254", // AWS/Azure/GCP
		"100.100.100.200", // Alibaba
		"192.0.0.192",     // Oracle
		"fd00:ec2::254",   // AWS over IPv6
	} {
		if d := p.CheckAddr(netip.MustParseAddr(addr)); d.Allowed {
			t.Errorf("metadata address %s allowed: %s", addr, d.Reason)
		}
	}
}

// An IPv4-mapped IPv6 address reaches the IPv4 address, so it must be evaluated
// as one.
func TestIPv4MappedIPv6IsUnmapped(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "example.test"}}, true)
	if d := p.CheckAddr(netip.MustParseAddr("::ffff:169.254.169.254")); d.Allowed {
		t.Fatalf("IPv4-mapped metadata address allowed: %s", d.Reason)
	}
}

// NAT64, 6to4 and Teredo all embed IPv4 addresses and can therefore reach
// metadata.
func TestTransitionRangesDenied(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "example.test"}}, true)
	for _, addr := range []string{
		"64:ff9b::a9fe:a9fe", // NAT64-embedded 169.254.169.254
		"2002:a9fe:a9fe::1",  // 6to4
		"2001:0:1::1",        // Teredo
	} {
		if d := p.CheckAddr(netip.MustParseAddr(addr)); d.Allowed {
			t.Errorf("transition address %s allowed: %s", addr, d.Reason)
		}
	}
}

// 0.0.0.0 routes to loopback on Linux and must not be treated as public.
func TestUnspecifiedAddressDenied(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "example.test"}}, false)
	for _, addr := range []string{"0.0.0.0", "::"} {
		if d := p.CheckAddr(netip.MustParseAddr(addr)); d.Allowed {
			t.Errorf("unspecified address %s allowed: %s", addr, d.Reason)
		}
	}
}

func TestHostAllowlistIsExact(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com"}}, false)
	cases := map[string]bool{
		"https://api.example.com/x":          true,
		"https://api.example.com./x":         true, // trailing dot normalizes
		"https://API.EXAMPLE.COM/x":          true, // case normalizes
		"https://evil.com/x":                 false,
		"https://api.example.com.evil.com/x": false, // suffix confusion
		"https://sub.api.example.com/x":      false,
	}
	for raw, want := range cases {
		if got := p.CheckURL(raw).Allowed; got != want {
			t.Errorf("CheckURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestWildcardMatchesExactlyOneLabel(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "*.example.com"}}, false)
	cases := map[string]bool{
		"https://api.example.com/":    true,
		"https://a.b.example.com/":    false, // two labels
		"https://example.com/":        false, // the apex is not covered
		"https://api.example.com.co/": false,
	}
	for raw, want := range cases {
		if got := p.CheckURL(raw).Allowed; got != want {
			t.Errorf("CheckURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

// An entry for https://host must not authorize a different port on that host,
// which could be an internal service.
func TestPortIsPartOfScope(t *testing.T) {
	p := mustPolicy(t, []Entry{{Scheme: "https", Host: "api.example.com"}}, false)
	if p.CheckURL("https://api.example.com:9200/").Allowed {
		t.Error("non-default port allowed by a default-port entry")
	}
	if !p.CheckURL("https://api.example.com/").Allowed {
		t.Error("default https port denied")
	}
	if p.CheckURL("http://api.example.com/").Allowed {
		t.Error("http allowed by an https-only entry")
	}
}

func TestExplicitPortsAreHonoured(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "localhost", Ports: []int{3000, 5173}}}, true)
	if !p.CheckURL("http://localhost:3000/").Allowed {
		t.Error("configured port 3000 denied")
	}
	if p.CheckURL("http://localhost:8080/").Allowed {
		t.Error("unconfigured port 8080 allowed")
	}
}

func TestPathPrefixConfinesGrant(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com", PathPrefix: "/v2/"}}, false)
	if !p.CheckURL("https://api.example.com/v2/users").Allowed {
		t.Error("in-prefix path denied")
	}
	if p.CheckURL("https://api.example.com/admin").Allowed {
		t.Error("out-of-prefix path allowed")
	}
}

// Credentials embedded in a URL would be sent to whatever host follows and are a
// common way to disguise a target.
func TestEmbeddedCredentialsRefused(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com"}}, false)
	if p.CheckURL("https://user:pass@api.example.com/").Allowed {
		t.Error("url with embedded credentials allowed")
	}
}

func TestNonHTTPSchemesRefused(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com"}}, false)
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://api.example.com/",
		"ftp://api.example.com/",
	} {
		if p.CheckURL(raw).Allowed {
			t.Errorf("scheme allowed for %q", raw)
		}
	}
}

func TestOutOfScopeHostsAreRecordedNotContacted(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com"}}, false)
	p.CheckURL("https://tracker.evil.com/beacon")
	hosts := p.OutOfScopeHosts()
	if len(hosts) != 1 || hosts[0] != "tracker.evil.com" {
		t.Fatalf("out-of-scope hosts = %v, want [tracker.evil.com]", hosts)
	}
}

func TestNewRejectsEmptyAllowlist(t *testing.T) {
	if _, err := New(nil, false); err == nil {
		t.Fatal("empty allowlist accepted; scope must fail closed")
	}
}

func TestNewRejectsMalformedEntries(t *testing.T) {
	if _, err := New([]Entry{{Host: ""}}, false); err == nil {
		t.Error("empty host accepted")
	}
	if _, err := New([]Entry{{Host: "x.com", Ports: []int{0}}}, false); err == nil {
		t.Error("port 0 accepted")
	}
	if _, err := New([]Entry{{Host: "x.com", Scheme: "gopher"}}, false); err == nil {
		t.Error("unsupported scheme accepted")
	}
}

// CheckURL is called from every assessment goroutine, so an unsynchronised
// recorded-hosts map is a concurrent-write crash rather than a data-quality
// problem. Run with -race.
func TestConcurrentCheckURLIsSafe(t *testing.T) {
	p := mustPolicy(t, []Entry{{Host: "api.example.com"}}, false)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p.CheckURL(fmt.Sprintf("https://out-%d-%d.example.net/", n, j))
				p.CheckURL("https://api.example.com/ok")
				p.CheckAddr(netip.MustParseAddr("93.184.216.34"))
			}
		}(i)
	}
	wg.Wait()
	if got := len(p.OutOfScopeHosts()); got != 16*200 {
		t.Errorf("recorded %d out-of-scope hosts, want %d", got, 16*200)
	}
}
