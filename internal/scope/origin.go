package scope

import (
	"fmt"
	"net/url"
	"strconv"
)

// Origin is a normalized (scheme, host, port) triple.
//
// It exists so that discovery can ask "is this the target's own origin?" — a
// different question from "does scope permit this?", because scope may
// deliberately authorize more than one host. Both questions must be answered by
// the same normalization, which is why this lives here rather than in the
// discovery package: a second, weaker origin parser is how a scope boundary gets
// bypassed by a trailing dot, a default port written out in full, an
// IPv4-in-IPv6 literal, or a Unicode homograph.
type Origin struct {
	// Scheme is "http" or "https", lowercased.
	Scheme string
	// Host is the IDNA-ASCII, lowercased, dot-stripped, bracket-stripped host.
	Host string
	// Port is the effective port, with the scheme default filled in.
	Port int
}

// ParseOrigin extracts the origin of a URL using the same normalization the
// allowlist uses.
//
// A URL carrying embedded credentials is refused rather than stripped, matching
// CheckURL: "https://target@evil.example/" has an origin of evil.example, and
// silently accepting it would let a discovered link name one host and reach
// another.
func ParseOrigin(raw string) (Origin, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, fmt.Errorf("url is not parseable")
	}
	return OriginOf(u)
}

// OriginOf extracts the origin of an already-parsed URL.
func OriginOf(u *url.URL) (Origin, error) {
	if u == nil {
		return Origin{}, fmt.Errorf("url is nil")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Origin{}, fmt.Errorf("scheme %q is not supported", u.Scheme)
	}
	if u.User != nil {
		return Origin{}, fmt.Errorf("url contains embedded credentials")
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return Origin{}, fmt.Errorf("host is not usable: %w", err)
	}
	port, err := effectivePort(u)
	if err != nil {
		return Origin{}, err
	}
	return Origin{Scheme: u.Scheme, Host: host, Port: port}, nil
}

// Equal reports whether two origins are the same.
//
// A wildcard never matches here. Scope allows "*.example.com" because an
// operator can authorize a subdomain deliberately; "the target's own origin" is
// a single host by definition, and treating a sibling subdomain as the same
// origin would let a link on the target send discovery somewhere the operator
// never named.
func (o Origin) Equal(other Origin) bool {
	return o.Scheme == other.Scheme && o.Host == other.Host && o.Port == other.Port
}

// String renders the origin, omitting the port when it is the scheme default.
func (o Origin) String() string {
	if (o.Scheme == "https" && o.Port == 443) || (o.Scheme == "http" && o.Port == 80) {
		return o.Scheme + "://" + o.Host
	}
	return o.Scheme + "://" + o.Host + ":" + strconv.Itoa(o.Port)
}
