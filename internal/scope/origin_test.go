package scope

import "testing"

// Origin comparison is a security boundary: discovery uses it to decide what it
// may fetch. Every row here is a way a target could try to look like itself.
func TestOriginEquality(t *testing.T) {
	target := "https://api.example.com/v1/"

	same := []string{
		"https://api.example.com/other",
		"https://API.EXAMPLE.COM/other",  // case
		"https://api.example.com./other", // trailing dot
		"https://api.example.com:443/x",  // default port written out
		"https://api.example.com",        // no path
	}

	for _, u := range same {
		got, err := ParseOrigin(u)
		if err != nil {
			t.Fatalf("ParseOrigin(%q): %v", u, err)
		}
		want, err := ParseOrigin(target)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(want) {
			t.Errorf("%q was not recognised as the target's own origin (%v vs %v)", u, got, want)
		}
	}

	different := map[string]string{
		"a sibling subdomain":      "https://evil.example.com/x",
		"a parent domain":          "https://example.com/x",
		"a prefix-matching name":   "https://api.example.com.evil.test/x",
		"a different scheme":       "http://api.example.com/x",
		"a non-default port":       "https://api.example.com:8443/x",
		"a homograph":              "https://аpi.example.com/x", // Cyrillic а
		"an unrelated host":        "https://cdn.jsdelivr.net/x",
		"cloud metadata":           "http://169.254.169.254/latest/meta-data/",
		"a credentialed lookalike": "https://api.example.com@evil.test/x",
	}
	want, err := ParseOrigin(target)
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range different {
		got, err := ParseOrigin(u)
		if err != nil {
			// Refusing to parse is a stronger answer than "not equal".
			continue
		}
		if got.Equal(want) {
			t.Errorf("%s: %q was treated as the target's own origin", name, u)
		}
	}
}

// A URL carrying credentials must be refused outright rather than stripped: the
// authority after the "@" is the host that would actually be contacted.
func TestParseOriginRefusesEmbeddedCredentials(t *testing.T) {
	if _, err := ParseOrigin("https://user:pass@example.com/"); err == nil {
		t.Fatal("a URL with embedded credentials produced an origin")
	}
}

func TestParseOriginRefusesNonHTTPSchemes(t *testing.T) {
	for _, u := range []string{
		"file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "ftp://example.com/",
	} {
		if _, err := ParseOrigin(u); err == nil {
			t.Errorf("ParseOrigin(%q) succeeded; only http and https are addressable", u)
		}
	}
}

// IPv6 literals normalize to a canonical form, so two spellings of one address
// are one origin.
func TestOriginNormalizesIPv6(t *testing.T) {
	a, err := ParseOrigin("http://[0:0:0:0:0:0:0:1]:8080/x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseOrigin("http://[::1]:8080/y")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Errorf("two spellings of ::1 produced different origins: %v vs %v", a, b)
	}
}

func TestOriginString(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/a":     "https://example.com",
		"https://example.com:443/a": "https://example.com",
		"http://example.com:80/a":   "http://example.com",
		"http://example.com:8080/a": "http://example.com:8080",
		"http://127.0.0.1:3000/a":   "http://127.0.0.1:3000",
	} {
		got, err := ParseOrigin(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got.String() != want {
			t.Errorf("ParseOrigin(%q).String() = %q, want %q", in, got.String(), want)
		}
	}
}

// Every shape a hostile target could use to make a different host look like the
// target's own origin. Discovery decides what it may fetch with Origin.Equal, so
// a single false positive here is a server-side request forgery.
//
// Both outcomes are acceptable: refusing to parse is stronger than "not equal",
// and either one keeps discovery on the target. What must never happen is Equal
// returning true.
func TestOriginEscapeAttemptsAllFail(t *testing.T) {
	target, err := ParseOrigin("http://127.0.0.1:8992/")
	if err != nil {
		t.Fatal(err)
	}
	attempts := map[string]string{
		"userinfo before the real authority": "http://127.0.0.1:8992@evil.test/",
		"the target in a fragment":           "http://evil.test#@127.0.0.1:8992/",
		"the target as a name prefix":        "http://127.0.0.1:8992.evil.test/",
		"IPv4-mapped IPv6":                   "http://[::ffff:127.0.0.1]:8992/",
		"hexadecimal octet":                  "http://0x7f.0.0.1:8992/",
		"integer address":                    "http://2130706433:8992/",
		"a neighbouring port":                "http://127.0.0.1:8993/",
		"a different scheme":                 "https://127.0.0.1:8992/",
		"the default port":                   "http://127.0.0.1/",
		"a backslash before the authority":   "http://127.0.0.1:8992\\@evil.test/",
	}
	for name, raw := range attempts {
		o, err := ParseOrigin(raw)
		if err != nil {
			continue // refused outright, which is stronger than "not equal"
		}
		if o.Equal(target) {
			t.Errorf("%s: %q was treated as the target's own origin (parsed as %s)",
				name, raw, o)
		}
	}
}
