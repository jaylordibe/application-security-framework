package discovery

import (
	"strings"
	"testing"
	"time"
)

// The Link grammar allows commas and semicolons inside quoted parameter values,
// so the naive comma split loses links and invents broken ones.
func TestParseLinkHeaderHandlesTheRealGrammar(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Link
	}{
		{
			name: "a single link",
			in:   `</api/next>; rel="next"`,
			want: []Link{{URI: "/api/next", Rel: "next"}},
		},
		{
			name: "several links in one field",
			in:   `</a>; rel="next", </b>; rel="prev", </c>; rel="last"`,
			want: []Link{{"/a", "next"}, {"/b", "prev"}, {"/c", "last"}},
		},
		{
			name: "a comma inside a quoted parameter does not split the member",
			in:   `</a>; rel="next"; title="one, two, three", </b>; rel="prev"`,
			want: []Link{{"/a", "next"}, {"/b", "prev"}},
		},
		{
			name: "a semicolon inside a quoted parameter is not a parameter break",
			in:   `</a>; title="x; rel=\"evil\""; rel="next"`,
			want: []Link{{"/a", "next"}},
		},
		{
			name: "an escaped quote inside a value",
			in:   `</a>; title="say \"hi\""; rel="next"`,
			want: []Link{{"/a", "next"}},
		},
		{
			name: "an unquoted rel",
			in:   `</a>; rel=next`,
			want: []Link{{"/a", "next"}},
		},
		{
			name: "the first rel wins, per RFC 8288",
			in:   `</a>; rel="first"; rel="second"`,
			want: []Link{{"/a", "first"}},
		},
		{
			name: "an absolute URI",
			in:   `<https://example.test/a>; rel="service-desc"`,
			want: []Link{{"https://example.test/a", "service-desc"}},
		},
		{
			name: "a link with no parameters at all",
			in:   `</a>`,
			want: []Link{{"/a", ""}},
		},
		{
			name: "a valueless parameter",
			in:   `</a>; anchor; rel="next"`,
			want: []Link{{"/a", "next"}},
		},
		{
			name: "whitespace everywhere",
			in:   "  </a> ;  rel = \"next\"  ,  </b> ; rel=\"prev\"  ",
			want: []Link{{"/a", "next"}, {"/b", "prev"}},
		},
	}

	for _, tc := range tests {
		got := ParseLinkHeader(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %d links %v, want %d", tc.name, len(got), got, len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: link %d = %+v, want %+v", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

// A target chooses this header. None of these may panic, hang or allocate
// without bound; returning nothing is always an acceptable answer.
func TestParseLinkHeaderSurvivesHostileInput(t *testing.T) {
	hostile := map[string]string{
		"empty":                    "",
		"only a comma":             ",",
		"only separators":          ",,;;,,",
		"unterminated angle":       "</a; rel=next",
		"unterminated quote":       `</a>; rel="next`,
		"no angle brackets":        `/a; rel=next`,
		"nested angles":            "<</a>>; rel=next",
		"a NUL byte":               "</a\x00b>; rel=next",
		"control characters":       "</a\x1b[2Jb>; rel=next",
		"a lone backslash":         `</a>; rel="\`,
		"unicode":                  "</é>; rel=next",
		"an enormous quoted value": `</a>; title="` + strings.Repeat("x", 200000) + `"; rel=next`,
		"deeply repeated members":  strings.Repeat("</a>; rel=next, ", 10000),
		"one huge uri":             "<" + strings.Repeat("/a", 500000) + ">",
		"broken member then good":  `<not-a-link; rel=x, </good>; rel="next"`,
	}

	for name, in := range hostile {
		done := make(chan []Link, 1)
		go func() { done <- ParseLinkHeader(in) }()
		select {
		case got := <-done:
			if len(got) > maxLinksPerHeader {
				t.Errorf("%s: returned %d links, above the cap of %d", name, len(got), maxLinksPerHeader)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: parsing did not finish, so a header is a denial of service", name)
		}
	}

	// The one case worth asserting positively: a broken member must not eat the
	// good one that follows it.
	got := ParseLinkHeader(`<not-a-link; rel=x, </good>; rel="next"`)
	found := false
	for _, l := range got {
		if l.URI == "/good" {
			found = true
		}
	}
	if !found {
		t.Errorf("a malformed member discarded the valid link that followed it: %v", got)
	}
}

// robots.txt names paths. It says nothing whatsoever about access control, and
// nothing in this package may treat it as though it did.
func TestParseRobotsExtractsPathsOnly(t *testing.T) {
	body := []byte(`# a comment
User-agent: *
Disallow: /admin
Disallow: /internal/export
Allow: /public/docs
Disallow: /search?q=      # query is part of the pattern
Disallow: /files/*.pdf
Disallow: /wild*
Disallow: /
Disallow:
Crawl-delay: 10
Sitemap: https://example.test/sitemap.xml
Host: example.test
garbage line with no colon
`)

	paths, truncated := ParseRobots(body, 100)
	if truncated {
		t.Error("a small robots.txt was reported as truncated")
	}

	want := map[string]bool{
		"/admin": true, "/internal/export": true, "/public/docs": true,
		"/search?q=": true, "/files/": true, "/wild": true,
	}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("path %q was not extracted", p)
	}

	// A Sitemap directive must never be read: fetching one is crawling.
	for _, p := range paths {
		if strings.Contains(p, "sitemap") {
			t.Errorf("a Sitemap directive became a path candidate: %q", p)
		}
	}
}

func TestParseRobotsSurvivesHostileInput(t *testing.T) {
	hostile := map[string][]byte{
		"empty":              {},
		"only newlines":      []byte("\n\n\n"),
		"no newline at all":  []byte(strings.Repeat("Disallow: /a", 1)),
		"binary":             {0x00, 0xff, 0xfe, 0x01, '\n', 'D', ':', '/'},
		"enormous one line":  []byte("Disallow: /" + strings.Repeat("a", 5_000_000)),
		"a million lines":    []byte(strings.Repeat("Disallow: /a\n", 200000)),
		"control characters": []byte("Disallow: /a\x1b[2Jb\n"),
	}
	for name, in := range hostile {
		done := make(chan bool, 1)
		go func() {
			ParseRobots(in, 50)
			done <- true
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: parsing did not finish", name)
		}
	}

	// A million lines must be bounded, not read.
	paths, truncated := ParseRobots([]byte(strings.Repeat("Disallow: /a\n", 200000)), 50)
	if len(paths) > 50 {
		t.Errorf("the candidate cap was exceeded: %d paths", len(paths))
	}
	_ = truncated
}

// Reaching the cap must be reported, because a truncated list that looks
// complete is the failure this whole feature exists to avoid.
func TestParseRobotsReportsTruncation(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("Disallow: /path")
		b.WriteString(strings.Repeat("x", i+1))
		b.WriteString("\n")
	}
	paths, truncated := ParseRobots([]byte(b.String()), 10)
	if !truncated {
		t.Fatal("hitting the candidate cap was not reported")
	}
	if len(paths) > 10 {
		t.Errorf("retained %d paths, above the cap", len(paths))
	}
}
