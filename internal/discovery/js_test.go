package discovery

import (
	"strings"
	"testing"
	"time"
)

func testLimits() Limits { return DefaultLimits() }

// What the extractor must find, and — far more importantly — what it must not.
func TestPathLiteralsExtractsRoutesAndNotEverythingElse(t *testing.T) {
	bundle := []byte(`
!function(e,t){"use strict";var n="/api/orders",r='/api/admin/users';
const a=` + "`/internal/export`" + `;
fetch("/api/orders?token=SECRET-abc123&page=2");
fetch("/api/reset#fragment");
var css="flex-container",msg="Something went wrong",key="userId";
var rel="users",dot=".hidden",proto="//cdn.example.test/lib.js";
var asset="/static/app.4f3a.js",style="/main.css",img="/logo.png",map="/app.js.map";
var abs="https://api.other.test/v1/things";
var slash="/",empty="";
`)

	paths, truncated := PathLiterals(bundle, testLimits())
	if truncated {
		t.Error("a small bundle was reported as truncated")
	}
	got := map[string]bool{}
	for _, p := range paths {
		got[p] = true
	}

	for _, want := range []string{"/api/orders", "/api/admin/users", "/internal/export", "/api/reset"} {
		if !got[want] {
			t.Errorf("route literal %q was not extracted: %v", want, paths)
		}
	}

	// A query string is dropped before anything is retained, so a token in a
	// URL literal cannot reach disk through this path.
	for _, p := range paths {
		if strings.Contains(p, "SECRET-abc123") || strings.Contains(p, "?") {
			t.Errorf("a query string survived extraction: %q", p)
		}
		if strings.Contains(p, "#") {
			t.Errorf("a fragment survived extraction: %q", p)
		}
	}

	for _, unwanted := range []string{
		"flex-container", "Something went wrong", "userId", "users", ".hidden",
		"//cdn.example.test/lib.js", "/static/app.4f3a.js", "/main.css", "/logo.png",
		"/app.js.map", "https://api.other.test/v1/things", "/", "",
	} {
		if got[unwanted] {
			t.Errorf("%q was extracted; it is not a route", unwanted)
		}
	}
}

// The extractor runs on a target-controlled file of arbitrary size. A regex with
// alternation and unbounded repetition is a denial of service handed to whoever
// is being audited, so there is none — and this is the test that would notice if
// one appeared.
func TestPathLiteralsCannotBeMadeToHang(t *testing.T) {
	hostile := map[string][]byte{
		"a five-megabyte single literal": []byte(`var x="/` + strings.Repeat("a", 5_000_000) + `";`),
		"a million quotes":               []byte(strings.Repeat(`"`, 1_000_000)),
		"nested escapes":                 []byte(`var x="` + strings.Repeat(`\\\"`, 200_000) + `";`),
		"unterminated literal":           []byte(`var x="/api/` + strings.Repeat("a", 1_000_000)),
		"alternating slashes":            []byte(strings.Repeat(`"/a/b/c/d/e"`, 200_000)),
		"the classic ReDoS shape":        []byte(`"` + strings.Repeat("/a", 100_000) + `!"`),
		"binary":                         make([]byte, 4<<20),
		"no quotes at all":               []byte(strings.Repeat("abcdefgh", 500_000)),
	}

	for name, in := range hostile {
		done := make(chan int, 1)
		go func() {
			p, _ := PathLiterals(in, testLimits())
			done <- len(p)
		}()
		select {
		case n := <-done:
			if n > testLimits().MaxCandidatesPerSource {
				t.Errorf("%s: produced %d candidates, above the per-source cap", name, n)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("%s: extraction did not finish; a bundle is a denial of service", name)
		}
	}
}

// A bundle full of distinct paths must be bounded and must say it was bounded.
func TestPathLiteralsBoundsCandidateExplosion(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50_000; i++ {
		b.WriteString(`"/route/`)
		b.WriteString(strings.Repeat("x", i%40+1))
		b.WriteString("/")
		b.WriteString(strings.Repeat("y", i%37+1))
		b.WriteString(`",`)
	}
	limits := testLimits()
	limits.MaxCandidatesPerSource = 25

	paths, truncated := PathLiterals([]byte(b.String()), limits)
	if len(paths) > 25 {
		t.Errorf("retained %d candidates, above the cap of 25", len(paths))
	}
	if !truncated {
		t.Fatal("a bundle that exhausted the candidate cap was reported as fully read")
	}
}

// An over-long literal is not silently cut into a path that was never there.
func TestPathLiteralsRefusesOverLongLiterals(t *testing.T) {
	limits := testLimits()
	limits.MaxPathLength = 32
	long := `"/` + strings.Repeat("a", 200) + `"`

	paths, _ := PathLiterals([]byte(long), limits)
	for _, p := range paths {
		if len(p) > 32 {
			t.Errorf("a path longer than the limit was retained: %d bytes", len(p))
		}
		if strings.HasPrefix(long[1:], p) && len(p) < 200 {
			t.Errorf("an over-long literal was truncated into a path that does not exist: %q", p)
		}
	}
}

// Extraction is a pure function of the bytes, so two runs agree.
func TestPathLiteralsIsDeterministic(t *testing.T) {
	bundle := []byte(`"/z","/a","/m","/b","/a"`)
	first, _ := PathLiterals(bundle, testLimits())
	for i := 0; i < 20; i++ {
		again, _ := PathLiterals(bundle, testLimits())
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d paths, first run produced %d", i, len(again), len(first))
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at %d: %q vs %q", i, j, again[j], first[j])
			}
		}
	}
	want := []string{"/a", "/b", "/m", "/z"}
	for i, w := range want {
		if first[i] != w {
			t.Errorf("output is not sorted: got %v, want %v", first, want)
		}
	}
}

// Only <script src> is read. Anchors, forms and iframes are deliberately not,
// because following one is the first line of a spider.
func TestScriptSourcesReadsScriptsAndNothingElse(t *testing.T) {
	html := []byte(`<!doctype html><html><head>
<script src="/static/app.js"></script>
<SCRIPT SRC='/static/vendor.js' defer></SCRIPT>
<script type="module" src=/static/mod.js></script>
<script src="https://cdn.example.test/x.js"></script>
<script>var inline="/api/inline";</script>
<script data-x="a>b" src="/static/quoted.js"></script>
<scriptfoo src="/not-a-script.js"></scriptfoo>
</head><body>
<a href="/should-not-be-followed">link</a>
<form action="/should-not-be-submitted"></form>
<iframe src="/should-not-be-entered"></iframe>
<img src="/should-not-be-fetched.png">
<link rel="stylesheet" href="/should-not-be-read.css">
</body></html>`)

	got := ScriptSources(html)
	want := map[string]bool{
		"/static/app.js": true, "/static/vendor.js": true, "/static/mod.js": true,
		"https://cdn.example.test/x.js": true, "/static/quoted.js": true,
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected script source %q", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("script source %q was not found", s)
	}

	joined := strings.Join(got, " ")
	for _, forbidden := range []string{
		"should-not-be-followed", "should-not-be-submitted", "should-not-be-entered",
		"should-not-be-fetched", "should-not-be-read", "not-a-script",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("%s was extracted; only <script src> may be", forbidden)
		}
	}
}

func TestScriptSourcesSurvivesBrokenMarkup(t *testing.T) {
	hostile := map[string][]byte{
		"empty":              {},
		"unterminated tag":   []byte(`<script src="/a.js"`),
		"unterminated quote": []byte(`<script src="/a.js></script>`),
		"a million tags":     []byte(strings.Repeat(`<script src="/a.js"></script>`, 100_000)),
		"nested angles":      []byte(`<script <script src="/a.js">`),
		"binary":             make([]byte, 1<<20),
		"just a bracket":     []byte("<"),
		"script with no src": []byte(`<script></script>`),
		"enormous attribute": []byte(`<script src="` + strings.Repeat("a", 2_000_000) + `">`),
		"control characters": []byte("<script src=\"/a\x00\x1b.js\">"),
	}
	for name, in := range hostile {
		done := make(chan int, 1)
		go func() { done <- len(ScriptSources(in)) }()
		select {
		case n := <-done:
			if n > maxScriptRefs {
				t.Errorf("%s: returned %d refs, above the cap", name, n)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: scanning did not finish", name)
		}
	}
}
