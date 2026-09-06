package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// clientFor builds the real scope-enforced client against a test server, so
// these tests exercise the same network path an assessment does. Discovery never
// constructs its own client, because the scope policy is the authorization
// boundary and a second client would be a second boundary.
func clientFor(t *testing.T, target string, extra ...scope.Entry) *httpx.Client {
	t.Helper()
	o, err := scope.ParseOrigin(target)
	if err != nil {
		t.Fatal(err)
	}
	entries := append([]scope.Entry{{Host: o.Host, Ports: []int{o.Port}}}, extra...)
	policy, err := scope.New(entries, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := httpx.New(httpx.Options{
		Policy:   policy,
		Redactor: redact.New(),
		Timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func run(t *testing.T, target string, client *httpx.Client, tweak func(*Options)) Result {
	t.Helper()
	opts := Options{
		Target: target,
		Client: client,
		Enable: AllSources(),
		Now:    func() time.Time { return time.Unix(1757000000, 0).UTC() },
	}
	if tweak != nil {
		tweak(&opts)
	}
	return Run(context.Background(), opts)
}

// paths renders a result as a set, for assertions.
func paths(res Result) map[string]bool {
	out := map[string]bool{}
	for _, c := range res.Candidates {
		if !c.OffOrigin {
			out[c.Path] = true
		}
	}
	return out
}

// sourcesFor returns the source kinds that named a path.
func sourcesFor(res Result, path string) map[model.SourceKind]bool {
	out := map[model.SourceKind]bool{}
	for _, c := range res.Candidates {
		if c.Path == path {
			for _, s := range c.Sources {
				out[s.Kind] = true
			}
		}
	}
	return out
}

// referenceApp is the paired fixture from the milestone's acceptance criteria:
// one route per discovery source, each absent from the specification except the
// declared one.
func referenceApp(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// A Link header naming a route the specification omits, plus a
		// pagination link that points at a documented route.
		w.Header().Add("Link", `</api/link-only>; rel="related"`)
		w.Header().Add("Link", `</api/declared>; rel="next", </api/link-only>; rel="alternate"`)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<script src="/static/app.js"></script>
</head><body><a href="/never-followed">home</a></body></html>`))
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /api/robots-only\nDisallow: /admin\n"))
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/js-only");fetch("/api/declared");var s="/api/orders/42";`))
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"http://ISSUER/",
"authorization_endpoint":"http://ISSUER/oauth/authorize",
"token_endpoint":"http://ISSUER/oauth/token",
"userinfo_endpoint":"/api/wellknown-only"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The milestone's headline claim: a route absent from the specification becomes
// visible, with the provenance that says how it was found.
func TestEachSourceMakesUndocumentedSurfaceVisible(t *testing.T) {
	srv := referenceApp(t)
	res := run(t, srv.URL, clientFor(t, srv.URL), nil)

	got := paths(res)
	want := map[string]model.SourceKind{
		"/api/link-only":      model.SourceLinkHeader,
		"/api/robots-only":    model.SourceRobotsTxt,
		"/api/js-only":        model.SourceJavaScript,
		"/api/wellknown-only": model.SourceWellKnown,
	}
	for path, kind := range want {
		if !got[path] {
			t.Errorf("%s was not discovered; candidates: %v", path, got)
			continue
		}
		if !sourcesFor(res, path)[kind] {
			t.Errorf("%s was discovered without provenance %s: %v", path, kind, sourcesFor(res, path))
		}
	}

	if res.Incomplete {
		t.Errorf("a small fixture application exhausted a budget: %v", res.Limitations)
	}

	// Every source must report that it was actually consulted.
	for _, a := range res.Attempts {
		if !a.Ran {
			t.Errorf("source %s was not consulted: %s", a.Source, a.Problem)
		}
	}
}

// One path named by two artefacts is one candidate carrying both, never two
// candidates that make the surface look twice as large.
func TestOnePathFoundTwiceIsOneCandidateWithTwoSources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Link", `</api/shared>; rel="related"`)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`fetch("/api/shared")`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Disallow: /api/shared\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := run(t, srv.URL, clientFor(t, srv.URL), nil)

	n := 0
	var found model.PathCandidate
	for _, c := range res.Candidates {
		if c.Path == "/api/shared" {
			n++
			found = c
		}
	}
	if n != 1 {
		t.Fatalf("/api/shared produced %d candidates, want exactly 1", n)
	}
	kinds := map[model.SourceKind]bool{}
	for _, s := range found.Sources {
		kinds[s.Kind] = true
	}
	for _, want := range []model.SourceKind{
		model.SourceLinkHeader, model.SourceRobotsTxt, model.SourceJavaScript,
	} {
		if !kinds[want] {
			t.Errorf("provenance %s was lost when the sources merged: %v", want, kinds)
		}
	}
}

// Nothing outside the target's own origin is ever contacted, whatever the
// application says. This is the SSRF test.
func TestOffOriginReferencesAreRecordedAndNeverFetched(t *testing.T) {
	var elsewhere struct {
		hits int
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.hits++
		_, _ = w.Write([]byte("should never be read"))
	}))
	defer other.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.Header().Add("Link", "<"+other.URL+"/link-target>; rel=\"related\"")
		w.Header().Add("Link", `<http://169.254.169.254/latest/meta-data/>; rel="related"`)
		w.Header().Set("Content-Type", "text/html")
		// An off-origin script, and one on the target.
		_, _ = w.Write([]byte(`<script src="` + other.URL + `/evil.js"></script>` +
			`<script src="//169.254.169.254/imds.js"></script>` +
			`<script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			`fetch("` + other.URL + `/api/external");` +
				`fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");` +
				`fetch("/api/local");`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Scope is deliberately widened to include the other server, to prove that
	// discovery's own origin rule is what stops it — not the scope policy. An
	// operator may authorize several hosts; a link on the target is still not
	// authorization to go exploring one of them.
	o, err := scope.ParseOrigin(other.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := clientFor(t, srv.URL, scope.Entry{Host: o.Host, Ports: []int{o.Port}})

	res := run(t, srv.URL, client, nil)

	if elsewhere.hits != 0 {
		t.Fatalf("discovery made %d request(s) to another origin", elsewhere.hits)
	}
	if !paths(res)["/api/local"] {
		t.Error("the same-origin script was not read, so this test proved nothing")
	}

	// The off-origin references are recorded — that is useful context — and the
	// metadata address is never among the things fetched.
	var refs []string
	for _, c := range res.Candidates {
		if c.OffOrigin {
			refs = append(refs, c.Reference)
		}
	}
	joined := strings.Join(refs, " ")
	if !strings.Contains(joined, "169.254.169.254") {
		t.Errorf("a cloud-metadata reference was not even recorded: %v", refs)
	}
	for _, c := range res.Candidates {
		if !c.OffOrigin && strings.Contains(c.Path, "169.254") {
			t.Error("a metadata URL was treated as target surface")
		}
	}
}

// A redirect is evidence, not permission. One same-origin hop is taken
// deliberately; an off-origin Location ends the walk.
func TestRedirectsCannotWidenTheAssessment(t *testing.T) {
	var otherHits int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		otherHits++
	}))
	defer other.Close()

	t.Run("a same-origin redirect is followed once", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.WriteHeader(404)
		})
		mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
		})
		mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`fetch("/api/after-redirect")`))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		res := run(t, srv.URL, clientFor(t, srv.URL), nil)
		if !paths(res)["/api/after-redirect"] {
			t.Errorf("a same-origin redirect to the real page was not followed: %v", paths(res))
		}
	})

	t.Run("an off-origin redirect is not followed", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		o, err := scope.ParseOrigin(other.URL)
		if err != nil {
			t.Fatal(err)
		}
		client := clientFor(t, srv.URL, scope.Entry{Host: o.Host, Ports: []int{o.Port}})
		run(t, srv.URL, client, nil)

		if otherHits != 0 {
			t.Fatalf("discovery followed a redirect to another origin (%d requests)", otherHits)
		}
	})
}

// A discovered URL is a likely place to find a token. Nothing but structure is
// kept, so there is nothing to leak.
func TestCredentialBearingURLsLoseTheirCredentials(t *testing.T) {
	const secret = "SECRET-b7f3a9e1-do-not-persist"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Link", `</api/reset?token=`+secret+`>; rel="related"`)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			`fetch("/api/session?sid=` + secret + `");` +
				`fetch("/api/signed?signature=` + secret + `&expires=1");` +
				`var u="https://api.example.test/x?apikey=` + secret + `";`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Disallow: /api/invite?code=" + secret + "\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := run(t, srv.URL, clientFor(t, srv.URL), nil)

	for _, c := range res.Candidates {
		if strings.Contains(c.Path, secret) || strings.Contains(c.Reference, secret) {
			t.Errorf("a credential survived into a candidate: path=%q reference=%q", c.Path, c.Reference)
		}
		for _, s := range c.Sources {
			if strings.Contains(s.Ref, secret) {
				t.Errorf("a credential survived into provenance: %q", s.Ref)
			}
		}
	}
	for _, l := range res.Limitations {
		if strings.Contains(l, secret) {
			t.Errorf("a credential survived into a limitation: %q", l)
		}
	}
	// The paths themselves are still discovered — the structure is the point.
	if !paths(res)["/api/session"] {
		t.Errorf("dropping the query also dropped the path: %v", paths(res))
	}
}

// Budgets must bound a hostile application, and exhaustion must never look like
// completion.
func TestBudgetExhaustionIsVisibleAndNeverLooksComplete(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString(`fetch("/api/route`)
		b.WriteString(strings.Repeat("x", i%50+1))
		b.WriteString(`/`)
		b.WriteString(strings.Repeat("y", i%31+1))
		b.WriteString(`");`)
	}
	huge := b.String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var scripts strings.Builder
		for i := 0; i < 200; i++ {
			scripts.WriteString(`<script src="/bundle`)
			scripts.WriteString(strings.Repeat("z", i%9+1))
			scripts.WriteString(`.js"></script>`)
		}
		_, _ = w.Write([]byte(scripts.String()))
	})
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, _ *http.Request) {})
	srv := httptest.NewServer(mux)
	// Every /bundle*.js serves the flood.
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {})
	defer srv.Close()

	t.Run("the candidate cap bounds a flood", func(t *testing.T) {
		flood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/":
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<script src="/a.js"></script><script src="/b.js"></script>`))
			default:
				_, _ = w.Write([]byte(huge))
			}
		}))
		defer flood.Close()

		res := run(t, flood.URL, clientFor(t, flood.URL), func(o *Options) {
			o.Limits = Limits{MaxRequests: 10, MaxScripts: 2, MaxBytes: 64 << 20,
				MaxCandidates: 20, MaxCandidatesPerSource: 15, MaxPathLength: 256}
		})

		if len(res.Candidates) > 20 {
			t.Errorf("retained %d candidates, above the cap of 20", len(res.Candidates))
		}
		if !res.Incomplete {
			t.Fatal("a run that hit the candidate cap reported itself as complete")
		}
		if len(res.Limitations) == 0 {
			t.Error("discovery stopped early and said nothing about it")
		}
	})

	t.Run("the request budget bounds a page of scripts", func(t *testing.T) {
		res := run(t, srv.URL, clientFor(t, srv.URL), func(o *Options) {
			o.Limits = Limits{MaxRequests: 4, MaxScripts: 50, MaxBytes: 1 << 20,
				MaxCandidates: 100, MaxCandidatesPerSource: 100, MaxPathLength: 256}
		})
		if res.Requests > 4 {
			t.Errorf("discovery made %d requests against a budget of 4", res.Requests)
		}
		if !res.Incomplete {
			t.Error("a run stopped by the request budget reported itself as complete")
		}
	})
}

// A failed source must not silently look like a source that found nothing.
func TestUnavailableSourcesAreReportedRatherThanAssumedEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res := run(t, srv.URL, clientFor(t, srv.URL), nil)

	if len(res.Candidates) != 0 {
		t.Errorf("an application serving nothing produced candidates: %v", res.Candidates)
	}
	byKind := map[model.SourceKind]Attempt{}
	for _, a := range res.Attempts {
		byKind[a.Source] = a
	}
	robots, ok := byKind[model.SourceRobotsTxt]
	if !ok {
		t.Fatal("robots.txt was not accounted for at all")
	}
	if robots.Problem == "" {
		t.Error("a robots.txt that returned 404 was recorded without explanation")
	}
	// A 404 establishes nothing. It must not read as "there is no hidden
	// surface".
	if strings.Contains(strings.ToLower(robots.Problem), "no undocumented") ||
		strings.Contains(strings.ToLower(robots.Problem), "complete") {
		t.Errorf("a 404 was described as evidence of absence: %q", robots.Problem)
	}
}

// Given the same responses, the same output. Ledger ordering must not depend on
// scheduling.
func TestDiscoveryIsDeterministic(t *testing.T) {
	srv := referenceApp(t)
	client := clientFor(t, srv.URL)

	first := run(t, srv.URL, client, nil)
	for i := 0; i < 10; i++ {
		again := run(t, srv.URL, client, nil)
		if len(again.Candidates) != len(first.Candidates) {
			t.Fatalf("run %d found %d candidates, first found %d",
				i, len(again.Candidates), len(first.Candidates))
		}
		for j := range again.Candidates {
			if again.Candidates[j].Path != first.Candidates[j].Path {
				t.Fatalf("run %d differs at %d: %q vs %q",
					i, j, again.Candidates[j].Path, first.Candidates[j].Path)
			}
			if len(again.Candidates[j].Sources) != len(first.Candidates[j].Sources) {
				t.Fatalf("run %d has different provenance for %s", i, first.Candidates[j].Path)
			}
		}
	}
}

// Discovery reads one page. Not two, not a graph.
func TestDiscoveryDoesNotCrawl(t *testing.T) {
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	requested := map[string]int{}
	record := func(p string) {
		<-mu
		requested[p]++
		mu <- struct{}{}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r.URL.Path)
		if r.URL.Path != "/" {
			w.Header().Set("Content-Type", "text/html")
			// Every other page also links onwards. If anything follows these,
			// the request count explodes and the assertion below catches it.
			_, _ = w.Write([]byte(`<a href="/page2"></a><a href="/page3"></a>` +
				`<script src="/deep.js"></script>`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<a href="/page1">1</a><a href="/page2">2</a>
<form action="/submit"></form><iframe src="/frame"></iframe>
<script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		record(r.URL.Path)
		// A script that names other scripts. Following one would be a graph.
		_, _ = w.Write([]byte(`import("/chunk1.js");require("/chunk2.js");` +
			`//# sourceMappingURL=/app.js.map` + "\n" + `fetch("/api/real")`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := run(t, srv.URL, clientFor(t, srv.URL), nil)

	<-mu
	defer func() { mu <- struct{}{} }()

	for _, forbidden := range []string{
		"/page1", "/page2", "/page3", "/submit", "/frame",
		"/chunk1.js", "/chunk2.js", "/app.js.map", "/deep.js",
	} {
		if requested[forbidden] > 0 {
			t.Errorf("discovery fetched %s; it must read one page and the scripts it names",
				forbidden)
		}
	}
	if requested["/app.js"] == 0 {
		t.Error("the root document's own script was not read, so this test proved nothing")
	}
	if !paths(res)["/api/real"] {
		t.Error("the script's path literal was not extracted")
	}
}
