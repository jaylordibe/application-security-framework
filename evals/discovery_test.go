// M5 evaluation: surface beyond the specification.
//
// The bar M5 has to clear is not "a path was extracted from a bundle". It is
// that a route the specification omits stops being invisible and becomes a
// counted, explained, untested row — without acquiring a method it does not
// have, an expectation nobody stated, or a request nobody authorized.
package evals

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/adapter"
	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/discovery"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// m5Spec documents one route. The fixture application serves five more.
const m5Spec = `{
  "openapi": "3.0.3",
  "info": {"title": "m5", "version": "1"},
  "paths": {"/api/orders": {"get": {"operationId": "listOrders",
    "security": [{"bearer": []}]}}},
  "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}
}`

// m5Fixture is the paired application: one declared route, and one
// undocumented route reachable through each discovery source.
func m5Fixture(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Add("Link", `</api/link-only>; rel="related"`)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head>` +
			`<script src="/static/app.js"></script>` +
			`<script src="https://cdn.example.test/vendor.js"></script>` +
			`</head><body><a href="/never-crawled">x</a></body></html>`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /api/robots-only\nDisallow: /admin\n"))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(
			`fetch("/api/js-only");fetch("/api/orders");` +
				`fetch("/api/session?token=` + secret + `");`))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userinfo_endpoint":"/api/wellknown-only"}`))
	})
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// m5Run performs a complete assessment with discovery, returning the report.
func m5Run(t *testing.T, srv *httptest.Server, adapterDocs []adapter.Document) report.Document {
	t.Helper()
	o, err := scope.ParseOrigin(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := scope.New([]scope.Entry{{Host: o.Host, Ports: []int{o.Port}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: policy, Redactor: red, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	now := func() time.Time { return time.Unix(1757000000, 0).UTC() }
	parsed, err := openapi.Parse([]byte(m5Spec), srv.URL,
		openapi.SourceAt(model.SourceOpenAPIFile, "m5.json", now()))
	if err != nil {
		t.Fatal(err)
	}

	surface := engine.Surface{
		SpecDerived: true,
		SpecSource:  openapi.SourceAt(model.SourceOpenAPIFile, "m5.json", now()),
		Fidelity:    parsed.Fidelity,
		Operations:  parsed.Operations,
	}

	if len(adapterDocs) > 0 {
		merged := adapter.MergeInto(surface.Operations, adapterDocs,
			func() model.Source { return model.Source{ObservedAt: now()} })
		surface.Operations = merged.Operations
		surface.AdapterUnmatched = merged.UnmatchedOperations
		surface.Operations = append(surface.Operations, merged.DiscoveredOperations...)
		model.SortOperations(surface.Operations)
		for _, op := range merged.DiscoveredOperations {
			surface.AdapterDiscovered = append(surface.AdapterDiscovered, op.ID)
		}
		surface.Fidelity = openapi.Grade(surface.Operations)
	}

	found := discovery.Run(context.Background(), discovery.Options{
		Target: srv.URL, Client: client, Enable: discovery.AllSources(), Now: now,
	})
	m := discovery.Merge(surface.Operations, found.Candidates)
	surface.Discovered = m.Undocumented
	surface.DiscoveryCorroborated = m.Corroborated
	surface.DiscoveryOffOrigin = m.OffOrigin
	surface.DiscoveryAttempts = found.Attempts
	surface.DiscoveryIncomplete = found.Incomplete
	surface.DiscoveryLimitations = found.Limitations
	surface.DiscoveryRequests = found.Requests
	surface.DiscoveryBytes = found.Bytes

	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "m5-eval", Target: srv.URL, Profile: model.ProfileVerification,
		Surface: surface,
		Checks:  []engine.Check{check.AuthRequired{Client: client, BaselineProbes: 1, Now: now}},
		Now:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return report.Build(res, "test")
}

// The milestone's own claim, end to end: four undocumented routes go from
// invisible to counted, each with the provenance that says how.
func TestUndocumentedSurfaceBecomesCountedUntestedWork(t *testing.T) {
	const secret = "SECRET-eval-4d2a9f-not-for-disk"
	doc := m5Run(t, m5Fixture(t, secret), nil)

	rows := map[string]report.CoverageEntry{}
	for _, c := range doc.Coverage {
		if c.Dimension == engine.DimensionPath {
			rows[c.Subject] = c
		}
	}

	for _, want := range []string{
		"path /api/link-only", "path /api/robots-only",
		"path /api/js-only", "path /api/wellknown-only",
	} {
		row, ok := rows[want]
		if !ok {
			t.Errorf("%s produced no ledger row, so it is still invisible", want)
			continue
		}
		if row.Disposition != string(model.DispositionUntested) {
			t.Errorf("%s: disposition = %s, want untested", want, row.Disposition)
		}
		if row.Cause != string(model.CauseNotInSpecification) {
			t.Errorf("%s: cause = %s, want not_in_specification", want, row.Cause)
		}
	}

	// The headline count must move. That is the entire point: before this, a
	// route the specification omitted contributed nothing at all.
	if doc.Assurance.UntestedSurface < 4 {
		t.Errorf("untested = %d; four discovered paths did not reach the headline count",
			doc.Assurance.UntestedSurface)
	}

	// And it must not have become a finding. Discovery finds surface, not
	// vulnerabilities.
	for _, f := range doc.Findings {
		if strings.Contains(f.Title, "js-only") || strings.Contains(f.Title, "robots-only") {
			t.Errorf("a discovered path became a finding: %s", f.Title)
		}
	}
}

// A route an adapter knows and the specification omits is the one case where
// discovered surface is testable: the method comes from the routing table and
// the expectation from the same adapter that would have supplied it anyway.
func TestAdapterDiscoveredRoutesAreAssessedAndJavaScriptCorroboratesThem(t *testing.T) {
	srv := m5Fixture(t, "unused")

	docs := []adapter.Document{{
		Adapter: adapter.AdapterInfo{
			Name: "test-adapter", ExtractionMethod: adapter.MethodStaticLexical,
		},
		Facts: []adapter.Fact{{
			Kind:      adapter.KindAuthentication,
			Operation: adapter.OperationRef{Method: "GET", Path: "/api/js-only"},
			Value:     adapter.AuthenticationRequired,
			Evidence:  adapter.Evidence{File: "routes.php", Line: 12},
		}},
	}}

	doc := m5Run(t, srv, docs)

	// The adapter's route is now assessed surface, with its method intact.
	found := false
	for _, id := range doc.Surface.Discovery.AdapterOperations {
		if id == "GET /api/js-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the adapter's undocumented route was not adopted: %v",
			doc.Surface.Discovery.AdapterOperations)
	}

	// JavaScript names the same path. It must corroborate that one operation
	// rather than appearing as separate undocumented surface.
	for _, c := range doc.Surface.Discovery.PathCandidates {
		if c.Path == "/api/js-only" {
			t.Error("the same route was reported both as an adapter operation and as an " +
				"undocumented path candidate")
		}
	}
	corroborated := false
	for _, c := range doc.Surface.Discovery.Corroborated {
		if c.OperationID == "GET /api/js-only" {
			corroborated = true
			for _, s := range c.Sources {
				if s.Kind == string(model.SourceJavaScript) {
					return // the assertion this test exists for
				}
			}
		}
	}
	if !corroborated {
		t.Error("the JavaScript literal did not corroborate the adapter's route")
	} else {
		t.Error("the corroboration lost its JavaScript provenance")
	}
}

// A discovered URL is a likely place to find a token. Nothing that reaches the
// report or the run directory may carry one.
func TestDiscoveredSecretsNeverReachTheReport(t *testing.T) {
	const secret = "SECRET-eval-4d2a9f-not-for-disk"
	doc := m5Run(t, m5Fixture(t, secret), nil)

	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatal("a credential embedded in a discovered URL reached the report")
	}
	// The path is still discovered; only the credential is gone.
	found := false
	for _, c := range doc.Surface.Discovery.PathCandidates {
		if c.Path == "/api/session" {
			found = true
		}
	}
	if !found {
		t.Error("dropping the query also dropped the path, so the surface was lost")
	}
}

// The report must never imply the application was fully enumerated.
func TestNoCompletenessPercentageIsInvented(t *testing.T) {
	doc := m5Run(t, m5Fixture(t, "x"), nil)

	// The account may say that no completeness figure exists. What it may never
	// do is contain one, and a proportion needs either a "%" or a ratio word.
	blob, _ := json.Marshal(doc.Surface.Discovery)
	body := string(blob) + " " + doc.Assurance.SurfaceCompleteness
	for _, forbidden := range []string{"%", " percent", "proportion of", " of the total"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the discovery account contains %q, implying a denominator that does not "+
				"exist", forbidden)
		}
	}

	statement := doc.Surface.Discovery.Statement + " " + doc.Assurance.SurfaceCompleteness
	if !strings.Contains(statement, "not a measure") && !strings.Contains(statement, "never all of it") {
		t.Errorf("neither statement says what these counts are not:\n%s", statement)
	}
}

// Discovery consulted every source, so a source that failed can be told apart
// from one that found nothing.
func TestEverySourceIsAccountedFor(t *testing.T) {
	doc := m5Run(t, m5Fixture(t, "x"), nil)

	kinds := map[string]bool{}
	for _, s := range doc.Surface.Discovery.Sources {
		kinds[s.Kind] = true
		if !s.Consulted && s.Problem == "" {
			t.Errorf("source %s was not consulted and gave no reason", s.Kind)
		}
	}
	for _, want := range []string{"link-header", "robots-txt", "javascript", "well-known"} {
		if !kinds[want] {
			t.Errorf("source %s is missing from the account entirely", want)
		}
	}
}
