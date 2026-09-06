// M3 evaluation: framework adapters and the provenance-aware oracle.
//
// The bar M3 has to clear is not "an adapter produced JSON". It is that an
// adapter-derived fact changes what AppSec tests, that a wrong or missing
// adapter never makes a report look better, and that a static inference is
// never presented as though a request had proved something.
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
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// silentSpec documents an operation but says nothing about its security. This
// is the common real case — a specification that enumerates routes without
// expressing the framework's authorization — and it is where an adapter has
// something to add.
const silentSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "silent", "version": "1"},
  "paths": {"/api/orders": {"get": {"operationId": "listOrders"}}}
}`

// publicSpec explicitly declares the same operation public.
const publicSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "public", "version": "1"},
  "paths": {"/api/orders": {"get": {"operationId": "listOrders", "security": []}}}
}`

func adapterDoc(facts ...adapter.Fact) adapter.Document {
	return adapter.Document{
		ContractVersion: adapter.ContractVersion,
		Adapter: adapter.AdapterInfo{
			Name: "laravel", Version: "0.1.0", ExtractionMethod: adapter.MethodStaticLexical,
		},
		Facts: facts,
	}
}

func authRequiredFact() adapter.Fact {
	return adapter.Fact{
		Kind:      adapter.KindAuthentication,
		Operation: adapter.OperationRef{Method: "GET", Path: "/api/orders"},
		Value:     adapter.AuthenticationRequired,
		Evidence: adapter.Evidence{
			File: "routes/api.php", Line: 12, Detail: "inside a middleware group applying auth:api",
		},
	}
}

// runWithAdapter assesses a target whose specification is `spec`, optionally
// merging adapter documents first.
func runWithAdapter(t *testing.T, handler http.Handler, spec string, docs []adapter.Document) engine.Result {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: redact.New(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	t.Cleanup(client.Close)

	parsed, err := openapi.Parse([]byte(spec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}

	surface := engine.Surface{
		SpecDerived: true, Operations: parsed.Operations, Fidelity: parsed.Fidelity,
	}
	if len(docs) > 0 {
		merged := adapter.MergeInto(surface.Operations, docs, nil)
		surface.Operations = merged.Operations
		surface.AdapterMerges = merged.Merges
		surface.AdapterLimitations = merged.Limitations
		surface.AdapterUnmatched = merged.UnmatchedOperations
		surface.Fidelity = openapi.Grade(surface.Operations)
	}

	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "eval-m3", Target: srv.URL, Profile: model.ProfileVerification,
		Surface: surface,
		Checks: []engine.Check{check.AuthRequired{
			Client: client, BaselineProbes: 2,
		}},
		Concurrency: 2, RequestsPerSecond: 500,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res
}

// servesEveryone is an application with no authentication at all.
func servesEveryone() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`[{"id":1,"customer":"alice"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	})
	return mux
}

// ---------------------------------------------------------------------------
// THE POINT OF M3: an adapter fact changes what gets tested
// ---------------------------------------------------------------------------

// The specification documents the route and says nothing about its security, so
// there is no oracle and nothing to test. The adapter reads the framework's
// route file, finds the authentication middleware, and the operation becomes
// testable — at which point the runtime probe finds it is not enforced.
//
// This is the whole milestone in one test: the adapter supplies the expectation,
// the request supplies the evidence, and neither substitutes for the other.
func TestM3_AdapterFactMakesAnUntestableOperationTestable(t *testing.T) {
	const opID = "GET /api/orders"

	without := runWithAdapter(t, servesEveryone(), silentSpec, nil)
	row := operationRow(t, without, opID)
	if row.Disposition != model.DispositionUntested || row.Cause != model.CauseNoOracle {
		t.Fatalf("without an adapter: row = %s/%s, want untested/no_oracle",
			row.Disposition, row.Cause)
	}
	if len(without.Findings) != 0 {
		t.Fatalf("a finding was produced with no oracle at all: %+v", without.Findings)
	}

	with := runWithAdapter(t, servesEveryone(), silentSpec,
		[]adapter.Document{adapterDoc(authRequiredFact())})

	if len(with.Findings) != 1 {
		t.Fatalf("with an adapter: findings = %d, want 1. The adapter's expectation did not "+
			"reach the oracle; coverage: %+v", len(with.Findings), with.Coverage)
	}
	f := with.Findings[0]
	if f.CheckID != check.AuthRequiredID {
		t.Errorf("finding = %s, want the declared-auth check", f.CheckID)
	}
	// The expectation came from an inference, so the finding must stay
	// suspected: no authenticated control ran, and a static reading is not
	// evidence that a request would be refused.
	if f.State != model.StateSuspected {
		t.Errorf("state = %s, want suspected; the oracle here is a static inference", f.State)
	}
	if operationRow(t, with, opID).Disposition != model.DispositionExecuted {
		t.Error("the operation was still not executed")
	}
}

// ---------------------------------------------------------------------------
// CONFLICT: two of the application's own artefacts disagree
// ---------------------------------------------------------------------------

func TestM3_OpenAPIConflictBehaviour(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		fact        adapter.Fact
		wantAgree   adapter.Agreement
		wantTested  bool
		mustMention string
	}{
		{
			name: "agreement is recorded as corroboration",
			spec: `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
			  "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
			  "paths":{"/api/orders":{"get":{"operationId":"o","security":[{"bearer":[]}]}}}}`,
			fact:       authRequiredFact(),
			wantAgree:  adapter.AgreementCorroborated,
			wantTested: true,
		},
		{
			name:      "specification public, adapter protected",
			spec:      publicSpec,
			fact:      authRequiredFact(),
			wantAgree: adapter.AgreementConflict,
			// A conflicted operation has no trustworthy oracle, so it must not
			// be tested against either claim.
			wantTested:  false,
			mustMention: "disagree",
		},
		{
			name: "specification protected, adapter public",
			spec: `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
			  "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
			  "paths":{"/api/orders":{"get":{"operationId":"o","security":[{"bearer":[]}]}}}}`,
			fact: adapter.Fact{
				Kind:      adapter.KindAuthentication,
				Operation: adapter.OperationRef{Method: "GET", Path: "/api/orders"},
				Value:     adapter.AuthenticationPublic,
			},
			wantAgree:   adapter.AgreementConflict,
			wantTested:  false,
			mustMention: "disagree",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := runWithAdapter(t, servesEveryone(), tc.spec,
				[]adapter.Document{adapterDoc(tc.fact)})

			if len(res.Surface.AdapterMerges) != 1 {
				t.Fatalf("merges = %d, want 1", len(res.Surface.AdapterMerges))
			}
			m := res.Surface.AdapterMerges[0]
			if m.Agreement != tc.wantAgree {
				t.Fatalf("agreement = %s, want %s (%s)", m.Agreement, tc.wantAgree, m.Detail)
			}
			if tc.mustMention != "" && !strings.Contains(m.Detail, tc.mustMention) {
				t.Errorf("detail %q does not mention %q", m.Detail, tc.mustMention)
			}

			row := operationRow(t, res, "GET /api/orders")
			tested := row.Disposition == model.DispositionExecuted
			if tested != tc.wantTested {
				t.Errorf("executed = %v, want %v (row: %s/%s %s)",
					tested, tc.wantTested, row.Disposition, row.Cause, row.Detail)
			}

			// A conflict must be visible in the report, not only in the ledger.
			doc := report.Build(res, "test")
			if tc.wantAgree == adapter.AgreementConflict {
				if doc.Adapters.Conflicting != 1 || len(doc.Adapters.Conflicts) != 1 {
					t.Errorf("the conflict is not reported: %+v", doc.Adapters)
				}
				if !strings.Contains(doc.Adapters.Statement, "disagree") {
					t.Errorf("the adapter statement does not mention the disagreement: %q",
						doc.Adapters.Statement)
				}
			}
		})
	}
}

// An operation only the adapter knows about is recorded, and deliberately not
// attacked. Testing undocumented routes is a separate milestone.
func TestM3_AdapterOnlyOperationIsRecordedNotAttacked(t *testing.T) {
	res := runWithAdapter(t, servesEveryone(), silentSpec, []adapter.Document{adapterDoc(
		adapter.Fact{
			Kind:      adapter.KindAuthentication,
			Operation: adapter.OperationRef{Method: "GET", Path: "/api/internal/admin"},
			Value:     adapter.AuthenticationPublic,
		},
	)})

	for _, e := range res.Coverage {
		if strings.Contains(e.Subject, "/api/internal/admin") {
			t.Fatalf("an adapter-only route entered the attack surface: %+v", e)
		}
	}
	doc := report.Build(res, "test")
	if len(doc.Adapters.UnmatchedOperations) != 1 {
		t.Fatalf("the adapter-only route was not recorded: %+v", doc.Adapters)
	}
}

// ---------------------------------------------------------------------------
// FAILURE MUST NOT MAKE A REPORT CLEANER
// ---------------------------------------------------------------------------

// A failed adapter leaves the oracle exactly as it was. It must not silently
// turn a testable operation into an untested one and it must say what was lost.
func TestM3_AdapterFailureDoesNotImproveTheReport(t *testing.T) {
	baseline := runWithAdapter(t, servesEveryone(), silentSpec, nil)

	failed := baseline
	failed.Surface.AdapterFailures = []string{
		"adapter laravel produced nothing usable (exit status 1), so no framework-derived " +
			"expectation was added for any operation. This does not mean the application has no " +
			"controls; it means none were read",
	}

	doc := report.Build(failed, "test")
	if doc.Adapters.Added != 0 || doc.Adapters.Corroborated != 0 {
		t.Error("a failed adapter contributed facts")
	}
	if len(doc.Adapters.Failures) != 1 {
		t.Fatalf("the failure is not reported: %+v", doc.Adapters)
	}
	if !strings.Contains(doc.Adapters.Statement, "does not mean the application has no") {
		t.Errorf("the statement lets a reader mistake a failure for an absence of controls: %q",
			doc.Adapters.Statement)
	}
	// The assurance the run can claim must be no greater than without adapters.
	base := report.Build(baseline, "test")
	if doc.Assurance.ExecutedChecks > base.Assurance.ExecutedChecks {
		t.Error("a failed adapter increased the number of checks the run claims to have executed")
	}
}

// A malformed document must contribute nothing at all, so a hostile or broken
// adapter cannot add an expectation the core then reports against.
func TestM3_MalformedAdapterOutputIsRejectedWholesale(t *testing.T) {
	for _, doc := range []string{
		`{"contractVersion":"appsec.adapter/v9","adapter":{"name":"laravel","version":"1",` +
			`"extractionMethod":"static-lexical"},"facts":[` +
			`{"kind":"operation.authentication","operation":{"method":"GET","path":"/api/orders"},` +
			`"value":"required"}]}`,
		`{not json`,
	} {
		if _, err := adapter.Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("malformed adapter output was accepted: %s", doc[:40])
		}
	}
}

// ---------------------------------------------------------------------------
// PROVENANCE: an inference is never presented as an observation
// ---------------------------------------------------------------------------

func TestM3_ReportKeepsExpectationSeparateFromEvidence(t *testing.T) {
	res := runWithAdapter(t, servesEveryone(), silentSpec,
		[]adapter.Document{adapterDoc(authRequiredFact())})
	doc := report.Build(res, "test")

	if !strings.Contains(doc.Adapters.Statement, "expectation") {
		t.Errorf("the adapter statement does not frame facts as expectations: %q",
			doc.Adapters.Statement)
	}
	if !strings.Contains(doc.Adapters.Statement, "not evidence") {
		t.Errorf("the adapter statement does not separate expectation from evidence: %q",
			doc.Adapters.Statement)
	}

	// A static inference must never be graded as a declaration or an
	// observation anywhere in the pipeline.
	for _, m := range res.Surface.AdapterMerges {
		if m.Provenance != model.ProvenanceInferred {
			t.Errorf("a static-lexical fact was graded %s", m.Provenance)
		}
	}

	// The finding it enabled stays suspected: reading source proves nothing
	// about what a request would do.
	for _, f := range res.Findings {
		if f.State == model.StateConfirmed {
			t.Errorf("a finding was confirmed on an adapter-derived expectation alone: %+v", f)
		}
	}

	var out strings.Builder
	if err := report.WriteJSON(&out, doc); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out.String()), &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["adapters"]; !ok {
		t.Error("the report has no adapters section, so a reader cannot tell how expectations arose")
	}
}
