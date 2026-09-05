// Package evals is Assay's evaluation harness.
//
// Evaluation is part of the product, not an afterthought. Every security-relevant
// behaviour is paired: a KNOWN VULNERABLE fixture that must be detected, and a
// KNOWN SECURE fixture that must not be reported. A check that cannot tell them
// apart is not finished, however good its code looks.
//
// The harness is fully offline. It runs against in-process HTTP servers, needs no
// network, no database and no external engine, so `go test ./...` is the whole
// story for a contributor.
package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// spec is a minimal OpenAPI document declaring one protected and one public
// operation, so the oracle discriminates rather than being uniform.
const spec = `{
  "openapi": "3.0.3",
  "info": {"title": "fixture", "version": "1"},
  "paths": {
    "/api/profile": {
      "get": {
        "operationId": "getProfile",
        "security": [{"bearer": []}]
      }
    },
    "/api/health": {
      "get": {
        "operationId": "health",
        "security": []
      }
    }
  }
}`

// outcomeFor runs the check against a fixture and returns the ledger and findings.
func runAgainst(t *testing.T, handler http.Handler) (engine.Result, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{
		{Host: "127.0.0.1", Ports: []int{port}},
		{Host: "localhost", Ports: []int{port}},
	}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	client, err := httpx.New(httpx.Options{
		Policy: pol, Redactor: redact.New(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}

	parsed, err := openapi.Parse([]byte(spec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}

	res, err := engine.Run(context.Background(), engine.Options{
		RunID:   "eval",
		Target:  srv.URL,
		Profile: model.ProfileVerification,
		Surface: engine.Surface{
			SpecDerived: true, Operations: parsed.Operations, Fidelity: parsed.Fidelity,
		},
		Checks:            []engine.Check{check.AuthRequired{Client: client, BaselineProbes: 2}},
		Concurrency:       2,
		RequestsPerSecond: 200,
		Now:               func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res, srv.URL
}

func serverPort(t *testing.T, url string) int {
	t.Helper()
	parts := strings.Split(url, ":")
	var p int
	if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &p); err != nil {
		t.Fatalf("port: %v", err)
	}
	return p
}

func findingsFor(res engine.Result, opID string) []model.Finding {
	var out []model.Finding
	for _, f := range res.Findings {
		if f.OperationID == opID {
			out = append(out, f)
		}
	}
	return out
}

func entryFor(res engine.Result, opID string) (model.CoverageEntry, bool) {
	for _, e := range res.Coverage {
		if e.Subject == opID {
			return e, true
		}
	}
	return model.CoverageEntry{}, false
}

func jsonHandler(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// ---------------------------------------------------------------------------
// KNOWN VULNERABLE — must detect
// ---------------------------------------------------------------------------

// The declared-protected operation serves data to an unauthenticated caller.
func TestVulnerable_DeclaredProtectedServesAnonymous(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, map[string]any{
		"id": 1, "email": "user@example.test", "role": "admin",
	}))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)

	got := findingsFor(res, "GET /api/profile")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for the protected operation, got %d", len(got))
	}
	f := got[0]
	if f.State != model.StateSuspected {
		t.Errorf("state = %s, want suspected (no authenticated control was available)", f.State)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if len(f.Verification.Unavailable) == 0 {
		t.Error("the missing authenticated control must be recorded, not hidden")
	}
}

// ---------------------------------------------------------------------------
// KNOWN SECURE — must NOT report
// ---------------------------------------------------------------------------

// The declared-protected operation refuses anonymous callers.
func TestSecure_DeclaredProtectedRefusesAnonymous(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(401, map[string]any{"message": "authentication required"}))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	if got := findingsFor(res, "GET /api/profile"); len(got) != 0 {
		t.Fatalf("false positive on a correctly protected operation: %+v", got)
	}
	e, ok := entryFor(res, "GET /api/profile")
	if !ok || e.Disposition != model.DispositionExecuted {
		t.Errorf("ledger disposition = %v, want executed", e.Disposition)
	}
}

// A declared-public operation returning 200 is correct and must never be a
// finding.
func TestSecure_DeclaredPublicOperationIsNotAFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(401, map[string]any{"message": "unauthorized"}))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	if got := findingsFor(res, "GET /api/health"); len(got) != 0 {
		t.Fatalf("declared-public operation reported as a finding: %+v", got)
	}
	e, ok := entryFor(res, "GET /api/health")
	if !ok {
		t.Fatal("no ledger entry for the public operation")
	}
	if e.Disposition != model.DispositionUntested || e.Cause != model.CauseNoOracle {
		t.Errorf("public operation ledger = %s/%s, want untested/no_oracle", e.Disposition, e.Cause)
	}
}

// A single-page-app catch-all returns 200 with HTML for everything. This is the
// largest false-positive source in API scanning and must be excluded.
func TestSecure_SPACatchAllIsNotAFinding(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<!doctype html><html><body><div id=root></div></body></html>"))
	})
	res, _ := runAgainst(t, handler)
	if got := findingsFor(res, "GET /api/profile"); len(got) != 0 {
		t.Fatalf("catch-all route reported as missing authentication: %+v", got)
	}
}

// A soft-404: HTTP 200 carrying an error envelope. Common in real applications
// and must be read as a denial, not a success.
func TestSecure_SoftDenialWith200IsNotAFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, map[string]any{
		"success": false, "message": "Unauthenticated.",
	}))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	if got := findingsFor(res, "GET /api/profile"); len(got) != 0 {
		t.Fatalf("soft denial with status 200 reported as a finding: %+v", got)
	}
}

// A cached response tells us nothing about the origin.
func TestBlocked_CachedResponseIsNotScored(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Age", "120")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":1,"email":"a@b.test"}`))
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	if got := findingsFor(res, "GET /api/profile"); len(got) != 0 {
		t.Fatalf("cached response reported as a finding: %+v", got)
	}
	e, _ := entryFor(res, "GET /api/profile")
	if e.Disposition != model.DispositionBlocked || e.Cause != model.CauseIndeterminateOutcome {
		t.Errorf("ledger = %s/%s, want blocked/indeterminate_outcome", e.Disposition, e.Cause)
	}
}

// Rate limiting must block the run rather than being read as a denial. A scanner
// that reads 429 as "denied" reports a falsely clean result.
func TestBlocked_RateLimitedIsNotADenial(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(429, map[string]any{"message": "too many requests"}))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	e, _ := entryFor(res, "GET /api/profile")
	if e.Disposition != model.DispositionBlocked || e.Cause != model.CauseRateLimited {
		t.Errorf("ledger = %s/%s, want blocked/rate_limited", e.Disposition, e.Cause)
	}
}

// A one-off success is more often a state artefact than a vulnerability.
func TestBlocked_NonReproducibleSuccessIsNotAFinding(t *testing.T) {
	var n int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, _ *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"id":1,"email":"a@b.test","role":"admin"}`))
			return
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	if got := findingsFor(res, "GET /api/profile"); len(got) != 0 {
		t.Fatalf("non-reproducible success reported as a finding: %+v", got)
	}
}
