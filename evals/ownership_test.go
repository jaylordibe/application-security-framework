// M2 evaluation fixtures: two identities and one owned resource.
//
// Every fixture below is a deterministic in-process application exhibiting one
// behaviour a real API exhibits, paired with the verdict AppSec Framework must
// reach. The pairing carries the weight: a check that reports the vulnerable
// application but also reports the one using 404 for anti-enumeration has not
// learned to tell them apart, it has only learned to complain.
package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/outcome"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/resource"
	"github.com/jaylordibe/application-security-framework/internal/scope"
	"github.com/jaylordibe/application-security-framework/internal/store"
)

// ownedSpec declares a parameterised resource operation, readable and writable.
// Before M2 both were untestable: probing /api/orders/{orderId} meant inventing
// an identifier.
const ownedSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "owned", "version": "1"},
  "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
  "paths": {
    "/api/orders/{orderId}": {
      "parameters": [
        {"name": "orderId", "in": "path", "required": true, "schema": {"type": "string"}}
      ],
      "get":   {"operationId": "getOrder",   "security": [{"bearer": []}]},
      "patch": {"operationId": "patchOrder", "security": [{"bearer": []}]}
    }
  }
}`

const (
	tokenA = "APPSEC_M2_TOKEN_ALICE_11d3a9c0f7"
	tokenB = "APPSEC_M2_TOKEN_BOB_44e8b1d2a6"
	// theOrder is the resource alice owns and bob must not reach.
	theOrder = "ord-777"
	readOp   = "GET /api/orders/{orderId}"
	writeOp  = "PATCH /api/orders/{orderId}"
)

// callerOf identifies which identity sent a request, or "" for anonymous.
func callerOf(r *http.Request) string {
	switch r.Header.Get("Authorization") {
	case "Bearer " + tokenA:
		return "alice"
	case "Bearer " + tokenB:
		return "bob"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	b, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ownershipOptions varies one fixture without rewriting the harness.
type ownershipOptions struct {
	expectation resource.Expectation
	// values overrides the fixture's parameter values.
	values map[string]string
	// mutation enables cross-owner write testing.
	mutation map[string]any
	// profile overrides the assessment profile.
	profile model.Profile
	// bobToken overrides bob's credential, to model a dead attacker identity.
	bobToken string
	// aliceToken overrides alice's credential, to model a dead owner identity.
	aliceToken string
	// canaryPath enables liveness canaries for both identities.
	canaryPath string
}

// runOwnership assesses handler with alice owning theOrder and bob probing it.
func runOwnership(t *testing.T, handler http.Handler, opt ownershipOptions) engine.Result {
	t.Helper()
	return runOwnershipWithSignals(t, handler, opt, outcome.Signals{})
}

// runOwnershipWithSignals is runOwnership with an operator-supplied oracle, for
// applications whose denial is an error code rather than a status.
func runOwnershipWithSignals(
	t *testing.T, handler http.Handler, opt ownershipOptions, signals outcome.Signals,
) engine.Result {
	t.Helper()
	return runOwnershipWithSpec(t, handler, opt, ownedSpec, signals)
}

// runOwnershipWithSpec is the full harness, parameterised by specification.
func runOwnershipWithSpec(
	t *testing.T, handler http.Handler, opt ownershipOptions, spec string, signals outcome.Signals,
) engine.Result {
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
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	t.Cleanup(client.Close)

	aTok, bTok := tokenA, tokenB
	if opt.aliceToken != "" {
		aTok = opt.aliceToken
	}
	if opt.bobToken != "" {
		bTok = opt.bobToken
	}
	t.Setenv("APPSEC_EVAL_ALICE", aTok)
	t.Setenv("APPSEC_EVAL_BOB", bTok)

	mk := func(id, env string) identity.Identity {
		i := identity.Identity{
			ID:   id,
			Auth: identity.Authentication{Scheme: identity.SchemeBearer, Credential: identity.CredentialSource{Env: env}},
		}
		if opt.canaryPath != "" {
			i.Live = identity.Liveness{Method: http.MethodGet, Path: opt.canaryPath}
		}
		return i
	}
	ids := identity.Resolve([]identity.Identity{
		mk("alice", "APPSEC_EVAL_ALICE"),
		mk("bob", "APPSEC_EVAL_BOB"),
	}, srv.URL, client, red)

	values := opt.values
	if values == nil {
		values = map[string]string{"orderId": theOrder}
	}
	expectation := opt.expectation
	if expectation == "" {
		expectation = resource.CrossOwnerDenied
	}
	fixture := resource.Fixture{
		ID: "order-alice", Type: "order", Owner: "alice",
		CrossOwnerAccess: expectation, Values: values,
		Provenance: resource.ProvenanceConfigured,
	}
	if opt.mutation != nil {
		fixture.Mutation = &resource.Mutation{Values: opt.mutation}
	}

	profile := opt.profile
	if profile == "" {
		profile = model.ProfileVerification
	}

	parsed, err := openapi.Parse([]byte(spec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}

	res, err := engine.Run(context.Background(), engine.Options{
		RunID:   "eval-m2",
		Target:  srv.URL,
		Profile: profile,
		Surface: engine.Surface{
			SpecDerived: true, Operations: parsed.Operations, Fidelity: parsed.Fidelity,
		},
		// Only the cross-owner check runs here, so a finding cannot be confused
		// with the M1 declared-auth check's output.
		Checks:            nil,
		ResourceCheck:     check.CrossOwner{Signals: signals},
		Resources:         []resource.Fixture{fixture},
		Identities:        ids,
		Concurrency:       2,
		RequestsPerSecond: 500,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res
}

// ownershipRow returns the cross-owner ledger row for an operation.
func ownershipRow(t *testing.T, res engine.Result, opID string) model.CoverageEntry {
	t.Helper()
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionOwnership && e.Subject == opID {
			return e
		}
	}
	var got []string
	for _, e := range res.Coverage {
		got = append(got, e.Dimension+"/"+e.Subject)
	}
	t.Fatalf("no cross-owner ledger row for %q; rows present: %v", opID, got)
	return model.CoverageEntry{}
}

// bolaFindings returns cross-owner findings.
func bolaFindings(res engine.Result) []model.Finding {
	var out []model.Finding
	for _, f := range res.Findings {
		if strings.HasPrefix(f.CheckID, "cross-owner-") {
			out = append(out, f)
		}
	}
	return out
}

// theOrderRecord is the protected resource alice owns.
func theOrderRecord() map[string]any {
	return map[string]any{
		"id": theOrder, "customer": "alice@example.test", "total": 4200, "status": "paid",
	}
}

// bobsOwnOrder is a different order, of identical shape. It exists so that shape
// agreement alone cannot be mistaken for evidence.
func bobsOwnOrder() map[string]any {
	return map[string]any{
		"id": "ord-111", "customer": "bob@example.test", "total": 99, "status": "paid",
	}
}

// ---------------------------------------------------------------------------
// The paired applications. They differ in one thing: whether the read is scoped
// by the caller.
// ---------------------------------------------------------------------------

// vulnerableApp serves any order to any authenticated caller.
func vulnerableApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})
	return mux
}

// secureApp scopes the read by the caller, exactly as one of this project's
// reference applications does: another user's record is never loaded and the
// caller gets a 404.
func secureApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		caller := callerOf(r)
		if caller == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		if caller != "alice" {
			writeJSON(w, 404, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})
	return mux
}

// ---------------------------------------------------------------------------
// KNOWN VULNERABLE — must be detected
// ---------------------------------------------------------------------------

func TestM2_Vulnerable_NonOwnerReadsTheResource(t *testing.T) {
	res := runOwnership(t, vulnerableApp(), ownershipOptions{canaryPath: "/api/me"})

	got := bolaFindings(res)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 cross-owner finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.State != model.StateConfirmed {
		t.Fatalf("state = %s, want confirmed. Verification: %+v", f.State, f.Verification)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.ResourceID != "order-alice" || f.OwnerIdentityID != "alice" || f.IdentityID != "bob" {
		t.Errorf("finding does not identify the parties: resource=%q owner=%q attacker=%q",
			f.ResourceID, f.OwnerIdentityID, f.IdentityID)
	}
	// The evidence must answer who owned it, who reached it, and how that was
	// established.
	names := map[string]bool{}
	for _, s := range f.Verification.Steps {
		names[s.Name] = s.Passed
	}
	for _, required := range []string{
		"owner-control-established", "non-owner-identity-live",
		"materially-equivalent-to-owner-response", "same-resource-as-owner-received",
	} {
		if !names[required] {
			t.Errorf("a confirmed finding must publish a passing %q step; steps: %+v",
				required, f.Verification.Steps)
		}
	}
	if row := ownershipRow(t, res, readOp); row.Disposition != model.DispositionExecuted {
		t.Errorf("ledger row = %s/%s, want executed", row.Disposition, row.Cause)
	}
}

// ---------------------------------------------------------------------------
// KNOWN SECURE — must NOT be reported
// ---------------------------------------------------------------------------

func TestM2_Secure_AntiEnumeration404IsNotAFinding(t *testing.T) {
	res := runOwnership(t, secureApp(), ownershipOptions{canaryPath: "/api/me"})

	if got := bolaFindings(res); len(got) != 0 {
		t.Fatalf("false positive against an application that scopes reads by caller: %+v", got)
	}
	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionExecuted {
		t.Fatalf("row = %s/%s, want executed", row.Disposition, row.Cause)
	}
	if !strings.Contains(row.Detail, "boundary held") {
		t.Errorf("the ledger does not record the verified denial: %q", row.Detail)
	}
}

// The same boundary expressed as 403 rather than 404 must also be a denial.
func TestM2_Secure_403IsNotAFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		switch callerOf(r) {
		case "alice":
			writeJSON(w, 200, theOrderRecord())
		case "bob":
			writeJSON(w, 403, map[string]any{"message": "forbidden"})
		default:
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
		}
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnership(t, mux, ownershipOptions{canaryPath: "/api/me"})
	if got := bolaFindings(res); len(got) != 0 {
		t.Fatalf("false positive on a 403 denial: %+v", got)
	}
}

// An application whose denial is a stable error code inside a 200 must also be
// understood, via the operator-supplied oracle the outcome classifier already
// takes.
func TestM2_Secure_ApplicationErrorCodeDenialIsNotAFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		switch callerOf(r) {
		case "alice":
			writeJSON(w, 200, theOrderRecord())
		case "bob":
			// A 200 that means "no".
			writeJSON(w, 200, map[string]any{"errorCode": "PERMISSION_DENIED"})
		default:
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
		}
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnershipWithSignals(t, mux, ownershipOptions{canaryPath: "/api/me"}, outcome.Signals{
		ErrorCodePointer: "/errorCode",
		DeniedCodes:      []string{"PERMISSION_DENIED"},
	})
	if got := bolaFindings(res); len(got) != 0 {
		t.Fatalf("false positive on an application error-code denial: %+v", got)
	}
	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionExecuted {
		t.Errorf("row = %s/%s, want executed", row.Disposition, row.Cause)
	}
}

// A resource the operator declares as legitimately shared must never be
// reported, however freely the non-owner reaches it.
func TestM2_SharedResourceIsNotAFinding(t *testing.T) {
	res := runOwnership(t, vulnerableApp(), ownershipOptions{
		expectation: resource.CrossOwnerAllowed, canaryPath: "/api/me",
	})
	if got := bolaFindings(res); len(got) != 0 {
		t.Fatalf("a declared-shared resource was reported as BOLA: %+v", got)
	}
	row := ownershipRow(t, res, readOp)
	if !strings.Contains(row.Detail, "legitimately shared") {
		t.Errorf("the ledger does not record why this was not a finding: %q", row.Detail)
	}
}

// ---------------------------------------------------------------------------
// MISLEADING SUCCESS — a 200 that is not the resource
// ---------------------------------------------------------------------------

// Each of these returns a success to the non-owner while serving something that
// is not the owner's resource. Confirming any of them would be a false
// confirmation, and the third is the one a shape-only comparison gets wrong: an
// application that quietly returns the caller's *own* record has an identical
// document shape and is not a BOLA at all.
func TestM2_MisleadingSuccessDoesNotConfirm(t *testing.T) {
	tests := []struct {
		name    string
		forBob  func(w http.ResponseWriter, r *http.Request)
		why     string
		mustNot string
	}{
		{
			name: "SPA catch-all HTML",
			forBob: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`<!doctype html><div id="root"></div>`))
			},
			why: "an application shell is not the protected resource",
		},
		{
			name: "success envelope with no record",
			forBob: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 200, map[string]any{"ok": true, "requestId": "r-1"})
			},
			why: "an acknowledgement is not the protected resource",
		},
		{
			name: "the caller's own record, identical in shape",
			forBob: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 200, bobsOwnOrder())
			},
			why: "returning the caller's own record is a different bug, and is not a BOLA. " +
				"Its shape matches the owner's perfectly, so shape alone must not confirm",
		},
		{
			name: "an unrelated document",
			forBob: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 200, map[string]any{"announcement": "scheduled maintenance"})
			},
			why: "a public document served at a protected path is not the owner's resource",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
				switch callerOf(r) {
				case "alice":
					writeJSON(w, 200, theOrderRecord())
				case "bob":
					tc.forBob(w, r)
				default:
					writeJSON(w, 401, map[string]any{"message": "authentication required"})
				}
			})
			mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, map[string]any{"id": callerOf(r)})
			})

			res := runOwnership(t, mux, ownershipOptions{canaryPath: "/api/me"})
			for _, f := range bolaFindings(res) {
				if f.State == model.StateConfirmed {
					t.Fatalf("false confirmation: %s. Verification: %+v", tc.why, f.Verification)
				}
				if len(f.Verification.Unavailable) == 0 {
					t.Error("a suspected finding must name what it could not establish")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BLOCKED, NEVER PASSED
// ---------------------------------------------------------------------------

// A resource its owner cannot read is not a valid ownership fixture. Reading the
// non-owner's denial as an enforced boundary would report an untested control as
// working, which is the false assurance this project exists to prevent.
func TestM2_OwnerCannotReachFixtureIsBlocked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		// Nobody can read it: the fixture id is wrong, or the record is gone.
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 404, map[string]any{"message": "not found"})
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnership(t, mux, ownershipOptions{canaryPath: "/api/me"})

	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionBlocked {
		t.Fatalf("row = %s, want blocked; a fixture the owner cannot read proves nothing",
			row.Disposition)
	}
	if row.Cause != model.CauseMissingResource {
		t.Errorf("cause = %s, want missing_resource", row.Cause)
	}
	if len(bolaFindings(res)) != 0 {
		t.Error("a finding was raised from a fixture the owner could not read")
	}
}

// A dead non-owner credential returns 401 to everything, which is
// indistinguishable from an enforced boundary. It must block, or forgetting to
// refresh a token would make every application look secure.
func TestM2_DeadAttackerIdentityIsBlockedNotEnforcement(t *testing.T) {
	res := runOwnership(t, vulnerableApp(), ownershipOptions{
		bobToken: "expired-token", canaryPath: "/api/me",
	})

	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionBlocked {
		t.Fatalf("row = %s/%s, want blocked. A dead attacker credential must never read as "+
			"ownership enforcement", row.Disposition, row.Cause)
	}
	if row.Cause != model.CauseAuthenticationFailed {
		t.Errorf("cause = %s, want authentication_failed", row.Cause)
	}
	if strings.Contains(row.Detail, "boundary held") {
		t.Error("a dead credential was described as an enforced boundary")
	}
	if len(bolaFindings(res)) != 0 {
		t.Error("a finding was raised using a dead attacker identity")
	}
}

// A dead owner credential invalidates the control, so nothing can be concluded.
func TestM2_DeadOwnerIdentityIsBlocked(t *testing.T) {
	res := runOwnership(t, vulnerableApp(), ownershipOptions{
		aliceToken: "expired-token", canaryPath: "/api/me",
	})

	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionBlocked {
		t.Fatalf("row = %s/%s, want blocked", row.Disposition, row.Cause)
	}
	if len(bolaFindings(res)) != 0 {
		t.Error("a finding was raised with an invalid owner identity")
	}
}

// The owner reads the resource, it disappears, and the non-owner's 404 now means
// nothing. Without the owner re-check this reads as an enforced boundary.
func TestM2_ResourceDisappearingMidTestIsBlocked(t *testing.T) {
	var aliceReads atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		switch callerOf(r) {
		case "alice":
			// Present for the control, gone by the re-check.
			if aliceReads.Add(1) == 1 {
				writeJSON(w, 200, theOrderRecord())
				return
			}
			writeJSON(w, 404, map[string]any{"message": "not found"})
		case "bob":
			writeJSON(w, 404, map[string]any{"message": "not found"})
		default:
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
		}
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnership(t, mux, ownershipOptions{canaryPath: "/api/me"})

	row := ownershipRow(t, res, readOp)
	if row.Disposition != model.DispositionBlocked {
		t.Fatalf("row = %s/%s, want blocked. The resource vanished between the control and the "+
			"re-check, so the non-owner's 404 cannot be read as enforcement",
			row.Disposition, row.Cause)
	}
	if !strings.Contains(row.Detail, "changed underneath") {
		t.Errorf("the ledger does not explain the disappearance: %q", row.Detail)
	}
}

// A fixture cannot be filled means untestable, and untestable means blocked.
func TestM2_UnfillableFixtureIsNotAPass(t *testing.T) {
	res := runOwnership(t, vulnerableApp(), ownershipOptions{
		values:     map[string]string{"somethingElse": "x"},
		canaryPath: "/api/me",
	})
	if len(bolaFindings(res)) != 0 {
		t.Error("a finding was raised from an unfillable fixture")
	}
	var sawUnaddressable bool
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionOwnership && e.Cause == model.CauseMissingResource {
			sawUnaddressable = true
		}
	}
	if !sawUnaddressable {
		t.Errorf("a fixture that addresses nothing produced no explanatory row: %+v", res.Coverage)
	}
}

// ---------------------------------------------------------------------------
// SAFETY AND SCOPE
// ---------------------------------------------------------------------------

// A cross-owner write against somebody's real resource is state-changing, so it
// requires the intrusive profile. Under verification it must be blocked, and the
// ledger must say so.
func TestM2_MutationRequiresTheIntrusiveProfile(t *testing.T) {
	var writes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			writes.Add(1)
		}
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnership(t, mux, ownershipOptions{
		mutation: map[string]any{"status": "appsec-m2-marker"}, canaryPath: "/api/me",
		// verification, not intrusive
	})

	row := ownershipRow(t, res, writeOp)
	if row.Disposition != model.DispositionBlocked || row.Cause != model.CauseSafetyPolicy {
		t.Fatalf("write row = %s/%s, want blocked/safety_policy", row.Disposition, row.Cause)
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("%d write requests were sent under the verification profile", n)
	}
}

// A fixture value must never be able to move a request to another origin.
func TestM2_FixtureValueCannotEscapeScope(t *testing.T) {
	var offOrigin atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		offOrigin.Add(1)
		w.WriteHeader(200)
	}))
	defer evil.Close()

	for _, value := range []string{
		"../../../admin", "..%2f..%2fadmin", "x/../../admin",
		strings.TrimPrefix(evil.URL, "http://") + "/collect",
		"//" + strings.TrimPrefix(evil.URL, "http://") + "/collect",
	} {
		t.Run(value, func(t *testing.T) {
			res := runOwnership(t, vulnerableApp(), ownershipOptions{
				values:     map[string]string{"orderId": value},
				canaryPath: "/api/me",
			})
			if len(bolaFindings(res)) != 0 {
				t.Error("a hostile fixture value produced a finding")
			}
		})
	}
	if n := offOrigin.Load(); n != 0 {
		t.Fatalf("a fixture value caused %d requests to another origin", n)
	}
}

// Neither identity's credential may follow a redirect off-origin.
func TestM2_MaliciousRedirectForwardsNoCredential(t *testing.T) {
	var offOrigin atomic.Int64
	var sawCredential atomic.Bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offOrigin.Add(1)
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, tokenA) || strings.Contains(auth, tokenB) {
			sawCredential.Store(true)
		}
		w.WriteHeader(200)
	}))
	defer evil.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", evil.URL+"/collect")
		w.WriteHeader(302)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnership(t, mux, ownershipOptions{canaryPath: "/api/me"})

	if n := offOrigin.Load(); n != 0 {
		t.Fatalf("the off-origin host received %d requests; redirects must never be followed", n)
	}
	if sawCredential.Load() {
		t.Fatal("a credential reached an unauthorized origin")
	}
	for _, f := range bolaFindings(res) {
		if f.State == model.StateConfirmed {
			t.Error("a redirect produced a confirmed finding")
		}
	}
}

// Alice and bob run concurrently across many fixtures inside one assessment.
// Neither may ever present the other's credential, and no request may carry
// both. This exercises the engine's real concurrent path rather than running
// several assessments side by side.
func TestM2_IdentitiesDoNotContaminateEachOther(t *testing.T) {
	var contaminated atomic.Int64
	var requests atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, tokenA) && strings.Contains(auth, tokenB) {
			contaminated.Add(1)
		}
		if callerOf(r) == "" {
			contaminated.Add(1)
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	defer client.Close()

	t.Setenv("APPSEC_EVAL_ALICE", tokenA)
	t.Setenv("APPSEC_EVAL_BOB", tokenB)
	ids := identity.Resolve([]identity.Identity{
		{ID: "alice", Auth: identity.Authentication{Scheme: identity.SchemeBearer,
			Credential: identity.CredentialSource{Env: "APPSEC_EVAL_ALICE"}},
			Live: identity.Liveness{Method: http.MethodGet, Path: "/api/me"}},
		{ID: "bob", Auth: identity.Authentication{Scheme: identity.SchemeBearer,
			Credential: identity.CredentialSource{Env: "APPSEC_EVAL_BOB"}},
			Live: identity.Liveness{Method: http.MethodGet, Path: "/api/me"}},
	}, srv.URL, client, red)

	// Many distinct fixtures, alternating owners, so both identities are acting
	// as owner and as non-owner at the same moment.
	var fixtures []resource.Fixture
	for i := 0; i < 12; i++ {
		owner := "alice"
		if i%2 == 1 {
			owner = "bob"
		}
		fixtures = append(fixtures, resource.Fixture{
			ID: fmt.Sprintf("order-%02d", i), Owner: owner,
			CrossOwnerAccess: resource.CrossOwnerDenied,
			Values:           map[string]string{"orderId": fmt.Sprintf("ord-%02d", i)},
			Provenance:       resource.ProvenanceConfigured,
		})
	}

	parsed, err := openapi.Parse([]byte(ownedSpec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}

	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "eval-m2-race", Target: srv.URL, Profile: model.ProfileVerification,
		Surface:       engine.Surface{SpecDerived: true, Operations: parsed.Operations},
		ResourceCheck: check.CrossOwner{},
		Resources:     fixtures,
		Identities:    ids,
		// Deliberately high, so units genuinely overlap.
		Concurrency:       8,
		RequestsPerSecond: 2000,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	if requests.Load() == 0 {
		t.Fatal("no requests were made, so this proves nothing")
	}
	if n := contaminated.Load(); n != 0 {
		t.Fatalf("%d requests carried the wrong or a mixed credential", n)
	}
	// Every fixture must have produced its own row: collapsing two resources
	// into one ledger key would let a single tested boundary stand in for many.
	rows := map[string]bool{}
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionOwnership {
			rows[e.ResourceID] = true
		}
	}
	if len(rows) != len(fixtures) {
		t.Errorf("ledger has rows for %d fixtures, want %d; resource identity is being collapsed",
			len(rows), len(fixtures))
	}
}

// ---------------------------------------------------------------------------
// MUTATION — a write is confirmed only by the owner's own view of the resource
// ---------------------------------------------------------------------------

// orderStore is a tiny stateful application backing the mutation fixtures.
//
// It exists so that a write either lands or does not, observably, rather than
// being simulated by a status code. The whole point of these fixtures is that a
// status code is not evidence.
type orderStore struct {
	mu sync.Mutex
	// status is the mutable field.
	status string
	// enforce controls whether writes are scoped to the owner.
	enforce bool
	// acceptAndDiscard makes writes return success while changing nothing.
	acceptAndDiscard bool
	writes           atomic.Int64
}

func (s *orderStore) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		caller := callerOf(r)
		if caller == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			body := map[string]any{
				"id": theOrder, "customer": "alice@example.test", "total": 4200, "status": s.status,
			}
			s.mu.Unlock()
			writeJSON(w, 200, body)
		case http.MethodPatch:
			s.writes.Add(1)
			if s.enforce && caller != "alice" {
				writeJSON(w, 404, map[string]any{"message": "not found"})
				return
			}
			var patch map[string]any
			_ = json.NewDecoder(r.Body).Decode(&patch)
			if !s.acceptAndDiscard {
				if v, ok := patch["status"].(string); ok {
					s.mu.Lock()
					s.status = v
					s.mu.Unlock()
				}
			}
			s.mu.Lock()
			body := map[string]any{
				"id": theOrder, "customer": "alice@example.test", "total": 4200, "status": s.status,
			}
			s.mu.Unlock()
			// Note: a discarding application still answers 200 with what it was
			// sent, which is exactly the response that fools a status-only check.
			if s.acceptAndDiscard {
				body["status"] = patch["status"]
			}
			writeJSON(w, 200, body)
		default:
			writeJSON(w, 405, map[string]any{"message": "method not allowed"})
		}
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})
	return mux
}

func (s *orderStore) current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func mutationOptions() ownershipOptions {
	return ownershipOptions{
		mutation:   map[string]any{"status": "appsec-m2-marker"},
		profile:    model.ProfileIntrusive,
		canaryPath: "/api/me",
	}
}

// A non-owner changes the owner's resource, and the owner's own re-read proves
// it. This is the only case in which a mutation finding is correct.
func TestM2_VulnerableMutation_IsConfirmedByOwnerSideObservation(t *testing.T) {
	store := &orderStore{status: "paid"}
	res := runOwnership(t, store.handler(), mutationOptions())

	var found *model.Finding
	for i, f := range bolaFindings(res) {
		if f.CheckID == check.CrossOwnerWriteID {
			found = &bolaFindings(res)[i]
		}
	}
	if found == nil {
		t.Fatalf("no cross-owner write finding; ledger: %+v", ownershipRow(t, res, writeOp))
	}
	if found.State != model.StateConfirmed {
		t.Errorf("state = %s, want confirmed", found.State)
	}
	if found.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want critical for an unauthorized write", found.Severity)
	}
	if !strings.Contains(found.Actual, "status changed from") {
		t.Errorf("the finding does not state the observed change: %q", found.Actual)
	}
	// Best-effort restoration must have put the value back, and must say so.
	if got := store.current(); got != "paid" {
		t.Errorf("the resource was left as %q; restoration did not run or did not work", got)
	}
	row := ownershipRow(t, res, writeOp)
	if !strings.Contains(row.Detail, "restored") {
		t.Errorf("the ledger does not report what happened to the resource: %q", row.Detail)
	}
}

// The write is refused. The owner's view is unchanged, so there is no finding.
func TestM2_SecureMutation_IsNotAFinding(t *testing.T) {
	store := &orderStore{status: "paid", enforce: true}
	res := runOwnership(t, store.handler(), mutationOptions())

	for _, f := range bolaFindings(res) {
		if f.CheckID == check.CrossOwnerWriteID {
			t.Fatalf("false positive on an enforced write boundary: %+v", f)
		}
	}
	if got := store.current(); got != "paid" {
		t.Errorf("the resource changed to %q despite the boundary being enforced", got)
	}
	row := ownershipRow(t, res, writeOp)
	if row.Disposition != model.DispositionExecuted {
		t.Errorf("row = %s/%s, want executed", row.Disposition, row.Cause)
	}
}

// MANDATORY. The write returns 200 and echoes the value back, but nothing
// actually changed. A status-only check confirms this; observing the owner's
// view does not. This is the single most important mutation fixture.
func TestM2_FakeSuccessMutation_IsNotConfirmed(t *testing.T) {
	store := &orderStore{status: "paid", acceptAndDiscard: true}
	res := runOwnership(t, store.handler(), mutationOptions())

	for _, f := range bolaFindings(res) {
		if f.CheckID == check.CrossOwnerWriteID {
			t.Fatalf("a write that changed nothing was reported as an unauthorized mutation. "+
				"This is the response every status-only check gets wrong: %+v", f)
		}
	}
	if store.writes.Load() == 0 {
		t.Fatal("no write was attempted, so this proves nothing")
	}
	if got := store.current(); got != "paid" {
		t.Errorf("the fixture is wrong: state changed to %q", got)
	}
	row := ownershipRow(t, res, writeOp)
	if row.Disposition != model.DispositionExecuted {
		t.Fatalf("row = %s/%s, want executed", row.Disposition, row.Cause)
	}
	if !strings.Contains(row.Detail, "success was not real") {
		t.Errorf("the ledger does not record that the reported success was hollow: %q", row.Detail)
	}
}

// A resource with no readable operation cannot have a write verified, so the
// write must not be attempted at all.
func TestM2_MutationWithoutAReadableOperationIsBlocked(t *testing.T) {
	const writeOnlySpec = `{
	  "openapi": "3.0.3",
	  "info": {"title": "write-only", "version": "1"},
	  "paths": {
	    "/api/orders/{orderId}": {
	      "parameters": [
	        {"name": "orderId", "in": "path", "required": true, "schema": {"type": "string"}}
	      ],
	      "patch": {"operationId": "patchOrder", "security": [{"bearer": []}]}
	    }
	  }
	}`
	var writes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			writes.Add(1)
		}
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r)})
	})

	res := runOwnershipWithSpec(t, mux, mutationOptions(), writeOnlySpec, outcome.Signals{})

	row := ownershipRow(t, res, writeOp)
	if row.Disposition != model.DispositionBlocked || row.Cause != model.CauseNoOracle {
		t.Fatalf("row = %s/%s, want blocked/no_oracle", row.Disposition, row.Cause)
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("%d unverifiable writes were sent against somebody's resource", n)
	}
}

// M2's roadmap promises that operations previously blocked as missing_resource
// become testable. That promise is about the declared-auth check too: without a
// fixture it cannot address /api/orders/{orderId} at all, and reports so.
func TestM2_FixtureMakesAParameterisedOperationTestable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		// Only the real resource exists. Anything else is a 404, so the check's
		// catch-all discriminator has a stable not-found fingerprint to work
		// against, exactly as a real application would provide.
		if !strings.HasSuffix(r.URL.Path, "/"+theOrder) {
			writeJSON(w, 404, map[string]any{"message": "not found"})
			return
		}
		// Declared protected, served to anyone: an authentication bypass that
		// was invisible before a fixture existed.
		writeJSON(w, 200, theOrderRecord())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 404, map[string]any{"message": "not found"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: redact.New(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	defer client.Close()

	parsed, err := openapi.Parse([]byte(ownedSpec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	fixture := resource.Fixture{
		ID: "order-alice", Owner: "alice", CrossOwnerAccess: resource.CrossOwnerDenied,
		Values: map[string]string{"orderId": theOrder}, Provenance: resource.ProvenanceConfigured,
	}

	run := func(fixtures []resource.Fixture) engine.Result {
		res, rerr := engine.Run(context.Background(), engine.Options{
			RunID: "eval", Target: srv.URL, Profile: model.ProfileVerification,
			Surface: engine.Surface{SpecDerived: true, Operations: parsed.Operations},
			Checks: []engine.Check{check.AuthRequired{
				Client: client, BaselineProbes: 2, Resources: fixtures,
			}},
			Concurrency: 1, RequestsPerSecond: 500,
		})
		if rerr != nil {
			t.Fatalf("engine: %v", rerr)
		}
		return res
	}

	// Without a fixture the operation cannot be addressed, and the ledger says
	// exactly that rather than reporting it as clean.
	without := run(nil)
	var sawMissingResource bool
	for _, e := range without.Coverage {
		if e.Dimension == engine.DimensionOperation && e.Subject == readOp {
			if e.Disposition != model.DispositionUntested || e.Cause != model.CauseMissingResource {
				t.Errorf("without a fixture: row = %s/%s, want untested/missing_resource",
					e.Disposition, e.Cause)
			}
			sawMissingResource = true
		}
	}
	if !sawMissingResource {
		t.Fatal("no ledger row for the parameterised operation")
	}
	if len(without.Findings) != 0 {
		t.Errorf("a finding was produced for an operation that could not be addressed: %+v",
			without.Findings)
	}

	// With one, the same operation is exercised and the bypass is found.
	with := run([]resource.Fixture{fixture})
	var found bool
	for _, f := range with.Findings {
		if f.OperationID == readOp && f.CheckID == check.AuthRequiredID {
			found = true
		}
	}
	if !found {
		t.Fatalf("a fixture did not make the parameterised operation testable; coverage: %+v",
			with.Coverage)
	}
}

// Two credentials in one assessment doubles the surface for a leak, and the
// cross-owner path writes request bodies as well as headers. This runs a real
// assessment against a target that reflects both credentials back, persists
// everything, and searches every byte of the run directory.
func TestM2_NeitherCredentialReachesDisk(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if callerOf(r) == "" {
			writeJSON(w, 401, map[string]any{"message": "authentication required"})
			return
		}
		// Maximally hostile: reflect the credential into a header, a body and a
		// Location it asks to be followed.
		w.Header().Set("X-Echo-Auth", auth)
		w.Header().Set("Location", "http://127.0.0.1:1/?leaked="+strings.TrimPrefix(auth, "Bearer "))
		writeJSON(w, 200, map[string]any{
			"id": theOrder, "customer": "alice@example.test", "youSent": auth,
		})
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": callerOf(r), "echo": r.Header.Get("Authorization")})
	})

	dir := t.TempDir()
	run, err := store.Create(dir, "20260906T130000Z-m2eval01", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	res, red := runOwnershipWithSink(t, mux, ownershipOptions{canaryPath: "/api/me"}, run.PutEvidence)
	if err := run.WriteFingerprintKey(red.FingerprintKey()); err != nil {
		t.Fatalf("fingerprint key: %v", err)
	}

	doc := report.Build(res, "test")
	var jsonBuf, sarifBuf strings.Builder
	if err := report.WriteJSON(&jsonBuf, doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := report.WriteSARIF(&sarifBuf, doc); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if err := run.WriteFile("report.json", []byte(jsonBuf.String())); err != nil {
		t.Fatalf("write json: %v", err)
	}
	if err := run.WriteFile("report.sarif", []byte(sarifBuf.String())); err != nil {
		t.Fatalf("write sarif: %v", err)
	}

	var checked, redacted int
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		checked++
		text := string(b)
		if strings.Contains(text, redact.Placeholder) {
			redacted++
		}
		for name, tok := range map[string]string{"alice": tokenA, "bob": tokenB} {
			if strings.Contains(text, tok) {
				rel, _ := filepath.Rel(dir, path)
				t.Errorf("%s's credential was written to %s", name, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("no files were written, so the search proved nothing")
	}
	if redacted == 0 {
		t.Error("no redaction placeholder appears anywhere; the target may not have reflected the " +
			"credentials at all, in which case this proves nothing")
	}

	for name, text := range map[string]string{
		"json report": jsonBuf.String(), "sarif report": sarifBuf.String(),
		"summary": report.Summary(doc),
	} {
		for who, tok := range map[string]string{"alice": tokenA, "bob": tokenB} {
			if strings.Contains(text, tok) {
				t.Errorf("%s's credential appears in the %s", who, name)
			}
		}
	}
}

// runOwnershipWithSink is the harness with evidence persistence.
func runOwnershipWithSink(
	t *testing.T, handler http.Handler, opt ownershipOptions,
	sink func(model.Exchange) (string, error),
) (engine.Result, *redact.Redactor) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpx: %v", err)
	}
	t.Cleanup(client.Close)

	t.Setenv("APPSEC_EVAL_ALICE", tokenA)
	t.Setenv("APPSEC_EVAL_BOB", tokenB)
	mk := func(id, env string) identity.Identity {
		i := identity.Identity{
			ID:   id,
			Auth: identity.Authentication{Scheme: identity.SchemeBearer, Credential: identity.CredentialSource{Env: env}},
		}
		if opt.canaryPath != "" {
			i.Live = identity.Liveness{Method: http.MethodGet, Path: opt.canaryPath}
		}
		return i
	}
	ids := identity.Resolve([]identity.Identity{
		mk("alice", "APPSEC_EVAL_ALICE"), mk("bob", "APPSEC_EVAL_BOB"),
	}, srv.URL, client, red)

	parsed, err := openapi.Parse([]byte(ownedSpec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "20260906T130000Z-m2eval01", Target: srv.URL, Profile: model.ProfileVerification,
		Surface:       engine.Surface{SpecDerived: true, Operations: parsed.Operations},
		ResourceCheck: check.CrossOwner{},
		Resources: []resource.Fixture{{
			ID: "order-alice", Owner: "alice", CrossOwnerAccess: resource.CrossOwnerDenied,
			Values: map[string]string{"orderId": theOrder}, Provenance: resource.ProvenanceConfigured,
		}},
		Identities:        ids,
		Concurrency:       2,
		RequestsPerSecond: 500,
		EvidenceSink:      sink,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res, red
}
