// M1 evaluation fixtures: identities and the authenticated control request.
//
// Each fixture is a deterministic in-process application exhibiting one
// behaviour a real target exhibits, paired with the verdict AppSec Framework
// must reach. The pairing is the point: a check that confirms the vulnerable
// fixture but also confirms the misleading one has not learned anything, it has
// merely become louder.
package evals

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/scope"
	"github.com/jaylordibe/application-security-framework/internal/store"
)

// theProtectedOperation is the operation every fixture below disagrees about.
const theProtectedOperation = "GET /api/profile"

// evalToken is the credential the fixtures authenticate with. It is distinctive
// so that the leakage fixture can search for it unambiguously.
const evalToken = "APPSEC_M1_SECRET_MUST_NEVER_PERSIST_7f91a2c4d8e6b0f3"

// identityOptions describes the identity a fixture configures.
type identityOptions struct {
	// unset omits the environment variable entirely, modelling a forgotten
	// credential.
	unset bool
	// canaryPath enables the liveness canary when non-empty.
	canaryPath string
}

// runWithIdentity runs an assessment against handler with one configured
// identity, returning the result and the run's redactor.
func runWithIdentity(t *testing.T, handler http.Handler, opt identityOptions) (engine.Result, *redact.Redactor) {
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

	const envName = "APPSEC_EVAL_TOKEN"
	if opt.unset {
		t.Setenv(envName, "")
		os.Unsetenv(envName)
	} else {
		t.Setenv(envName, evalToken)
	}

	id := identity.Identity{
		ID:    "admin",
		Label: "Administrator",
		Auth: identity.Authentication{
			Scheme:     identity.SchemeBearer,
			Credential: identity.CredentialSource{Env: envName},
		},
	}
	if opt.canaryPath != "" {
		id.Live = identity.Liveness{Method: http.MethodGet, Path: opt.canaryPath}
	}
	ids := identity.Resolve([]identity.Identity{id}, srv.URL, client, red)

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
		Checks: []engine.Check{check.AuthRequired{
			Client: client, BaselineProbes: 2, Control: ids.Primary(),
		}},
		Concurrency:       2,
		RequestsPerSecond: 200,
		Identities:        ids,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res, red
}

// theFinding returns the single finding for the protected operation.
func theFinding(t *testing.T, res engine.Result) model.Finding {
	t.Helper()
	got := findingsFor(res, theProtectedOperation)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding for %s, got %d", theProtectedOperation, len(got))
	}
	return got[0]
}

// identityRow returns the ledger row describing an identity.
func identityRow(t *testing.T, res engine.Result, id string) model.CoverageEntry {
	t.Helper()
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionIdentity && e.Subject == id {
			return e
		}
	}
	t.Fatalf("no identity ledger row for %q; authentication limits must be visible in coverage", id)
	return model.CoverageEntry{}
}

// operationRow returns the ledger row for an operation.
func operationRow(t *testing.T, res engine.Result, opID string) model.CoverageEntry {
	t.Helper()
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionOperation && e.Subject == opID {
			return e
		}
	}
	t.Fatalf("no operation ledger row for %q", opID)
	return model.CoverageEntry{}
}

// theRecord is the protected resource. Anonymous access to it is the bug.
func theRecord() map[string]any {
	return map[string]any{"id": 7, "email": "owner@example.test", "role": "admin"}
}

// authOnly serves body only to a caller presenting the right bearer token.
func authOnly(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+evalToken {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "authentication required"})
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// ---------------------------------------------------------------------------
// Fixture A — KNOWN VULNERABLE: a declared-protected operation serves everyone
// ---------------------------------------------------------------------------

// The operation ignores authentication entirely, so the anonymous caller
// receives exactly the record a legitimate caller receives. This is the one
// case in which a confirmed finding is correct.
func TestM1_Vulnerable_AnonymousReceivesTheProtectedResource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, theRecord()))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	f := theFinding(t, res)
	if f.State != model.StateConfirmed {
		t.Fatalf("state = %s, want confirmed; an authenticated control proved the anonymous "+
			"caller received the protected resource. Verification: %+v", f.State, f.Verification)
	}
	if f.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %s, want high", f.Confidence)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	var sawControlStep bool
	for _, s := range f.Verification.Steps {
		if s.Name == "authenticated-control-equivalent" {
			sawControlStep = true
			if !s.Passed {
				t.Error("the control step is recorded as failed on a confirmed finding")
			}
		}
	}
	if !sawControlStep {
		t.Error("a confirmed finding must publish the control step that confirmed it")
	}
	if row := identityRow(t, res, "admin"); row.Disposition != model.DispositionExecuted {
		t.Errorf("identity row disposition = %s, want executed", row.Disposition)
	}
}

// ---------------------------------------------------------------------------
// Fixture B — KNOWN SECURE: the control is enforced
// ---------------------------------------------------------------------------

// Anonymous access is refused and the identity succeeds. There is no finding,
// and configuring an identity must not manufacture one.
func TestM1_Secure_AnonymousRefusedIdentityAccepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", authOnly(200, theRecord()))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	if got := findingsFor(res, theProtectedOperation); len(got) != 0 {
		t.Fatalf("false positive on a correctly protected operation: %+v", got)
	}
	if row := operationRow(t, res, theProtectedOperation); row.Disposition != model.DispositionExecuted {
		t.Errorf("disposition = %s (%s), want executed", row.Disposition, row.Cause)
	}
	if row := identityRow(t, res, "admin"); row.Disposition != model.DispositionExecuted {
		t.Errorf("identity row = %s, want executed; the canary confirmed the credential", row.Disposition)
	}
}

// ---------------------------------------------------------------------------
// Fixture C — MISLEADING 200: the anonymous response is not the resource
// ---------------------------------------------------------------------------

// Each of these returns a success status to an anonymous caller while serving
// something that is not the protected resource. Confirming any of them would be
// a false confirmation, which is the failure that would cost this project its
// credibility fastest.
func TestM1_Misleading200DoesNotConfirm(t *testing.T) {
	tests := []struct {
		name      string
		anonymous http.HandlerFunc
		why       string
	}{
		{
			name: "application error envelope with a 200",
			anonymous: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+evalToken {
					jsonHandler(200, theRecord())(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"errorCode":"E_NOPE","requestId":"abc"}`))
			},
			why: "an error envelope is not the protected record",
		},
		{
			name: "fake success wrapper",
			anonymous: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+evalToken {
					jsonHandler(200, theRecord())(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true,"payload":{"placeholder":true}}`))
			},
			why: "a differently shaped document is not the protected record",
		},
		{
			name: "unrelated resource",
			anonymous: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+evalToken {
					jsonHandler(200, theRecord())(w, r)
					return
				}
				jsonHandler(200, map[string]any{"announcement": "scheduled maintenance"})(w, r)
			},
			why: "a public document served at a protected path is not the protected record",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/profile", tc.anonymous)
			mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
			mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
			mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

			res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

			for _, f := range findingsFor(res, theProtectedOperation) {
				if f.State == model.StateConfirmed {
					t.Fatalf("false confirmation: %s. Verification: %+v", tc.why, f.Verification)
				}
			}
			// Whatever the check concluded, it must not have reported the
			// operation as cleanly executed with no reservation recorded.
			for _, f := range findingsFor(res, theProtectedOperation) {
				if len(f.Verification.Unavailable) == 0 {
					t.Error("a suspected finding must name what it could not establish")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fixture D — MISSING CREDENTIAL: explicit, never a pass
// ---------------------------------------------------------------------------

func TestM1_MissingCredentialIsExplicitAndNeverAPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, theRecord()))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{unset: true})

	f := theFinding(t, res)
	if f.State == model.StateConfirmed {
		t.Fatal("a finding was confirmed with no credential at all")
	}
	if f.State != model.StateSuspected {
		t.Errorf("state = %s, want suspected", f.State)
	}
	if !mentions(f.Verification.Unavailable, "could not be resolved") {
		t.Errorf("the missing credential is not named in the finding: %v", f.Verification.Unavailable)
	}

	row := identityRow(t, res, "admin")
	if row.Disposition != model.DispositionBlocked {
		t.Errorf("identity row = %s, want blocked", row.Disposition)
	}
	if row.Cause != model.CauseMissingIdentity {
		t.Errorf("cause = %s, want missing_identity", row.Cause)
	}
	if !strings.Contains(row.Detail, "APPSEC_EVAL_TOKEN") {
		t.Errorf("the ledger does not say which credential source was empty: %q", row.Detail)
	}
}

// ---------------------------------------------------------------------------
// Fixture E — INVALID CREDENTIAL: an authentication failure, never a success
// ---------------------------------------------------------------------------

// The credential is present but the target rejects it. The control therefore
// establishes no baseline, so the finding must stay suspected — and the run must
// never read the rejection as evidence that the operation is protected, because
// the anonymous request already succeeded.
func TestM1_InvalidCredentialIsAnAuthenticationFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"invalid credentials"}`))
			return
		}
		jsonHandler(200, theRecord())(w, r)
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", jsonHandler(401, map[string]any{"message": "invalid credentials"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	f := theFinding(t, res)
	if f.State == model.StateConfirmed {
		t.Fatal("a rejected credential produced a confirmed finding")
	}
	if !mentions(f.Verification.Unavailable, "authenticated-control-request") {
		t.Errorf("the unusable control is not recorded: %v", f.Verification.Unavailable)
	}

	row := identityRow(t, res, "admin")
	if row.Disposition != model.DispositionBlocked || row.Cause != model.CauseAuthenticationFailed {
		t.Errorf("identity row = %s/%s, want blocked/authentication_failed", row.Disposition, row.Cause)
	}
}

// ---------------------------------------------------------------------------
// Fixture F — MID-ASSESSMENT INVALIDATION: conservative accounting
// ---------------------------------------------------------------------------

// The credential works when the run starts and is rejected by the time it ends.
//
// The corroboration gathered in between was produced by a credential that may
// already have been dead, so the confirmation is withdrawn: the finding drops to
// suspected and the ledger row is blocked. The finding itself survives, because
// the anonymous observation behind it never involved the credential.
func TestM1_MidRunInvalidationWithdrawsTheCorroboration(t *testing.T) {
	var canaryCalls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, theRecord()))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		// Good for the opening probe, rejected for every probe after it.
		if canaryCalls.Add(1) == 1 {
			jsonHandler(200, map[string]any{"id": 7})(w, r)
			return
		}
		jsonHandler(401, map[string]any{"message": "token expired"})(w, r)
	})
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	if canaryCalls.Load() < 2 {
		t.Fatalf("the canary ran %d times; it must probe at the start and the end of a run",
			canaryCalls.Load())
	}

	f := theFinding(t, res)
	if f.State == model.StateConfirmed {
		t.Fatal("a finding stayed confirmed on corroboration from an expired credential")
	}
	if !mentions(f.Verification.Unavailable, "withdrawn") {
		t.Errorf("the withdrawal is not explained in the finding: %v", f.Verification.Unavailable)
	}

	row := operationRow(t, res, theProtectedOperation)
	if row.Disposition != model.DispositionBlocked || row.Cause != model.CauseAuthenticationFailed {
		t.Errorf("operation row = %s/%s, want blocked/authentication_failed; a result resting on an "+
			"untrusted control has not established what it claims", row.Disposition, row.Cause)
	}
	if !strings.Contains(row.Detail, "withdrawn") {
		t.Errorf("the ledger does not explain the withdrawal: %q", row.Detail)
	}
	if idRow := identityRow(t, res, "admin"); idRow.Cause != model.CauseAuthenticationFailed {
		t.Errorf("identity row cause = %s, want authentication_failed", idRow.Cause)
	}
}

// ---------------------------------------------------------------------------
// Fixture G — MALICIOUS REDIRECT: a credential is never forwarded
// ---------------------------------------------------------------------------

// The target redirects an authenticated request to another origin. If the
// credential followed, the operator's token would be handed to a host they never
// authorized — the worst outcome this tool can produce.
func TestM1_MaliciousRedirectNeverForwardsTheCredential(t *testing.T) {
	var evilRequests atomic.Int64
	var evilSawCredential atomic.Bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilRequests.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), evalToken) {
			evilSawCredential.Store(true)
		}
		w.WriteHeader(200)
	}))
	defer evil.Close()

	mux := http.NewServeMux()
	// Every request to the protected operation is redirected off-origin.
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", evil.URL+"/collect")
		w.WriteHeader(302)
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", evil.URL+"/collect")
		w.WriteHeader(302)
	})

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	if n := evilRequests.Load(); n != 0 {
		t.Fatalf("the off-origin host received %d requests; redirects must never be followed", n)
	}
	if evilSawCredential.Load() {
		t.Fatal("the credential reached an unauthorized origin")
	}
	// And nothing was confirmed off the back of a redirect.
	for _, f := range findingsFor(res, theProtectedOperation) {
		if f.State == model.StateConfirmed {
			t.Errorf("a redirect produced a confirmed finding: %+v", f.Verification)
		}
	}
}

// A redirect to another origin must also be refused if anything ever tried to
// follow it, so the guarantee does not rest on one call site.
func TestM1_OffOriginRedirectTargetIsOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	if d := pol.CheckURL("http://attacker.example/collect"); d.Allowed {
		t.Fatal("an off-origin redirect target was inside scope")
	}
}

// ---------------------------------------------------------------------------
// Fixture H — SECRET LEAKAGE: end to end, nothing persists the credential
// ---------------------------------------------------------------------------

// A real assessment is run, its evidence and both report formats are written to
// a real run directory, and every byte of that directory is searched for the
// credential.
//
// This is deliberately not a unit test of the redactor. Redaction working in
// isolation says nothing about whether every path that writes a file actually
// goes through it.
func TestM1_CredentialNeverReachesDisk(t *testing.T) {
	mux := http.NewServeMux()
	// A maximally hostile target: it reflects the credential in a header, in a
	// body, and in a URL it asks to be followed.
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo-Auth", auth)
		w.Header().Set("Location", "http://127.0.0.1:1/?leaked="+strings.TrimPrefix(auth, "Bearer "))
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 7, "email": "owner@example.test", "role": "admin", "youSent": auth,
		})
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	dir := t.TempDir()
	run, err := store.Create(dir, "20260906T120000Z-eval0001", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	res, red := runWithIdentityAndSink(t, mux, identityOptions{canaryPath: "/api/me"}, run.PutEvidence)
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

	// The whole run directory: evidence, both reports, metadata, the key file.
	var checked int
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
		if strings.Contains(string(b), evalToken) {
			rel, _ := filepath.Rel(dir, path)
			t.Errorf("the credential was written to %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("no files were written, so the search proved nothing")
	}

	// And it is absent from the in-memory report the CLI prints, too.
	for name, text := range map[string]string{
		"json report":  jsonBuf.String(),
		"sarif report": sarifBuf.String(),
		"summary":      report.Summary(doc),
	} {
		if strings.Contains(text, evalToken) {
			t.Errorf("the credential appears in the %s", name)
		}
	}

	// The target really did reflect the credential, and redaction is what
	// removed it. Without this the fixture could pass simply because nothing
	// ever carried the token.
	//
	// Evidence lives in its own files rather than inside the report, so the
	// placeholder is looked for there.
	evidenceDir := filepath.Join(dir, "runs", "20260906T120000Z-eval0001", "evidence")
	evidence, err := os.ReadDir(evidenceDir)
	if err != nil {
		t.Fatalf("evidence directory: %v", err)
	}
	var sawPlaceholder bool
	for _, e := range evidence {
		b, rerr := os.ReadFile(filepath.Join(evidenceDir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if strings.Contains(string(b), redact.Placeholder) {
			sawPlaceholder = true
		}
	}
	if !sawPlaceholder {
		t.Error("no redaction placeholder appears in any evidence file; the fixture may not have " +
			"reflected the credential at all, in which case it proves nothing")
	}
}

// runWithIdentityAndSink is runWithIdentity with evidence persistence, used by
// the leakage fixture.
func runWithIdentityAndSink(
	t *testing.T,
	handler http.Handler,
	opt identityOptions,
	sink func(model.Exchange) (string, error),
) (engine.Result, *redact.Redactor) {
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

	const envName = "APPSEC_EVAL_TOKEN"
	t.Setenv(envName, evalToken)
	id := identity.Identity{
		ID:   "admin",
		Auth: identity.Authentication{Scheme: identity.SchemeBearer, Credential: identity.CredentialSource{Env: envName}},
	}
	if opt.canaryPath != "" {
		id.Live = identity.Liveness{Method: http.MethodGet, Path: opt.canaryPath}
	}
	ids := identity.Resolve([]identity.Identity{id}, srv.URL, client, red)

	parsed, err := openapi.Parse([]byte(spec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	res, err := engine.Run(context.Background(), engine.Options{
		RunID:   "20260906T120000Z-eval0001",
		Target:  srv.URL,
		Profile: model.ProfileVerification,
		Surface: engine.Surface{SpecDerived: true, Operations: parsed.Operations, Fidelity: parsed.Fidelity},
		Checks: []engine.Check{check.AuthRequired{
			Client: client, BaselineProbes: 2, Control: ids.Primary(),
		}},
		Concurrency:       2,
		RequestsPerSecond: 200,
		Identities:        ids,
		EvidenceSink:      sink,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res, red
}

// mentions reports whether any entry contains substr.
func mentions(entries []string, substr string) bool {
	for _, e := range entries {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// A run with no identity configured must behave exactly as it did before
// identities existed. M1 must not change M0's verdicts.
func TestM1_NoIdentityPreservesM0Behaviour(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", jsonHandler(200, theRecord()))
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runAgainst(t, mux)
	f := theFinding(t, res)
	if f.State != model.StateSuspected {
		t.Errorf("state = %s, want suspected with no identity configured", f.State)
	}
	if !mentions(f.Verification.Unavailable, "no identity is configured") {
		t.Errorf("the absent control is not named: %v", f.Verification.Unavailable)
	}
	for _, e := range res.Coverage {
		if e.Dimension == engine.DimensionIdentity {
			t.Errorf("an identity ledger row appeared with no identity configured: %+v", e)
		}
	}
	if len(res.Identities) != 0 {
		t.Errorf("identities reported with none configured: %+v", res.Identities)
	}
}

// ---------------------------------------------------------------------------
// Adversarial: the two failures that would discredit the tool
// ---------------------------------------------------------------------------

// FALSE ASSURANCE. No credential state may make an operation look protected.
//
// Every one of these targets serves the protected record to anonymous callers,
// so every one of them is vulnerable. The credential varies from absent to dead.
// Whatever the credential is doing, the anonymous bypass must still be reported
// and the row must never come back clean.
func TestM1_NoCredentialStateCanProduceAPass(t *testing.T) {
	tests := []struct {
		name    string
		opt     identityOptions
		canary  http.HandlerFunc
		profile http.HandlerFunc
	}{
		{
			name:    "credential absent",
			opt:     identityOptions{},
			profile: jsonHandler(200, theRecord()),
		},
		{
			name:    "credential unset in the environment",
			opt:     identityOptions{unset: true},
			profile: jsonHandler(200, theRecord()),
		},
		{
			name:    "credential rejected",
			opt:     identityOptions{canaryPath: "/api/me"},
			canary:  jsonHandler(401, map[string]any{"message": "invalid credentials"}),
			profile: jsonHandler(200, theRecord()),
		},
		{
			name:    "canary endpoint does not exist",
			opt:     identityOptions{canaryPath: "/api/me"},
			canary:  jsonHandler(404, map[string]any{"message": "not found"}),
			profile: jsonHandler(200, theRecord()),
		},
		{
			name:    "canary times out into a transport failure",
			opt:     identityOptions{canaryPath: "/api/me"},
			canary:  func(w http.ResponseWriter, _ *http.Request) { panic(http.ErrAbortHandler) },
			profile: jsonHandler(200, theRecord()),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/profile", tc.profile)
			mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
			if tc.canary != nil {
				mux.HandleFunc("/api/me", tc.canary)
			}
			mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

			res, _ := runWithIdentity(t, mux, tc.opt)

			// The bypass is reported.
			if got := findingsFor(res, theProtectedOperation); len(got) == 0 {
				t.Fatal("a real anonymous bypass went unreported because of the credential state")
			}
			// And the ledger never says this operation was cleanly tested with
			// nothing to report.
			row := operationRow(t, res, theProtectedOperation)
			if row.Disposition == model.DispositionExecuted && row.Detail == "" {
				t.Error("the operation row is clean and silent despite an unusable identity")
			}
		})
	}
}

// FALSE CONFIRMATION. A cached control response may be the anonymous response
// replayed by an intermediary, which would make the two trivially equivalent.
func TestM1_CachedControlDoesNotConfirm(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			// An intermediary answering from cache: same document, cache hit.
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Age", "37")
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(theRecord())
	})
	mux.HandleFunc("/api/health", jsonHandler(200, map[string]any{"status": "ok"}))
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", jsonHandler(404, map[string]any{"message": "not found"}))

	res, _ := runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	found := findingsFor(res, theProtectedOperation)
	if len(found) == 0 {
		t.Fatal("no finding at all, so this test would pass vacuously")
	}
	for _, f := range found {
		if f.State == model.StateConfirmed {
			t.Fatal("a cached control response confirmed a bypass; it may have been the " +
				"anonymous response replayed")
		}
		if !mentions(f.Verification.Unavailable, "cache") {
			t.Errorf("the cache is not named as the reason the control was unusable: %v",
				f.Verification.Unavailable)
		}
	}
}

// The anonymous probes must never carry a credential. If they did, the check
// would be comparing an authenticated response with another authenticated
// response and would confirm everything.
func TestM1_AnonymousProbesCarryNoCredential(t *testing.T) {
	var anonymousWithAuth atomic.Int64
	var sawBearer atomic.Bool
	mux := http.NewServeMux()
	record := func(r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, evalToken) {
			sawBearer.Store(true)
		}
	}
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		jsonHandler(200, theRecord())(w, r)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if strings.Contains(r.Header.Get("Authorization"), evalToken) {
			anonymousWithAuth.Add(1)
		}
		jsonHandler(200, map[string]any{"status": "ok"})(w, r)
	})
	mux.HandleFunc("/api/me", authOnly(200, map[string]any{"id": 7}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Baseline probes hit here. None of them is an authenticated request.
		if strings.Contains(r.Header.Get("Authorization"), evalToken) {
			anonymousWithAuth.Add(1)
		}
		jsonHandler(404, map[string]any{"message": "not found"})(w, r)
	})

	runWithIdentity(t, mux, identityOptions{canaryPath: "/api/me"})

	if !sawBearer.Load() {
		t.Fatal("no authenticated request was made at all, so this proves nothing")
	}
	if n := anonymousWithAuth.Load(); n != 0 {
		t.Fatalf("%d baseline or public-operation requests carried the credential", n)
	}
}
