package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Execute(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// Exit codes are a public contract, so each has a test.
func TestExitCodeMeaningsAreDefined(t *testing.T) {
	for _, c := range []int{ExitOK, ExitFindings, ExitUsage, ExitNothingExecuted, ExitAborted, ExitInternal} {
		if ExitCodeMeaning(c) == "unknown" {
			t.Errorf("exit code %d has no documented meaning", c)
		}
	}
	if ExitCodeMeaning(99) != "unknown" {
		t.Error("an undefined code should report unknown")
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{ExitOK, ExitFindings, ExitUsage, ExitNothingExecuted, ExitAborted, ExitInternal} {
		if seen[c] {
			t.Fatalf("exit code %d is duplicated", c)
		}
		seen[c] = true
	}
}

func TestScanWithNoTargetFailsWithUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	code, _, errOut := run(t, "scan")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "assay scan http://localhost:3000") {
		t.Errorf("error does not suggest the next command: %q", errOut)
	}
}

func TestInvalidProfileFailsWithUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	code, _, errOut := run(t, "scan", "http://127.0.0.1:1/", "--profile", "aggressive")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "discovery, verification, intrusive") {
		t.Errorf("error does not list valid profiles: %q", errOut)
	}
}

// A target with no discoverable specification must abort with an explanation,
// not report a clean run.
func TestNoSpecificationAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	code, _, errOut := run(t, "scan", srv.URL)
	if code != ExitAborted {
		t.Fatalf("exit = %d, want %d (aborted)", code, ExitAborted)
	}
	if !strings.Contains(strings.ToLower(errOut), "openapi") {
		t.Errorf("error does not explain the missing oracle: %q", errOut)
	}
}

// A run where every planned item was blocked must NOT return success.
func TestAllBlockedRunDoesNotReportSuccess(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{"/api/orders":{"post":{"security":[{"bearer":[]}]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(spec))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	// POST requires the intrusive profile, so nothing may run.
	code, _, errOut := run(t, "scan", srv.URL)
	if code != ExitNothingExecuted {
		t.Fatalf("exit = %d, want %d (nothing executed)", code, ExitNothingExecuted)
	}
	if !strings.Contains(errOut, "establishes nothing") {
		t.Errorf("stderr does not warn that nothing was established: %q", errOut)
	}
}

// The full path: discover, plan, execute, report.
func TestScanProducesReportAndLedger(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{
	    "/api/open":{"get":{"security":[]}},
	    "/api/protected":{"get":{"security":[{"bearer":[]}]}}
	  }}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(spec))
		case "/api/open":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/protected":
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)

	code, out, _ := run(t, "scan", srv.URL)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	// The summary wraps for the terminal, so compare on normalized whitespace.
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "does not establish that the target is secure") {
		t.Errorf("summary omits the assurance statement: %q", out)
	}

	matches, err := filepath.Glob(filepath.Join(dir, ".assay", "runs", "*", "report.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("report not written: %v %v", matches, err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc["schemaVersion"] == nil {
		t.Error("report has no schemaVersion")
	}
	if rows, _ := doc["coverage"].([]any); len(rows) != 2 {
		t.Errorf("coverage rows = %d, want 2", len(rows))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(matches[0]), "report.sarif")); err != nil {
		t.Errorf("SARIF not written: %v", err)
	}

	// Evidence must actually reach disk and be referenced, or the report's
	// evidenceRefs are a claim with nothing behind them.
	evidence, err := os.ReadDir(filepath.Join(filepath.Dir(matches[0]), "evidence"))
	if err != nil || len(evidence) == 0 {
		t.Fatalf("no evidence was stored: %v (%d files)", err, len(evidence))
	}
	cov, _ := doc["coverage"].([]any)
	sawRefs := false
	for _, row := range cov {
		m := row.(map[string]any)
		if refs, ok := m["evidenceRefs"].([]any); ok && len(refs) > 0 {
			sawRefs = true
			if s, _ := refs[0].(string); !strings.HasPrefix(s, "sha256:") {
				t.Errorf("evidence ref %q is not algorithm-prefixed", s)
			}
		}
	}
	if !sawRefs {
		t.Error("no coverage row references stored evidence")
	}
	info, err := os.Stat(filepath.Dir(matches[0]))
	if err == nil && info.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode = %o, want 700", info.Mode().Perm())
	}
}

// A run where scope refused everything must say so. Reporting "no document
// found" would misdescribe a refusal as an absence, which is the failure this
// project exists to prevent.
func TestScopeRefusalIsNotReportedAsNothingFound(t *testing.T) {
	t.Chdir(t.TempDir())
	// Cloud metadata is denied unconditionally, so every probe is refused.
	code, _, errOut := run(t, "scan", "http://169.254.169.254/")
	if code != ExitAborted {
		t.Fatalf("exit = %d, want %d", code, ExitAborted)
	}
	if !strings.Contains(errOut, "refused by the scope policy") {
		t.Errorf("a scope refusal was not reported as such: %q", errOut)
	}
	if !strings.Contains(errOut, "not a clean result") {
		t.Errorf("the refusal is not clearly distinguished from a clean result: %q", errOut)
	}
	if strings.Contains(errOut, "no OpenAPI document found") {
		t.Errorf("a scope refusal was misdescribed as a missing document: %q", errOut)
	}
}

func TestInitWritesConfigAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if code, _, _ := run(t, "init"); code != ExitOK {
		t.Fatalf("init exit = %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "assay.yaml"))
	if err != nil {
		t.Fatalf("assay.yaml not written: %v", err)
	}
	if !strings.Contains(string(data), "apiVersion: assay/v1alpha1") {
		t.Error("generated config has no apiVersion")
	}
	info, err := os.Stat(filepath.Join(dir, "assay.yaml"))
	if err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("assay.yaml mode = %o, want 600", info.Mode().Perm())
	}

	if code, _, _ := run(t, "init"); code != ExitUsage {
		t.Error("init overwrote an existing config without --force")
	}
	if code, _, _ := run(t, "init", "--force"); code != ExitOK {
		t.Error("init --force failed")
	}
}

// The generated config must itself be valid, or the first thing a user does
// fails.
func TestGeneratedConfigIsValid(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, _, _ := run(t, "init"); code != ExitOK {
		t.Fatal("init failed")
	}
	_, _, errOut := run(t, "scan", "http://127.0.0.1:1/")
	if strings.Contains(errOut, "unknown field") || strings.Contains(errOut, "apiVersion") {
		t.Fatalf("generated config does not parse: %q", errOut)
	}
}

func TestDoctorReportsMissingEnginesWithoutFailing(t *testing.T) {
	code, out, _ := run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	for _, want := range []string{"OWASP ZAP", "Nuclei", "Hadrian", "none are bundled"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q", want)
		}
	}
}

// The help text must not promise assurance.
func TestRootHelpDisclaimsAssurance(t *testing.T) {
	_, out, _ := run(t, "--help")
	if !strings.Contains(out, "does not prove the absence of vulnerabilities") {
		t.Error("root help does not disclaim assurance")
	}
	if !strings.Contains(out, "authorized to test") {
		t.Error("root help does not state the authorization requirement")
	}
}

// A hostname is not the address it resolves to. Deciding loopback from a string
// prefix would let an attacker-registrable name such as "127.0.0.1.nip.io"
// silently enable private addressing for the whole run.
func TestLoopbackDetectionUsesAddressesNotPrefixes(t *testing.T) {
	loopback := []string{
		"http://localhost:3000", "http://127.0.0.1:3000",
		"http://127.5.5.5:3000", "http://[::1]:3000",
	}
	for _, u := range loopback {
		if !isLoopbackTarget(u) {
			t.Errorf("isLoopbackTarget(%q) = false, want true", u)
		}
	}
	notLoopback := []string{
		"http://127.0.0.1.nip.io", // attacker-registrable name
		"http://127.0.0.1.example.com",
		"http://1270.0.0.1",
		"http://example.com",
		"http://localhost.evil.com",
	}
	for _, u := range notLoopback {
		if isLoopbackTarget(u) {
			t.Errorf("isLoopbackTarget(%q) = true; a name must never be assumed to be loopback", u)
		}
	}
}

// A detected authentication bypass must fail a pipeline. The only shipped check
// cannot reach "confirmed" without credentials, so gating solely on confirmed
// findings would exit zero on a real bypass.
func TestSuspectedHighFindingFailsThePolicy(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{
	    "/api/open":{"get":{"security":[]}},
	    "/api/admin":{"get":{"security":[{"bearer":[]}]}}
	  }}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(spec))
		case "/api/admin": // declared protected, served to anyone
			_, _ = w.Write([]byte(`{"users":[{"id":1,"email":"a@b.test","role":"admin"}]}`))
		case "/api/open":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	code, _, errOut := run(t, "scan", srv.URL)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d; a detected bypass must fail the build", code, ExitFindings)
	}
	if !strings.Contains(errOut, "policy threshold exceeded") {
		t.Errorf("stderr does not explain the failure: %q", errOut)
	}
}
