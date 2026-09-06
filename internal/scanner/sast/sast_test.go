package sast

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// A Semgrep/opengrep --json document.
const sample = `{"results":[
  {"check_id":"go.lang.security.audit.sqli","path":"internal/db/query.go",
   "start":{"line":42},"end":{"line":42},
   "extra":{"message":"Detected string concatenation in a SQL query.",
     "severity":"ERROR","lines":"  db.Query(\"SELECT * FROM t WHERE id=\" + id)",
     "metadata":{"cwe":["CWE-89: Improper Neutralization"],"confidence":"HIGH"}}}],
 "errors":[],"paths":{"scanned":["internal/db/query.go","main.go"]}}`

func normalize(t *testing.T, body string) scanner.Normalized {
	t.Helper()
	dir := t.TempDir()
	w := scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "out.json")}
	if err := os.WriteFile(w.OutputPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Engine{}.Normalize(nil, w,
		scanner.Provenance{Engine: "sast", RuleSource: "local rules"}, scanner.Settings{})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return n
}

// The engine's own severity scale — ERROR, WARNING, INFO — is a third scale
// again and must not be converted.
func TestNormalizePreservesTheAnalysersScale(t *testing.T) {
	n := normalize(t, sample)
	if len(n.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(n.Observations))
	}
	o := n.Observations[0]
	if o.RuleID != "go.lang.security.audit.sqli" {
		t.Errorf("RuleID = %q", o.RuleID)
	}
	if o.SourceSeverity != "ERROR" {
		t.Errorf("SourceSeverity = %q, want the analyser's own value", o.SourceSeverity)
	}
	if o.SourceConfidence != "HIGH" {
		t.Errorf("SourceConfidence = %q", o.SourceConfidence)
	}
	if o.Location != "internal/db/query.go:42" {
		t.Errorf("Location = %q, want file:line", o.Location)
	}
	if !strings.Contains(strings.Join(o.References, ","), "CWE-89") {
		t.Errorf("references = %v", o.References)
	}
}

// The matched source lines are the application's own code, and secrets live in
// source. A report that quotes them copies an application into an artefact
// attached to tickets.
func TestMatchedSourceIsNotImported(t *testing.T) {
	n := normalize(t, sample)
	whole, _ := json.Marshal(n.Observations)
	if strings.Contains(string(whole), "SELECT * FROM t") {
		t.Fatalf("the matched source lines were imported: %s", whole)
	}
}

// A source observation is not runtime proof, and the limitation must say so.
func TestStaticFindingsAreNotRuntimeProof(t *testing.T) {
	n := normalize(t, sample)
	if !mentions(n.Limitations, "not evidence that anything is reachable or exploitable at runtime") {
		t.Errorf("the static/runtime distinction is not stated: %v", n.Limitations)
	}
}

// Registry rule identifiers would fetch over the network and, for Semgrep, turn
// telemetry on. Only local paths are accepted.
func TestRegistryRuleSourcesAreRefused(t *testing.T) {
	for _, rules := range []string{ // appsec:refuses-registry
		"p/default", "r/go", "auto", "https://example.test/rules.yaml", // appsec:refuses-registry
	} {
		_, err := Engine{}.Invocation(
			scanner.Target{SourceRoot: t.TempDir(), Profile: model.ProfileVerification},
			scanner.Settings{Enabled: true, RuleSource: rules},
			scanner.Workspace{}, scanner.Availability{Present: true, Path: "/bin/semgrep"})
		if err == nil {
			t.Errorf("the registry rule source %q was accepted", rules)
			continue
		}
		if !strings.Contains(err.Error(), "local") {
			t.Errorf("the refusal of %q does not explain itself: %v", rules, err)
		}
	}
}

// No rules at all is refused rather than defaulting to a registry.
func TestNoRulesIsRefused(t *testing.T) {
	_, err := Engine{}.Invocation(
		scanner.Target{SourceRoot: t.TempDir(), Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true}, scanner.Workspace{},
		scanner.Availability{Present: true, Path: "/bin/semgrep"})
	if err == nil {
		t.Fatal("a scan was invoked with no rules, so the analyser would choose its own")
	}
	if !strings.Contains(err.Error(), "ships no rules") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// Telemetry is off and no network call is made, whichever binary is installed.
func TestInvocationDisablesTelemetryAndNetwork(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := Engine{}.Invocation(
		scanner.Target{SourceRoot: t.TempDir(), Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: rules},
		scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "o.json")},
		scanner.Availability{Present: true, Path: "/usr/local/bin/opengrep", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	args := strings.Join(inv.Spec.Args, " ")
	for _, required := range []string{"--metrics=off", "--disable-version-check", "--json"} {
		if !strings.Contains(args, required) {
			t.Errorf("the invocation omits %s: %s", required, args)
		}
	}
	if inv.Provenance.Verified {
		t.Error("a user-installed binary was reported as verified")
	}
}

// An analyser error makes the result partial, so a half-scanned tree cannot
// claim the class.
func TestAnalyserErrorsMakeTheResultPartial(t *testing.T) {
	n := normalize(t, `{"results":[],"errors":[{"level":"error","message":"parse failure"}],
	  "paths":{"scanned":[]}}`)
	if !n.Partial {
		t.Fatal("an analyser error was reported as a complete scan")
	}
	if len(n.Covered) != 0 {
		t.Fatal("a partial static scan claimed coverage")
	}
}

func TestMalformedOutputIsAnError(t *testing.T) {
	dir := t.TempDir()
	w := scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "o.json")}
	if err := os.WriteFile(w.OutputPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Engine{}).Normalize(nil, w, scanner.Provenance{}, scanner.Settings{}); err == nil {
		t.Fatal("a malformed document was accepted as an empty result")
	}
}

func mentions(all []string, substr string) bool {
	for _, s := range all {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
