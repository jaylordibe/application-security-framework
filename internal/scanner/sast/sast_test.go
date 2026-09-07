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
	// opengrep has no telemetry to disable and no --disable-version-check: it
	// removed the feature rather than making it configurable. Asserting those
	// flags here asserted a bug, and the real binary rejected the invocation
	// outright. What must hold for opengrep is structured output and no network
	// behaviour it does not need.
	args := strings.Join(inv.Spec.Args, " ")
	if !strings.Contains(args, "--json") {
		t.Errorf("the invocation omits --json: %s", args)
	}
	for _, absent := range []string{"--metrics", "--disable-version-check"} {
		if strings.Contains(args, absent) {
			t.Errorf("opengrep was passed %s, which its CLI rejects: %s", absent, args)
		}
	}
	if inv.Provenance.Verified {
		t.Error("a user-installed binary was reported as verified")
	}

	// Semgrep does have telemetry, and it stays off.
	sg, err := Engine{}.Invocation(
		scanner.Target{SourceRoot: t.TempDir(), Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true, RuleSource: rules},
		scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "o.json")},
		scanner.Availability{Present: true, Path: "/usr/local/bin/semgrep", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	sgArgs := strings.Join(sg.Spec.Args, " ")
	for _, required := range []string{"--metrics=off", "--disable-version-check", "--json"} {
		if !strings.Contains(sgArgs, required) {
			t.Errorf("the semgrep invocation omits %s: %s", required, sgArgs)
		}
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

// The profiles grade risk to the target, and this engine sends the target
// nothing: it reads a local checkout and never opens a socket. Requiring
// verification made the safest engine unavailable at the safest profile.
func TestSourceAnalysisRunsAtTheLowestProfile(t *testing.T) {
	if got := (Engine{}).RequiredProfile(scanner.Settings{}); got != model.ProfileDiscovery {
		t.Errorf("required profile = %s, want discovery: this engine makes no request to the "+
			"target, so no profile above the lowest can be justified", got)
	}
	// And it must be permitted at every higher profile too.
	for _, p := range []model.Profile{
		model.ProfileDiscovery, model.ProfileVerification, model.ProfileIntrusive,
	} {
		if !p.Permits(Engine{}.RequiredProfile(scanner.Settings{})) {
			t.Errorf("profile %s does not permit source analysis", p)
		}
	}
}

// M4 recorded that supporting opengrep alongside Semgrep "cost a name in a
// list", on the belief that the fork shares Semgrep's command line. Running the
// real opengrep v1.29.0 during the release gate showed otherwise, and the
// consequence was that the *preferred* engine could never run: every invocation
// exited 2 with "unknown option '--metrics'".
func TestOpengrepAndSemgrepGetDifferentArgumentVectors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "r.json")}
	settings := scanner.Settings{Enabled: true, RuleSource: dir}
	target := scanner.Target{SourceRoot: src, Profile: model.ProfileVerification}

	// Flags verified absent from the installed opengrep's own `scan --help`.
	absentFromOpengrep := []string{
		"--metrics=off", "--output", "--disable-version-check", "--quiet",
		"--timeout", "--max-target-bytes",
	}

	og, err := Engine{}.Invocation(target, settings, w,
		scanner.Availability{Present: true, Path: "/usr/local/bin/opengrep", Version: "1.29.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range absentFromOpengrep {
		for _, a := range og.Spec.Args {
			if a == flag {
				t.Errorf("opengrep was passed %s, which its CLI does not accept", flag)
			}
		}
	}
	if !contains(og.Spec.Args, "--json") || !contains(og.Spec.Args, "--no-rewrite-rule-ids") {
		t.Errorf("opengrep lost a flag it needs: %v", og.Spec.Args)
	}

	sg, err := Engine{}.Invocation(target, settings, w,
		scanner.Availability{Present: true, Path: "/usr/local/bin/semgrep", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	// Semgrep keeps telemetry suppression, which is the whole reason the flag
	// existed: opengrep has no telemetry to suppress.
	if !contains(sg.Spec.Args, "--metrics=off") {
		t.Errorf("semgrep lost --metrics=off: %v", sg.Spec.Args)
	}
	if !contains(sg.Spec.Args, "--no-rewrite-rule-ids") {
		t.Errorf("semgrep lost --no-rewrite-rule-ids: %v", sg.Spec.Args)
	}
}

// A rule id that carries the operator's rules-directory path changes between
// runs whenever that directory is temporary or per-checkout, which breaks both
// finding deduplication and the reproducibility this project claims.
func TestRuleIdsAreNotRewrittenToIncludeLocalPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/usr/local/bin/opengrep", "/usr/local/bin/semgrep"} {
		inv, err := Engine{}.Invocation(
			scanner.Target{SourceRoot: t.TempDir(), Profile: model.ProfileVerification},
			scanner.Settings{Enabled: true, RuleSource: dir},
			scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "o.json")},
			scanner.Availability{Present: true, Path: path, Version: "1"})
		if err != nil {
			t.Fatal(err)
		}
		if !contains(inv.Spec.Args, "--no-rewrite-rule-ids") {
			t.Errorf("%s: rule ids would be rewritten to include the rules path: %v",
				filepath.Base(path), inv.Spec.Args)
		}
	}
}

func contains(all []string, want string) bool {
	for _, a := range all {
		if a == want {
			return true
		}
	}
	return false
}
