package zap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// A ZAP JSON report of the shape `zap.sh -cmd -quickout` writes.
const sample = `{"@version":"2.15.0","site":[{"@name":"http://127.0.0.1:8080",
 "alerts":[{"pluginid":"40018","alertRef":"40018-1","name":"SQL Injection",
   "riskcode":"3","confidence":"2","riskdesc":"High (Medium)",
   "desc":"SQL injection may be possible.","cweid":"89","wascid":"19",
   "instances":[{"uri":"http://127.0.0.1:8080/search?q=1","method":"GET","param":"q",
     "evidence":"syntax error"}]},
  {"pluginid":"10021","alertRef":"10021","name":"X-Content-Type-Options Missing",
   "riskcode":"1","confidence":"3","desc":"Header missing.","cweid":"693","wascid":"15",
   "instances":[{"uri":"http://127.0.0.1:8080/","method":"GET","param":"","evidence":""}]}]}]}`

func normalize(t *testing.T, body string, s scanner.Settings) scanner.Normalized {
	t.Helper()
	dir := t.TempDir()
	w := scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "report.json")}
	if err := os.WriteFile(w.OutputPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Engine{}.Normalize(nil, w, scanner.Provenance{Engine: "zap"}, s)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return n
}

// ZAP's own risk and confidence scales must survive intact. Four risks and five
// confidences do not map onto AppSec's scales, and converting would invent an
// assessment nobody made.
func TestNormalizePreservesZAPScalesVerbatim(t *testing.T) {
	n := normalize(t, sample, scanner.Settings{Extra: map[string]string{"mode": "active"}})
	if len(n.Observations) != 2 {
		t.Fatalf("observations = %d, want 2", len(n.Observations))
	}
	sqli := n.Observations[0]
	if sqli.RuleID != "40018-1" {
		t.Errorf("RuleID = %q, want the alertRef", sqli.RuleID)
	}
	if sqli.SourceSeverity != "High" {
		t.Errorf("SourceSeverity = %q, want ZAP's own label for riskcode 3", sqli.SourceSeverity)
	}
	if sqli.SourceConfidence != "Medium" {
		t.Errorf("SourceConfidence = %q, want ZAP's own label for confidence 2", sqli.SourceConfidence)
	}
	if sqli.Parameter != "q" {
		t.Errorf("Parameter = %q; the implicated input is what makes an alert actionable", sqli.Parameter)
	}
	refs := strings.Join(sqli.References, ",")
	if !strings.Contains(refs, "CWE-89") || !strings.Contains(refs, "WASC-19") {
		t.Errorf("references = %v", sqli.References)
	}
}

// The central §30 rule: a passive scan did not attempt injection, so it must not
// claim that class.
func TestPassiveModeClaimsNoActiveCoverage(t *testing.T) {
	passive := normalize(t, sample, scanner.Settings{})
	if len(passive.Covered) != 0 {
		t.Fatalf("a passive ZAP run claimed coverage %v; its passive rules observe responses and "+
			"do not send the payloads that would test injection", passive.Covered)
	}
	if !mentions(passive.Limitations, "were NOT assessed by it") {
		t.Errorf("the passive limitation is not stated: %v", passive.Limitations)
	}

	active := normalize(t, sample, scanner.Settings{Extra: map[string]string{"mode": "active"}})
	if len(active.Covered) == 0 {
		t.Error("an active ZAP run claimed no coverage at all")
	}
}

// Active scanning is an attack and must be gated at intrusive; passive is not.
func TestProfileGatingFollowsMode(t *testing.T) {
	if got := (Engine{}).RequiredProfile(scanner.Settings{}); got != model.ProfileVerification {
		t.Errorf("passive required profile = %s, want verification", got)
	}
	got := Engine{}.RequiredProfile(scanner.Settings{Extra: map[string]string{"mode": "active"}})
	if got != model.ProfileIntrusive {
		t.Errorf("active required profile = %s, want intrusive: the active scanner sends attack "+
			"payloads", got)
	}
}

// ZAP must not accumulate state in the operator's home directory, and must not
// be handed credentials.
func TestInvocationIsolatesZAPState(t *testing.T) {
	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "r.json")}
	inv, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true}, w,
		scanner.Availability{Present: true, Path: "/opt/zap/zap.sh", Version: "2.15.0"})
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	args := strings.Join(inv.Spec.Args, " ")
	if !strings.Contains(args, "-cmd") {
		t.Error("ZAP was not run in one-shot mode; a daemon has a lifecycle this does not manage")
	}
	if !strings.Contains(args, "-dir "+filepath.Join(w.Dir, "zap-home")) {
		t.Errorf("ZAP was not given a private home inside the workspace: %s", args)
	}
	if _, err := os.Stat(filepath.Join(w.Dir, "zap-home")); err != nil {
		t.Error("the private ZAP home was not created")
	}
	// The JVM launcher genuinely needs these; nothing else, and no credential.
	for _, name := range inv.EnvNames {
		switch name {
		case "JAVA_HOME", "PATH", "TMPDIR":
		default:
			t.Errorf("ZAP asked for the environment variable %q", name)
		}
	}
	if inv.Provenance.Verified {
		t.Error("a user-installed binary was reported as verified")
	}
}

// A report that will not parse is a failure, not an empty result.
func TestMalformedReportIsAnError(t *testing.T) {
	dir := t.TempDir()
	w := scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "report.json")}
	if err := os.WriteFile(w.OutputPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Engine{}).Normalize(nil, w, scanner.Provenance{}, scanner.Settings{}); err == nil {
		t.Fatal("a malformed ZAP report was accepted as an empty result")
	}
}

// A missing report with no stdout is a failure too.
func TestMissingReportIsAnError(t *testing.T) {
	dir := t.TempDir()
	w := scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "absent.json")}
	if _, err := (Engine{}).Normalize(nil, w, scanner.Provenance{}, scanner.Settings{}); err == nil {
		t.Fatal("a missing ZAP report was accepted as an empty result")
	}
}

// ZAP's unauthenticated operation and unpinned add-on state must be stated.
func TestLimitationsAreStated(t *testing.T) {
	n := normalize(t, sample, scanner.Settings{})
	for _, want := range []string{
		"does not pass identity credentials",
		"which AppSec Framework does not pin",
		"cannot constrain where a ZAP rule sends a request",
	} {
		if !mentions(n.Limitations, want) {
			t.Errorf("limitations do not mention %q: %v", want, n.Limitations)
		}
	}
}

// An alert with no instances still yields one observation rather than vanishing.
func TestAlertWithoutInstancesIsStillReported(t *testing.T) {
	n := normalize(t, `{"site":[{"@name":"http://x/","alerts":[
	  {"pluginid":"1","name":"Something","riskcode":"2","confidence":"1","instances":[]}]}]}`,
		scanner.Settings{})
	if len(n.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(n.Observations))
	}
}

// Evidence is a fragment of a target response and is imported, but the caller
// sanitizes and redacts it. This asserts it is carried, not that it is trusted.
func TestEvidenceIsCarriedForTriage(t *testing.T) {
	n := normalize(t, sample, scanner.Settings{})
	if n.Observations[0].Evidence != "syntax error" {
		t.Errorf("evidence = %q; without it an alert cannot be triaged", n.Observations[0].Evidence)
	}
	whole, _ := json.Marshal(n.Observations)
	if strings.Contains(string(whole), "@version") {
		t.Error("report metadata leaked into observations")
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

// zap.sh talks about the JVM before it starts it, and the first version-shaped
// token in its output is Java's. Recording that as the engine version is a
// provenance failure, and provenance is most of what this project claims to add
// over running the scanner directly.
func TestVersionIsZAPsOwnNotTheJVMs(t *testing.T) {
	// Verbatim from ZAP 2.17.0 on JDK 21.
	const real = "Found Java version 21.0.2\n" +
		"Available memory: 36864 MB\n" +
		"Using JVM args: -Xmx9216m\n" +
		"2.17.0\n"

	if got := parseVersion(real); got != "2.17.0" {
		t.Errorf("parseVersion = %q, want ZAP's own 2.17.0 rather than the JVM's", got)
	}

	// The update warning appears on stderr after the version on some installs.
	const withWarning = "Found Java version 21.0.2\n2.17.0\n" +
		"No check for updates for over 3 month - add-ons may well be out of date\n"
	if got := parseVersion(withWarning); got != "2.17.0" {
		t.Errorf("parseVersion = %q with a trailing warning, want 2.17.0", got)
	}

	for _, none := range []string{"", "Found Java version 21.0.2", "no version here\n"} {
		if got := parseVersion(none); got != "" {
			t.Errorf("parseVersion(%q) = %q, want empty: only ZAP's own line counts", none, got)
		}
	}
}

// The launcher needs a JVM, and it locates one with JAVA_HOME and PATH. Probing
// it with no environment at all meant zap.sh exited 1 and ZAP was reported as
// not installed — so it could never be detected on a normal installation.
func TestTheVersionProbeGetsTheEnvironmentTheLauncherNeeds(t *testing.T) {
	want := map[string]bool{"JAVA_HOME": true, "PATH": true, "TMPDIR": true}
	for _, n := range launcherEnvNames {
		if !want[n] {
			t.Errorf("the launcher is given %q, which it does not need", n)
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("the launcher is not given %q and cannot find a JVM without it", n)
	}

	// And the scan uses the same list, so detection and execution cannot drift.
	dir := t.TempDir()
	inv, err := Engine{}.Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		scanner.Settings{Enabled: true},
		scanner.Workspace{Dir: dir, OutputPath: filepath.Join(dir, "z.json")},
		scanner.Availability{Present: true, Path: "/opt/zap/zap.sh", Version: "2.17.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.EnvNames) != len(launcherEnvNames) {
		t.Errorf("the scan declares %v, the probe uses %v", inv.EnvNames, launcherEnvNames)
	}
}
