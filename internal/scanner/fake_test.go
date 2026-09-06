package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/proc"
)

// The adversarial engine suite.
//
// These build real programs and run them through the real boundary, because
// every property being asserted — descendant cleanup, environment isolation,
// output bounding, hung-pipe protection — lives in the supervision rather than
// in any function that can be called directly. A fake engine that hangs, forks,
// floods and lies is a better test of this code than any real scanner, and it
// keeps CI deterministic and free of third-party binaries.

// buildFake compiles a Go program into a temporary executable.
func buildFake(t *testing.T, name, src string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available to build a fake engine")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot build fake engine: %v\n%s", err, out)
	}
	return bin
}

const fakePreamble = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("fake 9.9.9")
		return
	}
	_ = exec.Command
	_ = strings.Repeat
	_ = time.Sleep
`

// fakeEngine is an Engine whose behaviour the test controls.
type fakeEngine struct {
	bin        string
	caps       []Capability
	profile    model.Profile
	normalize  func(stdout []byte, w Workspace, p Provenance) (Normalized, error)
	envNames   []string
	extraArgs  []string
	detectFail string
}

func (f *fakeEngine) Meta() Meta {
	return Meta{
		ID: "fake", Title: "Fake", Capabilities: f.caps,
		Unlocks: "nothing", InstallHint: "it is a test fixture",
	}
}

func (f *fakeEngine) Detect(context.Context, Settings) Availability {
	if f.detectFail != "" {
		return Availability{Problem: f.detectFail}
	}
	return Availability{Present: true, Path: f.bin, Version: "9.9.9"}
}

func (f *fakeEngine) RequiredProfile(Settings) model.Profile {
	if f.profile != "" {
		return f.profile
	}
	return model.ProfileVerification
}

func (f *fakeEngine) Invocation(t Target, s Settings, w Workspace, a Availability) (Invocation, error) {
	return Invocation{
		Spec:     proc.Spec{Name: "fake", Path: f.bin, Args: append([]string{"scan"}, f.extraArgs...)},
		EnvNames: f.envNames,
		Provenance: Provenance{
			Engine: "fake", Version: a.Version, ExecutablePath: a.Path,
			RuleSource: "test", Verified: false,
		},
	}, nil
}

func (f *fakeEngine) Normalize(stdout []byte, w Workspace, p Provenance, _ Settings) (Normalized, error) {
	if f.normalize != nil {
		return f.normalize(stdout, w, p)
	}
	var obs []Observation
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var o Observation
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			return Normalized{}, err
		}
		obs = append(obs, o)
	}
	return Normalized{Observations: obs, Covered: f.caps}, nil
}

func runFake(t *testing.T, body string, mutate func(*fakeEngine, *Settings, *Target)) Outcome {
	t.Helper()
	e := &fakeEngine{bin: buildFake(t, "fake", fakePreamble+body+"\n}\n")}
	s := Settings{Enabled: true, TimeoutSeconds: 20}
	tgt := Target{BaseURL: "http://127.0.0.1:1", Profile: model.ProfileVerification}
	if mutate != nil {
		mutate(e, &s, &tgt)
	}
	return Run(context.Background(), e, tgt, s, Options{RunID: "test"})
}

// oneResult makes the fake engine emit a single well-formed observation.
const oneResult = "fmt.Println(`" +
	`{"RuleID":"fake-rule","RuleName":"Fake rule","Location":"http://127.0.0.1:1/","SourceSeverity":"critical"}` +
	"`)"

func TestEngineHappyPath(t *testing.T) {
	out := runFake(t, oneResult, nil)
	if out.Status != StatusCompleted {
		t.Fatalf("status = %s (%s)", out.Status, out.Detail)
	}
	if len(out.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(out.Observations))
	}
	if out.Provenance.ExecutablePath == "" || out.Provenance.Version != "9.9.9" {
		t.Errorf("provenance is incomplete: %+v", out.Provenance)
	}
	if out.Provenance.Verified {
		t.Error("a user-installed binary was reported as verified")
	}
}

// A missing scanner must be blocked, never clean.
func TestMissingEngineIsBlockedNotClean(t *testing.T) {
	e := &fakeEngine{detectFail: "executable not found on PATH"}
	out := Run(context.Background(), e,
		Target{Profile: model.ProfileVerification}, Settings{Enabled: true}, Options{})

	if out.Status != StatusBlocked {
		t.Fatalf("status = %s, want blocked", out.Status)
	}
	if out.Cause != model.CauseEngineUnavailable {
		t.Errorf("cause = %s, want engine_unavailable", out.Cause)
	}
	if !strings.Contains(out.Detail, "remain unassessed") {
		t.Errorf("the detail lets a reader mistake absence for a clean result: %q", out.Detail)
	}
	if len(out.Covered) != 0 {
		t.Error("an unavailable engine claimed coverage")
	}
}

// A crashed, malformed, hung or flooding scanner must be blocked, never zero
// findings.
func TestEngineFailuresAreExplicit(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCause model.BlockedCause
		mustSay   string
	}{
		{
			name: "crashes with no output", body: `os.Exit(3)`,
			wantCause: model.CauseEngineUnavailable, mustSay: "produced no results",
		},
		{
			name: "malformed structured output", body: "fmt.Println(`{not json`)",
			wantCause: model.CauseEngineUnavailable, mustSay: "could not be read",
		},
		{
			name: "hangs", body: `time.Sleep(120 * time.Second)`,
			wantCause: model.CauseBudgetExceeded, mustSay: "time budget",
		},
		{
			name:      "floods stdout",
			body:      "for i := 0; i < 200; i++ { fmt.Print(strings.Repeat(\"A\", 1024*1024)) }",
			wantCause: model.CauseBudgetExceeded, mustSay: "refused rather than truncated",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := runFake(t, tc.body, func(e *fakeEngine, s *Settings, _ *Target) {
				if tc.name == "hangs" {
					s.TimeoutSeconds = 2
				}
			})
			if out.Status != StatusBlocked {
				t.Fatalf("status = %s, want blocked (%s)", out.Status, out.Detail)
			}
			if out.Cause != tc.wantCause {
				t.Errorf("cause = %s, want %s", out.Cause, tc.wantCause)
			}
			if !strings.Contains(out.Detail, tc.mustSay) {
				t.Errorf("detail %q does not mention %q", out.Detail, tc.mustSay)
			}
			if len(out.Observations) != 0 {
				t.Error("a failed engine contributed observations")
			}
			if len(out.Covered) != 0 {
				t.Error("a failed engine claimed coverage")
			}
			if !strings.Contains(out.Detail, "remain unassessed") {
				t.Errorf("the failure does not say what was lost: %q", out.Detail)
			}
		})
	}
}

// The most important test here. A scanner runs against a target this tool
// authenticates to; if it could read the environment it would have the
// credentials.
func TestEngineEnvironmentIsBuiltFromNothing(t *testing.T) {
	body := `
	names := []string{}
	for _, kv := range os.Environ() { names = append(names, strings.SplitN(kv, "=", 2)[0]) }
	fmt.Fprintf(os.Stderr, "ENV:%s\n", strings.Join(names, ","))
	` + oneResult

	// Built before the environment is rewritten: the Go toolchain itself needs
	// HOME, and this test is about what the *engine* inherits, not the compiler.
	bin := buildFake(t, "fake", fakePreamble+body+"\n}\n")

	t.Setenv("APPSEC_ADMIN_TOKEN", "identity-bearer-token")
	t.Setenv("GITHUB_TOKEN", "ghp_secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("PGPASSWORD", "db-password")
	t.Setenv("HOME", "/home/appsec")

	t.Run("nothing is inherited by default", func(t *testing.T) {
		out := Run(context.Background(), &fakeEngine{bin: bin},
			Target{Profile: model.ProfileVerification},
			Settings{Enabled: true, TimeoutSeconds: 20}, Options{})
		for _, leaked := range []string{
			"APPSEC_ADMIN_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "PGPASSWORD",
		} {
			if strings.Contains(out.Stderr, leaked) {
				t.Errorf("%s reached the engine's environment", leaked)
			}
		}
		if strings.Contains(out.Stderr, "PATH") {
			t.Error("PATH was inherited; an engine is executed by resolved path")
		}
	})

	t.Run("an engine gets only what it declares", func(t *testing.T) {
		out := Run(context.Background(), &fakeEngine{bin: bin, envNames: []string{"HOME"}},
			Target{Profile: model.ProfileVerification},
			Settings{Enabled: true, TimeoutSeconds: 20}, Options{})
		if !strings.Contains(out.Stderr, "HOME") {
			t.Errorf("a declared variable did not reach the engine: %q", out.Stderr)
		}
		if strings.Contains(out.Stderr, "APPSEC_ADMIN_TOKEN") {
			t.Error("declaring one variable leaked another")
		}
	})

	t.Run("identity credentials are refused even when configured", func(t *testing.T) {
		out := Run(context.Background(), &fakeEngine{bin: bin},
			Target{Profile: model.ProfileVerification},
			Settings{Enabled: true, TimeoutSeconds: 20, PassEnv: []string{"APPSEC_ADMIN_TOKEN", "HOME"}},
			Options{ForbiddenEnv: []string{"APPSEC_ADMIN_TOKEN"}})

		if strings.Contains(out.Stderr, "APPSEC_ADMIN_TOKEN") {
			t.Fatal("an identity credential reached an external engine despite being forbidden")
		}
		if !strings.Contains(out.Stderr, "HOME") {
			t.Error("the forbidden variable suppressed an allowed one")
		}
	})
}

// A scanner must not be able to leave a descendant running. This is the
// JVM-and-browser case: ZAP starts helpers, Nuclei can start Chromium.
func TestDescendantsAreKilledWithTheEngine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are POSIX; the Windows limitation is recorded in the threat model")
	}
	marker := filepath.Join(t.TempDir(), "child-alive")

	// The engine spawns a long-lived grandchild that touches a file every
	// 200ms, then hangs itself. If the group is not killed, the grandchild
	// keeps writing after the engine is gone.
	body := `
	child := exec.Command("/bin/sh", "-c", "while true; do touch ` + marker + `; sleep 0.2; done")
	_ = child.Start()
	time.Sleep(120 * time.Second)`

	out := runFake(t, body, func(_ *fakeEngine, s *Settings, _ *Target) { s.TimeoutSeconds = 2 })
	if out.Status != StatusBlocked {
		t.Fatalf("a hanging engine was not stopped: %s", out.Status)
	}

	// Let anything that survived prove it.
	_ = os.Remove(marker)
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a grandchild process outlived the engine; the process group was not killed")
	}
}

// An engine that never closes its pipes must not hold the assessment.
func TestHungPipeDoesNotBlockForever(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on POSIX process groups")
	}
	// The engine writes a valid result, then leaves a child holding stdout open
	// and exits. Without WaitDelay the parent waits on the pipe forever.
	body := oneResult + `
	_ = exec.Command("/bin/sh", "-c", "sleep 120").Start()`

	done := make(chan Outcome, 1)
	go func() {
		done <- runFake(t, body, func(_ *fakeEngine, s *Settings, _ *Target) { s.TimeoutSeconds = 5 })
	}()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("a child holding the pipe open blocked the supervisor indefinitely")
	}
}

// Target URLs and configuration are arguments, never shell fragments.
func TestHostileArgumentsStayData(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "injected")
	hostile := []string{
		"http://x.test/;touch " + marker,
		"$(touch " + marker + ")",
		"`touch " + marker + "`",
		"a b\tc",
		"--not-a-flag",
		"-rf",
		"line\nbreak",
		`quote"and'quote`,
	}

	body := `
	for _, a := range os.Args[1:] { fmt.Fprintf(os.Stderr, "ARG:%s\n", a) }
	` + oneResult

	out := runFake(t, body, func(e *fakeEngine, _ *Settings, _ *Target) {
		e.extraArgs = hostile
	})
	if out.Status != StatusCompleted {
		t.Fatalf("status = %s (%s)", out.Status, out.Detail)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("an argument was interpreted by a shell")
	}
	// Each hostile value must have arrived as one argument. The comparison is
	// against the sanitized form, because stderr is cleaned of control
	// characters on the way back — the property under test is that nothing was
	// split, expanded or interpreted, not that a tab survives display.
	for _, h := range hostile {
		want := proc.Sanitize(strings.SplitN(h, "\n", 2)[0], MaxStringBytes)
		if !strings.Contains(out.Stderr, "ARG:"+want) {
			t.Errorf("argument %q did not reach the engine intact; stderr: %q", h, out.Stderr)
		}
	}
}

// Engine output is attacker-influenced. A target chooses what a scanner echoes
// back, and that reaches terminals and reports.
func TestHostileEngineOutputIsSanitized(t *testing.T) {
	// The escape is written as a JSON \u escape so the fixture source stays
	// plain ASCII.
	body := "fmt.Println(\"" +
		`{\"RuleID\":\"r\",\"RuleName\":\"\\u001b[2Jcleared\",` +
		`\"Location\":\"http://x.test/\",` +
		`\"Detail\":\"padding\",\"SourceSeverity\":\"high\"}` +
		"\")"

	out := runFake(t, body, nil)
	if out.Status != StatusCompleted {
		t.Fatalf("status = %s (%s)", out.Status, out.Detail)
	}
	o := out.Observations[0]
	if strings.ContainsRune(o.RuleName, 0x1b) {
		t.Errorf("a terminal escape survived sanitisation: %q", o.RuleName)
	}
	if !strings.Contains(o.RuleName, "cleared") {
		t.Errorf("sanitisation destroyed the forensic content: %q", o.RuleName)
	}
}

// An unbounded imported string is a flooding primitive.
func TestOversizedImportedStringsAreBounded(t *testing.T) {
	out := runFake(t, `
	huge := strings.Repeat("A", 40000)
	fmt.Printf("{\"RuleID\":\"r\",\"Location\":\"http://x/\",\"Detail\":\"%s\"}\n", huge)`, nil)
	if out.Status != StatusCompleted {
		t.Fatalf("status = %s (%s)", out.Status, out.Detail)
	}
	if got := len(out.Observations[0].Detail); got > MaxStringBytes+8 {
		t.Errorf("an unbounded string was imported: %d bytes", got)
	}
}

// An incomplete run is marked partial and claims no coverage.
func TestPartialResultsClaimNoCoverage(t *testing.T) {
	out := runFake(t, oneResult, func(e *fakeEngine, _ *Settings, _ *Target) {
		e.caps = []Capability{"CWE-89 SQL injection"}
		e.normalize = func(stdout []byte, w Workspace, p Provenance) (Normalized, error) {
			return Normalized{
				Observations: []Observation{{RuleID: "r", Location: "http://x/"}},
				Covered:      []Capability{"CWE-89 SQL injection"},
				Partial:      true,
				Limitations:  []string{"the scan was cut short"},
			}, nil
		}
	})

	if out.Status != StatusPartial {
		t.Fatalf("status = %s, want partial", out.Status)
	}
	if len(out.Covered) != 0 {
		t.Fatalf("a partial run claimed coverage %v; an incomplete scan of a class is not an "+
			"assessment of it", out.Covered)
	}
	if len(out.Observations) != 1 {
		t.Error("partial results were discarded rather than retained and marked")
	}
	if !strings.Contains(out.Detail, "NOT counted as assessed") {
		t.Errorf("the partial state is not explained: %q", out.Detail)
	}
}

// An engine that attacks must not run under a reconnaissance profile.
func TestProfileGateBlocksAggressiveEngines(t *testing.T) {
	out := runFake(t, oneResult, func(e *fakeEngine, _ *Settings, tgt *Target) {
		e.profile = model.ProfileIntrusive
		tgt.Profile = model.ProfileDiscovery
	})
	if out.Status != StatusBlocked || out.Cause != model.CauseSafetyPolicy {
		t.Fatalf("status/cause = %s/%s, want blocked/safety_policy", out.Status, out.Cause)
	}
	if !strings.Contains(out.Detail, "remain unassessed") {
		t.Errorf("a profile block does not say what was lost: %q", out.Detail)
	}
}

// A disabled engine is skipped, and skipping is not a failure.
func TestDisabledEngineIsSkipped(t *testing.T) {
	e := &fakeEngine{}
	out := Run(context.Background(), e, Target{Profile: model.ProfileVerification},
		Settings{Enabled: false}, Options{})
	if out.Status != StatusSkipped {
		t.Errorf("status = %s, want skipped", out.Status)
	}
	if out.Failed() {
		t.Error("a disabled engine was reported as failed")
	}
}

// An external alert never becomes a confirmed finding, whatever the engine says.
func TestExternalAlertsAreOnlyEverObserved(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "", "CONFIRMED"} {
		f := ToFinding(
			Observation{RuleID: "r", RuleName: "n", Location: "http://x/", SourceSeverity: sev},
			Provenance{Engine: "fake", Version: "1"}, "run-1")

		if f.State != model.StateObserved {
			t.Errorf("source severity %q produced state %s, want observed", sev, f.State)
		}
		if f.Severity != model.SeverityUnassessed {
			t.Errorf("source severity %q was translated into AppSec severity %s", sev, f.Severity)
		}
		if f.External == nil || f.External.Severity != sev {
			t.Errorf("the engine's own severity was not preserved verbatim: %+v", f.External)
		}
		if f.Verification.Performed {
			t.Error("an imported alert claimed AppSec verification")
		}
		// It must not be able to fail a build on its own.
		if f.Severity.AtLeast(model.SeverityLow) {
			t.Errorf("an unverified external alert satisfies a policy threshold")
		}
	}
}

// The temporary workspace must not survive the run.
func TestWorkspaceIsRemoved(t *testing.T) {
	var seen string
	e := &fakeEngine{bin: buildFake(t, "fake", fakePreamble+oneResult+"\n}\n")}
	e.normalize = func(stdout []byte, w Workspace, p Provenance) (Normalized, error) {
		seen = w.Dir
		return Normalized{}, nil
	}
	out := Run(context.Background(), e, Target{Profile: model.ProfileVerification},
		Settings{Enabled: true, TimeoutSeconds: 20}, Options{})
	if out.Status != StatusCompleted {
		t.Fatalf("status = %s (%s)", out.Status, out.Detail)
	}
	if seen == "" {
		t.Fatal("no workspace was created")
	}
	if _, err := os.Stat(seen); err == nil {
		t.Errorf("the engine workspace %s outlived the run", seen)
	}
}

// Consumers deduplicate on the finding id. An empty one collapses every
// imported alert into a single row, and one rule firing at two places is two
// findings, not one seen twice.
func TestImportedFindingsHaveDistinctStableIdentities(t *testing.T) {
	p := Provenance{Engine: "nuclei", Version: "v3.11.1"}
	a := ToFinding(Observation{RuleID: "CVE-2021-1", Location: "http://h/a"}, p, "run-1")
	b := ToFinding(Observation{RuleID: "CVE-2021-1", Location: "http://h/b"}, p, "run-1")

	if a.ID == "" {
		t.Fatal("an imported finding has no identity, so consumers cannot deduplicate it")
	}
	if a.ID == b.ID {
		t.Errorf("the same rule at two locations produced one identity: %q", a.ID)
	}

	// Stable across runs: the identity must not carry the run id.
	again := ToFinding(Observation{RuleID: "CVE-2021-1", Location: "http://h/a"}, p, "run-2")
	if again.ID != a.ID {
		t.Errorf("the identity changed between runs: %q then %q", a.ID, again.ID)
	}
}
