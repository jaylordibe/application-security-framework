package scanner_test

// Integration tests against the real engines.
//
// Every test here skips when its binary is absent, and CI installs none of
// them: the boundary's own properties are proven against fake engines in
// fake_test.go, deterministically and with no third-party software. What these
// add is the one thing a fake cannot — that the argument vector this code
// builds is accepted by the tool as shipped, and that the output that tool
// actually produces is the output this code parses. A normalizer tested only
// against a fixture is tested against a memory of a format.
//
// A skip is not a pass. `go test -v ./internal/scanner/` prints which engines
// were exercised, and an evaluation that reports engine results says which of
// these ran.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
	"github.com/jaylordibe/application-security-framework/internal/scanner/nuclei"
	"github.com/jaylordibe/application-security-framework/internal/scanner/sast"
	"github.com/jaylordibe/application-security-framework/internal/scanner/zap"
)

// requireEngine skips unless the engine is installed and answered a version
// probe.
func requireEngine(t *testing.T, e scanner.Engine, s scanner.Settings) scanner.Availability {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a := e.Detect(ctx, s)
	if !a.Present {
		t.Skipf("%s is not installed: %s", e.Meta().ID, a.Problem)
	}
	if a.Version == "" {
		t.Fatalf("%s was found at %s but reported no version", e.Meta().ID, a.Path)
	}
	t.Logf("%s %s at %s", e.Meta().ID, a.Version, a.Path)
	return a
}

// The end-to-end property: a real Nuclei accepts this argument vector, finds a
// planted marker on a local server, and its real output parses into exactly one
// observation that is observed and unassessed.
func TestNucleiFindsAPlantedMarker(t *testing.T) {
	settings := scanner.Settings{
		Enabled:        true,
		TimeoutSeconds: 120,
		Extra:          map[string]string{"allowUnsignedTemplates": "true"},
	}
	requireEngine(t, nuclei.New(), settings)

	const marker = "appsec-integration-marker"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			_, _ = w.Write([]byte("<html>" + marker + "</html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	template := "id: appsec-integration-probe\n" +
		"info:\n" +
		"  name: AppSec integration probe\n" +
		"  author:\n    - appsec\n" +
		"  severity: info\n" +
		"  tags:\n    - appsec\n" +
		"http:\n" +
		"  - method: GET\n" +
		"    path:\n" +
		"      - \"{{BaseURL}}/probe\"\n" +
		"    matchers:\n" +
		"      - type: word\n" +
		"        words:\n" +
		"          - \"" + marker + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "probe.yaml"), []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	settings.RuleSource = dir

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	out := scanner.Run(ctx, nuclei.New(),
		scanner.Target{BaseURL: srv.URL, Profile: model.ProfileVerification},
		settings, scanner.Options{RunID: "integration"})

	if out.Status != scanner.StatusCompleted {
		t.Fatalf("status = %s (%s: %s)\nstderr: %s",
			out.Status, out.Cause, out.Detail, out.Stderr)
	}
	if len(out.Observations) != 1 {
		t.Fatalf("observations = %d, want the one planted marker: %+v",
			len(out.Observations), out.Observations)
	}
	o := out.Observations[0]
	if o.RuleID != "appsec-integration-probe" {
		t.Errorf("RuleID = %q, want the template's own id", o.RuleID)
	}
	if !strings.Contains(o.Location, "/probe") {
		t.Errorf("Location = %q, want the matched URL", o.Location)
	}
	if o.SourceSeverity != "info" {
		t.Errorf("SourceSeverity = %q, want the template's own value verbatim", o.SourceSeverity)
	}

	assertOnlyObserved(t, out)
}

// The same property for a source scanner: whichever of opengrep or semgrep is
// installed, this rule file and this JSON output work as written.
func TestSASTFindsAPlantedMarker(t *testing.T) {
	settings := scanner.Settings{Enabled: true, TimeoutSeconds: 120}
	requireEngine(t, sast.New(), settings)

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "app.txt"),
		[]byte("harmless\nappsec_integration_marker\nharmless\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rules := t.TempDir()
	rule := "rules:\n" +
		"  - id: appsec-integration-marker\n" +
		"    message: the planted marker\n" +
		"    severity: WARNING\n" +
		"    languages:\n      - generic\n" +
		"    patterns:\n" +
		"      - pattern-regex: appsec_integration_marker\n"
	if err := os.WriteFile(filepath.Join(rules, "rules.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	settings.RuleSource = rules

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	out := scanner.Run(ctx, sast.New(),
		scanner.Target{SourceRoot: src, Profile: model.ProfileDiscovery},
		settings, scanner.Options{RunID: "integration"})

	if out.Status != scanner.StatusCompleted {
		t.Fatalf("status = %s (%s: %s)\nstderr: %s",
			out.Status, out.Cause, out.Detail, out.Stderr)
	}
	if len(out.Observations) != 1 {
		t.Fatalf("observations = %d, want the one planted marker: %+v",
			len(out.Observations), out.Observations)
	}
	o := out.Observations[0]
	if o.RuleID != "appsec-integration-marker" {
		t.Errorf("RuleID = %q", o.RuleID)
	}
	if !strings.Contains(o.Location, "app.txt") {
		t.Errorf("Location = %q, want the file that matched", o.Location)
	}
	if o.SourceSeverity != "WARNING" {
		t.Errorf("SourceSeverity = %q, want the engine's own value verbatim", o.SourceSeverity)
	}

	assertOnlyObserved(t, out)
}

// ZAP is detected but not driven here. A passive scan spiders the target and
// runs for minutes against a JVM, which is not something to start inside a unit
// test run; what is worth asserting without paying that cost is that the real
// launcher is found, identifies itself, and accepts being pointed at a private
// home directory rather than the operator's.
func TestZAPIsDetectedAndInvokedIntoItsOwnHome(t *testing.T) {
	settings := scanner.Settings{Enabled: true}
	a := requireEngine(t, zap.New(), settings)

	w := scanner.Workspace{Dir: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "zap.json")}
	inv, err := zap.New().Invocation(
		scanner.Target{BaseURL: "http://127.0.0.1:8080", Profile: model.ProfileVerification},
		settings, w, a)
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	if inv.Spec.Path != a.Path {
		t.Errorf("the invocation runs %q, not the detected launcher %q", inv.Spec.Path, a.Path)
	}
	if !strings.Contains(strings.Join(inv.Spec.Args, " "), w.Dir) {
		t.Errorf("ZAP was not confined to the run's own workspace: %v", inv.Spec.Args)
	}
}

// Nothing an external tool says is ever more than an observation, whatever
// severity it attached. This is asserted against the real engines as well as
// the fakes, because it is the property most likely to be eroded by a
// well-meaning change to a normalizer.
func assertOnlyObserved(t *testing.T, out scanner.Outcome) {
	t.Helper()
	for _, o := range out.Observations {
		f := scanner.ToFinding(o, out.Provenance, "integration")
		if f.State != model.StateObserved {
			t.Errorf("a %s result entered the ledger as %s, not observed", out.Engine, f.State)
		}
		if f.Severity != model.SeverityUnassessed {
			t.Errorf("a %s result arrived pre-severity-rated as %s", out.Engine, f.Severity)
		}
		blob, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("a finding from %s does not marshal: %v", out.Engine, err)
		}
		if strings.Contains(string(blob), "Bearer ") {
			t.Errorf("a credential reached a finding from %s", out.Engine)
		}
	}
}
