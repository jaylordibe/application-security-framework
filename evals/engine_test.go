// M4 evaluation: external engines end to end.
//
// The bar is not "a scanner ran". It is that an external alert travels the whole
// pipeline as an observation and arrives in the report still labelled as one,
// and that an engine which failed makes the report *less* confident rather than
// quieter.
package evals

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

	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/proc"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// buildEngine compiles a fake engine binary.
func buildEngine(t *testing.T, src string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "engine")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// jsonlEngine is a fake engine emitting one observation per line, like Nuclei.
type jsonlEngine struct {
	bin  string
	caps []scanner.Capability
}

func (j jsonlEngine) Meta() scanner.Meta {
	return scanner.Meta{
		ID: "fakescan", Title: "FakeScan", Capabilities: j.caps,
		Unlocks:     "a weakness class AppSec Framework does not test natively",
		InstallHint: "it is a test fixture",
	}
}

func (j jsonlEngine) Detect(context.Context, scanner.Settings) scanner.Availability {
	if j.bin == "" {
		return scanner.Availability{Problem: "no executable was configured"}
	}
	return scanner.Availability{Present: true, Path: j.bin, Version: "1.2.3"}
}

func (jsonlEngine) RequiredProfile(scanner.Settings) model.Profile { return model.ProfileVerification }

func (j jsonlEngine) Invocation(
	t scanner.Target, s scanner.Settings, w scanner.Workspace, a scanner.Availability,
) (scanner.Invocation, error) {
	return scanner.Invocation{
		Spec: proc.Spec{Name: "fakescan", Path: j.bin, Args: []string{"-target", t.BaseURL}},
		Provenance: scanner.Provenance{
			Engine: "fakescan", Version: a.Version, ExecutablePath: a.Path,
			RuleSource: "fixture corpus at commit abc1234",
		},
	}, nil
}

func (j jsonlEngine) Normalize(
	stdout []byte, w scanner.Workspace, p scanner.Provenance, _ scanner.Settings,
) (scanner.Normalized, error) {
	var out scanner.Normalized
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var o scanner.Observation
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			return scanner.Normalized{}, err
		}
		out.Observations = append(out.Observations, o)
	}
	out.Covered = j.caps
	return out, nil
}

const criticalAlert = `package main

import "fmt"

func main() {
	fmt.Println(` + "`" +
	`{"RuleID":"CVE-2021-44228","RuleName":"Log4Shell","Location":"http://127.0.0.1:1/api",` +
	`"SourceSeverity":"critical","SourceConfidence":"","References":["CWE-77","CVE-2021-44228"],` +
	`"Detail":"template matched"}` + "`" + `)
}
`

const sqlClass = scanner.Capability("CWE-89 SQL injection")

// runWithEngine assembles an assessment whose only work is the external engine.
func runWithEngine(t *testing.T, e scanner.Engine, s scanner.Settings) engine.Result {
	t.Helper()
	coll := scanner.RunAll(context.Background(), []scanner.Registered{{Engine: e, Settings: s}},
		scanner.Target{BaseURL: "http://127.0.0.1:1", Profile: model.ProfileVerification},
		scanner.Options{RunID: "eval-m4"})

	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "eval-m4", Target: "http://127.0.0.1:1", Profile: model.ProfileVerification,
		Surface:     engine.Surface{SpecDerived: true},
		Engines:     coll,
		Concurrency: 1, RequestsPerSecond: 100,
		Now: func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return res
}

func engineRow(t *testing.T, res engine.Result, id string) model.CoverageEntry {
	t.Helper()
	for _, e := range res.Coverage {
		if e.Dimension == scanner.DimensionEngine && e.Subject == id {
			return e
		}
	}
	t.Fatalf("no engine ledger row for %q; coverage: %+v", id, res.Coverage)
	return model.CoverageEntry{}
}

// ---------------------------------------------------------------------------
// The pipeline: alert -> observation -> evidence -> ledger -> JSON/SARIF
// ---------------------------------------------------------------------------

func TestM4_ExternalAlertTravelsThePipelineAsAnObservation(t *testing.T) {
	e := jsonlEngine{bin: buildEngine(t, criticalAlert), caps: []scanner.Capability{sqlClass}}
	res := runWithEngine(t, e, scanner.Settings{Enabled: true, TimeoutSeconds: 30})

	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]

	// The engine said critical. AppSec says it has not judged it.
	if f.State != model.StateObserved {
		t.Errorf("state = %s, want observed", f.State)
	}
	if f.Severity != model.SeverityUnassessed {
		t.Errorf("severity = %s; the engine's 'critical' must not become an AppSec severity",
			f.Severity)
	}
	if f.External == nil {
		t.Fatal("the finding carries no engine provenance")
	}
	for name, got := range map[string]string{
		"engine": f.External.Engine, "version": f.External.EngineVersion,
		"executable": f.External.ExecutablePath, "rule": f.External.RuleID,
		"source severity": f.External.Severity, "rule provenance": f.External.RuleProvenance,
	} {
		if got == "" {
			t.Errorf("provenance is missing %s", name)
		}
	}
	if f.External.Severity != "critical" {
		t.Errorf("the engine's severity was not preserved verbatim: %q", f.External.Severity)
	}

	// Ledger.
	row := engineRow(t, res, "fakescan")
	if row.Disposition != model.DispositionExecuted {
		t.Errorf("ledger row = %s/%s, want executed", row.Disposition, row.Cause)
	}

	// Reports.
	doc := report.Build(res, "test")
	if len(doc.Engines.Runs) != 1 || doc.Engines.Runs[0].Status != "completed" {
		t.Fatalf("the engine run is not reported: %+v", doc.Engines)
	}
	if doc.Engines.Runs[0].ProvenanceVerified {
		t.Error("a user-installed binary was reported as verified")
	}
	if doc.Findings[0].External == nil || doc.Findings[0].External.Severity != "critical" {
		t.Error("engine provenance did not survive into the JSON report")
	}
	if !strings.Contains(doc.Engines.Statement, "recorded as observed") {
		t.Errorf("the engine statement does not say what a result means: %q", doc.Engines.Statement)
	}

	var sarif strings.Builder
	if err := report.WriteSARIF(&sarif, doc); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fakescan", "CVE-2021-44228", "critical"} {
		if !strings.Contains(sarif.String(), want) {
			t.Errorf("SARIF lost engine provenance: missing %q", want)
		}
	}
}

// An engine's alert must never fail a build on its own.
func TestM4_ExternalObservationsCannotFailTheBuild(t *testing.T) {
	e := jsonlEngine{bin: buildEngine(t, criticalAlert)}
	res := runWithEngine(t, e, scanner.Settings{Enabled: true, TimeoutSeconds: 30})
	doc := report.Build(res, "test")

	if doc.Assurance.ConfirmedFindings != 0 {
		t.Errorf("an external alert was counted as confirmed")
	}
	if doc.Assurance.SuspectedFindings != 0 {
		t.Errorf("an external alert was counted as suspected")
	}
	for _, f := range res.Findings {
		if f.Severity.AtLeast(model.SeverityLow) {
			t.Errorf("an unverified external alert satisfies a policy threshold")
		}
	}
}

// ---------------------------------------------------------------------------
// Failure must make the report less confident, never quieter
// ---------------------------------------------------------------------------

func TestM4_EngineFailureDoesNotMakeTheReportCleaner(t *testing.T) {
	cases := map[string]string{
		"missing binary": "",
		"crash": `package main
import "os"
func main() { os.Exit(2) }
`,
		"malformed output": `package main
import "fmt"
func main() { fmt.Println("{not json") }
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			var bin string
			if src != "" {
				bin = buildEngine(t, src)
			}
			e := jsonlEngine{bin: bin, caps: []scanner.Capability{sqlClass}}
			res := runWithEngine(t, e, scanner.Settings{Enabled: true, TimeoutSeconds: 30})

			row := engineRow(t, res, "fakescan")
			if row.Disposition != model.DispositionBlocked {
				t.Fatalf("ledger row = %s, want blocked", row.Disposition)
			}
			if !strings.Contains(row.Detail, "remain unassessed") {
				t.Errorf("the row lets a reader mistake failure for a clean result: %q", row.Detail)
			}
			if len(res.Findings) != 0 {
				t.Error("a failed engine contributed findings")
			}

			// The class it would have covered must still be listed as not
			// assessed. This is the whole point: a broken scanner must not
			// silently remove a limitation.
			var stillListed bool
			for _, c := range res.ClassesNotAssessed {
				if strings.HasPrefix(c, string(sqlClass)) {
					stillListed = true
					if strings.Contains(c, "assessed by") {
						t.Errorf("a failed engine qualified a class as assessed: %q", c)
					}
				}
			}
			if !stillListed {
				t.Errorf("a failed engine removed a class from classesNotAssessed: %v",
					res.ClassesNotAssessed)
			}

			// And it is a recorded tool failure, not just a quiet row.
			if len(res.ToolFailures) == 0 {
				t.Error("an engine failure was not recorded as a tool failure")
			}
			doc := report.Build(res, "test")
			if len(doc.Engines.Failures) == 0 {
				t.Error("the report does not name the failed engine")
			}
		})
	}
}

// A successful engine removes its class from the not-assessed list, but only
// with its provenance attached: "assessed by Nuclei against these templates" and
// "assessed" are different claims.
func TestM4_SuccessfulEngineQualifiesRatherThanErasesCoverage(t *testing.T) {
	e := jsonlEngine{bin: buildEngine(t, criticalAlert), caps: []scanner.Capability{sqlClass}}
	res := runWithEngine(t, e, scanner.Settings{Enabled: true, TimeoutSeconds: 30})

	var found bool
	for _, c := range res.ClassesNotAssessed {
		if strings.HasPrefix(c, string(sqlClass)) {
			found = true
			if !strings.Contains(c, "assessed by fakescan 1.2.3") {
				t.Errorf("the class was not qualified with the engine and version: %q", c)
			}
			if !strings.Contains(c, "not verified by AppSec Framework") {
				t.Errorf("the qualification does not say the results are unverified: %q", c)
			}
			if !strings.Contains(c, "fixture corpus at commit abc1234") {
				t.Errorf("the qualification does not name the corpus that ran: %q", c)
			}
		}
	}
	if !found {
		t.Errorf("the covered class vanished from the account entirely: %v", res.ClassesNotAssessed)
	}
}

// Two engines reporting the same thing is not verification.
func TestM4_AgreementBetweenEnginesIsNotConfirmation(t *testing.T) {
	bin := buildEngine(t, criticalAlert)
	coll := scanner.RunAll(context.Background(), []scanner.Registered{
		{Engine: jsonlEngine{bin: bin}, Settings: scanner.Settings{Enabled: true, TimeoutSeconds: 30}},
		{Engine: secondEngine{jsonlEngine{bin: bin}}, Settings: scanner.Settings{Enabled: true, TimeoutSeconds: 30}},
	}, scanner.Target{BaseURL: "http://127.0.0.1:1", Profile: model.ProfileVerification},
		scanner.Options{RunID: "eval"})

	if len(coll.Findings) != 2 {
		t.Fatalf("findings = %d, want one per engine", len(coll.Findings))
	}
	for _, f := range coll.Findings {
		if f.State != model.StateObserved {
			t.Errorf("agreement between engines promoted a finding to %s", f.State)
		}
	}
}

// secondEngine is a second engine reporting the same alert.
type secondEngine struct{ jsonlEngine }

func (s secondEngine) Meta() scanner.Meta {
	m := s.jsonlEngine.Meta()
	m.ID, m.Title = "otherscan", "OtherScan"
	return m
}

func (s secondEngine) Invocation(
	t scanner.Target, st scanner.Settings, w scanner.Workspace, a scanner.Availability,
) (scanner.Invocation, error) {
	inv, err := s.jsonlEngine.Invocation(t, st, w, a)
	inv.Provenance.Engine = "otherscan"
	return inv, err
}

// A run with no engines configured says so rather than staying silent.
func TestM4_NoEnginesConfiguredIsStated(t *testing.T) {
	res := runWithEngine(t, jsonlEngine{}, scanner.Settings{Enabled: false})
	doc := report.Build(res, "test")
	if !strings.Contains(doc.Engines.Statement, "not enabled") &&
		!strings.Contains(doc.Engines.Statement, "No external scanning engine") {
		t.Errorf("statement = %q", doc.Engines.Statement)
	}
	// A skipped engine adds no ledger row: the ledger accounts for planned work.
	for _, e := range res.Coverage {
		if e.Dimension == scanner.DimensionEngine {
			t.Errorf("a disabled engine produced a ledger row: %+v", e)
		}
	}
}
