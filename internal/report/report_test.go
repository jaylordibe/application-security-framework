package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
)

func sampleResult() engine.Result {
	start := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return engine.Result{
		RunID:      "20260905T120000Z-abcd1234",
		Target:     "http://localhost:3000",
		TargetName: "fixture",
		Profile:    model.ProfileVerification,
		StartedAt:  start,
		FinishedAt: start.Add(3 * time.Second),
		Surface: engine.Surface{
			SpecDerived: true,
			SpecSource:  model.Source{Kind: model.SourceOpenAPIURL, Ref: "http://localhost:3000/openapi.json", ObservedAt: start},
			SpecTitle:   "fixture",
			SpecVersion: "3.0.3",
			Fidelity: openapi.Fidelity{
				Level: openapi.FidelityUsable, Provenance: model.ProvenanceDeclared,
				Total: 2, Protected: 1, Public: 1, Detail: "discriminates",
			},
			Operations: []model.Operation{
				{ID: "GET /api/profile", Method: "GET", PathTemplate: "/api/profile"},
				{ID: "GET /api/health", Method: "GET", PathTemplate: "/api/health"},
			},
		},
		Findings: []model.Finding{{
			ID: "declared-auth-not-enforced:GET /api/profile", CheckID: "declared-auth-not-enforced",
			Title: "Operation declared as requiring authentication is served without credentials",
			State: model.StateSuspected, Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
			CWE: []string{"CWE-306"}, OWASP: []string{"API2:2023 Broken Authentication"},
			OperationID: "GET /api/profile", IdentityID: "anonymous",
			Expected: "should be refused", Actual: "returned 200 twice",
			Verification: model.VerificationRecord{
				Strategy: "ladder", Performed: true, Result: "no discriminator explained it away",
				Steps:       []model.VerificationStep{{Name: "reproducible", Passed: true, Detail: "2 of 2"}},
				Unavailable: []string{"authenticated-control-request"},
			},
			Remediation:  "apply the control",
			Reproduction: []string{"GET http://localhost:3000/api/profile with no Authorization header"},
		}},
		Coverage: []model.CoverageEntry{
			{Dimension: "operation", Subject: "GET /api/profile", CheckID: "declared-auth-not-enforced",
				IdentityID: "anonymous", Disposition: model.DispositionExecuted},
			{Dimension: "operation", Subject: "GET /api/health", CheckID: "declared-auth-not-enforced",
				IdentityID: "anonymous", Disposition: model.DispositionUntested,
				Cause: model.CauseNoOracle, Detail: "declared public"},
		},
		ToolFailures:       []string{},
		OutOfScopeHosts:    []string{},
		ClassesNotAssessed: []string{"CWE-284 broken access control (object level, BOLA/IDOR)"},
	}
}

func TestBuildCountsAndAssurance(t *testing.T) {
	doc := Build(sampleResult(), "1.2.3")
	if doc.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %q", doc.SchemaVersion)
	}
	if doc.Assurance.ExecutedChecks != 1 || doc.Assurance.UntestedSurface != 1 {
		t.Errorf("assurance counts wrong: %+v", doc.Assurance)
	}
	if doc.Assurance.SuspectedFindings != 1 || doc.Assurance.ConfirmedFindings != 0 {
		t.Error("suspected and confirmed findings must be counted separately")
	}
	if !strings.Contains(doc.Assurance.Statement, "does not establish that the target is secure") {
		t.Errorf("assurance statement is too weak: %q", doc.Assurance.Statement)
	}
	if !strings.Contains(doc.Assurance.SurfaceCompleteness, "not documented") {
		t.Errorf("surface completeness does not disclose the specification limit: %q", doc.Assurance.SurfaceCompleteness)
	}
}

// A run that executed nothing must say so in the strongest terms.
func TestZeroExecutedChecksStatementIsUnambiguous(t *testing.T) {
	res := sampleResult()
	res.Coverage = []model.CoverageEntry{{
		Dimension: "operation", Subject: "GET /a", Disposition: model.DispositionBlocked,
		Cause: model.CauseEngineUnavailable,
	}}
	res.Findings = nil
	doc := Build(res, "test")
	if !strings.Contains(doc.Assurance.Statement, "establishes nothing") {
		t.Fatalf("statement = %q, want an explicit 'establishes nothing'", doc.Assurance.Statement)
	}
}

// The domain model carries no struct tags, so this asserts the mapping layer is
// actually doing the work rather than the model leaking into the wire format.
func TestJSONIsStableAndComplete(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Build(sampleResult(), "1.2.3")); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"schemaVersion", "tool", "run", "assurance", "surface",
		"findings", "coverage", "toolFailures", "outOfScopeHosts", "classesNotAssessed",
	} {
		if _, ok := round[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
	// Slices must marshal as [] rather than null so consumers need no null handling.
	if !strings.Contains(buf.String(), `"toolFailures": []`) {
		t.Error("empty slices must render as [], not null")
	}
}

// SARIF is validated against the actual OASIS schema, not by eye.
func TestSARIFValidatesAgainstOfficialSchema(t *testing.T) {
	raw, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	// Resolve everything locally. A validator that fetches remote $ref would be
	// a second, unguarded network client inside a security tool.
	if err := c.AddResource("https://sarif.local/schema.json", schemaDoc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := c.Compile("https://sarif.local/schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, Build(sampleResult(), "1.2.3")); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Fatalf("SARIF output does not validate against the OASIS 2.1.0 schema:\n%v", err)
	}
}

func TestSARIFSemantics(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, Build(sampleResult(), "1.2.3")); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0 pinned", log["version"])
	}
	run := log["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)

	// A suspected finding must not be presented as a failure.
	if result["kind"] != "open" {
		t.Errorf("kind = %v, want open for a suspected finding", result["kind"])
	}
	// Fingerprints must exist from the first release; adding them later would
	// change the identity of every existing alert.
	fp, ok := result["partialFingerprints"].(map[string]any)
	if !ok || len(fp) == 0 {
		t.Error("partialFingerprints missing")
	}
	// Coverage has no home in SARIF's vocabulary and must not be dropped.
	props := run["properties"].(map[string]any)
	if _, ok := props["coverage"]; !ok {
		t.Error("coverage was dropped from SARIF output")
	}
	if _, ok := props["classesNotAssessed"]; !ok {
		t.Error("classesNotAssessed was dropped from SARIF output")
	}
}

// A run that executed nothing did not succeed, whatever its exit status.
func TestSARIFInvocationReflectsExecution(t *testing.T) {
	res := sampleResult()
	res.Coverage = []model.CoverageEntry{{
		Dimension: "operation", Subject: "GET /a", Disposition: model.DispositionBlocked,
		Cause: model.CauseEngineUnavailable,
	}}
	res.Findings = nil

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, Build(res, "t")); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var log map[string]any
	_ = json.Unmarshal(buf.Bytes(), &log)
	inv := log["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false {
		t.Fatal("a run that executed no checks must not report executionSuccessful")
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	doc := Build(sampleResult(), "1.2.3")
	if err := WriteJSON(&a, doc); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, doc); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("JSON output is not deterministic")
	}
}
