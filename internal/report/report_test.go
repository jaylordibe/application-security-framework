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
	"github.com/jaylordibe/application-security-framework/internal/identity"
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

// The report is the artefact that leaves the machine. Whatever a Status
// contains, the published DTO must contain no credential-derived value at all —
// not the value, not its length, not a fingerprint of it.
func TestIdentityReportingCarriesNoCredentialMaterial(t *testing.T) {
	const secret = "APPSEC_M1_SECRET_MUST_NEVER_PERSIST_7f91"
	res := engine.Result{
		RunID: "r", Target: "http://localhost:3000", Profile: model.ProfileVerification,
		Surface: engine.Surface{SpecDerived: true},
		Identities: []identity.Status{{
			ID:        "admin",
			Label:     "Administrator",
			Scheme:    identity.SchemeBearer,
			Source:    "environment variable APPSEC_ADMIN_TOKEN",
			Usable:    true,
			Monitored: true,
			Liveness:  identity.LivenessGood,
			LastGood:  time.Unix(1000, 0),
			Probes:    2,
		}},
	}
	doc := Build(res, "test")

	if len(doc.Identities) != 1 {
		t.Fatalf("identities = %d, want 1", len(doc.Identities))
	}
	got := doc.Identities[0]
	if got.ID != "admin" || got.Scheme != "bearer" {
		t.Errorf("identity not published faithfully: %+v", got)
	}
	if got.CredentialSource != "environment variable APPSEC_ADMIN_TOKEN" {
		t.Errorf("credential source = %q; a location is publishable and must be published", got.CredentialSource)
	}
	if got.LastGoodAt == "" {
		t.Error("a confirmed-good canary time was not published")
	}
	if got.FirstBadAt != "" {
		t.Errorf("firstBadAt = %q, want empty; a zero time must not read as an observation", got.FirstBadAt)
	}

	var jsonOut, sarifOut strings.Builder
	if err := WriteJSON(&jsonOut, doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := WriteSARIF(&sarifOut, doc); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	for name, text := range map[string]string{
		"json":    jsonOut.String(),
		"sarif":   sarifOut.String(),
		"summary": Summary(doc),
	} {
		if strings.Contains(text, secret) {
			t.Errorf("the %s output contains credential material", name)
		}
	}

	// The identity reaches SARIF too, so a SARIF-only consumer is not told less.
	if !strings.Contains(sarifOut.String(), `"admin"`) {
		t.Error("SARIF does not carry the identity, so a SARIF consumer cannot see the limitation")
	}
}

// A reader who does not know whether an authenticated baseline existed cannot
// interpret "no confirmed findings". The statement must always be present and
// must distinguish the cases.
func TestAuthenticatedControlStatement(t *testing.T) {
	tests := []struct {
		name     string
		ids      []identity.Status
		mentions string
	}{
		{
			name:     "none configured",
			ids:      nil,
			mentions: "No identity was configured",
		},
		{
			name:     "credential unresolvable",
			ids:      []identity.Status{{ID: "a", Usable: false}},
			mentions: "no credential could be resolved",
		},
		{
			name:     "identity rejected mid-run",
			ids:      []identity.Status{{ID: "a", Usable: true, Monitored: true, Liveness: identity.LivenessBad}},
			mentions: "rejected by the target",
		},
		{
			name:     "usable but unmonitored",
			ids:      []identity.Status{{ID: "a", Usable: true, Monitored: false, Liveness: identity.LivenessUnknown}},
			mentions: "no liveness canary is configured",
		},
		{
			name:     "usable and monitored",
			ids:      []identity.Status{{ID: "a", Usable: true, Monitored: true, Liveness: identity.LivenessGood}},
			mentions: "confirmed live by a canary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := Build(engine.Result{
				RunID: "r", Surface: engine.Surface{SpecDerived: true}, Identities: tc.ids,
			}, "test")
			got := doc.Assurance.AuthenticatedControl
			if got == "" {
				t.Fatal("the authenticated-control statement is empty")
			}
			if !strings.Contains(got, tc.mentions) {
				t.Errorf("statement %q does not mention %q", got, tc.mentions)
			}
		})
	}
}

// A cross-owner finding is the most quotable thing this tool produces and the
// extent behind it is the least visible. The terminal summary — not only the
// JSON — has to carry the caveat, or an operator will generalise one tested
// boundary into a statement about the whole application.
func TestSummaryStatesOwnershipExtent(t *testing.T) {
	res := engine.Result{
		RunID: "r", Target: "http://localhost:3000", Profile: model.ProfileVerification,
		Surface: engine.Surface{SpecDerived: true},
		Coverage: []model.CoverageEntry{{
			Dimension: engine.DimensionOwnership, Subject: "GET /api/orders/{orderId}",
			CheckID: "cross-owner-resource-read", IdentityID: "bob",
			ResourceID: "order-alice", OwnerIdentityID: "alice",
			Disposition: model.DispositionExecuted,
		}},
		Ownership: engine.OwnershipSummary{
			Verified:   1,
			Statement:  "This run exercised 1 cross-owner boundary check(s), each named individually.",
			Boundaries: []string{"bob may not reach order-alice (owned by alice) via GET /api/orders/{orderId}"},
		},
	}
	out := Summary(Build(res, "test"))
	// The summary wraps for the terminal, so compare on normalized whitespace.
	flat := strings.Join(strings.Fields(out), " ")

	if !strings.Contains(flat, "ownership boundaries checked: 1") {
		t.Errorf("the summary does not report ownership work:\n%s", out)
	}
	if !strings.Contains(flat, "bob may not reach order-alice (owned by alice)") {
		t.Errorf("the summary does not name the boundary that was tested:\n%s", out)
	}
	if !strings.Contains(flat, "each named individually") {
		t.Errorf("the summary omits the statement bounding what was tested:\n%s", out)
	}
}

// A run with no fixtures must not grow an empty ownership section, which would
// read as a section that found nothing rather than one that was never asked.
func TestSummaryOmitsOwnershipWhenNoneWasPlanned(t *testing.T) {
	out := Summary(Build(engine.Result{
		RunID: "r", Surface: engine.Surface{SpecDerived: true},
	}, "test"))
	if strings.Contains(out, "ownership boundaries") {
		t.Errorf("an ownership section appeared with no fixtures configured:\n%s", out)
	}
}

// An imported alert is neither confirmed nor suspected, so the findings line
// alone would tell an operator whose engine reported a dozen criticals that
// nothing was found. The summary must say what the engines did.
func TestSummaryStatesWhatTheEnginesDid(t *testing.T) {
	doc := Document{
		Engines: EngineAccount{Runs: []EngineRun{
			{Engine: "nuclei", Status: "completed", Version: "v3.11.1", Observations: 2},
			{Engine: "zap", Status: "blocked", Cause: "engine_unavailable"},
			{Engine: "sast", Status: "skipped"},
		}},
		Findings: []Finding{
			{State: "observed"}, {State: "observed"},
		},
	}

	got := Summary(doc)

	if !strings.Contains(got, "engine nuclei: completed (v3.11.1), 2 observations") {
		t.Errorf("the terminal summary does not report what Nuclei did:\n%s", got)
	}
	if !strings.Contains(got, "engine zap: blocked") {
		t.Errorf("a failed engine is invisible in the terminal summary:\n%s", got)
	}
	if strings.Contains(got, "sast") {
		t.Errorf("an engine nobody enabled was listed as a result:\n%s", got)
	}
	if !strings.Contains(got, "2 external results are recorded as observed") {
		t.Errorf("imported results are not accounted for:\n%s", got)
	}
	// The whole point: they are reported without being promoted.
	if !strings.Contains(got, "unverified by AppSec Framework") {
		t.Errorf("the summary does not say these are unverified claims:\n%s", got)
	}
}

// With no engines configured the block must not appear at all.
func TestSummaryOmitsTheEngineBlockWhenNoneRan(t *testing.T) {
	if got := Summary(Document{}); strings.Contains(got, "engine ") {
		t.Errorf("an engine line appeared with no engines configured:\n%s", got)
	}
}
