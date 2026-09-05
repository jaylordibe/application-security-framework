package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/model"
)

// stubCheck is the second implementation that justifies the Check interface.
type stubCheck struct {
	id       string
	ran      atomic.Int32
	result   check.Result
	required model.Profile
	applies  bool
}

func (s *stubCheck) Metadata() check.Metadata {
	return check.Metadata{ID: s.id, Title: "stub"}
}

func (s *stubCheck) RequiredProfile(op model.Operation) model.Profile {
	if s.required != "" {
		return s.required
	}
	return model.RequiredProfileForMethod(op.Method)
}

func (s *stubCheck) Applicable(model.Operation) (bool, model.BlockedCause, string) {
	if s.applies {
		return true, model.CauseNone, ""
	}
	return false, model.CauseNoOracle, "stub declines"
}

func (s *stubCheck) Run(context.Context, model.Operation) check.Result {
	s.ran.Add(1)
	return s.result
}

func op(method, path string) model.Operation {
	return model.Operation{ID: model.OperationID(method, path), Method: method, PathTemplate: path}
}

func baseOptions(ops []model.Operation, checks []Check) Options {
	return Options{
		RunID: "test", Target: "http://localhost:3000", Profile: model.ProfileVerification,
		Surface:           Surface{SpecDerived: true, Operations: ops},
		Checks:            checks,
		Concurrency:       4,
		RequestsPerSecond: 1000,
		Now:               func() time.Time { return time.Unix(0, 0) },
	}
}

func entryFor(res Result, subject string) (model.CoverageEntry, bool) {
	for _, e := range res.Coverage {
		if e.Subject == subject {
			return e, true
		}
	}
	return model.CoverageEntry{}, false
}

// Every operation must produce a ledger row, so "never attempted" is always
// distinguishable from "tested and clean".
func TestEveryOperationProducesALedgerRow(t *testing.T) {
	ops := []model.Operation{op("GET", "/a"), op("GET", "/b"), op("POST", "/c")}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	res, err := Run(context.Background(), baseOptions(ops, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Coverage) != len(ops) {
		t.Fatalf("coverage rows = %d, want %d", len(res.Coverage), len(ops))
	}
}

// An unsafe method under a read-only profile must be blocked, not skipped.
func TestUnsafeMethodsAreBlockedBelowIntrusive(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	res, err := Run(context.Background(), baseOptions([]model.Operation{op("DELETE", "/orders/1")}, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	e, ok := entryFor(res, "DELETE /orders/1")
	if !ok {
		t.Fatal("no ledger row for the unsafe operation")
	}
	if e.Disposition != model.DispositionBlocked || e.Cause != model.CauseSafetyPolicy {
		t.Errorf("ledger = %s/%s, want blocked/safety_policy", e.Disposition, e.Cause)
	}
	if stub.ran.Load() != 0 {
		t.Fatal("an unsafe operation was executed under the verification profile")
	}
	if !strings.Contains(e.Detail, "intrusive") {
		t.Errorf("detail does not explain what would be required: %q", e.Detail)
	}
}

func TestIntrusiveProfilePermitsUnsafeMethods(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	opts := baseOptions([]model.Operation{op("DELETE", "/orders/1")}, []Check{stub})
	opts.Profile = model.ProfileIntrusive
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stub.ran.Load() != 1 {
		t.Fatal("the intrusive profile did not permit an unsafe method")
	}
}

// Sweeping authentication routes can lock real accounts.
func TestAuthRoutesAreExcludedByDefault(t *testing.T) {
	ops := []model.Operation{op("GET", "/api/login"), op("GET", "/api/profile")}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	opts := baseOptions(ops, []Check{stub})
	opts.ExcludeAuthEndpoints = true
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	e, _ := entryFor(res, "GET /api/login")
	if e.Disposition != model.DispositionUntested {
		t.Errorf("login route disposition = %s, want untested", e.Disposition)
	}
	if !strings.Contains(e.Detail, "lock real accounts") {
		t.Errorf("detail does not explain the exclusion: %q", e.Detail)
	}
	if stub.ran.Load() != 1 {
		t.Errorf("checks run = %d, want only the non-auth operation", stub.ran.Load())
	}
}

func TestExcludedOperationsAreRecorded(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	opts := baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub})
	opts.ExcludeOperations = []string{"GET /a"}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	e, _ := entryFor(res, "GET /a")
	if e.Disposition != model.DispositionUntested || !strings.Contains(e.Detail, "excluded") {
		t.Errorf("ledger = %s %q", e.Disposition, e.Detail)
	}
	if stub.ran.Load() != 0 {
		t.Fatal("an excluded operation was executed")
	}
}

// A check with no oracle must produce an untested row explaining why.
func TestInapplicableChecksExplainThemselves(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: false}
	res, err := Run(context.Background(), baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	e, _ := entryFor(res, "GET /a")
	if e.Disposition != model.DispositionUntested || e.Cause != model.CauseNoOracle {
		t.Errorf("ledger = %s/%s, want untested/no_oracle", e.Disposition, e.Cause)
	}
	if e.Detail == "" {
		t.Error("an untested row must say why")
	}
}

// A reader must be told which weakness classes nothing examined.
func TestClassesNotAssessedIsPopulated(t *testing.T) {
	stub := &stubCheck{id: check.AuthRequiredID, applies: true,
		result: check.Result{Disposition: model.DispositionExecuted}}
	res, err := Run(context.Background(), baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ClassesNotAssessed) == 0 {
		t.Fatal("no unassessed classes reported")
	}
	joined := strings.Join(res.ClassesNotAssessed, " ")
	if !strings.Contains(joined, "CWE-284") {
		t.Errorf("BOLA is not disclosed as unassessed: %v", res.ClassesNotAssessed)
	}
	if strings.Contains(joined, "CWE-306") {
		t.Error("a class that WAS assessed is listed as unassessed")
	}
}

func TestExecutedAndBlockedCounts(t *testing.T) {
	ops := []model.Operation{op("GET", "/a"), op("DELETE", "/b")}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	res, err := Run(context.Background(), baseOptions(ops, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExecutedCount() != 1 {
		t.Errorf("executed = %d, want 1", res.ExecutedCount())
	}
	if res.BlockedCount() != 1 {
		t.Errorf("blocked = %d, want 1", res.BlockedCount())
	}
}

// Checks collect evidence; if nothing persists it, findings reference nothing and
// the evidence directory stays empty while the documentation claims otherwise.
func TestEvidenceIsPersistedAndReferenced(t *testing.T) {
	ex := model.Exchange{
		Request:  model.CapturedRequest{Method: "GET", URL: "http://x.test/a"},
		Response: &model.CapturedResponse{Status: 200},
	}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{
		Disposition: model.DispositionExecuted,
		Exchanges:   []model.Exchange{ex, ex},
		Finding: &model.Finding{
			CheckID: "stub", Title: "t", State: model.StateSuspected,
			Severity: model.SeverityHigh, Confidence: model.ConfidenceLow,
			OperationID: "GET /a",
		},
	}}

	var stored int
	opts := baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub})
	opts.EvidenceSink = func(model.Exchange) (string, error) {
		stored++
		return "sha256:deadbeef", nil
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stored != 2 {
		t.Errorf("evidence sink called %d times, want 2", stored)
	}
	if len(res.Findings) != 1 || len(res.Findings[0].EvidenceRefs) != 2 {
		t.Errorf("finding carries %d evidence refs, want 2", len(res.Findings[0].EvidenceRefs))
	}
	e, _ := entryFor(res, "GET /a")
	if len(e.EvidenceRefs) != 2 {
		t.Errorf("ledger row carries %d evidence refs, want 2", len(e.EvidenceRefs))
	}
}

// A finding whose evidence could not be written is weaker than one whose evidence
// was, so the failure must surface rather than being discarded.
func TestEvidenceStorageFailureIsRecordedAsAToolFailure(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{
		Disposition: model.DispositionExecuted,
		Exchanges:   []model.Exchange{{Request: model.CapturedRequest{Method: "GET", URL: "http://x.test/a"}}},
	}}
	opts := baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub})
	opts.EvidenceSink = func(model.Exchange) (string, error) {
		return "", errors.New("disk full")
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ToolFailures) == 0 {
		t.Fatal("an evidence storage failure was silently discarded")
	}
	if !strings.Contains(strings.Join(res.ToolFailures, " "), "disk full") {
		t.Errorf("tool failures = %v, want the storage error", res.ToolFailures)
	}
}

// A nil sink must not panic: it simply means evidence is not retained.
func TestNilEvidenceSinkIsSafe(t *testing.T) {
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{
		Disposition: model.DispositionExecuted,
		Exchanges:   []model.Exchange{{Request: model.CapturedRequest{Method: "GET"}}},
	}}
	opts := baseOptions([]model.Operation{op("GET", "/a")}, []Check{stub})
	opts.EvidenceSink = nil
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run with a nil sink: %v", err)
	}
}

func TestInvalidProfileIsRejected(t *testing.T) {
	opts := baseOptions([]model.Operation{op("GET", "/a")}, nil)
	opts.Profile = "aggressive"
	if _, err := Run(context.Background(), opts); err == nil {
		t.Fatal("an invalid profile was accepted")
	}
}

// Output must be byte-stable so evaluation fixtures can be diffed.
func TestResultOrderingIsDeterministic(t *testing.T) {
	ops := []model.Operation{op("GET", "/z"), op("GET", "/a"), op("GET", "/m")}
	var last string
	for i := 0; i < 10; i++ {
		stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
		res, err := Run(context.Background(), baseOptions(ops, []Check{stub}))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		var b strings.Builder
		for _, e := range res.Coverage {
			b.WriteString(e.Key())
		}
		if i > 0 && b.String() != last {
			t.Fatal("coverage ordering is not deterministic across runs")
		}
		last = b.String()
	}
}

func TestCancellationStopsWork(t *testing.T) {
	ops := make([]model.Operation, 0, 50)
	for i := 0; i < 50; i++ {
		ops = append(ops, op("GET", "/p"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := baseOptions(ops, []Check{stub})
	opts.RequestsPerSecond = 1
	if _, err := Run(ctx, opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stub.ran.Load() > 2 {
		t.Errorf("work continued after cancellation: %d checks ran", stub.ran.Load())
	}
}

// Cancellation must not make a run look cleaner. Every planned job that never
// started still needs a ledger row, or a cancelled assessment silently reports
// less work and fewer problems than it planned.
func TestCancelledJobsStillAppearInTheLedger(t *testing.T) {
	ops := make([]model.Operation, 0, 20)
	for i := 0; i < 20; i++ {
		ops = append(ops, op("GET", fmt.Sprintf("/p%02d", i)))
	}
	stub := &stubCheck{id: "stub", applies: true, result: check.Result{Disposition: model.DispositionExecuted}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := Run(ctx, baseOptions(ops, []Check{stub}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Coverage) != len(ops) {
		t.Fatalf("coverage rows = %d, want %d — planned work vanished on cancellation",
			len(res.Coverage), len(ops))
	}
	cancelled := 0
	for _, e := range res.Coverage {
		if e.Cause == model.CauseCancelled {
			cancelled++
			if e.Disposition != model.DispositionBlocked {
				t.Errorf("cancelled row disposition = %s, want blocked", e.Disposition)
			}
		}
	}
	if cancelled == 0 {
		t.Error("no row attributes its absence to cancellation")
	}
}
