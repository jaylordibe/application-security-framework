// Assessment of a real, running application.
//
// The synthetic corpus in this package is deterministic, offline and fast, and
// it is why `go test ./...` is the whole story for a contributor. It is also how
// seven defects reached main: every one of them needed a real application to
// surface, and every one was invisible to fixtures that a contributor wrote to
// match the code they had just written.
//
// The specific blind spots, all now covered by targeted tests elsewhere:
// specifications whose paths are relative to a server base path, operations that
// take no path parameter, engines that are real binaries with real flags, and
// output an operator reads in a terminal rather than a JSON file.
//
// What this file adds is the part no fixture can: unknown unknowns. It runs the
// real assessment against a real application and asserts the invariants that
// must hold whatever that application is.
//
// It skips unless APPSEC_REFERENCE_TARGET is set, so it costs a contributor
// nothing and never makes `go test ./...` depend on a running service.
//
//	APPSEC_REFERENCE_TARGET=http://localhost:8000 \
//	APPSEC_REFERENCE_SPEC=http://localhost:8000/docs/api.json \
//	go test -v -run TestReferenceApplication ./evals/
package evals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// referenceRun performs one assessment against the configured application.
func referenceRun(t *testing.T) (engine.Result, report.Document) {
	t.Helper()
	target := os.Getenv("APPSEC_REFERENCE_TARGET")
	specURL := os.Getenv("APPSEC_REFERENCE_SPEC")
	if target == "" || specURL == "" {
		t.Skip("set APPSEC_REFERENCE_TARGET and APPSEC_REFERENCE_SPEC to assess a running " +
			"reference application")
	}

	origin, err := scope.ParseOrigin(target)
	if err != nil {
		t.Fatalf("APPSEC_REFERENCE_TARGET is not a usable origin: %v", err)
	}
	pol, err := scope.New([]scope.Entry{{Host: origin.Host, Ports: []int{origin.Port}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{
		Policy: pol, Redactor: red, Timeout: 20 * time.Second, RequestsPerSecond: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	ex, err := client.Do(context.Background(), httpx.Request{Method: "GET", URL: specURL})
	if err != nil || ex.Response == nil || ex.Response.Status != 200 {
		t.Fatalf("the specification at %s could not be fetched: %v", specURL, err)
	}
	parsed, err := openapi.Parse(ex.Response.Body, target,
		openapi.SourceAt(model.SourceOpenAPIURL, specURL, time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("the application's own specification did not parse: %v", err)
	}
	if len(parsed.Operations) == 0 {
		t.Fatal("the specification declared no operations, so this proves nothing")
	}

	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "reference", Target: target, Profile: model.ProfileVerification,
		Surface: engine.Surface{
			SpecDerived: true, SpecSource: parsed.Operations[0].Sources[0],
			Operations: parsed.Operations, Fidelity: parsed.Fidelity,
		},
		Checks:               []engine.Check{check.AuthRequired{Client: client, BaselineProbes: 2}},
		ExcludeAuthEndpoints: true,
		Concurrency:          4, RequestsPerSecond: 50,
		Now: time.Now,
	})
	if err != nil {
		t.Fatalf("the assessment failed against a running application: %v", err)
	}
	return res, report.Build(res, "reference")
}

// Every operation the specification declares is accounted for, exactly once.
//
// This is the ledger's core promise. An operation that produces no row is not
// untested — it is invisible, which is the failure this project exists to
// prevent, and it would be invisible in the summary too.
func TestReferenceApplicationAccountsForEveryOperation(t *testing.T) {
	res, doc := referenceRun(t)

	rows := map[string]int{}
	for _, c := range doc.Coverage {
		if c.Dimension == engine.DimensionOperation {
			rows[c.Subject]++
		}
	}
	for _, op := range res.Surface.Operations {
		switch n := rows[op.ID]; {
		case n == 0:
			t.Errorf("%s produced no ledger row: it is invisible rather than untested", op.ID)
		case n > 1:
			t.Errorf("%s produced %d ledger rows; one operation is one row per check", op.ID, n)
		}
	}
	t.Logf("%d operations, %d executed, %d blocked, %d untested",
		len(res.Surface.Operations), doc.Assurance.ExecutedChecks,
		doc.Assurance.BlockedChecks, doc.Assurance.UntestedSurface)
}

// Every row that did not execute says why, in a machine-readable way. "Blocked"
// without a cause is as useless as reporting nothing.
func TestReferenceApplicationExplainsEveryGap(t *testing.T) {
	_, doc := referenceRun(t)

	for _, c := range doc.Coverage {
		if c.Disposition == string(model.DispositionExecuted) {
			continue
		}
		if c.Cause == "" {
			t.Errorf("%s/%s is %s with no cause", c.Dimension, c.Subject, c.Disposition)
		}
		if !model.BlockedCause(c.Cause).Valid() {
			t.Errorf("%s/%s has unrecognised cause %q", c.Dimension, c.Subject, c.Cause)
		}
		if strings.TrimSpace(c.Detail) == "" {
			t.Errorf("%s/%s gives no operator-facing reason", c.Dimension, c.Subject)
		}
	}
}

// A confirmed finding against a real application must carry the evidence that
// confirmed it. This is the invariant that separates a finding from an opinion.
func TestReferenceApplicationConfirmedFindingsCarryEvidence(t *testing.T) {
	_, doc := referenceRun(t)

	for _, f := range doc.Findings {
		switch f.State {
		case string(model.StateConfirmed):
			if len(f.EvidenceRefs) == 0 {
				t.Errorf("confirmed finding %s carries no evidence reference", f.ID)
			}
			if !f.Verification.Performed {
				t.Errorf("confirmed finding %s records no verification", f.ID)
			}
		case string(model.StateObserved):
			if f.Severity != string(model.SeverityUnassessed) {
				t.Errorf("observed finding %s has severity %q; an imported observation is "+
					"unassessed", f.ID, f.Severity)
			}
		}
		if f.ID == "" {
			t.Errorf("a finding has no id, so no consumer can deduplicate it: %s", f.Title)
		}
	}
}

// The same application assessed twice produces the same account. Without this a
// ledger cannot be compared between runs, and comparison is what makes it useful
// in CI.
func TestReferenceApplicationIsReproducible(t *testing.T) {
	_, first := referenceRun(t)
	_, second := referenceRun(t)

	if h1, h2 := coverageHash(first), coverageHash(second); h1 != h2 {
		t.Errorf("two assessments of the same application produced different ledgers:\n  %s\n  %s",
			h1, h2)
	}
	if first.Assurance.ExecutedChecks != second.Assurance.ExecutedChecks {
		t.Errorf("executed checks differ between runs: %d then %d",
			first.Assurance.ExecutedChecks, second.Assurance.ExecutedChecks)
	}
	ids1, ids2 := findingIDs(first), findingIDs(second)
	if strings.Join(ids1, ",") != strings.Join(ids2, ",") {
		t.Errorf("finding identities are not stable between runs:\n  %v\n  %v", ids1, ids2)
	}
}

// The headline counters must describe the run. A summary whose numbers do not
// add up to the work it accounted for is a summary nobody can act on.
func TestReferenceApplicationCountersMatchTheLedger(t *testing.T) {
	_, doc := referenceRun(t)

	var executed, blocked, untested int
	for _, c := range doc.Coverage {
		if !engine.IsAssessmentWork(c.Dimension) {
			continue
		}
		switch c.Disposition {
		case string(model.DispositionExecuted):
			executed++
		case string(model.DispositionBlocked):
			blocked++
		case string(model.DispositionUntested):
			untested++
		}
	}
	if executed != doc.Assurance.ExecutedChecks {
		t.Errorf("executed: summary says %d, ledger has %d", doc.Assurance.ExecutedChecks, executed)
	}
	if blocked != doc.Assurance.BlockedChecks {
		t.Errorf("blocked: summary says %d, ledger has %d", doc.Assurance.BlockedChecks, blocked)
	}
	if untested != doc.Assurance.UntestedSurface {
		t.Errorf("untested: summary says %d, ledger has %d", doc.Assurance.UntestedSurface, untested)
	}

	// And the terminal an operator actually reads must agree with both.
	summary := report.Summary(doc)
	for label, n := range map[string]int{
		"executed:": executed, "blocked:": blocked, "untested:": untested,
	} {
		if !strings.Contains(summary, fmt.Sprintf("%s %d", label, n)) &&
			!strings.Contains(summary, fmt.Sprintf("%s  %d", label, n)) {
			t.Errorf("the terminal summary does not report %s %d:\n%s", label, n, summary)
		}
	}
}

// A run that executed nothing must never read as a clean result.
func TestReferenceApplicationNeverReadsCleanWithoutWork(t *testing.T) {
	_, doc := referenceRun(t)

	if doc.Assurance.ExecutedChecks == 0 {
		if !strings.Contains(doc.Assurance.Statement, "establishes nothing") {
			t.Errorf("a run that executed nothing does not say so: %q", doc.Assurance.Statement)
		}
	}
	// Whatever happened, the surface statement must never imply completeness.
	flat := strings.Join(strings.Fields(doc.Assurance.SurfaceCompleteness), " ")
	for _, forbidden := range []string{"%", " percent", "fully tested", "complete coverage"} {
		if strings.Contains(flat, forbidden) {
			t.Errorf("the surface statement implies completeness (%q): %s", forbidden, flat)
		}
	}
}

func coverageHash(doc report.Document) string {
	rows := make([]string, 0, len(doc.Coverage))
	for _, c := range doc.Coverage {
		rows = append(rows, strings.Join([]string{
			c.Dimension, c.Subject, c.CheckID, c.IdentityID, c.Disposition, c.Cause,
		}, "\x00"))
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

func findingIDs(doc report.Document) []string {
	out := make([]string, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}
