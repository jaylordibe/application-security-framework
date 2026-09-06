package engine

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/resource"
)

// Two boundaries that differ only in the resource must be two ledger rows.
// Collapsing them would let one tested boundary stand in for an untested one.
func TestOwnershipRowsAreKeyedByResourceAndOwner(t *testing.T) {
	base := model.CoverageEntry{
		Dimension: DimensionOwnership, Subject: "GET /api/orders/{id}",
		CheckID: check.CrossOwnerReadID, IdentityID: "bob",
	}
	a := base
	a.ResourceID, a.OwnerIdentityID = "order-1", "alice"
	b := base
	b.ResourceID, b.OwnerIdentityID = "order-2", "alice"
	c := base
	c.ResourceID, c.OwnerIdentityID = "order-1", "carol"

	if a.Key() == b.Key() {
		t.Error("two resources collapsed to one ledger key")
	}
	if a.Key() == c.Key() {
		t.Error("two owners collapsed to one ledger key")
	}
	// Two independently built rows describing the same boundary must key
	// identically, or the same unit would occupy two ledger rows.
	same := base
	same.ResourceID, same.OwnerIdentityID = "order-1", "alice"
	if a.Key() != same.Key() {
		t.Error("two rows describing the same boundary produced different keys")
	}
}

func TestSummariseOwnership(t *testing.T) {
	t.Run("nothing configured says so plainly", func(t *testing.T) {
		s := summariseOwnership(nil)
		if !strings.Contains(s.Statement, "No resource fixtures were configured") {
			t.Errorf("statement = %q", s.Statement)
		}
		if !strings.Contains(s.Statement, "Nothing in this report says anything") {
			t.Error("the statement does not say what the absence means")
		}
	})

	t.Run("counts and boundaries", func(t *testing.T) {
		s := summariseOwnership([]model.CoverageEntry{
			{Dimension: DimensionOwnership, Subject: "GET /a", IdentityID: "bob",
				ResourceID: "r1", OwnerIdentityID: "alice", Disposition: model.DispositionExecuted},
			{Dimension: DimensionOwnership, Subject: "GET /b", IdentityID: "bob",
				ResourceID: "r2", OwnerIdentityID: "alice", Disposition: model.DispositionBlocked},
			{Dimension: DimensionOwnership, Subject: "GET /c", IdentityID: "bob",
				ResourceID: "r3", OwnerIdentityID: "alice", Disposition: model.DispositionUntested},
			// An operation row must not be counted as ownership work.
			{Dimension: DimensionOperation, Subject: "GET /d", Disposition: model.DispositionExecuted},
		})
		if s.Verified != 1 || s.Blocked != 1 || s.Untested != 1 {
			t.Errorf("counts = %d/%d/%d, want 1/1/1", s.Verified, s.Blocked, s.Untested)
		}
		if len(s.Boundaries) != 1 {
			t.Fatalf("boundaries = %v, want exactly the executed one", s.Boundaries)
		}
		if !strings.Contains(s.Boundaries[0], "bob may not reach r1 (owned by alice)") {
			t.Errorf("boundary is not legible: %q", s.Boundaries[0])
		}
		// The statement must refuse to generalise.
		for _, must := range []string{"says nothing about any other resource", "does not imply",
			"each named individually"} {
			if !strings.Contains(s.Statement, must) {
				t.Errorf("statement does not disclaim generalisation (%q): %q", must, s.Statement)
			}
		}
	})
}

// A summary must never express itself as a percentage: the number of ownership
// boundaries an application has is unknowable from a specification.
func TestOwnershipSummaryHasNoPercentage(t *testing.T) {
	s := summariseOwnership([]model.CoverageEntry{
		{Dimension: DimensionOwnership, Subject: "GET /a", ResourceID: "r1",
			OwnerIdentityID: "alice", IdentityID: "bob", Disposition: model.DispositionExecuted},
	})
	if strings.Contains(s.Statement, "%") {
		t.Errorf("the ownership statement invents a percentage: %q", s.Statement)
	}
}

func TestNonOwnersNarrowing(t *testing.T) {
	// A nil identity set yields nothing rather than panicking: that is the
	// ordinary path when no identity is configured.
	if got := nonOwners(nil, resource.Fixture{Owner: "alice"}); got != nil {
		t.Errorf("nonOwners(nil) = %v, want nil", got)
	}
}

func TestPlanOwnershipWithoutFixturesPlansNothing(t *testing.T) {
	lg := &ledger{}
	units := planOwnership(Options{ResourceCheck: check.CrossOwner{}}, lg)
	if len(units) != 0 {
		t.Errorf("units = %d, want 0 with no fixtures", len(units))
	}
	if len(lg.entries) != 0 {
		t.Errorf("ledger rows = %d, want 0 with no fixtures", len(lg.entries))
	}
}

// A fixture whose owner is not a configured identity must block, naming the
// problem, rather than being silently dropped.
func TestPlanOwnershipBlocksAnUnknownOwner(t *testing.T) {
	lg := &ledger{}
	units := planOwnership(Options{
		ResourceCheck: check.CrossOwner{},
		Resources: []resource.Fixture{{
			ID: "r1", Owner: "ghost", CrossOwnerAccess: resource.CrossOwnerDenied,
			Values: map[string]string{"id": "1"},
		}},
	}, lg)
	if len(units) != 0 {
		t.Errorf("units = %d, want 0", len(units))
	}
	if len(lg.entries) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(lg.entries))
	}
	e := lg.entries[0]
	if e.Disposition != model.DispositionBlocked || e.Cause != model.CauseMissingIdentity {
		t.Errorf("row = %s/%s, want blocked/missing_identity", e.Disposition, e.Cause)
	}
	if !strings.Contains(e.Detail, "ghost") {
		t.Errorf("the row does not name the missing identity: %q", e.Detail)
	}
}

// Once cross-owner work has run, the not-assessed list must be neither wrong nor
// flattering: the class stays listed, with the extent attached.
func TestQualifyOwnershipClasses(t *testing.T) {
	classes := []string{
		"CWE-284 broken access control (object level, BOLA/IDOR)",
		"CWE-639 authorization bypass through user-controlled key",
		"CWE-89 SQL injection",
	}

	t.Run("no cross-owner work leaves the list untouched", func(t *testing.T) {
		got := qualifyOwnershipClasses(classes, OwnershipSummary{})
		for i := range classes {
			if got[i] != classes[i] {
				t.Errorf("entry %d changed with no ownership work: %q", i, got[i])
			}
		}
	})

	t.Run("executed work qualifies only the ownership classes", func(t *testing.T) {
		got := qualifyOwnershipClasses(classes, OwnershipSummary{Verified: 2})
		if !strings.Contains(got[0], "assessed only for the 2 cross-owner boundary check(s)") {
			t.Errorf("CWE-284 was not qualified: %q", got[0])
		}
		if !strings.Contains(got[1], "assessed only for the 2") {
			t.Errorf("CWE-639 was not qualified: %q", got[1])
		}
		if got[2] != "CWE-89 SQL injection" {
			t.Errorf("an unrelated class was altered: %q", got[2])
		}
		// The class must remain listed. Removing it would claim object-level
		// authorization is covered, which is a very different statement from
		// what actually happened.
		for _, c := range got[:2] {
			if !strings.HasPrefix(c, "CWE-") {
				t.Errorf("an ownership class stopped being a listed class: %q", c)
			}
		}
	})
}

// stubResourceCheck is the second implementation that earns the ResourceCheck
// interface.
//
// ADR-0009 is explicit that an interface with one implementation is indirection
// rather than abstraction. This one exists for the same reason the Check
// interface's does: it lets the engine's ownership execution path — evidence
// persistence, finding identity, tool-failure propagation, cancellation — be
// tested without an HTTP server, which is the difference between testing the
// engine and testing a fixture application through it.
type stubResourceCheck struct {
	mu     sync.Mutex
	ran    []string
	result check.Result
}

func (s *stubResourceCheck) MetadataFor(p check.ResourcePlan) check.Metadata {
	if p.Mutate {
		return check.Metadata{ID: check.CrossOwnerWriteID, Title: "stub write"}
	}
	return check.Metadata{ID: check.CrossOwnerReadID, Title: "stub read"}
}

func (s *stubResourceCheck) RunResource(ctx context.Context, p check.ResourcePlan) check.Result {
	s.mu.Lock()
	s.ran = append(s.ran, p.Fixture.ID+"|"+p.Subject()+"|"+attackerID(p))
	s.mu.Unlock()
	return s.result
}

func (s *stubResourceCheck) executed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.ran))
	copy(out, s.ran)
	sort.Strings(out)
	return out
}

// ownershipEngineOptions builds a run with two identities and one fixture,
// without any network.
func ownershipEngineOptions(t *testing.T, rc ResourceCheck, f resource.Fixture) Options {
	t.Helper()
	t.Setenv("APPSEC_STUB_A", "token-a")
	t.Setenv("APPSEC_STUB_B", "token-b")
	mk := func(id, env string) identity.Identity {
		return identity.Identity{ID: id, Auth: identity.Authentication{
			Scheme: identity.SchemeBearer, Credential: identity.CredentialSource{Env: env},
		}}
	}
	// No client is needed: the stub never issues a request, and Resolve only
	// reads credentials and registers them.
	ids := identity.Resolve([]identity.Identity{
		mk("alice", "APPSEC_STUB_A"), mk("bob", "APPSEC_STUB_B"),
	}, "http://target.test", nil, redact.New())

	return Options{
		RunID: "stub", Target: "http://target.test", Profile: model.ProfileVerification,
		Surface: Surface{SpecDerived: true, Operations: []model.Operation{{
			ID: "GET /api/orders/{orderId}", Method: "GET", PathTemplate: "/api/orders/{orderId}",
			BaseURL:    "http://target.test",
			Parameters: []model.Parameter{{Name: "orderId", In: "path", Required: true}},
		}}},
		ResourceCheck:     rc,
		Resources:         []resource.Fixture{f},
		Identities:        ids,
		Concurrency:       2,
		RequestsPerSecond: 1000,
		Now:               func() time.Time { return time.Unix(0, 0) },
	}
}

func aFixture() resource.Fixture {
	return resource.Fixture{
		ID: "order-a", Owner: "alice", CrossOwnerAccess: resource.CrossOwnerDenied,
		Values: map[string]string{"orderId": "abc123"}, Provenance: resource.ProvenanceConfigured,
	}
}

// The engine must plan one unit per (fixture, operation, non-owner) and carry the
// check's result onto a correctly identified ledger row.
func TestEngineRunsOwnershipUnitsAndRecordsThem(t *testing.T) {
	stub := &stubResourceCheck{result: check.Result{
		Disposition: model.DispositionExecuted, Detail: "boundary held",
	}}
	res, err := Run(context.Background(), ownershipEngineOptions(t, stub, aFixture()))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := stub.executed(); len(got) != 1 || got[0] != "order-a|GET /api/orders/{orderId}|bob" {
		t.Fatalf("units executed = %v, want exactly the owner/non-owner pair", got)
	}

	var row *model.CoverageEntry
	for i, e := range res.Coverage {
		if e.Dimension == DimensionOwnership {
			row = &res.Coverage[i]
		}
	}
	if row == nil {
		t.Fatal("no ownership ledger row")
	}
	if row.ResourceID != "order-a" || row.OwnerIdentityID != "alice" || row.IdentityID != "bob" {
		t.Errorf("row does not identify the parties: %+v", row)
	}
	if row.Disposition != model.DispositionExecuted || row.Detail != "boundary held" {
		t.Errorf("the check's result was not carried onto the row: %+v", row)
	}
	if res.Ownership.Verified != 1 {
		t.Errorf("ownership summary verified = %d, want 1", res.Ownership.Verified)
	}
}

// A finding from a cross-owner unit must carry an id that distinguishes the
// resource and the non-owner, or a consumer deduplicating on id would keep one
// finding and discard the rest.
func TestOwnershipFindingIDsDistinguishResourceAndAttacker(t *testing.T) {
	stub := &stubResourceCheck{result: check.Result{
		Disposition: model.DispositionExecuted,
		Finding: &model.Finding{
			CheckID: check.CrossOwnerReadID, State: model.StateConfirmed,
			OperationID: "GET /api/orders/{orderId}", ResourceID: "order-a",
		},
	}}
	res, err := Run(context.Background(), ownershipEngineOptions(t, stub, aFixture()))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	id := res.Findings[0].ID
	for _, part := range []string{check.CrossOwnerReadID, "GET /api/orders/{orderId}", "order-a", "bob"} {
		if !strings.Contains(id, part) {
			t.Errorf("finding id %q does not carry %q", id, part)
		}
	}
	if res.Ownership.Findings != 1 {
		t.Errorf("ownership summary findings = %d, want 1", res.Ownership.Findings)
	}
}

// A check that left the target modified must surface that as run-level tool
// state, not bury it in a ledger detail nobody reads.
func TestOwnershipToolFailureBecomesRunState(t *testing.T) {
	stub := &stubResourceCheck{result: check.Result{
		Disposition: model.DispositionExecuted,
		Detail:      "changed",
		ToolFailure: `fixture "order-a" was modified and could not be restored`,
	}}
	res, err := Run(context.Background(), ownershipEngineOptions(t, stub, aFixture()))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var found bool
	for _, f := range res.ToolFailures {
		if strings.Contains(f, "could not be restored") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a failed restoration did not reach ToolFailures: %v", res.ToolFailures)
	}
}

// Cancellation must leave a ledger row for every unit that was planned and not
// reached. A shorter run must never simply look cleaner.
func TestCancelledOwnershipUnitsStillAppearInTheLedger(t *testing.T) {
	stub := &stubResourceCheck{result: check.Result{Disposition: model.DispositionExecuted}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := Run(ctx, ownershipEngineOptions(t, stub, aFixture()))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := stub.executed(); len(got) != 0 {
		t.Errorf("units ran after cancellation: %v", got)
	}
	var cancelled int
	for _, e := range res.Coverage {
		if e.Dimension == DimensionOwnership && e.Cause == model.CauseCancelled {
			cancelled++
		}
	}
	if cancelled != 1 {
		t.Fatalf("cancelled ownership rows = %d, want 1; a planned unit vanished from the ledger",
			cancelled)
	}
}
