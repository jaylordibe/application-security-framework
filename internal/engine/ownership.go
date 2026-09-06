package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/resource"
)

// DimensionOwnership is the ledger dimension for cross-owner work.
//
// It is separate from the operation dimension because the two answer different
// questions. "This operation was checked for missing authentication" and
// "identity B could not read resource X through this operation" are not
// interchangeable, and a reader who cannot tell them apart will assume the
// second whenever they see the first.
const DimensionOwnership = "ownership"

// MaxOwnershipUnits bounds how much cross-owner work one run will plan.
//
// Fixtures multiply: every fixture applies to every operation it can address,
// for every identity that is not its owner. With explicitly configured fixtures
// that product is small, but the planner is where a future source of fixtures
// would make it large, so the bound exists now and is reported honestly rather
// than being discovered as a runaway run later. Work beyond the bound becomes an
// untested row, never a silent omission.
const MaxOwnershipUnits = 500

// ResourceCheck is a check whose unit of work is a resource, not an operation.
//
// It is a second interface rather than an extension of Check because the shape
// of the work genuinely differs: a Check is planned per operation and needs one
// identity, while this is planned per (operation, fixture, non-owner) and needs
// two. Folding both into one interface would give every existing check
// parameters it has no use for.
//
// It earns being an interface on the same terms Check does (ADR-0009): a test
// double is the second implementation, which is what lets this package test its
// own planning, evidence handling, finding identity, tool-failure propagation
// and cancellation without standing up an HTTP server. Testing the engine
// through a fixture application tests the fixture application.
type ResourceCheck interface {
	MetadataFor(check.ResourcePlan) check.Metadata
	RunResource(context.Context, check.ResourcePlan) check.Result
}

// ownershipUnit is one planned piece of cross-owner work together with the
// ledger row it will produce.
type ownershipUnit struct {
	plan check.ResourcePlan
	rc   ResourceCheck
}

// entry renders the unit's base ledger row.
func (u ownershipUnit) entry() model.CoverageEntry {
	return model.CoverageEntry{
		Dimension:       DimensionOwnership,
		Subject:         u.plan.Subject(),
		CheckID:         u.rc.MetadataFor(u.plan).ID,
		IdentityID:      attackerID(u.plan),
		ResourceID:      u.plan.Fixture.ID,
		OwnerIdentityID: u.plan.Fixture.Owner,
	}
}

func attackerID(p check.ResourcePlan) string {
	if p.Attacker == nil {
		return ""
	}
	return p.Attacker.ID()
}

// planOwnership expands fixtures and identities into cross-owner units, adding a
// ledger row for everything it decides not to run.
func planOwnership(opts Options, lg *ledger) []ownershipUnit {
	if opts.ResourceCheck == nil || len(opts.Resources) == 0 {
		return nil
	}

	fixtures := make([]resource.Fixture, len(opts.Resources))
	copy(fixtures, opts.Resources)
	resource.SortFixtures(fixtures)

	// Index readable operations by path template, so a mutation unit can find
	// the operation that observes its effect.
	readByPath := map[string]model.Operation{}
	for _, op := range opts.Surface.Operations {
		if model.IsSafeMethod(op.Method) && op.Method != "OPTIONS" {
			if _, seen := readByPath[op.PathTemplate]; !seen {
				readByPath[op.PathTemplate] = op
			}
		}
	}

	excluded := map[string]bool{}
	for _, id := range opts.ExcludeOperations {
		excluded[id] = true
	}

	var units []ownershipUnit
	var capped int

	for _, f := range fixtures {
		owner, ownerOK := opts.Identities.ByID(f.Owner)
		attackers := nonOwners(opts.Identities, f)

		if !ownerOK {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionBlocked, Cause: model.CauseMissingIdentity,
				Detail: fmt.Sprintf("fixture %q names owner %q, which is not a configured identity, "+
					"so ownership could not be established", f.ID, f.Owner),
			})
			continue
		}
		if len(attackers) == 0 {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionUntested, Cause: model.CauseMissingIdentity,
				Detail: fmt.Sprintf("fixture %q has no non-owner identity to probe with. A cross-owner "+
					"boundary needs a second identity; configure one, or list one in "+
					"resources[].nonOwners", f.ID),
			})
			continue
		}

		var addressable int
		for _, op := range opts.Surface.Operations {
			if !f.AppliesTo(op) {
				continue
			}
			binding, err := resource.Bind(op, f.Values)
			if err != nil {
				// Only report a fixture that was aimed at this operation
				// explicitly; otherwise every fixture would emit a row for every
				// operation in the specification.
				if len(f.Operations) > 0 {
					lg.add(model.CoverageEntry{
						Dimension: DimensionOwnership, Subject: op.ID, CheckID: check.CrossOwnerReadID,
						ResourceID: f.ID, OwnerIdentityID: f.Owner,
						Disposition: model.DispositionBlocked, Cause: model.CauseMissingResource,
						Detail: fmt.Sprintf("fixture %q cannot address this operation: %v", f.ID, err),
					})
				}
				continue
			}
			addressable++

			mutating := !model.IsSafeMethod(op.Method)
			for _, attacker := range attackers {
				plan := check.ResourcePlan{
					Operation: op, Fixture: f, URL: binding.URL,
					Owner: owner, Attacker: attacker, Mutate: mutating,
				}
				if mutating {
					if f.Mutation == nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
							model.CauseNoOracle,
							fmt.Sprintf("fixture %q configures no mutation values, so no write was "+
								"attempted. Set resources[].mutation.values to test whether a "+
								"non-owner can change this resource", f.ID)))
						continue
					}
					readOp, haveRead := readByPath[op.PathTemplate]
					if !haveRead {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseNoOracle,
							"no readable operation addresses this resource, so an unauthorized write "+
								"could not be verified by observing the owner's view of it. A write is "+
								"never confirmed from its own response status"))
						continue
					}
					readBinding, rerr := resource.Bind(readOp, f.Values)
					if rerr != nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseMissingResource,
							fmt.Sprintf("the readable operation for this resource could not be "+
								"addressed: %v", rerr)))
						continue
					}
					plan.ReadOperation = readOp
					plan.ReadURL = readBinding.URL
				}

				if excluded[op.ID] {
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
						model.CauseSafetyPolicy, "excluded by configuration"))
					continue
				}

				required := model.RequiredProfileForMethod(op.Method)
				if allowed, cause := model.GateProfile(opts.Profile, required); !allowed {
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked, cause,
						fmt.Sprintf("a cross-owner %s against somebody's real resource requires the %s "+
							"profile; the effective profile is %s. It was not attempted",
							op.Method, required, opts.Profile)))
					continue
				}

				if len(units) >= MaxOwnershipUnits {
					capped++
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
						model.CauseSafetyPolicy,
						fmt.Sprintf("this run planned more than %d cross-owner units and stopped "+
							"expanding. Narrow resources[].operations or resources[].nonOwners",
							MaxOwnershipUnits)))
					continue
				}
				units = append(units, ownershipUnit{plan: plan, rc: opts.ResourceCheck})
			}
		}

		if addressable == 0 {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionUntested, Cause: model.CauseMissingResource,
				Detail: fmt.Sprintf("no operation in the specification can be addressed with fixture "+
					"%q's values. Check that resources[].values names the operation's path "+
					"parameters exactly", f.ID),
			})
		}
	}
	return units
}

// planRow renders a ledger row for a unit that will not run.
func planRow(p check.ResourcePlan, rc ResourceCheck, d model.Disposition, cause model.BlockedCause, detail string) model.CoverageEntry {
	return model.CoverageEntry{
		Dimension:       DimensionOwnership,
		Subject:         p.Subject(),
		CheckID:         rc.MetadataFor(p).ID,
		IdentityID:      attackerID(p),
		ResourceID:      p.Fixture.ID,
		OwnerIdentityID: p.Fixture.Owner,
		Disposition:     d,
		Cause:           cause,
		Detail:          detail,
	}
}

// nonOwners returns the identities that should probe a fixture.
func nonOwners(set *identity.Set, f resource.Fixture) []*identity.Control {
	if set == nil {
		return nil
	}
	if len(f.NonOwners) > 0 {
		var out []*identity.Control
		for _, id := range f.NonOwners {
			if c, ok := set.ByID(id); ok && id != f.Owner {
				out = append(out, c)
			}
		}
		return out
	}
	var out []*identity.Control
	for _, c := range set.Controls() {
		if c.ID() != f.Owner {
			out = append(out, c)
		}
	}
	return out
}

// fixtureLocks serialises work that touches the same resource.
//
// Two units probing one fixture concurrently would interleave: a read's owner
// re-check could observe a write from another unit, and a write's before/after
// comparison could attribute somebody else's change to itself. Serialising per
// fixture — rather than serialising the whole engine — keeps different resources
// running in parallel while making each resource's sequence of observations
// mean what it says.
type fixtureLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func newFixtureLocks() *fixtureLocks { return &fixtureLocks{m: map[string]*sync.Mutex{}} }

func (f *fixtureLocks) get(id string) *sync.Mutex {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.m[id]; ok {
		return l
	}
	l := &sync.Mutex{}
	f.m[id] = l
	return l
}

// OwnershipSummary describes exactly which boundaries were tested.
//
// It is a list rather than a percentage. There is no denominator: the number of
// ownership boundaries an application has is unknown and unknowable from a
// specification, so any percentage would be invented. What can be stated
// truthfully is which tuples were exercised and which were not.
type OwnershipSummary struct {
	// Verified counts boundaries where a non-owner was demonstrably refused.
	Verified int
	// Findings counts boundaries where a non-owner was not refused.
	Findings int
	// Blocked counts units that could not establish anything.
	Blocked int
	// Untested counts units that were planned and deliberately not run.
	Untested int
	// Statement says in words what the numbers do and do not mean.
	Statement string
	// Boundaries lists each tested tuple, so a reader can see the actual extent.
	Boundaries []string
}

// summariseOwnership builds the ownership account from the ledger.
func summariseOwnership(entries []model.CoverageEntry) OwnershipSummary {
	var s OwnershipSummary
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Dimension != DimensionOwnership {
			continue
		}
		switch e.Disposition {
		case model.DispositionExecuted:
			s.Verified++
		case model.DispositionBlocked:
			s.Blocked++
		case model.DispositionUntested:
			s.Untested++
		}
		if e.Disposition == model.DispositionExecuted && e.ResourceID != "" {
			key := fmt.Sprintf("%s may not reach %s (owned by %s) via %s",
				e.IdentityID, e.ResourceID, e.OwnerIdentityID, e.Subject)
			if !seen[key] {
				seen[key] = true
				s.Boundaries = append(s.Boundaries, key)
			}
		}
	}
	sort.Strings(s.Boundaries)

	total := s.Verified + s.Blocked + s.Untested
	switch {
	case total == 0:
		s.Statement = "No resource fixtures were configured, so no ownership boundary was tested. " +
			"Nothing in this report says anything about whether one identity can reach another's data."
	default:
		// Position-neutral wording: this sentence is rendered above the list in
		// JSON and below it in the terminal, and a report that misdescribes its
		// own layout invites the reader to distrust the rest of it.
		s.Statement = fmt.Sprintf("This run exercised %d cross-owner boundary check(s), each named "+
			"individually, against the configured fixtures. It says nothing about any other "+
			"resource, any other identity pair, or any operation not named: an ownership boundary "+
			"that held here does not imply that the application enforces ownership anywhere else.",
			s.Verified)
	}
	return s
}

// ownershipFindings counts findings attributable to cross-owner checks.
func ownershipFindings(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if strings.HasPrefix(f.CheckID, "cross-owner-") {
			n++
		}
	}
	return n
}

// ownershipClasses are the weakness classes cross-owner work examines.
var ownershipClasses = []string{
	"CWE-284 broken access control (object level, BOLA/IDOR)",
	"CWE-639 authorization bypass through user-controlled key",
}

// qualifyOwnershipClasses annotates the not-assessed list once cross-owner work
// has actually run.
//
// The entries are qualified rather than removed. Removing them would say object-
// level authorization was covered, when what happened is that it was tested for
// the handful of resources somebody configured — which is a completely different
// claim, and the more flattering of the two. Leaving them untouched would be
// wrong in the other direction: the boundaries genuinely were probed.
//
// So the class stays on the list, with the extent attached to it.
func qualifyOwnershipClasses(classes []string, o OwnershipSummary) []string {
	if o.Verified == 0 {
		return classes
	}
	qualifier := fmt.Sprintf(" — assessed only for the %d cross-owner boundary check(s) listed under "+
		"ownership; not assessed for any other resource, identity pair or operation", o.Verified)
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		qualified := c
		for _, oc := range ownershipClasses {
			if c == oc {
				qualified = c + qualifier
				break
			}
		}
		out = append(out, qualified)
	}
	return out
}
