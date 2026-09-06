// Package engine runs an assessment: it plans work, gates it against the safety
// profile, executes it, and records both what happened and what did not.
//
// The ledger is the point. Any scanner can report what it found; this one is
// built so that a run cannot quietly omit what it never attempted.
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/adapter"
	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/identity"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/resource"
	"github.com/jaylordibe/application-security-framework/internal/scanner"
)

// Check is the contract the engine consumes.
//
// It is declared here, where it is used, rather than beside its implementation.
// Unlike the storage seam, this interface earns itself immediately: the engine
// iterates a heterogeneous set, the safety gate needs a uniform way to ask what
// a check requires, and a test double is the second implementation on day one.
type Check interface {
	Metadata() check.Metadata
	// RequiredProfile reports the profile needed for this operation, so that
	// impact is a property of the work rather than of the check.
	RequiredProfile(model.Operation) model.Profile
	// Applicable reports whether an oracle exists, and why not when it does not.
	Applicable(model.Operation) (bool, model.BlockedCause, string)
	Run(context.Context, model.Operation) check.Result
}

// Surface describes the attack surface and, critically, how much of it we can
// see.
//
// SpecDerived is recorded because it bounds every coverage number in the run:
// when the surface comes from a specification, an undocumented route is not
// untested, it is invisible. Reporting coverage against a surface handed to us
// by the thing we are auditing would reproduce, one level up, exactly the
// false-assurance failure this project exists to prevent.
type Surface struct {
	SpecDerived  bool
	SpecSource   model.Source
	SpecTitle    string
	SpecVersion  string
	Fidelity     openapi.Fidelity
	Operations   []model.Operation
	ExternalRefs []string
	Warnings     []string

	// Adapter* record what framework adapters contributed, and — at least as
	// importantly — what they could not. An adapter that failed found no
	// controls, and an application with no controls also has no controls; the
	// two must never read the same.
	AdapterMerges      []adapter.Merge
	AdapterFailures    []string
	AdapterLimitations []string
	AdapterUnmatched   []string
}

// Environment records operator-stated differences from production.
type Environment struct {
	Name        string
	Differences []string
}

// Options configures a run.
type Options struct {
	RunID        string
	Target       string
	TargetName   string
	Profile      model.Profile
	Surface      Surface
	Checks       []Check
	Environment  Environment
	ScopeEntries []string
	AllowPrivate bool
	// ExcludeOperations lists operation ids that must never be exercised.
	ExcludeOperations []string
	// ExcludeAuthEndpoints skips operations that look like authentication
	// routes, so that a sweep cannot trip account lockout.
	ExcludeAuthEndpoints bool
	Concurrency          int
	RequestsPerSecond    float64
	// Identities are the configured principals and their authenticated
	// controls. Nil means none is configured, in which case the run behaves
	// exactly as it did before identities existed.
	Identities *identity.Set
	// Resources are the configured resource fixtures. Empty means no
	// cross-owner work is planned, and the run behaves exactly as it did before
	// fixtures existed.
	Resources []resource.Fixture
	// ResourceCheck runs cross-owner work. Nil disables it.
	ResourceCheck ResourceCheck
	// Engines is what the external scanning engines contributed, including what
	// they failed to do.
	Engines scanner.Collection
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
	// EvidenceSink persists a captured exchange and returns a reference to it.
	//
	// It is a function rather than an interface so that the engine does not
	// depend on the storage package. When nil, evidence is discarded and
	// findings carry no references — which is why the CLI always supplies one.
	EvidenceSink func(model.Exchange) (string, error)
}

// Result is everything one assessment produced.
type Result struct {
	RunID        string
	Target       string
	TargetName   string
	Profile      model.Profile
	StartedAt    time.Time
	FinishedAt   time.Time
	Surface      Surface
	Environment  Environment
	ScopeEntries []string
	AllowPrivate bool

	Findings []model.Finding
	Coverage []model.CoverageEntry
	// ToolFailures records engines or components that failed. A failure is never
	// an absence of findings.
	ToolFailures []string
	// OutOfScopeHosts were discovered and deliberately not contacted.
	OutOfScopeHosts []string
	// ClassesNotAssessed names weakness classes no check covered. Without this,
	// a report of "no findings" implies far more than it should.
	ClassesNotAssessed []string
	// Identities records what was known about each configured identity. It
	// carries no credential, no credential length and no fingerprint.
	Identities []identity.Status
	// Ownership accounts for the cross-owner boundaries this run exercised, and
	// states plainly what they do not cover.
	Ownership OwnershipSummary
	// Engines is the external engine account.
	Engines scanner.Collection
}

// DimensionOperation is the ledger dimension for assessment work against one
// operation.
const DimensionOperation = "operation"

// DimensionIdentity is the ledger dimension for whether a configured identity
// could be used at all.
//
// Identity rows are ledger material rather than a report footnote: "could this
// identity authenticate?" is a unit of intended work that can be blocked, and a
// run in which it was blocked has tested less than a run in which it was not.
const DimensionIdentity = "identity"

// ExecutedCount returns how many assessment checks actually ran.
//
// Assessment work is counted; preconditions are not. An identity row records
// whether a credential worked, which has to happen before anything can be
// tested but is not itself a test — counting one would let merely configuring an
// identity inflate the number of checks a run claims to have executed.
//
// Cross-owner work does count. It is assessment: a boundary was probed and an
// answer obtained. Leaving it out produced a run that reported confirmed
// findings underneath the sentence "this assessment executed no checks", which
// is precisely the contradiction the assurance statement exists to prevent.
func (r Result) ExecutedCount() int {
	return r.countDisposition(model.DispositionExecuted)
}

// BlockedCount returns how many assessment checks were blocked.
func (r Result) BlockedCount() int {
	return r.countDisposition(model.DispositionBlocked)
}

// IsAssessmentWork reports whether a ledger dimension represents work that tests
// the target, as opposed to a precondition for testing it.
func IsAssessmentWork(dimension string) bool {
	return dimension == DimensionOperation ||
		dimension == DimensionOwnership ||
		// An external engine run is assessment: it was planned work against the
		// target. Leaving it out produced a summary reading "blocked: 0" while
		// three engines had failed, which understates exactly the thing this
		// milestone exists to make visible.
		dimension == scanner.DimensionEngine
}

func (r Result) countDisposition(d model.Disposition) int {
	n := 0
	for _, e := range r.Coverage {
		if IsAssessmentWork(e.Dimension) && e.Disposition == d {
			n++
		}
	}
	return n
}

// ledger accumulates coverage entries from concurrent checks.
type ledger struct {
	mu      sync.Mutex
	entries []model.CoverageEntry
}

func (l *ledger) add(e model.CoverageEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

// authPathHints match routes where an unauthenticated sweep risks locking real
// accounts or burning one-time codes.
var authPathHints = []string{
	"login", "signin", "sign-in", "authenticate", "auth/token", "oauth",
	"register", "signup", "sign-up", "password", "forgot", "reset",
	"verify", "otp", "mfa", "2fa", "token/refresh", "refresh-token",
}

// Run executes an assessment.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if !opts.Profile.Valid() {
		return Result{}, fmt.Errorf("engine: invalid profile %q", opts.Profile)
	}

	res := Result{
		RunID:        opts.RunID,
		Target:       opts.Target,
		TargetName:   opts.TargetName,
		Profile:      opts.Profile,
		StartedAt:    opts.Now(),
		Surface:      opts.Surface,
		Environment:  opts.Environment,
		ScopeEntries: opts.ScopeEntries,
		AllowPrivate: opts.AllowPrivate,
	}

	lg := &ledger{}
	var findingsMu sync.Mutex
	var findings []model.Finding

	// Establish whether each configured identity can authenticate, before any
	// assessment work depends on it.
	//
	// Doing this first matters. An identity that is already dead would otherwise
	// be discovered one failed control at a time, and every one of those
	// failures would be indistinguishable from an application that is correctly
	// refusing access.
	probeIdentities(ctx, opts.Identities)

	excluded := map[string]bool{}
	for _, id := range opts.ExcludeOperations {
		excluded[id] = true
	}

	type job struct {
		op model.Operation
		ck Check
	}
	var jobs []job

	// Planning. Every operation that is not planned produces a ledger row
	// explaining why, so the difference between "tested and clean" and "never
	// attempted" is always visible.
	for _, op := range opts.Surface.Operations {
		for _, ck := range opts.Checks {
			meta := ck.Metadata()
			base := model.CoverageEntry{
				Dimension:  DimensionOperation,
				Subject:    op.ID,
				CheckID:    meta.ID,
				IdentityID: model.AnonymousIdentity().ID,
			}

			if excluded[op.ID] {
				base.Disposition = model.DispositionUntested
				base.Cause = model.CauseSafetyPolicy
				base.Detail = "excluded by configuration"
				lg.add(base)
				continue
			}
			if opts.ExcludeAuthEndpoints && looksLikeAuthRoute(op.PathTemplate) {
				base.Disposition = model.DispositionUntested
				base.Cause = model.CauseSafetyPolicy
				base.Detail = "skipped because the path looks like an authentication route; " +
					"sweeping these can lock real accounts. Set assessment.excludeAuthEndpoints " +
					"to false to include them"
				lg.add(base)
				continue
			}

			if ok, cause, why := ck.Applicable(op); !ok {
				base.Disposition = model.DispositionUntested
				base.Cause = cause
				base.Detail = why
				lg.add(base)
				continue
			}

			required := ck.RequiredProfile(op)
			if allowed, cause := model.GateProfile(opts.Profile, required); !allowed {
				base.Disposition = model.DispositionBlocked
				base.Cause = cause
				base.Detail = fmt.Sprintf(
					"this operation uses %s, which requires the %s profile; the effective profile is %s. "+
						"Sending it could change or destroy data, so it was not attempted",
					op.Method, required, opts.Profile)
				lg.add(base)
				continue
			}

			jobs = append(jobs, job{op: op, ck: ck})
		}
	}

	// Cross-owner planning. Fixtures multiply operations by identities, so this
	// is where growth is bounded; everything not planned gets a ledger row.
	ownership := planOwnership(opts, lg)

	// Execution.
	controls := &controlLog{}
	locks := newFixtureLocks()
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var failuresMu sync.Mutex
	failures := map[string]struct{}{}

	for i, j := range jobs {
		if ctx.Err() != nil {
			// Every planned job must appear in the ledger. Abandoning the
			// remainder silently would be precisely the omission this package
			// exists to prevent — a shorter run would simply look cleaner.
			for _, remaining := range jobs[i:] {
				lg.add(model.CoverageEntry{
					Dimension:   DimensionOperation,
					Subject:     remaining.op.ID,
					CheckID:     remaining.ck.Metadata().ID,
					IdentityID:  model.AnonymousIdentity().ID,
					Disposition: model.DispositionBlocked,
					Cause:       model.CauseCancelled,
					Detail:      "the assessment was cancelled before this operation was reached",
				})
			}
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			out := j.ck.Run(ctx, j.op)
			meta := j.ck.Metadata()

			for _, u := range out.ControlsUsed {
				controls.record(controlUse{
					subject:    j.op.ID,
					checkID:    meta.ID,
					identityID: u.IdentityID,
					at:         u.At,
				})
			}

			// Persist the evidence first, so both the ledger row and any finding
			// can reference it rather than embedding copies.
			refs, sinkErrs := storeExchanges(opts.EvidenceSink, out.Exchanges)
			for _, e := range sinkErrs {
				failuresMu.Lock()
				failures["evidence: "+e] = struct{}{}
				failuresMu.Unlock()
			}

			lg.add(model.CoverageEntry{
				Dimension:    DimensionOperation,
				Subject:      j.op.ID,
				CheckID:      meta.ID,
				IdentityID:   model.AnonymousIdentity().ID,
				Disposition:  out.Disposition,
				Cause:        out.Cause,
				Detail:       out.Detail,
				EvidenceRefs: refs,
			})

			if out.Disposition == model.DispositionBlocked && out.Cause == model.CauseTransportError {
				failuresMu.Lock()
				failures[meta.ID+": "+out.Detail] = struct{}{}
				failuresMu.Unlock()
			}

			if out.Finding != nil {
				f := *out.Finding
				f.ID = findingID(meta.ID, j.op.ID)
				if len(f.EvidenceRefs) == 0 {
					f.EvidenceRefs = refs
				}
				findingsMu.Lock()
				findings = append(findings, f)
				findingsMu.Unlock()
			}
		}(j)
	}

	for i, u := range ownership {
		if ctx.Err() != nil {
			for _, remaining := range ownership[i:] {
				e := remaining.entry()
				e.Disposition = model.DispositionBlocked
				e.Cause = model.CauseCancelled
				e.Detail = "the assessment was cancelled before this cross-owner unit was reached"
				lg.add(e)
			}
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u ownershipUnit) {
			defer wg.Done()
			defer func() { <-sem }()

			// Serialise per fixture: two units observing one resource
			// concurrently would interleave their reads and writes, and each
			// would attribute the other's effect to itself.
			lock := locks.get(u.plan.Fixture.ID)
			lock.Lock()
			defer lock.Unlock()

			out := u.rc.RunResource(ctx, u.plan)
			meta := u.rc.MetadataFor(u.plan)

			for _, cu := range out.ControlsUsed {
				controls.record(controlUse{
					subject:    u.plan.Subject(),
					checkID:    meta.ID,
					identityID: cu.IdentityID,
					at:         cu.At,
					resourceID: u.plan.Fixture.ID,
				})
			}

			refs, sinkErrs := storeExchanges(opts.EvidenceSink, out.Exchanges)
			for _, e := range sinkErrs {
				failuresMu.Lock()
				failures["evidence: "+e] = struct{}{}
				failuresMu.Unlock()
			}

			entry := u.entry()
			entry.Disposition = out.Disposition
			entry.Cause = out.Cause
			entry.Detail = out.Detail
			entry.EvidenceRefs = refs
			lg.add(entry)

			if out.ToolFailure != "" {
				failuresMu.Lock()
				failures[meta.ID+": "+out.ToolFailure] = struct{}{}
				failuresMu.Unlock()
			}
			if out.Disposition == model.DispositionBlocked && out.Cause == model.CauseTransportError {
				failuresMu.Lock()
				failures[meta.ID+": "+out.Detail] = struct{}{}
				failuresMu.Unlock()
			}

			if out.Finding != nil {
				f := *out.Finding
				f.ID = ownershipFindingID(meta.ID, u.plan)
				if len(f.EvidenceRefs) == 0 {
					f.EvidenceRefs = refs
				}
				findingsMu.Lock()
				findings = append(findings, f)
				findingsMu.Unlock()
			}
		}(u)
	}

	wg.Wait()

	// Probe each identity again now that the work is done.
	//
	// A credential that expired mid-run is only ever observed by a later probe:
	// nothing announces an expiry at the moment it happens. The closing probe
	// bounds the uncertainty window at the end of the run, and any control that
	// ran inside that window is re-scored below.
	probeIdentities(ctx, opts.Identities)

	res.Coverage = lg.entries
	res.Findings = findings
	res.Identities = opts.Identities.Statuses()
	res.Coverage = append(res.Coverage, identityCoverage(res.Identities)...)
	invalidateExpiredControls(&res, controls.snapshot(), res.Identities)
	res.Ownership = summariseOwnership(res.Coverage)
	res.Ownership.Findings = ownershipFindings(res.Findings)

	// External engine work joins the ledger and the findings. A row is added
	// whether the engine succeeded or failed, because an engine that failed is
	// a class nobody assessed and silence about it is how a reader comes to
	// believe otherwise. An engine nobody enabled gets no row: it was never
	// planned work, and counting it would inflate "untested" with everything
	// this tool could conceivably have been configured to do.
	res.Engines = opts.Engines
	res.Coverage = append(res.Coverage, opts.Engines.Coverage...)
	res.Findings = append(res.Findings, opts.Engines.Findings...)
	res.ToolFailures = append(res.ToolFailures, opts.Engines.Failures...)
	for f := range failures {
		res.ToolFailures = append(res.ToolFailures, f)
	}
	res.ClassesNotAssessed = removeEngineCovered(
		qualifyOwnershipClasses(classesNotAssessed(opts.Checks), res.Ownership),
		opts.Engines)
	res.FinishedAt = opts.Now()

	sortResult(&res)
	return res, nil
}

// storeExchanges persists captured evidence and returns its references.
//
// A failure to store evidence is recorded as a tool failure rather than
// discarded: a finding whose evidence could not be written is weaker than one
// whose evidence was, and the report must be able to say so.
func storeExchanges(sink func(model.Exchange) (string, error), exchanges []model.Exchange) ([]string, []string) {
	if sink == nil || len(exchanges) == 0 {
		return nil, nil
	}
	refs := make([]string, 0, len(exchanges))
	var errs []string
	for _, ex := range exchanges {
		ref, err := sink(ex)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		refs = append(refs, ref)
	}
	return refs, errs
}

// sortResult orders every slice deterministically, so that two identical runs
// produce byte-identical output and evaluation fixtures can be diffed.
func sortResult(r *Result) {
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].OperationID != r.Findings[j].OperationID {
			return r.Findings[i].OperationID < r.Findings[j].OperationID
		}
		return r.Findings[i].CheckID < r.Findings[j].CheckID
	})
	sort.Slice(r.Coverage, func(i, j int) bool {
		return r.Coverage[i].Key() < r.Coverage[j].Key()
	})
	sort.Strings(r.ToolFailures)
	sort.Strings(r.OutOfScopeHosts)
	sort.Strings(r.ClassesNotAssessed)
}

// findingID builds a stable identifier so the same finding keeps its identity
// across runs, which consumers rely on for deduplication.
func findingID(checkID, operationID string) string {
	return checkID + ":" + operationID
}

// looksLikeAuthRoute reports whether a path resembles an authentication route.
func looksLikeAuthRoute(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range authPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// assessedClasses maps a check to the weakness classes it covers.
var assessedClasses = map[string][]string{
	check.AuthRequiredID: {"CWE-306"},
}

// notableClasses are weakness classes a reader of a security report will
// reasonably assume were considered.
var notableClasses = []string{
	"CWE-284 broken access control (object level, BOLA/IDOR)",
	"CWE-285 broken function-level authorization",
	"CWE-639 authorization bypass through user-controlled key",
	"CWE-89 SQL injection",
	"CWE-79 cross-site scripting",
	"CWE-918 server-side request forgery",
	"CWE-22 path traversal",
	"CWE-352 cross-site request forgery",
	"CWE-770 missing rate limiting",
	"CWE-915 mass assignment",
	"business logic and workflow abuse",
	"multi-tenant isolation",
}

// classesNotAssessed lists what nothing in this run looked at.
func classesNotAssessed(checks []Check) []string {
	covered := map[string]bool{}
	for _, c := range checks {
		for _, cls := range assessedClasses[c.Metadata().ID] {
			covered[cls] = true
		}
	}
	var out []string
	for _, cls := range notableClasses {
		key := strings.SplitN(cls, " ", 2)[0]
		if !covered[key] {
			out = append(out, cls)
		}
	}
	return out
}

// Request pacing lives in the HTTP client rather than here.
//
// Limiting once per job was wrong: a single check issues several requests
// (baseline probes, the primary request, a repeat, a credential probe), so the
// configured rate was exceeded by roughly that factor — and getting rate limited
// is precisely how an assessment turns into a falsely clean report.

// controlUse records that one ledger row's result depended on an authenticated
// control request issued by a named identity at a known time.
type controlUse struct {
	subject    string
	checkID    string
	identityID string
	at         time.Time
	// resourceID is set for cross-owner work, whose rows are keyed by resource
	// as well as by operation.
	resourceID string
}

// controlLog accumulates control usage from concurrent checks.
type controlLog struct {
	mu   sync.Mutex
	uses []controlUse
}

func (c *controlLog) record(u controlUse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uses = append(c.uses, u)
}

func (c *controlLog) snapshot() []controlUse {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]controlUse, len(c.uses))
	copy(out, c.uses)
	return out
}

// probeIdentities runs each identity's liveness canary.
//
// A probe is best-effort by design: an identity with no canary configured
// cannot be probed, and a transport failure leaves the previous knowledge
// intact rather than declaring the credential dead because the network
// stuttered. What a probe must never do is turn an unknown into a good.
func probeIdentities(ctx context.Context, ids *identity.Set) {
	if ids == nil {
		return
	}
	for _, c := range ids.Controls() {
		if ctx.Err() != nil {
			return
		}
		c.Probe(ctx)
	}
}

// identityCoverage turns each identity's status into a ledger row.
//
// This is what makes an authentication limitation visible in the ledger rather
// than only in a finding's prose. A run whose only identity could not
// authenticate has verified less than one whose identity could, and the
// coverage account has to say so.
func identityCoverage(statuses []identity.Status) []model.CoverageEntry {
	out := make([]model.CoverageEntry, 0, len(statuses))
	for _, st := range statuses {
		e := model.CoverageEntry{
			Dimension:  DimensionIdentity,
			Subject:    st.ID,
			IdentityID: st.ID,
		}
		switch {
		case !st.Usable:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseMissingIdentity
			e.Detail = "the credential could not be resolved from " + st.Source + ": " + st.Problem +
				". No authenticated control request was possible, so no finding for any operation " +
				"could be corroborated against a legitimate caller"
		case st.Liveness == identity.LivenessBad:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseAuthenticationFailed
			e.Detail = "the identity was rejected by the target: " + st.Problem +
				". Authenticated control requests using it are not trustworthy"
		case st.Liveness == identity.LivenessGood:
			e.Disposition = model.DispositionExecuted
			e.Detail = "the liveness canary confirmed this identity authenticates successfully"
		case !st.Monitored:
			e.Disposition = model.DispositionUntested
			e.Cause = model.CauseNoOracle
			e.Detail = "no liveness canary is configured for this identity, so an expiry during the " +
				"run could not be detected. Set identities[].liveness to a safe, " +
				"authentication-requiring operation to close this gap"
		default:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseAuthenticationFailed
			e.Detail = "the liveness canary did not complete, so it is not known whether this " +
				"identity can authenticate"
			if st.Problem != "" {
				e.Detail += ": " + st.Problem
			}
		}
		out = append(out, e)
	}
	return out
}

// invalidateExpiredControls re-scores work that depended on an identity later
// found to be invalid.
//
// A liveness canary observes an expiry when it next runs, not when it happens,
// so the interval between the last good probe and the first bad one is a window
// in which the credential's validity is genuinely unknown. Anything corroborated
// by a control request issued inside that window is therefore corroborated by
// something that may already have been dead.
//
// Two things happen to such work, and the asymmetry is deliberate:
//
//   - The ledger row becomes blocked{authentication_failed}. The check's result
//     rested on the control, and a result resting on an untrusted control has
//     not established what it claims.
//   - A confirmed finding is demoted to suspected rather than discarded. The
//     anonymous observation behind it did not involve the credential at all, so
//     deleting the finding would hide a real unauthenticated success. Only the
//     corroboration is withdrawn.
//
// The one thing that must never happen is the reverse: an expired credential
// making an operation look protected. That cannot arise here because a finding
// is only ever raised by an anonymous success, never by an authenticated
// failure.
func invalidateExpiredControls(res *Result, uses []controlUse, statuses []identity.Status) {
	windows := make(map[string]identity.Status, len(statuses))
	for _, st := range statuses {
		if _, _, ok := st.UncertaintyWindow(); ok {
			windows[st.ID] = st
		}
	}
	if len(windows) == 0 || len(uses) == 0 {
		return
	}

	type key struct{ subject, checkID, resourceID string }
	affected := make(map[key]identity.Status)
	for _, u := range uses {
		st, bad := windows[u.identityID]
		if !bad {
			continue
		}
		lastGood, _, _ := st.UncertaintyWindow()
		// A control that completed at or before the last good canary is backed
		// by a credential that was confirmed working afterwards.
		if !u.at.IsZero() && !lastGood.IsZero() && !u.at.After(lastGood) {
			continue
		}
		affected[key{u.subject, u.checkID, u.resourceID}] = st
	}
	if len(affected) == 0 {
		return
	}

	for i := range res.Coverage {
		e := &res.Coverage[i]
		if e.Dimension != DimensionOperation && e.Dimension != DimensionOwnership {
			continue
		}
		st, hit := affected[key{e.Subject, e.CheckID, e.ResourceID}]
		if !hit {
			continue
		}
		e.Disposition = model.DispositionBlocked
		e.Cause = model.CauseAuthenticationFailed
		e.Detail = e.Detail + ". This result is withdrawn: identity " + st.ID +
			" was found invalid at " + st.FirstBad.UTC().Format(time.RFC3339) +
			", and the authenticated control it relied on ran after the last confirmed-good canary at " +
			lastGoodLabel(st) + ", so the credential may already have expired when it was used"
	}

	for i := range res.Findings {
		f := &res.Findings[i]
		st, hit := affected[key{f.OperationID, f.CheckID, f.ResourceID}]
		if !hit {
			continue
		}
		note := "authenticated-control-request: identity " + st.ID + " was found invalid at " +
			st.FirstBad.UTC().Format(time.RFC3339) + "; the control that corroborated this finding ran " +
			"after the last confirmed-good canary at " + lastGoodLabel(st) + ", so the corroboration " +
			"is withdrawn and the finding is reported as suspected"
		f.Verification.Unavailable = append(f.Verification.Unavailable, note)
		if f.State == model.StateConfirmed {
			f.State = model.StateSuspected
			f.Confidence = model.ConfidenceMedium
		}
	}
}

// lastGoodLabel renders the last confirmed-good time, or says plainly that
// there was never one.
func lastGoodLabel(st identity.Status) string {
	if st.LastGood.IsZero() {
		return "no point at all — the identity was never confirmed good"
	}
	return st.LastGood.UTC().Format(time.RFC3339)
}

// ownershipFindingID builds a stable identifier for a cross-owner finding.
//
// It includes the resource and the non-owner, because the same operation can
// produce a different finding for a different resource or a different identity,
// and a consumer deduplicating on the id would otherwise lose all but one.
func ownershipFindingID(checkID string, p check.ResourcePlan) string {
	return strings.Join([]string{checkID, p.Subject(), p.Fixture.ID, attackerID(p)}, ":")
}

// removeEngineCovered drops classes an external engine actually assessed.
//
// "Actually" is doing the work. A capability is removed only when an engine
// completed and its normalizer reported the class as covered — which a blocked
// run, a partial run and a passive ZAP scan all decline to do. Removing a class
// because a process started would turn launching a binary into a security
// claim, which is the opposite of what this milestone is for.
//
// What is removed is also qualified rather than deleted outright: the class
// leaves the not-assessed list carrying the engine, its version and its corpus,
// because "assessed by Nuclei against these templates" and "assessed" are
// different statements.
func removeEngineCovered(classes []string, c scanner.Collection) []string {
	if len(c.Covered) == 0 {
		return classes
	}
	covered := map[string]bool{}
	for _, cap := range c.Covered {
		covered[string(cap)] = true
	}
	var by []string
	for _, o := range c.Outcomes {
		if o.Status == scanner.StatusCompleted {
			by = append(by, fmt.Sprintf("%s %s (%s)", o.Engine, o.Provenance.Version,
				o.Provenance.RuleSource))
		}
	}
	sort.Strings(by)
	qualifier := " — assessed by " + strings.Join(by, "; ") +
		", whose results are recorded as observed and are not verified by AppSec Framework"

	out := make([]string, 0, len(classes))
	for _, cl := range classes {
		if covered[cl] {
			out = append(out, cl+qualifier)
			continue
		}
		out = append(out, cl)
	}
	return out
}
