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

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
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
}

// ExecutedCount returns how many ledger entries actually ran.
func (r Result) ExecutedCount() int {
	n := 0
	for _, e := range r.Coverage {
		if e.Disposition == model.DispositionExecuted {
			n++
		}
	}
	return n
}

// BlockedCount returns how many ledger entries were blocked.
func (r Result) BlockedCount() int {
	n := 0
	for _, e := range r.Coverage {
		if e.Disposition == model.DispositionBlocked {
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
				Dimension:  "operation",
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

	// Execution.
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
					Dimension:   "operation",
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

			// Persist the evidence first, so both the ledger row and any finding
			// can reference it rather than embedding copies.
			refs, sinkErrs := storeExchanges(opts.EvidenceSink, out.Exchanges)
			for _, e := range sinkErrs {
				failuresMu.Lock()
				failures["evidence: "+e] = struct{}{}
				failuresMu.Unlock()
			}

			lg.add(model.CoverageEntry{
				Dimension:    "operation",
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
	wg.Wait()

	res.Coverage = lg.entries
	res.Findings = findings
	for f := range failures {
		res.ToolFailures = append(res.ToolFailures, f)
	}
	res.ClassesNotAssessed = classesNotAssessed(opts.Checks)
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
