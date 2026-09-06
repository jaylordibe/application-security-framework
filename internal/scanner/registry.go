package scanner

import (
	"context"
	"fmt"
	"sort"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// The registry is a fixed list of known engines, and that is the point.
//
// AppSec Framework does not let an operator name an arbitrary command with
// arbitrary arguments and an arbitrary environment. That would be a shell runner
// wearing a security tool's name, and every hardening in this package — the
// argument vector, the minimal environment, the profile gate, the output
// budgets — would become something a configuration file could opt out of.
//
// Supporting a new engine is a code change with tests, not a line of YAML.

// Registered is a named engine.
type Registered struct {
	Engine Engine
	// Enabled reflects whether the operator turned it on.
	Settings Settings
}

// Collection is what every configured engine contributed.
type Collection struct {
	Outcomes []Outcome
	// Findings are the imported observations, already in the observed state.
	Findings []model.Finding
	// Coverage rows account for each engine in the ledger.
	Coverage []model.CoverageEntry
	// Covered are the capabilities actually exercised across all engines.
	Covered []Capability
	// Failures name engines that produced nothing usable.
	Failures []string
	// Limitations aggregate what the engines could not do.
	Limitations []string
}

// DimensionEngine is the ledger dimension for external engine work.
const DimensionEngine = "engine"

// RunAll executes every configured engine and accounts for all of them.
//
// Engines run sequentially. They are subprocesses that may each start a JVM, a
// browser or a scan of an entire application, and running them concurrently
// multiplies the load on a target somebody is running, for no benefit: nothing
// needs the results until the assessment finishes.
func RunAll(ctx context.Context, engines []Registered, t Target, opts Options) Collection {
	var c Collection
	covered := map[Capability]bool{}

	for _, r := range engines {
		meta := r.Engine.Meta()
		var out Outcome
		if ctx.Err() != nil {
			out = Outcome{
				Engine: meta.ID, Status: StatusBlocked, Cause: model.CauseCancelled,
				Detail: meta.Title + " was not run: the assessment was cancelled. The weakness " +
					"classes it would have covered remain unassessed",
			}
		} else {
			out = Run(ctx, r.Engine, t, r.Settings, opts)
		}
		c.Outcomes = append(c.Outcomes, out)

		if out.Status == StatusSkipped {
			// An engine nobody enabled produced no ledger row, because the
			// ledger accounts for work that was planned and none was. It is not
			// hidden: it appears in the engine account with a skipped status,
			// and the classes it would have covered stay in classesNotAssessed,
			// which is the channel that already says what nothing looked at.
			//
			// Emitting a row here instead would add an untested entry for every
			// engine in the registry to every run, which inflates the untested
			// count with work nobody intended and makes the number mean less.
			continue
		}

		entry := model.CoverageEntry{
			Dimension: DimensionEngine, Subject: meta.ID, Detail: out.Detail,
		}
		switch out.Status {
		case StatusCompleted:
			entry.Disposition = model.DispositionExecuted
		case StatusPartial:
			// Partial work is blocked in the ledger. The intended unit was a
			// complete scan and that did not happen; the results it did produce
			// are still imported and still reported.
			entry.Disposition = model.DispositionBlocked
			entry.Cause = out.Cause
		default:
			entry.Disposition = model.DispositionBlocked
			entry.Cause = out.Cause
			c.Failures = append(c.Failures, out.Detail)
		}
		c.Coverage = append(c.Coverage, entry)

		for _, o := range out.Observations {
			c.Findings = append(c.Findings, ToFinding(o, out.Provenance, opts.RunID))
		}
		for _, cap := range out.Covered {
			covered[cap] = true
		}
		c.Limitations = append(c.Limitations, out.Limitations...)
		if out.Stderr != "" {
			c.Limitations = append(c.Limitations,
				fmt.Sprintf("%s diagnostics: %s", meta.Title, out.Stderr))
		}
	}

	for cap := range covered {
		c.Covered = append(c.Covered, cap)
	}
	sort.Slice(c.Covered, func(i, j int) bool { return c.Covered[i] < c.Covered[j] })
	sort.Strings(c.Failures)
	sort.Strings(c.Limitations)
	sort.Slice(c.Findings, func(i, j int) bool {
		if c.Findings[i].CheckID != c.Findings[j].CheckID {
			return c.Findings[i].CheckID < c.Findings[j].CheckID
		}
		return c.Findings[i].External.Location < c.Findings[j].External.Location
	})
	return c
}

// Failed reports whether any engine produced nothing usable.
func (c Collection) Failed() bool { return len(c.Failures) > 0 }

// Statement summarises what the engines did, for the assurance section.
func (c Collection) Statement() string {
	if len(c.Outcomes) == 0 {
		return "No external scanning engine was configured, so the weakness classes they cover " +
			"were not assessed."
	}
	var completed, partial, blocked, skipped int
	for _, o := range c.Outcomes {
		switch o.Status {
		case StatusCompleted:
			completed++
		case StatusPartial:
			partial++
		case StatusBlocked:
			blocked++
		case StatusSkipped:
			skipped++
		}
	}
	s := fmt.Sprintf("%d external engine(s) completed, %d were incomplete, %d were blocked and "+
		"%d were not enabled. ", completed, partial, blocked, skipped)
	s += "Every result an external engine reported is recorded as observed and nothing more: " +
		"AppSec Framework does not promote another tool's alert on that tool's own confidence, " +
		"and agreement between two engines is not verification either."
	if blocked > 0 || partial > 0 {
		s += " An engine that did not complete assessed nothing, and the classes it covers remain " +
			"unassessed however few results this report contains."
	}
	return s
}
