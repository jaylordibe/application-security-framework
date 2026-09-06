package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/proc"
	"github.com/jaylordibe/application-security-framework/internal/redact"
)

// The single most important property in this file: **a failed engine is never
// a clean result.**
//
// Every path that does not end in usable output ends in a blocked Outcome with
// a cause and a sentence saying what was lost. There is no branch that returns
// an empty observation list and a completed status. That asymmetry is
// deliberate, because the alternative — a crashed scanner silently contributing
// nothing to a report that then reads as green — is the exact failure this
// project exists to prevent, committed with somebody else's tool.

// Options configures a run.
type Options struct {
	// ForbiddenEnv names variables that must never reach an engine whatever the
	// operator asks for: this tool's own identity credentials.
	ForbiddenEnv []string
	// Redactor sanitizes imported evidence before it is persisted.
	Redactor *redact.Redactor
	// RunID identifies the assessment.
	RunID string
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
}

// Run executes one engine end to end.
func Run(ctx context.Context, e Engine, t Target, s Settings, opts Options) Outcome {
	meta := e.Meta()
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	out := Outcome{Engine: meta.ID}
	finish := func(o Outcome) Outcome {
		o.Duration = now().Sub(started)
		return o
	}

	blocked := func(cause model.BlockedCause, format string, args ...any) Outcome {
		out.Status = StatusBlocked
		out.Cause = cause
		// The detail always says what was lost, not just what broke. "Nuclei
		// failed" invites a reader to move on; naming the consequence does not.
		out.Detail = strings.TrimRight(fmt.Sprintf(format, args...), ". ") +
			". No result from this engine was imported, " +
			"and the weakness classes it would have covered remain unassessed"
		return finish(out)
	}

	if !s.Enabled {
		out.Status = StatusSkipped
		out.Detail = meta.Title + " is not enabled"
		return finish(out)
	}

	// Availability, before anything is attempted.
	avail := e.Detect(ctx, s)
	out.Limitations = append(out.Limitations, avail.Warnings...)
	if !avail.Present {
		return blocked(model.CauseEngineUnavailable,
			"%s is not available: %s. %s", meta.Title, avail.Problem, meta.InstallHint)
	}

	// Safety profile. An engine that sends attack traffic must not run because
	// somebody enabled it under a reconnaissance profile.
	required := e.RequiredProfile(s)
	if allowed, cause := model.GateProfile(t.Profile, required); !allowed {
		out.Status = StatusBlocked
		out.Cause = cause
		out.Detail = fmt.Sprintf("%s as configured requires the %s profile and the effective "+
			"profile is %s, so it was not run. The weakness classes it would have covered remain "+
			"unassessed", meta.Title, required, t.Profile)
		return finish(out)
	}

	work, cleanup, err := newWorkspace(meta.ID)
	if err != nil {
		return blocked(model.CauseEngineUnavailable, "%s could not be given a working directory: %v",
			meta.Title, err)
	}
	// Cleanup is deferred immediately after creation, so no later return path
	// can leave a temporary directory behind.
	defer cleanup()

	inv, err := e.Invocation(t, s, work, avail)
	if err != nil {
		return blocked(model.CauseEngineUnavailable, "%s could not be invoked: %v", meta.Title, err)
	}
	spec := inv.Spec
	// The environment is built here, not by the engine. An engine names what it
	// needs; this is where the operator's additions are applied and where this
	// tool's own credentials are refused however anyone asks.
	spec.Env = proc.MinimalEnv(append(append([]string{}, inv.EnvNames...), s.PassEnv...),
		opts.ForbiddenEnv)
	spec.Timeout = s.Timeout()
	spec.MaxStdout = MaxStdout
	spec.MaxStderr = MaxStderr
	spec.Dir = work.Dir
	prov := inv.Provenance
	prov.Arguments = redactArgs(spec.Args, opts.Redactor)
	out.Provenance = prov

	res, runErr := proc.Run(ctx, spec)
	out.Stderr = res.Stderr

	switch {
	case res.TimedOut:
		return blocked(model.CauseBudgetExceeded,
			"%s exceeded its %s time budget and was stopped, along with any process it started",
			meta.Title, s.Timeout())
	case res.Cancelled:
		return blocked(model.CauseCancelled, "%s was cancelled before it finished", meta.Title)
	case res.StdoutTruncated:
		// Refused rather than parsed. A truncated document holds fewer results
		// than the engine produced, and importing it would understate what was
		// found while looking like a complete scan.
		return blocked(model.CauseBudgetExceeded,
			"%s produced more than %d bytes of output; it was refused rather than truncated, "+
				"because a partial document reports fewer results than the engine found",
			meta.Title, MaxStdout)
	}

	// A non-zero exit is not automatically failure: several scanners use exit
	// status to signal "findings present". The engine's own normalizer decides,
	// and a document that will not parse is what actually settles it.
	norm, nerr := e.Normalize(res.Stdout, work, prov, s)
	if nerr != nil {
		detail := fmt.Sprintf("%s produced output that could not be read: %v", meta.Title, nerr)
		var parseExit *proc.ExitError
		if errors.As(runErr, &parseExit) {
			detail += fmt.Sprintf(" (it exited with status %d)", parseExit.Code)
		}
		return blocked(model.CauseEngineUnavailable, "%s", detail)
	}

	// A non-zero exit with nothing to show for it is a crash, whatever the
	// document parsed to.
	//
	// The two cases have to be separated. Several scanners exit non-zero to mean
	// "findings were present", so a bare non-zero status cannot be a failure;
	// but an engine that exited badly *and* produced no results did not complete
	// a scan, and reporting that as a completed scan with nothing found is the
	// precise shape of a false clean report.
	var exitErr *proc.ExitError
	if errors.As(runErr, &exitErr) && len(norm.Observations) == 0 {
		return blocked(model.CauseEngineUnavailable,
			"%s exited with status %d and produced no results, so it did not complete a scan",
			meta.Title, exitErr.Code)
	}

	if len(norm.Observations) > MaxObservations {
		norm.Observations = norm.Observations[:MaxObservations]
		norm.Partial = true
		norm.Limitations = append(norm.Limitations, fmt.Sprintf(
			"%s reported more than %d results; the remainder was not imported",
			meta.Title, MaxObservations))
	}

	out.Observations = sanitizeObservations(norm.Observations, opts.Redactor)
	out.Limitations = append(out.Limitations, norm.Limitations...)
	sort.Strings(out.Limitations)

	if norm.Partial {
		out.Status = StatusPartial
		out.Cause = model.CauseBudgetExceeded
		out.Detail = fmt.Sprintf("%s produced incomplete results. What it did report was imported "+
			"and is marked partial; the classes it would have covered are NOT counted as assessed, "+
			"because an incomplete scan of a class is not an assessment of it", meta.Title)
		// A partial run claims no coverage. This is the rule that stops "the
		// process launched" from becoming "the class was assessed".
		return finish(out)
	}

	out.Status = StatusCompleted
	out.Covered = norm.Covered
	out.Detail = fmt.Sprintf("%s %s completed and reported %d result(s)",
		meta.Title, prov.Version, len(out.Observations))
	return finish(out)
}

// newWorkspace creates a private temporary directory for one run.
func newWorkspace(id string) (Workspace, func(), error) {
	dir, err := os.MkdirTemp("", "appsec-engine-"+id+"-")
	if err != nil {
		return Workspace{}, func() {}, err
	}
	// Owner-only: an engine's working directory holds its output, which can
	// contain fragments of target responses.
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return Workspace{}, func() {}, err
	}
	w := Workspace{Dir: dir, OutputPath: filepath.Join(dir, "results.json")}
	return w, func() { _ = os.RemoveAll(dir) }, nil
}

// sanitizeObservations bounds and redacts everything an engine reported.
//
// Engine output is attacker-influenced by construction: a scanner reports what
// a target sent back, and a target chooses that. So it is sanitized for control
// characters, bounded in length, and passed through the run's redactor — which
// already knows this assessment's credentials, and which is the reason a
// reflected bearer token in a matched response does not reach disk.
func sanitizeObservations(in []Observation, red *redact.Redactor) []Observation {
	out := make([]Observation, 0, len(in))
	for _, o := range in {
		clean := Observation{
			RuleID:           sanitize(o.RuleID),
			RuleName:         sanitize(o.RuleName),
			Location:         sanitize(o.Location),
			Parameter:        sanitize(o.Parameter),
			SourceSeverity:   sanitize(o.SourceSeverity),
			SourceConfidence: sanitize(o.SourceConfidence),
			Detail:           sanitize(o.Detail),
			Evidence:         sanitize(o.Evidence),
			References:       sanitizeAll(o.References, 32),
		}
		if red != nil {
			clean.Location = red.URL(clean.Location)
			clean.Detail = red.String(clean.Detail)
			clean.Evidence = red.String(clean.Evidence)
			clean.RuleName = red.String(clean.RuleName)
		}
		if clean.RuleID == "" {
			// A result with nothing to identify it cannot be triaged, reported
			// or deduplicated. Importing it would add noise, not information.
			continue
		}
		out = append(out, clean)
	}
	return out
}

// redactArgs prepares an argument vector for display.
//
// A recorded command line is genuinely useful and is also the easiest place to
// leak a credential: a target URL can carry one in its query string, and an
// operator can put one in a header argument. Everything is redacted before it
// is stored, and the result is a record of what ran rather than a
// copy-and-paste command.
func redactArgs(args []string, red *redact.Redactor) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		c := proc.Sanitize(a, MaxStringBytes)
		if red != nil {
			c = red.String(red.URL(c))
		}
		out = append(out, c)
	}
	return out
}
