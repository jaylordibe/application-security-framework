package cli

import (
	"fmt"
	"io"

	"github.com/jaylordibe/application-security-framework/internal/config"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/report"
	"github.com/jaylordibe/application-security-framework/internal/store"
)

// persistAndSummarize writes the run artefacts and chooses the exit code.
func persistAndSummarize(res engine.Result, run *store.Run, pol config.Policy, stdout, stderr io.Writer) error {
	doc := report.Build(res, Version)

	if err := run.WriteJSON("report.json", doc); err != nil {
		return fail(ExitInternal, "%v", err)
	}
	if err := writeSARIF(run, doc); err != nil {
		return fail(ExitInternal, "%v", err)
	}

	fmt.Fprintln(stdout, report.Summary(doc))
	fmt.Fprintf(stdout, "  report:   %s\n", run.Path("report.json"))
	fmt.Fprintf(stdout, "  sarif:    %s\n", run.Path("report.sarif"))

	// An assessment that executed nothing establishes nothing, and must not
	// return the same code as one that ran cleanly.
	if res.ExecutedCount() == 0 {
		fmt.Fprintln(stderr,
			"\nassay: no checks executed. This run establishes nothing about the target.\n"+
				"       See the coverage ledger in the report for why each item did not run.")
		return &exitError{code: ExitNothingExecuted}
	}

	if reasons := policyFailures(res, pol); len(reasons) > 0 {
		fmt.Fprintln(stderr, "\nassay: policy threshold exceeded:")
		for _, r := range reasons {
			fmt.Fprintf(stderr, "  - %s\n", r)
		}
		return &exitError{code: ExitFindings}
	}
	return nil
}

// policyFailures lists the findings that breach the configured thresholds.
//
// Suspected findings count by default. The only shipped check cannot reach
// "confirmed" without credentials, so gating solely on confirmed findings would
// exit zero on a real authentication bypass — a silent pass is the worst
// possible default for a security gate.
func policyFailures(res engine.Result, pol config.Policy) []string {
	var out []string
	for _, f := range res.Findings {
		var threshold string
		switch f.State {
		case model.StateConfirmed:
			threshold = pol.FailOnConfirmed
		case model.StateSuspected:
			threshold = pol.FailOnSuspected
		default:
			continue
		}
		if threshold == "" {
			continue
		}
		if f.Severity.AtLeast(model.Severity(threshold)) {
			out = append(out, fmt.Sprintf("%s %s finding: %s (%s)",
				f.State, f.Severity, f.Title, f.OperationID))
		}
	}
	return out
}

func writeSARIF(run *store.Run, doc report.Document) error {
	var buf sarifBuffer
	if err := report.WriteSARIF(&buf, doc); err != nil {
		return err
	}
	return run.WriteFile("report.sarif", buf.Bytes())
}

// sarifBuffer is a tiny writer so SARIF can be rendered before it is stored
// atomically.
type sarifBuffer struct{ b []byte }

func (s *sarifBuffer) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *sarifBuffer) Bytes() []byte { return s.b }
