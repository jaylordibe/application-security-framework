package adapter

import (
	"context"
	"fmt"
	"sort"
)

// Collection is the outcome of running every configured adapter.
//
// It carries failures as prominently as successes. That is the whole point: an
// adapter that crashed found no controls, and an application with no controls
// also has no controls, and those two must never produce the same report. A
// failed adapter therefore becomes a stated limitation and a tool failure, and
// the oracle is left exactly as it was.
type Collection struct {
	// Documents are the validated outputs, in configuration order.
	Documents []Document
	// Outcomes are every invocation, successful or not.
	Outcomes []Outcome
	// Failures describe adapters that produced nothing usable, in operator
	// terms, sorted.
	Failures []string
	// Limitations aggregates what the adapters said they could not determine,
	// plus what the core dropped from their output.
	Limitations []string
}

// Failed reports whether any configured adapter did not produce usable output.
func (c Collection) Failed() bool { return len(c.Failures) > 0 }

// Collect runs every adapter and gathers what they produced.
//
// Adapters run sequentially. They are subprocesses reading a possibly large
// repository, and running several at once multiplies the memory and file
// descriptors an untrusted component can hold at one time for no benefit: the
// results are not needed until planning starts.
func Collect(ctx context.Context, specs []Spec, opts Options) Collection {
	var c Collection
	failures := map[string]struct{}{}
	limits := map[string]struct{}{}

	for _, spec := range specs {
		if ctx.Err() != nil {
			failures[fmt.Sprintf("adapter %s was not run: the assessment was cancelled", spec.Name)] = struct{}{}
			continue
		}
		out := Run(ctx, spec, opts)
		c.Outcomes = append(c.Outcomes, out)

		if out.Err != nil {
			// The message says what was lost, not just what broke. "Adapter
			// failed" invites the reader to move on; naming the consequence does
			// not.
			msg := fmt.Sprintf("adapter %s produced nothing usable (%v), so no framework-derived "+
				"expectation was added for any operation. This does not mean the application has "+
				"no controls; it means none were read", spec.Name, out.Err)
			failures[msg] = struct{}{}
			limits[msg] = struct{}{}
			continue
		}

		c.Documents = append(c.Documents, out.Result.Document)
		if out.Result.Dropped > 0 {
			limits[fmt.Sprintf("adapter %s reported %d fact(s) the core refused (%v); the remainder "+
				"was used", spec.Name, out.Result.Dropped, out.Result.DropReasons)] = struct{}{}
		}
	}

	for f := range failures {
		c.Failures = append(c.Failures, f)
	}
	for l := range limits {
		c.Limitations = append(c.Limitations, l)
	}
	sort.Strings(c.Failures)
	sort.Strings(c.Limitations)
	return c
}
