package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/proc"
)

// Running an adapter means running a program the operator chose, against a
// repository nobody vouched for, and letting its output reach the oracle. Three
// separate things therefore have to be contained: the adapter process, the
// repository it reads, and the document it emits.
//
// This file contains the first two. Parse contains the third.

// Execution budgets. Generous enough for a real codebase, bounded enough that
// nothing here can consume a machine.
const (
	// DefaultTimeout bounds one adapter invocation.
	DefaultTimeout = 60 * time.Second
	// MaxStdoutBytes bounds captured stdout. It matches the document limit,
	// because stdout *is* the document.
	MaxStdoutBytes = MaxDocumentBytes
	// MaxStderrBytes bounds captured stderr. Diagnostics are useful and are not
	// the payload, so this is much smaller.
	MaxStderrBytes = 256 << 10
)

// TrustMode says whether the operator has authorised running the target
// application's own code.
//
// This exists because framework-native introspection is not passive. Asking
// Laravel to list its routes boots the application: it loads the Composer
// autoloader, registers every service provider and runs their boot methods.
// Asking a NestJS app anything means importing modules, and importing a module
// executes it — one of this project's own reference applications calls
// startTelemetry() at import time, which patches http, pg and ioredis before
// anything else runs.
//
// So a "discover" step that quietly boots the application would be the tool
// doing something materially more dangerous than its name suggests. It requires
// saying so.
type TrustMode string

const (
	// TrustNone permits only adapters that do not execute target code.
	TrustNone TrustMode = "none"
	// TrustExecuteTargetCode permits framework-native introspection, which runs
	// the inspected repository's own code inside this process's blast radius.
	TrustExecuteTargetCode TrustMode = "execute-target-code"
)

// Valid reports whether t is a known trust mode.
func (t TrustMode) Valid() bool { return t == TrustNone || t == TrustExecuteTargetCode }

// Permits reports whether this trust mode allows an extraction method.
func (t TrustMode) Permits(m ExtractionMethod) bool {
	if !m.ExecutesTargetCode() {
		return true
	}
	return t == TrustExecuteTargetCode
}

// Spec describes one adapter invocation.
type Spec struct {
	// Name identifies the adapter in the ledger and reports.
	Name string
	// Path is the adapter executable. It is used verbatim as argv[0]; nothing
	// here is ever passed through a shell.
	Path string
	// Args are additional arguments, supplied by the operator.
	Args []string
	// SourceRoot is the repository to inspect. It becomes the working directory
	// and is passed explicitly, so an adapter never has to guess.
	SourceRoot string
	// Timeout bounds this invocation. Zero means DefaultTimeout.
	Timeout time.Duration
	// PassEnv names environment variables the operator wants forwarded. The
	// environment is otherwise built from nothing.
	PassEnv []string
}

// Options configures the executor.
type Options struct {
	// Trust says whether target-code execution is authorised.
	Trust TrustMode
	// ForbiddenEnv names variables that must never reach an adapter whatever the
	// operator asks for. These are AppSec's own identity credentials: forwarding
	// one would hand a third-party binary the token it uses to authenticate to
	// the application it is assessing.
	ForbiddenEnv []string
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
}

// Outcome is what one adapter invocation produced.
type Outcome struct {
	Spec Spec
	// Result is the validated document. Only meaningful when Err is nil.
	Result Result
	// Stderr is the adapter's captured diagnostics, sanitized and bounded.
	Stderr string
	// Duration is how long the invocation took.
	Duration time.Duration
	// Err is non-nil when the adapter produced nothing usable.
	Err error
}

// ErrTrustRequired is returned when an adapter would execute target code and
// the operator has not authorised it.
var ErrTrustRequired = errors.New("this adapter executes the inspected application's own code")

// Run invokes an adapter and validates its output.
//
// Nothing about this is a convenience wrapper around exec. Every option set
// here closes a specific way the invocation could go wrong: an inherited
// environment leaks credentials, an unbounded pipe lets the target flood memory,
// a missing process group leaves orphans when the run is cancelled, and a shell
// would turn an operator's argument into an injection point.
func Run(ctx context.Context, spec Spec, opts Options) Outcome {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	out := Outcome{Spec: spec}
	finish := func(err error) Outcome {
		out.Err = err
		out.Duration = now().Sub(started)
		return out
	}

	if spec.Name == "" || !isSlug(spec.Name) {
		return finish(fmt.Errorf("adapter name %q is not a plain identifier", sanitize(spec.Name, 64)))
	}
	if spec.Path == "" {
		return finish(errors.New("no adapter executable was configured"))
	}
	root, err := resolveSourceRoot(spec.SourceRoot)
	if err != nil {
		return finish(err)
	}
	spec.SourceRoot = root

	// Supervision is shared with the external-engine boundary (internal/proc).
	// Two implementations of process-group cleanup and pipe draining would be
	// two chances to get it wrong, and the failure mode is an orphaned process.
	run, runErr := proc.Run(ctx, proc.Spec{
		Name:      "adapter " + spec.Name,
		Path:      spec.Path,
		Args:      append([]string{"--source-root", spec.SourceRoot}, spec.Args...),
		Dir:       spec.SourceRoot,
		Env:       proc.MinimalEnv(spec.PassEnv, opts.ForbiddenEnv),
		Timeout:   spec.Timeout,
		MaxStdout: MaxStdoutBytes,
		MaxStderr: MaxStderrBytes,
	})
	out.Stderr = run.Stderr

	switch {
	case run.TimedOut, run.Cancelled:
		return finish(runErr)
	case run.StdoutTruncated:
		// Truncated output is refused rather than parsed. A partial document is
		// a smaller document, and a smaller document reports fewer controls.
		return finish(fmt.Errorf("adapter %s produced more than %d bytes on stdout; the output was "+
			"refused rather than truncated, because a partial document reports fewer controls than "+
			"the adapter found", spec.Name, MaxStdoutBytes))
	case runErr != nil:
		return finish(fmt.Errorf("adapter %s failed: %w", spec.Name, runErr))
	}

	res, err := Parse(bytes.NewReader(run.Stdout))
	if err != nil {
		return finish(fmt.Errorf("adapter %s: %w", spec.Name, err))
	}
	if res.Document.Adapter.Name != spec.Name {
		return finish(fmt.Errorf("adapter %s reported itself as %q; an adapter that misnames itself "+
			"cannot be attributed in a report", spec.Name, sanitize(res.Document.Adapter.Name, 64)))
	}
	if !opts.Trust.Permits(res.Document.Adapter.ExtractionMethod) {
		return finish(fmt.Errorf("adapter %s used %s extraction, which %w; set the adapter trust "+
			"mode to %q to authorise that, having read what it runs",
			spec.Name, res.Document.Adapter.ExtractionMethod, ErrTrustRequired, TrustExecuteTargetCode))
	}

	out.Result = res
	return finish(nil)
}

// resolveSourceRoot validates the inspected repository path.
//
// Symlinks are resolved before use so that the working directory is the place
// it appears to be. A root that is a symlink into somewhere else is not refused
// — that is a legitimate way to lay out a checkout — but the adapter runs in
// the resolved location, so the path recorded in evidence means what it says.
func resolveSourceRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("no source root was configured for the adapter")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("source root %q is not usable: %w", root, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("source root %q cannot be resolved: %w", root, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("source root %q cannot be read: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("source root %q is not a directory", root)
	}
	return resolved, nil
}
