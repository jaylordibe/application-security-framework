package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
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
	// killGrace is how long a cancelled adapter has to exit before its process
	// group is killed.
	killGrace = 5 * time.Second
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

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Explicit argument vector, never a shell string. The adapter is told the
	// root twice — as the working directory and as an argument — because an
	// adapter that has to discover its own root is an adapter that can be
	// pointed somewhere else.
	args := append([]string{"--source-root", spec.SourceRoot}, spec.Args...)
	cmd := exec.CommandContext(runCtx, spec.Path, args...)
	cmd.Dir = spec.SourceRoot
	cmd.Env = buildEnv(spec.PassEnv, opts.ForbiddenEnv)
	cmd.Stdin = nil
	// A cancelled adapter gets a grace period, then the process is killed rather
	// than left holding the pipe open forever.
	cmd.WaitDelay = killGrace
	configureProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return finish(fmt.Errorf("cannot capture adapter output: %w", err))
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return finish(fmt.Errorf("cannot capture adapter diagnostics: %w", err))
	}

	if err := cmd.Start(); err != nil {
		return finish(fmt.Errorf("adapter %s could not be started: %w", spec.Name, redactPath(err, spec.Path)))
	}

	// Both pipes are drained concurrently. Reading one to completion first
	// deadlocks as soon as the other fills its buffer, which a hostile adapter
	// can arrange deliberately.
	var stdoutTruncated, stderrTruncated bool
	done := make(chan struct{}, 2)
	go func() {
		stdoutTruncated = copyBounded(&stdout, stdoutPipe, MaxStdoutBytes)
		done <- struct{}{}
	}()
	go func() {
		stderrTruncated = copyBounded(&stderr, stderrPipe, MaxStderrBytes)
		done <- struct{}{}
	}()
	<-done
	<-done

	waitErr := cmd.Wait()
	out.Stderr = sanitize(stderr.String(), MaxStderrBytes)
	if stderrTruncated {
		out.Stderr += " […adapter diagnostics truncated]"
	}

	switch {
	case runCtx.Err() != nil && errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return finish(fmt.Errorf("adapter %s exceeded its %s budget and was stopped", spec.Name, timeout))
	case runCtx.Err() != nil:
		return finish(fmt.Errorf("adapter %s was cancelled before it finished", spec.Name))
	case stdoutTruncated:
		// Truncated output is refused rather than parsed. A partial document is
		// a smaller document, and a smaller document reports fewer controls.
		return finish(fmt.Errorf("adapter %s produced more than %d bytes on stdout; the output was "+
			"refused rather than truncated, because a partial document reports fewer controls than "+
			"the adapter found", spec.Name, MaxStdoutBytes))
	case waitErr != nil:
		return finish(fmt.Errorf("adapter %s failed: %w", spec.Name, redactPath(waitErr, spec.Path)))
	}

	res, err := Parse(bytes.NewReader(stdout.Bytes()))
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

// buildEnv constructs the adapter's environment from nothing.
//
// The parent environment is never inherited. A CI job's environment routinely
// holds a GitHub token, cloud credentials, a registry password and — in this
// tool's case — the very tokens it authenticates to the target with. Handing
// that to a third-party binary invoked against an untrusted repository is the
// single easiest way this feature could cause real harm.
//
// PATH is deliberately absent unless asked for. An adapter is executed by
// explicit path and does not need to look anything up; one that shells out to a
// helper can be given PATH explicitly by an operator who has decided to.
func buildEnv(pass, forbidden []string) []string {
	deny := make(map[string]bool, len(forbidden))
	for _, f := range forbidden {
		deny[f] = true
	}
	seen := map[string]bool{}
	env := make([]string, 0, len(pass)+1)
	for _, name := range pass {
		if name == "" || deny[name] || seen[name] {
			continue
		}
		seen[name] = true
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	// A stable, minimal locale so an adapter's output does not vary with the
	// machine it ran on.
	if !seen["LC_ALL"] {
		env = append(env, "LC_ALL=C")
	}
	sort.Strings(env)
	return env
}

// copyBounded copies at most limit bytes and reports whether more remained.
//
// It reads limit+1 so that "exactly at the limit" is distinguishable from
// "truncated", and it drains the rest so a writing child is not left blocked on
// a full pipe when we are about to wait for it.
func copyBounded(dst *bytes.Buffer, src io.Reader, limit int64) bool {
	n, _ := io.Copy(dst, io.LimitReader(src, limit+1))
	truncated := n > limit
	if truncated {
		dst.Truncate(int(limit))
		_, _ = io.Copy(io.Discard, src)
	}
	return truncated
}

// redactPath keeps an adapter's filesystem path out of an error that will be
// stored and displayed.
func redactPath(err error, path string) error {
	if err == nil || path == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), path, filepath.Base(path))
	return errors.New(sanitize(msg, 512))
}

// configureProcessGroup puts the adapter in its own process group where the
// platform supports it, so cancelling the run kills anything it spawned rather
// than orphaning it.
func configureProcessGroup(cmd *exec.Cmd) {
	if runtime.GOOS == "windows" {
		return
	}
	setProcessGroup(cmd)
}
