// Package proc supervises untrusted subprocesses.
//
// AppSec Framework runs two kinds of foreign program: framework adapters, which
// read an application's source, and external scanning engines, which attack it.
// Neither is trusted. Both can hang, fork, ignore signals, flood their pipes,
// print secrets or lie about what they are.
//
// The supervision they need is identical, so it lives here once. Two
// implementations of this would mean two chances to forget the process group,
// and the failure mode of forgetting it is a Chromium instance or a JVM still
// running after the assessment has exited.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Defaults. Callers override per invocation; these exist so that a caller who
// forgets cannot accidentally be unbounded.
const (
	// DefaultTimeout bounds one invocation.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxStdout bounds captured stdout.
	DefaultMaxStdout int64 = 64 << 20 // 64 MiB
	// DefaultMaxStderr bounds captured stderr. Diagnostics are not the payload.
	DefaultMaxStderr int64 = 256 << 10
	// KillGrace is how long a cancelled process has to exit before its group is
	// killed.
	KillGrace = 5 * time.Second
)

// Spec describes one invocation.
//
// There is deliberately no Command string and no shell. Everything is an
// argument vector, so a target URL containing a semicolon, a backtick or a
// newline stays data no matter what it holds.
type Spec struct {
	// Name identifies the process in errors and ledger rows.
	Name string
	// Path is the executable, used verbatim as argv[0].
	Path string
	// Args are its arguments, passed exactly as given.
	Args []string
	// Dir is the working directory. Empty means the process inherits none and
	// runs in the parent's, which callers should avoid.
	Dir string
	// Env is the complete environment. It is used as given: nothing is
	// inherited, so a caller that passes nil gets a process with no environment
	// at all rather than one holding every secret this process can see.
	Env []string
	// Stdin is optional input. Nil means the process gets no stdin.
	Stdin []byte
	// Timeout bounds the invocation. Zero uses DefaultTimeout.
	Timeout time.Duration
	// MaxStdout and MaxStderr bound captured output. Zero uses the defaults.
	MaxStdout int64
	MaxStderr int64
}

// Result is what one invocation produced.
type Result struct {
	// Stdout and Stderr are the captured streams, up to their budgets.
	Stdout []byte
	Stderr string
	// StdoutTruncated and StderrTruncated report that a budget was hit. A
	// caller must treat truncated stdout as a failed run rather than a shorter
	// one: a partial document reports fewer findings than the tool produced.
	StdoutTruncated bool
	StderrTruncated bool
	// ExitCode is the process exit status, or -1 when it did not exit normally.
	ExitCode int
	// Duration is how long the invocation took.
	Duration time.Duration
	// TimedOut and Cancelled distinguish why a run stopped early.
	TimedOut  bool
	Cancelled bool
}

// Failed reports whether the invocation should be treated as unsuccessful.
//
// A non-zero exit is not automatically a failure — several scanners exit
// non-zero to mean "findings were present" — so callers decide. What is always
// a failure is a run that was stopped or whose output was cut.
func (r Result) Failed() bool {
	return r.TimedOut || r.Cancelled || r.StdoutTruncated
}

// Run executes a program under full supervision.
//
// Every step here closes a specific way an untrusted child can hurt the parent:
//
//   - No shell, ever. Arguments are a vector.
//   - The environment is exactly what the caller built. Nothing is inherited.
//   - Its own process group, so cancellation kills descendants rather than
//     orphaning a browser, a JVM or a helper daemon.
//   - WaitDelay, so a child that closes neither pipe cannot hold Wait forever.
//   - Both pipes drained concurrently and bounded. Draining one to completion
//     first deadlocks the moment the other fills, which a hostile process can
//     arrange deliberately.
func Run(ctx context.Context, spec Spec) (Result, error) {
	var res Result
	started := time.Now()
	finish := func(err error) (Result, error) {
		res.Duration = time.Since(started)
		return res, err
	}

	if spec.Path == "" {
		return finish(errors.New("no executable was given"))
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxOut := spec.MaxStdout
	if maxOut <= 0 {
		maxOut = DefaultMaxStdout
	}
	maxErr := spec.MaxStderr
	if maxErr <= 0 {
		maxErr = DefaultMaxStderr
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	// A nil Env would make exec inherit the parent's. An empty non-nil slice is
	// what "no environment" has to be spelled as, and the difference between
	// the two is every secret this process holds.
	if spec.Env == nil {
		cmd.Env = []string{}
	} else {
		cmd.Env = spec.Env
	}
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	cmd.WaitDelay = KillGrace
	setProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return finish(fmt.Errorf("cannot capture output: %w", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return finish(fmt.Errorf("cannot capture diagnostics: %w", err))
	}

	if err := cmd.Start(); err != nil {
		return finish(fmt.Errorf("%s could not be started: %w", spec.Name, redactPath(err, spec.Path)))
	}

	var outBuf, errBuf bytes.Buffer
	done := make(chan struct{}, 2)
	go func() {
		res.StdoutTruncated = copyBounded(&outBuf, stdout, maxOut)
		done <- struct{}{}
	}()
	go func() {
		res.StderrTruncated = copyBounded(&errBuf, stderr, maxErr)
		done <- struct{}{}
	}()
	<-done
	<-done

	waitErr := cmd.Wait()
	res.Stdout = outBuf.Bytes()
	res.Stderr = Sanitize(errBuf.String(), int(maxErr))
	if res.StderrTruncated {
		res.Stderr += " […diagnostics truncated]"
	}

	res.ExitCode = -1
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.TimedOut = true
		return finish(fmt.Errorf("%s exceeded its %s budget and was stopped", spec.Name, timeout))
	case runCtx.Err() != nil:
		res.Cancelled = true
		return finish(fmt.Errorf("%s was cancelled before it finished", spec.Name))
	case waitErr != nil:
		// Returned alongside the result, not instead of it: a caller that
		// tolerates a non-zero exit still needs the output.
		return finish(&ExitError{Name: spec.Name, Code: res.ExitCode, Err: redactPath(waitErr, spec.Path)})
	}
	return finish(nil)
}

// ExitError reports a non-zero exit status.
type ExitError struct {
	Name string
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s exited with status %d", e.Name, e.Code)
}

func (e *ExitError) Unwrap() error { return e.Err }

// copyBounded copies at most limit bytes and reports whether more remained.
//
// It reads limit+1 so "exactly at the limit" is distinguishable from
// "truncated", and drains the rest so a writing child is not left blocked on a
// full pipe while the parent waits for it to exit.
func copyBounded(dst *bytes.Buffer, src io.Reader, limit int64) bool {
	n, _ := io.Copy(dst, io.LimitReader(src, limit+1))
	if n <= limit {
		return false
	}
	dst.Truncate(int(limit))
	_, _ = io.Copy(io.Discard, src)
	return true
}

// Sanitize bounds a string and removes control characters.
//
// Scanner output is attacker-influenced: a target chooses what appears in a
// matched response, and that reaches a terminal, a JSON report and eventually a
// SARIF viewer. An ANSI escape can clear a screen or rewrite a line, which is
// how a scan result lies about itself.
func Sanitize(s string, limit int) string {
	if s == "" {
		return ""
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if limit > 0 && len(s) > limit {
		for limit > 0 && !utf8.RuneStart(s[limit]) {
			limit--
		}
		s = s[:limit] + "…"
	}
	return s
}

// MinimalEnv builds an environment from nothing.
//
// The parent's environment is never a starting point. A CI job holds a GitHub
// token, cloud credentials, a registry password and — in this tool's case — the
// bearer tokens it authenticates to the target with. Handing that to a scanner
// is the easiest way this feature could cause real harm, and it would happen by
// doing nothing at all, because inheriting is exec's default.
//
// pass names variables the caller wants forwarded; forbidden names variables
// that must never be, whatever anyone asks for.
func MinimalEnv(pass, forbidden []string) []string {
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
	if !seen["LC_ALL"] {
		// A stable locale so output does not vary with the machine.
		env = append(env, "LC_ALL=C")
	}
	sort.Strings(env)
	return env
}

// redactPath keeps an executable's full path out of an error that will be
// stored and displayed.
func redactPath(err error, path string) error {
	if err == nil || path == "" {
		return err
	}
	return errors.New(Sanitize(strings.ReplaceAll(err.Error(), path, filepath.Base(path)), 512))
}
