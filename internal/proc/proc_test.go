package proc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These cover the parts of the supervisor that no caller exercises: the
// defaults that apply when a caller passes nothing, and the two string
// functions every ledger row and error message passes through. The behaviour
// under a hostile child — descendants, hung pipes, floods — is proven against
// real programs in internal/scanner.

// The most dangerous line in this package is the one that decides what an
// empty Env means. exec's default is "inherit everything", so a caller that
// forgets to build an environment must get nothing rather than every secret
// this process holds.
func TestNilEnvGivesTheChildNoEnvironment(t *testing.T) {
	bin := buildHelper(t, `
	for _, kv := range os.Environ() {
		fmt.Println(strings.SplitN(kv, "=", 2)[0])
	}`)

	t.Setenv("APPSEC_SECRET_UNDER_TEST", "bearer-token")
	t.Setenv("GITHUB_TOKEN", "ghp_secret")

	res, err := Run(context.Background(), Spec{Name: "helper", Path: bin, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Stderr)
	}

	var got []string
	for _, name := range strings.Fields(string(res.Stdout)) {
		// Go's exec re-adds SYSTEMROOT on Windows whatever the caller asks
		// for, because a process without it cannot start.
		if runtime.GOOS == "windows" && strings.EqualFold(name, "SYSTEMROOT") {
			continue
		}
		got = append(got, name)
	}
	if len(got) != 0 {
		t.Errorf("a nil Env produced an environment: %v", got)
	}
}

// No shell, ever: an argument holding shell metacharacters must arrive as one
// literal argument.
func TestArgumentsAreNeverInterpreted(t *testing.T) {
	bin := buildHelper(t, `
	for _, a := range os.Args[1:] {
		fmt.Printf("[%s]\n", a)
	}`)

	hostile := "; rm -rf / $(id) `whoami` && echo pwned | tee /tmp/x"
	res, err := Run(context.Background(), Spec{
		Name: "helper", Path: bin, Args: []string{hostile}, Env: []string{},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Stderr)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "["+hostile+"]" {
		t.Errorf("argument was not passed verbatim as one argument:\n got %q\nwant %q", got, "["+hostile+"]")
	}
}

func TestMinimalEnvBuildsFromNothing(t *testing.T) {
	t.Setenv("APPSEC_PASSED", "value")
	t.Setenv("APPSEC_FORBIDDEN", "secret")
	t.Setenv("APPSEC_NOT_ASKED_FOR", "also-secret")

	env := MinimalEnv(
		[]string{"APPSEC_PASSED", "APPSEC_FORBIDDEN", "APPSEC_PASSED", "", "APPSEC_ABSENT"},
		[]string{"APPSEC_FORBIDDEN"})

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "APPSEC_PASSED=value") {
		t.Errorf("a requested variable was dropped: %v", env)
	}
	if strings.Contains(joined, "APPSEC_FORBIDDEN") {
		t.Errorf("a forbidden variable survived being requested: %v", env)
	}
	if strings.Contains(joined, "APPSEC_NOT_ASKED_FOR") {
		t.Errorf("a variable nobody asked for was inherited: %v", env)
	}
	if strings.Contains(joined, "APPSEC_ABSENT") {
		t.Errorf("an unset variable produced an entry: %v", env)
	}
	if n := strings.Count(joined, "APPSEC_PASSED="); n != 1 {
		t.Errorf("a repeated name produced %d entries, want 1: %v", n, env)
	}
	if !strings.Contains(joined, "LC_ALL=C") {
		t.Errorf("no stable locale was set: %v", env)
	}
}

// A caller that names LC_ALL itself decides its value; the default must not
// overwrite it, and must not appear twice.
func TestMinimalEnvDoesNotOverrideAnExplicitLocale(t *testing.T) {
	t.Setenv("LC_ALL", "en_US.UTF-8")
	env := MinimalEnv([]string{"LC_ALL"}, nil)
	if len(env) != 1 || env[0] != "LC_ALL=en_US.UTF-8" {
		t.Errorf("MinimalEnv = %v, want exactly the caller's LC_ALL", env)
	}
}

func TestSanitizeStripsWhatWouldCorruptOutput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"escape sequences cannot repaint a terminal", "a\x1b[2Jb", 0, "a[2Jb"},
		{"NUL is removed", "a\x00b", 0, "ab"},
		{"a carriage return cannot overwrite the line", "real\rfake", 0, "realfake"},
		{"newlines become spaces so one message stays one line", "a\nb", 0, "a b"},
		{"tabs become spaces so a ledger row cannot fake a column", "a\tb", 0, "a b"},
		{"delete is removed", "a\x7fb", 0, "ab"},
		{"surrounding whitespace goes", "  a  ", 0, "a"},
		{"invalid UTF-8 is dropped rather than stored", "a\xffb", 0, "ab"},
		{"a long string is truncated visibly", "abcdef", 3, "abc…"},
		{"truncation does not split a rune", "aé", 2, "a…"},
		{"an empty string stays empty", "", 10, ""},
	} {
		if got := Sanitize(tc.in, tc.limit); got != tc.want {
			t.Errorf("%s: Sanitize(%q, %d) = %q, want %q", tc.name, tc.in, tc.limit, got, tc.want)
		}
	}
}

// Truncated stdout is a failed run, not a shorter one: a cut JSON document
// reports fewer findings than the engine actually produced.
func TestFailedCountsTruncationAndInterruption(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  Result
		want bool
	}{
		{"a clean run", Result{}, false},
		{"a non-zero exit is the caller's to judge", Result{ExitCode: 2}, false},
		{"truncated stdout", Result{StdoutTruncated: true}, true},
		{"truncated stderr is only diagnostics", Result{StderrTruncated: true}, false},
		{"a timeout", Result{TimedOut: true}, true},
		{"a cancellation", Result{Cancelled: true}, true},
	} {
		if got := tc.res.Failed(); got != tc.want {
			t.Errorf("%s: Failed() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An error naming the executable would put an operator's directory layout into
// stored evidence.
func TestErrorsDoNotCarryTheExecutablePath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "definitely-not-here")

	_, err := Run(context.Background(), Spec{Name: "helper", Path: missing, Env: []string{}})
	if err == nil {
		t.Fatal("running a missing executable succeeded")
	}
	if strings.Contains(err.Error(), dir) {
		t.Errorf("the error carries the full path: %v", err)
	}
	if !strings.Contains(err.Error(), "definitely-not-here") {
		t.Errorf("the error does not say which program was missing: %v", err)
	}
}

// buildHelper compiles a Go program whose body is src into a temporary
// executable. Building rather than shelling out keeps this test identical on
// Windows, where there is no /bin/sh to fall back on.
func buildHelper(t *testing.T, body string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available to build a helper")
	}
	src := "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"strings\"\n)\n\nfunc main() {\n\t_ = strings.SplitN\n" + body + "\n}\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot build helper: %v\n%s", err, out)
	}
	return bin
}
