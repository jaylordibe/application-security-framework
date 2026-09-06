package adapter

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

// These tests build small adapter programs and run them through the real
// executor, because every property being asserted — environment isolation,
// output bounding, timeouts, process-group cleanup — lives in the boundary
// rather than in any function that can be called directly.

// buildAdapter compiles a Go program into a temporary executable.
func buildAdapter(t *testing.T, name, body string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available to build a test adapter")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot build the test adapter: %v\n%s", err, out)
	}
	return bin
}

const adapterPreamble = `package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	_ = flag.String("source-root", "", "")
	flag.Parse()
	_ = time.Second
	_ = strings.Repeat
	_ = os.Getenv
	_ = fmt.Print
`

func runAdapter(t *testing.T, body string, opts Options, mutate func(*Spec)) Outcome {
	t.Helper()
	bin := buildAdapter(t, "adapter", adapterPreamble+body+"\n}\n")
	spec := Spec{Name: "probe", Path: bin, SourceRoot: t.TempDir(), Timeout: 20 * time.Second}
	if mutate != nil {
		mutate(&spec)
	}
	return Run(context.Background(), spec, opts)
}

const validDoc = `{"contractVersion":"appsec.adapter/v1alpha1",` +
	`"adapter":{"name":"probe","version":"1","extractionMethod":"static-lexical"},"facts":[]}`

func TestRunAcceptsAWellBehavedAdapter(t *testing.T) {
	out := runAdapter(t, "fmt.Print(`"+validDoc+"`)", Options{Trust: TrustNone}, nil)
	if out.Err != nil {
		t.Fatalf("a valid adapter failed: %v", out.Err)
	}
	if out.Result.Document.Adapter.Name != "probe" {
		t.Errorf("adapter name = %q", out.Result.Document.Adapter.Name)
	}
}

// The single most important property in this file. A CI environment holds cloud
// credentials, registry tokens and this tool's own identity credentials; an
// adapter runs against a repository nobody vouched for.
func TestAdapterEnvironmentIsBuiltFromNothing(t *testing.T) {
	t.Setenv("APPSEC_ADMIN_TOKEN", "super-secret-identity-token")
	t.Setenv("GITHUB_TOKEN", "ghp_secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("APPSEC_HARMLESS", "harmless-value")

	body := `
	names := []string{}
	for _, kv := range os.Environ() {
		names = append(names, strings.SplitN(kv, "=", 2)[0])
	}
	fmt.Fprintf(os.Stderr, "ENV:%s\n", strings.Join(names, ","))
	fmt.Print(` + "`" + validDoc + "`" + `)`

	t.Run("nothing is inherited by default", func(t *testing.T) {
		out := runAdapter(t, body, Options{Trust: TrustNone}, nil)
		if out.Err != nil {
			t.Fatalf("adapter failed: %v", out.Err)
		}
		for _, leaked := range []string{"APPSEC_ADMIN_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
			if strings.Contains(out.Stderr, leaked) {
				t.Errorf("%s reached the adapter's environment", leaked)
			}
		}
		if strings.Contains(out.Stderr, "PATH") {
			t.Error("PATH was inherited; an adapter is executed by explicit path and does not need it")
		}
	})

	t.Run("an explicitly named variable is forwarded", func(t *testing.T) {
		out := runAdapter(t, body, Options{Trust: TrustNone}, func(s *Spec) {
			s.PassEnv = []string{"APPSEC_HARMLESS"}
		})
		if !strings.Contains(out.Stderr, "APPSEC_HARMLESS") {
			t.Errorf("an explicitly passed variable did not reach the adapter: %q", out.Stderr)
		}
	})

	t.Run("a credential cannot be forwarded even when named", func(t *testing.T) {
		out := runAdapter(t, body, Options{
			Trust:        TrustNone,
			ForbiddenEnv: []string{"APPSEC_ADMIN_TOKEN"},
		}, func(s *Spec) {
			s.PassEnv = []string{"APPSEC_ADMIN_TOKEN", "APPSEC_HARMLESS"}
		})
		if strings.Contains(out.Stderr, "APPSEC_ADMIN_TOKEN") {
			t.Error("an identity credential was forwarded despite being forbidden")
		}
		if !strings.Contains(out.Stderr, "APPSEC_HARMLESS") {
			t.Error("the forbidden variable suppressed an allowed one")
		}
	})
}

// Framework-native extraction runs the inspected repository's own code. That
// must not happen because somebody named an executable.
func TestTargetCodeExecutionRequiresExplicitTrust(t *testing.T) {
	nativeDoc := strings.Replace(validDoc, "static-lexical", "framework-native", 1)
	body := "fmt.Print(`" + nativeDoc + "`)"

	out := runAdapter(t, body, Options{Trust: TrustNone}, nil)
	if out.Err == nil {
		t.Fatal("a framework-native adapter ran without explicit trust")
	}
	if !strings.Contains(out.Err.Error(), "executes the inspected application's own code") {
		t.Errorf("the refusal does not explain what was being authorised: %v", out.Err)
	}

	allowed := runAdapter(t, body, Options{Trust: TrustExecuteTargetCode}, nil)
	if allowed.Err != nil {
		t.Fatalf("an authorised framework-native adapter was still refused: %v", allowed.Err)
	}
}

func TestAdapterFailuresAreExplicit(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "non-zero exit", body: `os.Exit(3)`, wantErr: "failed"},
		{name: "no output", body: `_ = os.Stdout`, wantErr: "is empty"},
		{name: "malformed JSON", body: "fmt.Print(`{not json`)", wantErr: "not a valid contract document"},
		{
			name:    "unknown contract version",
			body:    "fmt.Print(`{\"contractVersion\":\"appsec.adapter/v9\",\"adapter\":{\"name\":\"probe\",\"version\":\"1\",\"extractionMethod\":\"static-lexical\"},\"facts\":[]}`)",
			wantErr: "not supported by this build",
		},
		{
			name:    "misnames itself",
			body:    "fmt.Print(`" + strings.Replace(validDoc, `"name":"probe"`, `"name":"other"`, 1) + "`)",
			wantErr: "reported itself as",
		},
		{
			name:    "floods stdout",
			body:    "for i := 0; i < 40; i++ { fmt.Print(strings.Repeat(\"A\", 1024*1024)) }",
			wantErr: "more than",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := runAdapter(t, tc.body, Options{Trust: TrustNone}, nil)
			if out.Err == nil {
				t.Fatal("a broken adapter was accepted")
			}
			if !strings.Contains(out.Err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", out.Err, tc.wantErr)
			}
			if len(out.Result.Document.Facts) != 0 {
				t.Error("a failed adapter still produced facts")
			}
		})
	}
}

// A hostile adapter must not be able to hang the assessment.
func TestAdapterTimeoutIsEnforced(t *testing.T) {
	out := runAdapter(t, `time.Sleep(60 * time.Second)`, Options{Trust: TrustNone}, func(s *Spec) {
		s.Timeout = 1500 * time.Millisecond
	})
	if out.Err == nil {
		t.Fatal("a hanging adapter was not stopped")
	}
	if !strings.Contains(out.Err.Error(), "budget") {
		t.Errorf("error = %v, want it to mention the time budget", out.Err)
	}
	if out.Duration > 20*time.Second {
		t.Errorf("the timeout took %s to take effect", out.Duration)
	}
}

// Cancelling the assessment must stop adapters rather than waiting for them.
func TestAdapterRespectsCancellation(t *testing.T) {
	bin := buildAdapter(t, "slow", adapterPreamble+`time.Sleep(60 * time.Second)`+"\n}\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := Run(ctx, Spec{Name: "probe", Path: bin, SourceRoot: t.TempDir()}, Options{Trust: TrustNone})
	if out.Err == nil {
		t.Fatal("a cancelled adapter reported success")
	}
}

// Stderr is diagnostics, not the payload, and a flood of it must not consume
// memory or reach a report unbounded.
func TestStderrIsBounded(t *testing.T) {
	body := `for i := 0; i < 8; i++ { fmt.Fprint(os.Stderr, strings.Repeat("E", 1024*1024)) }
	fmt.Print(` + "`" + validDoc + "`" + `)`
	out := runAdapter(t, body, Options{Trust: TrustNone}, nil)
	if out.Err != nil {
		t.Fatalf("stderr flooding broke a valid adapter: %v", out.Err)
	}
	if len(out.Stderr) > MaxStderrBytes+64 {
		t.Errorf("stderr was not bounded: %d bytes", len(out.Stderr))
	}
	if !strings.Contains(out.Stderr, "truncated") {
		t.Error("truncation was not disclosed")
	}
}

// An adapter that writes a huge stdout and a huge stderr at once must not
// deadlock: draining one pipe to completion first blocks as soon as the other
// fills, which a hostile adapter can arrange deliberately.
func TestBothPipesAreDrainedConcurrently(t *testing.T) {
	body := `
	go func() {
		for i := 0; i < 4; i++ { fmt.Fprint(os.Stderr, strings.Repeat("E", 1024*1024)) }
	}()
	fmt.Print(` + "`" + validDoc + "`" + `)
	time.Sleep(300 * time.Millisecond)`
	done := make(chan Outcome, 1)
	go func() { done <- runAdapter(t, body, Options{Trust: TrustNone}, nil) }()
	select {
	case out := <-done:
		if out.Err != nil {
			t.Fatalf("adapter failed: %v", out.Err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the executor deadlocked draining adapter output")
	}
}

func TestSpecValidation(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr string
	}{
		{name: "no name", spec: Spec{Path: "/bin/true", SourceRoot: "."}, wantErr: "plain identifier"},
		{name: "bad name", spec: Spec{Name: "../x", Path: "/bin/true", SourceRoot: "."}, wantErr: "plain identifier"},
		{name: "no path", spec: Spec{Name: "x", SourceRoot: "."}, wantErr: "no adapter executable"},
		{name: "no source root", spec: Spec{Name: "x", Path: "/bin/true"}, wantErr: "no source root"},
		{
			name:    "source root does not exist",
			spec:    Spec{Name: "x", Path: "/bin/true", SourceRoot: filepath.Join(t.TempDir(), "absent")},
			wantErr: "cannot be resolved",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := Run(context.Background(), tc.spec, Options{Trust: TrustNone})
			if out.Err == nil {
				t.Fatal("an invalid spec was accepted")
			}
			if !strings.Contains(out.Err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", out.Err, tc.wantErr)
			}
		})
	}
}

// Collect must report a failure in terms of what was lost, and must not let a
// failed adapter silently reduce the apparent attack surface.
func TestCollectReportsFailuresAsLimitations(t *testing.T) {
	bin := buildAdapter(t, "broken", adapterPreamble+`os.Exit(1)`+"\n}\n")
	c := Collect(context.Background(),
		[]Spec{{Name: "probe", Path: bin, SourceRoot: t.TempDir()}},
		Options{Trust: TrustNone})

	if !c.Failed() {
		t.Fatal("a failing adapter was not reported as a failure")
	}
	if len(c.Documents) != 0 {
		t.Error("a failing adapter contributed documents")
	}
	joined := strings.Join(c.Failures, " ")
	if !strings.Contains(joined, "does not mean the application has no controls") {
		t.Errorf("the failure does not say what it does and does not imply: %q", joined)
	}
	if len(c.Limitations) == 0 {
		t.Error("an adapter failure did not become a stated limitation")
	}
}

func TestCollectHandlesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := Collect(ctx, []Spec{{Name: "probe", Path: "/bin/true", SourceRoot: t.TempDir()}},
		Options{Trust: TrustNone})
	if !c.Failed() {
		t.Fatal("cancellation did not produce a failure")
	}
	if !strings.Contains(strings.Join(c.Failures, " "), "cancelled") {
		t.Errorf("failures = %v", c.Failures)
	}
}
