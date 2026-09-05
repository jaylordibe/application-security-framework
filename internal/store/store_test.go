package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func newRun(t *testing.T) *Run {
	t.Helper()
	r, err := Create(t.TempDir(), "testrun", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return r
}

func TestRunDirectoryIsOwnerOnly(t *testing.T) {
	if !PermissionsEnforced() {
		t.Skip("permissions are not enforced on " + runtime.GOOS)
	}
	r := newRun(t)
	info, err := os.Stat(r.Dir())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("run directory mode = %o, want 700", perm)
	}
	if err := r.WriteFile("x.json", []byte("{}")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, err := os.Stat(filepath.Join(r.Dir(), "x.json"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
}

func TestMetaIsWritten(t *testing.T) {
	r := newRun(t)
	data, err := os.ReadFile(filepath.Join(r.Dir(), "meta.json"))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, FormatVersion) {
		t.Error("meta.json does not record the format version")
	}
	if !strings.Contains(s, "Do not commit") {
		t.Error("meta.json does not warn about the directory's sensitivity")
	}
}

// A target-controlled name must never become a path.
func TestPathTraversalIsRefused(t *testing.T) {
	r := newRun(t)
	for _, name := range []string{
		"../escape.json",
		"../../escape.json",
		"evidence/../../escape.json",
		"/absolute.json",
		"",
		".",
	} {
		if err := r.WriteFile(name, []byte("x")); err == nil {
			t.Errorf("accepted a traversing name %q", name)
		}
	}
}

func TestRunIDIsValidated(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{
		"../escape", "a/b", "", strings.Repeat("x", 65), "with space", "semi;colon",
	} {
		if _, err := Create(root, id, time.Unix(0, 0)); err == nil {
			t.Errorf("accepted an unsafe run id %q", id)
		}
	}
	if _, err := Create(root, "20260905T120000Z-abcd1234", time.Unix(0, 0)); err != nil {
		t.Errorf("rejected a valid run id: %v", err)
	}
}

// A symlinked parent must not be able to redirect a write outside the run.
func TestSymlinkedParentIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	r := newRun(t)
	outside := t.TempDir()
	link := filepath.Join(r.Dir(), "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := r.WriteFile("linked/pwned.json", []byte("x")); err == nil {
		if _, serr := os.Stat(filepath.Join(outside, "pwned.json")); serr == nil {
			t.Fatal("a write escaped the run directory through a symlink")
		}
	}
}

func TestEvidenceIsContentAddressedAndIdempotent(t *testing.T) {
	r := newRun(t)
	ex := model.Exchange{
		Request: model.CapturedRequest{Method: "GET", URL: "http://x.test/a"},
		Response: &model.CapturedResponse{
			Status: 200,
			Header: map[string][]string{"Content-Type": {"application/json"}},
			Body:   []byte(`{"a":1}`),
		},
	}
	first, err := r.PutEvidence(ex)
	if err != nil {
		t.Fatalf("PutEvidence: %v", err)
	}
	second, err := r.PutEvidence(ex)
	if err != nil {
		t.Fatalf("PutEvidence again: %v", err)
	}
	if first != second {
		t.Errorf("identical exchanges produced different refs: %s vs %s", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Errorf("evidence ref %q is not algorithm-prefixed", first)
	}

	other := ex
	other.Response = &model.CapturedResponse{Status: 404}
	third, err := r.PutEvidence(other)
	if err != nil {
		t.Fatalf("PutEvidence other: %v", err)
	}
	if third == first {
		t.Error("different exchanges produced the same ref")
	}
}

// Concurrent stores of the same digest must not tear a file.
func TestConcurrentEvidenceWritesAreSafe(t *testing.T) {
	r := newRun(t)
	ex := model.Exchange{
		Request:  model.CapturedRequest{Method: "GET", URL: "http://x.test/a"},
		Response: &model.CapturedResponse{Status: 200, Body: []byte(`{"a":1}`)},
	}
	var wg sync.WaitGroup
	refs := make([]string, 16)
	errs := make([]error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			refs[n], errs[n] = r.PutEvidence(ex)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if refs[i] != refs[0] {
			t.Fatalf("goroutine %d produced a different ref", i)
		}
	}
}

// The redaction key must live beside the evidence, never inside a report.
func TestFingerprintKeyIsStoredSeparately(t *testing.T) {
	r := newRun(t)
	if err := r.WriteFingerprintKey([]byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("WriteFingerprintKey: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(r.Dir(), "fingerprint.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if strings.TrimSpace(string(data)) != "01020304" {
		t.Errorf("key = %q", string(data))
	}
}

// A partially written report must never be observable.
func TestWritesAreAtomic(t *testing.T) {
	r := newRun(t)
	if err := r.WriteJSON("report.json", map[string]any{"a": 1}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	entries, err := os.ReadDir(r.Dir())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}
