package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/adapters/internal/source"
	"github.com/jaylordibe/application-security-framework/internal/adapter"
)

// run executes the adapter end to end against a source root, exactly as the
// core would, and validates the result through the same contract parser.
func run(t *testing.T, root string) adapter.Document {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := source.Main{
		Name: "laravel", Version: version, Method: adapter.MethodStaticLexical,
		Extensions: []string{".php"},
		Wanted: func(rel string) bool {
			return strings.HasPrefix(rel, "routes/") ||
				strings.Contains(rel, "Http/Controllers/") || rel == "bootstrap/app.php"
		},
		Detect: detect, Extract: extract,
	}.Run([]string{"--source-root", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("adapter exited %d: %s", code, stderr.String())
	}
	res, err := adapter.Parse(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatalf("the adapter produced output the core rejects: %v", err)
	}
	if res.Dropped != 0 {
		t.Fatalf("the core dropped %d of this adapter's facts: %v", res.Dropped, res.DropReasons)
	}
	return res.Document
}

func factFor(doc adapter.Document, kind adapter.Kind, method, path string) (adapter.Fact, bool) {
	for _, f := range doc.Facts {
		if f.Kind == kind && f.Operation.Method == method && f.Operation.Path == path {
			return f, true
		}
	}
	return adapter.Fact{}, false
}

// The golden fixture. Each row is a security claim about Laravel's semantics,
// and getting one wrong produces either a false expectation or a missed one.
func TestLaravelGoldenFixture(t *testing.T) {
	doc := run(t, "testdata/app")

	tests := []struct {
		name    string
		kind    adapter.Kind
		method  string
		path    string
		want    adapter.Value
		control string
		why     string
	}{
		{
			name: "route outside any auth group is public", kind: adapter.KindAuthentication,
			method: "GET", path: "/api/health", want: adapter.AuthenticationPublic,
		},
		{
			name: "a throttle group is not authentication", kind: adapter.KindAuthentication,
			method: "POST", path: "/api/auth/sign-in", want: adapter.AuthenticationPublic,
			why: "throttling is rate limiting, not an access control",
		},
		{
			name: "route inside an auth:api group is protected", kind: adapter.KindAuthentication,
			method: "GET", path: "/api/orders/{orderId}", want: adapter.AuthenticationRequired,
		},
		{
			name: "nested prefix groups compose", kind: adapter.KindAuthentication,
			method: "GET", path: "/api/orders", want: adapter.AuthenticationRequired,
			why: "the api mount prefix and the orders group prefix must both apply",
		},
		{
			name: "web routes are not under the api prefix", kind: adapter.KindAuthentication,
			method: "GET", path: "/", want: adapter.AuthenticationPublic,
		},
		{
			name: "a Gate call in the controller is authorization", kind: adapter.KindAuthorization,
			method: "GET", path: "/api/orders/{orderId}", want: adapter.AuthorizationPresent,
			control: "view-order",
		},
		{
			name: "can: middleware on a continuation line is authorization",
			kind: adapter.KindAuthorization, method: "DELETE", path: "/api/orders/{orderId}",
			want: adapter.AuthorizationPresent, control: "can:delete,order",
			why: "a route chain spans lines; missing this reports an authorized route as unprotected",
		},
		{
			name: "no authorization call means absent", kind: adapter.KindAuthorization,
			method: "GET", path: "/api/orders", want: adapter.AuthorizationAbsent,
		},
		{
			name: "an unreadable controller means unknown, not absent",
			kind: adapter.KindAuthorization, method: "GET", path: "/api/reports/{reportId}",
			want: adapter.ValueUnknown,
			why:  "absence of evidence about a handler we never read is not evidence of absence",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := factFor(doc, tc.kind, tc.method, tc.path)
			if !ok {
				t.Fatalf("no %s fact for %s %s (%s)", tc.kind, tc.method, tc.path, tc.why)
			}
			if f.Value != tc.want {
				t.Fatalf("value = %s, want %s (%s); evidence: %s",
					f.Value, tc.want, tc.why, f.Evidence.Detail)
			}
			if tc.control != "" && f.Control != tc.control {
				t.Errorf("control = %q, want %q", f.Control, tc.control)
			}
			if f.Evidence.Detail == "" {
				t.Error("a fact must explain itself")
			}
			if f.Evidence.File == "" || f.Evidence.Line == 0 {
				t.Errorf("a fact must point at where it came from: %+v", f.Evidence)
			}
		})
	}
}

// The negative case. A route whose path is computed names no operation, so
// reporting a fact would attach it to whatever the guessed path collided with.
func TestLaravelDoesNotInventADynamicRoute(t *testing.T) {
	doc := run(t, "testdata/app")

	for _, f := range doc.Facts {
		if strings.Contains(f.Operation.Path, "dynamic") || f.Operation.Path == "/api" {
			t.Errorf("a computed route path was reported as an operation: %+v", f.Operation)
		}
	}
	if !mentions(doc.Limitations, "computed at runtime") {
		t.Errorf("the unreadable route was not reported as a limitation: %v", doc.Limitations)
	}
}

// Silence about a construct must always be accompanied by saying so.
func TestLaravelReportsItsBlindSpots(t *testing.T) {
	doc := run(t, "testdata/app")
	for _, want := range []string{
		"controller constructor",        // middleware it cannot see
		"policy or gate decides access", // why no ownership fact is reported
	} {
		if !mentions(doc.Limitations, want) {
			t.Errorf("limitations do not mention %q: %v", want, doc.Limitations)
		}
	}
	// No ownership fact is claimed, because a policy's basis is not knowable
	// without running it.
	for _, f := range doc.Facts {
		if f.Kind == adapter.KindOwnership && f.Value != adapter.ValueUnknown {
			t.Errorf("an ownership fact was claimed from static analysis: %+v", f)
		}
	}
}

// A directory that is not a Laravel application must yield no facts and say why,
// so the core never reads "wrong adapter" as "no controls found".
func TestLaravelDetectsANonLaravelTree(t *testing.T) {
	dir := t.TempDir()
	doc := run(t, dir)
	if len(doc.Facts) != 0 {
		t.Fatalf("facts were reported for a non-Laravel tree: %+v", doc.Facts)
	}
	if !mentions(doc.Limitations, "does not look like a Laravel application") {
		t.Errorf("the adapter did not say why it reported nothing: %v", doc.Limitations)
	}
}

// Two runs over one tree must produce identical documents, or evidence hashes
// churn and nothing can be diffed between assessments.
func TestLaravelExtractionIsDeterministic(t *testing.T) {
	first, err := json.Marshal(run(t, "testdata/app"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := json.Marshal(run(t, "testdata/app"))
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("two runs over the same source produced different documents")
		}
	}
}

func mentions(all []string, substr string) bool {
	for _, s := range all {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
