package adapter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// The conformance suite. An adapter author should be able to read these cases
// and know exactly what the core will accept, without reading any Go beyond
// this file.
//
// Every rejection here is a case where accepting the document could make an
// assessment look better than it is.

const minimalValid = `{
  "contractVersion": "appsec.adapter/v1alpha1",
  "adapter": {"name": "example", "version": "0.1.0", "extractionMethod": "static-lexical"},
  "facts": []
}`

func parseString(t *testing.T, s string) (Result, error) {
	t.Helper()
	return Parse(strings.NewReader(s))
}

func mustParse(t *testing.T, s string) Result {
	t.Helper()
	res, err := parseString(t, s)
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	return res
}

func TestMinimalValidDocumentIsAccepted(t *testing.T) {
	res := mustParse(t, minimalValid)
	if res.Document.ContractVersion != ContractVersion {
		t.Errorf("contract version = %q", res.Document.ContractVersion)
	}
	if len(res.Document.Facts) != 0 {
		t.Errorf("facts = %d, want 0", len(res.Document.Facts))
	}
	if res.Dropped != 0 {
		t.Errorf("dropped = %d, want 0", res.Dropped)
	}
}

func TestFullValidDocumentIsAccepted(t *testing.T) {
	res := mustParse(t, `{
	  "contractVersion": "appsec.adapter/v1alpha1",
	  "adapter": {"name": "laravel", "version": "0.1.0", "extractionMethod": "static-lexical"},
	  "target": {"framework": "laravel", "frameworkVersion": "12.x"},
	  "facts": [
	    {"kind": "operation.authentication", "operation": {"method": "get", "path": "api/users/{id}"},
	     "value": "required",
	     "evidence": {"file": "routes/api.php", "line": 81, "detail": "enclosing auth:api group"}},
	    {"kind": "operation.authorization", "operation": {"method": "GET", "path": "/api/users/{id}"},
	     "value": "present", "control": "READ_USER"},
	    {"kind": "operation.ownership", "operation": {"method": "GET", "path": "/api/users/{id}"},
	     "value": "owner-scoped"}
	  ],
	  "limitations": ["controller-level middleware is not visible to static extraction"]
	}`)

	if len(res.Document.Facts) != 3 {
		t.Fatalf("facts = %d, want 3", len(res.Document.Facts))
	}
	// Method is upper-cased and the path is rooted, so two adapters spelling one
	// route differently still agree.
	for _, f := range res.Document.Facts {
		if f.Operation.Method != "GET" {
			t.Errorf("method not normalized: %q", f.Operation.Method)
		}
		if f.Operation.Path != "/api/users/{id}" {
			t.Errorf("path not normalized: %q", f.Operation.Path)
		}
	}
	if len(res.Document.Limitations) != 1 {
		t.Error("limitations were lost; they are how absence stays distinguishable from ignorance")
	}
}

// A document the core cannot fully understand yields nothing at all. A partial
// view of an adapter's output reads exactly like a complete one.
func TestDocumentsAreRejectedWholesale(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{name: "empty", doc: ``, wantErr: "is empty"},
		{name: "not JSON", doc: `not json at all`, wantErr: "not a valid contract document"},
		{name: "truncated JSON", doc: `{"contractVersion":`, wantErr: "not a valid contract document"},
		{
			name:    "two documents concatenated",
			doc:     minimalValid + minimalValid,
			wantErr: "more than one JSON document",
		},
		{
			name: "no contract version",
			doc: `{"adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
			       "facts":[]}`,
			wantErr: "not an adapter contract version",
		},
		{
			name: "foreign contract version",
			doc: `{"contractVersion":"some.other/v1",
			       "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
			wantErr: "not an adapter contract version",
		},
		{
			name: "newer unknown contract version",
			doc: `{"contractVersion":"appsec.adapter/v9",
			       "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
			wantErr: "not supported by this build",
		},
		{
			name: "unknown top-level field",
			doc: `{"contractVersion":"appsec.adapter/v1alpha1",
			       "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
			       "facts":[],"trustMe":true}`,
			wantErr: "not a valid contract document",
		},
		{
			name:    "no adapter name",
			doc:     `{"contractVersion":"appsec.adapter/v1alpha1","adapter":{"version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
			wantErr: "does not name the adapter",
		},
		{
			name:    "adapter name is not an identifier",
			doc:     `{"contractVersion":"appsec.adapter/v1alpha1","adapter":{"name":"../../etc","version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
			wantErr: "not a plain identifier",
		},
		{
			name:    "unknown extraction method",
			doc:     `{"contractVersion":"appsec.adapter/v1alpha1","adapter":{"name":"x","version":"1","extractionMethod":"vibes"},"facts":[]}`,
			wantErr: "does not know",
		},
		{
			name:    "no extraction method",
			doc:     `{"contractVersion":"appsec.adapter/v1alpha1","adapter":{"name":"x","version":"1"},"facts":[]}`,
			wantErr: "does not know",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := parseString(t, tc.doc)
			if err == nil {
				t.Fatalf("an invalid document was accepted with %d facts", len(res.Document.Facts))
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
			var rejected *ErrRejected
			if !asRejected(err, &rejected) {
				t.Errorf("error is not an *ErrRejected, so a caller cannot classify it: %T", err)
			}
			if len(res.Document.Facts) != 0 {
				t.Error("a rejected document still yielded facts")
			}
		})
	}
}

func asRejected(err error, target **ErrRejected) bool {
	r, ok := err.(*ErrRejected)
	if ok {
		*target = r
	}
	return ok
}

// One bad fact must not suppress an adapter's whole output, and must not pass
// silently either. It is dropped and counted.
func TestIndividualFactsAreDroppedAndCounted(t *testing.T) {
	tests := []struct {
		name string
		fact string
		want string
	}{
		{name: "unknown kind", fact: `{"kind":"operation.vibes","operation":{"method":"GET","path":"/a"},"value":"required"}`,
			want: "unknown fact kind"},
		{name: "value from another kind", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"owner-scoped"}`,
			want: "value is not one this fact kind may assert"},
		{name: "no value", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"}}`,
			want: "value is not one this fact kind may assert"},
		{name: "not an HTTP method", fact: `{"kind":"operation.authentication","operation":{"method":"SUBSCRIBE","path":"/a"},"value":"required"}`,
			want: "not an HTTP method"},
		{name: "empty path", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":""},"value":"required"}`,
			want: "operation path is empty"},
		{name: "absolute URL as path", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"http://evil.test/a"},"value":"required"}`,
			want: "scheme, authority, query or fragment"},
		{name: "path with query", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a?x=1"},"value":"required"}`,
			want: "scheme, authority, query or fragment"},
		{name: "path traversal", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/../../etc/passwd"},"value":"required"}`,
			want: "parent-directory reference"},
		{name: "path with CRLF", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a\r\nX: 1"},"value":"required"}`,
			want: "control character"},
		{name: "absolute evidence path", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required","evidence":{"file":"/etc/shadow"}}`,
			want: "evidence path is absolute"},
		{name: "traversing evidence path", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required","evidence":{"file":"../../../etc/shadow"}}`,
			want: "escapes the inspected root"},
		{name: "windows evidence path", fact: `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required","evidence":{"file":"C:\\secrets"}}`,
			want: "drive letter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"contractVersion":"appsec.adapter/v1alpha1",
			  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
			  "facts":[` + tc.fact + `]}`
			res, err := parseString(t, doc)
			if err != nil {
				t.Fatalf("the document should parse with the fact dropped, got: %v", err)
			}
			if len(res.Document.Facts) != 0 {
				t.Fatalf("an invalid fact survived: %+v", res.Document.Facts)
			}
			if res.Dropped != 1 {
				t.Errorf("dropped = %d, want 1", res.Dropped)
			}
			if !strings.Contains(strings.Join(res.DropReasons, "; "), tc.want) {
				t.Errorf("drop reasons %v do not mention %q", res.DropReasons, tc.want)
			}
		})
	}
}

// An adapter that says two different things about one subject is not trusted
// about that subject at all. Keeping the first would make the result depend on
// document order; keeping the last would let a malicious adapter overwrite an
// inconvenient fact by appending.
func TestContradictoryFactsWithdrawBoth(t *testing.T) {
	res := mustParse(t, `{
	  "contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
	  "facts":[
	    {"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required"},
	    {"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"public"}
	  ]}`)
	if len(res.Document.Facts) != 0 {
		t.Fatalf("a self-contradicting adapter still influenced the oracle: %+v", res.Document.Facts)
	}
	if !strings.Contains(strings.Join(res.DropReasons, "; "), "conflicting values") {
		t.Errorf("the contradiction was not reported: %v", res.DropReasons)
	}
}

func TestExactDuplicateFactsAreCollapsed(t *testing.T) {
	res := mustParse(t, `{
	  "contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
	  "facts":[
	    {"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required"},
	    {"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required"}
	  ]}`)
	if len(res.Document.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(res.Document.Facts))
	}
}

// Adapter strings reach terminals, reports and future model prompts. Control
// characters can rewrite a terminal and unbounded length is a flooding
// primitive, so both are handled at the boundary.
func TestHostileStringsAreSanitized(t *testing.T) {
	long := strings.Repeat("A", MaxStringBytes*2)
	res := mustParse(t, `{
	  "contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
	  "facts":[{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},
	    "value":"required","control":"`+long+`",
	    "evidence":{"detail":"\u001b[2Jcleared\u0007 and \u0000 nulled"}}],
	  "limitations":["\u001b[31mred\u001b[0m"]}`)

	f := res.Document.Facts[0]
	if len(f.Control) > MaxStringBytes+8 {
		t.Errorf("control was not bounded: %d bytes", len(f.Control))
	}
	for _, s := range []string{f.Control, f.Evidence.Detail, strings.Join(res.Document.Limitations, "")} {
		if strings.ContainsAny(s, "\x1b\x00\x07") {
			t.Errorf("a control character survived sanitisation: %q", s)
		}
	}
}

func TestOversizedDocumentIsRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},"limitations":["`)
	b.WriteString(strings.Repeat("A", MaxDocumentBytes+16))
	b.WriteString(`"],"facts":[]}`)
	if _, err := parseString(t, b.String()); err == nil {
		t.Fatal("an oversized document was accepted")
	} else if !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("error = %v, want it to mention the size limit", err)
	}
}

func TestTooManyFactsIsRejected(t *testing.T) {
	facts := make([]string, 0, MaxFacts+1)
	for i := 0; i <= MaxFacts; i++ {
		facts = append(facts, `{"kind":"operation.authentication",`+
			`"operation":{"method":"GET","path":"/a`+strings.Repeat("b", i%3)+`"},"value":"required"}`)
	}
	doc := `{"contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
	  "facts":[` + strings.Join(facts, ",") + `]}`
	if _, err := parseString(t, doc); err == nil {
		t.Fatal("a document above the fact limit was accepted")
	}
}

// Deeply nested JSON must not be able to exhaust the stack during decoding.
func TestDeeplyNestedJSONIsRejected(t *testing.T) {
	depth := 100000
	doc := `{"contractVersion":"appsec.adapter/v1alpha1",
	  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},"facts":` +
		strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`
	if _, err := parseString(t, doc); err == nil {
		t.Fatal("a deeply nested document was accepted")
	}
}

// The core decides what a method is worth, not the adapter. An adapter cannot
// name its own provenance, so spoofing it means lying about the method — which
// is at least visible in the report.
func TestProvenanceIsDerivedFromMethodNotClaimed(t *testing.T) {
	tests := []struct {
		method   ExtractionMethod
		want     model.Provenance
		executes bool
	}{
		{MethodFrameworkNative, model.ProvenanceDeclared, true},
		{MethodStaticAST, model.ProvenanceInferred, false},
		{MethodStaticLexical, model.ProvenanceInferred, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.method), func(t *testing.T) {
			if got := tc.method.Provenance(); got != tc.want {
				t.Errorf("provenance = %s, want %s", got, tc.want)
			}
			if got := tc.method.ExecutesTargetCode(); got != tc.executes {
				t.Errorf("executes target code = %v, want %v", got, tc.executes)
			}
		})
	}

	// No extraction method may reach observed or verified. Those describe what a
	// request did, and reading source never establishes them.
	for _, m := range []ExtractionMethod{MethodFrameworkNative, MethodStaticAST, MethodStaticLexical} {
		switch m.Provenance() {
		case model.ProvenanceObserved, model.ProvenanceVerified:
			t.Errorf("%s claims runtime provenance from static or boot-time inspection", m)
		}
	}
}

func TestClassifyVersion(t *testing.T) {
	tests := []struct {
		in   string
		want VersionSupport
	}{
		{ContractVersion, VersionSupported},
		{"appsec.adapter/v2", VersionUnknown},
		{"appsec.adapter/", VersionUnparseable},
		{"", VersionUnparseable},
		{"v1alpha1", VersionUnparseable},
		{"other/v1", VersionUnparseable},
		{"appsec.adapter/v1 extra", VersionUnparseable},
	}
	for _, tc := range tests {
		if got := ClassifyVersion(tc.in); got != tc.want {
			t.Errorf("ClassifyVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The wire format must round-trip, so an adapter author can generate documents
// from this package's types and know the core will accept them.
func TestDocumentRoundTrips(t *testing.T) {
	original := Document{
		ContractVersion: ContractVersion,
		Adapter:         AdapterInfo{Name: "example", Version: "0.1.0", ExtractionMethod: MethodStaticLexical},
		Facts: []Fact{{
			Kind:      KindAuthentication,
			Operation: OperationRef{Method: "GET", Path: "/api/users/{id}"},
			Value:     AuthenticationRequired,
			Evidence:  Evidence{File: "routes/api.php", Line: 12, Detail: "auth group"},
		}},
		Limitations: []string{"dynamic middleware is not resolved"},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("a document this package produced was rejected: %v", err)
	}
	if len(res.Document.Facts) != 1 || res.Document.Facts[0] != original.Facts[0] {
		t.Errorf("round trip changed the fact: %+v", res.Document.Facts)
	}
}
