package openapi

import (
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func parse(t *testing.T, doc string) Result {
	t.Helper()
	res, err := Parse([]byte(doc), "https://api.example.com",
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "test", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func opByID(t *testing.T, res Result, id string) model.Operation {
	t.Helper()
	for _, op := range res.Operations {
		if op.ID == id {
			return op
		}
	}
	t.Fatalf("operation %q not found in %+v", id, res.Operations)
	return model.Operation{}
}

// The three security-requirement cases that decide whether an oracle exists.
func TestSecuritySemantics(t *testing.T) {
	doc := `{
      "openapi":"3.0.0","info":{"title":"t","version":"1"},
      "security":[{"global":[]}],
      "paths":{
        "/protected":{"get":{"security":[{"bearer":[]}]}},
        "/public":{"get":{"security":[]}},
        "/optional":{"get":{"security":[{},{"bearer":[]}]}},
        "/inherits":{"get":{}}
      }}`
	res := parse(t, doc)

	protected := opByID(t, res, "GET /protected")
	if !protected.DeclaresAuthRequired() {
		t.Error("explicit requirement not recognised")
	}

	// security: [] means EXPLICITLY PUBLIC, and must override the root.
	public := opByID(t, res, "GET /public")
	if public.DeclaresAuthRequired() {
		t.Error("security: [] treated as a requirement")
	}
	if !public.DeclaresPublic() {
		t.Error("security: [] not recognised as explicitly public")
	}

	// An empty member makes authentication OPTIONAL, so an unauthenticated
	// success is correct and must never be a finding.
	optional := opByID(t, res, "GET /optional")
	if optional.DeclaresAuthRequired() {
		t.Error("optional authentication ([{},{bearer}]) treated as required")
	}

	// An operation with no security inherits the root requirement.
	inherits := opByID(t, res, "GET /inherits")
	if !inherits.DeclaresAuthRequired() {
		t.Error("root-level security not inherited")
	}
}

// Absent security must stay distinguishable from explicit public.
func TestSilentDocumentYieldsNoOracle(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "paths":{"/a":{"get":{}}}}`)
	op := opByID(t, res, "GET /a")
	if op.Security != nil {
		t.Error("absent security should be nil, not an empty slice")
	}
	if op.DeclaresPublic() {
		t.Error("silence must not be read as explicitly public")
	}
	if res.Fidelity.Level != FidelitySilent {
		t.Errorf("fidelity = %s, want silent", res.Fidelity.Level)
	}
	if res.Fidelity.Provenance != model.ProvenanceInferred {
		t.Errorf("provenance = %s, want inferred", res.Fidelity.Provenance)
	}
}

// A generator that stamps one requirement on every route tells us nothing about
// any individual operation, and the grading must say so.
func TestUniformSecurityIsGradedAsLowFidelity(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "security":[{"bearer":[]}],
	  "paths":{"/a":{"get":{}},"/b":{"get":{}},"/c":{"post":{}}}}`)
	if res.Fidelity.Level != FidelityUniform {
		t.Errorf("fidelity = %s, want uniform", res.Fidelity.Level)
	}
	if res.Fidelity.Provenance != model.ProvenanceInferred {
		t.Errorf("provenance = %s, want inferred for a uniform document", res.Fidelity.Provenance)
	}
}

func TestDiscriminatingDocumentIsUsable(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "paths":{"/a":{"get":{"security":[{"bearer":[]}]}},"/b":{"get":{"security":[]}}}}`)
	if res.Fidelity.Level != FidelityUsable {
		t.Errorf("fidelity = %s, want usable", res.Fidelity.Level)
	}
	if res.Fidelity.Provenance != model.ProvenanceDeclared {
		t.Errorf("provenance = %s, want declared", res.Fidelity.Provenance)
	}
}

// A hostile document must not be able to make AppSec Framework read local files or contact
// other hosts.
func TestExternalRefsAreRefusedAndRecorded(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "paths":{"/a":{"get":{"parameters":[
	    {"$ref":"file:///etc/passwd"},
	    {"$ref":"http://169.254.169.254/latest/meta-data/"},
	    {"$ref":"../../secrets.yaml#/x"}
	  ]}}}}`)
	if len(res.ExternalRefs) != 3 {
		t.Fatalf("refused external refs = %v, want 3 recorded", res.ExternalRefs)
	}
	op := opByID(t, res, "GET /a")
	if len(op.Parameters) != 0 {
		t.Errorf("external refs were resolved into parameters: %+v", op.Parameters)
	}
}

func TestLocalRefsResolve(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "components":{"parameters":{"Id":{"name":"id","in":"path","required":true}}},
	  "paths":{"/a/{id}":{"get":{"parameters":[{"$ref":"#/components/parameters/Id"}]}}}}`)
	op := opByID(t, res, "GET /a/{id}")
	if len(op.RequiredPathParams()) != 1 || op.RequiredPathParams()[0] != "id" {
		t.Errorf("local ref did not resolve: %+v", op.Parameters)
	}
}

// Path parameters are inferred from the template even when undocumented, because
// probing /users/{id} with a literal placeholder tests nothing.
func TestPathParamsInferredFromTemplate(t *testing.T) {
	res := parse(t, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "paths":{"/users/{id}/posts/{postId}":{"get":{}}}}`)
	op := opByID(t, res, "GET /users/{id}/posts/{postId}")
	got := op.RequiredPathParams()
	if len(got) != 2 {
		t.Fatalf("inferred path params = %v, want id and postId", got)
	}
}

// Half-parsing a format we do not properly support would produce a confidently
// wrong attack surface.
func TestSwagger2IsRefused(t *testing.T) {
	_, err := Parse([]byte(`{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}`),
		"https://x.test", model.Source{})
	if err == nil || !strings.Contains(err.Error(), "Swagger 2.0") {
		t.Fatalf("error = %v, want a Swagger 2.0 refusal", err)
	}
}

func TestYAMLDocumentsAreAccepted(t *testing.T) {
	doc := "openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\npaths:\n  /a:\n    get:\n      security:\n        - bearer: []\n"
	res, err := Parse([]byte(doc), "https://x.test", model.Source{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(res.Operations))
	}
}

// Target-controlled text must not be able to rewrite an operator's terminal.
func TestControlCharactersAreStripped(t *testing.T) {
	res := parse(t, "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"e\\u001b[31mvil\",\"version\":\"1\"},"+
		"\"paths\":{\"/a\":{\"get\":{\"summary\":\"a\\u0007b\\u001b[2Jc\"}}}}")
	if strings.ContainsRune(res.Title, 0x1b) {
		t.Errorf("escape sequence survived in title: %q", res.Title)
	}
	op := opByID(t, res, "GET /a")
	if strings.ContainsAny(op.Summary, "\x1b\x07") {
		t.Errorf("control characters survived in summary: %q", op.Summary)
	}
}

func TestOversizedDocumentIsRefused(t *testing.T) {
	huge := make([]byte, MaxDocumentBytes+1)
	if _, err := Parse(huge, "https://x.test", model.Source{}); err == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestNonOpenAPIDocumentIsRefused(t *testing.T) {
	for _, doc := range []string{`{}`, `{"info":{}}`, `not json at all: [`} {
		if _, err := Parse([]byte(doc), "https://x.test", model.Source{}); err == nil {
			t.Errorf("accepted a non-OpenAPI document: %q", doc)
		}
	}
}

// Output must be deterministic so evaluation fixtures can be diffed.
func TestOperationOrderIsDeterministic(t *testing.T) {
	doc := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	  "paths":{"/z":{"get":{}},"/a":{"post":{},"get":{}},"/m":{"get":{}}}}`
	first := parse(t, doc)
	for i := 0; i < 20; i++ {
		again := parse(t, doc)
		for j := range first.Operations {
			if first.Operations[j].ID != again.Operations[j].ID {
				t.Fatalf("operation order is not deterministic at %d: %s vs %s",
					j, first.Operations[j].ID, again.Operations[j].ID)
			}
		}
	}
}
