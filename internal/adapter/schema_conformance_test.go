package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schema is the contract an adapter author in another language validates
// against. If it and the Go parser disagree, one of them is lying to somebody.

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "appsec.adapter.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("https://appsec.local/adapter.json", doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	s, err := c.Compile("https://appsec.local/adapter.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return s
}

func validateAgainstSchema(t *testing.T, s *jsonschema.Schema, doc string) error {
	t.Helper()
	var inst any
	if err := json.Unmarshal([]byte(doc), &inst); err != nil {
		return err
	}
	return s.Validate(inst)
}

// Documents the parser accepts must validate, or an adapter author following the
// schema would be rejected at runtime.
func TestSchemaAcceptsWhatTheParserAccepts(t *testing.T) {
	schema := compileSchema(t)
	docs := map[string]string{
		"minimal": minimalValid,
		"full": `{
		  "contractVersion": "appsec.adapter/v1alpha1",
		  "adapter": {"name": "laravel", "version": "0.1.0", "extractionMethod": "static-lexical"},
		  "target": {"framework": "laravel", "frameworkVersion": "12.x"},
		  "facts": [
		    {"kind": "operation.authentication", "operation": {"method": "GET", "path": "/api/a"},
		     "value": "required",
		     "evidence": {"file": "routes/api.php", "line": 3, "detail": "auth group"}},
		    {"kind": "operation.authorization", "operation": {"method": "GET", "path": "/api/a"},
		     "value": "unknown"},
		    {"kind": "operation.ownership", "operation": {"method": "GET", "path": "/api/a"},
		     "value": "owner-scoped"}
		  ],
		  "limitations": ["dynamic middleware is not resolved"]
		}`,
		"framework native": `{
		  "contractVersion": "appsec.adapter/v1alpha1",
		  "adapter": {"name": "x", "version": "1", "extractionMethod": "framework-native"},
		  "facts": []
		}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			if _, err := parseString(t, doc); err != nil {
				t.Fatalf("the parser rejected a document the schema should accept: %v", err)
			}
			if err := validateAgainstSchema(t, schema, doc); err != nil {
				t.Fatalf("the schema rejected a document the parser accepts:\n%v", err)
			}
		})
	}
}

// Documents the parser rejects wholesale must also fail the schema, so an
// adapter author finds the problem before running against the core.
func TestSchemaAndParserAgreeOnRejection(t *testing.T) {
	schema := compileSchema(t)
	docs := map[string]string{
		"unknown contract version": `{"contractVersion":"appsec.adapter/v9",
		  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
		"unknown top-level field": `{"contractVersion":"appsec.adapter/v1alpha1",
		  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
		  "facts":[],"trustMe":true}`,
		"unknown extraction method": `{"contractVersion":"appsec.adapter/v1alpha1",
		  "adapter":{"name":"x","version":"1","extractionMethod":"vibes"},"facts":[]}`,
		"adapter name is not a slug": `{"contractVersion":"appsec.adapter/v1alpha1",
		  "adapter":{"name":"../../etc","version":"1","extractionMethod":"static-lexical"},"facts":[]}`,
		"missing adapter": `{"contractVersion":"appsec.adapter/v1alpha1","facts":[]}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			if _, err := parseString(t, doc); err == nil {
				t.Error("the parser accepted an invalid document")
			}
			if err := validateAgainstSchema(t, schema, doc); err == nil {
				t.Error("the schema accepted an invalid document")
			}
		})
	}
}

// Facts the parser drops individually must also fail the schema where the schema
// can express the rule at all.
func TestSchemaRejectsMalformedFacts(t *testing.T) {
	schema := compileSchema(t)
	docs := map[string]string{
		"unknown kind":       `{"kind":"operation.vibes","operation":{"method":"GET","path":"/a"},"value":"required"}`,
		"unknown value":      `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"probably"}`,
		"unknown method":     `{"kind":"operation.authentication","operation":{"method":"SUBSCRIBE","path":"/a"},"value":"required"}`,
		"empty path":         `{"kind":"operation.authentication","operation":{"method":"GET","path":""},"value":"required"}`,
		"unknown fact field": `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required","confidence":"high"}`,
		"negative line":      `{"kind":"operation.authentication","operation":{"method":"GET","path":"/a"},"value":"required","evidence":{"line":-1}}`,
	}
	for name, fact := range docs {
		t.Run(name, func(t *testing.T) {
			doc := `{"contractVersion":"appsec.adapter/v1alpha1",
			  "adapter":{"name":"x","version":"1","extractionMethod":"static-lexical"},
			  "facts":[` + fact + `]}`
			if err := validateAgainstSchema(t, schema, doc); err == nil {
				t.Error("the schema accepted a malformed fact")
			}
			res, err := parseString(t, doc)
			if err == nil && len(res.Document.Facts) != 0 {
				t.Error("the parser kept a malformed fact")
			}
		})
	}
}

// An adapter cannot name its own provenance: the field does not exist. This
// asserts the absence, because "there is nowhere to claim confidence" is the
// property that makes provenance spoofing require lying about the method
// instead — which at least appears in the report.
func TestSchemaHasNoProvenanceField(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "appsec.adapter.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"provenance"`, `"confidence"`, `"trust"`, `"verified"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the contract exposes %s, which would let an adapter grade itself", forbidden)
		}
	}
}
