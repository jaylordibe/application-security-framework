package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The Go parser is the runtime authority; the JSON Schema exists for editor
// completion and CI validation. Two sources of truth drift silently, so this
// test asserts they agree on a corpus of documents: anything the parser accepts
// the schema must accept, and anything the parser rejects for a structural
// reason the schema must reject too.
//
// The schema is loaded from disk with remote reference resolution disabled. A
// validator that fetched a remote $ref would be a second, unguarded network
// client inside a security tool.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "assay.config.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	// No loader is registered, so any attempt to fetch a remote resource fails
	// closed rather than reaching the network.
	if err := c.AddResource("https://assay.local/config.json", doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	s, err := c.Compile("https://assay.local/config.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return s
}

func validateAgainstSchema(t *testing.T, schema *jsonschema.Schema, doc string) error {
	t.Helper()
	jsonBytes, err := yaml.YAMLToJSON([]byte(doc))
	if err != nil {
		t.Fatalf("convert to json: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("parse instance: %v", err)
	}
	return schema.Validate(inst)
}

// validDocuments must be accepted by both the parser and the schema.
var validDocuments = map[string]string{
	"minimal": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://localhost:3000
`,
	"full": `
apiVersion: assay/v1alpha1
target:
  baseURL: https://staging.example.com
  name: staging
scope:
  include:
    - scheme: https
      host: api.example.com
      ports: [443]
      pathPrefix: /v2/
  allowPrivateAddresses: false
assessment:
  profile: verification
  authorizeIntrusive: false
  concurrency: 8
  requestsPerSecond: 25
  timeoutSeconds: 30
  excludeOperations: ["POST /orders"]
  excludeAuthEndpoints: true
discovery:
  openAPIURL: https://staging.example.com/openapi.json
  probeWellKnownPaths: false
outcome:
  errorCodePointer: /errorCode
  deniedCodes: ["PERMISSION_DENIED"]
  notFoundCodes: ["RESOURCE_NOT_FOUND"]
environment:
  name: staging
  differences: ["rate limiting: relaxed"]
output:
  dir: .assay
`,
	"authorized intrusive": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://localhost:3000
assessment:
  profile: intrusive
  authorizeIntrusive: true
`,
}

// structurallyInvalidDocuments must be rejected by BOTH, because each violation
// is expressible in the schema.
var structurallyInvalidDocuments = map[string]string{
	"unknown top-level field": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
nonsense: true
`,
	"unknown nested field": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
assessment:
  profil: discovery
`,
	"invalid profile": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
assessment:
  profile: aggressive
`,
	"concurrency out of range": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
assessment:
  concurrency: 999
`,
	"port out of range": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
scope:
  include:
    - host: a.test
      ports: [70000]
`,
	"error pointer without leading slash": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://x.test
outcome:
  errorCodePointer: errorCode
`,
	"target with embedded credentials": `
apiVersion: assay/v1alpha1
target:
  baseURL: http://user:pass@x.test
`,
	"wrong apiVersion": `
apiVersion: assay/v99
target:
  baseURL: http://x.test
`,
}

func TestSchemaAcceptsEverythingTheParserAccepts(t *testing.T) {
	schema := compileSchema(t)
	for name, doc := range validDocuments {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(doc), name); err != nil {
				t.Fatalf("parser rejected a valid document: %v", err)
			}
			if err := validateAgainstSchema(t, schema, doc); err != nil {
				t.Fatalf("schema rejected a document the parser accepts:\n%v", err)
			}
		})
	}
}

func TestSchemaAndParserAgreeOnRejection(t *testing.T) {
	schema := compileSchema(t)
	for name, doc := range structurallyInvalidDocuments {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(doc), name); err == nil {
				t.Error("parser accepted an invalid document")
			}
			if err := validateAgainstSchema(t, schema, doc); err == nil {
				t.Error("schema accepted an invalid document")
			}
		})
	}
}

// The shipped example must be valid, or the first thing a user edits is broken.
func TestExampleConfigIsValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "assay.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	if _, err := Parse(bytes.NewReader(raw), "assay.example.yaml"); err != nil {
		t.Fatalf("the shipped example does not parse: %v", err)
	}
	if err := validateAgainstSchema(t, compileSchema(t), string(raw)); err != nil {
		t.Fatalf("the shipped example does not validate against the schema:\n%v", err)
	}
}
