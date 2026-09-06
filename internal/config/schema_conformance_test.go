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
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "appsec.config.schema.json"))
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
	if err := c.AddResource("https://appsec.local/config.json", doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	s, err := c.Compile("https://appsec.local/config.json")
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
	"surface discovery, every field set": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
discovery:
  openAPIFile: ./openapi.json
  surface:
    enabled: true
    linkHeaders: true
    robots: true
    javascript: false
    wellKnown: true
    maxRequests: 10
    maxScripts: 2
    maxBytes: 1048576
    maxCandidates: 50
    assessAdapterDiscovered: false
`,
	"surface discovery turned off entirely": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
discovery:
  openAPIFile: ./openapi.json
  surface:
    enabled: false
`,
	"resource fixture": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    type: order
    owner: user-a
    crossOwnerAccess: denied
    values:
      orderId: "abc123"
`,
	"shared resource with mutation and narrowing": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: allowed
    values: {orderId: "abc123"}
    operations: ["GET /api/orders/{orderId}"]
    nonOwners: [user-b]
    mutation:
      values:
        status: "appsec-marker"
`,
	"no resources": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
resources: []
`,
	"bearer identity": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
identities:
  - id: admin
    label: Administrator
    authentication:
      type: bearer
      credential:
        env: APPSEC_ADMIN_TOKEN
    liveness:
      method: GET
      path: /api/me
      expectStatus: [200]
`,
	"api key identity from a file": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
identities:
  - id: service
    authentication:
      type: apiKey
      header: X-API-Key
      valuePrefix: "Token "
      credential:
        file: /run/secrets/service-key
`,
	"no identities": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
identities: []
`,
	"minimal": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://localhost:3000
`,
	"full": `
apiVersion: appsec/v1alpha1
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
  dir: .appsec
`,
	"authorized intrusive": `
apiVersion: appsec/v1alpha1
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
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
nonsense: true
`,
	"unknown nested field": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
assessment:
  profil: discovery
`,
	"invalid profile": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
assessment:
  profile: aggressive
`,
	"concurrency out of range": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
assessment:
  concurrency: 999
`,
	"port out of range": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
scope:
  include:
    - host: a.test
      ports: [70000]
`,
	"error pointer without leading slash": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
outcome:
  errorCodePointer: errorCode
`,
	"target with embedded credentials": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://user:pass@x.test
`,
	"wrong apiVersion": `
apiVersion: appsec/v99
target:
  baseURL: http://x.test
`,
	"identity id is reserved": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: anonymous
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
`,
	"identity id is not a slug": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: "Admin User"
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
`,
	"unsupported authentication type": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: oauth2
      credential: {env: A_TOKEN}
`,
	"credential header name is not a token": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: apiKey
      header: "X-Key: injected"
      credential: {env: A_TOKEN}
`,
	"credential has neither env nor file": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: bearer
      credential: {}
`,
	"credential has both env and file": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN, file: /tmp/t}
`,
	"a literal credential value is not a field": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: bearer
      token: supersecret
      credential: {env: A_TOKEN}
`,
	"canary path is not absolute": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
    liveness:
      path: api/me
`,
	"resource has no crossOwnerAccess": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    values: {orderId: "1"}
`,
	"resource expectation is not a known value": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: maybe
    values: {orderId: "1"}
`,
	"resource value contains a path separator": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "../../admin"}
`,
	"resource value contains a query delimiter": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "a?b=1"}
`,
	"resource has no values": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {}
`,
	"resource id is not a slug": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: "Order A"
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
`,
	"mutation without values": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
    mutation: {}
`,
	"canary method is unsafe": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
    liveness:
      method: DELETE
      path: /api/me
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

// semanticallyInvalidDocuments are rejected by the parser but cannot be
// rejected by the schema.
//
// JSON Schema validates one document against a fixed shape. It cannot express
// "this owner must be one of the ids listed elsewhere in the same file", because
// that is a cross-reference between two arrays whose contents are only known at
// load time. The rule is real and is enforced; it simply has one enforcement
// point rather than two, and pretending otherwise in the conformance table would
// be the sort of overstatement this project exists to avoid.
var semanticallyInvalidDocuments = map[string]string{
	"resource owner is not a configured identity": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: ghost
    crossOwnerAccess: denied
    values: {orderId: "1"}
`,
	"non-owner is not a configured identity": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
    nonOwners: [ghost]
`,
	"owner listed as its own non-owner": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
    nonOwners: [user-a]
`,
	"duplicate resource ids": `
apiVersion: appsec/v1alpha1
target:
  baseURL: http://x.test
identities:
  - id: user-a
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: user-b
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
  - id: order-a
    owner: user-b
    crossOwnerAccess: denied
    values: {orderId: "2"}
`,
}

// The parser must reject every cross-reference error, and must say which name
// was wrong so the operator can fix it without guessing.
func TestParserRejectsInvalidCrossReferences(t *testing.T) {
	for name, doc := range semanticallyInvalidDocuments {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(doc), name); err == nil {
				t.Fatal("parser accepted a document with an invalid reference")
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
	raw, err := os.ReadFile(filepath.Join("..", "..", "appsec.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	if _, err := Parse(bytes.NewReader(raw), "appsec.example.yaml"); err != nil {
		t.Fatalf("the shipped example does not parse: %v", err)
	}
	if err := validateAgainstSchema(t, compileSchema(t), string(raw)); err != nil {
		t.Fatalf("the shipped example does not validate against the schema:\n%v", err)
	}
}
