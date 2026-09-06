// Package openapi turns an OpenAPI document into normalized operations and the
// authorization expectations the document declares.
//
// The specification is untrusted input. For one of the reference applications it
// is fetched from the target itself, so a hostile document must not be able to
// make AppSec Framework read local files or contact other hosts. Only local "#/" pointers
// are resolved; every external $ref is refused and recorded as a coverage gap.
//
// The security-requirement semantics implemented here are the most load-bearing
// rules in the package, and the ones most often got wrong:
//
//   - An operation-level `security` overrides the root-level `security`.
//   - `security: []` means the operation is EXPLICITLY PUBLIC.
//   - A list containing an empty object, e.g. `[{}, {"bearer": []}]`, means
//     authentication is OPTIONAL, so an unauthenticated success is correct
//     behaviour rather than a vulnerability.
//   - Absent `security` means the document said nothing, which is not the same
//     as public and must never be treated as a requirement.
package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// MaxDocumentBytes bounds a specification document.
const MaxDocumentBytes = 16 << 20 // 16 MiB

// maxRefDepth bounds local pointer resolution, defeating reference cycles.
const maxRefDepth = 16

// maxAliases bounds YAML anchor/alias use in a target-supplied document.
//
// A size cap on the input does NOT bound the cost of expansion: alias expansion
// is exponential, so a few hundred bytes of nested anchors can expand to
// hundreds of millions of nodes and wedge the process. A legitimate
// specification uses $ref, not YAML anchors, so a low cap costs nothing real.
const maxAliases = 64

// maxExpandedBytes bounds the document AFTER YAML expansion.
const maxExpandedBytes = MaxDocumentBytes

// maxOperations bounds how many operations a document may declare, so a large
// document cannot turn one assessment into an unbounded one.
const maxOperations = 5000

// parseTimeout bounds wall-clock time spent converting a target-supplied
// document, as a backstop to the alias cap.
const parseTimeout = 15 * time.Second

// ErrSwagger2 is returned for Swagger 2.0 documents. Half-parsing a format we do
// not properly support would produce a confidently wrong attack surface, so it
// is refused outright and recorded as blocked coverage.
var ErrSwagger2 = errors.New("openapi: Swagger 2.0 is not supported; convert the document to OpenAPI 3.x")

// Result is the outcome of ingesting a document.
type Result struct {
	Operations []model.Operation
	// Version is the declared OpenAPI version.
	Version string
	// Title is the document title, sanitized.
	Title string
	// ExternalRefs lists refused external references, so the report can say what
	// was not resolved rather than silently omitting it.
	ExternalRefs []string
	// Fidelity describes how much the declared security requirements can be
	// trusted.
	Fidelity Fidelity
	// Warnings records recoverable problems, sanitized.
	Warnings []string
}

// FidelityLevel grades how trustworthy a document's declared security is as an
// oracle.
type FidelityLevel string

const (
	// FidelityUsable means the document distinguishes protected from public
	// operations, so its declarations carry information.
	FidelityUsable FidelityLevel = "usable"
	// FidelityUniform means every operation carries the same requirement. A
	// generator that stamps one requirement on everything tells us nothing about
	// any individual operation.
	FidelityUniform FidelityLevel = "uniform"
	// FidelitySilent means no operation declares any requirement.
	FidelitySilent FidelityLevel = "silent"
)

// Fidelity is the oracle-quality assessment for a document.
//
// This exists because the specification is not the application. A document that
// marks every operation as requiring authentication, or none of them, produces
// an oracle that is either a wall of false positives or no oracle at all. Grading
// it is what lets the report say so instead of pretending otherwise.
type Fidelity struct {
	Level FidelityLevel
	// Total, Protected, Public and Silent count operations by declaration.
	Total     int
	Protected int
	Public    int
	Silent    int
	// Provenance is declared when the document discriminates, and inferred when
	// its uniformity means we are guessing.
	Provenance model.Provenance
	Detail     string
}

// document is the subset of OpenAPI that AppSec Framework reads.
type document struct {
	OpenAPI string                    `json:"openapi"`
	Swagger string                    `json:"swagger"`
	Info    info                      `json:"info"`
	Servers []server                  `json:"servers"`
	Paths   map[string]map[string]any `json:"paths"`
	Comps   components                `json:"components"`
	Securit []map[string][]string     `json:"security"`
}

type info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type server struct {
	URL string `json:"url"`
}

type components struct {
	Parameters map[string]json.RawMessage `json:"parameters"`
}

// operation is one method entry under a path.
type operation struct {
	OperationID string                `json:"operationId"`
	Summary     string                `json:"summary"`
	Deprecated  bool                  `json:"deprecated"`
	Parameters  []parameter           `json:"parameters"`
	Security    []map[string][]string `json:"security"`
	// securityPresent distinguishes an absent `security` from `security: []`.
	securityPresent bool
}

type parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Ref      string `json:"$ref"`
}

var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// Parse ingests a specification document.
//
// baseURL is the target's origin, used when the document's servers are relative
// or absent. source records where the document came from, for provenance.
func Parse(raw []byte, baseURL string, source model.Source) (Result, error) {
	if len(raw) == 0 {
		return Result{}, errors.New("openapi: document is empty")
	}
	if len(raw) > MaxDocumentBytes {
		return Result{}, fmt.Errorf("openapi: document exceeds %d bytes", MaxDocumentBytes)
	}

	jsonBytes, err := toJSON(raw)
	if err != nil {
		return Result{}, err
	}

	var doc document
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return Result{}, fmt.Errorf("openapi: document is not valid: %s", sanitize(err.Error()))
	}
	if doc.Swagger != "" && doc.OpenAPI == "" {
		return Result{}, ErrSwagger2
	}
	if doc.OpenAPI == "" {
		return Result{}, errors.New("openapi: document has no \"openapi\" version field")
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return Result{}, fmt.Errorf("openapi: unsupported version %q; 3.x is required", sanitize(doc.OpenAPI))
	}

	// Re-decode to learn which operations actually carry a `security` key, which
	// json.Unmarshal into a slice cannot distinguish from an empty list.
	var rawDoc map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &rawDoc); err != nil {
		return Result{}, fmt.Errorf("openapi: document is not an object: %s", sanitize(err.Error()))
	}
	rootSecurityPresent := false
	if _, ok := rawDoc["security"]; ok {
		rootSecurityPresent = true
	}

	res := Result{
		Version: sanitize(doc.OpenAPI),
		Title:   sanitize(doc.Info.Title),
	}

	base := resolveBase(doc.Servers, baseURL, &res)

	for path, methods := range doc.Paths {
		for method, rawOp := range methods {
			lower := strings.ToLower(method)
			if !httpMethods[lower] {
				continue
			}
			op, warns, refs := decodeOperation(rawOp, doc.Comps)
			res.Warnings = append(res.Warnings, warns...)
			res.ExternalRefs = append(res.ExternalRefs, refs...)

			security, present := effectiveSecurity(op, doc.Securit, rootSecurityPresent)

			m := model.Operation{
				ID:           model.OperationID(lower, path),
				Method:       strings.ToUpper(lower),
				PathTemplate: path,
				BaseURL:      base,
				Parameters:   toModelParams(op.Parameters, path),
				Deprecated:   op.Deprecated,
				Summary:      sanitize(op.Summary),
				Sources:      []model.Source{source},
			}
			if present {
				m.Security = security
			}
			res.Operations = append(res.Operations, m)
		}
	}

	if len(res.Operations) > maxOperations {
		return Result{}, fmt.Errorf(
			"openapi: document declares %d operations, more than the limit of %d",
			len(res.Operations), maxOperations)
	}

	model.SortOperations(res.Operations)
	sort.Strings(res.ExternalRefs)
	res.ExternalRefs = dedupe(res.ExternalRefs)
	sort.Strings(res.Warnings)
	res.Warnings = dedupe(res.Warnings)
	res.Fidelity = gradeFidelity(res.Operations)
	return res, nil
}

// toJSON accepts either JSON or YAML.
//
// The YAML path is hostile input: for one of the reference applications the
// document is served by the target itself. Three bounds apply, because the input
// size cap alone does not bound expansion cost.
func toJSON(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		return raw, nil
	}
	if n := countAliases(raw); n > maxAliases {
		return nil, fmt.Errorf(
			"openapi: document uses %d YAML aliases, more than the limit of %d; "+
				"alias expansion is exponential and is a denial-of-service vector, and a "+
				"specification should use $ref rather than YAML anchors", n, maxAliases)
	}

	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := yaml.YAMLToJSON(raw)
		done <- result{data, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			// The parser echoes a snippet of the untrusted document verbatim,
			// control characters included. Never propagate it raw.
			return nil, fmt.Errorf("openapi: document is neither valid JSON nor valid YAML: %s",
				sanitize(r.err.Error()))
		}
		if len(r.data) > maxExpandedBytes {
			return nil, fmt.Errorf(
				"openapi: document expands to %d bytes, more than the limit of %d",
				len(r.data), maxExpandedBytes)
		}
		return r.data, nil
	case <-time.After(parseTimeout):
		// The conversion goroutine is abandoned rather than leaked indefinitely
		// into the caller's critical path; the process exits after the run.
		return nil, fmt.Errorf("openapi: parsing the document exceeded %s and was abandoned", parseTimeout)
	}
}

// countAliases counts YAML alias nodes ("*name") outside quoted scalars.
//
// It is deliberately a cheap lexical pre-scan rather than a parse: the whole
// point is to decide before handing the document to the parser.
func countAliases(raw []byte) int {
	n := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '\n':
			inSingle, inDouble = false, false
		case c == '*' && !inSingle && !inDouble:
			// An alias follows a delimiter and is followed by a name character.
			if i+1 < len(raw) && isNameByte(raw[i+1]) &&
				(i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t' || raw[i-1] == '\n' ||
					raw[i-1] == '[' || raw[i-1] == '{' || raw[i-1] == ',' || raw[i-1] == '-') {
				n++
			}
		}
	}
	return n
}

func isNameByte(b byte) bool {
	return b == '_' || b == '-' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// decodeOperation reads one operation, resolving only local parameter
// references. External references are refused and returned for reporting.
func decodeOperation(rawOp any, comps components) (operation, []string, []string) {
	var warns, refs []string

	encoded, err := json.Marshal(rawOp)
	if err != nil {
		return operation{}, []string{"an operation could not be decoded"}, nil
	}
	var op operation
	if err := json.Unmarshal(encoded, &op); err != nil {
		return operation{}, []string{"an operation could not be decoded"}, nil
	}

	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &asMap); err == nil {
		_, op.securityPresent = asMap["security"]
	}

	resolved := make([]parameter, 0, len(op.Parameters))
	for _, p := range op.Parameters {
		if p.Ref == "" {
			resolved = append(resolved, p)
			continue
		}
		if !strings.HasPrefix(p.Ref, "#/") {
			// External references are a second, unguarded network and filesystem
			// client. Refuse and record rather than resolve.
			refs = append(refs, sanitize(p.Ref))
			continue
		}
		target, err := resolveLocalParam(p.Ref, comps, 0)
		if err != nil {
			warns = append(warns, "unresolved local reference: "+sanitize(p.Ref))
			continue
		}
		resolved = append(resolved, target)
	}
	op.Parameters = resolved
	return op, warns, refs
}

// resolveLocalParam resolves a "#/components/parameters/Name" pointer.
func resolveLocalParam(ref string, comps components, depth int) (parameter, error) {
	if depth > maxRefDepth {
		return parameter{}, errors.New("reference depth exceeded")
	}
	const prefix = "#/components/parameters/"
	if !strings.HasPrefix(ref, prefix) {
		return parameter{}, fmt.Errorf("unsupported local reference")
	}
	name := strings.TrimPrefix(ref, prefix)
	rawParam, ok := comps.Parameters[name]
	if !ok {
		return parameter{}, fmt.Errorf("reference not found")
	}
	var p parameter
	if err := json.Unmarshal(rawParam, &p); err != nil {
		return parameter{}, err
	}
	if p.Ref != "" {
		if !strings.HasPrefix(p.Ref, "#/") {
			return parameter{}, errors.New("external reference refused")
		}
		return resolveLocalParam(p.Ref, comps, depth+1)
	}
	return p, nil
}

// effectiveSecurity applies the override rules. The boolean reports whether the
// document said anything at all about this operation.
func effectiveSecurity(op operation, rootSecurity []map[string][]string, rootPresent bool) ([]model.SecurityRequirement, bool) {
	if op.securityPresent {
		return convertSecurity(op.Security), true
	}
	if rootPresent {
		return convertSecurity(rootSecurity), true
	}
	return nil, false
}

// convertSecurity maps the wire form to the model. An empty member is preserved,
// because it is what makes authentication optional.
func convertSecurity(in []map[string][]string) []model.SecurityRequirement {
	out := make([]model.SecurityRequirement, 0, len(in))
	for _, req := range in {
		schemes := make([]string, 0, len(req))
		for name := range req {
			schemes = append(schemes, sanitize(name))
		}
		sort.Strings(schemes)
		out = append(out, model.SecurityRequirement{Schemes: schemes})
	}
	return out
}

// toModelParams converts parameters, and infers path parameters from the path
// template when the document omits them — which real documents frequently do.
func toModelParams(in []parameter, pathTemplate string) []model.Parameter {
	out := make([]model.Parameter, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		if p.Name == "" {
			continue
		}
		name := sanitize(p.Name)
		in := strings.ToLower(sanitize(p.In))
		// Path parameters are always required, whatever the document claims.
		required := p.Required || in == "path"
		out = append(out, model.Parameter{Name: name, In: in, Required: required})
		if in == "path" {
			seen[name] = true
		}
	}
	for _, name := range pathTemplateParams(pathTemplate) {
		if !seen[name] {
			out = append(out, model.Parameter{Name: name, In: "path", Required: true})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].In != out[j].In {
			return out[i].In < out[j].In
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// pathTemplateParams extracts {name} placeholders from a path template.
func pathTemplateParams(path string) []string {
	var out []string
	for {
		open := strings.IndexByte(path, '{')
		if open < 0 {
			return out
		}
		close := strings.IndexByte(path[open:], '}')
		if close < 0 {
			return out
		}
		name := path[open+1 : open+close]
		if name != "" {
			out = append(out, sanitize(name))
		}
		path = path[open+close+1:]
	}
}

// resolveBase picks the base URL, preferring the target origin the operator
// supplied over a server entry the document controls.
func resolveBase(servers []server, baseURL string, res *Result) string {
	if len(servers) == 0 {
		return strings.TrimRight(baseURL, "/")
	}
	raw := strings.TrimSpace(servers[0].URL)
	if raw == "" || raw == "/" {
		return strings.TrimRight(baseURL, "/")
	}
	u, err := url.Parse(raw)
	if err != nil {
		res.Warnings = append(res.Warnings, "servers[0].url is not a valid URL; using the target base URL")
		return strings.TrimRight(baseURL, "/")
	}
	if !u.IsAbs() {
		// A relative server is a path prefix on the target origin.
		return strings.TrimRight(baseURL, "/") + "/" + strings.Trim(u.Path, "/")
	}
	// An absolute server URL is a fact from an untrusted document. It is kept,
	// but scope still decides whether it may be contacted.
	return strings.TrimRight(u.String(), "/")
}

// gradeFidelity assesses how much information the declared security carries.
// Grade assesses how much information a set of operations' declared security
// carries.
//
// It is exported because the surface can change after parsing: framework
// adapters may give operations an expectation the specification did not carry,
// and a fidelity grade describing the pre-merge surface would misdescribe the
// oracle the run actually used.
func Grade(ops []model.Operation) Fidelity { return gradeFidelity(ops) }

func gradeFidelity(ops []model.Operation) Fidelity {
	f := Fidelity{Total: len(ops), Provenance: model.ProvenanceDeclared}
	for _, op := range ops {
		switch {
		case op.Security == nil:
			f.Silent++
		case op.DeclaresAuthRequired():
			f.Protected++
		default:
			f.Public++
		}
	}
	switch {
	case f.Total == 0:
		f.Level = FidelitySilent
		f.Provenance = model.ProvenanceInferred
		f.Detail = "the document declares no operations"
	case f.Protected == 0:
		f.Level = FidelitySilent
		f.Provenance = model.ProvenanceInferred
		f.Detail = "no operation declares an authentication requirement, so the document " +
			"provides no authorization oracle"
	case f.Protected == f.Total:
		f.Level = FidelityUniform
		f.Provenance = model.ProvenanceInferred
		f.Detail = "every operation carries the same authentication requirement, which is " +
			"typical of a generator that stamps one requirement on all routes; the " +
			"declaration therefore says little about any individual operation"
	default:
		f.Level = FidelityUsable
		f.Detail = fmt.Sprintf("the document discriminates: %d protected, %d public, %d unstated",
			f.Protected, f.Public, f.Silent)
	}
	return f
}

// sanitize removes control characters from target-controlled text, so that a
// hostile document cannot rewrite an operator's terminal or corrupt a report.
func sanitize(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == ' ':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// Dropped: C0 controls and DEL, including ANSI escape introducers.
		case r >= 0x80 && r <= 0x9f:
			// Dropped: C1 controls.
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	const maxLen = 512
	if len(out) > maxLen {
		return out[:maxLen] + "…"
	}
	return out
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}

// WellKnownPaths are the usual locations of a specification on a target's own
// origin. They are probed only with the operator's consent, and only on the
// target host.
func WellKnownPaths() []string {
	return []string{
		"/openapi.json",
		"/openapi.yaml",
		"/swagger.json",
		"/api-docs",
		"/api/docs-json",
		"/v3/api-docs",
		"/docs/api.json",
		"/api/openapi.json",
	}
}

// SourceAt builds a Source for a document obtained now.
func SourceAt(kind model.SourceKind, ref string, now time.Time) model.Source {
	return model.Source{Kind: kind, Ref: ref, ObservedAt: now}
}
