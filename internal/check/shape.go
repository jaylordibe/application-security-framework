package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// Comparing two responses for "material equivalence" is the discriminator that
// separates a real authentication bypass from a target that merely returns 200
// to everyone.
//
// The naive comparison — anonymous 200 plus authenticated 200 equals confirmed —
// is wrong on every application that serves a single-page-app shell, a soft
// error envelope or a login page with a success status. Raw body equality is
// wrong in the other direction: real payloads carry request ids, timestamps and
// rotating tokens, so two identical resources rarely produce identical bytes.
//
// What is compared instead is the *shape*: the set of JSON key paths and the
// type of the value at each. Two responses match when an anonymous caller
// received a document with the same structure as the one a legitimate,
// authenticated caller received. That is precisely the claim a confirmed CWE-306
// finding makes, and it is stable against volatile values while remaining
// sensitive to the substitutions that a misleading target performs.

// maxShapeDepth bounds recursion into a target-controlled document.
const maxShapeDepth = 8

// maxShapePaths bounds how many distinct paths are recorded. A hostile body can
// otherwise be a million-key object built to exhaust memory during comparison.
const maxShapePaths = 512

// shape is a structural fingerprint of a response body.
type shape struct {
	// ok is false when a shape could not be computed, which forbids
	// confirmation. A body we could not model is never treated as a match.
	ok bool
	// paths is the sorted set of "path:type" entries.
	paths []string
	// kind records why a shape was rejected, for the verification record.
	kind string
}

// key renders the shape for comparison.
func (s shape) key() string { return strings.Join(s.paths, ";") }

// bodyShape computes the structural fingerprint of a response.
//
// Only JSON is modelled. A non-JSON body is deliberately unmodelled rather than
// compared byte-wise: the check already refuses HTML earlier, and asserting
// structural equivalence between two opaque blobs is a claim the evidence does
// not support.
func bodyShape(resp *model.CapturedResponse) shape {
	if resp == nil {
		return shape{kind: "no response"}
	}
	ct := normalizeContentType(resp.HeaderValue("Content-Type"))
	if !strings.Contains(ct, "json") {
		return shape{kind: "the body is not JSON, so its structure cannot be compared"}
	}
	if resp.BodyTruncated {
		// A truncated body has an incomplete structure. Two truncations that
		// happen to agree prove nothing about the documents behind them.
		return shape{kind: "the body exceeded the capture limit, so its structure is incomplete"}
	}
	body := bytes.TrimSpace(resp.Body)
	if len(body) == 0 {
		return shape{kind: "the body is empty"}
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return shape{kind: "the body is not well-formed JSON"}
	}

	set := make(map[string]struct{}, 32)
	if !walkShape("", doc, 0, set) {
		return shape{kind: "the body is too large or too deeply nested to model structurally"}
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return shape{ok: true, paths: paths}
}

// walkShape records every path and its value type. It returns false when a
// bound is exceeded.
//
// Array indices collapse to "[]" and the element shapes are unioned, so a list
// of two records and a list of five records share a shape. Length is a volatile
// property of data, not a structural property of the resource.
func walkShape(path string, v any, depth int, out map[string]struct{}) bool {
	if depth > maxShapeDepth {
		return false
	}
	if len(out) > maxShapePaths {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[path+":object(empty)"] = struct{}{}
			return true
		}
		for k, child := range t {
			if !walkShape(path+"/"+k, child, depth+1, out) {
				return false
			}
		}
	case []any:
		if len(t) == 0 {
			out[path+":array(empty)"] = struct{}{}
			return true
		}
		for _, child := range t {
			if !walkShape(path+"/[]", child, depth+1, out) {
				return false
			}
		}
	case json.Number:
		out[path+":number"] = struct{}{}
	case string:
		out[path+":string"] = struct{}{}
	case bool:
		out[path+":boolean"] = struct{}{}
	case nil:
		out[path+":null"] = struct{}{}
	default:
		out[path+":unknown"] = struct{}{}
	}
	return true
}

// equivalence is the result of comparing an anonymous response with an
// authenticated control response.
type equivalence struct {
	// Equivalent is true only when every discriminator agreed.
	Equivalent bool
	// Reason explains the decision in operator-facing terms, either way.
	Reason string
}

// materiallyEquivalent decides whether an anonymous response delivered the same
// substance as the authenticated control.
//
// Every condition must hold. Any single disagreement means the anonymous caller
// did not demonstrably reach what a legitimate caller reaches, and the finding
// stays suspected — the conservative direction, because a suspected finding
// invites a human to look while a wrong confirmation spends the credibility the
// whole project depends on.
func materiallyEquivalent(anon, auth *model.CapturedResponse) equivalence {
	if anon == nil || auth == nil {
		return equivalence{Reason: "one of the two responses is missing"}
	}
	if anon.Status != auth.Status {
		return equivalence{Reason: fmt.Sprintf(
			"the anonymous response returned %d and the authenticated control returned %d, so the "+
				"anonymous caller did not receive what a legitimate caller receives",
			anon.Status, auth.Status)}
	}
	anonCT := normalizeContentType(anon.HeaderValue("Content-Type"))
	authCT := normalizeContentType(auth.HeaderValue("Content-Type"))
	if anonCT != authCT {
		return equivalence{Reason: fmt.Sprintf(
			"the anonymous response is %s and the authenticated control is %s",
			quoteOrNone(anonCT), quoteOrNone(authCT))}
	}

	anonShape := bodyShape(anon)
	authShape := bodyShape(auth)
	if !anonShape.ok {
		return equivalence{Reason: "the anonymous response could not be modelled structurally: " + anonShape.kind}
	}
	if !authShape.ok {
		return equivalence{Reason: "the authenticated control could not be modelled structurally: " + authShape.kind}
	}
	if anonShape.key() != authShape.key() {
		return equivalence{Reason: "the two responses have different structures, so the anonymous " +
			"caller received something other than the protected resource — a shell, an error " +
			"envelope or an unrelated document"}
	}
	return equivalence{
		Equivalent: true,
		Reason: fmt.Sprintf("the anonymous response and the authenticated control both returned %d %s with "+
			"the same document structure across %d field paths", anon.Status, quoteOrNone(anonCT),
			len(anonShape.paths)),
	}
}

func quoteOrNone(s string) string {
	if s == "" {
		return "an unstated content type"
	}
	return s
}

// Material equivalence answers "did these two callers receive the same kind of
// document". For a cross-owner test that is necessary and not sufficient.
//
// Two different orders have the same shape. If identity B asks for A's order and
// the application quietly returns B's own order instead — a real and common bug
// — the shapes match perfectly, and shape alone would confirm a BOLA that does
// not exist. What has to be shown is that B received *this* resource, so the
// comparison needs an anchor in the resource's own identifying values.

// resourceEvidence is the outcome of looking for proof that two responses
// describe the same resource.
type resourceEvidence struct {
	// Proven is true when the non-owner's response demonstrably describes the
	// owner's resource rather than merely a document of the same shape.
	Proven bool
	// Reason explains the decision either way.
	Reason string
}

// sameResource looks for proof that attacker and owner received the same
// resource, anchored on the fixture's own parameter values.
//
// Two independent proofs are accepted, because applications differ in whether
// they echo an identifier back:
//
//  1. A fixture value appears at the same JSON path in both bodies. The value
//     addressed the resource, so finding it in the same field of both responses
//     ties them to the same record.
//  2. The two bodies are byte-identical and non-empty. Different records
//     essentially never serialise identically, so this covers APIs that do not
//     echo their identifiers.
//
// Neither being available is not a failure of the application; it is a limit of
// what this evidence can show, and it caps the finding at suspected.
func sameResource(owner, attacker *model.CapturedResponse, values map[string]string) resourceEvidence {
	if owner == nil || attacker == nil {
		return resourceEvidence{Reason: "one of the two responses is missing"}
	}
	if owner.BodyTruncated || attacker.BodyTruncated {
		// A truncated body has an unknown remainder. Two documents whose
		// captured prefixes agree may diverge in the part that was cut, so a
		// prefix match is not evidence that they describe the same resource.
		return resourceEvidence{Reason: "a response exceeded the capture limit, so the part that " +
			"would identify the resource may not have been captured"}
	}

	ownerBody := bytes.TrimSpace(owner.Body)
	attackerBody := bytes.TrimSpace(attacker.Body)
	if len(ownerBody) > 0 && bytes.Equal(ownerBody, attackerBody) {
		return resourceEvidence{
			Proven: true,
			Reason: "the non-owner received a byte-identical document to the owner's",
		}
	}

	ownerPaths, ok := valuePaths(owner)
	if !ok {
		return resourceEvidence{Reason: "the owner's response could not be modelled as JSON, so the " +
			"resource's identifying values could not be located in it"}
	}
	attackerPaths, ok := valuePaths(attacker)
	if !ok {
		return resourceEvidence{Reason: "the non-owner's response could not be modelled as JSON, so it " +
			"could not be tied to the owner's resource"}
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		v := values[name]
		if v == "" {
			continue
		}
		for _, path := range ownerPaths[v] {
			for _, other := range attackerPaths[v] {
				if path == other {
					return resourceEvidence{
						Proven: true,
						Reason: fmt.Sprintf("the fixture's %s value appears at %s in both the owner's "+
							"response and the non-owner's, so the non-owner received this resource "+
							"and not merely a document of the same shape", name, path),
					}
				}
			}
		}
	}

	return resourceEvidence{Reason: "no identifying value from the fixture appears at the same field " +
		"in both responses, and the two documents are not identical, so the non-owner's response " +
		"could not be tied to the owner's resource"}
}

// valuePaths indexes a JSON body by scalar value, mapping each value to the
// sorted paths at which it appears.
func valuePaths(resp *model.CapturedResponse) (map[string][]string, bool) {
	if resp == nil || resp.BodyTruncated {
		return nil, false
	}
	body := bytes.TrimSpace(resp.Body)
	if len(body) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	out := make(map[string][]string, 32)
	if !walkValues("", doc, 0, out) {
		return nil, false
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out, true
}

// walkValues records the path of every scalar, under the same bounds the shape
// walker uses so that a hostile body cannot exhaust memory here either.
func walkValues(path string, v any, depth int, out map[string][]string) bool {
	if depth > maxShapeDepth || len(out) > maxShapePaths {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if !walkValues(path+"/"+k, child, depth+1, out) {
				return false
			}
		}
	case []any:
		for i, child := range t {
			// Array position is part of the path here, unlike in the shape
			// walker: two responses agreeing on the value at items[3] is
			// stronger evidence than agreeing that some element carries it.
			if !walkValues(fmt.Sprintf("%s/[%d]", path, i), child, depth+1, out) {
				return false
			}
		}
	case json.Number:
		out[t.String()] = append(out[t.String()], path)
	case string:
		if t != "" {
			out[t] = append(out[t], path)
		}
	}
	return true
}
