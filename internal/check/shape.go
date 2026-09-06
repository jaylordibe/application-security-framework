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
