package check

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// mutationResult describes whether a write landed, judged from the owner's own
// view of the resource rather than from the write's response.
type mutationResult struct {
	// Changed is true when the owner's view now carries the written values and
	// did not before.
	Changed bool
	// Before holds the original values of the fields that changed, keyed the
	// same way as the configured mutation, so they can be written back.
	Before map[string]any
	// Detail explains the decision.
	Detail string
}

// mutationApplied compares the owner's before and after views for the fields a
// write attempted to change.
//
// Requiring both halves — the field did not have the written value before, and
// does after — is what makes the change attributable. A field that already held
// the written value proves nothing: the write could have been discarded and the
// state would look identical either way. That case is treated as no change,
// which is the conservative direction.
func mutationApplied(before, after *model.CapturedResponse, wrote map[string]any) mutationResult {
	if before == nil || after == nil {
		return mutationResult{Detail: "one of the owner's two reads is missing"}
	}
	beforeDoc, okBefore := decodeObject(before)
	afterDoc, okAfter := decodeObject(after)
	if !okBefore || !okAfter {
		return mutationResult{Detail: "the owner's view of the resource is not a JSON object, so a " +
			"field-level change could not be established"}
	}

	names := make([]string, 0, len(wrote))
	for k := range wrote {
		names = append(names, k)
	}
	sort.Strings(names)

	changed := map[string]any{}
	var descriptions []string
	for _, name := range names {
		want := canonical(wrote[name])
		had, hadIt := findField(beforeDoc, name)
		now, hasIt := findField(afterDoc, name)
		if !hasIt {
			continue
		}
		if canonical(now) != want {
			continue
		}
		if hadIt && canonical(had) == want {
			// Already had the written value. The write cannot be credited.
			continue
		}
		changed[name] = had
		descriptions = append(descriptions, fmt.Sprintf("%s changed from %s to %s",
			name, renderScalar(had, hadIt), renderScalar(now, true)))
	}

	if len(descriptions) == 0 {
		return mutationResult{Detail: "the owner's view of the resource is unchanged in every field " +
			"the write attempted to set"}
	}
	return mutationResult{
		Changed: true,
		Before:  changed,
		Detail: "the owner's own view of the resource changed: " +
			strings.Join(descriptions, "; "),
	}
}

// valuesPresent reports whether every named field now holds the given value,
// used to verify that a restoration actually took effect.
func valuesPresent(resp *model.CapturedResponse, want map[string]any) bool {
	doc, ok := decodeObject(resp)
	if !ok {
		return false
	}
	for name, v := range want {
		got, has := findField(doc, name)
		if !has || canonical(got) != canonical(v) {
			return false
		}
	}
	return true
}

// decodeObject parses a response body as a JSON object.
func decodeObject(resp *model.CapturedResponse) (map[string]any, bool) {
	if resp == nil || resp.BodyTruncated || len(resp.Body) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(string(resp.Body)))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	obj, ok := doc.(map[string]any)
	return obj, ok
}

// findField looks for a field at the top level, and one level inside a single
// wrapping object such as {"data": {...}}.
//
// One level, not arbitrary depth. Envelope wrapping is near-universal and cheap
// to support; searching the whole document would start matching a field of the
// same name on an unrelated nested record, which is how a comparison stops
// meaning anything.
func findField(doc map[string]any, name string) (any, bool) {
	if v, ok := doc[name]; ok {
		return v, true
	}
	for _, wrapper := range []string{"data", "result", "item", "record", "attributes", "payload"} {
		if nested, ok := doc[wrapper].(map[string]any); ok {
			if v, has := nested[name]; has {
				return v, true
			}
		}
	}
	return nil, false
}

// canonical renders a JSON scalar for comparison, so that 1 and 1.0, or a
// number and its string form, do not compare unequal by accident of encoding.
func canonical(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case json.Number:
		return "n:" + t.String()
	case float64:
		return "n:" + strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	case int:
		return fmt.Sprintf("n:%d", t)
	case string:
		return "s:" + t
	case bool:
		return fmt.Sprintf("b:%t", t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "?"
		}
		return "j:" + string(b)
	}
}

// renderScalar renders a value for a human-readable detail line, bounded so a
// hostile body cannot flood a report.
func renderScalar(v any, present bool) string {
	if !present {
		return "absent"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "an unrenderable value"
	}
	s := string(b)
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
