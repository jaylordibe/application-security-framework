package check

import (
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func jsonResp(body string) *model.CapturedResponse {
	return &model.CapturedResponse{
		Status: 200,
		Header: map[string][]string{"Content-Type": {"application/json"}},
		Body:   []byte(body),
	}
}

// Shape agreement says two callers got the same kind of document. Only this says
// they got the same document.
func TestSameResource(t *testing.T) {
	values := map[string]string{"orderId": "ord-777"}

	tests := []struct {
		name     string
		owner    string
		attacker string
		want     bool
		why      string
	}{
		{
			name:     "identical documents",
			owner:    `{"id":"ord-777","customer":"alice","total":42}`,
			attacker: `{"id":"ord-777","customer":"alice","total":42}`,
			want:     true,
		},
		{
			name:     "same record, one volatile field differs",
			owner:    `{"id":"ord-777","customer":"alice","requestId":"r-1"}`,
			attacker: `{"id":"ord-777","customer":"alice","requestId":"r-2"}`,
			want:     true,
			why:      "the identifier still anchors both to the same record",
		},
		{
			name:     "the caller's own record, identical in shape",
			owner:    `{"id":"ord-777","customer":"alice","total":42}`,
			attacker: `{"id":"ord-111","customer":"bob","total":99}`,
			want:     false,
			why:      "this is the false positive shape comparison alone would produce",
		},
		{
			name:     "identifier at a different path",
			owner:    `{"id":"ord-777"}`,
			attacker: `{"parentId":"ord-777"}`,
			want:     false,
			why:      "the same string in an unrelated field is not the same record",
		},
		{
			name:     "identifier nested identically",
			owner:    `{"data":{"id":"ord-777","x":1}}`,
			attacker: `{"data":{"id":"ord-777","x":1}}`,
			want:     true,
		},
		{
			name:     "no identifier echoed, different content",
			owner:    `{"customer":"alice"}`,
			attacker: `{"customer":"bob"}`,
			want:     false,
			why:      "nothing ties the two together, so nothing is proven",
		},
		{
			name:     "attacker body is not JSON",
			owner:    `{"id":"ord-777"}`,
			attacker: `<html></html>`,
			want:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sameResource(jsonResp(tc.owner), jsonResp(tc.attacker), values)
			if got.Proven != tc.want {
				t.Fatalf("Proven = %v, want %v (%s); reason: %s",
					got.Proven, tc.want, tc.why, got.Reason)
			}
			if got.Reason == "" {
				t.Error("a decision must always explain itself")
			}
		})
	}
}

// An API that does not echo its identifier is still supported, through identical
// bodies. Without this the check would be useless on a large class of APIs.
func TestSameResourceAcceptsIdenticalBodiesWithoutAnIdentifier(t *testing.T) {
	body := `{"customer":"alice","total":42}`
	got := sameResource(jsonResp(body), jsonResp(body), map[string]string{"orderId": "ord-777"})
	if !got.Proven {
		t.Fatalf("identical bodies were not accepted as evidence: %s", got.Reason)
	}
}

// A truncated body has an unknown remainder, so it cannot anchor anything.
func TestSameResourceRefusesTruncatedBodies(t *testing.T) {
	a := jsonResp(`{"id":"ord-777"}`)
	b := jsonResp(`{"id":"ord-777"}`)
	a.BodyTruncated = true
	if sameResource(a, b, map[string]string{"orderId": "ord-777"}).Proven {
		t.Fatal("a truncated body was accepted as evidence")
	}
}

// A write is credited only when the owner's view did not have the value before
// and does after. Anything weaker attributes somebody else's change to the probe.
func TestMutationApplied(t *testing.T) {
	wrote := map[string]any{"status": "appsec-m2-marker"}

	tests := []struct {
		name    string
		before  string
		after   string
		want    bool
		why     string
		mention string
	}{
		{
			name:    "value changed to what was written",
			before:  `{"id":"o1","status":"paid"}`,
			after:   `{"id":"o1","status":"appsec-m2-marker"}`,
			want:    true,
			mention: "status changed from",
		},
		{
			name:   "nothing changed",
			before: `{"id":"o1","status":"paid"}`,
			after:  `{"id":"o1","status":"paid"}`,
			want:   false,
			why:    "a discarded write must not be credited",
		},
		{
			name:   "already had the written value",
			before: `{"id":"o1","status":"appsec-m2-marker"}`,
			after:  `{"id":"o1","status":"appsec-m2-marker"}`,
			want:   false,
			why:    "the write cannot be credited for a value that was already there",
		},
		{
			name:   "changed to something else",
			before: `{"id":"o1","status":"paid"}`,
			after:  `{"id":"o1","status":"shipped"}`,
			want:   false,
			why:    "an unrelated change is not attributable to this write",
		},
		{
			name:    "value inside a data envelope",
			before:  `{"data":{"id":"o1","status":"paid"}}`,
			after:   `{"data":{"id":"o1","status":"appsec-m2-marker"}}`,
			want:    true,
			mention: "status changed from",
		},
		{
			name:   "field absent after the write",
			before: `{"id":"o1","status":"paid"}`,
			after:  `{"id":"o1"}`,
			want:   false,
		},
		{
			name:   "response is not an object",
			before: `[1,2,3]`,
			after:  `[1,2,3]`,
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mutationApplied(jsonResp(tc.before), jsonResp(tc.after), wrote)
			if got.Changed != tc.want {
				t.Fatalf("Changed = %v, want %v (%s); detail: %s",
					got.Changed, tc.want, tc.why, got.Detail)
			}
			if got.Detail == "" {
				t.Error("a decision must always explain itself")
			}
			if tc.mention != "" && !strings.Contains(got.Detail, tc.mention) {
				t.Errorf("detail %q does not mention %q", got.Detail, tc.mention)
			}
			if tc.want {
				if _, ok := got.Before["status"]; !ok {
					t.Error("the original value was not captured, so restoration is impossible")
				}
			}
		})
	}
}

// Numbers must compare by value, not by encoding, or a restoration check would
// report failure whenever an API round-trips 1 as 1.0.
func TestCanonicalComparesNumbersByValue(t *testing.T) {
	got := mutationApplied(
		jsonResp(`{"total":1}`),
		jsonResp(`{"total":2}`),
		map[string]any{"total": 2},
	)
	if !got.Changed {
		t.Fatalf("a numeric change was not detected: %s", got.Detail)
	}
}

func TestValuesPresent(t *testing.T) {
	if !valuesPresent(jsonResp(`{"status":"paid","x":1}`), map[string]any{"status": "paid"}) {
		t.Error("a present value was not found")
	}
	if valuesPresent(jsonResp(`{"status":"shipped"}`), map[string]any{"status": "paid"}) {
		t.Error("an absent value was reported present, so a failed restoration would look successful")
	}
	if valuesPresent(jsonResp(`not json`), map[string]any{"status": "paid"}) {
		t.Error("an unparseable body reported values present")
	}
}

// The mutation body must be byte-stable so evidence hashes do not churn between
// runs that did the same thing.
func TestMutationBodyIsDeterministic(t *testing.T) {
	values := map[string]any{"b": 2, "a": "x", "c": true}
	first, err := mutationBody(values)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := mutationBody(values)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("mutation body is not stable: %s vs %s", first, again)
		}
	}
	if string(first) != `{"a":"x","b":2,"c":true}` {
		t.Errorf("body = %s, want keys in sorted order", first)
	}
}
