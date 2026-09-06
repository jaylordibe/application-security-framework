package check

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func resp(status int, contentType, body string) *model.CapturedResponse {
	return &model.CapturedResponse{
		Status: status,
		Header: map[string][]string{"Content-Type": {contentType}},
		Body:   []byte(body),
	}
}

const jsonCT = "application/json"

// Material equivalence is the discriminator that decides whether a suspected
// finding may be confirmed. Every row here is a decision about whether a real
// application's response would be reported as a proven authentication bypass.
func TestMateriallyEquivalent(t *testing.T) {
	tests := []struct {
		name string
		anon *model.CapturedResponse
		auth *model.CapturedResponse
		want bool
		why  string
	}{
		{
			name: "identical documents",
			anon: resp(200, jsonCT, `{"id":1,"email":"a@b.test","role":"admin"}`),
			auth: resp(200, jsonCT, `{"id":1,"email":"a@b.test","role":"admin"}`),
			want: true,
		},
		{
			name: "same shape, different values",
			anon: resp(200, jsonCT, `{"id":1,"email":"a@b.test","role":"admin"}`),
			auth: resp(200, jsonCT, `{"id":97,"email":"z@y.test","role":"user"}`),
			want: true,
			why:  "volatile values must not defeat a real match",
		},
		{
			name: "same shape, different list lengths",
			anon: resp(200, jsonCT, `{"items":[{"id":1},{"id":2}]}`),
			auth: resp(200, jsonCT, `{"items":[{"id":9}]}`),
			want: true,
			why:  "list length is a property of data, not of the resource",
		},
		{
			name: "error envelope against a real record",
			anon: resp(200, jsonCT, `{"message":"not found"}`),
			auth: resp(200, jsonCT, `{"id":1,"email":"a@b.test","role":"admin"}`),
			want: false,
			why:  "a soft error must never confirm a bypass",
		},
		{
			name: "fake success envelope against a real record",
			anon: resp(200, jsonCT, `{"success":true,"data":null}`),
			auth: resp(200, jsonCT, `{"id":1,"email":"a@b.test"}`),
			want: false,
		},
		{
			name: "SPA shell against a real record",
			anon: resp(200, "text/html", `<!doctype html><div id="root"></div>`),
			auth: resp(200, jsonCT, `{"id":1,"email":"a@b.test"}`),
			want: false,
			why:  "differing content types are not the same resource",
		},
		{
			name: "different status",
			anon: resp(200, jsonCT, `{"id":1}`),
			auth: resp(201, jsonCT, `{"id":1}`),
			want: false,
		},
		{
			name: "extra field in the authenticated response",
			anon: resp(200, jsonCT, `{"id":1,"email":"a@b.test"}`),
			auth: resp(200, jsonCT, `{"id":1,"email":"a@b.test","ssn":"123"}`),
			want: false,
			why:  "the anonymous caller did not receive the whole protected resource",
		},
		{
			name: "type change at the same key",
			anon: resp(200, jsonCT, `{"id":"1"}`),
			auth: resp(200, jsonCT, `{"id":1}`),
			want: false,
		},
		{
			name: "nested shape difference",
			anon: resp(200, jsonCT, `{"user":{"id":1}}`),
			auth: resp(200, jsonCT, `{"user":{"id":1,"email":"a@b.test"}}`),
			want: false,
		},
		{
			name: "non-JSON bodies are never equivalent",
			anon: resp(200, "text/plain", "ok"),
			auth: resp(200, "text/plain", "ok"),
			want: false,
			why:  "structural equivalence between opaque blobs is not evidence",
		},
		{
			name: "malformed JSON is never equivalent",
			anon: resp(200, jsonCT, `{"id":`),
			auth: resp(200, jsonCT, `{"id":`),
			want: false,
		},
		{
			name: "empty bodies are never equivalent",
			anon: resp(204, jsonCT, ``),
			auth: resp(204, jsonCT, ``),
			want: false,
			why:  "an empty body carries no evidence that a resource was reached",
		},
		{
			name: "missing authenticated response",
			anon: resp(200, jsonCT, `{"id":1}`),
			auth: nil,
			want: false,
		},
		{
			name: "content type parameters are ignored",
			anon: resp(200, "application/json; charset=utf-8", `{"id":1}`),
			auth: resp(200, "application/json", `{"id":1}`),
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := materiallyEquivalent(tc.anon, tc.auth)
			if got.Equivalent != tc.want {
				t.Fatalf("Equivalent = %v, want %v (%s); reason: %s",
					got.Equivalent, tc.want, tc.why, got.Reason)
			}
			if got.Reason == "" {
				t.Error("a comparison must always explain itself, either way")
			}
		})
	}
}

// A truncated body has an incomplete structure. Two truncations that happen to
// agree prove nothing about the documents behind them.
func TestTruncatedBodiesAreNeverEquivalent(t *testing.T) {
	a := resp(200, jsonCT, `{"id":1,"email":"a@b.test"}`)
	b := resp(200, jsonCT, `{"id":1,"email":"a@b.test"}`)
	a.BodyTruncated = true
	if materiallyEquivalent(a, b).Equivalent {
		t.Fatal("a truncated body was accepted as evidence")
	}
}

// A hostile target controls the body. Shape computation must terminate and
// refuse rather than confirm on something it could not model.
func TestHostileBodiesAreRefusedNotConfirmed(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200)

	// Distinct keys, or the object collapses to one field and tests nothing.
	var wideKeys strings.Builder
	wideKeys.WriteString("{")
	for i := 0; i < maxShapePaths+50; i++ {
		fmt.Fprintf(&wideKeys, `"k%d":1,`, i)
	}
	wideKeys.WriteString(`"last":1}`)
	wide := wideKeys.String()

	for _, tc := range []struct{ name, body string }{
		{"deeply nested", deep},
		{"very wide", wide},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := resp(200, jsonCT, tc.body)
			if s := bodyShape(r); s.ok {
				t.Errorf("a body beyond the modelling bounds produced a usable shape")
			}
			if materiallyEquivalent(r, r).Equivalent {
				t.Error("an unmodellable body was confirmed against itself")
			}
		})
	}
}

func TestBodyShapeIsOrderIndependent(t *testing.T) {
	a := bodyShape(resp(200, jsonCT, `{"b":1,"a":"x"}`))
	b := bodyShape(resp(200, jsonCT, `{"a":"y","b":2}`))
	if !a.ok || !b.ok {
		t.Fatal("well-formed JSON did not produce a shape")
	}
	if a.key() != b.key() {
		t.Errorf("key order changed the shape: %q vs %q", a.key(), b.key())
	}
}
