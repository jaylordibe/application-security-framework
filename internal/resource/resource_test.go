package resource

import (
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func op(method, path string, pathParams ...string) model.Operation {
	o := model.Operation{
		ID:           model.OperationID(method, path),
		Method:       method,
		PathTemplate: path,
		BaseURL:      "http://target.test:8080",
	}
	for _, p := range pathParams {
		o.Parameters = append(o.Parameters, model.Parameter{Name: p, In: "path", Required: true})
	}
	return o
}

// A fixture value is typed by a human and interpolated into a URL. These are the
// values that must never reach the network as written.
func TestBindRefusesValuesThatCouldChangeTheURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"path traversal", "../../admin"},
		{"encoded traversal", "..%2Fadmin"},
		{"absolute path", "/etc/passwd"},
		{"backslash traversal", `..\..\admin`},
		{"query injection", "abc?admin=1"},
		{"fragment injection", "abc#frag"},
		{"authority injection", "evil.test/x"},
		{"userinfo injection", "user@evil.test"},
		{"scheme injection", "http://evil.test"},
		{"protocol-relative", "//evil.test/x"},
		{"percent double-encoding", "%2e%2e%2f"},
		{"null byte", "abc\x00def"},
		{"CRLF", "abc\r\nX-Injected: 1"},
		{"newline", "abc\ndef"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Bind(op("GET", "/api/orders/{orderId}", "orderId"), map[string]string{
				"orderId": tc.value,
			})
			if err == nil {
				t.Fatalf("a fixture value %q was accepted into a URL", tc.value)
			}
		})
	}
}

// Legitimate identifier shapes must still work. Refusing UUIDs or slugs would
// make the feature useless on most real applications.
func TestBindAcceptsRealIdentifierShapes(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"numeric", "123", "http://target.test:8080/api/orders/123"},
		{"uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
			"http://target.test:8080/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
		{"slug", "my-first-order", "http://target.test:8080/api/orders/my-first-order"},
		{"underscored", "order_42", "http://target.test:8080/api/orders/order_42"},
		{"dotted", "v1.2.3", "http://target.test:8080/api/orders/v1.2.3"},
		{"mongo objectid", "507f1f77bcf86cd799439011",
			"http://target.test:8080/api/orders/507f1f77bcf86cd799439011"},
		// A space is legal in a path segment and must be encoded, not refused.
		{"needs encoding", "order 42", "http://target.test:8080/api/orders/order%2042"},
		{"unicode", "naïve", "http://target.test:8080/api/orders/na%C3%AFve"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Bind(op("GET", "/api/orders/{orderId}", "orderId"), map[string]string{
				"orderId": tc.value,
			})
			if err != nil {
				t.Fatalf("a legitimate identifier was refused: %v", err)
			}
			if got.URL != tc.want {
				t.Errorf("URL = %q, want %q", got.URL, tc.want)
			}
			if len(got.Bound) != 1 || got.Bound[0] != "orderId" {
				t.Errorf("Bound = %v, want [orderId]", got.Bound)
			}
		})
	}
}

// Encoding must happen exactly once. A double-encoded identifier addresses a
// resource that does not exist, and the resulting 404 would read as a denial.
func TestBindDoesNotDoubleEncode(t *testing.T) {
	got, err := Bind(op("GET", "/api/orders/{orderId}", "orderId"), map[string]string{
		"orderId": "a b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.URL, "%2520") {
		t.Errorf("value was double-encoded: %s", got.URL)
	}
	if !strings.HasSuffix(got.URL, "/a%20b") {
		t.Errorf("URL = %q, want it to end with /a%%20b", got.URL)
	}
}

func TestBindComposite(t *testing.T) {
	got, err := Bind(
		op("GET", "/api/businesses/{businessId}/members/{memberId}", "businessId", "memberId"),
		map[string]string{"businessId": "b-1", "memberId": "m-2"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "http://target.test:8080/api/businesses/b-1/members/m-2" {
		t.Errorf("URL = %q", got.URL)
	}
	if len(got.Bound) != 2 {
		t.Errorf("Bound = %v, want both parameters", got.Bound)
	}
}

// A fixture that cannot fill an operation must say which parameter is missing,
// so the ledger row explains itself.
func TestBindReportsMissingParameters(t *testing.T) {
	_, err := Bind(
		op("GET", "/api/businesses/{businessId}/members/{memberId}", "businessId", "memberId"),
		map[string]string{"businessId": "b-1"},
	)
	var unfillable *ErrUnfillable
	if err == nil {
		t.Fatal("a partially fillable operation was bound")
	}
	if !strings.Contains(err.Error(), "memberId") {
		t.Errorf("error does not name the missing parameter: %v", err)
	}
	if !asUnfillable(err, &unfillable) {
		t.Errorf("error is not an *ErrUnfillable, so the caller cannot classify it: %T", err)
	}
}

func asUnfillable(err error, target **ErrUnfillable) bool {
	u, ok := err.(*ErrUnfillable)
	if ok {
		*target = u
	}
	return ok
}

// A template segment with no declared parameter must not be sent literally as
// "{name}", which addresses nothing and returns a meaningless 404.
func TestBindRefusesAnUnfilledTemplateSegment(t *testing.T) {
	o := op("GET", "/api/orders/{orderId}/lines/{lineId}", "orderId")
	_, err := Bind(o, map[string]string{"orderId": "1"})
	if err == nil {
		t.Fatal("an operation with an unfilled template segment was bound")
	}
	if !strings.Contains(err.Error(), "lineId") {
		t.Errorf("error does not name the unfilled segment: %v", err)
	}
}

func TestFixtureValidation(t *testing.T) {
	known := map[string]bool{"user-a": true, "user-b": true}
	base := func() Fixture {
		return Fixture{
			ID: "order-a", Type: "order", Owner: "user-a",
			CrossOwnerAccess: CrossOwnerDenied,
			Values:           map[string]string{"orderId": "abc123"},
			Provenance:       ProvenanceConfigured,
		}
	}
	tests := []struct {
		name    string
		mutate  func(*Fixture)
		wantErr string
	}{
		{name: "valid", mutate: func(*Fixture) {}},
		{name: "missing id", mutate: func(f *Fixture) { f.ID = "" }, wantErr: "id is required"},
		{name: "bad id", mutate: func(f *Fixture) { f.ID = "Order A" }, wantErr: "lowercase"},
		{name: "missing owner", mutate: func(f *Fixture) { f.Owner = "" }, wantErr: "owner is required"},
		{
			name:    "unknown owner",
			mutate:  func(f *Fixture) { f.Owner = "ghost" },
			wantErr: "is not a configured identity",
		},
		{
			name:    "no expectation",
			mutate:  func(f *Fixture) { f.CrossOwnerAccess = "" },
			wantErr: "crossOwnerAccess",
		},
		{
			name:    "invalid expectation",
			mutate:  func(f *Fixture) { f.CrossOwnerAccess = "maybe" },
			wantErr: "not one of denied, allowed",
		},
		{name: "no values", mutate: func(f *Fixture) { f.Values = nil }, wantErr: "values is required"},
		{
			name:    "empty value",
			mutate:  func(f *Fixture) { f.Values = map[string]string{"orderId": ""} },
			wantErr: "is empty",
		},
		{
			name:    "traversal in value",
			mutate:  func(f *Fixture) { f.Values = map[string]string{"orderId": "../admin"} },
			wantErr: "path separator",
		},
		{
			name:    "unknown non-owner",
			mutate:  func(f *Fixture) { f.NonOwners = []string{"ghost"} },
			wantErr: "is not a configured identity",
		},
		{
			name:    "owner listed as its own non-owner",
			mutate:  func(f *Fixture) { f.NonOwners = []string{"user-a"} },
			wantErr: "cannot be its own non-owner",
		},
		{
			name:    "mutation with no values",
			mutate:  func(f *Fixture) { f.Mutation = &Mutation{} },
			wantErr: "mutation.values is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base()
			tc.mutate(&f)
			problems := f.Validate("resources[0]", known)
			joined := strings.Join(problems, "\n")
			if tc.wantErr == "" {
				if len(problems) != 0 {
					t.Fatalf("valid fixture rejected:\n%s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.wantErr) {
				t.Fatalf("problems %q do not mention %q", joined, tc.wantErr)
			}
		})
	}
}

func TestDuplicateFixtureIDsAreRejected(t *testing.T) {
	known := map[string]bool{"user-a": true}
	f := Fixture{ID: "x", Owner: "user-a", CrossOwnerAccess: CrossOwnerDenied,
		Values: map[string]string{"id": "1"}}
	problems := ValidateAll([]Fixture{f, f}, known)
	if !strings.Contains(strings.Join(problems, "\n"), "duplicates") {
		t.Fatalf("duplicate fixture ids accepted: %v", problems)
	}
}

func TestAppliesTo(t *testing.T) {
	read := op("GET", "/api/orders/{orderId}", "orderId")
	other := op("GET", "/api/invoices/{invoiceId}", "invoiceId")

	unrestricted := Fixture{}
	if !unrestricted.AppliesTo(read) || !unrestricted.AppliesTo(other) {
		t.Error("a fixture with no operation allowlist must apply everywhere it can bind")
	}

	narrowed := Fixture{Operations: []string{read.ID}}
	if !narrowed.AppliesTo(read) {
		t.Error("an allowlisted operation was excluded")
	}
	if narrowed.AppliesTo(other) {
		t.Error("an operation outside the allowlist was included")
	}
}
