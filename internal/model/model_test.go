package model

import "testing"

// An unknown profile on either side must permit nothing, so malformed input
// fails closed rather than open.
func TestProfileGateFailsClosed(t *testing.T) {
	cases := []struct {
		effective, required Profile
		want                bool
	}{
		{ProfileDiscovery, ProfileDiscovery, true},
		{ProfileVerification, ProfileDiscovery, true},
		{ProfileIntrusive, ProfileVerification, true},
		{ProfileDiscovery, ProfileVerification, false},
		{ProfileVerification, ProfileIntrusive, false},
		{"bogus", ProfileDiscovery, false},
		{ProfileIntrusive, "bogus", false},
		{"", "", false},
	}
	for _, c := range cases {
		allowed, cause := GateProfile(c.effective, c.required)
		if allowed != c.want {
			t.Errorf("GateProfile(%q,%q) = %v, want %v", c.effective, c.required, allowed, c.want)
		}
		if !allowed && cause != CauseSafetyPolicy {
			t.Errorf("GateProfile(%q,%q) cause = %q, want safety_policy", c.effective, c.required, cause)
		}
	}
}

// Impact must be a property of the operation, or a sweep would send
// unauthenticated writes under a read-only profile.
func TestUnsafeMethodsRequireIntrusive(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if got := RequiredProfileForMethod(m); got != ProfileVerification {
			t.Errorf("%s requires %s, want verification", m, got)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "post", "delete"} {
		if got := RequiredProfileForMethod(m); got != ProfileIntrusive {
			t.Errorf("%s requires %s, want intrusive", m, got)
		}
	}
}

func TestDeclaresAuthRequired(t *testing.T) {
	cases := []struct {
		name     string
		security []SecurityRequirement
		want     bool
		public   bool
	}{
		{"silent", nil, false, false},
		{"explicitly public", []SecurityRequirement{}, false, true},
		{"required", []SecurityRequirement{{Schemes: []string{"bearer"}}}, true, false},
		{
			"optional via empty member",
			[]SecurityRequirement{{Schemes: nil}, {Schemes: []string{"bearer"}}},
			false, false,
		},
		{
			"multiple alternatives all requiring auth",
			[]SecurityRequirement{{Schemes: []string{"bearer"}}, {Schemes: []string{"oauth"}}},
			true, false,
		},
	}
	for _, c := range cases {
		op := Operation{Security: c.security}
		if got := op.DeclaresAuthRequired(); got != c.want {
			t.Errorf("%s: DeclaresAuthRequired = %v, want %v", c.name, got, c.want)
		}
		if got := op.DeclaresPublic(); got != c.public {
			t.Errorf("%s: DeclaresPublic = %v, want %v", c.name, got, c.public)
		}
	}
}

func TestRequiredPathParamsIsSorted(t *testing.T) {
	op := Operation{Parameters: []Parameter{
		{Name: "z", In: "path"},
		{Name: "a", In: "path"},
		{Name: "q", In: "query"},
	}}
	got := op.RequiredPathParams()
	if len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("RequiredPathParams = %v, want [a z]", got)
	}
}

func TestEnumValidation(t *testing.T) {
	if !SeverityHigh.Valid() || Severity("nonsense").Valid() {
		t.Error("severity validation is wrong")
	}
	if !ConfidenceLow.Valid() || Confidence("nonsense").Valid() {
		t.Error("confidence validation is wrong")
	}
	if !StateConfirmed.Valid() || FindingState("nonsense").Valid() {
		t.Error("finding state validation is wrong")
	}
	if !OutcomeIndeterminate.Valid() || Outcome("nonsense").Valid() {
		t.Error("outcome validation is wrong")
	}
	if !CauseRateLimited.Valid() || BlockedCause("nonsense").Valid() {
		t.Error("blocked cause validation is wrong")
	}
	if !ProvenanceVerified.Valid() || Provenance("nonsense").Valid() {
		t.Error("provenance validation is wrong")
	}
}

func TestOperationIDIsNormalized(t *testing.T) {
	if got := OperationID(" get ", " /a/b "); got != "GET /a/b" {
		t.Fatalf("OperationID = %q, want %q", got, "GET /a/b")
	}
}

func TestCapturedResponseHeaderLookupIsCaseInsensitive(t *testing.T) {
	r := CapturedResponse{Header: map[string][]string{"Content-Type": {"application/json"}}}
	if r.HeaderValue("content-type") != "application/json" {
		t.Error("header lookup is case sensitive")
	}
	if !r.HasHeader("CONTENT-TYPE") {
		t.Error("HasHeader is case sensitive")
	}
	if r.HeaderValue("missing") != "" {
		t.Error("missing header returned a value")
	}
}
