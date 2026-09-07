package adapter

import (
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func op(method, path string, security []model.SecurityRequirement) model.Operation {
	return model.Operation{
		ID: model.OperationID(method, path), Method: method, PathTemplate: path,
		BaseURL: "http://target.test", Security: security,
	}
}

func doc(facts ...Fact) Document {
	return Document{
		ContractVersion: ContractVersion,
		Adapter:         AdapterInfo{Name: "example", Version: "1", ExtractionMethod: MethodStaticLexical},
		Facts:           facts,
	}
}

func authFact(method, path string, v Value) Fact {
	return Fact{Kind: KindAuthentication, Operation: OperationRef{Method: method, Path: path}, Value: v}
}

var (
	protected = []model.SecurityRequirement{{Schemes: []string{"bearer"}}}
	public    = []model.SecurityRequirement{}
)

// The four ways a specification and an adapter can relate. Each has to be
// distinguishable in the result: collapsing any two of them is how a source
// silently overrides another.
func TestMergeAuthenticationAgreementMatrix(t *testing.T) {
	tests := []struct {
		name        string
		spec        []model.SecurityRequirement
		adapter     Value
		want        Agreement
		wantOracle  func(t *testing.T, got model.Operation)
		mustMention string
	}{
		{
			name: "specification silent, adapter says protected", spec: nil,
			adapter: AuthenticationRequired, want: AgreementNew,
			mustMention: "now has an expectation it did not have",
			wantOracle: func(t *testing.T, got model.Operation) {
				if !got.DeclaresAuthRequired() {
					t.Error("the adapter's expectation did not reach the oracle")
				}
			},
		},
		{
			name: "specification silent, adapter says public", spec: nil,
			adapter: AuthenticationPublic, want: AgreementNew,
			wantOracle: func(t *testing.T, got model.Operation) {
				if !got.DeclaresPublic() {
					t.Error("the adapter's public finding did not reach the oracle")
				}
			},
		},
		{
			name: "both say protected", spec: protected,
			adapter: AuthenticationRequired, want: AgreementCorroborated,
			mustMention: "independently found the same",
			wantOracle: func(t *testing.T, got model.Operation) {
				if !got.DeclaresAuthRequired() {
					t.Error("corroboration weakened an existing expectation")
				}
			},
		},
		{
			name: "both say public", spec: public,
			adapter: AuthenticationPublic, want: AgreementCorroborated,
			wantOracle: func(t *testing.T, got model.Operation) {
				if !got.DeclaresPublic() {
					t.Error("corroboration changed an existing expectation")
				}
			},
		},
		{
			name: "specification public, adapter protected", spec: public,
			adapter: AuthenticationRequired, want: AgreementConflict,
			mustMention: "disagree",
			wantOracle: func(t *testing.T, got model.Operation) {
				if got.Security != nil {
					t.Errorf("a conflicted operation kept an expectation: %+v", got.Security)
				}
			},
		},
		{
			name: "specification protected, adapter public", spec: protected,
			adapter: AuthenticationPublic, want: AgreementConflict,
			mustMention: "disagree",
			wantOracle: func(t *testing.T, got model.Operation) {
				if got.Security != nil {
					t.Errorf("a conflicted operation kept an expectation: %+v", got.Security)
				}
			},
		},
		{
			name: "adapter could not tell", spec: nil,
			adapter: ValueUnknown, want: AgreementUnknown,
			mustMention: "could not determine",
			wantOracle: func(t *testing.T, got model.Operation) {
				if got.Security != nil {
					t.Error("an unknown fact invented an expectation")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := []model.Operation{op("GET", "/api/a", tc.spec)}
			res := MergeInto(in, []Document{doc(authFact("GET", "/api/a", tc.adapter))}, nil)

			if len(res.Merges) != 1 {
				t.Fatalf("merges = %d, want 1", len(res.Merges))
			}
			m := res.Merges[0]
			if m.Agreement != tc.want {
				t.Fatalf("agreement = %s, want %s (detail: %s)", m.Agreement, tc.want, m.Detail)
			}
			if m.Detail == "" {
				t.Error("a merge must always explain itself")
			}
			if tc.mustMention != "" && !strings.Contains(m.Detail, tc.mustMention) {
				t.Errorf("detail %q does not mention %q", m.Detail, tc.mustMention)
			}
			tc.wantOracle(t, res.Operations[0])

			// Merging must never mutate the caller's slice, or a caller cannot
			// tell what an adapter changed.
			if in[0].Security != nil && tc.spec == nil {
				t.Error("merging mutated the input operations")
			}
		})
	}
}

// A conflict must not be resolvable by document order. Whichever way round the
// sources arrive, the answer is the same: neither is used.
func TestConflictIsOrderIndependent(t *testing.T) {
	both := []Document{
		doc(authFact("GET", "/api/a", AuthenticationRequired)),
		doc(authFact("GET", "/api/a", AuthenticationPublic)),
	}
	forward := MergeInto([]model.Operation{op("GET", "/api/a", nil)}, both, nil)
	reversed := MergeInto([]model.Operation{op("GET", "/api/a", nil)},
		[]Document{both[1], both[0]}, nil)

	if forward.Operations[0].Security != nil || reversed.Operations[0].Security != nil {
		t.Fatal("two adapters disagreeing still produced an expectation")
	}
	if len(forward.Conflicts()) == 0 || len(reversed.Conflicts()) == 0 {
		t.Error("the disagreement was not recorded as a conflict in both orders")
	}
}

// An adapter reporting a route the specification does not contain must be
// recorded and must not be added to the attack surface. Testing undocumented
// routes is a different milestone with its own safety questions.
func TestUnmatchedOperationsAreRecordedNotAttacked(t *testing.T) {
	res := MergeInto(
		[]model.Operation{op("GET", "/api/a", nil)},
		[]Document{doc(authFact("GET", "/api/secret-admin", AuthenticationPublic))},
		nil,
	)
	if len(res.Operations) != 1 {
		t.Fatalf("the attack surface grew to %d operations from an adapter report", len(res.Operations))
	}
	if len(res.UnmatchedOperations) != 1 {
		t.Fatalf("unmatched = %v, want the adapter-only operation recorded", res.UnmatchedOperations)
	}
	if !strings.Contains(res.UnmatchedOperations[0], "/api/secret-admin") {
		t.Errorf("the unmatched operation is not named: %v", res.UnmatchedOperations)
	}
	if len(res.Merges) != 0 {
		t.Errorf("an unmatched operation produced a merge: %+v", res.Merges)
	}
}

// Adapter blind spots must survive into the result, or the absence of a fact
// reads as the absence of a control.
func TestLimitationsAreCarriedForward(t *testing.T) {
	d := doc()
	d.Limitations = []string{"dynamic middleware is not resolved"}
	res := MergeInto([]model.Operation{op("GET", "/api/a", nil)}, []Document{d}, nil)
	if len(res.Limitations) != 1 {
		t.Fatalf("limitations = %v", res.Limitations)
	}
	if !strings.Contains(res.Limitations[0], "example: dynamic middleware") {
		t.Errorf("the limitation lost its adapter attribution: %v", res.Limitations)
	}
}

// Authorization and ownership have nothing in OpenAPI to conflict with, and
// must be recorded as sources rather than silently dropped.
func TestAuthorizationAndOwnershipFactsAreRecorded(t *testing.T) {
	res := MergeInto([]model.Operation{op("GET", "/api/a", protected)}, []Document{doc(
		Fact{Kind: KindAuthorization, Operation: OperationRef{Method: "GET", Path: "/api/a"},
			Value: AuthorizationPresent, Control: "READ_USER"},
		Fact{Kind: KindOwnership, Operation: OperationRef{Method: "GET", Path: "/api/a"},
			Value: OwnershipScoped},
	)}, nil)

	if len(res.Merges) != 2 {
		t.Fatalf("merges = %d, want 2", len(res.Merges))
	}
	if _, ok := res.FactFor("GET /api/a", KindOwnership); !ok {
		t.Error("the ownership fact is not retrievable")
	}
	if len(res.Operations[0].Sources) != 2 {
		t.Errorf("adapter sources = %d, want 2", len(res.Operations[0].Sources))
	}
	for _, s := range res.Operations[0].Sources {
		if s.Kind != model.SourceAdapter {
			t.Errorf("source kind = %s, want adapter", s.Kind)
		}
	}
}

// A static adapter's inference must never be graded as a declaration.
func TestMergeCarriesTheMethodsProvenance(t *testing.T) {
	native := doc(authFact("GET", "/api/a", AuthenticationRequired))
	native.Adapter.ExtractionMethod = MethodFrameworkNative
	static := doc(authFact("GET", "/api/a", AuthenticationRequired))

	forNative := MergeInto([]model.Operation{op("GET", "/api/a", nil)}, []Document{native}, nil)
	forStatic := MergeInto([]model.Operation{op("GET", "/api/a", nil)}, []Document{static}, nil)

	if forNative.Merges[0].Provenance != model.ProvenanceDeclared {
		t.Errorf("framework-native provenance = %s, want declared", forNative.Merges[0].Provenance)
	}
	if forStatic.Merges[0].Provenance != model.ProvenanceInferred {
		t.Errorf("static provenance = %s, want inferred", forStatic.Merges[0].Provenance)
	}
}

// The defect this pins was found by running against a real application, and it
// made the adapter worse than useless there.
//
// Laravel's Scramble emits `servers: [{url: "http://host/api"}]` with paths
// relative to it, so the specification spells a route `GET /activity-logs`. The
// adapter reads the routing table and spells the same route
// `GET /api/activity-logs`. Matching on the identifier alone meant every one of
// the adapter's 40 facts missed, the entire documented surface was reported as
// undocumented, and M5 then re-added all 40 as "adapter-discovered" operations —
// doubling the surface with duplicates of routes already in it.
func TestAdapterFactsMatchOperationsBehindAServerBasePath(t *testing.T) {
	ops := []model.Operation{{
		ID:           model.OperationID("GET", "/activity-logs"),
		Method:       "GET",
		PathTemplate: "/activity-logs",
		BaseURL:      "http://localhost:8000/api",
	}}

	docs := []Document{{
		Adapter: AdapterInfo{Name: "laravel", ExtractionMethod: MethodStaticLexical},
		Facts: []Fact{{
			Kind:      KindAuthentication,
			Operation: OperationRef{Method: "GET", Path: "/api/activity-logs"},
			Value:     AuthenticationRequired,
		}},
	}}

	res := MergeInto(ops, docs, func() model.Source { return model.Source{} })

	if len(res.UnmatchedOperations) != 0 {
		t.Errorf("the adapter's fact about a documented route was reported as undocumented: %v",
			res.UnmatchedOperations)
	}
	if len(res.DiscoveredOperations) != 0 {
		t.Errorf("a route already in the specification was re-added as discovered surface: %v",
			res.DiscoveredOperations)
	}
	if len(res.Merges) != 1 {
		t.Fatalf("merges = %d, want the adapter fact to reconcile with the operation", len(res.Merges))
	}
	if !res.Operations[0].DeclaresAuthRequired() {
		t.Error("the adapter's expectation did not reach the operation")
	}
}
