package adapter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// Merging is where adapter facts either earn their place or become a liability.
//
// AppSec may learn the same thing from a specification, from an adapter and
// eventually from a request. Those are not interchangeable, and the temptation
// is to let the most recently processed one win. That would make the oracle
// depend on the order sources happened to be read in, and it would let a static
// guess quietly replace something the application declared about itself.
//
// So nothing is overwritten. Sources corroborate, or they conflict, and a
// conflict is a fact about the application worth reporting in its own right:
// two of its own artefacts disagree about whether an endpoint is protected.

// Agreement classifies how an adapter fact relates to what was already known.
type Agreement string

const (
	// AgreementNew means nothing else had an opinion. This is where an adapter
	// adds an oracle that did not exist.
	AgreementNew Agreement = "new"
	// AgreementCorroborated means an existing source said the same thing.
	AgreementCorroborated Agreement = "corroborated"
	// AgreementConflict means an existing source said the opposite.
	AgreementConflict Agreement = "conflict"
	// AgreementUnknown means the adapter looked and could not tell.
	AgreementUnknown Agreement = "unknown"
)

// Merge is one adapter fact reconciled against what was already known.
type Merge struct {
	OperationID string
	Kind        Kind
	Agreement   Agreement
	// AdapterValue is what the adapter asserted.
	AdapterValue Value
	// ExistingValue describes what the prior source said, in words.
	ExistingValue string
	// Adapter names the adapter, and Provenance the grade its method earns.
	Adapter    string
	Provenance model.Provenance
	// Detail explains the reconciliation in one operator-facing sentence.
	Detail string
	// Evidence points at the application source behind the adapter's claim.
	Evidence Evidence
}

// MergeResult is everything one merge pass produced.
type MergeResult struct {
	// Operations is the surface after merging.
	Operations []model.Operation
	// Merges records every reconciliation, in a stable order.
	Merges []Merge
	// UnmatchedOperations names operations an adapter reported that the
	// specification does not contain.
	//
	// They are recorded and deliberately not added to the attack surface.
	// Testing a route that no specification documents is discovery of
	// undocumented surface, which is a separate milestone with its own safety
	// questions; silently attacking one here would be that milestone arriving
	// unannounced.
	UnmatchedOperations []string
	// Limitations carries each adapter's self-reported blind spots forward, so
	// the absence of a fact is never read as the absence of a control.
	Limitations []string
}

// Counts summarises merges by agreement, for reporting.
func (r MergeResult) Counts() map[Agreement]int {
	out := map[Agreement]int{}
	for _, m := range r.Merges {
		out[m.Agreement]++
	}
	return out
}

// Conflicts returns the merges where sources disagree.
func (r MergeResult) Conflicts() []Merge {
	var out []Merge
	for _, m := range r.Merges {
		if m.Agreement == AgreementConflict {
			out = append(out, m)
		}
	}
	return out
}

// authenticationState describes what a specification already says about an
// operation, in the vocabulary the contract uses.
func authenticationState(op model.Operation) (Value, string) {
	switch {
	case op.Security == nil:
		return ValueUnknown, "the specification states no security requirement"
	case op.DeclaresPublic():
		return AuthenticationPublic, "the specification declares this operation public"
	case op.DeclaresAuthRequired():
		return AuthenticationRequired, "the specification declares this operation requires authentication"
	default:
		return ValueUnknown, "the specification makes authentication optional for this operation"
	}
}

// MergeInto reconciles adapter documents with a specification-derived surface.
//
// The returned surface is a copy: merging never mutates the caller's operations,
// so a caller can compare before and after and see exactly what an adapter
// changed.
func MergeInto(ops []model.Operation, docs []Document, now func() model.Source) MergeResult {
	out := MergeResult{Operations: make([]model.Operation, len(ops))}
	copy(out.Operations, ops)

	index := make(map[string]int, len(ops))
	for i, op := range out.Operations {
		index[op.ID] = i
	}

	unmatched := map[string]struct{}{}
	limits := map[string]struct{}{}

	for _, doc := range docs {
		prov := doc.Adapter.ExtractionMethod.Provenance()
		for _, l := range doc.Limitations {
			limits[doc.Adapter.Name+": "+l] = struct{}{}
		}
		for _, f := range doc.Facts {
			opID := f.Operation.ID()
			idx, known := index[opID]
			if !known {
				unmatched[fmt.Sprintf("%s (reported by adapter %s)", opID, doc.Adapter.Name)] = struct{}{}
				continue
			}
			m := Merge{
				OperationID:  opID,
				Kind:         f.Kind,
				AdapterValue: f.Value,
				Adapter:      doc.Adapter.Name,
				Provenance:   prov,
				Evidence:     f.Evidence,
			}

			if f.Value == ValueUnknown {
				m.Agreement = AgreementUnknown
				m.Detail = fmt.Sprintf("adapter %s inspected this operation and could not determine "+
					"its %s, so nothing was added to the oracle", doc.Adapter.Name, shortKind(f.Kind))
				out.Merges = append(out.Merges, m)
				continue
			}

			switch f.Kind {
			case KindAuthentication:
				existing, describe := authenticationState(out.Operations[idx])
				m.ExistingValue = describe
				switch {
				case existing == ValueUnknown:
					m.Agreement = AgreementNew
					m.Detail = fmt.Sprintf("%s, and adapter %s found that it is %s. The operation "+
						"now has an expectation it did not have",
						describe, doc.Adapter.Name, humanValue(f.Value))
					applyAuthentication(&out.Operations[idx], f, doc, now)
				case existing == f.Value:
					m.Agreement = AgreementCorroborated
					m.Detail = fmt.Sprintf("%s, and adapter %s independently found the same",
						describe, doc.Adapter.Name)
					recordSource(&out.Operations[idx], f, doc, now)
				default:
					m.Agreement = AgreementConflict
					m.Detail = fmt.Sprintf("%s, but adapter %s found that it is %s. Two of the "+
						"application's own artefacts disagree, so neither is used as an oracle "+
						"and the disagreement is reported instead",
						describe, doc.Adapter.Name, humanValue(f.Value))
					// A conflicted operation loses its expectation entirely.
					// Choosing a winner would mean deciding, with no evidence,
					// which of the application's own artefacts is wrong.
					out.Operations[idx].Security = nil
					recordSource(&out.Operations[idx], f, doc, now)
				}

			case KindAuthorization, KindOwnership:
				// These add expectations the specification cannot express at
				// all, so there is nothing to conflict with. They are recorded
				// as sources and consumed by the checks that care.
				m.Agreement = AgreementNew
				m.Detail = fmt.Sprintf("adapter %s found that this operation is %s. OpenAPI cannot "+
					"express this, so there was nothing to compare it against",
					doc.Adapter.Name, humanValue(f.Value))
				recordSource(&out.Operations[idx], f, doc, now)
			}
			out.Merges = append(out.Merges, m)
		}
	}

	for u := range unmatched {
		out.UnmatchedOperations = append(out.UnmatchedOperations, u)
	}
	for l := range limits {
		out.Limitations = append(out.Limitations, l)
	}
	sort.Strings(out.UnmatchedOperations)
	sort.Strings(out.Limitations)
	sort.Slice(out.Merges, func(i, j int) bool {
		if out.Merges[i].OperationID != out.Merges[j].OperationID {
			return out.Merges[i].OperationID < out.Merges[j].OperationID
		}
		if out.Merges[i].Kind != out.Merges[j].Kind {
			return out.Merges[i].Kind < out.Merges[j].Kind
		}
		return out.Merges[i].Adapter < out.Merges[j].Adapter
	})
	return out
}

// applyAuthentication gives an operation an expectation it did not have.
//
// The scheme name records where the expectation came from, so a finding raised
// against it can say that the oracle was an adapter's inference rather than the
// specification's declaration.
func applyAuthentication(op *model.Operation, f Fact, doc Document, now func() model.Source) {
	switch f.Value {
	case AuthenticationRequired:
		op.Security = []model.SecurityRequirement{{
			Schemes: []string{"adapter:" + doc.Adapter.Name},
		}}
	case AuthenticationPublic:
		// An explicitly empty requirement list is how this model spells
		// "declared public".
		op.Security = []model.SecurityRequirement{}
	}
	recordSource(op, f, doc, now)
}

// recordSource appends the adapter as a source of this operation's facts.
func recordSource(op *model.Operation, f Fact, doc Document, now func() model.Source) {
	src := model.Source{Kind: model.SourceAdapter}
	if now != nil {
		src = now()
		src.Kind = model.SourceAdapter
	}
	ref := doc.Adapter.Name + " " + string(f.Kind) + "=" + string(f.Value)
	if f.Evidence.File != "" {
		ref += " (" + f.Evidence.File
		if f.Evidence.Line > 0 {
			ref += fmt.Sprintf(":%d", f.Evidence.Line)
		}
		ref += ")"
	}
	src.Ref = ref
	op.Sources = append(op.Sources, src)
}

// shortKind renders a fact kind for prose.
func shortKind(k Kind) string {
	return strings.TrimPrefix(string(k), "operation.")
}

// humanValue renders a fact value for prose.
func humanValue(v Value) string {
	switch v {
	case AuthenticationRequired:
		return "protected"
	case AuthenticationPublic:
		return "public"
	case AuthorizationPresent:
		return "subject to an authorization control"
	case AuthorizationAbsent:
		return "subject to no authorization control"
	case OwnershipScoped:
		return "scoped to the caller's own records"
	case OwnershipUnscoped:
		return "not scoped to the caller's own records"
	default:
		return string(v)
	}
}

// FactFor returns an adapter-derived fact recorded against an operation, if any
// adapter reported one.
//
// It reads back from the merge record rather than from the operation, because
// the operation carries the *effect* of a fact and the merge carries the fact
// itself along with how much it is worth.
func (r MergeResult) FactFor(operationID string, kind Kind) (Merge, bool) {
	for _, m := range r.Merges {
		if m.OperationID == operationID && m.Kind == kind && m.Agreement != AgreementUnknown {
			return m, true
		}
	}
	return Merge{}, false
}
