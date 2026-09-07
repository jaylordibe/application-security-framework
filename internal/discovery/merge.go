package discovery

import (
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

// Merged is the reconciliation of discovered paths against the known surface.
type Merged struct {
	// Corroborated are candidates whose path a known operation already covers.
	// They are not new surface; they are a second source for surface already
	// accounted for, and they are reported so that "the specification says this
	// exists and so does the application's own JavaScript" is visible.
	Corroborated []Corroboration
	// Undocumented are candidates no known operation covers. These are the
	// point of the milestone: surface that was invisible and is now untested.
	Undocumented []model.PathCandidate
	// OffOrigin are references to other origins, recorded and never contacted.
	OffOrigin []model.PathCandidate
}

// Corroboration links a discovered path to the operation it confirms.
type Corroboration struct {
	OperationID string
	Path        string
	Sources     []model.Source
}

// Merge reconciles discovered candidates with the operations already known.
//
// The rule is that a path is one thing however many artefacts mention it. A
// route in the OpenAPI document, the same route reported by a framework adapter
// and the same route appearing in a JavaScript bundle are one surface item with
// three sources — never three items, which would make the surface look three
// times larger than it is and the coverage three times worse.
//
// What Merge will not do is give a candidate a method. A JavaScript literal
// "/api/orders" establishes that the string exists; it does not establish that
// the route answers GET, or answers at all. Matching it against a known
// GET /api/orders corroborates that operation, because the operation's method
// came from a source that knew one. Failing to match leaves the candidate
// method-less, and a method-less candidate can only ever be accounted for, never
// probed.
func Merge(ops []model.Operation, candidates []model.PathCandidate) Merged {
	var out Merged

	// Index the known surface by path template. Several operations may share one
	// path (GET and POST on /users), so the value is a list.
	// Operations are indexed by the path the application actually serves, not by
	// the specification-relative template.
	//
	// A discovered path is always application-absolute — a Link header, a
	// robots.txt line and a JavaScript literal all name "/api/orders", never
	// "/orders". A specification whose server URL carries a base path spells the
	// same route "/orders". Indexing on the template alone means nothing
	// corroborates and every documented route is re-reported as undocumented.
	byPath := map[string][]model.Operation{}
	var templates []model.Operation
	for _, op := range ops {
		served := op.AbsolutePath()
		byPath[served] = append(byPath[served], op)
		if served != op.PathTemplate {
			byPath[op.PathTemplate] = append(byPath[op.PathTemplate], op)
		}
		if strings.ContainsRune(served, '{') {
			templates = append(templates, op)
		}
	}

	for _, cand := range candidates {
		if cand.OffOrigin {
			out.OffOrigin = append(out.OffOrigin, cand)
			continue
		}

		matched := byPath[cand.Path]
		if len(matched) == 0 {
			// A concrete URL such as /users/42 corroborates a templated
			// operation /users/{id}. Without this, every identifier a bundle
			// happens to contain would be reported as an undocumented route,
			// and the undocumented list — the one thing an operator is meant to
			// read — would fill with noise.
			matched = matchTemplates(templates, cand.Path)
		}
		if len(matched) > 0 {
			for _, op := range matched {
				out.Corroborated = append(out.Corroborated, Corroboration{
					OperationID: op.ID,
					Path:        cand.Path,
					Sources:     cand.Sources,
				})
			}
			continue
		}
		out.Undocumented = append(out.Undocumented, cand)
	}

	sort.Slice(out.Corroborated, func(i, j int) bool {
		if out.Corroborated[i].Path != out.Corroborated[j].Path {
			return out.Corroborated[i].Path < out.Corroborated[j].Path
		}
		return out.Corroborated[i].OperationID < out.Corroborated[j].OperationID
	})
	model.SortPathCandidates(out.Undocumented)
	sort.Slice(out.OffOrigin, func(i, j int) bool {
		return out.OffOrigin[i].Reference < out.OffOrigin[j].Reference
	})
	return out
}

// matchTemplates returns operations whose path template matches a concrete path.
func matchTemplates(templates []model.Operation, path string) []model.Operation {
	var out []model.Operation
	for _, op := range templates {
		if templateMatches(op.AbsolutePath(), path) || templateMatches(op.PathTemplate, path) {
			out = append(out, op)
		}
	}
	return out
}

// templateMatches reports whether a concrete path fits an OpenAPI path template.
//
// A "{param}" placeholder matches exactly one non-empty segment. It does not
// match across "/", because "/users/{id}" and "/users/42/orders" are different
// operations and treating the second as the first would hide a real route.
func templateMatches(template, path string) bool {
	t := strings.Split(strings.Trim(template, "/"), "/")
	p := strings.Split(strings.Trim(path, "/"), "/")
	if len(t) != len(p) {
		return false
	}
	for i := range t {
		seg := t[i]
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			if p[i] == "" {
				return false
			}
			continue
		}
		if seg != p[i] {
			return false
		}
	}
	return true
}

// CoverageRows renders discovered surface as ledger entries.
//
// Every undocumented path becomes an untested row with a machine-readable cause.
// That is the whole mechanism by which this milestone changes anything: before
// it, a route the specification omitted contributed nothing to the ledger and so
// could not be counted, mentioned or missed. After it, the same route is one
// line of the account of what was not assessed.
//
// The rows are deliberately untested rather than blocked. Blocked means work was
// planned and could not run; nothing was planned against these, because planning
// requires a method and an expectation, and a discovered path has neither.
func CoverageRows(dimension string, undocumented []model.PathCandidate) []model.CoverageEntry {
	out := make([]model.CoverageEntry, 0, len(undocumented))
	for _, c := range undocumented {
		out = append(out, model.CoverageEntry{
			Dimension:   dimension,
			Subject:     c.ID(),
			Disposition: model.DispositionUntested,
			Cause:       model.CauseNotInSpecification,
			Detail:      describeCandidate(c),
		})
	}
	return out
}

// describeCandidate explains, in one operator-facing sentence, what is known
// about a discovered path and what is not.
func describeCandidate(c model.PathCandidate) string {
	var b strings.Builder
	b.WriteString("this path was found by ")
	b.WriteString(joinSources(c.Sources))
	b.WriteString(" and no specification or adapter describes it. ")
	if c.Method == "" {
		b.WriteString("Its HTTP method is unknown, so no request can be formed that would mean " +
			"anything, and nothing states what it should return to whom. ")
	} else {
		b.WriteString("No source states what it should return to whom. ")
	}
	b.WriteString("It is recorded as surface that exists and was not assessed. Nothing here " +
		"implies it is exposed, protected or vulnerable")
	return b.String()
}

// joinSources renders provenance as a readable list.
func joinSources(sources []model.Source) string {
	if len(sources) == 0 {
		return "discovery"
	}
	seen := map[string]bool{}
	var names []string
	for _, s := range sources {
		n := sourceName(s.Kind)
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

// sourceName renders a source kind in operator-facing words.
func sourceName(k model.SourceKind) string {
	switch k {
	case model.SourceLinkHeader:
		return "a Link header"
	case model.SourceRobotsTxt:
		return "robots.txt"
	case model.SourceJavaScript:
		return "a JavaScript bundle the application served"
	case model.SourceHTML:
		return "the target's own root document"
	case model.SourceWellKnown:
		return "a well-known metadata document"
	case model.SourceAdapter:
		return "a framework adapter"
	default:
		return string(k)
	}
}
