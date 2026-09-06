package discovery

import (
	"strings"
	"testing"

	"github.com/jaylordibe/application-security-framework/internal/model"
)

func op(method, path string) model.Operation {
	return model.Operation{
		ID: model.OperationID(method, path), Method: method, PathTemplate: path,
	}
}

func candidate(path string, kinds ...model.SourceKind) model.PathCandidate {
	c := model.PathCandidate{Path: path}
	for _, k := range kinds {
		c.Sources = append(c.Sources, model.Source{Kind: k})
	}
	return c
}

// The cross-source case from the acceptance criteria: the specification, an
// adapter and a JavaScript bundle all naming one route must produce one surface
// item, not three.
func TestOneRouteNamedByEverySourceStaysOneItem(t *testing.T) {
	ops := []model.Operation{op("GET", "/api/orders")}
	cands := []model.PathCandidate{
		candidate("/api/orders", model.SourceJavaScript, model.SourceLinkHeader,
			model.SourceRobotsTxt),
	}

	m := Merge(ops, cands)

	if len(m.Undocumented) != 0 {
		t.Errorf("a documented route was reported as undocumented surface: %v", m.Undocumented)
	}
	if len(m.Corroborated) != 1 {
		t.Fatalf("corroborations = %d, want 1", len(m.Corroborated))
	}
	if m.Corroborated[0].OperationID != "GET /api/orders" {
		t.Errorf("corroborated %q", m.Corroborated[0].OperationID)
	}
	if len(m.Corroborated[0].Sources) != 3 {
		t.Errorf("provenance was lost in the merge: %v", m.Corroborated[0].Sources)
	}
}

// The disagreement case: an adapter knows the method, JavaScript knows only the
// string. The method must come from the adapter and must not be invented from
// the string.
func TestAMethodComesFromTheSourceThatKnewOne(t *testing.T) {
	ops := []model.Operation{op("POST", "/x")}
	m := Merge(ops, []model.PathCandidate{candidate("/x", model.SourceJavaScript)})

	if len(m.Undocumented) != 0 {
		t.Fatalf("the JavaScript literal became separate surface: %v", m.Undocumented)
	}
	if m.Corroborated[0].OperationID != "POST /x" {
		t.Errorf("the corroborated operation is %q; the adapter's method must survive",
			m.Corroborated[0].OperationID)
	}
}

// The most important negative in the milestone: a path string must never become
// a GET.
func TestAPathStringNeverBecomesAnOperation(t *testing.T) {
	m := Merge(nil, []model.PathCandidate{
		candidate("/api/admin/users", model.SourceJavaScript),
		candidate("/internal/export", model.SourceRobotsTxt),
	})

	if len(m.Undocumented) != 2 {
		t.Fatalf("undocumented = %d, want 2", len(m.Undocumented))
	}
	for _, c := range m.Undocumented {
		if c.Method != "" {
			t.Errorf("%s was given the method %q, which no source established", c.Path, c.Method)
		}
		if strings.HasPrefix(c.ID(), "GET ") {
			t.Errorf("%s was identified as a GET operation: %q", c.Path, c.ID())
		}
		if !strings.HasPrefix(c.ID(), "path ") {
			t.Errorf("a method-less candidate has an operation-shaped id: %q", c.ID())
		}
	}
}

// A path's name is not a security oracle. "/admin" and a robots Disallow are
// the two most tempting ways to invent one.
func TestPathNamesCreateNoSecurityExpectation(t *testing.T) {
	tempting := []model.PathCandidate{
		candidate("/admin", model.SourceRobotsTxt),
		candidate("/admin/users", model.SourceJavaScript),
		candidate("/private/keys", model.SourceJavaScript),
		candidate("/internal/debug", model.SourceRobotsTxt),
		candidate("/api/v1/superuser", model.SourceLinkHeader),
	}
	m := Merge(nil, tempting)
	rows := CoverageRows("path", m.Undocumented)

	if len(rows) != len(tempting) {
		t.Fatalf("rows = %d, want %d", len(rows), len(tempting))
	}
	for _, r := range rows {
		if r.Disposition != model.DispositionUntested {
			t.Errorf("%s: disposition = %s, want untested", r.Subject, r.Disposition)
		}
		if r.Cause != model.CauseNotInSpecification {
			t.Errorf("%s: cause = %s, want not_in_specification", r.Subject, r.Cause)
		}
		if r.CheckID != "" {
			t.Errorf("%s: a check was attributed to a path nothing was planned against", r.Subject)
		}
		// The detail ends with an explicit disclaimer, which necessarily names
		// the things that are not being claimed. Everything before it is what
		// the row actually asserts, and that is what must be free of invented
		// security properties.
		const disclaimer = "Nothing here implies"
		if !strings.Contains(r.Detail, disclaimer) {
			t.Errorf("%s: the row does not disclaim what it has not established:\n%s",
				r.Subject, r.Detail)
		}
		claim, _, _ := strings.Cut(r.Detail, disclaimer)
		lower := strings.ToLower(claim)
		for _, invented := range []string{
			"requires authentication", "should require", "must require",
			"is protected", "is public", "is sensitive", "is privileged",
			"is vulnerable", "is exposed", "appears to be", "likely",
			"admin-only", "should be protected",
		} {
			if strings.Contains(lower, invented) {
				t.Errorf("%s: the detail asserts %q, which no source established:\n%s",
					r.Subject, invented, r.Detail)
			}
		}
		if !strings.Contains(lower, "not assessed") {
			t.Errorf("%s: the detail does not say the path was not assessed:\n%s",
				r.Subject, r.Detail)
		}
	}
}

// A concrete URL corroborates a templated operation. Without this, every
// identifier in a bundle would be reported as an undocumented route and the list
// an operator is meant to read would fill with noise.
func TestConcreteURLsCorroborateTemplatedOperations(t *testing.T) {
	ops := []model.Operation{
		op("GET", "/api/users/{id}"),
		op("GET", "/api/users/{id}/orders/{orderId}"),
	}
	m := Merge(ops, []model.PathCandidate{
		candidate("/api/users/42", model.SourceJavaScript),
		candidate("/api/users/42/orders/7", model.SourceJavaScript),
		candidate("/api/users/42/invoices", model.SourceJavaScript),
	})

	if len(m.Corroborated) != 2 {
		t.Errorf("corroborated = %d, want the two that match templates: %+v",
			len(m.Corroborated), m.Corroborated)
	}
	if len(m.Undocumented) != 1 || m.Undocumented[0].Path != "/api/users/42/invoices" {
		t.Errorf("undocumented = %+v, want only /api/users/42/invoices", m.Undocumented)
	}
}

// A template placeholder matches one segment, never across a separator: hiding
// /users/42/orders inside /users/{id} would conceal a real route.
func TestTemplateMatchingDoesNotCrossSegments(t *testing.T) {
	cases := map[string]struct {
		template, path string
		want           bool
	}{
		"exact":                     {"/a/b", "/a/b", true},
		"one placeholder":           {"/a/{id}", "/a/42", true},
		"two placeholders":          {"/a/{x}/b/{y}", "/a/1/b/2", true},
		"placeholder spans a slash": {"/a/{id}", "/a/42/orders", false},
		"extra segment":             {"/a/b", "/a/b/c", false},
		"missing segment":           {"/a/b/c", "/a/b", false},
		"empty segment":             {"/a/{id}", "/a/", false},
		"different literal":         {"/a/b", "/a/c", false},
		"trailing slash tolerated":  {"/a/b", "/a/b/", true},
	}
	for name, tc := range cases {
		if got := templateMatches(tc.template, tc.path); got != tc.want {
			t.Errorf("%s: templateMatches(%q, %q) = %v, want %v",
				name, tc.template, tc.path, got, tc.want)
		}
	}
}

// Ordering must not depend on map iteration.
func TestMergeIsDeterministic(t *testing.T) {
	cands := []model.PathCandidate{
		candidate("/z", model.SourceJavaScript),
		candidate("/a", model.SourceRobotsTxt),
		candidate("/m", model.SourceLinkHeader),
	}
	ops := []model.Operation{op("GET", "/known")}

	first := Merge(ops, cands)
	for i := 0; i < 50; i++ {
		again := Merge(ops, cands)
		for j := range again.Undocumented {
			if again.Undocumented[j].Path != first.Undocumented[j].Path {
				t.Fatalf("run %d differs at %d", i, j)
			}
		}
	}
	want := []string{"/a", "/m", "/z"}
	for i, w := range want {
		if first.Undocumented[i].Path != w {
			t.Fatalf("undocumented is not sorted: %+v", first.Undocumented)
		}
	}
}

// The ledger row must name where the path came from, because "this exists and
// nothing checked it" is only actionable if a reader can go and look.
func TestCoverageRowsCarryProvenance(t *testing.T) {
	rows := CoverageRows("path", []model.PathCandidate{
		candidate("/x", model.SourceJavaScript, model.SourceRobotsTxt),
	})
	if len(rows) != 1 {
		t.Fatal("no row")
	}
	d := rows[0].Detail
	if !strings.Contains(d, "robots.txt") || !strings.Contains(d, "JavaScript") {
		t.Errorf("the row does not say where the path came from: %q", d)
	}
	if !strings.Contains(d, "method is unknown") {
		t.Errorf("the row does not say the method is unknown: %q", d)
	}
}

// Off-origin references are surfaced separately and never counted as target
// surface.
func TestOffOriginReferencesAreNotTargetSurface(t *testing.T) {
	m := Merge(nil, []model.PathCandidate{
		{OffOrigin: true, Reference: "https://cdn.example.test/lib.js",
			Sources: []model.Source{{Kind: model.SourceHTML}}},
		candidate("/local", model.SourceJavaScript),
	})
	if len(m.Undocumented) != 1 || m.Undocumented[0].Path != "/local" {
		t.Errorf("undocumented = %+v, want only the same-origin path", m.Undocumented)
	}
	if len(m.OffOrigin) != 1 {
		t.Fatalf("off-origin = %d, want 1", len(m.OffOrigin))
	}
	rows := CoverageRows("path", m.Undocumented)
	if len(rows) != 1 {
		t.Errorf("an off-origin reference produced a coverage row: %d rows", len(rows))
	}
}
