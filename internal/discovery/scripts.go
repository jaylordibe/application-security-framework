package discovery

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// javascript reads the scripts the target's own root document names.
//
// The selection rule is the product boundary in one sentence: only scripts the
// root page references, only on the target's own origin, and never a script
// found inside another script. There is no dependency graph, no dynamic import
// resolution and no source-map fetch — each of those would turn one document
// into a frontier, and a frontier is a crawler.
//
// A script on a CDN is not fetched. That is not a limitation to work around: the
// operator authorized an assessment of their application, and jsdelivr is not
// their application.
func (c *collector) javascript(
	ctx context.Context, opts Options, b *budget, rootBody []byte, rootURL string,
) []Attempt {
	a := Attempt{Source: model.SourceJavaScript}
	if rootURL == "" {
		a.Problem = "no root document was read, so no scripts could be identified"
		return []Attempt{a}
	}
	if len(rootBody) == 0 {
		a.Problem = "the target's root document contained no markup to read scripts from"
		return []Attempt{a}
	}

	refs := ScriptSources(rootBody)
	if len(refs) == 0 {
		a.Ran = true
		a.Problem = "the target's root document referenced no scripts"
		return []Attempt{a}
	}

	// Deterministic order, and deduplicated: a page listing the same bundle
	// twice must not spend two requests on it.
	var sameOrigin []string
	seen := map[string]bool{}
	for _, ref := range refs {
		abs, ok := c.sameOriginAbsolute(ref, rootURL)
		if !ok {
			// A third-party script. Recorded as a reference so the report can
			// say the application loads code from elsewhere, never fetched.
			c.resolve(ref, rootURL, model.Source{
				Kind: model.SourceHTML, Ref: rootURL, ObservedAt: c.now(),
			})
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		sameOrigin = append(sameOrigin, abs)
	}
	sort.Strings(sameOrigin)

	if len(sameOrigin) == 0 {
		a.Ran = true
		a.Problem = "every script the root document referenced is on another origin, so none " +
			"was fetched"
		return []Attempt{a}
	}

	if len(sameOrigin) > c.limits.MaxScripts {
		a.Truncated = true
		sameOrigin = sameOrigin[:c.limits.MaxScripts]
	}

	for _, s := range sameOrigin {
		resp, from, err := c.get(ctx, opts, b, s)
		if err != nil {
			if a.Problem == "" {
				a.Problem = "a script could not be read: " + err.Error()
			}
			continue
		}
		a.Ran = true
		if resp.Status != 200 {
			continue
		}
		if resp.BodyTruncated {
			// The body hit the HTTP client's own size ceiling, so what was
			// scanned is a prefix of the bundle. Saying so is the difference
			// between "these are the paths" and "these are some of the paths".
			a.Truncated = true
		}
		before := len(c.items)
		paths, truncated := PathLiterals(resp.Body, c.limits)
		if truncated {
			a.Truncated = true
		}
		src := model.Source{Kind: model.SourceJavaScript, Ref: from, ObservedAt: c.now()}
		for _, p := range paths {
			c.resolve(p, from, src)
		}
		a.Found += len(c.items) - before
	}

	if a.Truncated && a.Problem == "" {
		a.Problem = "not every referenced script, or not every path literal in one, was read"
	}
	return []Attempt{a}
}

// originOfURL is a thin wrapper so this package names the origin rule once.
func originOfURL(u *url.URL) (scope.Origin, error) { return scope.OriginOf(u) }

// wellKnown probes a deliberately small set of standardized metadata paths.
//
// The entire list is below, and every entry had to earn its place by answering
// one question: does this path, by a published standard, enumerate other paths?
// That test is what keeps this from becoming a wordlist. "/admin", "/debug" and
// "/backup.zip" all fail it — they are guesses about naming, and probing a list
// of guesses is directory brute forcing whatever it is called.
//
// Deliberately excluded, with reasons:
//
//   - /sitemap.xml — a list of pages to crawl. Reading one is the first step of
//     being a crawler, and its contents are site pages rather than API surface.
//   - /.well-known/security.txt (RFC 9116) — names a security contact, not a
//     path. Useful to a human, no surface.
//   - /.well-known/change-password — a single fixed redirect. Reveals nothing.
//   - The OpenAPI locations (/openapi.json, /v3/api-docs and friends) — already
//     probed by the specification loader when the operator permits it. Probing
//     them again here would duplicate requests and, worse, would mean discovery
//     silently assessing a second specification the operator never supplied.
func (c *collector) wellKnown(ctx context.Context, opts Options, b *budget) []Attempt {
	a := Attempt{Source: model.SourceWellKnown}
	base := strings.TrimRight(opts.Target, "/")

	for _, probe := range wellKnownProbes {
		resp, from, err := c.get(ctx, opts, b, base+probe.path)
		if err != nil {
			if a.Problem == "" {
				a.Problem = "a well-known path could not be probed: " + err.Error()
			}
			continue
		}
		a.Ran = true
		if resp.Status != 200 || len(resp.Body) == 0 {
			// Not an absence of surface. Only an absence of this document.
			continue
		}
		before := len(c.items)
		src := model.Source{Kind: model.SourceWellKnown, Ref: from, ObservedAt: c.now()}
		for _, ref := range probe.extract(resp.Body, c.limits) {
			c.resolve(ref, from, src)
		}
		a.Found += len(c.items) - before
	}

	if !a.Ran && a.Problem == "" {
		a.Problem = "no well-known metadata document was served"
	}
	return []Attempt{a}
}

// wellKnownProbe is one standardized document and how to read paths out of it.
type wellKnownProbe struct {
	path string
	// why records the standard that makes this path meaningful. It is not used
	// at runtime; it is here so that adding an entry requires writing down a
	// justification, and so that a reviewer can check each one.
	why     string
	extract func(body []byte, limits Limits) []string
}

var wellKnownProbes = []wellKnownProbe{
	{
		path: "/.well-known/openid-configuration",
		why: "OpenID Connect Discovery 1.0. The document's whole purpose is to " +
			"enumerate endpoints — authorization, token, userinfo, revocation, " +
			"introspection — so it names real authentication surface by design.",
		extract: extractJSONURLs,
	},
	{
		path: "/.well-known/oauth-authorization-server",
		why: "RFC 8414. Same document shape and the same purpose for plain OAuth 2.0 " +
			"deployments that do not implement OIDC.",
		extract: extractJSONURLs,
	},
	{
		path: "/.well-known/oauth-protected-resource",
		why: "RFC 9728. Published by a resource server rather than an authorization " +
			"server, and names the resource itself and its authorization servers.",
		extract: extractJSONURLs,
	},
	{
		path: "/.well-known/apple-app-site-association",
		why: "Apple universal links. The paths array is an explicit list of URL paths " +
			"the application serves to its own mobile client — frequently including " +
			"routes no web specification documents.",
		extract: extractJSONURLs,
	},
	{
		path: "/.well-known/assetlinks.json",
		why: "Android App Links, the Digital Asset Links standard. The same idea and " +
			"the same value as the Apple file.",
		extract: extractJSONURLs,
	},
}

// WellKnownProbePaths returns the probe list, for documentation and tests.
//
// It is exported so that a test can assert the list has not quietly grown into a
// wordlist: the size of this slice is a product decision, not an implementation
// detail.
func WellKnownProbePaths() []string {
	out := make([]string, 0, len(wellKnownProbes))
	for _, p := range wellKnownProbes {
		out = append(out, p.path)
	}
	return out
}

// extractJSONURLs pulls path-like and URL-like strings out of a JSON document.
//
// It reuses the JavaScript literal scanner rather than unmarshalling, for two
// reasons. The shapes differ between these documents — OIDC uses flat
// "*_endpoint" keys, the Apple file uses nested arrays of path patterns — so a
// struct per document would be five structs that each break when a vendor adds a
// field. And a target-supplied JSON document is untrusted input like any other:
// a bounded linear scan has no deep-nesting or allocation behaviour to reason
// about.
//
// URLs are handled as well as paths here, because an OIDC document's endpoints
// are absolute. resolve() then decides whether each one is this origin.
func extractJSONURLs(body []byte, limits Limits) []string {
	paths, _ := PathLiterals(body, limits)
	abs, _ := absoluteURLLiterals(body, limits)
	return append(paths, abs...)
}

// absoluteURLLiterals extracts http(s) URL literals with the same linear,
// regex-free scan used for paths.
func absoluteURLLiterals(body []byte, limits Limits) ([]string, bool) {
	s := string(body)
	seen := map[string]struct{}{}
	n := len(s)
	i := 0
	for i < n {
		c := s[i]
		if c != '"' && c != '\'' {
			i++
			continue
		}
		quote := c
		i++
		start := i
		for i < n && s[i] != quote && s[i] != '\n' && i-start <= limits.MaxPathLength {
			if s[i] == '\\' {
				i += 2
				continue
			}
			i++
		}
		if i >= n || s[i] != quote {
			i++
			continue
		}
		lit := s[start:i]
		i++
		if !strings.HasPrefix(lit, "http://") && !strings.HasPrefix(lit, "https://") {
			continue
		}
		if len(lit) > limits.MaxPathLength {
			continue
		}
		if _, dup := seen[lit]; dup {
			continue
		}
		if len(seen) >= limits.MaxCandidatesPerSource {
			return sortedUnique(seen), true
		}
		seen[lit] = struct{}{}
	}
	return sortedUnique(seen), false
}
