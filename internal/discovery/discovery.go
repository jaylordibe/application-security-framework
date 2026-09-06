// Package discovery finds attack surface the specification does not describe.
//
// The problem it solves is an accounting one. Coverage measured against a
// specification is coverage of a surface handed over by the thing being audited,
// and a route absent from that document is not reported as untested — it is
// invisible. A report that says "1 of 1 operations assessed" while the
// application serves forty is not wrong about the one; it is wrong about the
// application.
//
// What this package is not is equally important. It is not a crawler. It follows
// no anchors, submits no forms, enters no iframes, reads no sitemap, and never
// uses a document it fetched to decide what to fetch next beyond a single
// non-recursive step: the target's own root page names its own scripts. There is
// no queue, no frontier and no depth parameter, because there is no traversal to
// bound. Everything it does is one pass over a fixed, small set of artefacts the
// application publishes about itself.
//
// And discovery creates no expectations. A path found here is not vulnerable,
// protected, public, safe or testable. It is known to exist, which moves it from
// invisible to untested — and untested, with a reason, is the honest end state.
package discovery

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/scope"
)

// Limits bound everything a target can make discovery do.
//
// Every field exists because a hostile — or merely enormous — application can
// otherwise turn one of these sources into unbounded work. They are separate
// numbers rather than one because the failure modes are different: a thousand
// Link headers is a parsing problem, a 200 MB bundle is a memory problem, and a
// bundle containing a million distinct path literals is a storage problem.
type Limits struct {
	// MaxRequests bounds total HTTP requests discovery may make.
	MaxRequests int
	// MaxScripts bounds how many JavaScript files are fetched.
	MaxScripts int
	// MaxBytes bounds the total response bytes discovery downloads.
	MaxBytes int64
	// MaxCandidates bounds retained candidates across all sources.
	MaxCandidates int
	// MaxCandidatesPerSource bounds what one artefact may contribute, so a
	// single hostile bundle cannot consume the whole global budget and crowd out
	// every other source.
	MaxCandidatesPerSource int
	// MaxPathLength bounds one candidate path.
	MaxPathLength int
}

// DefaultLimits are deliberately small.
//
// The sizing rule is that a complete discovery pass should cost a target about
// as much as loading its own home page, and should never be mistaken for a scan.
func DefaultLimits() Limits {
	return Limits{
		MaxRequests:            20,
		MaxScripts:             5,
		MaxBytes:               8 << 20,
		MaxCandidates:          500,
		MaxCandidatesPerSource: 200,
		MaxPathLength:          512,
	}
}

// normalize fills zero fields with their defaults and clamps hostile values.
func (l Limits) normalize() Limits {
	d := DefaultLimits()
	if l.MaxRequests <= 0 {
		l.MaxRequests = d.MaxRequests
	}
	if l.MaxScripts <= 0 {
		// Zero means "unset", not "fetch none". Turning the source off is what
		// Sources.JavaScript is for, and a budget that silently disabled a
		// source would be a source that reports itself as having run.
		l.MaxScripts = d.MaxScripts
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxCandidates <= 0 {
		l.MaxCandidates = d.MaxCandidates
	}
	if l.MaxCandidatesPerSource <= 0 {
		l.MaxCandidatesPerSource = d.MaxCandidatesPerSource
	}
	if l.MaxPathLength <= 0 {
		l.MaxPathLength = d.MaxPathLength
	}
	return l
}

// Sources selects which discovery sources run. Each is independent: a target
// that serves no robots.txt still has its Link headers read.
type Sources struct {
	LinkHeaders bool
	Robots      bool
	JavaScript  bool
	WellKnown   bool
}

// AllSources enables every source.
func AllSources() Sources {
	return Sources{LinkHeaders: true, Robots: true, JavaScript: true, WellKnown: true}
}

// Any reports whether any source is enabled.
func (s Sources) Any() bool {
	return s.LinkHeaders || s.Robots || s.JavaScript || s.WellKnown
}

// Options configures one discovery pass.
type Options struct {
	// Target is the application's base URL. Its origin is the only origin
	// discovery will contact.
	Target string
	// Client is the scope-enforced HTTP client. Discovery never constructs its
	// own: the scope policy is the authorization boundary, and a second client
	// would be a second boundary.
	Client *httpx.Client
	Limits Limits
	Enable Sources
	Now    func() time.Time
}

// Attempt records what one source did.
//
// A source that was not reached and a source that found nothing must never read
// the same, which is why this carries both a Ran flag and a Problem string.
type Attempt struct {
	// Source names the artefact class.
	Source model.SourceKind
	// Ran reports whether the source was actually consulted.
	Ran bool
	// Found counts candidates it contributed before deduplication.
	Found int
	// Problem explains a source that could not be consulted. Empty on success.
	Problem string
	// Truncated reports that this source hit a limit and has more to give.
	Truncated bool
}

// Result is everything one discovery pass established.
type Result struct {
	// Candidates are the discovered paths, deterministically ordered.
	Candidates []model.PathCandidate
	// Attempts records every source, including those that failed.
	Attempts []Attempt
	// Incomplete reports that a budget stopped the pass. It exists so that a
	// truncated discovery can never be reported as a finished one: "we found
	// twelve paths" and "we stopped counting at twelve" are different claims,
	// and only one of them is compatible with an honest coverage ledger.
	Incomplete bool
	// Limitations are operator-facing sentences about what discovery could not
	// establish.
	Limitations []string
	// Requests counts the HTTP requests the pass made.
	Requests int
	// Bytes counts the response bytes it downloaded.
	Bytes int64
}

// budget tracks consumption across one pass.
type budget struct {
	limits   Limits
	requests int
	bytes    int64
	// exhausted names the first budget that ran out, for the limitation text.
	exhausted string
}

func (b *budget) canRequest() bool {
	if b.requests >= b.limits.MaxRequests {
		if b.exhausted == "" {
			b.exhausted = fmt.Sprintf("the discovery request budget of %d was reached",
				b.limits.MaxRequests)
		}
		return false
	}
	if b.bytes >= b.limits.MaxBytes {
		if b.exhausted == "" {
			b.exhausted = fmt.Sprintf("the discovery download budget of %d bytes was reached",
				b.limits.MaxBytes)
		}
		return false
	}
	return true
}

// Run performs one discovery pass.
//
// It never returns an error. Discovery is additive: a target that serves no
// robots.txt, no JavaScript and no Link headers is a target about which less is
// known, not a failed assessment. Every failure becomes an Attempt with a
// Problem, so the report can say which sources were consulted and which were
// not.
func Run(ctx context.Context, opts Options) Result {
	limits := opts.Limits.normalize()
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	var res Result
	if opts.Client == nil || !opts.Enable.Any() {
		return res
	}

	origin, err := scope.ParseOrigin(opts.Target)
	if err != nil {
		res.Limitations = append(res.Limitations,
			"discovery did not run: the target URL has no usable origin ("+err.Error()+")")
		return res
	}

	c := &collector{
		origin: origin,
		limits: limits,
		now:    now,
		items:  map[string]*model.PathCandidate{},
	}
	b := &budget{limits: limits}

	// The root document, fetched once. It is the only page discovery reads, and
	// it is read for two things: the Link headers on the response, and the
	// scripts the application itself names. Nothing in it leads anywhere else.
	var rootBody []byte
	var rootURL string
	if opts.Enable.LinkHeaders || opts.Enable.JavaScript {
		rootBody, rootURL = c.fetchRoot(ctx, opts, b)
	}

	if opts.Enable.LinkHeaders {
		res.Attempts = append(res.Attempts, c.linkAttempt)
	}
	if opts.Enable.Robots {
		res.Attempts = append(res.Attempts, c.robots(ctx, opts, b))
	}
	if opts.Enable.JavaScript {
		res.Attempts = append(res.Attempts, c.javascript(ctx, opts, b, rootBody, rootURL)...)
	}
	if opts.Enable.WellKnown {
		res.Attempts = append(res.Attempts, c.wellKnown(ctx, opts, b)...)
	}

	res.Candidates = c.finish()
	res.Requests = b.requests
	res.Bytes = b.bytes

	// Incompleteness propagates upward from every level.
	//
	// A global budget, the shared candidate cap and a single source hitting its
	// own limit are three different ways of not finishing, and all three mean
	// the same thing to a reader: there was more to find. Treating only the
	// global budget as "incomplete" would let one truncated bundle produce a
	// result that reports itself as a finished pass.
	if b.exhausted != "" || c.truncated {
		res.Incomplete = true
	}
	var truncatedSources []string
	for _, a := range res.Attempts {
		if a.Truncated {
			res.Incomplete = true
			truncatedSources = append(truncatedSources, sourceName(a.Source))
		}
	}
	if len(truncatedSources) > 0 {
		sort.Strings(truncatedSources)
		res.Limitations = append(res.Limitations,
			"a limit was reached while reading "+strings.Join(truncatedSources, ", ")+
				", so that source had more to give than was taken")
	}
	if b.exhausted != "" {
		res.Limitations = append(res.Limitations,
			"discovery stopped early: "+b.exhausted+". The paths below are what was found "+
				"before that point, not everything the application exposes")
	}
	if c.truncated {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"discovery retained the first %d path candidates and discarded the rest. The count "+
				"below is a floor, not a total", limits.MaxCandidates))
	}
	if c.offOrigin > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d referenced URL(s) point outside the target's own origin and were recorded "+
				"without being contacted. Discovery never widens the authorization boundary "+
				"because the application linked somewhere", c.offOrigin))
	}
	sort.Strings(res.Limitations)
	return res
}

// collector accumulates candidates, merging duplicates by identity.
type collector struct {
	origin    scope.Origin
	limits    Limits
	now       func() time.Time
	items     map[string]*model.PathCandidate
	truncated bool
	offOrigin int
	// linkAttempt is filled while reading the root response, because Link
	// headers arrive on a response fetched for another reason.
	linkAttempt Attempt
}

// add records one candidate, merging provenance when the path is already known.
func (c *collector) add(path string, src model.Source) bool {
	if len(c.items) >= c.limits.MaxCandidates {
		if _, known := c.items[path]; !known {
			c.truncated = true
			return false
		}
	}
	existing, known := c.items[path]
	if !known {
		existing = &model.PathCandidate{Path: path}
		c.items[path] = existing
	}
	for _, s := range existing.Sources {
		if s.Kind == src.Kind && s.Ref == src.Ref {
			// The same artefact naming the same path twice is one fact.
			return true
		}
	}
	existing.Sources = append(existing.Sources, src)
	return true
}

// addOffOrigin records a reference to another origin without fetching it.
func (c *collector) addOffOrigin(reference string, src model.Source) {
	c.offOrigin++
	key := "\x00off\x00" + reference
	if len(c.items) >= c.limits.MaxCandidates {
		if _, known := c.items[key]; !known {
			c.truncated = true
			return
		}
	}
	existing, known := c.items[key]
	if !known {
		existing = &model.PathCandidate{OffOrigin: true, Reference: reference}
		c.items[key] = existing
	}
	for _, s := range existing.Sources {
		if s.Kind == src.Kind && s.Ref == src.Ref {
			return
		}
	}
	existing.Sources = append(existing.Sources, src)
}

// finish renders the collected candidates in a stable order.
func (c *collector) finish() []model.PathCandidate {
	out := make([]model.PathCandidate, 0, len(c.items))
	for _, item := range c.items {
		sort.Slice(item.Sources, func(i, j int) bool {
			if item.Sources[i].Kind != item.Sources[j].Kind {
				return item.Sources[i].Kind < item.Sources[j].Kind
			}
			return item.Sources[i].Ref < item.Sources[j].Ref
		})
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OffOrigin != out[j].OffOrigin {
			return !out[i].OffOrigin
		}
		if out[i].OffOrigin {
			return out[i].Reference < out[j].Reference
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// resolve turns a reference found in an artefact into a candidate, deciding
// whether it is on the target's own origin.
//
// This is the function that decides what discovery is allowed to know about, and
// it answers one question: is this the target's origin? Not "does scope allow
// it" — scope may authorize several hosts, and a link on the target is not
// authorization to explore a different one. Not a string prefix check either:
// origin comparison goes through the same normalization the allowlist uses, so a
// trailing dot, an explicit default port, a Unicode homograph or an
// IPv4-in-IPv6 literal cannot make another host look like this one.
func (c *collector) resolve(ref, base string, src model.Source) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > c.limits.MaxPathLength*2 {
		return
	}
	u, err := url.Parse(ref)
	if err != nil {
		return
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		// mailto:, javascript:, data:, tel: — none is addressable surface.
		return
	}

	if u.IsAbs() || strings.HasPrefix(ref, "//") {
		abs := u
		if !u.IsAbs() {
			// A protocol-relative reference inherits the base scheme.
			b, err := url.Parse(base)
			if err != nil {
				return
			}
			abs = b.ResolveReference(u)
		}
		o, err := scope.OriginOf(abs)
		if err != nil {
			// Unparseable, credentialed or non-HTTP: recorded as nothing. A
			// reference we cannot even name an origin for is not a fact.
			return
		}
		if !o.Equal(c.origin) {
			c.addOffOrigin(o.String()+pathOnly(abs), src)
			return
		}
		c.addPath(pathOnly(abs), src)
		return
	}

	// A relative reference resolves against the document that contained it.
	b, err := url.Parse(base)
	if err != nil {
		return
	}
	abs := b.ResolveReference(u)
	o, err := scope.OriginOf(abs)
	if err != nil || !o.Equal(c.origin) {
		// Resolving a relative reference cannot change origin, so this is
		// defensive; if it ever does, the reference is dropped rather than used.
		return
	}
	c.addPath(pathOnly(abs), src)
}

// addPath validates and records a same-origin path.
func (c *collector) addPath(p string, src model.Source) {
	if p == "" || p == "/" || len(p) > c.limits.MaxPathLength {
		return
	}
	c.add(p, src)
}

// pathOnly renders the structural part of a URL and nothing else.
//
// The query string and fragment are dropped rather than redacted. A discovered
// URL is one of the likeliest places in an assessment to find a session token, a
// password-reset nonce or a signed parameter, and a deny-list of parameter names
// only removes the ones somebody thought of. Keeping no query at all removes the
// class. The escaped form is kept, so "%2f" is never decoded into a separator
// that changes what the path means.
func pathOnly(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// sortedUnique renders a set as a sorted slice.
func sortedUnique(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
