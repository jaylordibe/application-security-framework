# ADR-0016: A discovered path is not an operation, and discovery is not a crawler

- **Status:** Accepted
- **Date:** 2026-09-07
- **Relates to:** [ADR-0008](0008-scope-is-the-authorization-boundary.md),
  [ADR-0010](0010-coverage-is-a-ledger.md),
  [ADR-0014](0014-adapter-contract-and-extraction-trust.md)

## Context

Coverage measured against a specification is coverage of a surface handed over by
the thing being audited. A report saying "1 of 1 operations assessed" against an
application serving forty routes is not wrong about the one; it is wrong about
the application. That gap is the reason M5 exists.

It is also the point at which this project is most likely to become something it
decided not to be. The product thesis lists "a crawler / API inventory product"
as an explicit non-goal and names the mitigation — *defer crawling; never build a
spider*. Discovery is the feature that makes ignoring that easy, because every
step from "read the root page" to "read every page" is individually small.

Three decisions had to be made, and none is settled by the roadmap's one
sentence.

**What a discovered path is.** The existing model has `Operation`: a method, a
path, a security requirement, something a check can be planned against.
Discovery mostly produces a string. Finding `/api/admin/users` in a bundle
establishes that the literal appears in code the target served — not that the
route exists, not that it answers `GET`, and not that it requires anything.

**What discovery is allowed to fetch.** Scope is the authorization boundary and
may name several hosts. A link found on the target is not authorization to visit
one of them.

**What a discovered path means for the ledger.** It has to be visible, or the
milestone achieves nothing. It must not be assessed, or the milestone invents
requests nobody authorized against expectations nobody stated.

## Decision

**1. A discovered path is a new, smaller type — `model.PathCandidate` — and never
an `Operation`.**

It carries a path, provenance, and a method *only when a source genuinely
established one*. Forcing it into `Operation` would require choosing a method,
and there is no honest choice: an invented method produces an invented request,
an invented response and an invented conclusion. The type's identity reflects
this — a method-less candidate is `path /x`, which cannot collide with or be
mistaken for the operation identifier `GET /x`.

The one route from discovered to assessed runs through a framework adapter. An
adapter that reports `GET /hidden` read the application's routing table: the
method is known, and the authentication expectation comes from the same source
that would have supplied it had the route been documented. Nothing is invented,
so those operations are adopted into the assessed surface — behind a switch,
because it means requesting routes the operator may not have known were there.

**2. Discovery contacts the target's own origin and nothing else, and never
fetches anything it discovered.**

The set of URLs discovery will request is fixed before any target output is read:
the root (plus at most one same-origin redirect hop), `/robots.txt`, the
same-origin scripts the root document names, and five well-known paths. A path or
URL that discovery *finds* is recorded and never requested.

That is a stronger property than filtering discovered URLs would be, and it is
what makes server-side request forgery a non-question here rather than a control
to audit: there is no path from target output to a request target.

Origin comparison goes through `scope.Origin`, which reuses the allowlist's own
normalization. A second origin parser inside discovery is exactly how this would
have been bypassed by a trailing dot or a homograph, so there is not one.

**3. A discovered path becomes exactly one untested ledger row, and creates no
expectation.**

Dimension `path`, disposition `untested`, cause `not_in_specification`, and a
detail that says what is not known. It counts toward the headline untested
figure, because "surface that exists and was not assessed" is precisely what that
counter means.

No security property is ever derived from a path's name. `/admin` is a string.
`Disallow: /admin` in `robots.txt` is a request to search engines and says
nothing about who may reach it. This is written down because it is the single
easiest mistake available in this milestone, and because a tool that reported
"undocumented admin endpoint" would be inventing the only interesting word in
that sentence.

## Alternatives considered

**Give every discovered path a `GET` operation and probe it.** Rejected. Most
would 404, a 404 would be reported as "not exposed", and the report would carry
conclusions about routes whose methods were guessed. It would also be the
recursive discovery-to-scanner expansion loop that M4's boundary deliberately
avoids.

**Extend `Operation` with an optional method instead of adding a type.**
Rejected. Every consumer of `Operation` — the planner, the checks, the oracle,
SARIF — would then need to handle a method-less case, and each one that forgot
would silently do something plausible. A separate type makes the distinction
unforgettable, which is the property worth paying a type for.

**Follow anchors to find more scripts.** Rejected; this is the spider. One page's
`<script src>` is not a frontier, and two pages is.

**Read `sitemap.xml`.** Rejected. It is a list of pages to crawl, its contents
are site pages rather than API surface, and reading one is the first step of
being a crawler.

**Build a well-known path list from common admin and debug locations.** Rejected:
that is directory brute forcing. The list admits a path only when a published
standard says the document *enumerates other paths* — which is why it has five
entries and not five hundred.

## Consequences

- An undocumented route the application publishes about itself is now counted
  and named, rather than absent.
- The untested count rises, sometimes sharply. That is the correct direction: the
  work was always not done, and now it is visible.
- Discovery finds some undocumented surface, never all of it, and no report
  offers a completeness figure — there is no denominator, and inventing one would
  be the false-assurance failure this project exists to prevent, committed about
  our own coverage.
- Path-only candidates will include some strings that are not routes. Noise is
  accepted over invention: a wrong candidate costs one line in the ledger, where
  a wrong method would cost a finding.
