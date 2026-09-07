# ADR-0017: Reposition — the ledger is the product, authorization is a contributor

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes the priority ordering in:** [product thesis Q2](../research/product-thesis.md)
- **Evidence:** [Product Validation Gate](../evaluation/product-validation-gate.md)

## Context

The product thesis named four things this project should uniquely own, in
priority order: (1) oracle derivation from the application's own metadata,
(2) honest coverage accounting, (3) provenance and evidence semantics,
(4) tenancy and sub-HTTP verification.

A validation gate tested that ordering against two live reference applications
and a real external engine, with success criteria fixed in advance. The ordering
did not survive.

**Oracle derivation — priority 1 — measured zero.** Against a running
`laravel-api`, the Laravel adapter contributed 37 corroborating authentication
facts, 37 authorization facts and 3 previously undocumented routes, and changed
the number of operations actually tested from **11 to 11**. The specification was
already accurate: Scramble declared 33 protected operations and the framework has
exactly 33 `auth:api` routes. The adapter's expectations were redundant because
the application already published them correctly.

Worse, until the gate they did not merge at all. OpenAPI paths are relative to
`servers[].url`; the adapter reads the routing table and speaks in
application-absolute paths. All 40 facts missed, and M5 then re-added them as
"discovered", inflating the surface from 38 operations to 78 duplicates.

**The authorization differentiator is now contested.**
[Hadrian](https://github.com/praetorian-inc/hadrian) (Praetorian, Apache-2.0)
does BOLA *and* BFLA/roles, verifies mutations by observing state, creates
resource fixtures **dynamically**, and covers REST, GraphQL and gRPC. Two of the
capabilities this project deferred to later milestones — roles, and API-created
fixtures — it already ships.

**And the machinery behind that claim failed on first real contact.** The first
live cross-owner run produced **fourteen confirmed, high-severity findings, all
false**, and exited non-zero. A device-token fixture had been applied to
`GET /api/health/liveness`, `GET /api/enums` and `GET /api/roles` — operations
that name no object — because a fixture applied wherever it could *bind*, and an
operation with no path parameters binds trivially. Eighty-two passing evaluation
scenarios did not catch it.

**Coverage accounting — priority 2 — was the thing that held.** On a live
`nestjs-api`: 84 operations, **10 executed**, with a machine-readable cause for
every one of the other 74. On `laravel-api`: 11 of 38. A scanner reporting "0
findings" against either is true and misleading, and no open-source tool found in
the ecosystem review implements a per-endpoint tested/blocked/untested ledger with
causes. The concept is widely argued as best practice and appears unimplemented.

Provenance semantics — priority 3 — held too, and demonstrably: real Nuclei
called `/horizon/api/stats` *medium*, the endpoint really is `200` unauthenticated,
and whether that matters depends on `Horizon::check()` returning
`environment('local')`. AppSec recorded it `observed` / `unassessed`, where it
cannot satisfy a policy threshold. Promoting it would have manufactured a
medium-severity finding out of a development setting.

## Decision

**The coverage ledger and the refusal to overstate are the product. Native
authorization checking is one contributor to that ledger, not the headline.**

Concretely:

1. **The lead claim changes** from "evidence-based application security
   assessment" to an assessment-coverage and verification layer: run the engines
   an operator already trusts, refuse to overstate what they found, and produce a
   defensible account of what was and was not tested, and why.
2. **The thesis priority order is inverted.** Honest coverage accounting is
   first. Provenance and evidence semantics second. Oracle derivation third —
   retained, because it is real and unoccupied, but demoted because its measured
   value on a real application was zero and it is worth what it adds to the
   ledger, not what it promises in isolation.
3. **No code is deleted.** M1 and M2 keep working and keep contributing. This is
   a change of claim and of build order, which is why it is cheap and reversible:
   if oracle derivation later demonstrates value on an application whose
   specification is *wrong*, the ordering can be restored having lost nothing.
4. **The next milestone is evaluation hardening, not a new security dimension.**
   Seven defects in two days of real-application use, none of them findable from
   the synthetic corpus, is a statement about the evaluation method.
5. **Tenancy and roles move down, not out.** Both are real boundaries in
   `nestjs-api` — 9 roles, 41 scoped permissions, tenancy on three subjects — and
   both are where the competitor is strongest. Building them on a corpus that
   just missed a fourteen-false-positive defect would produce more confident
   wrongness.

## Alternatives considered

**CONTINUE unchanged.** Rejected. It requires believing oracle derivation is the
differentiator, and the only measurement available says it added nothing to a
real assessment.

**STOP.** Genuinely considered, and rejected on evidence: the ledger works, is
uncontested, and prevented a real false-assurance outcome in the same runs that
exposed the false positives. Something worth having was measured working.

**CONTINUE BUT SIMPLIFY.** Rejected because complexity is not the problem.
Baseline assessment is one command, zero configuration and about five seconds,
which is better than the alternatives. The problem was never operability; it was
which capability is being sold.

**Reposition to "an authorization testing framework".** Rejected: that is the
one position now directly occupied by a tool doing more of it.

## Consequences

- The README, product thesis and roadmap lead with coverage and verification.
- Adapters are documented as improving the ledger where a specification is silent
  or wrong, and as adding nothing where it is already accurate — which is a
  narrower and true claim.
- The project competes with nothing on its lead capability, and stops competing
  from behind on its old one.
- The risk taken: if a future application shows adapters closing a large oracle
  gap, this ADR under-sold them. That is recoverable, and the opposite mistake —
  continuing to lead with a contested claim whose machinery had a critical defect
  — is not.
