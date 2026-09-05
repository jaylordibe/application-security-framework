# ADR-0003: The differentiator is oracle derivation and coverage accounting

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The project was originally scoped around **application-aware multi-identity adversarial
authorization testing** as its primary differentiator.

Research found that capability already shipped. `praetorian-inc/hadrian` (Go, Apache-2.0,
last push 2026-09-04, verified by direct clone) provides a declarative `roles.yaml`
authorization oracle with `action:object:scope` permissions, privilege levels and
per-endpoint `owner_field`; a permutation engine cross-testing every attacker/victim role
pair; and three-phase `Setup`/`Attack`/`Verify` mutation testing with
`VerifyFieldChanged`. Its README claims verbatim that it *"proves write/delete
vulnerabilities actually occurred — not just that a 200 OK was returned."*

Building that again would be the reinvention the project was explicitly told to avoid.

Verified gaps, however, are real and consistent across the entire landscape:

- **Coverage and blocked-test accounting is absent from every open-source tool
  examined.** In Hadrian, `blocked`/`Blocked` returns 0 hits across `pkg internal cmd`.
- **No tool derives the oracle from the application's own metadata.** Hadrian's
  `roles.yaml` is hand-written or LLM-guessed. Yet `nestjs-api` carries a
  41-permission × 9-role catalog in source and `laravel-api` generates its gates from an
  enum — the answer is already in the code.
- Tenancy is not modelled (`org` exists only in a scope-validation list).
- Verification is HTTP re-fetch only.

## Decision

Reposition. Assay's differentiators are, in priority order:

1. **Oracle derivation** — deriving machine-checkable authorization expectations from the
   application's own metadata, with provenance, instead of hand-written YAML.
2. **Honest coverage accounting** — every unit of intended work has a disposition, and
   blocked tests are itemised with causes.
3. **Provenance and evidence semantics** — severity and confidence independent; scanner
   output enters as observation, never as a confirmed finding.
4. **Tenancy as a real dimension** and **verification below HTTP** where a trustworthy
   evidence source exists.

We explicitly **do not** claim novelty for multi-identity authorization testing.

## Alternatives considered

**Build it as originally scoped.** Rejected: re-implements a permissively licensed Go
tool that is roughly two to three quarters ahead, and the README would have to claim
novelty the research does not support.

**Contribute the gaps upstream to Hadrian instead of building.** A legitimate outcome and
seriously considered. Rejected for this repository because the gaps are architectural —
provenance-carrying oracle derivation and a coverage ledger are not features that bolt
onto a permutation engine — but upstream contribution remains compatible with this
direction and is preferred over duplicating Hadrian's attack loop.

**Stop entirely.** The correct outcome had the gaps not been real. They are.

## Consequences

Easier: a defensible, honest product claim; a smaller surface, since we do not own the
attack loop.

Harder: coverage accounting is the least glamorous differentiator to market; oracle
derivation may prove brittle where framework metadata diverges from runtime behaviour.

Accepted: we are late to this space, and our claim rests entirely on the four items
above. Every derived expectation must be falsifiable, so a wrong oracle surfaces as a
rejected hypothesis rather than a false finding.
