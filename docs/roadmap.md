# Roadmap

This is the dependency-ordered plan. It is written so that a reader can tell what is
built, what is next, and what is explicitly refused — and so that "we shipped a
foundation" cannot be mistaken for "we shipped a security product".

Ordering principle: **each milestone must make an existing honest limitation
disappear.** A milestone that adds surface without removing a limitation is deferred.

---

## Done — M0: Foundation

Delivered in this repository, with tests.

Research and justification; threat model; architecture and eleven ADRs; the domain model;
scope enforcement; the HTTP client; capture-time redaction; OpenAPI ingestion with oracle
grading; outcome classification; one check with a verification ladder; the coverage
ledger; JSON and SARIF reporting; the run store; the offline evaluation harness; CI.

**What it proves:** that the contracts hold end-to-end, and that a run can account for
every operation it did not test.
**What it does not prove:** anything about detection quality beyond one weakness class.

---

## M1 — Identities and an authenticated control request

**Removes the limitation:** no finding can currently reach `confirmed`, because there is
no authenticated baseline to compare an anonymous response against.

| Task | Acceptance criteria |
|---|---|
| Identity model and credential loading | Credentials come from environment variables or a secrets file, never from `appsec.yaml` in plaintext. Registered with the redactor before first use. |
| Bearer and API-key providers | A configured identity can issue an authenticated request; failure to authenticate is `blocked{authentication_failed}`, never a silent anonymous run. |
| Authenticated control request in the check | A finding reaches `confirmed` only when the anonymous and authenticated responses are materially equivalent; otherwise it stays `suspected` and says why. |
| Identity liveness canary | A known-authenticated operation is probed periodically. On credential expiry, every result since the last good canary is invalidated and marked blocked — otherwise a token expiring mid-run produces a sweep of false "denied" results that reads as a clean report. |

**Security considerations:** credentials never enter a report, a log line or the run
directory; authentication endpoints stay excluded from anonymous sweeps.
**Non-goals:** OAuth2 flows, browser login, custom multi-step authentication.

---

## M2 — Two identities and one owned resource: BOLA

**Removes the limitation:** the largest class of real API findings is invisible today.

The evidence says this needs no tenancy graph and no permission catalog. It needs
`identityA`, `identityB`, and a resource owned by A. That primitive covers OWASP API1.

| Task | Acceptance criteria |
|---|---|
| Resource fixtures | Resources are declared in configuration or created through the application's own API. A missing fixture is `blocked{missing_resource}`, never a pass. |
| Owner-side control request | A cross-owner probe is only meaningful if the owner can fetch the resource. Owner `200` + other `404` is a **proven** denial; owner `404` means the fixture is wrong, which is blocked, not clean. |
| Cross-owner read check | Paired fixtures: a repository with an ownership predicate and one without. |
| Mutation verification | A write is confirmed only by re-fetching as the owner and diffing. A `200` never confirms a mutation. |
| Path-parameter filling | Operations currently blocked as `missing_resource` become testable. |

**Non-goals:** tenancy, workflow state, privilege escalation. Those follow only once this
primitive is proven on two dissimilar applications.

---

## M3 — Framework adapters

**Removes the limitation:** the oracle depends entirely on a specification, and a
specification that marks everything protected (or nothing) carries no information — which
AppSec Framework currently grades and reports, but cannot improve.

| Task | Acceptance criteria |
|---|---|
| Adapter JSON contract + schema | Versioned, documented, and validated before it can influence a plan. |
| Golden conformance suite | An adapter author can validate against fixtures without reading the Go core. |
| Laravel adapter | Reads routes, middleware, gates and policies via `artisan`. |
| NestJS adapter | Reads the permission catalog and guard metadata via a TypeScript probe. |
| Provenance merging | Adapter-derived expectations are `inferred` until corroborated at runtime; conflicts with the specification are reported, not silently resolved. |

**Security considerations:** adapters are opt-in per run, never auto-discovered from a
target repository, invoked with explicit argument vectors, and their output is treated as
hostile.

---

## M4 — External engines

**Removes the limitation:** whole weakness classes are listed in `classesNotAssessed` with
nothing able to address them.

Integrated in this order, each behind the same boundary: Nuclei (single static binary,
MIT, lowest integration cost), then ZAP, then Semgrep or opengrep.

| Task | Acceptance criteria |
|---|---|
| Engine process supervision | Process groups so a killed engine does not orphan a JVM or a browser; `WaitDelay` so a hung child cannot block; both pipes drained concurrently; byte and time budgets; a minimal explicit environment so target credentials never leak into a third-party process. |
| Normalisation | Engine output enters as `observed`, never as `confirmed`. Source severity and confidence scales are preserved verbatim rather than converted. |
| Failure isolation | A crashed engine is a `blocked` row plus a recorded tool failure. It is never an absence of findings. |
| Nuclei hardening | `-disable-unsigned-templates`, never `-code`, pinned and checksummed templates, local network access restricted, Interactsh self-hosted or disabled. |

**Non-goals:** bundling any engine; shipping Semgrep registry rules; writing templates.

---

## M5 — Surface beyond the specification

**Removes the limitation:** undocumented routes are invisible, so the ledger measures
coverage of a surface handed to us by the thing being audited.

Passive extraction from `Link` headers, `robots.txt` and JavaScript bundles; a
conservative well-known-path probe on the target origin only. Every path found outside the
specification becomes a ledger row: `untested (not in specification)`.

---

## Later

Tenancy and cross-scope isolation; workflow and state-transition testing; environment
provisioning; CI policy and suppressions with expiry; assessment comparison and regression
detection; HTML reporting; the dashboard; optional provider-neutral AI restricted to
proposing hypotheses that deterministic verification must then confirm or reject.

---

## Explicit non-goals

Not "later" — **not at all**, unless the reasoning in
[the product thesis](research/product-thesis.md) changes:

- A general web vulnerability scanner, an injection engine, or a payload library.
- A CVE or misconfiguration template matcher.
- A static analysis engine or rule corpus.
- A findings-aggregation and triage platform.
- A crawler or API inventory product.
- A fourth YAML attack-template DSL.
- Any claim of novelty for multi-identity authorization testing.
- Any requirement for AI, a cloud service, or an account.

---

## What would make this project not worth continuing

Stated in advance, so it is harder to rationalise away later:

- If M2 lands and the false-positive rate on real applications is high enough that
  developers disable it, the oracle approach has failed and should be reported as such.
- If Hadrian, Akto or ZAP ship provenance-carrying oracle derivation and coverage
  accounting, the differentiator is gone and contributing upstream becomes the better
  use of everyone's time.
