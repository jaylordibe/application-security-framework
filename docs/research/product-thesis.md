# Product thesis: why AppSec Framework should exist

This document answers the eight questions the project was required to answer **before**
any code was written. It is deliberately blunt. If the answers had not held up, the
correct outcome was to report that and stop.

The honest summary: **the differentiator originally proposed for this project is already
shipped by someone else.** The project survives, but only after being repositioned onto
ground that is genuinely unoccupied.

> **Revalidated 2026-09-07, and repositioned a second time.**
>
> A [product validation gate](../evaluation/product-validation-gate.md) tested the answers
> below against two live reference applications, a real Nuclei binary and a refreshed
> ecosystem review. Two of them did not survive.
>
> **Q2's priority order was wrong.** Oracle derivation was ranked first; measured against a
> running application it changed the number of operations actually tested from 11 to 11,
> because the specification was already accurate. Honest coverage accounting was ranked
> second; it is the capability that held, and the only one no other open-source tool was
> found to implement.
>
> **Q1's "instead of Hadrian" argument is weaker than when written.** Hadrian now does BOLA
> *and* BFLA/roles, verifies mutations by observing state, and creates fixtures
> dynamically — two of which this project had deferred to future milestones.
>
> The priorities in Q2 have been reordered accordingly, and the reasoning is recorded in
> [ADR-0017](../adr/0017-reposition-to-coverage-and-verification.md). The text below is kept
> as written, because a thesis that quietly edits itself after contact with evidence is not
> a thesis.

---

## Q1. Why should this exist instead of just running ZAP + Nuclei + Semgrep + Hadrian?

It should **not** exist to re-run those tools. Orchestration alone is already owned by
DefectDojo, secureCodeBox and Faraday, and we refuse to compete there (Q3).

It exists because of a gap none of those tools fill, demonstrated on real code:

**Every one of those tools tells you what it found. None tells you what it did not
test, or why.**

That is not a reporting nicety. On both reference applications, the existing ZAP
configuration is *structurally incapable* of detecting an authorization break — it
authenticates as a single administrator holding `manage all`, and runs with `-I` so it
can never fail. The scan passes. The output implies safety. The truth is that the entire
record-level and tenant-scoped surface was never tested at all, and nothing in the report
says so.

Second, and specific to authorization: deciding whether a response is a vulnerability
requires knowing **what should have happened**. That expectation — the oracle — has to
come from somewhere. Today it is hand-written YAML (Hadrian), a body-length diff (Burp
extensions), or a status-code guess (RESTler). Meanwhile the application itself already
contains the answer: `nestjs-api` has a 41-permission × 9-role catalog in source;
`laravel-api` generates its gates from an enum.

**Accounting honestly for what was not tested is the product. Deriving the oracle from the
application's own metadata is how that account gets better where a specification is silent
or wrong** — a supporting capability, reordered after measurement (ADR-0017), not the
lead claim.

---

## Q2. What should this project uniquely own?

Four things. **The order below is the one established by measurement on 2026-09-07; the
original ordering, which put oracle derivation first, is recorded underneath.**

1. **Honest coverage accounting.** Route, operation, identity, resource and engine
   coverage, with every blocked and untested item itemised and attributed to a
   machine-readable cause. **Verified absent from every open-source tool examined**,
   Hadrian included, and re-verified in 2026: the idea is now widely argued as best
   practice and still appears unimplemented outside commercial platforms.
   *Measured:* 10 of 84 operations tested on `nestjs-api`, 11 of 38 on `laravel-api`,
   every gap named. A scanner reporting "0 findings" against either is true and
   misleading.
2. **Provenance and evidence semantics.** Every fact carries where it came from
   (`declared` / `inferred` / `observed` / `verified`). Severity and confidence are
   independent. Scanner output enters as an observation, never as a confirmed finding.
   *Measured:* real Nuclei rated an endpoint `medium`; whether it mattered depended on
   the application's environment, and recording it as `observed` / `unassessed` was the
   difference between a report and a fabricated finding.
3. **Oracle derivation.** Turn the application's own authorization metadata — via
   out-of-process, language-native adapters — into a normalized, machine-checkable
   expectation of who may do what to which resource. Nobody else does this, and it is
   retained for that reason. It is third rather than first because *measured against a
   real application it added nothing*: the specification was already accurate, so the
   adapter's 37 authentication facts were redundant and the operations tested went from
   11 to 11. Its value is real only where a specification is silent or wrong, and that
   case has not yet been demonstrated outside synthetic fixtures.
4. **Tenancy as a real dimension**, and **verification below the HTTP layer** where the
   evidence source is actually available and trustworthy. Both remain unbuilt, and both
   are now ground the competitor holds.

**As originally written (2026, pre-validation):** oracle derivation first, coverage
accounting second, provenance third, tenancy fourth. The reordering and its evidence are
in [ADR-0017](../adr/0017-reposition-to-coverage-and-verification.md).

---

## Q3. What should we explicitly refuse to rebuild?

- A general web vulnerability scanner. **ZAP owns runtime DAST.**
- A CVE / misconfiguration template matcher. **Nuclei owns it, MIT, ~0 integration cost.**
- A static analysis engine or rule corpus. **Semgrep/opengrep own it.**
- A findings-aggregation and triage platform. **DefectDojo and friends own it.**
- A crawler / API inventory product. **Vespasian, Akto and ZAP's spiders own it.**
- A dashboard-plus-database product. **That is Akto.**
- A fourth YAML attack-template DSL.
- **Any claim of novelty for multi-identity authorization testing.** Hadrian shipped it.

---

## Q4. Where are we at highest risk of reinventing existing tooling?

Ranked, with the mitigation actually adopted:

1. **The adversarial authorization engine.** Highest risk — this *is* Hadrian.
   *Mitigation:* Hadrian is an optional subprocess engine behind the same boundary as
   ZAP and Nuclei (ADR-0005). We contribute the oracle and the coverage ledger, not the
   permutation loop.
2. **Discovery and crawling.** *Mitigation:* consume specifications and adapter output;
   defer crawling; never build a spider.
3. **Reporting/triage.** *Mitigation:* emit SARIF and JSON and stop. Integrate, do not
   replace.
4. **Payload libraries.** *Mitigation:* explicit non-goal. We ship zero injection
   payloads.

---

## Q5. Is Go still the correct core language?

**Yes**, and it was re-examined explicitly rather than inherited from the brief.

- Distribution is the product's UX: one static, cross-compiled binary, no runtime. A
  developer security CLI that opens with "create a virtualenv" loses.
- The workload is concurrent HTTP plus subprocess supervision with timeouts,
  cancellation, bounded output and cleanup — `context` and goroutines fit it, and
  `go test -race` produces real evidence.
- Our own dependency surface is a security property. `govulncheck` does
  **reachability-based** analysis, telling us whether a CVE is actually callable.
- Ecosystem alignment: Nuclei, Trivy and Hadrian are Go; `gosec` is an importable
  Apache-2.0 library.

Python's genuine advantage — ML and program-analysis ecosystems — applies to work that is
explicitly optional, deferred, and forbidden from establishing findings on its own.

Crucially, **language choice does not determine adapter fidelity**. NestJS authorization
metadata lives in runtime decorators; Laravel's real route and gate tables come from
`artisan`. The best adapters must run inside the target's runtime whatever we write the
core in — so adapters are out-of-process probes emitting a JSON contract (ADR-0002), and
Python remains available exactly where it is the right tool.

See ADR-0001.

---

## Q6. Is the modular monolith appropriate?

**Yes.** A local-first CLI has no distributed-systems requirement to justify services.
One binary, internal packages with enforced boundaries, and a storage seam that can later
grow a server-backed implementation. Microservices are an explicit non-goal.

---

## Q7. Are there licensing problems with any planned integration?

One real constraint and several cleared:

| Component | Licence | Verdict |
|---|---|---|
| ZAP | Apache-2.0 | Clear. Subprocess. |
| Nuclei engine **and** templates | MIT | Clear, incl. commercial/SaaS. |
| Hadrian | Apache-2.0 | Clear. Subprocess only, by choice. |
| Semgrep **engine** | LGPL-2.1 | Clear **as a subprocess**. Never link. |
| **Semgrep rules** | Semgrep Rules License v1.0 | **Constraint.** Internal use only; distribution and service use forbidden. **Never ship, vendor or auto-fetch them.** |
| opengrep | LGPL-2.1 | Clear as a subprocess; rules repo archived/contested. |
| GitLab `sast-rules` | MIT | Clear, redistributable. |
| CodeQL | proprietary terms | **Excluded** — bars analysing non-open-source code without paid GHAS. |
| Burp `Autorize`, `Authz` | **no licence at all** | **Never vendor.** |
| Our own project | Apache-2.0 | Patent grant matters for security tooling. |

Because every engine is a **separate process**, no copyleft obligation propagates to our
Apache-2.0 code. That is a deliberate architectural consequence, not a coincidence — and
it is a second, independent reason to subprocess rather than link.

---

## Q8. What parts of the proposed architecture are premature?

Removed or deferred from the initial foundation, with reasons:

| Proposed | Verdict |
|---|---|
| SQLite persistence | **Deferred.** A run directory of JSON is inspectable, diffable, dependency-free and better for evaluation. Kept behind a store seam (ADR-0007). |
| Next.js dashboard | **Deferred.** Would make the repository look complete while proving nothing. |
| Playwright / browser engine | **Deferred.** ~650 MB + Node + root, narrow OS matrix. |
| ZAP / Nuclei / Semgrep integrations | **Deferred past Phase 1.** Prove the contracts first. |
| AI of any kind | **Excluded** from the foundation. Boundaries designed, nothing implemented. |
| Full finding lifecycle (6 states) | **Simplified.** `REMEDIATED`/`VERIFIED_FIXED` are properties of comparing two assessments, not states of a finding within one (ADR-0006). |
| Generic business-logic engine | **Deferred.** Boundary only. |
| Interfaces for every concept | **Rejected.** Concrete types until polymorphism is actually required. |

---

## The honest risk register

- **We are late.** Hadrian, StackHawk and Escape all shipped multi-identity
  authorization testing within roughly two quarters of each other. Our claim rests on
  oracle derivation and coverage, not on the attack technique.
- **Oracle derivation may prove brittle.** Framework metadata is not always faithful to
  runtime behaviour. Mitigation: every derived expectation carries provenance and is
  falsifiable; a wrong oracle must surface as a rejected hypothesis, not a finding.
- **Coverage is unglamorous.** It is the most defensible differentiator and the hardest
  to market.
- **Adapters are ongoing cost.** Each is a small project in another ecosystem, with its
  own upgrade treadmill.
- **We depend on tools we do not control.** Every engine is optional and swappable, and
  its absence is reported rather than hidden.
