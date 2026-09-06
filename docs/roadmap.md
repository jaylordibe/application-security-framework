# Roadmap

This is the dependency-ordered plan. It is written so that a reader can tell what is
built, what is next, and what is explicitly refused — and so that "we shipped a
foundation" cannot be mistaken for "we shipped a security product".

Ordering principle: **each milestone must make an existing honest limitation
disappear.** A milestone that adds surface without removing a limitation is deferred.

---

## Done — M0: Foundation

Delivered in this repository, with tests.

Research and justification; threat model; architecture and fifteen ADRs; the domain model;
scope enforcement; the HTTP client; capture-time redaction; OpenAPI ingestion with oracle
grading; outcome classification; one check with a verification ladder; the coverage
ledger; JSON and SARIF reporting; the run store; the offline evaluation harness; CI.

**What it proves:** that the contracts hold end-to-end, and that a run can account for
every operation it did not test.
**What it does not prove:** anything about detection quality beyond one weakness class.

---

## Done — M1: Identities and an authenticated control request

**Removed the limitation:** no finding could reach `confirmed`, because there was no
authenticated baseline to compare an anonymous response against.

| Task | Acceptance criteria | Delivered |
|---|---|---|
| Identity model and credential loading | Credentials come from environment variables or a secrets file, never from `appsec.yaml` in plaintext. Registered with the redactor before first use. | ✅ `internal/identity`. An identity holds a *reference*; the configuration schema has no field that accepts a value, and the absence is asserted by test. Both `env` and `file` sources. |
| Bearer and API-key providers | A configured identity can issue an authenticated request; failure to authenticate is `blocked{authentication_failed}`, never a silent anonymous run. | ✅ Bearer and header API-key. Header names are validated as RFC 9110 field names and framing headers are refused. Query-string API keys deferred deliberately (ADR-0012, T-16). |
| Authenticated control request in the check | A finding reaches `confirmed` only when the anonymous and authenticated responses are materially equivalent; otherwise it stays `suspected` and says why. | ✅ Material equivalence is a conjunction of outcome, status, content type, JSON document shape and cache state ([ADR-0012](adr/0012-authenticated-control-and-material-equivalence.md)). |
| Identity liveness canary | A known-authenticated operation is probed periodically. On credential expiry, every result since the last good canary is invalidated and marked blocked — otherwise a token expiring mid-run produces a sweep of false "denied" results that reads as a clean report. | ✅ with two deliberate refinements, below. |

**Two refinements to the canary criterion, stated because they differ from what was
written above.**

*Probing is event-driven, not periodic.* The canary runs at the start of a run, at the end,
and whenever an authenticated request returns something consistent with an invalid
credential. A timer probes when nothing has happened and stays silent when everything has;
probing at the moment a credential first looks wrong finds the expiry with the smallest
uncertainty window, which is exactly the interval that must then be distrusted. Nothing is
lost, because a control request that *succeeds* is itself direct evidence the credential was
live at that moment — the only case needing detection is a control that fails, and that is
precisely the trigger.

*Invalidation targets results that used the identity, not every result.* A row whose check
never issued a control request does not depend on the credential, so withdrawing it would
overstate the damage. Rows that did use a control inside `(lastGood, firstBad]` become
`blocked{authentication_failed}`, and any finding they corroborated drops to `suspected` —
but the finding is **kept**, because the anonymous observation behind it never involved the
credential and deleting it would let an expired token hide a real bypass.

**Security considerations:** credentials never enter a report, a log line or the run
directory — asserted end-to-end against a target that reflects the credential in a header,
a body and a `Location`, by searching every byte of the run directory. Redirects are never
followed, so a credential cannot be replayed off-origin. Authenticated traffic uses the same
scope-enforced client as anonymous traffic. See threat model T-16.
**Non-goals delivered as non-goals:** OAuth2 flows, OIDC, browser login, cookie-session
establishment, refresh rotation, custom multi-step authentication.

---

## Done — M2: Two identities and one owned resource: BOLA

**Removed the limitation:** the largest class of real API findings was invisible.

| Task | Acceptance criteria | Delivered |
|---|---|---|
| Resource fixtures | Resources are declared in configuration or created through the application's own API. A missing fixture is `blocked{missing_resource}`, never a pass. | ⚠️ **Partial.** Configured fixtures are implemented, validated and framework-neutral (`internal/resource`). A missing or unreachable fixture blocks. **API-created fixtures are deferred** — see below. |
| Owner-side control request | A cross-owner probe is only meaningful if the owner can fetch the resource. Owner `200` + other `404` is a **proven** denial; owner `404` means the fixture is wrong, which is blocked, not clean. | ✅ with a correction to the criterion, below. |
| Cross-owner read check | Paired fixtures: a repository with an ownership predicate and one without. | ✅ Paired vulnerable/secure applications differing only in whether the read is scoped by caller, plus 403, application-error-code, shared-resource and four misleading-200 variants. |
| Mutation verification | A write is confirmed only by re-fetching as the owner and diffing. A `200` never confirms a mutation. | ✅ Read-write-read as the owner, field-level attribution, best-effort verified restoration. Cross-owner `DELETE` is deliberately out of scope ([ADR-0013](adr/0013-cross-owner-verification-semantics.md)). |
| Path-parameter filling | Operations currently blocked as `missing_resource` become testable. | ✅ Both for cross-owner work and for the M1 declared-auth check, which previously reported every parameterised operation as untestable. |

### The owner-control criterion was not sufficient, and has been corrected

The criterion above said owner `200` + other `404` is a **proven** denial. It is
not, on its own. Three things produce that pair with no access control involved:
the non-owner's credential is dead and returns 404 to everything; the resource
stopped existing between the two requests; or the URL addresses nothing at all.

So a denial is recorded as verified only when the owner control succeeded, **both**
identities are live under M1's rules, and an **owner re-check after the probe**
shows the resource is still there. The re-check is not defensive padding: removing
it makes a fixture that disappears mid-test report as a verified denial, and the
test asserting that is in the suite. Full reasoning in
[ADR-0013](adr/0013-cross-owner-verification-semantics.md).

Two further corrections in the same record: a read is confirmed only when the
non-owner's response can be tied to *that resource* and not merely to a document
of the same shape, and ownership expectation is declared per fixture rather than
assumed, so a deliberately shared record is never reported.

### API-created fixtures are deferred, and M2 is partial because of it

The criterion allows resources to be "created through the application's own API".
That is not implemented, and the milestone is marked partial rather than complete
because of it.

Creating a resource needs a configured creation operation, a request body, an
extraction rule for the identifier the response returns, ordering guarantees
against the checks that consume it, and a lifecycle that deletes it afterwards or
explains why it could not. That is setup orchestration — the "environment
provisioning" listed under **Later** — and building a narrow version of it inside
M2 would produce exactly the premature architecture this project's ADRs exist to
prevent.

What this costs: an operator must know one resource identifier belonging to one
identity. On both reference applications that means logging in and reading one
list endpoint; the procedure is written down in
[docs/evaluation/cross-owner-integration.md](evaluation/cross-owner-integration.md). What it buys: no half-built provisioning layer to unpick when
environment provisioning is designed properly.

**Non-goals held:** no tenancy, no workflow state, no privilege escalation, no
permission or role matrices, no framework adapters.

---

## Done (partial) — M3: Framework adapters

**Removes the limitation:** the oracle depended entirely on a specification, and
a specification that marks everything protected — or nothing — carries no
information.

| Task | Acceptance criteria | Delivered |
|---|---|---|
| Adapter JSON contract + schema | Versioned, documented, and validated before it can influence a plan. | ✅ `appsec.adapter/v1alpha1`, `schemas/appsec.adapter.schema.json`, [an author guide](adapters/contract.md), and a conformance suite whose every case states why acceptance would be unsafe. |
| Golden conformance suite | An adapter author can validate against fixtures without reading the Go core. | ✅ `internal/adapter/validate_test.go`, plus a schema/parser agreement test so the two cannot drift. |
| Laravel adapter | Reads routes, middleware, gates and policies via `artisan`. | ⚠️ **Static tier only.** Routes and middleware groups are read from source; gates are detected as controls in controller actions. `artisan` is **not** used — see below. |
| NestJS adapter | Reads the permission catalog and guard metadata via a TypeScript probe. | ⚠️ **Static tier only.** Controllers, the global guard, `@Public()` and authorization decorators are read from source. No module is imported — see below. |
| Provenance merging | Adapter-derived expectations are `inferred` until corroborated at runtime; conflicts with the specification are reported, not silently resolved. | ✅ Agreement corroborates, disagreement withdraws the expectation from **both** sources and is reported. No extraction method reaches `observed` or `verified`. |

### The execution strategy in the criteria is unsafe as written, and was changed

The Laravel and NestJS criteria above name `artisan` and a TypeScript probe.
Implementing M3 established what those actually do, and neither can be the
default:

- `artisan` requires `vendor/autoload.php` and boots every service provider
  (`laravel-api/artisan:9-13`). A fresh clone has no `vendor/`, and
  `composer install` runs `@php artisan package:discover` from its
  `post-autoload-dump` hook — so installing dependencies is itself booting the
  application.
- `nestjs-api/src/main.ts` calls `startTelemetry()` at **import time**, patching
  `http`, `pg` and `ioredis`. Importing a module to read its metadata opens that
  machinery. A fresh clone has no `node_modules` either.

So framework-native introspection is arbitrary code execution against a
repository nobody vouched for, preceded by dependency installation that is more
of the same. It is now gated behind an explicit `adapters.trust:
execute-target-code`, and **M3 ships the static tier only**. Full reasoning in
[ADR-0014](adr/0014-adapter-contract-and-extraction-trust.md), which refines
ADR-0002's tier ordering rather than replacing it.

### Why this milestone is partial

The trust gate for tier 1 is built and tested; no tier-1 adapter ships. Writing
one means either a PHP or Node program whose own dependencies this project's
Go-only CI cannot install, or shipping security-critical code that CI never
exercises. Untested code in that position is worse than absent code.

What this costs: facts that genuinely need the runtime are not available.
`laravel-api` builds its gate table in a provider loop over an enum, so its
permission catalog cannot be enumerated without executing it. What it buys: the
shipped adapters run against a fresh clone with no install step, execute
nothing, and are covered by deterministic CI.

**Verified against the real reference applications:** 80 facts from
`laravel-api`, 168 from `nestjs-api`, no dependencies and no code execution, and
one operation moved from `untested{no_oracle}` to an executed check that found a
real anonymous bypass. Details and limitations in
[docs/evaluation/adapters-on-reference-applications.md](evaluation/adapters-on-reference-applications.md).

**Security considerations:** adapters are opt-in per run, never auto-discovered
from a target repository, invoked with explicit argument vectors, given an
environment built from nothing, and their output is treated as hostile input.
See threat model T-18.

---

## Done (partial) — M4: External engines

**Removes the limitation:** whole weakness classes were listed in
`classesNotAssessed` with nothing able to address them, because this project
deliberately does not reinvent mature scanners.

| Task | Acceptance criteria | Delivered |
|---|---|---|
| Engine process supervision | Process groups so a killed engine does not orphan a JVM or a browser; `WaitDelay` so a hung child cannot block; both pipes drained concurrently; byte and time budgets; a minimal explicit environment so target credentials never leak into a third-party process. | ✅ One supervisor in `internal/proc`, shared with the M3 adapter boundary so there is a single implementation. Proven with a fake engine that hangs, forks a surviving grandchild, floods, and holds a pipe open. |
| Normalisation | Engine output enters as `observed`, never as `confirmed`. Source severity and confidence scales are preserved verbatim rather than converted. | ✅ `ToFinding` takes no state parameter; AppSec severity is `unassessed`, which has no rank and cannot satisfy a policy threshold. |
| Failure isolation | A crashed engine is a `blocked` row plus a recorded tool failure. It is never an absence of findings. | ✅ Missing, crashed, hung, flooding, malformed and profile-refused engines all produce a blocked row whose text says what was lost. A failed engine cannot remove a class from `classesNotAssessed`. |
| Nuclei hardening | `-disable-unsigned-templates`, never `-code`, pinned and checksummed templates, local network access restricted, Interactsh self-hosted or disabled. | ✅ with the flags verified against Nuclei v3.11.x rather than assumed, and with a corpus that would execute nothing refused before the process starts — see below. |

### The flags in the criteria were checked, not copied

`-disable-unsigned-templates` and `-code` exist as written. The rest needed
verifying against the current CLI, and the distinction that matters turned out
to be which unsafe behaviours are already off:

- **Off by default, so never passed:** `-code`, `-headless`,
  `-allow-local-file-access`, `-follow-redirects`, `-dashboard`,
  `-cloud-upload`, `-proxy`.
- **On by default, so disabled explicitly:** `-disable-unsigned-templates`
  (`-dut`), `-no-interactsh` (`-ni`), `-disable-update-check` (`-duc`).
- Structured output is `-jsonl`, not `-json`.

"Pinned and checksummed templates" became something achievable: Nuclei refuses to
run without an operator-supplied template directory, and the corpus is recorded —
by commit where it is a git checkout, and explicitly as *unpinned* where it is
not. AppSec Framework does not bundle, download or checksum somebody else's
template corpus.

`-disable-unsigned-templates` then turned out to need a second decision. Templates
an operator writes themselves are unsigned, so passing the flag unconditionally
meant Nuclei would exclude the entire corpus, exit successfully, and produce a
scan reporting no findings after executing no security logic — the milestone's own
forbidden outcome, caused by a hardening measure. The corpus is now inspected
before the process starts: an empty one, or one in which nothing is signed, is
refused with an explanation, and `engines.nuclei.allowUnsignedTemplates` is the
deliberate opt-in for an operator's own templates. A waived signature check is
recorded in the provenance of every observation and in the report's limitations,
so a control that was turned off is never described as one that held.

### Semgrep or opengrep: both, and why that was cheap

opengrep is a fork of Semgrep's open-source engine: both LGPL-2.1, same
`--config`, same `--json` document. Supporting the second cost a name in a list,
so the criterion's "Semgrep or opengrep" is answered with either. opengrep is
preferred when both are installed, on evidence: Semgrep's metrics default to
`AUTO`, which sends telemetry when rules come from its registry, and those
registry rules are licensed for internal use only — which is why this repository
already has a CI check forbidding references to them.

### Why this milestone is partial

**No engine was executed against a real binary.** None of Nuclei, ZAP or
Semgrep/opengrep is installed in the environment this was built in, and
installing one would have meant AppSec Framework's own development doing exactly
what §33 forbids the tool from doing.

What that means concretely:

- The boundary is proven, adversarially, against fake engines that hang, fork,
  flood, crash, lie about their version and emit malformed output. Those tests
  exercise the supervision, and supervision is what M4 is actually about.
- Each engine's argument vector and output normalisation are covered by unit
  tests against real output samples of the shape each tool emits.
- **Not demonstrated:** that a real `nuclei -jsonl` invocation produces exactly
  the fields normalised here, that `zap.sh -cmd -quickout` writes exactly this
  report shape, or that these flags are accepted by the installed versions.

Integration tests against the real binaries now exist and skip, by name, when one
is absent — `go test -v -run FindsAPlantedMarker ./internal/scanner/` says which.
In this environment all three skipped, and a skip is not a pass. CI installs no
engine and they skip there too; the manual `engine-integration` workflow installs
a pinned Nuclei and **fails if its test skips**, so the one thing a fake engine
cannot prove — that the shipped tool accepts this argument vector — has a way to
be proven that does not put a third-party download on every pull request.

The run itself is written up in
[docs/evaluation/engines-on-reference-applications.md](evaluation/engines-on-reference-applications.md),
including the two defects writing it exposed: the headline summary counted a
failed engine as `blocked: 0`, and an all-unsigned template corpus would have
produced a completed Nuclei scan that executed nothing.

**Non-goals held:** no engine is bundled, no Semgrep registry rules are shipped
or referenced, no rule or template corpus is written, and nothing is installed.

---

## Done — M5: Surface beyond the specification

**Removes the limitation:** undocumented routes were invisible, so the ledger measured
coverage of a surface handed to us by the thing being audited.

| Task | Acceptance criteria | Delivered |
|---|---|---|
| Link headers | Parse RFC 8288 conservatively; same-origin only; record provenance. | ✅ A real single-pass parser, not a comma split: the grammar allows commas and semicolons inside quoted parameter values, and splitting loses links. Costs no additional request — the header arrives on the root response. |
| robots.txt | Fetch from the target origin only; parse path directives; treat them as hints. | ✅ `Allow` and `Disallow` both yield paths; wildcards are truncated to their literal prefix; `Sitemap` is deliberately ignored, because following one is crawling. |
| JavaScript bundles | Extract route candidates without executing anything or analysing semantics. | ✅ A linear literal scanner with no regular expression. Only same-origin scripts the root document names — no dependency graph, no source maps, no script found inside a script. |
| Well-known probes | A deliberately small, documented list; target origin only. | ✅ Five paths, each admitted only because a published standard says the document *enumerates other paths*. Every rejection is written down too. |
| Ledger | Every path outside the specification becomes `untested (not in specification)`. | ✅ Dimension `path`, cause `not_in_specification`, counted in the headline untested figure. |

### What was refined before implementation

**`sitemap.xml` was considered and rejected.** It is the closest thing to a crawler input
in the candidate set: a list of pages to crawl, whose contents are site pages rather than
API surface. Reading one is the first step of being a spider, and the thesis says not to
build one.

**The well-known list is five paths, not a wordlist.** Each had to answer one question:
does a published standard say this document enumerates other paths? OIDC Discovery, RFC
8414, RFC 9728, Apple universal links and Android App Links all do. `/.well-known/security.txt`
names a contact rather than a path and was rejected; so was `/.well-known/change-password`;
so was every guess at `/admin`, `/debug` or `/backup.zip`, because probing a list of guesses
is directory brute forcing whatever it is called.

**The OpenAPI well-known paths are not re-probed.** The specification loader already probes
them when the operator permits it. Doing it again here would duplicate requests and, worse,
would mean discovery quietly assessing a second specification the operator never supplied.

**One redirect hop is taken deliberately.** The HTTP client still never follows a redirect.
But a great many applications answer `/` with a 302 to `/login`, and refusing to look would
mean reading no markup at all on a large class of real targets. The hop is re-checked
against the target's origin, counts against the request budget, and drops the query string
before re-requesting. An off-origin `Location` ends the walk.

**Adapter-reported routes absent from the specification are now assessed.** M3 recorded
them and said in as many words that testing them belonged to a later milestone with its own
safety questions. This is that milestone and the questions have answers: the method comes
from the application's routing table, the expectation from the same adapter, and scope is
unchanged. Nothing is invented, so this is the one narrow case where discovered surface is
testable — behind `discovery.surface.assessAdapterDiscovered`.

### The boundary this milestone was most likely to cross

Discovery is where this project would have become a crawler, and the check is mechanical
rather than rhetorical: there is exactly one function in the package that makes a request,
and it has four call sites — the root (plus at most one same-origin redirect hop),
`/robots.txt`, the same-origin scripts the root names, and five fixed well-known paths.
**Nothing discovered is ever fetched.** No anchors, no forms, no iframes, no sitemap, no
recursion, no queue, no depth parameter, and no wordlist. The configuration cannot express
crawling because there is nothing to configure.

That also makes server-side request forgery a non-question rather than a control to audit:
the set of URLs discovery will request is fixed before any target output is read.

### What it does not do

Discovery finds some undocumented surface, never all of it. There is no denominator for
"how much of the application was found", so no report offers one — inventing a completeness
percentage would be this project's own thesis failing about its own coverage. A discovered
path gets no HTTP method and no security expectation: `/admin` is a string, and
`Disallow: /admin` is a request to search engines.

See [docs/evaluation/discovery-on-reference-applications.md](evaluation/discovery-on-reference-applications.md),
where the honest result on both reference applications is that the four runtime sources
find nothing additional — one ships an empty `Disallow:`, neither serves same-origin
JavaScript, and neither could be started without installing dependencies.

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
