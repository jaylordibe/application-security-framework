# Product Validation Gate

Does AppSec Framework materially improve real application-security assessment
enough to justify its complexity, compared with using mature tools directly?

**Conclusion: REPOSITION.**

There is real, demonstrated value here, and it is not the value the product
thesis claims. The differentiator that was supposed to carry the product —
application-specific authorization testing — is now covered *better* by an
Apache-2.0 competitor that appeared after this project started. The capability
that actually held up under measurement is the one that was framed as a
supporting detail: the coverage ledger, and the discipline that nothing may be
reported as clean unless it was actually tested.

---

## 1. What was evaluated

| | |
|---|---|
| AppSec Framework | `1c2d361b2478f0a628e88038a4d332874fd8be70` (before validation changes) |
| `jaylordibe/laravel-api` | `8302196839a50210693666797ff9433c219a02ee` (2026-09-01), unmodified, **run live** |
| `jaylordibe/nestjs-api` | `84e19a2e309827a1d8047cb287431aff405bdd33` (2026-08-27), unmodified, **run live** |
| Nuclei | **v3.11.1**, real binary, pinned, installed via the repository's own `engine-integration` CI command |
| nuclei-templates | commit `59ef5a2`, 13,686 templates, 13,479 signed |
| ZAP | **not run** — see limitations |
| Semgrep / opengrep | **not run** — see limitations |

Criteria were written before any measurement (`scratchpad/pvg/criteria.md`,
fixed 2026-09-06T23:52Z) specifically so that thresholds could not be chosen to
fit results.

The Laravel reference application was brought up for real (`./start.sh fresh` —
one command) with PostgreSQL, Redis, Passport OAuth2, migrations and seeds, and
every runtime measurement below is against that live instance.

---

## 2. Hypothesis verdicts

| | Hypothesis | Verdict |
|---|---|---|
| H1 | Detects application-specific authorization failures generic scanners miss | **PARTIALLY SUPPORTED** — mechanism verified on a real boundary; no true positive available |
| H2 | Verification quality — observations vs verified findings | **SUPPORTED** |
| H3 | Coverage honesty — exposes blocked/untested work | **SUPPORTED** |
| H4 | Orchestration value beyond concatenating scanners | **PARTIALLY SUPPORTED** |
| H5 | Setup burden proportionate to value | **PARTIALLY SUPPORTED** |
| H6 | Safety of orchestration | **SUPPORTED**, after two defects found and fixed here |
| H7 | Reproducibility | **SUPPORTED** |

### H1 — NOT YET PROVEN, and this is the central result

The single most important finding of this gate is negative, and it is about the
reference applications rather than about AppSec.

**`laravel-api` has no ownership boundary at all.** Established from source and
confirmed against the running instance:

- No `app/Policies` directory, no `Gate::define` for any resource, no controller
  or service that scopes a query by the authenticated user. `BaseModel` records
  `created_by` and never filters on it.
- Exactly **two roles**, `system_admin` and `app_admin`, and **both hold all four
  permissions** (`create_user`, `read_user`, `update_user`, `delete_user`).
- `POST /api/users` **requires** a `role` field, and the only accepted values are
  those two. The application has no concept of a non-admin principal.

So the cross-owner test AppSec exists to perform has nothing to test here. I did
confirm empirically that `appad` (user 2) reads `GET /api/device-tokens/1`, owned
by `sysad` (user 1), receiving the full record — but with both principals being
admins and no ownership model in the code, that is **not** demonstrably a
vulnerability, and this document does not claim it is.

**`nestjs-api` does have the boundaries**, and they are richer than AppSec can
express (source: `src/common/authorization/subject-key.ts`):

- Ownership on 3 subjects: `User`(id), `DeviceToken`(userId), `BusinessMembership`(userId)
- **Tenancy** on 3 subjects: `Business`(id), `BusinessMembership`(businessId), `BusinessInvitation`(businessId)
- 70 `@RequirePermission(...)` decorators, CASL-based; 41 `@Public()`

`BusinessMembership` is *both* ownable and tenant-scoped. AppSec's M2 model has
only ownership, so expressing this would mean using ownership to simulate
tenancy — which §20 of the gate brief explicitly warns against, and which would
be semantically wrong.

**`nestjs-api` was subsequently stood up and tested live**, which changed this
result. Two identities were registered (`alice`, `bob`), alice created a device
token, and the application enforced ownership correctly: owner `200`, non-owner
`404` (anti-enumeration). AppSec reached the correct verdict —

> `GET /api/device-tokens/{id}` **executed**: "the cross-owner boundary held:
> alice owns fixture `alice-device-token` and could read it both before and
> after, and bob was refused"

— with the owner-reachability and liveness controls that distinguish a real
denial from a dead credential or a vanished resource. That is a **verified true
negative on a real ownership boundary**, which is the mechanism H1 depends on.

It stops short of SUPPORTED because a true negative is not a detection. Neither
reference application contains a real BOLA, so AppSec's ability to *find* one
still rests on synthetic fixtures.

Getting there also exposed the worst defect in this gate (§3, defect 6): on the
first live cross-owner run AppSec produced **fourteen CONFIRMED HIGH false
positives** and failed the build.

The synthetic corpus does support the claim: 30 M2 scenarios pass, including
misleading-200, dead-attacker-credential, resource-disappears-mid-test, shared
resource, and mutation-confirmed-only-by-owner-side-observation. That is genuine
engineering quality. It is not the same as evidence from a real application.

### H2 — SUPPORTED

The clearest single piece of evidence came from the live run. Nuclei reported
`laravel-horizon-unauth` at `/horizon/api/stats` as **medium**, and the endpoint
does return 200 unauthenticated. Whether that is a vulnerability depends on
something no scanner knows: `Horizon::check()` returns
`app()->environment('local')` when no `authUsing` callback is registered, and
this instance runs `APP_ENV=local`. The application's own `viewHorizon` gate is
written correctly and denies by default.

AppSec recorded it as `state: observed`, `severity: unassessed`, with Nuclei's
`medium` preserved verbatim in `externalSource.sourceSeverity` and an explicit
note that AppSec has not translated it. It cannot fail a policy threshold,
because `unassessed` has no rank.

That is the thesis working: a scanner alert is a claim, and promoting it would
have manufactured a medium-severity finding out of a local development setting.

### H3 — SUPPORTED, and this is the strongest result

Baseline run against the live application, zero configuration:

```
surface:  38 operations from openapi-url
oracle:   usable (declared)     33 protected, 5 public, 0 unstated
executed: 11
blocked:  10
untested: 17
findings: 0 confirmed, 0 suspected
```

**Only 11 of 38 operations were actually tested, and the report says so with a
machine-readable reason for every one of the other 27:**

| Rows | Disposition | Cause |
|---|---|---|
| 11 | executed | — |
| 10 | untested | `missing_resource` — needs a fixture to supply `{appVersionId}` etc. |
| 10 | blocked | `safety_policy` — DELETE/PUT/POST need the intrusive profile |
| 5 | untested | `safety_policy` — looks like an auth route, excluded to avoid lockout |
| 2 | untested | `no_oracle` — declared public |

A scanner reporting "0 findings" against this application would be technically
true and materially misleading. AppSec reports 0 findings *and* that it examined
under a third of the surface. That difference is the product.

The same measurement on `nestjs-api`, a larger and more carefully built
application, is starker still: **84 operations, 10 executed** — 12% — with 35
untested for `missing_resource`, 15 blocked by safety policy, 13 with no oracle
(the specification leaves 17 operations unstated), 9 auth-route skips and 2
indeterminate.

Dead-credential scenario, live: with an expired token AppSec reported
`liveness: bad`, the canary's exact failing status, and "results that depended on
it are withdrawn and marked blocked". Raw scanner output in the same situation is
a clean scan.

### H4 — PARTIALLY SUPPORTED

Real Nuclei v3.11.1, 981 signed misconfiguration templates, against the live app:

| | Standalone Nuclei | Through AppSec |
|---|---|---|
| Alerts / observations | 4 | 4 — identical set |
| `laravel-horizon-unauth` | medium | `observed` / `unassessed`, engine severity preserved |
| Live `api_session` cookie in output | **yes** (`extracted-results`) | **no** |
| Untested surface accounted for | no | yes, 27 rows |

AppSec neither lost nor invented detections — important, because the risk was
that orchestration degrades the underlying tool. What it added over
`cat nuclei.jsonl` is: engine failures in the same ledger as native results, no
promotion of engine confidence, and secret suppression.

It is *partial* because with one engine actually exercised, "coordinating
complementary engines" is a claim about a configuration nobody has run here.

### H5 — PARTIALLY SUPPORTED

Baseline is genuinely excellent. Deep authorization is not.

| Path | Commands | Config lines | Human-supplied facts | Time |
|---|---|---|---|---|
| Baseline assessment | 1 | **0** | 0 | ~5 s |
| + framework adapter | 1 | 12 | 2 (adapter path, source root) | ~5 s |
| + one identity | 1 | 16 | 4 (id, scheme, env var, canary) | ~5 s |
| + cross-owner testing (laravel) | — | — | **blocked**: application has no non-admin principal | — |
| + cross-owner testing (nestjs) | 6 | **33** | 2 identities, 2 credentials, 1 fixture id, 1 parameter value | ~15 min |

Nothing duplicates OpenAPI: routes, methods and auth metadata are never restated
by hand. That is the design working.

Cross-owner setup on `nestjs-api` cost 33 configuration lines and six manual
steps that AppSec cannot perform: register two users, mark both email-verified
**directly in the database** (registration requires verification), log in twice,
create a resource as one of them, and copy its UUID into `resources[].values`.
Nothing keeps that UUID valid: it is a hand-copied identifier that goes stale the
next time the database is reset. This is the deferred M2 fixture gap, measured —
and it is the thing Hadrian creates dynamically.

Against it: reaching a working identity took **two failed configuration
attempts**, both needing the JSON schema to resolve — `control:` is spelled
`liveness:`, and `expectStatus:` (singular) takes a list. Neither is guessable
from the example config.

### H6 — SUPPORTED, after two defects found here

Both were found by running real tools against a real application, not by review.

**Defect 1 — latent secret sink (fixed).** AppSec imported Nuclei's
`extracted-results` as evidence, on the recorded belief that "it is sanitized and
redacted by the caller". Against the live app, the stock
`missing-cookie-samesite-strict` template extracted the entire `Set-Cookie`
header — including a live `api_session` value. The redactor cannot remove it: it
only knows credentials *this assessment* registered, never a secret belonging to
the target. Nothing leaked, because `ToFinding` happened to discard the field
before persistence — a fragile accident, one well-meaning change away from a leak.
`extracted-results` is now refused like `request`, `response` and `curl-command`;
the matcher name is imported instead.

**Defect 2 — false assurance in AppSec's own terminal (fixed).** With a dead
credential the JSON report was entirely correct and the terminal printed the same
counts as a healthy run and exited zero. An operator reading their console saw a
clean assessment of an application that had refused every credential.

Everything else held: zero unauthorized requests across every run, no shell
invocation, engine environment built from nothing, cloud metadata unreachable.

### H7 — SUPPORTED

Three consecutive runs against the live application: identical coverage-row
hash (`717b1b8f…`), identical dispositions, identical (empty) finding set,
4.26–4.35 s. Only run IDs and timestamps differ.

---

## 3. Defects found and fixed during this gate

| # | Defect | Severity | Status |
|---|---|---|---|
| 1 | **Adapter facts never matched a real specification.** OpenAPI paths are relative to `servers[].url`; Scramble emits `servers: [{url: ".../api"}]` and spells a route `/activity-logs`, while the adapter reads the routing table and spells it `/api/activity-logs`. `Operation.ID` is built from the relative path, so **all 40** adapter facts missed. M5 then re-added all 40 as "adapter-discovered", inflating the surface from 38 to 78 with duplicates of routes already in it. | **High** — the adapter was worse than useless on the real app | Fixed: `Operation.AbsolutePath()`, matched in both the adapter and discovery merges. 40 bogus "undocumented" routes → **3 genuine** ones. |
| 2 | Nuclei `extracted-results` imported; contained a live session cookie | High (latent) | Fixed, with a regression test built from the real observed record |
| 3 | Terminal silent about a rejected identity | High (false assurance) | Fixed |
| 4 | `TestDoctorReportsMissingEnginesWithoutFailing` depended on ambient `PATH` — passed only on machines *without* an engine, so the repo's own engine-integration job would have broken it | Low | Fixed: `PATH` emptied in the test |
| 6 | **The cross-owner check produced 14 confirmed high false positives on a real application.** An ownership fixture with no explicit operation allowlist applied to every operation it could "bind" — and an operation with *no* path parameters binds trivially. So a device-token fixture was applied to `GET /api/health/liveness`, `GET /api/enums`, `GET /api/roles`, `GET /api/permissions` and eleven others; two identities received identical bodies, as health and enumeration endpoints must; and each was reported as *"a resource is readable by an identity that does not own it"*, **confirmed, high**, exit code 1. Precision on that run: **0 of 14**. | **Critical** — the headline differentiator failing a build on false pretences | Fixed: `Fixture.Addresses()` requires the operation to actually name the object — at least one required path parameter, all supplied by the fixture. After: **0 findings, exit 0, one boundary checked** — the real one. |
| 5 | **An engine wrote into the operator's working directory.** The environment handed to an engine is built from nothing, so it has no `HOME`, and Nuclei responds by creating a `.nuclei-config` tree in its working directory. The scan is contained by its workspace; the version probe that runs first had no directory at all. Running the test suite with Nuclei present left that tree in two package directories of this repository. | Low | Fixed: `scanner.ProbeVersion` runs every probe in a scratch directory and removes it |

| 7 | **`appsec scan http://localhost:3000` aborted against a running target.** `localhost` resolves to `::1` and `127.0.0.1`; the NestJS app binds IPv4 only, as most Node development servers do. The dialer checked every resolved address against scope — correctly — and then dialled only the first, returning connection-refused for the whole assessment. `curl` reaches the same target because it falls back. | Medium — the most natural first command fails | Fixed: each already-authorized address is tried in turn, sequentially. A single denied address still refuses the request before any dial. |

Defects 6 and 1 are the most significant. Defect 1 means the M3 evaluation's adapter claims,
which were measured on synthetic fixtures whose specs had no `servers` entry,
did not hold on a real specification.

---

## 4. Adapter value, measured

Against `laravel-api`, **after** fixing defect 1:

| Metric | Value |
|---|---|
| Facts extracted | 80 |
| Authentication expectations corroborating the spec | 37 |
| Authorization facts added (OpenAPI cannot express) | 37 |
| Conflicts | **0** |
| Undetermined | 0 |
| Genuinely undocumented routes found | **3** (`GET /`, `GET /api/email/verify/{id}`, `GET /sample/pdf-export`) |
| Change in operations actually tested | **0** (11 → 11) |

The specification was already accurate — Scramble declared 33 protected
operations and the framework has exactly 33 `auth:api` routes. So the adapter's
authentication facts were **redundant on this application**, and the 37
authorization facts are consumed by no check today.

This is the honest answer to "150 facts extracted, do any improve the
assessment?": on this application, three extra routes and zero new testable
expectations.

---

## 5. Ecosystem reassessment

The roadmap contains a stop condition about differentiation. It has to be taken
seriously, because the landscape moved.

**[Hadrian](https://github.com/praetorian-inc/hadrian)** (Praetorian, Apache-2.0)
does the job AppSec's thesis reserved for itself, and does more of it:

| Capability | Hadrian | AppSec Framework |
|---|---|---|
| BOLA / object-level authorization | yes | yes (M2) |
| **BFLA / roles / function-level** | **yes** | **no** |
| Mutation verified by state observation | yes (3-phase) | yes (M2) |
| **Resource fixtures created dynamically** | **yes** | **no — deferred in M2, still manual** |
| REST / GraphQL / gRPC | all three | REST only |
| Expectations derived from framework source | no (operator writes `roles.yaml`) | yes (M3) |
| **Explicit tested / blocked / untested ledger** | not documented | **yes** |

Two of the three things AppSec deferred as "later milestones" — roles and
API-created fixtures — Hadrian already ships. It is young (75 stars, 157 commits)
and requires an operator-written roles file where AppSec derives expectations
from source, so AppSec is not strictly dominated. But on the specific job of
*application-specific authorization testing*, an open-source tool now does it
better, and continuing to build toward that job means competing from behind.

On coverage honesty the picture is the opposite. The idea is now widely argued as
best practice — "a clean report does not mean clean coverage, it means coverage
of what the scanner reached" — but the search found **no open-source tool that
implements a machine-readable per-endpoint tested/blocked/untested ledger with
causes.** The one platform claiming it ([Safeguard](https://safeguard.sh)) is
commercial, and the article arguing for it concedes the industry has not adopted
it.

**Jobs, not features:**

| Job | Who does it best |
|---|---|
| Known-vulnerability detection | Nuclei |
| Generic DAST | ZAP |
| SAST | Semgrep / opengrep |
| Application-specific authorization | **Hadrian** |
| Security-expectation derivation from source | **AppSec Framework** |
| Verification / refusing to promote alerts | AppSec Framework |
| **Coverage honesty** | **AppSec Framework** (uncontested in open source) |
| Operational burden | Nuclei (lowest) |

---

## 6. Decision: REPOSITION

Not CONTINUE, because the thesis as written is "a general application-security
assessment layer whose differentiator is application-specific authorization",
and the evidence does not support that:

- the authorization differentiator is now better served by Hadrian;
- it could not be demonstrated on either reference application;
- the adapter that was supposed to derive expectations added **zero** new testable
  expectations on the real app, because the specification was already accurate;
- two of the planned next milestones (roles, fixtures) are catching up to a
  competitor rather than extending a lead.

The live `nestjs-api` run sharpened this rather than softening it. AppSec did
reach the right answer on a real ownership boundary — but only after a fix, and
the run *before* that fix would have failed a build with fourteen confirmed
high-severity findings that were all wrong. Meanwhile the two boundaries that
application actually spends its complexity on — 9 roles with 41 scoped
permissions, and tenancy on three subjects — AppSec cannot express at all.

Not STOP, because something real was measured. On a live application AppSec
reported *11 of 38 operations tested, with a machine-readable reason for each of
the other 27*, refused to promote a medium-severity scanner alert that turned out
to be environment-conditional, and suppressed a session cookie that the
underlying scanner wrote to disk in clear text. No open-source tool found in this
review does that.

Not CONTINUE BUT SIMPLIFY, because the problem is not that the configuration is
too complex — baseline is one command and zero config, which is better than any
competitor. The problem is which capability is the product.

**The proposed reposition:** from *"an application-security assessment framework"*
to **"an assessment-coverage and verification layer"** — a tool whose job is to
run the engines you already trust, refuse to overstate what they found, and
produce a defensible account of what was and was not tested and why. Native
authorization checking stays as one contributor to that ledger, not as the
headline.

That is a narrower claim, and it is the one the evidence actually supports.

---

## 7. Recommended next milestone

Because the recommendation is REPOSITION, no new security dimension is proposed.
The smallest roadmap change that follows the evidence:

**M6 — Evaluation and evidence hardening.** Rationale: this gate found four
defects in a day of real-application use, one of them (defect 1) invalidating a
milestone's headline claim. Every one was invisible to a synthetic corpus. That
is a statement about the evaluation method, not about luck.

Concretely: real reference applications running in CI rather than read as source;
the specification-relative vs application-absolute path distinction covered
wherever operation identity is compared; ZAP and Semgrep integration proven
against real binaries as Nuclei now is.

Explicitly **not** M6: tenancy, roles, workflow, environment provisioning,
runtime adapters. Tenancy and roles are real boundaries in `nestjs-api` and are
worth building *if* the reposition is accepted and the ledger is the product —
but they are second, not first, and they are where Hadrian is strongest.

---

## 8. Path to 1.0

**Required before 1.0** — all evidence-derived:

1. The path-identity defect class closed wherever operation identity is compared.
2. ZAP and Semgrep/opengrep proven against real binaries (Nuclei now is).
3. At least one reference application with a real ownership boundary, running,
   with a demonstrated true positive and a demonstrated true negative.
4. Stable configuration and report contracts, with the two config-authoring traps
   found here (`liveness`, `expectStatus`) either renamed or documented in the
   example config.
5. No known false-clean path — two were found and fixed here; the class needs a
   systematic sweep.

**Not 1.0 blockers**, and no evidence was found for any of them: dashboard, AI,
HTML reporting.

---

## 9. Adversarial review of this evaluation

**Selection bias.** The corpus was inherited from M1–M5, so it was built by the
same process it now validates. Mitigation: the decisive evidence here is from a
live third-party application, and it is unfavourable.

**Competitor handicap.** Nuclei ran with the official signed corpus and its own
default flags, not a crippled subset. It found a real issue AppSec's native
checks did not and could not.

**AppSec advantage.** AppSec was given the OpenAPI document and framework source.
That is the product's intended input, not an unfair edge — but note that on this
application it converted to **zero** additional tested operations.

**Tiny corpus.** One live application, one engine, four real alerts. Everything
here is labelled evaluation-corpus results. No precision or recall figure is
offered for authorization detection, because the live corpus contains zero
confirmed authorization vulnerabilities — a rate over zero cases is not a rate.

**Metric gaming.** No blocked or untested row is counted as a detection anywhere
in this document. AppSec's detection count on the live application is **zero**,
and the only real issue found (`laravel-horizon-unauth`) is attributed to Nuclei.

**Confirmation bias.** The test: would the same evidence have produced CONTINUE
if reversed? If Hadrian did not exist, or if `laravel-api` had an ownership
boundary AppSec caught and scanners missed, H1 would be SUPPORTED and the answer
would be CONTINUE. It is not, so it is not.

---

## 10. Limitations of this validation

- **ZAP and Semgrep/opengrep were never run.** Docker image pulls failed in this
  environment (even a 3 MB image would not transfer, though the registry
  responded), so only Nuclei — installable through the repository's own Go-based
  CI command — could be exercised. H4 is partial for this reason.
- **No confirmed authorization vulnerability exists in either live application.**
  Both enforce the boundaries they define, so every live authorization result is
  a true negative. AppSec's ability to *detect* a real BOLA still rests entirely
  on synthetic fixtures.
- **Tenancy was never exercised.** `nestjs-api` scopes `Business`,
  `BusinessMembership` and `BusinessInvitation` by `businessId`, but no business
  was created during this gate, and AppSec has no tenancy dimension to express
  the boundary if one had been.
- **Roles and permissions were never exercised.** `nestjs-api` has 9 roles and 41
  scoped permissions; alice's `403` on `GET /api/users` is a real
  function-level boundary that AppSec observed only as an HTTP status, because it
  has no way to state "this identity should be refused this operation".
- **One application, one framework, one language.**
