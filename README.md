# Application Security Framework

**Evidence-based application security assessment.**

AppSec Framework derives what an application *says* should be protected from the
application's own metadata, observes what it *actually* does, and reports the difference
— together with an explicit account of everything it could not test.

> **AppSec Framework does not prove that an application is secure.** A run with no
> findings means only that the checks it executed, against the operations it could see,
> produced none.
> Every report states what was not tested and why. That is the point of the tool.

**Status: early foundation (v0.x).** Two checks are implemented: declared authentication
with an authenticated control behind it (M1), and cross-owner resource access (M2).
Framework adapters supply expectations the specification cannot express (M3, static tier),
and external engines can be orchestrated for classes AppSec Framework does not test itself
(M4). Schemas may change before 1.0. See
[What AppSec Framework does not do yet](#what-appsec-framework-does-not-do-yet) before
relying on it. It has not been evaluated for precision or recall against a corpus
of real applications, so no detection-quality claim is made.

---

## Naming

| | |
|---|---|
| Product name | Application Security Framework |
| Short name | AppSec Framework |
| Repository | `application-security-framework` |
| CLI executable | `appsec` |
| Configuration file | `appsec.yaml` |
| Runtime state directory | `.appsec/` |
| Machine-readable tool id | `application-security-framework` |

---

## Why this exists

Two real applications were studied while designing this project. Both run OWASP ZAP in
CI. Both scans pass. Both authenticate as a **single administrator** holding every
permission, and both run with `-I` so the job can never fail. One has a rules file that is
entirely comments.

Neither scan can detect a broken ownership or tenant boundary — not because ZAP is
deficient, but because a single-identity scan cannot express a cross-identity
expectation. **Nothing in either report says so.** The pipeline looks green.

AppSec Framework is built around the two things that make that possible:

1. **The oracle** — deciding whether a response is a vulnerability requires knowing what
   *should* have happened. AppSec Framework derives that expectation from the
   application's own artefacts, and grades how much the derivation can be trusted.
2. **The ledger** — every unit of intended work carries a disposition: executed, blocked
   with a machine-readable cause, or untested with a reason. Coverage accounting is
   [absent from every open-source tool we surveyed](docs/research/ecosystem.md).

What AppSec Framework deliberately does **not** claim: novelty for multi-identity
authorization testing. [`praetorian-inc/hadrian`](https://github.com/praetorian-inc/hadrian)
ships that, in Go, under Apache-2.0. Our reasoning is in
[ADR-0003](docs/adr/0003-differentiator-oracle-and-coverage.md).

---

## Install

```bash
go install github.com/jaylordibe/application-security-framework/cmd/appsec@latest
```

Or build from source:

```bash
git clone https://github.com/jaylordibe/application-security-framework
cd application-security-framework
make build      # produces ./dist/appsec
```

AppSec Framework is a single static binary. No runtime, no database, no account, no cloud
service.

---

## Use

```bash
appsec scan http://localhost:3000
```

The URL you pass **is the authorization you are granting**: AppSec Framework contacts that
origin and nothing else unless you widen the scope in `appsec.yaml`.

```bash
appsec init      # write a commented appsec.yaml
appsec doctor    # what is installed, and what each missing piece would unlock
appsec scan http://localhost:3000 --spec ./openapi.json
appsec scan https://staging.example.com --spec-url https://staging.example.com/openapi.json
```

### External engines

```yaml
engines:
  nuclei:
    enabled: true
    executable: /usr/local/bin/nuclei
    templates: ./nuclei-templates    # required; nothing is downloaded
```

AppSec Framework does not reimplement Nuclei's templates, ZAP's active scanner or
Semgrep's dataflow analysis. It supervises them: explicit argument vectors and never a
shell, an environment built from nothing so your bearer tokens cannot reach a third-party
process, process groups so a killed engine cannot leave a JVM or a browser running, and
budgets on time and output.

**An engine result is an observation, not a finding.** Nuclei saying `critical` is Nuclei's
opinion of its own template; it is not evidence that your application is exploitable. Every
imported result is `observed`, AppSec's own severity is `unassessed`, and nothing an engine
reports can fail your build on its own. Two engines agreeing is not verification either.

**A failed engine makes the report less confident, not quieter.** Missing, crashed, hung,
flooding or timed-out — each becomes a blocked ledger row saying which classes are
therefore still unassessed. An engine that did not complete assesses nothing, and a passive
ZAP scan does not claim the injection classes its active scanner would have tested.

`appsec doctor` reports which engines are installed, what each would unlock, and changes
nothing on your machine.

### Framework adapters

```yaml
adapters:
  sourceRoot: ../my-application
  use:
    - name: laravel
      path: ./dist/appsec-adapter-laravel
```

The shipped adapters read your source and **execute nothing** — no `artisan`, no module
imports, no `composer install`, no `npm install`, no project scripts. That matters more
than it sounds: `artisan` boots every service provider, importing a NestJS module runs it,
and installing dependencies runs their lifecycle hooks. Doing any of that against a
repository is a decision, so it sits behind `adapters.trust: execute-target-code` and no
adapter shipped here needs it.

Write your own in any language: [the contract](docs/adapters/contract.md) is JSON on
stdout with a JSON Schema and a conformance suite.

### Identities and owned resources

Give it a credential and it can compare what an anonymous caller received against what a
legitimate one receives. That comparison is the only way a finding reaches `confirmed`.

```yaml
identities:
  - id: admin
    label: Administrator
    authentication:
      type: bearer                      # or apiKey, with a header
      credential:
        env: APPSEC_ADMIN_TOKEN         # or: file: /run/secrets/admin-token
    liveness:                           # optional, strongly recommended
      method: GET
      path: /api/me
      expectStatus: [200]
```

```bash
APPSEC_ADMIN_TOKEN='...' appsec scan http://localhost:3000
```

**A credential is never written into `appsec.yaml`.** The file has no field that accepts
one — only a reference to an environment variable or a file — so it stays safe to commit
and safe to review. There is no `--token` flag either: process listings are readable by
other users and shell history outlives the run.

The `liveness` probe is an operation *you* nominate, because guessing `/me` or `/whoami`
would produce a 404 on most applications and a 404 is indistinguishable from an expired
credential. It is what lets a run notice that a token died halfway through instead of
reporting the resulting sweep of denials as a clean result.

With **two** identities and a resource you know one of them owns, it will test whether the
other can reach it — broken object-level authorization, the largest class of real API
findings:

```yaml
resources:
  - id: order-alice
    type: order
    owner: alice
    crossOwnerAccess: denied          # required; "allowed" for shared resources
    values:
      orderId: "abc123"               # fills GET /api/orders/{orderId}
```

A fixture also makes a parameterised operation testable at all. Without one,
`/api/orders/{orderId}` can only be probed by inventing an identifier, and the resulting
404 says nothing — so it is reported as untestable rather than clean.

`crossOwnerAccess` has no default on purpose. Assuming every owned resource is private
would report every deliberately shared record — a public profile, a team document — as a
broken access control.

### What a run looks like

```
AppSec Framework assessment 20260905T154341Z-7a55b019
  target:   http://127.0.0.1:8731
  profile:  verification
  surface:  6 operations from openapi-url
  oracle:   usable (declared)

  executed: 2
  blocked:  1
  untested: 3
  findings: 0 confirmed, 1 suspected
```

The ledger is the deliverable:

| disposition | operation | cause | why |
|---|---|---|---|
| executed | `GET /api/admin/users` | — | suspected finding raised |
| executed | `GET /api/profile` | — | refused anonymous access, as declared |
| untested | `GET /api/health` | `no_oracle` | declared public; success is expected |
| untested | `GET /api/orders/{id}` | `missing_resource` | requires a path parameter; probing with an invented id would test nothing |
| untested | `POST /api/auth/login` | `safety_policy` | authentication route; sweeping it can lock real accounts |
| blocked | `POST /api/orders` | `safety_policy` | `POST` needs the `intrusive` profile |

That fourth row is the one that matters. If `GET /api/orders/{id}` returns 404 because the
database is empty, the endpoint was **not** meaningfully security-tested — and most tools
would count it as covered.

---

## How it decides things

**Severity and confidence are independent.** Severity asks how bad it would be if real;
confidence asks how sure we are. `HIGH` severity with `LOW` confidence is valid and
expected. Confidence comes from evidence quality and verification state only — never from
how many tools agreed.

**A finding is `suspected` until verification succeeds.** A single unauthenticated `200`
is not proof, so the check runs a ladder of discriminators — catch-all fingerprinting,
content type, error envelopes carried in `2xx` bodies, cache-hit detection, repetition —
and records which ones passed. Without a configured identity there is no authenticated
control request, so nothing can reach `confirmed`, and the report *names that gap* rather
than rounding up.

**A finding is `confirmed` only by a live authenticated control that matches materially.**
Anonymous 200 plus authenticated 200 is not enough — that rule confirms every
single-page-app shell and every 200-carrying error envelope. Confirmation requires both
responses to classify as allowed, the same status, the same content type, the same JSON
document *shape* (key paths and value types, values ignored so a request id cannot break a
real match), and no cache hit on the control. Anything else stays `suspected` and names
the gap. See
[ADR-0012](docs/adr/0012-authenticated-control-and-material-equivalence.md).

**A broken credential can never produce a clean result.** Inference runs one way: a control
that succeeds and matches raises a finding; a control that is missing, rejected, expired or
different only ever leaves it suspected. A finding is raised by an anonymous success and
never by an authenticated failure, so forgetting to set an environment variable cannot turn
a vulnerable application green — it produces a blocked identity row and a named gap.

**An adapter fact is an expectation, never evidence.** Your framework knows things OpenAPI
cannot express — which routes are behind authentication middleware, which have an
authorization control. An adapter reads that and hands it to the oracle, which can make an
operation testable that had nothing to test it against. It does **not** establish that the
control works: that is what the requests are for. So an adapter-derived expectation
produces a *suspected* finding a human reads, never a confirmed one.

**Two sources that disagree are a finding about your application.** If OpenAPI says an
operation is public and the framework says it is protected, AppSec Framework does not pick
one. It withdraws the expectation from both and reports the disagreement — choosing a
winner with no evidence would be a guess, and which one won would depend on the order the
sources happened to be read in.

**An external scanner's confidence is not AppSec's.** ZAP emits four risks and five
confidences, Nuclei five severities and no confidence, Semgrep three levels. None of those
scales maps onto another, so none is converted: each engine's own values are preserved
verbatim beside AppSec's `unassessed`. See
[ADR-0015](docs/adr/0015-external-engine-boundary.md).

**A cross-owner result needs three requests, not two.** The owner reads the resource, the
non-owner probes it, and the owner reads it again. The re-check is not padding: without
it, a record deleted between the first two requests makes the non-owner's 404 look like an
enforced boundary, and the run would report an untested control as working. Both
identities must also be live, or a dead token returning 404 to everything would make any
application look secure.

**A cross-owner finding is confirmed only when the non-owner got *that* resource.** Two
orders have the same JSON shape, so an application that quietly returns the caller's own
record would match on shape alone. Confirmation additionally requires the fixture's own
identifying value at the same field in both responses, or two identical documents.

**A write is confirmed only by the owner's own view changing.** An HTTP 200 for a write
that was silently discarded is common — it is what a status-only check reports as an
unauthorized mutation, and it is wrong every time. See
[ADR-0013](docs/adr/0013-cross-owner-verification-semantics.md).

**`404` counts as a denial.** Returning not-found for a resource the caller may not see is
a legitimate anti-enumeration pattern; treating it as a distinct outcome would report good
security design as a bug.

**Status codes are not trusted alone.** One studied application returns `400` for
authentication failure, `400` for validation failure, `400` for a missing record, and `200`
for a record owned by a different user. If your application publishes a stable error code,
point `outcome.errorCodePointer` at it and AppSec Framework will use it in preference to
the status.

---

## Safety

Profiles are strictly ordered and never escalate implicitly:

| profile | permits |
|---|---|
| `discovery` | reconnaissance only |
| `verification` | real techniques, safe HTTP methods (**default**) |
| `intrusive` | may change or destroy data; requires `authorizeIntrusive: true` |

Impact is a property of the **operation**, not of the check: an unauthenticated `DELETE` is
gated even though the check that would send it is read-only in principle.

Scope is an **allowlist**, enforced both on the URL before any DNS is emitted and on every
resolved IP at dial time. Redirects are never followed automatically. Cloud metadata
addresses are denied even when private addressing is enabled. See
[ADR-0008](docs/adr/0008-scope-is-the-authorization-boundary.md).

Secrets are redacted **at capture time**, so they never reach disk. Run directories are
created `0700` with files `0600`. Redaction is a mitigation, not a guarantee — do not
commit `.appsec/`.

---

## What AppSec Framework does not do yet

Being specific about this is part of the product.

- **BOLA testing needs you to name the resource.** Fixtures are configured, not
  discovered: you must know one identifier belonging to one identity. Creating resources
  through the application's own API is deferred to environment provisioning, so M2 is
  marked partial in [the roadmap](docs/roadmap.md).
- **No tenancy, function-level authorization, or privilege escalation.** One owner, one
  non-owner, one resource is the whole primitive.
- **No cross-owner `DELETE`.** It destroys the fixture and proves nothing a `PATCH` does
  not.
- **External engines are orchestrated, not verified.** Nuclei, ZAP and Semgrep/opengrep can
  run behind one hardened boundary, but nothing they report is confirmed by AppSec
  Framework: an alert enters as `observed` with severity `unassessed` and stays there. No
  engine has yet been executed against a real installed binary in this repository's own
  testing, so the milestone is marked partial — see
  [the roadmap](docs/roadmap.md). Hadrian is not integrated.
- **You install and configure the engines.** AppSec Framework never downloads or installs
  one, ships no templates or rules, and will not let an engine fetch its own corpus: a
  corpus that changed overnight makes two runs incomparable.
- **Framework adapters read source; they do not ask the framework.** The Laravel and
  NestJS adapters never execute your application, which means they cannot resolve anything
  dynamic — a gate table built in a provider loop, a guard whose semantics they do not
  recognise. They say so, per fact and per run. Framework-native introspection is designed
  and gated but not shipped
  ([ADR-0014](docs/adr/0014-adapter-contract-and-extraction-trust.md)).
- **No undocumented-route discovery.** The attack surface comes from the specification, so
  routes absent from it are invisible — not merely untested. Every report says this.
- **Only bearer and header API-key authentication.** No OAuth2 flows, no OIDC, no browser
  login, no cookie-session establishment, no refresh rotation. Query-string API keys are
  refused deliberately: a credential in a URL reaches error text, reproduction strings and
  every intermediary's access log.
- **No AI**, no dashboard, no database, no crawler, no injection payloads.
- **No measured precision or recall.** The evaluation harness proves the check
  distinguishes paired vulnerable and secure fixtures; it does not establish a
  false-positive rate on real applications.
- **AppSec Framework is fingerprintable, so a hostile target can cloak.** Its user agent,
  cache buster and baseline paths are identifiable by design, because a scanner that
  disguises itself is harder to authorize and harder to stop. That is the right trade for
  assessing your own application, and a real limitation otherwise.

---

## Exit codes

A pipeline must be able to tell "ran cleanly" from "could not run".

| code | meaning |
|---|---|
| 0 | ran; no policy threshold exceeded |
| 1 | findings exceeded the configured policy |
| 2 | invalid command line or configuration; nothing ran |
| 3 | **executed no checks — establishes nothing** |
| 4 | could not complete |
| 5 | internal error |

The default policy fails the run on any confirmed finding, and on a **suspected** finding
of high severity or above:

```yaml
policy:
  failOnConfirmed: low
  failOnSuspected: high
```

Suspected findings count deliberately. AppSec Framework cannot reach `confirmed` without
configured credentials, so gating only on confirmed findings would exit `0` on a real
authentication bypass — a silent pass is the worst possible default for a security gate.

---

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | pipeline, packages, boundaries |
| [Product thesis](docs/research/product-thesis.md) | why this exists, and what it refuses to build |
| [Ecosystem research](docs/research/ecosystem.md) | ZAP, Nuclei, Semgrep, Playwright, Hadrian — licences and findings |
| [Reference applications](docs/research/reference-applications.md) | the evidence behind the design |
| [Threat model](docs/security/threat-model.md) | this framework's own attack surface |
| [Cross-owner integration](docs/evaluation/cross-owner-integration.md) | running M2 against the two reference APIs |
| [Writing an adapter](docs/adapters/contract.md) | the contract, in any language |
| [External engines](docs/engines/README.md) | installing, configuring and what each one covers |
| [Adapters on real applications](docs/evaluation/adapters-on-reference-applications.md) | what they extract, and what they cannot |
| [Engines on real applications](docs/evaluation/engines-on-reference-applications.md) | what M4 ran, what it could not, and why M4 is partial |
| [ADRs](docs/adr/) | consequential decisions and their alternatives |
| [Roadmap](docs/roadmap.md) | what is next, and what is explicitly out |

---

## Authorization

Assess only applications you own or are **explicitly authorized in writing** to test.
Running this against systems you do not control may be illegal. AppSec Framework is
deliberately identifiable in its `User-Agent`; do not remove that.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Application Security Framework is not affiliated with OWASP, Checkmarx, ProjectDiscovery,
Semgrep Inc. or Praetorian. Names are used only to identify those projects.
