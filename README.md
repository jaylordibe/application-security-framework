# Application Security Framework

**Evidence-based application security assessment.**

AppSec Framework derives what an application *says* should be protected from the
application's own metadata, observes what it *actually* does, and reports the difference
— together with an explicit account of everything it could not test.

> **AppSec Framework does not prove that an application is secure.** A run with no
> findings means only that the checks it executed, against the operations it could see,
> produced none.
> Every report states what was not tested and why. That is the point of the tool.

**Status: early foundation (v0.x).** One check is implemented, now with an authenticated
control request behind it (M1). Schemas may change before 1.0. See
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

### Identities

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

- **No BOLA/IDOR, tenancy, or cross-identity testing.** The single largest class of real
  API findings. Next milestone; see [the roadmap](docs/roadmap.md).
- **No engine integrations.** ZAP, Nuclei, Semgrep and Hadrian are designed as optional
  subprocesses ([ADR-0005](docs/adr/0005-external-engines-are-subprocesses.md)) but none is
  implemented. `appsec doctor` reports what is on your PATH.
- **No framework adapters.** The NestJS and Laravel probes are designed
  ([ADR-0002](docs/adr/0002-out-of-process-adapters.md)), not built.
- **No undocumented-route discovery.** The attack surface comes from the specification, so
  routes absent from it are invisible — not merely untested. Every report says this.
- **Only bearer and header API-key authentication.** No OAuth2 flows, no OIDC, no browser
  login, no cookie-session establishment, no refresh rotation. Query-string API keys are
  refused deliberately: a credential in a URL reaches error text, reproduction strings and
  every intermediary's access log.
- **One identity at a time.** Multiple identities can be configured, but comparing one
  against another — BOLA, IDOR, cross-tenant reads — is the next milestone, not this
  one.
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
