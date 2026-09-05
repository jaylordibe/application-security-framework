# Assay

**Evidence-based application security assessment.**

Assay derives what an application *says* should be protected from the application's
own metadata, observes what it *actually* does, and reports the difference — together
with an explicit account of everything it could not test.

> **Assay does not prove that an application is secure.** A run with no findings means
> only that the checks it executed, against the operations it could see, produced none.
> Every report states what was not tested and why. That is the point of the tool.

**Status: early foundation (v0.x).** One check is implemented. Schemas may change before
1.0. See [What Assay does not do yet](#what-assay-does-not-do-yet) before relying on it.
Assay has not been evaluated for precision or recall against a corpus of real
applications, so no detection-quality claim is made.

---

## Why this exists

Two real applications were studied while designing Assay. Both run OWASP ZAP in CI. Both
scans pass. Both authenticate as a **single administrator** holding every permission, and
both run with `-I` so the job can never fail. One has a rules file that is entirely
comments.

Neither scan can detect a broken ownership or tenant boundary — not because ZAP is
deficient, but because a single-identity scan cannot express a cross-identity
expectation. **Nothing in either report says so.** The pipeline looks green.

Assay is built around the two things that make that possible:

1. **The oracle** — deciding whether a response is a vulnerability requires knowing what
   *should* have happened. Assay derives that expectation from the application's own
   artefacts, and grades how much the derivation can be trusted.
2. **The ledger** — every unit of intended work carries a disposition: executed, blocked
   with a machine-readable cause, or untested with a reason. Coverage accounting is
   [absent from every open-source tool we surveyed](docs/research/ecosystem.md).

What Assay deliberately does **not** claim: novelty for multi-identity authorization
testing. [`praetorian-inc/hadrian`](https://github.com/praetorian-inc/hadrian) ships that,
in Go, under Apache-2.0. Our reasoning is in
[ADR-0003](docs/adr/0003-differentiator-oracle-and-coverage.md).

---

## Install

```bash
go install github.com/jaylordibe/application-security-framework/cmd/assay@latest
```

Or build from source:

```bash
git clone https://github.com/jaylordibe/application-security-framework
cd application-security-framework
make build      # produces ./dist/assay
```

Assay is a single static binary. No runtime, no database, no account, no cloud service.

---

## Use

```bash
assay scan http://localhost:3000
```

The URL you pass **is the authorization you are granting**: Assay contacts that origin and
nothing else unless you widen the scope in `assay.yaml`.

```bash
assay init      # write a commented assay.yaml
assay doctor    # what is installed, and what each missing piece would unlock
assay scan http://localhost:3000 --spec ./openapi.json
assay scan https://staging.example.com --spec-url https://staging.example.com/openapi.json
```

### What a run looks like

```
Assay assessment 20260905T154341Z-7a55b019
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

**A finding is `suspected` until verification succeeds.** A single unauthenticated `200` is
not proof, so the check runs a ladder of discriminators — catch-all fingerprinting, content
type, error envelopes carried in `2xx` bodies, cache-hit detection, repetition — and
records which ones passed. Without configured credentials there is no authenticated control
request, so nothing can reach `confirmed`, and the report *names that gap* rather than
rounding up.

**`404` counts as a denial.** Returning not-found for a resource the caller may not see is
a legitimate anti-enumeration pattern; treating it as a distinct outcome would report good
security design as a bug.

**Status codes are not trusted alone.** One studied application returns `400` for
authentication failure, `400` for validation failure, `400` for a missing record, and `200`
for a record owned by a different user. If your application publishes a stable error code,
point `outcome.errorCodePointer` at it and Assay will use it in preference to the status.

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
commit `.assay/`.

---

## What Assay does not do yet

Being specific about this is part of the product.

- **No BOLA/IDOR, tenancy, or multi-identity testing.** The single largest class of real
  API findings. Next milestone; see [the roadmap](docs/roadmap.md).
- **No engine integrations.** ZAP, Nuclei, Semgrep and Hadrian are designed as optional
  subprocesses ([ADR-0005](docs/adr/0005-external-engines-are-subprocesses.md)) but none is
  implemented. `assay doctor` reports what is on your PATH.
- **No framework adapters.** The NestJS and Laravel probes are designed
  ([ADR-0002](docs/adr/0002-out-of-process-adapters.md)), not built.
- **No undocumented-route discovery.** The attack surface comes from the specification, so
  routes absent from it are invisible — not merely untested. Every report says this.
- **No authentication providers**, so no authenticated control request, so nothing reaches
  `confirmed`.
- **No AI**, no dashboard, no database, no crawler, no injection payloads.
- **No measured precision or recall.** The evaluation harness proves the check
  distinguishes paired vulnerable and secure fixtures; it does not establish a
  false-positive rate on real applications.
- **Assay is fingerprintable, so a hostile target can cloak.** Its user agent, cache
  buster and baseline paths are identifiable by design, because a scanner that disguises
  itself is harder to authorize and harder to stop. That is the right trade for assessing
  your own application, and a real limitation otherwise.

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

Suspected findings count deliberately. Assay cannot reach `confirmed` without configured
credentials, so gating only on confirmed findings would exit `0` on a real authentication
bypass — a silent pass is the worst possible default for a security gate.

---

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | pipeline, packages, boundaries |
| [Product thesis](docs/research/product-thesis.md) | why this exists, and what it refuses to build |
| [Ecosystem research](docs/research/ecosystem.md) | ZAP, Nuclei, Semgrep, Playwright, Hadrian — licences and findings |
| [Reference applications](docs/research/reference-applications.md) | the evidence behind the design |
| [Threat model](docs/security/threat-model.md) | Assay's own attack surface |
| [ADRs](docs/adr/) | consequential decisions and their alternatives |
| [Roadmap](docs/roadmap.md) | what is next, and what is explicitly out |

---

## Authorization

Assess only applications you own or are **explicitly authorized in writing** to test.
Running this against systems you do not control may be illegal. Assay is deliberately
identifiable in its `User-Agent`; do not remove that.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Assay is not affiliated with OWASP, Checkmarx, ProjectDiscovery, Semgrep Inc. or
Praetorian. Names are used only to identify those projects.
