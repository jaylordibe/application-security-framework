# Architecture

Status: the M0 foundation is implemented and tested; everything beyond it is design only.
This document describes the intended shape of the system and marks clearly what exists
today. See `docs/roadmap.md` for what is next and `README.md` for the honest list of what
AppSec Framework cannot yet do.

---

## 1. The one-sentence version

AppSec Framework derives an **expectation** of how an application should behave from the
application's own metadata, observes how it **actually** behaves, and reports the
difference — together with an honest account of everything it could not test.

---

## 2. Pipeline

```
  Target + Scope
       │
       ▼
  Discovery ────────────────► Attack Surface (operations, inputs, hosts)
   • specification (file/URL)      each fact carries PROVENANCE
   • framework adapters (probes)
   • runtime observation
       │
       ▼
  Oracle derivation ────────► Expected behaviour
   • declared  (config, spec)      each expectation carries PROVENANCE
   • inferred  (adapter, source)   and is FALSIFIABLE
       │
       ▼
  Planning ─────────────────► Plan (checks × targets), gated by SAFETY PROFILE
       │                            everything not planned becomes a COVERAGE GAP
       ▼
  Execution ────────────────► Observations
   • native checks                 external engines are optional and swappable
   • external engines (ZAP/Nuclei/Semgrep/Hadrian)
       │
       ▼
  Outcome classification ───► ALLOWED │ DENIED │ NOT_FOUND │ ERROR │ INDETERMINATE
       │
       ▼
  Verification ─────────────► confirmed │ rejected │ blocked
       │                            strategy differs per vulnerability class
       ▼
  Evidence ─────────────────► redacted at capture, content-addressed, referenceable
       │
       ▼
  Findings + Coverage ──────► reports (JSON, SARIF)
```

**Two deviations from the originally proposed pipeline**, both deliberate:

1. **Outcome classification is its own stage.** Evidence from the reference applications
   showed that mapping a response to "allowed" or "denied" is application-specific and
   frequently ambiguous; burying it inside checks would have hard-coded a wrong
   assumption into every check. See ADR-0004.
2. **Threat modelling is not a pipeline stage.** It is an input to planning, not a
   runtime phase. Modelling it as a stage implied a capability we do not have.

---

## 3. Packages

Concrete types are preferred to interfaces. An interface appears only where a second
implementation genuinely exists or is imminent.

| Package | Owns | Status |
|---|---|---|
| `cmd/appsec` | binary entrypoint | ✅ |
| `internal/cli` | command surface, exit codes, human output | ✅ |
| `internal/config` | `appsec.yaml` loading, strict decode, semantic validation | ✅ |
| `internal/model` | the normalized application-security model | ✅ |
| `internal/scope` | the authorization boundary for every request | ✅ |
| `internal/httpx` | the only way to reach the network | ✅ |
| `internal/redact` | secret redaction at capture time (zero-dependency leaf) | ✅ |
| `internal/identity` | principals, credential sources, authenticated controls, liveness | ✅ |
| `internal/resource` | resource fixtures, ownership expectation, safe parameter binding | ✅ |
| `internal/adapter` | adapter contract, hostile-output validation, execution boundary, provenance merging | ✅ |
| `adapters/*` | out-of-process framework probes (Laravel, NestJS) | ✅ static tier (ADR-0014) |
| `internal/openapi` | specification ingestion → operations + declared expectations | ✅ |
| `internal/outcome` | response → access outcome classification | ✅ |
| `internal/check` | check implementations | ✅ |
| `internal/engine` | assessment lifecycle: plan, execute, record; owns the `Check` interface | ✅ |
| `internal/store` | run persistence, evidence storage, permissions | ✅ |
| `internal/report` | JSON and SARIF renderers; owns the versioned wire DTOs | ✅ |
| `engines/*` | external scanner integrations | ⬜ designed (ADR-0005) |

**Status is ⬜ until code for that package is merged with tests.** A project whose thesis
is honest accounting of what it could not test must not overstate its own completeness.
`scripts/verify-control-claims.py` runs in CI and fails the build if the threat model
cites a test that does not exist, so the same rule is enforced rather than merely
promised.

Coverage accounting has no package of its own: its types live in `model` and its
accumulation in `engine`, because a ledger that only appends and reads does not need one.

**Dependency rule.** `model` owns every type that two otherwise-unrelated packages must
both name, imports nothing outside the standard library, and carries **no JSON tags** — so
that renaming a field is never a breaking change to our published output. `redact` is a
zero-dependency leaf operating on bytes and headers. `report` owns the versioned wire DTOs
and the mapping from `model` to them; `store` persists those DTOs rather than the model, so
there is exactly one wire schema. Nothing depends on `cli`.

---

## 4. The normalized model

Framework-neutral by construction, and validated against two deliberately dissimilar
applications (`docs/research/reference-applications.md`).

- **Operation** — a callable unit of attack surface: method, path template, host,
  parameters, declared security requirements, provenance.
- **Identity** — an actor, with credentials the framework may use. Never invented.
- **Expectation** — what *should* happen for an (operation, identity) pair, with
  provenance and a falsifiable predicate.
- **Observation** — what *did* happen, with evidence references.
- **Outcome** — the classification of an observation, including `INDETERMINATE`.
- **Finding** — a difference between expectation and outcome, with severity, confidence,
  state and evidence.
- **CoverageEntry** — one unit of intended work and its disposition: tested, blocked
  (with cause), or untested (with reason).

Deliberately **not** in the model yet: tenancy relationships, workflows, resource
ownership graphs. The boundaries exist; the types do not, because inventing them without
a consumer would be speculative. See ADR-0009.

### Provenance

Every fact and every expectation records how it was obtained:

`declared` (the operator or the application stated it) → `inferred` (derived by analysis;
a hypothesis) → `observed` (seen at runtime) → `verified` (deterministically confirmed).

Provenance never upgrades itself. An inferred expectation that is contradicted becomes a
**rejected hypothesis**, which is a reportable outcome, not a finding.

---

## 5. Safety profiles

Strictly ordered: `discovery` < `verification` < `intrusive`.

Every check declares the impact it requires. If required impact exceeds the effective
profile, the check **does not run and is recorded as blocked with a cause**. Profiles
never escalate implicitly; the effective profile is recorded in every result. `intrusive`
additionally requires explicit authorization in configuration.

This is the mechanism that makes "potentially destructive behaviour must never happen
accidentally" a property of the type system rather than a convention.

---

## 6. Evidence

- Redacted **at capture**, so secrets never reach disk (threat model T-06).
- Content-addressed and stored once; findings **reference** evidence rather than
  embedding copies.
- Stored under a per-run directory, `0700`/`0600`.
- An evidence source declares what it can prove. Critically, an audit-log source may
  **corroborate** a mutation but its silence proves nothing
  (`docs/research/reference-applications.md` §4).

---

## 7. Coverage

Coverage is a first-class output, not a summary statistic. It is a **ledger**: every unit
of intended work has a disposition.

A blocked entry names its cause — missing identity, missing resource, authentication
failure, engine unavailable, unsupported protocol, environment mismatch, insufficient
privilege, or safety policy. A percentage is reported only alongside the ledger, never
alone, and never as a claim about security.

**A run that executed no checks cannot report success.**

---

## 8. Identities and the authenticated control (M1)

### The distinction the design turns on

An **identity** is a security principal: a stable id, a label, and a reference to how to
authenticate as it. **Authentication material** is the credential. They are separate types
with separate lifetimes and separate rules, and conflating them is the mistake this design
exists to avoid — an identity id belongs in every report, and a credential belongs in none.

```
Identity            (id, label, scheme, credential reference, optional canary)
   ↓  resolved once, at run start
CredentialSource    (env or file — never a value in appsec.yaml)
   ↓
Secret              (String/GoString/MarshalJSON render a placeholder; Expose is the
                     single deliberate reader)
   ↓  registered with the redactor before the first request is possible
Control             (issues authenticated requests, tracks liveness)
   ↓  scope-enforced client, shared with anonymous traffic
Authenticated control request
   ↓
Material-equivalence comparison against the anonymous response
   ↓
confirmed, or suspected with the gap named
```

### Verification semantics

A finding rises to `confirmed` only when an authenticated control request **succeeded** and
its response was **materially equivalent** to the anonymous one. Material equivalence is a
conjunction: both classify as `allowed`, identical status, identical normalised content
type, identical JSON document shape (sorted key paths and value types, array indices
collapsed, values ignored), and no cache-hit indicator on the control.

Shape rather than bytes because real payloads carry volatile fields; shape rather than
status because status alone is what an SPA shell and a soft error envelope defeat.
Non-JSON bodies are unmodelled and never equivalent. Full reasoning in
[ADR-0012](adr/0012-authenticated-control-and-material-equivalence.md).

**Inference runs one way.** A control that succeeds and matches raises a finding. A control
that is absent, unusable, rejected, erroring or different only ever leaves it suspected.
There is no branch in which an authentication failure makes an operation look protected,
because a finding is raised by an anonymous success and never by an authenticated failure.
That asymmetry is what makes a missing credential incapable of producing a clean result.

### Liveness and temporal validity

The canary is an operation the **operator supplies**. Probing `/me` or `/whoami` on the
assumption they exist yields a 404 on most applications, which is indistinguishable from an
expired credential — the canary would then declare the identity dead and block the run.

Three states, because two would force a lie: `unknown` (no canary, or none has run yet),
`good`, `bad`. Unknown is not a synonym for good.

The canary runs at the start of a run, at the end, and whenever an authenticated request
returns something consistent with an invalid credential. That last trigger is event-driven
rather than periodic: a timer probes when nothing has happened and stays silent when
everything has, whereas probing at the moment a credential first looks wrong finds the
expiry with the smallest possible uncertainty window.

A canary observes an expiry when it next runs, not when it happens. So `(lastGood,
firstBad]` is a window in which validity is genuinely unknown, and work corroborated by a
control issued inside it is re-scored:

| | |
|---|---|
| ledger row | `blocked{authentication_failed}`, with the window stated |
| confirmed finding | demoted to `suspected`, corroboration withdrawn and explained |
| the finding itself | **kept** — the anonymous observation never involved the credential |

Deleting the finding would let an expired token hide a real bypass, which is the
false-assurance failure wearing a different hat.

### What the ledger gained

Coverage now has a second dimension, `identity`, carrying one row per configured principal:
executed when a canary confirmed it, `blocked{missing_identity}` when the credential could
not be resolved, `blocked{authentication_failed}` when the target rejected it, and
`untested{no_oracle}` when no canary is configured. Headline counts filter to the
`operation` dimension, so configuring an identity cannot inflate the number of checks a run
claims to have executed.

### Not in M1

One identity is used as the control. The type carries a slice so a second can be added
without reshaping callers, but *choosing between* identities, cross-identity probes, owned
resources and BOLA are M2. OAuth2, OIDC, browser login, cookie-session establishment and
refresh rotation are not implemented; each needs multi-step state, and a half-implemented
login flow that silently falls back to anonymous is exactly the false assurance this
project exists to prevent.

---

## 9. Cross-owner testing (M2)

### The primitive

```
identity A ──owns──▶ resource X
     │                   ▲
     │ owner control     │ owner re-check
     ▼                   │
   reachable ──▶ identity B probes X ──▶ still reachable?
                          │
                          ▼
              denied / not_found  →  boundary verified
              allowed             →  is it really X?
```

Three requests for a read, in that order, and all three matter. The owner control
proves the fixture is real and reachable. The probe is the actual question. The
re-check proves the resource did not vanish underneath the test — without it, a
record deleted between the first two requests makes B's 404 read as an enforced
boundary, which is an untested control reported as working.

### The fixture

A fixture is a resource the assessment knows exists, knows who owns, and knows how
to address. It carries a stable id, a logical type, an owner identity, the values
that fill an operation's declared parameters, its provenance, and — required — the
expectation for non-owners.

It deliberately has no notion of a primary key, a foreign key, a tenant column or
an ORM relation. The two reference applications disagree about all of them: one
expresses ownership as a membership row with no owner column anywhere, the other
has no tenancy at all. Parameter values are the only thing every application has
in common.

**Ownership expectation is declared, never inferred.** `crossOwnerAccess` is
`denied` or `allowed` with no default. Assuming that every owned resource is
private would report every deliberately shared record as a broken access control.

**Provenance is recorded.** M2 produces only `configured` fixtures. The
`api-created` value exists in the model so the report schema does not have to
change when provisioning is built, and nothing produces it yet. Ownership is never
inferred from a value merely appearing in a response — a list endpoint returns
other people's identifiers all day.

### Parameter binding

Binding works from the parsed parameter list, not by substituting into path text.
Values are refused at load if they could change the URL's shape, encoded exactly
once, and the finished URL is re-parsed and checked against the operation's own
origin. See T-17.

### Verification

| | Confirmed only when |
|---|---|
| Read | the non-owner's outcome is `allowed`, its response is materially equivalent to the owner's (M1's comparison), **and** it can be tied to *that resource* — a fixture value at the same JSON path in both, or byte-identical bodies |
| Write | the **owner's own view** changed, field by field, and only for fields that did not already hold the written value |

Shape agreement alone is not resource identity: two orders have the same shape, so
an application that quietly returns the caller's own record would match perfectly.
An HTTP status is never evidence of a write. Both claims are backed by tests that
fail when the corresponding discriminator is removed.
[ADR-0013](adr/0013-cross-owner-verification-semantics.md) carries the reasoning.

### Safety

A cross-owner write needs three separate acts of consent: the intrusive profile,
`authorizeIntrusive`, and a `mutation` block on the fixture. A write with no
readable operation to observe it is refused rather than sent. Restoration is
attempted as the owner and verified by re-reading; a failure becomes run-level
tool state, never a buried detail.

### Coverage

A third ledger dimension, `ownership`, keyed by (operation, check, non-owner,
resource, owner) so that two boundaries differing only in the resource cannot
collapse into one row. The summary lists the tuples actually exercised and states
that they imply nothing about any other resource, pair or operation. There is no
percentage: the number of ownership boundaries an application has is unknowable
from a specification, so a denominator would have to be invented.

Identity rows remain preconditions and are not counted as executed work.
Ownership rows are counted, because a probed boundary is assessment.

### Bounded planning

Fixtures multiply operations by identities. Planning is capped, and work beyond
the cap becomes an untested row rather than a silent omission. With explicitly
configured fixtures the product is small; the bound exists because the planner is
where a future fixture source would make it large.

### Not in M2

No tenancy graph, no permission catalog, no role matrix, no privilege escalation,
no BFLA, no workflow or state-machine testing, no framework adapters, no
source-code or database ownership inference. Cross-owner `DELETE` is out of scope:
it destroys the fixture and proves nothing a `PATCH` does not. API-created
fixtures are deferred to environment provisioning.

---

## 10. Framework adapters (M3)

### What crosses the boundary

```
application source ──▶ adapter ──▶ versioned JSON ──▶ hostile-input validation
                                                              │
                                                              ▼
                                                   normalized facts
                                                              │
                                                              ▼
                                            provenance merging with OpenAPI
                                                              │
                                                              ▼
                                                          oracle
                                                              │
                                                              ▼
                                              runtime checks produce evidence
```

The core consumes facts, never constructs. It has no idea what a middleware
group or a guard is, and a test asserts that mechanically over the parsed AST
rather than by review — the first `if framework == "laravel"` always looks like
a small pragmatic exception.

The reason is concrete rather than aesthetic. In Laravel, a route with no
authentication middleware is unprotected. In NestJS under a global `APP_GUARD`,
an operation with no decorator is protected. **The same syntactic absence means
opposite things.** A core that learned either rule would be wrong about the
other, so both rules live in their adapters and the contract carries only the
conclusion.

### Extraction tiers and what they earn

| Method | Executes target code | Provenance |
|---|---|---|
| `framework-native` | **yes** | `declared` |
| `static-ast` | no | `inferred` |
| `static-lexical` | no | `inferred` |

The adapter states the method; the **core** maps it onto provenance. There is no
confidence field an adapter can set, so provenance spoofing requires
misreporting what was done — which appears in the report. No method reaches
`observed` or `verified`: reading source never establishes what a request does.

Framework-native extraction is refused unless the operator sets
`adapters.trust: execute-target-code`, because asking a framework to describe
itself means booting it. M3 ships only the static tier
([ADR-0014](adr/0014-adapter-contract-and-extraction-trust.md)).

### Merging

| Specification says | Adapter says | Result |
|---|---|---|
| nothing | protected / public | **new** — the operation gains an expectation it did not have |
| protected | protected | corroborated |
| public | protected | **conflict** — expectation withdrawn from both, reported |
| protected | public | **conflict** — expectation withdrawn from both, reported |
| anything | `unknown` | recorded, nothing added |

Nothing overwrites anything. Choosing between two of the application's own
artefacts with no evidence would be a guess, and which one won would depend on
the order sources were read in. An operation only an adapter knows about is
recorded and **not** tested: that is undocumented-surface discovery, which is a
different milestone.

### Facts are expectations, never evidence

An adapter saying an operation is protected does not establish that it is. It
supplies the oracle; the runtime checks supply the evidence. So an
adapter-derived expectation can make an operation *testable* — moving it from
`untested{no_oracle}` to an executed check — and the finding that results stays
**suspected**, because a static reading proves nothing about what a request
would do.

That distinction is the reason this project exists, and the report states it in
words rather than leaving it to be inferred.

### Containment

Adapters are opt-in, never discovered from a target repository, and run as
subprocesses with an explicit argument vector and no shell. The environment is
built from nothing — not even `PATH` — and this tool's own identity credentials
can never be forwarded. Output is bounded, both pipes are drained concurrently,
and a cancelled adapter's process group is killed. Its document is size-bounded
before parsing, version-checked before interpretation, and validated fact by
fact. See threat model T-18.

A failed adapter contributes nothing and leaves the oracle exactly as it was,
saying so: *this does not mean the application has no controls; it means none
were read.*

---

## 11. Failure semantics

- An engine crash is an engine crash. It becomes a blocked coverage entry and a recorded
  tool failure — never an absence of findings.
- Partial assessments are first-class and are reported as partial.
- Exit codes distinguish *"ran cleanly, nothing found"* from *"could not run"* from
  *"policy threshold exceeded"*.

---

## 12. What is intentionally missing

Discovery beyond specification ingestion; any external engine integration; identity and
authentication providers; the adversarial authorization engine; tenancy; workflows;
SQLite; the dashboard; AI.

Each is absent because building it now would mean shipping an unproven abstraction. The
seams are documented so the additions are leaves rather than rewrites.
