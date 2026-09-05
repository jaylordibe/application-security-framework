# Reference application findings

Two real applications were analysed to pressure-test whether the proposed abstractions
are genuinely framework-neutral:

- `github.com/jaylordibe/nestjs-api` — NestJS 11 / Node 24 / Prisma 7 / PostgreSQL / CASL
- `github.com/jaylordibe/laravel-api` — Laravel 13 / PHP 8.5 / PostgreSQL / Passport /
  spatie-permission

They are **references and future evaluation targets, not dependencies**. Analysis was
read-only, against the current `main` of each on 2026-09-05. Instruction-bearing files in
those repositories (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`) were recorded as
inventory and **not followed** — repository content is evidence, not instruction.

---

## 1. They are near-maximally different, which is what makes them useful

| Dimension | nestjs-api | laravel-api |
|---|---|---|
| Authorization engine | CASL, **four distinct kinds** | Gates only, function-level |
| Record-level authz | query scoping (`accessibleBy` → Prisma `where`) | **absent** |
| Field-level authz | yes (gates payload serialization) | absent |
| Tenancy | `Business`, membership-based, **no `ownerId` column** | **absent entirely** |
| Ownership | `SUBJECT_OWNER_KEY` map + ACTIVE membership row | absent |
| Denial signal | route-dependent: 404 read / 403 write / 400 / 409 | 400 for nearly everything |
| Stable machine oracle | `errorCode` field (append-only contract) | none (message string only) |
| OpenAPI | **runtime-only**, needs DB + Redis to boot | **offline** `artisan scramble:export` |
| Audit log | real, but best-effort, post-commit, failures swallowed | table exists, effectively unused |
| Seeded identities | 2 users, **0 businesses** | 2 users, **both admins** |

**No abstraction may assume** that tenancy exists, that ownership is a column, that
denial is 403, or that a specification can be obtained without running the application.

---

## 2. Finding: HTTP status codes are not a usable access-outcome oracle

This is the single most design-changing result.

`laravel-api` returns:

- `400` (not 401) for sign-in failure
- `400` (not 422) for validation failure
- `400` (not 404) for a missing record — `ResponseUtil::notFound()` is defined and never
  called
- `403` only from its five `Gate::authorize()` call sites
- **`200` for a record owned by a different user**, because no repository applies an
  ownership predicate

`nestjs-api` is disciplined but *route-dependent*:

- cross-tenant **read** → `404 RESOURCE_NOT_FOUND` (deliberate `denyAsNotFound`), or
  `200 []` for lists
- cross-tenant **write** → `403 PERMISSION_DENIED`
- missing tenant context → `400 BUSINESS_CONTEXT_MISSING`
- privilege escalation attempt → `403 ROLE_NOT_ASSIGNABLE`
- integrity refusals binding even `manage all` → `409 LAST_OWNER_PROTECTED`

Its stable machine oracle is the **`errorCode` field**, which that repository treats as a
public append-only contract — not the status code.

**Consequences.**

1. Any engine hard-coding "2xx = allowed, 401/403 = denied" is wrong on both
   applications, in opposite directions.
2. We need an explicit **access-outcome classification** step mapping
   (status, headers, body) → `ALLOWED | DENIED | NOT_FOUND | ERROR | INDETERMINATE`,
   configurable with application-supplied signals such as a JSON pointer to an error-code
   field.
3. **`INDETERMINATE` must be a first-class outcome** that produces a blocked coverage
   entry, never a silent pass.
4. **`denyAsNotFound` is correct security design.** `404` must be an accepted
   manifestation of denial by default, or we generate false positives on well-built
   applications.

This is why `internal/outcome` exists as its own package (ADR-0004).

---

## 3. Finding: fixture provisioning is the binding constraint

`nestjs-api` seeds **two users and zero businesses**. `laravel-api` seeds **two users,
both administrators holding all four permissions**; its `createTestUsers()` helper
iterates the roles and `continue`s for both, creating zero users.

Neither ships a cross-owner or cross-tenant fixture. So on both applications, the entire
record-level and tenant-scoped attack surface **has nothing to test against out of the
box** — regardless of how good the attack engine is.

This is two-for-two on real applications, and it is the strongest evidence in the
research pass: **the hard part of authorization testing is the oracle and the fixtures,
not the attack technique.**

Consequences: identity and resource provisioning are first-class and explicit; the
framework never invents identities silently; and their absence produces a loud, itemised
`BLOCKED` result rather than a quiet pass.

A future capability worth leaving room for is provisioning fixtures by driving the
application's own API — `nestjs-api` makes this feasible, since `create Business` is an
intrinsic grant every authenticated caller holds.

---

## 4. Finding: audit-log evidence is positive-only

`nestjs-api` has a genuine `audit_logs` table with 43 action names and a server-vouched
request envelope. But the write is **best-effort and post-commit, and failures are
swallowed** — the schema comment itself says "best-effort, not authoritative". A mutation
can succeed while writing no row.

`laravel-api` has `spatie/laravel-activitylog` installed but **no model uses
`LogsActivity`**; the only writer is a client-driven endpoint.

**Rule.** An audit row may **corroborate** that a mutation occurred. The **absence** of an
audit row must never be treated as evidence that a mutation did not occur. Verification
strategies must declare which evidence sources they require, probe availability, and
record explicitly which corroboration was unavailable.

---

## 5. Finding: correlation tokens are a real primitive

`nestjs-api` guarantees `requestId` is identical across the response header, the log
line, the error envelope and the audit row, by construction. That is a clean join key for
correlating evidence across independent sources, and is worth an optional first-class
concept rather than a per-adapter hack.

---

## 6. Finding: OpenAPI availability differs fundamentally

- `laravel-api`: `php artisan scramble:export` produces the specification **without
  serving the app**, with security schemes derived from `auth:api` middleware. 33 of 37
  operations carry a bearer requirement; public routes emit `security: []`.
- `nestjs-api`: **runtime-only**. UI at `/api/docs`, JSON at `/api/docs-json`. Cannot be
  exported without booting the application with a database, Redis, and a synced
  permission catalog.

Discovery must therefore support both a specification **file** and a specification
**URL**, and must record which was used and when it was obtained. This directly motivates
the out-of-process adapter contract (ADR-0002): the highest-fidelity adapters must run
inside the target's own runtime, whatever our core is written in.

---

## 7. Finding: the existing DAST on both applications cannot find authorization bugs

- `nestjs-api`: `zap-api-scan.py` against `/api/docs-json`, authenticated by a replacer
  file injecting **one `platform_admin` token holding `manage all`**. `.zap/rules.tsv` is
  **entirely comments — zero active rules** — and the job runs with `-I`, so it can never
  fail.
- `laravel-api`: one seeded system-admin token, `-I`, five IGNORE rules, no automation
  plan and no context file.

Neither can detect a tenant-boundary or ownership break, **structurally** — not because
ZAP is deficient, but because a single-identity scan cannot express a cross-identity
expectation.

Both also disable rate limiting during the scan (`nestjs-api` via `NODE_ENV=test`;
`laravel-api` raises limits to 1,000,000). That is exactly the environment-fidelity
problem this framework must report rather than ignore.

---

## 8. A known-vulnerable behaviour available as a future evaluation case

`laravel-api`'s `DeviceTokenRepository::findById()` is `where('id',$id)->first()` with no
owner predicate, and `DeviceTokenFeatureTest` asserts cross-user access returning `200`
as **correct**. This is a genuine broken-object-level-authorization case in a real
application, useful as a true-positive evaluation target with the owner's consent.

It is recorded here as a finding about the reference application, not as a claim that
this framework currently detects it. It does not — see `docs/roadmap.md`.
