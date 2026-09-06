# ADR-0014: The adapter contract carries conclusions, and extraction method decides trust

- **Status:** Accepted
- **Date:** 2026-09-06
- **Refines:** [ADR-0002](0002-out-of-process-adapters.md), whose tier model this keeps and whose default tier this changes

## Context

ADR-0002 established that adapters are separate processes emitting versioned
JSON, and ranked three fidelity tiers with **framework-native introspection
first**: `artisan route:list`, a NestJS runtime probe. Implementing M3 required
finding out what those actually do. The answer changes which tier can be the
default.

**Asking Laravel is booting Laravel.** `artisan` requires `vendor/autoload.php`
and then `Application::configure(...)->handleCommand(...)`, which registers and
boots every service provider the repository defines
(`laravel-api/artisan:9-13`). Worse, a fresh checkout has no `vendor/` at all,
so using artisan first requires `composer install` — and that repository's
`composer.json` runs `@php artisan package:discover` on `post-autoload-dump`, so
the install itself boots the application. There is no ordering in which AppSec
reads Laravel's routes without executing the repository's code.

**Importing a NestJS module is executing it.** `nestjs-api/src/main.ts` calls
`startTelemetry()` at import time — above the other imports, deliberately, so
that OpenTelemetry patches `http`, `pg` and `ioredis` before anything holds a
reference. A probe that imports the application to read decorator metadata opens
that machinery on a repository nobody vouched for, and on a fresh checkout
cannot run at all because `node_modules` is absent.

So tier 1 is not a faster way to read the same files. It is arbitrary code
execution against untrusted input, and it requires installing dependencies whose
lifecycle scripts are themselves arbitrary code.

A second problem surfaced while designing the fact model. The two frameworks
give the *same syntax* opposite meanings. A Laravel route with no authentication
middleware is unprotected; a NestJS route with no decorator, under a global
`APP_GUARD`, is protected. Any contract that shipped framework constructs to the
core would make the core learn that, and the core would then be wrong the moment
a third framework inverted it again.

## Decision

**Adapters ship conclusions, not constructs.** The contract's vocabulary is
`operation.authentication`, `operation.authorization`, `operation.ownership`
with values like `required`, `public`, `present`, `unknown`. There is no
middleware, guard, gate, policy, decorator or controller in it. A test asserts
this mechanically, over the parsed AST of the core rather than its comments,
because the first `if framework == "laravel"` always looks like a small
pragmatic exception.

**The adapter states its extraction method; the core decides what that is
worth.** There is no `provenance` or `confidence` field an adapter can set — the
schema is asserted not to have one. `framework-native` maps to
`ProvenanceDeclared`, everything static to `ProvenanceInferred`, and **no method
maps to observed or verified**. Reading source never establishes what a request
does.

**Framework-native extraction is gated behind explicit trust.** An adapter
reporting that method is refused unless the operator sets
`adapters.trust: execute-target-code`. Naming an executable is not consent to
run the target's own code, and a "discover" step that quietly boots an
application would be the tool doing something materially more dangerous than its
name suggests.

**M3 ships the static tier only.** The two reference adapters read files and
never execute anything. They are graded `inferred`, and everything they cannot
resolve is reported as a stated limitation rather than guessed at.

**Adapter output is hostile input.** It is size-bounded before parsing,
version-checked before interpretation, strictly decoded, and every fact is
validated individually. A document with an unknown contract version is refused
rather than parsed hopefully. An adapter that contradicts itself about one
subject has *both* assertions withdrawn: keeping the first would make the result
depend on document order, and keeping the last would let a malicious adapter
overwrite an inconvenient fact by appending.

**Nothing overwrites anything.** Sources corroborate or they conflict. On
conflict the operation loses its expectation entirely, because choosing between
two of the application's own artefacts with no evidence is a guess, and the
disagreement is reported as a finding about the application.

**A failed adapter leaves the oracle exactly as it was**, and says what was lost:
"this does not mean the application has no controls; it means none were read."

## Alternatives considered

**Implement tier 1 as the default, per ADR-0002.** Rejected on the evidence
above. It cannot run without installing dependencies, which §12 of the milestone
brief forbids and which is itself code execution.

**Implement tier 1 behind the trust gate as well as tier 3.** Deferred rather
than rejected. The gate is built and tested; what is missing is a tier-1 adapter,
and shipping one would mean either a PHP/Node program whose own dependencies CI
cannot install, or untested security-critical code. Untestable code in this
position is worse than absent code, so the milestone is marked partial and the
contract is ready for the adapter when its environment story exists.

**Write the adapters in PHP and TypeScript**, as ADR-0002's "ecosystem" argument
suggests. Rejected for the shipped reference adapters: both would need their own
dependency installation (`nikic/php-parser`, the TypeScript compiler API), which
this project's Go-only CI cannot do without becoming a multi-runtime build. The
contract is language-neutral and a community adapter in either language remains
a drop-in replacement — which is the property that argument was protecting.

**Let adapters state their own confidence.** Rejected. It makes provenance
spoofing a one-line change in an untrusted component. Deriving trust from a
declared *method* means a lying adapter must misreport what it did, which at
least appears in the report.

**Add adapter-reported routes to the attack surface.** Rejected. Testing routes
absent from the specification is undocumented-surface discovery, with its own
safety questions and its own milestone. They are recorded and left alone.

## Consequences

Easier: an operation whose specification says nothing about security can now be
tested, because the framework's own route file says it is protected. On the real
`laravel-api`, that moves `GET /api/users` from `untested{no_oracle}` to an
executed check that finds the deployed service serving it anonymously.

Harder: static extraction cannot resolve anything dynamic, and the adapters say
so at length. `laravel-api` builds its gate table in a provider loop over an
enum, so no adapter that does not run the application will ever enumerate its
permissions.

Accepted: the reference adapters are lexical, so they will misread source that
is unusual enough. Every fact carries a file and line for exactly that reason,
and a wrong fact produces a *suspected* finding a human reads — not a confirmed
one.
