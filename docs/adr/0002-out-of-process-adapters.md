# ADR-0002: Framework adapters are out-of-process probes with a JSON contract

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The product's differentiator is deriving the authorization oracle from the application's
own metadata (`docs/research/product-thesis.md` Q2). The reference applications show that
this metadata is often **only available at runtime**:

- `nestjs-api` exposes OpenAPI at `/api/docs-json` only; it cannot be exported without
  booting the app with PostgreSQL and Redis. Its authorization catalog is TypeScript
  decorator metadata resolved at runtime.
- `laravel-api` can export offline via `php artisan scramble:export`, but its gate table
  is generated in a provider loop from an enum — again, most faithfully read by asking
  the framework.

No general-purpose parser in any language reads these as faithfully as the framework
itself does.

## Decision

Adapters are **separate processes** that emit a documented, versioned JSON document on
stdout. The Go core consumes normalized facts and never parses TypeScript or PHP.

Three fidelity tiers, preferred in order, each stamping its facts with provenance:

1. **Ask the framework** — `artisan route:list --json`, `scramble:export`,
   `/api/docs-json`. Authoritative runtime truth.
2. **Language-native static probe** — TypeScript compiler API for NestJS,
   `nikic/PHP-Parser` for Laravel. No running app required.
3. **Tolerant extraction** (tree-sitter) — cheap and broad, low fidelity, always lower
   confidence.

## Alternatives considered

**Parse in the Go core.** Rejected: Go has no good TypeScript or PHP parser, and tier-1
fidelity is unreachable from outside the runtime regardless of parser quality.

**Require adapters to be Go plugins.** Rejected: Go's plugin system is
platform-restricted and fragile, and it would force contributors out of the ecosystem
where their framework knowledge lives.

**Make adapters long-lived services.** Rejected as unnecessary complexity for a
batch-oriented CLI, and it widens the attack surface of an untrusted component.

## Consequences

Easier: adapters are independently contributable, versionable and testable; a Django
adapter is a Python probe; the core stays small and stays out of the parsing business.

Harder: a cross-process contract must be versioned and schema-validated; adapter output
is untrusted input (threat model T-11); users need the adapter's runtime.

Accepted: adapters are opt-in per run, never auto-discovered from a target repository,
and never executed merely because a manifest exists.
