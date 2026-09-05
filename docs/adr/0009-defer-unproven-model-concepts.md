# ADR-0009: Defer tenancy, workflow and ownership types until a consumer exists

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The brief specifies a normalized model eventually covering identities, authentication,
authorization, resources with ownership and tenancy, workflows with state transitions,
and security invariants. All of that is the right long-term shape.

But the reference applications show how easy it is to get wrong by guessing. `nestjs-api`
has tenancy with **no `ownerId` column anywhere** — business ownership is a membership row
holding a role, deliberately, so a departed creator retains nothing. `laravel-api` has
**no tenancy at all**. A `Resource{OwnerID}` field designed before looking would have been
wrong for both.

The brief itself warns against creating dozens of empty interfaces and packages, and
against making every concept an interface prematurely.

## Decision

Phase 1 implements only the model concepts that have a **consumer in this repository
today**: operations, identities, expectations, observations, outcomes, evidence, findings
and coverage entries.

Tenancy relationships, resource ownership graphs, workflow state machines, authentication
provider contracts and security invariants are **documented boundaries, not types**. Each
is introduced when the capability that consumes it is built, informed by at least two
dissimilar applications.

## Alternatives considered

**Define the full model now.** Rejected: unproven abstractions calcify. Every field would
be untested, unvalidated against reality, and expensive to change once a report format
depends on it.

**Define interfaces now, implementations later.** Rejected explicitly. An interface with
one implementation is indirection, not abstraction, and the brief calls this out.

## Consequences

Easier: the model stays small, testable and honest; every type has a caller.

Harder: adding tenancy later touches the model and the report schema. Accepted, and
cheaper than shipping a wrong shape now — a versioned report schema makes the change
manageable.
