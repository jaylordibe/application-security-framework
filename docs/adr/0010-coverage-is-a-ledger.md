# ADR-0010: Coverage is a ledger, and no findings is not success

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

This is the project's most defensible differentiator: coverage accounting is **absent
from every open-source tool examined**, Hadrian included (`blocked`/`Blocked`: 0 hits
across its `pkg internal cmd`).

The motivating evidence is concrete. Both reference applications run ZAP in CI. Both
authenticate as a **single administrator**, both run with `-I` so the job can never fail,
and one has a rules file that is entirely comments. Both scans pass. Both reports imply
safety. Neither is structurally capable of detecting an authorization break, and **nothing
in either output says so**.

A percentage would not have helped. "94% of endpoints scanned" is true and useless when
every endpoint was scanned as the same omnipotent identity.

## Decision

Coverage is a **ledger**, not a statistic. Every unit of intended work carries a
disposition:

- `TESTED` — a check ran and produced a usable outcome.
- `BLOCKED` — work was planned but could not run, **with a machine-readable cause**:
  missing identity, missing resource, authentication failure, engine unavailable,
  unsupported protocol, environment mismatch, insufficient privilege, safety policy, or
  indeterminate outcome.
- `UNTESTED` — in the attack surface, never planned, **with a reason** (most commonly: no
  oracle available for it).

Rules that follow:

- A percentage may be reported only **alongside** the ledger, never alone, and never as a
  statement about security.
- **A run that executed no checks cannot report success.** This is enforced in the exit
  code, not left to the reader.
- An `INDETERMINATE` outcome (ADR-0004) is a blocked entry, never a pass.
- An engine crash is a blocked entry plus a recorded tool failure, never an absence of
  findings.
- Reports must state the effective profile, effective scope, blocked tests, untested
  surface, tool failures and environment differences. "No critical vulnerabilities found"
  must never render without them.

## Alternatives considered

**A single coverage percentage.** Rejected: it is precisely the security theatre that
makes the reference applications' CI misleading today.

**Endpoint coverage only.** Rejected: the interesting dimensions are identity, resource,
tenant and workflow coverage. Endpoint coverage is the one that most easily reaches 100%
while testing nothing.

**Report only what was tested.** Rejected: silence about the untested surface is the
false-assurance failure mode (threat model T-15).

## Consequences

Easier: honest reports; blocked work becomes actionable ("seed a second identity and this
surface becomes testable").

Harder: our output looks *worse* than competitors' on first run, because we admit what we
did not do. That is the intended trade and must be defended in documentation rather than
softened.
