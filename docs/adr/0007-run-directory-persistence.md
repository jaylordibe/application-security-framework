# ADR-0007: Filesystem run directory now, SQLite behind a seam later

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

SQLite was the proposed local persistence layer. It is a good eventual choice, but the
Phase 1 workload is: write one assessment's artefacts once, read them back to render
reports, and diff them in evaluation. There is no query workload, no concurrent writer,
and no cross-run analytics yet.

Against adopting it now: `modernc.org/sqlite` is the right CGO-free driver, but it is a
very large transpiled dependency to place in the foundation of a security tool before
anything needs it. A schema adopted before the domain is proven becomes a migration
liability.

For a filesystem run directory: zero dependencies, human-inspectable, diffable in git —
which matters enormously for the evaluation harness, where the artefact under test *is*
the output — and trivially content-addressable for evidence.

## Decision

Phase 1 persists to a **run directory** of JSON under `.appsec/runs/<run-id>/`, created
`0700` with files `0600`, behind a `store` seam.

SQLite is adopted when a real requirement appears — cross-run history, comparison
queries, or the dashboard — and not before. PostgreSQL compatibility is a later concern
for a team-server deployment, not a constraint on local storage.

## Alternatives considered

**SQLite now.** Rejected as premature: a large dependency and a schema commitment ahead of
a proven domain model, for no capability we currently need.

**In-memory only.** Rejected: evidence must be durable and referenceable, and evaluation
needs artefacts to diff.

**One giant JSON file per run.** Rejected: evidence blobs need independent addressing so
findings can reference rather than embed them.

## Consequences

Easier: no dependency, inspectable output, git-diffable evaluation fixtures, simple
content-addressed evidence.

Harder: no queries across runs; comparison features will need the store seam to grow.

Accepted: the store interface must stay narrow enough that a SQLite implementation is a
drop-in, and wide enough to be useful. This is the one interface introduced before a
second implementation exists, deliberately, because the migration is foreseeable.
