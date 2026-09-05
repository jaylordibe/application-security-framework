# ADR-0001: Go as the core implementation language

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The core owns the CLI, assessment orchestration, subprocess supervision, evidence
handling, coverage accounting and reporting. Reversing this choice means rewriting
everything, so it was re-examined from evidence rather than inherited from the brief.

The decisive observation is that **our core language buys us nothing from any security
tool ecosystem**, because every engine we integrate is already a subprocess in its own
language: ZAP is Java, Nuclei is a Go binary, Semgrep ships as a binary, Hadrian is a Go
binary. The usual reason to choose Python for security tooling — library reuse — does not
apply to an orchestrator.

A second observation removed the strongest counter-argument. The highest-fidelity
framework adapters must run **inside the target's own runtime**: NestJS authorization
metadata lives in runtime decorators and its OpenAPI document cannot be produced without
booting the app with a database and Redis; Laravel's real route and gate tables come from
`artisan`. Adapter fidelity is therefore independent of the core language (ADR-0002).

## Decision

**Go** for the core, distributed as a single statically linked, cross-compiled binary.
Framework adapters are out-of-process probes written in whatever language reads that
framework best.

## Alternatives considered

**Python.** Genuinely better for ML, program analysis and LLM tooling. Rejected because
that work is explicitly optional, deferred, and forbidden from establishing findings on
its own — reducing to provider-neutral HTTP calls. The costs are immediate and borne by
every user: no single-binary distribution for a developer CLI, GIL-constrained
concurrency for a workload dominated by concurrent HTTP and process supervision, a larger
dependency surface in software that is itself a supply-chain target, and no
reachability-based vulnerability analysis equivalent to `govulncheck`.

**Rust.** A single binary too, plus sum types that would model outcomes, provenance and
finding states more precisely than Go can. Rejected on contributor economics for an
open-source security project, slower iteration, and no ecosystem alignment with the Go
tools we integrate.

**Go with no polyglot adapters** (tree-sitter for everything). Simplest install, one
language for contributors. Rejected because it materially weakens the differentiator: it
cannot read NestJS runtime decorator metadata or Laravel's real gate table, which is
precisely the oracle-derivation capability the product is repositioned around.

## Consequences

Easier: distribution, concurrency and cancellation, process supervision, cross
compilation, a small auditable dependency graph, `go test -race` as real evidence,
ecosystem alignment with Nuclei, Trivy, Hadrian and the importable `gosec` library.

Harder: no sum types, so model variants become validated string enums or sealed
interfaces; verbose error handling; fewer batteries for anything data-heavy.

Accepted: users who want a specific framework adapter need that adapter's runtime. This
is mitigated by adapters being optional, and by a missing adapter producing an explicit
blocked coverage entry rather than silence.
