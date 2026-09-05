# Contributing to Assay

Thank you for considering it. This document is short on ceremony and specific about the
few rules that matter, because Assay is security software and some mistakes here are
worse than a bug.

## The one rule

**Never claim more than the evidence supports.** This applies to findings, to
documentation, to status tables, and to pull request descriptions. If a control is
designed but not implemented, say `designed`. If a test was skipped, say skipped. A
green check mark that is not true is the failure mode this project exists to prevent.

## Getting started

```bash
git clone https://github.com/jaylordibe/application-security-framework
cd application-security-framework
make check       # fmt, vet, staticcheck, test, race, govulncheck
```

`go test ./...` needs **no network, no database, no Docker and no external engine**. If a
change makes that untrue, the change is wrong. Evaluation fixtures run against in-process
HTTP servers.

## Adding a check

This should be one new file plus one fixture, and nothing else.

1. Add `internal/check/yourcheck.go` implementing the `engine.Check` contract:
   `Metadata`, `RequiredProfile`, `Applicable`, `Run`.
2. Register it in `internal/cli/scan.go`.
3. Declare the weakness classes it covers in `assessedClasses` in
   `internal/engine/engine.go`, so `classesNotAssessed` stays truthful.
4. Add **paired** fixtures in `evals/`: a known-vulnerable case that must be detected and
   at least one known-secure case that must not be reported.

**A check without a known-secure fixture will not be merged.** Anything can find a
vulnerability if it is willing to report everything; the fixtures are what demonstrate it
can tell the difference.

Read `internal/check/authrequired.go` first — its discriminator ladder is the pattern.

### What a check must do

- Return `blocked` with a cause rather than guessing. `indeterminate` is a respectable
  result; a confident wrong answer is not.
- Compute `RequiredProfile` from the **operation**, not from the check. A check that
  iterates a specification will otherwise send unauthenticated writes.
- Never reach `confirmed` without verification appropriate to that weakness class.
  Vulnerability classes need different proof; there is no generic rule and no "two tools
  agreed" shortcut.
- Record what it could **not** establish in `Verification.Unavailable`.

## Dependency policy

The dependency list is short on purpose: we are a supply-chain target.

- **Adding a direct dependency requires an ADR** stating what it replaces, its licence,
  its maintenance status, and what breaks if it is abandoned.
- Explicitly not wanted: **viper** (fights our strict-decode config), **logrus** or
  **zap** (use `log/slog`), **testify** (use the standard library).
- Never vendor code with no licence. This rules out some well-known Burp extensions.
- **Never ship, vendor, or auto-fetch Semgrep registry rules**, and do not reference
  `p/...` rule packs in examples, defaults, tests or documentation. Their licence permits
  internal use only. See [NOTICE](NOTICE).

## Security-sensitive code

Changes to `internal/scope`, `internal/httpx`, `internal/redact` or `internal/store` get
extra scrutiny and need tests that demonstrate the control, not merely exercise it. The
existing tests set the bar: the redirect test asserts the second server's request counter
is **zero**, and the out-of-scope test fails if the dialer is called at all.

If you find a scope-escape or secret-leak issue, follow [SECURITY.md](SECURITY.md) rather
than opening a pull request that reveals it.

## Style

- `gofmt` decides formatting. There is nothing to discuss.
- Comments explain **why**, not what. The code already says what.
- Errors are values and are handled; no `panic` in library code except for a genuinely
  impossible condition, with a comment saying why.
- Every user-facing string is written for someone who is tired and does not trust the
  tool yet. Say what happened, and what they can do about it.

## Commits and pull requests

- Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
  are used but not enforced by a bot.
- Contributions are accepted under the **Developer Certificate of Origin**. Sign off with
  `git commit -s`. There is no CLA: on a small security project a CLA mostly signals a
  future relicence, and we would rather have your trust.
- Describe what you tested and what you did not. "I did not test X" is a welcome sentence.

## Framework adapters

Adapters live in their own ecosystems (TypeScript for NestJS, PHP for Laravel, Python for
Django) and emit the documented JSON contract on stdout. They are versioned and released
independently; see [ADR-0002](docs/adr/0002-out-of-process-adapters.md). A conformance
suite is planned so an adapter author can validate against golden JSON without needing to
understand the Go core.

## Code of conduct

Be decent. Assume good faith. Disagree about the work, not about the person. Maintainers
will remove content and contributors that make this an unpleasant place to work.
