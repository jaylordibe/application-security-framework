# ADR-0004: Access-outcome classification is an explicit stage with an INDETERMINATE result

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Deciding whether a response means "allowed" or "denied" looks trivial and is not. Direct
evidence from two real applications:

`laravel-api` returns `400` for sign-in failure, `400` for validation failure, `400` for
a missing record, `403` only from five `Gate::authorize()` call sites — and **`200` for a
record owned by another user**, because no repository applies an ownership predicate.

`nestjs-api` is disciplined but route-dependent: cross-tenant **read** → `404`
(a deliberate `denyAsNotFound` pattern) or `200 []` for lists; cross-tenant **write** →
`403`; missing tenant context → `400`; integrity refusal → `409`. Its stable machine
oracle is an **`errorCode` field**, not the status code.

An engine hard-coding "2xx = allowed, 401/403 = denied" is wrong on both applications, in
opposite directions. Worse, flagging "expected 403, got 404" as a finding would report
`denyAsNotFound` — a *correct* security pattern — as a vulnerability.

## Decision

Classification is its own stage and its own package (`internal/outcome`), producing:

`ALLOWED` | `DENIED` | `NOT_FOUND` | `ERROR` | `INDETERMINATE`

with these rules:

- **`404` is an accepted manifestation of denial by default.** Not-found and denied are
  distinguished only when the application gives us a reliable signal.
- The classifier accepts **application-supplied signals** — notably a JSON pointer to an
  error-code field plus a value→outcome mapping — so an application with a real contract
  gets a reliable oracle.
- **`INDETERMINATE` is a first-class result.** It produces a blocked coverage entry and
  never a pass, a fail, or a finding.
- The classifier records *why* it classified as it did, so the decision is auditable.

## Alternatives considered

**Status codes only.** Rejected by direct evidence above.

**Body-similarity comparison** (the Burp-extension approach; Auth Analyzer uses a ±5%
body-length rule, Akto a ~90% match). Rejected as a *primary* oracle: it is a heuristic
that produces false positives on dynamic content and cannot distinguish a denial page
from an empty result set. Retained as a possible corroborating signal.

**Force the user to declare it.** Rejected as the only mechanism — it makes the tool
useless out of the box — but supported as an override, which is what the application-
supplied signals provide.

## Consequences

Easier: correct behaviour on applications that do not follow textbook status semantics;
false positives avoided on the correct `denyAsNotFound` pattern.

Harder: more `INDETERMINATE` results out of the box, which looks worse than a tool that
confidently guesses. That is the intended trade — an honest "I could not tell" is worth
more than a confident wrong answer.
