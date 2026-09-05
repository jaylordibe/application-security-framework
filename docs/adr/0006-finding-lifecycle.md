# ADR-0006: Finding lifecycle, and severity separate from confidence

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The proposed lifecycle was
`OBSERVED → SUSPECTED → VERIFICATION_REQUIRED → CONFIRMED/REJECTED → REMEDIATED →
VERIFIED_FIXED`.

Two problems on inspection. `VERIFICATION_REQUIRED` is not a state a finding is *in* — it
is a statement about what the finding still needs, which is derivable from its evidence.
And `REMEDIATED` / `VERIFIED_FIXED` are not properties of a finding within one
assessment; they are conclusions from **comparing two assessments**. Modelling them as
states of a single finding would mean a single run could claim a fix it never observed.

Separately, research showed engines disagree fundamentally on grading: ZAP emits 4 risk
levels (no Critical) × 5 confidence levels; Nuclei emits 5 severities and **no confidence
at all**. There is no faithful mapping between them.

## Decision

Within one assessment a finding is in exactly one of:

`OBSERVED` → `SUSPECTED` → `CONFIRMED` | `REJECTED` | `BLOCKED`

- **`OBSERVED`** — something was seen. All external engine output enters here.
- **`SUSPECTED`** — the observation matches a vulnerability hypothesis with a defined
  verification strategy.
- **`CONFIRMED`** — the verification strategy for that vulnerability class succeeded.
- **`REJECTED`** — verification actively disproved it. Reported, because a rejected
  hypothesis is useful information about a wrong oracle.
- **`BLOCKED`** — verification could not be performed. Never silently a pass or a fail.

`REMEDIATED` and `VERIFIED_FIXED` belong to assessment **comparison** and are out of scope
for a single run.

**Severity and confidence are independent and never derived from each other.** Severity
answers "how bad if real"; confidence answers "how sure are we it is real", and is a
function of **evidence quality and verification state only** — never of a model's
confidence language, and never of how many tools agreed.

`HIGH` severity with `LOW` confidence is a valid, expected, reportable combination.

## Alternatives considered

**Keep the six-state lifecycle.** Rejected: two states were not states, as above.

**Confirm on scanner agreement ("two scanners agree = confirmed").** Explicitly rejected.
Two tools sharing a heuristic share its false positives; agreement is correlation, not
verification. Verification requirements differ by vulnerability class, and that is the
whole point.

**A single risk score.** Rejected: it destroys the distinction that makes findings
actionable and is exactly the security theatre this project exists to avoid.

## Consequences

Easier: engine output can be ingested without pretending it is confirmed; AI can later
propose hypotheses without being able to confirm anything, enforced by the model rather
than by convention.

Harder: consumers must handle two axes instead of one, and reports must present
`BLOCKED` prominently rather than hiding it.
