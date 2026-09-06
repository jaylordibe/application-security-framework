# ADR-0012: A finding is confirmed only by a live authenticated control that matches materially

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

Until M1 no finding could reach `confirmed`. The declared-auth check could observe that an
unauthenticated request succeeded against an operation the specification marks protected,
but it could not show that the caller received *the protected resource* rather than a
single-page-app shell, a soft error envelope, a cached response or an unrelated public
document. ADR-0006 makes confidence a function of evidence, so with no authenticated
baseline the honest ceiling was `suspected`.

M1 supplies that baseline. The question this record settles is what the baseline has to
demonstrate before a finding may rise, and what must happen when the credential behind it
turns out to be unreliable.

Two failure modes bound the design, and they pull in opposite directions.

**False confirmation.** The naive rule — anonymous 200 plus authenticated 200 equals
confirmed — is wrong on every application that returns a success status for something that
is not the resource. Both reference applications do this. A tool that reports those as
proven authentication bypasses spends its credibility on the first run.

**False assurance.** A credential that is missing, wrong or expired makes authenticated
requests fail. If a failing authenticated request could ever be read as evidence that an
operation is protected, then forgetting to set an environment variable would turn a
vulnerable application green. This is the harm T-15 exists to prevent, and it is worse than
the first, because nobody looks at a clean report.

## Decision

**A finding rises to `confirmed` only when an authenticated control request succeeded and
its response was materially equivalent to the anonymous response.** Everything else leaves
the finding `suspected` with the gap named in `verification.unavailable`.

Material equivalence is a conjunction, evaluated deterministically with no model and no
heuristic scoring:

1. Both responses classify as `allowed` under the existing outcome rules, so a soft denial
   in either is disqualifying.
2. Identical HTTP status.
3. Identical normalised content type.
4. Identical **JSON document shape** — the sorted set of key paths and the type at each,
   with array indices collapsed and values ignored.
5. The control response shows no cache-hit indicator, because a cached control may be the
   anonymous response replayed by an intermediary, which would make the two trivially
   equal.

Shape rather than bytes, because real payloads carry request ids, timestamps and rotating
values, and two identical resources rarely produce identical bytes. Shape rather than
status alone, because that is precisely what a shell or an envelope defeats. Non-JSON
bodies are unmodelled and can never be equivalent: asserting structural equality between
two opaque blobs is a claim the evidence does not support.

**Inference runs in one direction only.** A control that succeeds and matches raises a
finding. A control that is missing, unusable, rejected, erroring or different only ever
leaves it where it was. There is deliberately no branch in which an authentication failure
makes an operation look protected — a finding is raised by an anonymous success and never
by an authenticated failure, so a dead credential cannot manufacture a clean result.

**Liveness is a canary the operator supplies**, not a guessed endpoint. Probing `/me` or
`/whoami` on the assumption they exist yields a 404 on most applications, which is
indistinguishable from an expired credential; the canary would then declare the identity
dead and block the run. The canary runs at the start of a run, at the end, and whenever an
authenticated request returns something consistent with an invalid credential.

**Temporal validity is an interval, not an instant.** A canary observes an expiry when it
next runs, not when it happens, so `(lastGood, firstBad]` is a window in which validity is
genuinely unknown. Work corroborated by a control issued inside that window has its ledger
row set to `blocked{authentication_failed}` and any confirmed finding demoted to
`suspected`. The finding is **not** deleted: the anonymous observation behind it never
involved the credential, so removing it would hide a real bypass. Only the corroboration is
withdrawn.

## Alternatives considered

**Confirm on matching status codes.** Rejected: it is the rule that produces a false
confirmation on every SPA and every application with a 200-carrying error envelope, which
is most of them.

**Confirm on byte-identical bodies.** Rejected in the other direction: volatile fields make
it almost never true, so the check would confirm nothing and M1 would remove no limitation.

**Require a liveness canary before any confirmation.** Rejected. Confirmation already
requires the control request to *succeed*, which is direct evidence that the credential
worked at that moment — a dead credential cannot produce a confirmation whether or not a
canary exists. Requiring one would exclude applications with no suitable safe endpoint for
no safety gain. The absence of a canary is instead recorded, because it bounds what a
*subsequent* expiry can be detected.

**Delete findings whose corroboration is withdrawn.** Rejected: the anonymous access
happened. Deleting the finding would make an expired token hide a real vulnerability, which
is the false-assurance failure wearing a different hat.

**Support query-string API keys.** Deferred. A credential in a URL reaches cache-busting
logic, reproduction strings, transport error text and every intermediary's access log. The
redactor covers known parameter names, but the exposure is broad and the benefit is small
against a header, so the mechanism is refused rather than mitigated. See T-16.

## Consequences

Easier: a confirmed finding now means something specific and checkable — an anonymous
caller received a document structurally identical to the one an authenticated identity
received at the same operation. A reviewer can audit the decision from the published
verification steps without rerunning anything.

Harder: an application whose protected resources are not JSON cannot reach `confirmed`
through this route. That is a real gap, and it is reported as `unavailable` rather than
worked around.

Also harder: the ledger now has a second dimension, so headline counts filter to the
operation dimension. Without that, configuring an identity would inflate the number of
checks a run claims to have executed.

Accepted: two identities running concurrently is now possible structurally, and choosing
between them is not implemented. That is M2.
