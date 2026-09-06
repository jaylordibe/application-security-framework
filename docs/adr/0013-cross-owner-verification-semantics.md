# ADR-0013: A cross-owner result requires an owner control, a live non-owner, and an owner re-check

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

M2 adds the primitive that finds broken object-level authorization: identity A
owns resource X, identity B asks for it, and B should be refused. The technique is
trivial. Everything difficult is in deciding what the answer means.

The roadmap's acceptance criterion said:

> Owner `200` + other `404` is a **proven** denial; owner `404` means the fixture
> is wrong, which is blocked, not clean.

The second half is right and is implemented. The first half is not sufficient, and
this record documents why, because the gap is a false negative and false negatives
in a security tool are worse than false positives — nobody re-reads a clean report.

Three things can produce "owner 200, other 404" with no access control involved:

1. **The non-owner's credential is dead.** An expired token returns 401 or 404 to
   everything. The boundary is untested and reads as enforced. Forgetting to
   refresh one token would make every application look secure.
2. **The resource stopped existing between the two requests.** The owner read it,
   something deleted it, and B's 404 now means "gone", not "forbidden". This is a
   plain time-of-check/time-of-use gap, and on a live application it is not rare.
3. **The URL addresses nothing.** A mis-typed fixture value produces a 404 for
   everybody. The owner control catches this one, which is why the criterion's
   second half matters.

Two further problems concern the opposite error, confirming a bypass that is not
there:

4. **Shape agreement is not resource identity.** Two orders have the same JSON
   shape. An application that quietly returns *the caller's own* record instead of
   the one requested — a real and common bug, and not a BOLA — matches the owner's
   response perfectly under a shape comparison.
5. **An HTTP success is not a write.** An application with no authorization on its
   update path frequently returns 200 for a write it discarded, because the record
   was filtered out of the query the update ran against, or because the handler
   echoes its input rather than the stored row.

## Decision

**A cross-owner read produces a conclusion only when all three of these hold**, and
the sequence is owner → non-owner → owner:

1. The **owner control** succeeded on the same bound URL. A resource its owner
   cannot read is not an ownership fixture, and the row is
   `blocked{missing_resource}`.
2. Both identities are **usable** under M1's liveness rules. A dead non-owner is
   `blocked{authentication_failed}`, never an enforced boundary.
3. The **owner re-check** after the probe still succeeds. If the resource stopped
   being reachable by its owner, the row is `blocked{missing_resource}` and says
   the resource changed underneath the test.

Only then is the non-owner's outcome meaningful. `denied` or `not_found` is a
**verified denial**, recorded as executed with the reasoning stated. Anything
ambiguous is blocked.

**A read finding is confirmed only when the non-owner demonstrably received the
owner's resource**, which needs both:

- material equivalence to the owner's response (M1's comparison, reused), and
- **resource identity**: a fixture value appearing at the same JSON path in both
  responses, or two byte-identical non-empty bodies.

Neither alone is enough. The second is what separates "B got a document like the
owner's" from "B got the owner's document".

**A write finding is confirmed only by the owner's own view of the resource
changing**, observed by reading as the owner before and after. A field is credited
to the write only if it did not hold the written value before and does after. An
HTTP status is never evidence.

**Ownership expectation is declared, never inferred.** Each fixture states
`crossOwnerAccess: denied` or `allowed`, and there is no default. Assuming every
owned resource is private would report every deliberately shared record — a public
profile, a team-visible document — as a broken access control.

## Alternatives considered

**Compare status codes.** Rejected. One of this project's own reference
applications scopes every query by owner precisely so that another user's record
"is never loaded and the caller gets a 404". Treating 404 as anything but a valid
denial reports correct design as a bug.

**Skip the owner re-check to save a request.** Rejected, and the test that proves
it exists: disabling the re-check makes a fixture that disappears mid-test report
as a *verified denial*. One extra GET is a small price for not inventing a control
that was never tested.

**Confirm a read on material equivalence alone.** Rejected. Disabling the resource
identity check makes an application that returns the caller's own record produce a
confirmed BOLA. Both discriminators are covered by tests that fail when either is
removed.

**Confirm a write on its response status.** Rejected outright; see the
fake-success fixture, which returns 200 and echoes the value while changing
nothing.

**Default `crossOwnerAccess` to denied.** Rejected. It reads as convenience and
behaves as a false-positive generator on every application with shared resources.

**Support cross-owner DELETE.** Deferred. A delete destroys the fixture, so it can
be attempted once and proves nothing a PATCH does not: both test the same
authorization decision on the same object. The instruction to use the least
destructive proof points at the write, and a delete's post-condition — a 404 — is
also the hardest to distinguish from an unrelated failure. Cross-owner writes are
limited to methods that carry configured values.

## Consequences

Easier: a confirmed cross-owner finding states something checkable — this identity
received, or changed, that identity's resource, and here is the owner-side
observation that shows it. A reviewer can audit it from the published verification
steps.

Harder: three requests per read unit and four to six per write unit, against an
application somebody is running. The bound on planned units exists for that reason.

Harder: an API that returns non-JSON, or that echoes no identifier and produces
non-identical bodies, cannot reach `confirmed` on a read. That gap is reported as
`unavailable` rather than papered over.

Accepted: a cross-owner write modifies real data. It requires the intrusive
profile, explicit `authorizeIntrusive`, and an explicit `mutation` block on the
fixture — three separate acts of consent. Restoration is attempted as the owner
and verified, and when it does not work the run says so as tool state rather than
in a detail string nobody reads.
