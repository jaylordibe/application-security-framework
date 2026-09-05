# ADR-0008: Scope is an allowlist enforced at dial time

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

A scanner that sends a request to a host it was not authorized to test is an attack tool.
This is the most serious threat in `docs/security/threat-model.md` (T-01, T-02).

Naive host checking is insufficient. A hostname can be checked and then resolve to a
different address on the connection attempt (DNS rebinding). A redirect can move the
request to a new host after the check. `169.254.169.254` is reachable from most CI
runners and cloud VMs. IPv6, IPv4-mapped IPv6 and decimal-encoded IPv4 all express the
same address differently.

The framework is also expected to be **easy** against `localhost`, which is the normal
case — so blanket-denying private ranges is not acceptable either.

## Decision

- Scope is an **allowlist**. Nothing is reachable unless the scope grants it. There is no
  deny-list to bypass.
- Scope is evaluated **per request**, and the check is on **both** the hostname and the
  **resolved IP address**.
- The connection is **pinned to the address that was checked**, by performing scope
  evaluation in the dialer. This closes the TOCTOU window that makes DNS rebinding work;
  checking before dialling and connecting afterwards does not.
- **Redirects are never followed automatically.** A redirect is recorded as evidence, and
  its target must pass scope evaluation as a fresh request.
- Private, loopback, link-local, unique-local, multicast and unspecified ranges are denied
  **unless explicitly allowed** — which local assessment does, making it a deliberate act
  rather than an accident.
- **Cloud metadata addresses are denied even when private ranges are allowed.** No
  legitimate assessment target is the metadata service.
- Out-of-scope hosts discovered during an assessment are **recorded and never contacted**.

## Alternatives considered

**Check the URL before the request.** Rejected: loses to DNS rebinding, and to redirects.

**Follow redirects and check afterwards.** Rejected: the request has already been sent.
The damage of an SSRF is in the sending.

**Deny-list of dangerous ranges.** Rejected: allowlists fail closed, deny-lists fail open,
and address encodings make deny-lists leaky.

## Consequences

Easier: a single auditable place that authorizes network access; scope escape becomes a
testable property rather than a hope.

Harder: manual redirect handling in every caller, and a custom dialer rather than the
default transport.

Accepted: some legitimate multi-host applications need explicit scope configuration. That
is the correct trade for a tool whose defining risk is attacking the wrong thing.
