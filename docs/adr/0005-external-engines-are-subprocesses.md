# ADR-0005: External engines are optional subprocesses, never linked dependencies

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Four candidate engines: ZAP (Apache-2.0, Java), Nuclei (MIT, Go, with an official
embeddable SDK), Semgrep (LGPL-2.1 engine, restrictively licensed rules), Hadrian
(Apache-2.0, Go).

Nuclei is the interesting case because embedding is genuinely available. Against it:
`nuclei/v3/lib`'s own README warns *"Expect breaking changes… Running nuclei as a service
may pose security risks"*; its `go.mod` has **457 require lines (329 indirect)**, so
embedding pulls Goja, a headless browser and vendor integrations into our binary along
with their entire CVE surface; it has documented non-thread-safe global state; and
`Close()` tears down a Chromium instance, so a missed call leaks processes.

Licensing points the same way. Semgrep's engine is LGPL-2.1 — safe to invoke, not to
link. Keeping every engine in a separate process means **no copyleft obligation
propagates** to our Apache-2.0 code.

ZAP adds a governance consideration: no longer an OWASP project, under no foundation, and
dependent on a single corporate sponsor whose own DAST product is built on it.

## Decision

Every external engine is an **optional subprocess** behind one normalized boundary:
identify, report version, report capabilities, check availability, prepare, execute,
collect, normalize, clean up. No engine is bundled, and no engine is a Go module
dependency.

**Hadrian is treated exactly like ZAP and Nuclei** — an optional engine we may invoke,
not a library we import and not a capability we rebuild.

An unavailable, mis-versioned, crashed or timed-out engine produces an explicit
**blocked** coverage entry naming the tool and the surface it would have covered. It
never produces silence, and never a clean result.

Raw engine output is normalized into our own evidence and finding model. Source scales
are preserved verbatim — ZAP emits 4 risks × 5 confidences, Nuclei 5 severities and no
confidence; these do not map onto each other and must not be silently converted.

## Alternatives considered

**Embed Nuclei's SDK.** Rejected on dependency surface, stability warnings and global
state, as above.

**Bundle engines in our distribution.** Rejected: it multiplies our binary size and
licence obligations, and makes us responsible for shipping other projects' security
updates. It is also impossible for Semgrep's rules, which may not be redistributed.

**Require engines to be present.** Rejected: it breaks local-first usability, and the
honest alternative — reporting their absence as blocked coverage — is more truthful.

## Consequences

Easier: engines are swappable and independently upgradable; process isolation gives a
hard kill switch and timeout; no copyleft entanglement; our dependency graph stays small.

Harder: a process boundary to supervise, output to parse hostilely (threat model T-05),
and version drift to detect.

Accepted: users must install engines themselves. Absence is reported, not hidden.
