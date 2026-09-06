# ADR-0015: One engine boundary, and an external alert is only ever an observation

- **Status:** Accepted
- **Date:** 2026-09-06
- **Refines:** [ADR-0005](0005-external-engines-are-subprocesses.md), whose decision this implements

## Context

ADR-0005 settled that external engines are optional subprocesses behind one
normalized boundary, and that source severity scales are preserved rather than
converted. M4 implements that, and implementing it forced three decisions that
record does not make.

**Where the supervision lives.** M3 had already built process-group cleanup,
bounded concurrent pipe draining and environment construction for framework
adapters. Writing a second copy for engines would have meant two chances to
forget the process group, and the cost of forgetting it is a JVM or a Chromium
instance still running after the assessment exits.

**What an engine result *is*.** A scanner alert arrives with the scanner's own
severity, and the temptation is to map it: Nuclei "critical" onto AppSec
critical, ZAP "High (Confirmed)" onto confirmed. That mapping is the single
most damaging thing this milestone could have shipped. Nuclei's severity
describes a template's category. ZAP's confidence describes ZAP's matcher.
Neither is a statement about whether *this* application is exploitable, and
this project's entire thesis is that the difference matters.

**What "assessed" means.** The milestone's purpose is to remove honest
limitations from `classesNotAssessed`. The failure mode is removing them for the
wrong reason: a Nuclei run with three templates does not assess "known
vulnerable components", and a ZAP passive scan does not assess injection at all,
because passive rules observe responses and never send the payloads that would
test it.

## Decision

**One supervisor, in `internal/proc`, shared with adapters.** Explicit argument
vectors and never a shell; an environment built from nothing; the child in its
own process group so cancellation reaches descendants; `WaitDelay` so a child
holding a pipe cannot block `Wait` forever; both pipes drained concurrently and
bounded. Draining one to completion first deadlocks the moment the other fills,
which a hostile process can arrange deliberately.

**External results enter as `observed` and stay there.** `ToFinding` takes no
state parameter: there is no argument any caller could pass that would produce
anything else. AppSec severity is `unassessed`, a value with no rank, so an
unverified alert cannot satisfy a policy threshold and cannot fail somebody's
build. The engine's own severity and confidence are preserved verbatim in
`ExternalSource`.

**Agreement between engines is not verification.** There is no rule anywhere
that promotes a finding because two tools reported it. Two tools being wrong the
same way is the normal case, not corroboration.

**Coverage is earned by what ran, not by what launched.** A capability leaves
`classesNotAssessed` only when an engine *completed* and its normalizer reported
the class covered — which a blocked run, a partial run and a passive ZAP scan
all decline to do. Even then the class is *qualified* rather than removed: it
stays in the list carrying the engine, its version and its corpus, because
"assessed by Nuclei against these templates" and "assessed" are different claims.

**Engines are a fixed registry, not a command runner.** There is no `command`,
`args` or `env` an operator can set. Those would make AppSec Framework a shell
runner wearing a security tool's name, and every hardening here would become
something a YAML file could opt out of. Adding an engine is a code change with
tests.

**Corpora are supplied and recorded, never fetched.** Nuclei refuses to run
without an explicit template directory and Semgrep/opengrep without local rules.
Letting either fetch its own makes two runs a week apart incomparable and makes
the corpus an unrecorded dependency. A git checkout is pinned by commit; anything
else is reported as unpinned.

**Provenance is honest about what cannot be established.** Every run records the
resolved executable path and the tool's self-reported version, and every one sets
`Verified: false`. AppSec cannot establish that a binary named `nuclei` is a
genuine ProjectDiscovery build, and says so rather than implying a chain of
custody it has not checked.

## Alternatives considered

**Map engine severity onto AppSec's scale.** Rejected; see above. The
`unassessed` severity exists precisely so the honest answer is expressible.

**Promote a finding when two engines agree.** Rejected explicitly. It is
superficially attractive and it is a correlation between two tools' false
positives.

**Let engines run concurrently.** Rejected. Each may start a JVM, a browser or a
scan of a whole application, and running them together multiplies the load on a
system somebody is operating, for no benefit: nothing needs the results until the
assessment finishes.

**Run ZAP as a daemon and use its API.** Rejected for M4. A daemon means a port,
an API key, a lifecycle and a whole class of "did it really stop" questions.
`zap.sh -cmd` runs to completion and exits, which is the smallest thing that
works.

**Pass identity credentials to ZAP so it can scan authenticated surface.**
Rejected for M4. It would hand this tool's bearer tokens to a third-party process
running against an untrusted target, and the resulting coverage is not worth
that. The consequence — everything reachable only when signed in is unscanned —
is stated in the report rather than quietly accepted.

**Choose between Semgrep and opengrep.** Rejected as a false choice: opengrep is
a fork of Semgrep's engine with the same CLI and the same `--json` document, so
supporting both costs a name in a list. opengrep is preferred when both are
installed, because Semgrep's metrics default to AUTO — telemetry when rules come
from its registry — and its registry rules are licensed for internal use only.

## Consequences

Easier: adding a fourth engine is an `Engine` implementation and a registry
entry; it inherits every hardening automatically. A reader of a report can tell
which tool said what, which version, against which corpus, and what AppSec
Framework itself concluded, which is nothing.

Harder: an operator must install and configure engines and supply corpora. That
is the cost of not being an installer, and the roadmap's alternative — fetching
binaries and rules — would put a supply chain inside a security tool.

Accepted: AppSec Framework cannot constrain what an individual Nuclei template or
ZAP rule does once the engine is running. Redirects are not followed, out-of-band
interaction is disabled, unsigned templates are refused and no proxy is set, but
a template in the supplied corpus can still address a host of its own choosing.
That is outside this tool's authorization boundary and is reported as a
limitation rather than papered over.
