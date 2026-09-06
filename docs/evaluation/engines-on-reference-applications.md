# External engines against the reference application

What M4's engine boundary actually did when it was run, and — the more important
half — what it did **not** do, because none of the three engines is installed in
the environment this was evaluated in.

**M4 is partial.** The boundary is implemented, hardened and tested. Nuclei, ZAP
and Semgrep/opengrep were each **blocked as unavailable**, so no assessment in
this document was produced by a real external engine, and none is presented as
though it were.

The blocker is stated plainly rather than worked around: installing an engine
would mean downloading a binary, a JVM or a Python package, and refusing to do
that is the control. AppSec Framework never installs an engine, and neither does
its evaluation.

## What was run

| | |
|---|---|
| Reference application | `jaylordibe/laravel-api` at commit `8302196`, unmodified |
| Target | a local static server on `http://127.0.0.1:8991` — see the caveat below |
| Profile | `verification` |
| Surface | 1 operation, from an OpenAPI file |
| Engines enabled | `nuclei`, `zap`, `sast` |
| Engines executed | **none** |
| Findings | **0**, and the run says so |

**The target is not the reference application running.** `laravel-api` needs
`composer install`, a database and a web server, and standing those up is
outside what this evaluation may do. `engines.sourceRoot` pointed at the real
checkout — which is what a source scanner would have read — and the HTTP target
was a static fixture. Nothing here shows an engine finding a real defect in a
real application, and no claim in this document depends on the target being one.

## Result: three engines, honestly blocked

```
appsec: Nuclei is not available: no nuclei executable was found on PATH and none
is configured at engines.nuclei.executable. Install Nuclei from
https://github.com/projectdiscovery/nuclei and point engines.nuclei.executable
at it. AppSec Framework never downloads or installs an engine. No result from
this engine was imported, and the weakness classes it would have covered remain
unassessed
```

The same shape for `zap` and `sast`. Then:

```
  executed: 0
  blocked:  3
  untested: 1
  findings: 0 confirmed, 0 suspected

  This assessment executed no checks. It establishes nothing about the
  security of the target.
```

Exit code `ExitNothingExecuted`, not `0`.

Three things in that output are the whole point of the milestone:

1. **`blocked: 3`, not `blocked: 0`.** An engine that could not run is charged
   to the ledger as work that did not happen. This was wrong when first written:
   engine rows were excluded from the headline counters, so the run printed
   `blocked: 0` while three engines had failed. Fixed, and
   `TestCountersIgnoreTheIdentityDimension` now pins engine rows *in*.
2. **`findings: 0` is never presented as a clean bill.** A failed engine
   producing zero findings and a successful engine producing zero findings are
   different events, and the second sentence of every blocked message names what
   was lost rather than what broke.
3. **The message says what to do and what AppSec will not do**: install it
   yourself; this tool downloads nothing.

## The boundary, exercised end to end

Since no real engine could run, the full path — invoke, supervise, parse,
normalize, import, report — was exercised with a **stand-in**: a 30-line Go
program that speaks Nuclei's CLI and emits one Nuclei JSONL record. It is not
Nuclei, it finds nothing, and it proves nothing about Nuclei. What it does prove
is what AppSec does with an engine's output, which is the part this repository
is responsible for.

Configured at `engines.nuclei.executable`, with an identity whose bearer token
came from `APPSEC_ADMIN_TOKEN`, and with `GITHUB_TOKEN` and
`AWS_SECRET_ACCESS_KEY` also set in the parent environment:

**The argument vector it received**

```
-target http://127.0.0.1:8991 -templates <corpus> -jsonl -silent -no-color
-no-interactsh -disable-update-check -timeout 10 -retries 1 -rate-limit 50
-output <workspace>/results.json
```

No `-code`, `-headless`, `-allow-local-file-access`, `-follow-redirects`,
`-dashboard`, `-cloud-upload`, `-update-templates`, `-proxy` or
`-interactsh-server`. No shell anywhere: it is a vector, and `execve` received
it as one.

**The environment it received**

```
STAND-IN ENV: LC_ALL=C
```

One variable. Not `APPSEC_ADMIN_TOKEN`, not `GITHUB_TOKEN`, not
`AWS_SECRET_ACCESS_KEY`, not `PATH`, not `HOME`. The environment is built from
nothing rather than filtered from the parent's, which is why this is a property
of the code rather than of the completeness of a deny-list.

**What the record became**

The stand-in reported a `high` severity result whose raw request carried
`Authorization: Bearer SHOULD-NOT-APPEAR`. In the report:

| field | value |
|---|---|
| `state` | `observed` — never `confirmed`, never `suspected` |
| `severity` | `unassessed` — no rank, so it cannot satisfy a policy threshold |
| `externalSource.sourceSeverity` | `high` — the engine's word, kept verbatim, untranslated |
| `verification.performed` | `false` |
| `id` | `nuclei:stand-in-marker:http://127.0.0.1:8991/` |

`high` did not become high. It stayed a quoted claim next to a statement that
AppSec has not assessed it.

**Secret leakage, checked rather than asserted**

Every file under `.appsec/`, plus stdout and stderr, grepped for all four
secrets — the bearer token, the CI token, the cloud key, and the credential the
engine echoed back in its own output:

| secret | occurrences |
|---|---|
| `APPSEC_ADMIN_TOKEN` value | 0 |
| `GITHUB_TOKEN` value | 0 |
| `AWS_SECRET_ACCESS_KEY` value | 0 |
| the `Bearer` token inside the engine's own raw request | 0 |

The last row is not the same control as the first three. Nuclei's `request`,
`response` and `curl-command` fields are never decoded at all, so a credential
the *target* reflects cannot reach a report through them either.

## What the ledger said afterwards

```
engine nuclei: completed (v3.11.1), 1 observation
1 external result is recorded as observed. It is another tool's claim,
unverified by AppSec Framework, and is not counted as a confirmed or
suspected finding.
```

That line is also a defect that this evaluation caught. Before it existed, the
terminal printed `findings: 0 confirmed, 0 suspected` and nothing else — an
operator whose Nuclei reported a dozen criticals would have read the summary as
"found nothing". The count is reported separately rather than folded into the
findings line, because merging them is precisely the promotion this project
refuses to perform.

## What remains unassessed

Everything the three engines exist to cover. Named, because an unassessed class
that nobody names reads as a class with no problems:

- **Nuclei** — known CVEs, misconfigurations and technology fingerprints. Not
  run. Nothing in this repository has been checked against a CVE corpus.
- **ZAP** — passive header, cookie and content findings; and, in active mode,
  injection classes. Not run, passively or actively.
- **Semgrep/opengrep** — source-level patterns in the `laravel-api` checkout.
  Not run. `engines.sourceRoot` was configured and read by nothing.

Plus everything M1–M3 already declares unassessed, which the run's own
`classesNotAssessed` lists: CWE-22, CWE-79, CWE-89, CWE-284, CWE-285, CWE-352,
CWE-639, CWE-770, CWE-915, CWE-918 and business logic.

## What a corpus refusal caught

Configuring Nuclei with a directory of hand-written templates — the normal case
for anyone writing their own — is refused unless the operator says
`allowUnsignedTemplates: true`:

> none of the 1 templates in `<dir>` carries a Nuclei signature, and unsigned
> templates are excluded from execution, so this run would check nothing and
> report no findings.

This was found by writing this evaluation, not by testing. `-disable-unsigned-templates`
was passed unconditionally as a supply-chain control; combined with the refusal
to fetch templates, it meant an operator's own corpus would have been excluded
in full, Nuclei would have exited successfully, and the run would have reported
a completed scan with no findings after executing no security logic at all. That
is the exact failure this milestone forbids, committed by a hardening measure.
Now: refuse, explain, and offer the deliberate opt-in — whose waiver is then
recorded in the provenance of every observation and in the report's limitations,
so a waived control is never described as an enforced one.

## Reproducing this

Real engines, if you have them installed:

```
go test -v -count=1 -run 'FindsAPlantedMarker|ZAPIsDetected' ./internal/scanner/
```

Each test skips with a named reason when its binary is absent. In this
environment all three skipped, and a skip is not a pass. CI installs no engine
and these skip there too; the manual `engine-integration` workflow installs a
pinned Nuclei and fails if its test skips.

The boundary's own properties — descendant cleanup, hung pipes, output floods,
hostile arguments, environment isolation — are proven against purpose-built
hostile fake engines in `internal/scanner/fake_test.go`, deterministically and
with no third-party software.
