# External engines

AppSec Framework can orchestrate Nuclei, ZAP and Semgrep/opengrep. It does not
reimplement what they do, and it does not believe what they say.

## What AppSec Framework does and does not do

| It does | It does not |
|---|---|
| Supervise the process: explicit argv, no shell, process groups, timeouts, output budgets | Install, download or update any engine |
| Build the environment from nothing, so your credentials cannot reach a scanner | Pass identity credentials to a third-party process |
| Record which binary ran, its version and which corpus | Claim it knows the binary is genuine |
| Normalise results and preserve each engine's own severity and confidence | Convert an engine's severity into its own |
| Account honestly for engines that failed, timed out or never ran | Treat a failed engine as a clean result |
| Ship no templates and no rules | Write a rule corpus or a payload library |

**Every engine result is `observed`.** AppSec Framework's severity for it is
`unassessed`, which has no rank and cannot satisfy a policy threshold. An engine
saying `critical` is that engine's opinion of its own rule. Two engines agreeing
is not verification.

## Installing

Nothing here is installed for you — a security tool that installs software is a
supply chain. `appsec doctor` reports what is present and what each absent engine
would unlock, and changes nothing.

| Engine | Get it from |
|---|---|
| Nuclei | <https://github.com/projectdiscovery/nuclei> |
| ZAP | <https://www.zaproxy.org/download/> |
| opengrep | <https://github.com/opengrep/opengrep> |
| Semgrep | <https://semgrep.dev> |

## Nuclei

```yaml
engines:
  nuclei:
    enabled: true
    executable: /usr/local/bin/nuclei
    templates: ./nuclei-templates
    rateLimit: 50
```

`templates` is **required**. Nuclei will otherwise fetch and use whatever the
public repository holds today, which makes two runs a week apart incomparable and
makes the corpus an unrecorded dependency. Point it at a checkout; if it is a git
checkout the commit is recorded, and if it is not, the report says the corpus is
unpinned.

### Your own templates are unsigned

Nuclei skips templates that carry no signature, and a template you wrote carries
none. So a corpus of your own templates would be excluded in full: Nuclei would
exit successfully, print nothing, and AppSec Framework would report a completed
scan with no findings — having executed no security logic at all.

That run is refused before it starts. If nothing in the directory is signed:

> none of the 12 templates in ./nuclei-templates carries a Nuclei signature, and
> unsigned templates are excluded from execution, so this run would check nothing
> and report no findings.

For your own templates, say so:

```yaml
engines:
  nuclei:
    templates: ./my-templates
    allowUnsignedTemplates: true
```

It defaults to `false` because a template is executable logic aimed at your own
target, and running unverified logic is a decision worth making on purpose. When
you do set it, every observation's provenance and the report's limitations record
that the check was waived — a control you turned off is never reported as one
that held.

A mixed corpus runs, and the provenance says how much of it did: *"40 of 52
templates are signed and the remaining 12 are excluded from execution, so the
corpus that ran is smaller than the directory."*

Hardening applied on every run, checked against Nuclei v3.11.x:

| Passed explicitly | Why |
|---|---|
| `-disable-unsigned-templates` | Templates are executable logic. Defaults to off. Omitted only when you set `allowUnsignedTemplates` — see below. |
| `-no-interactsh` | Out-of-band callbacks otherwise go to a third-party service. |
| `-disable-update-check` | An unannounced network call, and corpus drift mid-run. |
| `-jsonl` | Structured output; terminal text is never scraped. |

Never passed: `-code`, `-headless`, `-allow-local-file-access`,
`-follow-redirects`, `-dashboard`, `-cloud-upload`, `-update-templates`,
`-proxy`, `-interactsh-server`. All default to off; they are listed because "we
did not pass it" is only a control if you can see it was a decision.

**The honest limit:** once Nuclei is running, AppSec Framework cannot constrain
what an individual template does. A template in your corpus can address a host of
its own choosing. Redirects are not followed and OAST is disabled, which narrows
this; it does not close it, and every run says so.

## ZAP

```yaml
engines:
  zap:
    enabled: true
    executable: /opt/zap/zap.sh
    mode: passive        # or: active
```

Run one-shot (`zap.sh -cmd`), not as a daemon, with a private home inside the
run's workspace so a scan cannot accumulate state in your home directory.

- **`passive`** (default) spiders and reports what passive rules observe. It
  requires the `verification` profile.
- **`active`** additionally runs ZAP's active scanner, which sends attack
  payloads. It requires the `intrusive` profile and `authorizeIntrusive`.

A passive run **does not assess injection or cross-site scripting** and does not
claim to: those classes stay in `classesNotAssessed`, because passive rules
observe responses and never send the payloads that would test them.

ZAP runs **unauthenticated**. AppSec Framework does not hand identity credentials
to a third-party engine, so anything reachable only when signed in is unscanned.
That is a deliberate trade, and it is reported on every run.

## Semgrep / opengrep

```yaml
engines:
  sourceRoot: ../my-application
  sast:
    enabled: true
    executable: /usr/local/bin/opengrep
    rules: ./sast-rules
```

Either binary works: opengrep is a fork of Semgrep's engine with the same CLI and
the same `--json` document. opengrep is preferred when both are installed —
Semgrep's metrics default to `AUTO`, which sends telemetry when rules come from
its registry, and those registry rules are licensed for internal use only.

`rules` is **required and must be a local path**. A registry identifier such as
`p/default` or `auto` is refused: it fetches over the network and, for Semgrep,
enables telemetry. `--metrics=off` and `--disable-version-check` are passed
regardless.

**A source observation is not runtime proof.** A matched SQL-injection sink is
not a reachable or exploitable one. Matched source lines are deliberately not
imported: secrets live in source, and a report that quotes it copies your
application into an artefact attached to tickets.

## When something goes wrong

| | |
|---|---|
| Binary missing | `blocked{engine_unavailable}`, naming what is unassessed |
| Crash, or non-zero exit with no results | `blocked{engine_unavailable}` |
| Timeout, output flood | `blocked{budget_exceeded}` — output is refused, never truncated |
| Malformed output | `blocked{engine_unavailable}` |
| Incomplete results | `blocked{budget_exceeded}`, results retained and marked partial, **no coverage claimed** |
| Profile does not permit it | `blocked{safety_policy}` |

None of these is ever an empty result. A scanner that did not run assessed
nothing, and the report says which classes that leaves unassessed.
