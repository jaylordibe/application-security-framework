# Security policy

AppSec Framework is security software that deliberately connects to hostile applications,
stores captured credentials, and executes third-party tools. Its own attack surface is
treated accordingly: see [docs/security/threat-model.md](docs/security/threat-model.md).

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's advisory workflow:
<https://github.com/jaylordibe/application-security-framework/security/advisories/new>

Please include the version (`appsec --version`), your platform, a minimal reproduction, and
what you believe the impact is. If you cannot use GitHub advisories, open a public issue
containing **only** a request for a private contact channel and no details.

We aim to acknowledge within 7 days. There is no bug bounty.

## What counts as a vulnerability in AppSec Framework

These are the classes we consider most serious in our own code:

| Class | Why it is critical |
|---|---|
| **Scope escape** | Any way to make AppSec Framework send a request to a host the scope policy did not authorize. This is our highest-severity class: a scanner that contacts the wrong host is an attack tool. Includes DNS rebinding, redirect handling, proxy handling, and address-encoding bypasses. |
| **Secret leakage** | A credential, token, cookie or session value reaching a report, a log line, a terminal, or an un-redacted file on disk. |
| **Execution from untrusted input** | Any path where a target-controlled value (a specification, a response body, an engine's output, a filename) causes code execution, a shell invocation, an arbitrary file read or write, or a path traversal. |
| **False assurance** | A run that reports success while silently failing to test what it claimed to. A crashed engine, an unreachable target, or an ambiguous outcome being rendered as a pass is a security bug in this project, not a cosmetic one. |
| **Safety-profile bypass** | Any way for a state-changing request to be sent under a profile that does not permit it. |

The last two are unusual entries in a security policy. They are here because misleading a
user into believing an application was assessed is the most likely real-world harm this
tool can cause.

## Supported versions

Pre-1.0, only the latest release is supported. Output schemas
(`appsec.report/v1alpha1`, `appsec.run/v1alpha1`, `appsec/v1alpha1`) may change between
minor versions; each is versioned so a consumer can detect the change rather than misparse.

## Using AppSec Framework safely

- Assess only what you own or are **explicitly authorized in writing** to test.
- Prefer disposable environments for anything beyond the `verification` profile.
- `.appsec/` contains captured HTTP evidence. Redaction runs at capture time, but it is a
  mitigation and not a guarantee. Do not commit it; the shipped `.gitignore` excludes it.
- Treat a report as sensitive: it describes weaknesses in a real system.

## Our own supply chain

- Direct dependencies are deliberately few and each is justified in
  [docs/dependencies.md](docs/dependencies.md).
- `govulncheck` runs in CI and is reachability-based, so it reports whether a vulnerable
  symbol is actually callable from our code.
- CI actions are pinned by commit SHA, not by tag.
- No installation path in our documentation pipes a network response into a shell.
- No external security engine is bundled. Nothing is downloaded at runtime.
