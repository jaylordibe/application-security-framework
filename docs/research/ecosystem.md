# Ecosystem research

Status: complete for Phase 0. Conducted 2026-09-05 against primary sources
(project repositories, LICENSE files, official documentation).

Every claim below is either cited or explicitly marked UNKNOWN. Where this document
contradicts widely-repeated community claims, the contradiction is called out, because
several of those claims are stale and acting on them would have produced a wrong design.

---

## 1. Why this document exists

The project brief proposed integrating OWASP ZAP, Nuclei, Semgrep, Playwright and
"Hadrian". Before designing anything we needed to know, for each: what it actually is
today, what it is licensed under, whether it is maintained, whether we may depend on it,
and whether it already does what we intended to build.

Two of the answers changed the product. One changed the licensing posture. One removed a
planned dependency entirely.

---

## 2. ZAP

**License: Apache-2.0.** Unchanged throughout every governance event below.

**Three widely-repeated claims are wrong or stale:**

| Claim commonly repeated | Reality |
|---|---|
| "OWASP ZAP" | ZAP **left OWASP in September 2023** over funding. It is not an OWASP project. A source still calling it "OWASP ZAP" is stale. |
| "ZAP joined the Linux Foundation (2024)" | **False.** The proposed funding was withdrawn and ZAP did not join. |
| "ZAP is a foundation-governed community project" | Since 24 Sept 2024 the three project leads are **employed by Checkmarx** ("ZAP by Checkmarx"). ZAP today sits under **no foundation**. |

Canonical repository remains `github.com/zaproxy/zaproxy`. Stable 2.17.0 (2025-12-15),
weekly `wYYYY-MM-DD` tags, actively developed with three paid full-time maintainers.

**Assessment.** Healthy and better-resourced than ever, but **sponsor-concentrated**: a
single corporate sponsor, whose own commercial DAST product is built on ZAP. The
predecessor funding withdrawal nearly ended the project once.

**Consequence for us.** ZAP is a **swappable engine behind our own interface**. ZAP
vocabulary must never leak into our core model. See ADR-0005.

**Also current, and easy to get wrong:** as of 2026-07-06 ZAP recommends the **Client
Spider** over the AJAX Spider for modern applications. Most CI recipes in circulation
still use the AJAX Spider.

---

## 3. Nuclei

**License: MIT for the engine AND MIT for `nuclei-templates`** — byte-for-byte identical
license text, no supplementary terms, no restriction on commercial or SaaS use, no
restriction on redistributing templates. The recurring "did Nuclei relicense?" rumour is
not supported by the current LICENSE files.

**Do not embed the Go SDK.** `github.com/projectdiscovery/nuclei/v3/lib` is official and
real, but:

- its own README states *"Expect breaking changes… Running nuclei as a service may pose
  security risks."*
- `go.mod` declares **457 require lines (329 indirect)**. Embedding pulls Goja, a
  headless browser, Interactsh and vendor integrations into **our** binary — we would
  inherit Nuclei's entire dependency CVE surface.
- documented non-thread-safe global state (`Global*` methods); `ErrOptionsNotSupported`
  prevents varying some options per concurrent scan; `Close()` tears down a Chromium
  instance, so a missed call leaks processes.

Subprocessing `nuclei -jsonl-export` costs almost nothing (single static binary) and buys
process isolation, independent upgrades and a hard kill switch. See ADR-0005.

**Template execution risk (feeds the threat model).** The `code` and `javascript`
protocols execute arbitrary code **on the scanning host**. Unsigned `code`/`javascript`
templates are rejected before execution (ECDSA; ProjectDiscovery's public key is compiled
into the binary). **But unsigned templates of every other protocol (http, dns, tcp) load
and run with only a warning.** Those cannot execute code on our host, but they can SSRF
from our scanner's network position and exfiltrate via OAST.

Required hardening whenever we invoke Nuclei — see `docs/security/threat-model.md` T-09:

- never pass `-code`
- pass `-disable-unsigned-templates`
- vendor, pin and checksum templates; disable auto-update
- `-restrict-local-network-access` on, `-allow-local-file-access` off
- self-host or disable Interactsh (defaults leak target names to public `oast.*` servers)
- override the defaults of 150 rps / ~625 in-flight, which are internet-scale and will
  degrade a staging application

---

## 4. Semgrep — the licensing premise in the brief was wrong

**The engine never changed license.** `semgrep/semgrep` LICENSE is **LGPL-2.1**, and
Semgrep's own December 2024 announcement says outright *"Semgrep's engine remains LGPL
2.1!"*. "Semgrep OSS" was **renamed** to "Community Edition"; it was not relicensed.
Actively maintained, weekly cadence.

**What actually changed is the rules, and it is restrictive.** The Semgrep Rules License
v1.0 (2024-12-13) states verbatim: *"You may use the rules only for your own internal
business purposes. This license does not allow you to distribute the rules, or to make
them available to others as a service."*

**Consequences — hard constraints on this project:**

- We may **invoke** Semgrep as a subprocess.
- We must **never** vendor, bundle, redistribute, or auto-fetch Semgrep registry rules on
  a user's behalf as part of our product.
- Registry configs (`p/*`) require network access and enable telemetry by default
  (`--metrics` defaults to `auto`). Any invocation must pass `--metrics=off` and prefer
  local rule files.
- **Cross-function taint analysis is a paid feature** (`--pro`, `--pro-intrafile`).
  Semgrep CE analyses interactions within a single function only. We must not claim
  detection quality we cannot deliver with CE.

**Alternative engine: `opengrep`** — LGPL-2.1, forked at Semgrep v1.100.0, actively
maintained, ships standalone native binaries, rule-compatible, same JSON/SARIF output,
and **restores cross-function taint analysis for free**. It solves the *engine* licensing
problem but **not the rule-supply problem**: its own rules repository is archived and its
license status is contested.

**Rule supply that is actually redistributable:** GitLab `sast-rules` (MIT Expat, active,
Semgrep-format). Even so, our posture is to **point users at rules rather than ship
them**.

**Go-native alternatives preferred where they fit:** `gosec` (Apache-2.0, importable Go
library — no subprocess, no rules licensing issue) and `trivy` (Apache-2.0, Go) for
CVEs/IaC/secrets.

---

## 5. Playwright — deferred

Apache-2.0, excellent, actively released. But:

- **No official Go binding.** `playwright-go` is v0.x, single-maintainer, with a
  documented ~4-month release gap.
- Install cost: roughly **650 MB** of browser binaries, a bundled Node runtime, and
  root-level system dependencies, on a **narrow OS matrix** — no RHEL, Fedora, Alpine or
  Arch.

That converts a single static Go binary into a heavyweight, root-requiring,
OS-restricted install **for every user**, including the majority who would never use a
browser.

**Decision: defer.** Keep the engine boundary clean so a browser engine is a leaf
addition. When it is needed, evaluate `rod` (MIT, pure Go, no Node, no root) before an
optional TypeScript Playwright sidecar. Only two Playwright capabilities are genuinely
unmatched in Go — WebKit/Firefox coverage and the trace viewer.

---

## 6. "Hadrian" — the finding that changed the product

The name resolves to three different things. The one that matters:

**`praetorian-inc/hadrian`** — a real, actively developed, **Go, Apache-2.0** API
authorization testing framework. Verified by direct clone on 2026-09-05 (last push
2026-09-04).

It implements what the brief described as this project's *primary differentiator*:

- **`roles.yaml` is a declarative authorization oracle** — roles with numeric privilege
  `level`, permissions as `action:object:scope`, per-endpoint `object` and `owner_field`,
  explicit `anonymous` and `no_header` roles.
- **A permutation engine** cross-testing every attacker/victim role pair against every
  endpoint.
- **Three-phase mutation testing** — `Setup` (victim creates the resource) → `Attack` →
  `Verify`, with `VerifyFieldChanged` (`pkg/templates/template.go:100-225`). Its README
  states verbatim: *"Three-phase mutation testing proves write/delete vulnerabilities
  actually occurred — not just that a 200 OK was returned."*
- SARIF/JSON output and CI gating.

Praetorian also ships **Vespasian** (Go, Apache-2.0) for API discovery, and documents the
pipeline "generate a spec with Vespasian, then pass it to Hadrian".

**`hadrian.io`** is an unrelated commercial ASM company. Disambiguated.

**Verified gaps** (grep over `pkg internal cmd` of the cloned repository):

| Gap | Evidence |
|---|---|
| No coverage or blocked-test accounting | `blocked`/`Blocked`: **0 hits**; `coverage`: 7 hits total |
| No real tenancy model | `org` appears only in a scope-validation list (`pkg/roles/roles.go:114`); `tenant` in Go appears only in test header fixtures |
| Verification is HTTP re-fetch only | no database or target-audit-log evidence; `--audit-log` is Hadrian's *own* output log |
| No framework/source adapters | `roles.yaml` is hand-written or LLM-guessed |

---

## 7. Wider landscape

- **Akto** (MIT, Java, active) — not local-first (MongoDB + dashboard + 4 containers).
  Its BOLA template selects recorded 2xx traffic, sets `replace_auth_header: true`, and
  validates on 2xx plus a ~90% body-similarity match and an error-string denylist.
  **No ownership model, no seeding, no mutation verification.**
- **Burp ecosystem** (Autorize, AuthMatrix, Auth Analyzer, Authz) — **none of them
  verifies a mutation**; all are response-differs (Auth Analyzer's rule is a ±5%
  body-length comparison). None seeds resources. Coverage equals whatever you clicked.
  **Autorize and Authz carry no license at all — do not vendor.** Burp Scanner itself
  documents *"You can only use one authentication method per scan"*, and its broken
  access control check compares authenticated vs **un**authenticated, not user A vs
  user B.
- **RESTler** (MIT, Microsoft Research, thin maintenance) — the one tool pairing stateful
  sequence inference with a genuine two-identity checker, but its oracle is
  **status-code only**.
- **Nuclei** — 10 `idor`-tagged templates, all application-specific CVEs; **none sends an
  `Authorization` header**. Zero generic BOLA templates.
- **ZAP Access Control add-on** — maintained (v13, 2026-06-26) and genuinely
  multi-identity, but its rules are **URL-tree-keyed and GUI-authored**, its API exposes
  only `scan`/`getScanProgress`/`getScanStatus`/`writeHTMLreport` with **no API to define
  rules**, and it reports **HTML only**.
- Schemathesis, OFFAT, CATS: no authorization testing. Cherrybomb, Astra, Metlo dormant;
  APIClarity archived 2026-05-29; Dastardly appears withdrawn.

**Coverage accounting — reporting untested and blocked surface — is absent from every
open-source tool examined, Hadrian included.**

---

## 8. Normalisation is real work

ZAP emits **4 risk levels (no Critical) × 5 confidence levels**. Nuclei emits **5
severity levels and no confidence at all**. These scales do not map onto one another.

This is direct evidence for two design decisions: our model must own severity and
confidence **independently** (ADR-0008), and the source tool's own scale must be
preserved verbatim in evidence rather than silently converted.

SARIF is a better interchange target than ZAP's JSON report because it has a real
external schema. Both tools can emit it.

---

## 9. What this research changed

| Before research | After research |
|---|---|
| Differentiator = multi-identity adversarial authz testing | **Occupied by Hadrian.** Differentiator moved to oracle *derivation* + coverage accounting (ADR-0003) |
| Semgrep = a straightforward integration | Engine is fine; **rules are not redistributable**. Never ship them |
| Nuclei = maybe embed as a library | **Subprocess only.** 457 require lines and a documented "may pose security risks" warning |
| Playwright = browser automation from the start | **Deferred.** ~650 MB + Node + root, narrow OS matrix |
| ZAP = the OWASP community DAST | Not OWASP since 2023, under no foundation, single corporate sponsor. **Swappable engine** |
| Hadrian = evaluate for integration | Real, Apache-2.0, ahead of us. **Optional subprocess engine, never a Go dependency** (ADR-0005) |
