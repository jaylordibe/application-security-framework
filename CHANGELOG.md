# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/) — with the caveat that, before 1.0, output
schemas may change between minor versions. Each schema carries its own version string so a
consumer can detect a change rather than misparse.

## [Unreleased]

### Added

- Initial project foundation: research, threat model, architecture and ten ADRs.
- `appsec` CLI with `scan`, `init` and `doctor`, and a documented exit-code contract that
  distinguishes "ran cleanly" from "executed nothing".
- Framework-neutral domain model (`internal/model`) carrying no wire-format tags.
- Scope enforcement as an allowlist, checked on the URL before DNS is emitted and on every
  resolved address at dial time, with cloud-metadata and transition ranges denied.
- Scope-enforcing HTTP client with proxy inheritance disabled, keep-alives disabled,
  Happy Eyeballs disabled, bounded response reading and no automatic redirect following.
- Capture-time secret redaction, including credentials learned at runtime, with HMAC
  fingerprints under a per-run key held outside the report.
- OpenAPI 3.x ingestion with correct security-requirement semantics, external `$ref`
  refusal, and oracle-fidelity grading. Swagger 2.0 is refused rather than half-parsed.
- Access-outcome classification with a first-class `indeterminate` result and support for
  application-supplied error-code signals.
- The `declared-auth-not-enforced` check (CWE-306), with a verification ladder that
  excludes catch-all routes, HTML shells, cached responses, soft denials and
  non-reproducible successes.
- Coverage ledger keyed by (operation, check) with machine-readable blocked causes, plus
  surface-completeness and unassessed-class disclosures.
- JSON and SARIF 2.1.0 reporting; SARIF output is validated against the OASIS schema in
  tests and carries `partialFingerprints` from the first release.
- Run store with atomic writes, `0700`/`0600` permissions, content-addressed evidence and
  path-traversal and symlink refusal.
- Offline evaluation harness with paired known-vulnerable and known-secure fixtures.

### Added — M1: identities and an authenticated control request

- `internal/identity`: a framework-neutral identity model in which a principal holds a
  *reference* to a credential and never the credential itself. Credentials resolve from an
  environment variable or a file; `appsec.yaml` has no field that accepts a value, and no
  CLI flag does either.
- A `Secret` type whose `String`, `GoString` and `MarshalJSON` render a placeholder, so
  `%v`, `%+v`, `%#v`, structured logging, error formatting and whole-struct JSON marshalling
  are all closed at once rather than at every call site.
- Bearer and header API-key authentication. Header names are validated as RFC 9110 field
  names, and headers controlling message framing, the connection or the tool's
  identifiability are refused. Query-string API keys are deliberately not supported.
- An authenticated control request in the declared-auth check. A finding reaches
  `confirmed` only when the control succeeded and its response was materially equivalent to
  the anonymous one — same outcome, status, content type and JSON document shape, with no
  cache hit on the control. Everything else stays `suspected` with the gap named.
- An identity liveness canary on an operator-nominated safe operation, with three states,
  and conservative re-scoring of any work corroborated inside the window between the last
  confirmed-good probe and the first bad one.
- A second coverage dimension, `identity`, so that an authentication limitation is visible
  in the ledger rather than only in a finding's prose. Headline counts filter to the
  `operation` dimension so configuring an identity cannot inflate them.
- `identities` in the JSON report and SARIF run properties, and an
  `assurance.authenticatedControl` statement, because "no confirmed findings" means
  something different depending on whether an authenticated baseline existed.
- `appsec doctor` reports whether each identity's credential is available, by location,
  and never its value.
- Evaluation fixtures for a real bypass, a correctly protected operation, three misleading
  200 responses, a missing credential, a rejected credential, mid-run invalidation, a
  malicious off-origin redirect, and an end-to-end search of the whole run directory for the
  credential.

### Security hardening found by adversarial review of M1

- Refuse to confirm on a cached authenticated control response. An intermediary serving the
  anonymous response back for the authenticated request would have made the two trivially
  equivalent and confirmed a bypass that did not exist. Found by review, reproduced by test,
  and the test fails without the guard.

### Added — M2: two identities and one owned resource (BOLA)

- `internal/resource`: a framework-neutral resource fixture — a stable id, an owner
  identity, a required cross-owner expectation, the values that fill an operation's
  declared parameters, and provenance. It carries no notion of a primary key, foreign key
  or tenant column, because the two reference applications disagree about all of them.
- Safe parameter binding. Values that could change a URL's shape are refused at load
  rather than escaped; binding works from the parsed parameter list, encodes exactly once,
  and re-parses the finished URL to check the origin is unchanged.
- `cross-owner-resource-read`: owner control, cross-owner probe, owner re-check. A denial
  is verified only when the owner could read the resource both before and after and both
  identities are live. A finding is confirmed only when the non-owner's response is
  materially equivalent to the owner's **and** can be tied to that specific resource.
- `cross-owner-resource-write`: read as the owner, write as the non-owner, read as the
  owner again. Confirmed only when the owner's own view changed, field by field. Requires
  the intrusive profile, `authorizeIntrusive`, and an explicit `mutation` block. The
  changed fields are restored as the owner and the restoration is verified; a failure
  becomes run-level tool state.
- A third coverage dimension, `ownership`, keyed by resource and owner as well as by
  operation and identity, so two boundaries differing only in the resource cannot collapse
  into one row. The summary lists the tuples exercised and carries no percentage.
- Resource fixtures also make parameterised operations testable by the declared-auth
  check, which previously reported every one of them as untestable.
- `resources` in `appsec.yaml` with JSON Schema validation, and an `ownership` section in
  the JSON report and SARIF run properties.
- Paired evaluation fixtures: vulnerable and secure applications differing only in whether
  the read is scoped by caller, plus 403 denial, application-error-code denial, shared
  resources, four misleading-200 responses, unreachable fixtures, dead owner and dead
  attacker identities, mid-test resource disappearance, parameter injection, malicious
  redirects, credential isolation under `-race`, and vulnerable/secure/fake-success
  mutation.

### Added — M3: framework adapters (static tier)

- `internal/adapter`: a versioned, schema-validated contract (`appsec.adapter/v1alpha1`) in
  which adapters report *conclusions* — `operation.authentication`,
  `operation.authorization`, `operation.ownership` — rather than framework constructs. The
  core contains no middleware, guard, gate or decorator, asserted mechanically over its
  parsed AST rather than by review.
- Adapter output is treated as hostile input: size-bounded before parsing, version-checked
  before interpretation, strictly decoded, and validated fact by fact. An unknown contract
  version is refused rather than interpreted. An adapter that contradicts itself about one
  subject has **both** assertions withdrawn.
- An execution boundary with an explicit argument vector and no shell, an environment built
  from nothing — not even `PATH`, and never this tool's own credentials — bounded and
  concurrently drained pipes, a timeout, and process-group cleanup.
- Provenance merging. Agreement corroborates, disagreement withdraws the expectation from
  both sources and is reported, and an adapter-only operation is recorded but not tested.
  The adapter states its extraction *method* and the core decides what that is worth; no
  method reaches `observed` or `verified`.
- Reference adapters for Laravel and NestJS that read source and execute nothing, with
  golden and negative fixtures. Both reach the same normalized conclusions from opposite
  syntax: a Laravel route with no auth middleware is unprotected, while a NestJS operation
  with no decorator under a global guard is protected.
- An `adapters` section in the JSON report and SARIF run properties, stating in words that
  a fact is an expectation and not evidence that a control works.
- `docs/adapters/contract.md` for adapter authors in any language, plus
  `schemas/appsec.adapter.schema.json` and a test asserting the schema and the parser
  cannot drift apart.

### Added — M4: external engines

- `internal/proc`: one hardened subprocess supervisor, shared with the M3 adapter boundary
  rather than duplicated. Explicit argument vectors and never a shell, an environment built
  from nothing, process groups so a cancelled child's descendants die with it, `WaitDelay`
  against a held-open pipe, and both pipes drained concurrently and bounded.
- `internal/scanner`: one engine contract every engine shares — identify, detect, gate by
  profile, invoke, normalise — with a private per-run workspace that is always removed.
- External results enter as `observed` and stay there. `ToFinding` takes no state
  parameter, so no caller can produce anything else. AppSec severity is a new
  `unassessed` value with no rank, which cannot satisfy a policy threshold: an unverified
  scanner alert can never fail a build. Each engine's own severity and confidence are
  preserved verbatim in `ExternalSource`.
- Nuclei, with flags verified against v3.11.x rather than remembered:
  `-disable-unsigned-templates`, `-no-interactsh` and `-disable-update-check` passed
  explicitly because they default to unsafe; `-code`, `-headless`,
  `-allow-local-file-access`, `-follow-redirects`, `-dashboard` and `-proxy` never passed.
  Templates must be supplied locally and their provenance is recorded, pinned to a commit
  where the directory is a git checkout.
- ZAP, run one-shot with a private home inside the run's workspace. Passive mode requires
  the verification profile; active mode sends attack payloads and requires intrusive. A
  passive run claims no injection coverage.
- Semgrep and opengrep behind one integration — the fork shares the CLI and JSON document,
  so supporting both cost a name in a list. opengrep is preferred on evidence: Semgrep's
  metrics default to AUTO and its registry rules are licensed for internal use only.
  Registry rule identifiers are refused; `--metrics=off` is always passed.
- Secret-bearing engine fields are never imported: Nuclei's `request`, `response` and
  `curl-command`, and Semgrep's matched source lines. Everything imported is bounded,
  stripped of control characters and passed through the run's redactor.
- An `engines` ledger dimension, an `engines` section in the JSON report and SARIF run
  properties, per-finding engine provenance, and `appsec doctor` reporting each engine's
  version, path and what it would unlock — without installing anything.
- Coverage is earned by what ran. A class leaves `classesNotAssessed` only when an engine
  completed and reported it covered, and even then it stays listed, qualified with the
  engine, version and corpus.
- An adversarial fake-engine suite: engines that hang, fork a surviving grandchild, flood
  stdout, hold a pipe open, crash silently, emit malformed JSON and receive hostile
  arguments containing shell metacharacters.
- Integration tests against the real Nuclei, ZAP and Semgrep/opengrep that skip by name
  when the binary is absent, plus a manual `engine-integration` CI job that installs a
  pinned Nuclei and fails if its test skips. Ordinary CI installs no engine and stays
  deterministic.
- `engines.nuclei.allowUnsignedTemplates`, and a corpus inspection that refuses a template
  directory Nuclei would execute nothing from.
- The terminal summary now states each engine's status and the number of observed external
  results, separately from the confirmed and suspected counts.

### Corrected — M4

- `appsec doctor` previously reported engines as "not implemented yet" and listed them by
  PATH presence alone. It now resolves each executable, asks its version, and says whether
  it is enabled — presence on PATH says a file exists, not that it runs.
- Engine rows were excluded from the headline counters, so a run in which all three engines
  failed printed `blocked: 0`. An engine run is assessment work against the target, and a
  failed one is blocked work: the summary that omits it reads cleaner than the run was.
- `-disable-unsigned-templates` was passed unconditionally. Because an operator's own
  templates are unsigned, that combination meant Nuclei would exclude the whole corpus,
  exit `0`, and produce a completed scan reporting no findings after executing no security
  logic — the precise failure this milestone exists to prevent, caused by a hardening
  measure. The corpus is now inspected before the process starts, an empty or entirely
  unsigned one is refused with an explanation, and a waived signature check is recorded in
  provenance and limitations rather than reported as an enforced control.
- Imported findings carried an empty `id`, which would collapse every external alert into
  one row for any consumer deduplicating on it. They now carry a stable identity derived
  from the engine, rule and location.
- The terminal printed only `findings: 0 confirmed, 0 suspected` after an engine run, so an
  operator whose engine reported a dozen criticals read the summary as "found nothing".
  Observed results are now stated — separately, because folding them into the findings
  total is the promotion this project refuses to perform.
- The CI check forbidding Semgrep registry rule packs matched the code that refuses them.
  A mention must now be annotated as a refusal; anything else still fails.

### Corrected — stale documentation

- The README claimed "One identity at a time… comparing one against another — BOLA, IDOR,
  cross-tenant reads — is the next milestone", which M2 shipped. The bullet contradicted
  another three lines above it and has been removed.
- ADR-0002 ranks framework-native introspection first. It now points at ADR-0014, which
  changed that default on evidence, so a reader of ADR-0002 alone is not misled.

### Corrected — M3

- The M3 acceptance criteria named `artisan` and a TypeScript probe. Both execute the
  inspected repository's code and both require installing dependencies first, which is
  itself code execution: `laravel-api`'s `composer.json` runs `@php artisan
  package:discover` on `post-autoload-dump`, and `nestjs-api/src/main.ts` calls
  `startTelemetry()` at import time. Framework-native extraction is now gated behind an
  explicit trust mode and M3 ships the static tier only. The milestone is marked partial
  rather than claiming a tier it does not implement.

### Corrected

- The M2 acceptance criterion "owner `200` + other `404` is a **proven** denial" was not
  sufficient and has been revised in the roadmap with the evidence. A dead non-owner
  credential, or a resource deleted between the two requests, produces the same pair with
  no access control involved. Verified denials now additionally require both identities to
  be live and an owner re-check after the probe. Removing the re-check makes a
  disappearing fixture report as a verified denial, and the test asserting that is in the
  suite.
- Executed and blocked counts now include cross-owner work. Filtering them to the
  operation dimension alone produced a run that reported two confirmed findings underneath
  the sentence "this assessment executed no checks", which is precisely the contradiction
  the assurance statement exists to prevent.

### Security hardening found by adversarial review of M2

- Refuse to treat a truncated body as resource-identity evidence. Two responses whose
  captured prefixes agree may diverge in the part that was cut, so a prefix match is not
  proof that they describe the same resource.
- Refuse to confirm on a cached owner or cross-owner response, which an intermediary may
  have replayed from the other identity's request.

### Changed

- Adopted the project's final identity: product **Application Security Framework**,
  short name **AppSec Framework**, CLI `appsec`, configuration `appsec.yaml`, runtime
  state `.appsec/`. This reverses the unreleased bootstrap name *Assay*; see
  [ADR-0011](docs/adr/0011-product-identity-application-security-framework.md). Nothing
  had been released under the former name, so no compatibility alias is provided.

### Security hardening found by adversarial review

Each of these was a real defect in the first implementation, found by reviewing the code
rather than the design.

- Refuse YAML alias bombs before parsing: a 426-byte target-supplied document expanded to
  hundreds of millions of nodes and wedged the scanner indefinitely.
- Never propagate parser errors verbatim — the YAML parser echoes a snippet of the
  offending document, ANSI escapes included, straight to the operator's terminal.
- Decide loopback from a parsed address, not a string prefix: `127.0.0.1.nip.io` silently
  enabled private addressing for an entire run.
- Guard the scope policy's out-of-scope host set with a mutex; it is consulted from every
  assessment goroutine and an unsynchronised map is a process-killing concurrent write.
- Stop a target reclassifying its own success as a denial: a response carrying both a
  denial message and substantive content is now `indeterminate`, which blocks the row,
  instead of `denied`, which read as a pass.
- Format numeric error codes correctly — trailing-zero trimming turned `100` into `1` and
  broke every configured mapping.
- Emit a blocked ledger row for every planned item abandoned on cancellation, so a
  cancelled run cannot look cleaner than a completed one.
- Move request pacing into the HTTP client; limiting once per check exceeded the
  configured rate by roughly five times.
- Stop recording a catch-all discriminator as passed when no baseline was established, and
  lower confidence when it could not be.
- Persist captured evidence: findings referenced evidence that was never written.
- Fail the build on suspected high-severity findings, since no finding can reach
  `confirmed` without credentials.
- Discard a trailing margin from truncated bodies, so a secret straddling the capture
  limit cannot survive redaction as a readable prefix.
- Learn credentials from every field of an authentication header rather than guessing
  where a scheme prefix ends.
- Create the parent directory before the symlink containment check, which was otherwise
  skipped for any path whose parent did not yet exist.
- Refuse a connection whose remote address cannot be verified.

### Known limitations

- No BOLA/IDOR, tenancy or multi-identity testing.
- No external engine integrations, and no framework adapters.
- Attack surface comes only from a specification, so undocumented routes are invisible.
- Without configured credentials there is no authenticated control request, so no finding
  can reach `confirmed`.
