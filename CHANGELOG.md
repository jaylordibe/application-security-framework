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
