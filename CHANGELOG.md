# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/) — with the caveat that, before 1.0, output
schemas may change between minor versions. Each schema carries its own version string so a
consumer can detect a change rather than misparse.

## [Unreleased]

### Added

- Initial project foundation: research, threat model, architecture and ten ADRs.
- `assay` CLI with `scan`, `init` and `doctor`, and a documented exit-code contract that
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
