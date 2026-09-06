# Threat model: AppSec Framework itself

This is security software that will deliberately connect to hostile applications, execute
third-party scanners, and store captured credentials and personal data. Its own attack
surface must be treated as seriously as the targets it assesses.

Scope: the `appsec` CLI, its configuration, its adapters and engines, its evidence store
and its reports.

The status of each control is load-bearing, because claiming a control is implemented when
it is not would be the exact failure this project exists to prevent:

| Status | Meaning |
|---|---|
| **TESTED** | Implemented in this repository **and** covered by a test that demonstrates the control, named below. |
| **IMPLEMENTED** | Implemented, but not yet covered by a test that would catch its regression. |
| **DESIGNED** | The boundary exists; the capability it protects is not built yet. |
| **PLANNED** | Neither exists. |

Nothing here is marked TESTED without a test that fails if the control is removed.

---

## 1. Trust boundaries

```
        UNTRUSTED                          |  TRUSTED
------------------------------------------ | ---------------------------
 target HTTP responses, headers, bodies    |  appsec.yaml (user-authored)
 HTML, JavaScript, redirects               |  the operator's intent
 OpenAPI / GraphQL documents               |  the local filesystem we own
 target source repositories                |
 external scanner output (ZAP/Nuclei/...)  |
 adapter probe output                      |
 database rows and audit logs read as      |
   evidence                                |
 scanner templates and rules               |
```

**Everything on the left is data, never instruction.** It is never interpolated into a
shell, never used to construct a filesystem path, never used to decide what to attack,
and — when AI is eventually introduced — never treated as a prompt.

The configuration file is trusted because the operator wrote it. It is nonetheless
validated strictly, because a trusted author still makes mistakes and because a
configuration file may arrive via a pull request.

---

## 2. Threats

### T-01 Scope escape — the scanner attacks something it was not authorized to attack

The single most serious threat. An assessment tool that wanders off-target is an attack
tool. Vectors: a redirect to another host; an absolute URL in an OpenAPI `servers` entry;
a `Location` header pointing at cloud metadata; a hostname resolving to a different
address on the second lookup (DNS rebinding); IPv6 and IPv4-mapped representations of the
same address; DNS names that resolve to loopback.

**Controls**

- Scope is an allowlist and is the *only* thing that grants permission to send a request.
  Scope entries carry scheme, host, port and optional path prefix, so a grant for
  `https://api.example.com` does not authorize `http://api.example.com:9200`.
  **TESTED** (`scope.TestHostAllowlistIsExact`, `TestPortIsPartOfScope`,
  `TestPathPrefixConfinesGrant`).
- The URL is evaluated **before any name resolution**, so an out-of-scope host generates no
  DNS traffic — resolving a host in order to reject it would itself be a callback to
  attacker-controlled infrastructure. **TESTED** (`httpx.TestOutOfScopeURLSendsNoPacket`,
  which fails if the resolver or the dialer is called at all).
- Every **resolved address** is evaluated at dial time and the connection is made to a
  literal checked IP, closing the TOCTOU window that makes DNS rebinding work. If *any*
  returned address is forbidden the whole dial is refused, because a rebinding target
  returns both a permitted and a forbidden address. **TESTED**
  (`httpx.TestRebindingResolverIsRefused`, `TestAnyForbiddenAddressRefusesTheDial`).
- Three transport defaults that would silently defeat the above are overridden:
  `Proxy` is nil (`ProxyFromEnvironment` would hand the dialer the proxy's address while
  the real target travels inside CONNECT), keep-alives are disabled (pooled connections
  skip the dialer entirely), and Happy Eyeballs is disabled (dual-stack racing can connect
  to an address that was not evaluated). **IMPLEMENTED** (`internal/httpx`).
- Redirects are **never followed automatically**; a redirect is captured as evidence and
  its target must pass scope evaluation as a fresh request. **TESTED**
  (`httpx.TestRedirectsAreNotFollowed`, which asserts the redirect target's request
  counter is zero).
- Hostnames are normalised — lowercased, trailing dot stripped, IDN converted to ASCII —
  before comparison. **TESTED** (`scope.TestHostAllowlistIsExact`).
- Private, loopback, link-local, unique-local, multicast and unspecified ranges are denied
  unless the operator opts in, which local assessment does deliberately rather than
  accidentally. **TESTED** (`scope.TestDefaultDeniesLoopback`).
- Out-of-scope hosts discovered during an assessment are **recorded, never contacted**.
  **TESTED** (`scope.TestOutOfScopeHostsAreRecordedNotContacted`).
- The convenience that enables private addressing for a loopback target parses the host as
  an **address**, never as a string prefix. A prefix test would treat an
  attacker-registrable name such as `127.0.0.1.nip.io` as loopback and silently permit
  private addressing for the whole run. **TESTED**
  (`cli.TestLoopbackDetectionUsesAddressesNotPrefixes`).
- A connection whose remote address cannot be verified is **refused**, not accepted.
  **IMPLEMENTED**.
- Callback/OAST behaviour requires explicit configuration. **DESIGNED**.

### T-02 The scanner is used as an SSRF weapon

A hostile or careless target can attempt to make our privileged network position useful
to it — we may sit inside a VPN, a CI runner, or a cluster with access to metadata
endpoints.

**Controls.** Same as T-01, plus a deny list applied *after* IPv4-mapped unwrapping and
zone-identifier stripping, covering cloud metadata for AWS/Azure/GCP, Alibaba and Oracle;
link-local; and the transition ranges that embed IPv4 addresses and can therefore reach
metadata by another spelling — NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo
`2001::/32` — plus CGNAT and the unspecified addresses that route to loopback on Linux.
These stay denied **even when private addressing is enabled**, which is the normal
configuration for local assessment. **TESTED**
(`scope.TestMetadataDeniedEvenWithPrivateAllowed`, `TestIPv4MappedIPv6IsUnmapped`,
`TestTransitionRangesDenied`, `TestUnspecifiedAddressDenied`).

### T-03 Hostile responses exhaust or corrupt the scanner

An infinite body, a decompression bomb, a multi-gigabyte header set, a slow-loris trickle,
or a redirect cycle.

**Controls.** Bounded response reading with an explicit byte cap that never trusts
`Content-Length`, recording truncation so a report cannot imply the body was complete;
per-request timeouts honouring context cancellation; capped response header bytes.
**TESTED** (`httpx.TestBodyIsBounded` against a server that streams indefinitely,
`TestContextCancellationIsHonoured`).

Request pacing also protects the *target*: a scanner that trips a WAF sees every later
response as a denial and reports a falsely clean result. Pacing is enforced in the HTTP
client, not in the assessment loop — a single check issues several requests, so limiting
once per check exceeded the configured rate by that factor. **IMPLEMENTED**
(`internal/httpx`).

### T-04 Command injection through configuration or target-controlled data

Environment lifecycle commands, adapter probes and scanner invocations all execute
processes. A target-controlled string reaching a shell would be catastrophic.

**Controls**

- **No shell, ever.** Process execution will use explicit argument vectors
  (`exec.CommandContext` with `argv`), never a shell string. **DESIGNED** — AppSec
  Framework currently executes no subprocesses at all, which is why this is not marked implemented.
- YAML decoding is hardened against the non-shell execution paths: the decoder is never
  given `ReferenceFiles` or `ReferenceDirs`, which would let a configuration file pull
  anchor definitions from arbitrary filesystem paths, and input is size-capped because
  alias expansion is an exponential-blowup denial of service. **TESTED**
  (`config.TestOversizedInputIsRefused`, `TestUnknownFieldsAreRejected`).
- "No shell" is not the whole of "no untrusted execution or file access": see T-08 for the
  filesystem paths and T-05 for `$ref` resolution.
- Target-controlled data is **never** placed in an argument vector position that a tool
  interprets as a flag; values are passed via files or after `--` where the tool supports
  it.
- Environment lifecycle commands come only from configuration, are `argv` arrays rather
  than strings, and are **opt-in per run**. **DESIGNED**.

### T-05 Malicious scanner or adapter output

Scanner output is parsed by us. A hostile target can influence it (a reflected payload
becomes a finding title). Output may be enormous, malformed, or contain terminal escape
sequences that rewrite the operator's terminal.

**Controls.** For the untrusted input that AppSec Framework *does* parse today — OpenAPI documents,
which for one reference application are fetched from the target itself:

- **External `$ref` is refused outright**, not resolved. A hostile document containing
  `$ref: "file:///etc/passwd"` or `$ref: "http://169.254.169.254/..."` would otherwise
  produce arbitrary local file read and SSRF through the *parser*, entirely outside the
  scope-enforced HTTP client. Each refused reference is recorded as a coverage gap rather
  than silently dropped. **TESTED** (`openapi.TestExternalRefsAreRefusedAndRecorded`).
- Local pointer resolution is depth-bounded, defeating reference cycles. **IMPLEMENTED**.
- Document size is capped — but a size cap does **not** bound expansion cost. YAML alias
  expansion is exponential, so a 426-byte document of nested anchors expands to hundreds
  of millions of nodes and wedges the process indefinitely. Alias use is therefore
  counted and refused above a low threshold before the parser is invoked, the
  post-expansion size is checked, and conversion runs under a wall-clock bound. A
  legitimate specification uses `$ref`, not YAML anchors. **TESTED**
  (`openapi.TestOversizedDocumentIsRefused`, `openapi.TestYAMLAliasBombIsRefused`).
- The number of declared operations is capped, so one document cannot turn a bounded
  assessment into an unbounded one. **IMPLEMENTED**.
- Parser errors are **never propagated verbatim**: the YAML parser echoes a snippet of
  the offending document, control characters and ANSI escapes included, which would
  otherwise reach the operator's terminal through the CLI's error path.
  **IMPLEMENTED**.
- Swagger 2.0 is **refused** rather than half-parsed, because a partially understood
  document produces a confidently wrong attack surface. **TESTED**
  (`openapi.TestSwagger2IsRefused`).
- All target-controlled strings have C0/C1 control characters stripped and are
  length-bounded before they can reach a terminal or a report, so a hostile document
  cannot rewrite an operator's screen with ANSI escapes. **TESTED**
  (`openapi.TestControlCharactersAreStripped`).
- The JSON Schema validator used in tests is given no remote loader, so a remote `$ref`
  fails closed rather than reaching the network. **IMPLEMENTED**.

For scanner output specifically: **DESIGNED** (no engine integrations exist yet).

### T-06 Evidence contains secrets, credentials and personal data

The most likely real-world harm from this tool is not a broken scan — it is a captured
`Authorization` header committed to a repository or pasted into an issue.

**Controls**

- Redaction is applied **at capture time**, not at render time, so a secret never reaches
  disk. **TESTED** (`httpx.TestSensitiveHeadersAreRedactedInEvidence`).
- Sensitive headers are replaced entirely, case-insensitively. **TESTED**
  (`redact.TestSensitiveHeadersAreReplacedEntirely`).
- Credentials **learned at runtime** — a session cookie or refresh token the target issues
  mid-run — are added to the deny-list and redacted from every later capture. A static
  deny-list alone would miss exactly the credentials an assessment causes to exist.
  **TESTED** (`redact.TestRuntimeCredentialsAreLearned`,
  `TestBearerTokenValueIsLearnedWithoutScheme`).
- Registered secrets are matched in base64 and percent-encoded forms as well as raw.
  **TESTED** (`redact.TestEncodedFormsAreRedacted`).
- Credentials are learned from every substantial whitespace-delimited field of an
  authentication header, not by guessing where a scheme prefix ends. A fixed prefix
  heuristic misses long schemes such as `SharedAccessSignature`, leaving the token
  unregistered. **TESTED** (`redact.TestLongAuthSchemesAreLearned`).
- A truncated body discards a trailing margin, because redaction runs after capture and a
  secret straddling the cut would survive as a prefix that no longer matches any pattern —
  a JWT sliced mid-signature is still readable base64. **IMPLEMENTED** (`internal/httpx`).
- High-signal shapes (JWTs, vendor key prefixes, PEM private-key headers) are redacted
  without registration. **TESTED**
  (`redact.TestHighSignalPatternsRedactedWithoutRegistration`).
- URLs have userinfo and sensitive query parameters redacted, and **error strings have
  query strings stripped** — Go's `*url.Error` renders the full URL, so any transport
  failure would otherwise write `?api_key=…` into evidence. **TESTED**
  (`redact.TestErrorStringsHaveQueryStringsStripped`,
  `httpx.TestQuerySecretsRedactedInCapturedURL`).
- Fingerprints are **HMAC-SHA256 under a per-run key**, truncated, with the key stored in
  the run directory and never in a report. Values below a length threshold are not
  fingerprinted at all, because a bare hash of a PIN, a six-digit code or a numeric
  identifier is brute-forceable by anyone holding the report — and a stable keyless hash
  would correlate the same secret across reports and customers. **TESTED**
  (`redact.TestShortValuesAreNotFingerprinted`,
  `TestFingerprintIsStableWithinRunAndDiffersAcrossRuns`).
- Run directories are `0700`, files `0600`, on platforms that enforce them. **TESTED**
  (`store.TestRunDirectoryIsOwnerOnly`). On Windows `os.Chmod` only toggles a read-only
  attribute, so the CLI **warns** rather than implying a protection that does not exist.
- Configuration is not persisted into the run directory, so operator credentials cannot
  reach it. `.gitignore` excludes `.appsec/`, and `meta.json` warns whoever finds the
  directory later. **TESTED** (`store.TestMetaIsWritten`).
- Un-redacted capture is not available. If it is ever added it must be per-run, explicit,
  and loudly recorded in the report. **PLANNED**.

### T-07 Report and evidence leakage

Reports are the artefact most likely to be shared, attached to a ticket, or uploaded to
CI. They inherit every secret the evidence holds.

**Controls.** Reports render already-redacted evidence; there is no un-redacted path.
Output paths are validated and confined, and emitted files are `0600`. JSON output escapes
HTML-significant characters. **IMPLEMENTED** for JSON and SARIF.

A future HTML report must escape all target-controlled content — an XSS in our own report,
delivered by the application we were assessing, would be a real vulnerability. **PLANNED**.

### T-08 Path traversal, symlinks and unsafe temporary files

Target-controlled names (an OpenAPI `operationId`, a scanner rule id, a hostname) must
never become a filesystem path.

**Controls.** Evidence is addressed by SHA-256 of its redacted content, never by a
target-supplied name. Run identifiers are validated against a strict character set rather
than trusted. Paths are cleaned and checked for containment lexically, the parent is created, and only
then is containment re-checked against the symlink-resolved parent — checking before
creating would skip the symlink gate entirely for any directory that does not yet exist.
A resolution failure is a refusal, not a pass. Writes go to
a temporary file that is `chmod`-ed before an atomic rename, so the destination never
exists with permissive modes and a reader never observes a partial file. **TESTED**
(`store.TestPathTraversalIsRefused`, `TestRunIDIsValidated`,
`TestSymlinkedParentIsRefused`, `TestWritesAreAtomic`,
`TestEvidenceIsContentAddressedAndIdempotent`).

### T-09 Compromised or hostile scanner templates and rules

Nuclei's `code` and `javascript` protocols execute arbitrary code **on the scanning
host**. Unsigned templates of other protocols still load with only a warning and can SSRF
from our network position.

**Controls (all DESIGNED — no scanner integration exists yet).** Never pass `-code`; pass
`-disable-unsigned-templates`; vendor, pin and checksum templates rather than
auto-updating; `-restrict-local-network-access` on and `-allow-local-file-access` off;
self-host or disable Interactsh, whose defaults leak target names to public `oast.*`
servers; override internet-scale rate defaults. Recorded here so the integration cannot be
written without them.

### T-10 Supply-chain compromise of our own dependencies

We are a security tool; a backdoored dependency is a supply-chain attack on everyone who
runs us.

**Controls.** Six direct dependencies, each justified in `docs/dependencies.md`, with an
ADR required to add another. `go.sum` and the Go checksum database. `govulncheck` in CI
per-change and weekly, reachability-based rather than version-matching. CI actions pinned
by commit SHA, not by tag. No documented workflow pipes a network response into a shell.
No engine is bundled and nothing is downloaded at runtime. **IMPLEMENTED**.

### T-11 Unsafe adapter and plugin execution

Adapters are out-of-process probes that may run inside the target's runtime, and a
repository under assessment is untrusted.

**Controls.** Adapters are opt-in per run, never auto-discovered from the target
repository, never executed merely because a repository contains a manifest, and are
invoked with explicit `argv`. Adapter output is parsed with the same hostility as scanner
output, is size-capped, and is schema-validated before it can influence a plan.
**DESIGNED**.

### T-12 Destructive or state-changing tests running accidentally

The framework will eventually send requests that change data.

**Controls.** Three strictly ordered profiles. Required impact is computed per
**(check, operation)** rather than per check — a check that iterates a specification would
otherwise send an unauthenticated `DELETE` under a read-only profile, destroying data
while proving the very weakness it was hunting. Unsafe methods require `intrusive`; work
exceeding the effective profile is **not executed and is recorded as blocked with a
reason**. The gate fails closed on an unrecognised profile. Selecting `intrusive` is not
itself authorization: `authorizeIntrusive` must also be set. Authentication routes are
excluded from anonymous sweeps by default, because sweeping them can lock real accounts.
**TESTED** (`model.TestProfileGateFailsClosed`, `TestUnsafeMethodsRequireIntrusive`,
`engine.TestUnsafeMethodsAreBlockedBelowIntrusive`, `TestAuthRoutesAreExcludedByDefault`,
`config.TestIntrusiveProfileRequiresExplicitAuthorization`).

### T-13 Concurrent assessments interfere

**Controls.** Each run owns a directory keyed by a time-ordered id with a random suffix,
so two runs started in the same second cannot collide. The coverage ledger, the redactor
and the scope policy's record of out-of-scope hosts are all mutex-guarded — the scope
policy is consulted from every assessment goroutine, so an unsynchronised map there is a
process-killing concurrent write rather than a data-quality problem. Evidence writes are
atomic and idempotent, and every output slice is sorted before rendering so concurrent
execution cannot change the bytes produced. **TESTED** under `-race`
(`scope.TestConcurrentCheckURLIsSafe`, `store.TestConcurrentEvidenceWritesAreSafe`,
`engine.TestResultOrderingIsDeterministic`, `redact.TestConcurrentUseIsSafe`).

### T-14 Prompt injection when AI is eventually introduced

Source comments, HTTP responses, OpenAPI descriptions, database values and scanner output
are all attacker-controlled and would all be candidate model input.

**Controls (PLANNED — no AI exists in this repository).** Target-controlled content is
passed as clearly delimited data, never as instruction. Model output may only *propose* a
hypothesis; it can never mark a finding confirmed. Every AI-derived fact carries
`inferred` provenance and requires deterministic verification before it can change a
finding's state. This constraint is enforced by the finding model itself (ADR-0006), not
by convention.

### T-15 False assurance — the framework's own most likely harm

A clean report that hides the fact that nothing meaningful was tested is the failure mode
most likely to hurt a real user, and the one this project was created to fix.

**Controls.**

- Every report opens with an `assurance` block whose statement is written to survive being
  quoted alone, and which states plainly that the run does not establish the target is
  secure. **TESTED** (`report.TestBuildCountsAndAssurance`).
- A run that executed **no** checks says it "establishes nothing", returns a distinct exit
  code (3, not 0), and reports `executionSuccessful: false` in SARIF. **TESTED**
  (`report.TestZeroExecutedChecksStatementIsUnambiguous`,
  `TestSARIFInvocationReflectsExecution`, `cli.TestAllBlockedRunDoesNotReportSuccess`).
- Every ledger row carries a machine-readable cause; consumers are told to treat an
  unrecognised cause as blocked rather than as success.
- The ledger discloses that its denominator is the **specification**, so undocumented
  routes are not merely untested but invisible — otherwise coverage would be measured
  against a surface supplied by the thing being audited.
- `classesNotAssessed` names the weakness classes nothing in the run examined, so "no
  findings" cannot be read as "nothing wrong". **TESTED**
  (`engine.TestClassesNotAssessedIsPopulated`).
- Suspected and confirmed findings are counted separately and never conflated — but both
  can fail a build. The shipped check cannot reach `confirmed` without credentials, so
  gating only on confirmed findings would exit zero on a real authentication bypass and
  silently green-light a pipeline. **TESTED**
  (`cli.TestSuspectedHighFindingFailsThePolicy`).
- Cancelling a run does not make it look cleaner: every planned item that never started
  still gets a blocked ledger row attributing its absence to cancellation. **TESTED**
  (`engine.TestCancelledJobsStillAppearInTheLedger`).
- A discriminator that could not run is recorded as **not passed** and named in the
  finding's `unavailable` list, rather than reported as a verification step that
  succeeded. Confidence drops accordingly. **IMPLEMENTED** (`internal/check`).
- CI rejects any user-facing text that asserts a target's security
  (`scripts/verify-no-assurance-claims.py`).

---

### T-16 Operator credentials supplied to authenticate as an identity

M1 introduced the first credentials AppSec Framework holds on the operator's behalf. These
are worse than the credentials it observes: an observed session cookie belongs to a test
account created for the run, while a configured credential is one the operator chose to
hand over, often with real privilege.

**Configuration cannot contain a credential at all.**

- `appsec.yaml` has no field that accepts a credential value. Only a *reference* —
  `credential.env` or `credential.file` — is accepted, and strict decoding rejects anything
  else, so a `token:` key added by a hopeful contributor is a loud parse error rather than a
  committed secret. **TESTED** (`config.TestConfigurationCannotCarryACredentialValue`,
  `TestIdentityConfigurationIsValidated`).
- The same absence is asserted against the JSON Schema, so editor completion never offers a
  place to type one. **TESTED** (`config.TestSchemaAndParserAgreeOnRejection`).
- No CLI flag accepts a secret. Process listings are world-readable on most systems and
  shell history outlives the run. **TESTED** (`cli.TestNoFlagAcceptsARawSecret`).

**A resolved credential cannot reach output.**

- A credential lives in a `Secret`, whose `String`, `GoString` and `MarshalJSON` render a
  placeholder. Reading the value requires `Expose`, which is called from one place. This
  closes `%v`, `%+v`, `%#v`, `%s`, structured logging, error formatting and whole-struct
  JSON marshalling in a single move, rather than relying on every future call site to
  remember. **TESTED** (`identity.TestSecretNeverRendersItsValue`,
  `TestSecretRefusesToUnmarshal`).
- Resolution failures name the *location* and never the contents, so the error reporting a
  misconfigured credential does not become the leak. **TESTED**
  (`identity.TestResolveErrorsNeverContainTheCredential`).
- Credentials are registered with the redactor **before the first request is possible**,
  along with their on-the-wire form, so a target that reflects `Bearer <token>` in a body
  cannot defeat redaction by including the scheme. **TESTED**
  (`identity.TestResolveRegistersCredentialsWithTheRedactor`).
- A bespoke API-key header is registered by **name** as well as by value, so a target
  echoing only part of the credential cannot leave the rest readable. Blanket-redacting
  every unrecognised header would destroy the evidence the report exists to carry, so
  exactly the headers the operator declared as credentials are registered. **TESTED**
  (`identity.TestResolveRegistersCustomCredentialHeader`).
- The end-to-end guarantee is asserted against a hostile fixture that reflects the
  credential in a header, a body and a `Location`, after which every byte of the run
  directory — evidence, JSON, SARIF, metadata — is searched for it. Unit-testing the
  redactor proves the function works, not that every writer goes through it. **TESTED**
  (`evals.TestM1_CredentialNeverReachesDisk`).
- `doctor` reports whether a credential is *available* and never what it is, because its
  output is pasted into issues and CI logs. **TESTED**
  (`cli.TestDoctorReportsIdentitiesWithoutValues`).

**A credential cannot leave the authorized origin.**

- Redirects are never followed, so a `Location` chosen by the target cannot replay a
  credential anywhere. **TESTED** (`evals.TestM1_MaliciousRedirectNeverForwardsTheCredential`,
  which asserts that the off-origin host received *zero* requests).
- Authenticated requests traverse the same client as anonymous ones, so the URL gate and
  the dial-time address gate of T-01 — including the DNS-rebinding protection and the cloud
  metadata denial — apply unchanged. There is no authenticated code path that bypasses
  scope. **TESTED** (`evals.TestM1_OffOriginRedirectTargetIsOutOfScope`).
- Query-string API keys are **deliberately not supported**. A credential in a URL reaches
  the cache-busting logic, reproduction strings, transport error text and every
  intermediary's access log. The redactor covers known parameter names, but the exposure is
  broad and the benefit small, so the mechanism is refused rather than mitigated.

**Identities cannot contaminate one another.**

- `Control.Headers` allocates a fresh map per call and the HTTP client holds no per-request
  state, so two identities executing concurrently cannot present each other's credential.
  **TESTED** (`identity.TestConcurrentIdentitiesDoNotContaminate` asserts on the wire that
  every request carried the right token, `TestHeadersAreNotShared`), and the suite runs
  under `-race`.
- The check's anonymous probes and baseline probes carry no credential, which is what makes
  the anonymous/authenticated comparison meaningful at all. **TESTED**
  (`evals.TestM1_AnonymousProbesCarryNoCredential`).

**Residual risk, stated rather than mitigated.**

- A credential is a Go string in process memory for the run's duration. It is not locked,
  not zeroed on exit, and would appear in a core dump. Fixing this properly needs
  mlock-style handling that Go does not offer portably.
- A Go panic prints a goroutine traceback. Struct fields are rendered as words rather than
  as string contents, so a credential is not expected to appear, but this is a property of
  the runtime rather than a control this project enforces.
- Environment variables are readable by other processes of the same user, and on Linux via
  `/proc/<pid>/environ`. This is the standard secret-delivery mechanism for CI and is
  accepted as such; the file source exists for operators who prefer a mounted secret.
- A credential file's permissions are the operator's to set. A file readable by other users
  produces a **warning** rather than a refusal, because refusing to run because a CI system
  mounted a secret group-readable would be an obstruction.
- Future subprocess engines (M4) must be given a **minimal explicit environment**, or every
  configured credential would be inherited by a third-party binary. This is already recorded
  as an M4 acceptance criterion and is restated here because M1 is what makes it dangerous.

## 3. Residual risk accepted at this stage

Stated plainly rather than left for a reader to discover.

- **Redaction is deny-list and pattern based.** It will not catch every bespoke secret
  format — an opaque 32-character session identifier in a JSON field with an unremarkable
  name will survive. It is a mitigation, not a guarantee, and the user-facing
  documentation says so.
- **File permissions are not enforced on Windows.** `os.Chmod` only toggles a read-only
  attribute there. The CLI warns; it does not refuse. An explicit ACL is planned.
- **No sandboxing of external engines** beyond process isolation. Today the mitigation is
  that no engine integration exists at all.
- **`INDETERMINATE` outcomes are reported but not automatically re-tried.**
- **No signing of release artefacts.** Required before any binary distribution.
- **A WAF or intermediary in front of the target can produce false negatives.** AppSec
  Framework fingerprints edge headers and annotates a denial with the possibility that an
  intermediary, not the application, refused the request — but it cannot yet prove which.
- **The attack surface is specification-derived**, so an undocumented route is invisible.
  This is disclosed in every report rather than mitigated.
- **AppSec Framework is fingerprintable, and therefore cloakable.** Its `User-Agent`, its
  `__appsec_cb` cache-buster and its `appsec-nonexistent-*` baseline paths are all
  identifiable, so a hostile target can serve a denial to the scanner and real data to
  everyone else. Being identifiable is deliberate — an assessment tool that disguises itself is
  harder to authorize and harder to stop — so this is accepted rather than fixed by
  randomisation. It is a real limitation when assessing an application you do not fully
  control.
- **A target can still influence classification.** Ambiguous responses are now forced to
  `indeterminate` rather than `denied`, so the cheapest suppression attack yields a
  *blocked* row instead of a silent pass. A target that returns a pure, payload-free
  denial envelope alongside a separate data channel could still mislead a single-identity
  check; the answer to that is the authenticated control request, which arrives with
  identities.

## 4. Reporting a vulnerability

See `SECURITY.md`.
