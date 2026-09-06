package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

//go:generate true

// exampleConfig is written by `appsec init`. It is deliberately commented, because
// a security tool's configuration is where a user decides what may be attacked.
const exampleConfig = `# appsec.yaml — AppSec Framework assessment configuration
#
# AppSec Framework assesses applications you own or are explicitly
# authorized to test.
apiVersion: appsec/v1alpha1

target:
  # The application under assessment. Its origin is always in scope.
  baseURL: http://localhost:3000
  name: my-application

scope:
  # Scope is an allowlist. Nothing outside it is ever contacted; anything
  # discovered outside it is recorded and left alone.
  include: []
  #  - scheme: https
  #    host: api.example.com
  #    ports: [443]
  #    pathPrefix: /v2/

  # Required to assess a loopback or RFC1918 target. AppSec Framework sets
  # this automatically when the target you pass on the command line is
  # loopback.
  allowPrivateAddresses: true

assessment:
  # discovery    — reconnaissance only
  # verification — real techniques with controlled impact (default)
  # intrusive    — may change or destroy data; requires authorizeIntrusive
  profile: verification
  authorizeIntrusive: false

  concurrency: 4
  requestsPerSecond: 10
  timeoutSeconds: 20

  # Operations that must never be exercised, by operation id ("POST /orders").
  excludeOperations: []

  # Skip routes that look like authentication. Sweeping these with
  # unauthenticated requests can lock real accounts.
  excludeAuthEndpoints: true

identities:
  # A security principal AppSec Framework may act as. An identity is not a
  # credential: only a reference to where the credential lives is configured
  # here, so that this file can be committed and reviewed safely.
  #
  # With an identity, the declared-auth check can compare an anonymous response
  # against what a legitimate caller receives, which is the only way a finding
  # reaches "confirmed". Without one, findings stay "suspected" and say so.
  #
  # Supported types are bearer and apiKey. OAuth2, OIDC, browser login and
  # cookie-session flows are not implemented.
  []
  # - id: admin
  #   label: Administrator
  #   authentication:
  #     type: bearer
  #     credential:
  #       env: APPSEC_ADMIN_TOKEN     # or: file: /run/secrets/admin-token
  #   # A safe, authentication-requiring operation used to check that the
  #   # credential is still valid. Strongly recommended: without it, a token
  #   # expiring mid-run cannot be detected, and every result that depended on
  #   # it would silently rest on a dead credential.
  #   liveness:
  #     method: GET
  #     path: /api/me
  #     expectStatus: [200]
  #
  # - id: service
  #   authentication:
  #     type: apiKey
  #     header: X-API-Key            # validated as an HTTP header name
  #     credential:
  #       env: APPSEC_SERVICE_KEY

resources:
  # Concrete resources known to belong to an identity, used to test whether a
  # non-owner can reach or change them. Without a fixture, addressing
  # /api/orders/{orderId} means inventing an identifier and reading a 404 that
  # says nothing about authorization.
  #
  # A cross-owner test needs two identities: the owner and somebody who is not.
  []
  # - id: order-alice
  #   type: order
  #   owner: alice                 # must be an identities[].id
  #
  #   # Required. "denied" means non-owners must not reach it, which is the
  #   # boundary to test. "allowed" means it is legitimately shared, so a
  #   # non-owner reaching it is expected and is never reported.
  #   #
  #   # There is no default: whether a resource is private is a statement about
  #   # your application, and assuming it would report every deliberately
  #   # shared record as a broken access control.
  #   crossOwnerAccess: denied
  #
  #   # Values that fill the operation's declared path parameters. Each fills
  #   # one path segment; separators and URL delimiters are refused.
  #   values:
  #     orderId: "abc123"
  #
  #   # Optional. Narrow which operations and which non-owners are used.
  #   # operations: ["GET /api/orders/{orderId}"]
  #   # nonOwners: [bob]
  #
  #   # Optional. Enables cross-owner write testing, which requires the
  #   # intrusive profile and authorizeIntrusive. A write is confirmed only by
  #   # re-reading as the owner: an HTTP success never confirms one. The changed
  #   # fields are restored afterwards on a best-effort basis, and the report
  #   # says whether that worked.
  #   # mutation:
  #   #   values:
  #   #     status: "appsec-marker"

adapters:
  # Framework adapters read your application's own source and report what it
  # expects to enforce — which operations require authentication, which have an
  # authorization control. That gives the oracle information OpenAPI cannot
  # express, and makes operations testable that were previously untestable.
  #
  # An adapter fact is an expectation, never evidence. Whether a control
  # actually works is established by the runtime checks, not by reading source.
  #
  # Adapters are opt-in. Nothing runs unless you name it here.
  use: []
  # sourceRoot: ../my-application
  #
  # "none" (the default) permits only adapters that do not execute your
  # application's code. "execute-target-code" authorises framework-native
  # introspection — 'artisan route:list' boots the whole framework and runs
  # every service provider; importing a NestJS module executes it. Higher
  # fidelity, and a real decision.
  # trust: none
  #
  # use:
  #   - name: laravel
  #     path: ./dist/appsec-adapter-laravel
  #   - name: nestjs
  #     path: ./dist/appsec-adapter-nestjs
  #     # The adapter's environment is built from nothing. Name a variable here
  #     # to forward it; this tool's own credentials can never be forwarded.
  #     # passEnv: [HOME]

engines:
  # External scanning engines. AppSec Framework does not reimplement Nuclei's
  # templates, ZAP's active scanner or Semgrep's dataflow analysis; it
  # supervises them, keeps them inside your authorization boundary, records
  # where every result came from, and is explicit about what did not run.
  #
  # Every engine result is recorded as OBSERVED. A scanner saying "critical" is
  # that scanner's opinion of its own rule, not evidence that your application
  # is exploitable, and two scanners agreeing is not evidence either. Nothing
  # here can fail your build on its own.
  #
  # Engines are off by default and are never installed for you. An engine that
  # is missing, crashes or times out becomes a blocked ledger row saying what
  # was not assessed, never a clean result.
  {}
  #
  # sourceRoot: ../my-application   # for engines that read code
  #
  # nuclei:
  #   enabled: true
  #   executable: /usr/local/bin/nuclei
  #   # Required. Templates are executable security logic, so you supply them
  #   # and AppSec Framework records where from. A git checkout is pinned by
  #   # commit. Nothing is downloaded.
  #   templates: ./nuclei-templates
  #   rateLimit: 50
  #
  # zap:
  #   enabled: true
  #   executable: /opt/zap/zap.sh
  #   # "passive" (default) spiders and observes. "active" runs the active
  #   # scanner, which sends attack payloads and needs profile: intrusive.
  #   # A passive run does not assess injection and does not claim to.
  #   mode: passive
  #
  # sast:
  #   enabled: true
  #   executable: /usr/local/bin/opengrep
  #   # Required, and must be a local path. AppSec Framework ships no rules and
  #   # will not pull them from a registry.
  #   rules: ./sast-rules

discovery:
  # AppSec Framework derives expectations from the application's own
  # specification. Give it one, or let it probe the usual locations on the
  # target's origin.
  openAPIFile: ""
  openAPIURL: ""
  probeWellKnownPaths: true

outcome:
  # Real applications rarely follow textbook status codes. If yours publishes a
  # stable machine-readable error code, point AppSec Framework at it: it is
  # a far more reliable signal than the status, and it prevents both false
  # positives and false negatives.
  errorCodePointer: ""      # e.g. "/errorCode"
  deniedCodes: []           # e.g. ["PERMISSION_DENIED", "FORBIDDEN"]
  notFoundCodes: []         # e.g. ["RESOURCE_NOT_FOUND"]

policy:
  # When a run fails the build. Severity thresholds; empty disables a rule.
  #
  # Suspected findings count by default. A suspected finding is unverified by
  # definition, but AppSec Framework cannot reach "confirmed" without
  # credentials, so gating only on confirmed findings would exit 0 on a real
  # bypass.
  failOnConfirmed: low
  failOnSuspected: high

environment:
  # State how this environment differs from production. These are recorded as
  # facts on the report; AppSec Framework does not invent a fidelity score.
  name: local
  differences:
    - "rate limiting: relaxed for assessment"
    - "data: synthetic"

output:
  dir: .appsec
`

func newInitCommand(stdout, stderr io.Writer) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a commented appsec.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			const path = "appsec.yaml"
			if _, err := os.Stat(path); err == nil && !force {
				return fail(ExitUsage, "%s already exists; pass --force to overwrite", path)
			}
			if err := os.WriteFile(path, []byte(exampleConfig), 0o600); err != nil {
				return fail(ExitInternal, "cannot write %s: %v", path, err)
			}
			fmt.Fprintf(stdout, "Wrote %s\n\nNext:  appsec scan http://localhost:3000\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing appsec.yaml")
	return cmd
}
