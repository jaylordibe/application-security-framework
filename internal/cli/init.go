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
