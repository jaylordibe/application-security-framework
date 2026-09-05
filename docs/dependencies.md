# Dependencies

Assay is a supply-chain target: a backdoored dependency here is an attack on everyone who
runs it against their own infrastructure. The list is short deliberately, and **adding a
direct dependency requires an ADR**.

## Direct

| Module | Licence | Why | If it were abandoned |
|---|---|---|---|
| `github.com/spf13/cobra` | Apache-2.0 | Command tree, help, shell completion. Mild over-engineering for a handful of commands, but hand-rolling help and completion badly is worse. | Replaceable with `flag` in roughly a day; nothing outside `internal/cli` touches it. |
| `github.com/goccy/go-yaml` | MIT | Strict decoding that rejects unknown fields, and errors annotated with line, column and a source snippet — which is most of what makes a configuration error actionable. | Effectively single-maintainer. Documented fallback: `sigs.k8s.io/yaml` or `go.yaml.in/yaml/v3`, at the cost of error quality. |
| `golang.org/x/net` | BSD-3-Clause | `idna` only, to normalise internationalised hostnames before scope comparison. Without it, visually distinct spellings of the same host can bypass an exact match. | Vendorable; the surface used is one function. |
| `golang.org/x/text` | BSD-3-Clause | Transitive requirement of `idna`. | — |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | **Tests only.** Validates our SARIF against the official OASIS schema and asserts the config schema and the Go parser agree. | Tests would lose their strongest assertions; the binary is unaffected. |
| `github.com/inconshreveable/mousetrap` | Apache-2.0 | Transitive requirement of cobra (Windows only). | — |

Everything else is the standard library, including OpenAPI parsing, SARIF emission,
hashing, HTTP and the run store.

## Deliberately not used

| Rejected | Reason |
|---|---|
| **viper** | Arrives with cobra culturally, drags a large tree, and its precedence rules would fight the strict-decode configuration design. |
| **logrus**, **zap** | `log/slog` is in the standard library. |
| **testify** | The standard library's testing package is sufficient, and assertion DSLs obscure what a security test actually asserts. |
| **kin-openapi**, **libopenapi** | We extract a small subset — operations and declared security requirements — and would map away from their AST anyway. A heavy parser in the foundation of a security tool is a poor trade, and external `$ref` resolution in those loaders is a second, unguarded network and filesystem client. |
| A SARIF library | We emit a small fixed subtree, validated against the real schema in tests. |
| **modernc.org/sqlite** | Correct eventual choice, but a very large transpiled dependency for a workload that is currently "write once, read once". See ADR-0007. |
| **playwright-go** | v0.x, single maintainer, and ~650 MB of browsers plus Node plus root-level system dependencies for every user. See the ecosystem research. |
| Nuclei's Go SDK | 457 require lines, documented global state, and its own README warns about running it as a service. We subprocess it instead. See ADR-0005. |
| Unlicensed Burp extensions | Autorize and Authz carry no licence at all. Never vendor them. |
| Semgrep registry rules | Licensed for the user's own internal business purposes only; distribution and service use are forbidden. Never shipped, vendored, auto-fetched or referenced in examples. |

## Verification

- `go.sum` plus the Go checksum database on every build.
- `govulncheck` in CI, weekly as well as per-change, and reachability-based rather than
  version-matching.
- CI actions pinned by commit SHA.
- No documented installation path pipes a network response into a shell.
