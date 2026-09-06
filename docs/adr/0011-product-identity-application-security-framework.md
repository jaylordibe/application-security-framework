# ADR-0011: The product is Application Security Framework, and the CLI is `appsec`

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

The repository is `application-security-framework`, but the bootstrap commit shipped the
name **Assay** throughout: the `assay` CLI, `assay.yaml`, `.assay/`, the `assay/v1alpha1`
schema namespace and the product name in every document. No ADR recorded that choice, and
nothing was ever released under it.

Two facts forced a decision.

First, an existing open-source application-security scanner already uses the name Assay
([`TyrusRC/assay`](https://github.com/TyrusRC/assay)). Its domain substantially overlaps
this project's. Two security tools sharing a name collide in exactly the places that
matter for a tool people are asked to trust: search results, package metadata, issue
reports, CI configuration and vulnerability disclosure. A user cannot safely be uncertain
which scanner produced a report.

Second, the repository's own name already states the product's identity. Carrying a
second, unrelated brand inside a repository called `application-security-framework`
forces every reader to learn a mapping before they can read anything else.

The counter-argument is that `appsec` is a generic industry abbreviation for application
security. That is true, and it is accepted: the identity here is the explicit phrase
Application Security Framework, for which `appsec` is the natural short executable name.
A generic CLI name is a smaller cost than a name collision with an adjacent security
scanner.

## Decision

The project's identity is:

| Surface | Value |
|---|---|
| Product name | Application Security Framework |
| Short name (prose) | AppSec Framework |
| Repository | `application-security-framework` |
| Go module | `github.com/jaylordibe/application-security-framework` |
| CLI executable | `appsec` |
| Configuration file | `appsec.yaml` |
| Runtime state directory | `.appsec/` |
| Schema namespace | `appsec/v1alpha1`, `appsec.report/v1alpha1`, `appsec.run/v1alpha1`, `appsec.evidence/v1alpha1` |
| Machine-readable tool id | `application-security-framework` |

These are four distinct roles and are not interchangeable. The tool id in a report or a
SARIF driver is `application-security-framework`, because a producer identity should be
unambiguous rather than short. The filesystem and schema namespace is `appsec`, because a
path segment and an `apiVersion` prefix should be short and typed often. Prose uses
AppSec Framework; a title uses the full name.

No compatibility alias is provided for the former name. Nothing was released under it, so
`assay.yaml`, `.assay/` and an `assay` executable alias would be permanent migration
baggage for a name that never had users.

## Alternatives considered

**Keep Assay.** Rejected. The collision with `TyrusRC/assay` is in the same product
category, which is the case where a name collision does real harm — a reader who finds a
report, an issue or a package cannot tell which tool it belongs to.

**Keep Assay and disambiguate in documentation.** Rejected. Documentation cannot
disambiguate a search result, a binary on `PATH`, or a `tool.name` field in someone's
SARIF pipeline.

**Invent a third name.** Rejected. The repository already carries an accurate identity;
the work of establishing a novel brand buys nothing this project needs, and would have to
be re-litigated the first time the new name collided too.

**Use `appsec` as every internal identifier.** Rejected. A generic token is acceptable as
an executable name that a user types, and poor as a producer identity that a machine
records. The two roles are separated above.

## Consequences

Easier: a contributor reads the repository name and already knows the product, the CLI and
the config file. There is no second vocabulary to learn, and no risk of a user attributing
this tool's output to an unrelated scanner.

Harder: `appsec` is generic, so it is a weak search term and could collide with a local
alias or an unrelated internal tool on someone's `PATH`. Accepted — the machine-readable
identity in reports carries the disambiguation where it actually matters.

Also harder: pre-1.0 schema consumers reading `assay/v1alpha1` break. Accepted; nothing
was released, and every schema is versioned precisely so a consumer detects the change
rather than misparsing it.

## Note on the external Assay project

Where this repository's research discusses `TyrusRC/assay`, that name refers to the
external project and must not be renamed. Historical references to this project's own
former bootstrap name, where they remain, are labelled as such.
