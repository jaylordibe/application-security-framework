# Adapters against the reference applications

What the two shipped adapters actually extract from the current public
reference applications, what they cannot, and how that was established.

Neither repository was modified. Both were read at the commits below.

| | `jaylordibe/laravel-api` | `jaylordibe/nestjs-api` |
|---|---|---|
| Commit read | `8302196` | `84e19a2` |
| Extraction method | `static-lexical` | `static-lexical` |
| Target code executed | **none** | **none** |
| Dependencies required | **none** (`vendor/` is absent and not needed) | **none** (`node_modules` is absent and not needed) |
| Facts reported | 80 | 168 |
| authentication `required` | 33 | 62 |
| authentication `public` | 7 | 22 |
| authorization `present` | 5 | 58 |
| authorization `absent` | 35 | 26 |
| ownership | none reported — see below | none reported — see below |

Both run against a **fresh clone with no install step**, which is the property
that makes them usable at all: neither `vendor/` nor `node_modules` exists after
`git clone`, and creating either is code execution.

## The same concept, extracted from two different frameworks

This is the cross-framework proof, and the interesting part is that the two
frameworks express it in opposite directions.

| Normalized fact | Laravel | NestJS |
|---|---|---|
| `authentication: required` | the route is inside a `Route::middleware(['auth:api'])->group(...)` | a global `APP_GUARD` is registered and the operation carries no opt-out |
| `authentication: public` | the route is in no authentication group | the operation carries `@Public()` |
| `authorization: present` | `Gate::authorize(...)` in the controller action, or `can:` middleware | `@RequirePermission(...)` |

Note the inversion. In Laravel, an operation with nothing attached is
**unprotected**. In NestJS under a global guard, an operation with nothing
attached is **protected**. Both adapters reach the same normalized conclusion
from opposite syntax, and neither rule exists anywhere in the core — which is
what "framework-neutral" has to mean to be worth anything.

## Verified oracle improvement

Run end to end with the real `laravel-api` source and a specification that
documents `GET /api/users` without stating its security — the common case, and
what Scramble emits when no security scheme is annotated:

| | without the adapter | with the adapter |
|---|---|---|
| oracle grade | `silent` | `uniform` |
| executed checks | 0 | **1** |
| untested | 1 | 0 |
| findings | 0 | **1 suspected, high** |

The adapter found the route inside `auth:api` in `routes/api.php`, which gave
the operation an expectation the specification did not carry. The runtime probe
then found the service serving it anonymously.

The finding is **suspected, not confirmed**, and that is the design working: the
oracle is a static inference, and no authenticated control ran. An adapter fact
never confirms anything by itself.

## What the adapters could not determine

Reported as limitations in every document, so that the absence of a fact is
never read as the absence of a control.

**Laravel**

- Middleware attached in a controller constructor, a route-service provider or
  the application bootstrap is invisible to static extraction. A route reported
  `public` is one this adapter saw outside every authentication group it read —
  which is weaker than "the framework applies nothing here".
- A gate or policy decides access at runtime and its basis — ownership, role,
  something else — is not determinable without executing it. **No ownership
  fact is reported for either application**, and this is why.
- `AppServiceProvider.php:95` builds the gate table in a loop over an enum
  (`Gate::define($permission, ...)`). No adapter that does not run the
  application will ever enumerate that permission catalog. This is the clearest
  example in either repository of a fact that genuinely needs tier 1.
- A route whose path is computed — `Route::get(config('custom.dynamic_route'))` —
  is skipped entirely rather than reported under a guessed path, because a fact
  attached to the wrong operation is worse than no fact.

**NestJS**

- A guard whose semantics the adapter does not recognise yields `unknown` for
  authorization, not `absent`. Claiming absence would invent the absence of a
  control that is visibly there in the source.
- Without a global guard, an operation with no local decorator yields `unknown`
  rather than `public`, for the same reason.
- CASL abilities are resolved at runtime; `@RequirePermission('read','Order')`
  tells the adapter a control exists, not what it will decide.

## Conflicts with OpenAPI

Neither reference application produced a conflict in these runs, because neither
specification declares security on the operations the adapters reported on —
they are silent, so every adapter fact was `new` rather than corroborating or
conflicting. Conflict handling is exercised by deterministic fixtures instead
(`evals/adapter_test.go`), in both directions.

## What is not demonstrated

- **No tier-1 result is claimed.** Framework-native introspection is not
  implemented; see [ADR-0014](../adr/0014-adapter-contract-and-extraction-trust.md).
  The trust gate that would govern it is built and tested, and refuses any
  framework-native adapter unless the operator authorises it.
- **The static tier will misread unusual source.** Every fact carries a file and
  line so a human can check it, and a wrong fact can only ever produce a
  suspected finding somebody reads.

## Reproducing this

```bash
make build
git clone --depth 1 https://github.com/jaylordibe/laravel-api /tmp/laravel-api
./dist/appsec-adapter-laravel --source-root /tmp/laravel-api | jq '.facts | length'
```

The adapters are ordinary programs and print their document to stdout, so they
can be inspected without running an assessment at all.
