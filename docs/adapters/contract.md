# Writing an AppSec Framework adapter

An adapter observes an application's own source or runtime and reports
normalized security facts. AppSec Framework's core never learns what a Laravel
middleware group or a NestJS guard is: your adapter translates those into the
vocabulary below, and the core reasons only about that.

You can write one in any language. The contract is a JSON document on stdout,
and `schemas/appsec.adapter.schema.json` validates it.

## The shape

```json
{
  "contractVersion": "appsec.adapter/v1alpha1",
  "adapter": {
    "name": "laravel",
    "version": "0.1.0",
    "extractionMethod": "static-lexical"
  },
  "target": { "framework": "laravel", "frameworkVersion": "12.x" },
  "facts": [
    {
      "kind": "operation.authentication",
      "operation": { "method": "GET", "path": "/api/users/{userId}" },
      "value": "required",
      "evidence": {
        "file": "routes/api.php",
        "line": 81,
        "detail": "the route is inside a middleware group applying auth:api"
      }
    }
  ],
  "limitations": [
    "middleware attached in a controller constructor is not visible to static extraction"
  ]
}
```

Write the document to stdout and nothing else. Diagnostics go to stderr.

## Invocation

Your adapter is run with an explicit argument vector, never through a shell:

```
<your-executable> --source-root <absolute path> [your configured args...]
```

The working directory is the source root, and it is passed explicitly so you
never have to discover it. **The environment is built from nothing** — not even
`PATH`. If you need a variable, the operator names it in `passEnv`; AppSec's own
identity credentials can never be forwarded.

## The five rules that matter

**1. Report conclusions, not constructs.** There is no place in this contract
for a middleware, a guard, a gate or a decorator. Translate them. The reason is
concrete: in Laravel a route with no authentication middleware is unprotected,
while in NestJS under a global `APP_GUARD` a route with no decorator is
protected. If the core learned either rule it would be wrong about the other.

**2. You state the method; the core decides the trust.** There is no
`confidence` or `provenance` field, deliberately. `framework-native` earns
`declared` provenance, static methods earn `inferred`, and **nothing earns
`observed` or `verified`** — reading source never establishes what a request
does.

**3. `unknown` is a real answer, and often the right one.** When you meet a
dynamic construct, say `unknown`. Do not guess and do not stay silent: silence
is read as "no fact", which is easily mistaken for "no control".

**4. Say what you could not see.** `limitations` is what makes the absence of a
fact distinguishable from the absence of a control. An adapter that reports ten
protected routes and does not mention that it cannot read controller-level
middleware has told a half-truth.

**5. Do not execute the target's code unless you say so.** If your adapter boots
the application — `artisan route:list`, importing modules — you must report
`extractionMethod: framework-native`, and the operator must have set
`adapters.trust: execute-target-code`. Never install dependencies and never run
project scripts.

## Vocabulary

| kind | values | means |
|---|---|---|
| `operation.authentication` | `required`, `public`, `unknown` | whether a caller must be authenticated |
| `operation.authorization` | `present`, `absent`, `unknown` | whether a control beyond authentication applies |
| `operation.ownership` | `owner-scoped`, `not-owner-scoped`, `unknown` | whether the operation is limited to the caller's own records |

`operation.path` is a template with `{braces}`. Convert your framework's syntax:
NestJS `:id` becomes `{id}`. Include any global or mount prefix — an operation
reported as `/users/{id}` will never match a specification's `/api/users/{id}`,
and your adapter will silently corroborate nothing.

`control` is an opaque label such as a permission name. The core reports it and
never interprets it.

## What the core will do to your output

It is treated as hostile input, because an adapter is a third-party binary run
against an untrusted repository.

| | |
|---|---|
| Unknown `contractVersion` | whole document refused — a later contract may give a field a new meaning |
| Malformed JSON, trailing content, unknown field | whole document refused |
| Adapter name not matching what was invoked | whole document refused |
| `framework-native` without operator trust | whole document refused |
| A fact with a bad path, method, value or evidence location | that fact dropped and counted |
| Two facts disagreeing about one subject | **both** withdrawn |
| Output above the size budget | refused, not truncated |
| Your process hanging | killed on timeout, with its process group |

Facts are then merged with the specification. Agreement is corroboration,
disagreement withdraws the expectation from both sources and is reported, and an
operation only you know about is recorded but **not** tested.

## Conformance

`internal/adapter/validate_test.go` is the conformance suite. It is readable
without knowing Go and every case states why acceptance would be unsafe. Run
your document through it, or validate against the JSON Schema directly.

## Reference implementations

`adapters/laravel` and `adapters/nestjs` are static-lexical adapters that read
files and execute nothing. They are small and deliberately conservative; read
them for how the awkward cases are handled, particularly where they choose
`unknown` over a plausible guess.
