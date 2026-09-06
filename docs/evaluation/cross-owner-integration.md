# Running cross-owner tests against the reference applications

> Design-time analysis of these two applications lives in
> [docs/research/reference-applications.md](../research/reference-applications.md).
> This document is about *running* M2 against them.

The roadmap says the BOLA primitive should ultimately be proven on two dissimilar
applications. This document records what was verified about them, what an operator
must do to exercise M2 against each, and what is honestly not yet demonstrated.

**Nothing here is a claimed result.** The deterministic baseline is the paired
in-process fixtures in `evals/ownership_test.go`, which run offline in CI. What
follows is a reproducible procedure, not evidence that it has been run to
completion in this environment.

## What was verified about the applications

Both repositories were inspected at the commits below. Neither was modified, and
neither is a dependency of this project.

| | `jaylordibe/nestjs-api` | `jaylordibe/laravel-api` |
|---|---|---|
| Specification | Swagger via `@nestjs/swagger`, mounted at `api/docs` with a global `api` prefix (`src/main.ts`) | Scramble, served at `/docs/api` (`config/scramble.php`) |
| Authentication | JWT bearer; sign-in returns `accessToken` (`src/modules/auth/auth.service.ts`) | Laravel Passport bearer; `POST auth/sign-in` (`routes/api.php`) |
| A user-owned parameterised resource | `GET /api/device-tokens/:id`, plus `@Patch(':id')` and `@Delete(':id')` (`src/modules/device-tokens/device-tokens.controller.ts`) | `GET /api/device-tokens/{deviceTokenId}`, `PUT`, `DELETE` (`routes/api.php`) |
| Ownership enforcement | Queries are scoped by `userId`, and the code comments that another user's token "is never loaded and the caller gets a 404" | Controller-level scoping per route |
| Environment | `docker-compose` with postgres, redis and minio; Prisma migrations and seeds | `docker-compose`; migrations and `UserSeeder` |

Two things follow from this.

**The primitive fits both.** Each exposes a user-owned resource addressed by a
path parameter, in a different framework, with a different authentication stack
and a different specification generator. That is exactly the pair the roadmap asks
for.

**The 404 finding is not hypothetical.** `nestjs-api` deliberately returns 404 to a
non-owner as an anti-enumeration measure. Any cross-owner check that treated a 404
as a vulnerability would report correct, deliberate design as a bug on the first
run. This is why the outcome classifier decides denials and why the paired
`secure` fixture in `evals/ownership_test.go` models exactly this behaviour.

## What an operator must do

M2 uses **configured** fixtures, so the identifier of a resource owned by one
identity has to be known before the scan. Obtaining it is manual, and that is the
reason M2 is marked partial in the roadmap.

For either application, the shape is the same:

1. Bring the environment up with its own `docker-compose`, run its migrations and
   seeds.
2. Create or seed **two** users.
3. Sign in as each and keep the bearer token. Export them, never write them into
   `appsec.yaml`:
   ```bash
   export APPSEC_ALICE_TOKEN='...'
   export APPSEC_BOB_TOKEN='...'
   ```
4. As the first user, create one resource — a device token is the smallest — and
   note its identifier from the list endpoint.
5. Point `appsec.yaml` at the application's specification and describe what you
   learned:

   ```yaml
   identities:
     - id: alice
       authentication: {type: bearer, credential: {env: APPSEC_ALICE_TOKEN}}
       liveness: {method: GET, path: /api/me}      # an authenticated route
     - id: bob
       authentication: {type: bearer, credential: {env: APPSEC_BOB_TOKEN}}
       liveness: {method: GET, path: /api/me}

   resources:
     - id: device-token-alice
       type: device-token
       owner: alice
       crossOwnerAccess: denied
       values:
         # nestjs-api: the parameter is named "id"
         # laravel-api: the parameter is named "deviceTokenId"
         id: "<the identifier from step 4>"
   ```

6. Run `appsec scan`. Read-only cross-owner testing needs no special profile.

Set the `liveness` path to a route that genuinely requires authentication in that
application; if it 404s, the canary will report the identity dead and block the
run, which is the correct behaviour for an unknown probe and the reason the canary
is operator-supplied rather than guessed.

To exercise cross-owner **writes** as well, add a `mutation` block and switch to
`profile: intrusive` with `authorizeIntrusive: true`. Do this only against a
disposable environment: restoration is best-effort, and side effects such as
audit rows or webhooks cannot be undone.

## What is not demonstrated

- **No cross-framework result is claimed.** Running the above needs docker,
  databases and seeded accounts, none of which is available to the offline test
  suite, and fabricating a pass would be the exact failure this project exists to
  prevent.
- **The manual step is the gap.** Steps 2–4 are environment provisioning. Until
  that exists (see **Later** in the roadmap), M2 depends on an operator knowing one
  identifier.
- **Parameter names differ between the two.** `id` versus `deviceTokenId`. The
  fixture's `values` are keyed by the parameter name the specification declares, so
  the same fixture is not portable between them — correctly, since they are
  different APIs.
