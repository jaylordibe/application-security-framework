# Releasing

## What a release is, here

A git tag, a GitHub release carrying the notes, and nothing else.

**No binaries are published, and that is a decision rather than an omission.** The
documented install path is `go install`, which builds from source at a verified module
version — the Go module proxy and checksum database already provide integrity, and the
resulting binary is reproducible by anyone. Publishing binaries would add a signing story,
a checksum story, a multi-platform build matrix and a supply chain to defend, in exchange
for saving users one command they already have the toolchain for.

If that changes — if users appear who cannot install Go — binaries can be added later
without invalidating anything here. Adding them now would be release infrastructure built
for an audience that does not yet exist.

Version numbers come from the tag. `go install module@vX.Y.Z` records the version in the
binary, `appsec version` reports it, and every report embeds it. Nothing needs editing in
the source to cut a release.

## Procedure

Steps 1–3 are checks. Steps 4 onwards are the release, and are human-controlled.

```bash
# 1. Everything CI runs, locally, from a clean tree.
git status --porcelain          # must be empty
make check

# 2. The evaluation corpus and a real assessment.
go test ./evals/

# 3. Confirm the version mechanism reports what you expect.
go build -o /tmp/appsec ./cmd/appsec && /tmp/appsec version
```

Then, as the maintainer:

```bash
# 4. Annotated tag. Signed if you have a key configured.
git tag -a v0.1.0 -m "v0.1.0 — first public release"
#   or: git tag -s v0.1.0 -m "v0.1.0 — first public release"

# 5. Push it.
git push origin v0.1.0

# 6. Create the GitHub release using docs/releases/v0.1.0.md as the body.
gh release create v0.1.0 --title "v0.1.0" --notes-file docs/releases/v0.1.0.md

# 7. Verify the published tag installs, from a clean module cache.
cd "$(mktemp -d)"
GOBIN="$PWD/bin" go install github.com/jaylordibe/application-security-framework/cmd/appsec@v0.1.0
./bin/appsec version          # must print v0.1.0, not 0.0.0-dev

# 8. Post-release smoke test against a target you own.
./bin/appsec doctor
./bin/appsec scan http://localhost:3000 --spec-url http://localhost:3000/openapi.json
```

Step 7 is the one that matters: it is the only step that exercises what a new user will
actually do, and it fails loudly if the module path, the tag or the version mechanism is
wrong.

## After tagging

`@latest` resolves to the newest tag, so the README's first install command starts
returning the release rather than `main` with no further change.

## Optional: run the heavy validation

Neither is part of pull-request CI, because both install third-party software or boot other
people's applications.

```bash
gh workflow run ci.yml                 # real-engine integration: Nuclei, ZAP, opengrep
gh workflow run reference-apps.yml     # assessment against both reference applications
```
