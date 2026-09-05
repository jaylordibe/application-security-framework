# Assay build and validation.
#
# `make check` is what CI runs and what a contributor should run before opening a
# pull request. It requires no network, no database and no external engine.

GO      ?= go
BINARY  := assay
DIST    := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -s -w -X github.com/jaylordibe/application-security-framework/internal/cli.Version=$(VERSION)

.DEFAULT_GOAL := check

.PHONY: build
build: ## Build the binary into ./dist
	@mkdir -p $(DIST)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) ./cmd/assay

.PHONY: fmt
fmt: ## Format all Go source
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@unformatted=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck (skipped with a warning if absent)
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

.PHONY: test
test: ## Run tests
	$(GO) test ./...

.PHONY: race
race: ## Run tests under the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Run tests with a coverage profile
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: vuln
vuln: ## Run govulncheck (reachability-based)
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed; skipping (go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

.PHONY: tidy-check
tidy-check: ## Fail if go.mod or go.sum would change
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak
	@$(GO) mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
		mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
		echo "go.mod/go.sum are not tidy; run 'go mod tidy'"; exit 1; \
	fi
	@rm -f go.mod.bak go.sum.bak

.PHONY: check
check: fmt-check vet staticcheck test race vuln tidy-check ## Everything CI runs

.PHONY: tools
tools: ## Install the optional local tooling
	$(GO) install honnef.co/go/tools/cmd/staticcheck@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: clean
clean:
	rm -rf $(DIST) coverage.out

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
