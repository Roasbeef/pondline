# Pondline — common developer commands.
#
# Every target is a thin wrapper over the scripts and package tooling, so
# what CI runs and what you run locally are the same commands.

# Every Gleam package under packages/, found by its gleam.toml. Packages are
# built independently, so the order does not matter.
PACKAGES := $(patsubst packages/%/gleam.toml,%,$(wildcard packages/*/gleam.toml))

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- checking

.PHONY: check
check: fmt-check build test lint doc-check ## Full gate: format, warning-free build, tests, lint, docs

.PHONY: check-%
check-%: ## Full gate for one package, e.g. make check-core
	@cd packages/$* && gleam format --check src $$( [ ! -d test ] || echo test )
	@cd packages/$* && gleam build --warnings-as-errors
	@cd packages/$* && gleam test
	@scripts/lint.sh packages/$*/src

# ---------------------------------------------------------------- building

.PHONY: build
build: ## Warning-free build of every Gleam package
	@set -e; for p in $(PACKAGES); do \
		echo "==> build $$p"; \
		(cd packages/$$p && gleam build --warnings-as-errors); \
	done

.PHONY: test
test: sidecar ## Run every package's tests (builds the Tor sidecar the tor tests drive)
	@set -e; for p in $(PACKAGES); do \
		echo "==> test $$p"; \
		(cd packages/$$p && gleam test); \
	done

.PHONY: test-%
test-%: ## Run one package's tests, e.g. make test-core
	@cd packages/$* && gleam test

# ---------------------------------------------------------------- sidecar

.PHONY: sidecar
sidecar: ## Build the pondline-tor Arti sidecar (release); the tor package's tests need it
	cargo build --release --manifest-path native/pondline-tor/Cargo.toml

.PHONY: demo
demo: ## Run the two-daemon, two-sandboxed-agent demo: make demo CARRIER=loopback|tor
	scripts/demo.sh --carrier=$(or $(CARRIER),loopback)

# ---------------------------------------------------------------- releasing

# One self-contained tree, build/release/<platform>/pondline, holding both
# programs (bin/pondline and bin/mailbox) over its own ERTS, OpenSSL and Tor
# sidecar (docs/adr/003-packaging.md and its addendum). release.sh builds the
# sidecar itself unless PONDLINE_TOR_BIN names one already built, which is
# how a worktree reuses another checkout's.
.PHONY: release
release: ## Build the self-contained release into build/release/<platform>/pondline
	@scripts/release.sh

.PHONY: release-smoke
release-smoke: ## Boot the release with no erl, gleam or Homebrew: mailbox, two daemons, pair, send
	@scripts/release-smoke.sh

.PHONY: dist
dist: release release-smoke ## Package the release as dist/pondline-<version>-<platform>.tar.gz + .sha256
	@scripts/dist.sh

.PHONY: release-linux
release-linux: ## Build and bare-Ubuntu-24.04 smoke-test the linux-x86_64 release via Docker
	DOCKER_BUILDKIT=1 docker build --platform=linux/amd64 -f docker/release-builder.Dockerfile -t pondline-release-builder:local .
	docker run --rm --platform=linux/amd64 --ulimit nofile=65536:65536 -e HOST_UID=$$(id -u) -e HOST_GID=$$(id -g) -v "$(CURDIR):/work" -w /work pondline-release-builder:local bash -lc 'scripts/release.sh && scripts/dist.sh && chown -R "$$HOST_UID:$$HOST_GID" build dist native/pondline-tor/target'
	docker run --rm --platform=linux/amd64 --ulimit nofile=65536:65536 -v "$(CURDIR):/work" -w /work ubuntu:24.04 bash -lc 'apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates procps >/dev/null && scripts/release-smoke.sh && scripts/test-update.sh'

# Installs the release under $(PREFIX): the tree in $(PREFIX)/lib/pondline and
# the pondline and pondline-mailbox commands in $(PREFIX)/bin.
# scripts/install.sh says what lands where and why.
PREFIX ?= $(HOME)/.local

.PHONY: install
install: release ## Install pondline and pondline-mailbox under PREFIX (default ~/.local)
	@PREFIX="$(PREFIX)" scripts/install.sh

.PHONY: uninstall
uninstall: ## Remove what make install put under PREFIX (state directories are untouched)
	@PREFIX="$(PREFIX)" scripts/install.sh --uninstall

# ---------------------------------------------------------------- formatting

.PHONY: fmt
fmt: ## Format all Gleam sources in place
	@set -e; for p in $(PACKAGES); do \
		(cd packages/$$p && gleam format src $$( [ ! -d test ] || echo test )); \
	done

.PHONY: fmt-check
fmt-check: ## Verify formatting without writing (what CI enforces)
	@set -e; for p in $(PACKAGES); do \
		(cd packages/$$p && gleam format --check src $$( [ ! -d test ] || echo test )); \
	done

# ---------------------------------------------------------------- house rules

.PHONY: lint
lint: ## Run the house lint (errors gate; see packages/lint/CLAUDE.md)
	@scripts/lint.sh

.PHONY: lint-%
lint-%: ## Lint one package's src, e.g. make lint-core
	@scripts/lint.sh packages/$*/src

.PHONY: doc-check
doc-check: ## Gate the per-package CLAUDE.md/AGENTS.md graph and docs/ citations
	@scripts/doc_check.sh

# ---------------------------------------------------------------- generating

.PHONY: gen-sql
gen-sql: ## Regenerate the SQL modules after editing any .sql file (needs sqlite3, and the network once; ADR-007)
	@scripts/gen-sql.sh

# ---------------------------------------------------------------- formal

# Each formal/<tool>/check.sh runs one prover or model checker and exits
# non-zero on a failed property or a broken-variant model that no longer
# fails (docs/formal/). They need tools `make check` does not (Lean, P, TLC,
# a protocol prover), so they run here rather than in the gate.
.PHONY: formal
formal: ## Run every formal check under formal/ (proofs, model checkers; docs/formal/)
	@set -e; for script in formal/*/check.sh; do \
		echo "==> $$script"; bash "$$script"; \
	done

# ---------------------------------------------------------------- housekeeping

.PHONY: clean
clean: ## Remove every package's build directory, the releases and dist/
	@for p in $(PACKAGES); do rm -rf packages/$$p/build; done
	@rm -rf build/release build/dist-stage dist

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_%-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
