# Reedwire — common developer commands.
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
test: ## Run every package's tests
	@set -e; for p in $(PACKAGES); do \
		echo "==> test $$p"; \
		(cd packages/$$p && gleam test); \
	done

.PHONY: test-%
test-%: ## Run one package's tests, e.g. make test-core
	@cd packages/$* && gleam test

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

# ---------------------------------------------------------------- housekeeping

.PHONY: clean
clean: ## Remove every package's build directory
	@for p in $(PACKAGES); do rm -rf packages/$$p/build; done

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_%-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
