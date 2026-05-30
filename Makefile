# Tidewater developer Makefile.
#
# Local dev and CI share these targets so behaviour is identical everywhere.
# Python tooling runs out of a project-local virtualenv (.venv); the dashboard
# uses npm. AWS-touching targets (deploy/destroy/seed-history) are no-ops until
# the phase that wires them up.

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
DASHBOARD := dashboard
PY_SRC := lambdas infra tests

# Quiet the jsii Node-version deprecation banner during synth.
export JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION := 1

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

$(VENV)/bin/python:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: install
install: install-python install-dashboard ## Install all Python + dashboard dependencies

.PHONY: install-python
install-python: $(VENV)/bin/python ## Install Python deps (toolchain + infra + lambdas) into .venv
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -r infra/requirements.txt
	$(PIP) install -r lambdas/shared/requirements.txt

.PHONY: install-dashboard
install-dashboard: ## Install dashboard npm deps
	cd $(DASHBOARD) && npm ci

.PHONY: lint
lint: ## Ruff check + format check (Python) and prettier check (dashboard)
	$(RUFF) check $(PY_SRC)
	$(RUFF) format --check $(PY_SRC)
	cd $(DASHBOARD) && npm run format:check

.PHONY: format
format: ## Auto-fix Python lint + format, and prettier-write the dashboard
	$(RUFF) check --fix $(PY_SRC)
	$(RUFF) format $(PY_SRC)
	cd $(DASHBOARD) && npm run format

.PHONY: typecheck
typecheck: ## mypy over lambdas + infra
	$(MYPY) lambdas infra

.PHONY: test
test: ## Run pytest (all suites) and the dashboard typecheck
	$(PYTEST)
	cd $(DASHBOARD) && npm run typecheck

.PHONY: synth
synth: ## cdk synth (sanity-check IaC); requires the cdk CLI on PATH
	PATH="$(CURDIR)/$(VENV)/bin:$$PATH" cdk synth --quiet

.PHONY: deploy
deploy: ## (Phase 2+) cdk deploy --all
	@echo "deploy is not wired up until Phase 2 (CoreStack). No-op."

.PHONY: destroy
destroy: ## (Phase 2+) cdk destroy --all
	@echo "destroy is not wired up until Phase 2 (CoreStack). No-op."

.PHONY: seed-history
seed-history: ## (Phase 11) invoke the bootstrap_history Lambda
	@echo "seed-history is not wired up until Phase 11 (forecaster). No-op."

.PHONY: clean
clean: ## Remove virtualenv, caches, and build artifacts
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache infra/cdk.out
	rm -rf $(DASHBOARD)/node_modules $(DASHBOARD)/dist
