# inspector-triage. `make verify` is the one command that checks everything.
.DEFAULT_GOAL := help
SHELL := /bin/bash
PYTHON ?= python3
SAM ?= sam

# Fail with the install hint rather than a bare "command not found".
require = @command -v $(1) >/dev/null 2>&1 || { echo "missing $(1): $(2)"; exit 1; }

.PHONY: help test lint validate build package-check verify clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  %-15s %s\n", $$1, $$2}'

test: ## Run the unit, end-to-end and template tests
	$(PYTHON) -m unittest discover -s tests -v

lint: ## cfn-lint the template, shellcheck the scripts, compile the handler
	$(call require,cfn-lint,pip install cfn-lint)
	$(call require,shellcheck,brew install shellcheck)
	cfn-lint template.yaml
	shellcheck scripts/*.sh
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m py_compile src/handler.py scripts/check_package.py
	@echo "lint: clean"

validate: ## Validate the SAM transform
	$(call require,$(SAM),see the SAM CLI install docs)
	$(SAM) validate --lint

build: ## Build the deployment artifact into .aws-sam/build
	$(call require,$(SAM),see the SAM CLI install docs)
	$(SAM) build

package-check: build ## Assert the artifact ships what the handler needs
	$(PYTHON) scripts/check_package.py

verify: lint test package-check ## Everything: lint, tests, and the packaging check
	@echo
	@echo "verify: all checks passed"

clean: ## Remove build artifacts and bytecode
	rm -rf .aws-sam
	find . -name __pycache__ -type d -not -path './.git/*' -prune -exec rm -rf {} +
	@echo "clean: done"
