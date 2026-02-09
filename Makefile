# Makefile for Keycloak Operator Development and Testing

# Configuration
VERSION ?= $(shell grep '^version = ' pyproject.toml | cut -d'"' -f2)
REVISION ?= $(shell git rev-parse HEAD)
CREATED ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
KEYCLOAK_VERSION ?= 26.5.2
TEST_IMAGE_TAG ?= test
export UV_LINK_MODE=copy

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help: ## Show this help message
	@echo "Keycloak Operator Development Commands"
	@echo "====================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-35s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# Development Setup
# ============================================================================

.PHONY: install
install: ## Install development dependencies
	uv sync --group dev

.PHONY: install-hooks
install-hooks: ## Install pre-commit hooks
	uv run --group quality pre-commit install
	uv run --group quality pre-commit install --hook-type commit-msg

.PHONY: setup
setup: install install-hooks ## Complete development setup (install deps + hooks)

.PHONY: generate-models
generate-models: ## Generate Pydantic models from Keycloak OpenAPI specs
	uv run --group model-generation python scripts/generate_keycloak_models.py

# ============================================================================
# Code Quality
# ============================================================================

.PHONY: format
format: ## Format code with ruff
	uv run --group quality ruff format

.PHONY: lint
lint: ## Lint code with ruff
	uv run --group quality ruff check --fix

.PHONY: type-check
type-check: ## Run type checking with ty
	uv run --group quality ty check

.PHONY: quality
quality: format lint type-check ## Run all quality checks

.PHONY: validate-decisions
validate-decisions: ## Validate Decision Records (Architecture/Development)
	@if [ -n "$$(ls docs/decisions/*.yaml 2>/dev/null)" ]; then \
		uv run scripts/adr_validator.py --validate; \
	else \
		echo "No decision record files found"; \
	fi

.PHONY: validate-docs
validate-docs: ## Validate documentation examples against schemas
	uv run --group dev python scripts/lib/schema_validator.py --fail-on-error

.PHONY: validate-crd-pydantic
validate-crd-pydantic: ## Validate CRD schemas match Pydantic models
	uv run --group dev python scripts/lib/crd_pydantic_validator.py --fail-on-error

# ============================================================================
# Documentation
# ============================================================================

.PHONY: docs-generate-decisions
docs-generate-decisions: ## Generate markdown from decision record YAML files
	@./scripts/build-adr-docs.sh

.PHONY: docs-build
docs-build: docs-generate-decisions ## Build documentation site
	uv run --group docs mkdocs build

.PHONY: docs-clean
docs-clean: ## Clean generated documentation
	rm -rf site/
	rm -rf docs/decisions/generated-markdown/

# ============================================================================
# Unit Testing
# ============================================================================

.PHONY: test-unit
test-unit: ## Run unit tests with coverage (network disabled to catch accidental external calls)
	uv run --group test pytest tests/unit/ -v --disable-socket --allow-unix-socket --cov=keycloak_operator --cov-report=

# ============================================================================
# Integration Testing - Test Images
# ============================================================================

.PHONY: build-test
build-test: ## Build operator production image and load into Kind
	@echo "Building operator production image..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg CREATED=$(CREATED) \
		-f images/operator/Dockerfile --target production -t keycloak-operator:$(TEST_IMAGE_TAG) .
	@echo "✓ Operator image built"
	@echo "Loading operator image into Kind cluster..."
	kind load docker-image keycloak-operator:$(TEST_IMAGE_TAG) --name keycloak-operator-test
	@echo "✓ Operator image loaded into Kind"

.PHONY: build-test-coverage
build-test-coverage: ## Build operator test image with coverage instrumentation
	@echo "Building operator test image with coverage..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg CREATED=$(CREATED) \
		-f images/operator/Dockerfile --target test -t keycloak-operator:$(TEST_IMAGE_TAG) .
	@echo "✓ Operator coverage image built"

.PHONY: kind-load-test-coverage
kind-load-test-coverage: build-test-coverage ## Build and load coverage-instrumented image into Kind
	@echo "Loading coverage-instrumented operator image into Kind cluster..."
	kind load docker-image keycloak-operator:$(TEST_IMAGE_TAG) --name keycloak-operator-test
	@echo "✓ Coverage image loaded into Kind"

.PHONY: build-keycloak-optimized
build-keycloak-optimized: ## Build optimized Keycloak image
	@echo "Building optimized Keycloak image for faster startup..."
	docker build -f images/keycloak-optimized/Dockerfile \
		--build-arg KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) \
		-t keycloak-optimized:$(KEYCLOAK_VERSION) \
		.
	@echo "✓ Optimized Keycloak image built successfully"

.PHONY: kind-load-keycloak-optimized
kind-load-keycloak-optimized: build-keycloak-optimized ## Build and load optimized Keycloak into Kind
	@echo "Loading optimized Keycloak image into Kind cluster..."
	kind load docker-image keycloak-optimized:$(KEYCLOAK_VERSION) --name keycloak-operator-test
	@echo "✓ Optimized Keycloak image loaded into Kind"

.PHONY: build-keycloak-optimized-tracing
build-keycloak-optimized-tracing: ## Build optimized Keycloak image with tracing support
	@echo "Building optimized Keycloak image with tracing (OTEL) support..."
	docker build -f images/keycloak-optimized/Dockerfile \
		--build-arg KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) \
		--build-arg TRACING_ENABLED=true \
		-t keycloak-optimized-tracing:$(KEYCLOAK_VERSION) \
		.
	@echo "✓ Optimized Keycloak tracing image built successfully"

.PHONY: kind-load-keycloak-optimized-tracing
kind-load-keycloak-optimized-tracing: build-keycloak-optimized-tracing ## Build and load tracing Keycloak into Kind
	@echo "Loading optimized Keycloak tracing image into Kind cluster..."
	kind load docker-image keycloak-optimized-tracing:$(KEYCLOAK_VERSION) --name keycloak-operator-test
	@echo "✓ Optimized Keycloak tracing image loaded into Kind"

# Tracing detection: mirrors _is_tracing_enabled() in tests/integration/conftest.py
# - OTEL_TEST_TRACING_ENABLED explicitly set → normalize to lowercase, then match
# - CI env var set → tracing disabled (CI default)
# - Neither set → tracing enabled (local dev default)
_TRACING_ENABLED := $(if $(OTEL_TEST_TRACING_ENABLED),$(if $(filter true yes 1,$(shell printf '%s' '$(OTEL_TEST_TRACING_ENABLED)' | tr '[:upper:]' '[:lower:]')),true,false),$(if $(CI),false,true))

.PHONY: kind-load-keycloak-selected
kind-load-keycloak-selected: ## Build and load the correct Keycloak image variant based on tracing config
	@if [ "$(_TRACING_ENABLED)" = "true" ]; then \
		echo "Tracing enabled — loading keycloak-optimized-tracing image"; \
		$(MAKE) kind-load-keycloak-optimized-tracing; \
	else \
		echo "Tracing disabled — loading keycloak-optimized image"; \
		$(MAKE) kind-load-keycloak-optimized; \
	fi

.PHONY: kind-load-keycloak-all
kind-load-keycloak-all: ## Build and load BOTH optimized Keycloak images (for build mismatch tests)
	$(MAKE) kind-load-keycloak-optimized
	$(MAKE) kind-load-keycloak-optimized-tracing

.PHONY: build-all-test
build-all-test: build-test kind-load-keycloak-all ## Build and load all test images

# ============================================================================
# Integration Testing - Execution (INTERNAL TARGETS)
# ============================================================================
# WARNING: These targets are internal implementation details.
# DO NOT call these targets directly! Use 'make test' instead.
#
# Why? Integration tests require a FRESH cluster to guarantee a clean state.
# Calling test-integration or test-integration-coverage directly on an existing
# cluster can leave the cluster in a broken state (stuck namespaces, orphaned
# resources) that will cause subsequent test runs to fail.
#
# The 'make test' target properly:
# 1. Tears down any existing cluster
# 2. Creates a fresh cluster
# 3. Runs all tests in the correct order
# ============================================================================

# Internal target - do not use directly, use 'make test' instead
.PHONY: _test-integration
_test-integration: ensure-test-cluster build-all-test
	@echo "Running integration tests (tests deploy operator via Helm)..."
	TEST_IMAGE_TAG=$(TEST_IMAGE_TAG) KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) uv run pytest tests/integration/ -v -n auto --dist=loadscope

# Internal target - do not use directly, use 'make test' instead
.PHONY: _test-integration-coverage
_test-integration-coverage: ensure-test-cluster kind-load-test-coverage kind-load-keycloak-all
	@echo "Running integration tests with coverage enabled..."
	INTEGRATION_COVERAGE=true TEST_IMAGE_TAG=$(TEST_IMAGE_TAG) KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) uv run pytest tests/integration/ -v -n auto --dist=loadscope
	@echo "Combining coverage data..."
	./scripts/combine-coverage.sh

# Deprecated aliases that warn users - these will be removed in a future version
.PHONY: test-integration
test-integration:
	@echo ""
	@echo "=============================================================="
	@echo "ERROR: 'make test-integration' should not be used directly!"
	@echo "=============================================================="
	@echo ""
	@echo "Integration tests require a fresh cluster to guarantee clean state."
	@echo "Using this target directly can leave the cluster broken."
	@echo ""
	@echo "Please use 'make test' instead, which:"
	@echo "  1. Tears down any existing cluster"
	@echo "  2. Creates a fresh cluster"
	@echo "  3. Runs quality checks, unit tests, and integration tests"
	@echo ""
	@echo "If you absolutely need to run integration tests on an existing"
	@echo "cluster (not recommended), use: make _test-integration"
	@echo ""
	@exit 1

.PHONY: test-integration-coverage
test-integration-coverage:
	@echo ""
	@echo "=============================================================="
	@echo "ERROR: 'make test-integration-coverage' should not be used directly!"
	@echo "=============================================================="
	@echo ""
	@echo "Integration tests require a fresh cluster to guarantee clean state."
	@echo "Using this target directly can leave the cluster broken."
	@echo ""
	@echo "Please use 'make test' instead, which:"
	@echo "  1. Tears down any existing cluster"
	@echo "  2. Creates a fresh cluster"
	@echo "  3. Runs quality checks, unit tests, and integration tests"
	@echo ""
	@echo "If you absolutely need to run integration tests on an existing"
	@echo "cluster (not recommended), use: make _test-integration-coverage"
	@echo ""
	@exit 1

.PHONY: test-integration-clean
test-integration-clean:
	@echo ""
	@echo "=============================================================="
	@echo "WARNING: 'make test-integration-clean' is deprecated!"
	@echo "=============================================================="
	@echo ""
	@echo "Please use 'make test' instead."
	@echo ""
	@exit 1

# ============================================================================
# Complete Test Suite
# ============================================================================
# NOTE: Matches GitHub Actions CI/CD workflow (.github/workflows/ci-cd.yml)
# CI workflow: build-test-image -> code-quality + unit-tests (parallel) -> integration-tests
# Local workflow: quality -> fresh cluster -> unit tests -> integration tests

.PHONY: test
test: test-pre-commit ## Run complete test suite (quality + unit + integration)

.PHONY: test-pre-commit
test-pre-commit: ## Complete pre-commit flow (quality + docs validation + fresh cluster + unit + integration with coverage)
	@mkdir -p .tmp/test-logs
	@rm -f .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] =====================================" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Pre-commit test suite" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] =====================================" | tee -a .tmp/test-pre-commit.log
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Step 1/5: Running quality checks..." | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] -------------------------------------" | tee -a .tmp/test-pre-commit.log
	@bash -c "set -o pipefail; $(MAKE) quality 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Quality checks failed" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Quality checks passed" | tee -a .tmp/test-pre-commit.log
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Step 2/5: Validating documentation..." | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] -------------------------------------" | tee -a .tmp/test-pre-commit.log
	@bash -c "set -o pipefail; $(MAKE) validate-docs 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Documentation validation failed" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Documentation validation passed" | tee -a .tmp/test-pre-commit.log
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Step 3/5: Setting up fresh cluster..." | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] -------------------------------------" | tee -a .tmp/test-pre-commit.log
	@bash -c "set -o pipefail; $(MAKE) kind-teardown 2>&1 | tee -a .tmp/test-pre-commit.log" || true
	@bash -c "set -o pipefail; $(MAKE) kind-setup 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Failed to setup Kind cluster" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Fresh cluster ready" | tee -a .tmp/test-pre-commit.log
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Step 4/5: Running unit tests with coverage..." | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] -------------------------------------" | tee -a .tmp/test-pre-commit.log
	@bash -c "set -o pipefail; $(MAKE) test-unit 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Unit tests failed" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Unit tests passed" | tee -a .tmp/test-pre-commit.log
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Step 5/5: Running integration tests with coverage..." | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] -------------------------------------" | tee -a .tmp/test-pre-commit.log
	@bash -c "set -o pipefail; $(MAKE) install-cnpg 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Failed to install CNPG" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@bash -c "set -o pipefail; $(MAKE) install-cert-manager 2>&1 | tee -a .tmp/test-pre-commit.log" || { echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Failed to install cert-manager" | tee -a .tmp/test-pre-commit.log; exit 1; }
	@bash -c "set -o pipefail; INTEGRATION_COVERAGE=true $(MAKE) _test-integration-coverage 2>&1 | tee -a .tmp/test-pre-commit.log" || { \
		echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ❌ Integration tests failed, collecting diagnostics..." | tee -a .tmp/test-pre-commit.log; \
		$(MAKE) collect-test-logs; \
		exit 1; \
	}
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Integration tests passed" | tee -a .tmp/test-pre-commit.log
	@$(MAKE) collect-test-logs
	@echo "" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] =====================================" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ All pre-commit tests passed!" | tee -a .tmp/test-pre-commit.log
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] =====================================" | tee -a .tmp/test-pre-commit.log

.PHONY: collect-test-logs
collect-test-logs: ## Collect logs and diagnostics from test cluster
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] Collecting test logs and diagnostics..."
	@mkdir -p .tmp/test-logs
	@kubectl cluster-info > .tmp/test-logs/cluster-info.log 2>&1 || true
	@for pod in $$(kubectl get pods --all-namespaces -l app.kubernetes.io/name=keycloak-operator -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null); do \
		namespace=$$(echo $$pod | cut -d/ -f1); \
		podname=$$(echo $$pod | cut -d/ -f2); \
		echo "=== Logs from $$namespace/$$podname ===" >> .tmp/test-logs/operator-logs.log; \
		kubectl logs -n $$namespace $$podname --all-containers=true --tail=2000 >> .tmp/test-logs/operator-logs.log 2>&1 || true; \
	done
	@kubectl get deployment -l app.kubernetes.io/name=keycloak-operator --all-namespaces -o wide > .tmp/test-logs/operator-status.log 2>&1 || true
	@kubectl get keycloaks,keycloakrealms,keycloakclients --all-namespaces -o wide > .tmp/test-logs/test-resources.log 2>&1 || true
	@kubectl get events --all-namespaces --sort-by='.lastTimestamp' > .tmp/test-logs/events.log 2>&1 || true
	@kubectl get pods --all-namespaces -o wide > .tmp/test-logs/all-pods.log 2>&1 || true
	@echo "[$(shell date -u +%Y-%m-%dT%H:%M:%SZ)] ✓ Test logs collected in .tmp/test-logs/"

# ============================================================================
# Test Cluster Management
# ============================================================================

.PHONY: kind-setup
kind-setup: ## Create fresh Kind cluster
	@./scripts/kind-setup.sh

.PHONY: kind-teardown
kind-teardown: ## Destroy Kind cluster
	@./scripts/kind-teardown.sh

.PHONY: install-cnpg
install-cnpg: ## Install CNPG operator (idempotent)
	@./scripts/install-cnpg.sh

.PHONY: install-cert-manager
install-cert-manager: ## Install cert-manager for webhooks (idempotent)
	@./scripts/install-cert-manager.sh

.PHONY: ensure-test-cluster
ensure-test-cluster: ## Ensure clean test cluster ready for integration tests (idempotent)
	@echo "Ensuring test cluster is ready..."
	@if ! kind get clusters 2>/dev/null | grep -qx 'keycloak-operator-test'; then \
		echo "  Cluster doesn't exist - creating..."; \
		$(MAKE) kind-setup; \
	else \
		echo "  ✓ Cluster exists"; \
	fi
	@echo "  Ensuring CNPG operator is installed..."
	@$(MAKE) install-cnpg
	@echo "  Ensuring cert-manager is installed..."
	@$(MAKE) install-cert-manager
	@echo "✓ Test cluster ready for integration tests"

.PHONY: ensure-kind-cluster
ensure-kind-cluster: ensure-test-cluster ## Alias for ensure-test-cluster (for backwards compatibility)

# ============================================================================
# Cleanup & Maintenance
# ============================================================================

.PHONY: clean-integration-state
clean-integration-state: ## Reset Keycloak/DB state for cluster reuse (fast iteration)
	@./scripts/clean-integration-state.sh

.PHONY: clean-test-resources
clean-test-resources: ## Clean up stuck test namespaces
	@./scripts/clean-test-resources.sh --force

.PHONY: clean
clean: ## Clean development artifacts
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .coverage.*
	rm -rf test-logs/
	rm -rf .tmp/
	docker image prune -f

.PHONY: clean-all
clean-all: clean kind-teardown ## Clean everything including Kind cluster
	docker system prune -f

# ============================================================================
# Default
# ============================================================================

.DEFAULT_GOAL := help
