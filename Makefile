# Makefile for Keycloak Operator Development and Testing

# Configuration
VERSION ?= $(shell grep '^version = ' pyproject.toml | cut -d'"' -f2)
KEYCLOAK_VERSION ?= 26.4.1

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

# ============================================================================
# Unit Testing
# ============================================================================

.PHONY: test-unit
test-unit: ## Run unit tests
	uv run --group test pytest tests/unit/ -v

# ============================================================================
# Integration Testing - Test Images
# ============================================================================

.PHONY: build-test
build-test: ## Build operator test image and load into Kind
	@echo "Building operator test image..."
	docker build -t keycloak-operator:test .
	@echo "✓ Operator image built"
	@echo "Loading operator image into Kind cluster..."
	kind load docker-image keycloak-operator:test --name keycloak-operator-test
	@echo "✓ Operator image loaded into Kind"

.PHONY: build-keycloak-optimized
build-keycloak-optimized: ## Build optimized Keycloak image
	@echo "Building optimized Keycloak image for faster startup..."
	docker build -f Dockerfile.keycloak-optimized \
		--build-arg KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) \
		-t keycloak-optimized:$(KEYCLOAK_VERSION) \
		.
	@echo "✓ Optimized Keycloak image built successfully"

.PHONY: kind-load-keycloak-optimized
kind-load-keycloak-optimized: build-keycloak-optimized ## Build and load optimized Keycloak into Kind
	@echo "Loading optimized Keycloak image into Kind cluster..."
	kind load docker-image keycloak-optimized:$(KEYCLOAK_VERSION) --name keycloak-operator-test
	@echo "✓ Optimized Keycloak image loaded into Kind"

.PHONY: build-all-test
build-all-test: build-test kind-load-keycloak-optimized ## Build and load all test images

# ============================================================================
# Integration Testing - Execution
# ============================================================================

.PHONY: test-integration
test-integration: ensure-test-cluster build-all-test ## Run integration tests (builds images, deploys via Helm)
	@echo "Running integration tests (tests deploy operator via Helm)..."
	uv run pytest tests/integration/ -v -n auto --dist=loadscope

.PHONY: test-integration-clean
test-integration-clean: kind-teardown test-integration ## Tear down cluster, then run integration tests

# ============================================================================
# Complete Test Suite
# ============================================================================
# NOTE: Matches GitHub Actions CI/CD workflow (.github/workflows/ci-cd.yml)
# CI workflow: build-test-image -> code-quality + unit-tests (parallel) -> integration-tests
# Local workflow: quality -> fresh cluster -> unit tests -> integration tests

.PHONY: test
test: quality test-unit test-integration ## Run complete test suite (quality + unit + integration)

.PHONY: test-pre-commit
test-pre-commit: ## Complete pre-commit flow (quality + fresh cluster + unit + integration)
	@echo "====================================="
	@echo "Pre-commit test suite"
	@echo "====================================="
	@echo ""
	@echo "Step 1/4: Running quality checks..."
	@echo "-------------------------------------"
	@$(MAKE) quality || { echo "❌ Quality checks failed"; exit 1; }
	@echo "✓ Quality checks passed"
	@echo ""
	@echo "Step 2/4: Setting up fresh cluster..."
	@echo "-------------------------------------"
	@$(MAKE) kind-teardown || true
	@$(MAKE) kind-setup || { echo "❌ Failed to setup Kind cluster"; exit 1; }
	@echo "✓ Fresh cluster ready"
	@echo ""
	@echo "Step 3/4: Running unit tests..."
	@echo "-------------------------------------"
	@$(MAKE) test-unit || { echo "❌ Unit tests failed"; exit 1; }
	@echo "✓ Unit tests passed"
	@echo ""
	@echo "Step 4/4: Running integration tests..."
	@echo "-------------------------------------"
	@$(MAKE) install-cnpg || { echo "❌ Failed to install CNPG"; exit 1; }
	@mkdir -p .tmp
	@bash -c "set -o pipefail; $(MAKE) test-integration 2>&1 | tee .tmp/latest-integration-test.log" || { echo "❌ Integration tests failed"; exit 1; }
	@echo "✓ Integration tests passed"
	@echo ""
	@echo "====================================="
	@echo "✓ All pre-commit tests passed!"
	@echo "====================================="

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

.PHONY: ensure-test-cluster
ensure-test-cluster: ## Ensure clean test cluster ready for integration tests (idempotent)
	@echo "Ensuring test cluster is ready..."
	@if ! kind get clusters 2>/dev/null | grep -q "^keycloak-operator-test$$"; then \
		echo "  Cluster doesn't exist - creating..."; \
		$(MAKE) kind-setup; \
	else \
		echo "  ✓ Cluster exists"; \
	fi
	@echo "  Ensuring CNPG operator is installed..."
	@$(MAKE) install-cnpg
	@echo "  Resetting integration test state..."
	@$(MAKE) clean-integration-state
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
