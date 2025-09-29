# Makefile for Keycloak Operator development and testing

.PHONY: help
help: ## Show this help message
	@echo "Keycloak Operator Development Commands"
	@echo "====================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Development setup
.PHONY: install
install: ## Install development dependencies
	uv sync --all-extras

.PHONY: install-dev
install-dev: ## Install development dependencies only
	uv sync --group dev

.PHONY: install-integration
install-integration: ## Install integration test dependencies
	uv sync --group integration

# Code quality
.PHONY: lint
lint: ## Run linting checks
	uv run ruff check

.PHONY: lint-fix
lint-fix: ## Run linting with auto-fix
	uv run ruff check --fix

.PHONY: format
format: ## Format code
	uv run ruff format

.PHONY: format-check
format-check: ## Check code formatting
	uv run ruff format --check

.PHONY: quality
quality: lint format-check ## Run all code quality checks

# Testing (following 2025 operator best practices)
.PHONY: test
test: quality test-unit test-integration ## Run complete test suite (unit + integration)

.PHONY: test-unit
test-unit: ## Run unit tests only
	uv run pytest tests/unit/ -v -m "not integration"

.PHONY: test-integration
test-integration: deploy ## Run integration tests (auto-deploys operator)
	@echo "Running integration tests against existing cluster..."
	uv run --group integration pytest tests/integration/ -v -m integration

.PHONY: test-all
test-all: test ## Alias for complete test suite

.PHONY: test-cov
test-cov: ## Run tests with coverage
	uv run pytest tests/unit/ --cov=keycloak_operator --cov-report=term --cov-report=html

.PHONY: test-fast
test-fast: ## Run fast tests only (exclude slow tests)
	uv run pytest tests/ -v -m "not slow"

# Kind cluster management
.PHONY: kind-setup
kind-setup: ## Set up Kind cluster for integration testing
	./scripts/kind-setup.sh

.PHONY: kind-teardown
kind-teardown: ## Tear down Kind cluster
	./scripts/kind-teardown.sh

.PHONY: kind-status
kind-status: ## Check Kind cluster status
	@echo "Kind clusters:"
	@kind get clusters || echo "No Kind clusters found"
	@echo ""
	@echo "Kubernetes context:"
	@kubectl config current-context || echo "No active context"
	@echo ""
	@echo "Cluster info:"
	@kubectl cluster-info || echo "Cannot connect to cluster"


# Operator operations
.PHONY: build
build: ## Build operator Docker image
	docker build -t keycloak-operator:latest .

.PHONY: build-test
build-test: ## Build operator Docker image for testing
	docker build -t keycloak-operator:test .

# Deployment (following 2025 operator best practices)
.PHONY: deploy
deploy: deploy-local ## Deploy operator (standard target name)

.PHONY: deploy-local
deploy-local: build-test setup-cluster ## Deploy operator to local Kind cluster
	kind load docker-image keycloak-operator:test --name keycloak-operator-test
	kubectl apply -f k8s/crds/keycloak-crd.yaml
	kubectl apply -f k8s/crds/keycloakclient-crd.yaml
	kubectl apply -f k8s/crds/keycloakrealm-crd.yaml
	kubectl apply -f k8s/rbac/
	sed 's|image: keycloak-operator:latest|image: keycloak-operator:test|g' k8s/operator-deployment.yaml | \
	sed 's|imagePullPolicy: IfNotPresent|imagePullPolicy: Never|g' | \
	kubectl apply -f -

.PHONY: setup-cluster
setup-cluster: ## Ensure Kind cluster is running
	@if ! kind get clusters | grep -q keycloak-operator-test; then \
		echo "Setting up Kind cluster..."; \
		make kind-setup; \
	else \
		echo "Kind cluster 'keycloak-operator-test' already exists - reusing"; \
	fi

.PHONY: operator-logs
operator-logs: ## Show operator logs
	kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100 -f

.PHONY: operator-status
operator-status: ## Show operator status
	@echo "Operator deployment:"
	@kubectl get deployment keycloak-operator -n keycloak-system || echo "Operator not deployed"
	@echo ""
	@echo "Operator pods:"
	@kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator || echo "No operator pods"
	@echo ""
	@echo "CRDs:"
	@kubectl get crd | grep keycloak || echo "No Keycloak CRDs found"

# Development workflows (following 2025 operator best practices)
.PHONY: dev-setup
dev-setup: install setup-cluster ## Full development environment setup
	@echo "Development environment ready!"
	@echo "Run 'make deploy' to deploy the operator"
	@echo "Run 'make test' to run complete test suite"

.PHONY: dev-test
dev-test: quality test-unit ## Run development tests (quality + unit tests)

.PHONY: dev-full-test
dev-full-test: test ## Run full development test suite

.PHONY: clean
clean: ## Clean up development artifacts
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf test-logs/
	rm -rf .tmp/
	docker image prune -f

.PHONY: clean-all
clean-all: clean kind-teardown ## Clean up everything including Kind cluster
	docker system prune -f

# CI simulation (following 2025 operator best practices)
.PHONY: ci-test
ci-test: ## Simulate CI testing locally
	@echo "Running CI simulation..."
	make test

.PHONY: test-watch
test-watch: ## Run tests in watch mode for development
	@echo "Running tests in watch mode (press Ctrl+C to stop)..."
	while true; do \
		make test-unit; \
		echo "Waiting for changes... (press Ctrl+C to stop)"; \
		sleep 2; \
	done

# Documentation
.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	uv run mkdocs serve

.PHONY: docs-build
docs-build: ## Build documentation
	uv run mkdocs build

# Default target
.DEFAULT_GOAL := help