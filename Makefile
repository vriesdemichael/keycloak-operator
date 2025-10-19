# Makefile for Keycloak Operator development and testing

# Docker registry configuration
VERSION ?= $(shell grep '^version = ' pyproject.toml | cut -d'"' -f2)

.PHONY: help
help: ## Show this help message
	@echo "Keycloak Operator Development Commands"
	@echo "====================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Development setup
.PHONY: install
install: ## Install development dependencies
	uv sync --group dev

# Code quality
.PHONY: lint
lint: ## Run linting checks
	uv run --group quality ruff check --fix

.PHONY: format
format: ## Format code
	uv run --group quality ruff format

.PHONY: type-check
type-check: ## Run type checking
	uv run --group quality ty check

.PHONY: quality
quality: format lint type-check

# Testing
# ========
# NEW: Tests deploy operator themselves via Helm (no pre-deployment needed)
# Prerequisites: Kind cluster + operator image built and loaded

.PHONY: test
test: quality test-unit test-integration ## Run complete test suite (unit + integration)

.PHONY: test-unit
test-unit: ## Run unit tests only
	uv run --group test pytest tests/unit/ -v

.PHONY: test-integration
test-integration: ensure-kind-cluster build-all-test ## Run integration tests (builds images, tests deploy via Helm)
	@echo "Running integration tests (tests will deploy operator via Helm)..."
	uv run pytest tests/integration/ -v -n auto --dist=loadscope

.PHONY: test-integration-clean
test-integration-clean: kind-teardown test-integration ## Clean cluster first, then run integration tests


# Kind cluster management
# ========================
# kind-setup: Creates bare cluster with namespaces (no operator/CRDs)
# ensure-kind-cluster: Idempotent - creates cluster only if it doesn't exist
# kind-teardown: Complete cleanup of cluster and resources

.PHONY: kind-setup
kind-setup: ## Set up Kind cluster for integration testing
	./scripts/kind-setup.sh

.PHONY: kind-teardown
kind-teardown: ## Tear down Kind cluster
	./scripts/kind-teardown.sh


# Operator operations
.PHONY: build
build: ## Build operator Docker image
	docker build -f images/operator/Dockerfile -t keycloak-operator:latest .

.PHONY: build-test
build-test: ## Build operator Docker image for testing and load it into kind cluster
	docker build -f images/operator/Dockerfile -t keycloak-operator:test .
	@echo "Loading operator image into Kind cluster..."
	kind load docker-image keycloak-operator:test --name keycloak-operator-test

# Optimized Keycloak image operations
.PHONY: build-keycloak-optimized
build-keycloak-optimized: ## Build optimized Keycloak image for faster test startup
	@echo "Building optimized Keycloak image..."
	@echo "This may take 2-3 minutes on first build (downloads and optimizes Keycloak)..."
	docker build -f images/keycloak-optimized/Dockerfile -t keycloak-optimized:test images/keycloak-optimized/
	@echo "✓ Optimized Keycloak image built successfully"

.PHONY: kind-load-keycloak-optimized
kind-load-keycloak-optimized: build-keycloak-optimized ## Build and load optimized Keycloak image into Kind
	@echo "Loading optimized Keycloak image into Kind cluster..."
	kind load docker-image keycloak-optimized:test --name keycloak-operator-test
	@echo "✓ Optimized Keycloak image loaded into Kind"

.PHONY: build-all-test
build-all-test: build-test kind-load-keycloak-optimized ## Build operator and optimized Keycloak, load both into Kind


# Deployment
# ===========
# Deployment flow:
#   1. build-test: Build operator image tagged as 'test'
#   2. ensure-kind-cluster: Ensure Kind cluster exists (idempotent)
#   3. install-cnpg: Install CNPG operator (idempotent)
#   4. helm-deploy-operator: Deploy operator + Keycloak using Helm chart

.PHONY: deploy
deploy: deploy-local ## Deploy operator (standard target name)

.PHONY: deploy-local
deploy-local: build-test ensure-kind-cluster install-cnpg ## Deploy operator + test Keycloak instance to local Kind cluster
	@echo "Deploying operator and Keycloak using Helm chart..."
	@$(MAKE) helm-deploy-operator
	@echo "Waiting for operator to be ready..."
	kubectl rollout status deployment keycloak-operator -n keycloak-system --timeout=60s
	@echo "Waiting for keycloak instance to be ready..."
	kubectl wait --for=jsonpath='{.status.phase}'=Ready keycloak/keycloak -n keycloak-system --timeout=120s
	@echo "✓ Operator and Keycloak deployed successfully!"

.PHONY: helm-deploy-operator
helm-deploy-operator: ## Deploy operator using Helm chart (with Keycloak for testing)
	@echo "Deploying operator with Helm (admin password will be auto-generated)..."
	helm upgrade --install keycloak-operator ./charts/keycloak-operator \
		--namespace keycloak-system \
		--create-namespace \
		--set namespace.create=false \
		--set operator.image.repository=keycloak-operator \
		--set operator.image.tag=test \
		--set operator.image.pullPolicy=Never \
		--set operator.replicaCount=2 \
		--set keycloak.enabled=true \
		--set keycloak.replicas=1 \
		--set keycloak.version=26.0.0 \
		--set keycloak.database.type=postgresql \
		--set keycloak.database.cnpg.enabled=true \
		--set keycloak.database.cnpg.clusterName=keycloak-postgres \
		--wait \
		--timeout=300s
	@echo "✓ Operator deployed successfully"
	@echo "Admin credentials auto-generated in secret: keycloak-admin-credentials"

.PHONY: helm-uninstall-operator
helm-uninstall-operator: ## Uninstall operator Helm release
	@echo "Uninstalling operator Helm release..."
	helm uninstall keycloak-operator -n keycloak-system || echo "Release not found"


.PHONY: install-cnpg
install-cnpg: ## Install CloudNativePG operator (idempotent)
	@./scripts/install-cnpg.sh || echo "CNPG install script exited with code $$? (already installed?)"

.PHONY: ensure-kind-cluster
ensure-kind-cluster: ## Ensure Kind cluster is running
	@if ! kind get clusters | grep -q keycloak-operator-test; then \
		echo "Setting up Kind cluster..."; \
		make kind-setup; \
	else \
		echo "Kind cluster 'keycloak-operator-test' already exists - reusing"; \
	fi

.PHONY: operator-logs
operator-logs: ## Show recent operator logs (last 200 lines)
	kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=200

.PHONY: operator-logs-tail
operator-logs-tail: ## Tail operator logs (follow mode)
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

.PHONY: dev-setup
dev-setup: install ensure-kind-cluster ## Full development environment setup
	@echo "Development environment ready!"
	@echo "Run 'make deploy' to deploy the operator"
	@echo "Run 'make test' to run complete test suite"



.PHONY: clean
clean: ## Clean up development artifacts
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf test-logs/
	rm -rf .tmp/
	docker image prune -f

.PHONY: clean-test-resources
clean-test-resources: ## Clean up stuck test resources from Kubernetes
	@echo "Cleaning up test resources..."
	@./scripts/clean-test-resources.sh --force

.PHONY: clean-all
clean-all: clean kind-teardown ## Clean up everything including Kind cluster
	docker system prune -f



# Documentation
.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	uv run --group docs mkdocs serve

.PHONY: docs-build
docs-build: ## Build documentation
	uv run --group docs mkdocs build

# Default target
.DEFAULT_GOAL := help
