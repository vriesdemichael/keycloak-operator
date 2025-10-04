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

# Code quality
.PHONY: lint
lint: ## Run linting checks
	uv run ruff check --fix

.PHONY: format
format: ## Format code
	uv run ruff format

.PHONY: type-check
type-check: ## Run type checking
	uv run ty check

.PHONY: quality
quality: lint format type-check

# Testing
.PHONY: test
test: quality test-unit test-integration

.PHONY: test-unit
test-unit: ## Run unit tests only
	uv run pytest tests/unit/ -v -m "not integration"

.PHONY: test-integration
test-integration: kind-teardown kind-setup deploy
	@echo "Running integration tests on fresh cluster (with parallel execution)..."
	uv run --group integration pytest tests/integration/ -v -m integration -n auto --dist=loadscope


.PHONY: test-cov
test-cov: kind-teardown kind-setup deploy  ## Same as test, but with coverage
	uv run pytest tests --cov=keycloak_operator --cov-report=term --cov-report=html

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

# Deployment
.PHONY: deploy
deploy: deploy-local ## Deploy operator (standard target name) TODO: fix up with actual production deploy when images and manifest are stored externally.

.PHONY: deploy-local
deploy-local: build-test setup-cluster install-cnpg ## Deploy operator to local Kind cluster (with CNPG if not already present)
	kind load docker-image keycloak-operator:test --name keycloak-operator-test
	# Re-apply CRDs to ensure the latest (idempotent)
	kubectl apply -f k8s/crds/keycloak-crd.yaml
	kubectl apply -f k8s/crds/keycloakclient-crd.yaml
	kubectl apply -f k8s/crds/keycloakrealm-crd.yaml
	kubectl apply -f k8s/rbac/
	sed 's|image: keycloak-operator:latest|image: keycloak-operator:test|g' k8s/operator-deployment.yaml | \
	sed 's|imagePullPolicy: IfNotPresent|imagePullPolicy: Never|g' | \
	kubectl apply -f -
	# Force a rollout to ensure latest local image is used even if spec unchanged
	kubectl patch deployment keycloak-operator -n keycloak-system -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"restarted-at\":\"$$(date -u +%Y%m%d%H%M%S)\"}}}}}" >/dev/null 2>&1 || true
	@echo "Waiting for operator to be ready..."
	kubectl rollout status deployment keycloak-operator -n keycloak-system --timeout=60s
	@echo "✓ Operator deployed successfully!"


.PHONY: install-cnpg
install-cnpg: ## Install CloudNativePG operator (idempotent)
	@./scripts/install-cnpg.sh || echo "CNPG install script exited with code $$? (already installed?)"

.PHONY: setup-cluster
setup-cluster: ## Ensure Kind cluster is running
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
dev-setup: install setup-cluster ## Full development environment setup
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

.PHONY: clean-all
clean-all: clean kind-teardown ## Clean up everything including Kind cluster
	docker system prune -f



# Documentation
.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	uv run mkdocs serve

.PHONY: docs-build
docs-build: ## Build documentation
	uv run mkdocs build

# Default target
.DEFAULT_GOAL := help