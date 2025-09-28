# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

This is an early-stage alternative Keycloak operator project built to replace the existing realm operator with a fully GitOps-compatible solution.

## Project Requirements

### Core Objectives
- **Alternative to realm operator**: Replace the current "temporary workaround" implementation with a properly designed solution
- **Full GitOps compatibility**: Everything must work with GitOps workflows, no manual intervention required
- **Improved secret management**: Address the poor secret handling in the current realm operator

### Technical Requirements
- **Multi-namespace operation**: Watch and manage resources across all namespaces, not limited to a single namespace
- **Python-based with Kopf**: Use the Kopf framework for operator development (not Go-based controller-runtime)
- **Dynamic client provisioning**: Allow clients to be dynamically provisioned from any authorized namespace
- **Kubernetes-native security**: Bypass Keycloak's security mechanisms in favor of K8s RBAC for authorization
- **Least privilege principle**: Implement strict RBAC controls to manage permissions at the Kubernetes level

### Architecture Principles
- Kubernetes Custom Resource Definitions (CRDs) for Keycloak resource management
- Controller logic using Kopf for reconciliation loops
- RBAC-based authorization instead of Keycloak's built-in security
- Cross-namespace resource watching and management
- GitOps-first design for declarative configuration

## Development Setup

### Requirements
- Python environment with Kopf framework setup
- Kubernetes development environment (local cluster recommended)
- **Kind (Kubernetes in Docker)** - Required for local integration testing
- Docker - Required for Kind cluster creation
- kubectl - Kubernetes command-line tool
- CRD definitions for Keycloak resources
- RBAC policies and service account configuration
- Build and test automation for Python-based operator

### Installing Prerequisites

**Kind Installation:**
```bash
# Linux/WSL
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# macOS
brew install kind

# Windows
choco install kind
```

**Docker Installation:**
- Linux: Follow [Docker Engine installation guide](https://docs.docker.com/engine/install/)
- macOS/Windows: Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Development Habits
At the end of your task list always do:
1. `uv run ruff check --fix` - Fix linting issues
2. `uv run ruff format` - Format code consistently
3. `uv run pytest tests/unit/` - Run unit tests (fast)

For comprehensive testing after major changes:
4. `make test-integration-local` - Run full integration test suite

**Important**: Always use `uv run <command>` when running anything from this project or it won't pick up the dependencies.

### Testing Infrastructure

This project has comprehensive testing infrastructure:

**Test Types:**
- **Unit Tests**: Fast tests in `tests/unit/` that mock Kubernetes interactions
- **Integration Tests**: Real Kubernetes tests in `tests/integration/` using Kind clusters

**Quick Testing Commands:**
```bash
# Development test workflow (fast)
make dev-test                    # Run linting + unit tests

# Unit tests only
make test-unit                   # Fast unit tests
uv run pytest tests/unit/ -v    # Direct pytest

# Integration tests (requires Kind cluster)
make test-integration-local      # Full integration test suite
make kind-setup                  # Set up Kind cluster
make test-integration            # Python integration tests only

# All tests
make test-all                    # Both unit and integration tests
```

**Kind Cluster Management:**
```bash
# Cluster lifecycle
make kind-setup                  # Create Kind cluster with test dependencies
make kind-status                 # Check cluster status
make kind-teardown              # Clean up cluster

# Quick development cycle
make dev-setup                   # Install deps + setup cluster
make deploy-local               # Build and deploy operator to Kind
make operator-logs              # Follow operator logs
```

**Legacy Manual Testing (for reference):**

**Manual Test Steps:**

1. **Install/Update CRDs** (if changed):
   ```bash
   kubectl apply -f k8s/crds/
   ```

2. **Start the operator** (in background):
   ```bash
   uv run python -m keycloak_operator.operator &
   ```

3. **Create test namespace and secrets**:
   ```bash
   kubectl create namespace keycloak-test
   kubectl create secret generic keycloak-db-secret --from-literal=password=testpass -n keycloak-test
   kubectl create secret generic keycloak-admin-secret --from-literal=password=admin123 -n keycloak-test
   ```

4. **Deploy test Keycloak instance**:
   ```yaml
   # test-keycloak.yaml
   apiVersion: keycloak.mdvr.nl/v1
   kind: Keycloak
   metadata:
     name: test-keycloak
     namespace: keycloak-test
   spec:
     image: "quay.io/keycloak/keycloak:23.0.0"
     replicas: 1
     database:
       type: "h2"
       host: "localhost"
       name: "keycloak"
       username: "keycloak"
       password_secret:
         name: "keycloak-db-secret"
         key: "password"
     admin_access:
       username: "admin"
       password_secret:
         name: "keycloak-admin-secret"
         key: "password"
     service:
       type: "ClusterIP"
       port: 8080
   ```

5. **Apply and verify**:
   ```bash
   kubectl apply -f test-keycloak.yaml
   kubectl get keycloaks.keycloak.mdvr.nl -n keycloak-test
   kubectl get pods,services -n keycloak-test
   ```

6. **Test health endpoint**:
   ```bash
   kubectl port-forward -n keycloak-test service/test-keycloak-keycloak 8080:8080 &
   curl http://localhost:8080/health
   # Should return: {"status": "UP", ...}
   ```

7. **Cleanup**:
   ```bash
   kubectl delete -f test-keycloak.yaml
   kubectl delete namespace keycloak-test
   ```

## Documentation
Whenever a change in api is made or a significant change for the end user the readme.md is to be updated.
The readme should reflect how the end user will interact with the software.