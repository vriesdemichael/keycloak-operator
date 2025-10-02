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

```

**Docker Installation:**
- Linux: Follow [Docker Engine installation guide](https://docs.docker.com/engine/install/)

### Development Habits
At the end of your task list always do:
1. `make test` - Run complete test suite (quality + unit + integration)

For quick iteration during development:
1. `make test-unit` - Run only unit tests (fast)
2. `make quality` - Fix linting and formatting issues

**Important**: Always use `uv run <command>` when running Python commands directly, or use the Makefile targets which handle dependencies automatically.

### Testing Infrastructure

This project has comprehensive testing infrastructure:

**Test Types:**
- **Unit Tests**: Fast tests in `tests/unit/` that mock Kubernetes interactions
- **Integration Tests**: Real Kubernetes tests in `tests/integration/` using Kind clusters

**Testing Commands (following 2025 best practices):**
```bash
# Complete test suite (recommended)
make test                        # Quality + unit + integration tests with cluster reuse

# Individual test types
make test-unit                   # Fast unit tests only
make test-integration            # Integration tests (auto-deploys operator)
make quality                     # Linting and formatting

# Development workflow
make dev-test                    # Quality + unit tests (fast development cycle)
make test-watch                  # Continuous testing mode
```

**Cluster and Deployment Management:**
```bash
# One-command setup and deployment
make dev-setup                   # Install deps + setup cluster
make deploy                      # Deploy operator (auto-creates cluster if needed)

# Cluster management
make kind-setup                  # Create Kind cluster manually
make kind-status                 # Check cluster status
make kind-teardown              # Clean up cluster

# Operator monitoring
make operator-status             # Check operator deployment status
make operator-logs              # Follow operator logs
```

## Development File Management

### Temporary Files
When creating temporary test files, scripts, or scratch work during development:

```bash
# Create temporary directory
mkdir -p .tmp

# Use for temporary test resources
echo "apiVersion: ..." > .tmp/my-test-resource.yaml

# Use for development scripts
echo "#!/bin/bash" > .tmp/debug-script.sh

# Cleanup when done
rm -rf .tmp/
# Or use: make clean
```

### Guidelines
- Never commit temporary files to the root directory
- Use `.tmp/` for all development scratch work
- Clean up after development sessions
- The `.tmp/` directory is git-ignored automatically which means you cannot read it anymore after you have created it, reference your own memory for the contents.

## Keycloak API Reference

This project includes the **official Keycloak Admin REST API specification** at `keycloak-api-spec.yaml` (downloaded from https://www.keycloak.org/docs-api/latest/rest-api/openapi.yaml).

### Using the API Specification

**For API Implementation:**
- **ALWAYS** reference `keycloak-api-spec.yaml` when implementing new Keycloak admin client methods
- **VERIFY** endpoint URLs, HTTP methods, and request/response schemas against the spec
- **ENSURE** API calls use current endpoints - never rely on outdated documentation

**For Future Development:**
- When adding new Keycloak functionality, search the OpenAPI spec for relevant endpoints
- Pay attention to required parameters, authentication requirements, and response codes
- Test API implementations against a real Keycloak instance to verify spec compliance

**Updating the Spec:**
- Periodically update `keycloak-api-spec.yaml` from the official source
- After updating, verify existing API implementations for any breaking changes
- Document any API version requirements in deployment instructions

### Implementation Guidelines

1. **Method Naming**: Use descriptive method names that match OpenAPI operationId when available
2. **Error Handling**: Implement proper error handling based on documented response codes
3. **Parameter Validation**: Validate inputs according to OpenAPI schema requirements
4. **Documentation**: Include API endpoint references in method docstrings

**Example Implementation Pattern:**
```python
def create_client_role(self, client_uuid: str, role_config: dict[str, Any], realm_name: str = "master") -> dict[str, Any]:
    """
    Create a client role.

    Based on OpenAPI spec: POST /admin/realms/{realm}/clients/{id}/roles

    Args:
        client_uuid: Client UUID in Keycloak
        role_config: Role configuration dictionary
        realm_name: Target realm name

    Returns:
        Created role configuration

    Raises:
        KeycloakAdminError: If role creation fails
    """
```

## Documentation
Whenever a change in api is made or a significant change for the end user the readme.md is to be updated.
The readme should reflect how the end user will interact with the software.