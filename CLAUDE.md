# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. You may be redirected to this file for instruction if you are a different AI integration as well.

## Project Status

This is an early-stage alternative Keycloak operator project built to replace the existing realm operator with a fully GitOps-compatible solution.

## Project Requirements

### Core Objectives
- **Alternative to realm operator**: Replace the current "temporary workaround" implementation with a properly designed solution
- **Full GitOps compatibility**: Everything must work with GitOps workflows, no manual intervention required
- **Improved secret management**: Address the poor secret handling in the current realm operator
- **Least privilige**: No access to the keycloak instance other than through the CRDs

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
- First class support for CNPG as gitops database

### Keycloak Version Requirements
- **Minimum Version**: Keycloak 25.0.0 or later
- **Reason**: The separate management interface (port 9000) was introduced in Keycloak 25.0.0
- **Impact**: Earlier versions do not support `KC_HTTP_MANAGEMENT_PORT` and will fail health checks
- **Default Version**: Keycloak 26.4.0 (defined in `src/keycloak_operator/constants.py`)
- **Validation**: The operator automatically validates Keycloak versions and rejects unsupported versions during reconciliation

When using custom Keycloak images, ensure they are version 25.0.0 or later. The operator will log a warning if it cannot determine the version from the image tag (e.g., digest-based images).

## Development Setup
During development the environment is setup using uv and make.
Always prefer the make command for actions over manually doing them unless the configured actions are not sufficient.

The operator is installed in a container image, which can be deployed on a kubernetes cluster.
The folder k8s provides manifests for the CRDs, monitoring, RBAC and the operator itself.

The makefile should provide you with all the necessary actions to build, run and test the operator.


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
The following is expected to be installed.
- docker
- kind
- helm
- kubectl
- uv
- make
- yq
- jq

If they are not available, inform the user that it is required and suggest an installation method.


### Development Habits
Code quality:
When you are done with changes to the code run.
- `uv run ruff check --fix`
- `uv run ty check`
- `uv run ruff format`

You can run this in one swoop with `make quality`

Fix any issues that you find, after fixing them run the command again to see that you did not create new errors. Repeat until nothing is left.

Testing:
After you are done with changes to the code, run the unit tests first.
Only after these succeed will you run the integration test suite. This takes a LONG time, as it spins up a kind cluster to do so.

For testing use `make test-unit` and `make test-integration`

Testing during development:
When you made changes and want to verify that they work it might be overkill to run the integration test suite.
You can test the functionality directly on an existing cluster.
When you have made changes to the code you need to actualize the operator in the cluster. You can do so with.
`make deploy-local`


**Important**: Always use `uv run <command>` when running Python commands directly, or use the Makefile targets which handle dependencies automatically. When you try to run scripts with python directly you will run into issues with dependencies.

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
make operator-logs              # Show the most recent 200 log lines of the operator
make operator-logs-tail         # Follow the operator logs (DO NOT USE THIS AS LLM, YOU WILL GET STUCK! ONLY FOR HUMANS)
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

This project uses **type-safe Pydantic models** auto-generated from the official Keycloak Admin REST API specification.

### Architecture

**OpenAPI Spec:** `keycloak-api-spec.yaml` (from https://www.keycloak.org/docs-api/latest/rest-api/openapi.yaml)
**Generated Models:** `src/keycloak_operator/models/keycloak_api.py` (many models, in a very large file DO NOT UPDATE THIS FILE MANUALLY)
**Generation Script:** `scripts/generate-keycloak-models.sh`
**Validation Layer:** `_make_validated_request()` in `keycloak_admin.py`

### Using the Pydantic Models

**For new implementations, ALWAYS use the typed models instead of dicts:**

```python
from keycloak_operator.models.keycloak_api import (
    RealmRepresentation,
    ClientRepresentation,
    UserRepresentation,
)

# ✅ CORRECT - Type-safe with validation
def create_realm(self, realm_config: RealmRepresentation | dict[str, Any]) -> RealmRepresentation:
    """Create a realm with automatic validation."""
    if isinstance(realm_config, dict):
        realm_config = RealmRepresentation.model_validate(realm_config)

    return self._make_validated_request(
        "POST",
        "realms",
        request_model=realm_config,
        response_model=RealmRepresentation
    )

# ❌ WRONG - No validation, no type safety
def create_realm(self, realm_config: dict[str, Any]) -> dict[str, Any]:
    response = self._make_request("POST", "realms", data=realm_config)
    return realm_config
```

### Regenerating Models (When Keycloak Updates)

```bash
# 1. Download latest OpenAPI spec
curl -o keycloak-api-spec.yaml https://www.keycloak.org/docs-api/latest/rest-api/openapi.yaml

# 2. Regenerate models
./scripts/generate-keycloak-models.sh

# 3. Review changes
git diff src/keycloak_operator/models/keycloak_api.py

# 4. Run tests
uv run pytest tests/unit/test_keycloak_api_models.py

# 5. Commit
git add keycloak-api-spec.yaml src/keycloak_operator/models/keycloak_api.py
git commit -m "fix: update Keycloak API models to version X.Y.Z"
```

### Implementation Guidelines

1. **Use Pydantic Models**: Always use `RealmRepresentation`, `ClientRepresentation`, etc. instead of `dict[str, Any]`
2. **Validation Wrapper**: Use `_make_validated_request()` for automatic request/response validation
3. **Backward Compatibility**: Accept both Pydantic models and dicts, convert dicts to models
4. **Field Naming**: Python uses `snake_case`, API uses `camelCase` (models handle conversion automatically)
5. **Exclude None**: Use `model_dump(exclude_none=True, by_alias=True)` when sending to API

### Testing API Models

See `tests/unit/test_keycloak_api_models.py` and `tests/unit/test_keycloak_admin_api_models.py` for examples.

```python
def test_realm_creation():
    """Test realm creation with validation."""
    realm = RealmRepresentation(
        realm="test",
        enabled=True,
        display_name="Test Realm"
    )

    # Dump for API (camelCase, no None values)
    api_data = realm.model_dump(by_alias=True, exclude_none=True)
    assert api_data == {
        "realm": "test",
        "enabled": True,
        "displayName": "Test Realm"
    }
```

## Documentation

### When to Update Documentation

After making changes to the codebase, you MUST check if documentation needs updating. Use this checklist:

**Check README.md if you changed:**
- ✅ CRD definitions (new fields, changed behavior)
- ✅ Installation or deployment procedures
- ✅ User-facing features or API
- ✅ Configuration options or environment variables
- ✅ Prerequisites or requirements
- ✅ Example manifests or usage patterns

**Check CLAUDE.md if you changed:**
- ✅ Development workflow or tools
- ✅ Testing procedures or commands
- ✅ Build or deployment scripts
- ✅ Code architecture or patterns
- ✅ Makefile targets or development commands
- ✅ Type definitions or validation patterns

**Check docs/ folder if you changed:**
- ✅ Operator concepts or architecture
- ✅ Advanced features or configuration
- ✅ Troubleshooting or operational guides
- ✅ API reference or CRD schemas

### How to Check Documentation Impact

Before finishing your task, run through this mental checklist:

1. **Does this change how users interact with the operator?** → Update README.md
2. **Does this change how developers work on the code?** → Update CLAUDE.md
3. **Does this add/change advanced functionality?** → Update docs/
4. **Does this affect deployment or configuration?** → Update all three

**Example scenarios:**
- Added new CRD field → Update README.md with example, update docs/ with detailed explanation
- Changed Makefile command → Update CLAUDE.md development section
- Implemented new reconciler → Update CLAUDE.md architecture, update docs/ if user-facing
- Fixed bug in existing feature → Usually no docs update needed (unless behavior changed)

### Using MkDocs for Documentation

After updating documentation in `docs/`, preview and verify your changes:

```bash
# Serve documentation locally (opens in browser)
# DO NOT USE THIS IF YOU ARE A LLM, HUMANS ONLY!! It will create an endless process
make docs-serve
# View at: http://127.0.0.1:8000 


# Build documentation (generates static site)
make docs-build
# Output in: site/

# Stop the server: Ctrl+C
```

**When to use MkDocs:**
- After adding/editing any `.md` files in `docs/`
- To verify links work correctly
- To check formatting and appearance
- Before committing documentation changes

**Note:** README.md and CLAUDE.md are NOT part of MkDocs - they're standalone files in the root directory.


## Agentic workflow considerations
It is paramount to prevent annoyance of the user.
The following guidelines are there to prevent requiring interaction from the user. The user can allow you to use auto approval more easily if you follow the following rules

Use `kubectl <verb> -n <namespace>` instead of `kubectl -n <namespace> <verb>`. The approval rules are in the format `Bash(somecmd subcommand:*)`, which means all commands that start with `somecmd subcommand` will be allowed.

In fact, for any cli interaction that has the flexibility to rearrange flags and options, use the semantically import part first, then all the less significant flags and options.

For `kubectl` use `kubectl create` instead of `kubectl apply` whenever possible, the user will then rest easy knowing you wont patch anything temporarily instead of managing it with the make file.

Prefer not to change the directory. Keep in the same directory as this file. The construction (cd somedir && cmd) is known to change your working dir, which confuses you.

Do not use ` cat << 'EOF' | kubectl create -f -` constructions for applying, this requires manual approval every time because it cannot be targeted by auto approval rules properly. Prefer a tmp file, which you then ofcourse will delete afterwards.

## Planning
When creating a plan be detailed. Expect the developer that will follow your plan to be a complete idiot (but do not mention it in the plan). You will have to be explicit in the steps to be taken. Treat the implementer of the plan as an intern, which needs the work to be validated.

## Git
When commiting changes to git you are to use conventional commit messages.
Be strict with breaking changes, versioning is managed by semantic versioning, so commit messages matter!

