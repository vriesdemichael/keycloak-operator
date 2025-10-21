# Keycloak Operator

A GitOps-friendly Kubernetes operator for provisioning and reconciling Keycloak realms, clients, and core instances via Custom Resources.

## Highlights

- Built with [Kopf](https://kopf.readthedocs.io/) and async Python
- GitOps oriented: declarative CRDs for Keycloak, Realm, Client
- Observability: Prometheus metrics, structured logging, health endpoints
- Extensible reconciliation services and clean domain models

## Quick Start

```bash
# Install runtime dependencies (operators are usually containerized)
uv sync

# (Optional) Install dev + docs tooling
uv sync --group dev --group docs

# Run unit tests
uv run pytest

# Serve documentation locally
uv run --group docs mkdocs serve
```

## Documentation Sections

### Getting Started
- [Quick Start Guide](quickstart/README.md) - Get running in 10 minutes
- [Architecture Overview](architecture.md) - System design and components

### Security
- [Security Model](security.md) - Authorization and token system
- [Token Rotation](security.md#token-rotation) - Automatic rotation system

### Operations
- [Token Management Operations](operations/token-management.md) - Platform team runbooks
- [Observability](observability.md) - Metrics, logging, and monitoring

### Development
- [Development Guide](development.md) - Contributing and extending
- [RBAC Implementation](rbac-implementation.md) - Authorization patterns
- [API Reference](api/keycloak_operator.md) - Auto-generated API docs

---

Continue with the [Architecture](architecture.md) to understand internal components.
