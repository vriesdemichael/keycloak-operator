# Keycloak Operator

[![Tests](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/integration-tests.yml)
[![Release](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/release-please.yml/badge.svg)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/release-please.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients declaratively with full GitOps compatibility.

## 🚀 Quick Start

Get a complete Keycloak setup running in under 10 minutes:

```bash
# 1. Install the operator
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system --create-namespace

# 2. Deploy Keycloak with database
kubectl apply -f examples/01-keycloak-instance.yaml

# 3. Create an identity realm
kubectl apply -f examples/02-realm-example.yaml

# 4. Create an OAuth2 client
kubectl apply -f examples/03-client-example.yaml
```

**📖 [Full Quick Start Guide →](docs/quickstart/README.md)**

## ✨ Features

- **Declarative Configuration** - Manage Keycloak entirely through Kubernetes resources
- **GitOps Ready** - Full observability with status conditions and `observedGeneration` tracking
- **Cross-Namespace Support** - Secure delegation model for multi-tenant environments
- **Production Ready** - Circuit breakers, exponential backoff, and comprehensive monitoring
- **High Availability** - Multi-replica Keycloak with PostgreSQL clustering via CloudNativePG
- **OAuth2/OIDC Clients** - Automated client provisioning with credential management
- **Service Accounts** - Declarative role assignment for machine-to-machine authentication

## 📚 Documentation

- **[Quick Start Guide](docs/quickstart/README.md)** - Get started in 10 minutes
- **[Architecture](docs/architecture.md)** - How the operator works
- **[Security Model](docs/security.md)** - Secret-based authorization explained
- **[Observability](docs/observability.md)** - Metrics, logs, and status conditions
- **[Development Guide](docs/development.md)** - Contributing to the project

## 🏗️ Architecture

The operator manages three custom resources:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    Keycloak     │    │  KeycloakRealm   │    │ KeycloakClient  │
│   (Instance)    │◄───┤   (Identity)     │◄───┤   (OAuth2/OIDC) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

- **Keycloak**: The identity server instance with database and networking
- **KeycloakRealm**: Identity domain with users, roles, and authentication settings  
- **KeycloakClient**: OAuth2/OIDC applications with automated credential management

## 📊 Example

Create a complete OAuth2 setup:

```yaml
# Keycloak instance
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  replicas: 3
  version: "26.0.0"
  database:
    type: cnpg
    cluster: keycloak-postgres
---
# Identity realm
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-app-realm
  namespace: my-app
spec:
  realmName: my-app
  operatorRef:
    namespace: keycloak-system
    authorizationSecretRef:
      name: keycloak-operator-auth-token
---
# OAuth2 client
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: my-app-client
  namespace: my-app
spec:
  clientId: my-app
  realmRef:
    name: my-app-realm
    namespace: my-app
    authorizationSecretRef:
      name: my-app-realm-realm-auth
  redirectUris:
    - "https://my-app.example.com/callback"
```

See [examples/](examples/) for complete manifests with detailed configuration options.

## 🔐 Security

The operator uses a capability-based authorization model with Kubernetes secrets as bearer tokens. This enables:

- **Self-service**: Teams can create realms and clients without platform team intervention
- **Scalability**: Supports 100+ teams without RBAC complexity
- **Security**: Cryptographically random tokens with namespace isolation
- **Auditability**: All token access logged by Kubernetes API server

Read the [Security Model](docs/security.md) documentation for details on why this approach is superior to traditional RBAC.

## 📈 Monitoring

The operator exposes Prometheus metrics and includes a Grafana dashboard:

```bash
# Enable monitoring in Helm chart
helm install keycloak-operator ./charts/keycloak-operator \
  --set monitoring.enabled=true \
  --set monitoring.prometheusRules.enabled=true \
  --set monitoring.grafanaDashboard.enabled=true
```

Key metrics:
- Reconciliation success/failure rates
- Circuit breaker state
- Reconciliation duration (p50/p95/p99)
- Resource counts by phase

See [Observability](docs/observability.md) for full details.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/vriesdemichael/keycloak-operator.git
cd keycloak-operator

# Install dependencies
make setup

# Run tests
make test-unit

# Run operator locally
make run
```

See [Development Guide](docs/development.md) for more details.

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/vriesdemichael/keycloak-operator)
- [Issue Tracker](https://github.com/vriesdemichael/keycloak-operator/issues)
- [Documentation](docs/)
- [Changelog](CHANGELOG.md)
