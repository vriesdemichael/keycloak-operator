# Keycloak Operator

[![CI/CD Pipeline](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/ci-cd.yml)
[![Release](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/release-please.yml/badge.svg)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/release-please.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)

A Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients declaratively with full GitOps compatibility.

## 🚀 Quick Start

Get a complete Keycloak setup running in under 10 minutes:

```bash
# 1. Add the Helm repository
helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator
helm repo update

# 2. Install the operator
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system --create-namespace

# Or install from local charts:
# helm install keycloak-operator ./charts/keycloak-operator \
#   --namespace keycloak-system --create-namespace

# 3. Deploy Keycloak with database
kubectl apply -f examples/01-keycloak-instance.yaml

# 4. Create an identity realm
kubectl apply -f examples/02-realm-example.yaml

# 5. Create an OAuth2 client
kubectl apply -f examples/03-client-example.yaml
```

**📖 [Full Quick Start Guide →](docs/quickstart/README.md)**

## ✨ Features

- **Declarative Configuration** - Manage Keycloak entirely through Kubernetes resources
- **GitOps Ready** - Full observability with status conditions and `observedGeneration` tracking
- **Drift Detection** - Automatic detection of orphaned resources and configuration drift ([docs](docs/drift-detection.md))
- **Cross-Namespace Support** - Secure delegation model for multi-tenant environments
- **Production Ready** - Rate limiting, exponential backoff, and comprehensive monitoring
- **Rate Limiting** - Two-level throttling (global + per-namespace) protects Keycloak from overload
- **High Availability** - Multi-replica Keycloak with PostgreSQL clustering via CloudNativePG
- **OAuth2/OIDC Clients** - Automated client provisioning with credential management
- **Service Accounts** - Declarative role assignment for machine-to-machine authentication

## 📚 Documentation

- **[Quick Start Guide](docs/quickstart/README.md)** - Get started in 10 minutes
- **[Architecture](docs/architecture.md)** - How the operator works
- **[Security Model](docs/security.md)** - Secret-based authorization explained
- **[Drift Detection](docs/drift-detection.md)** - Orphan detection and auto-remediation
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
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
# Keycloak instance
apiVersion: vriesdemichael.github.io/v1
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
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
# Identity realm
apiVersion: vriesdemichael.github.io/v1
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
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
# OAuth2 client
apiVersion: vriesdemichael.github.io/v1
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

## 🎯 IDE Integration

Get autocompletion, validation, and inline documentation in your IDE using published JSON schemas:

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
# ... IDE will autocomplete fields with descriptions!
```

**Features:**
- ✅ Autocomplete for all CRD fields
- ✅ Inline validation with error messages
- ✅ Field descriptions from CRD schema
- ✅ Enum value suggestions

**Supported IDEs:**
- VS Code (with [YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml))
- IntelliJ IDEA / PyCharm (built-in)
- Neovim (with yaml-language-server)

**Available schemas:**
- `https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json`
- `https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json`
- `https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json`

Add the schema annotation as the first line of your YAML files to enable IDE features.

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
- Rate limiting wait times and timeouts
- Reconciliation duration (p50/p95/p99)
- Resource counts by phase

See [Observability](docs/observability.md) for full details.

## 🚦 Rate Limiting

The operator implements two-level rate limiting to protect Keycloak from API overload:

### Configuration

```yaml
env:
  # Global rate limit (all namespaces combined)
  - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
    value: "50"  # requests per second
  - name: KEYCLOAK_API_GLOBAL_BURST
    value: "100"  # burst capacity

  # Per-namespace rate limit (fair sharing)
  - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
    value: "5"  # requests per second
  - name: KEYCLOAK_API_NAMESPACE_BURST
    value: "10"  # burst capacity

  # Jitter to prevent thundering herd
  - name: RECONCILE_JITTER_MAX_SECONDS
    value: "5.0"  # 0-5 second random delay
```

### Protection Scenarios

| Scenario | Protection |
|----------|-----------|
| Spam 1000 realms in one namespace | Limited to 5 req/s = 200s minimum |
| Multiple teams overwhelming Keycloak | Global 50 req/s enforced |
| Operator restart (50+ resources) | Jitter + rate limiting prevents flood |

### Monitoring

Prometheus metrics available at `:8081/metrics`:
- `keycloak_api_rate_limit_wait_seconds` - Time waiting for tokens
- `keycloak_api_rate_limit_acquired_total` - Successful token acquisitions
- `keycloak_api_rate_limit_timeouts_total` - Rate limit timeout errors
- `keycloak_api_tokens_available` - Current available tokens per namespace

## 🤝 Contributing

Contributions welcome!

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/vriesdemichael/keycloak-operator.git
cd keycloak-operator

# Install dependencies
make install

# Run quality checks
make quality

# Run unit tests
make test-unit
```

See [Development Guide](docs/development.md) and [CLAUDE.md](CLAUDE.md) for more details.

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/vriesdemichael/keycloak-operator)
- [Issue Tracker](https://github.com/vriesdemichael/keycloak-operator/issues)
- [Documentation](docs/)
