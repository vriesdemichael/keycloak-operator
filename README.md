# Keycloak Operator

[![CI/CD Pipeline (Unified)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/ci-cd-unified.yml/badge.svg)](https://github.com/vriesdemichael/keycloak-operator/actions/workflows/ci-cd-unified.yml)
[![codecov](https://codecov.io/gh/vriesdemichael/keycloak-operator/branch/main/graph/badge.svg)](https://codecov.io/gh/vriesdemichael/keycloak-operator)
[![Helm Chart](https://img.shields.io/badge/dynamic/yaml?url=https://raw.githubusercontent.com/vriesdemichael/keycloak-operator/main/charts/keycloak-operator/Chart.yaml&query=$.version&label=chart&color=blue)](https://github.com/vriesdemichael/keycloak-operator/pkgs/container/charts%2Fkeycloak-operator)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/downloads/)

A Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients declaratively with full GitOps compatibility.

## 🚀 Quick Start

Get a complete Keycloak setup running in under 10 minutes.

Helm charts are the recommended deployment path. Direct CR manifests are supported for advanced/manual workflows where you want to manage RBAC, secret access, and lifecycle wiring yourself.

```bash
# 1. Install the operator and a managed Keycloak instance
# Note: The chart creates the namespace by default, don't use --create-namespace
helm install keycloak-operator \
  oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set keycloak.managed=true \
  --set keycloak.database.cnpg.enabled=true

# Or install from local charts:
# helm install keycloak-operator ./charts/keycloak-operator \
#   --namespace keycloak-system

# 2. Create an identity realm
helm install my-app-realm \
  oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace my-app \
  --create-namespace \
  --set realmName=my-app \
  --set operatorRef.namespace=keycloak-system \
  --set 'clientAuthorizationGrants={my-app}'

# 3. Create an OAuth2 client
helm install my-app-client \
  oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  --namespace my-app \
  --set clientId=my-app \
  --set realmRef.name=my-app-realm \
  --set realmRef.namespace=my-app \
  --set 'redirectUris={https://my-app.example.com/callback}'
```

**📖 [Full Quick Start Guide →](https://vriesdemichael.github.io/keycloak-operator/latest/quickstart/)**

**Advanced:** If you want to work directly with CR manifests instead of Helm releases, see [Helm vs Direct CR Deployments](https://vriesdemichael.github.io/keycloak-operator/latest/how-to/helm-vs-cr-deployments/).

## ✨ Features

- **Declarative Configuration** - Manage Keycloak entirely through Kubernetes resources
- **Admission Webhooks** - Immediate validation feedback with clear error messages ([docs](https://vriesdemichael.github.io/keycloak-operator/latest/admission-webhooks/))
- **GitOps Ready** - Full observability with status conditions and `observedGeneration` tracking
- **Drift Detection** - Automatic detection of orphaned resources and configuration drift ([docs](https://vriesdemichael.github.io/keycloak-operator/latest/guides/drift-detection/))
- **Cross-Namespace Support** - Secure delegation model for multi-tenant environments
- **Production Ready** - Rate limiting, exponential backoff, and comprehensive monitoring
- **Comprehensive Test Coverage** - Unit and integration tests with coverage tracking
- **Resource Quotas** - Namespace-level limits on realms and clients via admission webhooks
- **Rate Limiting** - Two-level throttling (global + per-namespace) protects Keycloak from overload
- **High Availability** - Multi-replica Keycloak with PostgreSQL clustering via CloudNativePG
- **OAuth2/OIDC Clients** - Automated client provisioning with credential management
- **Service Accounts** - Declarative role assignment for machine-to-machine authentication
- **OIDC Endpoint Discovery** - Automatic population of all OIDC/OAuth2 endpoints in realm status
- **Multi-Version Support** - Supports Keycloak 24.x, 25.x, and 26.x via compatibility adapters

## 📚 Documentation

**🌐 [Full Documentation](https://vriesdemichael.github.io/keycloak-operator/)** - Versioned documentation with version selector

### Quick Links

- **[Quick Start Guide](https://vriesdemichael.github.io/keycloak-operator/latest/quickstart/)** - Get started in 10 minutes
- **[Helm vs Direct CR Deployments](https://vriesdemichael.github.io/keycloak-operator/latest/how-to/helm-vs-cr-deployments/)** - Recommended workflow versus advanced manual path
- **[Architecture](https://vriesdemichael.github.io/keycloak-operator/latest/concepts/architecture/)** - How the operator works
- **[Admission Webhooks](https://vriesdemichael.github.io/keycloak-operator/latest/admission-webhooks/)** - Resource validation and quotas
- **[Security Model](https://vriesdemichael.github.io/keycloak-operator/latest/concepts/security/)** - Secret-based authorization explained
- **[Drift Detection](https://vriesdemichael.github.io/keycloak-operator/latest/guides/drift-detection/)** - Orphan detection and auto-remediation
- **[Observability](https://vriesdemichael.github.io/keycloak-operator/latest/guides/observability/)** - Metrics, logs, and status conditions
- **[Versioning](https://vriesdemichael.github.io/keycloak-operator/latest/versioning/)** - How to access older documentation and chart versions
- **[Development Guide](https://vriesdemichael.github.io/keycloak-operator/latest/development/)** - Contributing to the project

> **Note: Version-Specific Documentation**
> Use the version selector in the documentation to view docs for your installed version.
> See the [Versioning Guide](https://vriesdemichael.github.io/keycloak-operator/latest/versioning/) for details.

## 🏗️ Architecture

The operator manages three custom resources:

```
flowchart LR
  kc[Keycloak\nInstance]
  realm[KeycloakRealm\nIdentity Boundary]
  client[KeycloakClient\nOAuth2/OIDC Boundary]

  kc --> realm --> client
```

- **Keycloak**: The identity server instance with database and networking
- **KeycloakRealm**: Identity domain with users, roles, and authentication settings
- **KeycloakClient**: OAuth2/OIDC applications with automated credential management

## 🌐 External Keycloak Mode

The operator can manage resources (realms, clients) in an existing, external Keycloak instance instead of deploying its own.

### Configuration

In your `values.yaml`:

```yaml
keycloak:
  managed: false
  url: "https://keycloak.example.com"
  adminUsername: "admin"
  adminSecret: "my-external-secret"  # Secret in the operator namespace
  adminPasswordKey: "password"
```

This is the actual chart contract for external mode:

- `keycloak.managed=false` disables templating of the managed `Keycloak` CR
- `keycloak.url` tells the operator where the existing Keycloak instance lives
- `keycloak.adminSecret` tells the operator which Secret to read for the admin password
- `keycloak.adminPasswordKey` defaults to `password`, but can be overridden when your Secret uses a different key

Do not confuse this with `keycloak.admin.existingSecret`, which is only used for managed mode when `keycloak.managed=true`.

#### Creating the Admin Secret

The admin secret must exist in the operator's namespace. It only needs to contain the password value the operator will use together with `keycloak.adminUsername`.

```bash
kubectl create secret generic my-external-secret \
  --from-literal=password='your-admin-password' \
  --namespace keycloak-system
```

**Note:** In external mode, the operator connects directly to the existing Keycloak instance using `keycloak.url` and the configured admin Secret. You typically do not deploy a managed `Keycloak` CR from this chart in that setup.

## 📊 Example

Create a complete OAuth2 setup:

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
# Keycloak instance with PostgreSQL database
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  replicas: 3
  image: quay.io/keycloak/keycloak:26.0.0
  database:
    type: postgresql
    host: keycloak-postgres-rw
    port: 5432
    database: app
    username: app
    passwordSecret:
      name: keycloak-postgres-app
      key: password
---
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
# Identity realm with client authorization grants
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-app-realm
  namespace: my-app
spec:
  realmName: my-app
  operatorRef:
    namespace: keycloak-system
  # Namespaces authorized to create clients in this realm
  clientAuthorizationGrants:
    - my-app
---
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
# OAuth2 client (namespace must be in realm's clientAuthorizationGrants)
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
  publicClient: false
  redirectUris:
    - "https://my-app.example.com/callback"
```

See [examples/](examples/) for advanced raw-manifest examples. For normal installs, prefer the Helm charts and the quick start flow above.

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

The operator uses a **namespace grant authorization model** combining Kubernetes RBAC with declarative access control:

- **Realm Creation**: Controlled by standard Kubernetes RBAC (who can create `KeycloakRealm` resources)
- **Client Creation**: Controlled by realm's `clientAuthorizationGrants` list (which namespaces can create clients)
- **Self-service**: Teams can create realms and clients without platform team intervention
- **GitOps Native**: All authorization is declarative and stored in Git
- **Auditability**: All access changes tracked in Git history and Kubernetes audit logs

Read the [Security Model](https://vriesdemichael.github.io/keycloak-operator/latest/concepts/security/) documentation for detailed authorization architecture.

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

See [Observability](https://vriesdemichael.github.io/keycloak-operator/latest/guides/observability/) for full details.

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
- `keycloak_operator_api_rate_limit_wait_seconds` - Time waiting for tokens
- `keycloak_operator_api_rate_limit_acquired_total` - Successful token acquisitions
- `keycloak_operator_api_rate_limit_timeouts_total` - Rate limit timeout errors
- `keycloak_operator_api_rate_limit_budget_available` - Current available tokens per namespace

## 🤝 Contributing

Contributions welcome!

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/vriesdemichael/keycloak-operator.git
cd keycloak-operator

# Check required tools and install pre-commit hooks
task dev:setup

# Run quality checks
task quality:check

# Run unit tests
task test:unit
```

See [Development Guide](https://vriesdemichael.github.io/keycloak-operator/latest/development/) and [AGENTS.md](AGENTS.md) for more details.

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [GitHub Repository](https://github.com/vriesdemichael/keycloak-operator)
- [Issue Tracker](https://github.com/vriesdemichael/keycloak-operator/issues)
- [Documentation](https://vriesdemichael.github.io/keycloak-operator/latest/)
