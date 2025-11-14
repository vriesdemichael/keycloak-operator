# Keycloak Operator

A GitOps-friendly Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients declaratively.

## 🚀 Quick Start

Get a complete Keycloak setup running in 10 minutes:

```bash
# 1. Install the operator
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system --create-namespace

# 2. Deploy Keycloak
kubectl apply -f - <<EOF
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  hostname: keycloak.example.com
  replicas: 3
  database:
    vendor: postgres
    host: postgresql.keycloak-system.svc
    name: keycloak
    credentialsSecret: keycloak-db-credentials
EOF

# 3. Create an identity realm
kubectl apply -f - <<EOF
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-app-realm
  namespace: my-app
spec:
  realmName: my-app
  instanceRef:
    name: keycloak
    namespace: keycloak-system
EOF

# 4. Create an OAuth2 client
kubectl apply -f - <<EOF
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: my-app-client
  namespace: my-app
spec:
  clientId: my-app
  realmRef:
    name: my-app-realm
  publicClient: false
  standardFlowEnabled: true
  redirectUris:
    - https://my-app.example.com/callback
EOF
```

**📖 [Complete Quick Start Guide →](quickstart/README.md)**

## ✨ Key Features

- **🔒 Secure by Default** - Kubernetes RBAC controls all access, no separate auth system
- **📦 GitOps Ready** - Declarative CRDs with full status reporting and drift detection
- **🎯 Multi-Tenant** - Cross-namespace realm and client provisioning with namespace grants
- **⚡ Production Ready** - Rate limiting, admission webhooks, HA support with CloudNativePG
- **📊 Observable** - Prometheus metrics, structured logging, comprehensive status conditions
- **🔄 Drift Detection** - Automatic detection and remediation of configuration drift

## 🏗️ Architecture

The operator manages three core resources:

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Keycloak    │────▶│ KeycloakRealm   │────▶│ KeycloakClient   │
│  (Instance)  │     │ (Identity)      │     │ (OAuth2/OIDC)    │
└──────────────┘     └─────────────────┘     └──────────────────┘
```

- **Keycloak**: Identity server instance with PostgreSQL database
- **KeycloakRealm**: Identity domain containing users, roles, and settings
- **KeycloakClient**: OAuth2/OIDC applications with automated credentials

## 📚 Documentation

### Getting Started
- **[Quick Start Guide](quickstart/README.md)** - Get running in 10 minutes
- **[Architecture Overview](architecture.md)** - How the operator works
- **[Security Model](security.md)** - Authorization and access control

### Configuration
- **[KeycloakRealm Reference](reference/keycloak-realm-crd.md)** - Complete realm options
- **[KeycloakClient Reference](reference/keycloak-client-crd.md)** - Complete client options
- **[Identity Providers](identity-providers.md)** - Integrate Google, GitHub, Azure AD, etc.

### Operations
- **[Admission Webhooks](admission-webhooks.md)** - Validation and resource quotas
- **[Drift Detection](drift-detection.md)** - Orphan detection and remediation
- **[Observability](observability.md)** - Metrics, logging, and monitoring
- **[Troubleshooting](operations/troubleshooting.md)** - Common issues and solutions

### Development
- **[Development Guide](development.md)** - Contributing to the project
- **[Decision Records](decisions/README.md)** - Architecture decisions and rationale

## 🔒 Security & Authorization

The operator uses **Kubernetes RBAC** for all authorization - no separate token system.

### Realm Creation
Any user with RBAC permission to create `KeycloakRealm` resources can create realms. Control this with standard Kubernetes RoleBindings:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: realm-creator
  namespace: my-app
rules:
  - apiGroups: ["vriesdemichael.github.io"]
    resources: ["keycloakrealms"]
    verbs: ["create", "update", "patch"]
```

### Client Creation
Clients require **namespace authorization** from the realm. Realm owners grant access via `clientAuthorizationGrants`:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
spec:
  clientAuthorizationGrants:
    - dev-team-namespace
    - staging-namespace
```

Only namespaces in the grant list can create clients in that realm.

**📖 [Full Security Model Documentation →](security.md)**

## 📊 Status & Observability

All resources provide comprehensive status information:

```yaml
status:
  phase: Ready
  conditions:
    - type: Ready
      status: "True"
      reason: ReconciliationSucceeded
      message: "Realm is healthy and synchronized"
  observedGeneration: 5
  realmId: "a1b2c3d4-5678-90ab-cdef-1234567890ab"
  internalUrl: "http://keycloak.keycloak-system.svc:8080/realms/my-app"
  publicUrl: "https://keycloak.example.com/realms/my-app"
```

**📖 [Observability Guide →](observability.md)**

## 🔄 Drift Detection

The operator continuously monitors for:
- **Orphaned Resources** - Realms/clients in Keycloak not tracked by CRs
- **Configuration Drift** - Manual changes to Keycloak resources
- **Missing Resources** - CRs referencing deleted Keycloak objects

**📖 [Drift Detection Guide →](drift-detection.md)**

## 🚦 Admission Webhooks

Validate resources before they reach etcd:
- ✅ Immediate error feedback on `kubectl apply`
- ✅ Enforce resource quotas (max realms per namespace)
- ✅ Validate cross-resource references
- ✅ Prevent invalid configurations

**📖 [Admission Webhooks Guide →](admission-webhooks.md)**

## 🤝 Contributing

Contributions welcome! See the [Development Guide](development.md) for:
- Setting up your development environment
- Running tests
- Submitting pull requests
- Architecture decision records (ADRs)

## 📝 License

MIT License - see [LICENSE](../LICENSE) for details.

## 🔗 Links

- **[GitHub Repository](https://github.com/vriesdemichael/keycloak-operator)**
- **[Issue Tracker](https://github.com/vriesdemichael/keycloak-operator/issues)**
- **[Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)**
- **[Releases](https://github.com/vriesdemichael/keycloak-operator/releases)**
