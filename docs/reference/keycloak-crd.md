# Keycloak CRD Reference

Complete reference for the `Keycloak` Custom Resource Definition.

## Overview

The `Keycloak` CRD defines a Keycloak instance - an identity and access management server. This resource allows you to declaratively manage Keycloak deployments with database connections, TLS configuration, ingress settings, and more.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `Keycloak`
**Plural:** `keycloaks`
**Singular:** `keycloak`
**Short Names:** `kc`

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: my-keycloak
  namespace: keycloak-system
spec:
  database:
    type: postgresql
    host: postgres-postgresql
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
      key: password
```

## Spec Fields

### Core Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `image` | string | No | Uses operator default | Container image for Keycloak (e.g., `quay.io/keycloak/keycloak:26.4.1`) |
| `replicas` | integer | No | `1` | Number of Keycloak replicas (minimum: 1) |

**Example:**
```yaml
spec:
  image: quay.io/keycloak/keycloak:26.4.1
  replicas: 3
```

### Database Configuration

The database configuration is **required**. The operator supports PostgreSQL, MySQL, MariaDB, Oracle, and Microsoft SQL Server.

#### Basic Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `database.type` | string | Yes | `postgresql` | Database type. Options: `postgresql`, `mysql`, `mariadb`, `oracle`, `mssql` |
| `database.host` | string | Yes | - | Database hostname or IP address |
| `database.port` | integer | No | Auto-detected | Database port (1-65535). Auto-detected based on database type if not specified |
| `database.database` | string | Yes | - | Database name |
| `database.username` | string | No* | - | Database username (*required if not using `credentialsSecret`) |
| `database.passwordSecret` | object | No* | - | Secret reference for database password (*required if using `username`) |
| `database.passwordSecret.name` | string | Yes | - | Name of the secret containing the password |
| `database.passwordSecret.key` | string | No | `password` | Key in the secret |
| `database.credentialsSecret` | string | No | - | Alternative: Kubernetes secret name with complete database credentials |
| `database.connectionParams` | map[string]string | No | `{}` | Additional database connection parameters |

**Example - PostgreSQL with username/password:**
```yaml
spec:
  database:
    type: postgresql
    host: postgres-postgresql.default.svc.cluster.local
    port: 5432
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
      key: password
```

**Example - CloudNativePG:**
```yaml
spec:
  database:
    type: postgresql
    host: keycloak-postgres-rw  # CNPG read-write service
    database: keycloak
    username: keycloak
    passwordSecret:
      name: keycloak-postgres-app
      key: password
```

**Example - Using credentialsSecret:**
```yaml
spec:
  database:
    type: postgresql
    host: postgres-postgresql
    database: keycloak
    credentialsSecret: db-credentials  # Secret with keys: username, password
```

#### Connection Pool

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `database.connectionPool.maxConnections` | integer | No | `20` | Maximum number of database connections |
| `database.connectionPool.minConnections` | integer | No | `5` | Minimum number of database connections |
| `database.connectionPool.connectionTimeout` | string | No | `30s` | Connection timeout duration |

**Example:**
```yaml
spec:
  database:
    # ... other fields ...
    connectionPool:
      maxConnections: 50
      minConnections: 10
      connectionTimeout: "60s"
```

#### SSL/TLS

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `database.sslMode` | string | No | `require` | SSL mode for database connections. Options: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full` |

**Example:**
```yaml
spec:
  database:
    # ... other fields ...
    sslMode: verify-full  # Strict SSL with certificate verification
```

#### Migration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `database.migrationStrategy` | string | No | `auto` | Database migration strategy. Options: `auto` (automatic), `manual` (skip migrations), `skip` |

**Example:**
```yaml
spec:
  database:
    # ... other fields ...
    migrationStrategy: auto  # Automatically run schema migrations
```

### TLS Configuration

Configure TLS/SSL termination for Keycloak.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tls.enabled` | boolean | No | `false` | Enable TLS/SSL |
| `tls.secretName` | string | No | - | Secret containing TLS certificate (keys: `tls.crt`, `tls.key`) |
| `tls.hostname` | string | No | - | Hostname for TLS certificate (Server Name Indication) |

**Example:**
```yaml
spec:
  tls:
    enabled: true
    secretName: keycloak-tls
    hostname: keycloak.example.com
```

### Service Configuration

Configure the Kubernetes service for Keycloak.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `service.type` | string | No | `ClusterIP` | Service type. Options: `ClusterIP`, `NodePort`, `LoadBalancer` |
| `service.httpPort` | integer | No | `8080` | HTTP port (1-65535) |
| `service.httpsPort` | integer | No | `8443` | HTTPS port (1-65535) |
| `service.annotations` | map[string]string | No | `{}` | Service annotations (e.g., for cloud load balancers) |

**Example:**
```yaml
spec:
  service:
    type: LoadBalancer
    httpPort: 8080
    httpsPort: 8443
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
```

### Ingress Configuration

Configure ingress for external access to Keycloak.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ingress.enabled` | boolean | No | `false` | Enable ingress |
| `ingress.host` | string | No | - | Ingress hostname (e.g., `keycloak.example.com`) |
| `ingress.path` | string | No | `/` | Ingress path |
| `ingress.tlsEnabled` | boolean | No | `true` | Enable TLS for ingress |
| `ingress.tlsSecretName` | string | No | - | Secret name for ingress TLS certificate |
| `ingress.className` | string | No | - | Ingress class name (e.g., `nginx`, `traefik`) |
| `ingress.annotations` | map[string]string | No | `{}` | Ingress annotations |

**Example:**
```yaml
spec:
  ingress:
    enabled: true
    host: keycloak.example.com
    path: /
    tlsEnabled: true
    tlsSecretName: keycloak-ingress-tls
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      nginx.ingress.kubernetes.io/proxy-buffer-size: "128k"
```

### Resource Requirements

Configure CPU and memory limits for Keycloak pods.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `resources.requests` | map[string]string | No | - | Resource requests (e.g., `cpu: "500m"`, `memory: "1Gi"`) |
| `resources.limits` | map[string]string | No | - | Resource limits |

**Example:**
```yaml
spec:
  resources:
    requests:
      cpu: "1000m"
      memory: "2Gi"
    limits:
      cpu: "2000m"
      memory: "4Gi"
```

### Environment Variables

Inject custom environment variables into Keycloak containers.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `env` | map[string]string | No | `{}` | Environment variables as key-value pairs |

**Example:**
```yaml
spec:
  env:
    KC_LOG_LEVEL: "INFO"
    KC_FEATURES: "token-exchange,admin-fine-grained-authz"
```

**Common Keycloak environment variables:**
- `KC_LOG_LEVEL` - Logging level (`INFO`, `DEBUG`, `WARN`, `ERROR`)
- `KC_FEATURES` - Enable preview features
- `KC_PROXY` - Proxy mode (`edge`, `reencrypt`, `passthrough`)
- `KC_HTTP_RELATIVE_PATH` - Context path for Keycloak

### JVM Configuration

Configure JVM options for performance tuning.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `jvmOptions` | []string | No | `[]` | JVM options (e.g., heap size, GC settings) |

**Example:**
```yaml
spec:
  jvmOptions:
    - "-Xms2048m"
    - "-Xmx4096m"
    - "-XX:+UseG1GC"
    - "-XX:MaxGCPauseMillis=200"
    - "-XX:+DisableExplicitGC"
```

**Common JVM options:**
- `-Xms<size>` - Initial heap size
- `-Xmx<size>` - Maximum heap size
- `-XX:+UseG1GC` - Use G1 garbage collector (recommended)
- `-XX:MaxGCPauseMillis=<ms>` - Target GC pause time
- `-Djava.net.preferIPv4Stack=true` - Prefer IPv4

### Service Account

Assign a Kubernetes service account for workload identity.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `serviceAccount` | string | No | - | Service account name for Keycloak pods (for GCP Workload Identity, AWS IRSA, etc.) |

**Example:**
```yaml
spec:
  serviceAccount: keycloak-workload-identity
```

### Health Probes

Override default health probe configurations.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `startupProbe` | object | No | Operator defaults | Kubernetes startup probe configuration |
| `livenessProbe` | object | No | Operator defaults | Kubernetes liveness probe configuration |
| `readinessProbe` | object | No | Operator defaults | Kubernetes readiness probe configuration |

**Example:**
```yaml
spec:
  startupProbe:
    httpGet:
      path: /health/started
      port: 9000
    initialDelaySeconds: 30
    periodSeconds: 10
    failureThreshold: 30
  livenessProbe:
    httpGet:
      path: /health/live
      port: 9000
    periodSeconds: 30
  readinessProbe:
    httpGet:
      path: /health/ready
      port: 9000
    periodSeconds: 10
```

### Security Context

Configure pod and container security contexts.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `podSecurityContext` | object | No | - | Pod-level security context (fsGroup, runAsUser, etc.) |
| `securityContext` | object | No | - | Container-level security context (capabilities, privileged, etc.) |

**Example:**
```yaml
spec:
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    readOnlyRootFilesystem: false
```

## Status Fields

The operator populates the `status` subresource with the current state of the Keycloak instance.

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Provisioning`, `Ready`, `Failed`, `Updating`, `Degraded` |
| `message` | string | Human-readable status message |
| `reason` | string | Reason for current phase |
| `observedGeneration` | integer | Generation of spec that was last processed |
| `adminUsername` | string | Keycloak admin username |
| `adminSecret` | string | Name of secret containing admin password |
| `authorizationSecretName` | string | Name of secret containing operator's authorization token |
| `internalUrl` | string | Internal cluster URL |
| `externalUrl` | string | External URL (if ingress enabled) |
| `endpoints.admin` | string | Admin console endpoint |
| `endpoints.public` | string | Public endpoint for OIDC/SAML |
| `endpoints.management` | string | Management endpoint (health, metrics) |
| `deployment` | string | Name of the Keycloak deployment |
| `service` | string | Name of the Keycloak service |
| `readyReplicas` | integer | Number of ready replicas |
| `lastHealthCheck` | string (datetime) | Last health check timestamp |
| `databaseStatus` | string | Database connection status: `Connected`, `Connecting`, `Failed`, `Unknown` |

**Example status:**
```yaml
status:
  phase: Ready
  message: "Keycloak instance is healthy and ready"
  observedGeneration: 1
  adminUsername: admin
  adminSecret: my-keycloak-admin-password
  authorizationSecretName: my-keycloak-operator-token
  internalUrl: http://my-keycloak:8080
  externalUrl: https://keycloak.example.com
  endpoints:
    admin: https://keycloak.example.com/admin
    public: https://keycloak.example.com
    management: http://my-keycloak:9000
  deployment: my-keycloak
  service: my-keycloak
  readyReplicas: 3
  databaseStatus: Connected
```

## Complete Examples

### Production Setup with HA

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak-prod
  namespace: keycloak-system
spec:
  image: quay.io/keycloak/keycloak:26.4.1
  replicas: 3

  database:
    type: postgresql
    host: postgres-ha-rw.database.svc.cluster.local
    port: 5432
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
      key: password
    sslMode: verify-full
    connectionPool:
      maxConnections: 100
      minConnections: 20
      connectionTimeout: "30s"

  service:
    type: ClusterIP
    httpPort: 8080
    httpsPort: 8443

  ingress:
    enabled: true
    host: auth.example.com
    tlsEnabled: true
    tlsSecretName: keycloak-tls
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      nginx.ingress.kubernetes.io/proxy-buffer-size: "128k"
      nginx.ingress.kubernetes.io/affinity: "cookie"

  resources:
    requests:
      cpu: "2000m"
      memory: "4Gi"
    limits:
      cpu: "4000m"
      memory: "8Gi"

  jvmOptions:
    - "-Xms4g"
    - "-Xmx6g"
    - "-XX:+UseG1GC"
    - "-XX:MaxGCPauseMillis=200"

  env:
    KC_LOG_LEVEL: "INFO"
    KC_PROXY: "edge"
    KC_FEATURES: "token-exchange,admin-fine-grained-authz"
```

### Development Setup

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak-dev
  namespace: keycloak-dev
spec:
  replicas: 1

  database:
    type: postgresql
    host: postgres
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password

  service:
    type: NodePort

  env:
    KC_LOG_LEVEL: "DEBUG"
```

### With CloudNativePG

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  image: quay.io/keycloak/keycloak:26.4.1
  replicas: 3

  database:
    type: postgresql
    host: keycloak-postgres-rw  # CloudNativePG read-write service
    database: keycloak
    username: keycloak
    passwordSecret:
      name: keycloak-postgres-app  # CNPG generates this secret
      key: password
    sslMode: require

  ingress:
    enabled: true
    host: keycloak.example.com
    className: nginx
```

## See Also

**Related CRD References:**

- [KeycloakRealm CRD Reference](keycloak-realm-crd.md) - Configure realms on Keycloak instances
- [KeycloakClient CRD Reference](keycloak-client-crd.md) - Configure OAuth2/OIDC clients

**Deployment Guides:**

- [End-to-End Setup](../how-to/end-to-end-setup.md) - Deploy Keycloak instance with operator
- [Database Setup](../how-to/database-setup.md) - Configure PostgreSQL for production
- [High Availability Deployment](../how-to/ha-deployment.md) - Multi-replica Keycloak setup
- [Quick Start Guide](../quickstart/README.md) - Basic Keycloak instance deployment

**Architecture & Operations:**

- [Architecture](../architecture.md) - Operator design and reconciliation flow
- [Troubleshooting: Keycloak Instance Issues](../operations/troubleshooting.md#keycloak-instance-issues) - Common deployment problems
- [Observability](../observability.md) - Monitoring Keycloak instances
