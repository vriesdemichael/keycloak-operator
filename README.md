# Keycloak Operator

A comprehensive Kubernetes operator for managing Keycloak instances, realms, and clients with full GitOps compatibility and cross-namespace support.

## 🎯 Overview

This operator provides declarative management of Keycloak identity and access management infrastructure through Kubernetes custom resources. Built with Python and the Kopf framework, it supports enterprise-grade features including:

- **Cross-namespace operations** - Manage clients from any authorized namespace
- **GitOps compatibility** - Fully declarative with no manual intervention required
- **Kubernetes-native RBAC** - Leverages K8s security instead of Keycloak's built-in permissions
- **Dynamic client provisioning** - Create OAuth2/OIDC clients on-demand
- **Comprehensive realm management** - Full control over authentication, themes, and federation

## 🏗️ Architecture

The operator manages three primary custom resources:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    Keycloak     │    │  KeycloakRealm   │    │ KeycloakClient  │
│   (Instance)    │◄───┤   (Identity)     │◄───┤   (OAuth2/OIDC) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Resource Hierarchy
- **Keycloak**: Core identity server instance with database, TLS, and networking
- **KeycloakRealm**: Identity domain with users, roles, themes, and authentication flows
- **KeycloakClient**: OAuth2/OIDC client applications with credentials and endpoints

## 📋 Prerequisites

- Kubernetes cluster v1.25+
- Python 3.11+ (for development)
- [uv](https://github.com/astral-sh/uv) package manager
- kubectl access with cluster-admin privileges (for installation)

## 🚀 Quick Start

### 1. Install CRDs and RBAC

```bash
# Install Custom Resource Definitions
kubectl apply -f k8s/crds/

# Install RBAC configuration (creates keycloak-system namespace)
kubectl apply -f k8s/rbac/install-rbac.yaml
```

### 2. Deploy the Operator

```bash
# Build and deploy
docker build -t keycloak-operator:latest .
kubectl create deployment keycloak-operator \
  --image=keycloak-operator:latest \
  --namespace=keycloak-system

# Or use the provided deployment manifest (TODO: create deployment.yaml)
kubectl apply -f k8s/deploy/deployment.yaml
```

### 3. Create Your First Keycloak Instance

```yaml
# keycloak-instance.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: my-keycloak
  namespace: identity-system
spec:
  version: "23.0.0"
  replicas: 2

  database:
    type: postgresql
    host: postgres.database.svc.cluster.local
    name: keycloak
    username: keycloak
    password_secret:
      name: postgres-credentials
      key: password

  tls:
    enabled: true
    hostname: keycloak.example.com
    generate_certificate: true

  admin_access:
    username: admin
    password_secret:
      name: keycloak-admin
      key: password
```

```bash
kubectl apply -f keycloak-instance.yaml
```

### 4. Create a Realm

```yaml
# demo-realm.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: demo-realm
  namespace: applications
spec:
  realm_name: demo
  keycloak_instance_ref:
    name: my-keycloak
    namespace: identity-system

  security:
    registration_allowed: true
    verify_email: true
    ssl_required: external

  themes:
    login: custom-theme
    email: company-theme
```

### 5. Create OAuth2 Clients

```yaml
# webapp-client.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: webapp-client
  namespace: web-apps
spec:
  client_id: my-webapp
  keycloak_instance_ref:
    name: my-keycloak
    namespace: identity-system
  realm: demo

  public_client: false
  redirect_uris:
    - https://webapp.example.com/callback
  web_origins:
    - https://webapp.example.com

  settings:
    standard_flow_enabled: true
    service_accounts_enabled: true
```

## 🔧 Development Setup

### Local Development Environment

```bash
# Clone and setup
git clone <repository-url>
cd keycloak-operator

# Install dependencies
uv sync

# Run tests
uv run pytest

# Code formatting and linting
uv run ruff check --fix
uv run ruff format

# Type checking
uv run ty check
```

### Testing the Operator

**Automated Test Script:**

```bash
# Run the full integration test
./test-operator.sh

# Cleanup only (useful after manual testing)
./test-operator.sh --cleanup-only
```

**Manual Integration Test:**

1. **Install CRDs and start operator**:
   ```bash
   # Install Custom Resource Definitions
   kubectl apply -f k8s/crds/

   # Start operator in background
   uv run python -m keycloak_operator.operator &
   ```

2. **Create test environment**:
   ```bash
   # Create test namespace
   kubectl create namespace keycloak-test

   # Create required secrets
   kubectl create secret generic keycloak-db-secret \
     --from-literal=password=testpass -n keycloak-test
   kubectl create secret generic keycloak-admin-secret \
     --from-literal=password=admin123 -n keycloak-test
   ```

3. **Deploy test Keycloak instance**:
   ```yaml
   # Save as test-keycloak.yaml
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

4. **Deploy and verify**:
   ```bash
   kubectl apply -f test-keycloak.yaml

   # Wait for deployment
   kubectl wait --for=condition=ready pod -l app=keycloak -n keycloak-test --timeout=300s

   # Check resources
   kubectl get keycloaks.keycloak.mdvr.nl,pods,services -n keycloak-test
   ```

5. **Test connectivity**:
   ```bash
   # Port forward to Keycloak
   kubectl port-forward -n keycloak-test service/test-keycloak-keycloak 8080:8080 &

   # Test health endpoint
   curl http://localhost:8080/health
   # Expected: {"status": "UP", "checks": [...]}
   ```

6. **Cleanup**:
   ```bash
   kubectl delete -f test-keycloak.yaml
   kubectl delete namespace keycloak-test
   # Kill background processes
   pkill -f "port-forward"
   pkill -f "keycloak_operator"
   ```

### Development with Docker Compose

```bash
# Start local Keycloak + PostgreSQL for testing
docker-compose up -d postgres keycloak

# Run operator in development mode
docker-compose --profile dev up keycloak-operator

# Access local Keycloak
open http://localhost:8080
# Admin credentials: admin/admin
```

### Project Structure

```
keycloak-operator/
├── src/keycloak_operator/
│   ├── operator.py              # Main operator entry point
│   ├── handlers/
│   │   ├── keycloak.py         # Keycloak instance lifecycle
│   │   ├── client.py           # Client provisioning & management
│   │   └── realm.py            # Realm configuration & features
│   ├── utils/
│   │   ├── keycloak_admin.py   # Keycloak Admin API client
│   │   ├── kubernetes.py       # K8s resource management
│   │   └── validation.py       # Input validation & security
│   └── models/
│       ├── keycloak.py         # Keycloak resource models
│       ├── client.py           # Client resource models
│       └── realm.py            # Realm resource models
├── tests/                      # Comprehensive test suite
├── k8s/
│   ├── crds/                   # Custom Resource Definitions
│   └── rbac/                   # RBAC configuration
├── Dockerfile                  # Multi-stage container build
└── docker-compose.yaml         # Local development stack
```

## 📚 Custom Resources

### Keycloak Instance

Manages the core Keycloak server deployment:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
spec:
  # Core configuration
  version: "23.0.0"
  image: "quay.io/keycloak/keycloak:23.0"
  replicas: 3

  # Database (required)
  database:
    type: postgresql
    host: postgres.example.com
    port: 5432
    name: keycloak_db
    username: keycloak_user
    password_secret:
      name: db-credentials
      key: password
    ssl_mode: require

  # TLS/SSL
  tls:
    enabled: true
    secret_name: keycloak-tls
    hostname: keycloak.example.com
    generate_certificate: false

  # Service exposure
  service:
    type: LoadBalancer
    port: 8080
    https_port: 8443
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: nlb

  # Ingress
  ingress:
    enabled: true
    hostname: keycloak.example.com
    class_name: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod

  # Admin access
  admin_access:
    username: admin
    password_secret:
      name: keycloak-admin-secret
    restrict_to_namespace: true

  # Resources
  resources:
    requests:
      cpu: "500m"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "4Gi"

  # Additional configuration
  env:
    KC_LOG_LEVEL: INFO
    KC_METRICS_ENABLED: "true"
```

**Status Fields:**
- `phase`: Pending → Provisioning → Ready → Failed → Updating
- `external_url`: Public Keycloak URL
- `admin_secret`: Generated admin credentials
- `database_status`: Database connection health

### KeycloakRealm

Comprehensive realm configuration:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
spec:
  realm_name: production
  keycloak_instance_ref:
    name: keycloak-prod
    namespace: identity-system

  # Basic settings
  enabled: true
  display_name: "Production Environment"

  # Security configuration
  security:
    registration_allowed: false
    verify_email: true
    login_with_email_allowed: true
    ssl_required: external
    brute_force_protected: true

  # Token configuration
  tokens:
    access_token_lifespan: 300        # 5 minutes
    sso_session_idle_timeout: 1800    # 30 minutes
    sso_session_max_lifespan: 36000   # 10 hours

  # Themes
  themes:
    login: company-login
    admin: company-admin
    account: company-account
    email: company-email

  # Identity providers
  identity_providers:
    - alias: google
      provider_id: google
      enabled: true
      config:
        clientId: "google-client-id"
        clientSecret: "google-client-secret"
    - alias: azure-ad
      provider_id: oidc
      enabled: true
      config:
        clientId: "azure-client-id"
        clientSecret: "azure-client-secret"
        issuer: "https://login.microsoftonline.com/tenant-id/v2.0"

  # User federation
  user_federation_providers:
    - display_name: "Active Directory"
      provider_name: ldap
      config:
        connectionUrl: "ldap://ad.company.com:389"
        usersDn: "ou=Users,dc=company,dc=com"

  # Custom client scopes
  client_scopes:
    - name: company-profile
      description: "Company-specific user profile"
      protocol: openid-connect

  # Realm roles
  roles:
    realm_roles:
      - name: admin
        description: "Administrator role"
      - name: user
        description: "Standard user role"

  # Groups
  groups:
    - name: Administrators
      path: /Administrators
      realm_roles: ["admin"]
    - name: Users
      path: /Users
      realm_roles: ["user"]
```

### KeycloakClient

OAuth2/OIDC client configuration:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
spec:
  client_id: webapp-prod
  client_name: "Production Web Application"
  keycloak_instance_ref:
    name: keycloak-prod
    namespace: identity-system
  realm: production

  # Client type
  public_client: false              # Confidential client
  protocol: openid-connect

  # OAuth2 configuration
  redirect_uris:
    - https://app.company.com/auth/callback
    - https://app.company.com/silent-renew
  web_origins:
    - https://app.company.com
  post_logout_redirect_uris:
    - https://app.company.com/logout

  # Client settings
  settings:
    enabled: true
    standard_flow_enabled: true      # Authorization code flow
    implicit_flow_enabled: false
    direct_access_grants_enabled: false
    service_accounts_enabled: true   # Client credentials flow

    # Token lifespans
    access_token_lifespan: 300
    refresh_token_lifespan: 1800

  # Scopes
  default_client_scopes:
    - openid
    - profile
    - email
    - company-profile
  optional_client_scopes:
    - phone
    - address

  # Protocol mappers
  protocol_mappers:
    - name: company-id
      protocol: openid-connect
      protocol_mapper: oidc-usermodel-attribute-mapper
      config:
        user.attribute: companyId
        claim.name: company_id

  # Client roles
  client_roles:
    - webapp-admin
    - webapp-user

  # Secret management
  manage_secret: true              # Create K8s secret
  secret_name: webapp-credentials  # Custom secret name
  regenerate_secret: false         # Don't rotate on update
```

**Generated Secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: webapp-credentials
  namespace: web-apps
data:
  client-id: d2ViYXBwLXByb2Q=          # Base64: webapp-prod
  client-secret: c2VjcmV0LWhlcmU=      # Base64: secret-here
  issuer-url: aHR0cHM6Ly9rZXljbG9hay... # Base64: https://keycloak...
  auth-url: aHR0cHM6Ly9rZXljbG9hay...   # Base64: https://keycloak.../auth
  token-url: aHR0cHM6Ly9rZXljbG9hay...  # Base64: https://keycloak.../token
```

## 🔐 Security & RBAC

### Cross-Namespace Operations

The operator supports cross-namespace resource references with proper RBAC validation:

```yaml
# Client in namespace 'web-apps' referencing Keycloak in 'identity-system'
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: my-client
  namespace: web-apps
spec:
  client_id: cross-namespace-client
  keycloak_instance_ref:
    name: shared-keycloak
    namespace: identity-system    # Different namespace
  realm: shared-realm
```

**RBAC Requirements:**
- Service account must have cluster-wide permissions
- Keycloak instance namespace must allow client creation
- Proper network policies for cross-namespace communication

### Security Best Practices

1. **Least Privilege**: Operator runs with minimal required permissions
2. **Secret Management**: Credentials stored in Kubernetes secrets
3. **TLS Everywhere**: HTTPS for all Keycloak communications
4. **Network Policies**: Restrict pod-to-pod communication
5. **Pod Security**: Non-root containers with security contexts

## 🎛️ Configuration & Customization

### Environment Variables

**Operator Configuration:**
```bash
# Kopf framework
KOPF_LOG_LEVEL=INFO
KOPF_VERBOSE=false

# Operator behavior
KEYCLOAK_OPERATOR_NAMESPACE=keycloak-system
KEYCLOAK_OPERATOR_WATCH_NAMESPACE=""    # Empty = all namespaces
KEYCLOAK_OPERATOR_LOG_LEVEL=INFO
KEYCLOAK_OPERATOR_DRY_RUN=false

# Performance tuning
KEYCLOAK_OPERATOR_WORKER_THREADS=10
KEYCLOAK_OPERATOR_RECONCILE_INTERVAL=300
KEYCLOAK_OPERATOR_TIMEOUT=60

# Monitoring
KEYCLOAK_OPERATOR_METRICS_PORT=8080
KEYCLOAK_OPERATOR_HEALTH_PORT=8081
```

## 📊 Monitoring & Observability

### Metrics

The operator exposes Prometheus metrics on port 8080:

```
# Kopf framework metrics
kopf_events_total{type="create|update|delete"}
kopf_handlers_duration_seconds{handler="keycloak_create"}

# Custom operator metrics
keycloak_operator_resources_total{kind="Keycloak|KeycloakClient|KeycloakRealm"}
keycloak_operator_reconcile_duration_seconds{resource_kind}
keycloak_operator_errors_total{error_type}
```

### Health Checks

```bash
# Operator health
curl http://operator:8081/healthz

# Keycloak health
curl http://keycloak:8080/health/ready
curl http://keycloak:8080/health/live
```

## 🔄 GitOps Integration

### Flux/ArgoCD Compatibility

The operator is designed for GitOps workflows:

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  # Infrastructure
  - infrastructure/keycloak-instance.yaml
  - infrastructure/production-realm.yaml

  # Applications (different repo/team)
  - applications/webapp-client.yaml
  - applications/api-client.yaml

# Dependency management
dependsOn:
  - name: keycloak-operator
    namespace: keycloak-system
```

**Benefits:**
- **Declarative**: All configuration in Git
- **Auditable**: Full change history
- **Reversible**: Easy rollbacks
- **Collaborative**: PR-based workflow
- **Consistent**: Same config across environments

## 🚨 Troubleshooting

### Common Issues

**1. CRD Installation Fails**
```bash
# Check CRD status
kubectl get crd | grep keycloak

# Reinstall CRDs
kubectl delete crd keycloaks.keycloak.mdvr.nl keycloakclients.keycloak.mdvr.nl keycloakrealms.keycloak.mdvr.nl
kubectl apply -f k8s/crds/
```

**2. RBAC Permission Denied**
```bash
# Check service account
kubectl get sa keycloak-operator -n keycloak-system

# Check cluster role binding
kubectl get clusterrolebinding keycloak-operator

# Verify permissions
kubectl auth can-i create keycloaks --as=system:serviceaccount:keycloak-system:keycloak-operator
```

**3. Cross-Namespace Issues**
```bash
# Check network policies
kubectl get networkpolicy -A

# Test connectivity
kubectl run test-pod --rm -it --image=curlimages/curl -- \
  curl -k https://keycloak.identity-system.svc.cluster.local:8443/health
```

**4. Operator Development Issues**
```bash
# Operator not processing resources
kubectl get keycloaks.keycloak.mdvr.nl -A
kubectl describe keycloak test-keycloak -n keycloak-test

# Check for conflicting CRDs (common during development)
kubectl get crd | grep keycloak
# If you see multiple keycloak CRDs with different groups, delete old ones:
kubectl delete crd keycloaks.k8s.keycloak.org keycloakclients.legacy.k8s.keycloak.org

# Schema validation errors
kubectl get events -n keycloak-test --sort-by='.lastTimestamp'

# Operator process issues
ps aux | grep keycloak_operator
# Kill stuck operator: pkill -f keycloak_operator
```

**5. Test Deployment Issues**
```bash
# Keycloak pod not starting
kubectl describe pod -l app=keycloak -n keycloak-test
kubectl logs -l app=keycloak -n keycloak-test

# Missing secrets
kubectl get secrets -n keycloak-test
# Recreate if needed:
kubectl create secret generic keycloak-db-secret --from-literal=password=test -n keycloak-test

# Service not accessible
kubectl get svc -n keycloak-test
kubectl port-forward -n keycloak-test service/test-keycloak-keycloak 8080:8080
curl http://localhost:8080/health
```

### Debug Mode

```bash
# Enable debug logging
kubectl set env deployment/keycloak-operator \
  KOPF_LOG_LEVEL=DEBUG \
  KEYCLOAK_OPERATOR_LOG_LEVEL=DEBUG \
  -n keycloak-system

# Follow operator logs
kubectl logs -f deployment/keycloak-operator -n keycloak-system

# Check resource status
kubectl describe keycloak my-keycloak -n identity-system
```

## ⚠️ Production Considerations

### Why Not to Use H2 Database in Production

The test examples in this documentation use H2 database for simplicity, but **H2 should never be used in production** environments. Here's why:

#### H2 Database Limitations

**1. Data Persistence Issues**
- H2 stores data in temporary container storage that is lost when pods restart
- No backup/restore capabilities for production scenarios
- Data corruption risks during unexpected shutdowns

**2. Performance Limitations**
- Single-threaded nature cannot handle concurrent load
- No connection pooling optimization
- Memory-only mode loses all data on restart

**3. High Availability Issues**
- Cannot support multi-replica Keycloak deployments
- No clustering or replication support
- Single point of failure for authentication system

**4. Operational Challenges**
- No monitoring or performance metrics
- Limited transaction support
- No point-in-time recovery options

### Production Database Requirements

For production deployments, use enterprise-grade databases:

#### PostgreSQL (Recommended)
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: production-keycloak
  namespace: identity-system
spec:
  replicas: 3  # Multi-replica requires external DB

  database:
    type: postgresql
    host: postgres-cluster.database.svc.cluster.local
    port: 5432
    name: keycloak_production
    username: keycloak_user
    password_secret:
      name: postgres-credentials
      key: password

    # Production database settings
    connection_params:
      sslmode: require
      pool_size: "20"
      max_connections: "100"

  # High availability configuration
  resources:
    requests:
      cpu: "1000m"
      memory: "2Gi"
    limits:
      cpu: "4000m"
      memory: "8Gi"

  # Production security
  tls:
    enabled: true
    secret_name: keycloak-tls-prod

  ingress:
    enabled: true
    class_name: nginx
    host: auth.company.com
    tls_enabled: true
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
```

#### Other Supported Production Databases
- **MySQL/MariaDB**: Good performance, wide ecosystem support
- **Oracle**: Enterprise features, advanced security
- **Microsoft SQL Server**: Windows environment integration

### Production Deployment Checklist

#### Security Hardening
- [ ] External database with TLS encryption
- [ ] Strong admin passwords in Kubernetes secrets
- [ ] TLS/SSL enabled for all communications
- [ ] Network policies restricting pod communication
- [ ] Pod security contexts with non-root users
- [ ] Regular security updates and patches

#### High Availability
- [ ] Multiple Keycloak replicas (minimum 3)
- [ ] Database clustering/replication
- [ ] Load balancer with health checks
- [ ] Resource limits and requests configured
- [ ] Pod disruption budgets set
- [ ] Multi-zone deployment

#### Monitoring & Backup
- [ ] Prometheus metrics collection
- [ ] Centralized logging (Fluentd/Fluent Bit)
- [ ] Database backup automation
- [ ] Disaster recovery procedures tested
- [ ] Alert rules for critical failures
- [ ] SLA monitoring dashboards

#### Performance Optimization
- [ ] JVM heap size tuning based on load
- [ ] Database connection pool sizing
- [ ] CDN for static assets (themes, scripts)
- [ ] Session clustering configuration
- [ ] Cache optimization (Redis/Infinispan)

### Sample Production Values

```yaml
# Production Keycloak configuration
spec:
  replicas: 3

  resources:
    requests:
      cpu: "2000m"
      memory: "4Gi"
    limits:
      cpu: "4000m"
      memory: "8Gi"

  # JVM optimization for production load
  jvm_options:
    - "-Xms4g"
    - "-Xmx6g"
    - "-XX:+UseG1GC"
    - "-XX:MaxGCPauseMillis=200"

  # Production environment variables
  environment_variables:
    KC_CACHE: ispn
    KC_CACHE_STACK: kubernetes
    KC_LOG_LEVEL: WARN
    KC_METRICS_ENABLED: "true"

  # Clustering configuration
  keycloak_options:
    cache-embedded-mtls-enabled: "true"
    cache-remote-host: redis-cluster
    cache-remote-port: "6379"
```

**Remember**: Production environments require careful planning, regular maintenance, and proper operational procedures. The examples in this documentation are primarily for development and testing purposes.

## 🤝 Contributing

### Development Workflow

1. **Fork & Clone**
```bash
git clone https://github.com/vriesdemichael/keycloak-operator
cd keycloak-operator
```

2. **Setup Development Environment**
```bash
uv sync --dev
```

3. **Make Changes**
```bash
# Run tests frequently
uv run pytest

# Code formatting and linting
uv run ruff check --fix
uv run ruff format
```

4. **Test Changes Thoroughly**
```bash
# Unit tests
uv run pytest

# Integration test with real operator
kubectl apply -f k8s/crds/
uv run python -m keycloak_operator.operator &

# Create test environment
kubectl create namespace keycloak-test
kubectl create secret generic keycloak-db-secret --from-literal=password=test -n keycloak-test
kubectl create secret generic keycloak-admin-secret --from-literal=password=admin -n keycloak-test

# Deploy test Keycloak (use example from Testing section above)
kubectl apply -f test-keycloak.yaml

# Verify functionality
kubectl get keycloaks.keycloak.mdvr.nl -n keycloak-test
kubectl port-forward -n keycloak-test service/test-keycloak-keycloak 8080:8080 &
curl http://localhost:8080/health

# Cleanup
kubectl delete -f test-keycloak.yaml
kubectl delete namespace keycloak-test
pkill -f "keycloak_operator|port-forward"
```

5. **Alternative: Docker Development**
```bash
# Start development stack
docker-compose up -d

# Run operator locally
uv run python -m keycloak_operator.operator
```

### Code Guidelines

- **Type Hints**: All functions must have type annotations
- **Documentation**: Docstrings for all public APIs
- **Error Handling**: Proper exception chaining with `from e`
- **Logging**: Structured logging with context
- **Testing**: Unit tests for all business logic

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ using Python, Kopf, and Kubernetes**