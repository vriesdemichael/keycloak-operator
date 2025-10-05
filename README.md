# Keycloak Operator

A comprehensive Kubernetes operator for managing Keycloak instances, realms, and clients with full GitOps compatibility and cross-namespace support.

## 🎯 Overview

This operator provides declarative management of Keycloak identity and access management infrastructure through Kubernetes custom resources. Built with Python and the Kopf framework, it supports enterprise-grade features including:

- **Cross-namespace operations** - Manage clients from any authorized namespace
- **GitOps compatibility** - Fully declarative with no manual intervention required
- **Kubernetes-native RBAC** - Leverages K8s security instead of Keycloak's built-in permissions
- **Dynamic client provisioning** - Create OAuth2/OIDC clients on-demand
- **Service account automation** - Declarative role assignment for machine-to-machine credentials
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
All configuration of keycloak is done through CRs, you should not (and cannot) interact with the keycloak instance manually. 

Beware of recreating your resources, even though the configuration which you would normally do in the UI or through realm import/exports is done through gitops there are still runtime configurations stored in the database, such as users and their linked IDPs.


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


## 📧 Realm Configuration

### SMTP Configuration

Configure email delivery for password resets, email verification, and notifications.

#### Secure Configuration (Recommended)

Use Kubernetes secrets for SMTP passwords:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: smtp-credentials
  namespace: identity-system
type: Opaque
stringData:
  password: "your-smtp-password-here"
---
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: identity-system
spec:
  realm_name: my-realm
  keycloak_instance_ref:
    name: my-keycloak

  smtp_server:
    host: smtp.gmail.com
    port: 587
    from_address: noreply@example.com
    from_display_name: "My Application"
    reply_to: support@example.com
    starttls: true
    auth: true
    user: noreply@example.com
    password_secret:
      name: smtp-credentials
      key: password
```

#### GitOps-Compatible Secret Management

For production GitOps workflows, use sealed secrets or external secret operators:

**With Sealed Secrets:**
```bash
# Create sealed secret
kubectl create secret generic smtp-credentials \
  --from-literal=password='your-password' \
  --dry-run=client -o yaml | \
  kubeseal -o yaml > smtp-credentials-sealed.yaml

# Commit sealed secret to git
git add smtp-credentials-sealed.yaml
git commit -m "Add SMTP credentials"
```

**With External Secrets Operator:**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: smtp-credentials
  namespace: identity-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: smtp-credentials
  data:
  - secretKey: password
    remoteRef:
      key: smtp/password
```

#### SMTP Configuration Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | ✅ | SMTP server hostname |
| `port` | integer | ✅ | SMTP server port (1-65535) |
| `from_address` | string | ✅ | From email address |
| `from_display_name` | string | ❌ | Display name for from address |
| `reply_to` | string | ❌ | Reply-to email address |
| `envelope_from` | string | ❌ | Envelope from address |
| `ssl` | boolean | ❌ | Use SSL (default: false) |
| `starttls` | boolean | ❌ | Use STARTTLS (default: false) |
| `auth` | boolean | ❌ | Require authentication (default: false) |
| `user` | string | ❌ | SMTP username (required if auth=true) |
| `password` | string | ❌ | Direct password (not recommended) |
| `password_secret` | object | ❌ | Secret reference (recommended) |

#### Security Best Practices

**✅ DO:**
- Use `password_secret` for credential storage
- Use sealed secrets or external secret operators for GitOps
- Restrict secret access with Kubernetes RBAC
- Rotate SMTP credentials regularly
- Use TLS/STARTTLS for secure connections

**❌ DON'T:**
- Store passwords directly in `password` field
- Commit unencrypted secrets to Git
- Share SMTP credentials across multiple realms
- Use unencrypted SMTP connections in production


## 🤝 Contributing

### Development Workflow
Please do not develop fixes yourself. This entire repository was vibecoded. Provide an issue on github to have claude code implement it.

You can open manual pull requests that influence the instructions for claude code.
