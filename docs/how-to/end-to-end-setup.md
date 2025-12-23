# End-to-End Setup Guide

This guide walks you through deploying a **production-ready** Keycloak setup from scratch, including database configuration, high availability, TLS, and monitoring.

For a simpler quick start, see the [Quick Start Guide](../quickstart/README.md).

## Overview

This guide covers:

1. **Infrastructure Setup** - Kubernetes cluster, ingress, cert-manager, CloudNativePG
2. **Operator + Keycloak Installation** - Deploy using Helm with database and monitoring
3. **Multi-Tenant Setup** - Platform team configures namespaces and authorization
4. **Realm Creation** - Application teams create and manage realms via Helm
5. **Client Configuration** - OAuth2/OIDC client setup with credential management
6. **Verification & Testing** - End-to-end OAuth2 flow validation
7. **Production Checklist** - Security, monitoring, backup verification

**Estimated Time**: 30-45 minutes

---

## Prerequisites

### Required

| Component | Version | Purpose | Installation |
|-----------|---------|---------|--------------|
| **Kubernetes** | 1.26+ | Container orchestration | [kubernetes.io](https://kubernetes.io) |
| **kubectl** | 1.26+ | Kubernetes CLI | [Install Guide](https://kubernetes.io/docs/tasks/tools/) |
| **Helm** | 3.8+ | Package manager (OCI support required) | [helm.sh](https://helm.sh/docs/intro/install/) |

### Recommended for Production

| Component | Purpose | Installation |
|-----------|---------|--------------|
| **CloudNativePG** | PostgreSQL operator | [CNPG Docs](https://cloudnative-pg.io/documentation/current/installation_upgrade/) |
| **Ingress Controller** | External access (nginx, traefik) | [Ingress NGINX](https://kubernetes.github.io/ingress-nginx/deploy/) |
| **cert-manager** | Automatic TLS certificates | [cert-manager Docs](https://cert-manager.io/docs/installation/) |
| **Prometheus** | Metrics collection | [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) |

### Cluster Requirements

- **Nodes**: 3+ nodes for high availability
- **CPU**: 4+ cores per node recommended
- **Memory**: 8+ GB per node recommended
- **Storage**: StorageClass available for database persistence
- **RBAC**: Cluster admin permissions required for installation

---

## Part 1: Infrastructure Setup

### 1.1 Install CloudNativePG Operator

```bash
helm repo add cnpg https://cloudnative-pg.io/charts
helm repo update

helm install cnpg cnpg/cloudnative-pg \
  --namespace cnpg-system \
  --create-namespace \
  --wait

# Verify installation
kubectl get pods -n cnpg-system
```

### 1.2 Install Ingress Controller (nginx)

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --set controller.metrics.enabled=true \
  --wait

# Get external IP (may take a few minutes)
kubectl get svc -n ingress-nginx ingress-nginx-controller -w
```

### 1.3 Install cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true \
  --wait

# Verify installation
kubectl get pods -n cert-manager
```

### 1.4 Configure DNS

Point your domain to the ingress controller's external IP:

```bash
INGRESS_IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

echo "Configure DNS A record:"
echo "  keycloak.example.com  →  $INGRESS_IP"
```

### 1.5 Create ClusterIssuer for TLS

```bash
# Create Let's Encrypt ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com  # Update this
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
EOF

# Verify issuer is ready
kubectl get clusterissuer letsencrypt-prod
```

---

## Part 2: Operator + Keycloak Installation

### 2.1 Check Available StorageClasses

```bash
kubectl get storageclass

# Note your storageClass name for the next step
# Common values: standard, gp2, gp3, premium-rwo
```

### 2.2 Install Keycloak Operator with Keycloak Instance

Deploy the operator with a production-ready Keycloak instance and CloudNativePG database:

```bash
helm install keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set keycloak.enabled=true \
  --set keycloak.replicas=3 \
  --set keycloak.version="26.0.0" \
  --set keycloak.database.cnpg.enabled=true \
  --set keycloak.database.cnpg.clusterName=keycloak-postgres \
  --set keycloak.database.cnpg.instances=3 \
  --set keycloak.database.cnpg.storage.size=50Gi \
  --set keycloak.database.cnpg.storage.storageClass=standard \
  --set keycloak.ingress.enabled=true \
  --set keycloak.ingress.className=nginx \
  --set keycloak.ingress.hosts[0].host=keycloak.example.com \
  --set keycloak.ingress.hosts[0].paths[0].path=/ \
  --set keycloak.ingress.hosts[0].paths[0].pathType=Prefix \
  --set keycloak.ingress.tls[0].secretName=keycloak-tls \
  --set keycloak.ingress.tls[0].hosts[0]=keycloak.example.com \
  --set keycloak.ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-prod \
  --set monitoring.enabled=true \
  --set operator.replicaCount=2
```

> **Note**: Update `keycloak.example.com` to your actual domain and `storageClass` to match your cluster.

### 2.3 Verify Installation

```bash
# Wait for operator pods
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=keycloak-operator \
  -n keycloak-system \
  --timeout=120s

# Check Keycloak instance status
kubectl get keycloak -n keycloak-system

# Check PostgreSQL cluster
kubectl get cluster -n keycloak-system

# Check all pods
kubectl get pods -n keycloak-system
```

Expected output:
- Operator: 2 pods running
- Keycloak: 3 pods running
- PostgreSQL: 3 pods (1 primary, 2 replicas)

### 2.4 Retrieve Admin Credentials

```bash
# Get admin password
kubectl get secret keycloak-admin-password \
  -n keycloak-system \
  -o jsonpath='{.data.password}' | base64 -d && echo
```

> **Note**: Admin access is typically not needed - manage everything through Helm charts and CRDs.

---

## Part 3: Multi-Tenant Setup (Platform Team)

### 3.1 Understanding the Authorization Model

The operator uses **namespace-based authorization**:

- **Realm Creation**: Controlled by Kubernetes RBAC (who can install the keycloak-realm chart)
- **Client Creation**: Controlled by realm's `clientAuthorizationGrants` (which namespaces can install keycloak-client chart)
- **No Tokens/Secrets**: Authorization is purely declarative
- **GitOps-Friendly**: All authorization changes via Helm values

### 3.2 Create Application Team Namespace

```bash
kubectl create namespace team-alpha
kubectl label namespace team-alpha team=alpha environment=production
```

### 3.3 Create Realm for Application Team

Use the keycloak-realm Helm chart to create a realm:

```bash
helm install team-alpha-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace team-alpha \
  --set realmName=team-alpha \
  --set displayName="Team Alpha Identity" \
  --set operatorRef.namespace=keycloak-system \
  --set clientAuthorizationGrants[0]=team-alpha \
  --set security.registrationAllowed=false \
  --set security.resetPasswordAllowed=true \
  --set security.rememberMe=true \
  --set security.verifyEmail=true
```

### 3.4 Verify Realm Creation

```bash
# Wait for realm to be ready
kubectl wait --for=condition=Ready keycloakrealm/team-alpha-realm \
  -n team-alpha \
  --timeout=120s

# Check realm status
kubectl get keycloakrealm -n team-alpha

# View OIDC endpoints
kubectl get keycloakrealm team-alpha-realm -n team-alpha \
  -o jsonpath='{.status.endpoints}' | jq .
```

### 3.5 Grant Additional Namespaces (Optional)

To allow another namespace to create clients in this realm:

```bash
helm upgrade team-alpha-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace team-alpha \
  --reuse-values \
  --set clientAuthorizationGrants[0]=team-alpha \
  --set clientAuthorizationGrants[1]=team-alpha-staging
```

---

## Part 4: Realm Creation (Application Team)

Application teams create their own realms using the Helm chart.

### 4.1 Create Production Realm

```bash
helm install my-app-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace team-alpha \
  --set realmName=my-app-prod \
  --set displayName="My Application (Production)" \
  --set operatorRef.namespace=keycloak-system \
  --set clientAuthorizationGrants[0]=team-alpha \
  --set security.registrationAllowed=false \
  --set security.resetPasswordAllowed=true \
  --set security.verifyEmail=true \
  --set tokenSettings.accessTokenLifespan=300 \
  --set tokenSettings.ssoSessionIdleTimeout=1800 \
  --set tokenSettings.ssoSessionMaxLifespan=36000
```

### 4.2 Create Staging Realm

```bash
helm install my-app-staging-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace team-alpha \
  --set realmName=my-app-staging \
  --set displayName="My Application (Staging)" \
  --set operatorRef.namespace=keycloak-system \
  --set clientAuthorizationGrants[0]=team-alpha \
  --set security.registrationAllowed=true
```

### 4.3 Verify Realms

```bash
kubectl get keycloakrealm -n team-alpha
```

---

## Part 5: Client Configuration

### 5.1 Create Web Application Client

```bash
helm install my-webapp-client oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  --namespace team-alpha \
  --set clientId=my-webapp \
  --set clientName="My Web Application" \
  --set realmRef.name=my-app-realm \
  --set realmRef.namespace=team-alpha \
  --set publicClient=false \
  --set standardFlowEnabled=true \
  --set directAccessGrantsEnabled=false \
  --set redirectUris[0]="https://myapp.example.com/callback" \
  --set redirectUris[1]="https://myapp.example.com/silent-refresh" \
  --set webOrigins[0]="https://myapp.example.com"
```

### 5.2 Create API Client (Service Account)

```bash
helm install my-api-client oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  --namespace team-alpha \
  --set clientId=my-api \
  --set clientName="My API Service" \
  --set realmRef.name=my-app-realm \
  --set realmRef.namespace=team-alpha \
  --set publicClient=false \
  --set standardFlowEnabled=false \
  --set serviceAccountsEnabled=true
```

### 5.3 Verify Client Creation

```bash
# Wait for clients to be ready
kubectl wait --for=condition=Ready keycloakclient/my-webapp-client \
  -n team-alpha \
  --timeout=120s

# List all clients
kubectl get keycloakclient -n team-alpha
```

### 5.4 Retrieve Client Credentials

The operator automatically creates a secret with all OAuth2 credentials:

```bash
# View secret contents
kubectl get secret my-webapp-client-credentials -n team-alpha -o yaml

# Extract individual values
CLIENT_ID=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.client_id}' | base64 -d)
CLIENT_SECRET=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.client_secret}' | base64 -d)
ISSUER_URL=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.issuer_url}' | base64 -d)

echo "Client ID: $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo "Issuer URL: $ISSUER_URL"
```

### 5.5 Generate Environment File

```bash
kubectl get secret my-webapp-client-credentials -n team-alpha -o json | \
  jq -r '.data | to_entries[] | "\(.key | ascii_upcase)=\(.value | @base64d)"' > oauth2.env

cat oauth2.env
```

---

## Part 6: Verification & Testing

### 6.1 Verify All Resources

```bash
# Operator
kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Keycloak instance
kubectl get keycloak -n keycloak-system

# Database
kubectl get cluster -n keycloak-system

# Realms
kubectl get keycloakrealm -A

# Clients
kubectl get keycloakclient -A
```

All resources should show `PHASE=Ready`.

### 6.2 Test OIDC Discovery

```bash
ISSUER_URL=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.issuer_url}' | base64 -d)

curl -s "$ISSUER_URL/.well-known/openid-configuration" | jq .
```

### 6.3 Test Client Credentials Flow

```bash
CLIENT_ID=$(kubectl get secret my-api-client-credentials -n team-alpha \
  -o jsonpath='{.data.client_id}' | base64 -d)
CLIENT_SECRET=$(kubectl get secret my-api-client-credentials -n team-alpha \
  -o jsonpath='{.data.client_secret}' | base64 -d)
TOKEN_URL=$(kubectl get secret my-api-client-credentials -n team-alpha \
  -o jsonpath='{.data.token_url}' | base64 -d)

curl -s -X POST "$TOKEN_URL" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" | jq .
```

### 6.4 Test Authorization Code Flow

```bash
CLIENT_ID=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.client_id}' | base64 -d)
AUTH_URL=$(kubectl get secret my-webapp-client-credentials -n team-alpha \
  -o jsonpath='{.data.auth_url}' | base64 -d)

echo "Open in browser:"
echo "${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=https://myapp.example.com/callback&response_type=code&scope=openid%20profile%20email"
```

---

## Part 7: Production Checklist

### Security

- [ ] TLS enabled on ingress
- [ ] cert-manager issuing valid certificates
- [ ] Network policies configured (optional)
- [ ] RBAC configured for application teams
- [ ] Secrets stored securely (consider External Secrets Operator)

### High Availability

- [ ] Operator: 2+ replicas
- [ ] Keycloak: 3+ replicas
- [ ] PostgreSQL: 3+ instances (CloudNativePG)
- [ ] Pod anti-affinity configured
- [ ] PodDisruptionBudgets configured

### Backup & Recovery

- [ ] CloudNativePG backups configured (S3/GCS)
- [ ] Backup retention policy set
- [ ] Restore procedure tested
- [ ] Helm values stored in Git

### Monitoring

- [ ] ServiceMonitor created for Prometheus
- [ ] Grafana dashboards imported
- [ ] Alerts configured for critical issues
- [ ] Log aggregation configured

### GitOps

- [ ] All Helm values stored in Git
- [ ] ArgoCD/Flux applications configured
- [ ] PR workflow for changes
- [ ] Drift detection enabled

---

## GitOps with ArgoCD

### Repository Structure

```
gitops-repo/
├── infrastructure/
│   ├── cnpg/
│   │   └── application.yaml          # wave: 0
│   ├── cert-manager/
│   │   └── application.yaml          # wave: 0
│   └── ingress-nginx/
│       └── application.yaml          # wave: 0
├── keycloak/
│   ├── operator/
│   │   └── application.yaml          # wave: 1
│   └── realms/
│       ├── team-alpha/
│       │   ├── realm.yaml            # wave: 2
│       │   └── clients.yaml          # wave: 3
│       └── team-beta/
│           ├── realm.yaml            # wave: 2
│           └── clients.yaml          # wave: 3
```

### ArgoCD Application for Operator

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: keycloak-operator
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "1"
spec:
  project: default
  source:
    repoURL: ghcr.io/vriesdemichael/charts
    chart: keycloak-operator
    targetRevision: 0.3.x
    helm:
      valuesObject:
        keycloak:
          enabled: true
          replicas: 3
          database:
            cnpg:
              enabled: true
              instances: 3
        monitoring:
          enabled: true
        operator:
          replicaCount: 2
  destination:
    server: https://kubernetes.default.svc
    namespace: keycloak-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### ArgoCD Application for Realm

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: team-alpha-realm
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "2"
spec:
  project: default
  source:
    repoURL: ghcr.io/vriesdemichael/charts
    chart: keycloak-realm
    targetRevision: 0.3.x
    helm:
      valuesObject:
        realmName: team-alpha
        displayName: "Team Alpha Identity"
        operatorRef:
          namespace: keycloak-system
        clientAuthorizationGrants:
          - team-alpha
        security:
          resetPasswordAllowed: true
          verifyEmail: true
  destination:
    server: https://kubernetes.default.svc
    namespace: team-alpha
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

---

## Troubleshooting

### Operator Not Starting

```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
kubectl describe pod -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
```

### Keycloak Stuck in Pending

```bash
kubectl describe keycloak keycloak -n keycloak-system
kubectl get events -n keycloak-system --sort-by='.lastTimestamp'
kubectl get cluster -n keycloak-system  # Check database
```

### Realm Creation Fails

```bash
kubectl describe keycloakrealm <realm-name> -n <namespace>
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep <realm-name>
```

### Client Authorization Error

```bash
# Check realm's authorization grants
kubectl get keycloakrealm <realm-name> -n <namespace> \
  -o jsonpath='{.spec.clientAuthorizationGrants}'

# Ensure client namespace is in the list
helm upgrade <realm-release> oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace <namespace> \
  --reuse-values \
  --set clientAuthorizationGrants[0]=existing-ns \
  --set clientAuthorizationGrants[1]=new-ns
```

### Database Connection Issues

```bash
kubectl get cluster -n keycloak-system
kubectl logs -n keycloak-system -l cnpg.io/cluster=keycloak-postgres
```

---

## Next Steps

After completing this guide:

1. **Configure Identity Providers** - Add Google, GitHub, Azure AD SSO ([Guide](../guides/identity-providers.md))
2. **Set Up Monitoring** - Import Grafana dashboards ([Observability](../guides/observability.md))
3. **Configure Backups** - Set up CloudNativePG backups to S3 ([Backup Guide](./backup-restore.md))
4. **Add More Teams** - Repeat Part 3-5 for additional teams
5. **Review Security** - Implement network policies, audit logging

**Further Reading:**

- [Troubleshooting Guide](../operations/troubleshooting.md)
- [Multi-Tenant Configuration](./multi-tenant.md)
- [Database Setup Guide](./database-setup.md)
- [High Availability](./ha-deployment.md)
