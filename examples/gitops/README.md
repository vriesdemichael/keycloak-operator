# GitOps Examples for Keycloak Operator

This directory contains examples for deploying Keycloak operator resources (realms and clients) using GitOps tools.

## Available Examples

### 1. GitHub Actions (`github-actions-deploy.yaml`)

CI/CD pipeline for deploying Keycloak resources using GitHub Actions.

**Features:**
- YAML validation and schema checking
- Separate dev/production deployments
- Automatic waiting for resources to be ready
- Smoke tests and rollback capabilities
- Security scanning for hardcoded secrets
- Deployment approvals for production

**Setup:**
1. Save as `.github/workflows/deploy-keycloak.yaml` in your repository
2. Add `KUBECONFIG_DEV` and `KUBECONFIG_PROD` as repository secrets
3. Structure your manifests in `k8s/keycloak/` directory
4. Push to main/production branches to trigger deployment

**Directory Structure:**
```
your-repo/
├── .github/
│   └── workflows/
│       └── deploy-keycloak.yaml
└── k8s/
    └── keycloak/
        ├── realms/
        │   └── my-realm.yaml
        └── clients/
            └── my-client.yaml
```

### 2. ArgoCD (`argocd-application.yaml`)

GitOps deployment using ArgoCD for continuous synchronization.

**Features:**
- Automatic sync from Git repository
- Custom health checks for Keycloak CRDs
- Multi-environment support (dev, staging, production)
- Self-healing and auto-pruning
- AppProject for access control

**Setup:**
1. Install ArgoCD in your cluster
2. Add custom health checks to `argocd-cm` ConfigMap (see file comments)
3. Update `repoURL` to your Git repository
4. Apply Application: `kubectl apply -f argocd-application.yaml -n argocd`
5. Access ArgoCD UI to monitor sync status

**Directory Structure:**
```
your-repo/
└── k8s/
    └── keycloak/
        ├── base/
        │   ├── realms/
        │   └── clients/
        └── overlays/
            ├── dev/
            ├── staging/
            └── production/
```

**Recommended: Use Kustomize overlays for environment-specific configurations**

### 3. Flux CD (`flux-kustomization.yaml`)

GitOps deployment using Flux CD with automatic drift detection.

**Features:**
- GitRepository source management
- Separate Kustomizations for realms and clients
- Dependency ordering (realms → clients)
- Variable substitution for environment-specific values
- HelmRelease for operator installation
- Slack notifications on failures

**Setup:**
1. Install Flux CD: `flux bootstrap github --owner=your-org --repository=your-repo`
2. Create GitRepository resource (included in example)
3. Update `path` to your manifests directory
4. Apply Kustomizations: `kubectl apply -f flux-kustomization.yaml`
5. Monitor with: `flux get kustomizations`

**Directory Structure:**
```
your-repo/
├── flux/
│   ├── kustomizations/
│   │   └── keycloak.yaml
│   └── sources/
│       └── keycloak-repo.yaml
└── k8s/
    └── keycloak/
        ├── realms/
        │   ├── kustomization.yaml
        │   └── my-realm.yaml
        └── clients/
            ├── kustomization.yaml
            └── my-client.yaml
```

## Comparison

| Feature | GitHub Actions | ArgoCD | Flux CD |
|---------|---------------|--------|---------|
| **Sync Model** | Push (CI/CD) | Pull (GitOps) | Pull (GitOps) |
| **Deployment Trigger** | Git push | Auto/Manual | Auto |
| **Rollback** | Manual (backup artifacts) | UI-based | CLI-based |
| **Multi-cluster** | Via kubeconfig secrets | Native support | Native support |
| **Drift Detection** | No | Yes (self-heal) | Yes (reconciliation) |
| **Secret Management** | GitHub Secrets | External Secrets Operator | SOPS, External Secrets |
| **Best For** | CI/CD pipelines, testing | Multi-team, UI preference | Flux-native, Helm-heavy |

## Best Practices

### 1. Resource Ordering

Always deploy resources in this order:
1. **Keycloak instance** (if using operator-managed Keycloak)
2. **KeycloakRealm** resources (create authentication tokens)
3. **KeycloakClient** resources (depend on realm tokens)

### 2. Secret Management

**Never commit secrets to Git!** Use one of these approaches:

- **External Secrets Operator:** Reference secrets from external vaults
- **Sealed Secrets:** Encrypt secrets in Git, decrypt in-cluster
- **SOPS:** Encrypt secrets in Git with age/GPG
- **CI/CD Secrets:** Inject secrets during deployment (GitHub Actions)

Example with External Secrets:
```yaml
# Reference secret from AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: smtp-credentials
spec:
  secretStoreRef:
    name: aws-secretsmanager
  target:
    name: smtp-password
  data:
    - secretKey: password
      remoteRef:
        key: /keycloak/smtp-password
```

### 3. Environment Separation

Use Kustomize overlays for environment-specific configurations:

**Base (`k8s/keycloak/base/realm.yaml`):**
```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-app
spec:
  realmName: my-app
  # Common configuration
```

**Dev overlay (`k8s/keycloak/overlays/dev/kustomization.yaml`):**
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: development
resources:
  - ../../base
patches:
  - patch: |-
      - op: replace
        path: /spec/security/registrationAllowed
        value: true
    target:
      kind: KeycloakRealm
```

### 4. Health Checks

Ensure your GitOps tool waits for resources to be ready:

- **GitHub Actions:** `kubectl wait --for=condition=Ready`
- **ArgoCD:** Custom health checks (see example)
- **Flux:** `healthChecks` in Kustomization

### 5. Testing

Test manifest changes before deploying:

```bash
# Dry-run validation
kubectl apply --dry-run=client -f my-realm.yaml

# Schema validation
kubeconform -schema-location \
  'https://vriesdemichael.github.io/keycloak-operator/schemas/{{ .ResourceKind }}.json' \
  my-realm.yaml

# Check operator logs after deployment
kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=50
```

### 6. Monitoring

Monitor deployment status:

```bash
# Check resource status
kubectl get keycloakrealm,keycloakclient -A

# Watch for errors
kubectl get events --all-namespaces --field-selector type=Warning | grep keycloak

# Operator health
kubectl get pods -n keycloak-operator-system
```

## Troubleshooting

### Realms not reconciling

```bash
# Check operator logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=100

# Check realm status
kubectl describe keycloakrealm my-realm -n production

# Verify authorization token exists
kubectl get secret <auth-token-name> -n production
```

### Clients stuck in Pending

```bash
# Check if realm is ready first
kubectl get keycloakrealm -n production

# Check if realm auth secret exists
kubectl get secret my-realm-realm-auth -n production

# Check client status
kubectl describe keycloakclient my-client -n production
```

### GitOps sync failures

**ArgoCD:**
```bash
argocd app get keycloak-resources
argocd app sync keycloak-resources --prune
```

**Flux:**
```bash
flux get kustomizations
flux reconcile kustomization keycloak-realms --with-source
flux logs --level=error
```

## See Also

- [Quickstart Guide](../../docs/quickstart/README.md) - Basic operator usage
- [End-to-End Setup](../../docs/how-to/end-to-end-setup.md) - Complete production deployment
- [Troubleshooting Guide](../../docs/operations/troubleshooting.md) - Common issues and solutions
- [Architecture](../../docs/architecture.md) - Understanding operator internals
- [CRD References](../../docs/reference/) - Complete field documentation

## Contributing

Found an issue or want to add examples for other GitOps tools (e.g., Jenkins X, Spinnaker)?
Please open an issue or pull request in the main repository.
