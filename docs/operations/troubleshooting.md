# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Keycloak operator. Issues are organized by **symptom** for faster troubleshooting.

## Quick Diagnostic Commands

```bash
# Check all Keycloak resources at once
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces

# Check operator health
kubectl get pods -n keycloak-operator-system
kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=100

# Check events (recent issues)
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -20
```

---

## Table of Contents

1. [Operator Issues](#operator-issues)
2. [Keycloak Instance Issues](#keycloak-instance-issues)
3. [Realm Issues](#realm-issues)
4. [Client Issues](#client-issues)
5. [Token & Authorization Issues](#token-authorization-issues)
6. [Database Issues](#database-issues)
7. [Networking & Ingress Issues](#networking-ingress-issues)
8. [Performance Issues](#performance-issues)
9. [Common Pitfalls](#common-pitfalls)

---

## Operator Issues

### Symptom: Operator Pods Not Starting

**Possible Causes:**
- Image pull failure
- RBAC permissions missing
- Resource constraints
- CRD installation failure

**Diagnosis:**

```bash
# Check pod status
kubectl get pods -n keycloak-operator-system

# Check pod events
kubectl describe pod -n keycloak-operator-system <pod-name>

# Check operator logs
kubectl logs -n keycloak-operator-system <pod-name>
```

**Solutions:**

**Image Pull Failure:**
```bash
# Check imagePullSecrets configured
kubectl get deployment -n keycloak-operator-system keycloak-operator -o yaml | grep imagePullSecrets

# Verify image exists and is accessible
kubectl run test-pull --image=<operator-image> --restart=Never -n keycloak-operator-system
kubectl delete pod test-pull -n keycloak-operator-system
```

**RBAC Issues:**
```bash
# Verify ClusterRole exists
kubectl get clusterrole keycloak-operator

# Verify ClusterRoleBinding exists
kubectl get clusterrolebinding keycloak-operator

# Test operator service account permissions
kubectl auth can-i get keycloaks \
  --as=system:serviceaccount:keycloak-operator-system:keycloak-operator
```

**Resource Constraints:**
```bash
# Check node resources
kubectl top nodes

# Increase operator resources
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set resources.requests.cpu=200m \
  --set resources.requests.memory=512Mi
```

---

### Symptom: Operator Crashes or Restarts Frequently

**Possible Causes:**
- Memory pressure (OOMKilled)
- Unhandled exceptions
- Rate limiting issues
- Too many reconciliation loops

**Diagnosis:**

```bash
# Check restart count
kubectl get pods -n keycloak-operator-system

# Check for OOMKilled
kubectl describe pod -n keycloak-operator-system <pod-name> | grep -A5 "Last State"

# Check logs before crash
kubectl logs -n keycloak-operator-system <pod-name> --previous

# Check memory usage
kubectl top pod -n keycloak-operator-system
```

**Solutions:**

**OOMKilled:**
```bash
# Increase memory limits
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set resources.limits.memory=1Gi
```

**Reconciliation Loops:**
```bash
# Check for stuck resources
kubectl get keycloaks,keycloakrealms,keycloakclients --all-namespaces \
  | grep -v Ready

# Check operator logs for specific resource
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "namespace/resource-name"
```

**Rate Limiting:**
```bash
# Check rate limit metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep rate_limit

# Increase rate limits if needed
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set env.KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS=100
```

---

### Symptom: Operator Not Reconciling Resources

**Possible Causes:**
- Operator not watching the namespace
- Resource validation failures
- API server connectivity issues
- Rate limiting

**Diagnosis:**

```bash
# Check if operator sees the resource
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "namespace/resource-name"

# Check resource status
kubectl describe keycloakrealm <name> -n <namespace>

# Check for validation errors
kubectl get keycloakrealm <name> -n <namespace> -o yaml | grep -A10 status
```

**Solutions:**

**Operator Not Watching Namespace:**
```bash
# Verify operator is cluster-scoped (watches all namespaces)
kubectl get clusterrole keycloak-operator -o yaml | grep namespaces

# Restart operator to pick up new namespaces
kubectl rollout restart deployment/keycloak-operator -n keycloak-operator-system
```

**Validation Failures:**
```bash
# Check resource against schema
kubectl get keycloakrealm <name> -n <namespace> -o yaml

# Fix validation issues and reapply
kubectl apply -f fixed-resource.yaml
```

---

## Keycloak Instance Issues

### Symptom: Keycloak Instance Stuck in Pending/Provisioning

**Possible Causes:**
- Database not ready
- Image pull failure
- Insufficient resources
- PVC not bound

**Diagnosis:**

```bash
# Check Keycloak status
kubectl describe keycloak <name> -n <namespace>

# Check Keycloak pods
kubectl get pods -n <namespace> -l app=keycloak

# Check events
kubectl get events -n <namespace> --sort-by='.lastTimestamp' | tail -20

# Check database cluster
kubectl get cluster -n <db-namespace>
```

**Solutions:**

**Database Not Ready:**
```bash
# Check database cluster status
kubectl get cluster <cluster-name> -n <db-namespace>
kubectl get pods -n <db-namespace> -l cnpg.io/cluster=<cluster-name>

# Wait for database to become ready
kubectl wait --for=condition=Ready cluster/<cluster-name> \
  -n <db-namespace> --timeout=10m
```

**Image Pull Failure:**
```bash
# Check image name/tag
kubectl get keycloak <name> -n <namespace> -o jsonpath='{.spec.image}'

# Test image pull manually
kubectl run test-keycloak --image=quay.io/keycloak/keycloak:26.0.0 \
  --restart=Never -n <namespace>
kubectl delete pod test-keycloak -n <namespace>
```

**Insufficient Resources:**
```bash
# Check node resources
kubectl top nodes

# Check resource requests
kubectl get keycloak <name> -n <namespace> -o yaml | grep -A5 resources

# Reduce resource requests temporarily
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  resources:
    requests:
      cpu: 250m
      memory: 512Mi
'
```

---

### Symptom: Keycloak Pods CrashLoopBackOff

**Possible Causes:**
- Database connection failure
- Invalid configuration
- Port conflicts
- Health check failures

**Diagnosis:**

```bash
# Check pod logs
kubectl logs -n <namespace> <keycloak-pod> --tail=100

# Check previous container logs
kubectl logs -n <namespace> <keycloak-pod> --previous

# Check liveness/readiness probes
kubectl describe pod -n <namespace> <keycloak-pod> | grep -A5 "Liveness\|Readiness"
```

**Solutions:**

**Database Connection Failure:**
```bash
# Verify database credentials secret exists
kubectl get secret <db-credentials-secret> -n <db-namespace>

# Test database connection from pod
kubectl exec -it -n <namespace> <keycloak-pod> -- \
  psql -h <db-host> -U <db-user> -d keycloak -c "SELECT 1;"

# Check database credentials are correct
kubectl get secret <db-credentials-secret> -n <db-namespace> \
  -o jsonpath='{.data.username}' | base64 -d && echo
```

**Port 9000 Not Available (Keycloak < 25.0.0):**
```bash
# Check Keycloak version
kubectl get keycloak <name> -n <namespace> \
  -o jsonpath='{.spec.image.tag}'

# Keycloak requires version 25.0.0+ for management port 9000
# Upgrade to supported version:
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  image:
    tag: "26.0.0"
'
```

**Health Check Too Aggressive:**
```bash
# Increase probe delays
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  probes:
    liveness:
      initialDelaySeconds: 180
      periodSeconds: 30
    readiness:
      initialDelaySeconds: 120
      periodSeconds: 10
'
```

---

### Symptom: Need to Verify Keycloak Internal State

**Important:** You should **never** need to access the Keycloak admin console. All configuration and verification should be done through CRDs and Kubernetes-native tools.

**Preferred Verification Methods:**

```bash
# Check Keycloak instance status
kubectl get keycloak <name> -n <namespace>
kubectl describe keycloak <name> -n <namespace>

# Check all managed resources
kubectl get keycloakrealm,keycloakclient -n <namespace>

# View detailed realm configuration
kubectl get keycloakrealm <name> -n <namespace> -o yaml

# Check operator reconciliation logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=100
```

**Advanced Debugging (Operator Developers Only):**

If CRD status fields are insufficient and you need to query Keycloak's internal state directly:

```bash
# Port-forward to management API (port 9000, NOT UI)
kubectl port-forward svc/<keycloak-service> -n <namespace> 9000:9000

# Get admin credentials
ADMIN_USER=$(kubectl get secret <name>-admin-credentials -n <namespace> \
  -o jsonpath='{.data.username}' | base64 -d)
ADMIN_PASS=$(kubectl get secret <name>-admin-credentials -n <namespace> \
  -o jsonpath='{.data.password}' | base64 -d)

# Get access token
TOKEN=$(curl -s -X POST http://localhost:9000/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

# Query Keycloak API (example: get realm)
curl -s http://localhost:9000/admin/realms/<realm-name> \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Note:** The admin console UI (port 8080) is intentionally not exposed. This operator enforces least privilege - all configuration must be done through GitOps/CRDs.

---

## Realm Issues

### Symptom: Realm Stuck in Pending/Provisioning

**Possible Causes:**
- Authorization token invalid
- Keycloak instance not ready
- API connectivity issues
- Rate limiting

**Diagnosis:**

```bash
# Check realm status
kubectl describe keycloakrealm <name> -n <namespace>

# Check authorization secret exists
kubectl get secret <auth-secret-name> -n <namespace>

# Check Keycloak instance status
kubectl get keycloak -n <keycloak-namespace>

# Check operator logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "keycloakrealm/<name>"
```

**Solutions:**

**Authorization Token Missing:**
```bash
# Verify secret exists
kubectl get secret <auth-secret-name> -n <namespace>

# For first realm (admission token):
kubectl get secret admission-token-<namespace> -n <namespace>

# For subsequent realms (operational token):
kubectl get secret <namespace>-operator-token -n <namespace>

# Check secret has correct labels
kubectl get secret <auth-secret-name> -n <namespace> -o yaml | grep -A3 labels
```

**Keycloak Instance Not Ready:**
```bash
# Wait for Keycloak to become ready
kubectl wait --for=condition=Ready keycloak/<name> \
  -n <keycloak-namespace> --timeout=5m

# Check Keycloak pods
kubectl get pods -n <keycloak-namespace> -l app=keycloak
```

**API Connectivity:**
```bash
# Test connectivity from operator to Keycloak
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -v http://keycloak-keycloak.<keycloak-namespace>.svc:8080/health

# Check network policies
kubectl get networkpolicy -n <keycloak-namespace>
```

---

### Symptom: Realm Authorization Failed

**Possible Causes:**
- Token mismatch
- Token expired
- Wrong secret referenced
- Token not in metadata ConfigMap

**Diagnosis:**

```bash
# Check realm status for authorization error
kubectl describe keycloakrealm <name> -n <namespace> | grep -i authorization

# Check which secret realm is using
kubectl get keycloakrealm <name> -n <namespace> \
  # Authorization no longer uses tokens

# Verify secret exists
kubectl get secret <secret-name> -n <namespace>

# Check token in ConfigMap
TOKEN=$(kubectl get secret <secret-name> -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d)
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml | grep "$TOKEN_HASH"
```

**Solutions:**

**Using Wrong Token:**
```bash
# First realm should use admission token OR operational token
# Subsequent realms should use operational token

# Update realm to use operational token
kubectl patch keycloakrealm <name> -n <namespace> --type=merge -p '
spec:
  operatorRef:
      key: token
'
```

**Token Expired (Grace Period Ended):**
```bash
# Check token expiry
kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.metadata.annotations.vriesdemichael\.github\.io/valid-until}'

# Check if during grace period
kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.data}' | jq 'keys'
# During grace: ["token", "token-previous"]
# After grace: ["token"]

# If after grace period, ensure using "token" key (not "token-previous")
kubectl get keycloakrealm <name> -n <namespace> \
  # Authorization no longer uses tokens
# Should be "token"
```

**Bootstrap Not Completed:**
```bash
# Check if operational token was created
kubectl get secret <namespace>-operator-token -n <namespace>

# If missing, re-apply first realm with admission token
# This should trigger bootstrap and create operational token
```

---

### Symptom: Realm Configuration Not Applied

**Possible Causes:**
- Drift detection disabled
- Manual changes in Keycloak admin console
- Reconciliation not triggered
- Invalid configuration values

**Diagnosis:**

```bash
# Check realm status
kubectl get keycloakrealm <name> -n <namespace> -o yaml | grep -A20 status

# Check if drift detected
kubectl describe keycloakrealm <name> -n <namespace> | grep -i drift

# Compare CRD config to Keycloak
# (Requires admin access to Keycloak)

# Check operator logs for reconciliation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "keycloakrealm/<namespace>/<name>"
```

**Solutions:**

**Force Reconciliation:**
```bash
# Add/update annotation to trigger reconciliation
kubectl annotate keycloakrealm <name> -n <namespace> \
  reconcile=$(date +%s) --overwrite

# Watch reconciliation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator -f \
  | grep "keycloakrealm/<namespace>/<name>"
```

**Drift Detection:**
```bash
# Check if drift detection is enabled (check operator config)
kubectl get deployment -n keycloak-operator-system keycloak-operator \
  -o yaml | grep DRIFT_DETECTION

# Drift detection automatically corrects manual changes
# Manual changes in admin console will be reverted on next reconciliation
```

---

## Client Issues

### Symptom: Client Creation Fails

**Possible Causes:**
- Realm not ready
- Realm authorization token invalid
- Invalid client configuration
- Client ID already exists

**Diagnosis:**

```bash
# Check client status
kubectl describe keycloakclient <name> -n <namespace>

# Check realm is Ready
kubectl get keycloakrealm <realm-name> -n <namespace>

# Check realm authorization secret exists
kubectl get secret <realm-name>-realm-auth -n <namespace>

# Check operator logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "keycloakclient/<namespace>/<name>"
```

**Solutions:**

**Realm Not Ready:**
```bash
# Wait for realm
kubectl wait --for=condition=Ready keycloakrealm/<realm-name> \
  -n <namespace> --timeout=2m
```

**Realm Token Missing:**
```bash
# Realm token should be auto-created when realm becomes Ready
kubectl get secret <realm-name>-realm-auth -n <namespace>

# If missing, check realm status
kubectl describe keycloakrealm <realm-name> -n <namespace>

# Force realm reconciliation to generate token
kubectl annotate keycloakrealm <realm-name> -n <namespace> \
  reconcile=$(date +%s) --overwrite
```

**Invalid Configuration:**
```bash
# Check client spec for validation errors
kubectl get keycloakclient <name> -n <namespace> -o yaml

# Common issues:
# - Invalid redirect URIs
# - Missing required fields for client type
# - Invalid protocol mapper configuration

# Fix and reapply
kubectl apply -f fixed-client.yaml
```

---

### Symptom: Client Credentials Not Created

**Possible Causes:**
- Client not Ready
- Secret name conflict
- RBAC issues preventing secret creation

**Diagnosis:**

```bash
# Check client status
kubectl get keycloakclient <name> -n <namespace>

# Check if credentials secret exists
kubectl get secret <name>-credentials -n <namespace>

# Check operator logs for secret creation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "secret/<namespace>/<name>-credentials"
```

**Solutions:**

**Wait for Client to become Ready:**
```bash
kubectl wait --for=condition=Ready keycloakclient/<name> \
  -n <namespace> --timeout=2m

# Secret is created when client transitions to Ready
```

**Secret Name Conflict:**
```bash
# Check if secret already exists (from previous client)
kubectl get secret <name>-credentials -n <namespace>

# Delete old secret if safe to do so
kubectl delete secret <name>-credentials -n <namespace>

# Force client reconciliation
kubectl annotate keycloakclient <name> -n <namespace> \
  reconcile=$(date +%s) --overwrite
```

---

## Token & Authorization Issues

### Symptom: Bootstrap Not Working (No Operational Token Created)

**Possible Causes:**
- Admission token not found
- Admission token not in metadata ConfigMap
- Admission token already used
- Labels missing on admission token secret

**Diagnosis:**

```bash
# Check if admission token exists
kubectl get secret admission-token-<namespace> -n <namespace>

# Check labels on admission token
kubectl get secret admission-token-<namespace> -n <namespace> \
  -o yaml | grep -A5 labels

# Check token in metadata ConfigMap
TOKEN=$(kubectl get secret admission-token-<namespace> -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d)
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | jq --arg hash "$TOKEN_HASH" '.data[$hash]'

# Check operator logs for bootstrap
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep -i "bootstrap\|admission"
```

**Solutions:**

**Admission Token Missing Required Labels:**
```bash
# Add required labels
kubectl label secret admission-token-<namespace> \
  vriesdemichael.github.io/token-type=admission \
  vriesdemichael.github.io/allow-operator-read=true \
  --namespace=<namespace> --overwrite
```

**Admission Token Not in ConfigMap:**
```bash
# Re-create token metadata entry
ADMISSION_TOKEN=$(kubectl get secret admission-token-<namespace> -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d)
TOKEN_HASH=$(echo -n "$ADMISSION_TOKEN" | sha256sum | cut -d' ' -f1)

kubectl patch configmap keycloak-operator-token-metadata \
  --namespace=keycloak-operator-system \
  --type=merge \
  --patch "{
    \"data\": {
      \"$TOKEN_HASH\": \"{\\\"namespace\\\": \\\"<namespace>\\\", \\\"token_type\\\": \\\"admission\\\", \\\"token_hash\\\": \\\"$TOKEN_HASH\\\", \\\"issued_at\\\": \\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"valid_until\\\": \\\"$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"version\\\": 1, \\\"created_by_realm\\\": null, \\\"revoked\\\": false}\"
    }
  }"
```

**Force Bootstrap:**
```bash
# Delete first realm and recreate
kubectl delete keycloakrealm <first-realm> -n <namespace>
kubectl apply -f first-realm.yaml

# Watch for operational token creation
kubectl get secret -n <namespace> -w | grep operator-token
```

---

### Symptom: Token Rotation Not Happening

**Possible Causes:**
- Timer handler not running
- Token not expiring soon (> 7 days)
- ConfigMap update permissions missing
- Operator crashes during rotation

**Diagnosis:**

```bash
# Check token expiry date
kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.metadata.annotations.vriesdemichael\.github\.io/valid-until}'

# Calculate days until expiry
VALID_UNTIL=$(kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.metadata.annotations.vriesdemichael\.github\.io/valid-until}')
echo "Token expires: $VALID_UNTIL"
echo "Current time:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Check operator logs for rotation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep -i "rotation\|timer"

# Check rotation metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep token_rotation
```

**Solutions:**

**Rotation Not Due Yet:**
```bash
# Rotation happens automatically 7 days before expiry
# If > 7 days remaining, rotation won't trigger
# Manual rotation not recommended - wait for automatic rotation
```

**Operator Not Running Timer Handlers:**
```bash
# Restart operator to restart timer handlers
kubectl rollout restart deployment/keycloak-operator -n keycloak-operator-system

# Watch logs for timer startup
kubectl logs -n keycloak-operator-system -l app=keycloak-operator -f \
  | grep -i "timer\|rotation"
```

**ConfigMap Permissions:**
```bash
# Verify operator can update ConfigMap
kubectl auth can-i update configmap \
  --as=system:serviceaccount:keycloak-operator-system:keycloak-operator \
  --namespace=keycloak-operator-system

# Should return "yes"
```

---

### Symptom: Authorization Failed After Token Rotation

**Possible Causes:**
- Grace period ended, realm using old token
- Realm still referencing admission token
- Token key wrong ("token-previous" instead of "token")

**Diagnosis:**

```bash
# Check which token realm is using
kubectl get keycloakrealm <name> -n <namespace> \
  # Authorization no longer uses tokens

# Check operational token status
kubectl get secret <namespace>-operator-token -n <namespace> -o yaml

# Check if grace period active
kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.data}' | jq 'keys'
# During grace: ["token", "token-previous"]
# After grace: ["token"]
```

**Solutions:**

**Update Realm to Use Operational Token:**
```bash
# Update realm to use operational token (not admission token)
kubectl patch keycloakrealm <name> -n <namespace> --type=merge -p '
spec:
  operatorRef:
      key: token
'
```

**Ensure Using "token" Key (Not "token-previous"):**
```bash
# Check key
kubectl get keycloakrealm <name> -n <namespace> \
  # Authorization no longer uses tokens

# Should be "token" (default if not specified)
# Update if using wrong key:
kubectl patch keycloakrealm <name> -n <namespace> --type=merge -p '
spec:
  operatorRef:
    authorizationSecretRef:
      key: token
'
```

---

## Database Issues

### Symptom: Database Cluster Not Starting

**Possible Causes:**
- Storage not available
- Credentials secret missing
- CNPG operator not running
- Resource constraints

**Diagnosis:**

```bash
# Check cluster status
kubectl get cluster <name> -n <namespace>

# Check cluster events
kubectl describe cluster <name> -n <namespace>

# Check pods
kubectl get pods -n <namespace> -l cnpg.io/cluster=<name>

# Check CNPG operator
kubectl get pods -n cnpg-system
```

**Solutions:**

**Storage Issues:**
```bash
# Check PVCs
kubectl get pvc -n <namespace>

# Check StorageClass
kubectl get storageclass

# Ensure StorageClass exists and is default
kubectl patch storageclass <name> \
  -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

**Credentials Secret Missing:**
```bash
# Check secret exists
kubectl get secret <credentials-secret> -n <namespace>

# Recreate if missing
kubectl create secret generic <credentials-secret> \
  --from-literal=username=keycloak \
  --from-literal=password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --namespace=<namespace>
```

---

### Symptom: Database Connection Refused

**Possible Causes:**
- Database pods not ready
- Wrong database host/port
- Network policies blocking traffic
- Credentials incorrect

**Diagnosis:**

```bash
# Check database pods
kubectl get pods -n <db-namespace> -l cnpg.io/cluster=<cluster-name>

# Identify primary pod
kubectl get cluster <cluster-name> -n <db-namespace> \
  -o jsonpath='{.status.currentPrimary}'

# Test connection from Keycloak pod
kubectl exec -it -n <keycloak-namespace> <keycloak-pod> -- \
  psql -h <cluster-name>-rw.<db-namespace>.svc -U keycloak -d keycloak -c "SELECT 1;"
```

**Solutions:**

**Database Not Ready:**
```bash
# Wait for database
kubectl wait --for=condition=Ready cluster/<cluster-name> \
  -n <db-namespace> --timeout=5m
```

**Wrong Connection String:**
```bash
# Correct format for CNPG:
# Host: <cluster-name>-rw.<namespace>.svc
# Port: 5432
# Database: keycloak

# Update Keycloak resource with correct database config
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  database:
    type: cnpg
    cluster: <cluster-name>
    namespace: <db-namespace>
'
```

---

## Networking & Ingress Issues

### Symptom: Cannot Access Keycloak via Ingress

**Possible Causes:**
- Ingress not created
- DNS not configured
- TLS certificate not ready
- Ingress controller not working

**Diagnosis:**

```bash
# Check ingress exists
kubectl get ingress -n <namespace>

# Check ingress details
kubectl describe ingress <name> -n <namespace>

# Check ingress controller
kubectl get pods -n ingress-nginx

# Test DNS resolution
nslookup <hostname>

# Check certificate
kubectl get certificate -n <namespace>
```

**Solutions:**

**DNS Not Configured:**
```bash
# Get ingress external IP
kubectl get svc -n ingress-nginx ingress-nginx-controller

# Configure DNS A record:
# <hostname> → <external-ip>

# Verify DNS propagation
nslookup <hostname>
```

**TLS Certificate Not Ready:**
```bash
# Check certificate status
kubectl describe certificate <name>-tls -n <namespace>

# Check cert-manager logs
kubectl logs -n cert-manager -l app=cert-manager

# Force certificate renewal
kubectl delete certificaterequest -n <namespace> --all
```

**Ingress Not Created:**
```bash
# Enable ingress in Keycloak resource
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  ingress:
    enabled: true
    className: nginx
    hostname: keycloak.example.com
'
```

---

### Symptom: Port-Forward Not Working

**Possible Causes:**
- Service not found
- Pods not ready
- kubectl not configured correctly
- Port already in use

**Diagnosis:**

```bash
# Check service exists
kubectl get svc -n <namespace>

# Check pods are running
kubectl get pods -n <namespace>

# Check port not already in use
lsof -i :8080  # On macOS/Linux
netstat -ano | findstr :8080  # On Windows
```

**Solutions:**

**Use Different Local Port:**
```bash
# Use different local port
kubectl port-forward svc/<service-name> -n <namespace> 8888:8080

# Access at http://localhost:8888
```

**Port-Forward to Pod Directly:**
```bash
# If service not working, port-forward to pod
kubectl port-forward -n <namespace> <pod-name> 8080:8080
```

---

## Performance Issues

### Symptom: Slow Reconciliation

**Possible Causes:**
- Rate limiting too aggressive
- High API latency
- Resource constraints on operator
- Large number of resources

**Diagnosis:**

```bash
# Check rate limit metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep rate_limit

# Check operator resource usage
kubectl top pod -n keycloak-operator-system

# Check reconciliation metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep reconcile
```

**Solutions:**

**Increase Rate Limits:**
```bash
# Increase global and namespace rate limits
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set env.KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS=100 \
  --set env.KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS=10
```

**Increase Operator Resources:**
```bash
# Increase CPU/memory for operator
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=512Mi
```

---

### Symptom: High Memory Usage

**Possible Causes:**
- Memory leak in operator
- Too many reconciliation loops
- Large resource specifications
- Not enough replicas

**Diagnosis:**

```bash
# Check memory usage
kubectl top pod -n keycloak-operator-system

# Check for OOMKills
kubectl describe pod -n keycloak-operator-system <pod-name> | grep -i oom

# Check operator logs for memory errors
kubectl logs -n keycloak-operator-system <pod-name> | grep -i memory
```

**Solutions:**

**Increase Memory Limits:**
```bash
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set resources.limits.memory=1Gi
```

**Scale Operator Replicas:**
```bash
# Distribute load across multiple replicas
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --set replicas=3
```

---

## Common Pitfalls

### Pitfall 1: Using Operator Token in Production

**Problem**: Using the operator token (created at operator startup) for all realms instead of multi-tenant admission/operational token flow.

**Impact**:
- No token rotation
- All teams share one token
- Token compromise affects all realms

**Solution**: Use multi-tenant token flow:
1. Platform team creates admission token per namespace
2. First realm uses admission token → generates operational token
3. Subsequent realms use operational token
4. Tokens rotate automatically every 90 days

See: [Multi-Tenant Guide](../how-to/multi-tenant.md)

---

### Pitfall 2: Wrong Keycloak Version (< 25.0.0)

**Problem**: Using Keycloak version < 25.0.0 which doesn't support management port 9000.

**Impact**: Health checks fail, pods crash

**Solution**: Upgrade to Keycloak 25.0.0+:
```bash
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  image:
    tag: "26.0.0"
'
```

---

### Pitfall 3: Forgetting to Bootstrap Namespace

**Problem**: Creating realms without first creating admission token and bootstrapping.

**Impact**: Realm creation fails with authorization error

**Solution**: Follow bootstrap process:
1. Platform team creates admission token
2. Create first realm with admission token
3. Operational token generated automatically
4. Create subsequent realms

---

### Pitfall 4: Manual Changes in Keycloak Admin Console

**Problem**: Making configuration changes directly in Keycloak admin console instead of updating CRDs.

**Impact**: Changes reverted on next reconciliation (drift detection)

**Solution**: Always update CRDs, not admin console:
```bash
kubectl edit keycloakrealm <name> -n <namespace>
# Changes apply automatically via reconciliation
```

---

### Pitfall 5: Port 8080 vs Port 9000 Confusion

**Problem**: Trying to access management endpoints on port 8080 or user endpoints on port 9000.

**Ports**:
- **8080**: User-facing (realms, OAuth2, admin console)
- **9000**: Management only (health checks, metrics) - internal use

**Solution**: Always use port 8080 for user/admin access:
```bash
kubectl port-forward svc/<keycloak-service> -n <namespace> 8080:8080
```

---

### Pitfall 6: RBAC in Multi-Namespace Setup

**Problem**: Not configuring RBAC for application teams to read authorization secrets.

**Impact**: Teams can't create realms/clients

**Solution**: Create Role allowing secret read access:
```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-realm-manager
  namespace: <team-namespace>
rules:
  - apiGroups: ["vriesdemichael.github.io"]
    resources: ["keycloakrealms", "keycloakclients"]
    verbs: ["create", "update", "patch", "delete", "get", "list", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["<namespace>-operator-token", "*-realm-auth"]
    verbs: ["get"]
EOF
```

---

## Getting Help

If you've tried the solutions above and still have issues:

1. **Check Operator Logs**:
   ```bash
   kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=200
   ```

2. **Gather Diagnostics**:
   ```bash
   kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml > diagnostics.yaml
   kubectl get events --all-namespaces --sort-by='.lastTimestamp' > events.txt
   ```

3. **Report Issue**:
   - [GitHub Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
   - Include operator logs, resource YAML, and error messages

4. **Community Support**:
   - [GitHub Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)

---

## See Also

**Problem-Specific Guides:**

- [Security Model](../security.md) - Authorization and access control
- [Migration Guide](migration.md) - Troubleshooting migration from official Keycloak operator
- [FAQ: Troubleshooting](../faq.md#troubleshooting) - Quick answers to frequent problems

**Configuration Reference:**

- [Keycloak CRD Reference](../reference/keycloak-crd.md) - Valid configuration for Keycloak instances
- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md) - Valid realm configurations
- [KeycloakClient CRD Reference](../reference/keycloak-client-crd.md) - Valid client configurations

**Setup Guides:**

- [End-to-End Setup](../how-to/end-to-end-setup.md) - Complete production deployment walkthrough
- [Database Setup](../how-to/database-setup.md) - PostgreSQL configuration and troubleshooting
- [High Availability Deployment](../how-to/ha-deployment.md) - HA-specific troubleshooting
- [Multi-Tenant Setup](../how-to/multi-tenant.md) - Multi-tenant configuration issues

**Architecture:**

- [Architecture Overview](../architecture.md) - Understanding reconciliation flow and token system
- [Security Model](../security.md) - Authorization model and token types
- [Observability](../observability.md) - Metrics and monitoring for proactive issue detection

---

## Related Documentation

- [End-to-End Setup Guide](../how-to/end-to-end-setup.md)
- [Multi-Tenant Configuration](../how-to/multi-tenant.md)
- [Security Model](../security.md)
- [FAQ](../faq.md)
