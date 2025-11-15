# Example: Using extraManifests with External Secrets Operator

# This example shows how to use the new extraManifests feature to deploy
# ExternalSecrets alongside the Keycloak operator, realm, or client.

## Operator Chart - Database Password from Vault

```yaml
# values-with-eso.yaml for keycloak-operator
operator:
  replicaCount: 2
  image:
    repository: ghcr.io/vriesdemichael/keycloak-operator
    tag: "0.2.0"

keycloak:
  enabled: true
  name: keycloak
  database:
    type: postgresql
    passwordSecret:
      name: keycloak-db-password  # Will be created by ExternalSecret below
      key: password

# Deploy ExternalSecret alongside the operator
extraManifests:
  - apiVersion: external-secrets.io/v1beta1
    kind: ExternalSecret
    metadata:
      name: keycloak-db-password
      namespace: keycloak-system
    spec:
      secretStoreRef:
        name: vault-backend
        kind: SecretStore
      target:
        name: keycloak-db-password
        creationPolicy: Owner
      data:
        - secretKey: password
          remoteRef:
            key: secret/keycloak/database
            property: password
```

## Realm Chart - SMTP Password from AWS Secrets Manager

```yaml
# values-with-eso.yaml for keycloak-realm
realmName: myapp
operatorRef:
  namespace: keycloak-system

smtpServer:
  enabled: true
  host: smtp.gmail.com
  port: 587
  from: noreply@example.com
  auth: true
  user: smtp-user@example.com
  passwordSecret:
    name: smtp-password  # Will be created by ExternalSecret below
    key: password

# Deploy ExternalSecret alongside the realm
extraManifests:
  - apiVersion: external-secrets.io/v1beta1
    kind: ExternalSecret
    metadata:
      name: smtp-password
      namespace: app-namespace
    spec:
      secretStoreRef:
        name: aws-secrets
        kind: ClusterSecretStore
      target:
        name: smtp-password
      data:
        - secretKey: password
          remoteRef:
            key: /keycloak/smtp-credentials
            property: password
```

## Client Chart - SealedSecret for OAuth Credentials

```yaml
# values-with-sealed.yaml for keycloak-client
clientId: my-app
realmRef:
  name: myapp
  namespace: app-namespace

serviceAccountsEnabled: true
manageSecret: true

# Deploy SealedSecret alongside the client
extraManifests:
  - apiVersion: bitnami.com/v1alpha1
    kind: SealedSecret
    metadata:
      name: oauth-backend-config
      namespace: app-namespace
    spec:
      encryptedData:
        issuer: AgAx7f... # encrypted
        client-id: AgBy8g... # encrypted
        client-secret: AgCz9h... # encrypted
```

## Complex Example - Multiple Resources

```yaml
# values-complex.yaml
extraManifests:
  # 1. Create a PersistentVolume for backup storage
  - apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: keycloak-backup
    spec:
      capacity:
        storage: 10Gi
      accessModes:
        - ReadWriteOnce
      persistentVolumeReclaimPolicy: Retain
      storageClassName: backup
      nfs:
        server: nfs.example.com
        path: /backups/keycloak

  # 2. Create a NetworkPolicy to restrict access
  - apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: keycloak-ingress
      namespace: keycloak-system
    spec:
      podSelector:
        matchLabels:
          app.kubernetes.io/name: keycloak
      policyTypes:
        - Ingress
      ingress:
        - from:
          - namespaceSelector:
              matchLabels:
                name: ingress-nginx
          ports:
            - protocol: TCP
              port: 8080

  # 3. External Secret for admin credentials
  - apiVersion: external-secrets.io/v1beta1
    kind: ExternalSecret
    metadata:
      name: keycloak-admin-password
      namespace: keycloak-system
    spec:
      secretStoreRef:
        name: vault-backend
        kind: SecretStore
      target:
        name: keycloak-admin-password
      data:
        - secretKey: password
          remoteRef:
            key: secret/keycloak/admin
            property: password
```

## Using Templates in extraManifests

The `extraManifests` support uses Helm's `tpl` function, so you can reference chart values:

```yaml
extraManifests:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: {{ .Values.clientId }}-config
      namespace: {{ .Release.Namespace }}
      labels:
        app: {{ .Values.clientId }}
    data:
      issuer: "https://keycloak.example.com/realms/{{ .Values.realmRef.name }}"
      client-id: "{{ .Values.clientId }}"
      redirect-uri: "{{ index .Values.redirectUris 0 }}"
```

## Installation

```bash
# Install with extraManifests
helm install my-operator charts/keycloak-operator -f values-with-eso.yaml

# Verify resources were created
kubectl get externalsecrets -n keycloak-system
kubectl get secrets -n keycloak-system

# Install realm with SMTP secrets
helm install my-realm charts/keycloak-realm -f values-with-eso.yaml

# Install client with SealedSecret
helm install my-client charts/keycloak-client -f values-with-sealed.yaml
```

## Benefits

1. **Single Source of Truth**: All related resources in one values file
2. **GitOps Compatible**: Commit values files to Git, everything deploys together
3. **Flexible Secret Management**: Choose your preferred secret management solution
4. **No Manual Steps**: Everything deployed automatically with `helm install`
5. **Template Support**: Reference chart values in your extra manifests
