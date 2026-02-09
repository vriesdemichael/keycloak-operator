# User Federation Guide

This guide explains how to configure LDAP, Active Directory, and Kerberos user federation with the Keycloak Operator.

## Overview

User federation allows Keycloak to authenticate users against external identity stores like LDAP directories or Active Directory. The operator supports:

- **LDAP** - Standard LDAP directories (OpenLDAP, FreeIPA, etc.)
- **Active Directory** - Microsoft Active Directory with sAMAccountName/UPN support
- **Kerberos** - SPNEGO/Kerberos authentication integrated with LDAP

## Prerequisites

1. A running Keycloak instance managed by the operator
2. Network connectivity between Keycloak pods and your LDAP/AD server
3. A bind account with read access to your directory

## Configuration

### Basic LDAP Federation

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-namespace
spec:
  realmName: my-realm
  operatorRef:
    namespace: keycloak-system

  userFederation:
    - name: corporate-ldap
      providerId: ldap
      connectionUrl: "ldap://ldap.example.com:389"
      bindDn: "cn=readonly,dc=example,dc=com"
      bindCredentialSecret:
        name: ldap-credentials
        key: password
      usersDn: "ou=People,dc=example,dc=com"
      vendor: other
      usernameLdapAttribute: uid
      uuidLdapAttribute: entryUUID
      userObjectClasses:
        - inetOrgPerson
        - organizationalPerson
      editMode: READ_ONLY
      syncSettings:
        importEnabled: true
        fullSyncPeriod: 86400  # Full sync daily
        changedUsersSyncPeriod: 3600  # Changed users sync hourly
```

### Active Directory Configuration

```yaml
userFederation:
  - name: corporate-ad
    providerId: ldap
    connectionUrl: "ldaps://dc.corp.example.com:636"
    bindDn: "CN=Keycloak Service,OU=ServiceAccounts,DC=corp,DC=example,DC=com"
    bindCredentialSecret:
      name: ad-credentials
      key: password
    usersDn: "OU=Users,DC=corp,DC=example,DC=com"
    vendor: ad  # Important: Set to 'ad' for Active Directory
    usernameLdapAttribute: sAMAccountName
    uuidLdapAttribute: objectGUID
    rdnLdapAttribute: cn
    userObjectClasses:
      - user
      - organizationalPerson
    trustEmail: true
    startTls: false  # Using LDAPS on port 636
    mappers:
      - name: upn-mapper
        mapperType: user-attribute-ldap-mapper
        config:
          ldap.attribute: userPrincipalName
          user.model.attribute: username
          read.only: "true"
```

### Kerberos/SPNEGO Authentication

For environments using Kerberos authentication:

```yaml
userFederation:
  - name: kerberos-ldap
    providerId: ldap
    connectionUrl: "ldap://ldap.example.com:389"
    bindDn: "cn=readonly,dc=example,dc=com"
    bindCredentialSecret:
      name: ldap-credentials
      key: password
    usersDn: "ou=People,dc=example,dc=com"
    vendor: other

    # Kerberos settings
    allowKerberosAuthentication: true
    kerberosRealm: EXAMPLE.COM
    serverPrincipal: HTTP/keycloak.example.com@EXAMPLE.COM
    keytabSecret:
      name: kerberos-keytab
      key: keytab
    useKerberosForPasswordAuthentication: true
    debug: false
```

## Creating Secrets

Secrets must be labeled to allow operator access:

```bash
# Create the bind credential secret
kubectl create secret generic ldap-credentials \
  --from-literal=password='your-ldap-password' \
  -n your-namespace

# Label it for operator access
kubectl label secret ldap-credentials \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n your-namespace
```

For Kerberos keytab:

```bash
# Create keytab secret from file
kubectl create secret generic kerberos-keytab \
  --from-file=keytab=/path/to/keycloak.keytab \
  -n your-namespace

kubectl label secret kerberos-keytab \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n your-namespace
```

## Federation Mappers

Mappers transform LDAP attributes to Keycloak user properties:

```yaml
mappers:
  # Map email attribute
  - name: email-mapper
    mapperType: user-attribute-ldap-mapper
    config:
      ldap.attribute: mail
      user.model.attribute: email
      read.only: "true"
      always.read.value.from.ldap: "true"
      is.mandatory.in.ldap: "false"

  # Map first name
  - name: first-name-mapper
    mapperType: user-attribute-ldap-mapper
    config:
      ldap.attribute: givenName
      user.model.attribute: firstName
      read.only: "true"

  # Map groups from LDAP
  - name: group-mapper
    mapperType: group-ldap-mapper
    config:
      groups.dn: "ou=Groups,dc=example,dc=com"
      group.name.ldap.attribute: cn
      group.object.classes: groupOfNames
      membership.ldap.attribute: member
      membership.user.ldap.attribute: dn
      mode: READ_ONLY
```

## Edit Modes

| Mode | Description |
|------|-------------|
| `READ_ONLY` | Users are imported from LDAP but cannot be modified in Keycloak |
| `WRITABLE` | Changes in Keycloak are synced back to LDAP |
| `UNSYNCED` | Users are imported but changes are stored only in Keycloak |

## Sync Settings

| Setting | Description |
|---------|-------------|
| `importEnabled` | Whether to import users from LDAP |
| `fullSyncPeriod` | Interval (seconds) for full sync, -1 to disable |
| `changedUsersSyncPeriod` | Interval for syncing changed users, -1 to disable |
| `syncRegistrations` | Sync newly registered users to LDAP (if WRITABLE) |

## Monitoring

The operator exposes Prometheus metrics for federation monitoring:

- `keycloak_operator_user_federation_status` - Connection status (1=connected)

## Status

Federation status is reported in the realm's status field:

```bash
kubectl get keycloakrealm my-realm -o jsonpath='{.status.userFederationStatus}'
```

Each provider reports:
- `connected` - Whether the connection is healthy
- `lastSyncResult` - Result of last sync (Success/Failed/Never)
- `usersImported` - Number of imported users
- `syncErrors` - Count of sync errors

## Troubleshooting

### Connection Issues

1. Verify network connectivity from Keycloak pods:
   ```bash
   kubectl exec -it deploy/keycloak -- /bin/bash -c "nc -zv ldap.example.com 389"
   ```

2. Check that the bind credentials are correct

3. For LDAPS, ensure certificates are trusted

### Sync Issues

1. Check operator logs for federation errors:
   ```bash
   kubectl logs -l app.kubernetes.io/name=keycloak-operator -f | grep federation
   ```

2. Verify the `usersDn` path exists and contains users

3. Check that `userObjectClasses` matches your LDAP schema

### Kerberos Issues

1. Verify the keytab contains the correct service principal:
   ```bash
   klist -k /path/to/keycloak.keytab
   ```

2. Ensure DNS is properly configured for Kerberos realm

3. Check that Keycloak pods can reach the KDC on port 88
