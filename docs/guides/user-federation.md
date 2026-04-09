# User Federation Guide

This guide covers LDAP, Active Directory, and Kerberos-backed user federation for `KeycloakRealm` resources.

Use the `keycloak-realm` Helm chart as the main entry point. Raw `KeycloakRealm` manifests are still supported, but they are the advanced path.

## Overview

The realm chart exposes user federation through the top-level `userFederation` values key, which maps directly into `spec.userFederation` on the generated realm CR.

```yaml
# values.yaml for charts/keycloak-realm
userFederation:
  - name: corporate-ldap
    providerId: ldap
    connectionUrl: ldap://ldap.example.com:389
    bindDn: cn=readonly,dc=example,dc=com
    bindCredentialSecret:
      name: ldap-credentials
      key: password
    usersDn: ou=People,dc=example,dc=com
    vendor: other
    usernameLdapAttribute: uid
    uuidLdapAttribute: entryUUID
    userObjectClasses:
      - inetOrgPerson
      - organizationalPerson
    editMode: READ_ONLY
    syncSettings:
      importEnabled: true
      fullSyncPeriod: 86400
      changedUsersSyncPeriod: 3600
```

The values intentionally mirror the CR field names, so the same camelCase keys appear in Helm values and in `spec.userFederation`.

## Secret Requirements

Referenced secrets such as `bindCredentialSecret` and `keytabSecret` must:

- live in the same namespace as the `KeycloakRealm`
- include the label `vriesdemichael.github.io/keycloak-allow-operator-read: "true"`

Example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-credentials
  namespace: my-namespace
  labels:
    vriesdemichael.github.io/keycloak-allow-operator-read: "true"
stringData:
  password: your-ldap-password
```

## Using Helm

### Basic LDAP Federation

```yaml
userFederation:
  - name: corporate-ldap
    providerId: ldap
    enabled: true
    connectionUrl: ldap://ldap.example.com:389
    startTls: true
    bindDn: cn=readonly,dc=example,dc=com
    bindCredentialSecret:
      name: ldap-credentials
      key: password
    usersDn: ou=People,dc=example,dc=com
    vendor: other
    usernameLdapAttribute: uid
    uuidLdapAttribute: entryUUID
    userObjectClasses:
      - inetOrgPerson
      - organizationalPerson
    editMode: READ_ONLY
    syncSettings:
      importEnabled: true
      fullSyncPeriod: 86400
      changedUsersSyncPeriod: 3600
      syncRegistrations: false
```

### Active Directory

```yaml
userFederation:
  - name: corporate-ad
    providerId: ldap
    enabled: true
    connectionUrl: ldaps://dc.corp.example.com:636
    startTls: false
    bindDn: CN=Keycloak Service,OU=ServiceAccounts,DC=corp,DC=example,DC=com
    bindCredentialSecret:
      name: ad-credentials
      key: password
    usersDn: OU=Users,DC=corp,DC=example,DC=com
    vendor: ad
    usernameLdapAttribute: sAMAccountName
    uuidLdapAttribute: objectGUID
    rdnLdapAttribute: cn
    userObjectClasses:
      - user
      - organizationalPerson
    trustEmail: true
    editMode: READ_ONLY
    mappers:
      - name: upn-mapper
        mapperType: user-attribute-ldap-mapper
        config:
          ldap.attribute: userPrincipalName
          user.model.attribute: username
          read.only: "true"
```

### LDAP with Kerberos

```yaml
userFederation:
  - name: kerberos-ldap
    providerId: ldap
    enabled: true
    connectionUrl: ldap://ldap.example.com:389
    bindDn: cn=readonly,dc=example,dc=com
    bindCredentialSecret:
      name: ldap-credentials
      key: password
    usersDn: ou=People,dc=example,dc=com
    vendor: other
    allowKerberosAuthentication: true
    kerberosRealm: EXAMPLE.COM
    serverPrincipal: HTTP/keycloak.example.com@EXAMPLE.COM
    keytabSecret:
      name: kerberos-keytab
      key: keytab
    useKerberosForPasswordAuthentication: false
    debug: false
```

## LDAP Security Choices

Use one of these patterns:

- Port `389` with `startTls: true` when the directory starts plaintext and upgrades to TLS.
- Port `636` with `ldaps://...` and `startTls: false` when the directory expects implicit TLS from the start.

Also review `useTruststoreSpi` if your environment requires custom CA trust behavior.

## Common Mappers

User federation mappers live under `userFederation[].mappers` and use the `mapperType` field.

```yaml
userFederation:
  - name: corporate-ldap
    providerId: ldap
    mappers:
      - name: email-mapper
        mapperType: user-attribute-ldap-mapper
        config:
          ldap.attribute: mail
          user.model.attribute: email
          read.only: "true"
      - name: group-mapper
        mapperType: group-ldap-mapper
        config:
          groups.dn: ou=Groups,dc=example,dc=com
          group.name.ldap.attribute: cn
          membership.ldap.attribute: member
          membership.user.ldap.attribute: dn
          mode: READ_ONLY
```

## Kerberos Field Semantics

- `allowKerberosAuthentication`: enables Kerberos/SPNEGO as an authentication option.
- `useKerberosForPasswordAuthentication`: sends password authentication through Kerberos instead of standard LDAP bind behavior.

Set the second field only when your directory and realm design specifically require password auth through Kerberos.

## Status and Metrics

Realm status includes `userFederationStatus` entries with fields such as:

- `name`
- `providerId`
- `connected`
- `lastConnectionTest`
- `lastSyncResult`
- `lastFullSync`
- `lastChangedSync`
- `usersImported`
- `groupsImported`
- `syncErrors`
- `message`

Example:

```bash
kubectl get keycloakrealm my-realm -n my-namespace -o jsonpath='{.status.userFederationStatus}' | jq
```

The operator also exports:

```prometheus
keycloak_operator_user_federation_status{realm,provider_id}
```

Value `1` means connected, `0` means disconnected.

## Troubleshooting

### Bind or connection failures

- verify network reachability from Keycloak pods to the LDAP or AD server
- verify the bind DN and secret contents
- verify your TLS mode matches the port you chose

### Sync does not run

- check `syncSettings.fullSyncPeriod`
- check `syncSettings.changedUsersSyncPeriod`
- remember `-1` disables the periodic sync timer

### Secret not readable

Make sure the secret is in the same namespace as the realm and labeled for operator access.

## See Also

- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md)
- [Multi-Tenant Guide](../how-to/multi-tenant.md)
- `charts/keycloak-realm/README.md` for chart-specific values context
