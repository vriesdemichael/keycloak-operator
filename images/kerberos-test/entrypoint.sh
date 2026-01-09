#!/bin/bash
set -e

REALM="${KRB5_REALM:-EXAMPLE.ORG}"
KDC_HOSTNAME="${KDC_HOSTNAME:-kerberos}"
MASTER_PASSWORD="${KDC_MASTER_PASSWORD:-masterpassword}"
ADMIN_PASSWORD="${KDC_ADMIN_PASSWORD:-admin}"
KEYCLOAK_SERVICE_HOST="${KEYCLOAK_SERVICE_HOST:-keycloak.keycloak-test-system.svc.cluster.local}"

echo "=== MIT Kerberos KDC for Testing ==="
echo "Realm: $REALM"
echo "KDC Hostname: $KDC_HOSTNAME"
echo "Keycloak Service Host: $KEYCLOAK_SERVICE_HOST"

# Generate krb5.conf
cat > /etc/krb5.conf << EOF
[libdefaults]
  default_realm = $REALM
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  renew_lifetime = 7d
  forwardable = true
  rdns = false

[realms]
  $REALM = {
    kdc = $KDC_HOSTNAME
    admin_server = $KDC_HOSTNAME
  }

[domain_realm]
  .example.org = $REALM
  example.org = $REALM
EOF

# Generate kdc.conf
cat > /var/lib/krb5kdc/kdc.conf << EOF
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88

[realms]
  $REALM = {
    database_name = /var/lib/krb5kdc/principal
    admin_keytab = FILE:/var/lib/krb5kdc/kadm5.keytab
    acl_file = /var/lib/krb5kdc/kadm5.acl
    key_stash_file = /var/lib/krb5kdc/stash
    max_life = 24h 0m 0s
    max_renewable_life = 7d 0h 0m 0s
    master_key_type = aes256-cts-hmac-sha1-96
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  }

[logging]
  kdc = STDERR
  admin_server = STDERR
  default = STDERR
EOF

# Generate kadm5.acl
cat > /var/lib/krb5kdc/kadm5.acl << EOF
*/admin@$REALM    *
admin@$REALM      *
EOF

# Initialize KDC database if not exists
if [ ! -f /var/lib/krb5kdc/principal ]; then
  echo "Creating new KDC database..."

  # Create the KDC database
  kdb5_util create -s -P "$MASTER_PASSWORD" -r "$REALM"

  echo "Creating admin principal..."
  kadmin.local -q "addprinc -pw $ADMIN_PASSWORD admin@$REALM"
  kadmin.local -q "addprinc -pw $ADMIN_PASSWORD admin/admin@$REALM"

  echo "Creating test user principals..."
  kadmin.local -q "addprinc -pw alice alice@$REALM"
  kadmin.local -q "addprinc -pw bob bob@$REALM"
  kadmin.local -q "addprinc -pw charlie charlie@$REALM"

  echo "Creating HTTP service principal for Keycloak..."
  kadmin.local -q "addprinc -randkey HTTP/$KEYCLOAK_SERVICE_HOST@$REALM"
  kadmin.local -q "addprinc -randkey HTTP/localhost@$REALM"

  echo "Generating keytab for HTTP service..."
  kadmin.local -q "ktadd -k /var/lib/krb5kdc/keycloak.keytab HTTP/$KEYCLOAK_SERVICE_HOST@$REALM"
  kadmin.local -q "ktadd -k /var/lib/krb5kdc/keycloak.keytab HTTP/localhost@$REALM"

  # Make keytab readable
  chmod 644 /var/lib/krb5kdc/keycloak.keytab

  echo "=== KDC initialized successfully ==="
  echo "Keytab available at: /var/lib/krb5kdc/keycloak.keytab"
else
  echo "KDC database already exists, using existing data"
fi

echo "Starting KDC..."
exec krb5kdc -n
