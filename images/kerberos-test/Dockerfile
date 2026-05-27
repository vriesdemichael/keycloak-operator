# MIT Kerberos KDC for integration testing
# This image provides a minimal KDC for testing Kerberos user federation in Keycloak
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# Install Kerberos packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    krb5-kdc \
    krb5-admin-server \
    krb5-user \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Create required directories
RUN mkdir -p /var/lib/krb5kdc /var/log /etc/krb5kdc

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose KDC ports
EXPOSE 88/tcp 88/udp 749/tcp

# Volume for KDC data persistence (optional)
VOLUME ["/var/lib/krb5kdc"]

ENTRYPOINT ["/entrypoint.sh"]
