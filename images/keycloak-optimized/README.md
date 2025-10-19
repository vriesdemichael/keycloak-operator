# Optimized Keycloak Image

This directory contains a pre-optimized Keycloak container image designed for faster startup times in test and development environments.

## Why Optimize?

The default Keycloak image performs a build step on every startup to configure:
- Database drivers
- Feature enablement (health, metrics, etc.)
- Cache configuration
- Theme compilation
- HTTP/proxy settings

This build step takes **60-80 seconds locally** and **120-180 seconds in CI**.

By pre-building an optimized image, we move this build step to container build time, reducing startup to **20-30 seconds locally** and **60-90 seconds in CI**.

## What's Pre-Configured

This optimized image includes:
- ✅ **PostgreSQL database driver** (KC_DB=postgres)
- ✅ **Health endpoints** enabled (KC_HEALTH_ENABLED=true)
- ✅ **Metrics endpoints** enabled (KC_METRICS_ENABLED=true)
- ✅ **HTTP mode** enabled for ingress TLS termination
- ✅ **Proxy headers** forwarding (X-Forwarded-*)

## What's Still Configurable at Runtime

You can still configure via environment variables:
- **Database connection**: KC_DB_URL_HOST, KC_DB_URL_PORT, KC_DB_URL_DATABASE
- **Database credentials**: KC_DB_USERNAME, KC_DB_PASSWORD (or secret references)
- **Admin credentials**: KEYCLOAK_ADMIN, KEYCLOAK_ADMIN_PASSWORD
- **Hostname**: KC_HOSTNAME, KC_HOSTNAME_STRICT
- **Logging**: KC_LOG_LEVEL

## Building the Image

```bash
# Build locally
make build-keycloak-optimized

# Load into Kind cluster
make kind-load-keycloak-optimized
```

## Usage in Tests

The test fixtures automatically use this optimized image when available:

```python
# In conftest.py
keycloak_image = os.getenv("KEYCLOAK_IMAGE", "keycloak-optimized:test")
```

## License Considerations

This image is based on the official Keycloak image from quay.io/keycloak/keycloak which is Apache 2.0 licensed.

Our Dockerfile only adds build configuration and does not modify the Keycloak source code, making it suitable for distribution under the same license.

## Performance Comparison

| Environment | Default Image | Optimized Image | Improvement |
|-------------|---------------|-----------------|-------------|
| Local (M1)  | ~70s          | ~25s            | 64% faster  |
| CI (GitHub) | ~180s         | ~75s            | 58% faster  |

*Measurements are from pod creation to readiness probe success.*
