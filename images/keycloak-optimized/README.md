# Optimized Keycloak Image

This directory contains a pre-optimized Keycloak container image designed for faster startup times in test, development, and production environments.

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

## Version

**Current Version**: 26.4.1 (matches upstream Keycloak)

The optimized image uses the same version tag as the upstream Keycloak image it's based on. This ensures version consistency and makes it easy to use as a drop-in replacement.

## Building the Image

### Local Build

```bash
# Build with default version (26.4.1)
task image:build-keycloak

# Build with specific version
docker build \
  --build-arg KEYCLOAK_VERSION=26.4.1 \
  -t keycloak-optimized:26.4.1 \
  -f images/keycloak-optimized/Dockerfile \
  images/keycloak-optimized/

# Load into Kind cluster
task image:load-keycloak
```

### CI/CD Build

The CI/CD pipeline automatically:
1. Checks if `ghcr.io/<your-repo>/keycloak-optimized:26.4.1` exists
2. If not, builds and publishes it
3. Reuses the published image on subsequent runs

## Usage

### In Tests (Automatic)

The test fixtures automatically use this optimized image:

```python
# In conftest.py
keycloak_image = os.getenv("KEYCLOAK_IMAGE", "keycloak-optimized:26.4.1")
```

### In Production (Helm)

```yaml
keycloak:
  image: ghcr.io/<your-repo>/keycloak-operator/keycloak-optimized
  version: "26.4.1"
```

### Direct Docker Usage

```bash
# Pull from registry
docker pull ghcr.io/<your-repo>/keycloak-operator/keycloak-optimized:26.4.1

# Run with PostgreSQL
docker run -e KC_DB_URL_HOST=postgres \
           -e KC_DB_URL_DATABASE=keycloak \
           -e KC_DB_USERNAME=keycloak \
           -e KC_DB_PASSWORD=password \
           ghcr.io/<your-repo>/keycloak-operator/keycloak-optimized:26.4.1
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

## Test Results

Full integration test suite results with optimized image:

✅ **29/29 tests PASSED** in **82 seconds** (vs 440 seconds with default image)

**Performance Improvement**: **81% faster total test execution time**

See [TEST_RESULTS.md](TEST_RESULTS.md) for detailed breakdown.
