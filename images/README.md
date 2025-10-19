# Container Images

This directory contains Dockerfiles for building container images used by the Keycloak Operator project.

## Directory Structure

```
images/
├── operator/           # Keycloak Operator image
│   └── Dockerfile
└── keycloak-optimized/ # Pre-optimized Keycloak image for testing
    ├── Dockerfile
    └── README.md
```

## Images

### Operator Image (`images/operator/`)

The main operator image that runs the Keycloak Operator controller.

**Build:**
```bash
make build          # Build operator:latest
make build-test     # Build and load into Kind as operator:test
```

### Optimized Keycloak Image (`images/keycloak-optimized/`)

A pre-optimized Keycloak image designed for faster startup in test and development environments.

**Build:**
```bash
make build-keycloak-optimized      # Build keycloak-optimized:test
make kind-load-keycloak-optimized  # Load into Kind cluster
```

**Performance:**
- **Default Image**: 70s+ startup time (performs build on every start)
- **Optimized Image**: ~25s startup time (pre-built with PostgreSQL support)

See [keycloak-optimized/README.md](keycloak-optimized/README.md) for detailed information.

## Building All Images

```bash
# Build all test images and load into Kind
make build-all-test
```

## Measuring Performance

Compare startup times between default and optimized images:

```bash
make measure-startup
```

This will:
1. Deploy default Keycloak image and measure startup time
2. Deploy optimized Keycloak image and measure startup time
3. Report the improvement

## License

All images are based on open-source software:
- Keycloak: Apache License 2.0
- Operator: Apache License 2.0 (this project)
