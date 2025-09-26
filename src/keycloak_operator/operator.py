#!/usr/bin/env python3
"""
Keycloak Operator - Main entry point for the Kopf-based Keycloak operator.

This operator provides GitOps-compatible Keycloak management with:
- Multi-namespace operation (watches all namespaces by default)
- Dynamic client provisioning with RBAC-based authorization
- Kubernetes-native security instead of Keycloak's built-in auth
- Comprehensive secret management improvements

Usage:
    python -m keycloak_operator.operator
    # Or with kopf directly:
    kopf run keycloak_operator.operator --verbose --all-namespaces

Environment Variables:
    KEYCLOAK_OPERATOR_NAMESPACES: Comma-separated list of namespaces to watch
    KEYCLOAK_OPERATOR_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    KEYCLOAK_OPERATOR_DRY_RUN: Set to 'true' for dry-run mode
"""

import logging
import os
import sys

import kopf

# Import all handler modules to register them with kopf
# This is the standard pattern - importing modules registers their decorators
from keycloak_operator.handlers import client, keycloak, realm  # noqa: F401


def configure_logging() -> None:
    """Configure logging for the operator based on environment variables."""
    log_level = os.getenv("KEYCLOAK_OPERATOR_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Set kopf logging level to be less verbose by default
    kopf_level = "WARNING" if log_level == "INFO" else log_level
    logging.getLogger("kopf").setLevel(getattr(logging, kopf_level, logging.WARNING))


def get_watched_namespaces() -> list[str] | None:
    """
    Get the list of namespaces to watch from environment variables.

    Returns:
        List of namespace names, or None to watch all namespaces
    """
    namespaces_env = os.getenv("KEYCLOAK_OPERATOR_NAMESPACES")
    if namespaces_env:
        return [ns.strip() for ns in namespaces_env.split(",") if ns.strip()]
    return None  # Watch all namespaces by default


@kopf.on.startup()
def startup_handler(settings: kopf.OperatorSettings, **_) -> None:
    """
    Operator startup configuration.

    This handler runs once when the operator starts up and configures
    global operator settings including:
    - Resource scanning behavior
    - Error handling policies
    - Networking settings
    - Performance tuning
    """
    logging.info("Starting Keycloak Operator...")

    # Configure operator behavior
    settings.scanning.disabled = False  # Enable resource scanning
    settings.posting.enabled = True  # Enable status posting
    settings.watching.reconnect_backoff = 1.0  # Reconnect delay

    # Configure error handling - be more forgiving for temporary issues
    settings.execution.max_workers = 20  # Allow concurrent processing

    # Log configuration
    watched_namespaces = get_watched_namespaces()
    if watched_namespaces:
        logging.info(f"Watching namespaces: {', '.join(watched_namespaces)}")
    else:
        logging.info("Watching all namespaces (cluster-wide mode)")

    dry_run = os.getenv("KEYCLOAK_OPERATOR_DRY_RUN", "false").lower() == "true"
    if dry_run:
        logging.info("Running in DRY-RUN mode - no changes will be applied")


@kopf.on.cleanup()
def cleanup_handler(**_) -> None:
    """
    Operator cleanup handler.

    This runs when the operator is shutting down and can be used
    to perform cleanup tasks like:
    - Closing database connections
    - Cleaning up temporary resources
    - Logging shutdown information
    """
    logging.info("Shutting down Keycloak Operator...")


@kopf.on.probe(id="healthz")
def health_check(**_) -> dict[str, str]:
    """
    Health check probe for Kubernetes liveness/readiness checks.

    Returns:
        Dictionary indicating operator health status
    """
    return {"status": "healthy", "operator": "keycloak-operator"}


@kopf.on.probe(id="ready")
def readiness_check(**_) -> dict[str, str]:
    """
    Readiness check probe - indicates if operator is ready to handle requests.

    Returns:
        Dictionary indicating operator readiness
    """
    return {"status": "ready", "operator": "keycloak-operator"}


def main() -> None:
    """
    Main entry point for the operator.

    This function:
    1. Configures logging
    2. Determines namespace scope
    3. Runs the kopf operator with appropriate settings
    """
    configure_logging()

    # Get namespace configuration
    watched_namespaces = get_watched_namespaces()

    try:
        # Run the operator
        # Kopf will automatically discover all handlers through the imports above
        if watched_namespaces:
            # Watch specific namespaces
            kopf.run(
                namespaces=watched_namespaces,
                standalone=True,
                liveness_endpoint="http://0.0.0.0:8080/healthz",
                priority=100,
            )
        else:
            # Watch all namespaces (cluster-wide)
            kopf.run(
                clusterwide=True,
                standalone=True,
                liveness_endpoint="http://0.0.0.0:8080/healthz",
                priority=100,
            )
    except KeyboardInterrupt:
        logging.info("Received shutdown signal")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Operator failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
