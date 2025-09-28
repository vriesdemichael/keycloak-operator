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
from keycloak_operator.observability.health import HealthChecker
from keycloak_operator.observability.logging import setup_structured_logging
from keycloak_operator.observability.metrics import MetricsServer

# Global reference to metrics server for cleanup
_global_metrics_server: MetricsServer | None = None


def configure_logging() -> None:
    """Configure structured logging for the operator based on environment variables."""
    log_level = os.getenv("KEYCLOAK_OPERATOR_LOG_LEVEL", "INFO").upper()
    enable_json_logging = (
        os.getenv("KEYCLOAK_OPERATOR_JSON_LOGS", "true").lower() == "true"
    )
    enable_correlation_ids = (
        os.getenv("KEYCLOAK_OPERATOR_CORRELATION_IDS", "true").lower() == "true"
    )

    setup_structured_logging(
        log_level=log_level,
        enable_json_formatting=enable_json_logging,
        correlation_id_enabled=enable_correlation_ids,
    )


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
async def startup_handler(settings: kopf.OperatorSettings, **_) -> None:
    """
    Operator startup configuration.

    This handler runs once when the operator starts up and configures
    global operator settings including:
    - Resource scanning behavior
    - Error handling policies
    - Networking settings
    - Performance tuning
    - Metrics and health check endpoints
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

    # Start metrics server for Prometheus scraping and health checks
    metrics_port = int(os.getenv("METRICS_PORT", "8080"))
    metrics_host = os.getenv("METRICS_HOST", "0.0.0.0")

    try:
        metrics_server = MetricsServer(port=metrics_port, host=metrics_host)
        await metrics_server.start()
        logging.info(
            f"Metrics and health endpoints available on {metrics_host}:{metrics_port}"
        )

        # Store server reference for cleanup in a global variable
        # since OperatorSettings doesn't support custom attributes
        global _global_metrics_server
        _global_metrics_server = metrics_server

    except Exception as e:
        logging.error(f"Failed to start metrics server: {e}")
        # Don't fail operator startup if metrics server fails
        logging.warning("Continuing without metrics server")


@kopf.on.cleanup()
async def cleanup_handler(settings: kopf.OperatorSettings, **_) -> None:
    """
    Operator cleanup handler.

    This runs when the operator is shutting down and can be used
    to perform cleanup tasks like:
    - Closing database connections
    - Cleaning up temporary resources
    - Stopping metrics server
    - Logging shutdown information
    """
    logging.info("Shutting down Keycloak Operator...")

    # Stop metrics server if it was started
    global _global_metrics_server
    if _global_metrics_server:
        try:
            await _global_metrics_server.stop()
            logging.info("Metrics server stopped")
        except Exception as e:
            logging.error(f"Error stopping metrics server: {e}")


@kopf.on.probe(id="healthz")
async def health_check(**_) -> dict[str, str]:
    """
    Health check probe for Kubernetes liveness/readiness checks.

    Returns:
        Dictionary indicating operator health status
    """
    try:
        health_checker = HealthChecker()
        health_results = await health_checker.check_all()
        overall_health = health_checker.get_overall_health(health_results)

        timestamp = "unknown"
        if health_results and "kubernetes_api" in health_results:
            k8s_result = health_results["kubernetes_api"]
            if hasattr(k8s_result, "timestamp") and k8s_result.timestamp is not None:
                timestamp = str(k8s_result.timestamp)

        return {
            "status": overall_health,
            "operator": "keycloak-operator",
            "timestamp": timestamp,
        }
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "operator": "keycloak-operator", "error": str(e)}


@kopf.on.probe(id="ready")
async def readiness_check(**_) -> dict[str, str]:
    """
    Readiness check probe - indicates if operator is ready to handle requests.

    Returns:
        Dictionary indicating operator readiness
    """
    try:
        health_checker = HealthChecker()
        # For readiness, we only check essential components
        results = {}
        results["kubernetes_api"] = await health_checker._check_kubernetes_api()
        results["crds_installed"] = await health_checker._check_crds_installed()

        # Consider ready if K8s API and CRDs are healthy
        api_healthy = results["kubernetes_api"].status == "healthy"
        crds_healthy = results["crds_installed"].status == "healthy"

        if api_healthy and crds_healthy:
            return {"status": "ready", "operator": "keycloak-operator"}
        else:
            return {"status": "not_ready", "operator": "keycloak-operator"}

    except Exception as e:
        logging.error(f"Readiness check failed: {e}")
        return {"status": "not_ready", "operator": "keycloak-operator", "error": str(e)}


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
