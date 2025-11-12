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
import random
import sys

import kopf
from kubernetes import config

from keycloak_operator.constants import (
    RATE_LIMIT_GLOBAL_BURST,
    RATE_LIMIT_GLOBAL_TPS,
    RATE_LIMIT_NAMESPACE_BURST,
    RATE_LIMIT_NAMESPACE_TPS,
)

# Import all handler modules to register them with kopf
# This is the standard pattern - importing modules registers their decorators
from keycloak_operator.handlers import client as client_handler  # noqa: F401
from keycloak_operator.handlers import (  # noqa: F401
    keycloak,
    realm,
)
from keycloak_operator.observability.health import HealthChecker
from keycloak_operator.observability.leader_election import (
    get_leader_election_monitor,  # noqa: F401
)
from keycloak_operator.observability.logging import setup_structured_logging
from keycloak_operator.observability.metrics import MetricsServer
from keycloak_operator.utils.rate_limiter import RateLimiter

# Import webhook modules to register admission webhooks
from keycloak_operator.webhooks import client as client_webhook  # noqa: F401
from keycloak_operator.webhooks import keycloak as keycloak_webhook  # noqa: F401
from keycloak_operator.webhooks import realm as realm_webhook  # noqa: F401

# Global reference to metrics server for cleanup
_global_metrics_server: MetricsServer | None = None

# Operator configuration
OPERATOR_NAMESPACE = os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")


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
async def startup_handler(
    settings: kopf.OperatorSettings, memo: kopf.Memo, **_
) -> None:
    """
    Operator startup configuration.

    This handler runs once when the operator starts up and configures
    global operator settings including:
    - Resource scanning behavior
    - Error handling policies
    - Networking settings
    - Performance tuning
    - Metrics and health check endpoints
    - Rate limiting for Keycloak API calls
    - Admission webhook server
    """
    logging.info("Starting Keycloak Operator...")
    # Defaults commented out - adjust as needed
    # Configure operator behavior
    # settings.scanning.disabled = False  # Enable resource scanning
    # settings.posting.enabled = True  # Enable status posting
    settings.watching.reconnect_backoff = 1.0  # Reconnect delay

    # Configure peering for leader election with random priority
    # Each pod gets a unique priority to enable leader election
    settings.peering.name = "keycloak-operator"
    settings.peering.priority = random.randint(0, 32767)
    logging.info(
        f"Peering priority set to {settings.peering.priority} for leader election"
    )

    # Configure error handling - be more forgiving for temporary issues
    settings.execution.max_workers = 20  # Allow concurrent processing

    # Configure admission webhooks
    webhook_enabled = os.getenv("ENABLE_WEBHOOKS", "true").lower() == "true"
    if webhook_enabled:
        webhook_port = int(os.getenv("WEBHOOK_PORT", "8443"))

        # Determine webhook service hostname for cert generation
        # Format: <service-name>.<namespace>.svc
        operator_namespace = os.getenv("POD_NAMESPACE", "keycloak-system")
        webhook_service_name = os.getenv(
            "WEBHOOK_SERVICE_NAME", "keycloak-operator-webhook"
        )
        webhook_host = f"{webhook_service_name}.{operator_namespace}.svc"

        settings.admission.server = kopf.WebhookServer(
            port=webhook_port,
            host=webhook_host,  # Generate cert for service DNS name
        )
        settings.admission.managed = (
            "vriesdemichael.github.io"  # Auto-manage webhook configs
        )
        logging.info(
            f"Admission webhooks ENABLED on port {webhook_port} (host: {webhook_host})"
        )
    else:
        logging.info("Admission webhooks DISABLED")

    # Log configuration
    watched_namespaces = get_watched_namespaces()
    if watched_namespaces:
        logging.info(f"Watching namespaces: {', '.join(watched_namespaces)}")
    else:
        logging.info("Watching all namespaces (cluster-wide mode)")

    dry_run = os.getenv("KEYCLOAK_OPERATOR_DRY_RUN", "false").lower() == "true"
    if dry_run:
        logging.info("Running in DRY-RUN mode - no changes will be applied")

    # Load Kubernetes configuration if not already loaded
    try:
        config.load_incluster_config()
        logging.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        try:
            config.load_kube_config()
            logging.info("Loaded kubeconfig configuration")
        except config.ConfigException:
            logging.error("Failed to load Kubernetes configuration")
            raise

    # Validate operator instance ID is configured
    operator_instance_id = os.getenv("OPERATOR_INSTANCE_ID")
    if not operator_instance_id:
        logging.error(
            "OPERATOR_INSTANCE_ID environment variable is not set. "
            "This is required for drift detection and resource ownership tracking."
        )
        raise ValueError("OPERATOR_INSTANCE_ID is required but not configured")

    logging.info(f"Operator instance ID: {operator_instance_id}")

    # Start metrics server for Prometheus scraping and health checks
    metrics_port = int(os.getenv("METRICS_PORT", "8081"))
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

    # Initialize leader election monitoring
    monitor = get_leader_election_monitor()
    logging.info(
        f"Leader election monitoring initialized for instance: {monitor.instance_id}"
    )

    # Initialize rate limiter for Keycloak API calls
    memo.rate_limiter = RateLimiter(
        global_rate=RATE_LIMIT_GLOBAL_TPS,
        global_burst=RATE_LIMIT_GLOBAL_BURST,
        namespace_rate=RATE_LIMIT_NAMESPACE_TPS,
        namespace_burst=RATE_LIMIT_NAMESPACE_BURST,
    )
    logging.info(
        f"Rate limiter initialized: "
        f"global={RATE_LIMIT_GLOBAL_TPS} TPS (burst={RATE_LIMIT_GLOBAL_BURST}), "
        f"namespace={RATE_LIMIT_NAMESPACE_TPS} TPS (burst={RATE_LIMIT_NAMESPACE_BURST})"
    )


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


# Drift detection background task
@kopf.timer(
    "keycloakrealms",  # Run as timer on any realm resource (just to trigger periodic execution)
    interval=float(os.getenv("DRIFT_DETECTION_INTERVAL_SECONDS", "300")),
    initial_delay=60.0,  # Wait 1 minute after startup before first run
    idle=10.0,  # Run every interval even if there are no realm resources
)
async def drift_detection_timer(**kwargs) -> None:
    """
    Periodic drift detection task.

    This task runs on a timer to check for drift between Keycloak state
    and Kubernetes CRs. It detects:
    - Orphaned resources (created by operator but CR deleted)
    - Configuration drift (CR exists but state differs)
    - Unmanaged resources (exist in Keycloak without operator ownership)
    """
    from keycloak_operator.services.drift_detection_service import (
        DriftDetectionConfig,
        DriftDetector,
    )

    # Check if drift detection is enabled
    config = DriftDetectionConfig.from_env()
    if not config.enabled:
        return  # Silently skip if disabled

    logger = logging.getLogger(__name__)
    logger.info("Starting periodic drift detection scan")

    try:
        # Create drift detector
        detector = DriftDetector(config=config)

        # Scan for drift
        drift_results = await detector.scan_for_drift()

        # Log summary
        orphaned = [d for d in drift_results if d.drift_type == "orphaned"]
        config_drift = [d for d in drift_results if d.drift_type == "config_drift"]
        unmanaged = [d for d in drift_results if d.drift_type == "unmanaged"]

        logger.info(
            f"Drift scan completed: {len(orphaned)} orphaned, "
            f"{len(config_drift)} config drift, {len(unmanaged)} unmanaged"
        )

        # Remediate if enabled
        if config.auto_remediate and drift_results:
            await detector.remediate_drift(drift_results)

    except Exception as e:
        logger.error(f"Drift detection failed: {e}", exc_info=True)


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
        # Run the operator with leader election support
        # Peering and webhook settings are configured in the startup handler
        if watched_namespaces:
            # Watch specific namespaces
            kopf.run(
                namespaces=watched_namespaces,
                liveness_endpoint="http://0.0.0.0:8080/healthz",
            )
        else:
            # Watch all namespaces (cluster-wide)
            kopf.run(
                clusterwide=True,
                liveness_endpoint="http://0.0.0.0:8080/healthz",
            )
    except KeyboardInterrupt:
        logging.info("Received shutdown signal")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Operator failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
