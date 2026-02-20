"""
Prometheus metrics for the Keycloak operator.

This module provides comprehensive metrics collection for monitoring
operator performance, resource reconciliation, and system health.

Metric naming conventions (per ADR-048 and issue #171):
- All metrics use the ``keycloak_operator_`` prefix for Prometheus discoverability
- Labels are kept to operationally essential dimensions to limit cardinality
- High-cardinality labels (resource names, instance names) are excluded
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Any

# Note: aiohttp is not listed in pyproject.toml dependencies.
# It's provided transitively by Kopf (required for webhooks and health probes).
# We use it here to avoid adding duplicate dependencies while keeping HTTP server
# implementation consistent with Kopf's own usage.
from aiohttp.web import (
    Application,
    AppRunner,
    Request,
    Response,
    TCPSite,
    json_response,
)
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger(__name__)

# Global metrics registry
_metrics_registry: CollectorRegistry | None = None

# ---------------------------------------------------------------------------
# Reconciliation metrics
# ---------------------------------------------------------------------------

RECONCILIATION_TOTAL = Counter(
    "keycloak_operator_reconciliation_total",
    "Total number of reconciliation attempts",
    ["resource_type", "namespace", "result"],
    registry=None,  # Will be set during initialization
)

RECONCILIATION_DURATION = Histogram(
    "keycloak_operator_reconciliation_duration_seconds",
    "Time spent on reconciliation operations",
    ["resource_type", "namespace", "operation"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
    registry=None,
)

RECONCILIATION_ERRORS = Counter(
    "keycloak_operator_reconciliation_errors_total",
    "Total number of reconciliation errors",
    ["resource_type", "namespace", "error_type", "retryable"],
    registry=None,
)

ACTIVE_RESOURCES = Gauge(
    "keycloak_operator_active_resources",
    "Number of active Keycloak resources",
    ["resource_type", "namespace", "phase"],
    registry=None,
)

# Generation-based skip metrics
RECONCILIATION_SKIPPED_TOTAL = Counter(
    "keycloak_operator_reconciliation_skipped_total",
    "Total number of reconciliations skipped due to generation match",
    ["resource_type", "namespace"],
    registry=None,
)

# ---------------------------------------------------------------------------
# Database metrics
# ---------------------------------------------------------------------------

DATABASE_CONNECTION_STATUS = Gauge(
    "keycloak_operator_database_connection_status",
    "Database connection status (1=healthy, 0=unhealthy)",
    ["namespace", "database_type"],
    registry=None,
)

DATABASE_CONNECTION_DURATION = Histogram(
    "keycloak_operator_database_connection_duration_seconds",
    "Time spent testing database connections",
    ["namespace", "database_type"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
    registry=None,
)

# ---------------------------------------------------------------------------
# Admin session metrics (renamed from token_expires / operational_tokens)
# ---------------------------------------------------------------------------

ADMIN_SESSION_EXPIRES_TIMESTAMP = Gauge(
    "keycloak_operator_admin_session_expires_timestamp",
    "Unix timestamp when admin session JWT expires",
    ["namespace", "keycloak_instance"],
    registry=None,
)

ADMIN_SESSIONS_ACTIVE = Gauge(
    "keycloak_operator_admin_sessions_active",
    "Number of active admin sessions to Keycloak instances",
    [],
    registry=None,
)

# ---------------------------------------------------------------------------
# Keycloak instance & CNPG status metrics
# ---------------------------------------------------------------------------

KEYCLOAK_INSTANCE_STATUS = Gauge(
    "keycloak_operator_keycloak_instance_status",
    "Keycloak instance status (1=running, 0=not running)",
    ["namespace"],
    registry=None,
)

CNPG_CLUSTER_STATUS = Gauge(
    "keycloak_operator_cnpg_cluster_status",
    "CloudNativePG cluster status (1=healthy, 0=unhealthy)",
    ["namespace"],
    registry=None,
)

# ---------------------------------------------------------------------------
# RBAC metrics
# ---------------------------------------------------------------------------

RBAC_VALIDATIONS = Counter(
    "keycloak_operator_rbac_validations_total",
    "Total number of RBAC validation attempts",
    ["source_namespace", "target_namespace", "result"],
    registry=None,
)

# ---------------------------------------------------------------------------
# Rate limiting metrics (prefix fixed: keycloak_api_ -> keycloak_operator_api_)
# ---------------------------------------------------------------------------

RATE_LIMIT_WAIT_SECONDS = Histogram(
    "keycloak_operator_api_rate_limit_wait_seconds",
    "Time spent waiting for rate limit tokens",
    ["namespace", "limit_type"],
    buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
    registry=None,
)

RATE_LIMIT_ACQUIRED_TOTAL = Counter(
    "keycloak_operator_api_rate_limit_acquired_total",
    "Total rate limit tokens successfully acquired",
    ["namespace", "limit_type"],
    registry=None,
)

RATE_LIMIT_TIMEOUTS_TOTAL = Counter(
    "keycloak_operator_api_rate_limit_timeouts_total",
    "Total rate limit timeout errors",
    ["namespace", "limit_type"],
    registry=None,
)

RATE_LIMIT_BUDGET_AVAILABLE = Gauge(
    "keycloak_operator_api_rate_limit_budget_available",
    "Currently available rate limit budget (token bucket permits)",
    ["namespace"],
    registry=None,
)

# ---------------------------------------------------------------------------
# Circuit Breaker metrics
# ---------------------------------------------------------------------------

CIRCUIT_BREAKER_STATE = Gauge(
    "keycloak_operator_circuit_breaker_state",
    "Circuit breaker state (0=closed/healthy, 1=open/broken, 2=half-open/recovering)",
    ["keycloak_instance", "keycloak_namespace"],
    registry=None,
)

# ---------------------------------------------------------------------------
# Leader election metrics (namespace label removed – single-namespace deploy)
# ---------------------------------------------------------------------------

LEADER_ELECTION_STATUS = Gauge(
    "keycloak_operator_leader_election_status",
    "Leader election status (1=leader, 0=follower)",
    ["instance_id"],
    registry=None,
)

LEADER_ELECTION_CHANGES = Counter(
    "keycloak_operator_leader_election_changes_total",
    "Total number of leader election changes",
    [],
    registry=None,
)

LEADER_ELECTION_LEASE_RENEWALS = Counter(
    "keycloak_operator_leader_election_lease_renewals_total",
    "Total number of leader election lease renewals",
    ["instance_id", "result"],
    registry=None,
)

LEADER_ELECTION_LEASE_DURATION = Histogram(
    "keycloak_operator_leader_election_lease_duration_seconds",
    "Duration of leader election lease renewals",
    ["instance_id"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=None,
)

# ---------------------------------------------------------------------------
# Drift detection metrics
# ---------------------------------------------------------------------------

ORPHANED_RESOURCES = Gauge(
    "keycloak_operator_orphaned_resources",
    "Number of orphaned Keycloak resources (created by this operator, CR deleted)",
    ["resource_type", "operator_instance"],
    registry=None,
)

CONFIG_DRIFT = Gauge(
    "keycloak_operator_config_drift",
    "Number of resources with configuration drift (CR exists but state differs)",
    ["resource_type", "cr_namespace"],
    registry=None,
)

UNMANAGED_RESOURCES = Gauge(
    "keycloak_operator_unmanaged_resources",
    "Number of Keycloak resources not managed by any operator",
    ["resource_type"],
    registry=None,
)

REMEDIATION_TOTAL = Counter(
    "keycloak_operator_remediation_total",
    "Total number of drift remediation actions performed",
    ["resource_type", "action", "reason"],
    registry=None,
)

REMEDIATION_ERRORS_TOTAL = Counter(
    "keycloak_operator_remediation_errors_total",
    "Total number of drift remediation errors",
    ["resource_type", "action"],
    registry=None,
)

DRIFT_CHECK_DURATION = Histogram(
    "keycloak_operator_drift_check_duration_seconds",
    "Duration of drift detection scans",
    ["resource_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
    registry=None,
)

DRIFT_CHECK_ERRORS_TOTAL = Counter(
    "keycloak_operator_drift_check_errors_total",
    "Total number of drift check errors",
    ["resource_type"],
    registry=None,
)

DRIFT_CHECK_LAST_SUCCESS_TIMESTAMP = Gauge(
    "keycloak_operator_drift_check_last_success_timestamp",
    "Unix timestamp of last successful drift check",
    [],
    registry=None,
)

# ---------------------------------------------------------------------------
# User Federation metrics (sync metrics deleted – Keycloak-internal concern)
# ---------------------------------------------------------------------------

USER_FEDERATION_STATUS = Gauge(
    "keycloak_operator_user_federation_status",
    "User federation provider status (1=connected, 0=disconnected)",
    ["realm", "provider_id"],
    registry=None,
)

# ---------------------------------------------------------------------------
# Secret rotation metrics
# ---------------------------------------------------------------------------

SECRET_ROTATION_TOTAL = Counter(
    "keycloak_operator_secret_rotation_total",
    "Total number of secret rotation attempts",
    ["namespace", "result"],
    registry=None,
)

SECRET_ROTATION_ERRORS_TOTAL = Counter(
    "keycloak_operator_secret_rotation_errors_total",
    "Total number of secret rotation errors",
    ["namespace", "error_type"],
    registry=None,
)

SECRET_ROTATION_DURATION = Histogram(
    "keycloak_operator_secret_rotation_duration_seconds",
    "Duration of secret rotation operations",
    ["namespace"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
    registry=None,
)

SECRET_NEXT_ROTATION_TIMESTAMP = Gauge(
    "keycloak_operator_secret_next_rotation_timestamp",
    "Unix timestamp of next scheduled secret rotation",
    ["namespace"],
    registry=None,
)

SECRET_ROTATION_RETRIES_TOTAL = Counter(
    "keycloak_operator_secret_rotation_retries_total",
    "Total number of secret rotation retry attempts",
    ["namespace"],
    registry=None,
)


def get_metrics_registry() -> CollectorRegistry:
    """Get or create the global metrics registry."""
    global _metrics_registry

    if _metrics_registry is None:
        _metrics_registry = CollectorRegistry()

        # Register all metrics with the registry
        for metric in [
            RECONCILIATION_TOTAL,
            RECONCILIATION_DURATION,
            RECONCILIATION_ERRORS,
            ACTIVE_RESOURCES,
            RECONCILIATION_SKIPPED_TOTAL,
            DATABASE_CONNECTION_STATUS,
            DATABASE_CONNECTION_DURATION,
            ADMIN_SESSION_EXPIRES_TIMESTAMP,
            ADMIN_SESSIONS_ACTIVE,
            KEYCLOAK_INSTANCE_STATUS,
            CNPG_CLUSTER_STATUS,
            RBAC_VALIDATIONS,
            RATE_LIMIT_WAIT_SECONDS,
            RATE_LIMIT_ACQUIRED_TOTAL,
            RATE_LIMIT_TIMEOUTS_TOTAL,
            RATE_LIMIT_BUDGET_AVAILABLE,
            CIRCUIT_BREAKER_STATE,
            LEADER_ELECTION_STATUS,
            LEADER_ELECTION_CHANGES,
            LEADER_ELECTION_LEASE_RENEWALS,
            LEADER_ELECTION_LEASE_DURATION,
            ORPHANED_RESOURCES,
            CONFIG_DRIFT,
            UNMANAGED_RESOURCES,
            REMEDIATION_TOTAL,
            REMEDIATION_ERRORS_TOTAL,
            DRIFT_CHECK_DURATION,
            DRIFT_CHECK_ERRORS_TOTAL,
            DRIFT_CHECK_LAST_SUCCESS_TIMESTAMP,
            USER_FEDERATION_STATUS,
            SECRET_ROTATION_TOTAL,
            SECRET_ROTATION_ERRORS_TOTAL,
            SECRET_ROTATION_DURATION,
            SECRET_NEXT_ROTATION_TIMESTAMP,
            SECRET_ROTATION_RETRIES_TOTAL,
        ]:
            # Use try-except to handle registry assignment safely
            try:
                metric._registry = _metrics_registry  # type: ignore[attr-defined]
                _metrics_registry.register(metric)
            except Exception:
                # Fallback: just register the metric
                _metrics_registry.register(metric)

    return _metrics_registry


class MetricsCollector:
    """Collects and manages metrics for the Keycloak operator."""

    def __init__(self):
        """Initialize metrics collector."""
        self.registry = get_metrics_registry()

    @asynccontextmanager
    async def track_reconciliation(
        self,
        resource_type: str,
        namespace: str,
        name: str,
        operation: str = "reconcile",
    ):
        """
        Context manager to track reconciliation operations.

        Args:
            resource_type: Type of resource being reconciled
            namespace: Namespace of the resource
            name: Name of the resource (used for logging only, not in metrics)
            operation: Type of operation being performed
        """
        start_time = time.time()
        result = "unknown"

        try:
            yield
            result = "success"
        except Exception as e:
            result = "error"

            # Determine error type and retryability
            error_type = type(e).__name__
            retryable = "true" if hasattr(e, "retryable") and e.retryable else "false"

            RECONCILIATION_ERRORS.labels(
                resource_type=resource_type,
                namespace=namespace,
                error_type=error_type,
                retryable=retryable,
            ).inc()

            raise
        finally:
            duration = time.time() - start_time

            RECONCILIATION_TOTAL.labels(
                resource_type=resource_type,
                namespace=namespace,
                result=result,
            ).inc()

            RECONCILIATION_DURATION.labels(
                resource_type=resource_type, namespace=namespace, operation=operation
            ).observe(duration)

    def update_resource_status(
        self, resource_type: str, namespace: str, phase: str, count: int = 1
    ):
        """
        Update the count of resources in a specific phase.

        Args:
            resource_type: Type of resource
            namespace: Namespace of the resource
            phase: Current phase of the resource
            count: Number of resources (default: 1)
        """
        ACTIVE_RESOURCES.labels(
            resource_type=resource_type, namespace=namespace, phase=phase
        ).set(count)

    @property
    def admin_session_expires(self):
        """Gauge for admin session expiry timestamps."""
        return ADMIN_SESSION_EXPIRES_TIMESTAMP

    @property
    def admin_sessions_active(self):
        """Gauge for active admin sessions."""
        return ADMIN_SESSIONS_ACTIVE

    def record_database_connection_test(
        self,
        namespace: str,
        database_type: str,
        success: bool,
        duration: float,
    ):
        """
        Record database connection test results.

        Args:
            namespace: Namespace of the resource
            database_type: Type of database
            success: Whether the connection test succeeded
            duration: Time taken for the test
        """
        DATABASE_CONNECTION_STATUS.labels(
            namespace=namespace,
            database_type=database_type,
        ).set(1 if success else 0)

        DATABASE_CONNECTION_DURATION.labels(
            namespace=namespace,
            database_type=database_type,
        ).observe(duration)

    def update_keycloak_instance_status(self, namespace: str, running: bool):
        """
        Update Keycloak instance status.

        Args:
            namespace: Namespace of the instance
            running: Whether the instance is running
        """
        KEYCLOAK_INSTANCE_STATUS.labels(
            namespace=namespace,
        ).set(1 if running else 0)

    def record_rbac_validation(
        self, source_namespace: str, target_namespace: str, success: bool
    ):
        """
        Record RBAC validation attempt.

        Args:
            source_namespace: Source namespace of the operation
            target_namespace: Target namespace of the operation
            success: Whether the validation succeeded
        """
        RBAC_VALIDATIONS.labels(
            source_namespace=source_namespace,
            target_namespace=target_namespace,
            result="success" if success else "failure",
        ).inc()

    def update_cnpg_cluster_status(self, namespace: str, healthy: bool):
        """
        Update CloudNativePG cluster status.

        Args:
            namespace: Namespace of the cluster
            healthy: Whether the cluster is healthy
        """
        CNPG_CLUSTER_STATUS.labels(namespace=namespace).set(1 if healthy else 0)

    def update_leader_election_status(self, instance_id: str, is_leader: bool):
        """
        Update leader election status.

        Args:
            instance_id: Unique identifier for this operator instance
            is_leader: Whether this instance is currently the leader
        """
        LEADER_ELECTION_STATUS.labels(instance_id=instance_id).set(
            1 if is_leader else 0
        )

    def record_leader_election_change(self):
        """Record a leader election change event."""
        LEADER_ELECTION_CHANGES.inc()

    def record_lease_renewal(self, instance_id: str, success: bool, duration: float):
        """
        Record a leader election lease renewal attempt.

        Args:
            instance_id: Unique identifier for this operator instance
            success: Whether the lease renewal succeeded
            duration: Time taken for the renewal operation
        """
        result = "success" if success else "failure"

        LEADER_ELECTION_LEASE_RENEWALS.labels(
            instance_id=instance_id, result=result
        ).inc()

        LEADER_ELECTION_LEASE_DURATION.labels(
            instance_id=instance_id,
        ).observe(duration)

    def record_reconciliation_skip(
        self, resource_type: str, namespace: str, name: str
    ) -> None:
        """
        Record a skipped reconciliation due to generation match.

        This is called when a resource is already reconciled at the current
        generation and in Ready state, avoiding redundant API calls.

        Args:
            resource_type: Type of resource (e.g., 'keycloak', 'realm', 'client')
            namespace: Namespace of the resource
            name: Name of the resource (for logging only, not in metric labels)
        """
        RECONCILIATION_SKIPPED_TOTAL.labels(
            resource_type=resource_type,
            namespace=namespace,
        ).inc()


class MetricsServer:
    """HTTP server for exposing Prometheus metrics."""

    def __init__(self, port: int = 8081, host: str = "0.0.0.0"):
        """
        Initialize metrics server.

        Args:
            port: Port to serve metrics on
            host: Host interface to bind to
        """
        self.port = port
        self.host = host
        self.app = Application()
        self.runner: AppRunner | None = None
        self.site: TCPSite | None = None
        # Set up routes
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up HTTP routes for the metrics server."""
        self.app.router.add_get("/metrics", self._metrics_handler)
        self.app.router.add_get("/health", self._health_handler)
        self.app.router.add_get("/ready", self._ready_handler)
        self.app.router.add_get("/healthz", self._healthz_handler)  # K8s compatibility

    async def _metrics_handler(self, request: Request) -> Response:
        """Handle /metrics endpoint for Prometheus scraping."""
        try:
            registry = get_metrics_registry()
            metrics_data = generate_latest(registry)
            return Response(
                body=metrics_data,
                content_type="text/plain",
                charset="utf-8",
                headers={"X-Content-Type-Options": "nosniff"},
            )
        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            return Response(
                text=f"Error generating metrics: {type(e).__name__}. Check logs for details.",
                status=500,
            )

    async def _health_handler(self, request: Request) -> Response:
        """Handle /health endpoint for operator health checks."""
        try:
            from .health import HealthChecker

            health_checker = HealthChecker()
            health_results = await health_checker.check_all()
            health_dict = health_checker.to_dict(health_results)

            status_code = (
                200 if health_dict["status"] in ["healthy", "degraded"] else 503
            )

            return json_response(health_dict, status=status_code)
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return json_response(
                {
                    "status": "unhealthy",
                    "error": f"{type(e).__name__}. Check logs for details.",
                    "timestamp": time.time(),
                },
                status=500,
            )

    async def _ready_handler(self, request: Request) -> Response:
        """Handle /ready endpoint for readiness probes."""
        try:
            from .health import HealthChecker

            health_checker = HealthChecker()
            # For readiness, only check essential components
            results: dict[str, Any] = {}
            results["kubernetes_api"] = await health_checker._check_kubernetes_api()
            results["crds_installed"] = await health_checker._check_crds_installed()

            # Consider ready if K8s API and CRDs are healthy
            api_healthy = results["kubernetes_api"].status == "healthy"
            crds_healthy = results["crds_installed"].status == "healthy"

            if api_healthy and crds_healthy:
                ready_status = {
                    "status": "ready",
                    "timestamp": time.time(),
                    "checks": {
                        "kubernetes_api": results["kubernetes_api"].status,
                        "crds_installed": results["crds_installed"].status,
                    },
                }
                return json_response(ready_status)
            else:
                ready_status = {
                    "status": "not_ready",
                    "timestamp": time.time(),
                    "checks": {
                        "kubernetes_api": results["kubernetes_api"].status,
                        "crds_installed": results["crds_installed"].status,
                    },
                }
                return json_response(ready_status, status=503)

        except Exception as e:
            logger.error(f"Readiness check failed: {e}")
            return json_response(
                {
                    "status": "not_ready",
                    "error": f"{type(e).__name__}. Check logs for details.",
                    "timestamp": time.time(),
                },
                status=503,
            )

    async def _healthz_handler(self, request: Request) -> Response:
        """Handle /healthz endpoint for Kubernetes compatibility."""
        # Simple health check that returns 200 if the server is running
        return Response(text="ok")

    async def start(self) -> None:
        """Start the metrics server."""
        try:
            self.runner = AppRunner(self.app)
            await self.runner.setup()

            self.site = TCPSite(self.runner, self.host, self.port)
            await self.site.start()

            logger.info(f"Metrics server started on {self.host}:{self.port}")
            logger.info(f"Metrics available at http://{self.host}:{self.port}/metrics")
            logger.info(
                f"Health check available at http://{self.host}:{self.port}/health"
            )
            logger.info(
                f"Readiness check available at http://{self.host}:{self.port}/ready"
            )

        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")
            raise

    async def stop(self) -> None:
        """Stop the metrics server."""
        try:
            if self.site:
                await self.site.stop()
                self.site = None

            if self.runner:
                await self.runner.cleanup()
                self.runner = None

            logger.info("Metrics server stopped")
        except Exception as e:
            logger.error(f"Error stopping metrics server: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()


# Global metrics collector instance
metrics_collector = MetricsCollector()
