"""
Prometheus metrics for the Keycloak operator.

This module provides comprehensive metrics collection for monitoring
operator performance, resource reconciliation, and system health.
"""

import logging
import time
from contextlib import asynccontextmanager

from aiohttp import web
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger(__name__)

# Global metrics registry
_metrics_registry: CollectorRegistry | None = None

# Metrics definitions
RECONCILIATION_TOTAL = Counter(
    "keycloak_operator_reconciliation_total",
    "Total number of reconciliation attempts",
    ["resource_type", "namespace", "name", "result"],
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

DATABASE_CONNECTION_STATUS = Gauge(
    "keycloak_operator_database_connection_status",
    "Database connection status (1=healthy, 0=unhealthy)",
    ["resource_name", "namespace", "database_type"],
    registry=None,
)

DATABASE_CONNECTION_DURATION = Histogram(
    "keycloak_operator_database_connection_duration_seconds",
    "Time spent testing database connections",
    ["resource_name", "namespace", "database_type"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
    registry=None,
)

KEYCLOAK_INSTANCE_STATUS = Gauge(
    "keycloak_operator_keycloak_instance_status",
    "Keycloak instance status (1=running, 0=not running)",
    ["instance_name", "namespace"],
    registry=None,
)

RBAC_VALIDATIONS = Counter(
    "keycloak_operator_rbac_validations_total",
    "Total number of RBAC validation attempts",
    ["source_namespace", "target_namespace", "result"],
    registry=None,
)

CNPG_CLUSTER_STATUS = Gauge(
    "keycloak_operator_cnpg_cluster_status",
    "CloudNativePG cluster status (1=healthy, 0=unhealthy)",
    ["cluster_name", "namespace"],
    registry=None,
)

# Leader election metrics
LEADER_ELECTION_STATUS = Gauge(
    "keycloak_operator_leader_election_status",
    "Leader election status (1=leader, 0=follower)",
    ["instance_id", "namespace"],
    registry=None,
)

LEADER_ELECTION_CHANGES = Counter(
    "keycloak_operator_leader_election_changes_total",
    "Total number of leader election changes",
    ["previous_leader", "new_leader", "namespace"],
    registry=None,
)

LEADER_ELECTION_LEASE_RENEWALS = Counter(
    "keycloak_operator_leader_election_lease_renewals_total",
    "Total number of leader election lease renewals",
    ["instance_id", "namespace", "result"],
    registry=None,
)

LEADER_ELECTION_LEASE_DURATION = Histogram(
    "keycloak_operator_leader_election_lease_duration_seconds",
    "Duration of leader election lease renewals",
    ["instance_id", "namespace"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
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
            DATABASE_CONNECTION_STATUS,
            DATABASE_CONNECTION_DURATION,
            KEYCLOAK_INSTANCE_STATUS,
            RBAC_VALIDATIONS,
            CNPG_CLUSTER_STATUS,
            LEADER_ELECTION_STATUS,
            LEADER_ELECTION_CHANGES,
            LEADER_ELECTION_LEASE_RENEWALS,
            LEADER_ELECTION_LEASE_DURATION,
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
            name: Name of the resource
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
                name=name,
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

    def record_database_connection_test(
        self,
        resource_name: str,
        namespace: str,
        database_type: str,
        success: bool,
        duration: float,
    ):
        """
        Record database connection test results.

        Args:
            resource_name: Name of the Keycloak resource
            namespace: Namespace of the resource
            database_type: Type of database
            success: Whether the connection test succeeded
            duration: Time taken for the test
        """
        DATABASE_CONNECTION_STATUS.labels(
            resource_name=resource_name,
            namespace=namespace,
            database_type=database_type,
        ).set(1 if success else 0)

        DATABASE_CONNECTION_DURATION.labels(
            resource_name=resource_name,
            namespace=namespace,
            database_type=database_type,
        ).observe(duration)

    def update_keycloak_instance_status(
        self, instance_name: str, namespace: str, running: bool
    ):
        """
        Update Keycloak instance status.

        Args:
            instance_name: Name of the Keycloak instance
            namespace: Namespace of the instance
            running: Whether the instance is running
        """
        KEYCLOAK_INSTANCE_STATUS.labels(
            instance_name=instance_name, namespace=namespace
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

    def update_cnpg_cluster_status(
        self, cluster_name: str, namespace: str, healthy: bool
    ):
        """
        Update CloudNativePG cluster status.

        Args:
            cluster_name: Name of the CNPG cluster
            namespace: Namespace of the cluster
            healthy: Whether the cluster is healthy
        """
        CNPG_CLUSTER_STATUS.labels(cluster_name=cluster_name, namespace=namespace).set(
            1 if healthy else 0
        )

    def update_leader_election_status(
        self, instance_id: str, namespace: str, is_leader: bool
    ):
        """
        Update leader election status.

        Args:
            instance_id: Unique identifier for this operator instance
            namespace: Namespace where the operator is running
            is_leader: Whether this instance is currently the leader
        """
        LEADER_ELECTION_STATUS.labels(instance_id=instance_id, namespace=namespace).set(
            1 if is_leader else 0
        )

    def record_leader_election_change(
        self, previous_leader: str, new_leader: str, namespace: str
    ):
        """
        Record a leader election change event.

        Args:
            previous_leader: ID of the previous leader
            new_leader: ID of the new leader
            namespace: Namespace where the election occurred
        """
        LEADER_ELECTION_CHANGES.labels(
            previous_leader=previous_leader,
            new_leader=new_leader,
            namespace=namespace,
        ).inc()

    def record_lease_renewal(
        self, instance_id: str, namespace: str, success: bool, duration: float
    ):
        """
        Record a leader election lease renewal attempt.

        Args:
            instance_id: Unique identifier for this operator instance
            namespace: Namespace where the operator is running
            success: Whether the lease renewal succeeded
            duration: Time taken for the renewal operation
        """
        result = "success" if success else "failure"

        LEADER_ELECTION_LEASE_RENEWALS.labels(
            instance_id=instance_id, namespace=namespace, result=result
        ).inc()

        LEADER_ELECTION_LEASE_DURATION.labels(
            instance_id=instance_id, namespace=namespace
        ).observe(duration)


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
        self.app = web.Application()  # type: ignore[attr-defined]
        self.runner: web.AppRunner | None = None  # type: ignore[attr-defined]
        self.site: web.TCPSite | None = None  # type: ignore[attr-defined]
        # Set up routes
        self._setup_routes()

    def _setup_routes(self):
        """Set up HTTP routes for the metrics server."""
        self.app.router.add_get("/metrics", self._metrics_handler)
        self.app.router.add_get("/health", self._health_handler)
        self.app.router.add_get("/ready", self._ready_handler)
        self.app.router.add_get("/healthz", self._healthz_handler)  # K8s compatibility

    async def _metrics_handler(self, request: web.Request) -> web.Response:  # type: ignore[attr-defined]
        """Handle /metrics endpoint for Prometheus scraping."""
        try:
            registry = get_metrics_registry()
            metrics_data = generate_latest(registry)
            return web.Response(body=metrics_data, content_type=CONTENT_TYPE_LATEST)  # type: ignore[attr-defined]
        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            return web.Response(text=f"Error generating metrics: {str(e)}", status=500)  # type: ignore[attr-defined]

    async def _health_handler(self, request: web.Request) -> web.Response:  # type: ignore[attr-defined]
        """Handle /health endpoint for operator health checks."""
        try:
            from .health import HealthChecker

            health_checker = HealthChecker()
            health_results = await health_checker.check_all()
            health_dict = health_checker.to_dict(health_results)

            status_code = (
                200 if health_dict["status"] in ["healthy", "degraded"] else 503
            )

            return web.json_response(health_dict, status=status_code)  # type: ignore[attr-defined]
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return web.json_response(  # type: ignore[attr-defined]
                {"status": "unhealthy", "error": str(e), "timestamp": time.time()},
                status=500,
            )

    async def _ready_handler(self, request: web.Request) -> web.Response:  # type: ignore[attr-defined]
        """Handle /ready endpoint for readiness probes."""
        try:
            from .health import HealthChecker

            health_checker = HealthChecker()
            # For readiness, only check essential components
            results = {}
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
                return web.json_response(ready_status)  # type: ignore[attr-defined]
            else:
                ready_status = {
                    "status": "not_ready",
                    "timestamp": time.time(),
                    "checks": {
                        "kubernetes_api": results["kubernetes_api"].status,
                        "crds_installed": results["crds_installed"].status,
                    },
                }
                return web.json_response(ready_status, status=503)  # type: ignore[attr-defined]

        except Exception as e:
            logger.error(f"Readiness check failed: {e}")
            return web.json_response(  # type: ignore[attr-defined]
                {"status": "not_ready", "error": str(e), "timestamp": time.time()},
                status=503,
            )

    async def _healthz_handler(self, request: web.Request) -> web.Response:  # type: ignore[attr-defined]
        """Handle /healthz endpoint for Kubernetes compatibility."""
        # Simple health check that returns 200 if the server is running
        return web.Response(text="ok")  # type: ignore[attr-defined]

    async def start(self):
        """Start the metrics server."""
        try:
            self.runner = web.AppRunner(self.app)  # type: ignore[attr-defined]
            await self.runner.setup()

            self.site = web.TCPSite(self.runner, self.host, self.port)  # type: ignore[attr-defined]
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

    async def stop(self):
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
