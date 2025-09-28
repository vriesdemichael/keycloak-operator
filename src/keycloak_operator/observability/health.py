"""
Health check utilities for the Keycloak operator.

This module provides comprehensive health checking capabilities
for monitoring operator and system component health.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


@dataclass
class HealthCheckResult:
    """Result of a health check operation."""

    name: str
    status: str  # "healthy", "unhealthy", "degraded", "unknown"
    message: str
    details: dict[str, Any] | None = None
    duration: float = 0.0
    timestamp: float = 0.0


class HealthChecker:
    """Performs comprehensive health checks for the operator."""

    def __init__(self, k8s_client: client.ApiClient | None = None):
        """
        Initialize health checker.

        Args:
            k8s_client: Kubernetes API client
        """
        self.k8s_client = k8s_client

    async def check_all(self) -> dict[str, HealthCheckResult]:
        """
        Run all health checks.

        Returns:
            Dictionary of health check results
        """
        checks = {
            "kubernetes_api": self._check_kubernetes_api(),
            "crds_installed": self._check_crds_installed(),
            "rbac_permissions": self._check_rbac_permissions(),
            "operator_resources": self._check_operator_resources(),
        }

        results = {}
        for name, check_coro in checks.items():
            try:
                result = await check_coro
                results[name] = result
            except Exception as e:
                results[name] = HealthCheckResult(
                    name=name,
                    status="unhealthy",
                    message=f"Health check failed: {str(e)}",
                    timestamp=time.time(),
                )

        return results

    async def _check_kubernetes_api(self) -> HealthCheckResult:
        """Check Kubernetes API connectivity."""
        start_time = time.time()

        try:
            if not self.k8s_client:
                from ..utils.kubernetes import get_kubernetes_client

                self.k8s_client = get_kubernetes_client()

            # Simple API call to test connectivity
            core_api = client.CoreV1Api(self.k8s_client)
            namespaces = core_api.list_namespace(limit=1, timeout_seconds=5)

            duration = time.time() - start_time

            return HealthCheckResult(
                name="kubernetes_api",
                status="healthy",
                message="Kubernetes API is accessible",
                details={
                    "api_server_version": getattr(namespaces, "api_version", "unknown"),
                    "response_time_ms": round(duration * 1000, 2),
                },
                duration=duration,
                timestamp=time.time(),
            )

        except ApiException as e:
            duration = time.time() - start_time
            return HealthCheckResult(
                name="kubernetes_api",
                status="unhealthy",
                message=f"Kubernetes API error: {e.reason}",
                details={
                    "status_code": e.status,
                    "response_time_ms": round(duration * 1000, 2),
                },
                duration=duration,
                timestamp=time.time(),
            )

        except Exception as e:
            duration = time.time() - start_time
            return HealthCheckResult(
                name="kubernetes_api",
                status="unhealthy",
                message=f"Failed to connect to Kubernetes API: {str(e)}",
                duration=duration,
                timestamp=time.time(),
            )

    async def _check_crds_installed(self) -> HealthCheckResult:
        """Check if required CRDs are installed."""
        start_time = time.time()

        try:
            if not self.k8s_client:
                from ..utils.kubernetes import get_kubernetes_client

                self.k8s_client = get_kubernetes_client()

            api_extensions = client.ApiextensionsV1Api(self.k8s_client)

            # Define required CRDs
            required_crds = [
                "keycloaks.keycloak.mdvr.nl",
                "keycloakrealms.keycloak.mdvr.nl",
                "keycloakclients.keycloak.mdvr.nl",
            ]

            installed_crds = []
            missing_crds = []

            for crd_name in required_crds:
                try:
                    api_extensions.read_custom_resource_definition(name=crd_name)
                    installed_crds.append(crd_name)
                except ApiException as e:
                    if e.status == 404:
                        missing_crds.append(crd_name)
                    else:
                        raise

            duration = time.time() - start_time

            if missing_crds:
                return HealthCheckResult(
                    name="crds_installed",
                    status="unhealthy",
                    message=f"Missing required CRDs: {', '.join(missing_crds)}",
                    details={
                        "installed": installed_crds,
                        "missing": missing_crds,
                        "required": required_crds,
                    },
                    duration=duration,
                    timestamp=time.time(),
                )
            else:
                return HealthCheckResult(
                    name="crds_installed",
                    status="healthy",
                    message="All required CRDs are installed",
                    details={"installed": installed_crds},
                    duration=duration,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration = time.time() - start_time
            return HealthCheckResult(
                name="crds_installed",
                status="unhealthy",
                message=f"Failed to check CRDs: {str(e)}",
                duration=duration,
                timestamp=time.time(),
            )

    async def _check_rbac_permissions(self) -> HealthCheckResult:
        """Check if the operator has required RBAC permissions."""
        start_time = time.time()

        try:
            if not self.k8s_client:
                from ..utils.kubernetes import get_kubernetes_client

                self.k8s_client = get_kubernetes_client()

            # Test basic permissions
            auth_api = client.AuthorizationV1Api(self.k8s_client)

            # Define required permissions to test
            permission_tests = [
                {"resource": "keycloaks", "verb": "get", "group": "keycloak.mdvr.nl"},
                {
                    "resource": "keycloaks",
                    "verb": "create",
                    "group": "keycloak.mdvr.nl",
                },
                {
                    "resource": "keycloaks",
                    "verb": "update",
                    "group": "keycloak.mdvr.nl",
                },
                {"resource": "secrets", "verb": "get", "group": ""},
                {"resource": "secrets", "verb": "create", "group": ""},
                {"resource": "deployments", "verb": "get", "group": "apps"},
                {"resource": "deployments", "verb": "create", "group": "apps"},
                {"resource": "services", "verb": "get", "group": ""},
                {"resource": "services", "verb": "create", "group": ""},
            ]

            allowed_permissions = []
            denied_permissions = []

            for perm in permission_tests:
                try:
                    # Create SubjectAccessReview to test permission
                    access_review = client.V1SubjectAccessReview(
                        spec=client.V1SubjectAccessReviewSpec(
                            resource_attributes=client.V1ResourceAttributes(
                                group=perm["group"],
                                resource=perm["resource"],
                                verb=perm["verb"],
                            )
                        )
                    )

                    result = auth_api.create_subject_access_review(body=access_review)

                    if result.status.allowed:
                        allowed_permissions.append(
                            f"{perm['verb']} {perm['group']}/{perm['resource']}"
                        )
                    else:
                        denied_permissions.append(
                            f"{perm['verb']} {perm['group']}/{perm['resource']}"
                        )

                except Exception as e:
                    logger.warning(f"Failed to test permission {perm}: {e}")
                    denied_permissions.append(
                        f"{perm['verb']} {perm['group']}/{perm['resource']} (test failed)"
                    )

            duration = time.time() - start_time

            if denied_permissions:
                return HealthCheckResult(
                    name="rbac_permissions",
                    status="degraded" if allowed_permissions else "unhealthy",
                    message=f"Missing some RBAC permissions: {', '.join(denied_permissions[:3])}{'...' if len(denied_permissions) > 3 else ''}",
                    details={
                        "allowed": allowed_permissions,
                        "denied": denied_permissions,
                        "total_tested": len(permission_tests),
                    },
                    duration=duration,
                    timestamp=time.time(),
                )
            else:
                return HealthCheckResult(
                    name="rbac_permissions",
                    status="healthy",
                    message="All required RBAC permissions are available",
                    details={"allowed": allowed_permissions},
                    duration=duration,
                    timestamp=time.time(),
                )

        except Exception as e:
            duration = time.time() - start_time
            return HealthCheckResult(
                name="rbac_permissions",
                status="unhealthy",
                message=f"Failed to check RBAC permissions: {str(e)}",
                duration=duration,
                timestamp=time.time(),
            )

    async def _check_operator_resources(self) -> HealthCheckResult:
        """Check operator's own resources (deployment, service account, etc.)."""
        start_time = time.time()

        try:
            if not self.k8s_client:
                from ..utils.kubernetes import get_kubernetes_client

                self.k8s_client = get_kubernetes_client()

            # Get operator's namespace and name from environment or configuration
            import os

            operator_namespace = os.getenv(
                "OPERATOR_NAMESPACE", "keycloak-operator-system"
            )
            operator_name = os.getenv("OPERATOR_NAME", "keycloak-operator")

            apps_api = client.AppsV1Api(self.k8s_client)
            core_api = client.CoreV1Api(self.k8s_client)

            resource_status = {}

            # Check operator deployment
            try:
                deployment = apps_api.read_namespaced_deployment(
                    name=operator_name, namespace=operator_namespace
                )
                ready_replicas = deployment.status.ready_replicas or 0
                desired_replicas = deployment.spec.replicas or 1

                resource_status["deployment"] = {
                    "status": "healthy"
                    if ready_replicas >= desired_replicas
                    else "degraded",
                    "ready_replicas": ready_replicas,
                    "desired_replicas": desired_replicas,
                }

            except ApiException as e:
                if e.status == 404:
                    resource_status["deployment"] = {
                        "status": "unknown",
                        "message": "Operator deployment not found (running outside cluster?)",
                    }
                else:
                    resource_status["deployment"] = {
                        "status": "unhealthy",
                        "message": f"Failed to check deployment: {e.reason}",
                    }

            # Check service account
            try:
                core_api.read_namespaced_service_account(
                    name=operator_name, namespace=operator_namespace
                )
                resource_status["service_account"] = {"status": "healthy"}

            except ApiException as e:
                if e.status == 404:
                    resource_status["service_account"] = {
                        "status": "degraded",
                        "message": "Service account not found",
                    }
                else:
                    resource_status["service_account"] = {
                        "status": "unhealthy",
                        "message": f"Failed to check service account: {e.reason}",
                    }

            duration = time.time() - start_time

            # Determine overall status
            statuses = [
                res.get("status", "unknown") for res in resource_status.values()
            ]

            if "unhealthy" in statuses:
                overall_status = "unhealthy"
                message = "Some operator resources are unhealthy"
            elif "degraded" in statuses:
                overall_status = "degraded"
                message = "Some operator resources are degraded"
            elif "unknown" in statuses:
                overall_status = "degraded"
                message = "Some operator resources could not be verified"
            else:
                overall_status = "healthy"
                message = "All operator resources are healthy"

            return HealthCheckResult(
                name="operator_resources",
                status=overall_status,
                message=message,
                details=resource_status,
                duration=duration,
                timestamp=time.time(),
            )

        except Exception as e:
            duration = time.time() - start_time
            return HealthCheckResult(
                name="operator_resources",
                status="unhealthy",
                message=f"Failed to check operator resources: {str(e)}",
                duration=duration,
                timestamp=time.time(),
            )

    def get_overall_health(self, results: dict[str, HealthCheckResult]) -> str:
        """
        Determine overall health status from individual check results.

        Args:
            results: Dictionary of health check results

        Returns:
            Overall health status
        """
        if not results:
            return "unknown"

        statuses = [result.status for result in results.values()]

        if "unhealthy" in statuses:
            return "unhealthy"
        elif "degraded" in statuses or "unknown" in statuses:
            return "degraded"
        else:
            return "healthy"

    def to_dict(self, results: dict[str, HealthCheckResult]) -> dict[str, Any]:
        """
        Convert health check results to dictionary format.

        Args:
            results: Health check results

        Returns:
            Dictionary representation
        """
        overall_status = self.get_overall_health(results)

        return {
            "status": overall_status,
            "timestamp": time.time(),
            "checks": {
                name: {
                    "status": result.status,
                    "message": result.message,
                    "details": result.details,
                    "duration": result.duration,
                    "timestamp": result.timestamp,
                }
                for name, result in results.items()
            },
        }
