"""
Kubernetes helper utilities for integration tests.

This module provides common utilities for interacting with Kubernetes
resources during integration testing.
"""

import asyncio
import time
from collections.abc import Callable

from kubernetes import client
from kubernetes.client.rest import ApiException


class KubernetesTestHelper:
    """Helper class for Kubernetes operations in tests."""

    def __init__(self, k8s_client: client.ApiClient):
        """Initialize with Kubernetes client."""
        self.client = k8s_client
        self.core_v1 = client.CoreV1Api(k8s_client)
        self.apps_v1 = client.AppsV1Api(k8s_client)
        self.custom_objects = client.CustomObjectsApi(k8s_client)

    async def wait_for_condition(
        self,
        condition_func: Callable[[], bool],
        timeout: int = 300,
        interval: int = 5,
        description: str = "condition",
    ) -> bool:
        """
        Wait for a condition to be true.

        Args:
            condition_func: Function that returns True when condition is met
            timeout: Maximum time to wait in seconds
            interval: Check interval in seconds
            description: Description for logging

        Returns:
            True if condition was met, False if timeout
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                if condition_func():
                    return True
            except Exception as e:
                print(f"Condition check for '{description}' failed: {e}")

            await asyncio.sleep(interval)

        print(f"Timeout waiting for {description} after {timeout}s")
        return False

    async def wait_for_deployment_ready(
        self, name: str, namespace: str, timeout: int = 300
    ) -> bool:
        """Wait for a deployment to be ready."""

        def check_deployment():
            try:
                deployment = self.apps_v1.read_namespaced_deployment(
                    name=name, namespace=namespace
                )
                return (
                    deployment.status.ready_replicas
                    and deployment.status.ready_replicas == deployment.spec.replicas
                )
            except ApiException:
                return False

        return await self.wait_for_condition(
            check_deployment,
            timeout=timeout,
            description=f"deployment {name} in {namespace}",
        )

    async def wait_for_pod_ready(
        self, label_selector: str, namespace: str, timeout: int = 300
    ) -> bool:
        """Wait for pods matching selector to be ready."""

        def check_pods():
            try:
                pods = self.core_v1.list_namespaced_pod(
                    namespace=namespace, label_selector=label_selector
                )

                if not pods.items:
                    return False

                for pod in pods.items:
                    if pod.status.phase != "Running":
                        return False

                    if pod.status.container_statuses:
                        for container in pod.status.container_statuses:
                            if not container.ready:
                                return False

                return True
            except ApiException:
                return False

        return await self.wait_for_condition(
            check_pods,
            timeout=timeout,
            description=f"pods with selector {label_selector} in {namespace}",
        )

    async def wait_for_custom_resource(
        self,
        group: str,
        version: str,
        plural: str,
        name: str,
        namespace: str,
        condition_field: str | None = None,
        condition_value: str | None = None,
        timeout: int = 300,
    ) -> bool:
        """
        Wait for a custom resource to exist and optionally meet a condition.

        Args:
            group: API group
            version: API version
            plural: Resource plural name
            name: Resource name
            namespace: Resource namespace
            condition_field: Field path to check (e.g., "status.phase")
            condition_value: Expected value for condition
            timeout: Timeout in seconds
        """

        def check_resource():
            try:
                resource = self.custom_objects.get_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                )

                if not condition_field:
                    return True

                # Navigate to the condition field
                current = resource
                for field in condition_field.split("."):
                    current = current.get(field, {})
                    if not current:
                        return False

                return current == condition_value

            except ApiException:
                return False

        return await self.wait_for_condition(
            check_resource,
            timeout=timeout,
            description=f"custom resource {plural}/{name} in {namespace}",
        )

    async def wait_for_resource_deletion(
        self, resource_type: str, name: str, namespace: str, timeout: int = 300
    ) -> bool:
        """Wait for a resource to be deleted."""

        def check_deleted():
            try:
                if resource_type == "deployment":
                    self.apps_v1.read_namespaced_deployment(
                        name=name, namespace=namespace
                    )
                elif resource_type == "service":
                    self.core_v1.read_namespaced_service(name=name, namespace=namespace)
                elif resource_type == "pod":
                    self.core_v1.read_namespaced_pod(name=name, namespace=namespace)
                else:
                    # Assume it's a custom resource
                    parts = resource_type.split("/")
                    if len(parts) == 3:
                        group, version, plural = parts
                        self.custom_objects.get_namespaced_custom_object(
                            group=group,
                            version=version,
                            namespace=namespace,
                            plural=plural,
                            name=name,
                        )

                return False  # Resource still exists

            except ApiException as e:
                return e.status == 404  # Resource was deleted

        return await self.wait_for_condition(
            check_deleted,
            timeout=timeout,
            description=f"{resource_type} {name} deletion in {namespace}",
        )

    def get_resource_logs(
        self,
        name: str,
        namespace: str,
        container: str | None = None,
        tail_lines: int = 100,
    ) -> str:
        """Get logs from a pod or deployment."""
        try:
            # Try to get pod directly first
            try:
                return self.core_v1.read_namespaced_pod_log(
                    name=name,
                    namespace=namespace,
                    container=container,
                    tail_lines=tail_lines,
                )
            except ApiException:
                pass

            # Try to find pods by deployment
            pods = self.core_v1.list_namespaced_pod(
                namespace=namespace, label_selector=f"app={name}"
            )

            if pods.items:
                pod_name = pods.items[0].metadata.name
                return self.core_v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=namespace,
                    container=container,
                    tail_lines=tail_lines,
                )

            return f"No logs found for {name} in {namespace}"

        except ApiException as e:
            return f"Failed to get logs: {e}"

    def describe_resource(self, resource_type: str, name: str, namespace: str) -> dict:
        """Get detailed information about a resource."""
        try:
            if resource_type == "deployment":
                resource = self.apps_v1.read_namespaced_deployment(
                    name=name, namespace=namespace
                )
            elif resource_type == "service":
                resource = self.core_v1.read_namespaced_service(
                    name=name, namespace=namespace
                )
            elif resource_type == "pod":
                resource = self.core_v1.read_namespaced_pod(
                    name=name, namespace=namespace
                )
            else:
                return {"error": f"Unsupported resource type: {resource_type}"}

            return resource.to_dict()

        except ApiException as e:
            return {"error": f"Failed to describe {resource_type}: {e}"}

    def cleanup_namespace_resources(
        self, namespace: str, resource_types: list | None = None
    ) -> None:
        """Clean up all resources of specified types in a namespace."""
        if resource_types is None:
            resource_types = ["deployments", "services", "secrets", "configmaps"]

        for resource_type in resource_types:
            try:
                if resource_type == "deployments":
                    deployments = self.apps_v1.list_namespaced_deployment(
                        namespace=namespace
                    )
                    for deployment in deployments.items:
                        self.apps_v1.delete_namespaced_deployment(
                            name=deployment.metadata.name, namespace=namespace
                        )

                elif resource_type == "services":
                    services = self.core_v1.list_namespaced_service(namespace=namespace)
                    for service in services.items:
                        if (
                            service.metadata.name != "kubernetes"
                        ):  # Don't delete default service
                            self.core_v1.delete_namespaced_service(
                                name=service.metadata.name, namespace=namespace
                            )

                elif resource_type == "secrets":
                    secrets = self.core_v1.list_namespaced_secret(namespace=namespace)
                    for secret in secrets.items:
                        if not secret.metadata.name.startswith("default-token"):
                            self.core_v1.delete_namespaced_secret(
                                name=secret.metadata.name, namespace=namespace
                            )

                elif resource_type == "configmaps":
                    configmaps = self.core_v1.list_namespaced_config_map(
                        namespace=namespace
                    )
                    for configmap in configmaps.items:
                        self.core_v1.delete_namespaced_config_map(
                            name=configmap.metadata.name, namespace=namespace
                        )

            except ApiException as e:
                print(f"Warning: Failed to cleanup {resource_type} in {namespace}: {e}")


def create_test_resource(
    group: str,
    version: str,
    kind: str,
    plural: str,
    name: str,
    namespace: str,
    spec: dict,
    custom_objects_api: client.CustomObjectsApi,
) -> dict:
    """Create a test custom resource."""
    resource = {
        "apiVersion": f"{group}/{version}",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }

    return custom_objects_api.create_namespaced_custom_object(
        group=group, version=version, namespace=namespace, plural=plural, body=resource
    )


def delete_test_resource(
    group: str,
    version: str,
    plural: str,
    name: str,
    namespace: str,
    custom_objects_api: client.CustomObjectsApi,
) -> None:
    """Delete a test custom resource."""
    try:
        custom_objects_api.delete_namespaced_custom_object(
            group=group, version=version, namespace=namespace, plural=plural, name=name
        )
    except ApiException as e:
        if e.status != 404:  # Ignore not found errors
            raise
