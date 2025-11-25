"""
Integration tests for Keycloak instance reconciler.

Tests verify the reconciler correctly manages Keycloak instances:
- Instance creation and readiness
- Database connectivity
- Resource management (deployment, service, ingress)
- Admin credential management
- Production validation
- Instance cleanup and finalizers
"""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_deleted, wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestKeycloakReconciler:
    """Test Keycloak instance reconciler functionality."""

    @pytest.mark.timeout(180)
    async def test_keycloak_instance_lifecycle(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec,
    ) -> None:
        """Test complete Keycloak instance lifecycle: create, ready, delete."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-lifecycle-{suffix}"
        namespace = test_keycloak_namespace

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": sample_keycloak_spec,
        }

        try:
            # CREATE: Deploy Keycloak instance
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # READY: Wait for instance to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=150,  # Keycloak startup can take 60+ seconds
                operator_namespace=operator_namespace,
            )

            # Verify deployment was created
            deployment_name = f"{keycloak_name}-keycloak"
            deployment = await k8s_apps_v1.read_namespaced_deployment(
                deployment_name, namespace
            )
            assert deployment is not None
            assert deployment.status.ready_replicas == 1

            # Verify service was created
            service_name = f"{keycloak_name}-keycloak"
            service = await k8s_core_v1.read_namespaced_service(service_name, namespace)
            assert service is not None
            assert service.spec.type == "ClusterIP"

            # Verify admin secret was created
            admin_secret_name = f"{keycloak_name}-admin"
            admin_secret = await k8s_core_v1.read_namespaced_secret(
                admin_secret_name, namespace
            )
            assert admin_secret is not None
            assert "username" in admin_secret.data
            assert "password" in admin_secret.data

            # Verify CR status
            keycloak_cr = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
            )
            status = keycloak_cr.get("status", {})
            assert status.get("phase") == "Ready"
            assert "endpoints" in status
            assert status["endpoints"].get("admin") is not None
            assert status["endpoints"].get("public") is not None

            # DELETE: Remove instance
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            # Wait for complete deletion
            await wait_for_resource_deleted(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
            )

            # Verify resources were cleaned up
            with pytest.raises(ApiException) as exc_info:
                await k8s_apps_v1.read_namespaced_deployment(deployment_name, namespace)
            assert exc_info.value.status == 404  # type: ignore[attr-defined]

            with pytest.raises(ApiException) as exc_info:
                await k8s_core_v1.read_namespaced_service(service_name, namespace)
            assert exc_info.value.status == 404  # type: ignore[attr-defined]

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    @pytest.mark.timeout(180)
    async def test_keycloak_with_custom_replicas(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec,
    ) -> None:
        """Test Keycloak instance with custom replica count."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-replicas-{suffix}"
        namespace = test_keycloak_namespace

        # Modify spec to use 2 replicas
        custom_spec = {**sample_keycloak_spec, "replicas": 2}

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": custom_spec,
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=150,
                operator_namespace=operator_namespace,
            )

            # Verify deployment has 2 replicas
            deployment_name = f"{keycloak_name}-keycloak"
            deployment = await k8s_apps_v1.read_namespaced_deployment(
                deployment_name, namespace
            )
            assert deployment.spec.replicas == 2

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
