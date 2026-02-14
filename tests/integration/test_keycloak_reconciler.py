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

    @pytest.mark.timeout(
        360
    )  # Allow extra time for Keycloak pod graceful shutdown and finalizers
    async def test_keycloak_instance_lifecycle(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Test complete Keycloak instance lifecycle: create, ready, delete."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-lifecycle-{suffix}"
        namespace = test_keycloak_namespace

        # Get spec with secret copied to target namespace
        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
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
            admin_secret_name = f"{keycloak_name}-admin-credentials"
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

            # Wait for complete deletion (Keycloak pods have graceful termination)
            await wait_for_resource_deleted(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=240,
            )

            # Verify resources were cleaned up
            with pytest.raises(ApiException) as exc_info:
                await k8s_apps_v1.read_namespaced_deployment(deployment_name, namespace)
            assert exc_info.value.status == 404

            with pytest.raises(ApiException) as exc_info:
                await k8s_core_v1.read_namespaced_service(service_name, namespace)
            assert exc_info.value.status == 404

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
        sample_keycloak_spec_factory,
    ) -> None:
        """Test Keycloak instance with custom replica count."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-replicas-{suffix}"
        namespace = test_keycloak_namespace

        # Get spec with secret copied to target namespace
        base_spec = await sample_keycloak_spec_factory(namespace)

        # Modify spec to use 2 replicas
        custom_spec = {**base_spec, "replicas": 2}

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

    @pytest.mark.timeout(180)
    async def test_keycloak_discovery_service_created(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Test that headless discovery service is created for JGroups clustering."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-discovery-{suffix}"
        namespace = test_keycloak_namespace

        # Get spec with secret copied to target namespace
        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
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

            # Verify discovery service was created (headless service for JGroups)
            discovery_service_name = f"{keycloak_name}-discovery"
            discovery_service = await k8s_core_v1.read_namespaced_service(
                discovery_service_name, namespace
            )
            assert discovery_service is not None

            # Verify it's a headless service (clusterIP: None)
            assert discovery_service.spec.cluster_ip == "None"

            # Verify it publishes not-ready addresses (for peer discovery during startup)
            assert discovery_service.spec.publish_not_ready_addresses is True

            # Verify JGroups port 7800 is exposed
            jgroups_port = next(
                (p for p in discovery_service.spec.ports if p.name == "jgroups"),
                None,
            )
            assert jgroups_port is not None
            assert jgroups_port.port == 7800
            assert jgroups_port.target_port == 7800

            # Verify selector matches the Keycloak instance
            assert discovery_service.spec.selector["app"] == "keycloak"
            assert (
                discovery_service.spec.selector[
                    "vriesdemichael.github.io/keycloak-instance"
                ]
                == keycloak_name
            )

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
    async def test_keycloak_jgroups_env_vars_configured(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Test that deployment includes JGroups clustering environment variables."""
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-jgroups-{suffix}"
        namespace = test_keycloak_namespace

        # Get spec with secret copied to target namespace
        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
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

            # Verify deployment has JGroups configuration
            deployment_name = f"{keycloak_name}-keycloak"
            deployment = await k8s_apps_v1.read_namespaced_deployment(
                deployment_name, namespace
            )

            # Get container and env vars
            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify KC_CACHE_STACK is set to kubernetes for TCP-based discovery
            assert "KC_CACHE_STACK" in env_var_dict
            assert env_var_dict["KC_CACHE_STACK"].value == "kubernetes"

            # Verify JAVA_OPTS_APPEND contains JGroups DNS query pointing to discovery service
            assert "JAVA_OPTS_APPEND" in env_var_dict
            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            expected_dns = f"{keycloak_name}-discovery.{namespace}.svc.cluster.local"
            assert f"-Djgroups.dns.query={expected_dns}" in java_opts

            # Verify JGroups port 7800 is exposed in container
            port_names = {p.name: p.container_port for p in container.ports}
            assert "jgroups" in port_names
            assert port_names["jgroups"] == 7800

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    @pytest.mark.timeout(300)  # Allow extra time for 2-replica startup
    async def test_keycloak_clustering_with_multiple_replicas(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        k8s_core_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Test Keycloak clustering works with multiple replicas.

        Verifies that:
        1. Both replicas start successfully
        2. Discovery service has endpoints for both pods
        3. Infinispan cluster is actually formed (via ISPN000094 log message)
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-cluster-{suffix}"
        namespace = test_keycloak_namespace

        # Get spec with secret copied to target namespace
        base_spec = await sample_keycloak_spec_factory(namespace)

        cluster_spec = {**base_spec, "replicas": 2}

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": cluster_spec,
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
                timeout=240,  # 2 replicas need more time
                operator_namespace=operator_namespace,
            )

            # Verify both replicas are ready
            deployment_name = f"{keycloak_name}-keycloak"
            deployment = await k8s_apps_v1.read_namespaced_deployment(
                deployment_name, namespace
            )
            assert deployment.spec.replicas == 2
            assert deployment.status.ready_replicas == 2

            # Verify discovery service exists with correct configuration
            discovery_service_name = f"{keycloak_name}-discovery"
            discovery_service = await k8s_core_v1.read_namespaced_service(
                discovery_service_name, namespace
            )
            assert discovery_service.spec.cluster_ip == "None"

            # Verify the endpoints exist for the discovery service
            # This confirms DNS_PING will be able to discover peers
            endpoints = await k8s_core_v1.read_namespaced_endpoints(
                discovery_service_name, namespace
            )
            # With 2 ready replicas, we should have 2 addresses in the endpoints
            total_addresses = sum(
                len(subset.addresses or []) for subset in (endpoints.subsets or [])
            )
            assert total_addresses == 2, (
                f"Expected 2 endpoint addresses for 2 replicas, got {total_addresses}"
            )

            # Verify Infinispan cluster formation by checking pod logs
            # The ISPN000094 message indicates a cluster view was received with members
            pods = await k8s_core_v1.list_namespaced_pod(
                namespace,
                label_selector=f"vriesdemichael.github.io/keycloak-instance={keycloak_name}",
            )
            assert len(pods.items) == 2, f"Expected 2 pods, got {len(pods.items)}"

            # Check logs from each pod for cluster formation evidence
            cluster_formed = False
            for pod in pods.items:
                logs = await k8s_core_v1.read_namespaced_pod_log(
                    pod.metadata.name, namespace, container="keycloak"
                )
                # ISPN000094 is the Infinispan message for receiving a new cluster view
                # It includes the member count, e.g., "Received new cluster view for channel
                # ISPN: [node1, node2] (2)"
                if "ISPN000094" in logs and "(2)" in logs:
                    cluster_formed = True
                    break

            assert cluster_formed, (
                "Infinispan cluster not formed: ISPN000094 message with 2 members "
                "not found in any pod logs. JGroups DNS_PING may not be working."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
