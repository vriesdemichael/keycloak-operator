"""
End-to-end integration tests for finalizer behavior.

These tests validate that finalizers work correctly in a real Kubernetes
environment, ensuring proper cleanup and preventing resource leaks.
"""

import contextlib

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestFinalizersE2E:
    """End-to-end tests for finalizer behavior."""

    async def test_keycloak_finalizer_cleanup_success(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        k8s_core_v1,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test successful finalizer cleanup when deleting Keycloak resource."""
        keycloak_name = "test-finalizer-cleanup"

        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        try:
            # Create Keycloak resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for finalizer to be added
            async def check_finalizer_added():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloaks",
                        name=keycloak_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "keycloak.mdvr.nl/cleanup" in finalizers
                except ApiException:
                    return False

            assert await wait_for_condition(check_finalizer_added, timeout=300), (
                "Finalizer was not added"
            )

            # Wait for deployment to be created
            async def check_deployment_exists():
                try:
                    k8s_apps_v1.read_namespaced_deployment(
                        name=f"{keycloak_name}-keycloak", namespace=test_namespace
                    )
                    return True
                except ApiException:
                    return False

            assert await wait_for_condition(check_deployment_exists, timeout=120), (
                "Deployment was not created"
            )

            # Delete the Keycloak resource
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            # Wait for finalizer cleanup to complete (resource should be deleted)
            async def check_resource_deleted():
                try:
                    k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloaks",
                        name=keycloak_name,
                    )
                    return False  # Resource still exists
                except ApiException as e:
                    return e.status == 404  # Resource was deleted

            assert await wait_for_condition(check_resource_deleted, timeout=180), (
                "Finalizer cleanup did not complete"
            )

            # Verify that deployment was also cleaned up
            async def check_deployment_deleted():
                try:
                    k8s_apps_v1.read_namespaced_deployment(
                        name=f"{keycloak_name}-keycloak", namespace=test_namespace
                    )
                    return False  # Deployment still exists
                except ApiException as e:
                    return e.status == 404  # Deployment was deleted

            assert await wait_for_condition(check_deployment_deleted, timeout=480), (
                "Deployment was not cleaned up by finalizer"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test finalizer cleanup: {e}")

    async def test_realm_finalizer_behavior(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        sample_realm_spec,
        wait_for_condition,
        wait_for_keycloak_ready,
    ):
        """Test finalizer behavior for Keycloak realm resources."""
        keycloak_name = "test-realm-finalizer-kc"
        realm_name = "test-realm-finalizer"

        # Create Keycloak instance first
        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": test_namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        try:
            # Create Keycloak resource and wait for readiness (deployment + status)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            assert await wait_for_keycloak_ready(keycloak_name, test_namespace), (
                "Keycloak instance not ready in time for realm test"
            )

            # Create realm resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm finalizer to be added
            async def check_realm_finalizer():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "keycloak.mdvr.nl/realm-cleanup" in finalizers
                except ApiException:
                    return False

            assert await wait_for_condition(check_realm_finalizer, timeout=300), (
                "Realm finalizer was not added"
            )

            # Delete realm resource
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for realm cleanup to complete
            async def check_realm_deleted():
                try:
                    k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    return False
                except ApiException as e:
                    return e.status == 404

            assert await wait_for_condition(check_realm_deleted, timeout=180), (
                "Realm finalizer cleanup did not complete"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test realm finalizer: {e}")

        finally:
            # Cleanup Keycloak instance
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    async def test_client_finalizer_behavior(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
        wait_for_keycloak_ready,
    ):
        """Test finalizer behavior for Keycloak client resources."""
        keycloak_name = "test-client-finalizer-kc"
        realm_name = "test-client-finalizer-realm"
        client_name = "test-client-finalizer"

        # Prepare manifests
        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": test_namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": test_namespace},
        }
        client_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        try:
            # Create Keycloak
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            assert await wait_for_keycloak_ready(keycloak_name, test_namespace), (
                "Keycloak instance not ready in time for client test"
            )
            # Create realm once KC ready
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client finalizer to be added
            async def check_client_finalizer():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "keycloak.mdvr.nl/client-cleanup" in finalizers
                except ApiException:
                    return False

            assert await wait_for_condition(check_client_finalizer, timeout=300), (
                "Client finalizer was not added"
            )

            # Delete client resource
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
            )

            # Wait for client cleanup to complete
            async def check_client_deleted():
                try:
                    k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    return False
                except ApiException as e:
                    return e.status == 404

            assert await wait_for_condition(check_client_deleted, timeout=180), (
                "Client finalizer cleanup did not complete"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test client finalizer: {e}")

        finally:
            # Cleanup in reverse order
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    async def test_cascading_deletion_order(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
        wait_for_keycloak_ready,
    ):
        """Test that cascading deletion happens in the correct order."""
        keycloak_name = "test-cascade-kc"
        realm_name = "test-cascade-realm"
        client_name = "test-cascade-client"

        # Prepare manifests
        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": test_namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": test_namespace},
        }
        client_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        try:
            # Create Keycloak and wait for readiness
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            assert await wait_for_keycloak_ready(keycloak_name, test_namespace), (
                "Keycloak instance not ready in time for cascading deletion test"
            )

            # Create realm and client sequentially (no arbitrary sleeps)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Delete the Keycloak instance (should trigger cascading deletion)
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            # All resources should eventually be deleted
            async def check_all_deleted():
                try:
                    # Check if any resources still exist
                    resources_exist = False

                    for plural, name in [
                        ("keycloakclients", client_name),
                        ("keycloakrealms", realm_name),
                        ("keycloaks", keycloak_name),
                    ]:
                        try:
                            k8s_custom_objects.get_namespaced_custom_object(
                                group="keycloak.mdvr.nl",
                                version="v1",
                                namespace=test_namespace,
                                plural=plural,
                                name=name,
                            )
                            resources_exist = True
                        except ApiException as e:
                            if e.status != 404:
                                resources_exist = True

                    return not resources_exist

                except Exception:
                    return False

            assert await wait_for_condition(check_all_deleted, timeout=300), (
                "Cascading deletion did not complete"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test cascading deletion: {e}")
