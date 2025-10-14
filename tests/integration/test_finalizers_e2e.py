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
    """End-to-end tests for finalizer behavior.

    Note: Tests use shared Keycloak instance (1-1 operator-Keycloak coupling).
    Keycloak finalizer cleanup is not tested as the instance is never deleted.
    Focus is on dynamic resources: Realms and Clients.
    """

    async def test_realm_finalizer_behavior(
        self,
        k8s_custom_objects,
        shared_operator,
        operator_namespace,
        sample_realm_spec,
        wait_for_condition,
    ):
        """Test finalizer behavior for Keycloak realm resources using shared instance."""
        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        namespace = shared_operator["namespace"]
        realm_name = "test-realm-finalizer"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
                    key="token",
                ),
            ),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture

            # Create realm resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm finalizer to be added
            async def check_realm_finalizer():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
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
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for realm cleanup to complete
            async def check_realm_deleted():
                try:
                    k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
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

    async def test_client_finalizer_behavior(
        self,
        k8s_custom_objects,
        shared_operator,
        operator_namespace,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
    ):
        """Test finalizer behavior for Keycloak client resources using shared instance."""
        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        namespace = shared_operator["namespace"]
        realm_name = "test-client-finalizer-realm"
        client_name = "test-client-finalizer"

        # Prepare manifests
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
                    key="token",
                ),
            ),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(
                name=realm_name,
                namespace=namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=f"{realm_name}-auth-token",
                    key="token",
                ),
            ),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture
            # Create realm
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client finalizer to be added
            async def check_client_finalizer():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
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
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )

            # Wait for client cleanup to complete
            async def check_client_deleted():
                try:
                    k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
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
            # Cleanup realm only (shared Keycloak managed by fixture, client deleted by test)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    async def test_cascading_deletion_order(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
    ):
        """Test that cascading deletion happens when realm is deleted (realm→client).

        Note: We use shared Keycloak which is not deleted during tests.
        """
        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Use shared Keycloak and test realm→client cascading deletion
        realm_name = "test-cascade-realm"
        client_name = "test-cascade-client"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
                    key="token",
                ),
            ),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": test_namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(
                name=realm_name,
                namespace=test_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=f"{realm_name}-realm-auth",  # Fixed: correct secret name pattern
                    key="token",
                ),
            ),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": test_namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture

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

            # Delete the realm (should trigger cascading deletion to client)
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Realm and client should eventually be deleted (shared Keycloak persists)
            async def check_all_deleted():
                try:
                    # Check if realm or client still exist
                    resources_exist = False

                    for plural, name in [
                        ("keycloakclients", client_name),
                        ("keycloakrealms", realm_name),
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
