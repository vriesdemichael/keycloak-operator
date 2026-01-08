"""
End-to-end integration tests for finalizer behavior.

These tests validate that finalizers work correctly in a real Kubernetes
environment, ensuring proper cleanup and preventing resource leaks.
"""

import contextlib

import pytest
from kubernetes.client.rest import ApiException


async def _simple_wait(condition_func, timeout=300, interval=3):
    """Simple wait helper for conditions."""
    import asyncio
    import time

    start = time.time()
    while time.time() - start < timeout:
        if await condition_func():
            return True
        await asyncio.sleep(interval)
    return False


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
        test_namespace,
    ):
        """Test finalizer behavior for Keycloak realm resources using shared instance."""
        import uuid

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Use dedicated test namespace for isolation from other parallel tests
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-realm-finalizer-{suffix}"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture

            # Create realm resource
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm finalizer to be added
            async def check_realm_finalizer():
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "vriesdemichael.github.io/keycloak-operator" in finalizers
                except ApiException:
                    return False

            assert await _simple_wait(check_realm_finalizer, timeout=120), (
                "Realm finalizer was not added"
            )

            # Delete realm resource
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # First, verify K8s accepted the delete (deletionTimestamp is set)
            # This ensures the delete request was processed before we start waiting
            async def check_deletion_timestamp_set():
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    return (
                        resource.get("metadata", {}).get("deletionTimestamp")
                        is not None
                    )
                except ApiException as e:
                    # Already deleted is fine
                    return e.status == 404

            assert await _simple_wait(check_deletion_timestamp_set, timeout=30), (
                "K8s did not set deletionTimestamp on realm"
            )

            # Wait for realm cleanup to complete
            async def check_realm_deleted():
                try:
                    await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    return False
                except ApiException as e:
                    return e.status == 404

            assert await _simple_wait(check_realm_deleted, timeout=120), (
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
        test_namespace,
    ):
        """Test finalizer behavior for Keycloak client resources using shared instance."""
        import uuid

        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Use dedicated test namespace for isolation from other parallel tests
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-client-finalizer-realm-{suffix}"
        client_name = f"test-client-finalizer-{suffix}"

        # Prepare manifests
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[
                namespace
            ],  # Grant client creation in this namespace
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client finalizer to be added
            async def check_client_finalizer():
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "vriesdemichael.github.io/keycloak-operator" in finalizers
                except ApiException:
                    return False

            assert await _simple_wait(check_client_finalizer, timeout=120), (
                "Client finalizer was not added"
            )

            # Delete client resource
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )

            # First, verify K8s accepted the delete (deletionTimestamp is set)
            async def check_client_deletion_timestamp_set():
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    return (
                        resource.get("metadata", {}).get("deletionTimestamp")
                        is not None
                    )
                except ApiException as e:
                    # Already deleted is fine
                    return e.status == 404

            assert await _simple_wait(
                check_client_deletion_timestamp_set, timeout=30
            ), "K8s did not set deletionTimestamp on client"

            # Wait for client cleanup to complete
            async def check_client_deleted():
                try:
                    await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    return False
                except ApiException as e:
                    return e.status == 404

            assert await _simple_wait(check_client_deleted, timeout=120), (
                "Client finalizer cleanup did not complete"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test client finalizer: {e}")

        finally:
            # Cleanup realm only (shared Keycloak managed by fixture, client deleted by test)
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    async def test_cascading_deletion_order(
        self, k8s_custom_objects, test_namespace, operator_namespace, shared_operator
    ):
        """Test that cascading deletion happens when realm is deleted (realm→client).

        Note: We use shared Keycloak which is not deleted during tests.
        """
        import uuid

        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Use shared Keycloak and test realm→client cascading deletion
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-cascade-realm-{suffix}"
        client_name = f"test-cascade-client-{suffix}"

        # Create realm spec
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[
                test_namespace
            ],  # Grant client creation in this namespace
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": test_namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=test_namespace),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": test_namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Shared Keycloak instance is already ready from fixture

            # Create realm and wait for it to become ready
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be ready before creating client
            async def check_realm_ready():
                try:
                    realm = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    status = realm.get("status", {}) or {}
                    return status.get("phase") == "Ready"
                except ApiException:
                    return False

            assert await _simple_wait(check_realm_ready, timeout=60), (
                "Realm did not become ready before cascading deletion test"
            )

            # Create client
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to have finalizer (indicates it's been reconciled)
            async def check_client_has_finalizer():
                try:
                    client = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    meta = client.get("metadata", {})
                    finalizers = meta.get("finalizers", [])
                    return "vriesdemichael.github.io/keycloak-operator" in finalizers
                except ApiException:
                    return False

            assert await _simple_wait(check_client_has_finalizer, timeout=60), (
                "Client finalizer was not added (client not reconciled)"
            )

            # Now delete the realm (should trigger cascading deletion to client)
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Realm and client should eventually be deleted (shared Keycloak persists)
            async def check_all_deleted():
                try:
                    # Check if realm or client still exist
                    for plural, name in [
                        ("keycloakclients", client_name),
                        ("keycloakrealms", realm_name),
                    ]:
                        try:
                            await k8s_custom_objects.get_namespaced_custom_object(
                                group="vriesdemichael.github.io",
                                version="v1",
                                namespace=test_namespace,
                                plural=plural,
                                name=name,
                            )
                            # Resource still exists, not all deleted yet
                            return False
                        except ApiException as e:
                            if e.status != 404:
                                # Error checking resource, can't determine state
                                return False

                    # All resources returned 404, all deleted
                    return True

                except Exception:
                    return False

            assert await _simple_wait(check_all_deleted, timeout=180), (
                "Cascading deletion did not complete within 180s"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test cascading deletion: {e}")

    async def test_cascade_skips_already_deleting_client(
        self, k8s_custom_objects, test_namespace, operator_namespace, shared_operator
    ):
        """Test that cascade deletion skips clients that are already being deleted.

        This verifies the 'skipped_already_deleting' code path in realm cleanup.
        We achieve this by:
        1. Creating a realm and client
        2. Adding an extra finalizer to the client (prevents immediate deletion)
        3. Triggering client deletion (sets deletionTimestamp)
        4. Deleting the realm (cascade logic should skip the already-deleting client)
        5. Removing our extra finalizer to allow client deletion to complete
        """
        import asyncio
        import uuid

        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-skip-deleting-{suffix}"
        client_name = f"test-skip-client-{suffix}"
        test_finalizer = "test.example.com/block-deletion"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[test_namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": test_namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=test_namespace),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": test_namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be ready
            async def check_realm_ready():
                try:
                    realm = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    status = realm.get("status", {}) or {}
                    return status.get("phase") == "Ready"
                except ApiException:
                    return False

            assert await _simple_wait(check_realm_ready, timeout=60), (
                "Realm did not become ready"
            )

            # Create client
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to have its operator finalizer
            async def check_client_has_finalizer():
                try:
                    client = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    finalizers = client.get("metadata", {}).get("finalizers", [])
                    return "vriesdemichael.github.io/keycloak-operator" in finalizers
                except ApiException:
                    return False

            assert await _simple_wait(check_client_has_finalizer, timeout=60), (
                "Client finalizer was not added"
            )

            # Add our test finalizer to block deletion
            client = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
            )
            finalizers = client.get("metadata", {}).get("finalizers", [])
            if test_finalizer not in finalizers:
                finalizers.append(test_finalizer)
                client["metadata"]["finalizers"] = finalizers
                await k8s_custom_objects.patch_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=client_name,
                    body=client,
                )

            # Delete the client (will set deletionTimestamp but won't complete
            # due to our test finalizer)
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
            )

            # Verify deletionTimestamp is set
            async def check_client_has_deletion_timestamp():
                try:
                    client = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    return (
                        client.get("metadata", {}).get("deletionTimestamp") is not None
                    )
                except ApiException as e:
                    return e.status == 404

            assert await _simple_wait(
                check_client_has_deletion_timestamp, timeout=30
            ), "Client deletionTimestamp was not set"

            # Now delete the realm - its cascade logic should see the client
            # already has deletionTimestamp and skip it (the code path we're testing)
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait a bit for realm cleanup to process the cascade logic
            await asyncio.sleep(5)

            # Now remove our test finalizer to allow client deletion to complete
            try:
                client = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
                finalizers = client.get("metadata", {}).get("finalizers", [])
                if test_finalizer in finalizers:
                    finalizers.remove(test_finalizer)
                    client["metadata"]["finalizers"] = finalizers
                    await k8s_custom_objects.patch_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                        body=client,
                    )
            except ApiException as e:
                if e.status != 404:
                    raise

            # Wait for both resources to be fully deleted
            async def check_all_deleted():
                for plural, name in [
                    ("keycloakclients", client_name),
                    ("keycloakrealms", realm_name),
                ]:
                    try:
                        await k8s_custom_objects.get_namespaced_custom_object(
                            group="vriesdemichael.github.io",
                            version="v1",
                            namespace=test_namespace,
                            plural=plural,
                            name=name,
                        )
                        return False
                    except ApiException as e:
                        if e.status != 404:
                            return False
                return True

            assert await _simple_wait(check_all_deleted, timeout=120), (
                "Resources were not fully deleted after removing test finalizer"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test cascade skip already deleting: {e}")

        finally:
            # Cleanup: ensure test finalizer is removed if test failed mid-way
            with contextlib.suppress(ApiException):
                try:
                    client = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    finalizers = client.get("metadata", {}).get("finalizers", [])
                    if test_finalizer in finalizers:
                        finalizers.remove(test_finalizer)
                        client["metadata"]["finalizers"] = finalizers
                        await k8s_custom_objects.patch_namespaced_custom_object(
                            group="vriesdemichael.github.io",
                            version="v1",
                            namespace=test_namespace,
                            plural="keycloakclients",
                            name=client_name,
                            body=client,
                        )
                except ApiException:
                    pass

            # Try to delete resources if they still exist
            for plural, name in [
                ("keycloakclients", client_name),
                ("keycloakrealms", realm_name),
            ]:
                with contextlib.suppress(ApiException):
                    await k8s_custom_objects.delete_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural=plural,
                        name=name,
                    )
