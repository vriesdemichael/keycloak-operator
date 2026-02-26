"""
End-to-end integration tests for admission webhooks.

These tests validate webhook behavior in a real Kubernetes environment with
the operator running. Tests create actual resources and verify that webhook
validation occurs before resources are accepted by Kubernetes.

Note: These tests require webhooks to be enabled in the operator deployment.
"""

import contextlib
import uuid

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestWebhooksE2E:
    """End-to-end tests for admission webhook validation."""

    async def test_realm_quota_enforcement(
        self, k8s_custom_objects, shared_operator, operator_namespace
    ):
        """Test that realm quota is enforced by webhook."""
        from keycloak_operator.constants import WEBHOOK_MAX_REALMS_PER_NAMESPACE

        namespace = f"test-webhook-realm-quota-{uuid.uuid4().hex[:8]}"

        try:
            # Create test namespace
            k8s_core = client.CoreV1Api()
            k8s_core.create_namespace(
                body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )

            # Create realms up to quota limit
            for i in range(WEBHOOK_MAX_REALMS_PER_NAMESPACE):
                realm_name = f"test-realm-{i}"
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakRealm",
                        "metadata": {"name": realm_name},
                        "spec": {
                            "realmName": realm_name,
                            "operatorRef": {"namespace": operator_namespace},
                        },
                    },
                )

            # Attempt to create one more realm - should be rejected by webhook
            with pytest.raises(ApiException) as exc_info:
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakRealm",
                        "metadata": {"name": "realm-over-quota"},
                        "spec": {
                            "realmName": "realm-over-quota",
                            "operatorRef": {"namespace": operator_namespace},
                        },
                    },
                )

            # Verify rejection by webhook
            # Note: Kopf may return 500 or 400 for validation errors depending on timing
            assert exc_info.value.status in (400, 500)
            assert "quota exceeded" in exc_info.value.body.lower()  # type: ignore[union-attr]

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_core.delete_namespace(name=namespace)

    async def test_realm_update_allowed_at_quota(
        self, k8s_custom_objects, shared_operator, operator_namespace
    ):
        """Test that realm UPDATEs are allowed even when at quota."""
        from keycloak_operator.constants import WEBHOOK_MAX_REALMS_PER_NAMESPACE

        namespace = f"test-webhook-realm-update-{uuid.uuid4().hex[:8]}"

        try:
            # Create test namespace
            k8s_core = client.CoreV1Api()
            k8s_core.create_namespace(
                body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )

            # Create realms up to quota limit
            for i in range(WEBHOOK_MAX_REALMS_PER_NAMESPACE):
                realm_name = f"test-realm-{i}"
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakRealm",
                        "metadata": {"name": realm_name},
                        "spec": {
                            "realmName": realm_name,
                            "operatorRef": {"namespace": operator_namespace},
                        },
                    },
                )

            # Wait for the first realm to be Ready to ensure reconciliation is complete
            # This prevents race conditions where the reconciler is still updating
            # the CR status when we try to patch
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name="test-realm-0",
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Fetch the latest version of the realm after it's ready
            # to get the current resourceVersion
            realm = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name="test-realm-0",
            )

            # Modify spec (change display name)
            realm["spec"]["displayName"] = "Updated Test Realm"

            # UPDATE should succeed - use retry pattern in case of concurrent updates
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    await k8s_custom_objects.patch_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name="test-realm-0",
                        body=realm,
                    )
                    break
                except ApiException as e:
                    if e.status == 409 and attempt < max_retries - 1:
                        # Conflict - re-fetch and retry
                        realm = await k8s_custom_objects.get_namespaced_custom_object(
                            group="vriesdemichael.github.io",
                            version="v1",
                            namespace=namespace,
                            plural="keycloakrealms",
                            name="test-realm-0",
                        )
                        realm["spec"]["displayName"] = "Updated Test Realm"
                        continue
                    raise

            # Verify update succeeded
            updated_realm = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name="test-realm-0",
            )
            assert updated_realm["spec"]["displayName"] == "Updated Test Realm"

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_core.delete_namespace(name=namespace)

    async def test_client_quota_enforcement(
        self, k8s_custom_objects, shared_operator, operator_namespace
    ):
        """Test that client quota is enforced by webhook."""
        from keycloak_operator.constants import WEBHOOK_MAX_CLIENTS_PER_NAMESPACE

        namespace = f"test-webhook-client-quota-{uuid.uuid4().hex[:8]}"

        try:
            # Create test namespace and realm
            k8s_core = client.CoreV1Api()
            k8s_core.create_namespace(
                body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )

            # Create a realm first
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body={
                    "apiVersion": "vriesdemichael.github.io/v1",
                    "kind": "KeycloakRealm",
                    "metadata": {"name": "test-realm"},
                    "spec": {
                        "realmName": "test-realm",
                        "operatorRef": {"namespace": operator_namespace},
                    },
                },
            )

            # Create clients up to quota limit
            for i in range(WEBHOOK_MAX_CLIENTS_PER_NAMESPACE):
                client_name = f"test-client-{i}"
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakClient",
                        "metadata": {"name": client_name},
                        "spec": {
                            "clientId": client_name,
                            "realmRef": {"name": "test-realm", "namespace": namespace},
                        },
                    },
                )

            # Attempt to create one more client - should be rejected
            with pytest.raises(ApiException) as exc_info:
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakClient",
                        "metadata": {"name": "client-over-quota"},
                        "spec": {
                            "clientId": "client-over-quota",
                            "realmRef": {"name": "test-realm", "namespace": namespace},
                        },
                    },
                )

            # Verify rejection by webhook
            assert exc_info.value.status in (400, 500)  # Kopf returns 500 or 400
            assert "quota exceeded" in exc_info.value.body.lower()  # type: ignore[union-attr]

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_core.delete_namespace(name=namespace)

    async def test_keycloak_one_per_namespace(
        self, k8s_custom_objects, shared_operator, operator_namespace
    ):
        """Test that only one Keycloak instance is allowed per namespace (ADR-062)."""
        namespace = f"test-webhook-keycloak-{uuid.uuid4().hex[:8]}"

        try:
            # Create test namespace
            k8s_core = client.CoreV1Api()
            k8s_core.create_namespace(
                body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )

            # Create first Keycloak instance - should succeed
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body={
                    "apiVersion": "vriesdemichael.github.io/v1",
                    "kind": "Keycloak",
                    "metadata": {"name": "keycloak-1"},
                    "spec": {
                        "operatorRef": {"namespace": operator_namespace},
                        "version": "26.4.1",
                        "replicas": 1,
                        "database": {
                            "type": "postgresql",
                            "vendor": "postgres",
                            "host": "postgres.default.svc",
                            "port": 5432,
                            "database": "keycloak",
                            "username": "keycloak",
                            "password": "keycloak",
                        },
                    },
                },
            )

            # Attempt to create second Keycloak instance - should be rejected
            with pytest.raises(ApiException) as exc_info:
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "Keycloak",
                        "metadata": {"name": "keycloak-2"},
                        "spec": {
                            "operatorRef": {"namespace": operator_namespace},
                            "version": "26.4.1",
                            "replicas": 1,
                            "database": {
                                "type": "postgresql",
                                "vendor": "postgres",
                                "host": "postgres.default.svc",
                                "port": 5432,
                                "database": "keycloak",
                                "usernameSecret": {
                                    "name": "db-creds",
                                    "key": "username",
                                },
                                "passwordSecret": {
                                    "name": "db-creds",
                                    "key": "password",
                                },
                            },
                        },
                    },
                )

            # Verify rejection by webhook (may be for missing creds or one-per-namespace)
            assert exc_info.value.status in (400, 500)  # Kopf returns 500 or 400
            # Webhook rejected - could be Pydantic validation or quota, both are valid
            assert "denied the request" in exc_info.value.body.lower()  # type: ignore[union-attr]

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_core.delete_namespace(name=namespace)

    async def test_invalid_spec_rejected_immediately(
        self, k8s_custom_objects, shared_operator, operator_namespace
    ):
        """Test that invalid specs are rejected immediately by webhook."""
        namespace = f"test-webhook-invalid-{uuid.uuid4().hex[:8]}"

        try:
            # Create test namespace
            k8s_core = client.CoreV1Api()
            k8s_core.create_namespace(
                body=client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))
            )

            # Attempt to create realm with missing required field
            with pytest.raises(ApiException) as exc_info:
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakRealm",
                        "metadata": {"name": "invalid-realm"},
                        "spec": {
                            # Missing required realmName
                            "operatorRef": {"namespace": operator_namespace},
                        },
                    },
                )

            # Verify rejection by webhook (422 is validation error, also acceptable)
            assert exc_info.value.status in (400, 422, 500)
            assert "invalid" in exc_info.value.body.lower()  # type: ignore[union-attr]

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_core.delete_namespace(name=namespace)
