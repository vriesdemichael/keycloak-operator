"""Integration tests for namespace grant list authorization."""

from __future__ import annotations

import contextlib
import uuid

import pytest

from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

from .wait_helpers import wait_for_resource_condition, wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestGrantListAuthorization:
    """Test namespace grant list authorization end-to-end."""

    @pytest.mark.timeout(300)
    async def test_client_authorized_via_grant_list(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Test client creation succeeds when namespace is in grant list."""

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"grant-realm-{suffix}"
        client_namespace = test_namespace

        # Create realm with grant list including client namespace
        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(namespace=operator_namespace),
            client_authorization_grants=[
                client_namespace
            ],  # Authorize client namespace
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": client_namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be ready
            await wait_for_resource_ready(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakrealms",
                namespace=client_namespace,
                name=realm_name,
                timeout=180,
            )

            # Verify authorized namespaces in status
            realm = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm.get("status", {})
            authorized_ns = status.get("authorizedClientNamespaces", [])
            assert (
                client_namespace in authorized_ns
            ), f"Namespace {client_namespace} should be in authorized list"

            # Create client in authorized namespace
            client_name = f"test-client-{suffix}"
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=client_namespace),
                client_id=client_name,
                public_client=True,
            )

            client_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": client_namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to be ready
            await wait_for_resource_ready(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakclients",
                namespace=client_namespace,
                name=client_name,
                timeout=120,
            )

            # Verify authorization status
            client = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakclients",
                name=client_name,
            )
            client_status = client.get("status", {})
            assert (
                client_status.get("authorizationGranted") is True
            ), "Client should be authorized"
            assert (
                client_status.get("phase") == "Ready"
            ), f"Client should be Ready, got: {client_status.get('phase')}"

        finally:
            # Cleanup
            with contextlib.suppress(Exception):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=client_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )

            with contextlib.suppress(Exception):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=client_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_client_rejected_not_in_grant_list(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Test client creation fails when namespace is NOT in grant list."""

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"restricted-realm-{suffix}"
        client_namespace = test_namespace

        # Create realm with empty grant list (no namespaces authorized)
        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(namespace=operator_namespace),
            client_authorization_grants=[],  # No namespaces authorized
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": client_namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be ready
            await wait_for_resource_ready(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakrealms",
                namespace=client_namespace,
                name=realm_name,
                timeout=180,
            )

            # Try to create client (should fail authorization)
            client_name = f"unauthorized-client-{suffix}"
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=client_namespace),
                client_id=client_name,
                public_client=True,
            )

            client_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": client_namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to fail with authorization error
            await wait_for_resource_condition(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakclients",
                namespace=client_namespace,
                name=client_name,
                condition_func=lambda res: res.get("status", {}).get("phase")
                == "Failed",
                timeout=60,
            )

            # Verify authorization denial
            client = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=client_namespace,
                plural="keycloakclients",
                name=client_name,
            )
            client_status = client.get("status", {})
            assert (
                client_status.get("phase") == "Failed"
            ), "Client should be in Failed phase"
            assert (
                "not authorized" in client_status.get("message", "").lower()
            ), "Error message should mention authorization failure"

        finally:
            # Cleanup
            with contextlib.suppress(Exception):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=client_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )

            with contextlib.suppress(Exception):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=client_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
