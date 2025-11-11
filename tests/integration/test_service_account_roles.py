"""Integration tests for Keycloak client service account role mappings."""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestServiceAccountRoles:
    """Test service account role assignment with shared Keycloak instance."""

    @pytest.mark.timeout(
        180
    )  # 3 minutes: realm (60s) + client (60s) + role operations (60s)
    async def test_service_account_realm_roles_assigned(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
        admission_token_setup,
    ) -> None:
        """End-to-end verification that realm roles are assigned to service accounts.

        This integration test uses the shared Keycloak instance and requires:
        - Custom realm with specific configuration
        - Realm role creation via API
        - Service account client with role mappings
        - Verification of role assignments
        """

        # Use shared Keycloak instance in operator namespace

        # Create realm and client in test namespace for isolation
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"svc-roles-realm-{suffix}"
        client_name = f"svc-roles-client-{suffix}"
        service_account_role = f"svc-role-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ServiceAccountRoles,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Get admission token from fixture
        admission_secret_name, _ = admission_token_setup

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],  # Grant this namespace access
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
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=[service_account_role], client_roles={}
            ),
            settings=KeycloakClientSettings(service_accounts_enabled=True),
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm and wait until Ready
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=90,
                operator_namespace=operator_namespace,
                allow_degraded=False,
            )

            # Realm is ready - no longer need to wait for authorization secret
            # New grant list authorization doesn't create realm secrets

            # Create realm role using async HTTP call
            role_endpoint = (
                f"{keycloak_admin_client.server_url}/admin/realms/{realm_name}/roles"
            )
            import httpx

            async with httpx.AsyncClient(
                timeout=keycloak_admin_client.timeout
            ) as session:
                headers = {
                    "Authorization": f"Bearer {keycloak_admin_client.access_token}"
                }
                response = await session.post(
                    role_endpoint,
                    json={
                        "name": service_account_role,
                        "description": "integration-test role",
                    },
                    headers=headers,
                )
                if response.status_code not in (201, 409):
                    pytest.fail(
                        f"Failed to ensure realm role exists: HTTP {response.status_code} {response.text}"
                    )

            # Create client and wait until Ready
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
                allow_degraded=False,
            )

            client_repr = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            assert client_repr, "Client not found in Keycloak"
            assert client_repr.id, "Client missing ID"

            service_account_user = await keycloak_admin_client.get_service_account_user(
                client_repr.id, realm_name, namespace
            )
            user_id = service_account_user.id
            assert user_id, "Service account user missing identifier"

            # Check role mappings using async HTTP call
            role_mapping_endpoint = f"{keycloak_admin_client.server_url}/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"
            async with httpx.AsyncClient(
                timeout=keycloak_admin_client.timeout
            ) as session:
                headers = {
                    "Authorization": f"Bearer {keycloak_admin_client.access_token}"
                }
                mapping_response = await session.get(
                    role_mapping_endpoint, headers=headers
                )
                mapping_response.raise_for_status()
                assigned_roles_data = mapping_response.json()
                assigned_roles = {role["name"] for role in assigned_roles_data}

            assert service_account_role in assigned_roles
        finally:
            # No session to close with async client
            pass

            # Cleanup resources (client and realm only - shared Keycloak persists)
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
