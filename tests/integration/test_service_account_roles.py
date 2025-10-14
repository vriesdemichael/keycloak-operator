"""Integration tests for Keycloak client service account role mappings."""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestServiceAccountRoles:
    """Test service account role assignment with shared Keycloak instance."""

    @pytest.mark.timeout(
        600
    )  # Uses shared instance (10 minutes for realm+client creation)
    async def test_service_account_realm_roles_assigned(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
        keycloak_port_forward,
    ) -> None:
        """End-to-end verification that realm roles are assigned to service accounts.

        This integration test uses the shared Keycloak instance and requires:
        - Custom realm with specific configuration
        - Realm role creation via API
        - Service account client with role mappings
        - Verification of role assignments
        """

        # Use shared Keycloak instance in operator namespace
        keycloak_name = shared_operator["name"]
        keycloak_namespace = shared_operator["namespace"]

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
        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

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
                    name=f"{realm_name}-realm-auth",  # Created by realm reconciler
                    key="token",
                ),
            ),
            client_id=client_name,
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=[service_account_role],
                client_roles={},
            ),
            settings=KeycloakClientSettings(
                service_accounts_enabled=True,
            ),
        )

        client_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_ready(plural: str, name: str) -> None:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:  # pragma: no cover - integration path
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase == "Ready"

            assert await wait_for_condition(_condition, timeout=420, interval=5), (
                f"Resource {plural}/{name} did not become Ready"
            )

        admin_client = None

        try:
            # Create realm and wait until Ready
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await _wait_resource_ready("keycloakrealms", realm_name)

            # Set up port-forward to shared Keycloak instance
            local_port = await keycloak_port_forward(keycloak_name, keycloak_namespace)

            # Create admin client using localhost (via port-forward)
            from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
            from keycloak_operator.utils.kubernetes import get_admin_credentials

            username, password = get_admin_credentials(
                keycloak_name, keycloak_namespace
            )
            admin_client = KeycloakAdminClient(
                server_url=f"http://localhost:{local_port}",
                username=username,
                password=password,
            )
            admin_client.authenticate()

            role_endpoint = f"{admin_client.server_url}/admin/realms/{realm_name}/roles"
            response = admin_client.session.post(
                role_endpoint,
                json={
                    "name": service_account_role,
                    "description": "integration-test role",
                },
                timeout=admin_client.timeout,
            )
            if response.status_code not in (201, 409):
                pytest.fail(
                    f"Failed to ensure realm role exists: HTTP {response.status_code} {response.text}"
                )

            # Create client and wait until Ready
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            await _wait_resource_ready("keycloakclients", client_name)

            client_repr = admin_client.get_client_by_name(client_name, realm_name)
            assert client_repr, "Client not found in Keycloak"
            assert client_repr.id, "Client missing ID"

            service_account_user = admin_client.get_service_account_user(
                client_repr.id, realm_name
            )
            user_id = service_account_user.id
            assert user_id, "Service account user missing identifier"

            role_mapping_endpoint = f"{admin_client.server_url}/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"
            mapping_response = admin_client.session.get(
                role_mapping_endpoint,
                timeout=admin_client.timeout,
            )
            mapping_response.raise_for_status()
            assigned_roles = {role["name"] for role in mapping_response.json()}

            assert service_account_role in assigned_roles
        finally:
            if admin_client is not None:
                admin_client.session.close()

            # Cleanup resources (client and realm only - shared Keycloak persists)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
