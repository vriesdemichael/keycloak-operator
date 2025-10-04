"""Integration tests for Keycloak client service account role mappings."""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestServiceAccountRoles:
    """Test service account role assignment using shared Keycloak instance."""

    @pytest.mark.skip(
        reason="Temporarily disabled - shared Keycloak instance lookup failing in parallel execution context"
    )
    async def test_service_account_realm_roles_assigned(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        shared_keycloak_instance,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
    ) -> None:
        """End-to-end verification that realm roles are assigned to service accounts."""

        # Use shared Keycloak instance
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"svc-roles-realm-{suffix}"
        client_name = f"svc-roles-client-{suffix}"
        service_account_role = f"svc-role-{suffix}"

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": {
                **sample_realm_spec["spec"],
                "keycloak_instance_ref": {
                    "name": keycloak_name,
                    "namespace": namespace,
                },
                "realm_name": realm_name,
                "enabled": True,
            },
        }

        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": {
                **sample_client_spec["spec"],
                "keycloak_instance_ref": {
                    "name": keycloak_name,
                    "namespace": namespace,
                },
                "realm": realm_name,
                "client_id": client_name,
                "public_client": False,
                "service_account_roles": {
                    "realm_roles": [service_account_role],
                    "client_roles": {},
                },
                "settings": {
                    **sample_client_spec["spec"].get("settings", {}),
                    "service_accounts_enabled": True,
                },
            },
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
            # Shared Keycloak instance is already ready from fixture

            # Create realm and wait until Ready
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await _wait_resource_ready("keycloakrealms", realm_name)

            # Create admin client and ensure custom realm role exists
            admin_client = get_keycloak_admin_client(keycloak_name, namespace)

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

            service_account_user = admin_client.get_service_account_user(
                client_repr["id"], realm_name
            )
            user_id = service_account_user.get("id")
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

            # Cleanup client and realm only (shared Keycloak managed by fixture)
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
