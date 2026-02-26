"""
Integration tests for Scope Mappings management.

Tests verify the operator correctly manages scope mappings:
- Realm role scope mappings (Realm Role -> Client Scope)
- Realm role scope mappings (Realm Role -> Client)
- Client role scope mappings (Client Role -> Client Scope)
"""

from __future__ import annotations

import logging
import uuid

import pytest

from .cleanup_utils import delete_custom_resource_with_retry
from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_ready,
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestScopeMappings:
    """Test scope mappings management via the operator."""

    @pytest.mark.timeout(300)
    async def test_scope_mappings(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with various scope mappings."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"scope-maps-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.keycloak_api import ClientRepresentation
        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            KeycloakScopeMapping,
            OperatorRef,
        )

        # Define roles
        realm_role_name = "realm-role-1"
        client_role_name = "client-role-1"

        # Define client scope
        scope_name = "test-scope"

        # Define target client
        target_client_id = "target-client"

        # Define source client (role container)
        source_client_id = "source-client"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Scope Mappings Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(name=realm_role_name),
                ]
            ),
            client_scopes=[
                KeycloakClientScope(name=scope_name, protocol="openid-connect"),
            ],
            scope_mappings=[
                # Map realm role to client scope
                KeycloakScopeMapping(clientScope=scope_name, roles=[realm_role_name]),
                # Map realm role to client (direct)
                KeycloakScopeMapping(client=target_client_id, roles=[realm_role_name]),
            ],
            client_scope_mappings={
                source_client_id: [
                    # Map client role to client scope
                    KeycloakScopeMapping(
                        clientScope=scope_name, roles=[client_role_name]
                    ),
                    # Map client role to client (direct)
                    KeycloakScopeMapping(
                        client=target_client_id, roles=[client_role_name]
                    ),
                ]
            },
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_none=True),
        }

        try:
            # 1. Create the realm first
            initial_spec = realm_spec.model_copy()
            initial_spec.scope_mappings = []
            initial_spec.client_scope_mappings = {}

            realm_manifest["spec"] = initial_spec.model_dump(
                by_alias=True, exclude_none=True
            )

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
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # 2. Create the clients via API
            target_client = ClientRepresentation(
                clientId=target_client_id, enabled=True
            )
            await keycloak_admin_client.create_client(
                target_client, realm_name, namespace
            )

            source_client = ClientRepresentation(
                clientId=source_client_id, enabled=True
            )
            source_uuid = await keycloak_admin_client.create_client(
                source_client, realm_name, namespace
            )

            # Create client role
            from keycloak_operator.models.keycloak_api import RoleRepresentation

            await keycloak_admin_client.create_client_role(
                source_uuid,
                RoleRepresentation(name=client_role_name),
                realm_name,
                namespace,
            )

            # 3. Update the Realm CR with scope mappings
            realm_manifest["spec"] = realm_spec.model_dump(
                by_alias=True, exclude_none=True
            )

            updated_cr = await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=realm_manifest,
            )
            new_generation = updated_cr.get("metadata", {}).get("generation")

            # Wait for reconciliation
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=new_generation,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # 4. Verify Scope Mappings
            scope_mappings = await keycloak_admin_client.get_scope_mappings_realm_roles(
                realm_name,
                client_scope_id=(
                    await keycloak_admin_client.get_client_scope_by_name(
                        realm_name, scope_name, namespace
                    )
                ).id,
                namespace=namespace,
            )
            assert any(r.name == realm_role_name for r in scope_mappings)

            target_uuid = await keycloak_admin_client.get_client_uuid(
                target_client_id, realm_name, namespace
            )
            scope_mappings = await keycloak_admin_client.get_scope_mappings_realm_roles(
                realm_name, client_id=target_uuid, namespace=namespace
            )
            assert any(r.name == realm_role_name for r in scope_mappings)

            scope_mappings = (
                await keycloak_admin_client.get_scope_mappings_client_roles(
                    realm_name,
                    role_container_id=source_uuid,
                    client_scope_id=(
                        await keycloak_admin_client.get_client_scope_by_name(
                            realm_name, scope_name, namespace
                        )
                    ).id,
                    namespace=namespace,
                )
            )
            assert any(r.name == client_role_name for r in scope_mappings)

            scope_mappings = (
                await keycloak_admin_client.get_scope_mappings_client_roles(
                    realm_name,
                    role_container_id=source_uuid,
                    client_id=target_uuid,
                    namespace=namespace,
                )
            )
            assert any(r.name == client_role_name for r in scope_mappings)

            # 5. Test Updating Scope Mappings (Additive)
            realm_role_2_name = "realm-role-2"
            realm_role_3_name = "realm-role-3"
            assert realm_spec.roles is not None
            assert realm_spec.roles.realm_roles is not None
            realm_spec.roles.realm_roles.append(
                KeycloakRealmRole(name=realm_role_2_name)
            )
            realm_spec.roles.realm_roles.append(
                KeycloakRealmRole(name=realm_role_3_name)
            )

            realm_spec.scope_mappings.append(
                KeycloakScopeMapping(
                    clientScope=scope_name, roles=[realm_role_2_name, realm_role_3_name]
                )
            )

            realm_manifest["spec"] = realm_spec.model_dump(
                by_alias=True, exclude_none=True
            )

            updated_cr = await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=realm_manifest,
            )
            new_generation = updated_cr.get("metadata", {}).get("generation")

            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=new_generation,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Verify both roles are now mapped
            scope_mappings = await keycloak_admin_client.get_scope_mappings_realm_roles(
                realm_name,
                client_scope_id=(
                    await keycloak_admin_client.get_client_scope_by_name(
                        realm_name, scope_name, namespace
                    )
                ).id,
                namespace=namespace,
            )
            mapped_names = {r.name for r in scope_mappings}
            assert realm_role_name in mapped_names
            assert realm_role_2_name in mapped_names
            assert realm_role_3_name in mapped_names

            logger.info("✓ Successfully verified scope mappings updates")

        finally:
            await delete_custom_resource_with_retry(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
