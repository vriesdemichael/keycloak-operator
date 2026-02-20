"""
Integration tests for Default Roles management.

Tests verify the operator correctly manages default roles:
- Configuration of the `default-roles-<realm>` role attributes/description
- Adding legacy role list as composites to default role
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
class TestDefaultRoles:
    """Test default roles management via the operator."""

    @pytest.mark.timeout(300)
    async def test_default_roles(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with default roles configuration."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"def-roles-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            OperatorRef,
        )

        # Define extra roles to be added as defaults
        role1_name = "role-1"
        role2_name = "role-2"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Default Roles Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(name=role1_name),
                    KeycloakRealmRole(name=role2_name),
                ]
            ),
            # Issue #536: Configure default role attributes
            default_role=KeycloakRealmRole(
                name="ignored",  # Name is ignored, it always targets default-roles-<realm>
                description="Custom description for default role",
                attributes={"custom-attr": ["value1"]},
            ),
            # Issue #536: Legacy default roles list (added as composites)
            default_roles=[role1_name, role2_name],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
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

            # Verify Default Role Attributes
            default_role_name = f"default-roles-{realm_name}"
            default_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, default_role_name, namespace
            )
            assert default_role is not None
            assert default_role.description == "Custom description for default role"
            assert default_role.attributes["custom-attr"] == ["value1"]

            # Verify Default Role Composites
            composites = await keycloak_admin_client.get_realm_role_composites(
                realm_name, default_role_name, namespace
            )
            composite_names = {r.name for r in composites}
            assert role1_name in composite_names
            assert role2_name in composite_names
            # offline_access and uma_authorization are default composites, so we expect them too
            assert "offline_access" in composite_names
            assert "uma_authorization" in composite_names

            # 2. Test Updating Default Role
            assert realm_spec.default_role is not None
            realm_spec.default_role.description = "Updated description"
            if realm_spec.default_role.attributes is None:
                realm_spec.default_role.attributes = {}
            realm_spec.default_role.attributes["new-attr"] = ["new-value"]
            realm_spec.default_roles.append(
                "offline_access"
            )  # Should already be there, no change

            realm_manifest["spec"] = realm_spec.model_dump(
                by_alias=True, exclude_unset=True
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

            # Verify Updates
            default_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, default_role_name, namespace
            )
            assert default_role.description == "Updated description"
            assert default_role.attributes["new-attr"] == ["new-value"]

            logger.info("✓ Successfully verified default roles updates")

        finally:
            await delete_custom_resource_with_retry(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
