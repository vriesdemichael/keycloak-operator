"""
Integration tests for client authorization services.

Tests verify the operator correctly manages authorization:
- Authorization settings on clients
- Scopes, resources, policies, and permissions
- Full reconciliation of authorization configuration
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_resource_deleted,
    wait_for_resource_ready,
)

logger = logging.getLogger(__name__)


async def _simple_wait(condition_func, timeout=60, interval=2):
    """Simple wait helper for conditions with retry."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            if await condition_func():
                return True
        except Exception:
            pass  # Retry on any error
        await asyncio.sleep(interval)
    return False


async def _cleanup_resource(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 60,
) -> None:
    """Helper to delete a resource and wait for deletion to complete."""
    with contextlib.suppress(ApiException):
        await k8s_custom_objects.delete_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
        )
    # Wait for resource to be fully deleted (ignore if already gone)
    with contextlib.suppress(Exception):
        await wait_for_resource_deleted(
            k8s_custom_objects=k8s_custom_objects,
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
            timeout=timeout,
        )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientAuthorization:
    """Test client authorization management via the operator."""

    @pytest.mark.timeout(300)
    async def test_client_with_authorization_services(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a client with authorization services enabled.

        This test verifies that:
        - A client can be created with authorization services enabled
        - Authorization scopes are created
        - Authorization resources are created with scope associations
        - Role policies are created
        - Resource permissions are created
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"authz-test-{suffix}"
        client_name = f"authz-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            AuthorizationPermissions,
            AuthorizationPolicies,
            AuthorizationResource,
            AuthorizationScope,
            AuthorizationSettings,
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ResourcePermission,
            RolePolicy,
            RolePolicyRole,
        )
        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
        )

        # First create a realm
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Authorization Test Realm",
            client_authorization_grants=[namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Create client with authorization settings
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            client_name="Authorization Test Client",
            public_client=False,
            settings=KeycloakClientSettings(
                authorization_services_enabled=True,
                service_accounts_enabled=True,
            ),
            authorization_settings=AuthorizationSettings(
                policy_enforcement_mode="ENFORCING",
                decision_strategy="UNANIMOUS",
                scopes=[
                    AuthorizationScope(name="read", display_name="Read Access"),
                    AuthorizationScope(name="write", display_name="Write Access"),
                    AuthorizationScope(name="delete", display_name="Delete Access"),
                ],
                resources=[
                    AuthorizationResource(
                        name="documents",
                        display_name="Document Resources",
                        uris=["/api/documents/*"],
                        scopes=["read", "write", "delete"],
                    ),
                    AuthorizationResource(
                        name="reports",
                        display_name="Report Resources",
                        uris=["/api/reports/*"],
                        scopes=["read"],
                    ),
                ],
                policies=AuthorizationPolicies(
                    role_policies=[
                        RolePolicy(
                            name="admin-policy",
                            description="Policy for administrators",
                            logic="POSITIVE",
                            roles=[
                                RolePolicyRole(name="admin", required=False),
                            ],
                        ),
                        RolePolicy(
                            name="viewer-policy",
                            description="Policy for viewers",
                            logic="POSITIVE",
                            roles=[
                                RolePolicyRole(name="viewer", required=False),
                            ],
                        ),
                    ],
                ),
                permissions=AuthorizationPermissions(
                    resource_permissions=[
                        ResourcePermission(
                            name="admin-documents-permission",
                            description="Admins can manage documents",
                            resources=["documents"],
                            policies=["admin-policy"],
                            decision_strategy="UNANIMOUS",
                        ),
                        ResourcePermission(
                            name="viewer-reports-permission",
                            description="Viewers can read reports",
                            resources=["reports"],
                            policies=["viewer-policy"],
                            decision_strategy="AFFIRMATIVE",
                        ),
                    ],
                ),
            ),
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm first
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name}")

            # Wait for realm to become ready
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

            # Now create the client with authorization
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            logger.info(f"Created client CR: {client_name} with authorization")

            # Wait for client to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Verify client exists with authorization enabled
            client_repr = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            assert client_repr is not None, f"Client {client_name} should exist"
            assert client_repr.authorization_services_enabled is True, (
                "Authorization services should be enabled"
            )
            assert client_repr.service_accounts_enabled is True, (
                "Service accounts should be enabled"
            )

            # Get client UUID for authorization queries
            client_uuid = client_repr.id
            assert client_uuid is not None

            # Verify scopes were created
            scopes = await keycloak_admin_client.get_authorization_scopes(
                realm_name, client_uuid, namespace
            )
            scope_names = {s.get("name") for s in scopes}
            assert "read" in scope_names, "read scope should exist"
            assert "write" in scope_names, "write scope should exist"
            assert "delete" in scope_names, "delete scope should exist"
            logger.info(f"✓ Verified {len(scopes)} authorization scopes")

            # Verify resources were created
            resources = await keycloak_admin_client.get_authorization_resources(
                realm_name, client_uuid, namespace
            )
            resource_names = {r.get("name") for r in resources}
            assert "documents" in resource_names, "documents resource should exist"
            assert "reports" in resource_names, "reports resource should exist"

            # Verify resource has correct scopes
            documents_resource = next(
                (r for r in resources if r.get("name") == "documents"), None
            )
            assert documents_resource is not None
            doc_scope_names = {
                s.get("name") for s in documents_resource.get("scopes", [])
            }
            assert "read" in doc_scope_names, "documents should have read scope"
            assert "write" in doc_scope_names, "documents should have write scope"
            assert "delete" in doc_scope_names, "documents should have delete scope"
            logger.info(f"✓ Verified {len(resources)} authorization resources")

            # Verify policies were created
            policies = await keycloak_admin_client.get_authorization_policies(
                realm_name, client_uuid, namespace
            )
            policy_names = {p.get("name") for p in policies}
            assert "admin-policy" in policy_names, "admin-policy should exist"
            assert "viewer-policy" in policy_names, "viewer-policy should exist"
            logger.info(f"✓ Verified {len(policies)} authorization policies")

            # Verify permissions were created
            permissions = await keycloak_admin_client.get_authorization_permissions(
                realm_name, client_uuid, namespace
            )
            perm_names = {p.get("name") for p in permissions}
            assert "admin-documents-permission" in perm_names, (
                "admin-documents-permission should exist"
            )
            assert "viewer-reports-permission" in perm_names, (
                "viewer-reports-permission should exist"
            )
            logger.info(f"✓ Verified {len(permissions)} authorization permissions")

            logger.info("✓ Successfully verified complete authorization configuration")

        finally:
            # Cleanup client first, then realm
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(300)
    async def test_authorization_scope_permission(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a client with scope-based permissions.

        This test verifies that:
        - Scope permissions can be created
        - Scope permissions correctly reference scopes and policies
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"scope-perm-{suffix}"
        client_name = f"scope-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            AuthorizationPermissions,
            AuthorizationPolicies,
            AuthorizationResource,
            AuthorizationScope,
            AuthorizationSettings,
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            RolePolicy,
            RolePolicyRole,
            ScopePermission,
        )
        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
        )

        # First create a realm
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Scope Permission Test Realm",
            client_authorization_grants=[namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Create client with scope permissions
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            client_name="Scope Permission Test Client",
            public_client=False,
            settings=KeycloakClientSettings(
                authorization_services_enabled=True,
                service_accounts_enabled=True,
            ),
            authorization_settings=AuthorizationSettings(
                policy_enforcement_mode="ENFORCING",
                scopes=[
                    AuthorizationScope(name="view"),
                    AuthorizationScope(name="edit"),
                ],
                resources=[
                    AuthorizationResource(
                        name="profile",
                        uris=["/api/profile"],
                        scopes=["view", "edit"],
                    ),
                ],
                policies=AuthorizationPolicies(
                    role_policies=[
                        RolePolicy(
                            name="user-policy",
                            roles=[RolePolicyRole(name="user")],
                        ),
                    ],
                ),
                permissions=AuthorizationPermissions(
                    scope_permissions=[
                        ScopePermission(
                            name="view-profile-permission",
                            description="Users can view their profile",
                            scopes=["view"],
                            policies=["user-policy"],
                            decision_strategy="AFFIRMATIVE",
                        ),
                        ScopePermission(
                            name="edit-profile-permission",
                            description="Users can edit their profile",
                            resources=["profile"],
                            scopes=["edit"],
                            policies=["user-policy"],
                        ),
                    ],
                ),
            ),
        )

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm first
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

            # Create client
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
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Verify client and get UUID
            client_repr = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            assert client_repr is not None
            client_uuid = client_repr.id

            # Verify permissions
            permissions = await keycloak_admin_client.get_authorization_permissions(
                realm_name, client_uuid, namespace
            )
            perm_names = {p.get("name") for p in permissions}
            assert "view-profile-permission" in perm_names
            assert "edit-profile-permission" in perm_names

            # Verify scope permission details
            view_perm = (
                await keycloak_admin_client.get_authorization_permission_by_name(
                    realm_name, client_uuid, "view-profile-permission", namespace
                )
            )
            assert view_perm is not None
            assert view_perm.get("decisionStrategy") == "AFFIRMATIVE"

            logger.info("✓ Successfully verified scope permissions")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
