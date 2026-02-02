"""
Integration tests for realm organizations feature.

Tests verify the operator correctly manages organizations:
- Organization creation with domains
- Organization update and deletion
- Organization identity provider linking

NOTE: Organizations require Keycloak 26.0.0 or higher.
Tests will be skipped if running against an older Keycloak version.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid

import pytest
from kubernetes import client
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


async def _check_keycloak_version_supports_organizations(
    keycloak_admin_client, namespace: str
) -> bool:
    """Check if Keycloak version supports organizations (26.0.0+)."""
    try:
        # Try to access the organizations endpoint
        response = await keycloak_admin_client._make_request(
            "GET",
            "realms/master/organizations",
            namespace,
        )
        # 200 = feature available, 404 = feature not available
        return response.status_code == 200
    except Exception:
        return False


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmOrganizations:
    """Test realm organization management via the operator."""

    @pytest.mark.timeout(300)
    async def test_realm_with_organizations(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with organizations.

        This test verifies that:
        - A realm can be created with organizations enabled
        - Organizations are created with correct names and aliases
        - Organization domains are configured
        - Organizations can be retrieved via the admin API
        """
        # Check if Keycloak supports organizations
        supports_orgs = await _check_keycloak_version_supports_organizations(
            keycloak_admin_client, test_namespace
        )
        if not supports_orgs:
            pytest.skip(
                "Keycloak version does not support organizations (requires 26+)"
            )

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"org-test-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            Organization,
            OrganizationDomain,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Organizations Test Realm",
            client_authorization_grants=[namespace],
            organizations_enabled=True,
            organizations=[
                Organization(
                    name="acme-corp",
                    alias="acme",
                    description="ACME Corporation",
                    enabled=True,
                    domains=[
                        OrganizationDomain(name="acme.com", verified=True),
                        OrganizationDomain(name="acme.org", verified=False),
                    ],
                    attributes={"tier": ["enterprise"], "industry": ["technology"]},
                ),
                Organization(
                    name="globex-inc",
                    alias="globex",
                    description="Globex Incorporated",
                    enabled=True,
                    domains=[
                        OrganizationDomain(name="globex.com", verified=True),
                    ],
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with organizations
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with 2 organizations")

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

            # Verify realm exists
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Verify organizations were created
            orgs = await keycloak_admin_client.get_organizations(realm_name, namespace)
            org_names = {org.get("name") for org in orgs}

            assert "acme-corp" in org_names, "acme-corp organization should exist"
            assert "globex-inc" in org_names, "globex-inc organization should exist"
            logger.info(f"✓ Verified {len(orgs)} organizations created")

            # Verify organization details
            acme_org = await keycloak_admin_client.get_organization_by_name(
                realm_name, "acme-corp", namespace
            )
            assert acme_org is not None
            assert acme_org.get("alias") == "acme"
            assert acme_org.get("description") == "ACME Corporation"
            assert acme_org.get("enabled") is True

            # Verify domains
            acme_domains = acme_org.get("domains", [])
            domain_names = {d.get("name") for d in acme_domains}
            assert "acme.com" in domain_names, "acme.com domain should exist"
            assert "acme.org" in domain_names, "acme.org domain should exist"
            logger.info("✓ Successfully verified organization domains")

            # Verify attributes
            acme_attrs = acme_org.get("attributes", {})
            assert "tier" in acme_attrs, "tier attribute should exist"
            assert "enterprise" in acme_attrs.get("tier", [])
            logger.info("✓ Successfully verified organization attributes")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(300)
    async def test_organization_with_identity_provider_linking(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test linking identity providers to organizations.

        This test verifies that:
        - An IdP can be created in a realm
        - An organization can reference the IdP
        - The IdP is properly linked to the organization
        """
        # Check if Keycloak supports organizations
        supports_orgs = await _check_keycloak_version_supports_organizations(
            keycloak_admin_client, test_namespace
        )
        if not supports_orgs:
            pytest.skip(
                "Keycloak version does not support organizations (requires 26+)"
            )

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"org-idp-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakIdentityProvider,
            KeycloakIdentityProviderSecretRef,
            KeycloakRealmSpec,
            OperatorRef,
            Organization,
            OrganizationDomain,
            OrganizationIdentityProvider,
        )

        # Create a secret for the IdP client secret
        core_api = client.CoreV1Api()
        secret_name = f"org-idp-secret-{suffix}"
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            string_data={"clientSecret": "dummy-secret-for-testing"},
        )
        core_api.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Created secret {secret_name} for IdP client secret")

        # Create realm with an IdP and an organization that links to it
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Org IdP Linking Test Realm",
            client_authorization_grants=[namespace],
            organizations_enabled=True,
            # First configure the IdP at realm level
            identity_providers=[
                KeycloakIdentityProvider(
                    alias="corp-azure",
                    provider_id="oidc",
                    enabled=True,
                    trust_email=True,
                    config={
                        "clientId": "dummy-client-id",
                        "authorizationUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                        "tokenUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                        "defaultScope": "openid profile email",
                    },
                    config_secrets={
                        "clientSecret": KeycloakIdentityProviderSecretRef(
                            name=secret_name, key="clientSecret"
                        ),
                    },
                ),
            ],
            # Then create organization that links to the IdP
            organizations=[
                Organization(
                    name="corp-org",
                    alias="corp",
                    description="Corporation with Azure AD",
                    enabled=True,
                    domains=[
                        OrganizationDomain(name="corp.example.com", verified=True),
                    ],
                    identity_providers=[
                        OrganizationIdentityProvider(alias="corp-azure"),
                    ],
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with IdP and organization
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with IdP and organization")

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

            # Verify the IdP exists in the realm
            response = await keycloak_admin_client._make_request(
                "GET",
                f"realms/{realm_name}/identity-provider/instances",
                namespace=namespace,
            )
            assert response.status_code == 200, f"Failed to get IdPs: {response.text}"
            idps = response.json()
            idp_aliases = {idp.get("alias") for idp in idps}
            assert "corp-azure" in idp_aliases, "corp-azure IdP should exist"
            logger.info("✓ Verified IdP exists in realm")

            # Verify the organization exists
            org = await keycloak_admin_client.get_organization_by_name(
                realm_name, "corp-org", namespace
            )
            assert org is not None, "corp-org organization should exist"
            org_id = org.get("id")
            assert org_id is not None
            logger.info("✓ Verified organization exists")

            # Verify the IdP is linked to the organization
            linked_idps = (
                await keycloak_admin_client.get_organization_identity_providers(
                    realm_name, org_id, namespace
                )
            )
            linked_aliases = {idp.get("alias") for idp in linked_idps}
            assert "corp-azure" in linked_aliases, (
                "corp-azure should be linked to organization"
            )
            logger.info("✓ Successfully verified IdP linked to organization")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Cleanup secret
            with contextlib.suppress(Exception):
                core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)

    @pytest.mark.timeout(300)
    async def test_organization_deletion_when_removed_from_spec(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that organizations are deleted when removed from the spec.

        This test verifies that:
        - When an organization is removed from the spec, it's deleted from Keycloak
        - Other organizations remain intact
        """
        # Check if Keycloak supports organizations
        supports_orgs = await _check_keycloak_version_supports_organizations(
            keycloak_admin_client, test_namespace
        )
        if not supports_orgs:
            pytest.skip(
                "Keycloak version does not support organizations (requires 26+)"
            )

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"org-del-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            Organization,
            OrganizationDomain,
        )

        # Create realm with two organizations
        initial_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Org Deletion Test Realm",
            client_authorization_grants=[namespace],
            organizations_enabled=True,
            organizations=[
                Organization(
                    name="org-to-keep",
                    alias="keep",
                    enabled=True,
                    domains=[OrganizationDomain(name="keep.com", verified=True)],
                ),
                Organization(
                    name="org-to-delete",
                    alias="delete",
                    enabled=True,
                    domains=[OrganizationDomain(name="delete.com", verified=True)],
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": initial_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
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

            # Verify both organizations exist
            orgs = await keycloak_admin_client.get_organizations(realm_name, namespace)
            org_names = {org.get("name") for org in orgs}
            assert "org-to-keep" in org_names
            assert "org-to-delete" in org_names
            logger.info("✓ Verified both organizations exist initially")

            # Update spec to remove one organization
            updated_spec = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Org Deletion Test Realm",
                client_authorization_grants=[namespace],
                organizations_enabled=True,
                organizations=[
                    Organization(
                        name="org-to-keep",
                        alias="keep",
                        enabled=True,
                        domains=[OrganizationDomain(name="keep.com", verified=True)],
                    ),
                    # org-to-delete is removed
                ],
            )

            # Patch the realm
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body={
                    "spec": updated_spec.model_dump(by_alias=True, exclude_unset=True)
                },
            )

            logger.info("Patched realm to remove org-to-delete")

            # Wait for reconciliation to complete
            await asyncio.sleep(10)  # Give the operator time to reconcile

            # Wait for the deleted org to be removed
            async def org_deleted():
                orgs = await keycloak_admin_client.get_organizations(
                    realm_name, namespace
                )
                org_names = {org.get("name") for org in orgs}
                return "org-to-delete" not in org_names

            deleted = await _simple_wait(org_deleted, timeout=60)
            assert deleted, "org-to-delete should have been removed"

            # Verify org-to-keep still exists
            orgs = await keycloak_admin_client.get_organizations(realm_name, namespace)
            org_names = {org.get("name") for org in orgs}
            assert "org-to-keep" in org_names, "org-to-keep should still exist"
            logger.info("✓ Successfully verified organization deletion")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
