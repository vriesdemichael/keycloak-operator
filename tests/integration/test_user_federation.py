"""
Integration tests for Keycloak user federation (LDAP, AD, Kerberos).

These tests verify that the operator correctly:
1. Creates and configures LDAP user federation providers
2. Syncs users from LDAP to Keycloak
3. Updates federation configuration
4. Deletes federation providers when removed from spec
5. Handles AD-style schema (sAMAccountName, userPrincipalName)
6. Configures Kerberos authentication (when available)
"""

import asyncio
import logging
import uuid

import pytest
from kubernetes import client

from keycloak_operator.models.realm import (
    KeycloakRealmSpec,
    KeycloakUserFederation,
    KeycloakUserFederationMapper,
    KeycloakUserFederationSecretRef,
    KeycloakUserFederationSyncSettings,
    OperatorRef,
)

from .wait_helpers import wait_for_resource_ready

logger = logging.getLogger(__name__)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ldap_federation_create(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    k8s_custom_objects,
    openldap_ready,
):
    """Test creating a realm with LDAP user federation."""
    realm_name = f"test-ldap-{uuid.uuid4().hex[:8]}"

    # Create secret with LDAP bind password
    core_api = client.CoreV1Api()
    secret_name = f"ldap-bind-{uuid.uuid4().hex[:8]}"
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": openldap_ready["bind_password"]},
    )
    core_api.create_namespaced_secret(namespace=test_namespace, body=secret)
    logger.info(f"Created secret {secret_name} for LDAP bind credentials")

    # Configure LDAP federation
    ldap_config = KeycloakUserFederation(
        name="test-openldap",
        provider_id="ldap",
        connection_url=openldap_ready["connection_url"],
        bind_dn=openldap_ready["bind_dn"],
        bind_credential_secret=KeycloakUserFederationSecretRef(
            name=secret_name,
            key="password",
        ),
        users_dn=openldap_ready["users_dn"],
        vendor=openldap_ready["vendor"],
        username_ldap_attribute=openldap_ready["username_attribute"],
        uuid_ldap_attribute=openldap_ready["uuid_attribute"],
        user_object_classes=["inetOrgPerson", "organizationalPerson"],
        edit_mode="READ_ONLY",
        sync_settings=KeycloakUserFederationSyncSettings(
            import_enabled=True,
            full_sync_period=-1,  # Disable periodic sync for testing
            changed_users_sync_period=-1,
        ),
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(namespace=operator_namespace),
        user_federation=[ldap_config],
    )

    custom_api = client.CustomObjectsApi()

    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        # Create the realm CR
        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )
        logger.info(f"Created realm CR: {realm_name}")

        # Wait for realm to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=180,
        )

        # Verify realm was created
        realm_repr = await keycloak_admin_client.get_realm(realm_name, test_namespace)
        assert realm_repr is not None, "Realm should exist"

        # Get federation providers - should be available immediately after reconciliation
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )

        assert len(providers) == 1, f"Expected 1 provider, got {len(providers)}"

        provider = providers[0]
        assert provider.name == "test-openldap"
        assert provider.provider_id == "ldap"
        assert provider.config is not None

        # Verify connection URL in config
        connection_urls = provider.config.get("connectionUrl", [])
        assert len(connection_urls) == 1
        assert openldap_ready["connection_url"] in connection_urls[0]

        logger.info("✓ Successfully verified LDAP federation in Keycloak")

    finally:
        # Cleanup
        try:
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
        except Exception as e:
            logger.warning(f"Failed to delete realm {realm_name}: {e}")

        try:
            core_api.delete_namespaced_secret(
                name=secret_name, namespace=test_namespace
            )
        except Exception as e:
            logger.warning(f"Failed to delete secret {secret_name}: {e}")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ldap_federation_sync_users(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    k8s_custom_objects,
    openldap_ready,
):
    """Test that users are synced from LDAP to Keycloak."""
    realm_name = f"test-ldap-sync-{uuid.uuid4().hex[:8]}"

    # Create secret with LDAP bind password
    core_api = client.CoreV1Api()
    secret_name = f"ldap-bind-{uuid.uuid4().hex[:8]}"
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": openldap_ready["bind_password"]},
    )
    core_api.create_namespaced_secret(namespace=test_namespace, body=secret)

    # Configure LDAP federation with email mapper
    ldap_config = KeycloakUserFederation(
        name="sync-test-ldap",
        provider_id="ldap",
        connection_url=openldap_ready["connection_url"],
        bind_dn=openldap_ready["bind_dn"],
        bind_credential_secret=KeycloakUserFederationSecretRef(
            name=secret_name,
            key="password",
        ),
        users_dn=openldap_ready["users_dn"],
        vendor=openldap_ready["vendor"],
        username_ldap_attribute=openldap_ready["username_attribute"],
        uuid_ldap_attribute=openldap_ready["uuid_attribute"],
        user_object_classes=["inetOrgPerson", "organizationalPerson"],
        edit_mode="READ_ONLY",
        sync_settings=KeycloakUserFederationSyncSettings(
            import_enabled=True,
        ),
        # Add email mapper
        mappers=[
            KeycloakUserFederationMapper(
                name="email",
                mapper_type="user-attribute-ldap-mapper",
                config={
                    "ldap.attribute": "mail",
                    "user.model.attribute": "email",
                    "read.only": "true",
                    "always.read.value.from.ldap": "true",
                    "is.mandatory.in.ldap": "false",
                },
            ),
        ],
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(namespace=operator_namespace),
        user_federation=[ldap_config],
    )

    custom_api = client.CustomObjectsApi()

    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        # Create the realm
        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=180,
        )

        # Get federation provider ID
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 1
        provider_id = providers[0].id

        # Trigger a full sync
        sync_result = await keycloak_admin_client.trigger_user_federation_sync(
            realm_name, provider_id, full_sync=True, namespace=test_namespace
        )
        logger.info(f"Sync result: {sync_result}")

        # Wait a moment for sync to complete
        await asyncio.sleep(2)

        # Verify users were imported
        # Get users from Keycloak
        response = await keycloak_admin_client._make_request(
            "GET",
            f"realms/{realm_name}/users",
            namespace=test_namespace,
        )
        assert response.status_code == 200
        users = response.json()

        # Check that test users from OpenLDAP exist
        usernames = [u["username"] for u in users]
        expected_users = [user["uid"] for user in openldap_ready["test_users"]]

        for expected_user in expected_users:
            assert expected_user in usernames, f"User {expected_user} should be synced"

        logger.info(f"✓ Successfully synced {len(users)} users from LDAP")

    finally:
        try:
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
        except Exception as e:
            logger.warning(f"Failed to delete realm {realm_name}: {e}")

        try:
            core_api.delete_namespaced_secret(
                name=secret_name, namespace=test_namespace
            )
        except Exception as e:
            logger.warning(f"Failed to delete secret {secret_name}: {e}")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ldap_federation_delete(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    k8s_custom_objects,
    openldap_ready,
):
    """Test that removing federation from spec deletes it from Keycloak."""
    realm_name = f"test-ldap-del-{uuid.uuid4().hex[:8]}"

    # Create secret
    core_api = client.CoreV1Api()
    secret_name = f"ldap-bind-{uuid.uuid4().hex[:8]}"
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": openldap_ready["bind_password"]},
    )
    core_api.create_namespaced_secret(namespace=test_namespace, body=secret)

    # Configure LDAP federation
    ldap_config = KeycloakUserFederation(
        name="delete-test-ldap",
        provider_id="ldap",
        connection_url=openldap_ready["connection_url"],
        bind_dn=openldap_ready["bind_dn"],
        bind_credential_secret=KeycloakUserFederationSecretRef(
            name=secret_name,
            key="password",
        ),
        users_dn=openldap_ready["users_dn"],
        vendor=openldap_ready["vendor"],
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(namespace=operator_namespace),
        user_federation=[ldap_config],
    )

    custom_api = client.CustomObjectsApi()

    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        # Create realm with federation
        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=180,
        )

        # Verify federation exists
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 1, "Federation should exist"

        # Update realm to remove federation
        realm_cr_updated = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {
                "name": realm_name,
                "namespace": test_namespace,
            },
            "spec": {
                "realmName": realm_name,
                "operatorRef": {"namespace": operator_namespace},
                "userFederation": [],  # Empty - remove federation
            },
        }

        custom_api.patch_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            body=realm_cr_updated,
        )

        # Wait for reconciliation
        await asyncio.sleep(10)

        # Verify federation was deleted
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 0, "Federation should be deleted"

        logger.info("✓ Successfully verified federation deletion")

    finally:
        try:
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
        except Exception as e:
            logger.warning(f"Failed to delete realm {realm_name}: {e}")

        try:
            core_api.delete_namespaced_secret(
                name=secret_name, namespace=test_namespace
            )
        except Exception as e:
            logger.warning(f"Failed to delete secret {secret_name}: {e}")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ad_federation_with_sam_account_name(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    k8s_custom_objects,
    openldap_ad_ready,
):
    """Test LDAP federation with Active Directory schema simulation."""
    realm_name = f"test-ad-{uuid.uuid4().hex[:8]}"

    # Create secret
    core_api = client.CoreV1Api()
    secret_name = f"ad-bind-{uuid.uuid4().hex[:8]}"
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": openldap_ad_ready["bind_password"]},
    )
    core_api.create_namespaced_secret(namespace=test_namespace, body=secret)

    # Configure AD-style federation
    ad_config = KeycloakUserFederation(
        name="test-ad-ldap",
        provider_id="ldap",
        connection_url=openldap_ad_ready["connection_url"],
        bind_dn=openldap_ad_ready["bind_dn"],
        bind_credential_secret=KeycloakUserFederationSecretRef(
            name=secret_name,
            key="password",
        ),
        users_dn=openldap_ad_ready["users_dn"],
        vendor=openldap_ad_ready["vendor"],  # "ad"
        username_ldap_attribute=openldap_ad_ready[
            "username_attribute"
        ],  # sAMAccountName
        rdn_ldap_attribute=openldap_ad_ready.get("rdn_attribute", "cn"),
        uuid_ldap_attribute=openldap_ad_ready.get("uuid_attribute", "objectGUID"),
        user_object_classes=["inetOrgPerson", "msUser"],
        edit_mode="READ_ONLY",
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(namespace=operator_namespace),
        user_federation=[ad_config],
    )

    custom_api = client.CustomObjectsApi()

    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=180,
        )

        # Verify federation was created with AD settings
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 1

        provider = providers[0]
        assert provider.config is not None

        # Verify AD-specific settings
        vendor = provider.config.get("vendor", [])
        assert "ad" in vendor, "Vendor should be 'ad'"

        username_attr = provider.config.get("usernameLdapAttribute", [])
        assert "sAMAccountName" in username_attr, (
            "Username attr should be sAMAccountName"
        )

        logger.info("✓ Successfully verified AD federation configuration")

    finally:
        try:
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
        except Exception as e:
            logger.warning(f"Failed to delete realm {realm_name}: {e}")

        try:
            core_api.delete_namespaced_secret(
                name=secret_name, namespace=test_namespace
            )
        except Exception as e:
            logger.warning(f"Failed to delete secret {secret_name}: {e}")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ldap_federation_update_config(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    k8s_custom_objects,
    openldap_ready,
):
    """Test updating LDAP federation configuration."""
    realm_name = f"test-ldap-upd-{uuid.uuid4().hex[:8]}"

    # Create secret
    core_api = client.CoreV1Api()
    secret_name = f"ldap-bind-{uuid.uuid4().hex[:8]}"
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": openldap_ready["bind_password"]},
    )
    core_api.create_namespaced_secret(namespace=test_namespace, body=secret)

    # Initial configuration with search_scope=1 (one-level)
    ldap_config = KeycloakUserFederation(
        name="update-test-ldap",
        provider_id="ldap",
        connection_url=openldap_ready["connection_url"],
        bind_dn=openldap_ready["bind_dn"],
        bind_credential_secret=KeycloakUserFederationSecretRef(
            name=secret_name,
            key="password",
        ),
        users_dn=openldap_ready["users_dn"],
        vendor=openldap_ready["vendor"],
        search_scope=1,  # One-level initially
        batch_size_for_sync=500,
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(namespace=operator_namespace),
        user_federation=[ldap_config],
    )

    custom_api = client.CustomObjectsApi()

    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        # Create initial realm
        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=180,
        )

        # Verify initial config
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 1
        initial_scope = providers[0].config.get("searchScope", ["2"])[0]
        assert initial_scope == "1", f"Initial scope should be 1, got {initial_scope}"

        # Update configuration - change search scope to 2 (subtree)
        ldap_config_updated = KeycloakUserFederation(
            name="update-test-ldap",  # Same name
            provider_id="ldap",
            connection_url=openldap_ready["connection_url"],
            bind_dn=openldap_ready["bind_dn"],
            bind_credential_secret=KeycloakUserFederationSecretRef(
                name=secret_name,
                key="password",
            ),
            users_dn=openldap_ready["users_dn"],
            vendor=openldap_ready["vendor"],
            search_scope=2,  # Changed to subtree
            batch_size_for_sync=1000,  # Changed
        )

        realm_spec_updated = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(namespace=operator_namespace),
            user_federation=[ldap_config_updated],
        )

        realm_cr_updated = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {
                "name": realm_name,
                "namespace": test_namespace,
            },
            "spec": realm_spec_updated.model_dump(by_alias=True, exclude_unset=True),
        }

        custom_api.patch_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            body=realm_cr_updated,
        )

        # Wait for reconciliation
        await asyncio.sleep(10)

        # Verify updated config
        providers = await keycloak_admin_client.get_user_federation_providers(
            realm_name, test_namespace
        )
        assert len(providers) == 1
        updated_scope = providers[0].config.get("searchScope", ["1"])[0]
        assert updated_scope == "2", f"Updated scope should be 2, got {updated_scope}"

        updated_batch = providers[0].config.get("batchSizeForSync", ["500"])[0]
        assert updated_batch == "1000", (
            f"Batch size should be 1000, got {updated_batch}"
        )

        logger.info("✓ Successfully verified federation config update")

    finally:
        try:
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
        except Exception as e:
            logger.warning(f"Failed to delete realm {realm_name}: {e}")

        try:
            core_api.delete_namespaced_secret(
                name=secret_name, namespace=test_namespace
            )
        except Exception as e:
            logger.warning(f"Failed to delete secret {secret_name}: {e}")
