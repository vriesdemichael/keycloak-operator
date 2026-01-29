"""
Integration tests for Client Secret lifecycle management.

Tests verify:
- Secret regeneration (regenerateSecret: true)
- OwnerReference on secrets
- Automatic secret recreation (monitoring)
"""

from __future__ import annotations

import asyncio
import logging
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_ready,
    wait_for_secret_keys,
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientSecretLifecycle:
    """Test client secret lifecycle management."""

    @pytest.mark.timeout(300)
    async def test_secret_lifecycle(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
        helm_realm,
        helm_client,
    ) -> None:
        """Test secret regeneration, ownership, and monitoring."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"lifecycle-realm-{suffix}"
        client_name = f"lifecycle-client-{suffix}"
        realm_release_name = f"realm-{suffix}"
        client_release_name = f"client-{suffix}"
        namespace = test_namespace

        # 1. Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="Lifecycle Test Realm",
            fullnameOverride=realm_name,
        )

        await wait_for_resource_ready(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=120,
            operator_namespace=operator_namespace,
        )

        # 2. Create Client (Confidential)
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            manageSecret=True,
            fullnameOverride=client_name,
        )

        await wait_for_resource_ready(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
            timeout=120,
            operator_namespace=operator_namespace,
        )

        secret_name = f"{client_name}-credentials"

        # Wait for secret to have required keys (handles race condition where CR is Ready
        # but secret population is still in progress)
        secret = await wait_for_secret_keys(
            k8s_core_v1=k8s_core_v1,
            secret_name=secret_name,
            namespace=namespace,
            required_keys=["client-secret", "client-id"],
            timeout=60,
            operator_namespace=operator_namespace,
        )

        # 3. Verify OwnerReference (Issue 382)
        assert secret.metadata.owner_references, "Secret missing ownerReferences"
        owner_ref = secret.metadata.owner_references[0]
        assert owner_ref.kind == "KeycloakClient", (
            f"Unexpected owner kind: {owner_ref.kind}"
        )
        assert owner_ref.name == client_name, f"Unexpected owner name: {owner_ref.name}"
        assert owner_ref.controller is True, "Owner reference not marked as controller"

        initial_password = secret.data["client-secret"]

        # 4. Test Secret Regeneration (Issue 380/381)
        logger.info("Testing secret regeneration...")
        patch = {"spec": {"regenerateSecret": True}}

        await k8s_custom_objects.patch_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
            body=patch,
        )

        # Wait for update
        resource = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
        )
        current_gen = resource["metadata"]["generation"]

        await wait_for_reconciliation_complete(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
            min_generation=current_gen,
            timeout=120,
            operator_namespace=operator_namespace,
        )

        # Verify secret changed
        secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)
        new_password = secret.data["client-secret"]
        assert initial_password != new_password, "Secret was not regenerated"
        logger.info("Secret regeneration successful")

        # 5. Test Secret Monitoring (Issue 379)
        logger.info("Testing secret monitoring (automatic recreation)...")

        # Delete the secret
        await k8s_core_v1.delete_namespaced_secret(secret_name, namespace)

        # Wait for it to be recreated
        # The watcher triggers reconciliation, which might take a few seconds
        for _ in range(30):
            try:
                secret = await k8s_core_v1.read_namespaced_secret(
                    secret_name, namespace
                )
                logger.info("Secret recreated successfully")
                break
            except ApiException as e:
                if e.status != 404:
                    raise
                await asyncio.sleep(2)
        else:
            pytest.fail("Secret was not recreated automatically after deletion")

        # Verify OwnerReference is still there on recreated secret
        assert secret.metadata.owner_references, (
            "Recreated secret missing ownerReferences"
        )
        assert secret.metadata.owner_references[0].name == client_name

        logger.info("✓ Successfully verified client secret lifecycle")
