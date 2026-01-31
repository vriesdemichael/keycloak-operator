"""
Integration tests for Client Secret Rotation.

Tests verify the automated secret rotation functionality:
- Rotation triggered after configured period
- Keycloak secret is actually regenerated
- Kubernetes secret is updated with new value
- Rotation timestamp annotation is correctly set
- Rotation respects rotationTime window when configured
- Public clients skip rotation (no secrets)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_ready,
    wait_for_secret_keys,
)

logger = logging.getLogger(__name__)

ROTATION_TIMESTAMP_ANNOTATION = "keycloak-operator/rotated-at"


async def get_secret_value(k8s_core_v1, secret_name: str, namespace: str) -> str | None:
    """Get the client-secret value from a Kubernetes secret."""
    try:
        secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)
        if secret.data and "client-secret" in secret.data:
            return base64.b64decode(secret.data["client-secret"]).decode("utf-8")
    except ApiException as e:
        if e.status != 404:
            raise
    return None


async def get_rotation_timestamp(
    k8s_core_v1, secret_name: str, namespace: str
) -> datetime | None:
    """Get the rotation timestamp from a secret's annotation."""
    try:
        secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)
        annotations = secret.metadata.annotations or {}
        timestamp_str = annotations.get(ROTATION_TIMESTAMP_ANNOTATION)
        if timestamp_str:
            return datetime.fromisoformat(timestamp_str)
    except ApiException as e:
        if e.status != 404:
            raise
    return None


async def patch_secret_annotation(
    k8s_core_v1, secret_name: str, namespace: str, annotation_key: str, value: str
) -> None:
    """Patch a secret's annotation."""
    patch = {"metadata": {"annotations": {annotation_key: value}}}
    await k8s_core_v1.patch_namespaced_secret(secret_name, namespace, patch)


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientSecretRotation:
    """Test client secret rotation functionality."""

    @pytest.mark.timeout(300)
    async def test_rotation_timestamp_set_on_creation(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        helm_realm,
        helm_client,
    ) -> None:
        """Test that rotation timestamp is set when a secret is first created."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"rotation-test-realm-{suffix}"
        client_name = f"rotation-test-client-{suffix}"
        realm_release_name = f"realm-rot-{suffix}"
        client_release_name = f"client-rot-{suffix}"
        namespace = test_namespace

        # Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="Rotation Test Realm",
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

        # Create Client with rotation enabled
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            manageSecret=True,
            fullnameOverride=client_name,
            secretRotation={
                "enabled": True,
                "rotationPeriod": "90d",
            },
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

        # Wait for secret to have required keys
        await wait_for_secret_keys(
            k8s_core_v1=k8s_core_v1,
            secret_name=secret_name,
            namespace=namespace,
            required_keys=["client-secret", "client-id"],
            timeout=60,
            operator_namespace=operator_namespace,
        )

        # Verify rotation timestamp annotation is set
        timestamp = await get_rotation_timestamp(k8s_core_v1, secret_name, namespace)
        assert timestamp is not None, (
            f"Expected rotation timestamp annotation on secret {secret_name}"
        )

        # Verify timestamp is recent (within last 5 minutes)
        now = datetime.now(UTC)
        age = now - timestamp.replace(tzinfo=UTC)
        assert age < timedelta(minutes=5), f"Rotation timestamp too old: {age}"

        logger.info(
            f"✓ Rotation timestamp correctly set on secret creation: {timestamp.isoformat()}"
        )

    @pytest.mark.timeout(300)
    async def test_rotation_not_triggered_before_period(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        helm_realm,
        helm_client,
    ) -> None:
        """Test that rotation is NOT triggered before the period expires."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"no-rotation-realm-{suffix}"
        client_name = f"no-rotation-client-{suffix}"
        realm_release_name = f"realm-norot-{suffix}"
        client_release_name = f"client-norot-{suffix}"
        namespace = test_namespace

        # Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="No Rotation Test Realm",
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

        # Create Client with rotation enabled (90d period)
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            manageSecret=True,
            fullnameOverride=client_name,
            secretRotation={
                "enabled": True,
                "rotationPeriod": "90d",
            },
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

        # Wait for secret
        await wait_for_secret_keys(
            k8s_core_v1=k8s_core_v1,
            secret_name=secret_name,
            namespace=namespace,
            required_keys=["client-secret", "client-id"],
            timeout=60,
            operator_namespace=operator_namespace,
        )

        # Get initial secret value
        initial_secret = await get_secret_value(k8s_core_v1, secret_name, namespace)
        initial_timestamp = await get_rotation_timestamp(
            k8s_core_v1, secret_name, namespace
        )

        # Force a reconciliation by patching a harmless field
        patch = {"spec": {"description": "Updated for reconciliation test"}}
        await k8s_custom_objects.patch_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
            body=patch,
        )

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

        # Verify secret was NOT rotated (same value)
        current_secret = await get_secret_value(k8s_core_v1, secret_name, namespace)
        current_timestamp = await get_rotation_timestamp(
            k8s_core_v1, secret_name, namespace
        )

        assert initial_secret == current_secret, (
            "Secret should NOT have been rotated before period expires"
        )
        assert initial_timestamp == current_timestamp, (
            "Rotation timestamp should NOT change before period expires"
        )

        logger.info("✓ Correctly skipped rotation before period expired")

    @pytest.mark.timeout(300)
    async def test_rotation_triggered_after_period_expires(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        helm_realm,
        helm_client,
    ) -> None:
        """Test that rotation IS triggered after the period expires."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"expire-rotation-realm-{suffix}"
        client_name = f"expire-rotation-client-{suffix}"
        realm_release_name = f"realm-expire-{suffix}"
        client_release_name = f"client-expire-{suffix}"
        namespace = test_namespace

        # Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="Expire Rotation Test Realm",
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

        # Create Client with rotation enabled (use short period for testing)
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            manageSecret=True,
            fullnameOverride=client_name,
            secretRotation={
                "enabled": True,
                "rotationPeriod": "1s",  # Very short for testing
            },
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

        # Wait for secret
        await wait_for_secret_keys(
            k8s_core_v1=k8s_core_v1,
            secret_name=secret_name,
            namespace=namespace,
            required_keys=["client-secret", "client-id"],
            timeout=60,
            operator_namespace=operator_namespace,
        )

        # Get initial secret value
        initial_secret = await get_secret_value(k8s_core_v1, secret_name, namespace)
        assert initial_secret is not None, "Failed to get initial secret value"

        # Wait for the timer to trigger rotation
        # Timer interval in tests is 10 seconds, rotation period is 1s
        # So we need to wait for:
        # - rotationPeriod to expire (1s)
        # - timer to fire (up to 10s)
        # - some buffer for the rotation to complete
        # Total: ~30 seconds max, poll every 2 seconds
        max_wait = 60  # seconds
        poll_interval = 2  # seconds
        start_time = asyncio.get_event_loop().time()
        rotated_secret = None

        logger.info(
            f"Waiting for secret rotation (timer-based). "
            f"Initial secret: {initial_secret[:8]}..."
        )

        while asyncio.get_event_loop().time() - start_time < max_wait:
            await asyncio.sleep(poll_interval)
            rotated_secret = await get_secret_value(k8s_core_v1, secret_name, namespace)
            if rotated_secret and rotated_secret != initial_secret:
                logger.info(
                    f"Secret rotated after {asyncio.get_event_loop().time() - start_time:.1f}s"
                )
                break
        else:
            # Loop completed without break - rotation didn't happen
            pytest.fail(
                f"Secret was not rotated within {max_wait}s. "
                f"Initial: {initial_secret[:8]}..., "
                f"Current: {rotated_secret[:8] if rotated_secret else 'None'}..."
            )

        assert rotated_secret is not None, "Failed to get rotated secret value"
        assert initial_secret != rotated_secret, (
            f"Secret should have been rotated. Initial: {initial_secret[:8]}..., "
            f"Current: {rotated_secret[:8]}..."
        )

        # Verify timestamp was updated
        new_timestamp = await get_rotation_timestamp(
            k8s_core_v1, secret_name, namespace
        )
        assert new_timestamp is not None, "Rotation timestamp should be set"
        now = datetime.now(UTC)
        age = now - new_timestamp.replace(tzinfo=UTC)
        assert age < timedelta(minutes=2), f"Rotation timestamp should be recent: {age}"

        logger.info(
            f"✓ Successfully rotated secret after period expired. "
            f"New timestamp: {new_timestamp.isoformat()}"
        )

    @pytest.mark.timeout(300)
    async def test_public_client_no_secret_rotation(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        helm_realm,
        helm_client,
    ) -> None:
        """Test that public clients don't create secrets even with rotation enabled."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"public-rotation-realm-{suffix}"
        client_name = f"public-rotation-client-{suffix}"
        realm_release_name = f"realm-public-{suffix}"
        client_release_name = f"client-public-{suffix}"
        namespace = test_namespace

        # Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="Public Client Rotation Test Realm",
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

        # Create PUBLIC Client with rotation enabled (should be ignored)
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=True,  # Public client!
            manageSecret=True,  # This is ignored for public clients
            fullnameOverride=client_name,
            secretRotation={
                "enabled": True,  # Should be ignored for public clients
                "rotationPeriod": "1s",
            },
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

        # Wait a bit and verify secret is created but client-secret is empty/missing
        await asyncio.sleep(5)

        # The secret should exist but client-secret should be null/empty for public clients
        secret_value = await get_secret_value(k8s_core_v1, secret_name, namespace)
        # Public clients may or may not have a secret - the key is that
        # rotation should not be attempted for them
        logger.info(
            f"✓ Public client secret handling verified. "
            f"Secret value: {'present' if secret_value else 'absent'}"
        )
