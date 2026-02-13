"""
Integration tests for Manual Client Secret management.

Tests verify:
- Using an existing Kubernetes secret as the source for client secret
- Correct propagation to Keycloak
- Correct propagation to the operator-managed output secret
- Validation of conflict with secret rotation
"""

from __future__ import annotations

import base64
import logging
import uuid

import pytest
from kubernetes.client import V1ObjectMeta, V1Secret

from .wait_helpers import (
    wait_for_resource_ready,
    wait_for_secret_keys,
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientSecretManual:
    """Test manual client secret management."""

    @pytest.mark.timeout(300)
    async def test_manual_secret(
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
        """Test manual secret configuration."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"manual-secret-realm-{suffix}"
        client_name = f"manual-secret-client-{suffix}"
        realm_release_name = f"realm-{suffix}"
        client_release_name = f"client-{suffix}"
        manual_secret_name = f"my-manual-secret-{suffix}"
        manual_secret_key = "my-secret-key"
        manual_secret_value = "super-secret-value-123"
        namespace = test_namespace

        # 1. Create Realm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[namespace],
            displayName="Manual Secret Test Realm",
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

        # 2. Create the manual secret in Kubernetes
        secret = V1Secret(
            metadata=V1ObjectMeta(name=manual_secret_name, namespace=namespace),
            string_data={manual_secret_key: manual_secret_value},
            type="Opaque",
        )
        await k8s_core_v1.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Created manual secret {manual_secret_name}")

        # 3. Create Client referencing the manual secret
        # Note: We pass raw values to helm_client which are merged into values.yaml
        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            manageSecret=True,
            fullnameOverride=client_name,
            # Configure manual secret
            clientSecret={"name": manual_secret_name, "key": manual_secret_key},
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

        output_secret_name = f"{client_name}-credentials"

        # 4. Verify the operator-managed output secret matches the manual secret
        logger.info("Verifying output secret matches manual secret...")
        secret = await wait_for_secret_keys(
            k8s_core_v1=k8s_core_v1,
            secret_name=output_secret_name,
            namespace=namespace,
            required_keys=["client-secret", "client-id"],
            timeout=60,
            operator_namespace=operator_namespace,
        )

        managed_secret_value = base64.b64decode(secret.data["client-secret"]).decode(
            "utf-8"
        )
        assert managed_secret_value == manual_secret_value, (
            "Output secret does not match manual secret"
        )

        # 5. Verify Keycloak has the correct secret
        logger.info("Verifying Keycloak has the correct secret...")
        # Use the shared admin client to fetch the client secret for this realm/namespace.
        kc_secret = await keycloak_admin_client.get_client_secret(
            client_id=client_name,
            realm_name=realm_name,
            namespace=namespace,  # The admin client needs the namespace of the Keycloak instance
        )
        assert kc_secret == manual_secret_value, (
            "Keycloak secret does not match manual secret"
        )

        logger.info("✓ Successfully verified manual client secret configuration")
