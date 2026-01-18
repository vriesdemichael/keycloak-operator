"""
Integration tests for Client Secret Metadata management.

Tests verify the operator correctly manages metadata on client secrets:
- Adding labels and annotations to the generated secret
- Updating labels and annotations
"""

from __future__ import annotations

import contextlib
import logging
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_deleted,
    wait_for_resource_ready,
)

logger = logging.getLogger(__name__)


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
class TestClientSecretMetadata:
    """Test client secret metadata management via the operator."""

    @pytest.mark.timeout(300)
    async def test_client_secret_metadata(
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
        """Test creating a client with secret metadata.

        This test verifies that:
        - A client secret is created with specified labels and annotations
        - Metadata is updated when the client CR is updated
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"metadata-realm-{suffix}"
        client_name = f"metadata-client-{suffix}"
        realm_release_name = f"realm-{suffix}"
        client_release_name = f"client-{suffix}"
        namespace = test_namespace

        # 1. Create Realm via Helm
        await helm_realm(
            release_name=realm_release_name,
            realm_name=realm_name,
            namespace=namespace,
            displayName="Metadata Test Realm",
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

        # 2. Create Client with Secret Metadata via Helm
        custom_labels = {
            "example.com/managed-by": "gitops",
            "argocd.argoproj.io/secret-type": "repository",
        }
        custom_annotations = {"example.com/description": "This is a test secret"}

        await helm_client(
            release_name=client_release_name,
            client_id=client_name,
            realm_name=realm_name,
            realm_namespace=namespace,
            publicClient=False,
            secretMetadata={
                "labels": custom_labels,
                "annotations": custom_annotations,
            },
        )

        await wait_for_resource_ready(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,  # Note: Helm chart uses client name derived from release name or overridden.
            # The helm_client fixture passes clientId as "clientId" value.
            # The Helm chart templates the name as {{ include "keycloak-client.fullname" . }}.
            # If we don't set fullnameOverride, it uses release name.
            # Let's check the created name.
            # Wait, helm_client fixture calls _install_client.
            # The Helm chart uses `name: {{ include "keycloak-client.fullname" . }}`.
            # I should pass `fullnameOverride=client_name` to be safe/explicit, or use the release name if that's what it defaults to.
            # To be consistent with the manual test, I'll pass fullnameOverride.
            fullnameOverride=client_name,
            timeout=120,
            operator_namespace=operator_namespace,
        )

        # 3. Verify Secret Metadata
        secret_name = f"{client_name}-credentials"
        secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)

        logger.info(f"Checking secret {secret_name} labels and annotations")

        # Check labels
        for key, value in custom_labels.items():
            assert secret.metadata.labels.get(key) == value, f"Label {key} mismatch"

        # Check annotations
        for key, value in custom_annotations.items():
            assert secret.metadata.annotations.get(key) == value, (
                f"Annotation {key} mismatch"
            )

        # 4. Update Client with New Metadata via Patch
        new_labels = {"example.com/managed-by": "manual", "new-label": "true"}
        new_annotations = {"example.com/description": "Updated description"}

        # We patch the CR directly to simulate an update.
        # Ideally we would use helm upgrade, but the fixture doesn't support it easily.
        # Patching the CR is sufficient to test the operator's reconciliation logic.

        patch = {
            "spec": {
                "secretMetadata": {"labels": new_labels, "annotations": new_annotations}
            }
        }

        # Get current resource to ensure we have the latest version for patching?
        # patch_namespaced_custom_object handles merge patch.

        await k8s_custom_objects.patch_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
            body=patch,
        )

        # 5. Trigger Secret Regeneration to force update
        # Getting resource again to get latest version
        resource = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
        )
        current_gen = resource["metadata"].get("generation", 1)

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

        # 6. Verify Updated Metadata
        secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)

        logger.info(f"Checking updated secret {secret_name} labels and annotations")

        # Check new labels
        for key, value in new_labels.items():
            assert secret.metadata.labels.get(key) == value, (
                f"Updated Label {key} mismatch"
            )

        # Check old label (example.com/managed-by changed)
        assert secret.metadata.labels.get("example.com/managed-by") == "manual"

        # Check new annotations
        for key, value in new_annotations.items():
            assert secret.metadata.annotations.get(key) == value, (
                f"Updated Annotation {key} mismatch"
            )

        logger.info("✓ Successfully verified client secret metadata")
        # Cleanup is handled by fixtures
