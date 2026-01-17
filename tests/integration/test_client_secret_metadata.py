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
        k8s_core_api,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a client with secret metadata.

        This test verifies that:
        - A client secret is created with specified labels and annotations
        - Metadata is updated when the client CR is updated
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"metadata-realm-{suffix}"
        client_name = f"metadata-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            KeycloakClientSpec,
            RealmRef,
            SecretMetadata,
        )
        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
        )

        # 1. Create Realm
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Metadata Test Realm",
            client_authorization_grants=[namespace],
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
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # 2. Create Client with Secret Metadata
            custom_labels = {
                "example.com/managed-by": "gitops",
                "argocd.argoproj.io/secret-type": "repository",
            }
            custom_annotations = {"example.com/description": "This is a test secret"}

            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=namespace),
                client_id=client_name,
                public_client=False,
                secret_metadata=SecretMetadata(
                    labels=custom_labels,
                    annotations=custom_annotations,
                ),
            )

            client_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

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
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # 3. Verify Secret Metadata
            secret_name = f"{client_name}-credentials"
            secret = k8s_core_api.read_namespaced_secret(secret_name, namespace)

            logger.info(f"Checking secret {secret_name} labels and annotations")

            # Check labels
            for key, value in custom_labels.items():
                assert secret.metadata.labels.get(key) == value, f"Label {key} mismatch"

            # Check annotations
            for key, value in custom_annotations.items():
                assert secret.metadata.annotations.get(key) == value, (
                    f"Annotation {key} mismatch"
                )

            # 4. Update Client with New Metadata
            new_labels = {"example.com/managed-by": "manual", "new-label": "true"}
            new_annotations = {"example.com/description": "Updated description"}

            # Get current resource version
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            current_gen = resource["metadata"].get("generation", 1)

            assert client_spec.secret_metadata is not None
            client_spec.secret_metadata.labels = new_labels
            client_spec.secret_metadata.annotations = new_annotations

            # Cast to dict to satisfy type checker
            metadata: dict = client_manifest["metadata"]  # type: ignore
            metadata["resourceVersion"] = resource["metadata"]["resourceVersion"]
            client_manifest["spec"] = client_spec.model_dump(
                by_alias=True, exclude_unset=True
            )

            await k8s_custom_objects.replace_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                body=client_manifest,
            )

            # 5. Trigger Secret Regeneration to force update (since metadata updates might not trigger direct reconciliation if only metadata changed in secret but not spec?)
            # Actually, changing spec.secretMetadata IS a spec change, so it should trigger reconciliation.
            # However, create_client_secret uses update_existing=True which does patch.
            # We need to wait for reconciliation.

            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                min_generation=current_gen + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # 6. Verify Updated Metadata
            # We might need to wait a bit for the secret to be updated if it's async or cached
            secret = k8s_core_api.read_namespaced_secret(secret_name, namespace)

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
