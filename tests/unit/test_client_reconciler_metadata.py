"""Unit tests for KeycloakClientReconciler metadata handling."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.models.client import KeycloakClientSpec, RealmRef, SecretMetadata
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.mark.asyncio
async def test_manage_client_credentials_passes_metadata():
    """Test that manage_client_credentials passes metadata to create_client_secret."""

    # Mock dependencies
    mock_k8s_client = MagicMock()
    mock_admin_factory = AsyncMock()
    mock_admin_client = AsyncMock()
    mock_admin_factory.return_value = mock_admin_client
    mock_admin_client.get_client_secret.return_value = "test-secret"

    reconciler = KeycloakClientReconciler(
        k8s_client=mock_k8s_client, keycloak_admin_factory=mock_admin_factory
    )

    from keycloak_operator.settings import settings

    settings.operator_instance_id = "test-instance"
    with (
        patch(
            "keycloak_operator.services.client_reconciler.create_client_secret"
        ) as mock_create_secret,
        patch("keycloak_operator.services.client_reconciler.get_kubernetes_client"),
        patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api"
        ) as mock_core_api_cls,
        patch.object(
            KeycloakClientReconciler, "_get_realm_resource"
        ) as mock_get_realm_resource,
        patch("keycloak_operator.services.client_reconciler.asyncio") as mock_asyncio,
        patch(
            "keycloak_operator.utils.isolation.is_managed_by_this_operator",
            return_value=True,
        ),
    ):
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore[method-assign]
        reconciler._validate_namespace_authorization = AsyncMock()  # type: ignore[method-assign]
        mock_get_realm_resource.return_value = {
            "spec": {
                "realmName": "realm-name",
                "operatorRef": {"namespace": settings.operator_namespace},
                "clientAuthorizationGrants": ["ns"],
            }
        }
        # Mock to avoid threadpool calls
        mock_asyncio.to_thread = AsyncMock(side_effect=lambda f, *args: f(*args))

        # Mock CoreV1Api to return 404 (secret doesn't exist)
        mock_core_api = MagicMock()
        mock_core_api_cls.return_value = mock_core_api
        from kubernetes.client.rest import ApiException

        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=404)

        # Setup inputs
        spec = KeycloakClientSpec(
            clientId="test-client",
            realmRef=RealmRef(name="my-realm", namespace="ns"),
            secretMetadata=SecretMetadata(
                labels={"l1": "v1"}, annotations={"a1": "v1"}
            ),
        )

        # Execute
        await reconciler.manage_client_credentials(
            spec=spec,
            client_uuid="uuid",
            name="test-client-cr",
            namespace="ns",
            actual_realm_name="realm-name",
        )

        # Verify
        assert mock_create_secret.call_count >= 1
        call_kwargs = mock_create_secret.call_args[1]

        assert call_kwargs["labels"] == {"l1": "v1"}
        # Annotations should include user-provided AND operator-managed ones
        assert "a1" in call_kwargs["annotations"]
        assert call_kwargs["annotations"]["a1"] == "v1"


@pytest.mark.asyncio
async def test_do_update_passes_metadata_without_regeneration():
    """Test that do_update passes metadata when only metadata changes (no regeneration)."""

    # Mock dependencies
    mock_k8s_client = MagicMock()
    mock_admin_factory = AsyncMock()
    mock_admin_client = AsyncMock()
    mock_admin_factory.return_value = mock_admin_client

    reconciler = KeycloakClientReconciler(
        k8s_client=mock_k8s_client, keycloak_admin_factory=mock_admin_factory
    )

    from keycloak_operator.settings import settings

    settings.operator_instance_id = "test-instance"
    with (
        patch(
            "keycloak_operator.services.client_reconciler.create_client_secret"
        ) as mock_create_secret,
        patch("keycloak_operator.services.client_reconciler.get_kubernetes_client"),
        patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api"
        ) as mock_core_api_cls,
        patch.object(
            KeycloakClientReconciler, "_get_realm_resource"
        ) as mock_get_realm_resource,
        patch("keycloak_operator.services.client_reconciler.asyncio") as mock_asyncio,
        patch(
            "keycloak_operator.utils.isolation.is_managed_by_this_operator",
            return_value=True,
        ),
    ):
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore[method-assign]
        reconciler._validate_namespace_authorization = AsyncMock()  # type: ignore[method-assign]
        mock_get_realm_resource.return_value = {
            "spec": {
                "realmName": "realm-name",
                "operatorRef": {"namespace": settings.operator_namespace},
                "clientAuthorizationGrants": ["ns"],
            }
        }
        # Mock to avoid threadpool calls
        mock_asyncio.to_thread = AsyncMock(side_effect=lambda f, *args: f(*args))

        # Mock getting existing secret
        mock_admin_client.get_client_secret.return_value = "existing-secret"
        mock_core_api = MagicMock()
        mock_core_api_cls.return_value = mock_core_api
        mock_existing_secret = MagicMock()
        mock_existing_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": "2024-01-01T00:00:00Z"
        }
        import base64

        mock_existing_secret.data = {
            "client-secret": base64.b64encode(b"existing-secret").decode()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_existing_secret

        # Setup inputs
        old_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
        }

        new_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
            "regenerateSecret": False,
            "secretMetadata": {"labels": {"l3": "v3"}, "annotations": {"a3": "v3"}},
        }

        # Diff that triggers update
        diff = [
            ("change", ("spec", "secretMetadata"), None, new_spec["secretMetadata"])
        ]

        # Execute
        await reconciler.do_update(
            old_spec=old_spec,
            new_spec=new_spec,
            diff=diff,
            name="test-client-cr",
            namespace="ns",
            status=MagicMock(),
            meta={"generation": 1},
        )

        # Verify
        assert mock_create_secret.call_count >= 1
        call_kwargs = mock_create_secret.call_args[1]

        # Ensure secret was NOT regenerated (should use existing value)
        assert call_kwargs["client_secret"] == "existing-secret"
        assert call_kwargs["labels"] == {"l3": "v3"}
        assert "a3" in call_kwargs["annotations"]
        assert call_kwargs["annotations"]["a3"] == "v3"
        assert "keycloak-operator/rotated-at" in call_kwargs["annotations"]


@pytest.mark.asyncio
async def test_do_update_passes_metadata_on_regeneration():
    """Test that do_update passes metadata when regenerating secret."""

    # Mock dependencies
    mock_k8s_client = MagicMock()
    mock_admin_factory = AsyncMock()
    mock_admin_client = AsyncMock()
    mock_admin_factory.return_value = mock_admin_client

    reconciler = KeycloakClientReconciler(
        k8s_client=mock_k8s_client, keycloak_admin_factory=mock_admin_factory
    )

    from keycloak_operator.settings import settings

    settings.operator_instance_id = "test-instance"
    with (
        patch(
            "keycloak_operator.services.client_reconciler.create_client_secret"
        ) as mock_create_secret,
        patch("keycloak_operator.services.client_reconciler.get_kubernetes_client"),
        patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api"
        ) as mock_core_api_cls,
        patch.object(
            KeycloakClientReconciler, "_get_realm_resource"
        ) as mock_get_realm_resource,
        patch("keycloak_operator.services.client_reconciler.asyncio") as mock_asyncio,
        patch(
            "keycloak_operator.utils.isolation.is_managed_by_this_operator",
            return_value=True,
        ),
    ):
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore[method-assign]
        reconciler._validate_namespace_authorization = AsyncMock()  # type: ignore[method-assign]
        mock_get_realm_resource.return_value = {
            "spec": {
                "realmName": "realm-name",
                "operatorRef": {"namespace": settings.operator_namespace},
                "clientAuthorizationGrants": ["ns"],
            }
        }
        # Mock to avoid threadpool calls
        mock_asyncio.to_thread = AsyncMock(side_effect=lambda f, *args: f(*args))

        mock_admin_client.regenerate_client_secret.return_value = "new-secret"
        mock_core_api = MagicMock()
        mock_core_api_cls.return_value = mock_core_api
        from kubernetes.client.rest import ApiException

        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=404)

        # Setup inputs
        old_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
        }

        new_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
            "regenerateSecret": True,
            "secretMetadata": {"labels": {"l2": "v2"}, "annotations": {"a2": "v2"}},
        }

        # Diff that triggers update
        diff = []  # We don't need diff to trigger regeneration, it's checked via new_spec flag

        # Execute
        await reconciler.do_update(
            old_spec=old_spec,
            new_spec=new_spec,
            diff=diff,
            name="test-client-cr",
            namespace="ns",
            status=MagicMock(),
            meta={"generation": 1},
        )

        # Verify
        assert mock_create_secret.call_count >= 1
        call_kwargs = mock_create_secret.call_args[1]

        assert call_kwargs["labels"] == {"l2": "v2"}
        assert "a2" in call_kwargs["annotations"]
        assert call_kwargs["annotations"]["a2"] == "v2"
        assert "keycloak-operator/rotated-at" in call_kwargs["annotations"]
