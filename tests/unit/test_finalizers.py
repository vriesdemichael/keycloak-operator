"""
Test finalizer behavior for Keycloak operator resources.

This module tests the finalizer functionality across all resource types
to ensure proper cleanup and prevent orphaned resources.
"""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    BACKUP_ANNOTATION,
    CLIENT_FINALIZER,
    KEYCLOAK_FINALIZER,
    REALM_FINALIZER,
)
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler
from keycloak_operator.services.keycloak_reconciler import KeycloakInstanceReconciler
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler

BASE_KEYCLOAK_SPEC = {
    "database": {
        "type": "postgresql",
        "host": "postgres",
        "database": "keycloak",
        "username": "keycloak",
        "credentials_secret": "keycloak-db",
    }
}

BASE_REALM_SPEC = {
    "realm_name": "test-realm",
    "operator_ref": {
        "namespace": "keycloak-system",
        "authorization_secret_ref": {"name": "operator-token"},
    },
}

BASE_CLIENT_SPEC = {
    "client_id": "test-client",
    "realm_ref": {
        "name": "test-realm",
        "namespace": "default",
        "authorization_secret_ref": {"name": "realm-token"},
    },
}


def build_spec(base: dict, **overrides) -> dict:
    """Create a spec dict by merging overrides into the base template."""

    spec = deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(spec.get(key), dict):
            merged = deepcopy(spec[key])
            merged.update(value)
            spec[key] = merged
        else:
            spec[key] = value
    return spec


@pytest.fixture
def keycloak_k8s_apis():
    """Patch Kubernetes API clients used by the Keycloak reconciler."""

    apps_api = MagicMock()
    apps_api.delete_namespaced_deployment = MagicMock()
    apps_api.read_namespaced_deployment = MagicMock(
        side_effect=ApiException(status=404)
    )

    core_api = MagicMock()
    core_api.delete_namespaced_service = MagicMock()
    core_api.delete_namespaced_secret = MagicMock()
    core_api.delete_namespaced_config_map = MagicMock()
    core_api.list_namespaced_secret.return_value = SimpleNamespace(items=[])
    core_api.list_namespaced_config_map.return_value = SimpleNamespace(items=[])
    core_api.delete_namespaced_persistent_volume_claim = MagicMock()
    core_api.list_namespaced_persistent_volume_claim.return_value = SimpleNamespace(
        items=[SimpleNamespace(metadata=SimpleNamespace(name="pvc-1"))]
    )

    networking_api = MagicMock()
    networking_api.delete_namespaced_ingress = MagicMock()

    with (
        patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=apps_api,
        ),
        patch(
            "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api",
            return_value=core_api,
        ),
        patch(
            "keycloak_operator.services.keycloak_reconciler.client.NetworkingV1Api",
            return_value=networking_api,
        ),
    ):
        yield SimpleNamespace(apps=apps_api, core=core_api, networking=networking_api)


class TestKeycloakFinalizers:
    """Validate finalizer cleanup logic for Keycloak instances."""

    @pytest.fixture
    def keycloak_reconciler(self):
        # Create a mock Kubernetes API client to avoid loading kubeconfig
        mock_k8s_client = MagicMock()
        return KeycloakInstanceReconciler(k8s_client=mock_k8s_client)

    @staticmethod
    def make_keycloak_spec(**overrides) -> dict:
        return build_spec(BASE_KEYCLOAK_SPEC, **overrides)

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_resources_success(
        self, keycloak_reconciler, keycloak_k8s_apis
    ):
        spec = self.make_keycloak_spec(
            persistence={"enabled": True},
            ingress={"enabled": True},
        )

        await keycloak_reconciler.cleanup_resources(
            "test-keycloak", "test-namespace", spec
        )

        assert keycloak_k8s_apis.networking.delete_namespaced_ingress.called
        assert keycloak_k8s_apis.core.delete_namespaced_service.called
        assert keycloak_k8s_apis.apps.delete_namespaced_deployment.called
        assert keycloak_k8s_apis.core.delete_namespaced_persistent_volume_claim.called

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_missing_resources(
        self, keycloak_reconciler, keycloak_k8s_apis
    ):
        spec = self.make_keycloak_spec(persistence={"enabled": False})

        keycloak_k8s_apis.networking.delete_namespaced_ingress.side_effect = (
            ApiException(status=404)
        )

        await keycloak_reconciler.cleanup_resources(
            "test-keycloak", "test-namespace", spec
        )

        assert keycloak_k8s_apis.core.delete_namespaced_service.called
        assert keycloak_k8s_apis.apps.delete_namespaced_deployment.called

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_with_backup(
        self, keycloak_reconciler, keycloak_k8s_apis
    ):
        spec = self.make_keycloak_spec(
            metadata={
                "annotations": {
                    BACKUP_ANNOTATION: "true",
                }
            },
            persistence={"enabled": True},
        )

        backup_mock = AsyncMock()
        with patch.object(keycloak_reconciler, "_create_backup", backup_mock):
            await keycloak_reconciler.cleanup_resources(
                "test-keycloak", "test-namespace", spec
            )

        backup_mock.assert_awaited_once()


class TestRealmFinalizers:
    """Validate finalizer cleanup for Keycloak realms."""

    @pytest.fixture
    def realm_reconciler(self):
        # Create a mock Kubernetes API client to avoid loading kubeconfig
        mock_k8s_client = MagicMock()
        return KeycloakRealmReconciler(k8s_client=mock_k8s_client)

    @pytest.fixture
    def mock_keycloak_admin(self):
        admin = AsyncMock()
        admin.delete_realm = AsyncMock()
        admin.export_realm = AsyncMock(return_value={"realm": "test"})
        admin.get_realm_clients = AsyncMock(return_value=[])
        return admin

    @pytest.mark.asyncio
    async def test_realm_cleanup_success(self, realm_reconciler, mock_keycloak_admin):
        spec = build_spec(BASE_REALM_SPEC)

        async def mock_factory(*args, **kwargs):
            return mock_keycloak_admin

        realm_reconciler.keycloak_admin_factory = mock_factory

        await realm_reconciler.cleanup_resources(
            "test-realm", "test-namespace", spec, status=MagicMock()
        )

        mock_keycloak_admin.delete_realm.assert_called_with(
            "test-realm", "test-namespace"
        )

    @pytest.mark.asyncio
    async def test_realm_cleanup_keycloak_unreachable(self, realm_reconciler):
        spec = build_spec(BASE_REALM_SPEC)

        realm_reconciler.keycloak_admin_factory = MagicMock(
            side_effect=Exception("Connection failed")
        )

        await realm_reconciler.cleanup_resources(
            "test-realm", "test-namespace", spec, status=MagicMock()
        )


class TestClientFinalizers:
    """Validate finalizer cleanup for Keycloak clients."""

    @pytest.fixture
    def client_reconciler(self):
        # Create a mock Kubernetes API client to avoid loading kubeconfig
        mock_k8s_client = MagicMock()
        reconciler = KeycloakClientReconciler(k8s_client=mock_k8s_client)
        # Mock _get_realm_info to return expected values without calling K8s API
        # Returns: (actual_realm_name, keycloak_namespace, keycloak_name, realm_resource)
        reconciler._get_realm_info = MagicMock(  # ty: ignore[invalid-assignment]
            return_value=("test-realm", "test-namespace", "keycloak", {})
        )
        return reconciler

    @pytest.fixture
    def mock_keycloak_admin(self):
        admin = MagicMock()
        admin.delete_client = MagicMock()
        admin.get_client_secret = MagicMock(return_value="secret-value")
        return admin

    @pytest.fixture
    def mock_core_v1_api(self):
        api = MagicMock()
        api.delete_namespaced_secret = MagicMock()
        api.delete_namespaced_config_map = MagicMock()
        api.list_namespaced_config_map.return_value = SimpleNamespace(items=[])
        api.list_namespaced_secret.return_value = SimpleNamespace(items=[])
        return api

    @pytest.mark.asyncio
    async def test_client_cleanup_success(
        self, client_reconciler, mock_keycloak_admin, mock_core_v1_api
    ):
        spec = build_spec(BASE_CLIENT_SPEC, public_client=False)

        client_reconciler.keycloak_admin_factory = AsyncMock(
            return_value=mock_keycloak_admin
        )
        client_reconciler.k8s_client = MagicMock()

        with patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api",
            return_value=mock_core_v1_api,
        ):
            await client_reconciler.cleanup_resources(
                "test-client", "test-namespace", spec, status=MagicMock()
            )

        mock_keycloak_admin.delete_client.assert_called()
        mock_core_v1_api.delete_namespaced_secret.assert_called()

    @pytest.mark.asyncio
    async def test_client_cleanup_public_client(
        self, client_reconciler, mock_keycloak_admin, mock_core_v1_api
    ):
        spec = build_spec(BASE_CLIENT_SPEC, public_client=True)

        client_reconciler.keycloak_admin_factory = AsyncMock(
            return_value=mock_keycloak_admin
        )
        client_reconciler.k8s_client = MagicMock()

        with patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api",
            return_value=mock_core_v1_api,
        ):
            await client_reconciler.cleanup_resources(
                "test-client", "test-namespace", spec, status=MagicMock()
            )

        mock_keycloak_admin.delete_client.assert_called()
        mock_core_v1_api.delete_namespaced_secret.assert_called()

    @pytest.mark.asyncio
    async def test_client_cleanup_removes_labeled_resources(
        self, client_reconciler, mock_keycloak_admin, mock_core_v1_api
    ):
        spec = build_spec(BASE_CLIENT_SPEC)

        mock_core_v1_api.list_namespaced_config_map.return_value = SimpleNamespace(
            items=[SimpleNamespace(metadata=SimpleNamespace(name="cm-1"))]
        )
        mock_core_v1_api.list_namespaced_secret.return_value = SimpleNamespace(
            items=[SimpleNamespace(metadata=SimpleNamespace(name="extra-secret"))]
        )

        client_reconciler.keycloak_admin_factory = AsyncMock(
            return_value=mock_keycloak_admin
        )
        client_reconciler.k8s_client = MagicMock()

        with patch(
            "keycloak_operator.services.client_reconciler.client.CoreV1Api",
            return_value=mock_core_v1_api,
        ):
            await client_reconciler.cleanup_resources(
                "test-client", "test-namespace", spec, status=MagicMock()
            )

        mock_core_v1_api.delete_namespaced_config_map.assert_called()
        # Called for credentials secret and additional labeled secret
        assert mock_core_v1_api.delete_namespaced_secret.call_count >= 2


class TestFinalizerConstants:
    """Ensure finalizer constants remain stable."""

    def test_finalizer_constants_exist(self):
        assert KEYCLOAK_FINALIZER == "vriesdemichael.github.io/keycloak-cleanup"
        assert REALM_FINALIZER == "vriesdemichael.github.io/keycloak-realm-cleanup"
        assert CLIENT_FINALIZER == "vriesdemichael.github.io/keycloak-client-cleanup"

    def test_finalizer_constants_unique(self):
        finalizers = {KEYCLOAK_FINALIZER, REALM_FINALIZER, CLIENT_FINALIZER}
        assert len(finalizers) == 3


class TestFinalizerErrorHandling:
    """Exercise error handling paths during cleanup."""

    @pytest.fixture
    def keycloak_reconciler(self):
        # Create a mock Kubernetes API client to avoid loading kubeconfig
        mock_k8s_client = MagicMock()
        return KeycloakInstanceReconciler(k8s_client=mock_k8s_client)

    @pytest.mark.asyncio
    async def test_cleanup_continues_on_partial_failures(
        self, keycloak_reconciler, keycloak_k8s_apis
    ):
        spec = build_spec(BASE_KEYCLOAK_SPEC)

        keycloak_k8s_apis.core.delete_namespaced_service.side_effect = Exception(
            "Service deletion failed"
        )
        keycloak_k8s_apis.core.list_namespaced_secret.return_value = SimpleNamespace(
            items=[SimpleNamespace(metadata=SimpleNamespace(name="secret-1"))]
        )

        await keycloak_reconciler.cleanup_resources(
            "test-keycloak", "test-namespace", spec
        )

        assert keycloak_k8s_apis.apps.delete_namespaced_deployment.called
        assert keycloak_k8s_apis.core.delete_namespaced_secret.called

    @pytest.mark.asyncio
    async def test_cleanup_logs_errors_but_continues(
        self, keycloak_reconciler, keycloak_k8s_apis
    ):
        spec = build_spec(BASE_KEYCLOAK_SPEC)

        keycloak_k8s_apis.apps.delete_namespaced_deployment.side_effect = Exception(
            "Critical error"
        )

        keycloak_reconciler.logger = MagicMock()

        await keycloak_reconciler.cleanup_resources(
            "test-keycloak", "test-namespace", spec
        )

        keycloak_reconciler.logger.warning.assert_called()
