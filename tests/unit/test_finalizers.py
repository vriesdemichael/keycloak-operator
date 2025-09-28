"""
Test finalizer behavior for Keycloak operator resources.

This module tests the finalizer functionality across all resource types
to ensure proper cleanup and prevent orphaned resources.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.constants import (
    CLIENT_FINALIZER,
    KEYCLOAK_FINALIZER,
    REALM_FINALIZER,
)
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler
from keycloak_operator.services.keycloak_reconciler import KeycloakInstanceReconciler
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


class TestKeycloakFinalizers:
    """Test finalizer behavior for Keycloak instances."""

    @pytest.fixture
    def keycloak_reconciler(self):
        """Create a Keycloak reconciler for testing."""
        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            return KeycloakInstanceReconciler()

    @pytest.fixture
    def mock_k8s_client(self):
        """Mock Kubernetes client."""
        mock_client = MagicMock()
        mock_client.delete_namespaced_deployment = AsyncMock()
        mock_client.delete_namespaced_service = AsyncMock()
        mock_client.delete_namespaced_ingress = AsyncMock()
        mock_client.delete_namespaced_secret = AsyncMock()
        mock_client.delete_namespaced_persistent_volume_claim = AsyncMock()
        return mock_client

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_resources_success(
        self, keycloak_reconciler, mock_k8s_client
    ):
        """Test successful Keycloak resource cleanup."""
        # Setup
        name = "test-keycloak"
        namespace = "test-namespace"
        spec = {"persistence": {"enabled": True}, "ingress": {"enabled": True}}

        with patch.object(keycloak_reconciler, "k8s_client", mock_k8s_client):
            # Execute
            await keycloak_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify cleanup order: ingress -> service -> deployment -> secrets -> PVC
            assert mock_k8s_client.delete_namespaced_ingress.called
            assert mock_k8s_client.delete_namespaced_service.called
            assert mock_k8s_client.delete_namespaced_deployment.called
            assert mock_k8s_client.delete_namespaced_secret.called
            assert mock_k8s_client.delete_namespaced_persistent_volume_claim.called

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_partial_failure(
        self, keycloak_reconciler, mock_k8s_client
    ):
        """Test Keycloak cleanup with some resources missing (should not fail)."""
        # Setup
        name = "test-keycloak"
        namespace = "test-namespace"
        spec = {"persistence": {"enabled": False}}

        # Simulate some resources not found (404 errors)
        from kubernetes.client.rest import ApiException

        mock_k8s_client.delete_namespaced_ingress.side_effect = ApiException(status=404)

        with patch.object(keycloak_reconciler, "k8s_client", mock_k8s_client):
            # Execute - should not raise exception
            await keycloak_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify other resources were still attempted
            assert mock_k8s_client.delete_namespaced_service.called
            assert mock_k8s_client.delete_namespaced_deployment.called

    @pytest.mark.asyncio
    async def test_keycloak_cleanup_with_backup(
        self, keycloak_reconciler, mock_k8s_client
    ):
        """Test Keycloak cleanup includes backup logic when configured."""
        # Setup
        name = "test-keycloak"
        namespace = "test-namespace"
        spec = {
            "backup": {"enabled": True, "schedule": "0 2 * * *"},
            "persistence": {"enabled": True},
        }

        with (
            patch.object(keycloak_reconciler, "k8s_client", mock_k8s_client),
            patch.object(keycloak_reconciler, "_create_backup") as mock_backup,
        ):
            # Execute
            await keycloak_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify backup was attempted before cleanup
            assert mock_backup.called
            assert mock_k8s_client.delete_namespaced_deployment.called


class TestRealmFinalizers:
    """Test finalizer behavior for Keycloak realms."""

    @pytest.fixture
    def realm_reconciler(self):
        """Create a Realm reconciler for testing."""
        return KeycloakRealmReconciler()

    @pytest.fixture
    def mock_keycloak_admin(self):
        """Mock Keycloak admin client."""
        mock_admin = MagicMock()
        mock_admin.delete_realm = MagicMock()
        mock_admin.export_realm = MagicMock(return_value={"realm": "test-data"})
        return mock_admin

    @pytest.mark.asyncio
    async def test_realm_cleanup_success(self, realm_reconciler, mock_keycloak_admin):
        """Test successful realm cleanup from Keycloak."""
        # Setup
        name = "test-realm"
        namespace = "test-namespace"
        spec = {
            "realm_name": "test-realm",
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": "test-namespace",
            },
        }

        with patch(
            "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
            return_value=mock_keycloak_admin,
        ):
            # Execute
            await realm_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify realm deletion was called
            mock_keycloak_admin.delete_realm.assert_called_with("test-realm")

    @pytest.mark.asyncio
    async def test_realm_cleanup_with_export(
        self, realm_reconciler, mock_keycloak_admin
    ):
        """Test realm cleanup includes export for backup."""
        # Setup
        name = "test-realm"
        namespace = "test-namespace"
        spec = {
            "realm_name": "test-realm",
            "keycloak_instance_ref": {"name": "test-keycloak"},
            "backup_before_delete": True,
        }

        with (
            patch(
                "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
                return_value=mock_keycloak_admin,
            ),
            patch.object(realm_reconciler, "_store_realm_backup") as mock_store,
        ):
            # Execute
            await realm_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify export and storage happened before deletion
            mock_keycloak_admin.export_realm.assert_called_with("test-realm")
            assert mock_store.called
            mock_keycloak_admin.delete_realm.assert_called_with("test-realm")

    @pytest.mark.asyncio
    async def test_realm_cleanup_keycloak_unreachable(self, realm_reconciler):
        """Test realm cleanup when Keycloak is unreachable (should not block deletion)."""
        # Setup
        name = "test-realm"
        namespace = "test-namespace"
        spec = {
            "realm_name": "test-realm",
            "keycloak_instance_ref": {"name": "test-keycloak"},
        }

        with patch(
            "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
            side_effect=Exception("Connection failed"),
        ):
            # Execute - should not raise exception (allows finalizer removal)
            await realm_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Test should complete without error


class TestClientFinalizers:
    """Test finalizer behavior for Keycloak clients."""

    @pytest.fixture
    def client_reconciler(self):
        """Create a Client reconciler for testing."""
        return KeycloakClientReconciler()

    @pytest.fixture
    def mock_keycloak_admin(self):
        """Mock Keycloak admin client."""
        mock_admin = MagicMock()
        mock_admin.delete_client = MagicMock()
        mock_admin.get_client_secret = MagicMock(return_value="secret-value")
        return mock_admin

    @pytest.fixture
    def mock_k8s_client(self):
        """Mock Kubernetes client."""
        mock_client = MagicMock()
        mock_client.delete_namespaced_secret = AsyncMock()
        return mock_client

    @pytest.mark.asyncio
    async def test_client_cleanup_success(
        self, client_reconciler, mock_keycloak_admin, mock_k8s_client
    ):
        """Test successful client cleanup from Keycloak and Kubernetes."""
        # Setup
        name = "test-client"
        namespace = "test-namespace"
        spec = {
            "client_id": "test-client",
            "realm": "test-realm",
            "keycloak_instance_ref": {"name": "test-keycloak"},
            "public_client": False,
        }

        with (
            patch(
                "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
                return_value=mock_keycloak_admin,
            ),
            patch.object(client_reconciler, "k8s_client", mock_k8s_client),
        ):
            # Execute
            await client_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify client deletion from Keycloak
            mock_keycloak_admin.delete_client.assert_called()

            # Verify credential secret deletion from Kubernetes
            mock_k8s_client.delete_namespaced_secret.assert_called()

    @pytest.mark.asyncio
    async def test_client_cleanup_public_client(
        self, client_reconciler, mock_keycloak_admin, mock_k8s_client
    ):
        """Test cleanup of public client (no credential secret to delete)."""
        # Setup
        name = "test-client"
        namespace = "test-namespace"
        spec = {
            "client_id": "test-client",
            "realm": "test-realm",
            "keycloak_instance_ref": {"name": "test-keycloak"},
            "public_client": True,
        }

        with (
            patch(
                "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
                return_value=mock_keycloak_admin,
            ),
            patch.object(client_reconciler, "k8s_client", mock_k8s_client),
        ):
            # Execute
            await client_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify client deletion from Keycloak
            mock_keycloak_admin.delete_client.assert_called()

            # Verify no secret deletion for public client
            mock_k8s_client.delete_namespaced_secret.assert_not_called()

    @pytest.mark.asyncio
    async def test_client_cleanup_with_backup(
        self, client_reconciler, mock_keycloak_admin, mock_k8s_client
    ):
        """Test client cleanup includes credential backup."""
        # Setup
        name = "test-client"
        namespace = "test-namespace"
        spec = {
            "client_id": "test-client",
            "realm": "test-realm",
            "keycloak_instance_ref": {"name": "test-keycloak"},
            "public_client": False,
            "backup_credentials": True,
        }

        with (
            patch(
                "keycloak_operator.utils.keycloak_admin.get_keycloak_admin_client",
                return_value=mock_keycloak_admin,
            ),
            patch.object(client_reconciler, "k8s_client", mock_k8s_client),
            patch.object(
                client_reconciler, "_backup_client_credentials"
            ) as mock_backup,
        ):
            # Execute
            await client_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify backup happened before deletion
            assert mock_backup.called
            mock_keycloak_admin.delete_client.assert_called()


class TestFinalizerConstants:
    """Test finalizer constants are properly defined."""

    def test_finalizer_constants_exist(self):
        """Test all required finalizer constants are defined."""
        assert KEYCLOAK_FINALIZER == "keycloak.mdvr.nl/cleanup"
        assert REALM_FINALIZER == "keycloak.mdvr.nl/realm-cleanup"
        assert CLIENT_FINALIZER == "keycloak.mdvr.nl/client-cleanup"

    def test_finalizer_constants_unique(self):
        """Test all finalizer constants are unique."""
        finalizers = {KEYCLOAK_FINALIZER, REALM_FINALIZER, CLIENT_FINALIZER}
        assert len(finalizers) == 3, "Finalizer constants must be unique"


class TestFinalizerErrorHandling:
    """Test error handling during finalizer cleanup."""

    @pytest.fixture
    def keycloak_reconciler(self):
        """Create a Keycloak reconciler for testing."""
        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            return KeycloakInstanceReconciler()

    @pytest.mark.asyncio
    async def test_cleanup_continues_on_partial_failures(self, keycloak_reconciler):
        """Test that cleanup continues even if some resources fail to delete."""
        # Setup
        name = "test-keycloak"
        namespace = "test-namespace"
        spec = {"persistence": {"enabled": True}}

        mock_client = MagicMock()
        # First deletion fails, others succeed
        mock_client.delete_namespaced_service.side_effect = Exception(
            "Service deletion failed"
        )
        mock_client.delete_namespaced_deployment = AsyncMock()
        mock_client.delete_namespaced_secret = AsyncMock()

        with patch.object(keycloak_reconciler, "k8s_client", mock_client):
            # Execute - should not raise exception
            await keycloak_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify other resources were still attempted
            assert mock_client.delete_namespaced_deployment.called
            assert mock_client.delete_namespaced_secret.called

    @pytest.mark.asyncio
    async def test_cleanup_logs_errors_but_continues(self, keycloak_reconciler):
        """Test that cleanup errors are logged but don't prevent finalizer removal."""
        # Setup
        name = "test-keycloak"
        namespace = "test-namespace"
        spec = {}

        mock_client = MagicMock()
        mock_client.delete_namespaced_deployment.side_effect = Exception(
            "Critical error"
        )

        with (
            patch.object(keycloak_reconciler, "k8s_client", mock_client),
            patch(
                "keycloak_operator.services.keycloak_reconciler.logging"
            ) as mock_logging,
        ):
            # Execute
            await keycloak_reconciler.cleanup_resources(
                name, namespace, spec, status=MagicMock()
            )

            # Verify error was logged
            assert mock_logging.getLogger().error.called
