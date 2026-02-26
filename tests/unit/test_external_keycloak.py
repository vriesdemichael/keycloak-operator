import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.handlers.keycloak import ensure_keycloak_instance
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler
from keycloak_operator.settings import Settings
from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminError,
    get_keycloak_admin_client,
)
from keycloak_operator.utils.kubernetes import validate_keycloak_reference


# Test Settings
def test_external_keycloak_settings():
    settings = Settings(
        KEYCLOAK_URL="https://external.keycloak",
        KEYCLOAK_ADMIN_SECRET="ext-secret",
    )
    assert settings.keycloak_url == "https://external.keycloak"
    assert settings.keycloak_admin_secret == "ext-secret"
    assert settings.keycloak_admin_username == "admin"


# Test validate_keycloak_reference
@patch("keycloak_operator.utils.kubernetes.settings")
def test_validate_keycloak_reference_external(mock_settings):
    mock_settings.keycloak_url = "https://external.keycloak"

    result = validate_keycloak_reference("my-keycloak", "default")

    assert result is not None
    assert result["status"]["phase"] == "Ready"
    assert result["status"]["endpoints"]["admin"] == "https://external.keycloak"
    assert result["status"]["endpoints"]["public"] == "https://external.keycloak"


# Test get_keycloak_admin_client
@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin.KeycloakAdminClient")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._admin_client_cache", {})
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external(
    mock_cache_lock, mock_cls, mock_get_k8s, mock_settings
):
    # Setup mock lock to be an async context manager
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"
    mock_settings.keycloak_admin_username = "admin"
    mock_settings.keycloak_admin_password_key = "password"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock KeycloakAdminClient instance
    mock_instance = MagicMock()
    # Make authenticate awaitable
    future = asyncio.Future()
    future.set_result(None)
    mock_instance.authenticate.return_value = future
    mock_cls.return_value = mock_instance

    # Mock CoreV1Api usage
    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        mock_secret = MagicMock()
        mock_secret.data = {"password": base64.b64encode(b"secret-pass").decode()}
        mock_core.read_namespaced_secret.return_value = mock_secret

        # Call the function
        _ = await get_keycloak_admin_client("my-kc", "default")

        # Verify secret lookup
        mock_core.read_namespaced_secret.assert_called_with(
            name="ext-secret", namespace="operator-ns"
        )

        # Verify client creation
        mock_cls.assert_called_with(
            server_url="https://external.keycloak",
            username="admin",
            password="secret-pass",
            verify_ssl=False,
            rate_limiter=None,
            keycloak_name="global",
            keycloak_namespace="operator-ns",
        )


@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external_missing_key(
    mock_cache_lock, mock_get_k8s, mock_settings
):
    # Setup mock lock
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"
    mock_settings.keycloak_admin_username = "admin"
    mock_settings.keycloak_admin_password_key = "password"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock CoreV1Api usage with missing key
    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        mock_secret = MagicMock()
        mock_secret.data = {"wrong-key": "value"}
        mock_core.read_namespaced_secret.return_value = mock_secret

        with pytest.raises(KeycloakAdminError) as excinfo:
            await get_keycloak_admin_client("my-kc", "default")

        assert "Key 'password' not found" in str(excinfo.value)


@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external_secret_not_found(
    mock_cache_lock, mock_get_k8s, mock_settings
):
    # Setup mock lock
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock exception when reading secret
    # Need to import ApiException to mock it
    from kubernetes.client.rest import ApiException

    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        # Simulate 404
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        with pytest.raises(KeycloakAdminError) as excinfo:
            await get_keycloak_admin_client("my-kc", "default")

        assert "Could not retrieve admin credentials" in str(excinfo.value)


@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin.KeycloakAdminClient")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._admin_client_cache", {})
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external_secret_data_none(
    mock_cache_lock, mock_cls, mock_get_k8s, mock_settings
):
    # Setup mock lock
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"
    mock_settings.keycloak_admin_password_key = "password"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock CoreV1Api usage with secret.data = None
    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        mock_secret = MagicMock()
        mock_secret.data = None
        mock_core.read_namespaced_secret.return_value = mock_secret

        with pytest.raises(KeycloakAdminError) as excinfo:
            await get_keycloak_admin_client("my-kc", "default")

        assert "has no data" in str(excinfo.value)


@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin.KeycloakAdminClient")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._admin_client_cache", {})
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external_invalid_base64(
    mock_cache_lock, mock_cls, mock_get_k8s, mock_settings
):
    # Setup mock lock
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"
    mock_settings.keycloak_admin_password_key = "password"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock CoreV1Api usage with invalid base64
    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        mock_secret = MagicMock()
        mock_secret.data = {"password": "not-base64"}
        mock_core.read_namespaced_secret.return_value = mock_secret

        with pytest.raises(KeycloakAdminError) as excinfo:
            await get_keycloak_admin_client("my-kc", "default")

        assert "Could not process admin credentials" in str(excinfo.value)


@pytest.mark.asyncio
@patch("keycloak_operator.utils.keycloak_admin.settings")
@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
@patch("keycloak_operator.utils.keycloak_admin.KeycloakAdminClient")
@patch("keycloak_operator.utils.keycloak_admin._cache_lock", new_callable=MagicMock)
@patch("keycloak_operator.utils.keycloak_admin._admin_client_cache", {})
@patch("keycloak_operator.utils.keycloak_admin._pending_creations", {})
async def test_get_keycloak_admin_client_external_auth_failure(
    mock_cache_lock, mock_cls, mock_get_k8s, mock_settings
):
    # Setup mock lock
    mock_lock_instance = MagicMock()
    mock_lock_instance.__aenter__.return_value = None
    mock_lock_instance.__aexit__.return_value = None
    mock_cache_lock.return_value = mock_lock_instance

    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.keycloak_admin_secret = "ext-secret"
    mock_settings.pod_namespace = "operator-ns"
    mock_settings.keycloak_admin_username = "admin"
    mock_settings.keycloak_admin_password_key = "password"

    mock_core = MagicMock()
    mock_k8s_client = MagicMock()
    mock_get_k8s.return_value = mock_k8s_client

    # Mock KeycloakAdminClient instance
    mock_instance = MagicMock()

    # Make authenticate fail
    async def _fail_authenticate():
        raise KeycloakAdminError("Authentication failed")

    mock_instance.authenticate.side_effect = _fail_authenticate
    mock_cls.return_value = mock_instance

    # Mock CoreV1Api usage
    with patch("kubernetes.client.CoreV1Api", return_value=mock_core):
        mock_secret = MagicMock()
        mock_secret.data = {"password": base64.b64encode(b"secret-pass").decode()}
        mock_core.read_namespaced_secret.return_value = mock_secret

        with pytest.raises(KeycloakAdminError) as excinfo:
            await get_keycloak_admin_client("my-kc", "default")

        assert "Admin client creation failed" in str(excinfo.value)


@pytest.mark.asyncio
@patch("keycloak_operator.settings.settings")
@patch("keycloak_operator.handlers.keycloak.log_handler_entry")
async def test_ensure_keycloak_instance_external(mock_log, mock_settings):
    mock_settings.keycloak_url = "https://external.keycloak"

    patch_obj = MagicMock()
    patch_obj.status = {}

    # Mock spec with valid database config to pass Pydantic validation
    spec = {
        "database": {
            "type": "postgresql",
            "host": "localhost",
            "database": "keycloak",
            "username": "keycloak",
            "password": "password",
        }
    }

    # Mock kwargs to avoid key error
    kwargs = {"meta": {}}

    # In agnostic mode, it should proceed if it is owned.
    # We mock it NOT owned for this test to verify it returns early.
    with (
        patch(
            "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
            return_value=False,
        ),
        patch("keycloak_operator.utils.kubernetes.get_kubernetes_client"),
        patch(
            "keycloak_operator.services.keycloak_reconciler.KeycloakInstanceReconciler._validate_database_connectivity"
        ),
    ):
        result = await ensure_keycloak_instance(
            spec=spec,
            name="my-kc",
            namespace="default",
            status={},
            patch=patch_obj,
            memo=MagicMock(),
            **kwargs,
        )
        assert result is None


# Test Reconciler Ignore Logic (ADR-062)
@pytest.mark.asyncio
@patch("keycloak_operator.services.realm_reconciler.settings")
async def test_realm_reconciler_ignores_wrong_namespace(mock_settings):
    mock_settings.operator_namespace = "correct-ns"
    mock_settings.keycloak_url = "http://keycloak"
    mock_settings.keycloak_admin_secret = "secret"
    mock_settings.pod_namespace = "ns"

    with patch("keycloak_operator.utils.kubernetes.get_kubernetes_client"):
        reconciler = KeycloakRealmReconciler()
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore[method-assign]
        reconciler._check_realm_capacity = AsyncMock()  # type: ignore[method-assign]
        spec = {
            "realmName": "test",
            "operatorRef": {"namespace": "wrong-ns"},
        }

        result = await reconciler.do_reconcile(
            spec=spec, name="test", namespace="ns", status=MagicMock()
        )

        assert result == {}


@pytest.mark.asyncio
@patch("keycloak_operator.services.client_reconciler.settings")
@patch("keycloak_operator.services.client_reconciler.asyncio")
async def test_client_reconciler_ignores_wrong_namespace(mock_asyncio, mock_settings):
    mock_settings.operator_namespace = "correct-ns"
    mock_settings.keycloak_url = "http://keycloak"
    mock_settings.keycloak_admin_secret = "secret"
    mock_settings.pod_namespace = "ns"

    with patch("keycloak_operator.utils.kubernetes.get_kubernetes_client"):
        reconciler = KeycloakClientReconciler()
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore[method-assign]

        # Mock _get_realm_resource to return a realm controlled by a different operator
        reconciler._get_realm_resource = MagicMock(  # type: ignore[method-assign]
            return_value={
                "spec": {
                    "realmName": "realm",
                    "operatorRef": {"namespace": "wrong-ns"},
                    "clientAuthorizationGrants": ["ns"],
                }
            }
        )
        # Mock to avoid threadpool calls
        mock_asyncio.to_thread = AsyncMock(side_effect=lambda f, *args: f(*args))

        spec = {
            "clientId": "test",
            "realmRef": {"name": "realm", "namespace": "wrong-ns"},
        }

        result = await reconciler.do_reconcile(
            spec=spec, name="test", namespace="ns", status=MagicMock()
        )

        assert result == {}
