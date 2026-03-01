import base64
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.errors.operator_errors import ConfigurationError
from keycloak_operator.models.keycloak import KeycloakSpec
from keycloak_operator.services.keycloak_reconciler import KeycloakInstanceReconciler


@pytest.fixture
def k8s_client_mock():
    return MagicMock()


@pytest.fixture
def reconciler(k8s_client_mock):
    reconciler = KeycloakInstanceReconciler(k8s_client=k8s_client_mock)
    reconciler.logger = MagicMock()
    return reconciler


@pytest.fixture
def base_spec_dict():
    return {
        "image": "quay.io/keycloak/keycloak:26.4.0",
        "replicas": 1,
        "database": {
            "type": "postgresql",
            "host": "db",
            "database": "keycloak",
            "username": "kc",
            "passwordSecret": {"name": "db-secret"},
        },
    }


@pytest.fixture
def default_spec(base_spec_dict):
    return KeycloakSpec.model_validate(base_spec_dict)


@pytest.mark.asyncio
async def test_ensure_admin_access_generated(reconciler, default_spec):
    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret does not exist
        error = ApiException(status=404)
        core_api_mock.read_namespaced_secret.side_effect = error

        with patch(
            "keycloak_operator.utils.kubernetes.create_admin_secret"
        ) as mock_create:
            await reconciler.ensure_admin_access(default_spec, "test-kc", "default")

            mock_create.assert_called_once()
            _, kwargs = mock_create.call_args
            assert kwargs["name"] == "test-kc"
            assert kwargs["namespace"] == "default"
            assert kwargs["username"] == "admin"
            assert kwargs["password"] is None
            assert (
                kwargs["annotations"]["vriesdemichael.github.io/credential-source"]
                == "generated"
            )
            assert (
                kwargs["annotations"]["vriesdemichael.github.io/rotation-enabled"]
                == "true"
            )


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_success(reconciler, base_spec_dict):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Setup existing secret mock
        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }

        # Mock read_namespaced_secret to return custom secret first, then 404 for proxy
        def read_secret_side_effect(name, namespace):
            if name == "my-custom-secret":
                return manual_secret
            elif name == "test-kc-admin-credentials":
                raise ApiException(status=404)
            raise ValueError(f"Unexpected secret name {name}")

        core_api_mock.read_namespaced_secret.side_effect = read_secret_side_effect

        with patch(
            "keycloak_operator.utils.kubernetes.create_admin_secret"
        ) as mock_create:
            await reconciler.ensure_admin_access(spec, "test-kc", "default")

            mock_create.assert_called_once()
            _, kwargs = mock_create.call_args
            assert kwargs["name"] == "test-kc"
            assert kwargs["namespace"] == "default"
            assert kwargs["username"] == "custom_admin"
            assert kwargs["password"] == "custom_password"
            assert (
                kwargs["annotations"]["vriesdemichael.github.io/credential-source"]
                == "external:my-custom-secret"
            )
            assert (
                kwargs["annotations"]["vriesdemichael.github.io/rotation-enabled"]
                == "false"
            )


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_missing(reconciler, base_spec_dict):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret does not exist
        core_api_mock.read_namespaced_secret.side_effect = ApiException(status=404)

        with pytest.raises(ConfigurationError) as exc_info:
            await reconciler.ensure_admin_access(spec, "test-kc", "default")

        assert "not found" in str(exc_info.value)
        assert "my-custom-secret" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_invalid_keys(
    reconciler, base_spec_dict
):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret exists but missing password
        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8")
        }
        core_api_mock.read_namespaced_secret.return_value = manual_secret

        with pytest.raises(ConfigurationError) as exc_info:
            await reconciler.ensure_admin_access(spec, "test-kc", "default")

        assert "must contain 'username' and 'password' keys" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_proxy_needs_update(
    reconciler, base_spec_dict
):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Setup existing secret mock
        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }

        # Setup existing proxy secret mock with DIFFERENT values
        proxy_secret = MagicMock()
        proxy_secret.data = {
            "username": base64.b64encode(b"old_admin").decode("utf-8"),
            "password": base64.b64encode(b"old_password").decode("utf-8"),
        }
        proxy_secret.metadata.annotations = {}

        def read_secret_side_effect(name, namespace):
            if name == "my-custom-secret":
                return manual_secret
            elif name == "test-kc-admin-credentials":
                return proxy_secret
            raise ValueError(f"Unexpected secret name {name}")

        core_api_mock.read_namespaced_secret.side_effect = read_secret_side_effect

        await reconciler.ensure_admin_access(spec, "test-kc", "default")

        core_api_mock.replace_namespaced_secret.assert_called_once()
        _, kwargs = core_api_mock.replace_namespaced_secret.call_args
        assert kwargs["name"] == "test-kc-admin-credentials"

        updated_proxy = kwargs["body"]
        assert updated_proxy.data["username"] == base64.b64encode(
            b"custom_admin"
        ).decode("utf-8")
        assert updated_proxy.data["password"] == base64.b64encode(
            b"custom_password"
        ).decode("utf-8")
        assert (
            updated_proxy.metadata.annotations[
                "vriesdemichael.github.io/credential-source"
            ]
            == "external:my-custom-secret"
        )


@pytest.mark.asyncio
async def test_ensure_admin_access_generated_already_exists_needs_annotation_update(
    reconciler, default_spec
):
    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret already exists but lacks correct annotations
        existing_proxy = MagicMock()
        existing_proxy.data = {
            "username": base64.b64encode(b"admin").decode("utf-8"),
            "password": base64.b64encode(b"generated").decode("utf-8"),
        }
        existing_proxy.metadata.annotations = None
        core_api_mock.read_namespaced_secret.return_value = existing_proxy

        await reconciler.ensure_admin_access(default_spec, "test-kc", "default")

        core_api_mock.replace_namespaced_secret.assert_called_once()
        _, kwargs = core_api_mock.replace_namespaced_secret.call_args
        updated_proxy = kwargs["body"]
        assert (
            updated_proxy.metadata.annotations[
                "vriesdemichael.github.io/credential-source"
            ]
            == "generated"
        )


@pytest.mark.asyncio
async def test_ensure_admin_access_generated_already_exists_up_to_date(
    reconciler, default_spec
):
    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret already exists and is fully up to date
        existing_proxy = MagicMock()
        existing_proxy.data = {
            "username": base64.b64encode(b"admin").decode("utf-8"),
            "password": base64.b64encode(b"generated").decode("utf-8"),
        }
        existing_proxy.metadata.annotations = {
            "vriesdemichael.github.io/credential-source": "generated",
            "vriesdemichael.github.io/rotation-enabled": "true",
        }
        core_api_mock.read_namespaced_secret.return_value = existing_proxy

        await reconciler.ensure_admin_access(default_spec, "test-kc", "default")

        core_api_mock.replace_namespaced_secret.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_already_exists_needs_annotation_update(
    reconciler, base_spec_dict
):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }

        existing_proxy = MagicMock()
        existing_proxy.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }
        existing_proxy.metadata.annotations = {
            "vriesdemichael.github.io/credential-source": "generated"  # Wrong annotation
        }

        def read_secret_side_effect(name, namespace):
            if name == "my-custom-secret":
                return manual_secret
            elif name == "test-kc-admin-credentials":
                return existing_proxy
            raise ValueError(f"Unexpected secret name {name}")

        core_api_mock.read_namespaced_secret.side_effect = read_secret_side_effect

        await reconciler.ensure_admin_access(spec, "test-kc", "default")

        core_api_mock.replace_namespaced_secret.assert_called_once()
        _, kwargs = core_api_mock.replace_namespaced_secret.call_args
        updated_proxy = kwargs["body"]
        assert (
            updated_proxy.metadata.annotations[
                "vriesdemichael.github.io/credential-source"
            ]
            == "external:my-custom-secret"
        )


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_data_none(
    reconciler, base_spec_dict
):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }

        existing_proxy = MagicMock()
        existing_proxy.data = None  # data is None
        existing_proxy.metadata.annotations = {}

        def read_secret_side_effect(name, namespace):
            if name == "my-custom-secret":
                return manual_secret
            elif name == "test-kc-admin-credentials":
                return existing_proxy
            raise ValueError(f"Unexpected secret name {name}")

        core_api_mock.read_namespaced_secret.side_effect = read_secret_side_effect

        await reconciler.ensure_admin_access(spec, "test-kc", "default")

        core_api_mock.replace_namespaced_secret.assert_called_once()


@pytest.mark.asyncio
async def test_ensure_admin_access_api_exception_propagates(reconciler, default_spec):
    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Raise generic API exception (not 404)
        core_api_mock.read_namespaced_secret.side_effect = ApiException(status=500)

        with pytest.raises(ApiException):
            await reconciler.ensure_admin_access(default_spec, "test-kc", "default")


@pytest.mark.asyncio
async def test_ensure_admin_access_existing_secret_empty_values(
    reconciler, base_spec_dict
):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin"] = {"existingSecret": "my-custom-secret"}
    spec = KeycloakSpec.model_validate(spec_dict)

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Secret exists but has empty values
        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"").decode("utf-8"),
            "password": base64.b64encode(b"").decode("utf-8"),
        }
        core_api_mock.read_namespaced_secret.return_value = manual_secret

        with pytest.raises(ConfigurationError) as exc_info:
            await reconciler.ensure_admin_access(spec, "test-kc", "default")

        assert "must have non-empty 'username' and 'password' values" in str(
            exc_info.value
        )


@pytest.mark.asyncio
async def test_ensure_admin_access_legacy_admin_access(reconciler, base_spec_dict):
    spec_dict = dict(base_spec_dict)
    spec_dict["admin_access"] = {"existingSecret": "legacy-custom-secret"}
    # Pydantic should map this to `admin` due to AliasChoices
    spec = KeycloakSpec.model_validate(spec_dict)

    assert spec.admin is not None
    assert spec.admin.existing_secret == "legacy-custom-secret"

    with patch(
        "keycloak_operator.services.keycloak_reconciler.client.CoreV1Api"
    ) as mock_api:
        core_api_mock = MagicMock()
        mock_api.return_value = core_api_mock

        # Setup existing secret mock
        manual_secret = MagicMock()
        manual_secret.data = {
            "username": base64.b64encode(b"custom_admin").decode("utf-8"),
            "password": base64.b64encode(b"custom_password").decode("utf-8"),
        }

        def read_secret_side_effect(name, namespace):
            if name == "legacy-custom-secret":
                return manual_secret
            elif name == "test-kc-admin-credentials":
                raise ApiException(status=404)
            raise ValueError(f"Unexpected secret name {name}")

        core_api_mock.read_namespaced_secret.side_effect = read_secret_side_effect

        with patch(
            "keycloak_operator.utils.kubernetes.create_admin_secret"
        ) as mock_create:
            await reconciler.ensure_admin_access(spec, "test-kc", "default")

            mock_create.assert_called_once()
            _, kwargs = mock_create.call_args
            assert kwargs["name"] == "test-kc"
            assert kwargs["namespace"] == "default"
            assert kwargs["username"] == "custom_admin"
            assert kwargs["password"] == "custom_password"
            assert (
                kwargs["annotations"]["vriesdemichael.github.io/credential-source"]
                == "external:legacy-custom-secret"
            )
