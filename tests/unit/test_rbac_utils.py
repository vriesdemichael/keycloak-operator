"""
Unit tests for RBAC utility functions.

Tests check_namespace_access, validate_secret_label, and get_secret_with_validation
by mocking the Kubernetes API client.
"""

import base64
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import ALLOW_OPERATOR_READ_LABEL


# ---------------------------------------------------------------------------
# check_namespace_access
# ---------------------------------------------------------------------------
class TestCheckNamespaceAccess:
    """Test check_namespace_access SubjectAccessReview checks."""

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_access_allowed(self, mock_settings, mock_auth_cls):
        """Returns (True, None) when access is allowed."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_result = MagicMock()
        mock_result.status.allowed = True
        mock_auth.create_subject_access_review.return_value = mock_result

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is True
        assert error_msg is None

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_access_denied(self, mock_settings, mock_auth_cls):
        """Returns (False, error_msg) when access is denied."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_result = MagicMock()
        mock_result.status.allowed = False
        mock_result.status.reason = "no permission"
        mock_auth.create_subject_access_review.return_value = mock_result

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is False
        assert error_msg is not None
        assert "target-ns" in error_msg

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_access_denied_reason_none(self, mock_settings, mock_auth_cls):
        """Returns error_msg with 'Unknown reason' when status.reason is None."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_result = MagicMock()
        mock_result.status.allowed = False
        mock_result.status.reason = None
        mock_auth.create_subject_access_review.return_value = mock_result

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is False
        assert error_msg is not None

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_403_api_exception(self, mock_settings, mock_auth_cls):
        """HTTP 403 from SAR returns access denied."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_auth.create_subject_access_review.side_effect = ApiException(
            status=403, reason="Forbidden"
        )

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is False
        assert error_msg is not None

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_non_403_api_exception(self, mock_settings, mock_auth_cls):
        """Non-403 API error returns False with error message."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_auth.create_subject_access_review.side_effect = ApiException(
            status=500, reason="Internal Server Error"
        )

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is False
        assert error_msg is not None
        assert "API error" in error_msg

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_unexpected_exception(self, mock_settings, mock_auth_cls):
        """Unexpected exception returns False with error message."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = "my-sa"
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_auth.create_subject_access_review.side_effect = RuntimeError("boom")

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, error_msg = await check_namespace_access(
                "target-ns", "operator-ns"
            )

        assert has_access is False
        assert error_msg is not None
        assert "Unexpected error" in error_msg

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.AuthorizationV1Api")
    @patch("keycloak_operator.utils.rbac.settings")
    async def test_default_service_account_name(self, mock_settings, mock_auth_cls):
        """When service_account_name is None, uses fallback pattern."""
        from keycloak_operator.utils.rbac import check_namespace_access

        mock_settings.service_account_name = None
        mock_auth = MagicMock()
        mock_auth_cls.return_value = mock_auth
        mock_result = MagicMock()
        mock_result.status.allowed = True
        mock_auth.create_subject_access_review.return_value = mock_result

        with patch("keycloak_operator.utils.rbac._record_rbac_metric"):
            has_access, _ = await check_namespace_access("target-ns", "operator-ns")

        assert has_access is True
        # Verify the fallback SA name was used
        call_args = mock_auth.create_subject_access_review.call_args
        sar_body = (
            call_args.kwargs.get("body") or call_args[1].get("body") or call_args[0][0]
        )
        assert "keycloak-operator-operator-ns" in sar_body.spec.user


# ---------------------------------------------------------------------------
# validate_secret_label
# ---------------------------------------------------------------------------
class TestValidateSecretLabel:
    """Test validate_secret_label checks."""

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_with_label_is_valid(self, mock_core_cls):
        """Secret with the required label returns (True, None)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.metadata.labels = {ALLOW_OPERATOR_READ_LABEL: "true"}
        mock_core.read_namespaced_secret.return_value = mock_secret

        is_valid, error_msg = await validate_secret_label("my-secret", "ns-a")

        assert is_valid is True
        assert error_msg is None

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_without_label_is_invalid(self, mock_core_cls):
        """Secret missing the required label returns (False, error_msg)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.metadata.labels = {}
        mock_core.read_namespaced_secret.return_value = mock_secret

        is_valid, error_msg = await validate_secret_label("my-secret", "ns-a")

        assert is_valid is False
        assert error_msg is not None
        assert ALLOW_OPERATOR_READ_LABEL in error_msg

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_with_wrong_label_value(self, mock_core_cls):
        """Label set to 'false' instead of 'true' is invalid."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.metadata.labels = {ALLOW_OPERATOR_READ_LABEL: "false"}
        mock_core.read_namespaced_secret.return_value = mock_secret

        is_valid, error_msg = await validate_secret_label("my-secret", "ns-a")

        assert is_valid is False

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_with_none_labels(self, mock_core_cls):
        """Secret with labels=None is invalid."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.metadata.labels = None
        mock_core.read_namespaced_secret.return_value = mock_secret

        is_valid, error_msg = await validate_secret_label("my-secret", "ns-a")

        assert is_valid is False

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_not_found_404(self, mock_core_cls):
        """Secret not found returns (False, error_msg)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        is_valid, error_msg = await validate_secret_label("missing-secret", "ns-a")

        assert is_valid is False
        assert error_msg is not None
        assert "not found" in error_msg.lower()

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_forbidden_403(self, mock_core_cls):
        """403 on secret read returns (False, error_msg)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=403, reason="Forbidden"
        )

        is_valid, error_msg = await validate_secret_label(
            "secret", "ns-a", operator_namespace="op-ns"
        )

        assert is_valid is False

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_secret_other_api_error(self, mock_core_cls):
        """Other API errors return (False, error_msg)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=500, reason="Internal Server Error"
        )

        is_valid, error_msg = await validate_secret_label("secret", "ns-a")

        assert is_valid is False
        assert error_msg is not None
        assert "API error" in error_msg

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    async def test_unexpected_exception(self, mock_core_cls):
        """Unexpected exception returns (False, error_msg)."""
        from keycloak_operator.utils.rbac import validate_secret_label

        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_core.read_namespaced_secret.side_effect = RuntimeError("boom")

        is_valid, error_msg = await validate_secret_label("secret", "ns-a")

        assert is_valid is False
        assert error_msg is not None
        assert "Unexpected error" in error_msg


# ---------------------------------------------------------------------------
# get_secret_with_validation
# ---------------------------------------------------------------------------
class TestGetSecretWithValidation:
    """Test get_secret_with_validation orchestration."""

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    @patch("keycloak_operator.utils.rbac.check_namespace_access")
    async def test_same_namespace_skips_access_check(
        self, mock_access, mock_label, mock_core_cls
    ):
        """Reading from operator's own namespace skips namespace access check."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_label.return_value = (True, None)
        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.data = {"key": base64.b64encode(b"value").decode("utf-8")}
        mock_core.read_namespaced_secret.return_value = mock_secret

        value, error = await get_secret_with_validation(
            "my-secret", "op-ns", "op-ns", key="key"
        )

        mock_access.assert_not_called()
        assert value == "value"
        assert error is None

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    @patch("keycloak_operator.utils.rbac.check_namespace_access")
    async def test_different_namespace_checks_access(self, mock_access, mock_label):
        """Reading from different namespace performs access check."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_access.return_value = (False, "Access denied")

        value, error = await get_secret_with_validation(
            "my-secret", "target-ns", "op-ns", key="key"
        )

        mock_access.assert_called_once_with("target-ns", "op-ns")
        assert value is None
        assert error == "Access denied"

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    @patch("keycloak_operator.utils.rbac.check_namespace_access")
    async def test_missing_key_returns_error(
        self, mock_access, mock_label, mock_core_cls
    ):
        """Requesting a key that doesn't exist returns error."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_access.return_value = (True, None)
        mock_label.return_value = (True, None)
        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.data = {"other_key": base64.b64encode(b"val").decode("utf-8")}
        mock_core.read_namespaced_secret.return_value = mock_secret

        value, error = await get_secret_with_validation(
            "my-secret", "target-ns", "op-ns", key="missing_key"
        )

        assert value is None
        assert error is not None
        assert "missing_key" in error

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    @patch("keycloak_operator.utils.rbac.check_namespace_access")
    async def test_no_key_returns_all_decoded_data(
        self, mock_access, mock_label, mock_core_cls
    ):
        """Without a key, returns all decoded data as a dict."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_access.return_value = (True, None)
        mock_label.return_value = (True, None)
        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_secret = MagicMock()
        mock_secret.data = {
            "user": base64.b64encode(b"admin").decode("utf-8"),
            "pass": base64.b64encode(b"secret").decode("utf-8"),
        }
        mock_core.read_namespaced_secret.return_value = mock_secret

        value, error = await get_secret_with_validation(
            "my-secret", "target-ns", "op-ns"
        )

        assert error is None
        assert value == {"user": "admin", "pass": "secret"}

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    async def test_label_validation_fails(self, mock_label):
        """If label validation fails, returns error."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_label.return_value = (False, "Missing label")

        value, error = await get_secret_with_validation(
            "my-secret", "op-ns", "op-ns", key="key"
        )

        assert value is None
        assert error == "Missing label"

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rbac.client.CoreV1Api")
    @patch("keycloak_operator.utils.rbac.validate_secret_label")
    async def test_api_exception_on_read(self, mock_label, mock_core_cls):
        """ApiException during secret read returns error."""
        from keycloak_operator.utils.rbac import get_secret_with_validation

        mock_label.return_value = (True, None)
        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=500, reason="fail"
        )

        value, error = await get_secret_with_validation(
            "my-secret", "op-ns", "op-ns", key="key"
        )

        assert value is None
        assert error is not None
        assert "API error" in error
