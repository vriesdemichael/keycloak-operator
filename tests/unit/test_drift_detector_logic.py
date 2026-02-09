"""
Unit tests for DriftDetector core logic.

Tests _calculate_drift, _check_realm_resource_drift, _cr_exists, and
remediate_drift by mocking the Keycloak admin client and Kubernetes API.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.services.drift_detection_service import (
    DriftDetectionConfig,
    DriftDetector,
    DriftResult,
)


def _make_config(**overrides) -> DriftDetectionConfig:
    """Create a DriftDetectionConfig with sensible defaults."""
    defaults = {
        "enabled": True,
        "interval_seconds": 60,
        "auto_remediate": False,
        "minimum_age_hours": 1,
        "scope_realms": True,
        "scope_clients": True,
        "scope_identity_providers": False,
        "scope_roles": False,
    }
    defaults.update(overrides)
    return DriftDetectionConfig(**defaults)


def _make_detector(**overrides) -> DriftDetector:
    """Create a DriftDetector with all dependencies mocked out."""
    config = overrides.pop("config", _make_config())
    with (
        patch("keycloak_operator.services.drift_detection_service.client"),
        patch(
            "keycloak_operator.services.drift_detection_service.settings"
        ) as mock_settings,
    ):
        mock_settings.operator_namespace = "test-ns"
        mock_settings.operator_instance_id = "test-instance-id"
        detector = DriftDetector(
            config=config,
            k8s_client=MagicMock(),
            keycloak_admin_factory=overrides.get("keycloak_admin_factory", AsyncMock()),
            operator_instance_id="test-instance-id",
            operator_namespace="test-ns",
        )
    return detector


# ---------------------------------------------------------------------------
# _calculate_drift
# ---------------------------------------------------------------------------
class TestCalculateDrift:
    """Test _calculate_drift recursive diff logic."""

    def test_identical_dicts_no_drift(self):
        """Identical dicts produce no drift."""
        detector = _make_detector()
        assert detector._calculate_drift({"a": 1, "b": 2}, {"a": 1, "b": 2}) == []

    def test_missing_key_in_actual(self):
        """A key in desired but not in actual is reported as missing."""
        detector = _make_detector()
        result = detector._calculate_drift({"realm": "test"}, {})
        assert len(result) == 1
        assert "Missing field: realm" in result[0]

    def test_value_mismatch(self):
        """Different scalar values produce a value mismatch."""
        detector = _make_detector()
        result = detector._calculate_drift({"enabled": True}, {"enabled": False})
        assert len(result) == 1
        assert "Value mismatch" in result[0]
        assert "enabled" in result[0]

    def test_none_values_in_desired_are_skipped(self):
        """None values in desired config mean 'don't care' and are skipped."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"a": None, "b": 1}, {"a": "whatever", "b": 1}
        )
        assert result == []

    def test_nested_dict_drift(self):
        """Nested dict differences are reported with dotted path."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"parent": {"child": "expected"}},
            {"parent": {"child": "actual"}},
        )
        assert len(result) == 1
        assert "parent.child" in result[0]

    def test_nested_dict_missing_key(self):
        """Missing nested key is reported."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"parent": {"child": "value"}},
            {"parent": {}},
        )
        assert len(result) == 1
        assert "Missing field: parent.child" in result[0]

    def test_list_mismatch(self):
        """Different lists produce a list mismatch."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"uris": ["http://a"]},
            {"uris": ["http://b"]},
        )
        assert len(result) == 1
        assert "List mismatch" in result[0]

    def test_list_match(self):
        """Identical lists produce no drift."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"uris": ["http://a", "http://b"]},
            {"uris": ["http://a", "http://b"]},
        )
        assert result == []

    def test_extra_keys_in_actual_ignored(self):
        """Extra keys in actual that aren't in desired are not drift."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"a": 1},
            {"a": 1, "extra": "ignored"},
        )
        assert result == []

    def test_deeply_nested_drift(self):
        """Three-level nesting drift is reported."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"l1": {"l2": {"l3": "expected"}}},
            {"l1": {"l2": {"l3": "actual"}}},
        )
        assert len(result) == 1
        assert "l1.l2.l3" in result[0]

    def test_empty_desired_no_drift(self):
        """Empty desired config means nothing to check."""
        detector = _make_detector()
        result = detector._calculate_drift({}, {"a": 1, "b": 2})
        assert result == []

    def test_multiple_drifts(self):
        """Multiple differences are all reported."""
        detector = _make_detector()
        result = detector._calculate_drift(
            {"a": 1, "b": 2, "c": 3},
            {"a": 99, "b": 2, "c": 99},
        )
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _check_realm_resource_drift
# ---------------------------------------------------------------------------
class TestCheckRealmResourceDrift:
    """Test _check_realm_resource_drift with mocked Keycloak state."""

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=True,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_cr_reference",
        return_value=None,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_resource_age_hours",
        return_value=10.0,
    )
    async def test_owned_but_missing_cr_reference_is_orphaned(
        self, _age, _cr_ref, _owned
    ):
        """A realm owned by this operator but with no CR ref is orphaned."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "orphan-realm"
        realm.attributes = {"managed-by": "operator"}
        realm.model_dump.return_value = {"realm": "orphan-realm"}
        admin_client = AsyncMock()

        result = await detector._check_realm_resource_drift(realm, admin_client)

        assert result is not None
        assert result.drift_type == "orphaned"
        assert result.resource_name == "orphan-realm"

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=True,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_cr_reference",
        return_value=("ns-a", "my-realm-cr"),
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_resource_age_hours",
        return_value=5.0,
    )
    async def test_owned_cr_deleted_is_orphaned(self, _age, _cr_ref, _owned):
        """A realm whose CR no longer exists is orphaned."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "orphan-realm"
        realm.attributes = {}
        realm.model_dump.return_value = {"realm": "orphan-realm"}
        admin_client = AsyncMock()

        # _cr_exists returns False
        detector._cr_exists = AsyncMock(return_value=False)  # type: ignore

        result = await detector._check_realm_resource_drift(realm, admin_client)

        assert result is not None
        assert result.drift_type == "orphaned"
        assert result.cr_namespace == "ns-a"
        assert result.cr_name == "my-realm-cr"

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=False,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.is_managed_by_operator",
        return_value=False,
    )
    async def test_unmanaged_realm(self, _managed, _owned):
        """A realm not managed by any operator is 'unmanaged'."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "unmanaged-realm"
        realm.attributes = {}
        realm.model_dump.return_value = {"realm": "unmanaged-realm"}
        admin_client = AsyncMock()

        result = await detector._check_realm_resource_drift(realm, admin_client)

        assert result is not None
        assert result.drift_type == "unmanaged"

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=False,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.is_managed_by_operator",
        return_value=True,
    )
    async def test_owned_by_different_operator_returns_none(self, _managed, _owned):
        """A realm owned by a different operator instance is skipped."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "other-realm"
        realm.attributes = {}
        admin_client = AsyncMock()

        result = await detector._check_realm_resource_drift(realm, admin_client)

        assert result is None

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=True,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_cr_reference",
        return_value=("ns-a", "my-realm-cr"),
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_resource_age_hours",
        return_value=5.0,
    )
    async def test_skip_config_drift_flag(self, _age, _cr_ref, _owned):
        """With skip_config_drift=True, no config comparison is done."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "my-realm"
        realm.attributes = {}
        admin_client = AsyncMock()

        # CR exists
        detector._cr_exists = AsyncMock(return_value=True)  # type: ignore

        result = await detector._check_realm_resource_drift(
            realm, admin_client, skip_config_drift=True
        )

        # Should return None (no orphan, no config drift check)
        assert result is None

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.is_owned_by_this_operator",
        return_value=True,
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_cr_reference",
        return_value=("ns-a", "my-realm-cr"),
    )
    @patch(
        "keycloak_operator.services.drift_detection_service.get_resource_age_hours",
        return_value=5.0,
    )
    async def test_config_drift_detected(self, _age, _cr_ref, _owned):
        """Config drift is detected when CR spec differs from Keycloak state."""
        detector = _make_detector()
        realm = MagicMock()
        realm.realm = "my-realm"
        realm.attributes = {}
        realm.model_dump.return_value = {
            "realm": "my-realm",
            "enabled": False,  # different from CR
        }
        admin_client = AsyncMock()

        # CR exists
        detector._cr_exists = AsyncMock(return_value=True)  # type: ignore

        # Mock the K8s custom_objects_api to return a CR with enabled=True
        mock_cr = {
            "spec": {"realm": "my-realm", "enabled": True},
            "metadata": {"namespace": "ns-a", "name": "my-realm-cr"},
        }
        detector.custom_objects_api.get_namespaced_custom_object = MagicMock(  # type: ignore
            return_value=mock_cr
        )

        # Patch asyncio.to_thread to just call the function synchronously.
        # On Python 3.14+ asyncio.to_thread specs its argument which blows up
        # when the argument is already a MagicMock, so use a simple side_effect.
        async def _run_sync(fn, *a, **kw):
            return fn(*a, **kw)

        with patch(
            "keycloak_operator.services.drift_detection_service.asyncio.to_thread",
            side_effect=_run_sync,
        ):
            # We also need to mock KeycloakRealmSpec.model_validate
            with patch(
                "keycloak_operator.services.drift_detection_service.KeycloakRealmSpec"
            ) as mock_spec_cls:
                mock_spec = MagicMock()
                mock_spec.to_keycloak_config.return_value = {
                    "realm": "my-realm",
                    "enabled": True,
                }
                mock_spec_cls.model_validate.return_value = mock_spec

                result = await detector._check_realm_resource_drift(realm, admin_client)

        assert result is not None
        assert result.drift_type == "config_drift"
        assert result.cr_namespace == "ns-a"
        assert len(result.drift_details) > 0


# ---------------------------------------------------------------------------
# _cr_exists
# ---------------------------------------------------------------------------
class TestCrExists:
    """Test _cr_exists checking Kubernetes for CR presence.

    The production code uses ``asyncio.to_thread(self.custom_objects_api.get_namespaced_custom_object, ...)``.
    On Python 3.14+ ``to_thread`` validates the spec of its first argument,
    which explodes when that argument is already a ``MagicMock``.

    We work around this by mocking ``asyncio.to_thread`` with a plain
    ``side_effect`` that calls the function synchronously, and configuring
    the return value / side_effect on the underlying ``get_namespaced_custom_object`` mock.
    """

    @staticmethod
    async def _run_sync(fn, *a, **kw):
        return fn(*a, **kw)

    @pytest.mark.asyncio
    async def test_cr_exists_returns_true(self):
        """Returns True when the CR is found."""
        detector = _make_detector()
        detector.custom_objects_api.get_namespaced_custom_object = MagicMock(  # type: ignore
            return_value={"metadata": {"name": "test"}}
        )

        with patch(
            "keycloak_operator.services.drift_detection_service.asyncio.to_thread",
            side_effect=self._run_sync,
        ):
            result = await detector._cr_exists("KeycloakRealm", "ns-a", "test")

        assert result is True

    @pytest.mark.asyncio
    async def test_cr_exists_returns_false_on_404(self):
        """Returns False when the CR is not found (404)."""
        from kubernetes.client.rest import ApiException

        detector = _make_detector()
        detector.custom_objects_api.get_namespaced_custom_object = MagicMock(  # type: ignore
            side_effect=ApiException(status=404, reason="Not Found")
        )

        with patch(
            "keycloak_operator.services.drift_detection_service.asyncio.to_thread",
            side_effect=self._run_sync,
        ):
            result = await detector._cr_exists("KeycloakRealm", "ns-a", "test")

        assert result is False

    @pytest.mark.asyncio
    async def test_cr_exists_returns_false_on_other_api_error(self):
        """Returns False on non-404 API errors (with warning logged)."""
        from kubernetes.client.rest import ApiException

        detector = _make_detector()
        detector.custom_objects_api.get_namespaced_custom_object = MagicMock(  # type: ignore
            side_effect=ApiException(status=403, reason="Forbidden")
        )

        with patch(
            "keycloak_operator.services.drift_detection_service.asyncio.to_thread",
            side_effect=self._run_sync,
        ):
            result = await detector._cr_exists("KeycloakRealm", "ns-a", "test")

        assert result is False

    @pytest.mark.asyncio
    async def test_cr_exists_plural_map(self):
        """Verifies the plural mapping for different kinds."""
        detector = _make_detector()
        mock_get = MagicMock(return_value={})
        detector.custom_objects_api.get_namespaced_custom_object = mock_get  # type: ignore

        with patch(
            "keycloak_operator.services.drift_detection_service.asyncio.to_thread",
            side_effect=self._run_sync,
        ):
            await detector._cr_exists("KeycloakClient", "ns-a", "test")

        # Verify the plural was "keycloakclients" — it's the 5th positional arg
        # (group, version, namespace, plural, name) via keyword arguments
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        assert call_kwargs.kwargs.get("plural") == "keycloakclients"


# ---------------------------------------------------------------------------
# remediate_drift
# ---------------------------------------------------------------------------
class TestRemediateDrift:
    """Test remediate_drift orchestration."""

    @pytest.mark.asyncio
    async def test_auto_remediate_disabled_skips(self):
        """When auto_remediate is False, nothing happens."""
        config = _make_config(auto_remediate=False)
        detector = _make_detector(config=config)

        drift_results = [
            DriftResult(
                resource_type="realm",
                resource_name="orphan",
                drift_type="orphaned",
                keycloak_resource={},
                age_hours=10.0,
            ),
        ]

        # Should not raise
        await detector.remediate_drift(drift_results)

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.REMEDIATION_ERRORS_TOTAL"
    )
    async def test_remediate_orphan_called(self, mock_errors):
        """Orphaned drift triggers _remediate_orphan."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)
        detector._remediate_orphan = AsyncMock()  # type: ignore
        detector._remediate_config_drift = AsyncMock()  # type: ignore

        drift_results = [
            DriftResult(
                resource_type="realm",
                resource_name="orphan",
                drift_type="orphaned",
                keycloak_resource={},
                age_hours=10.0,
            ),
        ]

        await detector.remediate_drift(drift_results)

        detector._remediate_orphan.assert_awaited_once()  # type: ignore
        detector._remediate_config_drift.assert_not_awaited()  # type: ignore

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.REMEDIATION_ERRORS_TOTAL"
    )
    async def test_remediate_config_drift_called(self, mock_errors):
        """Config drift triggers _remediate_config_drift."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)
        detector._remediate_orphan = AsyncMock()  # type: ignore
        detector._remediate_config_drift = AsyncMock()  # type: ignore

        drift_results = [
            DriftResult(
                resource_type="realm",
                resource_name="drifted",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace="ns-a",
                cr_name="my-realm",
            ),
        ]

        await detector.remediate_drift(drift_results)

        detector._remediate_config_drift.assert_awaited_once()  # type: ignore
        detector._remediate_orphan.assert_not_awaited()  # type: ignore

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.REMEDIATION_ERRORS_TOTAL"
    )
    async def test_unmanaged_resources_not_remediated(self, mock_errors):
        """Unmanaged resources are left alone."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)
        detector._remediate_orphan = AsyncMock()  # type: ignore
        detector._remediate_config_drift = AsyncMock()  # type: ignore

        drift_results = [
            DriftResult(
                resource_type="realm",
                resource_name="unmanaged",
                drift_type="unmanaged",
                keycloak_resource={},
            ),
        ]

        await detector.remediate_drift(drift_results)

        detector._remediate_orphan.assert_not_awaited()  # type: ignore
        detector._remediate_config_drift.assert_not_awaited()  # type: ignore

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.services.drift_detection_service.REMEDIATION_ERRORS_TOTAL"
    )
    async def test_remediation_error_increments_metric(self, mock_errors):
        """When remediation fails, error metric is incremented."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)
        detector._remediate_orphan = AsyncMock(  # type: ignore
            side_effect=RuntimeError("delete failed")
        )

        drift_results = [
            DriftResult(
                resource_type="realm",
                resource_name="orphan",
                drift_type="orphaned",
                keycloak_resource={},
                age_hours=10.0,
            ),
        ]

        # Should not raise - error is caught
        await detector.remediate_drift(drift_results)

        mock_errors.labels.assert_called_with(
            resource_type="realm",
            action="delete",
        )
        mock_errors.labels().inc.assert_called_once()


# ---------------------------------------------------------------------------
# _remediate_orphan
# ---------------------------------------------------------------------------
class TestRemediateOrphan:
    """Test _remediate_orphan logic."""

    @pytest.mark.asyncio
    @patch("keycloak_operator.services.drift_detection_service.REMEDIATION_TOTAL")
    async def test_orphan_too_young_is_skipped(self, mock_total):
        """Orphans younger than minimum_age_hours are skipped."""
        config = _make_config(auto_remediate=True, minimum_age_hours=2)
        detector = _make_detector(config=config)

        drift = DriftResult(
            resource_type="realm",
            resource_name="young-orphan",
            drift_type="orphaned",
            keycloak_resource={},
            age_hours=1.0,  # younger than minimum
        )

        await detector._remediate_orphan(drift)

        # No remediation action taken
        mock_total.labels.assert_not_called()

    @pytest.mark.asyncio
    async def test_orphan_unknown_age_is_skipped(self):
        """Orphans with unknown age (None) are skipped."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)

        drift = DriftResult(
            resource_type="realm",
            resource_name="unknown-age",
            drift_type="orphaned",
            keycloak_resource={},
            age_hours=None,
        )

        # Should not raise
        await detector._remediate_orphan(drift)

    @pytest.mark.asyncio
    async def test_orphan_cr_reappeared_is_skipped(self):
        """If the CR re-appears during remediation, the orphan is skipped."""
        config = _make_config(auto_remediate=True, minimum_age_hours=1)
        detector = _make_detector(config=config)
        detector._cr_exists = AsyncMock(return_value=True)  # type: ignore

        drift = DriftResult(
            resource_type="realm",
            resource_name="maybe-orphan",
            drift_type="orphaned",
            keycloak_resource={},
            age_hours=10.0,
            cr_namespace="ns-a",
            cr_name="my-realm",
        )

        await detector._remediate_orphan(drift)

        # _cr_exists was called as safety check
        detector._cr_exists.assert_awaited_once()  # type: ignore

    @pytest.mark.asyncio
    @patch("keycloak_operator.services.drift_detection_service.REMEDIATION_TOTAL")
    async def test_realm_orphan_deleted_successfully(self, mock_total):
        """Successful realm orphan deletion records the metric."""
        config = _make_config(auto_remediate=True, minimum_age_hours=1)
        admin_factory = AsyncMock()
        mock_admin = AsyncMock()
        mock_admin.delete_realm.return_value = True
        admin_factory.return_value = mock_admin
        detector = _make_detector(config=config, keycloak_admin_factory=admin_factory)
        detector._cr_exists = AsyncMock(return_value=False)  # type: ignore

        drift = DriftResult(
            resource_type="realm",
            resource_name="dead-realm",
            drift_type="orphaned",
            keycloak_resource={},
            age_hours=10.0,
            cr_namespace="ns-a",
            cr_name="dead-cr",
        )

        await detector._remediate_orphan(drift)

        mock_admin.delete_realm.assert_awaited_once_with("dead-realm", "test-ns")
        mock_total.labels.assert_called_with(
            resource_type="realm",
            action="delete",
            reason="orphaned",
        )


# ---------------------------------------------------------------------------
# _remediate_config_drift
# ---------------------------------------------------------------------------
class TestRemediateConfigDrift:
    """Test _remediate_config_drift logic."""

    @pytest.mark.asyncio
    async def test_missing_cr_info_returns_early(self):
        """If cr_namespace or cr_name is missing, returns early."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)

        drift = DriftResult(
            resource_type="realm",
            resource_name="drifted",
            drift_type="config_drift",
            keycloak_resource={},
            cr_namespace=None,
            cr_name=None,
        )

        # Should not raise
        await detector._remediate_config_drift(drift)

    @pytest.mark.asyncio
    async def test_unsupported_resource_type_returns_early(self):
        """Unsupported resource types are logged and skipped."""
        config = _make_config(auto_remediate=True)
        detector = _make_detector(config=config)

        drift = DriftResult(
            resource_type="identity_provider",
            resource_name="drifted-idp",
            drift_type="config_drift",
            keycloak_resource={},
            cr_namespace="ns-a",
            cr_name="my-idp",
        )

        # Should not raise
        await detector._remediate_config_drift(drift)
