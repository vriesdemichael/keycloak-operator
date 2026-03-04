"""
Unit tests for admission webhooks.

Tests validate webhook validation logic without requiring a Kubernetes cluster.
K8s API calls are mocked to test validation logic in isolation.
"""

from unittest.mock import AsyncMock, patch

import kopf
import pytest


class TestRealmWebhook:
    """Unit tests for KeycloakRealm admission webhook."""

    @pytest.mark.asyncio
    async def test_valid_realm_spec_passes(self, monkeypatch):
        """Valid realm spec should pass Pydantic validation."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.realm import validate_realm

        valid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": "keycloak-system"},
        }

        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=0,
        ):
            result = await validate_realm(
                spec=valid_spec,
                namespace="test-ns",
                name="test-realm",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_invalid_realm_spec_fails(self, monkeypatch):
        """Invalid realm spec should raise AdmissionError."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.realm import validate_realm

        invalid_spec = {
            # Missing required realmName
            "operatorRef": {"namespace": "keycloak-system"},
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_realm(
                spec=invalid_spec,
                namespace="test-ns",
                name="test-realm",
                operation="CREATE",
                dryrun=False,
            )

        assert "Invalid realm specification" in str(exc_info.value)


class TestClientWebhook:
    """Unit tests for KeycloakClient admission webhook."""

    @pytest.mark.asyncio
    async def test_valid_client_spec_passes(self):
        """Valid client spec should pass Pydantic validation."""
        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        with (
            patch(
                "keycloak_operator.webhooks.client.get_client_count_in_namespace",
                return_value=0,
            ),
            patch(
                "keycloak_operator.utils.isolation.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.webhooks.client.client.ApiClient"),
        ):
            from keycloak_operator.webhooks.client import validate_client

            result = await validate_client(
                spec=valid_spec,
                namespace="test-ns",
                name="test-client",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_invalid_client_spec_fails(self):
        """Invalid client spec should raise AdmissionError."""
        invalid_spec = {
            # Missing required clientId
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        with (
            patch(
                "keycloak_operator.webhooks.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.webhooks.client.client.ApiClient"),
        ):
            from keycloak_operator.webhooks.client import validate_client

            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_client(
                    spec=invalid_spec,
                    namespace="test-ns",
                    name="test-client",
                    operation="CREATE",
                    dryrun=False,
                )

        assert "Invalid client specification" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_client_quota_at_limit_fails(self):
        """Creating client when at quota should fail."""
        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        # Mock: 50 clients exist, limit is 50
        with (
            patch(
                "keycloak_operator.webhooks.client.get_client_count_in_namespace",
                return_value=50,
            ),
            patch(
                "keycloak_operator.webhooks.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.webhooks.client.client.ApiClient"),
        ):
            from keycloak_operator.webhooks.client import validate_client

            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_client(
                    spec=valid_spec,
                    namespace="test-ns",
                    name="test-client",
                    operation="CREATE",
                    dryrun=False,
                )

            assert "Namespace quota exceeded" in str(exc_info.value)
            assert "50 clients" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_realm_ref_fails(self):
        """Client with missing realmRef fields should fail."""
        invalid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "", "namespace": ""},  # Empty refs
        }

        with (
            patch(
                "keycloak_operator.webhooks.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.webhooks.client.client.ApiClient"),
        ):
            from keycloak_operator.webhooks.client import validate_client

            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_client(
                    spec=invalid_spec,
                    namespace="test-ns",
                    name="test-client",
                    operation="CREATE",
                    dryrun=False,
                )

            assert "realmRef.name and realmRef.namespace are required" in str(
                exc_info.value
            )


class TestKeycloakWebhook:
    """Unit tests for Keycloak admission webhook."""

    # ── Helper to build a base spec ──────────────────────────────

    @staticmethod
    def _base_db():
        return {
            "type": "postgresql",
            "host": "postgres.default.svc",
            "port": 5432,
            "database": "keycloak",
            "username": "keycloak",
            "password": "keycloak",
        }

    # ── Basic validation ──────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_valid_keycloak_spec_passes(self, monkeypatch):
        """Valid Keycloak spec should pass Pydantic validation."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "version": "26.4.1",
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak:26.4.1",
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=valid_spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_default_image_passes(self, monkeypatch):
        """Keycloak spec using default image (no explicit image field) should pass."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec_default = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=spec_default,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    # ── Without upgradePolicy: non-semver tags should PASS ────────

    @pytest.mark.asyncio
    async def test_latest_tag_passes_without_upgrade_policy(self, monkeypatch):
        """Without upgradePolicy, 'latest' tag is accepted (no enforcement)."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak:latest",
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_digest_image_passes_without_upgrade_policy(self, monkeypatch):
        """Without upgradePolicy, digest-only image is accepted."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd1234",
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_no_tag_passes_without_upgrade_policy(self, monkeypatch):
        """Without upgradePolicy, tagless image is accepted."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak",
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    # ── With upgradePolicy: non-semver tags should FAIL ───────────

    @pytest.mark.asyncio
    async def test_latest_tag_rejected_with_upgrade_policy(self, monkeypatch):
        """With upgradePolicy, 'latest' tag is rejected."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak:latest",
            "upgradePolicy": {"backupTimeout": 600},
            "database": self._base_db(),
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )

        assert "not a valid semantic version" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_digest_image_rejected_with_upgrade_policy(self, monkeypatch):
        """With upgradePolicy, digest-only image is rejected."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd1234",
            "upgradePolicy": {"backupTimeout": 600},
            "database": self._base_db(),
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )

        assert "digest reference" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_no_tag_rejected_with_upgrade_policy(self, monkeypatch):
        """With upgradePolicy, tagless image is rejected."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak",
            "upgradePolicy": {"backupTimeout": 600},
            "database": self._base_db(),
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )

        assert "no tag" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_update_with_non_semver_rejected_with_upgrade_policy(
        self, monkeypatch
    ):
        """UPDATE with non-semver + upgradePolicy is also rejected."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak:latest",
            "upgradePolicy": {"backupTimeout": 600},
            "database": self._base_db(),
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="UPDATE",
                dryrun=False,
            )

        assert "not a valid semantic version" in str(exc_info.value)

    # ── With upgradePolicy: semver tags should PASS ───────────────

    @pytest.mark.asyncio
    async def test_semver_with_suffix_passes_with_upgrade_policy(self, monkeypatch):
        """With upgradePolicy, semver+suffix image tag passes."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "replicas": 1,
            "image": "quay.io/keycloak/keycloak:26.0.0-custom",
            "upgradePolicy": {"backupTimeout": 600},
            "database": self._base_db(),
        }

        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=0,
        ):
            result = await validate_keycloak(
                spec=spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}
