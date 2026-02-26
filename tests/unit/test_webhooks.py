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

    @pytest.mark.asyncio
    async def test_valid_keycloak_spec_passes(self, monkeypatch):
        """Valid Keycloak spec should pass Pydantic validation."""
        monkeypatch.setenv("OPERATOR_NAMESPACE", "keycloak-system")
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "version": "26.4.1",
            "replicas": 1,
            "database": {
                "type": "postgresql",
                "host": "postgres.default.svc",
                "port": 5432,
                "database": "keycloak",
                "username": "keycloak",
                "password": "keycloak",
            },
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
