"""
Unit tests for admission webhooks.

Tests validate webhook validation logic without requiring a Kubernetes cluster.
K8s API calls are mocked to test validation logic in isolation.
"""

from unittest.mock import patch

import kopf
import pytest


class TestRealmWebhook:
    """Unit tests for KeycloakRealm admission webhook."""

    @pytest.mark.asyncio
    async def test_valid_realm_spec_passes(self):
        """Valid realm spec should pass Pydantic validation."""
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
            assert result == {}  # Empty dict means allowed

    @pytest.mark.asyncio
    async def test_invalid_realm_spec_fails(self):
        """Invalid realm spec should raise AdmissionError."""
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

    @pytest.mark.asyncio
    async def test_quota_under_limit_passes(self):
        """Creating realm when under quota should pass."""
        from keycloak_operator.webhooks.realm import validate_realm

        valid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": "keycloak-system"},
        }

        # Mock: 9 realms already exist, limit is 10
        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=9,
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
    async def test_quota_at_limit_fails(self):
        """Creating realm when at quota should fail."""
        from keycloak_operator.webhooks.realm import validate_realm

        valid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": "keycloak-system"},
        }

        # Mock: 10 realms already exist, limit is 10
        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=10,
        ):
            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_realm(
                    spec=valid_spec,
                    namespace="test-ns",
                    name="test-realm",
                    operation="CREATE",
                    dryrun=False,
                )

            assert "Namespace quota exceeded" in str(exc_info.value)
            assert "10 realms" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_update_skips_quota_check(self):
        """UPDATE operation should skip quota check."""
        from keycloak_operator.webhooks.realm import validate_realm

        valid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": "keycloak-system"},
        }

        # Mock: 10 realms exist, but UPDATE should still pass
        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=10,
        ):
            result = await validate_realm(
                spec=valid_spec,
                namespace="test-ns",
                name="test-realm",
                operation="UPDATE",
                dryrun=False,
            )
            assert result == {}  # UPDATE allowed even at quota

    @pytest.mark.asyncio
    async def test_missing_operator_ref_namespace_fails(self):
        """Realm with missing operatorRef.namespace should fail."""
        from keycloak_operator.webhooks.realm import validate_realm

        invalid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": ""},  # Empty namespace
        }

        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=0,
        ):
            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_realm(
                    spec=invalid_spec,
                    namespace="test-ns",
                    name="test-realm",
                    operation="CREATE",
                    dryrun=False,
                )

            assert "operatorRef.namespace is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_quota_check_fail_open(self):
        """Quota check failure should fail-open (allow request)."""
        from keycloak_operator.webhooks.realm import validate_realm

        valid_spec = {
            "realmName": "test-realm",
            "operatorRef": {"namespace": "keycloak-system"},
        }

        # Mock K8s API failure - should return 0 (fail-open)
        with patch(
            "keycloak_operator.webhooks.realm.get_realm_count_in_namespace",
            return_value=0,  # Fail-open returns 0
        ):
            result = await validate_realm(
                spec=valid_spec,
                namespace="test-ns",
                name="test-realm",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}  # Allowed despite API error


class TestClientWebhook:
    """Unit tests for KeycloakClient admission webhook."""

    @pytest.mark.asyncio
    async def test_valid_client_spec_passes(self):
        """Valid client spec should pass Pydantic validation."""
        from keycloak_operator.webhooks.client import validate_client

        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        with patch(
            "keycloak_operator.webhooks.client.get_client_count_in_namespace",
            return_value=0,
        ):
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
        from keycloak_operator.webhooks.client import validate_client

        invalid_spec = {
            # Missing required clientId
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

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
    async def test_client_quota_under_limit_passes(self):
        """Creating client when under quota should pass."""
        from keycloak_operator.webhooks.client import validate_client

        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        # Mock: 49 clients exist, limit is 50
        with patch(
            "keycloak_operator.webhooks.client.get_client_count_in_namespace",
            return_value=49,
        ):
            result = await validate_client(
                spec=valid_spec,
                namespace="test-ns",
                name="test-client",
                operation="CREATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_client_quota_at_limit_fails(self):
        """Creating client when at quota should fail."""
        from keycloak_operator.webhooks.client import validate_client

        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        # Mock: 50 clients exist, limit is 50
        with patch(
            "keycloak_operator.webhooks.client.get_client_count_in_namespace",
            return_value=50,
        ):
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
    async def test_client_update_skips_quota(self):
        """UPDATE operation should skip quota check for clients."""
        from keycloak_operator.webhooks.client import validate_client

        valid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        }

        # Mock: 50 clients exist, but UPDATE should pass
        with patch(
            "keycloak_operator.webhooks.client.get_client_count_in_namespace",
            return_value=50,
        ):
            result = await validate_client(
                spec=valid_spec,
                namespace="test-ns",
                name="test-client",
                operation="UPDATE",
                dryrun=False,
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_missing_realm_ref_fails(self):
        """Client with missing realmRef fields should fail."""
        from keycloak_operator.webhooks.client import validate_client

        invalid_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "", "namespace": ""},  # Empty refs
        }

        with patch(
            "keycloak_operator.webhooks.client.get_client_count_in_namespace",
            return_value=0,
        ):
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
    async def test_valid_keycloak_spec_passes(self):
        """Valid Keycloak spec should pass Pydantic validation."""
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "version": "26.4.1",
            "replicas": 1,
            "database": {
                "type": "postgresql",
                "vendor": "postgres",
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

    @pytest.mark.asyncio
    async def test_invalid_keycloak_spec_fails(self):
        """Invalid Keycloak spec should raise AdmissionError."""
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        invalid_spec = {
            # Missing required fields
            "replicas": 1,
        }

        with pytest.raises(kopf.AdmissionError) as exc_info:
            await validate_keycloak(
                spec=invalid_spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="CREATE",
                dryrun=False,
            )

        assert "Invalid Keycloak specification" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_one_keycloak_per_namespace_passes(self):
        """Creating first Keycloak in namespace should pass."""
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "version": "26.4.1",
            "replicas": 1,
            "database": {
                "type": "postgresql",
                "vendor": "postgres",
                "host": "postgres.default.svc",
                "port": 5432,
                "database": "keycloak",
                "username": "keycloak",
                "password": "keycloak",
            },
        }

        # Mock: 0 Keycloaks exist
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
    async def test_one_keycloak_per_namespace_fails(self):
        """Creating second Keycloak in namespace should fail (ADR-062)."""
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "version": "26.4.1",
            "replicas": 1,
            "database": {
                "type": "postgresql",
                "vendor": "postgres",
                "host": "postgres.default.svc",
                "port": 5432,
                "database": "keycloak",
                "username": "keycloak",
                "password": "keycloak",
            },
        }

        # Mock: 1 Keycloak already exists
        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=1,
        ):
            with pytest.raises(kopf.AdmissionError) as exc_info:
                await validate_keycloak(
                    spec=valid_spec,
                    namespace="keycloak-system",
                    name="keycloak-2",
                    operation="CREATE",
                    dryrun=False,
                )

            assert "Only one Keycloak instance allowed per namespace" in str(
                exc_info.value
            )
            assert "ADR-062" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_keycloak_update_allowed(self):
        """UPDATE operation should be allowed even with existing instance."""
        from keycloak_operator.webhooks.keycloak import validate_keycloak

        valid_spec = {
            "version": "26.4.1",
            "replicas": 2,  # Scaling up
            "database": {
                "type": "postgresql",
                "vendor": "postgres",
                "host": "postgres.default.svc",
                "port": 5432,
                "database": "keycloak",
                "username": "keycloak",
                "password": "keycloak",
            },
        }

        # Mock: 1 Keycloak exists (the one being updated)
        with patch(
            "keycloak_operator.webhooks.keycloak.get_keycloak_count_in_namespace",
            return_value=1,
        ):
            result = await validate_keycloak(
                spec=valid_spec,
                namespace="keycloak-system",
                name="keycloak",
                operation="UPDATE",
                dryrun=False,
            )
            assert result == {}  # UPDATE allowed
