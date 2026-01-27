import logging

from keycloak_operator.compatibility import get_adapter
from keycloak_operator.models.generated.v24_0_5 import ClientRepresentation as ClientV24
from keycloak_operator.models.generated.v26_5_2 import ClientRepresentation as ClientV26


class TestCompatibility:
    def test_adapter_factory(self):
        """Test that get_adapter returns the correct adapter class."""
        assert get_adapter("26.5.2").version == "26.5.2"
        assert get_adapter("25.0.6").version == "25.0.6"
        assert get_adapter("24.0.5").version == "24.0.5"

        # Test fallback
        adapter = get_adapter("100.0.0")
        assert adapter.__class__.__name__ == "AdapterV26"

    def test_path_resolution_v26(self):
        """Test URL generation for V26 (modern paths)."""
        adapter = get_adapter("26.5.2")
        path = adapter.get_client_role_mapping_path("realm", "user-1", "client-uuid")
        assert path == "realms/realm/users/user-1/role-mappings/clients/client-uuid"

    def test_path_resolution_v24(self):
        """Test URL generation for V24."""
        adapter = get_adapter("24.0.5")
        path = adapter.get_client_role_mapping_path("realm", "user-1", "client-uuid")
        # In our implementation, we kept them same based on analysis, but this confirms the code path works
        assert path == "realms/realm/users/user-1/role-mappings/clients/client-uuid"

    def test_downgrade_model_strips_fields(self, caplog):
        """Test that fields present in V26 but missing in V24 are stripped and warned."""
        adapter = get_adapter("24.0.5")

        # Create a V26 client with the 'type' field (which exists in v26 but not v24)
        v26_client = ClientV26(
            clientId="test-client",
            type="confidential",  # This field doesn't exist in V24
            enabled=True,
        )

        # Convert to V24 target
        with caplog.at_level(logging.WARNING):
            result = adapter.convert_to_target(
                v26_client, ClientV26
            )  # We pass source class, adapter finds target

        # Verify 'type' is gone
        assert "type" not in result
        assert result["clientId"] == "test-client"
        assert result["enabled"] is True

        # Verify warning was logged
        assert "Configuration fields ['type'] are not supported" in caplog.text

    def test_downgrade_model_no_warning_if_none(self, caplog):
        """Test that no warning is issued if the unsupported field is None."""
        adapter = get_adapter("24.0.5")

        # Create a V26 client with type=None (default)
        v26_client = ClientV26(clientId="test-client", type=None, enabled=True)

        with caplog.at_level(logging.WARNING):
            result = adapter.convert_to_target(v26_client, ClientV26)

        assert "type" not in result
        assert "Configuration fields" not in caplog.text

    def test_target_class_resolution(self):
        """Test that the adapter can find the V24 class from the V26 class."""
        adapter = get_adapter("24.0.5")
        target_cls = adapter.get_target_model_class(ClientV26)
        assert target_cls == ClientV24

    def test_comprehensive_url_generation(self):
        """Verify that all URL generation methods work on the adapter."""
        adapter = get_adapter("26.5.2")
        realm = "my-realm"

        assert adapter.get_realms_path() == "realms"
        assert adapter.get_realm_path(realm) == f"realms/{realm}"
        assert adapter.get_clients_path(realm) == f"realms/{realm}/clients"
        assert adapter.get_client_path(realm, "123") == f"realms/{realm}/clients/123"
        assert (
            adapter.get_client_secret_path(realm, "123")
            == f"realms/{realm}/clients/123/client-secret"
        )
        assert (
            adapter.get_realm_role_path(realm, "admin") == f"realms/{realm}/roles/admin"
        )
        assert (
            adapter.get_identity_providers_path(realm)
            == f"realms/{realm}/identity-provider/instances"
        )
        assert (
            adapter.get_authentication_flows_path(realm)
            == f"realms/{realm}/authentication/flows"
        )

        # Test a deeper nested path
        assert (
            adapter.get_identity_provider_mapper_path(realm, "idp1", "map1")
            == f"realms/{realm}/identity-provider/instances/idp1/mappers/map1"
        )

    def test_downgrade_complex_model(self, caplog):
        """Test downgrading a complex model (RealmRepresentation)."""
        adapter = get_adapter("24.0.5")

        # We need to import RealmRepresentation from both versions
        from keycloak_operator.models.generated.v26_5_2 import (
            RealmRepresentation as RealmV26,
        )

        # V26 has 'organizationsEnabled' which is missing in V24
        v26_realm = RealmV26(
            realm="test-realm", enabled=True, organizationsEnabled=True
        )

        with caplog.at_level(logging.WARNING):
            result = adapter.convert_to_target(v26_realm)

        assert "organizationsEnabled" not in result
        assert result["realm"] == "test-realm"
        assert (
            "Configuration fields ['organizationsEnabled'] are not supported"
            in caplog.text
        )
