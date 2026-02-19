import pytest
from pydantic import ValidationError

from keycloak_operator.models.realm import KeycloakRealmSpec, KeycloakScopeMapping


def test_scope_mapping_model_validation():
    """Test validation of KeycloakScopeMapping model."""
    # Test valid client mapping
    mapping = KeycloakScopeMapping(client="my-client", roles=["role1"])
    assert mapping.client == "my-client"
    assert mapping.roles == ["role1"]
    assert mapping.client_scope is None

    # Test valid client scope mapping
    mapping = KeycloakScopeMapping(clientScope="my-scope", roles=["role1"])
    assert mapping.client_scope == "my-scope"
    assert mapping.roles == ["role1"]
    assert mapping.client is None

    # Test invalid: both client and clientScope
    with pytest.raises(ValidationError):
        KeycloakScopeMapping(
            client="my-client", clientScope="my-scope", roles=["role1"]
        )

    # Test invalid: neither client nor clientScope
    with pytest.raises(ValidationError):
        KeycloakScopeMapping(roles=["role1"])


def test_realm_spec_with_scope_mappings():
    """Test KeycloakRealmSpec with scope mappings."""
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "default"},
        scopeMappings=[
            {"client": "client1", "roles": ["role1", "role2"]},
            {"clientScope": "scope1", "roles": ["role3"]},
        ],
        clientScopeMappings={
            "source-client": [{"client": "target-client", "roles": ["client-role1"]}]
        },
    )

    assert len(spec.scope_mappings) == 2
    assert spec.scope_mappings[0].client == "client1"
    assert spec.scope_mappings[1].client_scope == "scope1"

    assert "source-client" in spec.client_scope_mappings
    assert len(spec.client_scope_mappings["source-client"]) == 1
    assert spec.client_scope_mappings["source-client"][0].client == "target-client"


def test_realm_spec_with_default_roles():
    """Test KeycloakRealmSpec with default roles configuration."""
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "default"},
        defaultRoles=["role1", "role2"],
        defaultRole={
            "name": "ignored",
            "description": "My default role",
            "attributes": {"attr1": ["value1"]},
        },
    )

    assert spec.default_roles == ["role1", "role2"]
    assert spec.default_role is not None
    assert spec.default_role.description == "My default role"
    assert spec.default_role.attributes is not None
    assert spec.default_role.attributes["attr1"] == ["value1"]
