from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.models.realm import (
    KeycloakRealmSpec,
    KeycloakScopeMapping,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def reconciler():
    return KeycloakRealmReconciler(k8s_client=MagicMock())


@pytest.mark.asyncio
async def test_configure_default_roles_attributes(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRole={
            "name": "ignored",
            "description": "New description",
            "attributes": {"attr1": ["val1"]},
        },
    )

    admin_client = AsyncMock()
    existing_role = MagicMock()
    existing_role.id = "role-uuid"
    admin_client.get_realm_role_by_name.return_value = existing_role

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_default_roles(spec, "name", "namespace")

    admin_client.get_realm_role_by_name.assert_called_with(
        "test-realm", "default-roles-test-realm", "namespace"
    )
    admin_client.update_realm_role.assert_called()
    call_args = admin_client.update_realm_role.call_args
    assert call_args[0][0] == "test-realm"
    assert call_args[0][1] == "default-roles-test-realm"
    role_repr = call_args[0][2]
    assert role_repr.description == "New description"
    assert role_repr.attributes == {"attr1": ["val1"]}


@pytest.mark.asyncio
async def test_configure_default_roles_composites(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRoles=["role1", "role2"],
    )

    admin_client = AsyncMock()
    admin_client.get_realm_role_composites.return_value = [
        MagicMock(name="offline_access")
    ]
    role1 = MagicMock()
    role1.name = "role1"
    role2 = MagicMock()
    role2.name = "role2"

    # We need to ensure get_realm_role_by_name returns something for both roles
    admin_client.get_realm_role_by_name.side_effect = lambda r, n, ns: (
        role1 if n == "role1" else role2
    )

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_default_roles(spec, "name", "namespace")

    admin_client.add_realm_role_composites.assert_called_once()
    args, _ = admin_client.add_realm_role_composites.call_args
    assert args[0] == "test-realm"
    assert args[1] == "default-roles-test-realm"
    # Convert list of mocks to set
    assert set(args[2]) == {role1, role2}
    assert args[3] == "namespace"


@pytest.mark.asyncio
async def test_configure_scope_mappings(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        scopeMappings=[
            KeycloakScopeMapping(client="target-client", roles=["realm-role1"])
        ],
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.return_value = "target-uuid"
    realm_role = MagicMock()
    realm_role.name = "realm-role1"
    admin_client.get_realm_role_by_name.return_value = realm_role

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_scope_mappings(spec, "name", "namespace")

    admin_client.add_scope_mappings_realm_roles.assert_called_with(
        "test-realm",
        [realm_role],
        client_id="target-uuid",
        client_scope_id=None,
        namespace="namespace",
    )


@pytest.mark.asyncio
async def test_configure_scope_mappings_client_scope(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        scopeMappings=[
            KeycloakScopeMapping(clientScope="target-scope", roles=["realm-role1"])
        ],
    )

    admin_client = AsyncMock()
    client_scope = MagicMock()
    client_scope.id = "scope-uuid"
    admin_client.get_client_scope_by_name.return_value = client_scope
    realm_role = MagicMock()
    realm_role.name = "realm-role1"
    admin_client.get_realm_role_by_name.return_value = realm_role

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_scope_mappings(spec, "name", "namespace")

    admin_client.add_scope_mappings_realm_roles.assert_called_with(
        "test-realm",
        [realm_role],
        client_id=None,
        client_scope_id="scope-uuid",
        namespace="namespace",
    )


@pytest.mark.asyncio
async def test_configure_client_scope_mappings(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        clientScopeMappings={
            "source-client": [
                KeycloakScopeMapping(client="target-client", roles=["client-role1"])
            ]
        },
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.side_effect = lambda n, r, ns: (
        "source-uuid" if n == "source-client" else "target-uuid"
    )
    client_role = MagicMock()
    client_role.name = "client-role1"
    admin_client.get_client_role.return_value = client_role

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_scope_mappings(spec, "name", "namespace")

    admin_client.add_scope_mappings_client_roles.assert_called_with(
        "test-realm",
        "source-uuid",
        [client_role],
        client_id="target-uuid",
        client_scope_id=None,
        namespace="namespace",
    )


@pytest.mark.asyncio
async def test_configure_default_roles_no_missing(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRoles=["role1"],
    )

    admin_client = AsyncMock()
    role1 = MagicMock()
    role1.name = "role1"
    admin_client.get_realm_role_composites.return_value = [role1]

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "debug") as mock_log:
        await reconciler.configure_default_roles(spec, "name", "namespace")
        mock_log.assert_any_call("All default roles already assigned")

    admin_client.add_realm_role_composites.assert_not_called()


@pytest.mark.asyncio
async def test_configure_default_roles_missing_extra_role(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRoles=["missing-role"],
    )

    admin_client = AsyncMock()
    admin_client.get_realm_role_composites.return_value = []
    admin_client.get_realm_role_by_name.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_default_roles(spec, "name", "namespace")
        mock_log.assert_any_call("Default role 'missing-role' not found, skipping")

    admin_client.add_realm_role_composites.assert_not_called()


@pytest.mark.asyncio
async def test_configure_scope_mappings_missing_target_scope(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        scopeMappings=[
            KeycloakScopeMapping(clientScope="missing-scope", roles=["realm-role1"])
        ],
    )

    admin_client = AsyncMock()
    admin_client.get_client_scope_by_name.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_scope_mappings(spec, "name", "namespace")
        mock_log.assert_called_with(
            "Target client scope 'missing-scope' not found for scope mapping"
        )


@pytest.mark.asyncio
async def test_configure_client_scope_mappings_missing_client_role(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        clientScopeMappings={
            "source-client": [
                KeycloakScopeMapping(
                    client="target-client", roles=["missing-client-role"]
                )
            ]
        },
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.side_effect = lambda n, r, ns: (
        "src-uuid" if n == "source-client" else "tgt-uuid"
    )
    admin_client.get_client_role.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_scope_mappings(spec, "name", "namespace")
        mock_log.assert_called_with(
            "Client role 'missing-client-role' not found in container 'src-uuid'"
        )


@pytest.mark.asyncio
async def test_configure_scope_mappings_missing_roles(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        scopeMappings=[
            KeycloakScopeMapping(client="target-client", roles=["missing-role"])
        ],
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.return_value = "target-uuid"
    admin_client.get_realm_role_by_name.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_scope_mappings(spec, "name", "namespace")
        mock_log.assert_called_with(
            "Realm role 'missing-role' not found in realm 'test-realm'"
        )

    admin_client.add_scope_mappings_realm_roles.assert_not_called()


@pytest.mark.asyncio
async def test_configure_client_scope_mappings_missing_source(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        clientScopeMappings={
            "missing-source": [
                KeycloakScopeMapping(client="target-client", roles=["client-role1"])
            ]
        },
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_scope_mappings(spec, "name", "namespace")
        mock_log.assert_called_with(
            "Source client 'missing-source' not found for scope mappings"
        )


@pytest.mark.asyncio
async def test_configure_default_roles_no_existing_role(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRole={"name": "ignored", "description": "New description"},
    )

    admin_client = AsyncMock()
    admin_client.get_realm_role_by_name.return_value = None

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_default_roles(spec, "name", "namespace")
        mock_log.assert_called_with(
            "Default role 'default-roles-test-realm' not found, cannot update attributes"
        )


@pytest.mark.asyncio
async def test_do_update_default_roles(reconciler):
    old_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
    }
    new_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
        "defaultRoles": ["role1"],
    }
    diff = [("add", ("spec", "defaultRoles"), None, ["role1"])]

    admin_client = AsyncMock()
    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    # Mock configure_default_roles
    with patch.object(
        reconciler, "configure_default_roles", new_callable=AsyncMock
    ) as mock_config:
        status = MagicMock()
        await reconciler.do_update(
            old_spec, new_spec, diff, "name", "namespace", status
        )
        mock_config.assert_called_once()


@pytest.mark.asyncio
async def test_do_update_scope_mappings(reconciler):
    old_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
    }
    new_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
        "scopeMappings": [{"client": "c1", "roles": ["r1"]}],
    }
    diff = [
        ("add", ("spec", "scopeMappings"), None, [{"client": "c1", "roles": ["r1"]}])
    ]

    admin_client = AsyncMock()
    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(
        reconciler, "configure_scope_mappings", new_callable=AsyncMock
    ) as mock_config:
        status = MagicMock()
        await reconciler.do_update(
            old_spec, new_spec, diff, "name", "namespace", status
        )
        mock_config.assert_called_once()


@pytest.mark.asyncio
async def test_do_update_client_scope_mappings(reconciler):
    old_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
    }
    new_spec = {
        "realmName": "test",
        "operatorRef": {"namespace": "ns"},
        "clientScopeMappings": {"src": [{"client": "c1", "roles": ["r1"]}]},
    }
    diff = [
        (
            "add",
            ("spec", "clientScopeMappings"),
            None,
            {"src": [{"client": "c1", "roles": ["r1"]}]},
        )
    ]

    admin_client = AsyncMock()
    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(
        reconciler, "configure_scope_mappings", new_callable=AsyncMock
    ) as mock_config:
        status = MagicMock()
        await reconciler.do_update(
            old_spec, new_spec, diff, "name", "namespace", status
        )
        mock_config.assert_called_once()


@pytest.mark.asyncio
async def test_configure_default_roles_error(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        defaultRoles=["role1"],
    )

    admin_client = AsyncMock()
    admin_client.get_realm_role_composites.side_effect = Exception("API error")

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_default_roles(spec, "name", "namespace")
        # Should catch exception and log warning
        args, _ = mock_log.call_args
        assert "Failed to configure default role composites" in args[0]


@pytest.mark.asyncio
async def test_configure_scope_mapping_error(reconciler):
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef=OperatorRef(namespace="target-ns"),
        scopeMappings=[
            KeycloakScopeMapping(client="target-client", roles=["realm-role1"])
        ],
    )

    admin_client = AsyncMock()
    admin_client.get_client_uuid.side_effect = Exception("API error")

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    with patch.object(reconciler.logger, "warning") as mock_log:
        await reconciler.configure_scope_mappings(spec, "name", "namespace")
        args, _ = mock_log.call_args
        assert "Failed to configure scope mapping" in args[0]
