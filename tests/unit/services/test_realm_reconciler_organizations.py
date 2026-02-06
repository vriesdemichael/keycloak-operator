"""Unit tests for KeycloakRealmReconciler organizations and client profiles methods."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.realm import (
    ClientPolicy,
    ClientPolicyCondition,
    ClientProfile,
    ClientProfileExecutor,
    KeycloakRealmSpec,
    OperatorRef,
    Organization,
    OrganizationDomain,
    OrganizationIdentityProvider,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client with organization and client profile methods."""
    mock = MagicMock()

    # Organization methods
    mock.get_organizations = AsyncMock(return_value=[])
    mock.create_organization = AsyncMock(return_value={"id": "org-1"})
    mock.update_organization = AsyncMock(return_value=True)
    mock.delete_organization = AsyncMock(return_value=True)

    # Organization IdP link methods
    mock.get_organization_identity_providers = AsyncMock(return_value=[])
    mock.link_organization_identity_provider = AsyncMock(return_value=True)
    mock.unlink_organization_identity_provider = AsyncMock(return_value=True)

    # Client profile/policy methods
    mock.update_client_profiles = AsyncMock(return_value=True)
    mock.update_client_policies = AsyncMock(return_value=True)

    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakRealmReconciler:
    """KeycloakRealmReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace, rate_limiter=None):
        return admin_mock

    reconciler_instance = KeycloakRealmReconciler(
        keycloak_admin_factory=mock_factory,
    )
    reconciler_instance.logger = MagicMock()

    return reconciler_instance


class TestConfigureOrganizations:
    """Tests for configure_organizations method."""

    @pytest.mark.asyncio
    async def test_creates_new_organization(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New organization should be created when it doesn't exist."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    alias="acme",
                    description="ACME Corporation",
                    enabled=True,
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        admin_mock.get_organizations.assert_called_once()
        admin_mock.create_organization.assert_called_once()
        call_args = admin_mock.create_organization.call_args
        assert call_args[0][1]["name"] == "acme-corp"
        assert call_args[0][1]["alias"] == "acme"

    @pytest.mark.asyncio
    async def test_creates_organization_with_domains(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Organization with domains should include domain data in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    domains=[
                        OrganizationDomain(name="acme.com", verified=True),
                        OrganizationDomain(name="acme.org", verified=False),
                    ],
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        call_args = admin_mock.create_organization.call_args
        assert "domains" in call_args[0][1]
        assert len(call_args[0][1]["domains"]) == 2

    @pytest.mark.asyncio
    async def test_creates_organization_with_attributes(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Organization with attributes should include them in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    attributes={"industry": ["technology"], "tier": ["enterprise"]},
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        call_args = admin_mock.create_organization.call_args
        assert "attributes" in call_args[0][1]
        assert call_args[0][1]["attributes"]["industry"] == ["technology"]

    @pytest.mark.asyncio
    async def test_updates_existing_organization(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing organization should be updated."""
        admin_mock.get_organizations.return_value = [
            {"id": "org-1", "name": "acme-corp"}
        ]

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    description="Updated description",
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        admin_mock.update_organization.assert_called_once()
        admin_mock.create_organization.assert_not_called()

    @pytest.mark.asyncio
    async def test_deletes_removed_organization(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Organizations not in spec should be deleted."""
        admin_mock.get_organizations.return_value = [
            {"id": "org-1", "name": "keep-org"},
            {"id": "org-2", "name": "delete-org"},
        ]

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(name="keep-org"),
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        admin_mock.delete_organization.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_get_organizations_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle failure to get organizations gracefully."""
        admin_mock.get_organizations.side_effect = Exception("Feature not enabled")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(name="acme-corp"),
            ],
        )

        # Should not raise, but log a warning
        await reconciler.configure_organizations(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]
        admin_mock.create_organization.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_create_organization_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle organization creation failure gracefully."""
        admin_mock.create_organization.side_effect = Exception("Creation failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(name="acme-corp"),
            ],
        )

        # Should not raise, but log a warning
        await reconciler.configure_organizations(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_handles_update_organization_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle organization update failure gracefully."""
        admin_mock.get_organizations.return_value = [
            {"id": "org-1", "name": "acme-corp"}
        ]
        admin_mock.update_organization.side_effect = Exception("Update failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(name="acme-corp"),
            ],
        )

        # Should not raise, but log a warning
        await reconciler.configure_organizations(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_handles_delete_organization_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle organization deletion failure gracefully."""
        admin_mock.get_organizations.return_value = [
            {"id": "org-1", "name": "delete-org"}
        ]
        admin_mock.delete_organization.side_effect = Exception("Delete failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[],  # No orgs desired - existing should be deleted
        )

        # Should not raise, but log a warning
        await reconciler.configure_organizations(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_reconciles_idp_links_for_new_organization(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """IdP links should be reconciled after creating organization."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    identity_providers=[
                        OrganizationIdentityProvider(alias="google-idp"),
                    ],
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        admin_mock.get_organization_identity_providers.assert_called()
        admin_mock.link_organization_identity_provider.assert_called_once()

    @pytest.mark.asyncio
    async def test_reconciles_idp_links_for_existing_organization(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """IdP links should be reconciled for existing organizations."""
        admin_mock.get_organizations.return_value = [
            {"id": "org-1", "name": "acme-corp"}
        ]

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            organizations=[
                Organization(
                    name="acme-corp",
                    identity_providers=[
                        OrganizationIdentityProvider(alias="google-idp"),
                    ],
                )
            ],
        )

        await reconciler.configure_organizations(spec, "test-realm", "default")

        admin_mock.get_organization_identity_providers.assert_called()


class TestReconcileOrganizationIdpLinks:
    """Tests for _reconcile_organization_idp_links method."""

    @pytest.mark.asyncio
    async def test_links_new_idp(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New IdP should be linked to organization."""
        admin_mock.get_organization_identity_providers.return_value = []

        desired_idps = [
            OrganizationIdentityProvider(alias="google-idp"),
        ]

        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        admin_mock.link_organization_identity_provider.assert_called_once()

    @pytest.mark.asyncio
    async def test_unlinks_removed_idp(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """IdPs not in desired state should be unlinked."""
        admin_mock.get_organization_identity_providers.return_value = [
            {"alias": "keep-idp"},
            {"alias": "remove-idp"},
        ]

        desired_idps = [
            OrganizationIdentityProvider(alias="keep-idp"),
        ]

        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        admin_mock.unlink_organization_identity_provider.assert_called_once()
        call_args = admin_mock.unlink_organization_identity_provider.call_args
        assert call_args[0][2] == "remove-idp"

    @pytest.mark.asyncio
    async def test_no_changes_when_idps_match(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """No operations when current and desired IdPs match."""
        admin_mock.get_organization_identity_providers.return_value = [
            {"alias": "google-idp"},
        ]

        desired_idps = [
            OrganizationIdentityProvider(alias="google-idp"),
        ]

        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        admin_mock.link_organization_identity_provider.assert_not_called()
        admin_mock.unlink_organization_identity_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_get_idps_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle failure to get IdPs gracefully."""
        admin_mock.get_organization_identity_providers.side_effect = Exception("Failed")

        desired_idps = [
            OrganizationIdentityProvider(alias="google-idp"),
        ]

        # Should not raise, but log a warning
        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]
        admin_mock.link_organization_identity_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_link_idp_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle IdP linking failure gracefully."""
        admin_mock.link_organization_identity_provider.side_effect = Exception(
            "Link failed"
        )

        desired_idps = [
            OrganizationIdentityProvider(alias="google-idp"),
        ]

        # Should not raise, but log a warning
        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_handles_unlink_idp_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle IdP unlinking failure gracefully."""
        admin_mock.get_organization_identity_providers.return_value = [
            {"alias": "remove-idp"},
        ]
        admin_mock.unlink_organization_identity_provider.side_effect = Exception(
            "Unlink failed"
        )

        desired_idps = []  # Want to remove the IdP

        # Should not raise, but log a warning
        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_links_multiple_idps(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Multiple IdPs should all be linked."""
        admin_mock.get_organization_identity_providers.return_value = []

        desired_idps = [
            OrganizationIdentityProvider(alias="google-idp"),
            OrganizationIdentityProvider(alias="github-idp"),
            OrganizationIdentityProvider(alias="azure-idp"),
        ]

        await reconciler._reconcile_organization_idp_links(
            admin_mock, "test-realm", "org-1", "acme-corp", desired_idps, "default"
        )

        assert admin_mock.link_organization_identity_provider.call_count == 3


class TestConfigureClientProfilesAndPolicies:
    """Tests for configure_client_profiles_and_policies method."""

    @pytest.mark.asyncio
    async def test_creates_client_profiles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Client profiles should be created."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[
                ClientProfile(
                    name="secure-profile",
                    description="Security profile",
                    executors=[
                        ClientProfileExecutor(
                            executor="pkce-enforcer",
                            configuration={"auto-configure": "true"},
                        ),
                    ],
                )
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        admin_mock.update_client_profiles.assert_called_once()
        call_args = admin_mock.update_client_profiles.call_args
        profiles = call_args[0][1]
        assert len(profiles) == 1
        assert profiles[0]["name"] == "secure-profile"
        assert profiles[0]["executors"][0]["executor"] == "pkce-enforcer"

    @pytest.mark.asyncio
    async def test_creates_client_policies(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Client policies should be created."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[
                ClientPolicy(
                    name="confidential-policy",
                    description="Policy for confidential clients",
                    enabled=True,
                    conditions=[
                        ClientPolicyCondition(
                            condition="client-access-type",
                            configuration={"type": ["confidential"]},
                        )
                    ],
                    profiles=["secure-profile"],
                )
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        admin_mock.update_client_policies.assert_called_once()
        call_args = admin_mock.update_client_policies.call_args
        policies = call_args[0][1]
        assert len(policies) == 1
        assert policies[0]["name"] == "confidential-policy"
        assert policies[0]["profiles"] == ["secure-profile"]

    @pytest.mark.asyncio
    async def test_clears_profiles_when_empty(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Empty profiles list should clear all realm profiles."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[],  # Explicit empty list
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        admin_mock.update_client_profiles.assert_called_once()
        call_args = admin_mock.update_client_profiles.call_args
        assert call_args[0][1] == []

    @pytest.mark.asyncio
    async def test_clears_policies_when_empty(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Empty policies list should clear all realm policies."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[],  # Explicit empty list
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        admin_mock.update_client_policies.assert_called_once()
        call_args = admin_mock.update_client_policies.call_args
        assert call_args[0][1] == []

    @pytest.mark.asyncio
    async def test_handles_profile_update_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle profile update failure gracefully."""
        admin_mock.update_client_profiles.side_effect = Exception("Update failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[
                ClientProfile(name="secure-profile"),
            ],
        )

        # Should not raise, but log a warning
        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_handles_policy_update_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle policy update failure gracefully."""
        admin_mock.update_client_policies.side_effect = Exception("Update failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[
                ClientPolicy(name="my-policy", enabled=True),
            ],
        )

        # Should not raise, but log a warning
        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_logs_warning_on_profile_update_returns_false(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should log warning when profile update returns false."""
        admin_mock.update_client_profiles.return_value = False

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[
                ClientProfile(name="secure-profile"),
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_logs_warning_on_policy_update_returns_false(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should log warning when policy update returns false."""
        admin_mock.update_client_policies.return_value = False

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[
                ClientPolicy(name="my-policy", enabled=True),
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_creates_multiple_profiles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Multiple profiles should all be included in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[
                ClientProfile(name="profile-1"),
                ClientProfile(name="profile-2"),
                ClientProfile(name="profile-3"),
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        call_args = admin_mock.update_client_profiles.call_args
        profiles = call_args[0][1]
        assert len(profiles) == 3

    @pytest.mark.asyncio
    async def test_creates_multiple_policies(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Multiple policies should all be included in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[
                ClientPolicy(name="policy-1", enabled=True),
                ClientPolicy(name="policy-2", enabled=False),
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        call_args = admin_mock.update_client_policies.call_args
        policies = call_args[0][1]
        assert len(policies) == 2

    @pytest.mark.asyncio
    async def test_profile_with_multiple_executors(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Profile with multiple executors should include all in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_profiles=[
                ClientProfile(
                    name="fapi-profile",
                    executors=[
                        ClientProfileExecutor(executor="pkce-enforcer"),
                        ClientProfileExecutor(executor="secure-client-authenticator"),
                        ClientProfileExecutor(executor="consent-required"),
                    ],
                )
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        call_args = admin_mock.update_client_profiles.call_args
        profile = call_args[0][1][0]
        assert len(profile["executors"]) == 3

    @pytest.mark.asyncio
    async def test_policy_with_multiple_conditions(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Policy with multiple conditions should include all in payload."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_policies=[
                ClientPolicy(
                    name="strict-policy",
                    enabled=True,
                    conditions=[
                        ClientPolicyCondition(
                            condition="client-access-type",
                            configuration={"type": ["confidential"]},
                        ),
                        ClientPolicyCondition(
                            condition="client-roles",
                            configuration={"roles": ["admin"]},
                        ),
                    ],
                )
            ],
        )

        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        call_args = admin_mock.update_client_policies.call_args
        policy = call_args[0][1][0]
        assert len(policy["conditions"]) == 2

    @pytest.mark.asyncio
    async def test_handles_clear_profiles_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle failure to clear profiles gracefully."""
        admin_mock.update_client_profiles.side_effect = Exception("Clear failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            # No profiles - should trigger clear
        )

        # Should not raise, but log a warning
        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_handles_clear_policies_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle failure to clear policies gracefully."""
        admin_mock.update_client_policies.side_effect = Exception("Clear failed")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            # No policies - should trigger clear
        )

        # Should not raise, but log a warning
        await reconciler.configure_client_profiles_and_policies(
            spec, "test-realm", "default"
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]
