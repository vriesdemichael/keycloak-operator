"""Unit tests for KeycloakAdminClient organization methods."""

from unittest.mock import AsyncMock

import pytest

from .test_helpers import MockResponse


class TestGetOrganizations:
    """Tests for get_organizations method."""

    @pytest.mark.asyncio
    async def test_returns_organizations_on_success(self, mock_admin_client):
        """Should return list of organizations when successful."""
        mock_response = MockResponse(
            200,
            [
                {"id": "org-1", "name": "acme-corp", "alias": "acme"},
                {"id": "org-2", "name": "globex", "alias": "globex"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        orgs = await mock_admin_client.get_organizations("test-realm", "default")

        assert len(orgs) == 2
        assert orgs[0]["name"] == "acme-corp"
        assert orgs[1]["name"] == "globex"
        mock_admin_client._make_request.assert_called_once_with(
            "GET",
            "realms/test-realm/organizations",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when organizations feature not enabled."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        orgs = await mock_admin_client.get_organizations("test-realm", "default")

        assert orgs == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_null_response(self, mock_admin_client):
        """Should return empty list when response is null."""
        mock_response = MockResponse(200, None)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        orgs = await mock_admin_client.get_organizations("test-realm", "default")

        assert orgs == []


class TestGetOrganizationByName:
    """Tests for get_organization_by_name method."""

    @pytest.mark.asyncio
    async def test_returns_organization_when_found(self, mock_admin_client):
        """Should return organization when it exists."""
        mock_response = MockResponse(
            200,
            [{"id": "org-1", "name": "acme-corp", "alias": "acme"}],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        org = await mock_admin_client.get_organization_by_name(
            "test-realm", "acme-corp", "default"
        )

        assert org is not None
        assert org["name"] == "acme-corp"
        # Verify search params were used
        mock_admin_client._make_request.assert_called_once()
        call_kwargs = mock_admin_client._make_request.call_args[1]
        assert call_kwargs["params"]["search"] == "acme-corp"
        assert call_kwargs["params"]["exact"] == "true"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when organization doesn't exist."""
        mock_response = MockResponse(200, [])
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        org = await mock_admin_client.get_organization_by_name(
            "test-realm", "nonexistent", "default"
        )

        assert org is None

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, mock_admin_client):
        """Should return None when organizations feature not enabled."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        org = await mock_admin_client.get_organization_by_name(
            "test-realm", "acme-corp", "default"
        )

        assert org is None

    @pytest.mark.asyncio
    async def test_filters_by_exact_name(self, mock_admin_client):
        """Should filter results to find exact name match."""
        mock_response = MockResponse(
            200,
            [
                {"id": "org-1", "name": "acme", "alias": "acme"},
                {"id": "org-2", "name": "acme-corp", "alias": "acme-corp"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        org = await mock_admin_client.get_organization_by_name(
            "test-realm", "acme-corp", "default"
        )

        assert org is not None
        assert org["name"] == "acme-corp"
        assert org["id"] == "org-2"


class TestCreateOrganization:
    """Tests for create_organization method."""

    @pytest.mark.asyncio
    async def test_returns_organization_on_success(self, mock_admin_client):
        """Should return created organization on success."""
        # create_organization calls get_organization_by_name on success
        mock_create_response = MockResponse(201, {})
        mock_get_response = MockResponse(
            200,
            [{"id": "org-1", "name": "acme-corp", "alias": "acme"}],
        )
        mock_admin_client._make_request = AsyncMock(
            side_effect=[mock_create_response, mock_get_response]
        )

        org = await mock_admin_client.create_organization(
            "test-realm",
            {"name": "acme-corp", "alias": "acme"},
            "default",
        )

        assert org is not None
        assert org["name"] == "acme-corp"

    @pytest.mark.asyncio
    async def test_returns_existing_on_conflict(self, mock_admin_client):
        """Should return existing organization on conflict (409)."""
        mock_conflict_response = MockResponse(409)
        mock_get_response = MockResponse(
            200,
            [{"id": "org-1", "name": "acme-corp", "alias": "acme"}],
        )
        mock_admin_client._make_request = AsyncMock(
            side_effect=[mock_conflict_response, mock_get_response]
        )

        org = await mock_admin_client.create_organization(
            "test-realm",
            {"name": "acme-corp", "alias": "acme"},
            "default",
        )

        assert org is not None
        assert org["name"] == "acme-corp"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on unexpected error (decorator catches error)."""
        mock_response = MockResponse(500, text="Internal Server Error")
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_create decorator catches the error and returns None
        org = await mock_admin_client.create_organization(
            "test-realm",
            {"name": "acme-corp"},
            "default",
        )

        assert org is None


class TestUpdateOrganization:
    """Tests for update_organization method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful update."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_organization(
            "test-realm",
            "org-id",
            {"name": "acme-corp", "description": "Updated description"},
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_not_found(self, mock_admin_client):
        """Should return False when organization doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_organization(
            "test-realm",
            "nonexistent",
            {"name": "acme-corp"},
            "default",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on unexpected error (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_update decorator catches the error and returns False
        result = await mock_admin_client.update_organization(
            "test-realm",
            "org-id",
            {"name": "acme-corp"},
            "default",
        )

        assert result is False


class TestDeleteOrganization:
    """Tests for delete_organization method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful deletion."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_organization(
            "test-realm", "org-id", "default"
        )

        assert result is True
        mock_admin_client._make_request.assert_called_once_with(
            "DELETE",
            "realms/test-realm/organizations/org-id",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when organization doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_organization(
            "test-realm", "nonexistent", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on unexpected error (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_delete decorator catches the error and returns False
        result = await mock_admin_client.delete_organization(
            "test-realm", "org-id", "default"
        )

        assert result is False


class TestGetOrganizationIdentityProviders:
    """Tests for get_organization_identity_providers method."""

    @pytest.mark.asyncio
    async def test_returns_idps_on_success(self, mock_admin_client):
        """Should return list of linked IdPs when successful."""
        mock_response = MockResponse(
            200,
            [
                {"alias": "google", "internalId": "idp-1"},
                {"alias": "azure-ad", "internalId": "idp-2"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        idps = await mock_admin_client.get_organization_identity_providers(
            "test-realm", "org-id", "default"
        )

        assert len(idps) == 2
        assert idps[0]["alias"] == "google"
        assert idps[1]["alias"] == "azure-ad"
        mock_admin_client._make_request.assert_called_once_with(
            "GET",
            "realms/test-realm/organizations/org-id/identity-providers",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when organization not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        idps = await mock_admin_client.get_organization_identity_providers(
            "test-realm", "nonexistent", "default"
        )

        assert idps == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_null_response(self, mock_admin_client):
        """Should return empty list when response is null."""
        mock_response = MockResponse(200, None)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        idps = await mock_admin_client.get_organization_identity_providers(
            "test-realm", "org-id", "default"
        )

        assert idps == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_error(self, mock_admin_client):
        """Should return empty list on error (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_get_list decorator catches the error and returns []
        idps = await mock_admin_client.get_organization_identity_providers(
            "test-realm", "org-id", "default"
        )

        assert idps == []


class TestLinkOrganizationIdentityProvider:
    """Tests for link_organization_identity_provider method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful link."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.link_organization_identity_provider(
            "test-realm", "org-id", "google", "default"
        )

        assert result is True
        mock_admin_client._make_request.assert_called_once_with(
            "POST",
            "realms/test-realm/organizations/org-id/identity-providers",
            "default",
            json="google",  # Just the alias string
        )

    @pytest.mark.asyncio
    async def test_returns_true_on_201(self, mock_admin_client):
        """Should return True on 201 Created."""
        mock_response = MockResponse(201)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.link_organization_identity_provider(
            "test-realm", "org-id", "azure-ad", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_conflict(self, mock_admin_client):
        """Should return True when IdP already linked (idempotent)."""
        mock_response = MockResponse(409)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.link_organization_identity_provider(
            "test-realm", "org-id", "google", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_not_found(self, mock_admin_client):
        """Should return False when org or IdP not found (decorator catches)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_update decorator catches the error
        result = await mock_admin_client.link_organization_identity_provider(
            "test-realm", "org-id", "nonexistent", "default"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on unexpected error (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.link_organization_identity_provider(
            "test-realm", "org-id", "google", "default"
        )

        assert result is False


class TestUnlinkOrganizationIdentityProvider:
    """Tests for unlink_organization_identity_provider method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful unlink."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.unlink_organization_identity_provider(
            "test-realm", "org-id", "google", "default"
        )

        assert result is True
        mock_admin_client._make_request.assert_called_once_with(
            "DELETE",
            "realms/test-realm/organizations/org-id/identity-providers/google",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when link doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.unlink_organization_identity_provider(
            "test-realm", "org-id", "nonexistent", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on unexpected error (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.unlink_organization_identity_provider(
            "test-realm", "org-id", "google", "default"
        )

        assert result is False
