"""
Keycloak Admin API client utilities.

This module provides a high-level interface to the Keycloak Admin REST API
for managing Keycloak instances, realms, clients, and other resources.

The client handles:
- Authentication with Keycloak admin credentials
- Session management and token refresh
- Error handling and retry logic
- Type-safe API interactions
- Rate limiting for API protection
"""

import asyncio
import logging
import time
from datetime import UTC, datetime

# Import RateLimiter - use TYPE_CHECKING to avoid circular import
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel

from keycloak_operator.models.keycloak_api import (
    AuthenticationFlowRepresentation,
    ClientRepresentation,
    ComponentRepresentation,
    IdentityProviderRepresentation,
    ProtocolMapperRepresentation,
    RealmRepresentation,
    RoleRepresentation,
    UserRepresentation,
)

if TYPE_CHECKING:
    from keycloak_operator.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Global cache for httpx clients - one per Keycloak instance
# Key: (server_url, verify_ssl), Value: httpx.AsyncClient
_httpx_client_cache: dict[tuple[str, bool], httpx.AsyncClient] = {}
_cache_lock = asyncio.Lock()


class KeycloakAdminError(Exception):
    """Base exception for Keycloak Admin API errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body

    def body_preview(self, limit: int = 2048) -> str | None:
        """Return a truncated preview of the response body for logging."""

        if self.response_body is None:
            return None

        if len(self.response_body) <= limit:
            return self.response_body

        return f"{self.response_body[:limit]}...<truncated>"


class KeycloakAdminClient:
    """
        High-level client for Keycloak Admin API operations.

        This client provides methods for managing Keycloak resources including
        realms, clients, users, and configuration. It handles authentication,
        session management, and provides a clean interface for the operator.

    This client provides comprehensive Keycloak Admin API operations with
        authentication, error handling, and retry logic.
    """

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        realm: str = "master",
        client_id: str = "admin-cli",
        verify_ssl: bool = True,
        timeout: int = 60,
        rate_limiter: "RateLimiter | None" = None,
    ) -> None:
        """
        Initialize Keycloak Admin client.

        Args:
            server_url: Base URL of the Keycloak server
            username: Admin username
            password: Admin password
            realm: Admin realm (default: master)
            client_id: Client ID for admin API access
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            rate_limiter: Optional rate limiter for API call throttling
        """
        self.server_url = server_url.rstrip("/")
        self.username = username
        self.password = password
        self.admin_realm = realm
        self.client_id = client_id
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.rate_limiter = rate_limiter

        # Authentication state
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expires_at: float | None = None

        logger.info(f"Initialized Keycloak Admin client for {server_url}")

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx client (lazy initialization with caching)."""
        cache_key = (self.server_url, self.verify_ssl)

        # Check if we have a cached client
        async with _cache_lock:
            if cache_key in _httpx_client_cache:
                cached_client = _httpx_client_cache[cache_key]
                if not cached_client.is_closed:
                    return cached_client
                else:
                    # Remove closed client from cache
                    del _httpx_client_cache[cache_key]

            # Create new httpx client with connection pooling and timeouts
            client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(
                    max_connections=100,  # Global connection pool
                    max_keepalive_connections=20,  # Keepalive pool
                ),
                headers={
                    "Content-Type": "application/json",
                },
                follow_redirects=False,
            )

            # Cache the client for reuse
            _httpx_client_cache[cache_key] = client
            logger.debug(f"Created and cached httpx client for {self.server_url}")
            return client

    async def close(self) -> None:
        """
        Close method for compatibility with async context manager.

        Note: With the caching strategy, we don't actually close the httpx client
        here as it's shared across multiple KeycloakAdminClient instances.
        The cached client will be reused until the operator shuts down.
        """
        # Clear authentication tokens but don't close the shared httpx client
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None

    async def __aenter__(self) -> "KeycloakAdminClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit - ensures session cleanup."""
        await self.close()

    async def authenticate(self) -> None:
        """
        Authenticate with Keycloak and obtain access tokens.

        Uses username/password grant to obtain access and refresh tokens.
        """
        auth_url = (
            f"{self.server_url}/realms/{self.admin_realm}/protocol/openid-connect/token"
        )

        auth_data = {
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
            "client_id": self.client_id,
        }

        try:
            client = await self._get_client()

            # Make authentication request
            # Use data parameter for form-urlencoded data
            response = await client.post(
                auth_url,
                data=auth_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            # Store tokens
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")

            # Calculate expiration time
            self.token_expires_at = time.time() + token_data.get("expires_in", 300)

            logger.debug("Successfully authenticated with Keycloak")

        except httpx.HTTPError as e:
            logger.error(f"Failed to authenticate with Keycloak: {e}")
            raise KeycloakAdminError(f"Authentication failed: {e}") from e

    async def _ensure_authenticated(self) -> None:
        """
        Ensure we have a valid access token, refreshing if necessary.
        """
        # If no token or token is expired (with 30s buffer)
        if not self.access_token or (
            self.token_expires_at and time.time() >= self.token_expires_at - 30
        ):
            if self.refresh_token:
                try:
                    # Try to refresh token
                    await self._refresh_token()
                except KeycloakAdminError:
                    # Refresh failed, re-authenticate
                    await self.authenticate()
            else:
                # No refresh token, re-authenticate
                await self.authenticate()

    async def _refresh_token(self) -> None:
        """
        Refresh the access token using the refresh token.
        """
        if not self.refresh_token:
            raise KeycloakAdminError("No refresh token available")

        auth_url = (
            f"{self.server_url}/realms/{self.admin_realm}/protocol/openid-connect/token"
        )

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }

        try:
            client = await self._get_client()

            # Use data parameter for form-urlencoded data
            response = await client.post(
                auth_url,
                data=refresh_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            # Update tokens and expiration
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")
            self.token_expires_at = time.time() + token_data.get("expires_in", 300)

            logger.debug("Successfully refreshed access token")

        except httpx.HTTPError as e:
            logger.error(f"Failed to refresh token: {e}")
            raise KeycloakAdminError(f"Token refresh failed: {e}") from e

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        namespace: str,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make an authenticated request to the Keycloak Admin API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to admin base)
            namespace: Origin namespace for rate limiting
            data: Request body data (deprecated, use json parameter)
            json: JSON request body data
            params: Query parameters

        Returns:
            Response object (httpx.Response) with body already buffered

        Raises:
            KeycloakAdminError: On API errors or rate limit timeouts
        """
        # Apply rate limiting before making request
        if self.rate_limiter:
            try:
                await self.rate_limiter.acquire(namespace)
            except TimeoutError as e:
                logger.warning(f"Rate limit timeout for namespace '{namespace}': {e}")
                raise KeycloakAdminError(
                    f"Rate limit timeout: {e}",
                    status_code=429,
                ) from e

        # Ensure we have valid authentication
        await self._ensure_authenticated()

        url = urljoin(f"{self.server_url}/admin/", endpoint.lstrip("/"))
        client = await self._get_client()

        try:
            # Prepare headers with auth token
            headers = {"Authorization": f"Bearer {self.access_token}"}

            # Make the request (httpx buffers response automatically)
            response = await client.request(
                method=method,
                url=url,
                json=json if json else data if data else None,
                params=params,
                headers=headers,
            )

            # Handle 401 - token might be expired
            if response.status_code == 401:
                logger.warning("Received 401, attempting re-authentication")
                await self.authenticate()

                # Retry with new token
                headers = {"Authorization": f"Bearer {self.access_token}"}
                response = await client.request(
                    method=method,
                    url=url,
                    json=json if json else data if data else None,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                return response

            response.raise_for_status()
            return response

        except httpx.HTTPStatusError as e:
            # HTTP error with response
            status_code = e.response.status_code
            response_body: str | None = None

            try:
                response_body = e.response.text or "<no content>"
            except Exception:  # pragma: no cover
                response_body = "<unavailable>"

            body_preview = (
                response_body[:1024] + "...<truncated>"
                if len(response_body) > 1024
                else response_body
            )

            logger.error(
                f"Request failed: {method} {url} - {e}",
                extra={
                    "http_status": status_code,
                    "response_body": body_preview,
                },
            )
            raise KeycloakAdminError(
                f"API request failed: {e}",
                status_code=status_code,
                response_body=response_body,
            ) from e

        except httpx.HTTPError as e:
            # Other HTTP errors (connection, timeout, etc.)
            logger.error(f"Request failed: {method} {url} - {e}")
            raise KeycloakAdminError(
                f"API request failed: {e}",
                status_code=None,
            ) from e

    async def _make_validated_request(
        self,
        method: str,
        endpoint: str,
        namespace: str,
        request_model: BaseModel | None = None,
        response_model: type[BaseModel] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Make an authenticated request with automatic Pydantic validation.

        This method wraps _make_request to provide automatic validation of
        request and response data using Pydantic models.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to admin base)
            namespace: Origin namespace for rate limiting
            request_model: Pydantic model instance to serialize as request body
            response_model: Pydantic model class to validate response data
            **kwargs: Additional arguments passed to _make_request

        Returns:
            Validated response model instance if response_model is provided,
            otherwise the raw Response object

        Raises:
            KeycloakAdminError: If the API request fails
            ValidationError: If response data doesn't match the expected model
        """
        # Validate and serialize request payload
        if request_model is not None:
            # Convert Pydantic model to JSON-compatible dict
            # exclude_none: Don't send null values to API
            # by_alias: Use camelCase field names for API
            kwargs["json"] = request_model.model_dump(exclude_none=True, by_alias=True)

        # Make the HTTP request
        response = await self._make_request(method, endpoint, namespace, **kwargs)

        # Validate and parse response
        if response_model is not None and response.status_code < 300:
            # Parse response JSON and validate against model (httpx buffers automatically)
            response_data = response.json()
            return response_model.model_validate(response_data)

        return response

    # Realm Management Methods

    async def create_realm(
        self, realm_config: RealmRepresentation | dict[str, Any], namespace: str
    ) -> RealmRepresentation:
        """
        Create a new realm in Keycloak.

        Args:
            realm_config: Realm configuration as RealmRepresentation or dict
            namespace: Origin namespace for rate limiting

        Returns:
            Created realm information as RealmRepresentation

        Raises:
            KeycloakAdminError: If realm creation fails
        """
        # Convert dict to model if needed
        if isinstance(realm_config, dict):
            realm_config = RealmRepresentation.model_validate(realm_config)

        logger.info(f"Creating realm: {realm_config.realm or 'unknown'}")

        # Use validated request
        response = await self._make_validated_request(
            "POST", "realms", namespace, request_model=realm_config
        )

        if response.status_code == 201:
            logger.info("Realm created successfully")
            # Return the realm config as validated model
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to create realm: {response.status_code}",
                response.status_code,
            )

    async def get_realm(
        self, realm_name: str, namespace: str
    ) -> RealmRepresentation | None:
        """
        Get realm configuration from Keycloak.

        Args:
            realm_name: Name of the realm to retrieve
            namespace: Origin namespace for rate limiting

        Returns:
            Realm configuration as RealmRepresentation or None if not found

        Raises:
            KeycloakAdminError: If the request fails (except 404)
        """
        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}",
                namespace,
                response_model=RealmRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                return None
            raise

    async def export_realm(
        self, realm_name: str, namespace: str
    ) -> RealmRepresentation | None:
        """
        Export realm configuration from Keycloak.

        Based on OpenAPI spec: GET /admin/realms/{realm}
        Returns the complete realm representation.

        Args:
            realm_name: Name of the realm to export
            namespace: Origin namespace for rate limiting

        Returns:
            Complete realm configuration as RealmRepresentation or None if not found

        Example:
            realm = await client.export_realm("my-realm", "default")
            if realm:
                print(f"Realm {realm.realm} has {len(realm.clients or [])} clients")
        """
        logger.info(f"Exporting realm '{realm_name}'")

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}",
                namespace,
                response_model=RealmRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(f"Realm '{realm_name}' not found for export")
                return None
            logger.error(f"Failed to export realm '{realm_name}': {e}")
            return None

    async def get_realms(
        self, namespace: str, brief_representation: bool = False
    ) -> list[RealmRepresentation] | None:
        """
        Get all accessible realms from Keycloak.

        Based on OpenAPI spec: GET /admin/realms
        Returns a list of accessible realms filtered by what the caller is allowed to view.

        Args:
            namespace: Origin namespace for rate limiting
            brief_representation: If True, return brief representation of realms

        Returns:
            List of realm configurations as RealmRepresentation or None on error

        Example:
            realms = await client.get_realms("default")
            for realm in realms:
                print(f"Realm: {realm.realm}, Enabled: {realm.enabled}")
        """
        logger.debug("Fetching all accessible realms")

        try:
            params = {}
            if brief_representation:
                params["briefRepresentation"] = "true"

            response = await self._make_request(
                "GET", "realms", namespace, params=params
            )

            if response.status_code == 200:
                realms_data = response.json()
                # Validate each realm with Pydantic
                return [
                    RealmRepresentation.model_validate(realm) for realm in realms_data
                ]
            else:
                logger.error(f"Failed to get realms: HTTP {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to get realms: {e}")
            return None

    async def update_realm(
        self,
        realm_name: str,
        realm_config: RealmRepresentation | dict[str, Any],
        namespace: str,
    ) -> RealmRepresentation:
        """
        Update realm configuration.

        Args:
            realm_name: Name of the realm to update
            realm_config: Updated realm configuration as RealmRepresentation or dict
            namespace: Origin namespace for rate limiting

        Returns:
            Updated realm configuration as RealmRepresentation

        Raises:
            KeycloakAdminError: If realm update fails
        """
        # Convert dict to model if needed
        if isinstance(realm_config, dict):
            realm_config = RealmRepresentation.model_validate(realm_config)

        logger.info(f"Updating realm: {realm_name}")

        # Use validated request
        response = await self._make_validated_request(
            "PUT", f"realms/{realm_name}", namespace, request_model=realm_config
        )

        if response.status_code == 204:  # No content on successful update
            # Return the updated config
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to update realm: {response.status_code}",
                response.status_code,
            )

    # Client Management Methods

    async def get_client_by_name(
        self, client_id: str, realm_name: str, namespace: str
    ) -> ClientRepresentation | None:
        """
        Get a client by its client ID in the specified realm.

        Args:
            client_id: The client ID to search for
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client data as ClientRepresentation if found, None otherwise

        Example:
            client = await admin_client.get_client_by_name("my-client", "my-realm", "default")
            if client:
                print(f"Client UUID: {client.id}, Enabled: {client.enabled}")
        """
        logger.info(f"Looking up client '{client_id}' in realm '{realm_name}'")

        try:
            # Get all clients in the realm
            response = await self._make_request(
                "GET", f"realms/{realm_name}/clients", namespace
            )
            clients_data = response.json()

            # Find client by clientId and validate
            for client_data in clients_data:
                if client_data.get("clientId") == client_id:
                    logger.info(
                        f"Found client '{client_id}' with ID: {client_data['id']}"
                    )
                    return ClientRepresentation.model_validate(client_data)

            logger.info(f"Client '{client_id}' not found in realm '{realm_name}'")
            return None

        except Exception as e:
            logger.error(f"Failed to get client '{client_id}': {e}")
            return None

    async def get_client_uuid(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Get client UUID by client ID in the specified realm.

        Args:
            client_id: The client ID to search for
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client UUID if found, None otherwise
        """
        client = await self.get_client_by_name(client_id, realm_name, namespace)
        if client:
            return client.id
        return None

    async def create_client(
        self,
        client_config: ClientRepresentation | dict[str, Any],
        realm_name: str,
        namespace: str,
    ) -> str | None:
        """
        Create a new client in the specified realm.

        Args:
            client_config: Client configuration as ClientRepresentation or dict
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client UUID if successful, None otherwise

        Raises:
            KeycloakAdminError: If client creation fails
        """
        # Convert dict to model if needed
        if isinstance(client_config, dict):
            client_config = ClientRepresentation.model_validate(client_config)

        client_id = client_config.client_id or "unknown"
        logger.info(f"Creating client '{client_id}' in realm '{realm_name}'")

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/clients",
                namespace,
                request_model=client_config,
            )

            if response.status_code == 201:
                # Get the created client UUID from Location header
                location = response.headers.get("Location", "")
                created_client_uuid = location.split("/")[-1] if location else None
                logger.info(
                    f"Successfully created client '{client_id}' with UUID: {created_client_uuid}"
                )
                return created_client_uuid
            else:
                logger.error(
                    f"Failed to create client '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to create client '{client_id}': {e}")
            return None

    async def update_client(
        self,
        client_uuid: str,
        client_config: ClientRepresentation | dict[str, Any],
        realm_name: str,
        namespace: str,
    ) -> bool:
        """
        Update an existing client configuration.

        Args:
            client_uuid: The UUID of the client to update
            client_config: Updated client configuration as ClientRepresentation or dict
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful

        Raises:
            KeycloakAdminError: If client update fails
        """
        # Convert dict to model if needed
        if isinstance(client_config, dict):
            client_config = ClientRepresentation.model_validate(client_config)

        client_id = client_config.client_id or "unknown"
        logger.info(
            f"Updating client '{client_id}' (UUID: {client_uuid}) in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/clients/{client_uuid}",
                namespace,
                request_model=client_config,
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated client '{client_id}'")
                return True
            else:
                error_msg = f"Failed to update client '{client_id}': HTTP {response.status_code}"
                logger.error(error_msg)
                raise KeycloakAdminError(error_msg, response.status_code)

        except KeycloakAdminError:
            raise
        except Exception as e:
            error_msg = f"Failed to update client '{client_id}': {e}"
            logger.error(error_msg)
            raise KeycloakAdminError(error_msg) from e

    async def get_client_secret(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Get the client secret for a confidential client.

        Args:
            client_id: The client ID
            realm_name: Name of the realm (defaults to "master")

        Returns:
            Client secret if found, None otherwise
        """
        logger.info(f"Getting client secret for '{client_id}' in realm '{realm_name}'")

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.error(f"Client '{client_id}' not found")
                return None

            client_uuid = client.id

            # Get the client secret
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/client-secret",
                namespace,
            )

            if response.status_code == 200:
                secret_data = response.json()
                secret = secret_data.get("value")
                if secret:
                    logger.info(
                        f"Successfully retrieved client secret for '{client_id}'"
                    )
                    return secret
                else:
                    logger.warning(f"No secret found for client '{client_id}'")
                    return None
            else:
                logger.error(
                    f"Failed to get client secret for '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to get client secret for '{client_id}': {e}")
            return None

    async def get_service_account_user(
        self, client_uuid: str, realm_name: str, namespace: str
    ) -> UserRepresentation:
        """Get the service account user for a client.

        Based on OpenAPI spec: GET /admin/realms/{realm}/clients/{id}/service-account-user

        Args:
            client_uuid: Client UUID in Keycloak
            realm_name: Target realm name
            namespace: Origin namespace for rate limiting

        Returns:
            Service account user representation as UserRepresentation

        Raises:
            KeycloakAdminError: If retrieval fails or service account is disabled

        Example:
            user = await admin_client.get_service_account_user(client_uuid, "my-realm", "default")
            print(f"Service account user: {user.username}, ID: {user.id}")
        """
        logger.debug(
            f"Fetching service account user for client {client_uuid} in realm {realm_name}"
        )

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/service-account-user",
                namespace,
                response_model=UserRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                raise KeycloakAdminError(
                    (
                        f"Service account user not found for client {client_uuid}. "
                        "Ensure service_accounts_enabled is true."
                    ),
                    status_code=404,
                ) from e
            raise

    async def get_realm_role(
        self, role_name: str, realm_name: str, namespace: str
    ) -> RoleRepresentation | None:
        """Get a realm role by name.

        Args:
            role_name: Name of the role to retrieve
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Role representation as RoleRepresentation or None if not found

        Example:
            role = await admin_client.get_realm_role("admin", "my-realm", "default")
            if role:
                print(f"Role: {role.name}, ID: {role.id}")
        """
        logger.debug(f"Fetching realm role '{role_name}' in realm '{realm_name}'")

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/roles/{role_name}",
                namespace,
                response_model=RoleRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(
                    f"Realm role '{role_name}' not found in realm '{realm_name}'"
                )
                return None
            raise

    async def get_client_role(
        self, client_uuid: str, role_name: str, realm_name: str, namespace: str
    ) -> RoleRepresentation | None:
        """Get a client role by name.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to retrieve
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Role representation as RoleRepresentation or None if not found

        Example:
            role = await admin_client.get_client_role(client_uuid, "admin", "my-realm", "default")
            if role:
                print(f"Client role: {role.name}, ID: {role.id}")
        """
        logger.debug(
            f"Fetching client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}",
                namespace,
                response_model=RoleRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(
                    f"Client role '{role_name}' not found for client '{client_uuid}'"
                )
                return None
            raise

    async def assign_realm_roles_to_user(
        self, user_id: str, role_names: list[str], realm_name: str, namespace: str
    ) -> None:
        """Assign realm-level roles to a user.

        Args:
            user_id: UUID of the user in Keycloak
            role_names: List of role names to assign
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Raises:
            KeycloakAdminError: If assignment fails

        Example:
            await admin_client.assign_realm_roles_to_user(
                user_id="123-456-789",
                role_names=["admin", "user"],
                realm_name="my-realm",
                namespace="default"
            )
        """
        logger.info(f"Assigning realm roles to user {user_id} in realm '{realm_name}'")

        roles: list[RoleRepresentation] = []
        for role_name in role_names:
            role = await self.get_realm_role(role_name, realm_name, namespace)
            if not role:
                logger.warning(
                    f"Realm role '{role_name}' not found in realm '{realm_name}', skipping"
                )
                continue
            roles.append(role)

        if not roles:
            logger.info(f"No valid realm roles to assign to user {user_id}")
            return

        # Serialize roles to dict for API
        roles_data = [
            role.model_dump(by_alias=True, exclude_none=True) for role in roles
        ]

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/users/{user_id}/role-mappings/realm",
                namespace,
                json=roles_data,
            )

            if response.status_code not in (200, 204):
                raise KeycloakAdminError(
                    f"Failed to assign realm roles to user: {response.text}",
                    status_code=response.status_code,
                )

            logger.info(
                f"Successfully assigned {len(roles)} realm roles to user {user_id}"
            )
        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to assign realm roles to user {user_id}: {e}")
            raise KeycloakAdminError(f"Failed to assign realm roles: {e}") from e

    async def assign_client_roles_to_user(
        self,
        user_id: str,
        client_uuid: str,
        role_names: list[str],
        realm_name: str,
        namespace: str,
    ) -> None:
        """Assign client-level roles to a user.

        Args:
            user_id: UUID of the user in Keycloak
            client_uuid: UUID of the client in Keycloak
            role_names: List of role names to assign
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Raises:
            KeycloakAdminError: If assignment fails

        Example:
            await admin_client.assign_client_roles_to_user(
                user_id="123-456-789",
                client_uuid="abc-def-ghi",
                role_names=["admin", "user"],
                realm_name="my-realm",
                namespace="default"
            )
        """
        logger.info(
            f"Assigning client roles to user {user_id} for client {client_uuid} in realm '{realm_name}'"
        )

        roles: list[RoleRepresentation] = []
        for role_name in role_names:
            role = await self.get_client_role(
                client_uuid, role_name, realm_name, namespace
            )
            if not role:
                logger.warning(
                    f"Client role '{role_name}' not found for client '{client_uuid}', skipping"
                )
                continue
            roles.append(role)

        if not roles:
            logger.info(f"No valid client roles to assign to user {user_id}")
            return

        # Serialize roles to dict for API
        roles_data = [
            role.model_dump(by_alias=True, exclude_none=True) for role in roles
        ]

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_uuid}",
                namespace,
                json=roles_data,
            )

            if response.status_code not in (200, 204):
                raise KeycloakAdminError(
                    f"Failed to assign client roles to user: {response.text}",
                    status_code=response.status_code,
                )

            logger.info(
                f"Successfully assigned {len(roles)} client roles to user {user_id}"
            )
        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to assign client roles to user {user_id}: {e}")
            raise KeycloakAdminError(f"Failed to assign client roles: {e}") from e

    async def delete_client(
        self, client_id: str, realm_name: str, namespace: str
    ) -> bool:
        """
        Delete a client from the specified realm.

        Args:
            client_id: The client ID to delete
            realm_name: Name of the realm (defaults to "master")

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting client '{client_id}' from realm '{realm_name}'")

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.warning(f"Client '{client_id}' not found, nothing to delete")
                return True  # Consider this successful

            client_uuid = client.id

            response = await self._make_request(
                "DELETE", f"realms/{realm_name}/clients/{client_uuid}", namespace
            )

            if response.status_code == 204:
                logger.info(f"Successfully deleted client '{client_id}'")
                return True
            else:
                logger.error(
                    f"Failed to delete client '{client_id}': {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete client '{client_id}': {e}")
            return False

    async def regenerate_client_secret(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Regenerate the client secret for a confidential client.

        Args:
            client_id: The client ID
            realm_name: Name of the realm (defaults to "master")

        Returns:
            New client secret if successful, None otherwise
        """
        logger.info(
            f"Regenerating client secret for '{client_id}' in realm '{realm_name}'"
        )

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.error(f"Client '{client_id}' not found")
                return None

            client_uuid = client.id

            # Regenerate the client secret
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/clients/{client_uuid}/client-secret",
                namespace,
            )

            if response.status_code == 200:
                secret_data = response.json()
                new_secret = secret_data.get("value")
                if new_secret:
                    logger.info(
                        f"Successfully regenerated client secret for '{client_id}'"
                    )
                    return new_secret
                else:
                    logger.error(f"No secret returned for client '{client_id}'")
                    return None
            else:
                logger.error(
                    f"Failed to regenerate client secret for '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to regenerate client secret for '{client_id}': {e}")
            return None

    # Realm Management Methods

    async def delete_realm(self, realm_name: str, namespace: str) -> bool:
        """
        Delete a realm from Keycloak.

        Args:
            realm_name: Name of the realm to delete

        Returns:
            True if successful, False otherwise
        """
        if realm_name == "master":
            logger.error("Cannot delete the master realm")
            return False

        logger.info(f"Deleting realm '{realm_name}'")

        try:
            response = await self._make_request(
                "DELETE", f"realms/{realm_name}", namespace
            )

            if response.status_code == 204:
                logger.info(f"Successfully deleted realm '{realm_name}'")
                return True
            else:
                logger.error(
                    f"Failed to delete realm '{realm_name}': {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete realm '{realm_name}': {e}")
            return False

    async def get_realm_clients(
        self, realm_name: str, namespace: str
    ) -> list[ClientRepresentation]:
        """
        Get all clients in a realm.

        Args:
            realm_name: Name of the realm

        Returns:
            List of client configurations as ClientRepresentation

        Example:
            clients = admin_client.get_realm_clients("my-realm")
            for client in clients:
                print(f"Client: {client.client_id}, Enabled: {client.enabled}")
        """
        logger.info(f"Getting all clients in realm '{realm_name}'")

        try:
            response = await self._make_request("GET", f"realms/{realm_name}/clients")

            if response.status_code == 200:
                clients_data = response.json()
                logger.info(
                    f"Found {len(clients_data)} clients in realm '{realm_name}'"
                )
                # Validate each client with Pydantic
                return [
                    ClientRepresentation.model_validate(client)
                    for client in clients_data
                ]
            else:
                logger.error(
                    f"Failed to get clients for realm '{realm_name}': {response.status_code}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to get clients for realm '{realm_name}': {e}")
            return []

    async def update_realm_themes(
        self, realm_name: str, themes: dict[str, Any], namespace: str
    ) -> bool:
        """
        Update realm theme configuration.

        Args:
            realm_name: Name of the realm
            themes: Theme configuration

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Updating themes for realm '{realm_name}'")

        try:
            realm_config = {
                "loginTheme": themes.get("login"),
                "accountTheme": themes.get("account"),
                "adminTheme": themes.get("admin"),
                "emailTheme": themes.get("email"),
            }

            # Remove None values
            realm_config = {k: v for k, v in realm_config.items() if v is not None}

            response = await self._make_request(
                "PUT", f"realms/{realm_name}", json=realm_config
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated themes for realm '{realm_name}'")
                return True
            else:
                logger.error(f"Failed to update themes: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to update realm themes: {e}")
            return False

    async def configure_authentication_flow(
        self,
        realm_name: str,
        flow_config: AuthenticationFlowRepresentation | dict[str, Any],
    ) -> bool:
        """
        Configure authentication flow for a realm.

        Args:
            realm_name: Name of the realm
            flow_config: Authentication flow configuration as AuthenticationFlowRepresentation or dict

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import AuthenticationFlowRepresentation

            flow = AuthenticationFlowRepresentation(
                alias="browser-custom",
                description="Custom browser flow"
            )
            success = admin_client.configure_authentication_flow("my-realm", flow)
        """
        # Convert dict to model if needed
        if isinstance(flow_config, dict):
            flow_config = AuthenticationFlowRepresentation.model_validate(flow_config)

        flow_alias = flow_config.alias or "unknown"
        logger.info(
            f"Configuring authentication flow '{flow_alias}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/authentication/flows",
                request_model=flow_config,
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully configured authentication flow '{flow_alias}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to configure authentication flow: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to configure authentication flow: {e}")
            return False

    async def configure_identity_provider(
        self,
        realm_name: str,
        provider_config: IdentityProviderRepresentation | dict[str, Any],
    ) -> bool:
        """
        Configure identity provider for a realm.

        Args:
            realm_name: Name of the realm
            provider_config: Identity provider configuration as IdentityProviderRepresentation or dict

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import IdentityProviderRepresentation

            provider = IdentityProviderRepresentation(
                alias="google",
                provider_id="google",
                enabled=True
            )
            success = admin_client.configure_identity_provider("my-realm", provider)
        """
        # Convert dict to model if needed
        if isinstance(provider_config, dict):
            provider_config = IdentityProviderRepresentation.model_validate(
                provider_config
            )

        provider_alias = provider_config.alias or "unknown"
        logger.info(
            f"Configuring identity provider '{provider_alias}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/identity-provider/instances",
                request_model=provider_config,
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully configured identity provider '{provider_alias}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to configure identity provider: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to configure identity provider: {e}")
            return False

    async def configure_user_federation(
        self,
        realm_name: str,
        federation_config: ComponentRepresentation | dict[str, Any],
    ) -> bool:
        """
        Configure user federation for a realm.

        Args:
            realm_name: Name of the realm
            federation_config: User federation configuration as ComponentRepresentation or dict

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import ComponentRepresentation

            federation = ComponentRepresentation(
                name="ldap",
                provider_id="ldap"
            )
            success = admin_client.configure_user_federation("my-realm", federation)
        """
        # Convert dict to model if needed
        if isinstance(federation_config, dict):
            federation_config = ComponentRepresentation.model_validate(
                federation_config
            )

        federation_name = federation_config.name or "unknown"
        logger.info(
            f"Configuring user federation '{federation_name}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/components",
                request_model=federation_config,
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully configured user federation '{federation_name}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to configure user federation: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to configure user federation: {e}")
            return False

    async def backup_realm(
        self, realm_name: str, namespace: str
    ) -> dict[str, Any] | None:
        """
        Create a backup of realm configuration.

        Args:
            realm_name: Name of the realm to backup

        Returns:
            Realm backup data if successful, None otherwise
        """
        logger.info(f"Creating backup of realm '{realm_name}'")

        try:
            # Get realm configuration
            realm_config = await self.get_realm(realm_name)
            if not realm_config:
                logger.error("Failed to get realm configuration for backup")
                return None

            # Get clients
            clients = await self.get_realm_clients(realm_name)

            # Get authentication flows
            flows_response = await self._make_request(
                "GET", f"realms/{realm_name}/authentication/flows"
            )
            flows = flows_response.json() if flows_response.status_code == 200 else []

            # Get identity providers
            idp_response = await self._make_request(
                "GET", f"realms/{realm_name}/identity-provider/instances"
            )
            identity_providers = (
                idp_response.json() if idp_response.status_code == 200 else []
            )

            # Get user federation
            federation_response = await self._make_request(
                "GET",
                f"realms/{realm_name}/components?type=org.keycloak.storage.UserStorageProvider",
            )
            user_federation = (
                federation_response.json()
                if federation_response.status_code == 200
                else []
            )

            backup_data = {
                "realm": realm_config,
                "clients": clients,
                "authentication_flows": flows,
                "identity_providers": identity_providers,
                "user_federation": user_federation,
                "backup_timestamp": datetime.now(UTC).isoformat(),
                "backup_version": "1.0",
            }

            logger.info(f"Successfully created backup of realm '{realm_name}'")
            return backup_data

        except Exception as e:
            logger.error(f"Failed to backup realm '{realm_name}': {e}")
            return None

    # Protocol Mappers API methods
    async def get_client_protocol_mappers(
        self, client_uuid: str, realm_name: str = "master"
    ) -> list[ProtocolMapperRepresentation] | None:
        """
        Get all protocol mappers for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            realm_name: Name of the realm

        Returns:
            List of protocol mapper configurations as ProtocolMapperRepresentation or None on error

        Example:
            mappers = admin_client.get_client_protocol_mappers(client_uuid, "my-realm")
            for mapper in mappers:
                print(f"Mapper: {mapper.name}, Protocol: {mapper.protocol}")
        """
        logger.debug(
            f"Fetching protocol mappers for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models",
            )

            if response.status_code == 200:
                mappers_data = response.json()
                # Validate each mapper with Pydantic
                return [
                    ProtocolMapperRepresentation.model_validate(mapper)
                    for mapper in mappers_data
                ]
            elif response.status_code == 404:
                logger.warning(f"Client {client_uuid} not found in realm {realm_name}")
                return []
            else:
                logger.error(f"Failed to get protocol mappers: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to get client protocol mappers: {e}")
            return None

    async def create_client_protocol_mapper(
        self,
        client_uuid: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> ProtocolMapperRepresentation | None:
        """
        Create a protocol mapper for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_config: Protocol mapper configuration as ProtocolMapperRepresentation or dict
            realm_name: Name of the realm

        Returns:
            Created mapper configuration as ProtocolMapperRepresentation or None on error

        Example:
            from keycloak_operator.models.keycloak_api import ProtocolMapperRepresentation

            mapper = ProtocolMapperRepresentation(
                name="email",
                protocol="openid-connect",
                protocol_mapper="oidc-usermodel-property-mapper"
            )
            created = admin_client.create_client_protocol_mapper(
                client_uuid, mapper, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name or "unknown"
        logger.info(
            f"Creating protocol mapper '{mapper_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models",
                request_model=mapper_config,
            )

            if response.status_code == 201:
                logger.info(f"Successfully created protocol mapper '{mapper_name}'")
                return mapper_config
            else:
                logger.error(
                    f"Failed to create protocol mapper: {response.status_code}"
                )
                return None
        except Exception as e:
            logger.error(f"Failed to create protocol mapper: {e}")
            return None

    async def update_client_protocol_mapper(
        self,
        client_uuid: str,
        mapper_id: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Update a protocol mapper for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_id: ID of the protocol mapper
            mapper_config: Updated protocol mapper configuration as ProtocolMapperRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            mappers = admin_client.get_client_protocol_mappers(client_uuid, "my-realm")
            mapper = mappers[0]
            mapper.protocol = "saml"
            success = admin_client.update_client_protocol_mapper(
                client_uuid, mapper.id, mapper, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name or "unknown"
        logger.info(
            f"Updating protocol mapper '{mapper_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}",
                request_model=mapper_config,
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated protocol mapper '{mapper_name}'")
                return True
            else:
                logger.error(
                    f"Failed to update protocol mapper: {response.status_code}"
                )
                return False
        except Exception as e:
            logger.error(f"Failed to update protocol mapper: {e}")
            return False

    async def delete_client_protocol_mapper(
        self, client_uuid: str, mapper_id: str, realm_name: str = "master"
    ) -> bool:
        """
        Delete a protocol mapper from a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_id: ID of the protocol mapper
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise
        """
        await self._ensure_authenticated()
        endpoint = f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}"

        try:
            response = await self._make_request("DELETE", endpoint)
            if response.status_code == 204:
                logger.info(f"Successfully deleted protocol mapper {mapper_id}")
                return True
            else:
                logger.error(
                    f"Failed to delete protocol mapper: {response.status_code}"
                )
                return False
        except Exception as e:
            logger.error(f"Failed to delete protocol mapper: {e}")
            return False

    # Client Roles API methods
    async def get_client_roles(
        self, client_uuid: str, realm_name: str = "master"
    ) -> list[RoleRepresentation] | None:
        """
        Get all roles for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            realm_name: Name of the realm

        Returns:
            List of client role configurations as RoleRepresentation or None on error

        Example:
            roles = admin_client.get_client_roles(client_uuid, "my-realm")
            for role in roles:
                print(f"Role: {role.name}, ID: {role.id}")
        """
        logger.debug(f"Fetching roles for client {client_uuid} in realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET", f"realms/{realm_name}/clients/{client_uuid}/roles"
            )

            if response.status_code == 200:
                roles_data = response.json()
                # Validate each role with Pydantic
                return [RoleRepresentation.model_validate(role) for role in roles_data]
            elif response.status_code == 404:
                logger.warning(f"Client {client_uuid} not found in realm {realm_name}")
                return []
            else:
                logger.error(f"Failed to get client roles: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to get client roles: {e}")
            return None

    async def create_client_role(
        self,
        client_uuid: str,
        role_config: RoleRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Create a role for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_config: Role configuration as RoleRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import RoleRepresentation

            role = RoleRepresentation(
                name="admin",
                description="Administrator role"
            )
            success = admin_client.create_client_role(client_uuid, role, "my-realm")
        """
        # Convert dict to model if needed
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        role_name = role_config.name or "unknown"
        logger.info(
            f"Creating client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/clients/{client_uuid}/roles",
                request_model=role_config,
            )

            if response.status_code == 201:
                logger.info(f"Successfully created client role '{role_name}'")
                return True
            else:
                logger.error(f"Failed to create client role: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to create client role: {e}")
            return False

    async def update_client_role(
        self,
        client_uuid: str,
        role_name: str,
        role_config: RoleRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Update a role for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to update
            role_config: Updated role configuration as RoleRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            role = admin_client.get_client_role(client_uuid, "admin", "my-realm")
            role.description = "Updated description"
            success = admin_client.update_client_role(
                client_uuid, "admin", role, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        logger.info(
            f"Updating client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}",
                request_model=role_config,
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated client role '{role_name}'")
                return True
            else:
                logger.error(f"Failed to update client role: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to update client role: {e}")
            return False

    async def delete_client_role(
        self, client_uuid: str, role_name: str, realm_name: str = "master"
    ) -> bool:
        """
        Delete a role from a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to delete
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise
        """
        await self._ensure_authenticated()
        endpoint = f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}"

        try:
            response = await self._make_request("DELETE", endpoint)
            if response.status_code == 204:
                logger.info(f"Successfully deleted client role '{role_name}'")
                return True
            else:
                logger.error(f"Failed to delete client role: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to delete client role: {e}")
            return False


async def get_keycloak_admin_client(
    keycloak_name: str,
    namespace: str,
    rate_limiter: "RateLimiter | None" = None,
    verify_ssl: bool = False,
) -> KeycloakAdminClient:
    """
    Factory function to create KeycloakAdminClient for a specific instance.

    This function handles:
    - Looking up Keycloak instance details from Kubernetes
    - Retrieving admin credentials from secrets
    - Creating configured admin client with rate limiting

    Args:
        keycloak_name: Name of the Keycloak instance
        namespace: Namespace where the Keycloak instance exists
        rate_limiter: Optional rate limiter for API throttling
        verify_ssl: Whether to verify SSL certificates (default: False for development)

    Returns:
        Configured KeycloakAdminClient instance
    """
    from kubernetes import client as k8s_client

    from keycloak_operator.utils.kubernetes import get_kubernetes_client

    logger.info(f"Creating admin client for Keycloak {keycloak_name} in {namespace}")

    try:
        # Get Keycloak instance details
        k8s = get_kubernetes_client()
        custom_api = k8s_client.CustomObjectsApi(k8s)

        # Get Keycloak instance
        keycloak_instance = custom_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )

        # Get server URL from instance status
        server_url = (
            keycloak_instance.get("status", {}).get("endpoints", {}).get("admin")
        )
        if not server_url:
            raise KeycloakAdminError(
                f"Keycloak instance {keycloak_name} does not have admin endpoint ready"
            )

        # Get admin credentials from secret
        core_api = k8s_client.CoreV1Api(k8s)
        admin_secret_name = f"{keycloak_name}-admin-credentials"

        try:
            secret = core_api.read_namespaced_secret(
                name=admin_secret_name, namespace=namespace
            )

            # Decode credentials from secret
            import base64

            username = base64.b64decode(secret.data["username"]).decode("utf-8")
            password = base64.b64decode(secret.data["password"]).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to retrieve admin credentials: {e}")
            raise KeycloakAdminError(
                f"Could not retrieve admin credentials for {keycloak_name}"
            ) from e

        # Create and return admin client
        admin_client = KeycloakAdminClient(
            server_url=server_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            rate_limiter=rate_limiter,
        )

        # Test authentication
        await admin_client.authenticate()

        logger.info(f"Successfully created admin client for {keycloak_name}")
        return admin_client

    except Exception as e:
        logger.error(f"Failed to create admin client: {e}")
        raise KeycloakAdminError(f"Admin client creation failed: {e}") from e
