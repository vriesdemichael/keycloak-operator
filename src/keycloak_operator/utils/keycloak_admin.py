"""
Keycloak Admin API client utilities.

This module provides a high-level interface to the Keycloak Admin REST API
for managing Keycloak instances, realms, clients, and other resources.

The client handles:
- Authentication with Keycloak admin credentials
- Session management and token refresh
- Error handling and retry logic
- Type-safe API interactions
"""

import logging
from typing import Any
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class KeycloakAdminError(Exception):
    """Base exception for Keycloak Admin API errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class KeycloakAdminClient:
    """
    High-level client for Keycloak Admin API operations.

    This client provides methods for managing Keycloak resources including
    realms, clients, users, and configuration. It handles authentication,
    session management, and provides a clean interface for the operator.

    TODO: Implement the following functionality:
    1. Authentication and token management
    2. Realm management (create, update, delete, get)
    3. Client management (create, update, delete, get)
    4. User management operations
    5. Identity provider configuration
    6. Authentication flow management
    7. Error handling with proper retries
    8. Connection pooling and session management
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
        """
        self.server_url = server_url.rstrip("/")
        self.username = username
        self.password = password
        self.admin_realm = realm
        self.client_id = client_id
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # TODO: Set up requests session with proper configuration
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set session defaults
        self.session.verify = verify_ssl
        self.session.timeout = timeout

        # Authentication state
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expires_at: float | None = None

        logger.info(f"Initialized Keycloak Admin client for {server_url}")

    def authenticate(self) -> None:
        """
        Authenticate with Keycloak and obtain access tokens.

        TODO: Implement authentication flow:
        1. Send POST request to /realms/{realm}/protocol/openid-connect/token
        2. Include username, password, grant_type, client_id
        3. Parse response and store access_token, refresh_token
        4. Calculate token expiration time
        5. Set Authorization header for future requests
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
            # TODO: Make authentication request
            response = self.session.post(auth_url, data=auth_data)
            response.raise_for_status()

            token_data = response.json()

            # TODO: Store tokens and set session headers
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")

            # TODO: Calculate expiration time
            # expires_in is in seconds, convert to timestamp
            import time

            self.token_expires_at = time.time() + token_data.get("expires_in", 300)

            # Set authorization header for all future requests
            self.session.headers.update(
                {
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                }
            )

            logger.debug("Successfully authenticated with Keycloak")

        except requests.RequestException as e:
            logger.error(f"Failed to authenticate with Keycloak: {e}")
            raise KeycloakAdminError(f"Authentication failed: {e}") from e

    def _ensure_authenticated(self) -> None:
        """
        Ensure we have a valid access token, refreshing if necessary.

        TODO: Implement token validation and refresh:
        1. Check if access_token exists and is not expired
        2. If expired, try to refresh using refresh_token
        3. If refresh fails, re-authenticate
        4. Update session headers with new token
        """
        import time

        # If no token or token is expired
        if not self.access_token or (
            self.token_expires_at and time.time() >= self.token_expires_at - 30
        ):
            if self.refresh_token:
                try:
                    # TODO: Implement token refresh
                    self._refresh_token()
                except KeycloakAdminError:
                    # Refresh failed, re-authenticate
                    self.authenticate()
            else:
                # No refresh token, re-authenticate
                self.authenticate()

    def _refresh_token(self) -> None:
        """
        Refresh the access token using the refresh token.

        TODO: Implement token refresh:
        1. Send POST request to token endpoint with refresh_token
        2. Update stored tokens and expiration
        3. Update session headers
        """
        if not self.refresh_token:
            raise KeycloakAdminError("No refresh token available")

        # TODO: Implement refresh logic
        pass

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> requests.Response:
        """
        Make an authenticated request to the Keycloak Admin API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to admin base)
            data: Request body data
            params: Query parameters

        Returns:
            Response object

        TODO: Implement request handling:
        1. Ensure authentication
        2. Build full URL
        3. Make request with proper error handling
        4. Handle common errors (401, 403, 404, etc.)
        5. Return response or raise appropriate exceptions
        """
        self._ensure_authenticated()

        url = urljoin(f"{self.server_url}/admin/", endpoint.lstrip("/"))

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data if data else None,
                params=params,
            )

            # Handle common HTTP errors
            if response.status_code == 401:
                # Token might be expired, try re-authenticating once
                logger.warning("Received 401, attempting re-authentication")
                self.authenticate()
                # Retry the request
                response = self.session.request(
                    method=method,
                    url=url,
                    json=data if data else None,
                    params=params,
                )

            response.raise_for_status()
            return response

        except requests.RequestException as e:
            logger.error(f"Request failed: {method} {url} - {e}")
            raise KeycloakAdminError(f"API request failed: {e}") from e

    # Realm Management Methods

    def create_realm(self, realm_config: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new realm in Keycloak.

        Args:
            realm_config: Realm configuration dictionary

        Returns:
            Created realm information

        TODO: Implement realm creation:
        1. Validate realm configuration
        2. Send POST request to /realms
        3. Handle conflicts (realm already exists)
        4. Return created realm details
        """
        logger.info(f"Creating realm: {realm_config.get('realm', 'unknown')}")

        # TODO: Implement realm creation
        response = self._make_request("POST", "realms", data=realm_config)

        if response.status_code == 201:
            logger.info("Realm created successfully")
            # TODO: Return realm details (may need separate GET request)
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to create realm: {response.status_code}",
                response.status_code,
            )

    def get_realm(self, realm_name: str) -> dict[str, Any] | None:
        """
        Get realm configuration from Keycloak.

        Args:
            realm_name: Name of the realm to retrieve

        Returns:
            Realm configuration or None if not found

        TODO: Implement realm retrieval:
        1. Send GET request to /realms/{realm_name}
        2. Handle 404 errors (realm not found)
        3. Return realm configuration
        """
        try:
            response = self._make_request("GET", f"realms/{realm_name}")
            return response.json()
        except KeycloakAdminError as e:
            if e.status_code == 404:
                return None
            raise

    def update_realm(
        self, realm_name: str, realm_config: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Update realm configuration.

        Args:
            realm_name: Name of the realm to update
            realm_config: Updated realm configuration

        Returns:
            Updated realm configuration

        TODO: Implement realm update:
        1. Send PUT request to /realms/{realm_name}
        2. Handle errors appropriately
        3. Return updated configuration
        """
        logger.info(f"Updating realm: {realm_name}")

        # TODO: Implement realm update
        response = self._make_request("PUT", f"realms/{realm_name}", data=realm_config)

        if response.status_code == 204:  # No content on successful update
            # Return the updated config (may need separate GET)
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to update realm: {response.status_code}",
                response.status_code,
            )

    def delete_realm(self, realm_name: str) -> None:
        """
        Delete a realm from Keycloak.

        Args:
            realm_name: Name of the realm to delete

        TODO: Implement realm deletion:
        1. Send DELETE request to /realms/{realm_name}
        2. Handle errors appropriately
        3. Log successful deletion
        """
        logger.info(f"Deleting realm: {realm_name}")

        response = self._make_request("DELETE", f"realms/{realm_name}")

        if response.status_code == 204:
            logger.info(f"Successfully deleted realm: {realm_name}")
        else:
            raise KeycloakAdminError(
                f"Failed to delete realm: {response.status_code}",
                response.status_code,
            )

    # Client Management Methods

    def create_client(
        self, client_config: dict[str, Any], realm_name: str = "master"
    ) -> dict[str, Any]:
        """
        Create a new client in the specified realm.

        Args:
            client_config: Client configuration dictionary
            realm_name: Target realm name

        Returns:
            Created client information including client ID and secret

        TODO: Implement client creation:
        1. Send POST request to /realms/{realm}/clients
        2. Handle client ID conflicts
        3. Generate and return client secret for confidential clients
        4. Return complete client information
        """
        logger.info(
            f"Creating client {client_config.get('clientId')} in realm {realm_name}"
        )

        # TODO: Implement client creation
        response = self._make_request(
            "POST", f"realms/{realm_name}/clients", data=client_config
        )

        if response.status_code == 201:
            # TODO: Get the created client details and secret
            client_id = client_config.get("clientId")
            created_client = self.get_client_by_name(client_id, realm_name)
            return created_client
        else:
            raise KeycloakAdminError(
                f"Failed to create client: {response.status_code}",
                response.status_code,
            )

    def get_client_by_name(
        self, client_id: str, realm_name: str = "master"
    ) -> dict[str, Any] | None:
        """
        Get client by client ID (name).

        Args:
            client_id: Client ID to search for
            realm_name: Realm to search in

        Returns:
            Client configuration or None if not found

        TODO: Implement client retrieval:
        1. Send GET request to /realms/{realm}/clients
        2. Filter results by clientId
        3. Return first match or None
        """
        try:
            response = self._make_request(
                "GET", f"realms/{realm_name}/clients", params={"clientId": client_id}
            )
            clients = response.json()

            # TODO: Find client with matching clientId
            for client in clients:
                if client.get("clientId") == client_id:
                    return client

            return None

        except KeycloakAdminError as e:
            logger.error(f"Failed to get client {client_id}: {e}")
            return None

    def update_client(
        self,
        client_uuid: str,
        client_config: dict[str, Any],
        realm_name: str = "master",
    ) -> dict[str, Any]:
        """
        Update client configuration.

        Args:
            client_uuid: Internal client UUID (not clientId)
            client_config: Updated client configuration
            realm_name: Target realm name

        Returns:
            Updated client configuration

        TODO: Implement client update:
        1. Send PUT request to /realms/{realm}/clients/{uuid}
        2. Handle errors appropriately
        3. Return updated configuration
        """
        logger.info(f"Updating client {client_uuid} in realm {realm_name}")

        # TODO: Implement client update
        response = self._make_request(
            "PUT", f"realms/{realm_name}/clients/{client_uuid}", data=client_config
        )

        if response.status_code == 204:
            return client_config
        else:
            raise KeycloakAdminError(
                f"Failed to update client: {response.status_code}",
                response.status_code,
            )

    def delete_client(self, client_id: str, realm_name: str = "master") -> None:
        """
        Delete a client from the specified realm.

        Args:
            client_id: Client ID to delete
            realm_name: Target realm name

        TODO: Implement client deletion:
        1. Find client UUID by client ID
        2. Send DELETE request to /realms/{realm}/clients/{uuid}
        3. Handle errors appropriately
        """
        logger.info(f"Deleting client {client_id} from realm {realm_name}")

        # TODO: Find client first
        client = self.get_client_by_name(client_id, realm_name)
        if not client:
            logger.warning(f"Client {client_id} not found, nothing to delete")
            return

        client_uuid = client["id"]
        response = self._make_request(
            "DELETE", f"realms/{realm_name}/clients/{client_uuid}"
        )

        if response.status_code == 204:
            logger.info(f"Successfully deleted client: {client_id}")
        else:
            raise KeycloakAdminError(
                f"Failed to delete client: {response.status_code}",
                response.status_code,
            )

    def get_client_secret(
        self, client_id: str, realm_name: str = "master"
    ) -> str | None:
        """
        Get the secret for a confidential client.

        Args:
            client_id: Client ID
            realm_name: Target realm name

        Returns:
            Client secret or None if public client

        TODO: Implement client secret retrieval:
        1. Find client UUID by client ID
        2. Send GET request to /realms/{realm}/clients/{uuid}/client-secret
        3. Return secret value
        """
        client = self.get_client_by_name(client_id, realm_name)
        if not client:
            return None

        if client.get("publicClient", True):
            return None  # Public clients don't have secrets

        client_uuid = client["id"]

        try:
            response = self._make_request(
                "GET", f"realms/{realm_name}/clients/{client_uuid}/client-secret"
            )
            secret_data = response.json()
            return secret_data.get("value")

        except KeycloakAdminError:
            return None

    def regenerate_client_secret(
        self, client_id: str, realm_name: str = "master"
    ) -> str:
        """
        Regenerate the secret for a confidential client.

        Args:
            client_id: Client ID
            realm_name: Target realm name

        Returns:
            New client secret

        TODO: Implement client secret regeneration:
        1. Find client UUID by client ID
        2. Send POST request to /realms/{realm}/clients/{uuid}/client-secret
        3. Return new secret value
        """
        client = self.get_client_by_name(client_id, realm_name)
        if not client:
            raise KeycloakAdminError(f"Client {client_id} not found")

        client_uuid = client["id"]

        response = self._make_request(
            "POST", f"realms/{realm_name}/clients/{client_uuid}/client-secret"
        )

        secret_data = response.json()
        return secret_data.get("value")

    # Additional utility methods

    def health_check(self) -> bool:
        """
        Perform a health check on the Keycloak instance.

        Returns:
            True if Keycloak is healthy and accessible

        TODO: Implement health check:
        1. Try to access a simple endpoint
        2. Verify authentication works
        3. Return boolean status
        """
        try:
            # Try to get the master realm as a health check
            self.get_realm("master")
            return True
        except Exception as e:
            logger.error(f"Keycloak health check failed: {e}")
            return False


def get_keycloak_admin_client(
    keycloak_name: str, namespace: str
) -> KeycloakAdminClient:
    """
    Factory function to create KeycloakAdminClient for a specific instance.

    This function handles:
    - Looking up Keycloak instance details from Kubernetes
    - Retrieving admin credentials from secrets
    - Creating configured admin client

    Args:
        keycloak_name: Name of the Keycloak instance
        namespace: Namespace where the Keycloak instance exists

    Returns:
        Configured KeycloakAdminClient instance

    TODO: Implement the following functionality:
    1. Look up Keycloak instance in Kubernetes
    2. Get server URL from instance status
    3. Retrieve admin credentials from associated secret
    4. Create and return configured admin client
    5. Handle errors appropriately
    """
    from kubernetes import client as k8s_client

    from keycloak_operator.utils.kubernetes import get_kubernetes_client

    logger.info(f"Creating admin client for Keycloak {keycloak_name} in {namespace}")

    try:
        # TODO: Get Keycloak instance details
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

        # TODO: Get server URL from instance status
        server_url = (
            keycloak_instance.get("status", {}).get("endpoints", {}).get("admin")
        )
        if not server_url:
            raise KeycloakAdminError(
                f"Keycloak instance {keycloak_name} does not have admin endpoint ready"
            )

        # TODO: Get admin credentials from secret
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
            verify_ssl=False,  # TODO: Make this configurable
        )

        # Test authentication
        admin_client.authenticate()

        logger.info(f"Successfully created admin client for {keycloak_name}")
        return admin_client

    except Exception as e:
        logger.error(f"Failed to create admin client: {e}")
        raise KeycloakAdminError(f"Admin client creation failed: {e}") from e
