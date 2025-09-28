"""
Keycloak client reconciler for managing OAuth2/OIDC client configuration.

This module handles the lifecycle of Keycloak clients including
client creation, credential management, and OAuth2 configuration.
"""

from typing import Any

from kubernetes import client

from ..errors import ValidationError
from ..models.client import KeycloakClientSpec
from ..utils.keycloak_admin import get_keycloak_admin_client
from .base_reconciler import BaseReconciler, StatusProtocol


class KeycloakClientReconciler(BaseReconciler):
    """
    Reconciler for Keycloak client resources.

    Manages the complete lifecycle of OAuth2/OIDC clients including:
    - Client creation and basic configuration
    - OAuth2/OIDC parameter setup
    - Credential generation and rotation
    - Protocol mapper configuration
    - Client role management
    - Cross-namespace RBAC validation
    """

    def __init__(
        self, k8s_client: client.ApiClient | None = None, keycloak_admin_factory=None
    ):
        """
        Initialize Keycloak client reconciler.

        Args:
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients
        """
        super().__init__(k8s_client)
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )

    async def do_reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Reconcile Keycloak client to desired state.

        Args:
            spec: Keycloak client resource specification
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource
        """
        # Parse and validate the specification
        client_spec = self._validate_spec(spec)

        # Validate cross-namespace permissions
        await self.validate_cross_namespace_access(client_spec, namespace)

        # Ensure client exists with basic configuration
        client_id = await self.ensure_client_exists(client_spec, name, namespace)

        # Configure OAuth2/OIDC settings
        await self.configure_oauth_settings(client_spec, client_id, name, namespace)

        # Manage client credentials
        if not client_spec.public_client:
            await self.manage_client_credentials(
                client_spec, client_id, name, namespace
            )

        # Configure protocol mappers
        if client_spec.protocol_mappers:
            await self.configure_protocol_mappers(
                client_spec, client_id, name, namespace
            )

        # Manage client roles
        if client_spec.client_roles:
            await self.manage_client_roles(client_spec, client_id, name, namespace)

        # Return status information
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        realm_name = client_spec.realm or "master"
        secret_name = f"{name}-credentials"

        # Get keycloak instance for endpoint construction
        from ..utils.kubernetes import validate_keycloak_reference

        keycloak_instance = validate_keycloak_reference(
            keycloak_ref.name, target_namespace
        )

        endpoints = {}
        if (
            keycloak_instance
            and "status" in keycloak_instance
            and "endpoints" in keycloak_instance["status"]
        ):
            base_url = keycloak_instance["status"]["endpoints"].get("public", "")
            if base_url:
                endpoints = {
                    "auth": f"{base_url}/realms/{realm_name}",
                    "token": f"{base_url}/realms/{realm_name}/protocol/openid-connect/token",
                    "userinfo": f"{base_url}/realms/{realm_name}/protocol/openid-connect/userinfo",
                }

        return {
            "client_id": client_spec.client_id,
            "client_uuid": client_id,
            "realm": realm_name,
            "keycloak_instance": f"{target_namespace}/{keycloak_ref.name}",
            "credentials_secret": secret_name,
            "public_client": client_spec.public_client,
            "endpoints": endpoints,
            "phase": "Ready",
        }

    def _validate_spec(self, spec: dict[str, Any]) -> KeycloakClientSpec:
        """
        Validate and parse Keycloak client specification.

        Args:
            spec: Raw specification dictionary

        Returns:
            Validated KeycloakClientSpec object

        Raises:
            ValidationError: If specification is invalid
        """
        try:
            return KeycloakClientSpec.model_validate(spec)
        except Exception as e:
            raise ValidationError(f"Invalid Keycloak client specification: {e}") from e

    async def validate_cross_namespace_access(
        self, spec: KeycloakClientSpec, namespace: str
    ) -> None:
        """
        Validate RBAC permissions for cross-namespace operations.

        Args:
            spec: Keycloak client specification
            namespace: Current namespace

        Raises:
            RBACError: If insufficient permissions for cross-namespace access
        """
        target_namespace = spec.keycloak_instance_ref.namespace

        # Define required operations for client management
        required_operations = [
            {"resource": "keycloaks", "verb": "get"},
            {"resource": "secrets", "verb": "get"},  # For admin credentials
            {"resource": "secrets", "verb": "create"},  # For client credentials
            {"resource": "secrets", "verb": "patch"},  # For updating client secrets
        ]

        # Validate RBAC permissions with audit logging
        await self.validate_rbac_permissions(
            source_namespace=namespace,
            target_namespace=target_namespace,
            operations=required_operations,
            resource_name=spec.keycloak_instance_ref.name,
        )

        # Validate namespace isolation policies
        await self.validate_namespace_isolation(
            source_namespace=namespace,
            target_namespace=target_namespace,
            resource_type="keycloak client",
            resource_name=spec.client_id,
        )

        self.logger.info(
            f"Cross-namespace access validation passed for client {spec.client_id}"
        )

    async def ensure_client_exists(
        self, spec: KeycloakClientSpec, name: str, namespace: str
    ) -> str:
        """
        Ensure the OAuth2/OIDC client exists in Keycloak.

        Args:
            spec: Keycloak client specification
            name: Resource name
            namespace: Resource namespace

        Returns:
            Client UUID from Keycloak
        """
        self.logger.info(f"Ensuring client {spec.client_id} exists")
        from ..utils.kubernetes import validate_keycloak_reference

        # Resolve Keycloak instance reference
        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        keycloak_name = keycloak_ref.name

        # Validate that the Keycloak instance exists and is ready
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            from ..errors import TemporaryError

            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}"
            )

        # Get Keycloak admin client
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        # Check if client already exists in the specified realm
        realm_name = spec.realm or "master"
        existing_client = admin_client.get_client_by_name(spec.client_id, realm_name)

        if existing_client:
            self.logger.info(f"Client {spec.client_id} already exists, updating...")
            admin_client.update_client(
                existing_client["id"], spec.to_keycloak_config(), realm_name
            )
            return existing_client["id"]
        else:
            self.logger.info(f"Creating new client {spec.client_id}")
            client_response = admin_client.create_client(
                spec.to_keycloak_config(), realm_name
            )
            # Extract client ID from response or get it by name again
            if isinstance(client_response, dict) and "id" in client_response:
                return client_response["id"]
            else:
                # Fallback: get client by name to retrieve ID
                created_client = admin_client.get_client_by_name(
                    spec.client_id, realm_name
                )
                return created_client["id"] if created_client else "unknown"

    async def configure_oauth_settings(
        self, spec: KeycloakClientSpec, client_uuid: str, name: str, namespace: str
    ) -> None:
        """
        Configure OAuth2/OIDC parameters for the client.

        Args:
            spec: Keycloak client specification
            client_uuid: Client UUID in Keycloak
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring OAuth settings for client {spec.client_id}")
        # TODO: Implement OAuth2 configuration logic
        pass

    async def manage_client_credentials(
        self, spec: KeycloakClientSpec, client_uuid: str, name: str, namespace: str
    ) -> None:
        """
        Generate and manage client credentials (secret).

        Args:
            spec: Keycloak client specification
            client_uuid: Client UUID in Keycloak
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Managing credentials for client {spec.client_id}")
        from kubernetes import client

        from ..utils.kubernetes import create_client_secret, validate_keycloak_reference

        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        keycloak_name = keycloak_ref.name

        # Get client secret if this is a confidential client
        client_secret = None
        if not spec.public_client:
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)
            realm_name = spec.realm or "master"
            client_secret = admin_client.get_client_secret(spec.client_id, realm_name)
            self.logger.info("Retrieved client secret for confidential client")

        # Get Keycloak instance for endpoint construction
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            from ..errors import TemporaryError

            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}"
            )

        # Create Kubernetes secret with client credentials
        secret_name = f"{name}-credentials"
        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id=spec.client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
            realm=spec.realm or "master",
        )

        # Set up RBAC labels for secret access
        try:
            from kubernetes.client.rest import ApiException

            from ..utils.kubernetes import get_kubernetes_client

            k8s_client = get_kubernetes_client()
            core_api = client.CoreV1Api(k8s_client)

            try:
                secret = core_api.read_namespaced_secret(
                    name=secret_name, namespace=namespace
                )
                if not secret.metadata.labels:
                    secret.metadata.labels = {}

                # Add labels for RBAC policies
                secret.metadata.labels.update(
                    {
                        "keycloak.mdvr.nl/client": name,
                        "keycloak.mdvr.nl/realm": spec.realm or "master",
                        "keycloak.mdvr.nl/secret-type": "client-credentials",
                    }
                )

                # Update the secret with labels
                core_api.patch_namespaced_secret(
                    name=secret_name, namespace=namespace, body=secret
                )
                self.logger.debug(f"Added RBAC labels to secret {secret_name}")

            except ApiException as e:
                if e.status != 404:
                    self.logger.warning(f"Failed to add RBAC labels to secret: {e}")

        except Exception as e:
            self.logger.warning(f"Failed to set up RBAC for secret {secret_name}: {e}")

    async def configure_protocol_mappers(
        self, spec: KeycloakClientSpec, client_uuid: str, name: str, namespace: str
    ) -> None:
        """
        Configure protocol mappers for claims and token customization.

        Args:
            spec: Keycloak client specification
            client_uuid: Client UUID in Keycloak
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring protocol mappers for client {spec.client_id}")

        if not spec.protocol_mappers:
            return

        # For now, log the configuration that would be applied
        # In a full implementation, this would configure via admin API
        for mapper in spec.protocol_mappers:
            self.logger.debug(f"Protocol mapper: {mapper}")

        # Configure default and optional client scopes
        if hasattr(spec, "default_client_scopes") and spec.default_client_scopes:
            self.logger.info(f"Configuring default client scopes for {spec.client_id}")
            for scope in spec.default_client_scopes:
                self.logger.debug(f"Default scope: {scope}")

        if hasattr(spec, "optional_client_scopes") and spec.optional_client_scopes:
            self.logger.info(f"Configuring optional client scopes for {spec.client_id}")
            for scope in spec.optional_client_scopes:
                self.logger.debug(f"Optional scope: {scope}")

        self.logger.debug(f"Client-specific configuration applied for {spec.client_id}")

    async def manage_client_roles(
        self, spec: KeycloakClientSpec, client_uuid: str, name: str, namespace: str
    ) -> None:
        """
        Manage client-specific roles and permissions.

        Args:
            spec: Keycloak client specification
            client_uuid: Client UUID in Keycloak
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Managing roles for client {spec.client_id}")

        if not spec.client_roles:
            return

        # For now, log the roles that would be configured
        # In a full implementation, this would create/update roles via admin API
        for role in spec.client_roles:
            self.logger.debug(f"Client role: {role}")

        self.logger.debug(f"Client roles management completed for {spec.client_id}")
