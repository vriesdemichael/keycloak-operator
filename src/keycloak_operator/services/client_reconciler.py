"""
Keycloak client reconciler for managing OAuth2/OIDC client configuration.

This module handles the lifecycle of Keycloak clients including
client creation, credential management, and OAuth2 configuration.
"""

from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import KeycloakAdminError, ReconciliationError, ValidationError
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
        client_uuid = await self.ensure_client_exists(client_spec, name, namespace)

        # Configure OAuth2/OIDC settings
        await self.configure_oauth_settings(client_spec, client_uuid, name, namespace)

        # Manage client credentials
        if not client_spec.public_client:
            await self.manage_client_credentials(
                client_spec, client_uuid, name, namespace
            )

        # Configure protocol mappers
        if client_spec.protocol_mappers:
            await self.configure_protocol_mappers(
                client_spec, client_uuid, name, namespace
            )

        # Manage client roles
        if client_spec.client_roles:
            await self.manage_client_roles(client_spec, client_uuid, name, namespace)

        # Manage service account roles
        if client_spec.settings.service_accounts_enabled:
            await self.manage_service_account_roles(
                client_spec, client_uuid, name, namespace
            )

        # Return status information
        realm_ref = client_spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        secret_name = f"{name}-credentials"

        # Get keycloak instance for endpoint construction
        from ..utils.kubernetes import validate_keycloak_reference

        keycloak_name = "keycloak"  # Default Keycloak instance name
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)

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

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        # Update status to ready
        self.update_status_ready(status, "Client configured and ready", generation)

        # Set additional status fields via StatusWrapper to avoid conflicts with Kopf
        status.client_id = client_spec.client_id
        status.client_uuid = client_uuid
        status.realm = realm_name
        status.keycloak_instance = f"{target_namespace}/{keycloak_name}"
        status.credentials_secret = secret_name
        status.public_client = client_spec.public_client
        status.endpoints = endpoints

        # Return empty dict - status updates are done via StatusWrapper
        return {}

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
        target_namespace = spec.realm_ref.namespace

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
            resource_name=spec.realm_ref.name,
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
        from ..utils.auth import validate_authorization
        from ..utils.kubernetes import validate_keycloak_reference

        # Resolve realm reference
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # Validate authorization: Check realm token
        # First, we need to get the realm resource to find its authorization secret
        from kubernetes.client.rest import ApiException

        try:
            custom_api = client.CustomObjectsApi()
            realm_resource = custom_api.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=target_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Get the realm's authorization secret name from its status
            realm_auth_secret_name = realm_resource.get("status", {}).get(
                "authorizationSecretName"
            )
            if not realm_auth_secret_name:
                from ..errors import TemporaryError

                raise TemporaryError(
                    f"Realm {realm_name} does not have an authorization secret yet. "
                    f"Waiting for realm to complete initialization.",
                    delay=30,
                )

            # Read the expected token from the realm's secret
            core_v1 = client.CoreV1Api()
            try:
                realm_secret = core_v1.read_namespaced_secret(
                    name=realm_auth_secret_name, namespace=target_namespace
                )
                import base64

                realm_token_encoded = realm_secret.data.get("token", "")
                realm_token = base64.b64decode(realm_token_encoded).decode("utf-8")
            except ApiException as secret_err:
                from ..errors import TemporaryError

                if secret_err.status == 404:
                    raise TemporaryError(
                        f"Realm authorization secret {realm_auth_secret_name} not found. "
                        f"Waiting for realm to create the secret.",
                        delay=30,
                    ) from secret_err
                raise

            # Validate the provided token matches the realm's token
            if not validate_authorization(
                secret_ref=realm_ref.authorization_secret_ref,
                secret_namespace=namespace,  # Client's namespace (where the secret should be)
                expected_token=realm_token,
                k8s_client=core_v1,
            ):
                from ..errors import PermanentError

                raise PermanentError(
                    f"Authorization failed: Invalid or missing realm token for client {spec.client_id}"
                )

            self.logger.info(f"Authorization validated for client {spec.client_id}")

        except ApiException as e:
            if e.status == 404:
                from ..errors import TemporaryError

                raise TemporaryError(
                    f"Referenced realm {realm_name} not found in namespace {target_namespace}. "
                    f"Ensure the realm exists before creating clients.",
                    delay=30,
                ) from e
            raise

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
        existing_client = admin_client.get_client_by_name(spec.client_id, realm_name)

        if existing_client:
            self.logger.info(f"Client {spec.client_id} already exists, updating...")
            admin_client.update_client(
                existing_client.id, spec.to_keycloak_config(), realm_name
            )
            return existing_client.id
        else:
            self.logger.info(f"Creating new client {spec.client_id}")
            client_response = admin_client.create_client(
                spec.to_keycloak_config(), realm_name
            )
            # Extract client UUID from response or get it by name again
            if client_response:
                # create_client returns UUID string directly
                return client_response
            else:
                # Fallback: get client by name to retrieve UUID
                created_client = admin_client.get_client_by_name(
                    spec.client_id, realm_name
                )
                return created_client.id if created_client else "unknown"

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

        # Get Keycloak admin client
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        try:
            # Build OAuth2/OIDC client configuration
            client_config = {
                "id": client_uuid,
                "clientId": spec.client_id,
                "name": spec.client_name or spec.client_id,
                "description": spec.description or "",
                "enabled": spec.settings.enabled,
                "publicClient": spec.public_client,
                "bearerOnly": spec.bearer_only or False,
                "protocol": spec.protocol or "openid-connect",
                # OAuth2/OIDC flow settings
                "standardFlowEnabled": getattr(spec, "standard_flow_enabled", True),
                "implicitFlowEnabled": getattr(spec, "implicit_flow_enabled", False),
                "directAccessGrantsEnabled": getattr(
                    spec, "direct_access_grants_enabled", True
                ),
                "serviceAccountsEnabled": getattr(
                    spec, "service_accounts_enabled", not spec.public_client
                ),
                # URI configurations
                "redirectUris": spec.redirect_uris or [],
                "webOrigins": getattr(spec, "web_origins", []),
                "adminUrl": getattr(spec, "admin_url", ""),
                "baseUrl": getattr(spec, "base_url", ""),
                "rootUrl": getattr(spec, "root_url", ""),
                # Additional OAuth2 settings
                "consentRequired": getattr(spec, "consent_required", False),
                "displayOnConsentScreen": getattr(
                    spec, "display_on_consent_screen", True
                ),
                "frontchannelLogout": getattr(spec, "frontchannel_logout", False),
                "fullScopeAllowed": getattr(spec, "full_scope_allowed", True),
                "nodeReRegistrationTimeout": getattr(
                    spec, "node_re_registration_timeout", -1
                ),
                "notBefore": getattr(spec, "not_before", 0),
                "surrogateAuthRequired": getattr(
                    spec, "surrogate_auth_required", False
                ),
                # Client authentication method for confidential clients
                "clientAuthenticatorType": getattr(
                    spec, "client_authenticator_type", "client-secret"
                )
                if not spec.public_client
                else None,
            }

            # Remove None values to avoid sending unnecessary data
            client_config = {k: v for k, v in client_config.items() if v is not None}

            # Update the client with OAuth2 settings
            success = admin_client.update_client(client_uuid, client_config, realm_name)
            if success:
                self.logger.info(
                    f"Successfully configured OAuth settings for client {spec.client_id}"
                )
            else:
                self.logger.error(
                    f"Failed to configure OAuth settings for client {spec.client_id}"
                )

        except Exception as e:
            self.logger.error(f"Error configuring OAuth settings: {e}")
            raise

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

        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # Get client secret if this is a confidential client
        client_secret = None
        if not spec.public_client:
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)
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
            realm=realm_name,
            update_existing=True,  # Update if exists (idempotent)
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
                        "keycloak.mdvr.nl/realm": realm_name,
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
            self.logger.debug("No protocol mappers specified, skipping configuration")
            return

        # Get Keycloak admin client
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        try:
            # Get existing protocol mappers from Keycloak
            existing_mappers = admin_client.get_client_protocol_mappers(
                client_uuid, realm_name
            )
            if existing_mappers is None:
                self.logger.error(
                    f"Failed to retrieve existing protocol mappers for client {spec.client_id}"
                )
                return

            # Create a map of existing mappers by name for easy lookup
            existing_mappers_by_name = {
                mapper["name"]: mapper for mapper in existing_mappers
            }

            # Process each protocol mapper from the spec
            for mapper_spec in spec.protocol_mappers:
                mapper_name = mapper_spec.name
                if not mapper_name:
                    self.logger.warning("Protocol mapper missing name, skipping")
                    continue

                existing_mapper = existing_mappers_by_name.get(mapper_name)
                mapper_dict = mapper_spec.model_dump()

                if existing_mapper:
                    # Check if update is needed (compare configs excluding ID)
                    needs_update = self._protocol_mapper_needs_update(
                        existing_mapper, mapper_dict
                    )
                    if needs_update:
                        self.logger.info(f"Updating protocol mapper '{mapper_name}'")
                        success = admin_client.update_client_protocol_mapper(
                            client_uuid, existing_mapper["id"], mapper_dict, realm_name
                        )
                        if not success:
                            self.logger.error(
                                f"Failed to update protocol mapper '{mapper_name}'"
                            )
                    else:
                        self.logger.debug(
                            f"Protocol mapper '{mapper_name}' is up to date"
                        )
                else:
                    # Create new protocol mapper
                    self.logger.info(f"Creating protocol mapper '{mapper_name}'")
                    created_mapper = admin_client.create_client_protocol_mapper(
                        client_uuid, mapper_dict, realm_name
                    )
                    if not created_mapper:
                        self.logger.error(
                            f"Failed to create protocol mapper '{mapper_name}'"
                        )

            # Remove protocol mappers that are no longer specified
            desired_mapper_names = {
                mapper.name for mapper in spec.protocol_mappers if mapper.name
            }
            for existing_mapper in existing_mappers:
                if existing_mapper["name"] not in desired_mapper_names:
                    self.logger.info(
                        f"Removing obsolete protocol mapper '{existing_mapper['name']}'"
                    )
                    success = admin_client.delete_client_protocol_mapper(
                        client_uuid, existing_mapper["id"], realm_name
                    )
                    if not success:
                        self.logger.error(
                            f"Failed to delete protocol mapper '{existing_mapper['name']}'"
                        )

        except Exception as e:
            self.logger.error(f"Error configuring protocol mappers: {e}")
            raise

        self.logger.info(
            f"Protocol mappers configuration completed for {spec.client_id}"
        )

    def _protocol_mapper_needs_update(
        self, existing: dict[str, Any], desired: dict[str, Any]
    ) -> bool:
        """
        Check if a protocol mapper needs to be updated.

        Args:
            existing: Existing protocol mapper from Keycloak
            desired: Desired protocol mapper configuration

        Returns:
            True if update is needed, False otherwise
        """
        # Compare key fields (excluding ID and other Keycloak-generated fields)
        compare_fields = ["name", "protocol", "protocolMapper", "config"]

        for field in compare_fields:
            if existing.get(field) != desired.get(field):
                return True

        return False

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
            self.logger.debug("No client roles specified, skipping role management")
            return

        # Get Keycloak admin client
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        try:
            # Get existing client roles from Keycloak
            existing_roles = admin_client.get_client_roles(client_uuid, realm_name)
            if existing_roles is None:
                self.logger.error(
                    f"Failed to retrieve existing client roles for client {spec.client_id}"
                )
                return

            # Create a map of existing roles by name for easy lookup
            existing_roles_by_name = {role["name"]: role for role in existing_roles}

            # Process each client role from the spec
            for role_name in spec.client_roles:
                if not role_name:
                    self.logger.warning("Client role missing name, skipping")
                    continue

                existing_role = existing_roles_by_name.get(role_name)

                if not existing_role:
                    # Create new client role
                    self.logger.info(f"Creating client role '{role_name}'")
                    role_config = {"name": role_name}
                    success = admin_client.create_client_role(
                        client_uuid, role_config, realm_name
                    )
                    if not success:
                        self.logger.error(f"Failed to create client role '{role_name}'")
                else:
                    self.logger.debug(f"Client role '{role_name}' already exists")

            # Remove client roles that are no longer specified
            desired_role_names = set(spec.client_roles)
            for existing_role in existing_roles:
                if existing_role["name"] not in desired_role_names:
                    self.logger.info(
                        f"Removing obsolete client role '{existing_role['name']}'"
                    )
                    success = admin_client.delete_client_role(
                        client_uuid, existing_role["name"], realm_name
                    )
                    if not success:
                        self.logger.error(
                            f"Failed to delete client role '{existing_role['name']}'"
                        )

        except Exception as e:
            self.logger.error(f"Error managing client roles: {e}")
            raise

        self.logger.info(f"Client roles management completed for {spec.client_id}")

    def _client_role_needs_update(
        self, existing: dict[str, Any], desired: dict[str, Any]
    ) -> bool:
        """
        Check if a client role needs to be updated.

        Args:
            existing: Existing client role from Keycloak
            desired: Desired client role configuration

        Returns:
            True if update is needed, False otherwise
        """
        # Compare key fields (excluding ID and other Keycloak-generated fields)
        compare_fields = [
            "name",
            "description",
            "composite",
            "clientRole",
            "containerId",
        ]

        for field in compare_fields:
            if existing.get(field) != desired.get(field):
                return True

        return False

    async def manage_service_account_roles(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
    ) -> None:
        """Manage role mappings for the client's service account user."""

        roles_config = spec.service_account_roles

        if not spec.settings.service_accounts_enabled:
            self.logger.debug(
                "Service accounts disabled for client %s; skipping role assignment",
                spec.client_id,
            )
            return

        if not roles_config.realm_roles and not roles_config.client_roles:
            self.logger.debug(
                f"No service account roles defined for client {spec.client_id}"
            )
            return

        self.logger.info(
            f"Configuring service account roles for client {spec.client_id} (resource {namespace}/{name})"
        )

        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name

        try:
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

            self.logger.debug(
                f"Fetching service account user for client {spec.client_id}"
            )
            service_account_user = admin_client.get_service_account_user(
                client_uuid, realm_name
            )
            user_id = service_account_user.id if service_account_user else None

            if not user_id:
                raise ReconciliationError(
                    f"Service account user missing identifier for client {spec.client_id}",
                    retryable=False,
                )

            if roles_config.realm_roles:
                self.logger.info(
                    f"Assigning {len(roles_config.realm_roles)} realm roles to service account for client {spec.client_id}"
                )
                admin_client.assign_realm_roles_to_user(
                    user_id=user_id,
                    role_names=roles_config.realm_roles,
                    realm_name=realm_name,
                )

            if roles_config.client_roles:
                for target_client_id, role_names in roles_config.client_roles.items():
                    if not role_names:
                        self.logger.debug(
                            f"No roles listed for target client {target_client_id} when assigning to {spec.client_id}"
                        )
                        continue

                    self.logger.info(
                        f"Assigning {len(role_names)} client roles from '{target_client_id}' to service account for client {spec.client_id}"
                    )

                    target_client = admin_client.get_client_by_name(
                        target_client_id, realm_name
                    )
                    if not target_client:
                        self.logger.warning(
                            f"Target client '{target_client_id}' not found in realm '{realm_name}'; skipping role assignment"
                        )
                        continue

                    target_client_uuid = target_client.id
                    if not target_client_uuid:
                        self.logger.warning(
                            f"Target client '{target_client_id}' missing UUID; skipping role assignment"
                        )
                        continue

                    admin_client.assign_client_roles_to_user(
                        user_id=user_id,
                        client_uuid=target_client_uuid,
                        role_names=role_names,
                        realm_name=realm_name,
                    )

            self.logger.info(
                f"Service account roles successfully configured for client {spec.client_id} (resource {namespace}/{name})"
            )

        except KeycloakAdminError as exc:
            self.logger.error(
                f"Failed Keycloak admin operation while managing service account roles for {spec.client_id}: {exc}"
            )
            raise ReconciliationError(
                f"Service account role management failed: {exc}", retryable=False
            ) from exc
        except ApiException as exc:
            self.logger.error(
                f"Kubernetes API error while managing service account roles for {spec.client_id}: {exc}"
            )
            raise ReconciliationError(
                f"Kubernetes API error during service account role management: {exc}"
            ) from exc
        except Exception as exc:
            self.logger.error(
                f"Unexpected error managing service account roles for {spec.client_id}: {exc}"
            )
            raise ReconciliationError(
                f"Unexpected error managing service account roles: {exc}"
            ) from exc

    async def do_update(
        self,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        diff: Any,
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any] | None:
        """
        Handle updates to Keycloak client specifications.

        Args:
            old_spec: Previous specification dictionary
            new_spec: New specification dictionary
            diff: List of changes between old and new specs
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Updated status dictionary or None if no changes needed
        """

        from ..errors import PermanentError, TemporaryError
        from ..utils.kubernetes import create_client_secret, validate_keycloak_reference

        self.logger.info(f"Updating KeycloakClient {name} in namespace {namespace}")

        # Log changes for debugging
        for operation, field_path, old_value, new_value in diff:
            self.logger.info(
                f"KeycloakClient change - {operation}: {field_path} "
                f"from {old_value} to {new_value}"
            )

        status.phase = "Updating"
        status.message = "Applying client configuration changes"

        # Validate that immutable fields haven't changed
        old_client_spec = self._validate_spec(old_spec)
        new_client_spec = self._validate_spec(new_spec)

        # Check for changes to immutable fields
        if old_client_spec.client_id != new_client_spec.client_id:
            raise PermanentError("Cannot change client_id of existing KeycloakClient")

        if old_client_spec.realm_ref != new_client_spec.realm_ref:
            raise PermanentError("Cannot change realmRef of existing KeycloakClient")

        # Get admin client for the target Keycloak instance
        realm_ref = new_client_spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # Get Keycloak instance for URL
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}",
                delay=30,
            )

        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        # Apply configuration updates based on the diff
        client_update_needed = False

        for operation, field_path, old_value, new_value in diff:
            if field_path[:2] == ("spec", "redirectUris"):
                self.logger.info(
                    f"Updating client redirect URIs: {old_value} -> {new_value}"
                )
                client_update_needed = True

            elif field_path[:2] == ("spec", "scopes"):
                self.logger.info(f"Updating client scopes: {old_value} -> {new_value}")
                client_update_needed = True

            elif field_path[:2] == ("spec", "settings"):
                self.logger.info(
                    f"Updating client settings: {field_path[2:]} = {new_value}"
                )
                client_update_needed = True

            elif field_path[:2] == ("spec", "protocol_mappers"):
                self.logger.info(
                    f"Protocol mappers changed: {operation} at {field_path}"
                )
                # Get client UUID for protocol mapper configuration
                client_uuid = admin_client.get_client_uuid(
                    new_client_spec.client_id, realm_name
                )
                if client_uuid:
                    await self.configure_protocol_mappers(
                        new_client_spec, client_uuid, name, namespace
                    )
                else:
                    self.logger.warning(
                        f"Could not find client UUID for {new_client_spec.client_id} - skipping protocol mappers"
                    )

            elif field_path[:2] == ("spec", "client_roles"):
                self.logger.info(f"Client roles changed: {operation} at {field_path}")
                # Get client UUID for role management
                client_uuid = admin_client.get_client_uuid(
                    new_client_spec.client_id, realm_name
                )
                if client_uuid:
                    await self.manage_client_roles(
                        new_client_spec, client_uuid, name, namespace
                    )
                else:
                    self.logger.warning(
                        f"Could not find client UUID for {new_client_spec.client_id}"
                    )

        # Apply core client configuration changes if needed
        if client_update_needed:
            self.logger.info(
                f"Applying client configuration update for {new_client_spec.client_id}"
            )
            try:
                admin_client.update_client(
                    new_client_spec.client_id,
                    new_client_spec.to_keycloak_config(),
                    realm_name,
                )
                self.logger.info("Client configuration updated successfully")
            except Exception as e:
                raise TemporaryError(
                    f"Failed to update client configuration: {e}", delay=30
                ) from e

        # Handle client secret regeneration
        regenerate_secret = new_client_spec.regenerate_secret
        if regenerate_secret and not new_client_spec.public_client:
            self.logger.info("Regenerating client secret")
            # Generate new secret in Keycloak
            new_secret = admin_client.regenerate_client_secret(
                new_client_spec.client_id, realm_name
            )

            # Update Kubernetes secret
            secret_name = f"{name}-credentials"
            create_client_secret(
                secret_name=secret_name,
                namespace=namespace,
                client_id=new_client_spec.client_id,
                client_secret=new_secret,
                keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
                realm=realm_name,
                update_existing=True,
            )

        self.logger.info(f"Successfully updated KeycloakClient {name}")

        # Update status to ready with generation tracking
        generation = kwargs.get("meta", {}).get("generation", 0)
        self.update_status_ready(
            status, "Client configuration updated successfully", generation
        )

        # Return empty dict - status updates are done via StatusWrapper
        return {}

    async def cleanup_resources(
        self,
        name: str,
        namespace: str,
        spec: dict[str, Any],
        status: StatusProtocol,
    ) -> None:
        """
        Clean up client from Keycloak and associated Kubernetes resources.

        Args:
            name: Name of the KeycloakClient resource
            namespace: Namespace containing the resource
            spec: Client specification
            status: Resource status for tracking cleanup progress

        Raises:
            TemporaryError: If cleanup fails but should be retried
        """

        from ..errors import TemporaryError

        self.logger.info(f"Starting cleanup of KeycloakClient {name} in {namespace}")

        try:
            client_spec = KeycloakClientSpec.model_validate(spec)
        except Exception as e:
            raise TemporaryError(f"Failed to parse KeycloakClient spec: {e}") from e

        # Get admin client for the target Keycloak instance
        realm_ref = client_spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_name = realm_ref.name
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # Delete client from Keycloak (if instance still exists)
        try:
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

            admin_client.delete_client(client_spec.client_id, realm_name)
            self.logger.info(
                f"Deleted client {client_spec.client_id} from Keycloak realm {realm_name}"
            )

        except Exception as e:
            self.logger.warning(
                f"Could not delete client from Keycloak (instance may be deleted): {e}"
            )

        # Clean up Kubernetes resources associated with this client
        try:
            await self._delete_client_k8s_resources(name, namespace, client_spec)
        except Exception as e:
            self.logger.warning(f"Failed to clean up Kubernetes resources: {e}")

        self.logger.info(f"Successfully completed cleanup of KeycloakClient {name}")

    async def _delete_client_k8s_resources(
        self, name: str, namespace: str, client_spec: KeycloakClientSpec
    ) -> None:
        """Delete Kubernetes resources associated with the client."""
        core_api = client.CoreV1Api(self.kubernetes_client)

        # Delete the credentials secret
        secret_name = f"{name}-credentials"
        try:
            core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)
            self.logger.info(f"Deleted credentials secret {secret_name}")
        except ApiException as e:
            if e.status != 404:  # Ignore "not found" errors
                self.logger.warning(
                    f"Failed to delete credentials secret {secret_name}: {e}"
                )

        # Delete any configmaps associated with this client
        try:
            configmaps = core_api.list_namespaced_config_map(
                namespace=namespace,
                label_selector=f"keycloak.mdvr.nl/client={name}",
            )
            for cm in configmaps.items:
                try:
                    core_api.delete_namespaced_config_map(
                        name=cm.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted client configmap {cm.metadata.name}")
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete configmap {cm.metadata.name}: {e}"
                        )

        except ApiException as e:
            self.logger.warning(f"Failed to list client configmaps for cleanup: {e}")

        # Delete any secrets with client labels (excluding credentials which we handled above)
        try:
            secrets = core_api.list_namespaced_secret(
                namespace=namespace,
                label_selector=f"keycloak.mdvr.nl/client={name},keycloak.mdvr.nl/secret-type!=credentials",
            )
            for secret in secrets.items:
                try:
                    core_api.delete_namespaced_secret(
                        name=secret.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted client secret {secret.metadata.name}")
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete secret {secret.metadata.name}: {e}"
                        )

        except ApiException as e:
            self.logger.warning(f"Failed to list client secrets for cleanup: {e}")
