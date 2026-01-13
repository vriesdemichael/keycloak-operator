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
from ..utils.ownership import get_cr_reference, is_owned_by_cr
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
        self,
        k8s_client: client.ApiClient | None = None,
        keycloak_admin_factory: Any = None,
        rate_limiter: Any = None,
    ):
        """
        Initialize Keycloak client reconciler.

        Args:
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients
            rate_limiter: Rate limiter for Keycloak API calls
        """
        super().__init__(k8s_client)
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )
        self.rate_limiter = rate_limiter

    def _get_realm_info(
        self, realm_resource_name: str, realm_namespace: str
    ) -> tuple[str, str, str, str]:
        """
        Get realm information including actual realm name and Keycloak instance.

        Args:
            realm_resource_name: Name of the realm Kubernetes resource
            realm_namespace: Namespace of the realm resource

        Returns:
            Tuple of (actual_realm_name, keycloak_namespace, keycloak_name, realm_resource_name)

        Raises:
            ApiException: If realm resource cannot be retrieved
            PermanentError: If realm spec is invalid
        """
        try:
            custom_api = client.CustomObjectsApi()
            realm_resource = custom_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=realm_namespace,
                plural="keycloakrealms",
                name=realm_resource_name,
            )

            # Get actual Keycloak realm name from spec
            actual_realm_name = realm_resource.get("spec", {}).get("realmName")
            if not actual_realm_name:
                from ..errors import PermanentError

                raise PermanentError(
                    f"Realm resource {realm_resource_name} does not have a realmName in spec"
                )

            # Get Keycloak instance from status
            realm_status = realm_resource.get("status", {})
            keycloak_instance = realm_status.get("keycloakInstance", "")

            # Parse "namespace/name" format
            if "/" in keycloak_instance and keycloak_instance.count("/") == 1:
                keycloak_namespace, keycloak_name = keycloak_instance.split("/", 1)
            else:
                # Fallback to defaults if format is unexpected
                self.logger.warning(
                    f"Realm {realm_resource_name} has unexpected keycloakInstance format: '{keycloak_instance}'. "
                    f"Using default: {realm_namespace}/keycloak"
                )
                keycloak_namespace, keycloak_name = realm_namespace, "keycloak"

            return actual_realm_name, keycloak_namespace, keycloak_name, realm_resource

        except ApiException as e:
            if e.status == 404:
                self.logger.error(
                    f"Realm {realm_resource_name} not found in namespace {realm_namespace}"
                )
            else:
                self.logger.error(f"Failed to get realm {realm_resource_name}: {e}")
            raise

    def _get_keycloak_instance_from_realm(
        self, realm_resource_name: str, realm_namespace: str
    ) -> tuple[str, str]:
        """
        Get Keycloak instance name and namespace from a realm's status.

        DEPRECATED: Use _get_realm_info instead for new code.

        Args:
            realm_resource_name: Name of the realm resource
            realm_namespace: Namespace of the realm resource

        Returns:
            Tuple of (keycloak_namespace, keycloak_name)
        """
        try:
            _, kc_ns, kc_name, _ = self._get_realm_info(
                realm_resource_name, realm_namespace
            )
            return kc_ns, kc_name
        except Exception:
            # Fallback to defaults
            return realm_namespace, "keycloak"

    async def do_reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs: Any,
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

        # Configure client-level scope assignments
        if client_spec.default_client_scopes or client_spec.optional_client_scopes:
            await self.configure_client_scopes(
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
        realm_resource_name = realm_ref.name
        secret_name = f"{name}-credentials"

        # Get keycloak instance and actual realm name from realm's status
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )
        from ..utils.kubernetes import validate_keycloak_reference

        keycloak_instance = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
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
                    "auth": f"{base_url}/realms/{actual_realm_name}",
                    "token": f"{base_url}/realms/{actual_realm_name}/protocol/openid-connect/token",
                    "userinfo": f"{base_url}/realms/{actual_realm_name}/protocol/openid-connect/userinfo",
                }

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        # Update status to ready
        self.update_status_ready(status, "Client configured and ready", generation)

        # Set additional status fields via StatusWrapper to avoid conflicts with Kopf
        status.client_id = client_spec.client_id
        status.client_uuid = client_uuid
        status.realm = actual_realm_name
        status.keycloak_instance = f"{keycloak_namespace}/{keycloak_name}"
        status.credentials_secret = secret_name
        status.public_client = client_spec.public_client
        status.endpoints = endpoints

        # Authorization status
        status.authorization_granted = True
        status.authorization_message = f"Namespace '{namespace}' is authorized by realm"

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

    async def _validate_namespace_authorization(
        self,
        realm_resource: dict[str, Any],
        realm_name: str,
        realm_namespace: str,
        client_namespace: str,
        client_id: str,
    ) -> None:
        """
        Validate that client's namespace is authorized via realm's grant list.

        Args:
            realm_resource: The KeycloakRealm custom resource
            realm_name: Name of the realm
            realm_namespace: Namespace of the realm
            client_namespace: Namespace of the client
            client_id: ID of the client

        Raises:
            PermanentError: If namespace is not in grant list
        """
        from ..errors import PermanentError

        # Get the grant list from realm spec
        realm_spec = realm_resource.get("spec", {})
        grant_list = realm_spec.get("clientAuthorizationGrants", [])

        # Check if client's namespace is in the grant list
        if client_namespace not in grant_list:
            error_msg = (
                f"Authorization denied: Namespace '{client_namespace}' is not authorized "
                f"to create clients in realm '{realm_name}' (namespace: '{realm_namespace}'). "
                f"The realm owner must add '{client_namespace}' to the "
                f"spec.clientAuthorizationGrants list in the realm CR."
            )

            if not grant_list:
                error_msg += (
                    " (Note: The realm has no authorized namespaces configured)"
                )
            else:
                error_msg += f" (Currently authorized: {', '.join(grant_list)})"

            self.logger.warning(error_msg)
            raise PermanentError(error_msg)

        self.logger.info(
            f"Authorization granted: Namespace '{client_namespace}' is authorized "
            f"for realm '{realm_name}'"
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

        # Resolve realm reference and get realm info
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_resource_name = realm_ref.name

        # Get all realm information in one call
        try:
            actual_realm_name, keycloak_namespace, keycloak_name, realm_resource = (
                self._get_realm_info(realm_resource_name, target_namespace)
            )
        except Exception as e:
            from kubernetes.client.rest import ApiException

            from ..errors import TemporaryError

            if isinstance(e, ApiException) and e.status == 404:
                raise TemporaryError(
                    f"Referenced realm {realm_resource_name} not found in namespace {target_namespace}. "
                    f"Ensure the realm exists before creating clients.",
                    delay=30,
                ) from e
            raise

        # NEW: Validate authorization via namespace grant list
        await self._validate_namespace_authorization(
            realm_resource=realm_resource,
            realm_name=realm_resource_name,
            realm_namespace=target_namespace,
            client_namespace=namespace,
            client_id=spec.client_id,
        )

        # Validate that the Keycloak instance exists and is ready
        keycloak_instance_obj = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
        )
        if not keycloak_instance_obj:
            from ..errors import TemporaryError

            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {keycloak_namespace}"
            )

        # Get Keycloak admin client
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )

        # Check if client already exists in the specified realm
        existing_client = await admin_client.get_client_by_name(
            spec.client_id, actual_realm_name, namespace
        )

        # Prepare client config with ownership attributes
        from ..utils.ownership import create_ownership_attributes

        client_config = spec.to_keycloak_config()

        # Add ownership attributes for drift detection
        if "attributes" not in client_config:
            client_config["attributes"] = {}

        ownership_attrs = create_ownership_attributes(namespace, name)
        client_config["attributes"].update(ownership_attrs)

        if existing_client:
            self.logger.info(f"Client {spec.client_id} already exists, updating...")
            await admin_client.update_client(
                existing_client.id,
                client_config,
                actual_realm_name,
                namespace,
            )
            return existing_client.id
        else:
            self.logger.info(f"Creating new client {spec.client_id}")
            client_response = await admin_client.create_client(
                client_config, actual_realm_name, namespace
            )
            # Extract client UUID from response or get it by name again
            if client_response:
                # create_client returns UUID string directly
                return client_response
            else:
                # Fallback: get client by name to retrieve UUID
                created_client = await admin_client.get_client_by_name(
                    spec.client_id, actual_realm_name, namespace
                )
                if created_client and created_client.id:
                    return created_client.id
                else:
                    # Client creation failed - raise error instead of returning
                    # invalid UUID to prevent subsequent API calls with bad UUID
                    from ..errors import TemporaryError

                    raise TemporaryError(
                        f"Failed to create client '{spec.client_id}' in realm "
                        f"'{actual_realm_name}'. The realm may be missing or "
                        f"Keycloak may be unavailable."
                    )

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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )

        try:
            # Get settings with defaults
            settings = spec.settings

            # Build attributes dict for optional settings
            attributes: dict[str, str] = {}
            if settings.access_token_lifespan is not None:
                attributes["access.token.lifespan"] = str(
                    settings.access_token_lifespan
                )
            if settings.client_session_idle_timeout is not None:
                attributes["client.session.idle.timeout"] = str(
                    settings.client_session_idle_timeout
                )
            if settings.client_session_max_lifespan is not None:
                attributes["client.session.max.lifespan"] = str(
                    settings.client_session_max_lifespan
                )
            if settings.pkce_code_challenge_method:
                attributes["pkce.code.challenge.method"] = (
                    settings.pkce_code_challenge_method
                )

            # Build OAuth2/OIDC client configuration
            client_config: dict[str, Any] = {
                "id": client_uuid,
                "clientId": spec.client_id,
                "name": spec.client_name or spec.client_id,
                "description": spec.description or "",
                "enabled": True,  # Client is enabled when CR exists
                "publicClient": spec.public_client,
                "bearerOnly": spec.bearer_only or False,
                "protocol": spec.protocol or "openid-connect",
                # OAuth2/OIDC flow settings from settings
                "standardFlowEnabled": settings.standard_flow_enabled,
                "implicitFlowEnabled": settings.implicit_flow_enabled,
                "directAccessGrantsEnabled": settings.direct_access_grants_enabled,
                "serviceAccountsEnabled": settings.service_accounts_enabled,
                # URI configurations
                "redirectUris": spec.redirect_uris or [],
                "webOrigins": getattr(spec, "web_origins", []),
                "adminUrl": getattr(spec, "admin_url", ""),
                "baseUrl": getattr(spec, "base_url", ""),
                "rootUrl": getattr(spec, "root_url", ""),
                # Additional OAuth2 settings from settings
                "consentRequired": settings.consent_required,
                "displayOnConsentScreen": settings.display_on_consent_screen,
                "frontchannelLogout": settings.frontchannel_logout,
                "fullScopeAllowed": settings.full_scope_allowed,
                "authorizationServicesEnabled": settings.authorization_services_enabled,
                "nodeReRegistrationTimeout": getattr(
                    spec, "node_re_registration_timeout", -1
                ),
                "notBefore": getattr(spec, "not_before", 0),
                "surrogateAuthRequired": getattr(
                    spec, "surrogate_auth_required", False
                ),
                # Client authentication method for confidential clients
                "clientAuthenticatorType": settings.client_authenticator_type
                if not spec.public_client
                else None,
            }

            # Add attributes if any were set
            if attributes:
                client_config["attributes"] = attributes

            # Remove None values to avoid sending unnecessary data
            client_config = {k: v for k, v in client_config.items() if v is not None}

            # Update the client with OAuth2 settings
            success = await admin_client.update_client(
                client_uuid, client_config, actual_realm_name, namespace
            )
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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )

        # Get client secret if this is a confidential client
        client_secret = None
        if not spec.public_client:
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, keycloak_namespace
            )
            client_secret = await admin_client.get_client_secret(
                spec.client_id, actual_realm_name, namespace
            )
            self.logger.info("Retrieved client secret for confidential client")

        # Get Keycloak instance for endpoint construction
        keycloak_instance = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
        )
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
            realm=actual_realm_name,
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
                        "vriesdemichael.github.io/keycloak-client": name,
                        "vriesdemichael.github.io/keycloak-realm": actual_realm_name,
                        "vriesdemichael.github.io/keycloak-secret-type": "client-credentials",
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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )

        try:
            # Get existing protocol mappers from Keycloak
            existing_mappers = await admin_client.get_client_protocol_mappers(
                client_uuid, actual_realm_name
            )
            if existing_mappers is None:
                self.logger.error(
                    f"Failed to retrieve existing protocol mappers for client {spec.client_id}"
                )
                return

            # Create a map of existing mappers by name for easy lookup
            existing_mappers_by_name = {
                mapper.name: mapper for mapper in existing_mappers
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
                        success = await admin_client.update_client_protocol_mapper(
                            client_uuid,
                            existing_mapper.id,
                            mapper_dict,
                            actual_realm_name,
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
                    created_mapper = await admin_client.create_client_protocol_mapper(
                        client_uuid, mapper_dict, actual_realm_name
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
                if existing_mapper.name not in desired_mapper_names:
                    self.logger.info(
                        f"Removing obsolete protocol mapper '{existing_mapper.name}'"
                    )
                    success = await admin_client.delete_client_protocol_mapper(
                        client_uuid, existing_mapper.id, actual_realm_name
                    )
                    if not success:
                        self.logger.error(
                            f"Failed to delete protocol mapper '{existing_mapper.name}'"
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

    async def configure_client_scopes(
        self, spec: KeycloakClientSpec, client_uuid: str, name: str, namespace: str
    ) -> None:
        """
        Configure client-level default and optional scope assignments.

        Args:
            spec: Keycloak client specification
            client_uuid: Client UUID in Keycloak
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring client scopes for client {spec.client_id}")

        # Get the realm info for the admin client
        realm_ref = spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_resource_name = realm_ref.name

        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace, rate_limiter=self.rate_limiter
        )

        # Get all available client scopes to build name-to-id mapping
        all_scopes = await admin_client.get_client_scopes(actual_realm_name, namespace)
        scope_name_to_id = {
            scope.name: scope.id for scope in all_scopes if scope.name and scope.id
        }

        # Configure default client scopes for this client
        if spec.default_client_scopes:
            current_defaults = await admin_client.get_client_default_scopes(
                actual_realm_name, client_uuid, namespace
            )
            current_default_names = {s.name for s in current_defaults if s.name}
            current_default_map = {
                s.name: s.id for s in current_defaults if s.name and s.id
            }

            desired_default_names = set(spec.default_client_scopes)

            # Add new default scopes
            for scope_name in desired_default_names - current_default_names:
                scope_id = scope_name_to_id.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Adding '{scope_name}' as default scope for client {spec.client_id}"
                    )
                    try:
                        await admin_client.add_client_default_scope(
                            actual_realm_name, client_uuid, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add client default scope '{scope_name}': {e}"
                        )
                else:
                    self.logger.warning(
                        f"Client scope '{scope_name}' not found in realm"
                    )

            # Remove scopes no longer in default list
            for scope_name in current_default_names - desired_default_names:
                scope_id = current_default_map.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Removing '{scope_name}' from client {spec.client_id} default scopes"
                    )
                    try:
                        await admin_client.remove_client_default_scope(
                            actual_realm_name, client_uuid, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to remove client default scope '{scope_name}': {e}"
                        )

        # Configure optional client scopes for this client
        if spec.optional_client_scopes:
            current_optionals = await admin_client.get_client_optional_scopes(
                actual_realm_name, client_uuid, namespace
            )
            current_optional_names = {s.name for s in current_optionals if s.name}
            current_optional_map = {
                s.name: s.id for s in current_optionals if s.name and s.id
            }

            desired_optional_names = set(spec.optional_client_scopes)

            # Add new optional scopes
            for scope_name in desired_optional_names - current_optional_names:
                scope_id = scope_name_to_id.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Adding '{scope_name}' as optional scope for client {spec.client_id}"
                    )
                    try:
                        await admin_client.add_client_optional_scope(
                            actual_realm_name, client_uuid, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add client optional scope '{scope_name}': {e}"
                        )
                else:
                    self.logger.warning(
                        f"Client scope '{scope_name}' not found in realm"
                    )

            # Remove scopes no longer in optional list
            for scope_name in current_optional_names - desired_optional_names:
                scope_id = current_optional_map.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Removing '{scope_name}' from client {spec.client_id} optional scopes"
                    )
                    try:
                        await admin_client.remove_client_optional_scope(
                            actual_realm_name, client_uuid, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to remove client optional scope '{scope_name}': {e}"
                        )

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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )

        try:
            # Get existing client roles from Keycloak
            existing_roles = await admin_client.get_client_roles(
                client_uuid, actual_realm_name
            )
            if existing_roles is None:
                self.logger.error(
                    f"Failed to retrieve existing client roles for client {spec.client_id}"
                )
                return

            # Create a map of existing roles by name for easy lookup
            existing_roles_by_name = {role.name: role for role in existing_roles}

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
                    success = await admin_client.create_client_role(
                        client_uuid, role_config, actual_realm_name
                    )
                    if not success:
                        self.logger.error(f"Failed to create client role '{role_name}'")
                else:
                    self.logger.debug(f"Client role '{role_name}' already exists")

            # Remove client roles that are no longer specified
            desired_role_names = set(spec.client_roles)
            for existing_role in existing_roles:
                if existing_role.name not in desired_role_names:
                    self.logger.info(
                        f"Removing obsolete client role '{existing_role.name}'"
                    )
                    success = await admin_client.delete_client_role(
                        client_uuid, existing_role.name, actual_realm_name
                    )
                    if not success:
                        self.logger.error(
                            f"Failed to delete client role '{existing_role.name}'"
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
                f"Service accounts disabled for client {spec.client_id}; skipping role assignment"
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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )

        try:
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, keycloak_namespace
            )

            self.logger.debug(
                f"Fetching service account user for client {spec.client_id}"
            )
            service_account_user = await admin_client.get_service_account_user(
                client_uuid, actual_realm_name, namespace
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
                await admin_client.assign_realm_roles_to_user(
                    user_id=user_id,
                    role_names=roles_config.realm_roles,
                    realm_name=actual_realm_name,
                    namespace=namespace,
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

                    target_client = await admin_client.get_client_by_name(
                        target_client_id, actual_realm_name, namespace
                    )
                    if not target_client:
                        self.logger.warning(
                            f"Target client '{target_client_id}' not found in realm '{actual_realm_name}'; skipping role assignment"
                        )
                        continue

                    target_client_uuid = target_client.id
                    if not target_client_uuid:
                        self.logger.warning(
                            f"Target client '{target_client_id}' missing UUID; skipping role assignment"
                        )
                        continue

                    await admin_client.assign_client_roles_to_user(
                        user_id=user_id,
                        client_uuid=target_client_uuid,
                        role_names=role_names,
                        realm_name=actual_realm_name,
                        namespace=namespace,
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
        **kwargs: Any,
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
        realm_resource_name = realm_ref.name
        actual_realm_name, keycloak_namespace, keycloak_name, _ = self._get_realm_info(
            realm_resource_name, target_namespace
        )

        # Get Keycloak instance for URL
        keycloak_instance = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
        )
        if not keycloak_instance:
            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}",
                delay=30,
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )

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
                client_uuid = await admin_client.get_client_uuid(
                    new_client_spec.client_id, actual_realm_name, namespace
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
                client_uuid = await admin_client.get_client_uuid(
                    new_client_spec.client_id, actual_realm_name, namespace
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
                await admin_client.update_client(
                    new_client_spec.client_id,
                    new_client_spec.to_keycloak_config(),
                    actual_realm_name,
                    namespace,
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
                new_client_spec.client_id, actual_realm_name, namespace
            )

            # Update Kubernetes secret
            secret_name = f"{name}-credentials"
            create_client_secret(
                secret_name=secret_name,
                namespace=namespace,
                client_id=new_client_spec.client_id,
                client_secret=new_secret,
                keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
                realm=actual_realm_name,
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

    async def check_resource_exists(
        self,
        name: str,
        namespace: str,
        spec: dict[str, Any],
        status: StatusProtocol,
    ) -> bool:
        """
        Check if client resource actually exists in Keycloak.

        Args:
            name: Name of the KeycloakClient resource
            namespace: Namespace containing the resource
            spec: Client specification
            status: Resource status

        Returns:
            True if client exists in Keycloak, False otherwise
        """
        try:
            client_spec = KeycloakClientSpec.model_validate(spec)
        except Exception as e:
            self.logger.warning(f"Cannot parse spec to check resource existence: {e}")
            return False

        # Get admin client for the target Keycloak instance
        realm_ref = client_spec.realm_ref
        target_namespace = realm_ref.namespace
        realm_resource_name = realm_ref.name

        try:
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(realm_resource_name, target_namespace)
            )
        except ApiException as e:
            if e.status == 404:
                # Realm is already deleted, so client definitely doesn't exist in Keycloak
                self.logger.info(
                    f"Realm {realm_resource_name} not found (already deleted), "
                    f"client {name} cannot exist in Keycloak"
                )
                return False
            raise

        try:
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, keycloak_namespace
            )

            # Try to get client by client_id
            existing_client = await admin_client.get_client_by_name(
                client_spec.client_id, actual_realm_name, namespace
            )

            if existing_client:
                self.logger.info(
                    f"Client {client_spec.client_id} exists in Keycloak "
                    f"realm {actual_realm_name}"
                )
                return True
            else:
                self.logger.info(
                    f"Client {client_spec.client_id} does not exist in Keycloak "
                    f"realm {actual_realm_name}"
                )
                return False

        except Exception as e:
            self.logger.warning(
                f"Cannot verify if client exists in Keycloak: {e}. "
                f"Assuming it doesn't exist (resource never materialized)."
            )
            return False

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
        realm_resource_name = realm_ref.name

        # Try to get realm info - if realm is already deleted, just clean up K8s resources
        realm_deleted = False
        try:
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(realm_resource_name, target_namespace)
            )
        except ApiException as e:
            if e.status == 404:
                self.logger.info(
                    f"Realm {realm_resource_name} not found (already deleted), "
                    f"skipping Keycloak cleanup for client {name}"
                )
                realm_deleted = True
            else:
                raise

        # Delete client from Keycloak (if realm still exists and we own it)
        if not realm_deleted:
            try:
                admin_client = await self.keycloak_admin_factory(
                    keycloak_name, keycloak_namespace
                )

                # Check if client exists in Keycloak
                existing_client = await admin_client.get_client_by_name(
                    client_spec.client_id, actual_realm_name, namespace
                )

                if existing_client is None:
                    # Client doesn't exist in Keycloak - nothing to delete
                    self.logger.info(
                        f"Client {client_spec.client_id} does not exist in Keycloak "
                        f"realm {actual_realm_name}, skipping Keycloak cleanup"
                    )
                else:
                    # Client exists - check ownership before deleting
                    client_attributes = (
                        existing_client.attributes
                        if hasattr(existing_client, "attributes")
                        else None
                    )

                    if not is_owned_by_cr(client_attributes, namespace, name):
                        # This CR doesn't own the client - don't delete it
                        owner_ref = get_cr_reference(client_attributes)
                        if owner_ref:
                            owner_ns, owner_name = owner_ref
                            self.logger.warning(
                                f"Skipping deletion of client {client_spec.client_id}: "
                                f"owned by {owner_ns}/{owner_name}, not by {namespace}/{name}"
                            )
                        else:
                            self.logger.warning(
                                f"Skipping deletion of client {client_spec.client_id}: "
                                f"no ownership attributes found (unmanaged resource)"
                            )
                    else:
                        # This CR owns the client - proceed with deletion
                        await admin_client.delete_client(
                            client_spec.client_id, actual_realm_name, namespace
                        )
                        self.logger.info(
                            f"Deleted client {client_spec.client_id} from Keycloak realm {actual_realm_name}"
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
                label_selector=f"vriesdemichael.github.io/keycloak-client={name}",
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
                label_selector=f"vriesdemichael.github.io/keycloak-client={name},vriesdemichael.github.io/keycloak-secret-type!=credentials",
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
