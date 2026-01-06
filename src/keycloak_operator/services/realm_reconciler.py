"""
Keycloak realm reconciler for managing realm configuration and features.

This module handles the lifecycle of Keycloak realms including
themes, authentication flows, identity providers, and user federation.
"""

import asyncio
import json
from typing import Any

from kubernetes import client

from keycloak_operator.settings import settings

from ..errors import ValidationError
from ..models.realm import KeycloakRealmSpec
from ..utils.keycloak_admin import KeycloakAdminError, get_keycloak_admin_client
from ..utils.ownership import get_cr_reference, is_owned_by_cr
from ..utils.rbac import get_secret_with_validation
from .base_reconciler import BaseReconciler, StatusProtocol


class KeycloakRealmReconciler(BaseReconciler):
    """
    Reconciler for Keycloak realm resources.

    Manages the complete configuration of Keycloak realms including:
    - Basic realm creation and settings
    - Theme and branding configuration
    - Authentication flows and security
    - Identity provider integration
    - User federation setup
    - Cross-namespace RBAC validation
    """

    def __init__(
        self,
        k8s_client: client.ApiClient | None = None,
        keycloak_admin_factory: Any = None,
        rate_limiter: Any = None,
    ):
        """
        Initialize Keycloak realm reconciler.

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

    async def do_reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Reconcile Keycloak realm to desired state.

        Args:
            spec: Keycloak realm resource specification
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource
        """
        # Parse and validate the specification
        realm_spec = self._validate_spec(spec)

        # Validate cross-namespace permissions
        await self.validate_cross_namespace_access(realm_spec, namespace)

        # Ensure basic realm exists (pass kwargs for ownership tracking)
        await self.ensure_realm_exists(realm_spec, name, namespace, **kwargs)

        # Configure realm features
        if realm_spec.themes:
            await self.configure_themes(realm_spec, name, namespace)

        if realm_spec.authentication_flows:
            await self.configure_authentication(realm_spec, name, namespace)

        if realm_spec.required_actions:
            await self.configure_required_actions(realm_spec, name, namespace)

        # Apply flow bindings AFTER authentication flows are created
        # This must happen after configure_authentication so the flows exist
        if self._has_flow_bindings(realm_spec):
            await self.apply_flow_bindings(realm_spec, name, namespace)

        if realm_spec.identity_providers:
            await self.configure_identity_providers(realm_spec, name, namespace)

        if realm_spec.user_federation:
            await self.configure_user_federation(realm_spec, name, namespace)

        # Configure client scopes (must be before default/optional scope assignments)
        if realm_spec.client_scopes:
            await self.configure_client_scopes(realm_spec, name, namespace)

        # Configure realm-level default and optional client scopes
        if realm_spec.default_client_scopes or realm_spec.optional_client_scopes:
            await self.configure_realm_default_client_scopes(
                realm_spec, name, namespace
            )

        # Configure realm roles (must be before groups since groups reference roles)
        if realm_spec.roles and realm_spec.roles.realm_roles:
            await self.configure_realm_roles(realm_spec, name, namespace)

        # Configure groups (including role assignments and subgroups)
        if realm_spec.groups:
            await self.configure_groups(realm_spec, name, namespace)

        # Configure default groups
        if realm_spec.default_groups:
            await self.configure_default_groups(realm_spec, name, namespace)

        # Setup backup preparation
        await self.manage_realm_backup(realm_spec, name, namespace)

        # Return status information
        operator_ref = realm_spec.operator_ref
        target_namespace = operator_ref.namespace

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        # Set custom status fields using attribute assignment (camelCase as in CRD)
        # IMPORTANT: Use attribute assignment, not item assignment!
        # Kopf StatusWrapper supports status.camelCase = value
        status.realmName = realm_spec.realm_name
        status.keycloakInstance = f"{target_namespace}/keycloak"

        # Update authorized client namespaces from spec
        status.authorizedClientNamespaces = realm_spec.client_authorization_grants or []

        status.features = {
            "userRegistration": realm_spec.security.registration_allowed
            if realm_spec.security
            else False,
            "passwordReset": realm_spec.security.reset_password_allowed
            if realm_spec.security
            else True,
            "identityProviders": len(realm_spec.identity_providers or []),
            "userFederationProviders": len(realm_spec.user_federation or []),
            "customThemes": bool(realm_spec.themes),
            "realmRoles": len(realm_spec.roles.realm_roles) if realm_spec.roles else 0,
            "groups": len(realm_spec.groups or []),
            "clientScopes": len(realm_spec.client_scopes or []),
        }

        # Update realm roles count in status
        status.realmRolesCount = (
            len(realm_spec.roles.realm_roles) if realm_spec.roles else 0
        )

        # Update client scopes count in status
        status.clientScopesCount = len(realm_spec.client_scopes or [])

        # Populate OIDC endpoint discovery
        try:
            from ..models.keycloak import Keycloak
            from ..utils.oidc_endpoints import (
                construct_oidc_endpoints,
                get_keycloak_base_url,
            )

            # Fetch the Keycloak CR to get its base URL
            custom_api = client.CustomObjectsApi(self.k8s_client)
            keycloak_dict = custom_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=target_namespace,
                plural="keycloaks",
                name="keycloak",  # Default Keycloak instance name
            )

            # Parse into Pydantic model
            keycloak = Keycloak.model_validate(keycloak_dict)

            # Get base URL from Keycloak instance
            base_url = get_keycloak_base_url(keycloak)

            # Construct OIDC endpoints
            oidc_endpoints = construct_oidc_endpoints(base_url, realm_spec.realm_name)

            # Populate status.endpoints
            status.endpoints = oidc_endpoints

            self.logger.debug(
                f"Populated OIDC endpoints for realm {realm_spec.realm_name}: "
                f"issuer={oidc_endpoints['issuer']}"
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to populate OIDC endpoints for realm {realm_spec.realm_name}: {e}"
            )
            # Don't fail reconciliation if endpoint population fails
            # Endpoints will be populated on next reconciliation

        # Update status to indicate successful reconciliation
        # This sets observedGeneration, phase, message, and timestamps
        self.update_status_ready(status, "Realm configured and ready", generation)

        # Return empty dict - status already set above
        return {}

    def _validate_spec(self, spec: dict[str, Any]) -> KeycloakRealmSpec:
        """
        Validate and parse Keycloak realm specification.

        Args:
            spec: Raw specification dictionary

        Returns:
            Validated KeycloakRealmSpec object

        Raises:
            ValidationError: If specification is invalid
        """
        try:
            return KeycloakRealmSpec.model_validate(spec)
        except Exception as e:
            raise ValidationError(f"Invalid Keycloak realm specification: {e}") from e

    async def validate_cross_namespace_access(
        self, spec: KeycloakRealmSpec, namespace: str
    ) -> None:
        """
        Validate RBAC permissions for cross-namespace operations.

        Args:
            spec: Keycloak realm specification
            namespace: Current namespace

        Raises:
            RBACError: If insufficient permissions for cross-namespace access
        """
        target_namespace = spec.operator_ref.namespace

        # Define required operations for realm management
        required_operations = [
            {"resource": "keycloaks", "verb": "get"},
            {"resource": "secrets", "verb": "get"},  # For admin credentials
        ]

        # Validate RBAC permissions with audit logging
        await self.validate_rbac_permissions(
            source_namespace=namespace,
            target_namespace=target_namespace,
            operations=required_operations,
            resource_name=spec.operator_ref.namespace,
        )

        # Validate namespace isolation policies
        await self.validate_namespace_isolation(
            source_namespace=namespace,
            target_namespace=target_namespace,
            resource_type="keycloak realm",
            resource_name=spec.realm_name,
        )

        self.logger.info(
            f"Cross-namespace access validation passed for realm {spec.realm_name}"
        )

    async def _check_realm_capacity(
        self, keycloak_namespace: str, keycloak_name: str, realm_name: str
    ) -> None:
        """
        Check if Keycloak operator has capacity for new realms.

        Args:
            keycloak_namespace: Namespace containing the Keycloak instance
            keycloak_name: Name of the Keycloak instance
            realm_name: Name of the realm being created

        Raises:
            PermanentError: If capacity is exhausted and new realms are not allowed
        """
        from ..errors import PermanentError, TemporaryError

        try:
            # Fetch the Keycloak instance
            custom_objects_api = client.CustomObjectsApi(self.k8s_client)
            keycloak = custom_objects_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=keycloak_namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            spec = keycloak.get("spec", {})
            realm_capacity = spec.get("realmCapacity", {})

            # If no capacity config, allow unlimited realms
            if not realm_capacity:
                self.logger.debug(
                    "No realm capacity configuration, allowing realm creation"
                )
                return

            # Check if new realms are allowed
            allow_new_realms = realm_capacity.get("allowNewRealms", True)
            if not allow_new_realms:
                capacity_message = realm_capacity.get(
                    "capacityMessage",
                    f"Keycloak instance '{keycloak_name}' in namespace '{keycloak_namespace}' "
                    f"is not accepting new realms. Contact platform team for assistance.",
                )
                raise PermanentError(
                    f"Cannot create realm '{realm_name}': {capacity_message}"
                )

            # Check max realms limit
            max_realms = realm_capacity.get("maxRealms")
            if max_realms is not None:
                # Count existing realms
                realm_list = await custom_objects_api.list_cluster_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    plural="keycloakrealms",
                )

                # Count realms that reference this Keycloak instance
                realm_count = sum(
                    1
                    for item in realm_list.get("items", [])
                    if item.get("spec", {}).get("operatorRef", {}).get("namespace")
                    == keycloak_namespace
                )

                if realm_count >= max_realms:
                    capacity_message = realm_capacity.get(
                        "capacityMessage",
                        f"Keycloak instance '{keycloak_name}' has reached maximum realm capacity "
                        f"({max_realms} realms). Contact platform team to increase capacity.",
                    )
                    raise PermanentError(
                        f"Cannot create realm '{realm_name}': {capacity_message}"
                    )

                self.logger.info(
                    f"Realm capacity check passed: {realm_count}/{max_realms} realms"
                )

        except PermanentError:
            # Re-raise capacity errors as permanent
            raise
        except Exception as e:
            # Other errors (like Keycloak not found) are temporary
            raise TemporaryError(
                f"Failed to check realm capacity: {e}. Will retry.",
                delay=30,
            ) from e

    async def _fetch_secret_value(
        self, namespace: str, secret_name: str, secret_key: str
    ) -> str:
        """
        Fetch secret value from Kubernetes secret with RBAC validation.

        This method enforces namespace access control and secret labeling requirements.
        The secret must:
        1. Be accessible via RoleBinding granting operator access to the namespace
        2. Have the label: vriesdemichael.github.io/keycloak-allow-operator-read=true

        Args:
            namespace: Namespace containing the secret
            secret_name: Name of the secret
            secret_key: Key in secret data

        Returns:
            Decoded secret value string

        Raises:
            ValidationError: If RBAC validation fails, secret not found, or key missing
        """
        try:
            # Validate RBAC and read secret
            result, error = await get_secret_with_validation(
                secret_name=secret_name,
                namespace=namespace,
                operator_namespace=settings.operator_namespace,
                key=secret_key,
            )

            if error:
                raise ValidationError(error)

            if result is None or not isinstance(result, str):
                raise ValidationError(
                    f"Key '{secret_key}' not found in secret '{secret_name}' or invalid value type"
                )

            secret_value = result

            self.logger.debug(
                f"Successfully fetched secret value from secret {secret_name} "
                f"in namespace {namespace} with RBAC validation"
            )
            return secret_value

        except ValidationError:
            # Re-raise validation errors as-is
            raise
        except Exception as e:
            raise ValidationError(
                f"Failed to fetch secret value from secret '{secret_name}' "
                f"in namespace '{namespace}': {e}"
            ) from e

    async def ensure_realm_exists(
        self, spec: KeycloakRealmSpec, name: str, namespace: str, **kwargs: Any
    ) -> None:
        """
        Ensure the basic realm exists in Keycloak with ownership tracking.

        This method implements ownership tracking to prevent multiple CRs from
        managing the same realm and to handle orphaned realms properly.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
            **kwargs: Additional handler arguments (uid, meta, etc.)
        """
        self.logger.info(f"Ensuring realm {spec.realm_name} exists")
        from ..utils.kubernetes import validate_keycloak_reference

        # Resolve Keycloak operator reference
        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        # For now, use the operator namespace as keycloak name (will be updated in Phase 4)
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # NEW: Check capacity before creating new realms
        await self._check_realm_capacity(target_namespace, keycloak_name, name)

        self.logger.info(f"Authorization validated for realm {spec.realm_name}")

        # Validate that the Keycloak instance exists and is ready
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            from ..errors import TemporaryError

            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}"
            )

        # Get Keycloak admin client
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        # Extract CR UID for ownership tracking
        cr_uid = kwargs.get("uid", "")

        # Check if realm already exists
        realm_name = spec.realm_name

        # Generate realm payload - we'll determine whether to include flow bindings
        # based on whether this is a create or update operation
        # For creates, flows don't exist yet so we can't bind to them
        realm_payload_without_bindings = spec.to_keycloak_config(
            include_flow_bindings=False
        )
        realm_payload_with_bindings = spec.to_keycloak_config(
            include_flow_bindings=True
        )

        # Helper to inject SMTP and ownership into a payload
        def inject_common_fields(payload: dict[str, Any]) -> None:
            # Inject SMTP password from secret if configured
            if spec.smtp_server:
                if spec.smtp_server.password_secret:
                    # Intentionally a no-op: when a password_secret is configured,
                    # the SMTP password is fetched asynchronously and injected in
                    # the "Inject SMTP password from secret if configured" section
                    # below. Doing anything here would duplicate that logic.
                    pass
                elif spec.smtp_server.password:
                    # Direct password (discouraged but supported)
                    if "smtpServer" not in payload:
                        payload["smtpServer"] = {}
                    payload["smtpServer"]["password"] = spec.smtp_server.password

            # Add ownership metadata to realm attributes
            from ..utils.ownership import create_ownership_attributes

            if "attributes" not in payload:
                payload["attributes"] = {}
            ownership_attrs = create_ownership_attributes(namespace, name)
            payload["attributes"].update(ownership_attrs)

        # Inject SMTP password from secret if configured (async operation)
        smtp_password = None
        if spec.smtp_server and spec.smtp_server.password_secret:
            smtp_password = await self._fetch_secret_value(
                namespace=namespace,
                secret_name=spec.smtp_server.password_secret.name,
                secret_key=spec.smtp_server.password_secret.key,
            )
            self.logger.debug("Injected SMTP password from secret into realm config")

        # Apply common fields to both payloads
        inject_common_fields(realm_payload_without_bindings)
        inject_common_fields(realm_payload_with_bindings)

        # Inject SMTP password if fetched from secret
        if smtp_password:
            for payload in [
                realm_payload_without_bindings,
                realm_payload_with_bindings,
            ]:
                if "smtpServer" not in payload:
                    payload["smtpServer"] = {}
                payload["smtpServer"]["password"] = smtp_password

        # Log warning for direct password usage
        if (
            spec.smtp_server
            and spec.smtp_server.password
            and not spec.smtp_server.password_secret
        ):
            self.logger.warning(
                "Using direct SMTP password from spec. "
                "Consider using password_secret for better security."
            )

        # Use payload with bindings for logging preview (more complete)
        payload_json = json.dumps(realm_payload_with_bindings, default=str)
        payload_preview = (
            payload_json
            if len(payload_json) <= 2048
            else f"{payload_json[:2048]}...<truncated>"
        )

        self.logger.debug(
            "Prepared realm configuration for apply",
            keycloak_instance=keycloak_name,
            realm_name=realm_name,
            cr_uid=cr_uid,
            payload_preview=payload_preview,
        )

        # Check if realm already exists and validate ownership
        # Import errors early for ownership validation logic
        from ..errors import PermanentError, TemporaryError

        try:
            existing_realm = await admin_client.get_realm(realm_name, namespace)
        except KeycloakAdminError as exc:
            if getattr(exc, "status_code", None) == 404:
                self.logger.info(f"Realm {realm_name} not found, creating new realm")
                existing_realm = None
            else:
                self.logger.error(
                    "Failed to look up realm before apply",
                    keycloak_instance=keycloak_name,
                    realm_name=realm_name,
                    status_code=exc.status_code,
                    response_body=exc.body_preview(),
                )
                raise

        if existing_realm:
            # Validate ownership before updating
            # Access Pydantic model attributes directly (not with .get())
            attributes = existing_realm.attributes or {}
            owner_uid = (
                attributes.get("kubernetes.operator.uid") if attributes else None
            )
            owner_name = (
                attributes.get("kubernetes.operator.name") if attributes else None
            )
            owner_namespace = (
                attributes.get("kubernetes.operator.namespace") if attributes else None
            )

            if not owner_uid:
                # Orphaned realm - adopt it
                self.logger.info(
                    f"Adopting orphaned realm {realm_name} "
                    f"(no ownership metadata found)"
                )
                try:
                    await admin_client.update_realm(
                        realm_name, realm_payload_with_bindings, namespace
                    )
                    self.logger.info(f"Successfully adopted realm {realm_name}")
                except KeycloakAdminError as exc:
                    self.logger.error(
                        "Failed to adopt orphaned realm",
                        keycloak_instance=keycloak_name,
                        realm_name=realm_name,
                        status_code=exc.status_code,
                        response_body=exc.body_preview(),
                    )
                    raise
            elif owner_uid == cr_uid:
                # Owned by this CR - normal update
                self.logger.info(f"Updating realm {realm_name} (owned by this CR)")
                try:
                    await admin_client.update_realm(
                        realm_name, realm_payload_with_bindings, namespace
                    )
                except KeycloakAdminError as exc:
                    self.logger.error(
                        "Realm update failed",
                        keycloak_instance=keycloak_name,
                        realm_name=realm_name,
                        status_code=exc.status_code,
                        response_body=exc.body_preview(),
                        payload_preview=payload_preview,
                    )
                    raise
            else:
                # Owned by different CR - conflict!
                error_msg = (
                    f"Realm {realm_name} is already managed by another KeycloakRealm CR. "
                    f"Existing owner: {owner_name} in namespace {owner_namespace} (UID: {owner_uid[:8]}...). "
                    f"This CR: {name} in namespace {namespace} (UID: {cr_uid[:8]}...). "
                    f"Multiple CRs cannot manage the same realm name."
                )
                self.logger.error(
                    "Realm ownership conflict detected",
                    realm_name=realm_name,
                    existing_owner=f"{owner_namespace}/{owner_name}",
                    existing_owner_uid=owner_uid,
                    this_cr=f"{namespace}/{name}",
                    this_cr_uid=cr_uid,
                )
                raise PermanentError(error_msg)
        else:
            # Realm doesn't exist - create it WITHOUT flow bindings
            # (flows don't exist yet, will be created and bound later)
            self.logger.info(
                f"Creating new realm {realm_name}",
                keycloak_instance=keycloak_name,
                realm_name=realm_name,
                cr_uid=cr_uid,
            )
            try:
                await admin_client.create_realm(
                    realm_payload_without_bindings, namespace
                )
                self.logger.info(f"Successfully created realm {realm_name}")
            except KeycloakAdminError as exc:
                # Handle 409 conflict (race condition - realm created between GET and CREATE)
                if getattr(exc, "status_code", None) == 409:
                    self.logger.warning(
                        f"Realm {realm_name} was created concurrently (409 conflict). "
                        f"Retrying to check ownership..."
                    )
                    raise TemporaryError(
                        f"Realm {realm_name} created concurrently, retrying reconciliation",
                        delay=5,
                    ) from exc
                else:
                    self.logger.error(
                        "Realm creation failed",
                        keycloak_instance=keycloak_name,
                        realm_name=realm_name,
                        status_code=exc.status_code,
                        response_body=exc.body_preview(),
                        payload_preview=payload_preview,
                    )
                    raise

    async def configure_themes(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure themes and branding for the realm.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring themes for realm {spec.realm_name}")

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        try:
            theme_config = {}
            if hasattr(spec.themes, "login_theme") and spec.themes.login_theme:
                theme_config["login_theme"] = spec.themes.login_theme
            if hasattr(spec.themes, "account_theme") and spec.themes.account_theme:
                theme_config["account_theme"] = spec.themes.account_theme
            if hasattr(spec.themes, "admin_theme") and spec.themes.admin_theme:
                theme_config["admin_theme"] = spec.themes.admin_theme
            if hasattr(spec.themes, "email_theme") and spec.themes.email_theme:
                theme_config["email_theme"] = spec.themes.email_theme

            if theme_config:
                await admin_client.update_realm_themes(
                    spec.realm_name, theme_config, namespace
                )
        except Exception as e:
            self.logger.warning(f"Failed to configure themes: {e}")

    async def configure_authentication(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure authentication flows and security settings.

        This method handles:
        - Creating new authentication flows
        - Copying from built-in flows (when copyFrom is specified)
        - Adding executions to flows
        - Configuring execution requirements
        - Setting up authenticator configurations

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring authentication for realm {spec.realm_name}")

        if not spec.authentication_flows:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        for flow_config in spec.authentication_flows:
            try:
                flow_alias = flow_config.alias
                self.logger.info(f"Processing authentication flow '{flow_alias}'")

                # Check if flow already exists
                existing_flow = await admin_client.get_authentication_flow_by_alias(
                    realm_name, flow_alias, namespace
                )

                if existing_flow:
                    self.logger.info(
                        f"Authentication flow '{flow_alias}' already exists, "
                        f"updating executions"
                    )
                    # Flow exists - update executions if needed
                    await self._sync_flow_executions(
                        admin_client,
                        realm_name,
                        flow_alias,
                        flow_config,
                        namespace,
                    )
                else:
                    # Flow doesn't exist - create it
                    if flow_config.copy_from:
                        # Copy from existing built-in flow
                        self.logger.info(
                            f"Copying flow '{flow_config.copy_from}' to '{flow_alias}'"
                        )
                        success = await admin_client.copy_authentication_flow(
                            realm_name,
                            flow_config.copy_from,
                            flow_alias,
                            namespace,
                        )
                        if not success:
                            self.logger.error(
                                f"Failed to copy flow '{flow_config.copy_from}' "
                                f"to '{flow_alias}'"
                            )
                            continue

                        # After copying, sync executions to match desired state
                        await self._sync_flow_executions(
                            admin_client,
                            realm_name,
                            flow_alias,
                            flow_config,
                            namespace,
                        )
                    else:
                        # Create new flow from scratch
                        from keycloak_operator.models.keycloak_api import (
                            AuthenticationFlowRepresentation,
                        )

                        flow_repr = AuthenticationFlowRepresentation(
                            alias=flow_alias,
                            description=flow_config.description,
                            provider_id=flow_config.provider_id,
                            top_level=flow_config.top_level,
                            built_in=False,
                        )

                        success = await admin_client.create_authentication_flow(
                            realm_name, flow_repr, namespace
                        )

                        if not success:
                            self.logger.error(
                                f"Failed to create authentication flow '{flow_alias}'"
                            )
                            continue

                        # Add executions to the new flow
                        await self._add_flow_executions(
                            admin_client,
                            realm_name,
                            flow_alias,
                            flow_config,
                            namespace,
                        )

                # Set up authenticator configurations
                if flow_config.authenticator_config:
                    await self._configure_authenticator_configs(
                        admin_client,
                        realm_name,
                        flow_alias,
                        flow_config,
                        namespace,
                    )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure authentication flow '{flow_config.alias}': {e}"
                )

    async def _add_flow_executions(
        self,
        admin_client,
        realm_name: str,
        flow_alias: str,
        flow_config,
        namespace: str,
    ) -> None:
        """
        Add executions to a newly created flow.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            flow_alias: Alias of the flow
            flow_config: Flow configuration with executions
            namespace: Origin namespace for rate limiting
        """
        for execution in flow_config.authentication_executions:
            try:
                if execution.authenticator_flow and execution.flow_alias:
                    # This is a sub-flow reference
                    execution_id = await admin_client.add_subflow_to_flow(
                        realm_name,
                        flow_alias,
                        execution.flow_alias,
                        "basic-flow",
                        None,
                        namespace,
                    )
                elif execution.authenticator:
                    # This is an authenticator execution
                    execution_id = await admin_client.add_execution_to_flow(
                        realm_name,
                        flow_alias,
                        execution.authenticator,
                        namespace,
                    )
                else:
                    self.logger.warning(
                        "Execution has neither authenticator nor flowAlias, skipping"
                    )
                    continue

                # Update requirement if execution was added successfully
                if execution_id and execution.requirement != "DISABLED":
                    await admin_client.update_execution_requirement(
                        realm_name,
                        flow_alias,
                        execution_id,
                        execution.requirement,
                        namespace,
                    )

            except Exception as e:
                self.logger.warning(
                    f"Failed to add execution to flow '{flow_alias}': {e}"
                )

    async def _sync_flow_executions(
        self,
        admin_client,
        realm_name: str,
        flow_alias: str,
        flow_config,
        namespace: str,
    ) -> None:
        """
        Synchronize executions for an existing flow.

        This updates execution requirements to match the desired state.
        Note: Adding/removing executions from existing flows is complex
        and not fully implemented - we only update requirements for now.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            flow_alias: Alias of the flow
            flow_config: Flow configuration with desired executions
            namespace: Origin namespace for rate limiting
        """
        if not flow_config.authentication_executions:
            return

        try:
            # Get current executions
            current_executions = await admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            # Build a map of current executions by provider ID or alias
            execution_map: dict[str, Any] = {}
            for ex in current_executions:
                key = ex.provider_id or ex.alias or ex.display_name
                if key:
                    execution_map[key] = ex

            # Update requirements for matching executions
            for desired_execution in flow_config.authentication_executions:
                # Find matching execution
                match_key = (
                    desired_execution.authenticator or desired_execution.flow_alias
                )
                if not match_key:
                    continue

                matching_execution = execution_map.get(match_key)
                if matching_execution and matching_execution.id:
                    # Check if requirement needs updating
                    if matching_execution.requirement != desired_execution.requirement:
                        self.logger.info(
                            f"Updating execution '{match_key}' requirement "
                            f"from '{matching_execution.requirement}' "
                            f"to '{desired_execution.requirement}'"
                        )
                        await admin_client.update_execution_requirement(
                            realm_name,
                            flow_alias,
                            matching_execution.id,
                            desired_execution.requirement,
                            namespace,
                        )
                else:
                    self.logger.debug(
                        f"Execution '{match_key}' not found in flow, skipping update"
                    )

        except Exception as e:
            self.logger.warning(
                f"Failed to sync executions for flow '{flow_alias}': {e}"
            )

    async def _configure_authenticator_configs(
        self,
        admin_client,
        realm_name: str,
        flow_alias: str,
        flow_config,
        namespace: str,
    ) -> None:
        """
        Configure authenticator configurations for executions in a flow.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            flow_alias: Alias of the flow
            flow_config: Flow configuration with authenticator configs
            namespace: Origin namespace for rate limiting
        """
        if not flow_config.authenticator_config:
            return

        try:
            # Get current executions to find which need configuration
            executions = await admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            # Build map of config alias to config
            config_map = {
                cfg.alias: cfg for cfg in flow_config.authenticator_config if cfg.alias
            }

            # Find executions that reference these configs
            for execution in flow_config.authentication_executions:
                if not execution.authenticator_config:
                    continue

                config_alias = execution.authenticator_config
                if config_alias not in config_map:
                    self.logger.warning(
                        f"Authenticator config '{config_alias}' referenced "
                        f"but not defined in authenticatorConfig list"
                    )
                    continue

                config = config_map[config_alias]

                # Find the execution for this authenticator
                found_execution = None
                for ex in executions:
                    if ex.provider_id == execution.authenticator:
                        found_execution = ex
                        break

                if not found_execution:
                    self.logger.warning(
                        f"Could not find execution for authenticator "
                        f"'{execution.authenticator}' to apply config"
                    )
                    continue

                exec_id = found_execution.id

                # Check if config already exists
                if found_execution.authentication_config:
                    # Update existing config
                    from keycloak_operator.models.keycloak_api import (
                        AuthenticatorConfigRepresentation,
                    )

                    config_repr = AuthenticatorConfigRepresentation(
                        id=found_execution.authentication_config,
                        alias=config.alias,
                        config=config.config,
                    )
                    await admin_client.update_authenticator_config(
                        realm_name,
                        found_execution.authentication_config,
                        config_repr,
                        namespace,
                    )
                else:
                    # Create new config
                    from keycloak_operator.models.keycloak_api import (
                        AuthenticatorConfigRepresentation,
                    )

                    config_repr = AuthenticatorConfigRepresentation(
                        alias=config.alias,
                        config=config.config,
                    )
                    await admin_client.create_authenticator_config(
                        realm_name,
                        exec_id,
                        config_repr,
                        namespace,
                    )

        except Exception as e:
            self.logger.warning(
                f"Failed to configure authenticator configs for flow '{flow_alias}': {e}"
            )

    async def configure_required_actions(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure required actions for the realm.

        Required actions are actions users must perform, such as:
        - CONFIGURE_TOTP: Set up two-factor authentication
        - VERIFY_EMAIL: Verify email address
        - UPDATE_PASSWORD: Change password
        - UPDATE_PROFILE: Update user profile

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring required actions for realm {spec.realm_name}")

        if not spec.required_actions:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        for action_config in spec.required_actions:
            try:
                action_alias = action_config.alias
                self.logger.info(f"Configuring required action '{action_alias}'")

                # Check if the action already exists
                existing_action = await admin_client.get_required_action(
                    realm_name, action_alias, namespace
                )

                if existing_action:
                    # Update existing action
                    from keycloak_operator.models.keycloak_api import (
                        RequiredActionProviderRepresentation,
                    )

                    action_repr = RequiredActionProviderRepresentation(
                        alias=action_alias,
                        name=action_config.name or existing_action.name,
                        provider_id=action_config.provider_id or action_alias,
                        enabled=action_config.enabled,
                        default_action=action_config.default_action,
                        priority=action_config.priority,
                        config=action_config.config or None,
                    )

                    success = await admin_client.update_required_action(
                        realm_name, action_alias, action_repr, namespace
                    )

                    if success:
                        self.logger.info(
                            f"Successfully updated required action '{action_alias}'"
                        )
                    else:
                        self.logger.warning(
                            f"Failed to update required action '{action_alias}'"
                        )
                else:
                    # Action doesn't exist - try to register it
                    self.logger.info(
                        f"Required action '{action_alias}' not found, "
                        f"attempting to register"
                    )

                    success = await admin_client.register_required_action(
                        realm_name,
                        action_config.provider_id or action_alias,
                        action_config.name or action_alias,
                        namespace,
                    )

                    if success:
                        # Now update the configuration
                        from keycloak_operator.models.keycloak_api import (
                            RequiredActionProviderRepresentation,
                        )

                        action_repr = RequiredActionProviderRepresentation(
                            alias=action_alias,
                            name=action_config.name,
                            provider_id=action_config.provider_id or action_alias,
                            enabled=action_config.enabled,
                            default_action=action_config.default_action,
                            priority=action_config.priority,
                            config=action_config.config or None,
                        )

                        await admin_client.update_required_action(
                            realm_name, action_alias, action_repr, namespace
                        )

                        self.logger.info(
                            f"Successfully registered required action '{action_alias}'"
                        )
                    else:
                        self.logger.warning(
                            f"Failed to register required action '{action_alias}'"
                        )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure required action '{action_config.alias}': {e}"
                )

    def _has_flow_bindings(self, spec: KeycloakRealmSpec) -> bool:
        """Check if the realm spec has any flow bindings configured."""
        return any(
            [
                spec.browser_flow,
                spec.registration_flow,
                spec.direct_grant_flow,
                spec.reset_credentials_flow,
                spec.client_authentication_flow,
                spec.docker_authentication_flow,
                spec.first_broker_login_flow,
            ]
        )

    async def apply_flow_bindings(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Apply authentication flow bindings to the realm.

        This must be called AFTER authentication flows are created,
        as flow bindings reference flows by alias.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Applying flow bindings for realm {spec.realm_name}")

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Build payload with only flow binding fields
        flow_binding_payload: dict[str, Any] = {"realm": realm_name}

        if spec.browser_flow:
            flow_binding_payload["browserFlow"] = spec.browser_flow
        if spec.registration_flow:
            flow_binding_payload["registrationFlow"] = spec.registration_flow
        if spec.direct_grant_flow:
            flow_binding_payload["directGrantFlow"] = spec.direct_grant_flow
        if spec.reset_credentials_flow:
            flow_binding_payload["resetCredentialsFlow"] = spec.reset_credentials_flow
        if spec.client_authentication_flow:
            flow_binding_payload["clientAuthenticationFlow"] = (
                spec.client_authentication_flow
            )
        if spec.docker_authentication_flow:
            flow_binding_payload["dockerAuthenticationFlow"] = (
                spec.docker_authentication_flow
            )
        if spec.first_broker_login_flow:
            flow_binding_payload["firstBrokerLoginFlow"] = spec.first_broker_login_flow

        try:
            await admin_client.update_realm(realm_name, flow_binding_payload, namespace)
            self.logger.info(
                f"Successfully applied flow bindings for realm {realm_name}"
            )
        except Exception as e:
            self.logger.warning(f"Failed to apply flow bindings: {e}")

    async def configure_identity_providers(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure external identity providers with full lifecycle management.

        This method:
        1. Creates new identity providers
        2. Updates existing identity providers
        3. Deletes identity providers removed from spec
        4. Manages IDP mappers for each identity provider

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring identity providers for realm {spec.realm_name}")

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        # Get existing IDPs from Keycloak
        existing_idps = await admin_client.get_identity_providers(
            spec.realm_name, namespace
        )
        existing_aliases = {idp.alias for idp in existing_idps if idp.alias}

        # Build set of desired aliases
        desired_aliases: set[str] = set()
        if spec.identity_providers:
            desired_aliases = {idp.alias for idp in spec.identity_providers}

        # Delete IDPs that are no longer in spec
        for alias in existing_aliases - desired_aliases:
            self.logger.info(
                f"Deleting identity provider '{alias}' from realm '{spec.realm_name}' "
                f"(no longer in spec)"
            )
            try:
                await admin_client.delete_identity_provider(
                    spec.realm_name, alias, namespace
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to delete identity provider '{alias}': {e}"
                )

        # Configure desired IDPs
        if not spec.identity_providers:
            return

        for idp_config in spec.identity_providers:
            try:
                from typing import cast

                idp_dict = cast(
                    dict[str, Any],
                    idp_config.model_dump()
                    if hasattr(idp_config, "model_dump")
                    else idp_config,
                )

                # Inject secrets from configSecrets into config
                if idp_config.config_secrets:
                    if "config" not in idp_dict:
                        idp_dict["config"] = {}

                    for config_key, secret_ref in idp_config.config_secrets.items():
                        secret_value = await self._fetch_secret_value(
                            namespace=namespace,
                            secret_name=secret_ref.name,
                            secret_key=secret_ref.key,
                        )
                        idp_dict["config"][config_key] = secret_value
                        self.logger.debug(
                            f"Injected secret value for IDP config key '{config_key}' "
                            f"from secret '{secret_ref.name}'"
                        )

                # Remove fields not part of Keycloak API
                idp_dict.pop("configSecrets", None)
                idp_dict.pop("config_secrets", None)
                idp_dict.pop("mappers", None)  # Mappers handled separately

                await admin_client.configure_identity_provider(
                    spec.realm_name, idp_dict, namespace
                )

                # Configure mappers for this IDP
                await self._configure_identity_provider_mappers(
                    admin_client=admin_client,
                    realm_name=spec.realm_name,
                    idp_alias=idp_config.alias,
                    desired_mappers=idp_config.mappers,
                    namespace=namespace,
                )

            except Exception as e:
                self.logger.warning(f"Failed to configure identity provider: {e}")

    async def _configure_identity_provider_mappers(
        self,
        admin_client: Any,
        realm_name: str,
        idp_alias: str,
        desired_mappers: list[Any],
        namespace: str,
    ) -> None:
        """
        Configure mappers for an identity provider with full lifecycle management.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            idp_alias: Identity provider alias
            desired_mappers: List of desired mapper configurations
            namespace: Origin namespace for rate limiting
        """
        # Get existing mappers from Keycloak
        existing_mappers = await admin_client.get_identity_provider_mappers(
            realm_name, idp_alias, namespace
        )

        # Build set of desired mapper names
        desired_mapper_names: set[str] = set()
        if desired_mappers:
            desired_mapper_names = {m.name for m in desired_mappers}

        # Delete mappers that are no longer in spec
        for mapper in existing_mappers:
            if mapper.name and mapper.name not in desired_mapper_names:
                self.logger.info(
                    f"Deleting mapper '{mapper.name}' from IDP '{idp_alias}' "
                    f"(no longer in spec)"
                )
                if mapper.id:
                    try:
                        await admin_client.delete_identity_provider_mapper(
                            realm_name, idp_alias, mapper.id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to delete mapper '{mapper.name}': {e}"
                        )

        # Configure desired mappers
        if not desired_mappers:
            return

        from keycloak_operator.models.keycloak_api import (
            IdentityProviderMapperRepresentation,
        )

        for mapper_config in desired_mappers:
            try:
                mapper_repr = IdentityProviderMapperRepresentation(
                    name=mapper_config.name,
                    identity_provider_alias=idp_alias,
                    identity_provider_mapper=mapper_config.identity_provider_mapper,
                    config=mapper_config.config,
                )
                await admin_client.configure_identity_provider_mapper(
                    realm_name, idp_alias, mapper_repr, namespace
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to configure mapper '{mapper_config.name}': {e}"
                )

    async def configure_user_federation(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure user federation (LDAP, Active Directory, etc.).

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring user federation for realm {spec.realm_name}")

        if not spec.user_federation:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        for federation_config in spec.user_federation:
            try:
                from typing import cast

                federation_dict = cast(
                    dict[str, Any],
                    federation_config.model_dump()
                    if hasattr(federation_config, "model_dump")
                    else federation_config,
                )
                admin_client.configure_user_federation(spec.realm_name, federation_dict)
            except Exception as e:
                self.logger.warning(f"Failed to configure user federation: {e}")

    async def configure_client_scopes(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure client scopes with full lifecycle management.

        This method:
        1. Creates new client scopes
        2. Updates existing client scopes
        3. Deletes client scopes removed from spec (except built-in scopes)
        4. Manages protocol mappers for each client scope

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring client scopes for realm {spec.realm_name}")

        if not spec.client_scopes:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Built-in Keycloak client scopes that should not be deleted
        BUILTIN_SCOPES = {
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "roles",
            "web-origins",
            "microprofile-jwt",
            "acr",
            "basic",
            "role_list",  # SAML scope
        }

        # Get existing client scopes from Keycloak
        existing_scopes = await admin_client.get_client_scopes(realm_name, namespace)
        existing_scope_names = {scope.name for scope in existing_scopes if scope.name}
        existing_scope_map = {
            scope.name: scope for scope in existing_scopes if scope.name
        }

        # Build set of desired scope names
        desired_scope_names = {scope.name for scope in spec.client_scopes}

        # Delete scopes that are no longer in spec (except built-in scopes)
        for scope_name in existing_scope_names - desired_scope_names:
            if scope_name in BUILTIN_SCOPES:
                self.logger.debug(f"Skipping built-in scope '{scope_name}'")
                continue

            existing_scope = existing_scope_map.get(scope_name)
            if existing_scope and existing_scope.id:
                self.logger.info(
                    f"Deleting client scope '{scope_name}' from realm '{realm_name}' "
                    f"(no longer in spec)"
                )
                try:
                    await admin_client.delete_client_scope(
                        realm_name, existing_scope.id, namespace
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to delete client scope '{scope_name}': {e}"
                    )

        # Create or update scopes
        for scope_config in spec.client_scopes:
            try:
                scope_name = scope_config.name

                # Check if scope exists
                existing_scope = existing_scope_map.get(scope_name)

                from keycloak_operator.models.keycloak_api import (
                    ClientScopeRepresentation,
                    ProtocolMapperRepresentation,
                )

                if existing_scope and existing_scope.id:
                    # Update existing scope
                    scope_repr = ClientScopeRepresentation(
                        id=existing_scope.id,
                        name=scope_name,
                        description=scope_config.description,
                        protocol=scope_config.protocol,
                        attributes=scope_config.attributes or {},
                    )
                    self.logger.info(f"Updating client scope '{scope_name}'")
                    await admin_client.update_client_scope(
                        realm_name, existing_scope.id, scope_repr, namespace
                    )

                    # Sync protocol mappers for existing scope
                    await self._sync_client_scope_protocol_mappers(
                        admin_client,
                        realm_name,
                        existing_scope.id,
                        scope_config.protocol_mappers,
                        namespace,
                    )
                else:
                    # Create new scope
                    scope_repr = ClientScopeRepresentation(
                        name=scope_name,
                        description=scope_config.description,
                        protocol=scope_config.protocol,
                        attributes=scope_config.attributes or {},
                    )
                    self.logger.info(f"Creating client scope '{scope_name}'")
                    scope_id = await admin_client.create_client_scope(
                        realm_name, scope_repr, namespace
                    )

                    # Add protocol mappers to new scope
                    if scope_id and scope_config.protocol_mappers:
                        for mapper_config in scope_config.protocol_mappers:
                            mapper_repr = ProtocolMapperRepresentation(
                                name=mapper_config.name,
                                protocol=mapper_config.protocol,
                                protocol_mapper=mapper_config.protocol_mapper,
                                config=mapper_config.config or {},
                            )
                            await admin_client.create_client_scope_protocol_mapper(
                                realm_name, scope_id, mapper_repr, namespace
                            )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure client scope '{scope_config.name}': {e}"
                )

    async def _sync_client_scope_protocol_mappers(
        self,
        admin_client,
        realm_name: str,
        scope_id: str,
        desired_mappers: list,
        namespace: str,
    ) -> None:
        """
        Synchronize protocol mappers for a client scope.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            scope_id: ID of the client scope
            desired_mappers: List of desired mapper configurations
            namespace: Origin namespace for rate limiting
        """
        from keycloak_operator.models.keycloak_api import ProtocolMapperRepresentation

        # Get current mappers
        current_mappers = await admin_client.get_client_scope_protocol_mappers(
            realm_name, scope_id, namespace
        )
        current_mapper_names = {m.name for m in current_mappers if m.name}
        current_mapper_map = {m.name: m for m in current_mappers if m.name}

        # Build set of desired mapper names
        desired_mapper_names = (
            {m.name for m in desired_mappers} if desired_mappers else set()
        )

        # Delete mappers no longer in spec
        for mapper_name in current_mapper_names - desired_mapper_names:
            mapper = current_mapper_map.get(mapper_name)
            if mapper and mapper.id:
                self.logger.info(f"Deleting protocol mapper '{mapper_name}' from scope")
                try:
                    await admin_client.delete_client_scope_protocol_mapper(
                        realm_name, scope_id, mapper.id, namespace
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to delete protocol mapper '{mapper_name}': {e}"
                    )

        # Create or update mappers
        if not desired_mappers:
            return

        for mapper_config in desired_mappers:
            try:
                mapper_name = mapper_config.name
                existing_mapper = current_mapper_map.get(mapper_name)

                mapper_repr = ProtocolMapperRepresentation(
                    name=mapper_name,
                    protocol=mapper_config.protocol,
                    protocol_mapper=mapper_config.protocol_mapper,
                    config=mapper_config.config or {},
                )

                if existing_mapper and existing_mapper.id:
                    # Update existing mapper
                    self.logger.info(f"Updating protocol mapper '{mapper_name}'")
                    await admin_client.update_client_scope_protocol_mapper(
                        realm_name, scope_id, existing_mapper.id, mapper_repr, namespace
                    )
                else:
                    # Create new mapper
                    self.logger.info(f"Creating protocol mapper '{mapper_name}'")
                    await admin_client.create_client_scope_protocol_mapper(
                        realm_name, scope_id, mapper_repr, namespace
                    )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure protocol mapper '{mapper_config.name}': {e}"
                )

    async def configure_realm_default_client_scopes(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure realm-level default and optional client scopes.

        Default scopes are automatically assigned to new clients.
        Optional scopes are available for clients to request.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(
            f"Configuring realm default/optional client scopes for {spec.realm_name}"
        )

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Get all client scopes to build name-to-id mapping
        all_scopes = await admin_client.get_client_scopes(realm_name, namespace)
        scope_name_to_id = {
            scope.name: scope.id for scope in all_scopes if scope.name and scope.id
        }

        # Configure default client scopes
        if spec.default_client_scopes:
            current_defaults = await admin_client.get_realm_default_client_scopes(
                realm_name, namespace
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
                    self.logger.info(f"Adding '{scope_name}' as realm default scope")
                    try:
                        await admin_client.add_realm_default_client_scope(
                            realm_name, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add default scope '{scope_name}': {e}"
                        )
                else:
                    self.logger.warning(
                        f"Client scope '{scope_name}' not found, cannot add as default"
                    )

            # Remove scopes no longer in default list
            for scope_name in current_default_names - desired_default_names:
                scope_id = current_default_map.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Removing '{scope_name}' from realm default scopes"
                    )
                    try:
                        await admin_client.remove_realm_default_client_scope(
                            realm_name, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to remove default scope '{scope_name}': {e}"
                        )

        # Configure optional client scopes
        if spec.optional_client_scopes:
            current_optionals = await admin_client.get_realm_optional_client_scopes(
                realm_name, namespace
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
                    self.logger.info(f"Adding '{scope_name}' as realm optional scope")
                    try:
                        await admin_client.add_realm_optional_client_scope(
                            realm_name, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to add optional scope '{scope_name}': {e}"
                        )
                else:
                    self.logger.warning(
                        f"Client scope '{scope_name}' not found, cannot add as optional"
                    )

            # Remove scopes no longer in optional list
            for scope_name in current_optional_names - desired_optional_names:
                scope_id = current_optional_map.get(scope_name)
                if scope_id:
                    self.logger.info(
                        f"Removing '{scope_name}' from realm optional scopes"
                    )
                    try:
                        await admin_client.remove_realm_optional_client_scope(
                            realm_name, scope_id, namespace
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to remove optional scope '{scope_name}': {e}"
                        )

    async def configure_realm_roles(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure realm-level roles with full lifecycle management.

        This method:
        1. Creates new realm roles
        2. Updates existing realm roles
        3. Deletes realm roles removed from spec (except built-in roles)
        4. Manages composite role memberships

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring realm roles for realm {spec.realm_name}")

        if not spec.roles or not spec.roles.realm_roles:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Built-in Keycloak roles that should not be deleted
        BUILTIN_ROLES = {
            "offline_access",
            "uma_authorization",
            "default-roles-" + realm_name.lower(),
        }

        # Get existing roles from Keycloak
        existing_roles = await admin_client.get_realm_roles(realm_name, namespace)
        existing_role_names = {role.name for role in existing_roles if role.name}

        # Build set of desired role names
        desired_role_names = {role.name for role in spec.roles.realm_roles}

        # Delete roles that are no longer in spec (except built-in roles)
        for role_name in existing_role_names - desired_role_names:
            if role_name in BUILTIN_ROLES or role_name.startswith("default-roles-"):
                self.logger.debug(f"Skipping built-in role '{role_name}'")
                continue

            self.logger.info(
                f"Deleting realm role '{role_name}' from realm '{realm_name}' "
                f"(no longer in spec)"
            )
            try:
                await admin_client.delete_realm_role(realm_name, role_name, namespace)
            except Exception as e:
                self.logger.warning(f"Failed to delete realm role '{role_name}': {e}")

        # Create or update roles
        for role_config in spec.roles.realm_roles:
            try:
                role_name = role_config.name

                # Check if role exists
                existing_role = await admin_client.get_realm_role_by_name(
                    realm_name, role_name, namespace
                )

                from keycloak_operator.models.keycloak_api import RoleRepresentation

                if existing_role:
                    # Update existing role - include id for Keycloak API
                    role_repr = RoleRepresentation(
                        id=existing_role.id,
                        name=role_name,
                        description=role_config.description,
                        composite=role_config.composite
                        or bool(role_config.composite_roles),
                        attributes=role_config.attributes,
                    )
                    self.logger.info(f"Updating realm role '{role_name}'")
                    await admin_client.update_realm_role(
                        realm_name, role_name, role_repr, namespace
                    )
                else:
                    # Create new role
                    role_repr = RoleRepresentation(
                        name=role_name,
                        description=role_config.description,
                        composite=role_config.composite
                        or bool(role_config.composite_roles),
                        attributes=role_config.attributes,
                    )
                    self.logger.info(f"Creating realm role '{role_name}'")
                    await admin_client.create_realm_role(
                        realm_name, role_repr, namespace
                    )

                # Handle composite roles
                if role_config.composite_roles:
                    await self._configure_composite_roles(
                        admin_client,
                        realm_name,
                        role_name,
                        role_config.composite_roles,
                        namespace,
                    )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure realm role '{role_config.name}': {e}"
                )

    async def _configure_composite_roles(
        self,
        admin_client: Any,
        realm_name: str,
        parent_role_name: str,
        desired_child_names: list[str],
        namespace: str,
    ) -> None:
        """
        Configure composite role memberships.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            parent_role_name: Name of the parent composite role
            desired_child_names: List of child role names to include
            namespace: Origin namespace for rate limiting
        """
        self.logger.info(
            f"Configuring composite role '{parent_role_name}' with "
            f"{len(desired_child_names)} child roles"
        )

        try:
            # Get current composites
            current_composites = await admin_client.get_realm_role_composites(
                realm_name, parent_role_name, namespace
            )
            current_child_names = {
                role.name for role in current_composites if role.name
            }

            # Determine roles to add and remove
            to_add = set(desired_child_names) - current_child_names
            to_remove = current_child_names - set(desired_child_names)

            # Add new composites
            if to_add:
                roles_to_add = []
                for child_name in to_add:
                    child_role = await admin_client.get_realm_role_by_name(
                        realm_name, child_name, namespace
                    )
                    if child_role:
                        roles_to_add.append(child_role)
                    else:
                        self.logger.warning(
                            f"Child role '{child_name}' not found, skipping"
                        )

                if roles_to_add:
                    await admin_client.add_realm_role_composites(
                        realm_name, parent_role_name, roles_to_add, namespace
                    )

            # Remove old composites
            if to_remove:
                roles_to_remove = [
                    role for role in current_composites if role.name in to_remove
                ]
                if roles_to_remove:
                    await admin_client.remove_realm_role_composites(
                        realm_name, parent_role_name, roles_to_remove, namespace
                    )

        except Exception as e:
            self.logger.warning(
                f"Failed to configure composite roles for '{parent_role_name}': {e}"
            )

    async def configure_groups(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure groups with full lifecycle management.

        This method:
        1. Creates new groups (including nested subgroups)
        2. Updates existing groups
        3. Deletes groups removed from spec
        4. Manages group role assignments (realm and client roles)

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring groups for realm {spec.realm_name}")

        if not spec.groups:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Get existing groups from Keycloak
        existing_groups = await admin_client.get_groups(realm_name, namespace)

        # Build map of existing groups by path/name
        existing_group_map: dict[str, Any] = {}
        self._build_group_map(existing_groups, existing_group_map)

        # Build set of desired group paths
        desired_group_paths: set[str] = set()
        self._collect_group_paths(spec.groups, desired_group_paths)

        # Delete groups that are no longer in spec
        for group_path, group_info in existing_group_map.items():
            if group_path not in desired_group_paths:
                self.logger.info(
                    f"Deleting group '{group_path}' from realm '{realm_name}' "
                    f"(no longer in spec)"
                )
                try:
                    await admin_client.delete_group(
                        realm_name, group_info["id"], namespace
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to delete group '{group_path}': {e}")

        # Create or update groups (top-level first, then subgroups)
        for group_config in spec.groups:
            await self._configure_group_recursive(
                admin_client,
                realm_name,
                group_config,
                parent_id=None,
                namespace=namespace,
            )

    def _build_group_map(
        self,
        groups: list[Any],
        group_map: dict[str, Any],
        parent_path: str = "",
    ) -> None:
        """Build a map of group paths to group info (including subgroups)."""
        for group in groups:
            path = group.path or f"{parent_path}/{group.name}"
            group_map[path] = {"id": group.id, "name": group.name, "group": group}
            if group.sub_groups:
                self._build_group_map(group.sub_groups, group_map, path)

    def _collect_group_paths(
        self, groups: list[Any], paths: set[str], parent_path: str = ""
    ) -> None:
        """Collect all group paths from the spec (including subgroups)."""
        for group in groups:
            path = group.path or f"{parent_path}/{group.name}"
            # Normalize path to start with /
            if not path.startswith("/"):
                path = "/" + path
            paths.add(path)
            if hasattr(group, "subgroups") and group.subgroups:
                self._collect_group_paths(group.subgroups, paths, path)

    async def _configure_group_recursive(
        self,
        admin_client: Any,
        realm_name: str,
        group_config: Any,
        parent_id: str | None,
        namespace: str,
        parent_path: str = "",
    ) -> str | None:
        """
        Configure a group and its subgroups recursively.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            group_config: Group configuration
            parent_id: ID of parent group (None for top-level)
            namespace: Origin namespace for rate limiting
            parent_path: Path of parent group

        Returns:
            Group ID if created/updated successfully, None otherwise
        """
        group_name = group_config.name
        group_path = group_config.path or f"{parent_path}/{group_name}"
        if not group_path.startswith("/"):
            group_path = "/" + group_path

        try:
            from keycloak_operator.models.keycloak_api import GroupRepresentation

            # Check if group exists
            existing_group = await admin_client.get_group_by_path(
                realm_name, group_path, namespace
            )

            group_id: str | None = None

            if existing_group:
                # Update existing group
                group_id = existing_group.id
                self.logger.info(f"Updating group '{group_path}'")
                # Include id in the update request - required by Keycloak API
                group_repr = GroupRepresentation(
                    id=group_id,
                    name=group_name,
                    path=group_path,
                    attributes=group_config.attributes or {},
                )
                await admin_client.update_group(
                    realm_name, group_id, group_repr, namespace
                )
            else:
                # Create new group
                group_repr = GroupRepresentation(
                    name=group_name,
                    path=group_path,
                    attributes=group_config.attributes or {},
                )
                self.logger.info(f"Creating group '{group_path}'")
                if parent_id:
                    group_id = await admin_client.create_subgroup(
                        realm_name, parent_id, group_repr, namespace
                    )
                else:
                    group_id = await admin_client.create_group(
                        realm_name, group_repr, namespace
                    )

            if not group_id:
                # Try to get the group if creation returned None (e.g., 409 conflict)
                existing_group = await admin_client.get_group_by_path(
                    realm_name, group_path, namespace
                )
                group_id = existing_group.id if existing_group else None

            if group_id:
                # Configure realm role mappings
                if group_config.realm_roles:
                    await self._configure_group_realm_roles(
                        admin_client,
                        realm_name,
                        group_id,
                        group_config.realm_roles,
                        namespace,
                    )

                # Configure client role mappings
                if group_config.client_roles:
                    await self._configure_group_client_roles(
                        admin_client,
                        realm_name,
                        group_id,
                        group_config.client_roles,
                        namespace,
                    )

                # Configure subgroups recursively
                if hasattr(group_config, "subgroups") and group_config.subgroups:
                    for subgroup in group_config.subgroups:
                        await self._configure_group_recursive(
                            admin_client,
                            realm_name,
                            subgroup,
                            parent_id=group_id,
                            namespace=namespace,
                            parent_path=group_path,
                        )

            return group_id

        except Exception as e:
            self.logger.warning(f"Failed to configure group '{group_path}': {e}")
            return None

    async def _configure_group_realm_roles(
        self,
        admin_client: Any,
        realm_name: str,
        group_id: str,
        desired_role_names: list[str],
        namespace: str,
    ) -> None:
        """
        Configure realm role assignments for a group.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            group_id: ID of the group
            desired_role_names: List of realm role names to assign
            namespace: Origin namespace for rate limiting
        """
        try:
            # Get current role mappings
            current_roles = await admin_client.get_group_realm_role_mappings(
                realm_name, group_id, namespace
            )
            current_role_names = {role.name for role in current_roles if role.name}

            # Determine roles to add and remove
            to_add = set(desired_role_names) - current_role_names
            to_remove = current_role_names - set(desired_role_names)

            # Add new role assignments
            if to_add:
                roles_to_add = []
                for role_name in to_add:
                    role = await admin_client.get_realm_role_by_name(
                        realm_name, role_name, namespace
                    )
                    if role:
                        roles_to_add.append(role)
                    else:
                        self.logger.warning(
                            f"Realm role '{role_name}' not found, skipping"
                        )

                if roles_to_add:
                    await admin_client.assign_realm_roles_to_group(
                        realm_name, group_id, roles_to_add, namespace
                    )

            # Remove old role assignments
            if to_remove:
                roles_to_remove = [
                    role for role in current_roles if role.name in to_remove
                ]
                if roles_to_remove:
                    await admin_client.remove_realm_roles_from_group(
                        realm_name, group_id, roles_to_remove, namespace
                    )

        except Exception as e:
            self.logger.warning(
                f"Failed to configure realm roles for group '{group_id}': {e}"
            )

    async def _configure_group_client_roles(
        self,
        admin_client: Any,
        realm_name: str,
        group_id: str,
        client_roles: dict[str, list[str]],
        namespace: str,
    ) -> None:
        """
        Configure client role assignments for a group.

        Args:
            admin_client: Keycloak admin client
            realm_name: Name of the realm
            group_id: ID of the group
            client_roles: Dict mapping client IDs to list of role names
            namespace: Origin namespace for rate limiting
        """
        for client_id, role_names in client_roles.items():
            try:
                # Get client UUID
                client_uuid = await admin_client.get_client_uuid(
                    realm_name, client_id, namespace
                )
                if not client_uuid:
                    self.logger.warning(
                        f"Client '{client_id}' not found, skipping role assignment"
                    )
                    continue

                # Get current role mappings
                current_roles = await admin_client.get_group_client_role_mappings(
                    realm_name, group_id, client_uuid, namespace
                )
                current_role_names = {role.name for role in current_roles if role.name}

                # Determine roles to add
                to_add = set(role_names) - current_role_names

                # Add new role assignments
                if to_add:
                    roles_to_add = []
                    for role_name in to_add:
                        role = await admin_client.get_client_role(
                            realm_name, client_uuid, role_name
                        )
                        if role:
                            roles_to_add.append(role)

                    if roles_to_add:
                        await admin_client.assign_client_roles_to_group(
                            realm_name, group_id, client_uuid, roles_to_add, namespace
                        )

            except Exception as e:
                self.logger.warning(
                    f"Failed to configure client roles for group '{group_id}' "
                    f"and client '{client_id}': {e}"
                )

    async def configure_default_groups(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure default groups for the realm.

        Default groups are automatically assigned to new users.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring default groups for realm {spec.realm_name}")

        if not spec.default_groups:
            return

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = spec.realm_name

        # Get current default groups
        current_defaults = await admin_client.get_default_groups(realm_name, namespace)
        current_default_paths = {
            group.path or f"/{group.name}" for group in current_defaults
        }

        # Normalize desired paths
        desired_default_paths: set[str] = set()
        for group_ref in spec.default_groups:
            # Handle both group names and paths
            if group_ref.startswith("/"):
                desired_default_paths.add(group_ref)
            else:
                desired_default_paths.add(f"/{group_ref}")

        # Determine groups to add and remove
        to_add = desired_default_paths - current_default_paths
        to_remove = current_default_paths - desired_default_paths

        # Add new default groups
        for group_path in to_add:
            try:
                group = await admin_client.get_group_by_path(
                    realm_name, group_path, namespace
                )
                if group and group.id:
                    await admin_client.add_default_group(
                        realm_name, group.id, namespace
                    )
                    self.logger.info(f"Added '{group_path}' as default group")
                else:
                    self.logger.warning(
                        f"Group '{group_path}' not found, cannot add as default"
                    )
            except Exception as e:
                self.logger.warning(f"Failed to add default group '{group_path}': {e}")

        # Remove old default groups
        for group_path in to_remove:
            try:
                # Find the group in current defaults
                for group in current_defaults:
                    current_path = group.path or f"/{group.name}"
                    if current_path == group_path and group.id:
                        await admin_client.remove_default_group(
                            realm_name, group.id, namespace
                        )
                        self.logger.info(f"Removed '{group_path}' from default groups")
                        break
            except Exception as e:
                self.logger.warning(
                    f"Failed to remove default group '{group_path}': {e}"
                )

    async def manage_realm_backup(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Manage realm backup operations based on spec configuration.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Managing backup for realm {spec.realm_name}")

        # Check if backup is requested
        backup_on_delete = getattr(spec, "backup_on_delete", False)
        periodic_backup = getattr(spec, "periodic_backup", False)

        if backup_on_delete:
            self.logger.info(f"Backup on delete is enabled for realm {spec.realm_name}")
            # Store metadata to track that backup is needed during deletion
            # This is handled in cleanup_resources method

        if periodic_backup:
            self.logger.info(f"Periodic backup is enabled for realm {spec.realm_name}")
            # Implement periodic backup logic
            await self._create_realm_backup(
                spec, name, namespace, backup_type="periodic"
            )

        self.logger.debug(f"Backup management configured for realm {spec.realm_name}")

    async def _create_realm_backup(
        self,
        spec: KeycloakRealmSpec,
        name: str,
        namespace: str,
        backup_type: str = "manual",
    ) -> dict[str, Any] | None:
        """
        Create a backup of the realm configuration.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
            backup_type: Type of backup (manual, periodic, deletion)

        Returns:
            Backup data dictionary or None if backup failed
        """
        from datetime import UTC, datetime

        from ..errors import TemporaryError

        self.logger.info(f"Creating {backup_type} backup of realm {spec.realm_name}")

        try:
            # Get admin client for the target Keycloak instance
            operator_ref = spec.operator_ref
            target_namespace = operator_ref.namespace
            keycloak_name = "keycloak"  # Default Keycloak instance name
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, target_namespace, rate_limiter=self.rate_limiter
            )

            # Create realm backup
            backup_data = await admin_client.backup_realm(spec.realm_name, namespace)
            if not backup_data:
                self.logger.error(
                    f"Failed to create backup data for realm {spec.realm_name}"
                )
                return None

            # Store backup in Kubernetes secret for persistence
            backup_name = f"{name}-backup-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
            await self._store_backup_in_secret(
                backup_data, backup_name, namespace, backup_type
            )

            self.logger.info(
                f"Successfully created backup {backup_name} for realm {spec.realm_name}"
            )
            return backup_data

        except Exception as e:
            self.logger.error(
                f"Failed to create backup for realm {spec.realm_name}: {e}"
            )
            if backup_type == "deletion":
                # Don't block deletion if backup fails, but log the error
                return None
            else:
                raise TemporaryError(f"Backup creation failed: {e}", delay=60) from e

    async def _store_backup_in_secret(
        self,
        backup_data: dict[str, Any],
        backup_name: str,
        namespace: str,
        backup_type: str,
    ) -> None:
        """
        Store backup data in a Kubernetes secret.

        Args:
            backup_data: Backup data to store
            backup_name: Name for the backup
            namespace: Namespace to store the secret
            backup_type: Type of backup
        """
        import json

        from kubernetes import client

        try:
            k8s_client = client.CoreV1Api()

            # Create secret with backup data
            secret_data = {"backup.json": json.dumps(backup_data, indent=2)}

            secret = client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=backup_name,
                    namespace=namespace,
                    labels={
                        "vriesdemichael.github.io/keycloak-backup": "true",
                        "vriesdemichael.github.io/keycloak-backup-type": backup_type,
                        "vriesdemichael.github.io/keycloak-realm": backup_data.get(
                            "realm", {}
                        ).get("realm", "unknown"),
                    },
                ),
                string_data=secret_data,
                type="Opaque",
            )

            k8s_client.create_namespaced_secret(namespace=namespace, body=secret)
            self.logger.info(
                f"Backup {backup_name} stored as secret in namespace {namespace}"
            )

        except Exception as e:
            self.logger.error(f"Failed to store backup {backup_name} in secret: {e}")
            raise

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
        Handle updates to Keycloak realm specifications.

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
        from typing import cast

        from ..errors import PermanentError

        self.logger.info(f"Updating KeycloakRealm {name} in namespace {namespace}")

        # Log changes for debugging
        for operation, field_path, old_value, new_value in diff:
            self.logger.info(
                f"KeycloakRealm change - {operation}: {field_path} "
                f"from {old_value} to {new_value}"
            )

        status.phase = "Updating"
        status.message = "Applying realm configuration changes"

        # Validate that immutable fields haven't changed
        old_realm_spec = self._validate_spec(old_spec)
        new_realm_spec = self._validate_spec(new_spec)

        # Check for changes to immutable fields
        if old_realm_spec.realm_name != new_realm_spec.realm_name:
            raise PermanentError("Cannot change realm_name of existing KeycloakRealm")

        if old_realm_spec.operator_ref != new_realm_spec.operator_ref:
            raise PermanentError("Cannot change operatorRef of existing KeycloakRealm")

        # Get admin client for the target Keycloak instance
        operator_ref = new_realm_spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = await self.keycloak_admin_factory(
            keycloak_name, target_namespace, rate_limiter=self.rate_limiter
        )

        realm_name = new_realm_spec.realm_name

        # Apply configuration updates based on the diff
        configuration_changed = False
        for _operation, field_path, _old_value, _new_value in diff:
            if field_path[:2] == ("spec", "themes"):
                self.logger.info("Updating realm themes")
                try:
                    if new_realm_spec.themes:
                        theme_config = {}
                        if (
                            hasattr(new_realm_spec.themes, "login_theme")
                            and new_realm_spec.themes.login_theme
                        ):
                            theme_config["login_theme"] = (
                                new_realm_spec.themes.login_theme
                            )
                        if (
                            hasattr(new_realm_spec.themes, "account_theme")
                            and new_realm_spec.themes.account_theme
                        ):
                            theme_config["account_theme"] = (
                                new_realm_spec.themes.account_theme
                            )
                        if (
                            hasattr(new_realm_spec.themes, "admin_theme")
                            and new_realm_spec.themes.admin_theme
                        ):
                            theme_config["admin_theme"] = (
                                new_realm_spec.themes.admin_theme
                            )
                        if (
                            hasattr(new_realm_spec.themes, "email_theme")
                            and new_realm_spec.themes.email_theme
                        ):
                            theme_config["email_theme"] = (
                                new_realm_spec.themes.email_theme
                            )

                        if theme_config:
                            await admin_client.update_realm_themes(
                                realm_name, theme_config, namespace
                            )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update themes: {e}")

            elif field_path[:2] == ("spec", "localization"):
                self.logger.info("Updating realm localization")
                try:
                    if new_realm_spec.localization:
                        self.logger.info(
                            f"Updated localization settings: {new_realm_spec.localization}"
                        )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update localization: {e}")

            elif field_path[:2] == ("spec", "authenticationFlows"):
                self.logger.info("Updating authentication flows")
                try:
                    # Use the full configure_authentication method which handles:
                    # - copyFrom logic for copying built-in flows
                    # - creating new flows with executions
                    # - updating existing flow executions
                    await self.configure_authentication(new_realm_spec, name, namespace)

                    # Also apply flow bindings if any are specified
                    if self._has_flow_bindings(new_realm_spec):
                        await self.apply_flow_bindings(new_realm_spec, name, namespace)

                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update authentication flows: {e}")

            elif field_path[:2] == ("spec", "identityProviders"):
                self.logger.info("Updating identity providers")
                try:
                    for idp_config in new_realm_spec.identity_providers or []:
                        idp_dict = cast(
                            dict[str, Any],
                            idp_config.model_dump()
                            if hasattr(idp_config, "model_dump")
                            else idp_config,
                        )

                        # Inject secrets from configSecrets into config
                        if idp_config.config_secrets:
                            if "config" not in idp_dict:
                                idp_dict["config"] = {}

                            for (
                                config_key,
                                secret_ref,
                            ) in idp_config.config_secrets.items():
                                secret_value = await self._fetch_secret_value(
                                    namespace=namespace,
                                    secret_name=secret_ref.name,
                                    secret_key=secret_ref.key,
                                )
                                idp_dict["config"][config_key] = secret_value

                        # Remove configSecrets from payload
                        idp_dict.pop("configSecrets", None)
                        idp_dict.pop("config_secrets", None)

                        await admin_client.configure_identity_provider(
                            realm_name, idp_dict, namespace
                        )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update identity providers: {e}")

            elif field_path[:2] == ("spec", "userFederation"):
                self.logger.info("Updating user federation")
                try:
                    await self.configure_user_federation(
                        new_realm_spec, name, namespace
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update user federation: {e}")

            elif field_path[:2] == ("spec", "clientScopes"):
                self.logger.info("Updating client scopes")
                try:
                    await self.configure_client_scopes(new_realm_spec, name, namespace)
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update client scopes: {e}")

            elif field_path[:2] == ("spec", "defaultClientScopes"):
                self.logger.info("Updating realm default client scopes")
                try:
                    await self.configure_realm_default_client_scopes(
                        new_realm_spec, name, namespace
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update default client scopes: {e}")

            elif field_path[:2] == ("spec", "optionalClientScopes"):
                self.logger.info("Updating realm optional client scopes")
                try:
                    await self.configure_realm_default_client_scopes(
                        new_realm_spec, name, namespace
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update optional client scopes: {e}")

            elif field_path[:2] == ("spec", "requiredActions"):
                self.logger.info("Updating required actions")
                try:
                    await self.configure_required_actions(
                        new_realm_spec, name, namespace
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update required actions: {e}")

            elif field_path[:2] == ("spec", "settings"):
                self.logger.info("Updating realm settings")
                try:
                    await admin_client.update_realm(
                        realm_name, new_realm_spec.to_keycloak_config(), namespace
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update realm settings: {e}")

            # Handle basic realm field updates (using camelCase as they appear in CRD)
            elif field_path[:2] in [
                ("spec", "displayName"),
                ("spec", "description"),
                ("spec", "loginPageTitle"),
                ("spec", "tokenSettings"),
                ("spec", "smtpServer"),
                ("spec", "browserFlow"),
                ("spec", "directGrantFlow"),
                ("spec", "registrationFlow"),
                ("spec", "resetCredentialsFlow"),
                ("spec", "clientAuthenticationFlow"),
                ("spec", "dockerAuthenticationFlow"),
                ("spec", "firstBrokerLoginFlow"),
                ("spec", "eventsConfig"),
                ("spec", "passwordPolicy"),
            ]:
                field_name = field_path[1] if len(field_path) > 1 else "unknown"
                self.logger.info(f"Updating realm field: {field_name}")
                try:
                    if field_name == "smtpServer":
                        # SMTP needs special handling for password injection
                        await self.ensure_realm_exists(
                            new_realm_spec, name, namespace, **kwargs
                        )
                    else:
                        # Regular field update
                        await admin_client.update_realm(
                            realm_name, new_realm_spec.to_keycloak_config(), namespace
                        )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update realm {field_name}: {e}")

            # Handle roles updates
            elif field_path[:2] == ("spec", "roles"):
                self.logger.info("Updating realm roles")
                try:
                    await self.configure_realm_roles(new_realm_spec, name, namespace)
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update realm roles: {e}")

            # Handle groups updates
            elif field_path[:2] == ("spec", "groups"):
                self.logger.info("Updating groups")
                try:
                    await self.configure_groups(new_realm_spec, name, namespace)
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update groups: {e}")

            # Handle default groups updates
            elif field_path[:2] == ("spec", "defaultGroups"):
                self.logger.info("Updating default groups")
                try:
                    await self.configure_default_groups(new_realm_spec, name, namespace)
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update default groups: {e}")

        if configuration_changed:
            self.logger.info(f"Successfully updated KeycloakRealm {name}")
            return {
                "phase": "Ready",
                "message": "Realm configuration updated successfully",
                "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
            }

        return None  # No changes needed

    async def check_resource_exists(
        self,
        name: str,
        namespace: str,
        spec: dict[str, Any],
        status: StatusProtocol,
    ) -> bool:
        """
        Check if realm resource actually exists in Keycloak.

        Args:
            name: Name of the KeycloakRealm resource
            namespace: Namespace containing the resource
            spec: Realm specification
            status: Resource status

        Returns:
            True if realm exists in Keycloak, False otherwise
        """
        realm_name = None
        target_namespace = None

        try:
            realm_spec = KeycloakRealmSpec.model_validate(spec)
            realm_name = realm_spec.realm_name
            target_namespace = realm_spec.operator_ref.namespace
        except Exception as e:
            self.logger.warning(f"Cannot parse spec to check resource existence: {e}")
            # Try to extract from raw dict
            realm_name = spec.get("realmName") or spec.get("realm_name")
            operator_ref = spec.get("operatorRef") or spec.get("operator_ref", {})
            target_namespace = operator_ref.get("namespace")

        if not realm_name or not target_namespace:
            self.logger.warning("Cannot determine realm name or namespace from spec")
            return False

        keycloak_name = "keycloak"  # Default Keycloak instance name

        try:
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, target_namespace, rate_limiter=self.rate_limiter
            )

            # Try to get realm
            existing_realm = await admin_client.get_realm(realm_name, namespace)

            if existing_realm:
                self.logger.info(f"Realm {realm_name} exists in Keycloak")
                return True
            else:
                self.logger.info(f"Realm {realm_name} does not exist in Keycloak")
                return False

        except Exception as e:
            self.logger.warning(
                f"Cannot verify if realm exists in Keycloak: {e}. "
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
        Clean up realm from Keycloak and associated Kubernetes resources.

        Args:
            name: Name of the KeycloakRealm resource
            namespace: Namespace containing the resource
            spec: Realm specification
            status: Resource status for tracking cleanup progress

        Raises:
            TemporaryError: If cleanup fails but should be retried
        """

        self.logger.info(f"Starting cleanup of KeycloakRealm {name} in {namespace}")

        # Try to parse spec, but fallback to raw dict extraction if validation fails
        # This ensures we can still clean up realms with invalid/outdated specs
        realm_spec = None
        realm_name = None
        target_namespace = None

        try:
            realm_spec = KeycloakRealmSpec.model_validate(spec)
            realm_name = realm_spec.realm_name
            target_namespace = realm_spec.operator_ref.namespace
        except Exception as e:
            self.logger.warning(
                f"Failed to parse KeycloakRealm spec during cleanup (spec may be invalid/outdated): {e}. "
                f"Attempting cleanup using raw spec dictionary..."
            )
            # Extract minimal required fields from raw spec dict
            realm_name = spec.get("realmName") or spec.get("realm_name")
            operator_ref = spec.get("operatorRef", {})
            target_namespace = operator_ref.get("namespace")

            if not realm_name or not target_namespace:
                self.logger.error(
                    f"Cannot extract realm name or target namespace from invalid spec. "
                    f"Spec keys: {list(spec.keys())}. Skipping Keycloak cleanup."
                )
                # Still return successfully - we can't do Keycloak cleanup, but we won't block deletion
                return

        # Get admin client for the target Keycloak instance

        # Delete realm from Keycloak (if instance still exists and we own it)
        try:
            keycloak_name = "keycloak"  # Default Keycloak instance name
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, target_namespace, rate_limiter=self.rate_limiter
            )

            # Check if realm exists in Keycloak
            existing_realm = await admin_client.get_realm(realm_name, namespace)

            if existing_realm is None:
                # Realm doesn't exist in Keycloak - nothing to delete
                self.logger.info(
                    f"Realm {realm_name} does not exist in Keycloak, "
                    f"skipping Keycloak cleanup"
                )
            else:
                # Realm exists - check ownership before deleting
                realm_attributes = (
                    existing_realm.attributes
                    if hasattr(existing_realm, "attributes")
                    else None
                )

                if not is_owned_by_cr(realm_attributes, namespace, name):
                    # This CR doesn't own the realm - don't delete it
                    owner_ref = get_cr_reference(realm_attributes)
                    if owner_ref:
                        owner_ns, owner_name = owner_ref
                        self.logger.warning(
                            f"Skipping deletion of realm {realm_name}: "
                            f"owned by {owner_ns}/{owner_name}, not by {namespace}/{name}"
                        )
                    else:
                        self.logger.warning(
                            f"Skipping deletion of realm {realm_name}: "
                            f"no ownership attributes found (unmanaged resource)"
                        )
                else:
                    # This CR owns the realm - proceed with deletion
                    self.logger.info(
                        f"Realm {realm_name} is owned by {namespace}/{name}, "
                        f"proceeding with deletion"
                    )

                    # Backup realm data if requested (only if spec parsed successfully)
                    if realm_spec and getattr(realm_spec, "backup_on_delete", False):
                        self.logger.info(
                            f"Backing up realm {realm_name} before deletion"
                        )
                        try:
                            await self._create_realm_backup(
                                realm_spec, name, namespace, backup_type="deletion"
                            )
                        except Exception as e:
                            self.logger.warning(f"Realm backup failed: {e}")

                    # Delete the realm from Keycloak
                    # Keycloak automatically cascade-deletes all clients, scopes, etc.
                    # within the realm - no need to delete them individually
                    await admin_client.delete_realm(realm_name, namespace)
                    self.logger.info(
                        f"Deleted realm {realm_name} from Keycloak "
                        f"(Keycloak cascade-deleted all child resources)",
                        extra={
                            "resource_type": "realm",
                            "resource_name": name,
                            "namespace": namespace,
                            "cleanup_phase": "keycloak_realm_deleted",
                        },
                    )

            # Trigger deletion of KeycloakClient CRs that reference this realm.
            # Since the realm is now deleted from Keycloak, the client delete handlers
            # will find their resources already gone and will:
            # 1. Skip Keycloak cleanup (check_resource_exists returns False)
            # 2. Clean up K8s resources (credentials secrets, configmaps)
            # 3. Remove their finalizers
            # We just trigger the delete - don't force-remove finalizers.
            try:
                custom_api = client.CustomObjectsApi(self.k8s_client)
                clients = await asyncio.to_thread(
                    custom_api.list_namespaced_custom_object,
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                )
                for client_cr in clients.get("items", []):
                    client_spec_dict = client_cr.get("spec", {})
                    realm_ref = client_spec_dict.get("realmRef", {})
                    # Check if this client references the realm being deleted
                    if (
                        realm_ref.get("name") == realm_name
                        and realm_ref.get("namespace") == namespace
                    ):
                        client_cr_name = client_cr["metadata"]["name"]
                        client_meta = client_cr.get("metadata", {})

                        # Check if client is already being deleted
                        deletion_timestamp = client_meta.get("deletionTimestamp")
                        if deletion_timestamp:
                            self.logger.info(
                                f"Cascading delete: KeycloakClient CR {client_cr_name} "
                                f"already being deleted, skipping",
                                extra={
                                    "resource_type": "client",
                                    "resource_name": client_cr_name,
                                    "namespace": namespace,
                                    "cleanup_phase": "skipped_already_deleting",
                                },
                            )
                            continue

                        self.logger.info(
                            f"Cascading delete: Triggering deletion of KeycloakClient CR "
                            f"{client_cr_name} (realm {realm_name} already deleted)",
                            extra={
                                "resource_type": "client",
                                "resource_name": client_cr_name,
                                "namespace": namespace,
                                "cleanup_phase": "cascade_delete_triggered",
                            },
                        )
                        try:
                            # Just delete the CR - let the client's delete handler
                            # do its cleanup (it will find the client gone from Keycloak
                            # and proceed to clean up K8s resources)
                            await asyncio.to_thread(
                                custom_api.delete_namespaced_custom_object,
                                group="vriesdemichael.github.io",
                                version="v1",
                                namespace=namespace,
                                plural="keycloakclients",
                                name=client_cr_name,
                            )
                        except Exception as delete_error:
                            self.logger.warning(
                                f"Failed to trigger deletion of KeycloakClient CR "
                                f"{client_cr_name}: {delete_error}",
                                extra={
                                    "resource_type": "client",
                                    "resource_name": client_cr_name,
                                    "namespace": namespace,
                                    "error_type": type(delete_error).__name__,
                                    "cleanup_phase": "cascade_delete_failed",
                                },
                            )
            except Exception as e:
                self.logger.warning(
                    f"Failed to cascade delete KeycloakClient CRs: {e}",
                    extra={
                        "resource_type": "realm",
                        "resource_name": name,
                        "namespace": namespace,
                        "error_type": type(e).__name__,
                        "cleanup_phase": "cascade_delete_error",
                    },
                )

        except Exception as e:
            self.logger.warning(
                f"Could not delete realm from Keycloak (instance may be deleted): {e}",
                extra={
                    "resource_type": "realm",
                    "resource_name": name,
                    "namespace": namespace,
                    "error_type": type(e).__name__,
                    "cleanup_phase": "keycloak_cleanup_warning",
                },
            )

        # Clean up Kubernetes resources associated with this realm
        self.log_cleanup_step(
            "Cleaning up K8s resources",
            resource_type="realm",
            name=name,
            namespace=namespace,
        )
        try:
            await self._delete_realm_k8s_resources(name, namespace, realm_name)
        except Exception as e:
            self.logger.warning(
                f"Failed to clean up Kubernetes resources: {e}",
                extra={
                    "resource_type": "realm",
                    "resource_name": name,
                    "namespace": namespace,
                    "error_type": type(e).__name__,
                    "cleanup_phase": "k8s_cleanup_warning",
                },
            )

        self.logger.info(
            f"Successfully completed cleanup of KeycloakRealm {name}",
            extra={
                "resource_type": "realm",
                "resource_name": name,
                "namespace": namespace,
                "cleanup_phase": "cleanup_completed",
            },
        )

    async def _create_realm_backup(
        self,
        name: str,
        namespace: str,
        realm_spec: KeycloakRealmSpec,
        admin_client,
    ) -> None:
        """Create a backup of realm data before deletion."""
        import json
        from datetime import UTC, datetime

        try:
            # Export realm configuration
            backup_data = admin_client.export_realm(realm_spec.realm_name)
            if not backup_data:
                self.logger.warning(
                    f"No backup data retrieved for realm {realm_spec.realm_name}"
                )
                return

            # Create backup configmap
            core_api = client.CoreV1Api(self.kubernetes_client)
            backup_name = (
                f"{name}-realm-backup-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
            )

            backup_cm = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(
                    name=backup_name,
                    namespace=namespace,
                    labels={
                        "vriesdemichael.github.io/keycloak-realm": realm_spec.realm_name,
                        "vriesdemichael.github.io/keycloak-backup": "true",
                        "vriesdemichael.github.io/keycloak-resource": name,
                    },
                ),
                data={
                    "realm-backup.json": json.dumps(backup_data, indent=2),
                    "backup-timestamp": datetime.now(UTC).isoformat(),
                    "realm-name": realm_spec.realm_name,
                },
            )

            core_api.create_namespaced_config_map(namespace=namespace, body=backup_cm)
            self.logger.info(f"Realm backup stored in configmap {backup_name}")

        except Exception as e:
            self.logger.warning(f"Failed to create realm backup: {e}")
            # Continue with deletion even if backup fails

    async def _delete_realm_k8s_resources(
        self, name: str, namespace: str, realm_name: str
    ) -> None:
        """Delete Kubernetes resources associated with the realm."""

        core_api = client.CoreV1Api(self.kubernetes_client)

        # Delete configmaps related to this realm (except backups)
        try:
            configmaps = core_api.list_namespaced_config_map(
                namespace=namespace,
                label_selector=f"vriesdemichael.github.io/keycloak-realm={realm_name},vriesdemichael.github.io/keycloak-backup!=true",
            )
            for cm in configmaps.items:
                try:
                    core_api.delete_namespaced_config_map(
                        name=cm.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted realm configmap {cm.metadata.name}")
                except Exception as e:
                    self.logger.warning(
                        f"Failed to delete configmap {cm.metadata.name}: {e}"
                    )

        except Exception as e:
            self.logger.warning(f"Failed to list realm configmaps for cleanup: {e}")

        # Delete secrets related to this realm (except client credentials managed separately)
        try:
            secrets = core_api.list_namespaced_secret(
                namespace=namespace,
                label_selector=f"vriesdemichael.github.io/keycloak-realm={realm_name},vriesdemichael.github.io/keycloak-secret-type!=client-credentials",
            )
            for secret in secrets.items:
                try:
                    core_api.delete_namespaced_secret(
                        name=secret.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted realm secret {secret.metadata.name}")
                except Exception as e:
                    self.logger.warning(
                        f"Failed to delete secret {secret.metadata.name}: {e}"
                    )

        except Exception as e:
            self.logger.warning(f"Failed to list realm secrets for cleanup: {e}")
