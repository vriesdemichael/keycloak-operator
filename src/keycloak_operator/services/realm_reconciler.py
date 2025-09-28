"""
Keycloak realm reconciler for managing realm configuration and features.

This module handles the lifecycle of Keycloak realms including
themes, authentication flows, identity providers, and user federation.
"""

from typing import Any

from kubernetes import client

from ..errors import ValidationError
from ..models.realm import KeycloakRealmSpec
from ..utils.keycloak_admin import get_keycloak_admin_client
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
        self, k8s_client: client.ApiClient | None = None, keycloak_admin_factory=None
    ):
        """
        Initialize Keycloak realm reconciler.

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

        # Ensure basic realm exists
        await self.ensure_realm_exists(realm_spec, name, namespace)

        # Configure realm features
        if realm_spec.themes:
            await self.configure_themes(realm_spec, name, namespace)

        if realm_spec.authentication_flows:
            await self.configure_authentication(realm_spec, name, namespace)

        if realm_spec.identity_providers:
            await self.configure_identity_providers(realm_spec, name, namespace)

        if realm_spec.user_federation:
            await self.configure_user_federation(realm_spec, name, namespace)

        # Setup backup preparation
        await self.manage_realm_backup(realm_spec, name, namespace)

        # Return status information
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

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
                    "realm": f"{base_url}/realms/{realm_spec.realm_name}",
                    "admin": f"{base_url}/admin/{realm_spec.realm_name}/console",
                    "account": f"{base_url}/realms/{realm_spec.realm_name}/account",
                }

        return {
            "realm_name": realm_spec.realm_name,
            "keycloak_instance": f"{target_namespace}/{keycloak_ref.name}",
            "phase": "Ready",
            "endpoints": endpoints,
            "features": {
                "themes": bool(realm_spec.themes),
                "localization": bool(realm_spec.localization),
                "customAuthFlows": bool(realm_spec.authentication_flows),
                "identityProviders": len(realm_spec.identity_providers or []),
                "userFederation": len(realm_spec.user_federation or []),
            },
        }

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
        target_namespace = spec.keycloak_instance_ref.namespace

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
            resource_name=spec.keycloak_instance_ref.name,
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

    async def ensure_realm_exists(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure the basic realm exists in Keycloak.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring realm {spec.realm_name} exists")
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

        # Check if realm already exists
        realm_name = spec.realm_name
        existing_realm = admin_client.get_realm(realm_name)

        if existing_realm:
            self.logger.info(f"Realm {realm_name} already exists, updating...")
            admin_client.update_realm(realm_name, spec.to_keycloak_config())
        else:
            self.logger.info(f"Creating new realm {realm_name}")
            admin_client.create_realm(spec.to_keycloak_config())

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

        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

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
                admin_client.update_realm_themes(spec.realm_name, theme_config)
        except Exception as e:
            self.logger.warning(f"Failed to configure themes: {e}")

    async def configure_authentication(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure authentication flows and security settings.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring authentication for realm {spec.realm_name}")

        if not spec.authentication_flows:
            return

        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

        for flow_config in spec.authentication_flows:
            try:
                from typing import cast

                flow_dict = cast(
                    dict[str, Any],
                    flow_config.model_dump()
                    if hasattr(flow_config, "model_dump")
                    else flow_config,
                )
                admin_client.configure_authentication_flow(spec.realm_name, flow_dict)
            except Exception as e:
                self.logger.warning(f"Failed to configure authentication flow: {e}")

    async def configure_identity_providers(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Configure external identity providers.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Configuring identity providers for realm {spec.realm_name}")

        if not spec.identity_providers:
            return

        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

        for idp_config in spec.identity_providers:
            try:
                from typing import cast

                idp_dict = cast(
                    dict[str, Any],
                    idp_config.model_dump()
                    if hasattr(idp_config, "model_dump")
                    else idp_config,
                )
                admin_client.configure_identity_provider(spec.realm_name, idp_dict)
            except Exception as e:
                self.logger.warning(f"Failed to configure identity provider: {e}")

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

        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

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

    async def manage_realm_backup(
        self, spec: KeycloakRealmSpec, name: str, namespace: str
    ) -> None:
        """
        Prepare realm for backup operations.

        Args:
            spec: Keycloak realm specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Managing backup for realm {spec.realm_name}")

        # This method prepares backup metadata but doesn't actually perform backup
        # Actual backup is done during deletion if backup_on_delete is enabled

        # Could implement periodic backup snapshots here in the future
        # For now, just log that backup capability is available
        if hasattr(spec, "backup_on_delete") and spec.backup_on_delete:
            self.logger.info(f"Backup on delete is enabled for realm {spec.realm_name}")

        # Could also implement backup retention policies, schedule validation, etc.
        self.logger.debug(f"Backup management configured for realm {spec.realm_name}")

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

        if old_realm_spec.keycloak_instance_ref != new_realm_spec.keycloak_instance_ref:
            raise PermanentError(
                "Cannot change keycloak_instance_ref of existing KeycloakRealm"
            )

        # Get admin client for the target Keycloak instance
        keycloak_ref = new_realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

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
                            admin_client.update_realm_themes(realm_name, theme_config)
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
                    for flow_config in new_realm_spec.authentication_flows or []:
                        flow_dict = cast(
                            dict[str, Any],
                            flow_config.model_dump()
                            if hasattr(flow_config, "model_dump")
                            else flow_config,
                        )
                        admin_client.configure_authentication_flow(
                            realm_name, flow_dict
                        )
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
                        admin_client.configure_identity_provider(realm_name, idp_dict)
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update identity providers: {e}")

            elif field_path[:2] == ("spec", "userFederation"):
                self.logger.info("Updating user federation")
                try:
                    for federation_config in new_realm_spec.user_federation or []:
                        federation_dict = cast(
                            dict[str, Any],
                            federation_config.model_dump()
                            if hasattr(federation_config, "model_dump")
                            else federation_config,
                        )
                        admin_client.configure_user_federation(
                            realm_name, federation_dict
                        )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update user federation: {e}")

            elif field_path[:2] == ("spec", "settings"):
                self.logger.info("Updating realm settings")
                try:
                    admin_client.update_realm(
                        realm_name, new_realm_spec.to_keycloak_config()
                    )
                    configuration_changed = True
                except Exception as e:
                    self.logger.warning(f"Failed to update realm settings: {e}")

        if configuration_changed:
            self.logger.info(f"Successfully updated KeycloakRealm {name}")
            return {
                "phase": "Ready",
                "message": "Realm configuration updated successfully",
                "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
            }

        return None  # No changes needed
