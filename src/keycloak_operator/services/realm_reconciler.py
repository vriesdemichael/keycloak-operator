"""
Keycloak realm reconciler for managing realm configuration and features.

This module handles the lifecycle of Keycloak realms including
themes, authentication flows, identity providers, and user federation.
"""

import json
from typing import Any

from kubernetes import client

from ..errors import ValidationError
from ..models.realm import KeycloakRealmSpec
from ..utils.keycloak_admin import KeycloakAdminError, get_keycloak_admin_client
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

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        # Update status to ready
        self.update_status_ready(status, "Realm configured and ready", generation)

        # Set additional status fields via StatusWrapper to avoid conflicts with Kopf
        status.realm_name = realm_spec.realm_name
        status.keycloak_instance = f"{target_namespace}/{keycloak_ref.name}"
        status.endpoints = endpoints
        status.features = {
            "themes": bool(realm_spec.themes),
            "localization": bool(realm_spec.localization),
            "customAuthFlows": bool(realm_spec.authentication_flows),
            "identityProviders": len(realm_spec.identity_providers or []),
            "userFederation": len(realm_spec.user_federation or []),
        }

        # Return empty dict - status updates are done via StatusWrapper
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

    async def _fetch_smtp_password(
        self, namespace: str, secret_name: str, secret_key: str = "password"
    ) -> str:
        """
        Fetch SMTP password from Kubernetes secret.

        Args:
            namespace: Namespace containing the secret
            secret_name: Name of the secret
            secret_key: Key in secret data (default: password)

        Returns:
            Decoded password string

        Raises:
            ValidationError: If secret not found or key missing
        """
        import base64

        try:
            core_api = client.CoreV1Api(self.k8s_client)
            secret = core_api.read_namespaced_secret(
                name=secret_name, namespace=namespace
            )

            if secret_key not in secret.data:
                raise ValidationError(
                    f"Key '{secret_key}' not found in secret '{secret_name}'"
                )

            password = base64.b64decode(secret.data[secret_key]).decode("utf-8")
            self.logger.debug(
                f"Successfully fetched SMTP password from secret {secret_name}"
            )
            return password

        except client.ApiException as e:
            if e.status == 404:
                raise ValidationError(
                    f"SMTP password secret '{secret_name}' not found in namespace '{namespace}'"
                ) from e
            else:
                raise ValidationError(
                    f"Failed to fetch SMTP password from secret '{secret_name}': {e}"
                ) from e
        except Exception as e:
            raise ValidationError(
                f"Failed to decode SMTP password from secret '{secret_name}': {e}"
            ) from e

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
        realm_payload = spec.to_keycloak_config()

        # Inject SMTP password from secret if configured
        if spec.smtp_server:
            if spec.smtp_server.password_secret:
                # Fetch password from Kubernetes secret
                password = await self._fetch_smtp_password(
                    namespace=namespace,
                    secret_name=spec.smtp_server.password_secret.name,
                    secret_key=spec.smtp_server.password_secret.key,
                )
                if "smtpServer" not in realm_payload:
                    realm_payload["smtpServer"] = {}
                realm_payload["smtpServer"]["password"] = password
                self.logger.debug(
                    "Injected SMTP password from secret into realm config"
                )
            elif spec.smtp_server.password:
                # Direct password (discouraged but supported)
                if "smtpServer" not in realm_payload:
                    realm_payload["smtpServer"] = {}
                realm_payload["smtpServer"]["password"] = spec.smtp_server.password
                self.logger.warning(
                    "Using direct SMTP password from spec. "
                    "Consider using password_secret for better security."
                )

        payload_json = json.dumps(realm_payload, default=str)
        payload_preview = (
            payload_json
            if len(payload_json) <= 2048
            else f"{payload_json[:2048]}...<truncated>"
        )

        self.logger.debug(
            "Prepared realm configuration for apply",
            keycloak_instance=keycloak_name,
            realm_name=realm_name,
            payload_preview=payload_preview,
        )

        try:
            existing_realm = admin_client.get_realm(realm_name)
        except KeycloakAdminError as exc:
            if getattr(exc, "status_code", None) == 404:
                self.logger.info("Realm %s not found, creating new realm", realm_name)
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
            self.logger.info(
                f"Realm {realm_name} already exists, updating...",
                keycloak_instance=keycloak_name,
                realm_name=realm_name,
            )
            try:
                admin_client.update_realm(realm_name, realm_payload)
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
            self.logger.info(
                f"Creating new realm {realm_name}",
                keycloak_instance=keycloak_name,
                realm_name=realm_name,
            )
            try:
                admin_client.create_realm(realm_payload)
            except KeycloakAdminError as exc:
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
            keycloak_ref = spec.keycloak_instance_ref
            target_namespace = keycloak_ref.namespace or namespace
            admin_client = self.keycloak_admin_factory(
                keycloak_ref.name, target_namespace
            )

            # Create realm backup
            backup_data = admin_client.backup_realm(spec.realm_name)
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
                        "keycloak.mdvr.nl/backup": "true",
                        "keycloak.mdvr.nl/backup-type": backup_type,
                        "keycloak.mdvr.nl/realm": backup_data.get("realm", {}).get(
                            "realm", "unknown"
                        ),
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
        from ..errors import TemporaryError

        self.logger.info(f"Starting cleanup of KeycloakRealm {name} in {namespace}")

        try:
            realm_spec = KeycloakRealmSpec.model_validate(spec)
        except Exception as e:
            raise TemporaryError(f"Failed to parse KeycloakRealm spec: {e}") from e

        # Get admin client for the target Keycloak instance
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        # Delete realm from Keycloak (if instance still exists)
        try:
            admin_client = self.keycloak_admin_factory(
                keycloak_ref.name, target_namespace
            )

            # Backup realm data if requested
            if getattr(realm_spec, "backup_on_delete", False):
                self.logger.info(
                    f"Backing up realm {realm_spec.realm_name} before deletion"
                )
                try:
                    await self._create_realm_backup(
                        realm_spec, name, namespace, backup_type="deletion"
                    )
                except Exception as e:
                    self.logger.warning(f"Realm backup failed: {e}")

            # Clean up all clients in this realm first
            try:
                realm_clients = admin_client.get_realm_clients(realm_spec.realm_name)
                for client_config in realm_clients:
                    client_id = client_config.get("clientId")
                    if client_id:
                        self.logger.info(
                            f"Cleaning up client {client_id} from realm {realm_spec.realm_name}"
                        )
                        admin_client.delete_client(client_id, realm_spec.realm_name)
            except Exception as e:
                self.logger.warning(f"Failed to clean up realm clients: {e}")

            # Delete the realm itself
            admin_client.delete_realm(realm_spec.realm_name)
            self.logger.info(f"Deleted realm {realm_spec.realm_name} from Keycloak")

        except Exception as e:
            self.logger.warning(
                f"Could not delete realm from Keycloak (instance may be deleted): {e}"
            )

        # Clean up Kubernetes resources associated with this realm
        try:
            await self._delete_realm_k8s_resources(name, namespace, realm_spec)
        except Exception as e:
            self.logger.warning(f"Failed to clean up Kubernetes resources: {e}")

        self.logger.info(f"Successfully completed cleanup of KeycloakRealm {name}")

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
                        "keycloak.mdvr.nl/realm": realm_spec.realm_name,
                        "keycloak.mdvr.nl/backup": "true",
                        "keycloak.mdvr.nl/resource": name,
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
        self, name: str, namespace: str, realm_spec: KeycloakRealmSpec
    ) -> None:
        """Delete Kubernetes resources associated with the realm."""

        core_api = client.CoreV1Api(self.kubernetes_client)

        # Delete configmaps related to this realm (except backups)
        try:
            configmaps = core_api.list_namespaced_config_map(
                namespace=namespace,
                label_selector=f"keycloak.mdvr.nl/realm={realm_spec.realm_name},keycloak.mdvr.nl/backup!=true",
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
                label_selector=f"keycloak.mdvr.nl/realm={realm_spec.realm_name},keycloak.mdvr.nl/secret-type!=client-credentials",
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
