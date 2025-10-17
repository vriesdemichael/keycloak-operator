"""
Keycloak realm reconciler for managing realm configuration and features.

This module handles the lifecycle of Keycloak realms including
themes, authentication flows, identity providers, and user federation.
"""

import json
import os
from typing import Any

from kubernetes import client
from pykube import HTTPClient

from ..errors import ValidationError
from ..models.realm import KeycloakRealmSpec
from ..utils.keycloak_admin import KeycloakAdminError, get_keycloak_admin_client
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

        # Generate/retrieve realm authorization token
        owner_uid = kwargs.get("uid", "")
        realm_auth_secret_name = await self.ensure_realm_authorization_secret(
            realm_name=realm_spec.realm_name,
            realm_cr_name=name,
            namespace=namespace,
            owner_uid=owner_uid,
        )

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
        operator_ref = realm_spec.operator_ref
        target_namespace = operator_ref.namespace

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        # Set custom status fields using attribute assignment (camelCase as in CRD)
        # IMPORTANT: Use attribute assignment, not item assignment!
        # Kopf StatusWrapper supports status.camelCase = value
        status.realmName = realm_spec.realm_name
        status.keycloakInstance = f"{target_namespace}/keycloak"
        status.authorizationSecretName = realm_auth_secret_name
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
        }
        # TODO: Add OIDC endpoint discovery (issuer, auth, token, userinfo, jwks, endSession, registration)

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

    async def _fetch_smtp_password(
        self, namespace: str, secret_name: str, secret_key: str = "password"
    ) -> str:
        """
        Fetch SMTP password from Kubernetes secret with RBAC validation.

        This method enforces namespace access control and secret labeling requirements.
        The secret must:
        1. Be accessible via RoleBinding granting operator access to the namespace
        2. Have the label: keycloak.mdvr.nl/allow-operator-read=true

        Args:
            namespace: Namespace containing the secret
            secret_name: Name of the secret
            secret_key: Key in secret data (default: password)

        Returns:
            Decoded password string

        Raises:
            ValidationError: If RBAC validation fails, secret not found, or key missing
        """
        try:
            # Get operator namespace from environment
            operator_namespace = os.getenv("OPERATOR_NAMESPACE", "keycloak-system")

            # Create pykube HTTPClient from kubernetes client
            api = HTTPClient(config=self.k8s_client.configuration)

            # Validate RBAC and read secret
            result, error = await get_secret_with_validation(
                api=api,
                secret_name=secret_name,
                namespace=namespace,
                operator_namespace=operator_namespace,
                key=secret_key,
            )

            if error:
                raise ValidationError(error)

            if result is None or not isinstance(result, str):
                raise ValidationError(
                    f"Key '{secret_key}' not found in secret '{secret_name}' or invalid value type"
                )

            password = result

            self.logger.debug(
                f"Successfully fetched SMTP password from secret {secret_name} "
                f"in namespace {namespace} with RBAC validation"
            )
            return password

        except ValidationError:
            # Re-raise validation errors as-is
            raise
        except Exception as e:
            raise ValidationError(
                f"Failed to fetch SMTP password from secret '{secret_name}' "
                f"in namespace '{namespace}': {e}"
            ) from e

    async def ensure_realm_authorization_secret(
        self, realm_name: str, realm_cr_name: str, namespace: str, owner_uid: str
    ) -> str:
        """
        Generate or retrieve authorization secret for this realm.

        Creates a Kubernetes secret containing a secure token that will be used
        by clients to authenticate their requests to manage resources within this realm.

        The secret has an owner reference to the realm resource for automatic cleanup.

        Args:
            realm_name: Name of the realm (used in secret name)
            realm_cr_name: Name of the realm CR (used in owner reference)
            namespace: Namespace to create the secret in
            owner_uid: UID of the realm resource (for owner reference)

        Returns:
            Name of the secret containing the realm authorization token

        Raises:
            ValidationError: If secret creation fails
        """
        import base64

        from ..utils.auth import generate_token

        secret_name = f"{realm_name}-realm-auth"

        # Check if secret already exists
        core_api = client.CoreV1Api(self.k8s_client)
        try:
            core_api.read_namespaced_secret(name=secret_name, namespace=namespace)
            self.logger.debug(
                f"Realm authorization secret {secret_name} already exists, reusing"
            )
            return secret_name
        except client.ApiException as e:
            if e.status != 404:
                raise ValidationError(
                    f"Failed to check for existing realm authorization secret: {e}"
                ) from e
            # Secret doesn't exist, create it
            self.logger.info(f"Creating realm authorization secret {secret_name}")

        # Generate secure token
        token = generate_token(length=32)  # 256-bit entropy
        token_bytes = token.encode("utf-8")
        encoded_token = base64.b64encode(token_bytes).decode("utf-8")

        # Create secret with owner reference for automatic cleanup
        secret_body = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=namespace,
                labels={
                    "app.kubernetes.io/managed-by": "keycloak-operator",
                    "app.kubernetes.io/component": "realm-authorization",
                    "keycloak.k8s.intility.io/realm": realm_name,
                },
                owner_references=[
                    client.V1OwnerReference(
                        api_version="keycloak.mdvr.nl/v1",
                        kind="KeycloakRealm",
                        name=realm_cr_name,
                        uid=owner_uid,
                        controller=True,
                        block_owner_deletion=True,
                    )
                ]
                if owner_uid
                else None,
            ),
            data={"token": encoded_token},
            type="Opaque",
        )

        try:
            core_api.create_namespaced_secret(namespace=namespace, body=secret_body)
            self.logger.info(
                f"Created realm authorization secret {secret_name} in namespace {namespace}"
            )
            return secret_name
        except client.ApiException as e:
            if e.status == 409:
                # Secret was created by another reconciliation, reuse it
                self.logger.debug(
                    f"Realm authorization secret {secret_name} created by concurrent reconciliation"
                )
                return secret_name
            raise ValidationError(
                f"Failed to create realm authorization secret: {e}"
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
        from ..utils.auth import validate_authorization
        from ..utils.kubernetes import validate_keycloak_reference

        # Resolve Keycloak operator reference
        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        # For now, use the operator namespace as keycloak name (will be updated in Phase 4)
        keycloak_name = "keycloak"  # Default Keycloak instance name

        # Validate authorization: Check operator token
        # Import here to avoid circular dependency
        from ..operator import OPERATOR_AUTH_SECRET_NAME, OPERATOR_NAMESPACE

        # Read the operator token directly from the secret to ensure we have the current value
        # This avoids issues with module-level variables in multi-worker environments
        core_v1 = client.CoreV1Api()
        try:
            operator_secret = core_v1.read_namespaced_secret(
                name=OPERATOR_AUTH_SECRET_NAME, namespace=OPERATOR_NAMESPACE
            )
            import base64

            expected_operator_token = base64.b64decode(
                operator_secret.data["token"]
            ).decode("utf-8")
        except Exception as e:
            from ..errors import PermanentError

            raise PermanentError(
                f"Cannot read operator authorization token: {e}"
            ) from e

        if not validate_authorization(
            secret_ref=operator_ref.authorization_secret_ref,
            secret_namespace=target_namespace,
            expected_token=expected_operator_token,
            k8s_client=client.CoreV1Api(),
        ):
            from ..errors import PermanentError

            raise PermanentError(
                f"Authorization failed: Invalid or missing operator token for realm {spec.realm_name}"
            )

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
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

        # Extract CR UID for ownership tracking
        cr_uid = kwargs.get("uid", "")

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

        # Add ownership metadata to realm attributes
        from datetime import UTC, datetime

        if "attributes" not in realm_payload:
            realm_payload["attributes"] = {}

        realm_payload["attributes"].update(
            {
                "kubernetes.operator.uid": cr_uid,
                "kubernetes.operator.namespace": namespace,
                "kubernetes.operator.name": name,
                "kubernetes.operator.timestamp": datetime.now(UTC).isoformat(),
            }
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
            cr_uid=cr_uid,
            payload_preview=payload_preview,
        )

        # Check if realm already exists and validate ownership
        # Import errors early for ownership validation logic
        from ..errors import PermanentError, TemporaryError

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
                    admin_client.update_realm(realm_name, realm_payload)
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
            # Realm doesn't exist - create it
            self.logger.info(
                f"Creating new realm {realm_name}",
                keycloak_instance=keycloak_name,
                realm_name=realm_name,
                cr_uid=cr_uid,
            )
            try:
                admin_client.create_realm(realm_payload)
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
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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

        operator_ref = spec.operator_ref
        target_namespace = operator_ref.namespace
        keycloak_name = "keycloak"  # Default Keycloak instance name
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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
            operator_ref = spec.operator_ref
            target_namespace = operator_ref.namespace
            keycloak_name = "keycloak"  # Default Keycloak instance name
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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
        admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

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
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

            # Try to get realm
            existing_realm = admin_client.get_realm(realm_name=realm_name)

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

        # Delete realm from Keycloak (if instance still exists)
        try:
            keycloak_name = "keycloak"  # Default Keycloak instance name
            admin_client = self.keycloak_admin_factory(keycloak_name, target_namespace)

            # Backup realm data if requested (only if spec parsed successfully)
            if realm_spec and getattr(realm_spec, "backup_on_delete", False):
                self.logger.info(f"Backing up realm {realm_name} before deletion")
                try:
                    await self._create_realm_backup(
                        realm_spec, name, namespace, backup_type="deletion"
                    )
                except Exception as e:
                    self.logger.warning(f"Realm backup failed: {e}")

            # Clean up all clients in this realm from Keycloak FIRST
            # This prevents client finalizers from trying to access the realm during deletion
            # Skip built-in Keycloak clients which cannot be deleted
            BUILTIN_CLIENTS = {
                "admin-cli",
                "broker",
                "realm-management",
                "security-admin-console",
                "account",
                "account-console",
            }
            try:
                realm_clients = admin_client.get_realm_clients(realm_name)
                for client_config in realm_clients:
                    client_id = client_config.client_id
                    if client_id and client_id not in BUILTIN_CLIENTS:
                        self.logger.info(
                            f"Cleaning up client {client_id} from realm {realm_name} in Keycloak"
                        )
                        admin_client.delete_client(client_id, realm_name)
                    elif client_id in BUILTIN_CLIENTS:
                        self.logger.debug(
                            f"Skipping built-in client {client_id} (cannot be deleted)"
                        )
            except Exception as e:
                self.logger.warning(
                    f"Failed to clean up realm clients from Keycloak: {e}"
                )

            # Delete the realm itself from Keycloak
            admin_client.delete_realm(realm_name)
            self.logger.info(f"Deleted realm {realm_name} from Keycloak")

            # Now delete KeycloakClient CRs (after Keycloak cleanup to avoid deadlock)
            # We remove their finalizers first so they don't try to clean up Keycloak again
            try:
                custom_api = client.CustomObjectsApi(self.k8s_client)
                clients = custom_api.list_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
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
                        self.logger.info(
                            f"Cascading delete: Removing KeycloakClient CR {client_cr_name} "
                            f"that references realm {realm_name}"
                        )
                        try:
                            # Remove finalizers first to prevent deadlock
                            client_cr["metadata"]["finalizers"] = []
                            custom_api.patch_namespaced_custom_object(
                                group="keycloak.mdvr.nl",
                                version="v1",
                                namespace=namespace,
                                plural="keycloakclients",
                                name=client_cr_name,
                                body=client_cr,
                            )
                            # Then delete the CR
                            custom_api.delete_namespaced_custom_object(
                                group="keycloak.mdvr.nl",
                                version="v1",
                                namespace=namespace,
                                plural="keycloakclients",
                                name=client_cr_name,
                            )
                        except Exception as delete_error:
                            self.logger.warning(
                                f"Failed to delete KeycloakClient CR {client_cr_name}: {delete_error}"
                            )
            except Exception as e:
                self.logger.warning(f"Failed to cascade delete KeycloakClient CRs: {e}")

        except Exception as e:
            self.logger.warning(
                f"Could not delete realm from Keycloak (instance may be deleted): {e}"
            )

        # Clean up Kubernetes resources associated with this realm
        try:
            await self._delete_realm_k8s_resources(name, namespace, realm_name)
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
        self, name: str, namespace: str, realm_name: str
    ) -> None:
        """Delete Kubernetes resources associated with the realm."""

        core_api = client.CoreV1Api(self.kubernetes_client)

        # Delete configmaps related to this realm (except backups)
        try:
            configmaps = core_api.list_namespaced_config_map(
                namespace=namespace,
                label_selector=f"keycloak.mdvr.nl/realm={realm_name},keycloak.mdvr.nl/backup!=true",
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
                label_selector=f"keycloak.mdvr.nl/realm={realm_name},keycloak.mdvr.nl/secret-type!=client-credentials",
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
