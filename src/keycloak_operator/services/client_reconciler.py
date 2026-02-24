"""
Keycloak client reconciler for managing OAuth2/OIDC client configuration.

This module handles the lifecycle of Keycloak clients including
client creation, credential management, and OAuth2 configuration.
"""

import base64
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import ReconciliationError, ValidationError
from ..models.client import KeycloakClientSpec
from ..settings import settings
from ..utils.keycloak_admin import get_keycloak_admin_client
from .base_reconciler import BaseReconciler, StatusProtocol

# Constants for security restrictions
DANGEROUS_SCRIPT_MAPPER_TYPES = {
    "oidc-script-based-protocol-mapper",
    "saml-javascript-mapper",
}

RESTRICTED_CLIENT_ROLES = {
    "realm-management": {
        "realm-admin",
        "manage-realm",
        "manage-authorization",
        "manage-users",
        "manage-clients",
        "manage-events",
        "manage-identity-providers",
    }
}


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
    ) -> tuple[str, str, str, dict[str, Any]]:
        """
        Get realm information including actual realm name and Keycloak instance.

        Args:
            realm_resource_name: Name of the realm Kubernetes resource
            realm_namespace: Namespace of the realm resource

        Returns:
            Tuple of (actual_realm_name, keycloak_namespace, keycloak_name, realm_resource)

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

        # 1. Resolve realm info EARLY to check ownership and get Keycloak details
        realm_ref = client_spec.realm_ref
        try:
            actual_realm_name, keycloak_namespace, keycloak_name, realm_resource = (
                self._get_realm_info(realm_ref.name, realm_ref.namespace)
            )
        except Exception as e:
            # If realm lookup fails, we can't determine ownership yet.
            # We return early but don't return an empty dict, so Kopf retries.
            from ..errors import TemporaryError

            self.logger.debug(f"Could not determine ownership for client {name}: {e}")
            raise TemporaryError(
                f"Waiting for parent realm {realm_ref.name} to determine ownership",
                delay=10,
            ) from e

        # 2. IGNORE resources not managed by this operator instance (ADR-062)
        target_op_ns = (
            realm_resource.get("spec", {}).get("operatorRef", {}).get("namespace")
        )
        if target_op_ns != settings.operator_namespace:
            self.logger.debug(
                f"Ignoring KeycloakClient {name}: parent realm '{realm_ref.name}' "
                f"is managed by operator in '{target_op_ns}', but we are '{settings.operator_namespace}'"
            )
            return {}

        # 3. Validate cross-namespace permissions
        await self.validate_cross_namespace_access(client_spec, namespace)

        # 4. Validate authorization via namespace grant list
        await self._validate_namespace_authorization(
            realm_resource=realm_resource,
            realm_name=realm_ref.name,
            realm_namespace=realm_ref.namespace,
            client_namespace=namespace,
            client_id=client_spec.client_id,
        )

        # 5. Ensure client exists with basic configuration
        client_uuid = await self.ensure_client_exists(
            client_spec,
            name,
            namespace,
            actual_realm_name=actual_realm_name,
            keycloak_namespace=keycloak_namespace,
            keycloak_name=keycloak_name,
            realm_resource=realm_resource,
        )

        # 6. Configure OAuth2/OIDC settings
        await self.configure_oauth_settings(
            client_spec,
            client_uuid,
            name,
            namespace,
            actual_realm_name=actual_realm_name,
            keycloak_namespace=keycloak_namespace,
            keycloak_name=keycloak_name,
        )

        # Get owner UID from resource body
        owner_uid = kwargs.get("body", {}).get("metadata", {}).get("uid")

        # 7. Manage client credentials
        if not client_spec.public_client:
            await self.manage_client_credentials(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
                owner_uid=owner_uid,
            )

        # 8. Configure protocol mappers
        if client_spec.protocol_mappers:
            await self.configure_protocol_mappers(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
            )

        # 9. Configure client-level scope assignments
        if client_spec.default_client_scopes or client_spec.optional_client_scopes:
            await self.configure_client_scopes(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
            )

        # 10. Manage client roles
        if client_spec.client_roles:
            await self.manage_client_roles(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
            )

        # 11. Manage service account roles
        if client_spec.settings.service_accounts_enabled:
            await self.manage_service_account_roles(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
            )

        # 12. Configure authorization services (resources and scopes)
        if client_spec.settings.authorization_services_enabled:
            await self.configure_authorization_settings(
                client_spec,
                client_uuid,
                name,
                namespace,
                actual_realm_name=actual_realm_name,
                keycloak_namespace=keycloak_namespace,
                keycloak_name=keycloak_name,
            )

        # 13. Return status information
        secret_name = f"{name}-credentials"

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

        # Store the latest admin event timestamp for drift detection
        if settings.drift_detection_enabled:
            try:
                admin_client_for_ts = await self.keycloak_admin_factory(
                    keycloak_name, keycloak_namespace, rate_limiter=self.rate_limiter
                )
                latest_event_time = (
                    await admin_client_for_ts.get_latest_admin_event_time(
                        actual_realm_name,
                        namespace,
                        scope="client",
                        client_uuid=client_uuid,
                    )
                )
                if latest_event_time is not None:
                    status.lastReconcileEventTime = latest_event_time
                else:
                    current_time_ms = int(time.time() * 1000)
                    status.lastReconcileEventTime = current_time_ms
            except Exception as e:
                self.logger.warning(
                    f"Failed to get latest admin event time for drift detection: {e}"
                )

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
        """Validate and parse Keycloak client specification."""
        try:
            return KeycloakClientSpec.model_validate(spec)
        except Exception as e:
            raise ValidationError(f"Invalid Keycloak client specification: {e}") from e

    async def validate_cross_namespace_access(
        self, spec: KeycloakClientSpec, namespace: str
    ) -> None:
        """Validate RBAC permissions for cross-namespace operations."""
        target_namespace = spec.realm_ref.namespace
        required_operations = [
            {"resource": "keycloaks", "verb": "get"},
            {"resource": "secrets", "verb": "get"},
            {"resource": "secrets", "verb": "create"},
            {"resource": "secrets", "verb": "patch"},
        ]
        await self.validate_rbac_permissions(
            source_namespace=namespace,
            target_namespace=target_namespace,
            operations=required_operations,
            resource_name=spec.realm_ref.name,
        )
        await self.validate_namespace_isolation(
            source_namespace=namespace,
            target_namespace=target_namespace,
            resource_type="keycloak client",
            resource_name=spec.client_id,
        )

    async def _validate_namespace_authorization(
        self,
        realm_resource: dict[str, Any],
        realm_name: str,
        realm_namespace: str,
        client_namespace: str,
        client_id: str,
    ) -> None:
        """Validate that client's namespace is authorized via realm's grant list."""
        from ..errors import PermanentError

        realm_spec = realm_resource.get("spec", {})
        grant_list = realm_spec.get("clientAuthorizationGrants", [])

        if client_namespace not in grant_list:
            error_msg = (
                f"Authorization denied: Namespace '{client_namespace}' is not authorized "
                f"to create clients in realm '{realm_name}' (namespace: '{realm_namespace}'). "
                f"The realm owner must add '{client_namespace}' to the "
                f"spec.clientAuthorizationGrants list in the realm CR."
            )
            self.logger.warning(error_msg)
            raise PermanentError(error_msg)

    async def ensure_client_exists(
        self,
        spec: KeycloakClientSpec,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
        realm_resource: dict[str, Any] | None = None,
    ) -> str:
        """Ensure client exists."""
        from ..utils.kubernetes import validate_keycloak_reference

        if not all(
            [actual_realm_name, keycloak_namespace, keycloak_name, realm_resource]
        ):
            actual_realm_name, keycloak_namespace, keycloak_name, realm_resource = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        keycloak_instance_obj = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
        )
        if not keycloak_instance_obj:
            from ..errors import TemporaryError

            raise TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {keycloak_namespace}"
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        existing_client = await admin_client.get_client_by_name(
            spec.client_id, actual_realm_name, namespace
        )

        from ..utils.ownership import create_ownership_attributes

        client_config = spec.to_keycloak_config()
        if not existing_client and client_config.get("authorizationServicesEnabled"):
            client_config["authorizationServicesEnabled"] = False

        if "attributes" not in client_config:
            client_config["attributes"] = {}
        ownership_attrs = create_ownership_attributes(namespace, name)
        client_config["attributes"].update(ownership_attrs)

        if existing_client:
            await admin_client.update_client(
                existing_client.id, client_config, actual_realm_name, namespace
            )
            return existing_client.id
        else:
            client_response = await admin_client.create_client(
                client_config, actual_realm_name, namespace
            )
            if client_response:
                return client_response
            else:
                created_client = await admin_client.get_client_by_name(
                    spec.client_id, actual_realm_name, namespace
                )
                if created_client and created_client.id:
                    return created_client.id
                else:
                    from ..errors import TemporaryError

                    raise TemporaryError(f"Failed to create client '{spec.client_id}'")

    async def configure_oauth_settings(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Configure OAuth settings."""
        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        settings_spec = spec.settings
        attributes = {}
        if settings_spec.access_token_lifespan is not None:
            attributes["access.token.lifespan"] = str(
                settings_spec.access_token_lifespan
            )
        if settings_spec.client_session_idle_timeout is not None:
            attributes["client.session.idle.timeout"] = str(
                settings_spec.client_session_idle_timeout
            )
        if settings_spec.client_session_max_lifespan is not None:
            attributes["client.session.max.lifespan"] = str(
                settings_spec.client_session_max_lifespan
            )
        if settings_spec.pkce_code_challenge_method:
            attributes["pkce.code.challenge.method"] = (
                settings_spec.pkce_code_challenge_method
            )

        client_config = {
            "id": client_uuid,
            "clientId": spec.client_id,
            "name": spec.client_name or spec.client_id,
            "description": spec.description or "",
            "enabled": True,
            "publicClient": spec.public_client,
            "bearerOnly": spec.bearer_only or False,
            "protocol": spec.protocol or "openid-connect",
            "standardFlowEnabled": settings_spec.standard_flow_enabled,
            "implicitFlowEnabled": settings_spec.implicit_flow_enabled,
            "directAccessGrantsEnabled": settings_spec.direct_access_grants_enabled,
            "serviceAccountsEnabled": settings_spec.service_accounts_enabled,
            "redirectUris": spec.redirect_uris or [],
            "webOrigins": getattr(spec, "web_origins", []),
            "adminUrl": getattr(spec, "admin_url", ""),
            "baseUrl": getattr(spec, "base_url", ""),
            "rootUrl": getattr(spec, "root_url", ""),
            "consentRequired": settings_spec.consent_required,
            "displayOnConsentScreen": settings_spec.display_on_consent_screen,
            "frontchannelLogout": settings_spec.frontchannel_logout,
            "fullScopeAllowed": settings_spec.full_scope_allowed,
            "authorizationServicesEnabled": settings_spec.authorization_services_enabled,
            "nodeReRegistrationTimeout": getattr(
                spec, "node_re_registration_timeout", -1
            ),
            "notBefore": getattr(spec, "not_before", 0),
            "surrogateAuthRequired": getattr(spec, "surrogate_auth_required", False),
            "clientAuthenticatorType": settings_spec.client_authenticator_type
            if not spec.public_client
            else None,
        }
        if attributes:
            client_config["attributes"] = attributes

        client_config = {k: v for k, v in client_config.items() if v is not None}
        await admin_client.update_client(
            client_uuid, client_config, actual_realm_name, namespace
        )

    def _parse_duration(self, duration_str: str) -> timedelta:
        """Parse duration string into timedelta."""
        if not duration_str:
            return timedelta(days=90)
        unit = duration_str[-1].lower()
        if unit not in ["s", "m", "h", "d"]:
            raise ValidationError(f"Invalid duration unit in '{duration_str}'")
        try:
            value = int(duration_str[:-1])
        except ValueError as e:
            raise ValidationError(f"Invalid duration format '{duration_str}'") from e

        if value <= 0:
            raise ValidationError(
                f"Duration value must be a positive integer in '{duration_str}'"
            )

        if unit == "s":
            return timedelta(seconds=value)
        elif unit == "m":
            return timedelta(minutes=value)
        elif unit == "h":
            return timedelta(hours=value)
        elif unit == "d":
            return timedelta(days=value)
        return timedelta(days=90)

    def _should_rotate_secret(
        self, spec: KeycloakClientSpec, secret: client.V1Secret
    ) -> bool:
        """Check if client secret should be rotated."""
        if not spec.secret_rotation.enabled:
            return False
        annotations = secret.metadata.annotations or {}
        rotated_at_str = annotations.get("keycloak-operator/rotated-at")
        if not rotated_at_str:
            return False
        try:
            rotated_at = datetime.fromisoformat(rotated_at_str)
            if rotated_at.tzinfo is None:
                rotated_at = rotated_at.replace(tzinfo=UTC)
        except ValueError:
            return False

        rotation_period = self._parse_duration(spec.secret_rotation.rotation_period)
        expiration_time = rotated_at + rotation_period
        now = datetime.now(UTC)

        if now < expiration_time:
            return False

        if spec.secret_rotation.rotation_time:
            try:
                target_tz = ZoneInfo(spec.secret_rotation.timezone)
                expiration_in_tz = expiration_time.astimezone(target_tz)
                target_hour, target_minute = map(
                    int, spec.secret_rotation.rotation_time.split(":")
                )

                target_rotation_dt = expiration_in_tz.replace(
                    hour=target_hour, minute=target_minute, second=0, microsecond=0
                )

                if target_rotation_dt < expiration_in_tz:
                    target_rotation_dt += timedelta(days=1)

                now_in_tz = now.astimezone(target_tz)
                if now_in_tz < target_rotation_dt:
                    return False
            except Exception as e:
                self.logger.warning(
                    f"Error calculating rotation schedule: {e}. Falling back to immediate rotation."
                )
                return True

        return True

    async def manage_client_credentials(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
        owner_uid: str | None = None,
    ) -> None:
        """Manage client credentials."""
        from ..utils.kubernetes import (
            create_client_secret,
            get_kubernetes_client,
            validate_keycloak_reference,
        )

        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        secret_name = f"{name}-credentials"
        k8s_client = get_kubernetes_client()
        core_api = client.CoreV1Api(k8s_client)
        existing_secret = None
        try:
            existing_secret = core_api.read_namespaced_secret(secret_name, namespace)
        except ApiException as e:
            if e.status != 404:
                raise

        should_rotate = False
        rotation_succeeded = False
        client_secret = None

        if existing_secret:
            should_rotate = self._should_rotate_secret(spec, existing_secret)
            if (
                not should_rotate
                and not spec.regenerate_secret
                and existing_secret.data
                and "client-secret" in existing_secret.data
            ):
                client_secret = base64.b64decode(
                    existing_secret.data["client-secret"]
                ).decode("utf-8")

        if spec.regenerate_secret:
            should_rotate = True

        if spec.client_secret:
            manual_secret = core_api.read_namespaced_secret(
                spec.client_secret.name, namespace
            )
            client_secret = base64.b64decode(
                manual_secret.data[spec.client_secret.key]
            ).decode("utf-8")
            current_kc_secret = await admin_client.get_client_secret(
                spec.client_id, actual_realm_name, namespace
            )
            if current_kc_secret != client_secret:
                await admin_client.update_client(
                    client_uuid,
                    {"id": client_uuid, "secret": client_secret},
                    actual_realm_name,
                    namespace,
                )
            rotation_succeeded = True
        elif (not client_secret or should_rotate) and not spec.public_client:
            if should_rotate:
                client_secret = await admin_client.regenerate_client_secret(
                    spec.client_id, actual_realm_name, namespace
                )
                rotation_succeeded = True
            else:
                client_secret = await admin_client.get_client_secret(
                    spec.client_id, actual_realm_name, namespace
                )

        keycloak_instance = validate_keycloak_reference(
            keycloak_name, keycloak_namespace
        )
        if not keycloak_instance:
            from ..errors import TemporaryError

            raise TemporaryError(f"Keycloak instance {keycloak_name} not found")

        labels = spec.secret_metadata.labels if spec.secret_metadata else None
        annotations = (
            dict(spec.secret_metadata.annotations)
            if spec.secret_metadata and spec.secret_metadata.annotations
            else {}
        )
        if existing_secret is None or rotation_succeeded:
            annotations["keycloak-operator/rotated-at"] = datetime.now(UTC).isoformat()
        elif (
            existing_secret
            and existing_secret.metadata
            and existing_secret.metadata.annotations
            and "keycloak-operator/rotated-at" in existing_secret.metadata.annotations
        ):
            annotations["keycloak-operator/rotated-at"] = (
                existing_secret.metadata.annotations["keycloak-operator/rotated-at"]
            )

        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id=spec.client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
            realm=actual_realm_name,
            update_existing=True,
            labels=labels,
            annotations=annotations,
            owner_uid=owner_uid,
            owner_name=name,
        )

    async def configure_protocol_mappers(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Configure protocol mappers."""
        # Security validation (Moved here but should also be in webhook)
        if not settings.allow_script_mappers and spec.protocol_mappers:
            for mapper_spec in spec.protocol_mappers:
                m_type = (
                    mapper_spec.protocol_mapper.lower()
                    if mapper_spec.protocol_mapper
                    else ""
                )
                if m_type in DANGEROUS_SCRIPT_MAPPER_TYPES:
                    raise ValidationError(
                        f"Script mapper '{mapper_spec.name}' (type: {mapper_spec.protocol_mapper}) is not allowed."
                    )

        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        existing_mappers = await admin_client.get_client_protocol_mappers(
            client_uuid, actual_realm_name
        )
        existing_mappers_by_name = {m.name: m for m in existing_mappers}
        for mapper_spec in spec.protocol_mappers:
            existing = existing_mappers_by_name.get(mapper_spec.name)
            mapper_dict = mapper_spec.model_dump()
            if existing:
                if self._protocol_mapper_needs_update(existing, mapper_dict):
                    await admin_client.update_client_protocol_mapper(
                        client_uuid, existing.id, mapper_dict, actual_realm_name
                    )
            else:
                result = await admin_client.create_client_protocol_mapper(
                    client_uuid, mapper_dict, actual_realm_name
                )
                if not result:
                    self.logger.warning(
                        f"Failed to create protocol mapper '{mapper_spec.name}' for client {spec.client_id}"
                    )

    def _protocol_mapper_needs_update(self, existing: Any, desired: dict) -> bool:
        """Check if protocol mapper needs update."""
        for field in ["name", "protocol", "protocolMapper", "config"]:
            if getattr(existing, field, None) != desired.get(field):
                return True
        return False

    async def configure_client_scopes(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Configure client scopes."""
        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace, rate_limiter=self.rate_limiter
        )
        all_scopes = await admin_client.get_client_scopes(actual_realm_name, namespace)
        scope_name_to_id = {s.name: s.id for s in all_scopes if s.name and s.id}

        if spec.default_client_scopes:
            current = await admin_client.get_client_default_scopes(
                actual_realm_name, client_uuid, namespace
            )
            current_names = {s.name for s in current if s.name}
            desired = set(spec.default_client_scopes)
            for sname in desired - current_names:
                if sname in scope_name_to_id:
                    await admin_client.add_client_default_scope(
                        actual_realm_name,
                        client_uuid,
                        scope_name_to_id[sname],
                        namespace,
                    )
            for sname in current_names - desired:
                sid = next((s.id for s in current if s.name == sname), None)
                if sid:
                    await admin_client.remove_client_default_scope(
                        actual_realm_name, client_uuid, sid, namespace
                    )

        if spec.optional_client_scopes:
            current = await admin_client.get_client_optional_scopes(
                actual_realm_name, client_uuid, namespace
            )
            current_names = {s.name for s in current if s.name}
            desired = set(spec.optional_client_scopes)
            self.logger.warning(
                f"DEBUG_SCOPES: desired optional scopes: {desired}, current: {current_names}, available: {list(scope_name_to_id.keys())}"
            )
            for sname in desired - current_names:
                if sname in scope_name_to_id:
                    self.logger.warning(f"DEBUG_SCOPES: Adding optional scope {sname}")
                    await admin_client.add_client_optional_scope(
                        actual_realm_name,
                        client_uuid,
                        scope_name_to_id[sname],
                        namespace,
                    )
                else:
                    self.logger.warning(
                        f"DEBUG_SCOPES: Could not add {sname} because it is not in scope_name_to_id"
                    )
            for sname in current_names - desired:
                sid = next((s.id for s in current if s.name == sname), None)
                if sid:
                    await admin_client.remove_client_optional_scope(
                        actual_realm_name, client_uuid, sid, namespace
                    )

    async def manage_client_roles(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Manage client roles."""
        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        existing = await admin_client.get_client_roles(client_uuid, actual_realm_name)
        existing_names = {r.name for r in existing}
        for role_name in spec.client_roles:
            if role_name not in existing_names:
                await admin_client.create_client_role(
                    client_uuid, {"name": role_name}, actual_realm_name
                )

    async def manage_service_account_roles(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Manage service account roles."""
        if not spec.settings.service_accounts_enabled:
            return

        roles_config = spec.service_account_roles
        if not roles_config.realm_roles and not roles_config.client_roles:
            return

        # Security validation (Moved here but should also be in webhook)
        restricted_realm_roles = {"admin"}
        for role in roles_config.realm_roles:
            if role in restricted_realm_roles:
                raise ValidationError(f"Restricted realm role '{role}' not allowed")

        if roles_config.client_roles:
            for target_client, roles in roles_config.client_roles.items():
                if target_client in RESTRICTED_CLIENT_ROLES:
                    restricted = RESTRICTED_CLIENT_ROLES[target_client]
                    for role in roles:
                        if role == "impersonation" and settings.allow_impersonation:
                            continue
                        if role in restricted or role == "impersonation":
                            raise ValidationError(
                                f"Restricted client role '{role}' not allowed"
                            )

        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace
        )
        sa_user = await admin_client.get_service_account_user(
            client_uuid, actual_realm_name, namespace
        )
        if sa_user and sa_user.id:
            if roles_config.realm_roles:
                await admin_client.assign_realm_roles_to_user(
                    user_id=sa_user.id,
                    role_names=roles_config.realm_roles,
                    realm_name=actual_realm_name,
                    namespace=namespace,
                )
            if roles_config.client_roles:
                for target_id, role_names in roles_config.client_roles.items():
                    target_client = await admin_client.get_client_by_name(
                        target_id, actual_realm_name, namespace
                    )
                    if target_client and target_client.id:
                        await admin_client.assign_client_roles_to_user(
                            user_id=sa_user.id,
                            client_uuid=target_client.id,
                            role_names=role_names,
                            realm_name=actual_realm_name,
                            namespace=namespace,
                        )
        else:
            raise ReconciliationError(
                f"Service account user missing for client {spec.client_id}",
                retryable=False,
            )

    async def configure_authorization_settings(
        self,
        spec: KeycloakClientSpec,
        client_uuid: str,
        name: str,
        namespace: str,
        actual_realm_name: str | None = None,
        keycloak_namespace: str | None = None,
        keycloak_name: str | None = None,
    ) -> None:
        """Configure authorization settings."""
        if not all([actual_realm_name, keycloak_namespace, keycloak_name]):
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(spec.realm_ref.name, spec.realm_ref.namespace)
            )

        admin_client = await self.keycloak_admin_factory(
            keycloak_name, keycloak_namespace, rate_limiter=self.rate_limiter
        )
        authz = spec.authorization_settings
        if authz:
            server_settings = {
                "policyEnforcementMode": authz.policy_enforcement_mode,
                "decisionStrategy": authz.decision_strategy,
                "allowRemoteResourceManagement": authz.allow_remote_resource_management,
            }
            await admin_client.update_resource_server_settings(
                actual_realm_name, client_uuid, server_settings, namespace
            )
            await self._reconcile_authorization_scopes(
                admin_client,
                actual_realm_name,
                client_uuid,
                authz.scopes,
                namespace,
                spec.client_id,
            )
            await self._reconcile_authorization_resources(
                admin_client,
                actual_realm_name,
                client_uuid,
                authz.resources,
                namespace,
                spec.client_id,
            )
            if authz.policies:
                await self._reconcile_authorization_policies(
                    admin_client,
                    actual_realm_name,
                    client_uuid,
                    authz.policies,
                    namespace,
                    spec.client_id,
                )
            if authz.permissions:
                await self._reconcile_authorization_permissions(
                    admin_client,
                    actual_realm_name,
                    client_uuid,
                    authz.permissions,
                    namespace,
                    spec.client_id,
                )

    async def _reconcile_authorization_scopes(
        self,
        admin_client,
        realm_name,
        client_uuid,
        desired_scopes,
        namespace,
        client_id,
    ):
        existing = await admin_client.get_authorization_scopes(
            realm_name, client_uuid, namespace
        )
        existing_by_name = {s.get("name"): s for s in existing}
        desired_names = {s.name for s in desired_scopes}
        for scope in desired_scopes:
            scope_dict = {
                "name": scope.name,
                "displayName": scope.display_name,
                "iconUri": scope.icon_uri,
            }
            scope_dict = {k: v for k, v in scope_dict.items() if v is not None}
            if scope.name in existing_by_name:
                ext = existing_by_name[scope.name]
                if (
                    ext.get("displayName") != scope.display_name
                    or ext.get("iconUri") != scope.icon_uri
                ):
                    await admin_client.update_authorization_scope(
                        realm_name, client_uuid, ext.get("id"), scope_dict, namespace
                    )
            else:
                result = await admin_client.create_authorization_scope(
                    realm_name, client_uuid, scope_dict, namespace
                )
                if not result:
                    self.logger.warning(
                        f"Failed to create authorization scope '{scope.name}' for client {client_id}"
                    )
        for ext in existing:
            if ext.get("name") not in desired_names:
                await admin_client.delete_authorization_scope(
                    realm_name, client_uuid, ext.get("id"), namespace
                )

    async def _reconcile_authorization_resources(
        self,
        admin_client,
        realm_name,
        client_uuid,
        desired_resources,
        namespace,
        client_id,
    ):
        existing = await admin_client.get_authorization_resources(
            realm_name, client_uuid, namespace
        )
        existing_by_name = {r.get("name"): r for r in existing}
        desired_names = {r.name for r in desired_resources}
        scopes = await admin_client.get_authorization_scopes(
            realm_name, client_uuid, namespace
        )
        scope_name_to_id = {s.get("name"): s.get("id") for s in scopes}
        for res in desired_resources:
            scope_refs = []
            for sn in res.scopes:
                if sn in scope_name_to_id:
                    scope_refs.append({"id": scope_name_to_id[sn], "name": sn})
                else:
                    self.logger.warning(
                        f"Scope '{sn}' not found for resource '{res.name}'"
                    )

            res_dict = {
                "name": res.name,
                "displayName": res.display_name,
                "type": res.type,
                "uris": res.uris,
                "scopes": scope_refs,
                "ownerManagedAccess": res.owner_managed_access,
            }
            res_dict = {k: v for k, v in res_dict.items() if v is not None}
            if res.name in existing_by_name:
                ext = existing_by_name[res.name]
                res_dict["_id"] = ext.get("_id")
                await admin_client.update_authorization_resource(
                    realm_name, client_uuid, ext.get("_id"), res_dict, namespace
                )
            else:
                result = await admin_client.create_authorization_resource(
                    realm_name, client_uuid, res_dict, namespace
                )
                if not result:
                    self.logger.warning(
                        f"Failed to create authorization resource '{res.name}' for client {client_id}"
                    )
        for ext in existing:
            ename = ext.get("name")
            if ename not in desired_names and ename != "Default Resource":
                await admin_client.delete_authorization_resource(
                    realm_name, client_uuid, ext.get("_id"), namespace
                )

    async def _reconcile_authorization_policies(
        self, admin_client, realm_name, client_uuid, policies, namespace, client_id
    ):
        existing = await admin_client.get_authorization_policies(
            realm_name, client_uuid, namespace
        )
        existing_by_name = {p.get("name"): p for p in existing}
        desired_names = set()
        policy_configs = []

        def _to_dict(p, ptype):
            desired_names.add(p.name)
            d = {"name": p.name, "description": p.description, "logic": p.logic}
            if ptype == "role":
                d["roles"] = [
                    {"id": r.id or r.name, "required": r.required} for r in p.roles
                ]
                d["fetchRoles"] = p.fetch_roles
            elif ptype == "user":
                d["users"] = p.users
            elif ptype == "group":
                d["groups"] = p.groups
                d["groupsClaim"] = p.groups_claim
            elif ptype == "client":
                d["clients"] = p.clients
            elif ptype == "time":
                for f in [
                    "not_before",
                    "not_on_or_after",
                    "day_month",
                    "day_month_end",
                    "month",
                    "month_end",
                    "year",
                    "year_end",
                    "hour",
                    "hour_end",
                    "minute",
                    "minute_end",
                ]:
                    val = getattr(p, f, None)
                    if val is not None:
                        d[
                            f.replace("_", "")
                            .replace("notbefore", "notBefore")
                            .replace("notonorafter", "notOnOrAfter")
                        ] = str(val)
            elif ptype == "regex":
                d["targetClaim"] = p.target_claim
                d["pattern"] = p.pattern
            elif ptype == "aggregate":
                d["decisionStrategy"] = p.decision_strategy
                d["policies"] = p.policies
            elif ptype == "js":
                d["code"] = p.code
            return ptype, d

        for p in policies.role_policies:
            policy_configs.append(_to_dict(p, "role"))
        for p in policies.user_policies:
            policy_configs.append(_to_dict(p, "user"))
        for p in policies.group_policies:
            policy_configs.append(_to_dict(p, "group"))
        for p in policies.client_policies:
            policy_configs.append(_to_dict(p, "client"))
        for p in policies.time_policies:
            policy_configs.append(_to_dict(p, "time"))
        for p in policies.regex_policies:
            policy_configs.append(_to_dict(p, "regex"))

        if policies.javascript_policies:
            if not policies.allow_javascript_policies:
                self.logger.warning(
                    f"JavaScript policies blocked for client {client_id}"
                )
            else:
                self.logger.warning(
                    f"SECURITY WARNING: JavaScript policies enabled for client {client_id}"
                )
                for p in policies.javascript_policies:
                    policy_configs.append(_to_dict(p, "js"))

        for ptype, pdata in policy_configs:
            if pdata["name"] in existing_by_name:
                await admin_client.update_authorization_policy(
                    realm_name,
                    client_uuid,
                    ptype,
                    existing_by_name[pdata["name"]].get("id"),
                    pdata,
                    namespace,
                )
            else:
                await admin_client.create_authorization_policy(
                    realm_name, client_uuid, ptype, pdata, namespace
                )

        # Aggregate policies last
        existing = await admin_client.get_authorization_policies(
            realm_name, client_uuid, namespace
        )
        pname_to_id = {p.get("name"): p.get("id") for p in existing}
        for p in policies.aggregate_policies:
            ptype, pdata = _to_dict(p, "aggregate")
            # Resolve policy names to IDs
            pdata["policies"] = [
                pname_to_id[sn] for sn in pdata["policies"] if sn in pname_to_id
            ]
            if p.name in existing_by_name:
                await admin_client.update_authorization_policy(
                    realm_name,
                    client_uuid,
                    ptype,
                    existing_by_name[p.name].get("id"),
                    pdata,
                    namespace,
                )
            else:
                await admin_client.create_authorization_policy(
                    realm_name, client_uuid, ptype, pdata, namespace
                )

        for ext in existing:
            pname = ext.get("name")
            if (
                pname not in desired_names
                and not pname.startswith("Default ")
                and ext.get("type") not in ("resource", "scope")
            ):
                await admin_client.delete_authorization_policy(
                    realm_name, client_uuid, ext.get("id"), namespace
                )

    async def _reconcile_authorization_permissions(
        self, admin_client, realm_name, client_uuid, permissions, namespace, client_id
    ):
        existing = await admin_client.get_authorization_permissions(
            realm_name, client_uuid, namespace
        )
        existing_by_name = {p.get("name"): p for p in existing}

        policies = await admin_client.get_authorization_policies(
            realm_name, client_uuid, namespace
        )
        pname_to_id = {p.get("name"): p.get("id") for p in policies}
        resources = await admin_client.get_authorization_resources(
            realm_name, client_uuid, namespace
        )
        rname_to_id = {r.get("name"): r.get("_id") for r in resources}
        scopes = await admin_client.get_authorization_scopes(
            realm_name, client_uuid, namespace
        )
        sname_to_id = {s.get("name"): s.get("id") for s in scopes}

        desired_names = set()
        for p in permissions.resource_permissions:
            desired_names.add(p.name)

            # Resolve refs
            res_ids = [rname_to_id[rn] for rn in p.resources if rn in rname_to_id]
            pol_ids = [pname_to_id[pn] for pn in p.policies if pn in pname_to_id]

            if len(res_ids) < len(p.resources) or len(pol_ids) < len(p.policies):
                missing_res = [rn for rn in p.resources if rn not in rname_to_id]
                missing_pol = [pn for pn in p.policies if pn not in pname_to_id]
                raise ReconciliationError(
                    f"Permission '{p.name}' missing refs: res={missing_res}, pol={missing_pol}"
                )

            pdata = {
                "name": p.name,
                "description": p.description,
                "decisionStrategy": p.decision_strategy,
                "resources": res_ids,
                "policies": pol_ids,
            }
            if p.resource_type:
                pdata["resourceType"] = p.resource_type
            if p.name in existing_by_name:
                await admin_client.update_authorization_permission(
                    realm_name,
                    client_uuid,
                    "resource",
                    existing_by_name[p.name].get("id"),
                    pdata,
                    namespace,
                )
            else:
                await admin_client.create_authorization_permission(
                    realm_name, client_uuid, "resource", pdata, namespace
                )

        for p in permissions.scope_permissions:
            desired_names.add(p.name)

            # Resolve refs
            sco_ids = [sname_to_id[sn] for sn in p.scopes if sn in sname_to_id]
            pol_ids = [pname_to_id[pn] for pn in p.policies if pn in pname_to_id]

            if len(sco_ids) < len(p.scopes) or len(pol_ids) < len(p.policies):
                missing_sco = [sn for sn in p.scopes if sn not in sname_to_id]
                missing_pol = [pn for pn in p.policies if pn not in pname_to_id]
                raise ReconciliationError(
                    f"Permission '{p.name}' missing refs: scopes={missing_sco}, pol={missing_pol}"
                )

            pdata = {
                "name": p.name,
                "description": p.description,
                "decisionStrategy": p.decision_strategy,
                "scopes": sco_ids,
                "policies": pol_ids,
            }
            if p.resources:
                pdata["resources"] = [
                    rname_to_id[rn] for rn in p.resources if rn in rname_to_id
                ]
            if p.resource_type:
                pdata["resourceType"] = p.resource_type
            if p.name in existing_by_name:
                await admin_client.update_authorization_permission(
                    realm_name,
                    client_uuid,
                    "scope",
                    existing_by_name[p.name].get("id"),
                    pdata,
                    namespace,
                )
            else:
                await admin_client.create_authorization_permission(
                    realm_name, client_uuid, "scope", pdata, namespace
                )

        for ext in existing:
            pname = ext.get("name")
            if pname not in desired_names and not pname.startswith("Default "):
                await admin_client.delete_authorization_permission(
                    realm_name, client_uuid, ext.get("id"), namespace
                )

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
        """Handle updates to Keycloak client specifications."""
        # Ensure we don't pass spec twice if it's already in kwargs
        kwargs.pop("spec", None)
        return await self.do_reconcile(new_spec, name, namespace, status, **kwargs)

    async def check_resource_exists(
        self,
        name: str,
        namespace: str,
        spec: dict[str, Any],
        status: StatusProtocol,
    ) -> bool:
        """Check if client resource actually exists in Keycloak."""
        try:
            client_spec = KeycloakClientSpec.model_validate(spec)
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(
                    client_spec.realm_ref.name, client_spec.realm_ref.namespace
                )
            )
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, keycloak_namespace
            )
            existing_client = await admin_client.get_client_by_name(
                client_spec.client_id, actual_realm_name, namespace
            )
            return existing_client is not None
        except Exception:
            return False

    async def cleanup_resources(
        self,
        name: str,
        namespace: str,
        spec: dict[str, Any],
        status: StatusProtocol,
        **kwargs: Any,
    ) -> None:
        """Clean up Keycloak client resources."""
        try:
            client_spec = self._validate_spec(spec)
            actual_realm_name, keycloak_namespace, keycloak_name, _ = (
                self._get_realm_info(
                    client_spec.realm_ref.name, client_spec.realm_ref.namespace
                )
            )
            admin_client = await self.keycloak_admin_factory(
                keycloak_name, keycloak_namespace
            )
            existing_client = await admin_client.get_client_by_name(
                client_spec.client_id, actual_realm_name, namespace
            )
            if existing_client:
                await admin_client.delete_client(
                    existing_client.id, actual_realm_name, namespace
                )
        except Exception as e:
            self.logger.warning(f"Cleanup failed for client {name}: {e}")

        # Clean up Kubernetes resources manually
        try:
            core_api = client.CoreV1Api(self.k8s_client)

            # Delete credentials secret
            try:
                core_api.delete_namespaced_secret(f"{name}-credentials", namespace)
            except ApiException as e:
                if e.status != 404:
                    self.logger.warning(
                        f"Failed to delete credentials secret for client {name}: {e}"
                    )

            # Delete other resources managed by this client (e.g., config maps, other secrets)
            # Find resources with label vriesdemichael.github.io/keycloak-client=name
            label_selector = f"vriesdemichael.github.io/keycloak-client={name}"

            try:
                config_maps = core_api.list_namespaced_config_map(
                    namespace, label_selector=label_selector
                )
                for cm in config_maps.items:
                    core_api.delete_namespaced_config_map(cm.metadata.name, namespace)
            except ApiException as e:
                self.logger.warning(
                    f"Failed to list/delete labeled config maps for client {name}: {e}"
                )

            try:
                secrets = core_api.list_namespaced_secret(
                    namespace, label_selector=label_selector
                )
                for s in secrets.items:
                    # Skip the credentials secret as we already deleted it
                    if s.metadata.name != f"{name}-credentials":
                        core_api.delete_namespaced_secret(s.metadata.name, namespace)
            except ApiException as e:
                self.logger.warning(
                    f"Failed to list/delete labeled secrets for client {name}: {e}"
                )

        except Exception as e:
            self.logger.warning(f"Kubernetes cleanup failed for client {name}: {e}")
