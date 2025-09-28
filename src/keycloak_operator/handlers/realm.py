"""
KeycloakRealm handlers - Manages realm lifecycle and configuration.

This module handles realm management within Keycloak instances, including:
- Creating and configuring realms
- Setting up authentication flows and identity providers
- Managing realm-level settings and policies
- Configuring user federation and storage
- Setting up realm-specific themes and localization

Realms provide isolation between different applications or tenants
and can be managed independently across different namespaces.
"""

import logging
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import kopf

from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.services import KeycloakRealmReconciler
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client

logger = logging.getLogger(__name__)


class StatusProtocol(Protocol):
    """Protocol for kopf Status objects that allow dynamic attribute assignment."""

    def __setattr__(self, name: str, value: Any) -> None: ...
    def __getattr__(self, name: str) -> Any: ...


class StatusWrapper:
    """Wrapper to make dict status compatible with StatusProtocol."""

    def __init__(self, status_dict: dict[str, Any]):
        self._status = status_dict

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._status[name] = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        return self._status.get(name)


@kopf.on.create("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
async def ensure_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Ensure KeycloakRealm exists in the target Keycloak instance.

    This handler creates and configures realms in Keycloak instances.
    Realms can be created in Keycloak instances across namespaces,
    subject to RBAC permissions.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the KeycloakRealm resource exists
        status: Current status of the resource

    Returns:
        Dictionary with status information for the resource

    """
    logger.info(f"Ensuring KeycloakRealm {name} in namespace {namespace}")

    # Create reconciler and delegate to service layer
    reconciler = KeycloakRealmReconciler()
    status_wrapper = StatusWrapper(status)
    return await reconciler.reconcile(
        spec=spec, name=name, namespace=namespace, status=status_wrapper, **kwargs
    )


@kopf.on.update("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
def update_keycloak_realm(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Handle updates to KeycloakRealm specifications.

    This handler processes changes to realm configurations and applies
    them to the target Keycloak instance.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    logger.info(f"Updating KeycloakRealm {name} in namespace {namespace}")

    # Log changes for debugging
    for operation, field_path, old_value, new_value in diff:
        logger.info(
            f"KeycloakRealm change - {operation}: {field_path} "
            f"from {old_value} to {new_value}"
        )

    status.update(
        {
            "phase": "Updating",
            "message": "Applying realm configuration changes",
        }
    )

    try:
        # Validate that immutable fields haven't changed
        old_spec = KeycloakRealmSpec.model_validate(old["spec"])
        new_spec = KeycloakRealmSpec.model_validate(new["spec"])

        # Check for changes to immutable fields
        if old_spec.realm_name != new_spec.realm_name:
            raise kopf.PermanentError(
                "Cannot change realm_name of existing KeycloakRealm"
            )

        if old_spec.keycloak_instance_ref != new_spec.keycloak_instance_ref:
            raise kopf.PermanentError(
                "Cannot change keycloak_instance_ref of existing KeycloakRealm"
            )

        # Get admin client for the target Keycloak instance
        keycloak_ref = new_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        realm_name = new_spec.realm_name

        # Apply configuration updates based on the diff
        configuration_changed = False
        for _operation, field_path, _old_value, _new_value in diff:
            if field_path[:2] == ("spec", "themes"):
                logger.info("Updating realm themes")
                try:
                    if new_spec.themes:
                        theme_config = {}
                        if (
                            hasattr(new_spec.themes, "login_theme")
                            and new_spec.themes.login_theme
                        ):
                            theme_config["login_theme"] = new_spec.themes.login_theme
                        if (
                            hasattr(new_spec.themes, "account_theme")
                            and new_spec.themes.account_theme
                        ):
                            theme_config["account_theme"] = (
                                new_spec.themes.account_theme
                            )
                        if (
                            hasattr(new_spec.themes, "admin_theme")
                            and new_spec.themes.admin_theme
                        ):
                            theme_config["admin_theme"] = new_spec.themes.admin_theme
                        if (
                            hasattr(new_spec.themes, "email_theme")
                            and new_spec.themes.email_theme
                        ):
                            theme_config["email_theme"] = new_spec.themes.email_theme

                        if theme_config:
                            admin_client.update_realm_themes(realm_name, theme_config)
                    configuration_changed = True
                except Exception as e:
                    logger.warning(f"Failed to update themes: {e}")

            elif field_path[:2] == ("spec", "localization"):
                logger.info("Updating realm localization")
                try:
                    if new_spec.localization:
                        logger.info(
                            f"Updated localization settings: {new_spec.localization}"
                        )
                    configuration_changed = True
                except Exception as e:
                    logger.warning(f"Failed to update localization: {e}")

            elif field_path[:2] == ("spec", "authenticationFlows"):
                logger.info("Updating authentication flows")
                try:
                    for flow_config in new_spec.authentication_flows or []:
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
                    logger.warning(f"Failed to update authentication flows: {e}")

            elif field_path[:2] == ("spec", "identityProviders"):
                logger.info("Updating identity providers")
                try:
                    for idp_config in new_spec.identity_providers or []:
                        idp_dict = cast(
                            dict[str, Any],
                            idp_config.model_dump()
                            if hasattr(idp_config, "model_dump")
                            else idp_config,
                        )
                        admin_client.configure_identity_provider(realm_name, idp_dict)
                    configuration_changed = True
                except Exception as e:
                    logger.warning(f"Failed to update identity providers: {e}")

            elif field_path[:2] == ("spec", "userFederation"):
                logger.info("Updating user federation")
                try:
                    for federation_config in new_spec.user_federation or []:
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
                    logger.warning(f"Failed to update user federation: {e}")

            elif field_path[:2] == ("spec", "settings"):
                logger.info("Updating realm settings")
                try:
                    admin_client.update_realm(realm_name, new_spec.to_keycloak_config())
                    configuration_changed = True
                except Exception as e:
                    logger.warning(f"Failed to update realm settings: {e}")

        if configuration_changed:
            logger.info(f"Successfully updated KeycloakRealm {name}")
            return {
                "phase": "Ready",
                "message": "Realm configuration updated successfully",
                "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
            }

    except Exception as e:
        logger.error(f"Failed to update KeycloakRealm {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Update failed: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Realm update failed: {e}", delay=30) from e

    return None  # No changes needed


@kopf.on.delete("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
def delete_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakRealm deletion.

    This handler removes the realm from Keycloak and cleans up
    associated resources.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists

    """
    logger.info(f"Deleting KeycloakRealm {name} in namespace {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # Check for deletion protection
        # Some realms might be protected from accidental deletion
        protection_enabled = realm_spec.deletion_protection
        if protection_enabled:
            finalizers = kwargs.get("meta", {}).get("finalizers", [])
            if "keycloak.mdvr.nl/deletion-confirmed" not in finalizers:
                logger.warning(
                    f"Realm {realm_spec.realm_name} is protected from deletion. "
                    "Add finalizer 'keycloak.mdvr.nl/deletion-confirmed' to proceed."
                )
                return

        # Get admin client for the target Keycloak instance
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        try:
            admin_client = get_keycloak_admin_client(
                keycloak_ref.name, target_namespace
            )

            # Backup realm data if requested
            if realm_spec.backup_on_delete:
                logger.info(f"Backing up realm {realm_spec.realm_name}")
                backup_data = admin_client.backup_realm(realm_spec.realm_name)
                if backup_data:
                    # Store backup in configmap for safe keeping
                    try:
                        import json
                        from datetime import datetime

                        from kubernetes import client as k8s_client

                        from keycloak_operator.utils.kubernetes import (
                            get_kubernetes_client,
                        )

                        k8s = get_kubernetes_client()
                        core_api = k8s_client.CoreV1Api(k8s)

                        # Create backup configmap
                        backup_name = f"{name}-realm-backup-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
                        backup_cm = k8s_client.V1ConfigMap(
                            metadata=k8s_client.V1ObjectMeta(
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

                        core_api.create_namespaced_config_map(
                            namespace=namespace, body=backup_cm
                        )
                        logger.info(f"Realm backup stored in configmap {backup_name}")

                    except Exception as backup_error:
                        logger.warning(
                            f"Failed to store backup in configmap: {backup_error}"
                        )
                        # Continue with deletion even if backup storage fails

                    logger.info("Realm backup created successfully")
                else:
                    logger.warning(
                        f"Failed to create backup for realm {realm_spec.realm_name}"
                    )

            # Clean up clients in this realm first
            # This ensures proper cleanup order and prevents orphaned resources
            realm_clients = admin_client.get_realm_clients(realm_spec.realm_name)
            for client in realm_clients:
                client_id = client.get("clientId")
                if client_id:
                    logger.info(f"Cleaning up client {client_id}")
                    admin_client.delete_client(client_id, realm_spec.realm_name)

            # Remove the realm from Keycloak
            admin_client.delete_realm(realm_spec.realm_name)
            logger.info(f"Deleted realm {realm_spec.realm_name} from Keycloak")

        except Exception as e:
            logger.warning(
                f"Could not delete realm from Keycloak (instance may be deleted): {e}"
            )

        # Clean up any external resources
        # Look for and clean up any additional resources that may have been created
        try:
            from kubernetes import client as k8s_client

            from keycloak_operator.utils.kubernetes import get_kubernetes_client

            k8s = get_kubernetes_client()
            core_api = k8s_client.CoreV1Api(k8s)

            # Clean up any configmaps related to this realm (except backups if they should be preserved)
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
                        logger.info(
                            f"Deleted realm-related configmap {cm.metadata.name}"
                        )
                    except Exception as cm_error:
                        logger.warning(
                            f"Failed to delete configmap {cm.metadata.name}: {cm_error}"
                        )

            except Exception as e:
                logger.warning(f"Failed to clean up realm configmaps: {e}")

            # Clean up any secrets related to this realm (except client credentials which are managed separately)
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
                        logger.info(
                            f"Deleted realm-related secret {secret.metadata.name}"
                        )
                    except Exception as secret_error:
                        logger.warning(
                            f"Failed to delete secret {secret.metadata.name}: {secret_error}"
                        )

            except Exception as e:
                logger.warning(f"Failed to clean up realm secrets: {e}")

            logger.debug(
                f"Completed external resource cleanup for realm {realm_spec.realm_name}"
            )

        except Exception as e:
            logger.warning(f"Failed to clean up external resources: {e}")
            # Don't fail deletion for cleanup issues

        logger.info(f"Successfully deleted KeycloakRealm {name}")

    except Exception as e:
        logger.error(f"Error deleting KeycloakRealm {name}: {e}")
        # Don't raise an error - we want deletion to proceed
        # even if cleanup fails partially


@kopf.timer("keycloakrealms", interval=600)  # Check every 10 minutes
def monitor_realm_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any] | None:
    """
    Periodic health check for KeycloakRealms.

    This timer verifies that realms still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed realms
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of KeycloakRealm {name} in {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # Get admin client and verify connection
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # Check if realm exists in Keycloak
        realm_name = realm_spec.realm_name
        existing_realm = admin_client.get_realm(realm_name)

        if not existing_realm:
            logger.warning(f"Realm {realm_name} missing from Keycloak")
            return {
                "phase": "Degraded",
                "message": "Realm missing from Keycloak, will recreate",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

        # Verify realm configuration matches spec
        try:
            current_realm = admin_client.get_realm(realm_name)
            config_matches = (
                _verify_realm_config(current_realm, realm_spec)
                if current_realm
                else False
            )
        except Exception as e:
            logger.warning(f"Failed to verify realm configuration: {e}")
            config_matches = False
        if not config_matches:
            logger.info(f"Realm {realm_name} configuration drift detected")
            return {
                "phase": "Degraded",
                "message": "Configuration drift detected",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

        # Check authentication flows
        if realm_spec.authentication_flows:
            flows_valid = _verify_authentication_flows(
                admin_client, realm_name, realm_spec.authentication_flows
            )
            if not flows_valid:
                return {
                    "phase": "Degraded",
                    "message": "Authentication flows configuration mismatch",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }

        # Check identity providers
        if realm_spec.identity_providers:
            idps_valid = _verify_identity_providers(
                admin_client, realm_name, realm_spec.identity_providers
            )
            if not idps_valid:
                return {
                    "phase": "Degraded",
                    "message": "Identity provider configuration mismatch",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }

        # Check user federation connections
        if realm_spec.user_federation:
            federation_healthy = _test_user_federation(
                admin_client, realm_name, realm_spec.user_federation
            )
            if not federation_healthy:
                return {
                    "phase": "Degraded",
                    "message": "User federation connection issues detected",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakRealm {name} health check passed")
            return {
                "phase": "Ready",
                "message": "Realm is healthy and properly configured",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

    except Exception as e:
        logger.error(f"Health check failed for KeycloakRealm {name}: {e}")
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": datetime.now(UTC).isoformat(),
        }

    return None  # No status update needed


# Helper functions for health monitoring


def _verify_realm_config(
    current_realm: dict[str, Any], realm_spec: KeycloakRealmSpec
) -> bool:
    """
    Verify that the current realm configuration matches the spec.

    Args:
        current_realm: Current realm configuration from Keycloak
        realm_spec: Desired realm specification

    Returns:
        True if configuration matches, False otherwise
    """
    try:
        # Check basic realm settings
        if current_realm.get("realm") != realm_spec.realm_name:
            return False

        if current_realm.get("enabled") != realm_spec.enabled:
            return False

        if current_realm.get("displayName") != realm_spec.display_name:
            return False

        # Check token settings if specified
        if realm_spec.token_settings:
            token_lifespan = current_realm.get("accessTokenLifespan")
            if token_lifespan != realm_spec.token_settings.access_token_lifespan:
                return False

        # Check security settings if specified
        return not (
            realm_spec.security
            and (
                current_realm.get("bruteForceProtected")
                != realm_spec.security.brute_force_protected
            )
        )

    except Exception:
        return False


def _verify_authentication_flows(
    admin_client, realm_name: str, flow_specs: list
) -> bool:
    """
    Verify that authentication flows exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        flow_specs: List of expected authentication flow specifications

    Returns:
        True if flows are valid, False otherwise
    """
    try:
        # Get current flows from Keycloak
        response = admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/authentication/flows"
        )

        if response.status_code != 200:
            return False

        current_flows = response.json()
        flow_aliases = {flow.get("alias") for flow in current_flows}

        # Check that all expected flows exist
        for flow_spec in flow_specs:
            expected_alias = (
                flow_spec.get("alias")
                if isinstance(flow_spec, dict)
                else flow_spec.alias
            )
            if expected_alias not in flow_aliases:
                return False

        return True

    except Exception:
        return False


def _verify_identity_providers(admin_client, realm_name: str, idp_specs: list) -> bool:
    """
    Verify that identity providers exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        idp_specs: List of expected identity provider specifications

    Returns:
        True if identity providers are valid, False otherwise
    """
    try:
        # Get current identity providers from Keycloak
        response = admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/identity-provider/instances"
        )

        if response.status_code != 200:
            return False

        current_idps = response.json()
        idp_aliases = {idp.get("alias") for idp in current_idps}

        # Check that all expected identity providers exist
        for idp_spec in idp_specs:
            expected_alias = (
                idp_spec.get("alias") if isinstance(idp_spec, dict) else idp_spec.alias
            )
            if expected_alias not in idp_aliases:
                return False

        return True

    except Exception:
        return False


def _test_user_federation(
    admin_client, realm_name: str, federation_specs: list
) -> bool:
    """
    Test user federation connections.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        federation_specs: List of user federation specifications

    Returns:
        True if federation is healthy, False otherwise
    """
    try:
        # Get current user federation components
        response = admin_client._make_request(
            "GET",
            f"/admin/realms/{realm_name}/components?type=org.keycloak.storage.UserStorageProvider",
        )

        if response.status_code != 200:
            return False

        current_federation = response.json()

        # Basic check that expected federation providers exist
        provider_names = {comp.get("name") for comp in current_federation}

        for federation_spec in federation_specs:
            expected_name = (
                federation_spec.get("name")
                if isinstance(federation_spec, dict)
                else federation_spec.name
            )
            if expected_name not in provider_names:
                return False

        return True

    except Exception:
        return False
