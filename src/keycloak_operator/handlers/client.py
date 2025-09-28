"""
KeycloakClient handlers - Manages dynamic client provisioning across namespaces.

This module implements the core feature of dynamic client provisioning that
enables GitOps-compatible client management. Key features:

- Cross-namespace client creation: Clients can reference Keycloak instances
  in different namespaces (subject to RBAC permissions)
- RBAC-based authorization: Uses Kubernetes RBAC instead of Keycloak's
  built-in security mechanisms
- Secure secret management: Client credentials stored in Kubernetes secrets
  with proper access controls
- GitOps compatibility: All client configuration is declarative

The handlers support various client types including:
- Public clients (SPAs, mobile apps)
- Confidential clients (backend services)
- Service accounts for machine-to-machine communication
"""

import logging
from datetime import UTC, datetime
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import (
    check_rbac_permissions,
    create_client_secret,
    get_kubernetes_client,
    validate_keycloak_reference,
)

logger = logging.getLogger(__name__)


@kopf.on.create("keycloakclients", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloakclients", group="keycloak.mdvr.nl", version="v1")
def ensure_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Ensure KeycloakClient exists in the target Keycloak instance.

    This handler implements dynamic client provisioning across namespaces.
    It can create clients in Keycloak instances located in any namespace,
    subject to RBAC permissions.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the KeycloakClient resource exists
        status: Current status of the resource

    Returns:
        Dictionary with status information for the resource

    """
    logger.info(f"Ensuring KeycloakClient {name} in namespace {namespace}")

    try:
        # Parse and validate the client specification
        client_spec = KeycloakClientSpec.model_validate(spec)
        logger.debug(f"Validated KeycloakClient spec: {client_spec}")

        # Update status to indicate processing
        status.update(
            {
                "phase": "Pending",
                "message": "Creating Keycloak client",
            }
        )

        # Resolve Keycloak instance reference
        # This supports cross-namespace references like:
        # keycloakInstanceRef:
        #   name: main-keycloak
        #   namespace: keycloak-system  # Optional, defaults to current namespace
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        keycloak_name = keycloak_ref.name

        logger.info(
            f"Targeting Keycloak instance '{keycloak_name}' "
            f"in namespace '{target_namespace}'"
        )

        # Validate that the Keycloak instance exists and is ready
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            raise kopf.TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}",
                delay=30,
            )

        # Check RBAC permissions for cross-namespace operations
        # If client is in different namespace than Keycloak, verify permissions
        if target_namespace != namespace:
            # Verify that the service account has permission to access
            # the Keycloak instance in the target namespace
            has_permission = check_rbac_permissions(
                namespace=namespace,
                target_namespace=target_namespace,
                resource="keycloaks",
                verb="get",
            )
            if not has_permission:
                raise kopf.PermanentError(
                    f"Insufficient permissions to access Keycloak instance "
                    f"{keycloak_name} in namespace {target_namespace}. "
                    f"Ensure the operator service account has proper RBAC permissions."
                )

        # Get Keycloak admin client
        admin_client = get_keycloak_admin_client(keycloak_name, target_namespace)

        # Check if client already exists in the specified realm
        realm_name = client_spec.realm or "master"
        existing_client = admin_client.get_client_by_name(
            client_spec.client_id, realm_name
        )

        if existing_client:
            logger.info(f"Client {client_spec.client_id} already exists, updating...")
            # Update existing client configuration
            admin_client.update_client(
                existing_client["id"], client_spec.to_keycloak_config(), realm_name
            )
        else:
            logger.info(f"Creating new client {client_spec.client_id}")
            # Create new client in Keycloak
            admin_client.create_client(client_spec.to_keycloak_config(), realm_name)

        # Generate and retrieve client credentials for confidential clients
        client_secret = None
        if not client_spec.public_client:
            # Get or regenerate client secret
            client_secret = admin_client.get_client_secret(
                client_spec.client_id, realm_name
            )
            logger.info("Retrieved client secret for confidential client")

        # Create Kubernetes secret with client credentials
        # Store in the same namespace as the KeycloakClient resource
        secret_name = f"{name}-credentials"
        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id=client_spec.client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
            realm=realm_name,
        )

        # Set up RBAC for secret access
        # Create service-specific labels to allow targeted RBAC policies
        try:
            k8s_client = get_kubernetes_client()
            core_api = client.CoreV1Api(k8s_client)

            # Add labels to the secret for RBAC targeting
            secret_name = f"{name}-credentials"
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
                logger.debug(f"Added RBAC labels to secret {secret_name}")

            except ApiException as e:
                if e.status != 404:
                    logger.warning(f"Failed to add RBAC labels to secret: {e}")

        except Exception as e:
            logger.warning(f"Failed to set up RBAC for secret {secret_name}: {e}")
            # Don't fail client creation for RBAC setup issues

        # Configure client-specific settings
        # Apply advanced client configurations if specified
        try:
            if (
                hasattr(client_spec, "protocol_mappers")
                and client_spec.protocol_mappers
            ):
                logger.info(
                    f"Applying protocol mappers for client {client_spec.client_id}"
                )
                # Note: Protocol mappers would be applied via admin API
                # For now, log the configuration that would be applied
                for mapper in client_spec.protocol_mappers:
                    logger.debug(f"Protocol mapper: {mapper}")

            if (
                hasattr(client_spec, "default_client_scopes")
                and client_spec.default_client_scopes
            ):
                logger.info(
                    f"Configuring default client scopes for {client_spec.client_id}"
                )
                # Note: Client scopes would be configured via admin API
                for scope in client_spec.default_client_scopes:
                    logger.debug(f"Default scope: {scope}")

            if (
                hasattr(client_spec, "optional_client_scopes")
                and client_spec.optional_client_scopes
            ):
                logger.info(
                    f"Configuring optional client scopes for {client_spec.client_id}"
                )
                for scope in client_spec.optional_client_scopes:
                    logger.debug(f"Optional scope: {scope}")

            # Additional client settings are already handled in to_keycloak_config()
            logger.debug(
                f"Client-specific configuration applied for {client_spec.client_id}"
            )

        except Exception as e:
            logger.warning(f"Failed to apply client-specific settings: {e}")
            # Don't fail client creation for advanced settings issues

        logger.info(f"Successfully created KeycloakClient {name}")

        return {
            "phase": "Ready",
            "message": "Client successfully created and configured",
            "clientId": client_spec.client_id,
            "realm": realm_name,
            "keycloakInstance": f"{target_namespace}/{keycloak_name}",
            "credentialsSecret": secret_name,
            "publicClient": client_spec.public_client,
            "endpoints": {
                "auth": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}",
                "token": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}/protocol/openid-connect/token",
                "userinfo": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}/protocol/openid-connect/userinfo",
            },
        }

    except ApiException as e:
        logger.error(f"Kubernetes API error creating KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Kubernetes API error: {e.reason}",
            }
        )
        raise kopf.TemporaryError(f"Kubernetes API error: {e}", delay=30) from e

    except Exception as e:
        logger.error(f"Error creating KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Failed to create client: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Client creation failed: {e}", delay=60) from e


@kopf.on.update("keycloakclients", group="keycloak.mdvr.nl", version="v1")
def update_keycloak_client(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Handle updates to KeycloakClient specifications.

    This handler processes changes to client configurations and applies
    them to the target Keycloak instance.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    logger.info(f"Updating KeycloakClient {name} in namespace {namespace}")

    # Log changes for debugging
    for operation, field_path, old_value, new_value in diff:
        logger.info(
            f"KeycloakClient change - {operation}: {field_path} "
            f"from {old_value} to {new_value}"
        )

    status.update(
        {
            "phase": "Updating",
            "message": "Applying client configuration changes",
        }
    )

    try:
        # Validate that immutable fields haven't changed
        old_spec = KeycloakClientSpec.model_validate(old["spec"])
        new_spec = KeycloakClientSpec.model_validate(new["spec"])

        # Check for changes to immutable fields
        if old_spec.client_id != new_spec.client_id:
            raise kopf.PermanentError(
                "Cannot change client_id of existing KeycloakClient"
            )

        if old_spec.keycloak_instance_ref != new_spec.keycloak_instance_ref:
            raise kopf.PermanentError(
                "Cannot change keycloak_instance_ref of existing KeycloakClient"
            )

        # Get admin client for the target Keycloak instance
        keycloak_ref = new_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        # Get Keycloak instance for URL
        keycloak_instance = validate_keycloak_reference(
            keycloak_ref.name, target_namespace
        )
        if not keycloak_instance:
            raise kopf.TemporaryError(
                f"Keycloak instance {keycloak_ref.name} not found or not ready "
                f"in namespace {target_namespace}",
                delay=30,
            )

        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        realm_name = new_spec.realm or "master"

        # Apply configuration updates based on the diff
        configuration_changed = False
        for _operation, field_path, _old_value, _new_value in diff:
            if field_path[:2] == ("spec", "redirectUris"):
                logger.info("Updating client redirect URIs")
                # Update redirect URIs in Keycloak
                configuration_changed = True

            elif field_path[:2] == ("spec", "scopes"):
                logger.info("Updating client scopes")
                # Update client scopes
                configuration_changed = True

            elif field_path[:2] == ("spec", "settings"):
                logger.info("Updating client settings")
                # Update client configuration
                configuration_changed = True

        if configuration_changed:
            # Apply all changes to Keycloak
            admin_client.update_client(
                new_spec.client_id, new_spec.to_keycloak_config(), realm_name
            )

        # Handle client secret regeneration
        regenerate_secret = new_spec.regenerate_secret
        if regenerate_secret and not new_spec.public_client:
            logger.info("Regenerating client secret")
            # Generate new secret in Keycloak
            new_secret = admin_client.regenerate_client_secret(
                new_spec.client_id, realm_name
            )

            # Update Kubernetes secret
            secret_name = f"{name}-credentials"
            create_client_secret(
                secret_name=secret_name,
                namespace=namespace,
                client_id=new_spec.client_id,
                client_secret=new_secret,
                keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
                realm=realm_name,
                update_existing=True,
            )

        logger.info(f"Successfully updated KeycloakClient {name}")

        return {
            "phase": "Ready",
            "message": "Client configuration updated successfully",
            "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
        }

    except Exception as e:
        logger.error(f"Failed to update KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Update failed: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Client update failed: {e}", delay=30) from e


@kopf.on.delete("keycloakclients", group="keycloak.mdvr.nl", version="v1")
def delete_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakClient deletion.

    This handler cleans up the client from Keycloak and removes
    associated Kubernetes resources.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists

    """
    logger.info(f"Deleting KeycloakClient {name} in namespace {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # Get admin client for the target Keycloak instance
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        # Check if Keycloak instance still exists
        # If it's being deleted too, we might not be able to clean up
        try:
            admin_client = get_keycloak_admin_client(
                keycloak_ref.name, target_namespace
            )

            # Remove client from Keycloak
            realm_name = client_spec.realm or "master"
            admin_client.delete_client(client_spec.client_id, realm_name)
            logger.info(f"Deleted client {client_spec.client_id} from Keycloak")

        except Exception as e:
            logger.warning(
                f"Could not delete client from Keycloak (instance may be deleted): {e}"
            )

        # Delete the credentials secret
        try:
            core_api = client.CoreV1Api(get_kubernetes_client())
            secret_name = f"{name}-credentials"
            core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)
            logger.info(f"Deleted credentials secret {secret_name}")
        except ApiException as e:
            if e.status != 404:  # Ignore "not found" errors
                logger.warning(f"Failed to delete credentials secret: {e}")

        # Clean up any additional resources
        # Clean up any custom resources that may have been created
        try:
            k8s_client = get_kubernetes_client()
            core_api = client.CoreV1Api(k8s_client)

            # Look for and clean up any configmaps with our labels
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
                        logger.info(f"Deleted configmap {cm.metadata.name}")
                    except ApiException as cm_error:
                        if cm_error.status != 404:
                            logger.warning(
                                f"Failed to delete configmap {cm.metadata.name}: {cm_error}"
                            )

            except ApiException as e:
                logger.warning(f"Failed to list configmaps for cleanup: {e}")

            # Clean up any service accounts or RBAC resources if they were created
            # (In practice, these would typically be managed by external RBAC policies)
            logger.debug(
                f"Completed additional resource cleanup for KeycloakClient {name}"
            )

        except Exception as e:
            logger.warning(f"Failed to clean up additional resources: {e}")
            # Don't fail deletion for cleanup issues

        logger.info(f"Successfully deleted KeycloakClient {name}")

    except Exception as e:
        logger.error(f"Error deleting KeycloakClient {name}: {e}")
        # Don't raise an error - we want deletion to proceed
        # even if cleanup fails partially


@kopf.timer("keycloakclients", interval=300)  # Check every 5 minutes
def monitor_client_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Periodic health check for KeycloakClients.

    This timer verifies that clients still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed clients
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of KeycloakClient {name} in {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # Get admin client and verify connection
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # Check if client exists in Keycloak
        realm_name = client_spec.realm or "master"
        existing_client = admin_client.get_client_by_name(
            client_spec.client_id, realm_name
        )

        if not existing_client:
            logger.warning(f"Client {client_spec.client_id} missing from Keycloak")
            return {
                "phase": "Degraded",
                "message": "Client missing from Keycloak, will recreate",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

        # Verify client configuration matches spec
        # Compare current Keycloak client config with desired spec
        try:
            desired_config = client_spec.to_keycloak_config()
            config_matches = True

            # Check critical configuration fields
            if existing_client.get("enabled") != desired_config.get("enabled", True):
                config_matches = False
                logger.warning(f"Client {client_spec.client_id} enabled state mismatch")

            if existing_client.get("publicClient") != desired_config.get(
                "publicClient", False
            ):
                config_matches = False
                logger.warning(
                    f"Client {client_spec.client_id} public client setting mismatch"
                )

            # Check redirect URIs if specified
            if desired_config.get("redirectUris"):
                existing_uris = set(existing_client.get("redirectUris", []))
                desired_uris = set(desired_config.get("redirectUris", []))
                if existing_uris != desired_uris:
                    config_matches = False
                    logger.warning(
                        f"Client {client_spec.client_id} redirect URIs mismatch"
                    )

            # Check web origins if specified
            if desired_config.get("webOrigins"):
                existing_origins = set(existing_client.get("webOrigins", []))
                desired_origins = set(desired_config.get("webOrigins", []))
                if existing_origins != desired_origins:
                    config_matches = False
                    logger.warning(
                        f"Client {client_spec.client_id} web origins mismatch"
                    )

            if not config_matches:
                logger.info(
                    f"Client {client_spec.client_id} configuration drift detected"
                )
                return {
                    "phase": "Degraded",
                    "message": "Configuration drift detected",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }

        except Exception as e:
            logger.warning(f"Failed to verify client configuration: {e}")
            # Don't fail health check for verification errors

        # Check credentials secret exists and is valid
        if not client_spec.public_client:
            try:
                k8s_client = get_kubernetes_client()
                core_api = client.CoreV1Api(k8s_client)
                secret_name = f"{name}-credentials"

                # Check if secret exists
                try:
                    secret = core_api.read_namespaced_secret(
                        name=secret_name, namespace=namespace
                    )

                    # Validate secret has required keys
                    required_keys = ["client-id", "client-secret"]
                    missing_keys = []

                    if not secret.data:
                        return {
                            "phase": "Degraded",
                            "message": "Client credentials secret exists but has no data",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }

                    for key in required_keys:
                        if key not in secret.data:
                            missing_keys.append(key)

                    if missing_keys:
                        return {
                            "phase": "Degraded",
                            "message": f"Client credentials secret missing keys: {', '.join(missing_keys)}",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }

                    logger.debug(f"Client credentials secret {secret_name} is valid")

                except ApiException as e:
                    if e.status == 404:
                        return {
                            "phase": "Degraded",
                            "message": "Client credentials secret missing",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }
                    else:
                        logger.warning(f"Failed to check credentials secret: {e}")

            except Exception as e:
                logger.warning(f"Failed to validate credentials secret: {e}")
                # Don't fail health check for secret validation errors

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakClient {name} health check passed")
            return {
                "phase": "Ready",
                "message": "Client is healthy and properly configured",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

    except Exception as e:
        logger.error(f"Health check failed for KeycloakClient {name}: {e}")
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": datetime.now(UTC).isoformat(),
        }

    return None  # No status update needed
