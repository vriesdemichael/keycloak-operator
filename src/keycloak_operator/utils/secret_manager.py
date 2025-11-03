"""
Secret management utilities for authorization tokens.

This module handles Kubernetes secret operations for token storage,
including creation, rotation, and cleanup of operational tokens.
"""

import base64
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import AuthorizationError, KubernetesAPIError
from .token_manager import GRACE_PERIOD_DAYS

logger = logging.getLogger(__name__)


class SecretManager:
    """Manages Kubernetes secrets for authorization tokens."""

    def __init__(self, k8s_client: client.ApiClient | None = None):
        """
        Initialize secret manager.

        Args:
            k8s_client: Optional Kubernetes API client
        """
        self.k8s_client = k8s_client
        self._v1: client.CoreV1Api | None = None

    @property
    def v1(self) -> client.CoreV1Api:
        """Get CoreV1Api client."""
        if self._v1 is None:
            if self.k8s_client:
                self._v1 = client.CoreV1Api(self.k8s_client)
            else:
                self._v1 = client.CoreV1Api()
        return self._v1

    async def get_secret(self, name: str, namespace: str) -> client.V1Secret | None:
        """
        Retrieve a secret.

        Args:
            name: Secret name
            namespace: Secret namespace

        Returns:
            Secret object if found, None if not found

        Raises:
            KubernetesAPIError: If read fails for reasons other than 404
        """
        try:
            return self.v1.read_namespaced_secret(name=name, namespace=namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise KubernetesAPIError(
                f"Failed to read secret {namespace}/{name}: {e.reason}",
                reason=e.reason,
            ) from e

    async def create_operational_secret(
        self,
        namespace: str,
        token: str,
        token_version: int,
        valid_until: datetime,
        owner_realm_name: str | None = None,
        owner_realm_uid: str | None = None,
    ) -> client.V1Secret:
        """
        Create an operational token secret.

        Args:
            namespace: Namespace to create secret in
            token: The operational token
            token_version: Token version number
            valid_until: Token expiry timestamp
            owner_realm_name: Optional realm that triggered creation
            owner_realm_uid: Optional realm UID for owner reference

        Returns:
            Created secret object

        Raises:
            KubernetesAPIError: If creation fails
        """
        secret_name = f"{namespace}-operator-token"

        secret_body: dict[str, Any] = {
            "metadata": {
                "name": secret_name,
                "namespace": namespace,
                "labels": {
                    "vriesdemichael.github.io/keycloak-token-type": "operational",
                    "vriesdemichael.github.io/keycloak-managed-by": "keycloak-operator",
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true",
                },
                "annotations": {
                    "vriesdemichael.github.io/keycloak-version": str(token_version),
                    "vriesdemichael.github.io/keycloak-issued-at": datetime.now(
                        UTC
                    ).isoformat(),
                    "vriesdemichael.github.io/keycloak-valid-until": valid_until.isoformat(),
                },
            },
            "type": "Opaque",
            "data": {"token": base64.b64encode(token.encode()).decode()},
        }

        # Add owner reference if realm info provided
        if owner_realm_name and owner_realm_uid:
            secret_body["metadata"]["ownerReferences"] = [
                {
                    "apiVersion": "vriesdemichael.github.io/v1",
                    "kind": "KeycloakRealm",
                    "name": owner_realm_name,
                    "uid": owner_realm_uid,
                    "blockOwnerDeletion": False,
                }
            ]
            secret_body["metadata"]["annotations"][
                "vriesdemichael.github.io/keycloak-created-by-realm"
            ] = owner_realm_name

        try:
            secret = self.v1.create_namespaced_secret(
                namespace=namespace, body=secret_body
            )
            logger.info(
                f"Created operational token secret: {namespace}/{secret_name}, "
                f"version={token_version}"
            )
            return secret
        except ApiException as e:
            if e.status == 409:
                # Already exists (race condition), return existing
                logger.debug(
                    f"Operational token secret already exists: {namespace}/{secret_name}"
                )
                existing = await self.get_secret(secret_name, namespace)
                if existing:
                    return existing
            raise KubernetesAPIError(
                f"Failed to create operational token secret: {e.reason}",
                reason=e.reason,
            ) from e

    async def update_secret_with_rotation(
        self,
        secret: client.V1Secret,
        new_token: str,
        new_version: int,
        new_valid_until: datetime,
    ) -> client.V1Secret:
        """
        Update secret with rotated token (dual token for grace period).

        Args:
            secret: Existing secret object
            new_token: New token value
            new_version: New version number
            new_valid_until: New expiry timestamp

        Returns:
            Updated secret object

        Raises:
            KubernetesAPIError: If update fails
        """
        if not secret.metadata or not secret.metadata.name:
            raise ValueError("Secret must have metadata.name")

        namespace = secret.metadata.namespace
        name = secret.metadata.name

        # Preserve current token as token-previous
        current_token = secret.data.get("token", "") if secret.data else ""

        # Update secret data with dual tokens
        secret.data = {
            "token": base64.b64encode(new_token.encode()).decode(),
            "token-previous": current_token,
        }

        # Update annotations
        if not secret.metadata.annotations:
            secret.metadata.annotations = {}

        grace_period_end = datetime.now(UTC) + timedelta(days=GRACE_PERIOD_DAYS)
        secret.metadata.annotations.update(
            {
                "vriesdemichael.github.io/keycloak-version": str(new_version),
                "vriesdemichael.github.io/keycloak-rotated-at": datetime.now(
                    UTC
                ).isoformat(),
                "vriesdemichael.github.io/keycloak-valid-until": new_valid_until.isoformat(),
                "vriesdemichael.github.io/keycloak-grace-period-ends": grace_period_end.isoformat(),
            }
        )

        try:
            updated = self.v1.replace_namespaced_secret(
                name=name, namespace=namespace, body=secret
            )
            logger.info(
                f"Updated secret with rotated token: {namespace}/{name}, "
                f"version={new_version}, grace_period_ends={grace_period_end}"
            )
            return updated
        except ApiException as e:
            raise KubernetesAPIError(
                f"Failed to update secret with rotation: {e.reason}", reason=e.reason
            ) from e

    async def cleanup_previous_token(self, secret: client.V1Secret) -> client.V1Secret:
        """
        Remove token-previous from secret after grace period.

        Args:
            secret: Secret object with token-previous

        Returns:
            Updated secret object

        Raises:
            KubernetesAPIError: If update fails
        """
        if not secret.metadata or not secret.metadata.name:
            raise ValueError("Secret must have metadata.name")

        namespace = secret.metadata.namespace
        name = secret.metadata.name

        # Remove token-previous from data
        if secret.data and "token-previous" in secret.data:
            secret.data.pop("token-previous")

        # Remove grace period annotation
        if secret.metadata.annotations:
            secret.metadata.annotations.pop(
                "vriesdemichael.github.io/keycloak-grace-period-ends", None
            )

        try:
            updated = self.v1.replace_namespaced_secret(
                name=name, namespace=namespace, body=secret
            )
            logger.info(f"Cleaned up previous token from secret: {namespace}/{name}")
            return updated
        except ApiException as e:
            raise KubernetesAPIError(
                f"Failed to cleanup previous token: {e.reason}", reason=e.reason
            ) from e

    async def get_token_from_secret(
        self, secret: client.V1Secret, namespace: str
    ) -> str:
        """
        Extract token from secret, trying current then previous.

        Args:
            secret: Secret containing token(s)
            namespace: Namespace (for error messages)

        Returns:
            Token value (current or previous if in grace period)

        Raises:
            AuthorizationError: If no valid token found
        """
        if not secret.data:
            raise AuthorizationError(
                f"Secret has no data: {namespace}/{secret.metadata.name}"
            )

        # Try current token first
        if "token" in secret.data:
            try:
                token = base64.b64decode(secret.data["token"]).decode()
                return token
            except Exception as e:
                logger.error(f"Failed to decode current token: {e}")

        # Try previous token (grace period)
        if "token-previous" in secret.data:
            try:
                token = base64.b64decode(secret.data["token-previous"]).decode()
                logger.warning(
                    f"Using previous token for {namespace} (grace period active)"
                )
                return token
            except Exception as e:
                logger.error(f"Failed to decode previous token: {e}")

        raise AuthorizationError(
            f"No valid token found in secret: {namespace}/{secret.metadata.name}"
        )

    async def get_token_type(self, secret: client.V1Secret) -> str:
        """
        Get token type from secret labels.

        Args:
            secret: Secret to check

        Returns:
            Token type ('admission', 'operational', or 'unknown')
        """
        if not secret.metadata or not secret.metadata.labels:
            return "unknown"

        return secret.metadata.labels.get(
            "vriesdemichael.github.io/keycloak-token-type", "unknown"
        )
