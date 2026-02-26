"""
Multi-operator isolation and ownership utilities (ADR-062).

This module implements the logic for determining which operator instance owns
a specific Custom Resource, ensuring that multiple operators can coexist in
the same cluster without interfering with each other.
"""

import asyncio
import logging
import os
from typing import Any

from keycloak_operator.settings import settings

logger = logging.getLogger(__name__)


def get_our_operator_namespace() -> str:
    """Get the namespace where this operator instance is running."""
    return os.environ.get("OPERATOR_NAMESPACE", settings.operator_namespace)


def is_managed_by_this_operator(spec: dict[str, Any], resource_namespace: str) -> bool:
    """
    Check if a Keycloak or KeycloakRealm resource is managed by this operator.

    Logic:
    1. If spec.operatorRef.namespace is provided, it must match ours.
    2. If missing, it's managed if the resource is in our own namespace.
    3. Fallback: If we are cluster-wide (watching all namespaces), we manage it.

    Args:
        spec: Resource specification
        resource_namespace: Namespace where the resource exists

    Returns:
        True if this operator instance should manage the resource
    """
    operator_ref = spec.get("operatorRef", {})
    target_operator_ns = operator_ref.get("namespace")
    our_namespace = get_our_operator_namespace()

    # 1. Explicit target: if operatorRef.namespace is provided, it must match ours
    if target_operator_ns:
        return target_operator_ns == our_namespace

    # 2. Implicit target: no operatorRef provided.
    # Manage if the resource is in our own namespace.
    if resource_namespace == our_namespace:
        return True

    # 3. Cluster-wide fallback: if we are watching all namespaces
    # and no explicit target is set, we manage it by default.
    if not settings.namespaces:
        return True

    # If we are watching specific namespaces, check if this one is in the list
    watch_list = [ns.strip() for ns in settings.namespaces.split(",") if ns.strip()]
    return resource_namespace in watch_list


async def is_client_managed_by_this_operator(
    spec: dict[str, Any],
    resource_namespace: str,
    k8s_client: Any,
) -> bool:
    """
    Check if a KeycloakClient resource is managed by this operator instance.

    A client is managed by the operator that manages its parent realm.

    Args:
        spec: Client resource specification
        resource_namespace: Namespace where the client exists
        k8s_client: Kubernetes API client

    Returns:
        True if this operator instance should manage the client
    """
    from kubernetes import client as k8s_client_mod

    realm_ref = spec.get("realmRef", {})
    realm_name = realm_ref.get("name")
    realm_namespace = realm_ref.get("namespace", resource_namespace)

    if not realm_name:
        logger.warning(f"Client in {resource_namespace} is missing realmRef.name")
        return False

    try:
        custom_objects_api = k8s_client_mod.CustomObjectsApi(k8s_client)
        realm = await asyncio.to_thread(
            custom_objects_api.get_namespaced_custom_object,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=realm_namespace,
            plural="keycloakrealms",
            name=realm_name,
        )
        return is_managed_by_this_operator(realm.get("spec", {}), realm_namespace)
    except Exception as e:
        logger.warning(
            f"Could not determine ownership for client in {resource_namespace}: "
            f"parent realm '{realm_name}' in '{realm_namespace}' lookup failed: {e}"
        )
        # If the realm is missing, we can't claim ownership.
        # Returning False ensures we don't touch the status of an orphan we don't own.
        return False
