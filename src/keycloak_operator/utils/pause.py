"""
Reconciliation pause utilities.

Provides helpers for checking whether reconciliation is paused for each
CR type (Keycloak, Realm, Client). The pause state is driven by
operator-level environment variables set through Helm values.

Delete handlers always proceed regardless of pause state — this module
only gates create/resume, update, health-check, drift-detection and
secret-rotation paths.
"""

from keycloak_operator.settings import settings


def is_keycloak_paused() -> bool:
    """Return True if Keycloak CR reconciliation is paused."""
    return settings.reconcile_pause_keycloak


def is_realms_paused() -> bool:
    """Return True if KeycloakRealm CR reconciliation is paused."""
    return settings.reconcile_pause_realms


def is_clients_paused() -> bool:
    """Return True if KeycloakClient CR reconciliation is paused."""
    return settings.reconcile_pause_clients


def get_pause_message() -> str:
    """Return the operator-configured pause message."""
    return settings.reconcile_pause_message
