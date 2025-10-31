"""Pydantic models for integration test fixtures.

These models provide type safety and clear documentation for fixture return values.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict


class SharedOperatorInfo(BaseModel):
    """Information about the shared operator deployment.

    The shared operator is deployed once per test session and reused across tests
    for performance. It includes both the operator and a Keycloak instance.
    """

    name: str  # Name of the Keycloak instance (e.g., "keycloak")
    namespace: str  # Namespace where operator and Keycloak are deployed


class KeycloakReadySetup(BaseModel):
    """Complete Keycloak setup with operator, port-forward, and admin client.

    This composite fixture provides everything needed to interact with Keycloak
    from tests running on the host machine.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    operator: SharedOperatorInfo  # Operator deployment info
    local_port: int  # Local port for port-forwarded Keycloak access
    admin_client: Any  # KeycloakAdminClient instance (authenticated)
