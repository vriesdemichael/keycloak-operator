"""
Utils package - Utility modules for Keycloak operator functionality.

Contains helper modules for:
- Keycloak Admin API interactions
- Kubernetes resource management
- Input validation and schema checking
- RBAC and permission checking
"""

from keycloak_operator.utils.rbac import (
    check_namespace_access,
    get_secret_with_validation,
    validate_secret_label,
)

__all__ = [
    "check_namespace_access",
    "validate_secret_label",
    "get_secret_with_validation",
]
