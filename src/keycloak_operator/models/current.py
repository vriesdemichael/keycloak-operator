"""
Canonical Keycloak API Models for the Operator.

This module re-exports all Pydantic models from the canonical Keycloak API spec
(currently 26.5.2). All operator logic should be written against these models.

Why wildcard import?
-------------------
The keycloak_api.py module contains 111 auto-generated Pydantic models representing
the complete Keycloak Admin REST API. Listing them explicitly would:
1. Create maintenance burden when regenerating models
2. Risk missing newly added models
3. Provide no practical benefit since this is a deliberate re-export module

The wildcard import is intentional here - this module exists solely to provide
a stable import path for canonical models while the underlying generation may change.

Usage:
    from keycloak_operator.models.current import RealmRepresentation, ClientRepresentation
    # or
    from keycloak_operator.models import keycloak_api
"""

from .keycloak_api import *  # noqa: F401, F403

# Note: __all__ is intentionally not defined here.
# This module re-exports everything from keycloak_api.py.
