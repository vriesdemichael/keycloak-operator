"""
Common models shared across different resource types.

This module defines shared data structures used by multiple resource models,
such as authorization references and secret references.
"""

from pydantic import BaseModel, Field


class AuthorizationSecretRef(BaseModel):
    """Reference to a secret containing an authorization token."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Name of the authorization secret")
    key: str = Field("token", description="Key within the secret containing the token")
