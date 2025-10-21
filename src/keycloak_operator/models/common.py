"""
Common models shared across different resource types.

This module defines shared data structures used by multiple resource models,
such as authorization references and secret references.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AuthorizationSecretRef(BaseModel):
    """Reference to a secret containing an authorization token."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Name of the authorization secret")
    key: str = Field("token", description="Key within the secret containing the token")


class TokenMetadata(BaseModel):
    """
    Metadata for authorization tokens.

    Stored in ConfigMap for persistence across operator restarts.
    Tokens are stored as SHA-256 hashes for security.
    """

    model_config = {"populate_by_name": True}

    namespace: str = Field(..., description="Namespace this token is valid for")
    token_hash: str = Field(..., description="SHA-256 hash of the token")
    token_type: Literal["admission", "operational"] = Field(
        ..., description="Type of token (admission or operational)"
    )
    issued_at: datetime = Field(..., description="When the token was issued")
    valid_until: datetime = Field(..., description="When the token expires")
    version: int = Field(1, description="Token version (increments on rotation)")
    created_by_realm: str | None = Field(
        None, description="Name of realm that triggered operational token creation"
    )
    revoked: bool = Field(False, description="Whether token has been revoked")
    revoked_at: datetime | None = Field(None, description="When token was revoked")


class AuthorizationStatus(BaseModel):
    """
    Authorization status for a resource.

    Tracks which token is being used and its validity status.
    """

    model_config = {"populate_by_name": True}

    secret_ref: AuthorizationSecretRef = Field(
        ..., description="Reference to the secret containing the token"
    )
    token_type: Literal["admission", "operational"] = Field(
        ..., description="Type of token being used"
    )
    token_version: str = Field(..., description="Version of the token")
    valid_until: datetime = Field(..., description="When the token expires")
    requires_update: bool = Field(
        False, description="Whether token needs to be updated"
    )
