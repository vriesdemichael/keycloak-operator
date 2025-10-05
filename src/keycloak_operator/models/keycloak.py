"""
Pydantic models for Keycloak instance resources.

This module defines type-safe data models for Keycloak instance specifications
and status. These models ensure proper validation and provide IDE support
for the operator development.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class SecretReference(BaseModel):
    """Reference to a secret key for sensitive data."""

    name: str = Field(..., description="Name of the secret")
    key: str = Field("password", description="Key within the secret")


class KeycloakInstanceRef(BaseModel):
    """Reference to a Keycloak instance in any namespace."""

    name: str = Field(..., description="Name of the Keycloak instance")
    namespace: str | None = Field(
        None, description="Namespace of the Keycloak instance (defaults to current)"
    )


class KeycloakTLSConfig(BaseModel):
    """TLS configuration for Keycloak instance."""

    enabled: bool = Field(False, description="Enable TLS/SSL")
    secret_name: str | None = Field(
        None, description="Name of secret containing TLS certificate and key"
    )
    hostname: str | None = Field(None, description="Hostname for TLS certificate (SNI)")


class KeycloakServiceConfig(BaseModel):
    """Service configuration for Keycloak instance."""

    type: str = Field("ClusterIP", description="Kubernetes service type")
    http_port: int = Field(8080, description="HTTP port number", ge=1, le=65535)
    https_port: int = Field(8443, description="HTTPS port number", ge=1, le=65535)
    annotations: dict[str, str] = Field(
        default_factory=dict, description="Service annotations"
    )

    @field_validator("type")
    @classmethod
    def validate_service_type(cls, v):
        valid_types = ["ClusterIP", "NodePort", "LoadBalancer", "ExternalName"]
        if v not in valid_types:
            raise ValueError(f"Service type must be one of {valid_types}")
        return v


class KeycloakIngressConfig(BaseModel):
    """Ingress configuration for Keycloak instance."""

    enabled: bool = Field(False, description="Enable ingress")
    class_name: str | None = Field(None, description="Ingress class name")
    host: str | None = Field(None, description="Ingress hostname")
    path: str = Field("/", description="Ingress path")
    annotations: dict[str, str] = Field(
        default_factory=dict, description="Ingress annotations"
    )
    tls_enabled: bool = Field(True, description="Enable TLS for ingress")
    tls_secret_name: str | None = Field(
        None, description="Secret containing TLS certificate"
    )


class KeycloakResourceRequirements(BaseModel):
    """Resource requirements for Keycloak pods."""

    requests: dict[str, str] = Field(
        default_factory=lambda: {"cpu": "500m", "memory": "512Mi"},
        description="Resource requests",
    )
    limits: dict[str, str] = Field(
        default_factory=lambda: {"cpu": "1000m", "memory": "1Gi"},
        description="Resource limits",
    )


class CloudNativePGReference(BaseModel):
    """Reference to a CloudNativePG Cluster resource."""

    name: str = Field(..., description="Name of the CloudNativePG Cluster")
    namespace: str | None = Field(
        None, description="Namespace of the CNPG Cluster (defaults to same namespace)"
    )
    database: str = Field(
        "keycloak", description="Database name to use within the cluster"
    )
    application_name: str = Field(
        "keycloak", description="Application name for connection tracking"
    )

    @field_validator("name")
    @classmethod
    def validate_cluster_name(cls, v):
        if not v or not v.strip():
            raise ValueError("CloudNativePG cluster name cannot be empty")
        return v.strip()


class ExternalSecretReference(BaseModel):
    """Reference to an ExternalSecrets resource."""

    name: str = Field(..., description="Name of the ExternalSecret")
    namespace: str | None = Field(
        None, description="Namespace of the ExternalSecret (defaults to same namespace)"
    )
    refresh_interval: str = Field(
        "15m", description="Refresh interval for secret rotation"
    )

    @field_validator("refresh_interval")
    @classmethod
    def validate_refresh_interval(cls, v):
        # Basic validation for Kubernetes duration format
        import re

        if not re.match(r"^\d+[smh]$", v):
            raise ValueError(
                "Refresh interval must be in format like '15m', '1h', '30s'"
            )
        return v


class KeycloakDatabaseConfig(BaseModel):
    """
    Database configuration for Keycloak instance.

    Production-ready configuration that enforces external database usage
    with support for CloudNativePG integration and ExternalSecrets.
    """

    type: str = Field(
        ..., description="Database type (no default - must be explicitly specified)"
    )

    # CloudNativePG Integration (recommended)
    cnpg_cluster: CloudNativePGReference | None = Field(
        None, description="CloudNativePG cluster reference (recommended for PostgreSQL)"
    )

    # Traditional database configuration
    host: str | None = Field(
        None, description="Database host (required if not using CNPG)"
    )
    port: int | None = Field(
        None, description="Database port (auto-detected if not specified)"
    )
    database: str | None = Field(
        None, description="Database name (required if not using CNPG)"
    )
    username: str | None = Field(None, description="Database username")

    # Secret management options
    password_secret: SecretReference | None = Field(
        None, description="Secret reference for database password (recommended)"
    )
    credentials_secret: str | None = Field(
        None, description="Kubernetes secret name with database credentials"
    )
    external_secret: ExternalSecretReference | None = Field(
        None, description="ExternalSecrets reference for credential management"
    )

    # Advanced configuration
    connection_params: dict[str, str] = Field(
        default_factory=dict, description="Additional database connection parameters"
    )
    connection_pool: dict[str, Any] = Field(
        default_factory=lambda: {
            "max_connections": 20,
            "min_connections": 5,
            "connection_timeout": "30s",
        },
        description="Database connection pool configuration",
    )
    ssl_mode: str = Field("require", description="SSL mode for database connections")
    migration_strategy: str = Field(
        "auto", description="Database migration strategy (auto, manual, skip)"
    )

    @field_validator("type")
    @classmethod
    def validate_database_type(cls, v):
        # Removed H2 from valid types - enforce external database usage
        valid_types = ["postgresql", "mysql", "mariadb", "oracle", "mssql", "cnpg"]
        if v not in valid_types:
            raise ValueError(
                f"Database type must be one of {valid_types}. "
                f"H2 is not supported for production deployments. "
                f"Use 'cnpg' type with cnpg_cluster for CloudNativePG integration."
            )
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v):
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("ssl_mode")
    @classmethod
    def validate_ssl_mode(cls, v):
        valid_modes = [
            "disable",
            "allow",
            "prefer",
            "require",
            "verify-ca",
            "verify-full",
        ]
        if v not in valid_modes:
            raise ValueError(f"SSL mode must be one of {valid_modes}")
        return v

    @field_validator("migration_strategy")
    @classmethod
    def validate_migration_strategy(cls, v):
        valid_strategies = ["auto", "manual", "skip"]
        if v not in valid_strategies:
            raise ValueError(f"Migration strategy must be one of {valid_strategies}")
        return v

    @model_validator(mode="after")
    def validate_database_configuration(self) -> "KeycloakDatabaseConfig":
        """Validate complete database configuration with production-ready requirements."""

        # CloudNativePG configuration
        if self.type == "cnpg":
            if not self.cnpg_cluster:
                raise ValueError(
                    "When using 'cnpg' type, cnpg_cluster reference must be specified"
                )
            # CNPG handles connection details automatically
            return self

        # Traditional external database configuration
        missing_fields = []

        if not self.host:
            missing_fields.append("host")

        if not self.database:
            missing_fields.append("database")

        # Set default ports based on database type
        default_ports = {
            "postgresql": 5432,
            "mysql": 3306,
            "mariadb": 3306,
            "oracle": 1521,
            "mssql": 1433,
        }

        if not self.port and self.type in default_ports:
            object.__setattr__(self, "port", default_ports[self.type])

        if missing_fields:
            raise ValueError(
                f"Database type '{self.type}' requires the following fields: {', '.join(missing_fields)}. "
                f"Alternatively, use type 'cnpg' with cnpg_cluster for CloudNativePG integration."
            )

        # Validate credential configuration
        credential_sources = [
            self.username,
            self.credentials_secret,
            self.external_secret,
        ]

        if not any(credential_sources):
            raise ValueError(
                "Database credentials must be specified via username/password, "
                "credentials_secret, or external_secret. "
                "For CloudNativePG, use type 'cnpg' with cnpg_cluster."
            )

        # Warn about security best practices
        if self.ssl_mode in ["disable", "allow"]:
            import warnings

            warnings.warn(
                f"SSL mode '{self.ssl_mode}' is not recommended for production. "
                f"Consider using 'require' or higher for better security.",
                UserWarning,
                stacklevel=2,
            )

        return self


class KeycloakSpec(BaseModel):
    """
    Specification for a Keycloak instance.

    This model defines all configurable aspects of a Keycloak deployment
    including resources, networking, persistence, and authentication.
    """

    # Core configuration
    image: str = Field(
        "quay.io/keycloak/keycloak:26.4.0", description="Keycloak container image"
    )
    replicas: int = Field(1, description="Number of Keycloak replicas", ge=1)

    # Resource management
    resources: KeycloakResourceRequirements = Field(
        default_factory=KeycloakResourceRequirements,
        description="Resource requirements for Keycloak pods",
    )

    # Networking
    service: KeycloakServiceConfig = Field(
        default_factory=KeycloakServiceConfig, description="Service configuration"
    )
    ingress: KeycloakIngressConfig = Field(
        default_factory=KeycloakIngressConfig, description="Ingress configuration"
    )
    tls: KeycloakTLSConfig = Field(
        default_factory=KeycloakTLSConfig, description="TLS configuration"
    )

    # Database
    database: KeycloakDatabaseConfig = Field(
        default_factory=KeycloakDatabaseConfig, description="Database configuration"
    )

    # Environment and configuration
    env: dict[str, str] = Field(
        default_factory=dict, description="Additional environment variables"
    )
    jvm_options: list[str] = Field(
        default_factory=list, description="JVM options for Keycloak"
    )

    # Operational settings
    startup_probe: dict[str, Any] = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/started", "port": 9000},
            "initialDelaySeconds": 30,
            "periodSeconds": 10,
            "timeoutSeconds": 5,
            "failureThreshold": 30,
        },
        description="Startup probe configuration",
    )
    liveness_probe: dict[str, Any] = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/live", "port": 9000},
            "initialDelaySeconds": 60,
            "periodSeconds": 30,
            "timeoutSeconds": 5,
            "failureThreshold": 3,
        },
        description="Liveness probe configuration",
    )
    readiness_probe: dict[str, Any] = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/ready", "port": 9000},
            "initialDelaySeconds": 30,
            "periodSeconds": 10,
            "timeoutSeconds": 5,
            "failureThreshold": 3,
        },
        description="Readiness probe configuration",
    )

    # Security and RBAC
    pod_security_context: dict[str, Any] = Field(
        default_factory=dict, description="Pod security context"
    )
    security_context: dict[str, Any] = Field(
        default_factory=dict, description="Container security context"
    )
    service_account: str | None = Field(
        None, description="Service account to use for Keycloak pods"
    )

    @field_validator("image")
    @classmethod
    def validate_image(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Image must be a non-empty string")
        return v

    @field_validator("replicas")
    @classmethod
    def validate_replicas(cls, v):
        if v < 1:
            raise ValueError("Replicas must be at least 1")
        if v > 1:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"Keycloak replica count is {v}. For multi-replica deployments, "
                "ensure you have configured: (1) external database (not H2), "
                "(2) shared storage for themes/extensions, "
                "(3) proper load balancing, and (4) session affinity or "
                "distributed caching for optimal performance."
            )
        return v


class KeycloakEndpoints(BaseModel):
    """Endpoints for accessing Keycloak instance."""

    public: str | None = Field(None, description="Public endpoint URL")
    admin: str | None = Field(None, description="Admin console URL")
    internal: str | None = Field(None, description="Internal cluster URL")
    management: str | None = Field(None, description="Management endpoint URL")


class KeycloakCondition(BaseModel):
    """Status condition for Keycloak instance."""

    type: str = Field(..., description="Condition type")
    status: str = Field(..., description="Condition status (True/False/Unknown)")
    reason: str | None = Field(None, description="Reason for the condition")
    message: str | None = Field(None, description="Human-readable message")
    last_transition_time: str | None = Field(
        None, description="Last time the condition transitioned"
    )


class KeycloakStatus(BaseModel):
    """
    Status of a Keycloak instance.

    This model represents the current state and health of a Keycloak deployment
    as observed by the operator.
    """

    # Overall status
    phase: str = Field("Pending", description="Current phase of the Keycloak instance")
    message: str | None = Field(None, description="Human-readable status message")
    reason: str | None = Field(None, description="Reason for current phase")

    # Detailed status
    conditions: list[KeycloakCondition] = Field(
        default_factory=list, description="Detailed status conditions"
    )
    observed_generation: int | None = Field(
        None, description="Generation of the spec that was last processed"
    )

    # Deployment status
    replicas: int | None = Field(None, description="Total number of replicas")
    ready_replicas: int | None = Field(None, description="Number of ready replicas")
    available_replicas: int | None = Field(
        None, description="Number of available replicas"
    )

    # Resource information
    deployment: str | None = Field(None, description="Name of the deployment")
    service: str | None = Field(None, description="Name of the service")
    ingress: str | None = Field(None, description="Name of the ingress")
    persistent_volume_claims: list[str] = Field(
        default_factory=list, description="Names of persistent volume claims"
    )

    # Endpoints
    endpoints: KeycloakEndpoints = Field(
        default_factory=KeycloakEndpoints, description="Access endpoints"
    )

    # Version and capability information
    version: str | None = Field(None, description="Running Keycloak version")
    capabilities: list[str] = Field(
        default_factory=list, description="Detected capabilities"
    )

    # Health and monitoring
    last_health_check: str | None = Field(
        None, description="Timestamp of last health check"
    )
    health_status: str | None = Field(None, description="Current health status")

    # Statistics (optional)
    stats: dict[str, Any] = Field(
        default_factory=dict, description="Operational statistics"
    )


class Keycloak(BaseModel):
    """
    Complete Keycloak custom resource model.

    This represents the full Kubernetes custom resource including
    metadata, spec, and status sections.
    """

    api_version: str = Field("keycloak.mdvr.nl/v1", alias="apiVersion")
    kind: str = Field("Keycloak")
    metadata: dict[str, Any] = Field(..., description="Kubernetes metadata")
    spec: KeycloakSpec = Field(..., description="Keycloak specification")
    status: KeycloakStatus | None = Field(
        None, description="Keycloak status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"
