"""
Pydantic models for Keycloak instance resources.

This module defines type-safe data models for Keycloak instance specifications
and status. These models ensure proper validation and provide IDE support
for the operator development.
"""

import re

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from keycloak_operator.models.types import (
    KubernetesMetadata,
    KubernetesProbeConfig,
    KubernetesSecurityContext,
    OperationalStats,
    OperatorRef,
)


class SecretReference(BaseModel):
    """
    Reference to a secret key for sensitive data.

    The secret must be in the same namespace as the resource referencing it.
    Cross-namespace secret references are not supported for security reasons.
    """

    model_config = {"populate_by_name": True}

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

    model_config = {"populate_by_name": True}

    enabled: bool = Field(False, description="Enable TLS/SSL")
    secret_name: str | None = Field(
        None,
        alias="secretName",
        description="Name of secret containing TLS certificate and key",
    )
    hostname: str | None = Field(None, description="Hostname for TLS certificate (SNI)")


class KeycloakServiceConfig(BaseModel):
    """Service configuration for Keycloak instance."""

    model_config = {"populate_by_name": True}

    type: str = Field("ClusterIP", description="Kubernetes service type")
    http_port: int = Field(
        8080, alias="httpPort", description="HTTP port number", ge=1, le=65535
    )
    https_port: int = Field(
        8443, alias="httpsPort", description="HTTPS port number", ge=1, le=65535
    )
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

    model_config = {"populate_by_name": True}

    enabled: bool = Field(False, description="Enable ingress")
    class_name: str | None = Field(
        None, alias="className", description="Ingress class name"
    )
    host: str | None = Field(None, description="Ingress hostname")
    path: str = Field("/", description="Ingress path")
    annotations: dict[str, str] = Field(
        default_factory=dict, description="Ingress annotations"
    )
    tls_enabled: bool = Field(
        True, alias="tlsEnabled", description="Enable TLS for ingress"
    )
    tls_secret_name: str | None = Field(
        None, alias="tlsSecretName", description="Secret containing TLS certificate"
    )


class ConnectionPoolConfig(BaseModel):
    """Database connection pool configuration."""

    model_config = {"populate_by_name": True}

    max_connections: int = Field(
        20, alias="maxConnections", description="Maximum number of connections"
    )
    min_connections: int = Field(
        5, alias="minConnections", description="Minimum number of connections"
    )
    connection_timeout: str = Field(
        "30s", alias="connectionTimeout", description="Connection timeout"
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


class CnpgDatabaseConfig(BaseModel):
    """
    Tier 1: CloudNativePG-managed database configuration (ADR-088).

    When using CNPG, the operator resolves connection details from the
    CNPG Cluster CR automatically. Users only need to specify the cluster
    name. This tier supports automated backup via the CNPG Backup API.
    """

    model_config = {"populate_by_name": True}

    cluster_name: str = Field(
        ...,
        alias="clusterName",
        description="Name of the CNPG Cluster resource",
    )
    namespace: str | None = Field(
        None,
        description="Namespace of the CNPG Cluster (defaults to Keycloak namespace)",
    )


class ManagedDatabaseConfig(BaseModel):
    """
    Tier 2: Generic managed PostgreSQL database configuration (ADR-088).

    For databases where the operator has connection access but does not
    manage the database lifecycle. Supports backup via VolumeSnapshot
    (Phase 2).
    """

    model_config = {"populate_by_name": True}

    host: str = Field(..., description="Database host")
    port: int | None = Field(
        None, description="Database port (defaults to 5432 for postgresql)"
    )
    database: str = Field(..., description="Database name")
    username: str | None = Field(None, description="Database username")
    password_secret: SecretReference | None = Field(
        None,
        alias="passwordSecret",
        description="Secret reference for database password",
    )
    credentials_secret: str | None = Field(
        None,
        alias="credentialsSecret",
        description="Kubernetes secret name with database credentials",
    )
    connection_params: dict[str, str] = Field(
        default_factory=dict,
        alias="connectionParams",
        description="Additional database connection parameters",
    )
    connection_pool: ConnectionPoolConfig = Field(
        default_factory=ConnectionPoolConfig,
        alias="connectionPool",
        description="Database connection pool configuration",
    )
    ssl_mode: str = Field(
        "require", alias="sslMode", description="SSL mode for database connections"
    )
    pvc_name: str | None = Field(
        None,
        alias="pvcName",
        description="PersistentVolumeClaim name for VolumeSnapshot backup during upgrades (ADR-088 Phase 2)",
    )
    volume_snapshot_class_name: str | None = Field(
        None,
        alias="volumeSnapshotClassName",
        description="VolumeSnapshotClass name for backup snapshots (ADR-088 Phase 2). "
        "Required when pvcName is set.",
    )

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("ssl_mode")
    @classmethod
    def validate_ssl_mode(cls, v: str) -> str:
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


class ExternalDatabaseConfig(BaseModel):
    """
    Tier 3: Externally managed database configuration (ADR-088).

    For databases fully managed outside the operator's control. The operator
    can connect but cannot perform backups. During upgrades, a manual gate
    (annotation-based confirmation) is required.
    """

    model_config = {"populate_by_name": True}

    host: str = Field(..., description="Database host")
    port: int | None = Field(
        None, description="Database port (defaults to 5432 for postgresql)"
    )
    database: str = Field(..., description="Database name")
    username: str | None = Field(None, description="Database username")
    password_secret: SecretReference | None = Field(
        None,
        alias="passwordSecret",
        description="Secret reference for database password",
    )
    credentials_secret: str | None = Field(
        None,
        alias="credentialsSecret",
        description="Kubernetes secret name with database credentials",
    )
    connection_params: dict[str, str] = Field(
        default_factory=dict,
        alias="connectionParams",
        description="Additional database connection parameters",
    )
    connection_pool: ConnectionPoolConfig = Field(
        default_factory=ConnectionPoolConfig,
        alias="connectionPool",
        description="Database connection pool configuration",
    )
    ssl_mode: str = Field(
        "require", alias="sslMode", description="SSL mode for database connections"
    )

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("ssl_mode")
    @classmethod
    def validate_ssl_mode(cls, v: str) -> str:
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


class KeycloakDatabaseConfig(BaseModel):
    """
    Database configuration for Keycloak instance.

    Supports three tiers (ADR-088):
    - cnpg: CloudNativePG-managed (Tier 1) — operator resolves connection from CNPG Cluster
    - managed: Generic PostgreSQL (Tier 2) — operator has direct connection access
    - external: Externally managed (Tier 3) — operator connects but cannot back up

    Legacy flat fields are preserved for backward compatibility. When none of
    the tiered fields are set, the flat fields are used and the tier is "legacy"
    (treated as external for upgrade purposes).
    """

    model_config = {"populate_by_name": True}

    type: str = Field(
        ..., description="Database type (no default - must be explicitly specified)"
    )

    # Tiered configuration (ADR-088) — exactly one should be set, or none for legacy
    cnpg: CnpgDatabaseConfig | None = Field(
        None,
        description="Tier 1: CloudNativePG-managed database (ADR-088)",
    )
    managed: ManagedDatabaseConfig | None = Field(
        None,
        description="Tier 2: Generic managed PostgreSQL database (ADR-088)",
    )
    external: ExternalDatabaseConfig | None = Field(
        None,
        description="Tier 3: Externally managed database (ADR-088)",
    )

    # Legacy flat fields (backward compatibility — used when no tier is specified)
    host: str | None = Field(None, description="Database host")
    port: int | None = Field(
        None, description="Database port (auto-detected if not specified)"
    )
    database: str | None = Field(None, description="Database name")
    username: str | None = Field(None, description="Database username")

    # Secret management options
    password_secret: SecretReference | None = Field(
        None,
        alias="passwordSecret",
        description="Secret reference for database password (recommended)",
    )
    credentials_secret: str | None = Field(
        None,
        alias="credentialsSecret",
        description="Kubernetes secret name with database credentials",
    )

    # Advanced configuration
    connection_params: dict[str, str] = Field(
        default_factory=dict,
        alias="connectionParams",
        description="Additional database connection parameters",
    )
    connection_pool: ConnectionPoolConfig = Field(
        default_factory=ConnectionPoolConfig,
        alias="connectionPool",
        description="Database connection pool configuration",
    )
    ssl_mode: str = Field(
        "require", alias="sslMode", description="SSL mode for database connections"
    )
    migration_strategy: str = Field(
        "auto",
        alias="migrationStrategy",
        description="Database migration strategy (auto, manual, skip)",
    )

    @property
    def tier(self) -> str:
        """Return the database tier: 'cnpg', 'managed', 'external', or 'legacy'."""
        if self.cnpg is not None:
            return "cnpg"
        if self.managed is not None:
            return "managed"
        if self.external is not None:
            return "external"
        return "legacy"

    @property
    def effective_host(self) -> str | None:
        """Return the effective database host based on tier."""
        if self.cnpg is not None:
            # CNPG: host is resolved from the Cluster CR naming convention.
            # When a cross-namespace reference is used, generate a FQDN so
            # pods in the Keycloak namespace can reach the CNPG service.
            base = f"{self.cnpg.cluster_name}-rw"
            if self.cnpg.namespace:
                return f"{base}.{self.cnpg.namespace}.svc.cluster.local"
            return base
        if self.managed is not None:
            return self.managed.host
        if self.external is not None:
            return self.external.host
        return self.host

    @property
    def effective_port(self) -> int | None:
        """Return the effective database port based on tier."""
        if self.cnpg is not None:
            return 5432
        if self.managed is not None:
            return self.managed.port
        if self.external is not None:
            return self.external.port
        return self.port

    @property
    def effective_database(self) -> str | None:
        """Return the effective database name based on tier."""
        if self.cnpg is not None:
            return "app"  # CNPG default database name
        if self.managed is not None:
            return self.managed.database
        if self.external is not None:
            return self.external.database
        return self.database

    @property
    def effective_username(self) -> str | None:
        """Return the effective database username based on tier."""
        if self.cnpg is not None:
            return None  # CNPG credentials come from auto-generated secret
        if self.managed is not None:
            return self.managed.username
        if self.external is not None:
            return self.external.username
        return self.username

    @property
    def effective_password_secret(self) -> "SecretReference | None":
        """Return the effective password secret based on tier."""
        if self.cnpg is not None:
            return None  # CNPG credentials come from credentials_secret
        if self.managed is not None:
            return self.managed.password_secret
        if self.external is not None:
            return self.external.password_secret
        return self.password_secret

    @property
    def effective_credentials_secret(self) -> str | None:
        """Return the effective credentials secret based on tier."""
        if self.cnpg is not None:
            return f"{self.cnpg.cluster_name}-app"
        if self.managed is not None:
            return self.managed.credentials_secret
        if self.external is not None:
            return self.external.credentials_secret
        return self.credentials_secret

    @property
    def effective_ssl_mode(self) -> str:
        """Return the effective SSL mode based on tier."""
        if self.managed is not None:
            return self.managed.ssl_mode
        if self.external is not None:
            return self.external.ssl_mode
        return self.ssl_mode

    @property
    def effective_connection_params(self) -> dict[str, str]:
        """Return the effective connection params based on tier."""
        if self.managed is not None:
            return self.managed.connection_params
        if self.external is not None:
            return self.external.connection_params
        return self.connection_params

    @property
    def effective_connection_pool(self) -> "ConnectionPoolConfig":
        """Return the effective connection pool config based on tier."""
        if self.managed is not None:
            return self.managed.connection_pool
        if self.external is not None:
            return self.external.connection_pool
        return self.connection_pool

    @field_validator("type")
    @classmethod
    def validate_database_type(cls, v: str) -> str:
        # Removed H2 from valid types - enforce external database usage
        valid_types = ["postgresql", "mysql", "mariadb", "oracle", "mssql"]
        if v not in valid_types:
            raise ValueError(
                f"Database type must be one of {valid_types}. "
                f"H2 is not supported for production deployments."
            )
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("ssl_mode")
    @classmethod
    def validate_ssl_mode(cls, v: str) -> str:
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
    def validate_migration_strategy(cls, v: str) -> str:
        valid_strategies = ["auto", "manual", "skip"]
        if v not in valid_strategies:
            raise ValueError(f"Migration strategy must be one of {valid_strategies}")
        return v

    @model_validator(mode="after")
    def validate_database_configuration(self) -> "KeycloakDatabaseConfig":
        """Validate complete database configuration with production-ready requirements."""

        # Validate mutual exclusivity of tiered configs
        tier_count = sum(
            1 for t in [self.cnpg, self.managed, self.external] if t is not None
        )
        if tier_count > 1:
            raise ValueError(
                "Only one database tier may be specified: cnpg, managed, or external. "
                "These are mutually exclusive (ADR-088)."
            )

        # CNPG tier requires postgresql type
        if self.cnpg is not None and self.type != "postgresql":
            raise ValueError(
                f"CNPG database tier requires type 'postgresql'. Got '{self.type}'."
            )

        # If a tiered config is set, flat connection fields should not also be set
        # (they will be resolved from the tier config)
        if tier_count == 1 and self.host is not None:
            raise ValueError(
                "When using tiered database configuration (cnpg/managed/external), "
                "do not set top-level 'host' field. Connection details come from the tier config."
            )

        # For legacy mode (no tier set), validate flat fields as before
        if tier_count == 0:
            if not self.host:
                raise ValueError(
                    "Database host is required. Either specify 'host' directly "
                    "or use a tiered config (cnpg, managed, or external)."
                )
            if not self.database:
                raise ValueError(
                    "Database name is required. Either specify 'database' directly "
                    "or use a tiered config (cnpg, managed, or external)."
                )

        # Set default ports based on database type (legacy mode only)
        default_ports = {
            "postgresql": 5432,
            "mysql": 3306,
            "mariadb": 3306,
            "oracle": 1521,
            "mssql": 1433,
        }

        if tier_count == 0 and not self.port and self.type in default_ports:
            object.__setattr__(self, "port", default_ports[self.type])

        # Set default port on managed/external tier configs
        if self.managed is not None and not self.managed.port:
            object.__setattr__(self.managed, "port", default_ports.get(self.type))
        if self.external is not None and not self.external.port:
            object.__setattr__(self.external, "port", default_ports.get(self.type))

        # Validate credential configuration for legacy and managed/external tiers
        if tier_count == 0:
            credential_sources = [
                self.username,
                self.credentials_secret,
            ]
            if not any(credential_sources):
                raise ValueError(
                    "Database credentials must be specified via username/password or credentials_secret."
                )

        if (
            self.managed is not None
            and not self.managed.username
            and not self.managed.credentials_secret
        ):
            raise ValueError(
                "Managed database tier requires credentials: set username or credentialsSecret."
            )

        if (
            self.external is not None
            and not self.external.username
            and not self.external.credentials_secret
        ):
            raise ValueError(
                "External database tier requires credentials: set username or credentialsSecret."
            )

        # CNPG credentials come from the CNPG Cluster CR (auto-generated secret)
        # so no credential validation is needed for that tier.

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


class RealmCapacity(BaseModel):
    """
    Capacity management for realms.

    Controls how many realms can be managed by this Keycloak operator
    and whether new realm creation is allowed.
    """

    model_config = {"populate_by_name": True}

    max_realms: int | None = Field(
        None,
        alias="maxRealms",
        description="Maximum number of realms (None = unlimited)",
        ge=1,
    )
    allow_new_realms: bool = Field(
        True,
        alias="allowNewRealms",
        description="Whether to allow creation of new realms",
    )
    capacity_message: str | None = Field(
        None,
        alias="capacityMessage",
        description="Message to show when capacity is reached",
    )


class MaintenanceMode(BaseModel):
    """
    Maintenance mode configuration for blue-green upgrades (ADR-088).

    When enabled, the operator annotates the Keycloak ingress to block
    or limit traffic before the old deployment is scaled down. This
    ensures graceful connection draining during major version upgrades.
    """

    model_config = {"populate_by_name": True}

    enabled: bool = Field(
        False,
        description="Enable maintenance mode",
    )
    mode: str = Field(
        "full-block",
        description=(
            "Maintenance mode type: 'read-only' allows GET/HEAD/OPTIONS, "
            "'full-block' returns 503 for all requests."
        ),
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/health",
            "/health/live",
            "/health/ready",
            "/health/started",
        ],
        alias="excludePaths",
        description="Paths excluded from maintenance mode (always accessible)",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid_modes = ["read-only", "full-block"]
        if v not in valid_modes:
            raise ValueError(f"Maintenance mode must be one of {valid_modes}")
        return v

    @field_validator("exclude_paths")
    @classmethod
    def validate_exclude_paths(cls, v: list[str]) -> list[str]:
        """Validate that exclude paths are safe URL paths.

        Each path must start with ``/`` and contain only URL-safe characters
        (alphanumeric, ``/``, ``-``, ``_``, ``.``, ``~``).  This prevents
        injection of regex metacharacters into the nginx server-snippet.
        """
        path_pattern = re.compile(r"^/[a-zA-Z0-9/_\-.~]*$")
        for path in v:
            if not path_pattern.match(path):
                raise ValueError(
                    f"Invalid exclude path '{path}'. Paths must start with '/' "
                    "and contain only alphanumeric characters, '/', '-', '_', '.', '~'."
                )
        return v


class CacheIsolation(BaseModel):
    """
    JGroups cache isolation configuration for blue-green upgrades (ADR-088).

    Ensures old and new Keycloak versions form separate JGroups clusters
    by using distinct cluster names and discovery service selectors. This
    prevents cross-version cache poisoning during blue-green upgrades.
    """

    model_config = {"populate_by_name": True}

    cluster_name: str | None = Field(
        None,
        alias="clusterName",
        description=(
            "Explicit JGroups cluster name. When set, the discovery service "
            "selector is scoped to pods with this cluster label."
        ),
    )
    auto_suffix: bool = Field(
        False,
        alias="autoSuffix",
        description=(
            "Automatically append Keycloak version to the cluster name "
            "to isolate caches between versions. Overridden by explicit clusterName."
        ),
    )

    @field_validator("cluster_name")
    @classmethod
    def validate_cluster_name_as_k8s_label(cls, v: str | None) -> str | None:
        """Validate that cluster_name is a valid Kubernetes label value.

        Kubernetes label values must be at most 63 characters, consist of
        alphanumeric characters, ``-``, ``_``, or ``.``, and must start and
        end with an alphanumeric character.
        """
        if v is None:
            return v
        if len(v) > 63:
            raise ValueError(
                f"cluster_name must be at most 63 characters, got {len(v)}"
            )
        if not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?", v):
            raise ValueError(
                f"cluster_name '{v}' is not a valid Kubernetes label value. "
                "Must consist of alphanumeric characters, '-', '_', or '.', "
                "and must start and end with an alphanumeric character."
            )
        return v


class UpgradePolicy(BaseModel):
    """
    Upgrade policy configuration for Keycloak version upgrades (ADR-088 Phase 2).

    Controls pre-upgrade backup behavior and (in Phase 3) blue-green
    deployment strategy. The backup behavior depends on the database tier:

    - **cnpg**: Automated backup via CNPG Backup API.
    - **managed**: Automated backup via VolumeSnapshot (requires pvcName).
    - **external/legacy**: Warn-and-proceed by default; opt-in manual gate
      via ``require_backup_confirmation``.

    When ``require_backup_confirmation`` is true for external/legacy tiers,
    the operator halts at ``WaitingForBackupConfirmation`` phase until the
    annotation ``operator.keycloak.io/backup-confirmed: "true"`` is applied
    to the Keycloak CR.
    """

    model_config = {"populate_by_name": True}

    require_backup_confirmation: bool = Field(
        False,
        alias="requireBackupConfirmation",
        description=(
            "Require manual backup confirmation before proceeding with upgrades "
            "on external/legacy database tiers. When true, the operator halts "
            "at WaitingForBackupConfirmation until the annotation "
            "operator.keycloak.io/backup-confirmed is set to 'true'. "
            "Default: false (warn-and-proceed)."
        ),
    )
    backup_timeout: int = Field(
        600,
        alias="backupTimeout",
        description=(
            "Maximum time in seconds to wait for a pre-upgrade backup to complete. "
            "Applies to CNPG and VolumeSnapshot backups. Default: 600 (10 minutes)."
        ),
        ge=60,
        le=3600,
    )


class KeycloakTracingConfig(BaseModel):
    """
    OpenTelemetry distributed tracing configuration for Keycloak.

    Keycloak 26.x+ has built-in OpenTelemetry support via Quarkus.
    This configuration enables end-to-end distributed tracing.
    """

    model_config = {"populate_by_name": True}

    enabled: bool = Field(
        False,
        description="Enable OpenTelemetry tracing in Keycloak",
    )
    endpoint: str = Field(
        "http://localhost:4317",
        description="OTLP collector endpoint (gRPC)",
    )
    service_name: str = Field(
        "keycloak",
        alias="serviceName",
        description="Service name for traces",
    )
    sample_rate: float = Field(
        1.0,
        alias="sampleRate",
        description="Trace sampling rate (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )


class KeycloakAdminConfig(BaseModel):
    """
    Configuration for Keycloak administrator credentials.
    """

    model_config = {"populate_by_name": True}

    existing_secret: str | None = Field(
        None,
        alias="existingSecret",
        description="Name of an existing Kubernetes secret containing admin credentials (must contain 'username' and 'password' keys).",
    )


class KeycloakSpec(BaseModel):
    """
    Specification for a Keycloak instance.

    This model defines all configurable aspects of a Keycloak deployment
    including resources, networking, persistence, and authentication.
    """

    model_config = {"populate_by_name": True}

    # Core configuration
    image: str = Field(
        "quay.io/keycloak/keycloak:26.4.0", description="Keycloak container image"
    )
    keycloak_version: str | None = Field(
        None,
        alias="keycloakVersion",
        description="Keycloak version override for custom images without version tags. "
        "Used to determine health port (24.x uses 8080, 25.x+ uses 9000). "
        "Auto-detected from image tag if not specified.",
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

    # Admin configuration
    admin: KeycloakAdminConfig = Field(
        default_factory=KeycloakAdminConfig,
        validation_alias=AliasChoices("admin", "admin_access"),
        description="Admin credentials configuration",
    )
    admin_access: KeycloakAdminConfig | None = Field(
        None,
        alias="admin_access",
        description="Legacy admin credentials configuration (backward-compatible alias for .spec.admin).",
    )

    # Environment and configuration
    env: dict[str, str] = Field(
        default_factory=dict, description="Additional environment variables"
    )
    jvm_options: list[str] = Field(
        default_factory=list, alias="jvmOptions", description="JVM options for Keycloak"
    )
    optimized: bool = Field(
        False,
        description="Use --optimized startup flag. Set to true when using a pre-built "
        "Keycloak image (e.g. keycloak-optimized). Set to false for stock "
        "quay.io/keycloak/keycloak images that have not been pre-built with "
        "'kc.sh build'. Defaults to false for backward compatibility; the "
        "operator Helm chart should explicitly set this to true when using a "
        "pre-built optimized image.",
    )

    # Operational settings
    startup_probe: KubernetesProbeConfig = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/started", "port": 9000},
            "initialDelaySeconds": 30,
            "periodSeconds": 10,
            "timeoutSeconds": 5,
            "failureThreshold": 30,
        },
        alias="startupProbe",
        description="Startup probe configuration",
    )
    liveness_probe: KubernetesProbeConfig = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/live", "port": 9000},
            "initialDelaySeconds": 60,
            "periodSeconds": 30,
            "timeoutSeconds": 5,
            "failureThreshold": 3,
        },
        alias="livenessProbe",
        description="Liveness probe configuration",
    )
    readiness_probe: KubernetesProbeConfig = Field(
        default_factory=lambda: {
            "httpGet": {"path": "/health/ready", "port": 9000},
            "initialDelaySeconds": 30,
            "periodSeconds": 10,
            "timeoutSeconds": 5,
            "failureThreshold": 3,
        },
        alias="readinessProbe",
        description="Readiness probe configuration",
    )

    # Security and RBAC
    pod_security_context: KubernetesSecurityContext = Field(
        default_factory=dict,
        alias="podSecurityContext",
        description="Pod security context",
    )
    security_context: KubernetesSecurityContext = Field(
        default_factory=dict,
        alias="securityContext",
        description="Container security context",
    )
    service_account: str | None = Field(
        None,
        alias="serviceAccount",
        description="Service account to use for Keycloak pods",
    )

    # Realm capacity management
    realm_capacity: RealmCapacity | None = Field(
        None,
        alias="realmCapacity",
        description="Capacity management for realms",
    )

    # Blue-green upgrade support (ADR-088)
    maintenance_mode: MaintenanceMode | None = Field(
        None,
        alias="maintenanceMode",
        description="Maintenance mode for ingress traffic control during blue-green upgrades (ADR-088)",
    )
    cache_isolation: CacheIsolation | None = Field(
        None,
        alias="cacheIsolation",
        description="JGroups cache isolation for blue-green upgrades (ADR-088)",
    )
    upgrade_policy: UpgradePolicy | None = Field(
        None,
        alias="upgradePolicy",
        description="Pre-upgrade backup and upgrade strategy configuration (ADR-088 Phase 2)",
    )

    # OpenTelemetry tracing
    tracing: KeycloakTracingConfig | None = Field(
        None,
        description="OpenTelemetry distributed tracing configuration",
    )

    # Operator identification
    operator_ref: OperatorRef = Field(
        default_factory=OperatorRef,
        alias="operatorRef",
        description="Reference to the operator instance managing this resource (ADR-062)",
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

    model_config = {"populate_by_name": True}

    type: str = Field(..., description="Condition type")
    status: str = Field(..., description="Condition status (True/False/Unknown)")
    reason: str | None = Field(None, description="Reason for the condition")
    message: str | None = Field(None, description="Human-readable message")
    last_transition_time: str | None = Field(
        None,
        alias="lastTransitionTime",
        description="Last time the condition transitioned",
    )


class KeycloakStatus(BaseModel):
    """
    Status of a Keycloak instance.

    This model represents the current state and health of a Keycloak deployment
    as observed by the operator.
    """

    model_config = {"populate_by_name": True}

    # Overall status
    phase: str = Field("Pending", description="Current phase of the Keycloak instance")
    message: str | None = Field(None, description="Human-readable status message")
    reason: str | None = Field(None, description="Reason for current phase")

    # Detailed status
    conditions: list[KeycloakCondition] = Field(
        default_factory=list, description="Detailed status conditions"
    )
    observed_generation: int | None = Field(
        None,
        alias="observedGeneration",
        description="Generation of the spec that was last processed",
    )

    # Deployment status
    replicas: int | None = Field(None, description="Total number of replicas")
    ready_replicas: int | None = Field(
        None, alias="readyReplicas", description="Number of ready replicas"
    )
    available_replicas: int | None = Field(
        None, alias="availableReplicas", description="Number of available replicas"
    )

    # Resource information
    deployment: str | None = Field(None, description="Name of the deployment")
    service: str | None = Field(None, description="Name of the service")
    ingress: str | None = Field(None, description="Name of the ingress")
    persistent_volume_claims: list[str] = Field(
        default_factory=list,
        alias="persistentVolumeClaims",
        description="Names of persistent volume claims",
    )

    # Authorization
    authorization_secret_name: str | None = Field(
        None,
        alias="authorizationSecretName",
        description="Name of the secret containing the operator's authorization token",
    )

    # Endpoints
    endpoints: KeycloakEndpoints = Field(
        default_factory=KeycloakEndpoints, description="Access endpoints"
    )

    # Realm capacity status
    realm_count: int | None = Field(
        None,
        alias="realmCount",
        description="Current number of managed realms",
    )
    accepting_new_realms: bool = Field(
        True,
        alias="acceptingNewRealms",
        description="Whether new realm creation is currently allowed",
    )
    capacity_status: str | None = Field(
        None,
        alias="capacityStatus",
        description="Human-readable capacity status message",
    )

    # Version and capability information
    version: str | None = Field(None, description="Running Keycloak version")
    capabilities: list[str] = Field(
        default_factory=list, description="Detected capabilities"
    )

    # Health and monitoring
    last_health_check: str | None = Field(
        None, alias="lastHealthCheck", description="Timestamp of last health check"
    )
    health_status: str | None = Field(
        None, alias="healthStatus", description="Current health status"
    )

    # Statistics (optional)
    stats: OperationalStats = Field(
        default_factory=dict, description="Operational statistics"
    )


class Keycloak(BaseModel):
    """
    Complete Keycloak custom resource model.

    This represents the full Kubernetes custom resource including
    metadata, spec, and status sections.
    """

    api_version: str = Field("vriesdemichael.github.io/v1", alias="apiVersion")
    kind: str = Field("Keycloak")
    metadata: KubernetesMetadata = Field(..., description="Kubernetes metadata")
    spec: KeycloakSpec = Field(..., description="Keycloak specification")
    status: KeycloakStatus | None = Field(
        None, description="Keycloak status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"
