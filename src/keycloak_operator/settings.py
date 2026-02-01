"""Centralized operator settings using pydantic-settings.

This module provides a single source of truth for all operator configuration
loaded from environment variables. Uses pydantic for automatic validation,
type coercion, and documentation.
"""

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TracingSettings(BaseModel):
    """OpenTelemetry tracing configuration.

    Controls distributed tracing for the operator and optionally
    propagates settings to managed Keycloak instances.
    """

    enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry distributed tracing",
    )
    endpoint: str = Field(
        default="http://localhost:4317",
        description="OTLP collector endpoint (gRPC)",
    )
    service_name: str = Field(
        default="keycloak-operator",
        description="Service name for traces",
    )
    sample_rate: float = Field(
        default=1.0,
        description="Trace sampling rate (0.0-1.0, 1.0 = 100%)",
        ge=0.0,
        le=1.0,
    )
    propagate_to_keycloak: bool = Field(
        default=True,
        description="Propagate tracing settings to managed Keycloak instances",
    )
    insecure: bool = Field(
        default=True,
        description="Use insecure connection to OTLP collector (no TLS)",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional headers for OTLP exporter (e.g., authentication)",
    )


class Settings(BaseSettings):
    """Operator configuration loaded from environment variables.

    All settings have sensible defaults for production use. Override via
    environment variables as documented per field.
    """

    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Operator identification
    operator_namespace: str = Field(
        default="keycloak-system",
        description="Namespace where the operator is deployed",
        validation_alias="OPERATOR_NAMESPACE",
    )
    operator_instance_id: str = Field(
        default="",
        description="Unique ID for this operator instance (required for drift detection)",
        validation_alias="OPERATOR_INSTANCE_ID",
    )
    operator_name: str = Field(
        default="keycloak-operator",
        description="Name of the operator deployment",
        validation_alias="OPERATOR_NAME",
    )

    # Pod identification (from downward API)
    pod_name: str = Field(
        default="",
        description="Name of the operator pod",
        validation_alias="POD_NAME",
    )
    pod_namespace: str = Field(
        default="keycloak-system",
        description="Namespace of the operator pod",
        validation_alias="POD_NAMESPACE",
    )
    service_account_name: str = Field(
        default="keycloak-operator",
        description="Service account name used by the operator",
        validation_alias="SERVICE_ACCOUNT_NAME",
    )

    # Logging configuration
    log_level: str = Field(
        default="INFO",
        validation_alias="LOG_LEVEL",
        description="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    json_logs: bool = Field(
        default=True,
        validation_alias="JSON_LOGS",
        description="Enable JSON formatted logging for structured log aggregation",
    )
    correlation_ids: bool = Field(
        default=True,
        validation_alias="CORRELATION_IDS",
        description="Enable correlation IDs in logs for request tracing",
    )
    log_health_probes: bool = Field(
        default=False,
        validation_alias="LOG_HEALTH_PROBES",
        description="Log health/readiness probe requests (disabled by default to reduce noise)",
    )
    webhook_log_level: str = Field(
        default="WARNING",
        validation_alias="WEBHOOK_LOG_LEVEL",
        description="Log level for webhook requests (DEBUG, INFO, WARNING, ERROR)",
    )
    handler_entry_log_level: str = Field(
        default="INFO",
        validation_alias="HANDLER_ENTRY_LOG_LEVEL",
        description="Log level for handler invocation messages (DEBUG, INFO, WARNING, ERROR). "
        "Set to DEBUG to reduce noise in production.",
    )

    # Namespace watching
    namespaces: str = Field(
        default="",
        validation_alias="KEYCLOAK_OPERATOR_NAMESPACES",
        description="Comma-separated list of namespaces to watch (empty = all namespaces)",
    )

    # Operator behavior
    dry_run: bool = Field(
        default=False,
        validation_alias="DRY_RUN",
        description="Run in dry-run mode (no changes applied to Keycloak)",
    )

    # Metrics and observability
    metrics_port: int = Field(
        default=8081,
        validation_alias="METRICS_PORT",
        description="Port for Prometheus metrics endpoint",
    )
    metrics_host: str = Field(
        default="0.0.0.0",
        validation_alias="METRICS_HOST",
        description="Host address to bind metrics server",
    )

    # Rate limiting for Keycloak API
    api_global_rate_limit_tps: float = Field(
        default=50.0,
        validation_alias="KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS",
        description="Global transactions per second limit for Keycloak API calls",
    )
    api_global_burst: int = Field(
        default=100,
        validation_alias="KEYCLOAK_API_GLOBAL_BURST",
        description="Global burst capacity for Keycloak API rate limiting",
    )
    api_namespace_rate_limit_tps: float = Field(
        default=5.0,
        validation_alias="KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS",
        description="Per-namespace transactions per second limit for Keycloak API",
    )
    api_namespace_burst: int = Field(
        default=10,
        validation_alias="KEYCLOAK_API_NAMESPACE_BURST",
        description="Per-namespace burst capacity for Keycloak API rate limiting",
    )

    # Reconciliation behavior
    reconcile_jitter_max_seconds: float = Field(
        default=5.0,
        validation_alias="RECONCILE_JITTER_MAX_SECONDS",
        description="Maximum jitter in seconds for reconciliation scheduling",
    )

    # Drift detection
    drift_detection_enabled: bool = Field(
        default=True,
        validation_alias="DRIFT_DETECTION_ENABLED",
        description="Enable drift detection background task",
    )
    drift_detection_interval_seconds: int = Field(
        default=300,
        validation_alias="DRIFT_DETECTION_INTERVAL_SECONDS",
        description="Interval in seconds between drift detection runs",
    )
    drift_detection_auto_remediate: bool = Field(
        default=False,
        validation_alias="DRIFT_DETECTION_AUTO_REMEDIATE",
        description="Automatically remediate detected drift",
    )
    drift_detection_minimum_age_hours: int = Field(
        default=24,
        validation_alias="DRIFT_DETECTION_MINIMUM_AGE_HOURS",
        description="Minimum age in hours before resources are checked for drift",
    )
    drift_detection_scope_realms: bool = Field(
        default=True,
        validation_alias="DRIFT_DETECTION_SCOPE_REALMS",
        description="Include realms in drift detection",
    )
    drift_detection_scope_clients: bool = Field(
        default=True,
        validation_alias="DRIFT_DETECTION_SCOPE_CLIENTS",
        description="Include clients in drift detection",
    )
    drift_detection_scope_identity_providers: bool = Field(
        default=True,
        validation_alias="DRIFT_DETECTION_SCOPE_IDENTITY_PROVIDERS",
        description="Include identity providers in drift detection",
    )
    drift_detection_scope_roles: bool = Field(
        default=True,
        validation_alias="DRIFT_DETECTION_SCOPE_ROLES",
        description="Include roles in drift detection",
    )

    # Health check timer intervals (seconds)
    # These also serve as the stuck finalizer detection interval
    # All default to 300s (5 min) for production. Set lower (e.g., 10s) in tests.
    timer_interval_keycloak: int = Field(
        default=300,
        validation_alias="TIMER_INTERVAL_KEYCLOAK",
        description="Health check interval for Keycloak instances in seconds. "
        "Also determines how quickly stuck finalizers are detected.",
    )
    timer_interval_realm: int = Field(
        default=300,
        validation_alias="TIMER_INTERVAL_REALM",
        description="Health check interval for KeycloakRealms in seconds. "
        "Also determines how quickly stuck finalizers are detected.",
    )
    timer_interval_client: int = Field(
        default=300,
        validation_alias="TIMER_INTERVAL_CLIENT",
        description="Health check interval for KeycloakClients in seconds. "
        "Also determines how quickly stuck finalizers are detected.",
    )

    # Admission webhooks
    enable_webhooks: bool = Field(
        default=True,
        validation_alias="ENABLE_WEBHOOKS",
        description="Enable admission webhooks for validation",
    )
    webhook_port: int = Field(
        default=8443,
        validation_alias="WEBHOOK_PORT",
        description="Port for admission webhook server",
    )
    webhook_max_realms_per_namespace: int = Field(
        default=10,
        validation_alias="WEBHOOK_MAX_REALMS_PER_NAMESPACE",
        description="Maximum number of realms allowed per namespace",
    )
    webhook_max_clients_per_namespace: int = Field(
        default=50,
        validation_alias="WEBHOOK_MAX_CLIENTS_PER_NAMESPACE",
        description="Maximum number of clients allowed per namespace",
    )

    # Security settings
    allow_script_mappers: bool = Field(
        default=False,
        validation_alias="KEYCLOAK_ALLOW_SCRIPT_MAPPERS",
        description=(
            "Allow usage of script-based protocol mappers in Keycloak realms. "
            "Disabled by default as a hardening measure because script mappers "
            "execute dynamic code inside the Keycloak JVM and can be abused to "
            "run arbitrary logic. Enable only in tightly controlled environments "
            "where realm administrators are fully trusted and script mappers are "
            "required for compatibility or advanced customization."
        ),
    )
    allow_impersonation: bool = Field(
        default=False,
        validation_alias="KEYCLOAK_ALLOW_IMPERSONATION",
        description="Allow service accounts to use the 'impersonation' role from realm-management. "
        "WARNING: Enabling this allows the service account to impersonate ANY user in the realm, "
        "including realm admins, effectively granting full administrative access to Keycloak.",
    )

    # OpenTelemetry tracing
    tracing_enabled: bool = Field(
        default=False,
        validation_alias="OTEL_TRACING_ENABLED",
        description="Enable OpenTelemetry distributed tracing",
    )
    otel_exporter_otlp_endpoint: str = Field(
        default="http://localhost:4317",
        validation_alias="OTEL_EXPORTER_OTLP_ENDPOINT",
        description="OTLP collector endpoint (gRPC)",
    )
    otel_service_name: str = Field(
        default="keycloak-operator",
        validation_alias="OTEL_SERVICE_NAME",
        description="Service name for traces",
    )
    otel_sample_rate: float = Field(
        default=1.0,
        validation_alias="OTEL_SAMPLE_RATE",
        description="Trace sampling rate (0.0-1.0, 1.0 = 100%)",
        ge=0.0,
        le=1.0,
    )
    otel_propagate_to_keycloak: bool = Field(
        default=True,
        validation_alias="OTEL_PROPAGATE_TO_KEYCLOAK",
        description="Propagate tracing settings to managed Keycloak instances",
    )
    otel_insecure: bool = Field(
        default=True,
        validation_alias="OTEL_EXPORTER_OTLP_INSECURE",
        description="Use insecure connection to OTLP collector (no TLS)",
    )

    @property
    def tracing(self) -> TracingSettings:
        """Get tracing settings as a nested model for convenience."""
        return TracingSettings(
            enabled=self.tracing_enabled,
            endpoint=self.otel_exporter_otlp_endpoint,
            service_name=self.otel_service_name,
            sample_rate=self.otel_sample_rate,
            propagate_to_keycloak=self.otel_propagate_to_keycloak,
            insecure=self.otel_insecure,
        )

    @property
    def watched_namespaces(self) -> list[str] | None:
        """Parse watched namespaces from comma-separated string.

        Returns:
            List of namespace names, or None to watch all namespaces
        """
        if self.namespaces:
            return [ns.strip() for ns in self.namespaces.split(",") if ns.strip()]
        return None


# Global settings instance - initialized once at module import
settings = Settings()
