"""Centralized operator settings using pydantic-settings.

This module provides a single source of truth for all operator configuration
loaded from environment variables. Uses pydantic for automatic validation,
type coercion, and documentation.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
