"""
Unit tests for Blue-Green Phase 1 features (ADR-088).

Covers:
- #607: Tiered database configuration (CNPG / Managed / External / Legacy)
- #601: Maintenance mode (ingress annotations for traffic control)
- #603: JGroups cache isolation (cluster naming and discovery service scoping)
"""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from keycloak_operator.constants import (
    CACHE_CLUSTER_LABEL,
    MAINTENANCE_MODE_ANNOTATION,
    MAINTENANCE_MODE_SNIPPET_ANNOTATION,
)
from keycloak_operator.models.keycloak import (
    CacheIsolation,
    CnpgDatabaseConfig,
    ExternalDatabaseConfig,
    KeycloakDatabaseConfig,
    KeycloakSpec,
    MaintenanceMode,
    ManagedDatabaseConfig,
)
from keycloak_operator.utils.kubernetes import (
    build_maintenance_mode_annotations,
    create_keycloak_deployment,
    create_keycloak_discovery_service,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _legacy_db(**overrides) -> dict:
    """Build a minimal legacy database config dict."""
    base = {
        "type": "postgresql",
        "host": "db.example.com",
        "database": "keycloak",
        "credentials_secret": "db-creds",
    }
    base.update(overrides)
    return base


def _spec_with_db(db_dict: dict | None = None, **spec_overrides) -> KeycloakSpec:
    """Build a KeycloakSpec with the given database config."""
    db = db_dict or _legacy_db()
    return KeycloakSpec(database=db, **spec_overrides)


# ===========================================================================
# #607 — Tiered Database Configuration
# ===========================================================================


class TestCnpgDatabaseConfig:
    """Tests for Tier 1: CloudNativePG database configuration."""

    def test_cnpg_minimal(self):
        """CNPG tier only requires cluster_name."""
        cfg = CnpgDatabaseConfig(cluster_name="my-cluster")
        assert cfg.cluster_name == "my-cluster"
        assert cfg.namespace is None

    def test_cnpg_with_namespace(self):
        """CNPG tier accepts optional namespace."""
        cfg = CnpgDatabaseConfig(cluster_name="my-cluster", namespace="cnpg-ns")
        assert cfg.namespace == "cnpg-ns"

    def test_cnpg_alias(self):
        """CNPG tier accepts camelCase alias."""
        cfg = CnpgDatabaseConfig.model_validate({"clusterName": "x"})
        assert cfg.cluster_name == "x"


class TestManagedDatabaseConfig:
    """Tests for Tier 2: Managed database configuration."""

    def test_managed_minimal(self):
        """Managed tier requires host and database."""
        cfg = ManagedDatabaseConfig(host="db.managed.io", database="keycloak")
        assert cfg.host == "db.managed.io"
        assert cfg.database == "keycloak"
        assert cfg.port is None
        assert cfg.ssl_mode == "require"

    def test_managed_full(self):
        """Managed tier accepts all optional fields."""
        cfg = ManagedDatabaseConfig(
            host="db.managed.io",
            database="keycloak",
            port=5433,
            username="admin",
            credentials_secret="managed-creds",
            ssl_mode="verify-full",
            connection_params={"application_name": "kc"},
        )
        assert cfg.port == 5433
        assert cfg.username == "admin"
        assert cfg.credentials_secret == "managed-creds"
        assert cfg.ssl_mode == "verify-full"
        assert cfg.connection_params == {"application_name": "kc"}

    def test_managed_invalid_port(self):
        """Port validation rejects out-of-range values."""
        with pytest.raises(ValidationError, match="Port must be between"):
            ManagedDatabaseConfig(host="h", database="d", port=99999)

    def test_managed_invalid_ssl_mode(self):
        """SSL mode validation rejects unknown values."""
        with pytest.raises(ValidationError, match="SSL mode must be one of"):
            ManagedDatabaseConfig(host="h", database="d", ssl_mode="bogus")


class TestExternalDatabaseConfig:
    """Tests for Tier 3: External database configuration."""

    def test_external_minimal(self):
        """External tier requires host and database."""
        cfg = ExternalDatabaseConfig(host="ext.db.io", database="keycloak")
        assert cfg.host == "ext.db.io"
        assert cfg.database == "keycloak"

    def test_external_full(self):
        """External tier accepts all fields."""
        cfg = ExternalDatabaseConfig(
            host="ext.db.io",
            database="keycloak",
            port=5432,
            username="admin",
            credentials_secret="ext-creds",
            ssl_mode="verify-ca",
        )
        assert cfg.port == 5432
        assert cfg.credentials_secret == "ext-creds"
        assert cfg.ssl_mode == "verify-ca"


class TestKeycloakDatabaseConfigTiers:
    """Tests for tiered database configuration on KeycloakDatabaseConfig."""

    # ---- tier property ----

    def test_tier_legacy(self):
        """No tier sub-object → 'legacy'."""
        cfg = KeycloakDatabaseConfig(**_legacy_db())
        assert cfg.tier == "legacy"

    def test_tier_cnpg(self):
        """CNPG sub-object → 'cnpg'."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg-cluster"),
        )
        assert cfg.tier == "cnpg"

    def test_tier_managed(self):
        """Managed sub-object → 'managed'."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="m.db",
                database="kc",
                username="u",
            ),
        )
        assert cfg.tier == "managed"

    def test_tier_external(self):
        """External sub-object → 'external'."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            external=ExternalDatabaseConfig(
                host="e.db",
                database="kc",
                username="u",
            ),
        )
        assert cfg.tier == "external"

    # ---- mutual exclusivity ----

    def test_mutual_exclusivity_cnpg_managed(self):
        """CNPG + managed raises ValueError."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            KeycloakDatabaseConfig(
                type="postgresql",
                cnpg=CnpgDatabaseConfig(cluster_name="c"),
                managed=ManagedDatabaseConfig(host="h", database="d", username="u"),
            )

    def test_mutual_exclusivity_cnpg_external(self):
        """CNPG + external raises ValueError."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            KeycloakDatabaseConfig(
                type="postgresql",
                cnpg=CnpgDatabaseConfig(cluster_name="c"),
                external=ExternalDatabaseConfig(host="h", database="d", username="u"),
            )

    def test_mutual_exclusivity_managed_external(self):
        """Managed + external raises ValueError."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            KeycloakDatabaseConfig(
                type="postgresql",
                managed=ManagedDatabaseConfig(host="h", database="d", username="u"),
                external=ExternalDatabaseConfig(host="h2", database="d2", username="u"),
            )

    def test_mutual_exclusivity_all_three(self):
        """All three tiers raises ValueError."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            KeycloakDatabaseConfig(
                type="postgresql",
                cnpg=CnpgDatabaseConfig(cluster_name="c"),
                managed=ManagedDatabaseConfig(host="h", database="d", username="u"),
                external=ExternalDatabaseConfig(host="h2", database="d2", username="u"),
            )

    # ---- CNPG requires postgresql ----

    def test_cnpg_requires_postgresql(self):
        """CNPG tier rejects non-postgresql types."""
        with pytest.raises(
            ValidationError, match="CNPG database tier requires type 'postgresql'"
        ):
            KeycloakDatabaseConfig(
                type="mysql",
                cnpg=CnpgDatabaseConfig(cluster_name="c"),
            )

    # ---- tier + host conflict ----

    def test_tier_and_host_conflict(self):
        """Setting both a tier and a top-level host is rejected."""
        with pytest.raises(ValidationError, match="do not set top-level 'host'"):
            KeycloakDatabaseConfig(
                type="postgresql",
                host="should-not-be-here",
                cnpg=CnpgDatabaseConfig(cluster_name="c"),
            )

    # ---- legacy mode validation ----

    def test_legacy_requires_host(self):
        """Legacy mode without host raises error."""
        with pytest.raises(ValidationError, match="Database host is required"):
            KeycloakDatabaseConfig(
                type="postgresql",
                database="keycloak",
                credentials_secret="creds",
            )

    def test_legacy_requires_database(self):
        """Legacy mode without database raises error."""
        with pytest.raises(ValidationError, match="Database name is required"):
            KeycloakDatabaseConfig(
                type="postgresql",
                host="db",
                credentials_secret="creds",
            )

    def test_legacy_requires_credentials(self):
        """Legacy mode without any credentials raises error."""
        with pytest.raises(
            ValidationError, match="Database credentials must be specified"
        ):
            KeycloakDatabaseConfig(
                type="postgresql",
                host="db",
                database="keycloak",
            )

    def test_managed_requires_credentials(self):
        """Managed tier without credentials raises error."""
        with pytest.raises(
            ValidationError, match="Managed database tier requires credentials"
        ):
            KeycloakDatabaseConfig(
                type="postgresql",
                managed=ManagedDatabaseConfig(host="h", database="d"),
            )

    def test_external_requires_credentials(self):
        """External tier without credentials raises error."""
        with pytest.raises(
            ValidationError, match="External database tier requires credentials"
        ):
            KeycloakDatabaseConfig(
                type="postgresql",
                external=ExternalDatabaseConfig(host="h", database="d"),
            )

    def test_cnpg_does_not_require_credentials(self):
        """CNPG tier does not require explicit credentials (auto-generated)."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.tier == "cnpg"


class TestEffectiveProperties:
    """Tests for effective_* property resolution across tiers."""

    def test_effective_host_legacy(self):
        cfg = KeycloakDatabaseConfig(**_legacy_db(host="legacy-host"))
        assert cfg.effective_host == "legacy-host"

    def test_effective_host_cnpg(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg-cluster"),
        )
        assert cfg.effective_host == "pg-cluster-rw"

    def test_effective_host_cnpg_cross_namespace(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg-cluster", namespace="other-ns"),
        )
        assert cfg.effective_host == "pg-cluster-rw.other-ns.svc.cluster.local"

    def test_effective_host_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="managed.db", database="kc", username="u"
            ),
        )
        assert cfg.effective_host == "managed.db"

    def test_effective_host_external(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            external=ExternalDatabaseConfig(host="ext.db", database="kc", username="u"),
        )
        assert cfg.effective_host == "ext.db"

    def test_effective_port_cnpg_always_5432(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.effective_port == 5432

    def test_effective_port_managed_default(self):
        """Managed tier gets default port from type when not specified."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(host="h", database="d", username="u"),
        )
        # Model validator sets default port to 5432 for postgresql
        assert cfg.effective_port == 5432

    def test_effective_port_managed_explicit(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="h", database="d", port=5433, username="u"
            ),
        )
        assert cfg.effective_port == 5433

    def test_effective_database_cnpg(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.effective_database == "app"

    def test_effective_database_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(host="h", database="mydb", username="u"),
        )
        assert cfg.effective_database == "mydb"

    def test_effective_database_legacy(self):
        cfg = KeycloakDatabaseConfig(**_legacy_db(database="legacy-db"))
        assert cfg.effective_database == "legacy-db"

    def test_effective_username_cnpg_is_none(self):
        """CNPG credentials come from auto-generated secret, not username."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.effective_username is None

    def test_effective_username_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(host="h", database="d", username="admin"),
        )
        assert cfg.effective_username == "admin"

    def test_effective_password_secret_cnpg_is_none(self):
        """CNPG uses credentials_secret, not password_secret."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.effective_password_secret is None

    def test_effective_credentials_secret_cnpg(self):
        """CNPG auto-generates secret name from cluster name."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg-cluster"),
        )
        assert cfg.effective_credentials_secret == "pg-cluster-app"

    def test_effective_credentials_secret_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="h",
                database="d",
                credentials_secret="managed-creds",
            ),
        )
        assert cfg.effective_credentials_secret == "managed-creds"

    def test_effective_credentials_secret_legacy(self):
        cfg = KeycloakDatabaseConfig(**_legacy_db(credentials_secret="leg-creds"))
        assert cfg.effective_credentials_secret == "leg-creds"

    def test_effective_ssl_mode_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="h",
                database="d",
                username="u",
                ssl_mode="verify-full",
            ),
        )
        assert cfg.effective_ssl_mode == "verify-full"

    def test_effective_ssl_mode_external(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            external=ExternalDatabaseConfig(
                host="h",
                database="d",
                username="u",
                ssl_mode="verify-ca",
            ),
        )
        assert cfg.effective_ssl_mode == "verify-ca"

    def test_effective_ssl_mode_cnpg_falls_through_to_top_level(self):
        """CNPG tier doesn't have ssl_mode → falls through to top-level default."""
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            cnpg=CnpgDatabaseConfig(cluster_name="pg"),
        )
        assert cfg.effective_ssl_mode == "require"

    def test_effective_connection_params_managed(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(
                host="h",
                database="d",
                username="u",
                connection_params={"application_name": "kc"},
            ),
        )
        assert cfg.effective_connection_params == {"application_name": "kc"}

    def test_effective_connection_pool_external(self):
        from keycloak_operator.models.keycloak import ConnectionPoolConfig

        pool = ConnectionPoolConfig(min_connections=5, max_connections=25)
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            external=ExternalDatabaseConfig(
                host="h",
                database="d",
                username="u",
                connection_pool=pool,
            ),
        )
        assert cfg.effective_connection_pool.min_connections == 5
        assert cfg.effective_connection_pool.max_connections == 25


class TestDefaultPorts:
    """Tests for automatic port assignment across tiers."""

    def test_legacy_postgresql_default_port(self):
        cfg = KeycloakDatabaseConfig(**_legacy_db())
        assert cfg.port == 5432

    def test_legacy_mysql_default_port(self):
        cfg = KeycloakDatabaseConfig(
            type="mysql",
            host="db",
            database="kc",
            credentials_secret="c",
        )
        assert cfg.port == 3306

    def test_managed_gets_default_port(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            managed=ManagedDatabaseConfig(host="h", database="d", username="u"),
        )
        assert cfg.managed is not None
        assert cfg.managed.port == 5432

    def test_external_gets_default_port(self):
        cfg = KeycloakDatabaseConfig(
            type="postgresql",
            external=ExternalDatabaseConfig(host="h", database="d", username="u"),
        )
        assert cfg.external is not None
        assert cfg.external.port == 5432


class TestCamelCaseAliases:
    """Test camelCase deserialization for tiered configs."""

    def test_cnpg_from_camelcase(self):
        cfg = KeycloakDatabaseConfig.model_validate(
            {
                "type": "postgresql",
                "cnpg": {"clusterName": "my-pg"},
            }
        )
        assert cfg.cnpg is not None
        assert cfg.cnpg.cluster_name == "my-pg"
        assert cfg.tier == "cnpg"

    def test_managed_from_camelcase(self):
        cfg = KeycloakDatabaseConfig.model_validate(
            {
                "type": "postgresql",
                "managed": {
                    "host": "h",
                    "database": "d",
                    "credentialsSecret": "s",
                    "sslMode": "verify-full",
                    "connectionParams": {"a": "b"},
                },
            }
        )
        assert cfg.managed is not None
        assert cfg.managed.credentials_secret == "s"
        assert cfg.managed.ssl_mode == "verify-full"

    def test_external_from_camelcase(self):
        cfg = KeycloakDatabaseConfig.model_validate(
            {
                "type": "postgresql",
                "external": {
                    "host": "h",
                    "database": "d",
                    "credentialsSecret": "s",
                    "passwordSecret": {"name": "sec", "key": "pw"},
                },
            }
        )
        assert cfg.external is not None
        assert cfg.external.credentials_secret == "s"
        assert cfg.external.password_secret is not None
        assert cfg.external.password_secret.name == "sec"


# ===========================================================================
# #601 — Maintenance Mode
# ===========================================================================


class TestMaintenanceModeModel:
    """Tests for the MaintenanceMode Pydantic model."""

    def test_defaults(self):
        """Defaults: disabled, full-block mode, standard health paths, default blocked paths."""
        mm = MaintenanceMode()
        assert mm.enabled is False
        assert mm.mode == "full-block"
        assert "/health" in mm.exclude_paths
        assert "/health/live" in mm.exclude_paths
        assert "/health/ready" in mm.exclude_paths
        assert "/health/started" in mm.exclude_paths
        # Default blocked paths for read-only mode
        assert "/admin" in mm.blocked_paths
        assert "/realms/[^/]+/account" in mm.blocked_paths
        assert "/realms/[^/]+/login-actions/registration" in mm.blocked_paths
        assert "/realms/[^/]+/broker" in mm.blocked_paths

    def test_enabled(self):
        mm = MaintenanceMode(enabled=True)
        assert mm.enabled is True

    def test_mode_read_only(self):
        mm = MaintenanceMode(mode="read-only")
        assert mm.mode == "read-only"

    def test_mode_full_block(self):
        mm = MaintenanceMode(mode="full-block")
        assert mm.mode == "full-block"

    def test_invalid_mode(self):
        with pytest.raises(ValidationError, match="Maintenance mode must be one of"):
            MaintenanceMode(mode="partial")

    def test_custom_exclude_paths(self):
        mm = MaintenanceMode(exclude_paths=["/custom", "/api/v1/status"])
        assert mm.exclude_paths == ["/custom", "/api/v1/status"]

    def test_camelcase_alias_exclude_paths(self):
        mm = MaintenanceMode.model_validate({"excludePaths": ["/x"]})
        assert mm.exclude_paths == ["/x"]

    def test_camelcase_alias_blocked_paths(self):
        mm = MaintenanceMode.model_validate({"blockedPaths": ["/custom-admin"]})
        assert mm.blocked_paths == ["/custom-admin"]

    def test_custom_blocked_paths(self):
        mm = MaintenanceMode(blocked_paths=["/custom-admin", "/special"])
        assert mm.blocked_paths == ["/custom-admin", "/special"]

    def test_blocked_paths_regex_chars_allowed(self):
        """Regex chars like [^/]+ are allowed (nginx regex)."""
        mm = MaintenanceMode(blocked_paths=["/realms/[^/]+/account"])
        assert mm.blocked_paths == ["/realms/[^/]+/account"]

    def test_blocked_paths_must_start_with_slash(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="must start with '/'"):
            MaintenanceMode(blocked_paths=["no-leading-slash"])

    def test_blocked_paths_rejects_double_quote(self):
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="quotes, newlines, semicolons, or braces"
        ):
            MaintenanceMode(blocked_paths=['/admin"injected'])

    def test_blocked_paths_rejects_newline(self):
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="quotes, newlines, semicolons, or braces"
        ):
            MaintenanceMode(blocked_paths=["/admin\nreturn 200"])

    def test_blocked_paths_rejects_semicolon(self):
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="quotes, newlines, semicolons, or braces"
        ):
            MaintenanceMode(blocked_paths=["/admin; return 200"])

    def test_blocked_paths_rejects_braces(self):
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="quotes, newlines, semicolons, or braces"
        ):
            MaintenanceMode(blocked_paths=["/admin{injected}"])


class TestBuildMaintenanceModeAnnotations:
    """Tests for build_maintenance_mode_annotations() in kubernetes.py."""

    def test_disabled_returns_empty(self):
        """When maintenance mode is disabled, no annotations are generated."""
        spec = _spec_with_db(maintenance_mode=MaintenanceMode(enabled=False))
        assert build_maintenance_mode_annotations(spec) == {}

    def test_none_returns_empty(self):
        """When maintenance_mode is None, no annotations are generated."""
        spec = _spec_with_db()
        assert spec.maintenance_mode is None
        assert build_maintenance_mode_annotations(spec) == {}

    def test_full_block_annotations(self):
        """Full-block mode generates correct annotations."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(enabled=True, mode="full-block"),
        )
        annotations = build_maintenance_mode_annotations(spec)

        assert MAINTENANCE_MODE_ANNOTATION in annotations
        assert annotations[MAINTENANCE_MODE_ANNOTATION] == "full-block"

        assert MAINTENANCE_MODE_SNIPPET_ANNOTATION in annotations
        snippet = annotations[MAINTENANCE_MODE_SNIPPET_ANNOTATION]
        assert "return 503" in snippet

    def test_read_only_blocks_admin_paths(self):
        """Read-only mode blocks admin/account/registration/broker paths."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(enabled=True, mode="read-only"),
        )
        annotations = build_maintenance_mode_annotations(spec)

        assert annotations[MAINTENANCE_MODE_ANNOTATION] == "read-only"
        snippet = annotations[MAINTENANCE_MODE_SNIPPET_ANNOTATION]
        assert "/admin" in snippet
        assert "/realms/[^/]+/account" in snippet
        assert "/realms/[^/]+/login-actions/registration" in snippet
        assert "/realms/[^/]+/broker" in snippet
        assert "return 503" in snippet

    def test_read_only_does_not_block_token_endpoint(self):
        """Read-only mode must NOT block POST /realms/.../protocol/openid-connect/token.

        Authentication flows use POST. Blocking all POST requests is wrong
        and would prevent users from logging in during an upgrade window.
        """
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(enabled=True, mode="read-only"),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        # The default block list must not contain the token endpoint path
        assert "protocol/openid-connect/token" not in snippet
        # Method-based blocking (GET|HEAD|OPTIONS pattern) must not appear
        assert "GET|HEAD|OPTIONS" not in snippet
        assert "$request_method" not in snippet

    def test_read_only_custom_blocked_paths(self):
        """Custom blocked paths are reflected in the snippet."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="read-only",
                blocked_paths=["/custom-admin", "/special-route"],
            ),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        assert "/custom-admin" in snippet
        assert "/special-route" in snippet
        # Default paths are NOT present since we overrode the list
        assert "/realms/[^/]+/account" not in snippet

    def test_read_only_empty_blocked_paths_produces_empty_snippet(self):
        """Empty blocked_paths in read-only mode produces a minimal snippet."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="read-only",
                blocked_paths=[],
            ),
        )
        annotations = build_maintenance_mode_annotations(spec)
        # Annotation key should still be present
        assert MAINTENANCE_MODE_ANNOTATION in annotations
        # Snippet may be empty or contain only whitespace after stripping
        snippet = annotations.get(MAINTENANCE_MODE_SNIPPET_ANNOTATION, "")
        assert "return 503" not in snippet

    def test_full_block_ignores_blocked_paths(self):
        """blocked_paths have no effect in full-block mode."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="full-block",
                blocked_paths=["/special"],
            ),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        # Full-block returns 503 for everything; path-specific blocks are not added
        assert "return 503" in snippet
        # The blocked path should not appear as a targeted rule
        assert "/special" not in snippet

    def test_exclude_paths_in_snippet(self):
        """Excluded paths appear in the nginx server-snippet."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="full-block",
                exclude_paths=["/health", "/health/live"],
            ),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        # Paths are properly escaped for nginx regex via re.escape
        assert "/health" in snippet
        assert "/health/live" in snippet
        assert "break" in snippet

    def test_empty_exclude_paths(self):
        """No exclude paths → no break directive in snippet."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="full-block",
                exclude_paths=[],
            ),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        assert "break" not in snippet
        assert "return 503" in snippet


class TestMaintenanceModeOnSpec:
    """Tests for maintenance_mode field on KeycloakSpec."""

    def test_spec_maintenance_mode_none_by_default(self):
        spec = _spec_with_db()
        assert spec.maintenance_mode is None

    def test_spec_with_maintenance_mode(self):
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(enabled=True, mode="read-only"),
        )
        assert spec.maintenance_mode is not None
        assert spec.maintenance_mode.enabled is True
        assert spec.maintenance_mode.mode == "read-only"

    def test_spec_from_dict_camelcase(self):
        spec = KeycloakSpec.model_validate(
            {
                "database": _legacy_db(),
                "maintenanceMode": {
                    "enabled": True,
                    "mode": "full-block",
                    "excludePaths": ["/custom"],
                },
            }
        )
        assert spec.maintenance_mode is not None
        assert spec.maintenance_mode.enabled is True
        assert spec.maintenance_mode.exclude_paths == ["/custom"]


# ===========================================================================
# #603 — JGroups Cache Isolation
# ===========================================================================


class TestCacheIsolationModel:
    """Tests for the CacheIsolation Pydantic model."""

    def test_defaults(self):
        ci = CacheIsolation()
        assert ci.cluster_name is None
        assert ci.auto_suffix is False

    def test_explicit_cluster_name(self):
        ci = CacheIsolation(cluster_name="blue-v26")
        assert ci.cluster_name == "blue-v26"

    def test_auto_suffix(self):
        ci = CacheIsolation(auto_suffix=True)
        assert ci.auto_suffix is True

    def test_camelcase_alias(self):
        ci = CacheIsolation.model_validate(
            {
                "clusterName": "green-v27",
                "autoSuffix": True,
            }
        )
        assert ci.cluster_name == "green-v27"
        assert ci.auto_suffix is True


class TestCacheIsolationOnSpec:
    """Tests for cache_isolation field on KeycloakSpec."""

    def test_spec_cache_isolation_none_by_default(self):
        spec = _spec_with_db()
        assert spec.cache_isolation is None

    def test_spec_with_cache_isolation(self):
        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="prod-v26"),
        )
        assert spec.cache_isolation is not None
        assert spec.cache_isolation.cluster_name == "prod-v26"

    def test_spec_from_dict_camelcase(self):
        spec = KeycloakSpec.model_validate(
            {
                "database": _legacy_db(),
                "cacheIsolation": {
                    "clusterName": "blue",
                    "autoSuffix": False,
                },
            }
        )
        assert spec.cache_isolation is not None
        assert spec.cache_isolation.cluster_name == "blue"


class TestResolveCacheClusterName:
    """Tests for _resolve_cache_cluster_name() in kubernetes.py."""

    def test_none_spec(self):
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        assert _resolve_cache_cluster_name("kc", None) is None

    def test_no_cache_isolation(self):
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db()
        assert _resolve_cache_cluster_name("kc", spec) is None

    def test_explicit_cluster_name(self):
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="explicit-name"),
        )
        assert _resolve_cache_cluster_name("kc", spec) == "explicit-name"

    def test_auto_suffix_from_image_tag(self):
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        assert _resolve_cache_cluster_name("my-kc", spec) == "my-kc-26.0.0"

    def test_auto_suffix_no_tag(self):
        """Image without tag → 'latest' suffix."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak",
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        assert _resolve_cache_cluster_name("my-kc", spec) == "my-kc-latest"

    def test_explicit_overrides_auto_suffix(self):
        """When both cluster_name and auto_suffix are set, explicit wins."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(cluster_name="explicit", auto_suffix=True),
        )
        assert _resolve_cache_cluster_name("kc", spec) == "explicit"

    def test_neither_cluster_name_nor_auto_suffix(self):
        """CacheIsolation with defaults (no cluster_name, auto_suffix=False) → None."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(cache_isolation=CacheIsolation())
        assert _resolve_cache_cluster_name("kc", spec) is None


class TestCacheIsolationDeployment:
    """Tests for cache isolation labels and JAVA_OPTS in deployment creation."""

    def _create_deployment_and_get_body(self, spec: KeycloakSpec):
        """Helper: create deployment with mocks and return the body."""
        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )
            call_args = mock_apps_api.create_namespaced_deployment.call_args
            return call_args[1]["body"]

    def test_no_cache_isolation_no_cluster_label(self):
        """Without cache isolation, pods don't get a cache-cluster label."""
        spec = _spec_with_db(optimized=True)
        deployment = self._create_deployment_and_get_body(spec)
        pod_labels = deployment.spec.template.metadata.labels
        assert CACHE_CLUSTER_LABEL not in pod_labels

    def test_no_cache_isolation_no_jgroups_cluster_name(self):
        """Without cache isolation, JAVA_OPTS_APPEND has no -Djgroups.cluster.name."""
        spec = _spec_with_db(optimized=True)
        deployment = self._create_deployment_and_get_body(spec)
        container = deployment.spec.template.spec.containers[0]
        env_dict = {e.name: e for e in container.env}
        java_opts = env_dict["JAVA_OPTS_APPEND"].value
        assert "-Djgroups.cluster.name=" not in java_opts

    def test_cache_isolation_adds_cluster_label(self):
        """With explicit cluster name, pods get the cache-cluster label."""
        spec = _spec_with_db(
            optimized=True,
            cache_isolation=CacheIsolation(cluster_name="blue-v26"),
        )
        deployment = self._create_deployment_and_get_body(spec)
        pod_labels = deployment.spec.template.metadata.labels
        assert pod_labels[CACHE_CLUSTER_LABEL] == "blue-v26"

    def test_cache_isolation_adds_jgroups_cluster_name(self):
        """With cache isolation, JAVA_OPTS_APPEND includes -Djgroups.cluster.name."""
        spec = _spec_with_db(
            optimized=True,
            cache_isolation=CacheIsolation(cluster_name="blue-v26"),
        )
        deployment = self._create_deployment_and_get_body(spec)
        container = deployment.spec.template.spec.containers[0]
        env_dict = {e.name: e for e in container.env}
        java_opts = env_dict["JAVA_OPTS_APPEND"].value
        assert "-Djgroups.cluster.name=blue-v26" in java_opts

    def test_cache_isolation_auto_suffix(self):
        """Auto-suffix uses image tag in cluster name."""
        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.4.0",
            optimized=True,
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        deployment = self._create_deployment_and_get_body(spec)
        pod_labels = deployment.spec.template.metadata.labels
        assert pod_labels[CACHE_CLUSTER_LABEL] == "my-keycloak-26.4.0"

        container = deployment.spec.template.spec.containers[0]
        env_dict = {e.name: e for e in container.env}
        java_opts = env_dict["JAVA_OPTS_APPEND"].value
        assert "-Djgroups.cluster.name=my-keycloak-26.4.0" in java_opts


class TestCacheIsolationDiscoveryService:
    """Tests for cache isolation labels on the discovery service."""

    def _create_discovery_and_get_body(self, spec: KeycloakSpec | None = None):
        """Helper: create discovery service and return the body."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            create_keycloak_discovery_service(
                name="my-keycloak",
                namespace="test-ns",
                k8s_client=mock_k8s_client,
                spec=spec,
            )
            call_args = mock_core_api.create_namespaced_service.call_args
            return call_args[1]["body"]

    def test_no_cache_isolation_no_cluster_label(self):
        """Without cache isolation, discovery service has no cache-cluster label."""
        service = self._create_discovery_and_get_body()
        assert CACHE_CLUSTER_LABEL not in service.metadata.labels
        assert CACHE_CLUSTER_LABEL not in service.spec.selector

    def test_cache_isolation_adds_label_to_service(self):
        """With cache isolation, discovery service labels include cache-cluster."""
        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="blue-v26"),
        )
        service = self._create_discovery_and_get_body(spec)
        assert service.metadata.labels[CACHE_CLUSTER_LABEL] == "blue-v26"

    def test_cache_isolation_adds_label_to_selector(self):
        """With cache isolation, discovery service selector includes cache-cluster."""
        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="blue-v26"),
        )
        service = self._create_discovery_and_get_body(spec)
        assert service.spec.selector[CACHE_CLUSTER_LABEL] == "blue-v26"

    def test_cache_isolation_preserves_existing_selector(self):
        """Cache-cluster label is added alongside existing selector labels."""
        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="green-v27"),
        )
        service = self._create_discovery_and_get_body(spec)

        # Original selector labels must still be present
        assert service.spec.selector["app"] == "keycloak"
        assert (
            service.spec.selector["vriesdemichael.github.io/keycloak-instance"]
            == "my-keycloak"
        )
        # Plus the cache cluster label
        assert service.spec.selector[CACHE_CLUSTER_LABEL] == "green-v27"

    def test_cache_isolation_with_none_spec(self):
        """spec=None → no cache isolation labels (backward compat)."""
        service = self._create_discovery_and_get_body(None)
        assert CACHE_CLUSTER_LABEL not in service.metadata.labels
        assert CACHE_CLUSTER_LABEL not in service.spec.selector

    def test_service_still_headless_with_cache_isolation(self):
        """Cache isolation does not break headless service behavior."""
        spec = _spec_with_db(
            cache_isolation=CacheIsolation(cluster_name="test"),
        )
        service = self._create_discovery_and_get_body(spec)
        assert service.spec.cluster_ip == "None"
        assert service.spec.publish_not_ready_addresses is True


# ===========================================================================
# Review Comment Fixes — Additional Validation Tests
# ===========================================================================


class TestCacheIsolationLabelValidation:
    """Tests for K8s label value validation on CacheIsolation.cluster_name."""

    def test_valid_simple_name(self):
        ci = CacheIsolation(cluster_name="blue-v26")
        assert ci.cluster_name == "blue-v26"

    def test_valid_with_dots_and_underscores(self):
        ci = CacheIsolation(cluster_name="my_cluster.v26")
        assert ci.cluster_name == "my_cluster.v26"

    def test_valid_single_char(self):
        ci = CacheIsolation(cluster_name="a")
        assert ci.cluster_name == "a"

    def test_valid_max_length(self):
        name = "a" * 63
        ci = CacheIsolation(cluster_name=name)
        assert ci.cluster_name == name

    def test_too_long_rejected(self):
        with pytest.raises(ValidationError, match="at most 63 characters"):
            CacheIsolation(cluster_name="a" * 64)

    def test_starts_with_dot_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name=".invalid")

    def test_ends_with_hyphen_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name="invalid-")

    def test_contains_spaces_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name="has space")

    def test_contains_slash_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name="has/slash")

    def test_contains_colon_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name="has:colon")

    def test_empty_string_rejected(self):
        with pytest.raises(ValidationError, match="not a valid Kubernetes label value"):
            CacheIsolation(cluster_name="")

    def test_none_is_allowed(self):
        ci = CacheIsolation(cluster_name=None)
        assert ci.cluster_name is None


class TestMaintenanceModePathValidation:
    """Tests for exclude_paths validation on MaintenanceMode."""

    def test_valid_health_paths(self):
        mm = MaintenanceMode(exclude_paths=["/health", "/health/live"])
        assert mm.exclude_paths == ["/health", "/health/live"]

    def test_valid_path_with_tilde(self):
        mm = MaintenanceMode(exclude_paths=["/path/~user"])
        assert mm.exclude_paths == ["/path/~user"]

    def test_valid_path_with_dots(self):
        mm = MaintenanceMode(exclude_paths=["/api/v1.0/status"])
        assert mm.exclude_paths == ["/api/v1.0/status"]

    def test_path_without_leading_slash_rejected(self):
        with pytest.raises(ValidationError, match="Invalid exclude path"):
            MaintenanceMode(exclude_paths=["health"])

    def test_path_with_regex_metachar_rejected(self):
        with pytest.raises(ValidationError, match="Invalid exclude path"):
            MaintenanceMode(exclude_paths=["/health.*"])

    def test_path_with_parentheses_rejected(self):
        with pytest.raises(ValidationError, match="Invalid exclude path"):
            MaintenanceMode(exclude_paths=["/path(evil)"])

    def test_path_with_space_rejected(self):
        with pytest.raises(ValidationError, match="Invalid exclude path"):
            MaintenanceMode(exclude_paths=["/path with space"])

    def test_path_with_question_mark_rejected(self):
        with pytest.raises(ValidationError, match="Invalid exclude path"):
            MaintenanceMode(exclude_paths=["/path?query=1"])

    def test_empty_list_is_valid(self):
        mm = MaintenanceMode(exclude_paths=[])
        assert mm.exclude_paths == []


class TestExtractImageTag:
    """Tests for _extract_image_tag() robustness."""

    def test_standard_image_with_tag(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        assert _extract_image_tag("quay.io/keycloak/keycloak:26.0.0") == "26.0.0"

    def test_image_without_tag(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        assert _extract_image_tag("quay.io/keycloak/keycloak") == "latest"

    def test_digest_only(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        result = _extract_image_tag("quay.io/keycloak/keycloak@sha256:abc123def456")
        assert result == "sha256-abc123def456"

    def test_tag_plus_digest(self):
        """When both tag and digest are present, tag wins."""
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        result = _extract_image_tag("quay.io/keycloak/keycloak:26.0.0@sha256:abc123")
        assert result == "26.0.0"

    def test_registry_with_port(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        result = _extract_image_tag("registry:5000/keycloak/keycloak:26.0.0")
        assert result == "26.0.0"

    def test_registry_with_port_no_tag(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        result = _extract_image_tag("registry:5000/keycloak/keycloak")
        assert result == "latest"

    def test_registry_with_port_and_digest(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        result = _extract_image_tag("registry:5000/keycloak/keycloak@sha256:abc123")
        assert result == "sha256-abc123"

    def test_simple_image_with_tag(self):
        from keycloak_operator.utils.kubernetes import _extract_image_tag

        assert _extract_image_tag("keycloak:latest") == "latest"


class TestNormalizeK8sLabelValue:
    """Tests for _normalize_k8s_label_value()."""

    def test_already_valid(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        assert _normalize_k8s_label_value("my-app-26.0.0") == "my-app-26.0.0"

    def test_truncation(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        long_value = "a" * 100
        result = _normalize_k8s_label_value(long_value)
        assert len(result) <= 63

    def test_replaces_invalid_chars(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        result = _normalize_k8s_label_value("my app:v1")
        assert " " not in result
        assert ":" not in result
        assert result == "my-app-v1"

    def test_strips_leading_trailing_special(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        result = _normalize_k8s_label_value("--my-app--")
        assert result == "my-app"

    def test_empty_after_strip(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        result = _normalize_k8s_label_value("---")
        assert result == ""

    def test_custom_max_length(self):
        from keycloak_operator.utils.kubernetes import _normalize_k8s_label_value

        result = _normalize_k8s_label_value("abcdef", max_length=3)
        assert result == "abc"


class TestAutoSuffixRobustImageParsing:
    """Tests for _resolve_cache_cluster_name with various image formats."""

    def test_registry_with_port(self):
        """Registry port should not confuse tag extraction."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="registry:5000/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        assert _resolve_cache_cluster_name("kc", spec) == "kc-26.0.0"

    def test_digest_reference(self):
        """Digest-only image should produce a valid label value."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak@sha256:abc123def",
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        result = _resolve_cache_cluster_name("kc", spec)
        assert result is not None
        assert len(result) <= 63
        # Should not contain the colon from sha256:
        assert ":" not in result

    def test_very_long_name_truncated(self):
        """Extremely long auto-suffix results are truncated to <=63 chars."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_suffix=True),
        )
        # Use a very long Keycloak instance name
        result = _resolve_cache_cluster_name("a" * 60, spec)
        assert result is not None
        assert len(result) <= 63


class TestMaintenanceModeAnnotationRemoval:
    """Tests for ensure_ingress removing stale maintenance annotations."""

    def test_build_maintenance_returns_empty_when_disabled(self):
        """When maintenance mode is disabled, empty dict is returned."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(enabled=False),
        )
        annotations = build_maintenance_mode_annotations(spec)
        assert annotations == {}

    def test_snippet_uses_re_escape(self):
        """Paths with dots are properly escaped via re.escape."""
        spec = _spec_with_db(
            maintenance_mode=MaintenanceMode(
                enabled=True,
                mode="full-block",
                exclude_paths=["/api/v1.0/health"],
            ),
        )
        snippet = build_maintenance_mode_annotations(spec)[
            MAINTENANCE_MODE_SNIPPET_ANNOTATION
        ]
        # re.escape escapes the dot: v1\.0
        assert r"v1\.0" in snippet


class TestExtractMajorVersion:
    """Tests for _extract_major_version() (ADR-090)."""

    def test_standard_semver(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:26.0.0") == 26

    def test_minor_only(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:26.1") == 26

    def test_major_only(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:26") == 26

    def test_latest_returns_none(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:latest") is None

    def test_nightly_returns_none(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:nightly") is None

    def test_no_tag_returns_none(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak") is None

    def test_digest_only_returns_none(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak@sha256:abc123") is None

    def test_semver_with_suffix(self):
        """Tags like 26.0.0-redhat-1 still yield major 26."""
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:26.0.0-redhat-1") == 26

    def test_registry_with_port(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("registry:5000/keycloak/keycloak:26.0.0") == 26

    def test_different_major(self):
        from keycloak_operator.utils.kubernetes import _extract_major_version

        assert _extract_major_version("quay.io/keycloak/keycloak:25.0.6") == 25


class TestAutoRevisionCacheIsolationModel:
    """Tests for CacheIsolation.auto_revision field (ADR-090)."""

    def test_auto_revision_defaults_false(self):
        ci = CacheIsolation()
        assert ci.auto_revision is False

    def test_auto_revision_set_true(self):
        ci = CacheIsolation(auto_revision=True)
        assert ci.auto_revision is True

    def test_camelcase_alias(self):
        ci = CacheIsolation.model_validate({"autoRevision": True})
        assert ci.auto_revision is True

    def test_auto_revision_and_auto_suffix_independent(self):
        ci = CacheIsolation(auto_revision=True, auto_suffix=True)
        assert ci.auto_revision is True
        assert ci.auto_suffix is True


class TestResolveCacheClusterNameAutoRevision:
    """Tests for _resolve_cache_cluster_name with auto_revision (ADR-090)."""

    def test_auto_revision_semver(self):
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        assert _resolve_cache_cluster_name("my-kc", spec) == "my-kc-v26"

    def test_auto_revision_patch_upgrade_stable(self):
        """26.0.0 and 26.0.1 both produce the same cluster name."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec_a = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        spec_b = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.1",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        assert _resolve_cache_cluster_name("kc", spec_a) == _resolve_cache_cluster_name(
            "kc", spec_b
        )

    def test_auto_revision_major_upgrade_splits(self):
        """25.x and 26.x produce different cluster names."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec_25 = _spec_with_db(
            image="quay.io/keycloak/keycloak:25.0.6",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        spec_26 = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        assert _resolve_cache_cluster_name(
            "kc", spec_25
        ) != _resolve_cache_cluster_name("kc", spec_26)

    def test_auto_revision_non_semver_returns_none(self):
        """Non-semver tag disables isolation and returns None."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:latest",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        assert _resolve_cache_cluster_name("kc", spec) is None

    def test_auto_revision_non_semver_logs_warning(self):
        """Non-semver tag triggers a logger.warning call."""
        import logging
        from unittest.mock import MagicMock

        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        mock_logger = MagicMock(spec=logging.Logger)
        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:latest",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        result = _resolve_cache_cluster_name("kc", spec, logger=mock_logger)
        assert result is None
        mock_logger.warning.assert_called_once()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "autoRevision" in warning_msg
        assert "semver" in warning_msg

    def test_auto_revision_no_logger_is_safe(self):
        """Non-semver tag with no logger passed does not raise."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:latest",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        result = _resolve_cache_cluster_name("kc", spec, logger=None)
        assert result is None

    def test_auto_revision_overrides_auto_suffix(self):
        """auto_revision takes priority over auto_suffix."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_revision=True, auto_suffix=True),
        )
        result = _resolve_cache_cluster_name("kc", spec)
        assert result == "kc-v26"

    def test_cluster_name_overrides_auto_revision(self):
        """Explicit cluster_name overrides auto_revision."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(cluster_name="explicit", auto_revision=True),
        )
        assert _resolve_cache_cluster_name("kc", spec) == "explicit"

    def test_auto_revision_digest_returns_none(self):
        """Digest-only reference has no parseable major version."""
        from keycloak_operator.utils.kubernetes import _resolve_cache_cluster_name

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak@sha256:abc123",
            cache_isolation=CacheIsolation(auto_revision=True),
        )
        assert _resolve_cache_cluster_name("kc", spec) is None


class TestDiscoveryServiceSelectorReconciliation:
    """Tests for ensure_discovery_service patching stale selectors (ADR-090)."""

    @pytest.mark.asyncio
    async def test_selector_patched_when_cluster_name_changes(self):
        """When the existing selector has a stale cluster label, it is patched."""
        from unittest.mock import MagicMock, patch

        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        mock_core_api = MagicMock()

        existing_service = MagicMock()
        existing_service.spec.selector = {
            "app": "keycloak",
            "vriesdemichael.github.io/keycloak-instance": "my-kc",
            "vriesdemichael.github.io/cache-cluster": "my-kc-v25",
        }
        existing_service.metadata.labels = {
            "vriesdemichael.github.io/cache-cluster": "my-kc-v25"
        }
        mock_core_api.read_namespaced_service.return_value = existing_service

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.0",
            cache_isolation=CacheIsolation(auto_revision=True),
        )

        reconciler = MagicMock(spec=KeycloakInstanceReconciler)
        reconciler.kubernetes_client = MagicMock()
        reconciler.logger = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            await KeycloakInstanceReconciler.ensure_discovery_service(
                reconciler, "my-kc", "ns", spec
            )

        mock_core_api.patch_namespaced_service.assert_called_once()
        patch_body = mock_core_api.patch_namespaced_service.call_args[1]["body"]
        assert (
            patch_body["spec"]["selector"]["vriesdemichael.github.io/cache-cluster"]
            == "my-kc-v26"
        )

    @pytest.mark.asyncio
    async def test_no_patch_when_selector_is_current(self):
        """When selector already has the correct label, no patch is made."""
        from unittest.mock import MagicMock, patch

        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        mock_core_api = MagicMock()

        existing_service = MagicMock()
        existing_service.spec.selector = {
            "app": "keycloak",
            "vriesdemichael.github.io/cache-cluster": "my-kc-v26",
        }
        existing_service.metadata.labels = {}
        mock_core_api.read_namespaced_service.return_value = existing_service

        spec = _spec_with_db(
            image="quay.io/keycloak/keycloak:26.0.1",
            cache_isolation=CacheIsolation(auto_revision=True),
        )

        reconciler = MagicMock(spec=KeycloakInstanceReconciler)
        reconciler.kubernetes_client = MagicMock()
        reconciler.logger = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            await KeycloakInstanceReconciler.ensure_discovery_service(
                reconciler, "my-kc", "ns", spec
            )

        mock_core_api.patch_namespaced_service.assert_not_called()

    @pytest.mark.asyncio
    async def test_selector_label_removed_when_isolation_disabled(self):
        """When cache isolation is removed from spec, stale label is patched out."""
        from unittest.mock import MagicMock, patch

        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        mock_core_api = MagicMock()

        existing_service = MagicMock()
        existing_service.spec.selector = {
            "app": "keycloak",
            "vriesdemichael.github.io/cache-cluster": "my-kc-v26",
        }
        existing_service.metadata.labels = {
            "vriesdemichael.github.io/cache-cluster": "my-kc-v26"
        }
        mock_core_api.read_namespaced_service.return_value = existing_service

        spec = _spec_with_db()

        reconciler = MagicMock(spec=KeycloakInstanceReconciler)
        reconciler.kubernetes_client = MagicMock()
        reconciler.logger = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            await KeycloakInstanceReconciler.ensure_discovery_service(
                reconciler, "my-kc", "ns", spec
            )

        mock_core_api.patch_namespaced_service.assert_called_once()
        patch_body = mock_core_api.patch_namespaced_service.call_args[1]["body"]
        assert (
            "vriesdemichael.github.io/cache-cluster"
            not in patch_body["spec"]["selector"]
        )
