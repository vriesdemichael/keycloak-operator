"""
Unit tests for UpgradePolicy model and related Phase 2 model additions (ADR-088).

Covers:
- UpgradePolicy model validation
- ManagedDatabaseConfig pvc_name / volume_snapshot_class_name fields
- KeycloakSpec.upgrade_policy integration
- New status phases and conditions
"""

import pytest
from pydantic import ValidationError

from keycloak_operator.constants import (
    BACKUP_CONFIRMED_ANNOTATION,
    CONDITION_BACKUP_NOT_VERIFIED,
    DEFAULT_BACKUP_TIMEOUT,
    PHASE_BACKING_UP,
    PHASE_WAITING_FOR_BACKUP_CONFIRMATION,
)
from keycloak_operator.models.keycloak import (
    KeycloakSpec,
    ManagedDatabaseConfig,
    UpgradePolicy,
)

# ===========================================================================
# UpgradePolicy Model
# ===========================================================================


class TestUpgradePolicy:
    """Test UpgradePolicy model validation and defaults."""

    def test_default_values(self):
        policy = UpgradePolicy()
        assert policy.require_backup_confirmation is False
        assert policy.backup_timeout == 600

    def test_custom_values(self):
        policy = UpgradePolicy(
            require_backup_confirmation=True,
            backup_timeout=120,
        )
        assert policy.require_backup_confirmation is True
        assert policy.backup_timeout == 120

    def test_alias_names(self):
        """Test that camelCase aliases work."""
        policy = UpgradePolicy(
            requireBackupConfirmation=True,
            backupTimeout=300,
        )
        assert policy.require_backup_confirmation is True
        assert policy.backup_timeout == 300

    def test_backup_timeout_minimum(self):
        """Timeout must be at least 60 seconds."""
        with pytest.raises(ValidationError, match="greater than or equal to 60"):
            UpgradePolicy(backup_timeout=30)

    def test_backup_timeout_maximum(self):
        """Timeout must be at most 3600 seconds."""
        with pytest.raises(ValidationError, match="less than or equal to 3600"):
            UpgradePolicy(backup_timeout=7200)

    def test_backup_timeout_boundary_60(self):
        policy = UpgradePolicy(backup_timeout=60)
        assert policy.backup_timeout == 60

    def test_backup_timeout_boundary_3600(self):
        policy = UpgradePolicy(backup_timeout=3600)
        assert policy.backup_timeout == 3600

    def test_model_dump_by_alias(self):
        """Dump with aliases produces camelCase keys."""
        policy = UpgradePolicy(
            require_backup_confirmation=True,
            backup_timeout=300,
        )
        data = policy.model_dump(by_alias=True, exclude_none=True)
        assert "requireBackupConfirmation" in data
        assert "backupTimeout" in data
        assert data["requireBackupConfirmation"] is True
        assert data["backupTimeout"] == 300


# ===========================================================================
# ManagedDatabaseConfig — Phase 2 fields
# ===========================================================================


class TestManagedDatabaseConfigPhase2:
    """Test pvc_name and volume_snapshot_class_name on ManagedDatabaseConfig."""

    def test_pvc_name_default_none(self):
        config = ManagedDatabaseConfig(
            host="db.example.com",
            database="keycloak",
            username="admin",
        )
        assert config.pvc_name is None
        assert config.volume_snapshot_class_name is None

    def test_pvc_name_set(self):
        config = ManagedDatabaseConfig(
            host="db.example.com",
            database="keycloak",
            username="admin",
            pvc_name="data-postgres-0",
        )
        assert config.pvc_name == "data-postgres-0"

    def test_volume_snapshot_class_name_set(self):
        config = ManagedDatabaseConfig(
            host="db.example.com",
            database="keycloak",
            username="admin",
            pvc_name="data-pvc",
            volume_snapshot_class_name="csi-hostpath-snapclass",
        )
        assert config.volume_snapshot_class_name == "csi-hostpath-snapclass"

    def test_aliases_work(self):
        config = ManagedDatabaseConfig(
            host="db.example.com",
            database="keycloak",
            username="admin",
            pvcName="data-pvc",
            volumeSnapshotClassName="my-class",
        )
        assert config.pvc_name == "data-pvc"
        assert config.volume_snapshot_class_name == "my-class"

    def test_model_dump_aliases(self):
        config = ManagedDatabaseConfig(
            host="db.example.com",
            database="keycloak",
            username="admin",
            pvc_name="data-pvc",
            volume_snapshot_class_name="my-class",
        )
        data = config.model_dump(by_alias=True, exclude_none=True)
        assert data["pvcName"] == "data-pvc"
        assert data["volumeSnapshotClassName"] == "my-class"


# ===========================================================================
# KeycloakSpec.upgrade_policy
# ===========================================================================


class TestKeycloakSpecUpgradePolicy:
    """Test upgrade_policy on KeycloakSpec."""

    def _base_spec(self, **overrides) -> KeycloakSpec:
        db = {
            "type": "postgresql",
            "host": "db.example.com",
            "database": "keycloak",
            "credentials_secret": "db-creds",
        }
        defaults = {"database": db}
        defaults.update(overrides)
        return KeycloakSpec(**defaults)

    def test_upgrade_policy_default_none(self):
        spec = self._base_spec()
        assert spec.upgrade_policy is None

    def test_upgrade_policy_set(self):
        spec = self._base_spec(
            upgrade_policy=UpgradePolicy(
                require_backup_confirmation=True,
                backup_timeout=120,
            )
        )
        assert spec.upgrade_policy is not None
        assert spec.upgrade_policy.require_backup_confirmation is True
        assert spec.upgrade_policy.backup_timeout == 120

    def test_upgrade_policy_from_dict(self):
        spec = self._base_spec(
            upgrade_policy={
                "requireBackupConfirmation": True,
                "backupTimeout": 300,
            }
        )
        assert spec.upgrade_policy is not None
        assert spec.upgrade_policy.require_backup_confirmation is True

    def test_upgrade_policy_alias(self):
        spec = self._base_spec(
            upgradePolicy={
                "requireBackupConfirmation": False,
                "backupTimeout": 600,
            }
        )
        assert spec.upgrade_policy is not None
        assert spec.upgrade_policy.backup_timeout == 600


# ===========================================================================
# Constants — Phase 2 additions
# ===========================================================================


class TestPhase2Constants:
    """Verify Phase 2 constants exist and have expected values."""

    def test_backup_confirmed_annotation(self):
        assert BACKUP_CONFIRMED_ANNOTATION == "operator.keycloak.io/backup-confirmed"

    def test_phase_backing_up(self):
        assert PHASE_BACKING_UP == "BackingUp"

    def test_phase_waiting_for_confirmation(self):
        assert PHASE_WAITING_FOR_BACKUP_CONFIRMATION == "WaitingForBackupConfirmation"

    def test_condition_backup_not_verified(self):
        assert CONDITION_BACKUP_NOT_VERIFIED == "BackupNotVerified"

    def test_default_backup_timeout(self):
        assert DEFAULT_BACKUP_TIMEOUT == 600
