"""
Unit tests for version detection utilities (ADR-088 Phase 2).

Covers:
- VersionBumpType enum classification
- VersionChange dataclass properties
- detect_version_change() for all bump types, downgrades, unparseable images
- get_deployment_image() dict extraction
- get_deployment_image_from_k8s() typed object extraction
- _classify_bump() internal helper
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from keycloak_operator.utils.version import (
    VersionBumpType,
    VersionChange,
    _classify_bump,
    detect_version_change,
    get_deployment_image,
    get_deployment_image_from_k8s,
)

# ===========================================================================
# _classify_bump
# ===========================================================================


class TestClassifyBump:
    """Test the internal _classify_bump helper."""

    def test_no_change(self):
        assert _classify_bump((26, 0, 0), (26, 0, 0)) == VersionBumpType.NONE

    def test_patch_bump(self):
        assert _classify_bump((26, 0, 0), (26, 0, 1)) == VersionBumpType.PATCH

    def test_minor_bump(self):
        assert _classify_bump((26, 0, 0), (26, 1, 0)) == VersionBumpType.MINOR

    def test_major_bump(self):
        assert _classify_bump((25, 0, 0), (26, 0, 0)) == VersionBumpType.MAJOR

    def test_major_bump_takes_priority_over_minor(self):
        assert _classify_bump((25, 3, 2), (26, 1, 0)) == VersionBumpType.MAJOR

    def test_minor_bump_takes_priority_over_patch(self):
        assert _classify_bump((26, 0, 5), (26, 1, 3)) == VersionBumpType.MINOR

    def test_downgrade_major(self):
        """Downgrades still classify the bump type correctly."""
        assert _classify_bump((26, 0, 0), (25, 0, 0)) == VersionBumpType.MAJOR

    def test_downgrade_minor(self):
        assert _classify_bump((26, 1, 0), (26, 0, 0)) == VersionBumpType.MINOR

    def test_downgrade_patch(self):
        assert _classify_bump((26, 0, 1), (26, 0, 0)) == VersionBumpType.PATCH


# ===========================================================================
# VersionChange dataclass
# ===========================================================================


class TestVersionChange:
    """Test VersionChange properties."""

    def test_requires_backup_for_major_upgrade(self):
        vc = VersionChange(
            old_image="keycloak:25.0.0",
            new_image="keycloak:26.0.0",
            old_version="25.0.0",
            new_version="26.0.0",
            bump_type=VersionBumpType.MAJOR,
            is_upgrade=True,
            is_downgrade=False,
        )
        assert vc.requires_backup is True

    def test_requires_backup_for_minor_upgrade(self):
        vc = VersionChange(
            old_image="keycloak:26.0.0",
            new_image="keycloak:26.1.0",
            old_version="26.0.0",
            new_version="26.1.0",
            bump_type=VersionBumpType.MINOR,
            is_upgrade=True,
            is_downgrade=False,
        )
        assert vc.requires_backup is True

    def test_no_backup_for_patch_upgrade(self):
        vc = VersionChange(
            old_image="keycloak:26.0.0",
            new_image="keycloak:26.0.1",
            old_version="26.0.0",
            new_version="26.0.1",
            bump_type=VersionBumpType.PATCH,
            is_upgrade=True,
            is_downgrade=False,
        )
        assert vc.requires_backup is False

    def test_no_backup_for_downgrade(self):
        vc = VersionChange(
            old_image="keycloak:26.0.0",
            new_image="keycloak:25.0.0",
            old_version="26.0.0",
            new_version="25.0.0",
            bump_type=VersionBumpType.MAJOR,
            is_upgrade=False,
            is_downgrade=True,
        )
        assert vc.requires_backup is False

    def test_no_backup_for_no_change(self):
        vc = VersionChange(
            old_image="keycloak:26.0.0",
            new_image="keycloak:26.0.0",
            old_version="26.0.0",
            new_version="26.0.0",
            bump_type=VersionBumpType.NONE,
            is_upgrade=False,
            is_downgrade=False,
        )
        assert vc.requires_backup is False

    def test_is_image_change_true(self):
        vc = VersionChange(
            old_image="keycloak:25.0.0",
            new_image="keycloak:26.0.0",
            old_version="25.0.0",
            new_version="26.0.0",
            bump_type=VersionBumpType.MAJOR,
            is_upgrade=True,
            is_downgrade=False,
        )
        assert vc.is_image_change is True

    def test_is_image_change_false(self):
        vc = VersionChange(
            old_image="keycloak:26.0.0",
            new_image="keycloak:26.0.0",
            old_version="26.0.0",
            new_version="26.0.0",
            bump_type=VersionBumpType.NONE,
            is_upgrade=False,
            is_downgrade=False,
        )
        assert vc.is_image_change is False

    def test_frozen_dataclass(self):
        """VersionChange instances should be immutable."""
        vc = VersionChange(
            old_image="keycloak:25.0.0",
            new_image="keycloak:26.0.0",
            old_version="25.0.0",
            new_version="26.0.0",
            bump_type=VersionBumpType.MAJOR,
            is_upgrade=True,
            is_downgrade=False,
        )
        with pytest.raises(AttributeError):
            vc.is_upgrade = False  # type: ignore[misc]


# ===========================================================================
# detect_version_change
# ===========================================================================


class TestDetectVersionChange:
    """Test detect_version_change() integration."""

    def test_major_upgrade(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:25.0.6",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.MAJOR
        assert result.is_upgrade is True
        assert result.is_downgrade is False
        assert result.requires_backup is True
        assert result.old_version == "25.0.6"
        assert result.new_version == "26.0.0"

    def test_minor_upgrade(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak:26.1.0",
        )
        assert result.bump_type == VersionBumpType.MINOR
        assert result.is_upgrade is True
        assert result.requires_backup is True

    def test_patch_upgrade(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak:26.0.1",
        )
        assert result.bump_type == VersionBumpType.PATCH
        assert result.is_upgrade is True
        assert result.requires_backup is False

    def test_no_change(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.is_upgrade is False
        assert result.is_downgrade is False
        assert result.requires_backup is False

    def test_downgrade(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak:25.0.6",
        )
        assert result.bump_type == VersionBumpType.MAJOR
        assert result.is_upgrade is False
        assert result.is_downgrade is True
        assert result.requires_backup is False

    def test_digest_image_old(self):
        """Digest-only images can't be parsed for version."""
        result = detect_version_change(
            "quay.io/keycloak/keycloak@sha256:abc123",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.old_version is None
        assert result.new_version == "26.0.0"
        assert result.is_image_change is True

    def test_digest_image_new(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak@sha256:abc123",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.old_version == "26.0.0"
        assert result.new_version is None

    def test_both_digest_images(self):
        result = detect_version_change(
            "quay.io/keycloak/keycloak@sha256:abc123",
            "quay.io/keycloak/keycloak@sha256:def456",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.old_version is None
        assert result.new_version is None
        assert result.is_image_change is True

    def test_no_tag(self):
        """Images without tags can't be parsed for version."""
        result = detect_version_change(
            "quay.io/keycloak/keycloak",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.old_version is None

    def test_custom_tag(self):
        """Non-version tags like 'latest' can't be parsed."""
        result = detect_version_change(
            "quay.io/keycloak/keycloak:latest",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.old_version is None
        assert result.new_version == "26.0.0"

    def test_different_registries_same_version(self):
        """Different registries but same version tag => no bump."""
        result = detect_version_change(
            "docker.io/keycloak/keycloak:26.0.0",
            "quay.io/keycloak/keycloak:26.0.0",
        )
        assert result.bump_type == VersionBumpType.NONE
        assert result.is_upgrade is False
        assert result.is_image_change is True

    def test_multi_digit_versions(self):
        result = detect_version_change(
            "keycloak:24.10.3",
            "keycloak:25.0.0",
        )
        assert result.bump_type == VersionBumpType.MAJOR
        assert result.is_upgrade is True


# ===========================================================================
# get_deployment_image (dict-based)
# ===========================================================================


class TestGetDeploymentImage:
    """Test get_deployment_image() with raw dicts."""

    def test_keycloak_container_preferred(self):
        deployment = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "sidecar", "image": "sidecar:1.0"},
                            {"name": "keycloak", "image": "keycloak:26.0.0"},
                        ]
                    }
                }
            }
        }
        assert get_deployment_image(deployment) == "keycloak:26.0.0"

    def test_fallback_to_first_container(self):
        deployment = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "my-app", "image": "my-app:1.0"},
                        ]
                    }
                }
            }
        }
        assert get_deployment_image(deployment) == "my-app:1.0"

    def test_empty_containers(self):
        deployment = {"spec": {"template": {"spec": {"containers": []}}}}
        assert get_deployment_image(deployment) is None

    def test_missing_spec(self):
        assert get_deployment_image({}) is None

    def test_missing_template(self):
        assert get_deployment_image({"spec": {}}) is None

    def test_none_deployment(self):
        assert get_deployment_image(None) is None

    def test_string_deployment(self):
        assert get_deployment_image("not-a-dict") is None


# ===========================================================================
# get_deployment_image_from_k8s (typed object)
# ===========================================================================


class TestGetDeploymentImageFromK8s:
    """Test get_deployment_image_from_k8s() with mock k8s objects."""

    def _make_deployment(self, containers):
        """Create a mock V1Deployment-like object."""
        mock_containers = []
        for c in containers:
            mc = SimpleNamespace(name=c["name"], image=c["image"])
            mock_containers.append(mc)

        return SimpleNamespace(
            spec=SimpleNamespace(
                template=SimpleNamespace(
                    spec=SimpleNamespace(containers=mock_containers)
                )
            )
        )

    def test_keycloak_container_preferred(self):
        dep = self._make_deployment(
            [
                {"name": "sidecar", "image": "sidecar:1.0"},
                {"name": "keycloak", "image": "keycloak:26.0.0"},
            ]
        )
        assert get_deployment_image_from_k8s(dep) == "keycloak:26.0.0"

    def test_fallback_to_first_container(self):
        dep = self._make_deployment(
            [
                {"name": "my-app", "image": "my-app:1.0"},
            ]
        )
        assert get_deployment_image_from_k8s(dep) == "my-app:1.0"

    def test_empty_containers(self):
        dep = SimpleNamespace(
            spec=SimpleNamespace(
                template=SimpleNamespace(spec=SimpleNamespace(containers=[]))
            )
        )
        assert get_deployment_image_from_k8s(dep) is None

    def test_none_deployment(self):
        assert get_deployment_image_from_k8s(None) is None

    def test_missing_spec(self):
        dep = SimpleNamespace(spec=None)
        assert get_deployment_image_from_k8s(dep) is None

    def test_missing_containers_attribute(self):
        dep = MagicMock()
        dep.spec.template.spec.containers = None
        assert get_deployment_image_from_k8s(dep) is None


# ===========================================================================
# VersionBumpType enum
# ===========================================================================


class TestVersionBumpType:
    """Test VersionBumpType enum values."""

    def test_values(self):
        assert VersionBumpType.NONE.value == "none"
        assert VersionBumpType.PATCH.value == "patch"
        assert VersionBumpType.MINOR.value == "minor"
        assert VersionBumpType.MAJOR.value == "major"

    def test_all_members(self):
        assert set(VersionBumpType) == {
            VersionBumpType.NONE,
            VersionBumpType.PATCH,
            VersionBumpType.MINOR,
            VersionBumpType.MAJOR,
        }
