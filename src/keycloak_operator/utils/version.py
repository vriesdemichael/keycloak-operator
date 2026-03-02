"""
Version detection utilities for Keycloak upgrade orchestration.

This module provides semantic version parsing, comparison, and version
change detection for the pre-upgrade backup workflow (ADR-088 Phase 2).

The operator needs to detect when a Keycloak image change constitutes a
major, minor, or patch version bump to determine whether a pre-upgrade
backup should be triggered.

Key design decisions:
- Reuses _parse_version / _extract_version_from_image from validation.py
  to avoid duplication.
- Introduces a VersionChange dataclass that encapsulates the comparison
  result so callers don't need to reason about semver tuples.
- Compares the *running* deployment image against the *desired* spec image
  to detect upgrades in the reconciler.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from keycloak_operator.utils.validation import (
    _extract_version_from_image,
    _parse_version,
)

logger = logging.getLogger(__name__)


class VersionBumpType(Enum):
    """Classification of a semantic version change."""

    NONE = "none"
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


@dataclass(frozen=True)
class VersionChange:
    """
    Result of comparing two Keycloak versions.

    Attributes:
        old_image: The previous (currently running) container image.
        new_image: The desired (spec) container image.
        old_version: Parsed version string from old_image, or None if unparseable.
        new_version: Parsed version string from new_image, or None if unparseable.
        bump_type: Classification of the version change.
        is_upgrade: True if new_version > old_version (not a downgrade or no-op).
        is_downgrade: True if new_version < old_version.
    """

    old_image: str
    new_image: str
    old_version: str | None
    new_version: str | None
    bump_type: VersionBumpType
    is_upgrade: bool
    is_downgrade: bool

    @property
    def requires_backup(self) -> bool:
        """Whether this version change warrants a pre-upgrade backup.

        Backups are triggered for major and minor upgrades. Patch upgrades
        and downgrades do not trigger automated backups (downgrades are
        explicitly unsupported by Keycloak and should be handled manually).
        """
        return self.is_upgrade and self.bump_type in (
            VersionBumpType.MAJOR,
            VersionBumpType.MINOR,
        )

    @property
    def is_image_change(self) -> bool:
        """Whether the image reference changed at all (including non-version changes)."""
        return self.old_image != self.new_image


def _classify_bump(
    old: tuple[int, int, int], new: tuple[int, int, int]
) -> VersionBumpType:
    """Classify the semver bump between two parsed version tuples."""
    if old == new:
        return VersionBumpType.NONE
    if old[0] != new[0]:
        return VersionBumpType.MAJOR
    if old[1] != new[1]:
        return VersionBumpType.MINOR
    return VersionBumpType.PATCH


def detect_version_change(old_image: str, new_image: str) -> VersionChange:
    """
    Compare two Keycloak container images and classify the version change.

    This function extracts version tags from both images, parses them as
    semver, and classifies the change. If either version cannot be parsed
    (e.g. digest-only images, custom tags), the bump type is NONE and
    the caller should fall back to image-string comparison.

    Args:
        old_image: Currently running container image reference.
        new_image: Desired container image reference from the spec.

    Returns:
        VersionChange with full comparison details.
    """
    old_version_str = _extract_version_from_image(old_image)
    new_version_str = _extract_version_from_image(new_image)

    # Default: no classified change
    bump_type = VersionBumpType.NONE
    is_upgrade = False
    is_downgrade = False

    if old_version_str and new_version_str:
        try:
            old_parsed = _parse_version(old_version_str)
            new_parsed = _parse_version(new_version_str)

            bump_type = _classify_bump(old_parsed, new_parsed)
            is_upgrade = new_parsed > old_parsed
            is_downgrade = new_parsed < old_parsed

            if is_upgrade:
                logger.info(
                    "Keycloak version upgrade detected: %s -> %s (%s bump)",
                    old_version_str,
                    new_version_str,
                    bump_type.value,
                )
            elif is_downgrade:
                logger.warning(
                    "Keycloak version downgrade detected: %s -> %s. "
                    "Downgrades are not supported by Keycloak and may cause data loss.",
                    old_version_str,
                    new_version_str,
                )
        except ValueError:
            logger.warning(
                "Could not parse Keycloak versions for comparison: %s, %s",
                old_version_str,
                new_version_str,
            )
    elif old_image != new_image:
        # Image changed but we can't parse version(s)
        logger.info(
            "Keycloak image changed but version could not be determined: %s -> %s",
            old_image,
            new_image,
        )

    return VersionChange(
        old_image=old_image,
        new_image=new_image,
        old_version=old_version_str,
        new_version=new_version_str,
        bump_type=bump_type,
        is_upgrade=is_upgrade,
        is_downgrade=is_downgrade,
    )


def get_deployment_image(deployment: dict) -> str | None:
    """
    Extract the Keycloak container image from a Deployment resource dict.

    Searches the deployment's containers for one named 'keycloak' or falls
    back to the first container.

    Args:
        deployment: Kubernetes Deployment as a dictionary (e.g. from
            ``apps_api.read_namespaced_deployment().to_dict()``).

    Returns:
        Container image string, or None if the deployment has no containers.
    """
    try:
        containers = (
            deployment.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        if not containers:
            return None

        # Prefer the container named 'keycloak'
        for container in containers:
            if container.get("name") == "keycloak":
                return container.get("image")

        # Fall back to first container
        return containers[0].get("image")
    except (AttributeError, TypeError, IndexError):
        logger.debug("Could not extract image from deployment: %s", deployment)
        return None


def get_deployment_image_from_k8s(deployment_obj: object) -> str | None:
    """
    Extract the Keycloak container image from a kubernetes-client Deployment object.

    This variant works with the typed kubernetes-client V1Deployment objects
    (as returned by ``apps_api.read_namespaced_deployment()``).

    Args:
        deployment_obj: kubernetes.client.V1Deployment object.

    Returns:
        Container image string, or None if the deployment has no containers.
    """
    try:
        containers = deployment_obj.spec.template.spec.containers  # type: ignore[union-attr]
        if not containers:
            return None

        # Prefer the container named 'keycloak'
        for container in containers:
            if container.name == "keycloak":
                return container.image

        # Fall back to first container
        return containers[0].image
    except (AttributeError, TypeError, IndexError):
        logger.debug(
            "Could not extract image from k8s deployment object: %s", deployment_obj
        )
        return None
