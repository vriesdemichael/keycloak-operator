#!/usr/bin/env python3
"""
Keycloak API Stability Verification Tool

Compares OpenAPI specs between Keycloak versions to detect breaking changes.
Used during version maintenance (bumping canonical, adding supported versions).

Usage:
    # Check all supported version ranges (first/last of each major)
    uv run scripts/verify_api_stability.py --check-all

    # Compare specific versions
    uv run scripts/verify_api_stability.py --from 26.0.0 --to 26.1.0

    # Verify a new version before adding support
    uv run scripts/verify_api_stability.py --verify-new 27.0.0

Output: YAML report to stdout (pipe to file for archiving)
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent.absolute()
CACHE_DIR = SCRIPT_DIR / ".keycloak-specs"

# Version ranges to check (first and last of each major with available specs)
# Note: Not all versions have published OpenAPI specs
VERSION_RANGES = {
    24: ("24.0.5", "24.0.5"),  # Only one spec available
    25: ("25.0.6", "25.0.6"),  # Only one spec available
    26: ("26.2.0", "26.5.2"),  # Multiple specs: 26.2.0, 26.3.0, 26.4.0, 26.5.0, 26.5.2
}

# Additional 26.x versions to check for minor version stability
V26_MINOR_VERSIONS = ["26.2.0", "26.3.0", "26.4.0", "26.5.0", "26.5.2"]

CANONICAL_VERSION = "26.5.2"


@dataclass
class FieldInfo:
    """Information about a field in a model class."""

    name: str
    field_type: str
    required: bool
    description: str | None = None


@dataclass
class ClassInfo:
    """Information about a model class."""

    name: str
    fields: dict[str, FieldInfo] = field(default_factory=dict)
    description: str | None = None


@dataclass
class Change:
    """A single API change between versions."""

    change_type: (
        str  # added_class, removed_class, added_field, removed_field, type_change
    )
    name: str
    location: str  # class name or "new class" / "removed class"
    details: dict[str, Any] = field(default_factory=dict)
    breaking: bool = False
    impact: str | None = None
    mitigation: str | None = None


@dataclass
class Comparison:
    """Result of comparing two API specs."""

    from_version: str
    to_version: str
    version_type: str  # patch, minor, major
    status: str  # stable, additions, breaking
    changes: list[Change] = field(default_factory=list)

    @property
    def added_classes(self) -> list[Change]:
        return [c for c in self.changes if c.change_type == "added_class"]

    @property
    def removed_classes(self) -> list[Change]:
        return [c for c in self.changes if c.change_type == "removed_class"]

    @property
    def added_fields(self) -> list[Change]:
        return [c for c in self.changes if c.change_type == "added_field"]

    @property
    def removed_fields(self) -> list[Change]:
        return [c for c in self.changes if c.change_type == "removed_field"]

    @property
    def type_changes(self) -> list[Change]:
        return [c for c in self.changes if c.change_type == "type_change"]

    @property
    def breaking_changes(self) -> list[Change]:
        return [c for c in self.changes if c.breaking]


def get_version_type(from_ver: str, to_ver: str) -> str:
    """Determine the type of version change."""
    from_parts = [int(x) for x in from_ver.split(".")]
    to_parts = [int(x) for x in to_ver.split(".")]

    if from_parts[0] != to_parts[0]:
        return "major"
    elif from_parts[1] != to_parts[1]:
        return "minor"
    else:
        return "patch"


def download_spec(version: str) -> Path | None:
    """Download OpenAPI spec for a version, using cache if available."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / f"{version}.yaml"

    if cache_path.exists() and cache_path.stat().st_size > 0:
        logger.debug(f"Using cached spec for {version}")
        return cache_path

    url = f"https://www.keycloak.org/docs-api/{version}/rest-api/openapi.yaml"
    logger.info(f"Downloading spec for {version} from {url}")

    try:
        response = httpx.get(url, follow_redirects=True, timeout=30.0)
        response.raise_for_status()
        cache_path.write_bytes(response.content)
        logger.info(f"Cached spec for {version}")
        return cache_path
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.warning(f"Spec not found for version {version} (404)")
            return None
        logger.error(f"Failed to download spec for {version}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to download spec for {version}: {e}")
        return None


def parse_spec(spec_path: Path) -> dict[str, ClassInfo]:
    """Parse OpenAPI spec and extract schema definitions."""
    with open(spec_path) as f:
        spec = yaml.safe_load(f)

    classes: dict[str, ClassInfo] = {}
    schemas = spec.get("components", {}).get("schemas", {})

    for name, schema in schemas.items():
        if schema.get("type") != "object":
            # Skip non-object schemas (enums, etc.)
            # But we should track enums too for completeness
            if "enum" in schema:
                # Track as a simple class with no fields
                classes[name] = ClassInfo(
                    name=name,
                    fields={},
                    description=schema.get("description"),
                )
            continue

        class_info = ClassInfo(
            name=name,
            description=schema.get("description"),
        )

        properties = schema.get("properties", {})
        required_fields = set(schema.get("required", []))

        for field_name, field_schema in properties.items():
            field_type = resolve_type(field_schema)
            class_info.fields[field_name] = FieldInfo(
                name=field_name,
                field_type=field_type,
                required=field_name in required_fields,
                description=field_schema.get("description"),
            )

        classes[name] = class_info

    return classes


def resolve_type(schema: dict[str, Any] | bool) -> str:
    """Resolve a JSON schema type to a Python-like type string."""
    # Handle boolean schema (true = any, false = none)
    if isinstance(schema, bool):
        return "Any" if schema else "Never"

    if "$ref" in schema:
        return schema["$ref"].split("/")[-1]

    schema_type = schema.get("type")

    if schema_type == "string":
        if "enum" in schema:
            return f"Literal{schema['enum']}"
        return "str"
    elif schema_type == "integer":
        return "int"
    elif schema_type == "number":
        return "float"
    elif schema_type == "boolean":
        return "bool"
    elif schema_type == "array":
        items = schema.get("items", {})
        item_type = resolve_type(items)
        return f"list[{item_type}]"
    elif schema_type == "object":
        additional = schema.get("additionalProperties")
        if additional:
            value_type = resolve_type(additional)
            return f"dict[str, {value_type}]"
        return "dict[str, Any]"
    elif "oneOf" in schema or "anyOf" in schema:
        variants = schema.get("oneOf", schema.get("anyOf", []))
        types = [resolve_type(v) for v in variants]
        return " | ".join(types)
    elif schema_type is None and not schema:
        return "Any"

    return "Any"


def compare_specs(
    from_classes: dict[str, ClassInfo],
    to_classes: dict[str, ClassInfo],
    from_version: str,
    to_version: str,
) -> Comparison:
    """Compare two parsed specs and identify changes."""
    version_type = get_version_type(from_version, to_version)
    changes: list[Change] = []

    from_names = set(from_classes.keys())
    to_names = set(to_classes.keys())

    # Removed classes (BREAKING)
    for name in from_names - to_names:
        changes.append(
            Change(
                change_type="removed_class",
                name=name,
                location="removed class",
                breaking=True,
                impact=f"Code using {name} will fail",
                mitigation="Remove usage or map to alternative",
            )
        )

    # Added classes (compatible)
    for name in to_names - from_names:
        changes.append(
            Change(
                change_type="added_class",
                name=name,
                location="new class",
                breaking=False,
                details={"description": to_classes[name].description},
            )
        )

    # Compare fields in common classes
    for name in from_names & to_names:
        from_class = from_classes[name]
        to_class = to_classes[name]

        from_fields = set(from_class.fields.keys())
        to_fields = set(to_class.fields.keys())

        # Removed fields (BREAKING)
        for field_name in from_fields - to_fields:
            field_info = from_class.fields[field_name]
            changes.append(
                Change(
                    change_type="removed_field",
                    name=field_name,
                    location=name,
                    breaking=True,
                    impact=f"Field access on {name}.{field_name} will fail",
                    mitigation="Remove usage (field was deprecated or removed)",
                    details={"field_type": field_info.field_type},
                )
            )

        # Added fields (compatible)
        for field_name in to_fields - from_fields:
            field_info = to_class.fields[field_name]
            changes.append(
                Change(
                    change_type="added_field",
                    name=field_name,
                    location=name,
                    breaking=False,
                    details={
                        "field_type": field_info.field_type,
                        "description": field_info.description,
                    },
                )
            )

        # Type changes in common fields
        for field_name in from_fields & to_fields:
            from_field = from_class.fields[field_name]
            to_field = to_class.fields[field_name]

            if from_field.field_type != to_field.field_type:
                # Determine if breaking
                breaking = is_type_change_breaking(
                    from_field.field_type, to_field.field_type
                )
                changes.append(
                    Change(
                        change_type="type_change",
                        name=field_name,
                        location=name,
                        breaking=breaking,
                        impact=f"Type mismatch in {name}.{field_name}"
                        if breaking
                        else None,
                        mitigation="Update code to handle new type"
                        if breaking
                        else None,
                        details={
                            "from_type": from_field.field_type,
                            "to_type": to_field.field_type,
                        },
                    )
                )

    # Determine overall status
    if any(c.breaking for c in changes):
        status = "breaking"
    elif changes:
        status = "additions"
    else:
        status = "stable"

    return Comparison(
        from_version=from_version,
        to_version=to_version,
        version_type=version_type,
        status=status,
        changes=changes,
    )


def is_type_change_breaking(from_type: str, to_type: str) -> bool:
    """Determine if a type change is breaking."""
    # Adding None (making optional) is not breaking
    if to_type == f"{from_type} | None" or to_type == f"None | {from_type}":
        return False

    # Removing None (making required) IS breaking
    if from_type == f"{to_type} | None" or from_type == f"None | {to_type}":
        return True

    # Any other type change is potentially breaking
    return True


def generate_limitations_report(
    canonical_classes: dict[str, ClassInfo],
    older_classes: dict[str, ClassInfo],
    older_version: str,
) -> dict[str, Any]:
    """Generate 'what you lose' report for an older version."""
    canonical_names = set(canonical_classes.keys())
    older_names = set(older_classes.keys())

    unavailable_classes = []
    for name in canonical_names - older_names:
        unavailable_classes.append(
            {
                "name": name,
                "description": canonical_classes[name].description or "No description",
            }
        )

    unavailable_fields = []
    for name in canonical_names & older_names:
        canonical_class = canonical_classes[name]
        older_class = older_classes[name]

        canonical_fields = set(canonical_class.fields.keys())
        older_fields = set(older_class.fields.keys())

        for field_name in canonical_fields - older_fields:
            field_info = canonical_class.fields[field_name]
            unavailable_fields.append(
                {
                    "class": name,
                    "field": field_name,
                    "type": field_info.field_type,
                    "description": field_info.description or "No description",
                }
            )

    # Sort for consistent output
    unavailable_classes.sort(key=lambda x: x["name"])
    unavailable_fields.sort(key=lambda x: (x["class"], x["field"]))

    major = older_version.split(".")[0]
    return {
        f"v{major}": {
            "compared_to": CANONICAL_VERSION,
            "spec_version": older_version,
            "unavailable_classes_count": len(unavailable_classes),
            "unavailable_fields_count": len(unavailable_fields),
            "unavailable_classes": unavailable_classes[:50],  # Limit for readability
            "unavailable_fields": unavailable_fields[:100],  # Limit for readability
            "note": "Lists truncated"
            if len(unavailable_classes) > 50 or len(unavailable_fields) > 100
            else None,
        }
    }


def comparison_to_dict(comp: Comparison) -> dict[str, Any]:
    """Convert Comparison to dict for YAML output."""
    return {
        "from_version": comp.from_version,
        "to_version": comp.to_version,
        "version_type": comp.version_type,
        "status": comp.status,
        "summary": {
            "total_changes": len(comp.changes),
            "added_classes": len(comp.added_classes),
            "removed_classes": len(comp.removed_classes),
            "added_fields": len(comp.added_fields),
            "removed_fields": len(comp.removed_fields),
            "type_changes": len(comp.type_changes),
            "breaking_changes": len(comp.breaking_changes),
        },
        "breaking_changes": [
            {
                "type": c.change_type,
                "name": c.name,
                "location": c.location,
                "impact": c.impact,
                "mitigation": c.mitigation,
                **c.details,
            }
            for c in comp.breaking_changes
        ],
        "additions": [
            {
                "type": c.change_type,
                "name": c.name,
                "location": c.location,
                **c.details,
            }
            for c in comp.changes
            if not c.breaking and c.change_type.startswith("added")
        ][:50],  # Limit additions list
    }


def check_all() -> dict[str, Any]:
    """Run full stability check across all major versions."""
    version_ranges_checked: dict[str, dict[str, str]] = {}
    comparisons: list[dict[str, Any]] = []
    version_limitations: dict[str, Any] = {}

    # Download canonical spec first
    canonical_path = download_spec(CANONICAL_VERSION)
    if not canonical_path:
        logger.error(f"Could not download canonical spec {CANONICAL_VERSION}")
        sys.exit(1)

    canonical_classes = parse_spec(canonical_path)
    logger.info(f"Canonical spec has {len(canonical_classes)} classes")

    all_comparisons: list[Comparison] = []

    # Check each major version range
    for major, (first, last) in sorted(VERSION_RANGES.items()):
        logger.info(f"Checking version range {first} -> {last}")
        version_ranges_checked[f"v{major}"] = {"first": first, "last": last}

        first_path = download_spec(first)
        last_path = download_spec(last)

        if not first_path or not last_path:
            logger.warning(f"Could not download specs for major version {major}")
            continue

        first_classes = parse_spec(first_path)
        last_classes = parse_spec(last_path)

        # Compare first to last within major
        comp = compare_specs(first_classes, last_classes, first, last)
        all_comparisons.append(comp)
        comparisons.append(comparison_to_dict(comp))

        # Generate limitations report (what you lose vs canonical)
        if major != 26:  # Don't compare canonical to itself
            limitations = generate_limitations_report(
                canonical_classes, last_classes, last
            )
            version_limitations.update(limitations)

    # Check 26.x minor version stability (sequential comparisons)
    logger.info("Checking 26.x minor version stability...")
    v26_classes: dict[str, dict[str, ClassInfo]] = {}
    for version in V26_MINOR_VERSIONS:
        path = download_spec(version)
        if path:
            v26_classes[version] = parse_spec(path)

    # Compare each consecutive pair
    for i in range(len(V26_MINOR_VERSIONS) - 1):
        from_ver = V26_MINOR_VERSIONS[i]
        to_ver = V26_MINOR_VERSIONS[i + 1]

        if from_ver in v26_classes and to_ver in v26_classes:
            logger.info(f"Comparing 26.x versions: {from_ver} -> {to_ver}")
            comp = compare_specs(
                v26_classes[from_ver], v26_classes[to_ver], from_ver, to_ver
            )
            all_comparisons.append(comp)
            comparisons.append(comparison_to_dict(comp))

    # Also compare across major versions (last of each major to canonical)
    for _major, (_, last) in sorted(VERSION_RANGES.items()):
        if last == CANONICAL_VERSION:
            continue

        last_path = download_spec(last)
        if not last_path:
            continue

        last_classes = parse_spec(last_path)
        comp = compare_specs(last_classes, canonical_classes, last, CANONICAL_VERSION)
        all_comparisons.append(comp)
        comparisons.append(comparison_to_dict(comp))

    # Generate recommendations
    needs_review = any(
        c.status == "breaking" for c in all_comparisons if c.version_type == "patch"
    )
    minor_changes = any(
        c.status != "stable" for c in all_comparisons if c.version_type == "minor"
    )

    if needs_review:
        recommendations = {
            "model_structure": "needs_review",
            "reasoning": "Breaking changes detected within patch versions. This is unexpected and requires investigation.",
        }
    elif minor_changes:
        recommendations = {
            "model_structure": "major_or_minor",
            "reasoning": "Changes detected within minor versions. Consider whether one model per major is sufficient, or if minor-level granularity is needed for recent versions.",
        }
    else:
        recommendations = {
            "model_structure": "major",
            "reasoning": "API is stable within major versions. One model per major version (v24.py, v25.py, v26.py) is sufficient.",
        }

    return {
        "report_generated": datetime.now(UTC).isoformat(),
        "canonical_version": CANONICAL_VERSION,
        "version_ranges_checked": version_ranges_checked,
        "comparisons": comparisons,
        "version_limitations": version_limitations,
        "recommendations": recommendations,
    }


def compare_versions(from_version: str, to_version: str) -> dict[str, Any]:
    """Compare two specific versions."""
    from_path = download_spec(from_version)
    to_path = download_spec(to_version)

    if not from_path or not to_path:
        logger.error("Could not download one or both specs")
        sys.exit(1)

    from_classes = parse_spec(from_path)
    to_classes = parse_spec(to_path)

    comp = compare_specs(from_classes, to_classes, from_version, to_version)

    return {
        "report_generated": datetime.now(UTC).isoformat(),
        "comparison": comparison_to_dict(comp),
    }


def verify_new_version(new_version: str) -> dict[str, Any]:
    """Verify a new version against canonical."""
    canonical_path = download_spec(CANONICAL_VERSION)
    new_path = download_spec(new_version)

    if not canonical_path or not new_path:
        logger.error("Could not download one or both specs")
        sys.exit(1)

    canonical_classes = parse_spec(canonical_path)
    new_classes = parse_spec(new_path)

    comp = compare_specs(canonical_classes, new_classes, CANONICAL_VERSION, new_version)

    return {
        "report_generated": datetime.now(UTC).isoformat(),
        "verification": {
            "new_version": new_version,
            "canonical_version": CANONICAL_VERSION,
            "comparison": comparison_to_dict(comp),
            "safe_to_add": comp.status != "breaking",
            "recommendation": "Safe to add support"
            if comp.status != "breaking"
            else "Breaking changes detected - investigate before adding support",
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Keycloak API Stability Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check-all",
        action="store_true",
        help="Check all supported version ranges",
    )
    group.add_argument(
        "--from",
        dest="from_version",
        help="Starting version for comparison",
    )
    group.add_argument(
        "--verify-new",
        dest="new_version",
        help="Verify a new version against canonical",
    )

    parser.add_argument(
        "--to",
        dest="to_version",
        help="Ending version for comparison (required with --from)",
    )

    args = parser.parse_args()

    if args.from_version and not args.to_version:
        parser.error("--to is required when using --from")

    if args.check_all:
        report = check_all()
    elif args.from_version:
        report = compare_versions(args.from_version, args.to_version)
    elif args.new_version:
        report = verify_new_version(args.new_version)
    else:
        parser.print_help()
        sys.exit(1)

    # Output YAML report
    print(
        yaml.dump(report, sort_keys=False, default_flow_style=False, allow_unicode=True)
    )


if __name__ == "__main__":
    main()
