#!/usr/bin/env python3
"""
CRD to Pydantic schema validator.

Validates that CRD openAPIV3Schema matches Pydantic model JSON schemas.
Ensures the Kubernetes API (CRD) stays in sync with the Python models.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Add parent directory to path for imports when running as script
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.models.keycloak import KeycloakSpec
from keycloak_operator.models.realm import KeycloakRealmSpec


@dataclass
class SchemaMismatch:
    """A single schema mismatch between CRD and Pydantic."""

    kind: str
    path: str
    location: str  # "pydantic" or "crd"
    message: str


@dataclass
class ValidationResult:
    """Result of CRD-Pydantic validation."""

    total_compared: int
    total_matched: int
    total_mismatched: int
    mismatches: list[SchemaMismatch]


def to_camel_case(name: str) -> str:
    """Convert snake_case to camelCase."""
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def get_all_property_paths(
    schema: dict[str, Any],
    prefix: str = "",
    defs: dict[str, Any] | None = None,
    normalize_to_camel: bool = False,
) -> set[str]:
    """
    Recursively extract all property paths from a JSON schema.

    Args:
        schema: JSON schema dict
        prefix: Current path prefix
        defs: Schema $defs for resolving references
        normalize_to_camel: Convert snake_case to camelCase

    Returns:
        Set of dotted property paths
    """
    if defs is None:
        defs = schema.get("$defs", {})

    paths: set[str] = set()
    props = schema.get("properties", {})

    for name, prop in props.items():
        normalized_name = to_camel_case(name) if normalize_to_camel else name
        full_path = f"{prefix}.{normalized_name}" if prefix else normalized_name
        paths.add(full_path)

        # Handle $ref
        if "$ref" in prop:
            ref_name = prop["$ref"].split("/")[-1]
            if ref_name in defs:
                paths.update(
                    get_all_property_paths(
                        defs[ref_name], full_path, defs, normalize_to_camel
                    )
                )

        # Handle anyOf (for Optional types)
        if "anyOf" in prop:
            for option in prop["anyOf"]:
                if "$ref" in option:
                    ref_name = option["$ref"].split("/")[-1]
                    if ref_name in defs:
                        paths.update(
                            get_all_property_paths(
                                defs[ref_name], full_path, defs, normalize_to_camel
                            )
                        )
                elif "properties" in option:
                    paths.update(
                        get_all_property_paths(
                            option, full_path, defs, normalize_to_camel
                        )
                    )

        # Handle nested object
        if prop.get("type") == "object" and "properties" in prop:
            paths.update(
                get_all_property_paths(prop, full_path, defs, normalize_to_camel)
            )

    return paths


class CrdPydanticValidator:
    """Validates CRD schemas against Pydantic models."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.crds_path = project_root / "charts" / "keycloak-operator" / "crds"

        # Map of CRD kind to (Pydantic model class, CRD filename)
        self.models = {
            "Keycloak": (KeycloakSpec, "keycloak-crd.yaml"),
            "KeycloakRealm": (KeycloakRealmSpec, "keycloakrealm-crd.yaml"),
            "KeycloakClient": (KeycloakClientSpec, "keycloakclient-crd.yaml"),
        }

    def _load_crd_spec_schema(self, crd_file: str) -> dict[str, Any] | None:
        """Load the spec schema from a CRD file."""
        crd_path = self.crds_path / crd_file
        if not crd_path.exists():
            return None

        with open(crd_path) as f:
            crd = yaml.safe_load(f)

        versions = crd.get("spec", {}).get("versions", [])
        for version in versions:
            if version.get("served", False):
                return (
                    version.get("schema", {})
                    .get("openAPIV3Schema", {})
                    .get("properties", {})
                    .get("spec", {})
                )

        return None

    def compare_schemas(self, kind: str) -> list[SchemaMismatch]:
        """Compare CRD and Pydantic schemas for a given kind."""
        if kind not in self.models:
            return [
                SchemaMismatch(
                    kind=kind,
                    path="",
                    location="config",
                    message=f"Unknown kind: {kind}",
                )
            ]

        model_class, crd_file = self.models[kind]
        mismatches: list[SchemaMismatch] = []

        # Get Pydantic schema
        pydantic_schema = model_class.model_json_schema()

        # Get CRD schema
        crd_schema = self._load_crd_spec_schema(crd_file)
        if crd_schema is None:
            return [
                SchemaMismatch(
                    kind=kind,
                    path="",
                    location="crd",
                    message=f"Could not load CRD schema from {crd_file}",
                )
            ]

        # Get property paths - normalize Pydantic snake_case to camelCase
        pydantic_paths = get_all_property_paths(
            pydantic_schema, normalize_to_camel=True
        )
        crd_paths = get_all_property_paths(crd_schema, normalize_to_camel=False)

        # Find mismatches
        in_pydantic_only = pydantic_paths - crd_paths
        in_crd_only = crd_paths - pydantic_paths

        for path in in_pydantic_only:
            mismatches.append(
                SchemaMismatch(
                    kind=kind,
                    path=path,
                    location="pydantic",
                    message="Field exists in Pydantic model but not in CRD",
                )
            )

        for path in in_crd_only:
            mismatches.append(
                SchemaMismatch(
                    kind=kind,
                    path=path,
                    location="crd",
                    message="Field exists in CRD but not in Pydantic model",
                )
            )

        return mismatches

    def validate_all(self) -> ValidationResult:
        """Validate all CRD-Pydantic pairs."""
        all_mismatches: list[SchemaMismatch] = []
        total_compared = 0
        total_matched = 0

        for kind in self.models:
            mismatches = self.compare_schemas(kind)
            all_mismatches.extend(mismatches)

            total_compared += 1
            if not mismatches:
                total_matched += 1

        return ValidationResult(
            total_compared=total_compared,
            total_matched=total_matched,
            total_mismatched=total_compared - total_matched,
            mismatches=all_mismatches,
        )


def print_validation_report(result: ValidationResult) -> None:
    """Print a human-readable validation report."""
    print("\n" + "=" * 70)
    print("CRD-PYDANTIC VALIDATION REPORT")
    print("=" * 70)

    print(f"\nCompared: {result.total_compared} CRD/Pydantic pairs")
    print(f"  ✅ Matched:    {result.total_matched}")
    print(f"  ❌ Mismatched: {result.total_mismatched}")

    if result.mismatches:
        print("\n" + "-" * 70)
        print("MISMATCHES")
        print("-" * 70)

        # Group by kind
        by_kind: dict[str, list[SchemaMismatch]] = {}
        for m in result.mismatches:
            by_kind.setdefault(m.kind, []).append(m)

        for kind, mismatches in sorted(by_kind.items()):
            print(f"\n{kind}:")

            in_pydantic = [m for m in mismatches if m.location == "pydantic"]
            in_crd = [m for m in mismatches if m.location == "crd"]

            if in_pydantic:
                print(f"  In Pydantic but not CRD ({len(in_pydantic)}):")
                for m in sorted(in_pydantic, key=lambda x: x.path)[:10]:
                    print(f"    - {m.path}")
                if len(in_pydantic) > 10:
                    print(f"    ... and {len(in_pydantic) - 10} more")

            if in_crd:
                print(f"  In CRD but not Pydantic ({len(in_crd)}):")
                for m in sorted(in_crd, key=lambda x: x.path)[:10]:
                    print(f"    - {m.path}")
                if len(in_crd) > 10:
                    print(f"    ... and {len(in_crd) - 10} more")

    print("\n" + "-" * 70)
    if result.total_mismatched == 0:
        print("✅ All CRD and Pydantic schemas match!")
    else:
        print(f"❌ {len(result.mismatches)} schema mismatch(es) found")


def export_to_json(result: ValidationResult) -> dict[str, Any]:
    """Export validation results to JSON format."""
    return {
        "summary": {
            "total_compared": result.total_compared,
            "total_matched": result.total_matched,
            "total_mismatched": result.total_mismatched,
        },
        "mismatches": [
            {
                "kind": m.kind,
                "path": m.path,
                "location": m.location,
                "message": m.message,
            }
            for m in result.mismatches
        ],
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate CRD schemas against Pydantic models"
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output as JSON instead of human-readable report",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit with non-zero code if any mismatches found",
    )

    args = parser.parse_args()

    # Find project root
    project_root = Path(__file__).parent.parent.parent

    # Validate
    validator = CrdPydanticValidator(project_root)
    result = validator.validate_all()

    # Output results
    if args.json:
        output = export_to_json(result)
        print(json.dumps(output, indent=2))
    else:
        print_validation_report(result)

    # Exit code
    if args.fail_on_error and result.total_mismatched > 0:
        sys.exit(1)
