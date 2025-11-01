#!/usr/bin/env python3
"""
Generate JSON schemas from Kubernetes CRDs for IDE autocomplete.

This script extracts OpenAPI v3 schemas from CRD YAML files and converts them
to standalone JSON Schema Draft 07 format for IDE integration.

Output structure:
    _schemas/
    ├── v1/
    │   ├── Keycloak.json
    │   ├── KeycloakRealm.json
    │   └── KeycloakClient.json
    └── latest/
        ├── Keycloak.json
        ├── KeycloakRealm.json
        └── KeycloakClient.json
"""

import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

import yaml


def log(message: str) -> None:
    """Print a log message to stdout."""
    print(f"[INFO] {message}")


def error(message: str) -> None:
    """Print an error message to stderr and exit."""
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)


def success(message: str) -> None:
    """Print a success message to stdout."""
    print(f"[SUCCESS] {message}")


def load_crd(crd_path: Path) -> dict:
    """Load a CRD YAML file."""
    try:
        with crd_path.open() as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                error(f"CRD file {crd_path} does not contain a valid YAML object")
            return data
    except Exception as e:
        error(f"Failed to load CRD from {crd_path}: {e}")
        # Unreachable, but needed for type checker since error() calls sys.exit()
        return {}


def extract_schemas(
    crd: dict, crd_path: Path, base_url: str
) -> list[tuple[str, str, dict]]:
    """
    Extract JSON schemas from a CRD.

    Returns:
        List of (version, kind, schema) tuples
    """
    kind = crd.get("spec", {}).get("names", {}).get("kind")
    if not kind:
        error(f"CRD {crd_path} missing spec.names.kind")

    versions = crd.get("spec", {}).get("versions", [])
    if not versions:
        error(f"CRD {crd_path} has no versions defined")

    schemas = []
    for version_spec in versions:
        version = version_spec.get("name")
        served = version_spec.get("served", False)

        if not served:
            log(f"Skipping non-served version {version} for {kind}")
            continue

        openapi_schema = version_spec.get("schema", {}).get("openAPIV3Schema")
        if not openapi_schema:
            error(f"CRD {crd_path} version {version} missing openAPIV3Schema")

        # Wrap OpenAPI schema with JSON Schema metadata
        json_schema = {
            "$schema": "https://json-schema.org/draft-07/schema#",
            "$id": f"{base_url}/{version}/{kind}.json",
            "title": kind,
            "description": openapi_schema.get(
                "description", f"Keycloak Operator {kind} resource"
            ),
            **openapi_schema,
        }

        schemas.append((version, kind, json_schema))
        log(f"Extracted schema for {kind} version {version}")

    return schemas


def write_schema(output_dir: Path, version: str, kind: str, schema: dict) -> Path:
    """Write a JSON schema to disk."""
    version_dir = output_dir / version
    version_dir.mkdir(parents=True, exist_ok=True)

    schema_path = version_dir / f"{kind}.json"
    with schema_path.open("w") as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return schema_path


def create_latest_symlinks(output_dir: Path, latest_version: str) -> None:
    """Create symlinks from latest/ to the current stable version."""
    latest_dir = output_dir / "latest"
    version_dir = output_dir / latest_version

    if not version_dir.exists():
        error(f"Version directory {version_dir} does not exist")

    # Remove existing latest directory
    if latest_dir.exists():
        shutil.rmtree(latest_dir)

    latest_dir.mkdir(parents=True, exist_ok=True)

    # Copy schemas (using copy instead of symlink for GitHub Pages compatibility)
    for schema_file in version_dir.glob("*.json"):
        target = latest_dir / schema_file.name
        shutil.copy2(schema_file, target)
        log(f"Copied {schema_file.name} to latest/")


def main() -> None:
    """Main entry point."""
    # Configuration
    project_root = Path(__file__).parent.parent
    crds_dir = project_root / "charts" / "keycloak-operator" / "crds"
    output_dir = project_root / "_schemas"
    base_url = "https://vriesdemichael.github.io/keycloak-operator/schemas"

    # Exclusions (not our CRDs)
    excluded_files = {"kopf-peering-crds.yaml"}

    log(f"Generating JSON schemas from CRDs in {crds_dir}")
    log(f"Output directory: {output_dir}")

    # Clean output directory
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Process all CRD files
    crd_files = sorted(crds_dir.glob("*.yaml"))
    if not crd_files:
        error(f"No CRD files found in {crds_dir}")

    all_schemas = []
    for crd_path in crd_files:
        if crd_path.name in excluded_files:
            log(f"Skipping excluded file: {crd_path.name}")
            continue

        log(f"Processing {crd_path.name}")
        crd = load_crd(crd_path)

        # Check if it's actually a CRD
        if crd.get("kind") != "CustomResourceDefinition":
            log(f"Skipping non-CRD file: {crd_path.name}")
            continue

        schemas = extract_schemas(crd, crd_path, base_url)
        all_schemas.extend(schemas)

        # Write schemas to disk
        for version, kind, schema in schemas:
            schema_path = write_schema(output_dir, version, kind, schema)
            success(f"Generated {schema_path.relative_to(project_root)}")

    if not all_schemas:
        error("No schemas were generated")

    # Determine latest stable version (assume all use the same version)
    versions = {version for version, _, _ in all_schemas}
    if len(versions) > 1:
        # Group kinds by version for a clearer error message
        version_kinds: dict[str, list[str]] = defaultdict(list)
        for v, k, _ in all_schemas:
            version_kinds[v].append(k)
        formatted = ", ".join(
            f"{v} ({', '.join(sorted(set(version_kinds[v])))})"
            for v in sorted(version_kinds)
        )
        error(
            f"Multiple versions detected across CRDs: {formatted}. Manual intervention needed."
        )

    latest_version = versions.pop()

    # Create latest/ directory
    create_latest_symlinks(output_dir, latest_version)

    success(f"Generated {len(all_schemas)} schema(s) for version {latest_version}")
    log(f"Published schemas will be available at: {base_url}/")


if __name__ == "__main__":
    main()
