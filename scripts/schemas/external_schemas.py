"""
External schema management for documentation validation.

Loads external schemas from local files in scripts/schemas/external/:
- Kubernetes JSON Schema definitions (for core K8s types)
- CNPG CRD (for CloudNativePG resources)
- cert-manager CRD (for Certificate resources)

These schemas are committed to the repo to avoid downloading during CI.
"""

import json
from pathlib import Path
from typing import Any

import yaml

# Directory containing external schemas
SCHEMAS_DIR = Path(__file__).parent / "external"


def _load_json_schema(filename: str) -> dict[str, Any]:
    """Load a JSON schema file."""
    path = SCHEMAS_DIR / filename
    if path.exists():
        return json.loads(path.read_text())
    return {}


def _load_yaml_file(filename: str) -> dict[str, Any] | list[Any] | None:
    """Load a YAML file."""
    path = SCHEMAS_DIR / filename
    if path.exists():
        return yaml.safe_load(path.read_text())
    return None


def get_k8s_definitions() -> dict[str, Any]:
    """Get Kubernetes JSON Schema definitions."""
    return _load_json_schema("k8s_definitions.json")


def get_k8s_affinity_schema() -> dict[str, Any] | None:
    """Get schema for io.k8s.api.core.v1.Affinity."""
    defs = get_k8s_definitions()
    if not defs:
        return None

    affinity_def = defs.get("definitions", {}).get("io.k8s.api.core.v1.Affinity")
    if affinity_def:
        return _resolve_refs(affinity_def, defs.get("definitions", {}))
    return None


def get_k8s_resources_schema() -> dict[str, Any] | None:
    """Get schema for io.k8s.api.core.v1.ResourceRequirements."""
    defs = get_k8s_definitions()
    if not defs:
        return None

    resources_def = defs.get("definitions", {}).get(
        "io.k8s.api.core.v1.ResourceRequirements"
    )
    if resources_def:
        return _resolve_refs(resources_def, defs.get("definitions", {}))
    return None


def get_k8s_tolerations_schema() -> dict[str, Any] | None:
    """Get schema for io.k8s.api.core.v1.Toleration (as array)."""
    defs = get_k8s_definitions()
    if not defs:
        return None

    toleration_def = defs.get("definitions", {}).get("io.k8s.api.core.v1.Toleration")
    if toleration_def:
        return {
            "type": "array",
            "items": _resolve_refs(toleration_def, defs.get("definitions", {})),
        }
    return None


def get_k8s_node_selector_schema() -> dict[str, Any] | None:
    """Get schema for nodeSelector (simple string map)."""
    return {"type": "object", "additionalProperties": {"type": "string"}}


def _resolve_refs(
    schema: dict[str, Any], definitions: dict[str, Any], depth: int = 0
) -> dict[str, Any]:
    """Resolve $ref references in a schema (limited depth to avoid cycles)."""
    if depth > 5:
        return schema

    if not isinstance(schema, dict):
        return schema

    result = {}
    for key, value in schema.items():
        if key == "$ref" and isinstance(value, str):
            ref_name = value.split("/")[-1]
            if ref_name in definitions:
                resolved = _resolve_refs(definitions[ref_name], definitions, depth + 1)
                result.update(resolved)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = _resolve_refs(value, definitions, depth + 1)
        elif isinstance(value, list):
            result[key] = [
                _resolve_refs(item, definitions, depth + 1)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def get_cnpg_cluster_schema() -> dict[str, Any] | None:
    """Get CNPG Cluster CRD schema."""
    content = _load_yaml_file("cnpg-cluster-crd.yaml")
    if not content or not isinstance(content, dict):
        return None

    # Extract spec schema from CRD
    try:
        spec = content.get("spec", {})
        if not isinstance(spec, dict):
            return None
        versions = spec.get("versions", [])
        for version in versions:
            schema = version.get("schema", {}).get("openAPIV3Schema", {})
            if schema:
                return schema.get("properties", {}).get("spec", {})
    except (AttributeError, TypeError):
        pass
    return None


def get_cert_manager_certificate_schema() -> dict[str, Any] | None:
    """Get cert-manager Certificate CRD schema."""
    content = _load_yaml_file("cert-manager_crds.yaml")
    if not content:
        return None

    # Multi-document YAML - need to find Certificate CRD
    path = SCHEMAS_DIR / "cert-manager_crds.yaml"
    if not path.exists():
        return None

    for doc in yaml.safe_load_all(path.read_text()):
        if not doc:
            continue
        kind = doc.get("kind")
        name = doc.get("metadata", {}).get("name", "")
        if kind == "CustomResourceDefinition" and "certificates" in name:
            versions = doc.get("spec", {}).get("versions", [])
            for version in versions:
                schema = version.get("schema", {}).get("openAPIV3Schema", {})
                if schema:
                    return schema.get("properties", {}).get("spec", {})
    return None
