"""
External schema management for documentation validation.

Downloads and caches external schemas from:
- Kubernetes JSON Schema project (for core K8s types)
- CNPG CRD (for CloudNativePG resources)
- cert-manager CRD (for Certificate resources)
"""

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

# Cache directory for downloaded schemas
CACHE_DIR = Path(__file__).parent / ".cache"

# Schema sources
K8S_SCHEMA_BASE = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/v1.29.0"
CNPG_CRD_URL = "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/config/crd/bases/postgresql.cnpg.io_clusters.yaml"
CERTMANAGER_CRD_URL = "https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.crds.yaml"


def _ensure_cache_dir() -> Path:
    """Ensure cache directory exists."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def _download_url(url: str, cache_name: str, force: bool = False) -> str | None:
    """Download URL content with caching."""
    cache_file = _ensure_cache_dir() / cache_name

    if cache_file.exists() and not force:
        return cache_file.read_text()

    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8")
            cache_file.write_text(content)
            return content
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"Warning: Failed to download {url}: {e}")
        # Try to use cached version if available
        if cache_file.exists():
            return cache_file.read_text()
        return None


def get_k8s_definitions() -> dict[str, Any]:
    """Get Kubernetes JSON Schema definitions."""
    content = _download_url(
        f"{K8S_SCHEMA_BASE}/_definitions.json",
        "k8s_definitions.json"
    )
    if content:
        return json.loads(content)
    return {}


def get_k8s_affinity_schema() -> dict[str, Any] | None:
    """Get schema for io.k8s.api.core.v1.Affinity."""
    defs = get_k8s_definitions()
    if not defs:
        return None

    # The definitions use a specific format
    affinity_def = defs.get("definitions", {}).get("io.k8s.api.core.v1.Affinity")
    if affinity_def:
        # Inline the $ref references for standalone validation
        return _resolve_refs(affinity_def, defs.get("definitions", {}))
    return None


def get_k8s_resources_schema() -> dict[str, Any] | None:
    """Get schema for io.k8s.api.core.v1.ResourceRequirements."""
    defs = get_k8s_definitions()
    if not defs:
        return None

    resources_def = defs.get("definitions", {}).get("io.k8s.api.core.v1.ResourceRequirements")
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
        # Tolerations is usually an array
        return {
            "type": "array",
            "items": _resolve_refs(toleration_def, defs.get("definitions", {}))
        }
    return None


def get_k8s_node_selector_schema() -> dict[str, Any] | None:
    """Get schema for nodeSelector (simple string map)."""
    return {
        "type": "object",
        "additionalProperties": {"type": "string"}
    }


def _resolve_refs(schema: dict[str, Any], definitions: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Resolve $ref references in a schema (limited depth to avoid cycles)."""
    if depth > 5:
        return schema

    if not isinstance(schema, dict):
        return schema

    result = {}
    for key, value in schema.items():
        if key == "$ref" and isinstance(value, str):
            # Extract definition name from #/definitions/...
            ref_name = value.split("/")[-1]
            if ref_name in definitions:
                # Merge the referenced definition
                resolved = _resolve_refs(definitions[ref_name], definitions, depth + 1)
                result.update(resolved)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = _resolve_refs(value, definitions, depth + 1)
        elif isinstance(value, list):
            result[key] = [
                _resolve_refs(item, definitions, depth + 1) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def get_cnpg_cluster_schema() -> dict[str, Any] | None:
    """Get CNPG Cluster CRD schema."""
    content = _download_url(CNPG_CRD_URL, "cnpg_cluster_crd.yaml")
    if not content:
        return None

    try:
        crd = yaml.safe_load(content)
        # Extract the spec schema from the CRD
        versions = crd.get("spec", {}).get("versions", [])
        for version in versions:
            if version.get("served") and version.get("storage"):
                schema = version.get("schema", {}).get("openAPIV3Schema", {})
                return schema.get("properties", {}).get("spec", {})
        return None
    except yaml.YAMLError:
        return None


def get_certmanager_certificate_schema() -> dict[str, Any] | None:
    """Get cert-manager Certificate CRD schema."""
    content = _download_url(CERTMANAGER_CRD_URL, "certmanager_crds.yaml")
    if not content:
        return None

    try:
        # cert-manager CRDs are in a multi-document YAML
        for doc in yaml.safe_load_all(content):
            if not doc:
                continue
            if doc.get("kind") == "CustomResourceDefinition":
                name = doc.get("metadata", {}).get("name", "")
                if name == "certificates.cert-manager.io":
                    versions = doc.get("spec", {}).get("versions", [])
                    for version in versions:
                        if version.get("served") and version.get("storage"):
                            schema = version.get("schema", {}).get("openAPIV3Schema", {})
                            return schema.get("properties", {}).get("spec", {})
        return None
    except yaml.YAMLError:
        return None


# Pre-defined partial schema extractors
PARTIAL_SCHEMAS: dict[str, Any] = {}


def get_partial_schema(partial_type: str) -> dict[str, Any] | None:
    """Get schema for a partial snippet type."""
    schema_getters = {
        "affinity": get_k8s_affinity_schema,
        "resources": get_k8s_resources_schema,
        "tolerations": get_k8s_tolerations_schema,
        "nodeSelector": get_k8s_node_selector_schema,
    }

    if partial_type in schema_getters:
        return schema_getters[partial_type]()

    return None


def clear_cache() -> None:
    """Clear the schema cache."""
    import shutil
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
