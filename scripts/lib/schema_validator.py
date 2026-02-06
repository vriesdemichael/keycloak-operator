#!/usr/bin/env python3
"""
Schema validator for documentation references.

This module validates extracted references against their appropriate schemas:
1. Helm --set flags against values.schema.json
2. Helm values snippets against values.schema.json
3. CR instances against CRD schemas

Provides detailed error messages with "did you mean?" suggestions.
"""

import json
import sys
from dataclasses import dataclass
from difflib import get_close_matches
from pathlib import Path
from typing import Any

import yaml

# Add parent directory to path for imports when running as script
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.lib.doc_extractor import (
    ExtractedReference,
    ExtractionResult,
    ReferenceContext,
    extract_all_references,
)
from scripts.schemas.external_schemas import (
    get_cnpg_cluster_schema,
    get_k8s_affinity_schema,
    get_k8s_node_selector_schema,
    get_k8s_resources_schema,
    get_k8s_tolerations_schema,
)


@dataclass
class ValidationError:
    """A single validation error."""

    file: Path
    line: int
    context: str
    message: str
    suggestion: str | None = None
    key_path: str | None = None


@dataclass
class ValidationResult:
    """Result of validating all references."""

    total_validated: int
    total_passed: int
    total_failed: int
    total_skipped: int
    errors: list[ValidationError]
    skipped_reasons: dict[str, int]  # reason -> count
    unknown_snippets: list[ExtractedReference] | None = None  # Truly unrecognized


# Known skip reasons that are intentional (external tools, partial configs we can't validate)
KNOWN_SKIP_REASONS = {
    "partial:cnpg",
    "partial:annotation",
    "partial:prometheus",
    "partial:app-config",
    "partial:spec",
    "partial:idp-config",
    "partial:federation-mappers",
    "external:fluxcd",
    "external:prometheus",
    "external:cert-manager",
    "external:kyverno:no-schema",  # When Kyverno schema can't be loaded
    "external chart: ingress-nginx",
    "helm-values unknown chart",
}


class SchemaValidator:
    """Validates documentation references against schemas."""

    # External chart schema mappings (chart name -> schema file in scripts/schemas/external/)
    EXTERNAL_CHART_SCHEMAS: dict[str, str] = {
        "cert-manager": "cert-manager-values.schema.json",
        "cloudnative-pg": "cnpg-operator-values.schema.json",
        # ingress-nginx doesn't publish a values.schema.json
    }

    # External CRD schema mappings (kind -> schema file in scripts/schemas/external/)
    EXTERNAL_CRD_SCHEMAS: dict[str, str] = {
        "ClusterPolicy": "kyverno-clusterpolicy.schema.json",
    }

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.charts_path = project_root / "charts"
        self.crds_path = self.charts_path / "keycloak-operator" / "crds"
        self.external_schemas_path = project_root / "scripts" / "schemas" / "external"

        # Lazy-loaded caches
        self._values_schemas: dict[str, dict[str, Any]] = {}
        self._crd_schemas: dict[str, dict[str, Any]] = {}
        self._validatable_charts: set[str] | None = None
        self._crd_kind_to_file: dict[str, str] | None = None
        self._external_schemas: dict[str, dict[str, Any]] = {}

    def _discover_validatable_charts(self) -> set[str]:
        """Auto-discover charts that have values.schema.json."""
        if self._validatable_charts is not None:
            return self._validatable_charts

        charts: set[str] = set()
        if self.charts_path.exists():
            for chart_dir in self.charts_path.iterdir():
                if chart_dir.is_dir() and (chart_dir / "values.schema.json").exists():
                    charts.add(chart_dir.name)

        self._validatable_charts = charts
        return charts

    def _discover_crd_kinds(self) -> dict[str, str]:
        """Auto-discover CRD kinds and their file mappings."""
        if self._crd_kind_to_file is not None:
            return self._crd_kind_to_file

        kind_to_file: dict[str, str] = {}
        if self.crds_path.exists():
            for crd_file in self.crds_path.glob("*.yaml"):
                # Skip non-CRD files
                if "peering" in crd_file.name:
                    continue

                try:
                    with open(crd_file) as f:
                        crd = yaml.safe_load(f)
                        if crd and crd.get("kind") == "CustomResourceDefinition":
                            kind = crd.get("spec", {}).get("names", {}).get("kind")
                            if kind:
                                kind_to_file[kind] = crd_file.name
                except (yaml.YAMLError, OSError):
                    continue

        self._crd_kind_to_file = kind_to_file
        return kind_to_file

    def _load_values_schema(self, chart_name: str) -> dict[str, Any] | None:
        """Load values.schema.json for a chart (local or external)."""
        if chart_name in self._values_schemas:
            return self._values_schemas[chart_name]

        # Try local chart first
        schema_path = self.charts_path / chart_name / "values.schema.json"
        if schema_path.exists():
            with open(schema_path) as f:
                schema = json.load(f)
                self._values_schemas[chart_name] = schema
                return schema

        # Try external chart schema
        return self._load_external_chart_schema(chart_name)

    def _load_external_chart_schema(self, chart_name: str) -> dict[str, Any] | None:
        """Load external chart schema from scripts/schemas/external/."""
        if chart_name in self._external_schemas:
            return self._external_schemas[chart_name]

        if chart_name not in self.EXTERNAL_CHART_SCHEMAS:
            return None

        schema_file = (
            self.external_schemas_path / self.EXTERNAL_CHART_SCHEMAS[chart_name]
        )
        if not schema_file.exists():
            return None

        with open(schema_file) as f:
            schema = json.load(f)
            self._external_schemas[chart_name] = schema
            self._values_schemas[chart_name] = schema
            return schema

    def _has_chart_schema(self, chart_name: str) -> bool:
        """Check if a schema exists for the chart (local or external)."""
        # Check local charts
        if chart_name in self._discover_validatable_charts():
            return True
        # Check external charts
        return chart_name in self.EXTERNAL_CHART_SCHEMAS

    def _load_crd_schema(self, kind: str) -> dict[str, Any] | None:
        """Load CRD schema for a kind."""
        if kind in self._crd_schemas:
            return self._crd_schemas[kind]

        # Auto-discover CRD files
        crd_files = self._discover_crd_kinds()

        if kind not in crd_files:
            return None

        crd_path = self.crds_path / crd_files[kind]
        if not crd_path.exists():
            return None

        with open(crd_path) as f:
            crd = yaml.safe_load(f)

        # Extract the openAPIV3Schema from the CRD
        versions = crd.get("spec", {}).get("versions", [])
        for version in versions:
            if version.get("served", False):
                schema = version.get("schema", {}).get("openAPIV3Schema", {})
                self._crd_schemas[kind] = schema
                return schema

        return None

    def _load_external_crd_schema(self, kind: str) -> dict[str, Any] | None:
        """Load external CRD schema for a kind (e.g., Kyverno ClusterPolicy)."""
        if kind in self._crd_schemas:
            return self._crd_schemas[kind]

        if kind not in self.EXTERNAL_CRD_SCHEMAS:
            return None

        schema_file = self.external_schemas_path / self.EXTERNAL_CRD_SCHEMAS[kind]
        if not schema_file.exists():
            return None

        with open(schema_file) as f:
            schema = json.load(f)
            self._crd_schemas[kind] = schema
            return schema

    def get_crd_spec_fields(self, kind: str) -> set[str]:
        """
        Get top-level spec fields for a CRD kind.

        Useful for generating context detection indicators.
        """
        schema = self._load_crd_schema(kind)
        if not schema:
            return set()

        spec_schema = schema.get("properties", {}).get("spec", {})
        return set(spec_schema.get("properties", {}).keys())

    def get_values_root_keys(self, chart_name: str) -> set[str]:
        """
        Get top-level keys from a values schema.

        Useful for generating context detection indicators.
        """
        schema = self._load_values_schema(chart_name)
        if not schema:
            return set()

        return set(schema.get("properties", {}).keys())

    def _resolve_ref(
        self, ref: str, root_schema: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Resolve a $ref to its definition."""
        if not ref.startswith("#/"):
            return None

        # Parse path like "#/$defs/helm-values.crds"
        parts = ref[2:].split("/")  # Remove "#/" prefix
        current = root_schema
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current if isinstance(current, dict) else None

    def _get_schema_properties(
        self,
        schema: dict[str, Any],
        path: str = "",
        root_schema: dict[str, Any] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """
        Recursively extract all property paths from a JSON schema.

        Handles $ref resolution for schemas that use $defs.
        Returns dict mapping dotted paths to their schema definitions.
        """
        if root_schema is None:
            root_schema = schema

        properties: dict[str, dict[str, Any]] = {}

        # Handle schemas that wrap everything in $defs with a root definition
        # (common pattern: $defs/helm-values contains actual properties)
        if "$defs" in schema and "properties" not in schema:
            # Look for a root definition like "helm-values"
            defs = schema["$defs"]
            for def_name in ["helm-values", "values"]:
                if def_name in defs and isinstance(defs[def_name], dict):
                    return self._get_schema_properties(
                        defs[def_name], path, root_schema
                    )

        if "properties" in schema:
            for prop_name, prop_schema in schema["properties"].items():
                full_path = f"{path}.{prop_name}" if path else prop_name

                # Resolve $ref if present
                resolved = prop_schema
                if "$ref" in prop_schema:
                    resolved = self._resolve_ref(prop_schema["$ref"], root_schema)
                    if resolved is None:
                        resolved = prop_schema  # Keep original if can't resolve

                properties[full_path] = resolved

                # Recurse into nested objects
                if resolved.get("type") == "object" or "properties" in resolved:
                    nested = self._get_schema_properties(
                        resolved, full_path, root_schema
                    )
                    properties.update(nested)

        return properties

    def _validate_key_exists(
        self, key: str, schema: dict[str, Any], schema_name: str
    ) -> ValidationError | None:
        """
        Validate that a key path exists in a schema.

        Returns ValidationError if invalid, None if valid.
        """
        properties = self._get_schema_properties(schema)
        valid_keys = set(properties.keys())

        # Check if the key exists directly
        if key in valid_keys:
            return None

        # Check if it's a prefix of a valid key (partial path is OK)
        for valid_key in valid_keys:
            if valid_key.startswith(key + "."):
                return None

        # Key not found - suggest alternatives
        suggestion = self._suggest_correction(key, valid_keys)

        return ValidationError(
            file=Path(""),  # Will be filled in by caller
            line=0,
            context="helm-set",
            message=f"Unknown key '{key}' in {schema_name}",
            suggestion=suggestion,
            key_path=key,
        )

    def _suggest_correction(self, invalid_key: str, valid_keys: set[str]) -> str | None:
        """Suggest the closest valid key using edit distance."""
        # Try exact suffix match first
        key_parts = invalid_key.split(".")
        for valid_key in valid_keys:
            valid_parts = valid_key.split(".")
            if len(valid_parts) >= len(key_parts) and valid_parts[
                -len(key_parts) :
            ] == key_parts[:-1] + [
                get_close_matches(key_parts[-1], [valid_parts[-1]], n=1, cutoff=0.6)
            ]:
                return valid_key

        # Try fuzzy match on the full key
        matches = get_close_matches(invalid_key, list(valid_keys), n=1, cutoff=0.6)
        if matches:
            return matches[0]

        # Try matching just the last part
        last_part = key_parts[-1]
        last_parts = [k.split(".")[-1] for k in valid_keys]
        matches = get_close_matches(last_part, last_parts, n=1, cutoff=0.6)
        if matches:
            # Find the full key that ends with this match
            for valid_key in valid_keys:
                if valid_key.endswith("." + matches[0]) or valid_key == matches[0]:
                    return valid_key

        return None

    def _validate_helm_set(self, ref: ExtractedReference) -> ValidationError | None:
        """Validate a --set flag against the appropriate chart schema."""
        chart_name = ref.metadata.get("chart_name", "unknown")

        # Skip charts we don't have schemas for
        if not self._has_chart_schema(chart_name):
            return None  # Skip, not an error

        schema = self._load_values_schema(chart_name)
        if schema is None:
            return ValidationError(
                file=ref.file,
                line=ref.line,
                context="helm-set",
                message=f"Could not load schema for chart '{chart_name}'",
                key_path=str(ref.content),
            )

        key = str(ref.content)
        error = self._validate_key_exists(
            key, schema, f"{chart_name}/values.schema.json"
        )

        if error:
            error.file = ref.file
            error.line = ref.line

        return error

    def _validate_helm_values(self, ref: ExtractedReference) -> list[ValidationError]:
        """Validate a Helm values block against the chart schema."""
        errors: list[ValidationError] = []

        chart_name = ref.metadata.get("chart_name", "unknown")

        # Try to infer chart from content if unknown
        if chart_name == "unknown":
            content = ref.content if isinstance(ref.content, dict) else {}
            # keycloak-operator has these top-level keys
            operator_keys = {
                "operator",
                "keycloak",
                "monitoring",
                "webhooks",
                "ingress",
                "extraManifests",
                "jvm",
                "resources",
            }
            if content.keys() & operator_keys:
                chart_name = "keycloak-operator"
            # keycloak-client values have 'clientId' at top level
            elif "clientId" in content:
                chart_name = "keycloak-client"
            # keycloak-realm values have 'realmName' at top level
            elif "realmName" in content:
                chart_name = "keycloak-realm"

        if chart_name == "unknown":
            return errors  # Can't determine chart, skip

        # Check if we have a schema for this chart
        validatable_charts = self._discover_validatable_charts()
        if chart_name not in validatable_charts:
            return errors  # External chart, skip

        schema = self._load_values_schema(chart_name)
        if schema is None:
            return errors

        content = ref.content
        if not isinstance(content, dict):
            return errors

        # Validate each top-level key
        for key, value in content.items():
            error = self._validate_key_exists(key, schema, chart_name)
            if error:
                error.file = ref.file
                error.line = ref.line
                error.context = "helm-values"
                errors.append(error)
            elif isinstance(value, dict):
                # Validate nested structure
                prop_schema = self._get_property_schema(schema, key)
                if prop_schema:
                    nested_errors = self._validate_object_against_schema(
                        value, prop_schema, key, ref
                    )
                    for e in nested_errors:
                        e.context = "helm-values"
                    errors.extend(nested_errors)

        return errors

    def _validate_cr_instance(
        self, ref: ExtractedReference, kind: str
    ) -> list[ValidationError]:
        """Validate a CR instance against its CRD schema."""
        errors: list[ValidationError] = []

        schema = self._load_crd_schema(kind)
        if schema is None:
            errors.append(
                ValidationError(
                    file=ref.file,
                    line=ref.line,
                    context=ref.context.value,
                    message=f"Could not load CRD schema for kind '{kind}'",
                )
            )
            return errors

        content = ref.content
        if not isinstance(content, dict):
            return errors

        # Get the spec schema
        spec_schema = schema.get("properties", {}).get("spec", {})
        if not spec_schema:
            return errors

        # If the content has a 'spec' key, validate its contents
        if "spec" in content:
            spec_content = content["spec"]
            if isinstance(spec_content, dict):
                spec_errors = self._validate_object_against_schema(
                    spec_content, spec_schema, "spec", ref
                )
                errors.extend(spec_errors)
        elif ref.parent_path:
            # This is a partial snippet - validate against the appropriate sub-schema
            # For now, we'll skip deep validation of partial snippets
            pass

        return errors

    def _validate_object_against_schema(
        self,
        obj: dict[str, Any],
        schema: dict[str, Any],
        path: str,
        ref: ExtractedReference,
    ) -> list[ValidationError]:
        """Validate an object against a JSON schema."""
        errors: list[ValidationError] = []

        schema_properties = schema.get("properties", {})
        valid_keys = set(schema_properties.keys())

        # Check if additional properties are allowed
        # additionalProperties can be:
        # - True or missing: any additional keys allowed
        # - False: no additional keys allowed
        # - object: additional keys must match this schema
        additional_properties = schema.get("additionalProperties", True)
        allows_additional = additional_properties is not False

        for key in obj:
            full_path = f"{path}.{key}"

            if key not in valid_keys:
                # If additionalProperties is allowed, skip this key
                if allows_additional:
                    continue

                suggestion = self._suggest_correction(key, valid_keys)
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context=ref.context.value,
                        message=f"Unknown property '{key}' in {path}",
                        suggestion=f"Did you mean '{suggestion}'?"
                        if suggestion
                        else None,
                        key_path=full_path,
                    )
                )
            else:
                # Recursively validate nested objects
                prop_schema = schema_properties[key]
                if prop_schema.get("type") == "object" and isinstance(obj[key], dict):
                    nested_errors = self._validate_object_against_schema(
                        obj[key], prop_schema, full_path, ref
                    )
                    errors.extend(nested_errors)

        return errors

    def _validate_argocd_helm_values(
        self, ref: ExtractedReference
    ) -> list[ValidationError]:
        """
        Validate ArgoCD Application resources that contain Helm values.

        Extracts the helm values from the ArgoCD Application spec and validates
        against the appropriate chart schema.
        """
        errors: list[ValidationError] = []

        if not isinstance(ref.content, dict):
            return errors

        # Navigate to spec.source.helm.values or spec.source.helm.valuesObject
        spec = ref.content.get("spec", {})
        source = spec.get("source", {})
        helm = source.get("helm", {})

        # Get the chart path to determine which chart this is for
        chart_path = source.get("path", "")
        # repoURL not currently used for validation

        # Determine chart name from path
        chart_name = None
        if "keycloak-operator" in chart_path:
            chart_name = "keycloak-operator"
        elif "keycloak-realm" in chart_path:
            chart_name = "keycloak-realm"
        elif "keycloak-client" in chart_path:
            chart_name = "keycloak-client"

        if not chart_name:
            # Can't determine chart, skip validation
            return errors

        # Get values - can be string (YAML) or object
        values_str = helm.get("values", "")
        values_obj = helm.get("valuesObject", {})

        values_to_validate = None
        if values_obj:
            values_to_validate = values_obj
        elif values_str:
            try:
                values_to_validate = yaml.safe_load(values_str)
            except yaml.YAMLError:
                return errors  # Can't parse, skip

        if not values_to_validate or not isinstance(values_to_validate, dict):
            return errors

        # Load schema and validate
        schema = self._load_values_schema(chart_name)
        if schema is None:
            return errors

        # Validate each top-level key
        for key, value in values_to_validate.items():
            error = self._validate_key_exists(key, schema, chart_name)
            if error:
                error.file = ref.file
                error.line = ref.line
                error.context = "argocd-helm-values"
                errors.append(error)
            elif isinstance(value, dict):
                # Validate nested structure
                prop_schema = self._get_property_schema(schema, key)
                if prop_schema:
                    nested_errors = self._validate_object_against_schema(
                        value, prop_schema, key, ref
                    )
                    for e in nested_errors:
                        e.context = "argocd-helm-values"
                    errors.extend(nested_errors)

        return errors

    def _validate_rbac_resource(self, ref: ExtractedReference) -> list[ValidationError]:
        """
        Validate RBAC resources (Role, ClusterRole, RoleBinding, ClusterRoleBinding).

        Performs basic structural validation without needing the full K8s schema.
        """
        errors: list[ValidationError] = []

        if not isinstance(ref.content, dict):
            return errors

        kind = ref.content.get("kind", "")
        if kind not in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            return errors

        # Validate Role/ClusterRole rules
        if kind in ("Role", "ClusterRole"):
            rules = ref.content.get("rules", [])
            if not isinstance(rules, list):
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="rbac",
                        message=f"{kind}.rules must be an array",
                    )
                )
            else:
                for i, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        continue
                    # Check required fields
                    if "verbs" not in rule:
                        errors.append(
                            ValidationError(
                                file=ref.file,
                                line=ref.line,
                                context="rbac",
                                message=f"{kind}.rules[{i}] missing required 'verbs'",
                            )
                        )
                    # Check for valid verb values
                    verbs = rule.get("verbs", [])
                    valid_verbs = {
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                        "deletecollection",
                        "*",
                    }
                    for verb in verbs:
                        if verb not in valid_verbs:
                            errors.append(
                                ValidationError(
                                    file=ref.file,
                                    line=ref.line,
                                    context="rbac",
                                    message=f"Unknown verb '{verb}' in {kind}.rules[{i}]",
                                    suggestion=f"Valid verbs: {', '.join(sorted(valid_verbs))}",
                                )
                            )

        # Validate RoleBinding/ClusterRoleBinding
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            # Check roleRef
            role_ref = ref.content.get("roleRef", {})
            if not role_ref:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="rbac",
                        message=f"{kind} missing required 'roleRef'",
                    )
                )
            else:
                for field in ("apiGroup", "kind", "name"):
                    if field not in role_ref:
                        errors.append(
                            ValidationError(
                                file=ref.file,
                                line=ref.line,
                                context="rbac",
                                message=f"{kind}.roleRef missing required '{field}'",
                            )
                        )
            # Check subjects
            subjects = ref.content.get("subjects", [])
            if not subjects:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="rbac",
                        message=f"{kind} missing required 'subjects'",
                    )
                )

        return errors

    def _validate_env_array(self, ref: ExtractedReference) -> list[ValidationError]:
        """
        Validate partial env: array snippets.

        Checks that each env item has the required structure (name + value/valueFrom).
        """
        errors: list[ValidationError] = []

        # Handle both raw string and parsed content
        content = ref.content
        if isinstance(content, str):
            try:
                content = yaml.safe_load(content)
            except yaml.YAMLError:
                return errors

        if not isinstance(content, dict):
            return errors

        env_list = content.get("env", [])
        if not isinstance(env_list, list):
            return errors

        for i, env_item in enumerate(env_list):
            if not isinstance(env_item, dict):
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="env-var",
                        message=f"env[{i}] must be an object",
                    )
                )
                continue

            # Must have name
            if "name" not in env_item:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="env-var",
                        message=f"env[{i}] missing required 'name'",
                    )
                )

            # Must have value or valueFrom
            if "value" not in env_item and "valueFrom" not in env_item:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="env-var",
                        message=f"env[{i}] (name={env_item.get('name', '?')}) must have 'value' or 'valueFrom'",
                    )
                )

            # If valueFrom, check structure
            value_from = env_item.get("valueFrom", {})
            if value_from:
                valid_sources = {
                    "secretKeyRef",
                    "configMapKeyRef",
                    "fieldRef",
                    "resourceFieldRef",
                }
                sources_found = [k for k in value_from if k in valid_sources]
                if not sources_found:
                    errors.append(
                        ValidationError(
                            file=ref.file,
                            line=ref.line,
                            context="env-var",
                            message=f"env[{i}].valueFrom must have one of: {', '.join(sorted(valid_sources))}",
                        )
                    )

        return errors

    def _get_property_schema(
        self, schema: dict[str, Any], key: str
    ) -> dict[str, Any] | None:
        """Get the schema for a specific property."""
        properties = self._get_schema_properties(schema)
        return properties.get(key)

    def _validate_status_snippet(
        self, ref: ExtractedReference
    ) -> list[ValidationError]:
        """
        Validate status snippets against CRD status schemas.

        Tries to match against Keycloak, KeycloakRealm, or KeycloakClient status.
        """
        errors: list[ValidationError] = []

        content = ref.content
        if isinstance(content, str):
            try:
                content = yaml.safe_load(content)
            except yaml.YAMLError:
                return errors

        if not isinstance(content, dict):
            return errors

        # Get the status object
        status_content = content.get("status", content)
        if not isinstance(status_content, dict):
            return errors

        # Try to determine which CRD this status belongs to based on fields
        # Keycloak: has deployment, service, adminSecret, databaseStatus
        # KeycloakRealm: has realmName, internalId (for realm)
        # KeycloakClient: has clientId, internalId, realm, credentialsSecret

        crd_kind = None
        if "clientId" in status_content or "credentialsSecret" in status_content:
            crd_kind = "KeycloakClient"
        elif "realmName" in status_content and "clientId" not in status_content:
            crd_kind = "KeycloakRealm"
        elif (
            "deployment" in status_content
            or "adminSecret" in status_content
            or "databaseStatus" in status_content
        ):
            crd_kind = "Keycloak"
        else:
            # Check for common status fields that could match any CRD
            # Default to Keycloak if we can't determine
            if "phase" in status_content:
                # Could be any - try Keycloak first as it's most common
                crd_kind = "Keycloak"

        if not crd_kind:
            return errors  # Can't determine, skip

        # Load CRD schema
        schema = self._load_crd_schema(crd_kind)
        if schema is None:
            return errors

        # Get the status schema
        status_schema = schema.get("properties", {}).get("status", {})
        if not status_schema:
            return errors

        # Validate status fields
        status_errors = self._validate_object_against_schema(
            status_content, status_schema, "status", ref
        )
        for e in status_errors:
            e.context = f"status:{crd_kind}"
        errors.extend(status_errors)

        return errors

    def _categorize_k8s_other(self, ref: ExtractedReference) -> str:
        """Categorize a k8s-other reference for appropriate validation."""
        raw = ref.raw if isinstance(ref.raw, str) else str(ref.raw)
        content = ref.content if isinstance(ref.content, dict) else {}

        # Check for ArgoCD
        if "argoproj.io" in raw:
            return "argocd"

        # Check for RBAC
        kind = content.get("kind", "")
        if kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            return "rbac"
        if "rbac.authorization.k8s.io" in raw:
            return "rbac"

        # Check for env snippet (may have comments before env:)
        # Strip comments and check for env:
        raw_no_comments = "\n".join(
            line for line in raw.split("\n") if not line.strip().startswith("#")
        )
        if raw_no_comments.strip().startswith("env:"):
            return "env"
        # Also check if content has env key
        if isinstance(content, dict) and "env" in content:
            return "env"

        # Check for status snippets (informational, skip validation)
        if raw.strip().startswith("status:"):
            return "status"
        if (
            isinstance(content, dict)
            and "status" in content
            and "phase" in content.get("status", {})
        ):
            return "status"

        # Check for CNPG
        api_version = content.get("apiVersion", "")
        if "cnpg.io" in api_version or "postgresql.cnpg.io" in api_version:
            return "cnpg"

        # Check for known K8s core resources
        k8s_core_kinds = {
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "Service",
            "ConfigMap",
            "Secret",
            "Namespace",
            "PersistentVolumeClaim",
            "PersistentVolume",
            "StorageClass",
            "NetworkPolicy",
            "PodDisruptionBudget",
            "Ingress",
            "IngressClass",
            "ServiceAccount",
            "LimitRange",
            "ResourceQuota",
            "HorizontalPodAutoscaler",
        }
        if kind in k8s_core_kinds:
            return "k8s-core"

        # Check for external operators/tools
        external_apis = {
            "kyverno.io": "kyverno",
            "kustomize.toolkit.fluxcd.io": "fluxcd",
            "monitoring.coreos.com": "prometheus",
            "cert-manager.io": "cert-manager",
        }
        for api_prefix, name in external_apis.items():
            if api_prefix in api_version:
                return f"external:{name}"

        # Partial snippets (no apiVersion/kind) - categorize by content
        if not api_version and not kind:
            # Check for CNPG-specific affinity keys (must check before generic affinity)
            cnpg_affinity_keys = {
                "podAntiAffinityType",
                "enablePodAntiAffinity",
                "additionalPodAffinity",
                "additionalPodAntiAffinity",
            }
            if "affinity" in content or raw.strip().startswith("affinity:"):
                # Check if it has CNPG-specific keys
                affinity_content = content.get("affinity", content)
                if (
                    isinstance(affinity_content, dict)
                    and affinity_content.keys() & cnpg_affinity_keys
                ):
                    return "partial:cnpg"

            # Check for common partial config patterns
            partial_patterns = {
                "affinity": "partial:affinity",
                "tolerations": "partial:tolerations",
                "nodeSelector": "partial:nodeSelector",
                "resources": "partial:resources",
                "bootstrap": "partial:cnpg",
                "backup": "partial:cnpg",
                "postgresql": "partial:cnpg",
                "retentionPolicy": "partial:cnpg",
                "certificates": "partial:cnpg",  # CNPG TLS config
                "groups": "partial:prometheus",
                "spring": "partial:app-config",  # Spring Boot config
                "config": "partial:idp-config",  # Identity provider config fragments
                "mappers": "partial:federation-mappers",  # User federation mappers
            }
            for key in partial_patterns:
                if key in content or raw.strip().startswith(f"{key}:"):
                    return partial_patterns[key]

            # Check for spec: without apiVersion (partial CNPG or other)
            if raw.strip().startswith("spec:"):
                # Likely a partial resource spec
                if "certificates" in raw or "tls" in raw.lower():
                    return "partial:cnpg"
                return "partial:spec"

            # Single annotation/label
            if "vriesdemichael.github.io" in raw:
                return "partial:annotation"

        return "other"

    def _validate_k8s_core_resource(
        self, ref: ExtractedReference
    ) -> list[ValidationError]:
        """
        Validate basic structure of core K8s resources.

        Performs structural validation without the full K8s schema.
        """
        errors: list[ValidationError] = []

        if not isinstance(ref.content, dict):
            return errors

        kind = ref.content.get("kind", "")
        api_version = ref.content.get("apiVersion", "")

        # All K8s resources need apiVersion and kind
        if not api_version:
            errors.append(
                ValidationError(
                    file=ref.file,
                    line=ref.line,
                    context="k8s-core",
                    message=f"{kind} missing required 'apiVersion'",
                )
            )

        # Most need metadata.name
        metadata = ref.content.get("metadata", {})
        if not metadata.get("name") and kind not in ("Namespace",):
            # Some examples might omit metadata, that's ok for docs
            pass

        # Kind-specific validation
        if kind == "Service":
            spec = ref.content.get("spec", {})
            if not spec.get("ports") and spec.get("clusterIP") != "None":
                # Headless services don't need ports
                pass
            if spec.get("type") not in (
                None,
                "ClusterIP",
                "NodePort",
                "LoadBalancer",
                "ExternalName",
            ):
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="k8s-core",
                        message=f"Invalid Service type: {spec.get('type')}",
                    )
                )

        elif kind == "NetworkPolicy":
            spec = ref.content.get("spec", {})
            if "podSelector" not in spec:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="k8s-core",
                        message="NetworkPolicy missing required 'spec.podSelector'",
                    )
                )

        elif kind == "PodDisruptionBudget":
            spec = ref.content.get("spec", {})
            if "selector" not in spec:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="k8s-core",
                        message="PodDisruptionBudget missing required 'spec.selector'",
                    )
                )
            if "minAvailable" not in spec and "maxUnavailable" not in spec:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="k8s-core",
                        message="PodDisruptionBudget needs 'minAvailable' or 'maxUnavailable'",
                    )
                )

        elif kind == "StorageClass":
            if "provisioner" not in ref.content:
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context="k8s-core",
                        message="StorageClass missing required 'provisioner'",
                    )
                )

        return errors

    def _validate_partial_k8s(
        self, ref: ExtractedReference, partial_type: str
    ) -> list[ValidationError]:
        """
        Validate partial K8s snippets (affinity, resources, tolerations, nodeSelector)
        against official K8s JSON schemas.
        """
        errors: list[ValidationError] = []

        if not isinstance(ref.content, dict):
            return errors

        # Get the appropriate schema
        schema_getters = {
            "affinity": get_k8s_affinity_schema,
            "resources": get_k8s_resources_schema,
            "tolerations": get_k8s_tolerations_schema,
            "nodeSelector": get_k8s_node_selector_schema,
        }

        if partial_type not in schema_getters:
            return errors

        schema = schema_getters[partial_type]()
        if not schema:
            # Schema unavailable, skip validation
            return errors

        # The content may have the key as top-level, or be the value directly
        content_to_validate = ref.content
        if partial_type in ref.content:
            content_to_validate = ref.content[partial_type]

        # Validate structure against schema
        validation_errors = self._validate_against_schema(
            content_to_validate, schema, partial_type, ref
        )
        errors.extend(validation_errors)

        return errors

    def _validate_against_schema(
        self,
        content: Any,
        schema: dict[str, Any],
        path: str,
        ref: ExtractedReference,
    ) -> list[ValidationError]:
        """Validate content against a JSON schema structure."""
        errors: list[ValidationError] = []

        if schema.get("type") == "object":
            if not isinstance(content, dict):
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context=f"partial:{path}",
                        message=f"Expected object at '{path}', got {type(content).__name__}",
                    )
                )
                return errors

            # Check for unknown keys
            allowed_props = set(schema.get("properties", {}).keys())
            if allowed_props and not schema.get("additionalProperties", True):
                for key in content:
                    if key not in allowed_props:
                        suggestion = self._suggest_correction(key, allowed_props)
                        errors.append(
                            ValidationError(
                                file=ref.file,
                                line=ref.line,
                                context=f"partial:{path}",
                                message=f"Unknown key '{key}' at '{path}'",
                                suggestion=suggestion,
                            )
                        )

            # Recursively validate known properties
            for prop, prop_schema in schema.get("properties", {}).items():
                if prop in content:
                    prop_errors = self._validate_against_schema(
                        content[prop], prop_schema, f"{path}.{prop}", ref
                    )
                    errors.extend(prop_errors)

        elif schema.get("type") == "array":
            if not isinstance(content, list):
                errors.append(
                    ValidationError(
                        file=ref.file,
                        line=ref.line,
                        context=f"partial:{path}",
                        message=f"Expected array at '{path}', got {type(content).__name__}",
                    )
                )
                return errors

            # Validate array items
            items_schema = schema.get("items", {})
            for i, item in enumerate(content):
                item_errors = self._validate_against_schema(
                    item, items_schema, f"{path}[{i}]", ref
                )
                errors.extend(item_errors)

        return errors

    def _validate_cnpg_cluster(self, ref: ExtractedReference) -> list[ValidationError]:
        """Validate CNPG Cluster resources against the official CRD schema."""
        errors: list[ValidationError] = []

        if not isinstance(ref.content, dict):
            return errors

        # Only validate Cluster resources - other CNPG types have different schemas
        kind = ref.content.get("kind", "")
        if kind and kind != "Cluster":
            # ScheduledBackup, Backup, etc. have different schemas - skip for now
            return errors

        schema = get_cnpg_cluster_schema()
        if not schema:
            # Schema unavailable, skip
            return errors

        # Get the spec portion
        spec = ref.content.get("spec", ref.content)

        # Validate top-level spec keys
        allowed_props = set(schema.get("properties", {}).keys())
        if allowed_props:
            for key in spec:
                if key not in allowed_props:
                    suggestion = self._suggest_correction(key, allowed_props)
                    errors.append(
                        ValidationError(
                            file=ref.file,
                            line=ref.line,
                            context="cnpg",
                            message=f"Unknown CNPG Cluster spec key '{key}'",
                            suggestion=suggestion,
                        )
                    )

        return errors

    def _validate_external_crd(
        self, ref: ExtractedReference, kind: str
    ) -> list[ValidationError] | None:
        """Validate external CRD resources (e.g., Kyverno ClusterPolicy).

        Returns:
            List of validation errors if validation was performed.
            None if validation cannot be performed (should be skipped).
        """
        if not isinstance(ref.content, dict):
            return None

        schema = self._load_external_crd_schema(kind)
        if not schema:
            # Schema unavailable - return None to indicate skip
            # The caller should handle this by recording a skip
            return None

        # Validate the spec portion against the schema using full JSON Schema validation
        spec_schema = schema.get("properties", {}).get("spec", {})
        spec_content = ref.content.get("spec", {})

        if not spec_schema or not spec_content:
            # No spec to validate - counts as passed (empty errors)
            return []

        # Use the full validation method for proper additionalProperties handling
        # and recursive validation of nested objects
        return self._validate_object_against_schema(
            spec_content, spec_schema, "spec", ref
        )

    def _record_validation(
        self,
        ref_errors: list[ValidationError] | ValidationError | None,
        all_errors: list[ValidationError],
        stats: dict[str, int],
    ) -> None:
        """
        Record validation result, updating stats and error list.

        Helper to reduce repetitive validation recording logic.
        """
        stats["validated"] += 1
        if ref_errors:
            if isinstance(ref_errors, list):
                all_errors.extend(ref_errors)
            else:
                all_errors.append(ref_errors)
            stats["failed"] += 1
        else:
            stats["passed"] += 1

    def _record_skip(
        self,
        reason: str,
        ref: ExtractedReference,
        stats: dict[str, int],
        skipped_reasons: dict[str, int],
        unknown_snippets: list[ExtractedReference],
    ) -> None:
        """
        Record a skipped reference, tracking if it's truly unknown.

        Helper to reduce repetitive skip recording logic.
        """
        stats["skipped"] += 1
        skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1

        # Track truly unknown snippets (not in known skip reasons)
        if reason not in KNOWN_SKIP_REASONS and not reason.startswith(
            "external chart:"
        ):
            unknown_snippets.append(ref)

    def validate_references(self, results: list[ExtractionResult]) -> ValidationResult:
        """Validate all extracted references."""
        errors: list[ValidationError] = []
        stats = {"validated": 0, "passed": 0, "failed": 0, "skipped": 0}
        skipped_reasons: dict[str, int] = {}
        unknown_snippets: list[ExtractedReference] = []

        for result in results:
            for ref in result.references:
                if ref.context == ReferenceContext.HELM_SET:
                    chart_name = ref.metadata.get("chart_name", "unknown")
                    if not self._has_chart_schema(chart_name):
                        self._record_skip(
                            f"external chart: {chart_name}",
                            ref,
                            stats,
                            skipped_reasons,
                            unknown_snippets,
                        )
                        continue

                    self._record_validation(self._validate_helm_set(ref), errors, stats)

                elif ref.context == ReferenceContext.HELM_VALUES:
                    chart_name = ref.metadata.get("chart_name", "unknown")
                    # Try to infer chart from content if unknown
                    content = ref.content if isinstance(ref.content, dict) else {}
                    if chart_name == "unknown":
                        # keycloak-operator has these top-level keys
                        operator_keys = {
                            "operator",
                            "keycloak",
                            "monitoring",
                            "webhooks",
                            "ingress",
                            "extraManifests",
                            "jvm",
                            "resources",
                        }
                        if content.keys() & operator_keys:
                            chart_name = "keycloak-operator"
                        elif "clientId" in content:
                            chart_name = "keycloak-client"
                        elif "realmName" in content:
                            chart_name = "keycloak-realm"

                    if not self._has_chart_schema(chart_name):
                        self._record_skip(
                            "helm-values unknown chart",
                            ref,
                            stats,
                            skipped_reasons,
                            unknown_snippets,
                        )
                    else:
                        self._record_validation(
                            self._validate_helm_values(ref), errors, stats
                        )

                elif ref.context == ReferenceContext.CR_KEYCLOAK:
                    self._record_validation(
                        self._validate_cr_instance(ref, "Keycloak"), errors, stats
                    )

                elif ref.context == ReferenceContext.CR_REALM:
                    self._record_validation(
                        self._validate_cr_instance(ref, "KeycloakRealm"), errors, stats
                    )

                elif ref.context == ReferenceContext.CR_CLIENT:
                    self._record_validation(
                        self._validate_cr_instance(ref, "KeycloakClient"), errors, stats
                    )

                elif ref.context == ReferenceContext.K8S_OTHER:
                    self._validate_k8s_other(
                        ref, errors, stats, skipped_reasons, unknown_snippets
                    )

                elif ref.context == ReferenceContext.UNKNOWN:
                    self._record_skip(
                        "unknown context", ref, stats, skipped_reasons, unknown_snippets
                    )

        return ValidationResult(
            total_validated=stats["validated"],
            total_passed=stats["passed"],
            total_failed=stats["failed"],
            total_skipped=stats["skipped"],
            errors=errors,
            skipped_reasons=skipped_reasons,
            unknown_snippets=unknown_snippets if unknown_snippets else None,
        )

    def _validate_k8s_other(
        self,
        ref: ExtractedReference,
        errors: list[ValidationError],
        stats: dict[str, int],
        skipped_reasons: dict[str, int],
        unknown_snippets: list[ExtractedReference],
    ) -> None:
        """Validate K8S_OTHER references based on their category."""
        category = self._categorize_k8s_other(ref)

        # Map categories to their validators
        category_validators = {
            "argocd": self._validate_argocd_helm_values,
            "rbac": self._validate_rbac_resource,
            "env": self._validate_env_array,
            "cnpg": self._validate_cnpg_cluster,
            "status": self._validate_status_snippet,
            "k8s-core": self._validate_k8s_core_resource,
        }

        if category in category_validators:
            self._record_validation(category_validators[category](ref), errors, stats)
        elif category.startswith("external:"):
            # External operators - validate if we have a schema, otherwise skip
            external_name = category.split(":", 1)[1]
            # Map external names to CRD kinds we can validate
            external_kind_map = {
                "kyverno": "ClusterPolicy",
            }
            if external_name in external_kind_map:
                kind = external_kind_map[external_name]
                validation_result = self._validate_external_crd(ref, kind)
                if validation_result is None:
                    # Schema unavailable or content not validatable - skip
                    self._record_skip(
                        f"external:{external_name}:no-schema",
                        ref,
                        stats,
                        skipped_reasons,
                        unknown_snippets,
                    )
                else:
                    self._record_validation(validation_result, errors, stats)
            else:
                # No schema available (FluxCD, Prometheus, cert-manager)
                self._record_skip(
                    category, ref, stats, skipped_reasons, unknown_snippets
                )
        elif category.startswith("partial:"):
            partial_type = category.split(":", 1)[1]
            # Validate K8s partial types we have schemas for
            k8s_partial_types = {"affinity", "resources", "tolerations", "nodeSelector"}
            if partial_type in k8s_partial_types:
                self._record_validation(
                    self._validate_partial_k8s(ref, partial_type), errors, stats
                )
            else:
                # Other partial types (cnpg, prometheus, app-config) - skip
                self._record_skip(
                    category, ref, stats, skipped_reasons, unknown_snippets
                )
        else:
            # Truly unknown - this should trigger a warning
            self._record_skip(
                "k8s-other", ref, stats, skipped_reasons, unknown_snippets
            )


def print_validation_report(result: ValidationResult) -> None:
    """Print a human-readable validation report."""
    print("\n" + "=" * 70)
    print("VALIDATION REPORT")
    print("=" * 70)

    print(f"\nValidated: {result.total_validated}")
    print(f"  ✅ Passed:  {result.total_passed}")
    print(f"  ❌ Failed:  {result.total_failed}")
    print(f"  ⏭️  Skipped: {result.total_skipped}")

    if result.skipped_reasons:
        print("\nSkipped reasons:")
        for reason, count in sorted(
            result.skipped_reasons.items(), key=lambda x: -x[1]
        ):
            # Mark unknown reasons with a warning indicator
            is_known = reason in KNOWN_SKIP_REASONS or reason.startswith(
                "external chart:"
            )
            indicator = "  " if is_known else "⚠️"
            print(f"  {indicator} {reason}: {count}")

    # Show warning for truly unknown snippets
    if result.unknown_snippets:
        print("\n" + "-" * 70)
        print("⚠️  WARNING: UNRECOGNIZED SNIPPETS FOUND")
        print("-" * 70)
        print("The following snippets could not be validated automatically.")
        print("Please verify them manually before committing.")
        print("See: docs/decisions/072-handling-unrecognized-doc-snippets.yaml")
        print()
        for ref in result.unknown_snippets[:10]:  # Limit to first 10
            raw_preview = ref.raw[:80].replace("\n", " ")
            print(f"  📄 {ref.file}:{ref.line}")
            print(f"     {raw_preview}...")
        if len(result.unknown_snippets) > 10:
            print(f"  ... and {len(result.unknown_snippets) - 10} more")

    if result.errors:
        print("\n" + "-" * 70)
        print("ERRORS")
        print("-" * 70)

        for error in result.errors:
            print(f"\n❌ {error.file}:{error.line}")
            print(f"   Context: {error.context}")
            print(f"   {error.message}")
            if error.suggestion:
                print(f"   💡 {error.suggestion}")

    print("\n" + "-" * 70)
    if result.total_failed == 0:
        print("✅ All validations passed!")
    else:
        print(f"❌ {result.total_failed} validation error(s) found")


def export_validation_to_json(result: ValidationResult) -> dict[str, Any]:
    """Export validation results to JSON format."""
    output: dict[str, Any] = {
        "summary": {
            "total_validated": result.total_validated,
            "total_passed": result.total_passed,
            "total_failed": result.total_failed,
            "total_skipped": result.total_skipped,
            "has_unknown_snippets": result.unknown_snippets is not None
            and len(result.unknown_snippets) > 0,
        },
        "skipped_reasons": result.skipped_reasons,
        "errors": [
            {
                "file": str(e.file),
                "line": e.line,
                "context": e.context,
                "message": e.message,
                "suggestion": e.suggestion,
                "key_path": e.key_path,
            }
            for e in result.errors
        ],
    }

    if result.unknown_snippets:
        output["unknown_snippets"] = [
            {
                "file": str(ref.file),
                "line": ref.line,
                "context": ref.context.value,
                "raw_preview": ref.raw[:100],
            }
            for ref in result.unknown_snippets
        ]

    return output


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Validate documentation schema references"
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
        help="Exit with non-zero code if any errors found",
    )

    args = parser.parse_args()

    # Find project root
    project_root = Path(__file__).parent.parent.parent
    docs_path = project_root / "docs"
    examples_path = project_root / "examples"

    if not docs_path.exists():
        print(f"Error: docs path does not exist: {docs_path}", file=sys.stderr)
        sys.exit(1)

    # Extract references
    if not args.json:
        print("Extracting documentation references...")

    extraction_results = extract_all_references(docs_path, examples_path)

    # Validate references
    if not args.json:
        print("Validating against schemas...")

    validator = SchemaValidator(project_root)
    validation_result = validator.validate_references(extraction_results)

    # Output results
    if args.json:
        output = export_validation_to_json(validation_result)
        print(json.dumps(output, indent=2))
    else:
        print_validation_report(validation_result)

    # Exit code
    if args.fail_on_error and validation_result.total_failed > 0:
        sys.exit(1)
