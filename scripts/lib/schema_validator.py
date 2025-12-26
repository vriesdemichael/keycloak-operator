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


class SchemaValidator:
    """Validates documentation references against schemas."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.charts_path = project_root / "charts"
        self.crds_path = self.charts_path / "keycloak-operator" / "crds"

        # Lazy-loaded caches
        self._values_schemas: dict[str, dict[str, Any]] = {}
        self._crd_schemas: dict[str, dict[str, Any]] = {}
        self._validatable_charts: set[str] | None = None
        self._crd_kind_to_file: dict[str, str] | None = None

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
        """Load values.schema.json for a chart."""
        if chart_name in self._values_schemas:
            return self._values_schemas[chart_name]

        schema_path = self.charts_path / chart_name / "values.schema.json"
        if not schema_path.exists():
            return None

        with open(schema_path) as f:
            schema = json.load(f)
            self._values_schemas[chart_name] = schema
            return schema

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

    def _get_schema_properties(
        self, schema: dict[str, Any], path: str = ""
    ) -> dict[str, dict[str, Any]]:
        """
        Recursively extract all property paths from a JSON schema.

        Returns dict mapping dotted paths to their schema definitions.
        """
        properties: dict[str, dict[str, Any]] = {}

        if "properties" in schema:
            for prop_name, prop_schema in schema["properties"].items():
                full_path = f"{path}.{prop_name}" if path else prop_name
                properties[full_path] = prop_schema

                # Recurse into nested objects
                if prop_schema.get("type") == "object":
                    nested = self._get_schema_properties(prop_schema, full_path)
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

        # Skip charts we don't validate (auto-discovered)
        validatable_charts = self._discover_validatable_charts()
        if chart_name not in validatable_charts:
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

    def validate_references(self, results: list[ExtractionResult]) -> ValidationResult:
        """Validate all extracted references."""
        errors: list[ValidationError] = []
        total_validated = 0
        total_passed = 0
        total_failed = 0
        total_skipped = 0
        skipped_reasons: dict[str, int] = {}

        # Auto-discover validatable charts
        validatable_charts = self._discover_validatable_charts()

        for result in results:
            for ref in result.references:
                if ref.context == ReferenceContext.HELM_SET:
                    chart_name = ref.metadata.get("chart_name", "unknown")
                    if chart_name not in validatable_charts:
                        total_skipped += 1
                        reason = f"external chart: {chart_name}"
                        skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1
                        continue

                    total_validated += 1
                    error = self._validate_helm_set(ref)
                    if error:
                        errors.append(error)
                        total_failed += 1
                    else:
                        total_passed += 1

                elif ref.context == ReferenceContext.HELM_VALUES:
                    # TODO: Implement helm values validation
                    total_skipped += 1
                    skipped_reasons["helm-values not implemented"] = (
                        skipped_reasons.get("helm-values not implemented", 0) + 1
                    )

                elif ref.context == ReferenceContext.CR_KEYCLOAK:
                    total_validated += 1
                    cr_errors = self._validate_cr_instance(ref, "Keycloak")
                    if cr_errors:
                        errors.extend(cr_errors)
                        total_failed += 1
                    else:
                        total_passed += 1

                elif ref.context == ReferenceContext.CR_REALM:
                    total_validated += 1
                    cr_errors = self._validate_cr_instance(ref, "KeycloakRealm")
                    if cr_errors:
                        errors.extend(cr_errors)
                        total_failed += 1
                    else:
                        total_passed += 1

                elif ref.context == ReferenceContext.CR_CLIENT:
                    total_validated += 1
                    cr_errors = self._validate_cr_instance(ref, "KeycloakClient")
                    if cr_errors:
                        errors.extend(cr_errors)
                        total_failed += 1
                    else:
                        total_passed += 1

                elif ref.context == ReferenceContext.K8S_OTHER:
                    total_skipped += 1
                    skipped_reasons["k8s-other"] = (
                        skipped_reasons.get("k8s-other", 0) + 1
                    )

                elif ref.context == ReferenceContext.UNKNOWN:
                    total_skipped += 1
                    skipped_reasons["unknown context"] = (
                        skipped_reasons.get("unknown context", 0) + 1
                    )

        return ValidationResult(
            total_validated=total_validated,
            total_passed=total_passed,
            total_failed=total_failed,
            total_skipped=total_skipped,
            errors=errors,
            skipped_reasons=skipped_reasons,
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
            print(f"  {reason}: {count}")

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
    return {
        "summary": {
            "total_validated": result.total_validated,
            "total_passed": result.total_passed,
            "total_failed": result.total_failed,
            "total_skipped": result.total_skipped,
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
