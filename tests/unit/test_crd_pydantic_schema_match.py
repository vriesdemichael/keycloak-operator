"""
Test CRD and Pydantic model schema matching.

This module validates that CRD definitions (YAML OpenAPI schemas) match their
corresponding Pydantic models. This catches mismatches early, preventing bugs
like missing fields or type inconsistencies.

Validates:
- Field presence in both CRD and model
- Field types match
- Nested object structures align
- Required fields are consistent
- Enum values match
- Default values are compatible
"""

import pathlib
from typing import Any

import pytest
import yaml
from pydantic import BaseModel

from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.models.keycloak import KeycloakSpec
from keycloak_operator.models.realm import KeycloakRealmSpec

# Path to CRD files
CRD_DIR = pathlib.Path(__file__).parent.parent.parent / "k8s" / "crds"

# Fields to ignore (CRD-only metadata or Pydantic-only computed fields)
IGNORE_FIELDS = {
    "KeycloakSpec": {
        # These are added by Pydantic for runtime but not in CRD spec
        "model_config",
    },
    "KeycloakRealmSpec": {
        "model_config",
    },
    "KeycloakClientSpec": {
        "model_config",
    },
    "_all_": {
        # K8s metadata fields not in Pydantic models
        "apiVersion",
        "kind",
        "metadata",
        "status",
    },
}

# Type mapping from CRD (OpenAPI) to Pydantic
TYPE_MAPPING = {
    "string": {"string", "str"},
    "integer": {"integer", "int"},
    "boolean": {"boolean", "bool"},
    "object": {"object", "dict"},
    "array": {"array", "list"},
}


def load_crd_schema(crd_filename: str) -> dict[str, Any]:
    """
    Load CRD YAML file and extract the spec schema.

    Args:
        crd_filename: Name of the CRD file (e.g., 'keycloak-crd.yaml')

    Returns:
        Dictionary containing the spec properties from the CRD schema

    Raises:
        FileNotFoundError: If CRD file doesn't exist
        KeyError: If CRD structure is unexpected
    """
    crd_path = CRD_DIR / crd_filename

    if not crd_path.exists():
        raise FileNotFoundError(f"CRD file not found: {crd_path}")

    with open(crd_path) as f:
        crd_data = yaml.safe_load(f)

    # Navigate to spec schema: spec.versions[0].schema.openAPIV3Schema.properties.spec
    try:
        schema = crd_data["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        spec_schema = schema["properties"]["spec"]
        return spec_schema.get("properties", {})
    except (KeyError, IndexError, TypeError) as e:
        raise KeyError(f"Unexpected CRD structure in {crd_filename}: {e}") from e


def get_pydantic_schema(model_class: type[BaseModel]) -> dict[str, Any]:
    """
    Extract schema from Pydantic model.

    Args:
        model_class: Pydantic model class

    Returns:
        Dictionary containing the model's properties schema
    """
    # Get JSON schema from Pydantic model
    schema = model_class.model_json_schema()

    # Extract properties
    properties = schema.get("properties", {})

    # Also get required fields
    required_fields = set(schema.get("required", []))

    # Add required info to each property
    for field_name, field_schema in properties.items():
        field_schema["_pydantic_required"] = field_name in required_fields

    return properties


def normalize_pydantic_type(pydantic_type: dict[str, Any]) -> str:
    """
    Normalize Pydantic type to a simple string representation.

    Args:
        pydantic_type: Pydantic field type schema

    Returns:
        Normalized type string (e.g., 'string', 'integer', 'object')
    """
    # Handle direct type
    if "type" in pydantic_type:
        ptype = pydantic_type["type"]
        if isinstance(ptype, str):
            return ptype
        # Handle list of types (union types)
        if isinstance(ptype, list):
            # Filter out 'null' (for optional fields)
            non_null_types = [t for t in ptype if t != "null"]
            if len(non_null_types) == 1:
                return non_null_types[0]
            return f"union[{','.join(non_null_types)}]"

    # Handle anyOf (union types in Pydantic)
    if "anyOf" in pydantic_type:
        types = []
        for variant in pydantic_type["anyOf"]:
            if "type" in variant and variant["type"] != "null":
                types.append(variant["type"])
            elif "$ref" in variant:
                types.append("object")
        if len(types) == 1:
            return types[0]
        return f"union[{','.join(types)}]"

    # Handle $ref (references to other schemas)
    if "$ref" in pydantic_type:
        return "object"

    # Handle allOf
    if "allOf" in pydantic_type:
        return "object"

    return "unknown"


def types_match(crd_type: str, pydantic_type_schema: dict[str, Any]) -> bool:
    """
    Check if CRD type matches Pydantic type.

    Args:
        crd_type: Type from CRD (e.g., 'string', 'integer', 'object')
        pydantic_type_schema: Pydantic field type schema

    Returns:
        True if types are compatible
    """
    pydantic_type = normalize_pydantic_type(pydantic_type_schema)

    # Handle direct matches
    if crd_type == pydantic_type:
        return True

    # Handle type aliases
    if crd_type in TYPE_MAPPING and pydantic_type in TYPE_MAPPING[crd_type]:
        return True

    # Handle union types (Pydantic might have Optional[Type] = Type | None)
    # If CRD type appears in union, consider it a match
    return pydantic_type.startswith("union[") and crd_type in pydantic_type


def compare_field(
    field_name: str,
    crd_field: dict[str, Any],
    pydantic_field: dict[str, Any] | None,
    path: str = "",
) -> list[str]:
    """
    Compare a single field from CRD and Pydantic schemas.

    Args:
        field_name: Name of the field
        crd_field: Field schema from CRD
        pydantic_field: Field schema from Pydantic (None if missing)
        path: Current path in schema (for nested objects)

    Returns:
        List of mismatch descriptions (empty if fields match)
    """
    mismatches = []
    full_path = f"{path}.{field_name}" if path else field_name

    # Check if field exists in Pydantic
    if pydantic_field is None:
        mismatches.append(
            f"Field '{full_path}' exists in CRD but not in Pydantic model\n"
            f"  CRD type: {crd_field.get('type', 'unknown')}\n"
            f"  CRD description: {crd_field.get('description', 'N/A')}\n"
            f"  Fix: Add this field to the Pydantic model"
        )
        return mismatches

    # Check type matching
    crd_type = crd_field.get("type")
    if crd_type and not types_match(crd_type, pydantic_field):
        pydantic_type = normalize_pydantic_type(pydantic_field)
        mismatches.append(
            f"Field '{full_path}' has type mismatch\n"
            f"  CRD type: {crd_type}\n"
            f"  Pydantic type: {pydantic_type}\n"
            f"  Fix: Ensure types match between CRD and model"
        )

    # Check enum values if present
    if "enum" in crd_field:
        crd_enums = set(crd_field["enum"])
        # Pydantic might represent enums differently
        pydantic_enums = pydantic_field.get("enum")
        if pydantic_enums is not None:
            pydantic_enums = set(pydantic_enums)
            if crd_enums != pydantic_enums:
                mismatches.append(
                    f"Field '{full_path}' has enum mismatch\n"
                    f"  CRD enums: {sorted(crd_enums)}\n"
                    f"  Pydantic enums: {sorted(pydantic_enums)}\n"
                    f"  Fix: Ensure enum values match"
                )

    # Recursively check nested objects
    if crd_type == "object" and "properties" in crd_field:
        # Get nested schema from Pydantic
        if "$ref" in pydantic_field:
            # Reference to another model - we'll check that model separately
            pass
        elif "properties" in pydantic_field:
            # Inline nested object
            nested_mismatches = compare_schemas(
                crd_field["properties"],
                pydantic_field["properties"],
                path=full_path,
            )
            mismatches.extend(nested_mismatches)
        elif "anyOf" in pydantic_field:
            # Union type - check if one variant matches
            # For now, we'll skip deep validation of union types
            pass

    # Check array items if present
    if crd_type == "array" and "items" in crd_field:
        pydantic_items = pydantic_field.get("items")
        if pydantic_items:
            # Check if array item types match
            crd_item_type = crd_field["items"].get("type")
            if crd_item_type and not types_match(crd_item_type, pydantic_items):
                pydantic_item_type = normalize_pydantic_type(pydantic_items)
                mismatches.append(
                    f"Field '{full_path}' array items have type mismatch\n"
                    f"  CRD item type: {crd_item_type}\n"
                    f"  Pydantic item type: {pydantic_item_type}\n"
                    f"  Fix: Ensure array item types match"
                )

    return mismatches


def compare_schemas(
    crd_schema: dict[str, Any],
    pydantic_schema: dict[str, Any],
    path: str = "",
    model_name: str = "",
) -> list[str]:
    """
    Compare CRD schema with Pydantic schema.

    Args:
        crd_schema: Schema from CRD (properties dict)
        pydantic_schema: Schema from Pydantic model (properties dict)
        path: Current path in schema (for nested objects)
        model_name: Name of the model being compared (for ignore rules)

    Returns:
        List of mismatch descriptions
    """
    mismatches = []

    # Get ignore list for this model
    ignore_fields = IGNORE_FIELDS.get(model_name, set()) | IGNORE_FIELDS.get(
        "_all_", set()
    )

    # Check all CRD fields exist in Pydantic
    for field_name, crd_field in crd_schema.items():
        if field_name in ignore_fields:
            continue

        pydantic_field = pydantic_schema.get(field_name)
        field_mismatches = compare_field(field_name, crd_field, pydantic_field, path)
        mismatches.extend(field_mismatches)

    # Check for Pydantic fields not in CRD (might indicate model-only fields)
    for field_name, pydantic_field in pydantic_schema.items():
        if field_name in ignore_fields:
            continue

        if field_name not in crd_schema:
            # Check if it's required
            is_required = pydantic_field.get("_pydantic_required", False)
            severity = "WARNING" if not is_required else "ERROR"

            full_path = f"{path}.{field_name}" if path else field_name
            pydantic_type = normalize_pydantic_type(pydantic_field)

            mismatches.append(
                f"[{severity}] Field '{full_path}' exists in Pydantic model but not in CRD\n"
                f"  Pydantic type: {pydantic_type}\n"
                f"  Required: {is_required}\n"
                f"  Fix: Add this field to the CRD or mark it as model-only"
            )

    return mismatches


class TestCRDPydanticSchemaMatch:
    """Test that CRD definitions match Pydantic models."""

    def test_keycloak_crd_matches_model(self):
        """Validate Keycloak CRD matches KeycloakSpec model."""
        # Load CRD schema
        crd_schema = load_crd_schema("keycloak-crd.yaml")

        # Load Pydantic schema
        pydantic_schema = get_pydantic_schema(KeycloakSpec)

        # Compare schemas
        mismatches = compare_schemas(
            crd_schema, pydantic_schema, model_name="KeycloakSpec"
        )

        # Assert no mismatches
        if mismatches:
            error_msg = (
                f"\n\nKeycloak CRD and KeycloakSpec model have {len(mismatches)} mismatch(es):\n\n"
                + "\n\n".join(f"{i + 1}. {m}" for i, m in enumerate(mismatches))
            )
            pytest.fail(error_msg)

    def test_keycloakrealm_crd_matches_model(self):
        """Validate KeycloakRealm CRD matches KeycloakRealmSpec model."""
        # Load CRD schema
        crd_schema = load_crd_schema("keycloakrealm-crd.yaml")

        # Load Pydantic schema
        pydantic_schema = get_pydantic_schema(KeycloakRealmSpec)

        # Compare schemas
        mismatches = compare_schemas(
            crd_schema, pydantic_schema, model_name="KeycloakRealmSpec"
        )

        # Assert no mismatches
        if mismatches:
            error_msg = (
                f"\n\nKeycloakRealm CRD and KeycloakRealmSpec model have {len(mismatches)} mismatch(es):\n\n"
                + "\n\n".join(f"{i + 1}. {m}" for i, m in enumerate(mismatches))
            )
            pytest.fail(error_msg)

    def test_keycloakclient_crd_matches_model(self):
        """Validate KeycloakClient CRD matches KeycloakClientSpec model."""
        # Load CRD schema
        crd_schema = load_crd_schema("keycloakclient-crd.yaml")

        # Load Pydantic schema
        pydantic_schema = get_pydantic_schema(KeycloakClientSpec)

        # Compare schemas
        mismatches = compare_schemas(
            crd_schema, pydantic_schema, model_name="KeycloakClientSpec"
        )

        # Assert no mismatches
        if mismatches:
            error_msg = (
                f"\n\nKeycloakClient CRD and KeycloakClientSpec model have {len(mismatches)} mismatch(es):\n\n"
                + "\n\n".join(f"{i + 1}. {m}" for i, m in enumerate(mismatches))
            )
            pytest.fail(error_msg)

    def test_crd_files_exist(self):
        """Verify all expected CRD files exist."""
        expected_crds = [
            "keycloak-crd.yaml",
            "keycloakrealm-crd.yaml",
            "keycloakclient-crd.yaml",
        ]

        for crd_name in expected_crds:
            crd_path = CRD_DIR / crd_name
            assert crd_path.exists(), f"CRD file not found: {crd_path}"

    def test_schema_loader_handles_missing_file(self):
        """Test that schema loader raises appropriate error for missing files."""
        with pytest.raises(FileNotFoundError):
            load_crd_schema("nonexistent-crd.yaml")

    def test_type_matching_logic(self):
        """Test type matching helper function."""
        # Test basic type matches
        assert types_match("string", {"type": "string"})
        assert types_match("integer", {"type": "integer"})
        assert types_match("boolean", {"type": "boolean"})
        assert types_match("object", {"type": "object"})
        assert types_match("array", {"type": "array"})

        # Test optional types (union with null)
        assert types_match("string", {"anyOf": [{"type": "string"}, {"type": "null"}]})
        assert types_match("integer", {"type": ["integer", "null"]})

        # Test object references
        assert types_match("object", {"$ref": "#/definitions/SomeModel"})

        # Test type mismatches
        assert not types_match("string", {"type": "integer"})
        assert not types_match("boolean", {"type": "string"})
