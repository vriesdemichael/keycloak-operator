#!/bin/bash
#
# Generate Pydantic models from Keycloak OpenAPI specification
#
# This script converts the official Keycloak Admin REST API OpenAPI spec
# into type-safe Pydantic models for validation and type checking.
#
# Usage: ./scripts/generate-keycloak-models.sh
#

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

INPUT_SPEC="$PROJECT_ROOT/keycloak-api-spec.yaml"
OUTPUT_FILE="$PROJECT_ROOT/src/keycloak_operator/models/keycloak_api.py"

echo "Generating Keycloak API Pydantic models..."
echo "  Input:  $INPUT_SPEC"
echo "  Output: $OUTPUT_FILE"
echo

# Check if input spec exists
if [ ! -f "$INPUT_SPEC" ]; then
    echo "ERROR: Keycloak API spec not found at: $INPUT_SPEC"
    exit 1
fi

# Generate models using datamodel-code-generator
uv run python -m datamodel_code_generator \
    --input "$INPUT_SPEC" \
    --output "$OUTPUT_FILE" \
    --input-file-type openapi \
    --output-model-type pydantic_v2.BaseModel \
    --use-standard-collections \
    --use-schema-description \
    --use-field-description \
    --use-default \
    --snake-case-field \
    --target-python-version 3.13 \
    --disable-timestamp \
    --enum-field-as-literal one \
    --field-constraints \
    --use-annotated \
    --use-double-quotes \
    --use-union-operator \
    --collapse-root-models \
    --allow-population-by-field-name

echo
echo "✓ Models generated successfully!"
echo "  Output: $OUTPUT_FILE"
echo
echo "Next steps:"
echo "  1. Review the generated file"
echo "  2. Test imports: python -c \"from keycloak_operator.models.keycloak_api import RealmRepresentation\""
echo "  3. Run tests: pytest tests/unit/test_keycloak_api_models.py"
