#!/bin/bash
set -euo pipefail

# Script to generate Markdown documentation from decision record YAML files
# This should be run before building documentation (mkdocs build)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DECISIONS_DIR="${PROJECT_ROOT}/docs/decisions"
OUTPUT_DIR="${DECISIONS_DIR}/generated-markdown"

echo "Generating decision record documentation..."

# Check that decisions directory exists
if [[ ! -d "${DECISIONS_DIR}" ]]; then
    echo "Error: Decision records directory not found: ${DECISIONS_DIR}" >&2
    exit 1
fi

# Check that YAML files exist
if ! compgen -G "${DECISIONS_DIR}/*.yaml" > /dev/null; then
    echo "Error: No YAML files found in ${DECISIONS_DIR}" >&2
    exit 1
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Convert each YAML file to Markdown
for yaml_file in "${DECISIONS_DIR}"/*.yaml; do
    if [[ -f "$yaml_file" ]]; then
        basename=$(basename "$yaml_file" .yaml)
        output_file="${OUTPUT_DIR}/${basename}.md"
        echo "  Converting: $basename"
        uv run python "${SCRIPT_DIR}/adr_to_markdown.py" "$yaml_file" > "$output_file"
    fi
done

echo "Decision record documentation generated in ${OUTPUT_DIR}"
echo "Total records: $(find "${OUTPUT_DIR}" -name "*.md" | wc -l)"

# Update the decision records index with categorized lists
echo "Updating decision records index..."
uv run python "${SCRIPT_DIR}/update-decision-index.py"

echo "✓ All decision record documentation ready"
