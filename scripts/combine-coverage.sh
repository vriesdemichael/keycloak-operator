#!/usr/bin/env bash
# Combine unit test and integration test coverage data
# Usage: ./scripts/combine-coverage.sh

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "${SCRIPT_DIR}/common.sh"

# Configuration
COVERAGE_DIR=".tmp/coverage"
COMBINED_DATA=".coverage"
MINIMUM_COVERAGE="${MINIMUM_COVERAGE:-50}"

log "Combining coverage data..."

# Check if we have any coverage files
if [ ! -f ".coverage" ] && [ ! -d "${COVERAGE_DIR}" ]; then
    error "No coverage data found"
    error "Expected .coverage (unit tests) or ${COVERAGE_DIR}/ (integration tests)"
    exit 1
fi

# List available coverage files
log "Available coverage files:"
if [ -f ".coverage" ]; then
    log "  - .coverage (unit tests)"
fi
if [ -d "${COVERAGE_DIR}" ]; then
    INTEGRATION_FILES=$(find "${COVERAGE_DIR}" -name ".coverage*" -type f 2>/dev/null || true)
    if [ -n "${INTEGRATION_FILES}" ]; then
        echo "${INTEGRATION_FILES}" | while read -r file; do
            log "  - ${file} (integration tests)"
        done
    fi
fi

# Combine coverage data
log "Combining coverage files..."
if command -v uv >/dev/null 2>&1; then
    # Use uv run to ensure correct environment
    uv run coverage combine .coverage "${COVERAGE_DIR}/.coverage"* 2>/dev/null || true
    log "Combined coverage data into ${COMBINED_DATA}"
else
    # Fallback to direct coverage command
    coverage combine .coverage "${COVERAGE_DIR}/.coverage"* 2>/dev/null || true
    log "Combined coverage data into ${COMBINED_DATA}"
fi

# Generate reports
log "Generating coverage reports..."

# Terminal report
log "Coverage summary:"
if command -v uv >/dev/null 2>&1; then
    uv run coverage report --show-missing
else
    coverage report --show-missing
fi

# XML report for Codecov
log "Generating XML report for Codecov..."
if command -v uv >/dev/null 2>&1; then
    uv run coverage xml
else
    coverage xml
fi
success "Generated coverage.xml"

# HTML report for local viewing
log "Generating HTML report..."
if command -v uv >/dev/null 2>&1; then
    uv run coverage html
else
    coverage html
fi
success "Generated htmlcov/ directory"
log "View HTML report: open htmlcov/index.html"

# Check minimum coverage threshold
log "Checking coverage threshold (minimum: ${MINIMUM_COVERAGE}%)..."
if command -v uv >/dev/null 2>&1; then
    if uv run coverage report --fail-under="${MINIMUM_COVERAGE}" >/dev/null 2>&1; then
        success "Coverage meets minimum threshold of ${MINIMUM_COVERAGE}%"
    else
        error "Coverage below minimum threshold of ${MINIMUM_COVERAGE}%"
        exit 1
    fi
else
    if coverage report --fail-under="${MINIMUM_COVERAGE}" >/dev/null 2>&1; then
        success "Coverage meets minimum threshold of ${MINIMUM_COVERAGE}%"
    else
        error "Coverage below minimum threshold of ${MINIMUM_COVERAGE}%"
        exit 1
    fi
fi

success "Coverage combination complete!"
exit 0
