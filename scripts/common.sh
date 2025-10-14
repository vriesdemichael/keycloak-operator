#!/bin/bash
# common.sh - Shared functions for Keycloak operator scripts
#
# This file provides common logging and utility functions used across
# all operator development and testing scripts.
#
# Usage: source scripts/common.sh

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Logging functions with timestamps and color coding

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

# Alternative shorter names for CNPG script compatibility
err() {
    error "$1"
}

ok() {
    success "$1"
}
