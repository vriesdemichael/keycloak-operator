#!/usr/bin/env python3
"""
Validate conventional commit messages with enforced scopes.

This script validates that commit messages follow the conventional commit format
and use valid scopes from the release-please configuration.

Valid scopes:
- operator
- chart-operator
- chart-realm
- chart-client

Scopes can be combined with '+' (e.g., 'operator+chart-operator').
Components must be in alphabetical order and not duplicated.

Examples:
  ✅ feat(operator): add new feature
  ✅ fix(chart-realm): fix bug
  ✅ feat(chart-client+chart-realm): update both charts
  ✅ chore!: breaking change without scope (allowed)
  ❌ feat(invalid): wrong scope
  ❌ feat(operator+operator): duplicate component
  ❌ feat(chart-realm+chart-client): wrong order (should be chart-client+chart-realm)
"""

import re
import sys
from pathlib import Path

# Valid component scopes from release-please-config.json
VALID_SCOPES = {
    "operator",
    "chart-operator",
    "chart-realm",
    "chart-client",
}

# Conventional commit pattern
# Matches: type(scope): description
# Optional: ! for breaking changes, scope is optional
COMMIT_PATTERN = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore|ci|build|revert)"
    r"(?:\((?P<scope>[^)]+)\))?"
    r"(?P<breaking>!)?"
    r": "
    r"(?P<description>.+)"
)


def validate_scope(scope: str | None) -> tuple[bool, str]:
    """
    Validate the scope part of a conventional commit message.

    Args:
        scope: The scope string (can be None, single scope, or combined scopes with '+')

    Returns:
        Tuple of (is_valid, error_message)
    """
    if scope is None:
        # Scope is optional for certain commit types
        return True, ""

    # Split by '+' to get individual components
    components = scope.split("+")

    # Check for duplicates
    if len(components) != len(set(components)):
        duplicates = [c for c in components if components.count(c) > 1]
        return False, f"Duplicate components in scope: {', '.join(set(duplicates))}"

    # Validate each component
    invalid_components = [c for c in components if c not in VALID_SCOPES]
    if invalid_components:
        return False, (
            f"Invalid scope components: {', '.join(invalid_components)}\n"
            f"Valid scopes: {', '.join(sorted(VALID_SCOPES))}"
        )

    # Check if components are in alphabetical order (for consistency)
    sorted_components = sorted(components)
    if components != sorted_components:
        return False, (
            f"Scope components must be in alphabetical order.\n"
            f"Current: {'+'.join(components)}\n"
            f"Expected: {'+'.join(sorted_components)}"
        )

    return True, ""


def validate_commit_message(message: str) -> tuple[bool, str]:
    """
    Validate a conventional commit message.

    Args:
        message: The commit message to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Get first line of commit message
    first_line = message.split("\n")[0].strip()

    # Check if it matches conventional commit pattern
    match = COMMIT_PATTERN.match(first_line)
    if not match:
        return False, (
            "Commit message does not follow conventional commit format.\n"
            "Expected format: type(scope): description\n"
            "Valid types: feat, fix, docs, style, refactor, perf, test, chore, ci, build, revert\n"
            f"Example: feat(operator): add new feature\n\n"
            f"Your message: {first_line}"
        )

    # Validate the scope
    scope = match.group("scope")
    scope_valid, scope_error = validate_scope(scope)
    if not scope_valid:
        return False, scope_error

    return True, ""


def main() -> int:
    """Main entry point for the commit message validator."""
    if len(sys.argv) < 2:
        print("Error: No commit message file provided", file=sys.stderr)
        return 1

    commit_msg_file = Path(sys.argv[1])
    if not commit_msg_file.exists():
        print(
            f"Error: Commit message file not found: {commit_msg_file}", file=sys.stderr
        )
        return 1

    commit_message = commit_msg_file.read_text(encoding="utf-8")

    # Skip validation for merge commits
    if commit_message.startswith("Merge "):
        return 0

    # Skip validation for revert commits (they have special format)
    if commit_message.startswith("Revert "):
        return 0

    is_valid, error_message = validate_commit_message(commit_message)

    if not is_valid:
        print("\n❌ Invalid commit message!", file=sys.stderr)
        print("-" * 60, file=sys.stderr)
        print(error_message, file=sys.stderr)
        print("-" * 60, file=sys.stderr)
        print("\nValid scopes:", file=sys.stderr)
        for scope in sorted(VALID_SCOPES):
            print(f"  - {scope}", file=sys.stderr)
        print(
            "\nYou can combine scopes with '+' (in alphabetical order):",
            file=sys.stderr,
        )
        print("  - chart-client+chart-realm", file=sys.stderr)
        print("  - operator+chart-operator", file=sys.stderr)
        print(
            "\nScope is optional for chore, docs, ci, and test commits.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
