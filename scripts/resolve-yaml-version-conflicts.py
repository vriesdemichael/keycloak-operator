#!/usr/bin/env python3
"""
Resolve merge conflicts in YAML files containing version numbers.

This script handles conflicts in Chart.yaml and values.yaml files where
version numbers conflict. Resolution strategy:
- For version/appVersion/tag fields: take the higher semver version
- For other fields: keep the value from main (theirs)

Usage:
    python resolve-yaml-version-conflicts.py <file_path>

The file is modified in-place if conflicts are resolved.
Exit codes:
    0 - Success (conflicts resolved or no conflicts)
    1 - Error (unparseable conflicts or other issues)
"""

import re
import sys
from pathlib import Path


def parse_semver(version: str) -> tuple[int, int, int]:
    """
    Parse a semver string into a tuple of (major, minor, patch).

    Handles versions with or without 'v' prefix.
    Only plain versions are supported (no pre-release or build metadata).
    """
    # Remove 'v' prefix if present
    version = version.lstrip("v")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if not match:
        raise ValueError(f"Invalid semver: {version}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def compare_versions(v1: str, v2: str) -> int:
    """Compare two semver strings. Returns >0 if v1>v2, <0 if v1<v2, 0 if equal."""
    t1 = parse_semver(v1)
    t2 = parse_semver(v2)
    for a, b in zip(t1, t2, strict=True):
        if a != b:
            return a - b
    return 0


def max_version(v1: str, v2: str) -> str:
    """
    Return the higher of two semver versions.

    Preserves the format (v prefix, quotes) of the higher version.
    """
    # Strip quotes for comparison
    v1_clean = v1.strip('"').strip("'")
    v2_clean = v2.strip('"').strip("'")

    if compare_versions(v1_clean, v2_clean) >= 0:
        return v1
    return v2


# Keys that contain version numbers and should use max-version logic
VERSION_KEYS = {"version", "appVersion", "tag"}


def resolve_yaml_conflict(content: str) -> str | None:
    """
    Resolve conflicts in a YAML file by taking max versions for version fields.

    For non-version fields, takes the value from 'theirs' (main branch).
    Returns resolved content or None if resolution failed.
    """
    if "<<<<<<< " not in content:
        return content  # No conflicts

    lines = content.split("\n")
    result_lines = []
    in_conflict = False
    in_ours = False
    in_theirs = False
    ours_lines: list[str] = []
    theirs_lines: list[str] = []

    for line in lines:
        if line.startswith("<<<<<<< "):
            in_conflict = True
            in_ours = True
            ours_lines = []
            theirs_lines = []
            continue
        elif line.startswith("=======") and in_conflict:
            in_ours = False
            in_theirs = True
            continue
        elif line.startswith(">>>>>>> ") and in_conflict:
            in_conflict = False
            in_theirs = False
            # Resolve this conflict block
            resolved = resolve_conflict_block(ours_lines, theirs_lines)
            if resolved is None:
                return None
            result_lines.extend(resolved)
            continue

        if in_conflict:
            if in_ours:
                ours_lines.append(line)
            elif in_theirs:
                theirs_lines.append(line)
        else:
            result_lines.append(line)

    return "\n".join(result_lines)


def resolve_conflict_block(
    ours_lines: list[str], theirs_lines: list[str]
) -> list[str] | None:
    """
    Resolve a single conflict block.

    For version fields, takes the max version.
    For other fields, takes theirs (main branch).
    """
    # Parse both sides into key-value pairs
    ours_kv = parse_yaml_lines(ours_lines)
    theirs_kv = parse_yaml_lines(theirs_lines)

    # If we couldn't parse either side, fall back to theirs
    if not ours_kv and not theirs_kv:
        return None
    if not ours_kv:
        return theirs_lines
    if not theirs_kv:
        return ours_lines

    # Merge: for version keys take max, otherwise take theirs
    result_lines = []

    # Use theirs as the base structure
    for line in theirs_lines:
        key = extract_key(line)
        if key and key in VERSION_KEYS:
            ours_val = ours_kv.get(key)
            theirs_val = theirs_kv.get(key)
            if ours_val and theirs_val:
                try:
                    max_val = max_version(ours_val, theirs_val)
                    # Replace the value in theirs line with max value
                    result_lines.append(replace_value(line, max_val))
                except ValueError:
                    # Not valid semver, keep theirs
                    result_lines.append(line)
            else:
                result_lines.append(line)
        else:
            result_lines.append(line)

    return result_lines


def parse_yaml_lines(lines: list[str]) -> dict[str, str]:
    """
    Parse YAML lines into a dict of key -> value.

    Only handles simple key: value pairs (not nested structures).
    """
    result = {}
    # Pattern for simple YAML key: value pairs
    pattern = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*):\s*(.+?)\s*$")

    for line in lines:
        match = pattern.match(line)
        if match:
            key = match.group(2)
            value = match.group(3)
            result[key] = value

    return result


def extract_key(line: str) -> str | None:
    """Extract the key from a YAML line."""
    pattern = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*):\s*")
    match = pattern.match(line)
    if match:
        return match.group(2)
    return None


def replace_value(line: str, new_value: str) -> str:
    """Replace the value in a YAML line while preserving formatting."""
    pattern = re.compile(r"^(\s*[a-zA-Z_][a-zA-Z0-9_]*:\s*)(.+?)\s*$")
    match = pattern.match(line)
    if match:
        return match.group(1) + new_value
    return line


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>", file=sys.stderr)
        return 1

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"File not found: {file_path}", file=sys.stderr)
        return 1

    content = file_path.read_text()

    # Check for conflict markers
    if "<<<<<<< " not in content:
        print(f"No conflicts in {file_path}")
        return 0

    resolved = resolve_yaml_conflict(content)

    if resolved is None:
        print(f"Failed to resolve conflicts in {file_path}", file=sys.stderr)
        return 1

    file_path.write_text(resolved)
    print(f"Resolved conflicts in {file_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
