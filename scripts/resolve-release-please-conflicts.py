#!/usr/bin/env python3
"""
Resolve merge conflicts in release-please manifest files.

This script handles the predictable conflict pattern where multiple release PRs
have different versions for the same components. Resolution strategy:
- For version conflicts: take the higher semver version
- For components present in only one side: include them

Usage:
    python resolve-release-please-conflicts.py <file_path>

The file is modified in-place if conflicts are resolved.
Exit codes:
    0 - Success (conflicts resolved or no conflicts)
    1 - Error (unparseable conflicts or other issues)
"""

import contextlib
import json
import re
import sys
from pathlib import Path


def parse_semver(version: str) -> tuple[int, int, int]:
    """
    Parse a basic semver string into a tuple of (major, minor, patch).

    Only plain `MAJOR.MINOR.PATCH` versions are supported. Versions with
    pre-release identifiers (e.g., `1.0.0-beta.1`) or build metadata
    (e.g., `1.0.0+build.123`) are considered invalid and will raise
    ValueError.
    """
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
    """Return the higher of two semver versions."""
    return v1 if compare_versions(v1, v2) >= 0 else v2


def resolve_json_conflict(content: str) -> str | None:
    """
    Resolve conflicts in a JSON file by merging and taking max versions.
    Returns resolved content or None if resolution failed.
    """
    # Check if there are conflict markers
    if "<<<<<<< " not in content:
        return content  # No conflicts

    # Try to extract the two sides
    # For JSON files, we need to reconstruct valid JSON from each side

    # Pattern: entire file might be conflicted, or just parts
    # Handle the case where the conflict is within the JSON object

    lines = content.split("\n")
    ours_lines = []
    theirs_lines = []
    in_conflict = False
    in_ours = False
    in_theirs = False

    for line in lines:
        if line.startswith("<<<<<<< "):
            in_conflict = True
            in_ours = True
            continue
        elif line.startswith("=======") and in_conflict:
            in_ours = False
            in_theirs = True
            continue
        elif line.startswith(">>>>>>> ") and in_conflict:
            in_conflict = False
            in_theirs = False
            continue

        if in_conflict:
            if in_ours:
                ours_lines.append(line)
            elif in_theirs:
                theirs_lines.append(line)
        else:
            ours_lines.append(line)
            theirs_lines.append(line)

    # Try to parse each side as JSON
    try:
        ours_json = json.loads("\n".join(ours_lines))
        theirs_json = json.loads("\n".join(theirs_lines))
    except json.JSONDecodeError:
        # Try reconstructing by merging base with conflict portions
        # This handles partial conflicts within the file
        return resolve_partial_json_conflict(content)

    # Merge: take max version for each component
    # Preserve key order: use theirs (main) as base, then add any new keys from ours
    merged = {}
    # First, add all keys from theirs (main branch) to preserve order
    for key in theirs_json:
        theirs_val = theirs_json[key]
        ours_val = ours_json.get(key)
        if ours_val is None:
            merged[key] = theirs_val
        else:
            # Both have the key - take max version
            try:
                merged[key] = max_version(ours_val, theirs_val)
            except ValueError:
                # Not a semver, just take theirs (main branch)
                merged[key] = theirs_val

    # Then add any keys only in ours
    for key in ours_json:
        if key not in merged:
            merged[key] = ours_json[key]

    # Format with consistent ordering
    return json.dumps(merged, indent=2) + "\n"


def resolve_partial_json_conflict(content: str) -> str | None:
    """
    Handle conflicts where only part of the JSON is conflicted.
    This reconstructs the JSON by parsing conflict regions separately.

    Note: This fallback function does not preserve key ordering from main.
    It is only used when the primary JSON parsing fails.
    """
    # Remove conflict markers and collect all key-value pairs
    # Then deduplicate by taking max versions

    all_pairs: dict[str, str] = {}

    # Remove conflict markers and extract all "key": "value" pairs
    # This is a simplified approach that works for flat JSON objects

    # First, get clean lines from both sides
    lines = content.split("\n")
    clean_lines = []

    for line in lines:
        if (
            line.startswith("<<<<<<< ")
            or line.startswith("=======")
            or line.startswith(">>>>>>> ")
        ):
            continue
        clean_lines.append(line)

    # Extract key-value pairs using regex
    pair_pattern = r'"([^"]+)":\s*"([^"]+)"'

    for line in clean_lines:
        for match in re.finditer(pair_pattern, line):
            key, value = match.group(1), match.group(2)
            if key in all_pairs:
                # Take max version, keep existing if not valid semver
                with contextlib.suppress(ValueError):
                    all_pairs[key] = max_version(all_pairs[key], value)
            else:
                all_pairs[key] = value

    if not all_pairs:
        return None

    return json.dumps(all_pairs, indent=2) + "\n"


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

    resolved = resolve_json_conflict(content)

    if resolved is None:
        print(f"Failed to resolve conflicts in {file_path}", file=sys.stderr)
        return 1

    # Validate the result is valid JSON
    try:
        json.loads(resolved)
    except json.JSONDecodeError as e:
        print(f"Resolved content is not valid JSON: {e}", file=sys.stderr)
        return 1

    file_path.write_text(resolved)
    print(f"Resolved conflicts in {file_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
