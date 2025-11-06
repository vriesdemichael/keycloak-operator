#!/usr/bin/env python3
"""Convert ADR YAML files to Markdown for MkDocs."""

import sys
from pathlib import Path

import yaml


def yaml_to_markdown(yaml_path: Path) -> str:
    """Convert a single ADR YAML file to Markdown."""
    with open(yaml_path) as f:
        adr = yaml.safe_load(f)

    number = adr["number"]
    title = adr["title"]
    category = adr["category"]
    decision = adr["decision"]
    rationale = adr["rationale"]
    agent_instructions = adr.get("agent_instructions", "")
    provenance = adr.get("provenance", "unknown")
    rejected_alternatives = adr.get("rejected_alternatives", [])

    # Build markdown
    md = f"""# ADR-{number:03d}: {title}

**Category:** {category}
**Provenance:** {provenance}

## Decision

{decision}

## Rationale

{rationale}
"""

    if agent_instructions:
        md += f"""
## Agent Instructions

{agent_instructions}
"""

    if rejected_alternatives:
        md += "\n## Rejected Alternatives\n\n"
        for alt in rejected_alternatives:
            alternative = alt.get("alternative", "")
            reason = alt.get("reason", "")
            md += f"### {alternative}\n\n{reason}\n\n"

    return md


def main():
    """Convert ADR YAML file to Markdown."""
    if len(sys.argv) != 2:
        print("Usage: adr_to_markdown.py <yaml_file>", file=sys.stderr)
        sys.exit(1)

    yaml_path = Path(sys.argv[1])
    if not yaml_path.exists():
        print(f"Error: File not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)

    markdown = yaml_to_markdown(yaml_path)
    print(markdown)


if __name__ == "__main__":
    main()
