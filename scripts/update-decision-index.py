#!/usr/bin/env python3
"""
Update the decision records index with categorized lists.

This script scans all decision record markdown files, extracts their
category and title, and generates a categorized index page.
"""

import re
from pathlib import Path


def extract_metadata(filepath: Path) -> tuple[str, str] | None:
    """Extract title and category from a decision record file."""
    try:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return None

    # Extract title (# ADR-XXX: Title)
    title_match = re.search(r"^#+ (ADR-\d+: .+)$", content, re.MULTILINE)
    if not title_match:
        return None

    # Extract category
    category_match = re.search(r"\*\*Category:\*\* (\w+)", content)
    if not category_match:
        return None

    title = title_match.group(1)
    category = category_match.group(1)

    return title, category


def generate_index(docs_dir: Path) -> str:
    """Generate the categorized index content."""
    decision_dir = docs_dir / "decisions" / "generated-markdown"

    if not decision_dir.exists():
        print(f"Error: Decision records directory not found: {decision_dir}")
        return ""

    architecture = []
    development = []

    # Scan all markdown files
    for filepath in sorted(decision_dir.glob("*.md")):
        if filepath.name == "index.md":
            continue

        metadata = extract_metadata(filepath)
        if not metadata:
            continue

        title, category = metadata
        link = f"- [{title}]({filepath.name})"

        if category == "architecture":
            architecture.append(link)
        else:
            development.append(link)

    # Generate the index content
    content = f"""# Decision Records

This section contains Architecture Decision Records (ADRs) documenting significant architectural and design decisions made during the development of the Keycloak Operator.

## Browse by Category

### Architecture Decisions ({len(architecture)} records)
Core design decisions affecting system structure, behavior, and runtime characteristics.

### Development Decisions ({len(development)} records)
Tooling, processes, testing strategies, and development workflow decisions.

## About ADRs

Architecture Decision Records capture important architectural decisions along with their context and consequences. Each ADR documents:

- **Decision**: What was decided
- **Context**: Why the decision was needed
- **Rationale**: Why this particular solution was chosen
- **Consequences**: Expected positive and negative outcomes
- **Alternatives**: Other options considered and why they were rejected

## Key Decision Records

Here are some particularly important ADRs for understanding the system:

- **[ADR-017](017-kubernetes-rbac-over-keycloak-security.md)**: Kubernetes RBAC over Keycloak security
- **[ADR-063](063-namespace-grant-list-authorization.md)**: Namespace grant list authorization (current model)
- **[ADR-040](040-admission-webhooks-for-validation.md)**: Admission webhooks for validation
- **[ADR-019](019-drift-detection-and-continuous-reconciliation.md)**: Drift detection
- **[ADR-001](001-kopf-as-operator-framework.md)**: Kopf as operator framework

## Architecture Decisions

{chr(10).join(architecture)}

## Development Decisions

{chr(10).join(development)}
"""

    return content


def main():
    """Main entry point."""
    # Get repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    docs_dir = repo_root / "docs"

    # Generate new index content
    print("Generating decision records index...")
    new_content = generate_index(docs_dir)

    if not new_content:
        print("Error: Could not generate index content")
        return 1

    # Write to index file
    index_file = docs_dir / "decisions" / "generated-markdown" / "index.md"

    try:
        with open(index_file, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"✓ Updated {index_file}")

        # Count records
        total_links = new_content.count("- [ADR-")

        print(f"  Total records: {total_links}")
        return 0
    except Exception as e:
        print(f"Error: Could not write index file: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
