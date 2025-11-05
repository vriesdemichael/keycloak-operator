#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pydantic>=2.0", "PyYAML>=6.0"]
# ///
"""ADR validator and creator for the keycloak-operator project."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

DECISIONS_DIR = Path("docs/decisions")

TitleStr = str


class RejectedAlternative(BaseModel):
    """A rejected alternative with reasoning."""

    alternative: str
    reason: str


class DecisionRecordModel(BaseModel):
    """Decision Record model (Architecture or Development)."""

    number: int = Field(..., description="Sequential number (e.g., 1, 2, 3)")
    title: TitleStr = Field(
        ..., description="Brief description (e.g., 'Kopf as operator framework')"
    )
    category: Literal["architecture", "development"]
    decision: str
    agent_instructions: str
    rationale: str
    rejected_alternatives: list[RejectedAlternative] | None = None
    provenance: Literal["human", "guided-ai", "autonomous-ai"]


def slugify_title(title: str) -> str:
    """Convert title to slug for filename."""
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s[:80]


def read_yaml(path: Path) -> dict:
    """Read YAML file."""
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def validate_file(path: Path) -> None:
    """Validate a single decision record file."""
    data = read_yaml(path)
    try:
        DecisionRecordModel.model_validate(data)
    except ValidationError as e:
        print(f"VALIDATION ERROR in {path}:\n{e}", file=sys.stderr)
        raise SystemExit(2) from None
    print(f"✓ {path}")


def create_decision(
    number: int,
    title: str,
    category: str,
    decision: str,
    agent_instructions: str,
    rationale: str,
    provenance: str,
    rejected_alternatives: list[dict] | None = None,
) -> Path:
    """Create a new decision record file."""
    DECISIONS_DIR.mkdir(parents=True, exist_ok=True)

    # Determine next number if not provided
    if number == 0:
        existing = sorted(DECISIONS_DIR.glob("*.yaml"))
        numbers = []
        for p in existing:
            m = re.match(r"^(\d+)-", p.name)
            if m:
                numbers.append(int(m.group(1)))
        number = (max(numbers) + 1) if numbers else 1

    filename = f"{number:03d}-{slugify_title(title)}.yaml"
    path = DECISIONS_DIR / filename

    content = {
        "number": number,
        "title": title,
        "category": category,
        "decision": decision.strip(),
        "agent_instructions": agent_instructions.strip(),
        "rationale": rationale.strip(),
        "provenance": provenance,
    }

    if rejected_alternatives:
        content["rejected_alternatives"] = rejected_alternatives

    with path.open("w", encoding="utf-8") as fh:
        fh.write(yaml.safe_dump(content, sort_keys=False))
    return path


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    p = argparse.ArgumentParser(
        prog="decision_validator",
        description="Validate and create Decision Records (Architecture/Development)",
    )
    p.add_argument(
        "--validate",
        nargs="*",
        help="Files to validate (defaults to all in docs/decisions)",
        default=None,
    )
    p.add_argument(
        "--create", action="store_true", help="Create a decision record from stdin YAML"
    )
    args = p.parse_args(argv)

    if args.create:
        raw = sys.stdin.read()
        data = yaml.safe_load(raw)
        try:
            DecisionRecordModel.model_validate(data)
        except ValidationError as e:
            print(f"VALIDATION ERROR:\n{e}", file=sys.stderr)
            return 2
        path = create_decision(
            number=data.get("number", 0),
            title=data["title"],
            category=data["category"],
            decision=data["decision"],
            agent_instructions=data["agent_instructions"],
            rationale=data["rationale"],
            provenance=data["provenance"],
            rejected_alternatives=data.get("rejected_alternatives"),
        )
        print(f"✓ Created {path}")
        return 0

    if args.validate is not None:
        files = args.validate if args.validate else list(DECISIONS_DIR.glob("*.yaml"))
        if not files:
            print("No decision record files found", file=sys.stderr)
            return 0
        for f in files:
            validate_file(Path(f))
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
