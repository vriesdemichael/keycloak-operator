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
from pydantic import BaseModel, Field, ValidationError, model_validator

ADRS_DIR = Path("docs/architecture/decisions")

TitleStr = str


class ADRModel(BaseModel):
    """Architecture Decision Record model."""

    title: TitleStr = Field(
        ..., description="Numeric id + title, e.g. '42 Service-side feature-flagging'"
    )
    status: Literal["accepted", "proposed", "deprecated", "superseded"]
    decision: str
    agent_instructions: str
    rationale: str
    provenance: Literal["human", "ai"]
    superseded_by: str | None = None

    @model_validator(mode="after")
    def check_agent_instructions_has_yq(self):
        """Validate agent_instructions contains yq snippet."""
        ai = self.agent_instructions
        if not re.search(r"\byq\b", ai):
            raise ValueError(
                "agent_instructions must contain a yq snippet the agent can run (contains 'yq')."
            )
        if "keep" not in ai.lower() and "context" not in ai.lower():
            raise ValueError(
                "agent_instructions should tell the agent to keep the retrieved instructions in its context."
            )
        return self

    @model_validator(mode="after")
    def check_superseded_status(self):
        """Validate superseded status has superseded_by field."""
        if self.status == "superseded" and not self.superseded_by:
            raise ValueError("superseded status requires superseded_by field")
        return self


def slugify_title(title: str) -> str:
    """Convert title to slug for filename."""
    s = re.sub(r"^\d+\s+", "", title)
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:80]


def read_yaml(path: Path) -> dict:
    """Read YAML file."""
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def validate_file(path: Path) -> None:
    """Validate a single ADR file."""
    data = read_yaml(path)
    try:
        ADRModel.model_validate(data)
    except ValidationError as e:
        print(f"VALIDATION ERROR in {path}:\n{e}", file=sys.stderr)
        raise SystemExit(2) from None
    print(f"✓ {path}")


def create_adr(
    title: str,
    decision: str,
    agent_instructions: str,
    rationale: str,
    provenance: str,
    status: str = "accepted",
) -> Path:
    """Create a new ADR file."""
    ADRS_DIR.mkdir(parents=True, exist_ok=True)
    existing = sorted(ADRS_DIR.glob("*.yaml"))
    ids = []
    for p in existing:
        m = re.match(r"^(\d+)-", p.name)
        if m:
            ids.append(int(m.group(1)))
    next_id = (max(ids) + 1) if ids else 1
    filename = f"{next_id:03d}-{slugify_title(title)}.yaml"
    path = ADRS_DIR / filename
    content = {
        "title": f"{next_id} {title}",
        "status": status,
        "decision": decision.strip(),
        "agent_instructions": agent_instructions.strip(),
        "rationale": rationale.strip(),
        "provenance": provenance,
    }
    with path.open("w", encoding="utf-8") as fh:
        fh.write(yaml.safe_dump(content, sort_keys=False))
    return path


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    p = argparse.ArgumentParser(
        prog="adr_validator",
        description="Validate and create Architecture Decision Records",
    )
    p.add_argument(
        "--validate",
        nargs="*",
        help="Files to validate (defaults to all in docs/architecture/decisions)",
        default=None,
    )
    p.add_argument(
        "--create", action="store_true", help="Create an ADR from stdin YAML"
    )
    args = p.parse_args(argv)

    if args.create:
        raw = sys.stdin.read()
        data = yaml.safe_load(raw)
        try:
            ADRModel.model_validate(data)
        except ValidationError as e:
            print(f"VALIDATION ERROR:\n{e}", file=sys.stderr)
            return 2
        path = create_adr(
            title=data["title"],
            decision=data["decision"],
            agent_instructions=data["agent_instructions"],
            rationale=data["rationale"],
            provenance=data["provenance"],
            status=data.get("status", "accepted"),
        )
        print(f"✓ Created {path}")
        return 0

    if args.validate is not None:
        files = args.validate if args.validate else list(ADRS_DIR.glob("*.yaml"))
        if not files:
            print("No ADR files found", file=sys.stderr)
            return 0
        for f in files:
            validate_file(Path(f))
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
