# Decision Records

The repository uses YAML decision records in this directory to document architecture and development choices.

These files are part contributor reference, part machine-validated project contract. They are also consumed by generated documentation and by agent workflows described in the repository's `AGENTS.md`.

## Categories

Two categories are valid:

- `architecture`: system boundaries, technology choices, operational model, security model, data flow
- `development`: tooling, testing workflow, validation rules, contributor process, release or maintenance conventions

## File Naming

Each file uses this pattern:

```text
NNN-short-kebab-case-title.yaml
```

Examples:

- `017-kubernetes-rbac-over-keycloak-security.yaml`
- `088-blue-green-keycloak-upgrade-strategy.yaml`

## Required Fields

Every record is validated by the repository validator script.

Core fields:

| Field | Required | Description |
| --- | --- | --- |
| `number` | yes | sequential ADR number |
| `title` | yes | short human-readable title |
| `category` | yes | `architecture` or `development` |
| `decision` | yes | what was decided |
| `agent_instructions` | yes | concrete instructions agents should follow |
| `rationale` | yes | why the decision exists |
| `provenance` | yes | `human`, `guided-ai`, or `autonomous-ai` |

Lifecycle fields:

| Field | Required | Description |
| --- | --- | --- |
| `status` | no | `proposed`, `accepted`, `superseded`, or `deprecated` |
| `superseded_by` | no | ADR number that replaced this one |
| `supersedes` | no | one ADR number or a list of ADR numbers replaced by this record |

Optional supporting fields:

| Field | Required | Description |
| --- | --- | --- |
| `rejected_alternatives` | no | list of rejected options with reasons |

## Example Record

```yaml
number: 0
title: "Example decision"
category: architecture
status: accepted
decision: >
  Describe the choice that was made.
agent_instructions: >
  Describe how contributors and agents should apply this decision.
rationale: >
  Describe the pressure, trade-offs, and why this option won.
rejected_alternatives:
  - alternative: "Other option"
    reason: "Why it lost"
provenance: human
```

Setting `number: 0` is the supported way to request the next sequential number when creating a record through the helper script.

## Preferred Workflow

Use the task targets first. They are the contributor-facing entry points.

Validate decision records:

```bash
task quality:validate-decisions
```

Generate rendered Markdown from the YAML records:

```bash
task docs:generate-decisions
```

Build the full documentation site:

```bash
task docs:build
```

The lower-level commands are still useful when you need to work on the ADR tooling itself:

```bash
uv run scripts/adr_validator.py --validate
bash scripts/build-adr-docs.sh
```

## Creating A New Record

Use the validator's create mode so the file is schema-checked before it lands on disk.

```bash
cat <<'YAML' | uv run scripts/adr_validator.py --create
number: 0
title: "Use example title here"
category: development
status: proposed
decision: >
  State the decision clearly.
agent_instructions: >
  State the operational rule contributors and agents should follow.
rationale: >
  Explain the trade-offs and why this is the chosen path.
provenance: human
YAML
```

The script will:

- validate the YAML against the ADR schema
- assign the next number when `number: 0` is used
- create the correctly named file in `docs/decisions/`

## How YAML Becomes Published Docs

The repository does not hand-maintain Markdown copies of each ADR.

The documentation flow is:

1. Source YAML lives in `docs/decisions/*.yaml`.
2. `task docs:generate-decisions` runs `scripts/build-adr-docs.sh`.
3. That script calls `scripts/adr_to_markdown.py` for each record.
4. Generated pages land in `docs/decisions/generated-markdown/`.
5. MkDocs includes those generated pages during `task docs:build`.

This is why manual edits to generated Markdown are the wrong place to make lasting changes.

## Agent Guidance Boundary

This README explains the record format and contributor workflow.

Repository-specific agent behavior lives in `AGENTS.md`, including:

- when agents must read ADRs
- how ADR guidance interacts with user requests
- when agents should propose new decisions
- when agents must not modify existing records without approval

If this README and `AGENTS.md` ever disagree on agent workflow, `AGENTS.md` is the authoritative source.

The current ADR extraction command used by the repository guidance is:

```bash
for f in docs/decisions/*.yaml; do
  yq -c '{number: .number, title: .title, category: .category, agent_instructions: .agent_instructions}' "$f"
done
```

## When To Add A Decision Record

Add a new ADR when a change introduces or formalizes a durable rule, for example:

- a new reconciliation or deployment architecture
- a new backup or upgrade contract
- a new testing or release requirement
- a new security boundary or compatibility promise

Do not add one for every ordinary bug fix. If the change does not create a rule future contributors need to remember, it probably does not need an ADR.

## References

- Repository guidance: `AGENTS.md`
- Task definitions: `Taskfile.yml`
- Validator implementation: `scripts/adr_validator.py`
- Markdown generation script: `scripts/build-adr-docs.sh`
