# GitHub Copilot Instructions

All authoritative project guidance lives in [`AGENTS.md`](../AGENTS.md). Keep that file as the single source of truth for architecture, workflows, and development expectations.

## How to work in this repo
- Start every new task by reviewing `AGENTS.md`, paying particular attention to the sections on project status, requirements, and testing habits.
- Follow the documented task commands and `uv` usage in `AGENTS.md` when running quality checks, tests, or cluster automation.
- If you discover gaps or stale content, update `AGENTS.md` directly and reference the change here only if you add new sections.


## Maintenance note
Whenever these instructions need refinement, prefer improving `AGENTS.md` and keeping this file as a thin pointer so every AI assistant reads the same canonical guidance.

## Copilot specific instructions, not for other AI integrations:
Do not edit commands using sed or other cli tools. This messes up the tracking of your edits and requires manual merging and issues where the files you edited have different content than what you expect. Instead, make the changes directly in the files using your integrated edit tools.
