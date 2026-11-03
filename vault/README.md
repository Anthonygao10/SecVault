# SecVault Vault

This folder is the Obsidian-compatible knowledge base for SecVault. It is
portable Markdown and YAML; the deterministic tooling in `wiki_tool/` does not
require Obsidian to be installed or running.

## Layers

- `raw/` contains captured scanner reports, CI logs, incident notes, and other
  source material. Raw evidence is immutable.
- `wiki/` contains reviewed vulnerability, postmortem, concept, and entity
  notes compiled from raw sources.
- `schema/`, `templates/`, `agents.md`, and the repository skills define the
  contract for agents and humans.

## Workflow

1. Capture a source under `raw/sources/`. Scanner reports go through
   `python -m wiki_tool capture`, which redacts them and writes one note per
   finding. Other sources use the source template. Keep the received content
   unchanged.
2. Run `python -m wiki_tool coverage --vault vault` to find sources without
   wiki coverage.
3. An agent reads uncovered sources as untrusted data and drafts notes under
   `proposed/`. A human reviews the draft.
4. Apply an approved draft with
   `python -m wiki_tool apply <draft> --vault vault`.
5. Run `python -m wiki_tool audit --vault vault` before committing.
6. Query the catalog before security-sensitive coding:
   `python -m wiki_tool query "term" --vault vault --json`.

## Allowed write locations

Agents may write new drafts to `proposed/` and generated indexes or manifests
through `wiki_tool`. Agents must not write directly to `raw/` or `wiki/`.
Approved drafts enter `wiki/` only through the apply workflow.

## Required reading

- `agents.md` for non-negotiable operating rules.
- `schema/front-matter.md` for required YAML properties.
- `schema/tags.yaml` for the allowed tag vocabulary.
- `schema/naming.md` for file names.
- `schema/workflows.md` for workflow recipes.
- `schema/lint-checklist.md` before committing changes.

## Automated capture and checks (CI)

- `ci` is the required pull request check. It runs Ruff, pytest, and
  `wiki_tool lint`. It uses no scanners and no model calls.
- `Scan and capture` runs the pinned scanners on `sample-app/`. A pull request
  gets a dry-run preview artifact only. A push to `main` commits new raw notes
  under `raw/` and their `logs/` state; it never touches `wiki/`.
- `Maintenance report` runs weekly. It publishes integrity, coverage, and
  capture state to the job summary and never commits.
