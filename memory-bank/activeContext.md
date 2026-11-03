# Active Context

_Last updated: 2026-11-03_

## Current focus

Planning is complete at the PRD level (v0.4). Phases 1 through 5 are complete.
The build-time memory bank and Cursor rules are assistant context;
the portable product entry point is `AGENTS.md`, with product skills under
`.agents/skills/`. The next work is Phase 6: the review loop.

## Immediate next steps

1. Implement draft -> `proposed/` -> approve -> apply, with validation and tests.
2. Add a prompt-injection fixture to the test suite.
3. Keep hosted CI free of LLM drafting; drafting remains local and reviewed.
4. Preserve the Phase 4 demo as the regression narrative for later phases.
5. Manual GitHub step: require the `ci` check in branch protection, and allow
   `github-actions[bot]` to push to `main` for capture (see Phase 5 decisions).

## Open questions

These remain open in PRD section 12:

- Which Ollama model gives acceptable drafts on the available hardware?

## Decisions already made

- Use a monorepo for v1.
- Keep the tag vocabulary strict and versioned; unknown tags fail lint.
- Use append-only `status_history`; a human confirms the `fixed` status.
- Use a vault-firewall wrapper with documented limitations.
- Treat Obsidian as an optional viewer; keep tooling filesystem-based.
- Build the model-agnostic review loop before integrating Ollama.
- Keep `wiki_tool` outside the Obsidian vault.
- Keep raw sources immutable and verify them with manifest hashes.

## Working conventions

- Follow the PRD phase order and commit at the end of every phase.
- Validate manually in Phase 4 before automating the workflow in Phase 5.
- Write tests alongside each validator rather than afterward.
- When a decision is made or an open question is resolved, update this file and the PRD changelog.
- Keep `memory-bank/` (development context for the coding assistant) separate from `vault/` (the product's own knowledge base).

## Decisions made during Phase 1

- Keep portable product skills in `.agents/skills/`; expose them to individual
  agents through their native adapter conventions.
- Make root `AGENTS.md` the cross-agent product entry point.
- Keep `memory-bank/` and `.cursor/rules/` as build-time context rather than
  product dependencies.
- Use Python 3.11+, `venv` + `pip`, PyYAML, pytest, and Ruff.

## Decisions made during Phases 2-4

- Use root `AGENTS.md` as the cross-agent product entry point and
  `.agents/skills/` as the portable skill source of truth.
- Keep raw source notes immutable; derive manifest `processed` state from
  authoritative wiki citations.
- Use Trivy 0.74.0, Checkov 3.3.20, and gitleaks 8.30.1 for the local demo.
- Require explicit human approval before applying generated drafts; all five
  Phase 4 drafts were approved before entering `wiki/`.

## Decisions made during Phase 5

- Stable finding ID: `sha256(scanner|rule_id|normalized_path|resource_or_secret_hash)[:12]`, with no line numbers. For gitleaks, the key is a hash of the secret value, which is never stored.
- One raw note per finding, named `source-YYYY-MM-DD-<scanner>-<rule>-<id>.md`. Notes are never rewritten.
- "Last seen" and "candidate fixed" state lives in `logs/capture-state.json`. A human confirms `fixed`.
- Main-branch capture commits raw evidence directly to `main` as `github-actions[bot]`. CI never writes to `wiki/`. Branch protection must allow the bot, or the job fails safely.
- Pull requests run a dry-run capture into a throwaway vault copy, upload an artifact, and use read-only permissions.
- Scheduled maintenance is report-only: no `manifest`, no commits.
- Hosted CI never runs an LLM.
- Integrity fix: a modified raw file keeps its recorded hash, so `manifest` and `audit` cannot re-bless it.
- Scanner archives are pinned and SHA-256 checked in `.github/actions/run-scanners/action.yml`. gitleaks runs without `--redact`, because finding IDs depend on the secret hash.
