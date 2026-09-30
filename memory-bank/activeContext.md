# Active Context

_Last updated: 2026-09-30_

## Current focus

Planning is complete at the PRD level (v0.3). Phase 1 is complete. The
build-time memory bank and Cursor rules are assistant context;
the portable product entry point is `AGENTS.md`, with product skills under
`.agents/skills/`.

## Immediate next steps

1. Build `vault/agents.md`, the schema documents, and the six templates for
   Phase 2.
2. Define the note types and tag vocabulary so Phase 3 validators have a
   stable contract.
3. Install the Obsidian-aware skills and enable the Obsidian CLI for local
   interactive use if desired.
4. Continue to keep `wiki_tool` filesystem-only; Obsidian setup is optional
   local viewer configuration.

## Open questions

These remain open in PRD section 12:

- Which coding agent(s) should be used for the primary demo and for testing agent-agnosticism?
- Which Ollama model gives acceptable drafts on the available hardware?
- What stable-ID scheme should be used when code moves between lines or files?
- Should scheduled maintenance auto-open a PR or only report?

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
