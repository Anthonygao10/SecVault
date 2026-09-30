# Active Context

_Last updated: 2026-09-30_

## Current focus

Planning is complete at the PRD level (v0.3). Phases 1, 2, and 3 are complete.
The build-time memory bank and Cursor rules are assistant context;
the portable product entry point is `AGENTS.md`, with product skills under
`.agents/skills/`. Phase 4 is validating the end-to-end workflow against the
intentionally vulnerable sample app.

## Immediate next steps

1. Build the intentionally vulnerable Python sample app and Terraform
   configuration.
2. Run or document Trivy, Checkov, and gitleaks scans with fake credentials
   only.
3. Capture redacted scan findings as raw sources, draft proposed notes, apply
   an approved draft, and run the maintain/query/lint loop.
4. Verify raw hash protection, body-text query behavior, and the human review
   boundary.

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
