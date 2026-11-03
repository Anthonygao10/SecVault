# Progress

_Last updated: 2026-11-03_

## Overall status

The PRD is drafted (v0.4). Phases 1 through 5 are complete; Phase 6 is next.

## Completed

- [x] PRD v0.2: initial structure
- [x] PRD v0.3: threat model, repository layout, sample app, stable IDs, `status_history`, query specification, test requirements, scanner updates, and resolved decisions
- [x] Development memory bank created
- [x] PRD v0.4: Phase 5 decisions and the raw-integrity fix (stable IDs, one raw note per finding, main-only capture, report-only maintenance)

## Phase checklist

- [x] **Phase 1: Foundation** — repository skeleton, portable `AGENTS.md`, Python package/CLI surface, `.gitignore`, development-tool decisions, local environment, validation, and initial commit
- [x] **Phase 2: Schema & Templates** — create the folder structure, README, `agents.md`, front matter schema, naming rules, `tags.yaml`, workflows, lint checklist, and six templates
- [x] **Phase 3: Tooling & Skills** — build `wiki_tool` (catalog with body text, manifest hashes, coverage, validation, query, and audit), pytest fixtures, and ingest/maintain/query/lint skills
- [x] **Phase 4: Manual Validation** — create `sample-app/`, run Trivy/Checkov/gitleaks, hand-ingest findings, run maintain, verify queries, and test each stage separately
- [x] **Phase 5: CI Automation** — add scanning, stable-ID redacted idempotent capture, required lint/test checks, and scheduled maintenance
- [ ] **Phase 6: Review Loop** — implement draft -> proposed -> approve -> apply and add a prompt-injection fixture
- [ ] **Phase 7: Local Model, Launchers & Firewall** — integrate Ollama, add Windows launchers, and build/test the Obsidian-safe wrapper
- [ ] **Phase 8: Packaging & Demo** — Dockerize the tooling, write install docs, add an architecture diagram and CI badge, document limitations, and record the walkthrough

## Known risks

- Hosted workflows are validated locally (actionlint, a YAML parse, and the workflows' own bash blocks run against a clone), but they have not run on GitHub-hosted runners yet. The first run on `main` is the real test.
- Branch protection may block the bot's direct push to `main`. The capture job then fails safely; configure protection to allow it.
- gitleaks coverage in CI is limited to `sample-app/`. A repo-wide gitleaks gate with an allowlist is a follow-up.
- Local model quality is unknown; the workflow should be proven with a stronger agent before Ollama is introduced.
- The firewall is a guardrail, not a hard security boundary; this limitation must remain documented.

## Decision log

| Date | Decision |
|---|---|
| 2026-09-30 | Created the development memory bank at `memory-bank/` from PRD v0.3 |
| 2026-09-30 | Chose `.agents/skills/` as the portable product skill location; made `AGENTS.md` the cross-agent entry point and kept memory-bank/Cursor rules as build-time context |
| 2026-09-30 | Started Phase 1: added repository skeleton, Python packaging metadata, and `wiki_tool` CLI stubs |
| 2026-11-03 | Phase 5: stable finding IDs (12-hex, no line numbers); one raw note per finding; capture state in `logs/capture-state.json` |
| 2026-11-03 | Phase 5: main-only capture commits raw evidence directly to `main` as the bot; PRs run a dry run with read-only permissions; scheduled maintenance is report-only |
| 2026-11-03 | Phase 5: fixed the raw-integrity gap (`audit` re-blessed modified raw files); capture job lints and tests before committing |
