# Progress

_Last updated: 2026-09-30_

## Overall status

The PRD is drafted (v0.3). Phase 1 foundation scaffolding is in progress.

## Completed

- [x] PRD v0.2: initial structure
- [x] PRD v0.3: threat model, repository layout, sample app, stable IDs, `status_history`, query specification, test requirements, scanner updates, and resolved decisions
- [x] Development memory bank created

## Phase checklist

- [ ] **Phase 1: Foundation** — repository skeleton, portable `AGENTS.md`, Python package/CLI surface, `.gitignore`, and development-tool decisions are scaffolded; Git/dependency verification and the initial commit remain
- [ ] **Phase 2: Schema & Templates** — create the folder structure, README, `agents.md`, front matter schema, naming rules, `tags.yaml`, workflows, lint checklist, and six templates
- [ ] **Phase 3: Tooling & Skills** — build `wiki_tool` (catalog with body text, manifest hashes, coverage, validation, query, and audit), pytest fixtures, and ingest/maintain/query/lint skills
- [ ] **Phase 4: Manual Validation** — create `sample-app/`, run Trivy/Checkov/gitleaks, hand-ingest findings, run maintain, verify queries, and test each stage separately
- [ ] **Phase 5: CI Automation** — add scanning, stable-ID redacted idempotent capture, required lint/test checks, and scheduled maintenance
- [ ] **Phase 6: Review Loop** — implement draft -> proposed -> approve -> apply and add a prompt-injection fixture
- [ ] **Phase 7: Local Model, Launchers & Firewall** — integrate Ollama, add Windows launchers, and build/test the Obsidian-safe wrapper
- [ ] **Phase 8: Packaging & Demo** — Dockerize the tooling, write install docs, add an architecture diagram and CI badge, document limitations, and record the walkthrough

## Known risks

- The stable-ID scheme is unresolved and affects idempotent capture in Phase 5.
- Local model quality is unknown; the workflow should be proven with a stronger agent before Ollama is introduced.
- The firewall is a guardrail, not a hard security boundary; this limitation must remain documented.

## Decision log

| Date | Decision |
|---|---|
| 2026-09-30 | Created the development memory bank at `memory-bank/` from PRD v0.3 |
| 2026-09-30 | Chose `.agents/skills/` as the portable product skill location; made `AGENTS.md` the cross-agent entry point and kept memory-bank/Cursor rules as build-time context |
| 2026-09-30 | Started Phase 1: added repository skeleton, Python packaging metadata, and `wiki_tool` CLI stubs |
