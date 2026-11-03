# Progress

_Last updated: 2026-11-03_

## Overall status

The PRD is drafted (v0.5). Phases 1 through 5 are complete; Phase 6 is next.

## Completed

- [x] PRD v0.2: initial structure
- [x] PRD v0.3: threat model, repository layout, sample app, stable IDs, `status_history`, query specification, test requirements, scanner updates, and resolved decisions
- [x] Development memory bank created
- [x] PRD v0.4: Phase 5 decisions and the raw-integrity fix (stable IDs, one raw note per finding, main-only capture, report-only maintenance)
- [x] PRD v0.5: repo-wide secret gate and SHA-pinned third-party actions
- [x] Public GitHub repo `Anthonygao10/SecVault`; CI, the secrets gate, capture, the PR dry run, and maintenance verified on GitHub-hosted runners (2026-11-03)

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

- Hosted workflows have run on GitHub-hosted runners (2026-11-03). One real bug surfaced and is fixed: the Checkov venv on `GITHUB_PATH` shadowed setup-python's `python` in the capture job. The run record is in `activeContext.md`.
- Branch rules on `main` block force-push and deletion only. Requiring pull requests would block the capture bot's direct push, so `ci` and `secrets` report on every push and PR but do not gate anything yet. This decision is open.
- Bot commits made with `GITHUB_TOKEN` do not start `ci.yml`, so the `secrets` gate does not scan the evidence commit. Capture output is redacted and hash-based by design.
- The path filters in `scan-capture.yml` do not include `.github/actions/install-gitleaks/**`, so a change only to that action does not trigger a capture.
- Checkov is pinned by version but not hash-locked.
- The repo-wide `secrets` gate scans full history. A secret committed and later deleted still fails it; clearing one needs a reviewed allowlist entry, because history is not rewritten. The allowlist covers only `sample-app/`.
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
| 2026-11-03 | Pinned third-party actions to commit SHAs (checkout v7.0.1, setup-python v7.1.0, upload-artifact v7.0.2; all node24) and enabled Dependabot updates |
| 2026-11-03 | Added the repo-wide `secrets` gate: `gitleaks git --redact` over full history, allowlist limited to `sample-app/`; capture keeps gitleaks defaults |
| 2026-11-03 | Created the public repo `Anthonygao10/SecVault`. Branch rules on `main` block force-push and deletion only; requiring pull requests is deferred because the GitHub Actions bypass is unavailable on a personal repo |
| 2026-11-03 | Kept the Checkov venv off `GITHUB_PATH`, which had shadowed setup-python's `python` in the capture job; Checkov runs by path, with regression tests |
