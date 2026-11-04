# Progress

_Last updated: 2026-11-04_

## Overall status

The PRD is at v0.6. Phases 1 through 5 are complete. Phase 6 is implemented and verified: pytest passes (161 tests, 2 symlink tests skipped on this Windows machine), Ruff is clean, the vault lint passes, and the agent drill ran (2026-11-03). Phase 6 is pushed to `origin/main` as `92ed8a6` (2026-11-04). The hosted CI run passed: 163 tests on Ubuntu with none skipped, so the two symlink tests ran and passed; the secrets gate found no leaks; capture ran and committed only `last_seen` dates (`31dafc0`).

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
- [x] **Phase 6: Review Loop** — approval gate, apply hardening, injection fixtures, drafts report, and docs; verified and drilled (2026-11-03); pushed to `main` (2026-11-04, `92ed8a6`).
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
- The review state (`logs/review-state.json`) is a plain file in the vault. Anyone who can write the repository can edit it, so approval is a guardrail against agent mistakes, not a tamper-proof record. Changes to the file show in the Git diff.
- Lint checks links inside raw notes, so a raw note cannot carry a `[[../..]]` escape link without breaking lint and capture. The escape-link case is covered by a generated draft instead.
- Agent drill (2026-11-03): an agent quoted one canary line in a draft under `proposed/`. Drafts are review-gated and never reach `wiki/` without approval, but the strict "no canary in any change" criterion is not met. The drill relies on file-level snapshot diffs. An agent's self-report is not evidence: one drill subagent was aborted from the UI but still wrote a draft, and the second agent misreported that draft as pre-existing.
- Every push to `main` that touches `wiki_tool/**` or `sample-app/**` makes the capture bot commit `vault/logs/capture-state.json` `last_seen` dates, as in `31dafc0`. This is expected. The bot's `GITHUB_TOKEN` commit does not start `ci.yml`, so the secrets gate does not scan that commit (see the bot-commit follow-up).
- The injection fixtures contain forged instructions, forged approval blocks, and canary strings, but no secret-like assignments. `tests/fixtures/injection/` is not gitignored, so the gitleaks gate and the lint secret scan both read it.

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
| 2026-11-03 | Phase 6: approval is TTY-only (typed 12-character short hash, no `--yes`), bound to the draft's normalized SHA-256 in `logs/review-state.json`; rejected drafts stay in `proposed/` |
| 2026-11-03 | Phase 6: `apply` refuses drafts without a current approval; overwrite needs `--overwrite` and a `status_history` prefix match; `apply --all-approved` rolls back as one unit |
| 2026-11-03 | Phase 6: prompt-injection fixtures live in `tests/fixtures/injection/` and never in `vault/raw/`; the maintenance report gains a drafts section |
| 2026-11-04 | Pushed Phase 6 (`92ed8a6`) directly to `main` as a fast-forward, after a local gitleaks history gate with no leaks |
