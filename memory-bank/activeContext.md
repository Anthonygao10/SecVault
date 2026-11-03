# Active Context

_Last updated: 2026-11-03_

## Current focus

Planning is complete at the PRD level (v0.5). Phases 1 through 5 are complete.
The build-time memory bank and Cursor rules are assistant context;
the portable product entry point is `AGENTS.md`, with product skills under
`.agents/skills/`. The next work is Phase 6: the review loop.

## Immediate next steps

1. Implement draft -> `proposed/` -> approve -> apply, with validation and tests.
2. Add a prompt-injection fixture to the test suite.
3. Keep hosted CI free of LLM drafting; drafting remains local and reviewed.
4. Preserve the Phase 4 demo as the regression narrative for later phases.
5. Open GitHub decision: whether `main` requires pull requests and checks. Doing so blocks
   the capture bot's direct push, so it needs PR-based capture or a GitHub App bypass (see
   the GitHub setup record below).

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
- Main-branch capture commits raw evidence directly to `main` as `github-actions[bot]`. CI never writes to `wiki/`. Branch rules on `main` block only force-push and deletion, so the bot's direct push still works.
- Pull requests run a dry-run capture into a throwaway vault copy, upload an artifact, and use read-only permissions.
- Scheduled maintenance is report-only: no `manifest`, no commits.
- Hosted CI never runs an LLM.
- Integrity fix: a modified raw file keeps its recorded hash, so `manifest` and `audit` cannot re-bless it.
- Scanner archives are pinned and SHA-256 checked in `.github/actions/run-scanners/action.yml` and `.github/actions/install-gitleaks/action.yml`. Capture runs gitleaks without `--redact`, because finding IDs depend on the secret hash.

## Decisions made after Phase 5 (gate and pins)

- Third-party actions are pinned to full commit SHAs, with the release in a trailing comment: `actions/checkout` v7.0.1, `actions/setup-python` v7.1.0, and `actions/upload-artifact` v7.0.2. All three run on node24. Dependabot proposes weekly updates, and `tests/test_workflows.py` fails on any unpinned third-party `uses:`.
- Repo-wide `secrets` gate: `gitleaks git --redact` over the full history, with `.github/gitleaks-gate.toml`. Its allowlist covers only `sample-app/`, and a test pins that list. Verification found no other hits in history, so no further entries were added.
- Gate output is redacted for public logs. Capture scans never use `--redact` or the gate config, because finding IDs need the real secret hash and capture must still see the demo findings.
- The gate scans history, so a secret that was committed and later deleted still fails it. Clearing one needs a reviewed allowlist entry; history is not rewritten.

## GitHub setup and first runs (2026-11-03)

- Repository: public at `https://github.com/Anthonygao10/SecVault`, by the user's choice. Commits on `main`: `c9282a1` (SHA pins), `4790d2d` (secrets gate), `8bdbc10` (docs), `18dfb07` (Checkov PATH fix), and `18c2aae` (the bot's capture commit, 36 raw notes).
- CI on push, run `41736149177`: `ci` (12s) and `secrets` (7s) passed on Ubuntu. This was the first Linux run of pytest and of the redacted full-history gate.
- The first push to the new repository did not start `scan-capture.yml`; the cause is unconfirmed. Later pushes triggered it normally.
- Manual capture dispatch `41736348555` failed at "Lint and test before committing": `python -m pytest` ran in the Checkov venv, because its bin directory was on `GITHUB_PATH`. Fixed in `18dfb07`: Checkov runs by path, and two tests guard the rule. Push run `41736759412` then passed, and the bot committed `18c2aae`.
- Idempotency: dispatch run `41737857294` printed "No new raw evidence to commit."
- PR dry run: PR #1 (closed unmerged, branch deleted). Its capture preview `41737591843` and the `ci` and `secrets` checks passed. The preview reported Trivy 9, Checkov 26, and gitleaks 1 findings, all already captured, 0 new. The artifact has no gitleaks report and no demo secret value. It holds all 45 raw source notes, not only new ones.
- Maintenance run `41737860429` (report-only): catalog current, 36 open findings, 0 candidates for fixed.
- Dependabot run `41736150743` passed. No pull requests are open.
- Ruleset `Protect main from rewrites` (id `26494248`) blocks force-push and deletion on `main`, with no bypass actors. A ruleset that also required pull requests was rejected (HTTP 422: the GitHub Actions integration must belong to the ruleset source or owner organization), so the checks are not enforced.
- Open decision: enforce pull requests and checks on `main` by either (a) PR-based capture, a design change that needs a PRD update, or (b) a GitHub App as the bypass actor, which needs a new app and a secret. Until then, `ci` and `secrets` report but gate nothing.

Follow-ups, in rough priority order:

1. Decide the enforcement path above.
2. Add `.github/actions/install-gitleaks/**` to the `scan-capture.yml` path filters.
3. Limit the preview artifact to new notes. It currently uploads the whole `raw/sources` folder.
4. Hash-lock Checkov (`pip install --require-hashes`).
5. Pin the runner image. `ubuntu-latest` now runs Ubuntu 26.04.1 LTS, and GitHub has announced a migration.
6. Revisit the bot-commit gap: `GITHUB_TOKEN` pushes do not start `ci.yml`, so the `secrets` gate does not scan the evidence commit. Revisit it with the PR-based option.
7. Review Dependabot's weekly pull requests, and require `ci` and `secrets` on them once enforcement exists.
8. Start Phase 6 (review loop).
