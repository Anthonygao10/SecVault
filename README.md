# SecVault

SecVault is a portable, git-versioned security memory layer for AI coding
agents. It captures raw security findings, compiles reviewed notes into an
Obsidian-compatible wiki, and enforces the schema with deterministic Python
tooling.

## Project status

Phases 1 through 6 are complete: the vault schema and templates, the
`wiki_tool` commands, the repo-local skills, a manually validated sample app,
CI automation, and the review loop. Phase 7 (a local model) is next.

Read `AGENTS.md` before working on the product. The product's vault
constitution lives at `vault/agents.md`.

## Development setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m wiki_tool --help
```

The tooling is filesystem-only and does not require Obsidian to be running.
Obsidian is an optional viewer and local interactive integration.

## Commands

```powershell
.\.venv\Scripts\python.exe -m wiki_tool capture --scanner trivy --input report.json --path-prefix sample-app --vault vault
.\.venv\Scripts\python.exe -m wiki_tool report --vault vault
.\.venv\Scripts\python.exe -m wiki_tool lint --vault vault
```

`capture` accepts Trivy, Checkov, or gitleaks JSON. It redacts secret-like
values, writes one raw note per finding, and refuses to run when the vault does
not lint cleanly. `report` is read-only.

### Review loop

Drafts land in `vault/proposed/`. A person reviews them and records the decision:

```powershell
.\.venv\Scripts\python.exe -m wiki_tool proposed --vault vault
.\.venv\Scripts\python.exe -m wiki_tool review proposed\<draft>.md --vault vault
.\.venv\Scripts\python.exe -m wiki_tool approve proposed\<draft>.md --vault vault --reviewer "<name>"
.\.venv\Scripts\python.exe -m wiki_tool apply proposed\<draft>.md --vault vault
```

`approve` runs only in an interactive terminal. It shows the review packet and
asks for the first 12 characters of the draft's SHA-256, and it has no `--yes`
flag. `apply` refuses any draft without a current approval, so a draft written
by an agent cannot reach `vault/wiki/` on its own. Approval is bound to the
draft's exact bytes, and an edit after approval makes it stale.

## Continuous integration

- **`ci`** runs Ruff, pytest, and vault lint on pull requests and pushes to
  `main`. They report on every push and pull request. Requiring them before merge
  would need a pull-request rule, which blocks the capture bot's direct push, so this
  repository does not enforce them yet.
- **`secrets`** runs gitleaks over the full git history on the same events. It
  uses `--redact`, so public logs never print secret values. The check fails on
  any secret, including one that was committed and later deleted. The allowlist in
  `.github/gitleaks-gate.toml` skips only `sample-app/`, which holds intentionally
  fake secrets. Capture scans run gitleaks without that config and without
  `--redact`, because their finding IDs need the real secret hash.
- **Scan and capture** runs the pinned scanners (Trivy 0.74.0, gitleaks 8.30.1,
  Checkov 3.3.20) on `sample-app/`. Pull requests get a dry-run preview artifact.
  A push to `main` commits new raw notes as `github-actions[bot]`. The ruleset on
  `main` blocks only force-push and deletion, so that push is allowed. If a push is
  ever rejected, the job fails, and the next run recomputes the same findings.
- **Maintenance report** runs weekly and publishes a summary only.
- Third-party actions are pinned to full commit SHAs, with the release in a
  trailing comment. Dependabot opens weekly pull requests to update them, and a
  test fails if any third-party `uses:` reference is not pinned.

Hosted CI never runs a language model. Drafting stays local and goes through
human review.
