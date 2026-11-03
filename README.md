# SecVault

SecVault is a portable, git-versioned security memory layer for AI coding
agents. It captures raw security findings, compiles reviewed notes into an
Obsidian-compatible wiki, and enforces the schema with deterministic Python
tooling.

## Project status

Phases 1 through 5 are complete: the vault schema and templates, the
`wiki_tool` commands, the repo-local skills, a manually validated sample app,
and CI automation. Phase 6 (the review loop) is next.

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

## Continuous integration

- **`ci`** runs Ruff, pytest, and vault lint on pull requests and pushes to
  `main`. Mark it as a required status check in branch protection.
- **Scan and capture** runs the pinned scanners (Trivy 0.74.0, gitleaks 8.30.1,
  Checkov 3.3.20) on `sample-app/`. Pull requests get a dry-run preview artifact.
  A push to `main` commits new raw notes as `github-actions[bot]`. Branch
  protection must allow that push. If it does not, the job fails, and the next
  run recomputes the same findings.
- **Maintenance report** runs weekly and publishes a summary only.

Hosted CI never runs a language model. Drafting stays local and goes through
human review.
