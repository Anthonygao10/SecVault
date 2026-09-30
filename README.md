# SecVault

SecVault is a portable, git-versioned security memory layer for AI coding
agents. It captures raw security findings, compiles reviewed notes into an
Obsidian-compatible wiki, and enforces the schema with deterministic Python
tooling.

## Project status

The repository is currently in Phase 1: Foundation. The vault schema,
templates, tooling commands, and workflow skills are being built in the
following phases.

Read `AGENTS.md` before working on the product. The product's vault
constitution will live at `vault/agents.md` after Phase 2.

## Development setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m wiki_tool --help
```

The tooling is filesystem-only and does not require Obsidian to be running.
Obsidian is an optional viewer and local interactive integration.
