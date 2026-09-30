# Tech Context

## Stack

| Component | Choice |
|---|---|
| Knowledge base | Obsidian vault (Markdown, YAML front matter, wiki links); viewer/editor only |
| Obsidian CLI | Local interactive agent sessions only; not in CI or Docker |
| Version control | Git, with commits at each workflow stage and a private remote |
| Tooling | Python 3.11+ (`wiki_tool`) with `venv` + `pip`, PyYAML, pytest, and Ruff |
| Coding agent | Any agentic coding tool; agent-agnostic by design |
| Local model | Ollama; model selection is still open |
| CI/CD | GitHub Actions for scanning, capture, lint/test gates, and scheduled maintenance |
| Security scanning | Trivy, Checkov, gitleaks, project linters, and project tests |
| Packaging | Docker image for tooling and scripts |
| Access control | Obsidian-safe wrapper script and skill with a vault allowlist |

## Development environment

- OS: Windows 10 (win32 10.0.19045)
- Shell: PowerShell
- Workspace: `C:\Users\Antho\Downloads\Personal Projects\SecVault`
- Windows launchers are required (`.bat`/`.ps1`) for checking raw sources, drafting with Ollama, and applying the latest draft.
- Scripts and documentation must handle Windows paths and PowerShell quoting safely.

## Constraints

- `wiki_tool` operates on plain files and must not require Obsidian.
- LLM drafting does not run in hosted CI runners because they have no GPU and local models are unsuitable there.
- `sample-app/` is intentionally insecure: SQL injection, a hardcoded fake secret, weak input validation, and Terraform misconfigurations such as a public S3 bucket and over-permissive IAM.
- The sample app must be clearly labeled and must never contain real credentials.
- Python scripts live outside `vault/` because Obsidian does not read them.
- `.gitignore` must exclude local configuration and Obsidian workspace files.

## Testing requirements

The pytest suite uses good and bad fixture vaults and covers every validator. At minimum:

- A valid vault passes.
- Missing front matter fails with a clear message.
- An unknown tag fails with a clear message.
- A broken link fails with a clear message.
- A missing source citation fails with a clear message.
- A modified raw file fails hash validation with a clear message.
- Redaction removes seeded fake secrets, including AWS-style keys, tokens, and private-key headers.
- A prompt-injection fixture is added during the review-loop phase.

The suite runs in CI.

## Tutorial-derived skills

The planned Obsidian skill pack includes CLI, Markdown, Bases, Canvas, and Defuddle skills so agents write valid Obsidian syntax and links. The Obsidian CLI is enabled only for interactive local sessions and is never used by CI or Docker.

## Current technical state

Phases 1 through 4 are complete. The repository uses Python 3.11+, a
standard-library `venv` managed with `pip`, PyYAML as the runtime dependency,
pytest for tests, and Ruff for linting/formatting. The initial `wiki_tool`
command surface is implemented as filesystem-only operations. The vault
schema, versioned tag vocabulary, workflows, templates, portable skills, and
pytest fixtures are defined; Phase 4 validates the complete workflow.
The demo uses Trivy 0.74.0, Checkov 3.3.20, and gitleaks 8.30.1. Scanner
binaries are local ignored tools; their redacted findings are captured under
`vault/raw/sources/`.
