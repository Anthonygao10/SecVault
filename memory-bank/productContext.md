# Product Context

## Problem
A coding assistant starts every session with zero knowledge of a project's past security bugs. The same classes of problem (SQL injection, hardcoded secrets, over-permissive IAM) get rediscovered repeatedly, and scanner output is lost after a single PR check.

## Intended user experience
- **Developer:** pushes code; CI scans and captures findings. Later, on their machine, they run ingest, the agent drafts notes into `proposed/`, they review and approve, and the maintain loop finalizes and commits.
- **Coding assistant:** before touching security-sensitive code, runs the query skill against the catalog and surfaces related past findings with source citations.
- **Reviewer:** focuses on severity, status, root-cause accuracy, and correct source citation of drafts.

## Key user flows
1. Push -> GitHub Actions runs Trivy, Checkov, gitleaks, tests -> normalized, redacted findings written to `raw/sources/`.
2. Manual capture (Obsidian Web Clipper, pasted incident notes) uses the same source template.
3. Ingest skill finds uncovered raw sources -> agent drafts to `proposed/` using templates.
4. Human approves -> apply step writes to wiki (refuses to overwrite without confirmation) -> maintain loop rebuilds catalog, lints, updates manifest, logs, commits.
5. PR merge gate re-runs lint and tests.
6. Later coding session queries the catalog and recalls the finding.

## Note types (templates)
Source, Vulnerability (severity, CWE/OWASP, component, status, append-only `status_history`, fix commit), Bug postmortem, Concept, Entity, Log.

## Finding lifecycle
`status` (open / fixed / accepted) is never silently overwritten. Each change appends to `status_history` (status, date, commit/PR ref, note). Findings that stop appearing in scans become "candidate fixed"; a human confirms.

## Demo narrative (Phase 8)
Scan finds a vulnerability -> raw entry created -> agent drafts a record -> human approves -> lint passes -> a later coding session recalls the finding.

## Privacy stance
Local-first (Ollama) by default. Unfixed vulnerability records are sensitive and never sent to hosted models unless the user opts in. Repo private by default; this portfolio copy is public, by choice (2026-11-03).
