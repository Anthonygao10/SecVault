# Front Matter Schema

All Markdown notes use YAML front matter delimited by `---`. Dates use ISO
format: `YYYY-MM-DD`. Lists must remain YAML lists, even when they contain one
item.

## Common wiki fields

Required for every note under `wiki/`, `proposed/`, and `logs/`:

| Field | Type | Rule |
|---|---|---|
| `type` | string | One of the note types below. |
| `title` | string | Human-readable title; must match the note title. |
| `tags` | list of strings | Every tag must be in `tags.yaml`. |
| `created` | date | Creation date. |
| `updated` | date | Last metadata or content update. |
| `sources` | list of wiki-links | At least one resolvable raw source for wiki notes. |

## Source fields

Source notes live under `raw/sources/` and are captured before ingestion:

```yaml
---
type: source
title: "Trivy configuration scan"
tags:
  - source
created: 2026-09-30
updated: 2026-09-30
sources: []
finding_id: "101aad4318ba"
scanner: trivy
captured: 2026-09-30
processed: false
---
```

`finding_id` and `scanner` may be `null` for a manually captured incident
source. `processed` is always a boolean and records capture-time metadata.

For scanner findings, `finding_id` is a 12-character lowercase hex ID written by
`wiki_tool capture`: the first 12 characters of the SHA-256 of
`scanner|rule_id|normalized_path|resource_or_secret_hash`. Line numbers are
excluded, so a finding that moves within a file keeps its ID. For gitleaks, the
hash covers the secret value, which is never stored.
Because raw evidence is immutable, current coverage is recorded in
`raw/manifest.json` rather than by editing this source note.

## Vulnerability fields

Vulnerability notes add:

```yaml
severity: high
cwe: "CWE-89"
owasp: "A03:2021-Injection"
component: "sample-app/search.py"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "capture"
    note: "First recorded."
finding_id: "101aad4318ba"
fix_commit: null
```

`status` is one of `open`, `fixed`, or `accepted`. Every status change
appends a new object to `status_history`; existing entries are not removed.

## Other note types

- **Postmortem:** common fields plus body sections for symptom, root cause,
  fix, prevention, and related vulnerabilities.
- **Concept:** common fields plus a reusable explanation of a security idea.
- **Entity:** common fields plus the affected file, service, tool, or component.
- **Log:** common fields plus `event` and `actor`; the canonical append-only log
  is `logs/wiki-log.md`.

## Link format

Use vault-relative Obsidian links in `sources`, for example:

```yaml
sources:
  - "[[raw/sources/source-2026-09-30-trivy-config]]"
```

Links must resolve to an existing Markdown note. Do not use external URLs as a
substitute for source citations.
