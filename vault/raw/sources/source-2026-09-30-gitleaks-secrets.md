---
type: source
title: "gitleaks secret scan: sample app"
tags:
  - source
  - secrets-management
created: 2026-09-30
updated: 2026-09-30
sources: []
finding_id: "gitleaks:sample-app:secrets"
scanner: gitleaks
captured: 2026-09-30
processed: false
---

# gitleaks secret scan: sample app

Capture mode: normalized and redacted gitleaks output. The detected secret
value is intentionally omitted from this raw record.

## Findings

- `gitleaks:generic-api-key:sample-app/app.py:15` — generic API key detected.
  Secret value: `[REDACTED]`.
