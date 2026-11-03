---
type: source
title: "gitleaks generic-api-key in sample-app/app.py"
tags:
  - source
  - secrets-management
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "5490f72b5b06"
scanner: gitleaks
captured: 2026-11-03
processed: false
---

# gitleaks generic-api-key in sample-app/app.py

Capture mode: normalized and redacted gitleaks output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: gitleaks
- Rule: `generic-api-key`
- Severity: not reported
- Location: `sample-app/app.py` line 15
- Secret value: `[REDACTED]` (omitted by design)
- Revision: `18dfb07b42b9`

## Description

Detected a Generic API Key, potentially exposing access to various services and sensitive operations.

## Recommended action

Rotate the exposed credential and remove it from the code history.
