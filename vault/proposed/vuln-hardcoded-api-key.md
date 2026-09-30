---
type: vulnerability
title: "Hardcoded API key in sample application"
tags:
  - vulnerability
  - cwe-798-hardcoded-credentials
  - secrets-management
created: 2026-09-30
updated: 2026-09-30
sources:
  - "[[raw/sources/source-2026-09-30-gitleaks-secrets]]"
  - "[[raw/sources/source-2026-09-30-manual-code-review]]"
severity: high
cwe: "CWE-798"
owasp: "A07:2021-Identification-and-Authentication-Failures"
component: "sample-app/app.py"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "gitleaks:generic-api-key:sample-app/app.py:15"
    note: "Secret value was redacted in the captured source."
finding_id: "gitleaks:generic-api-key:sample-app/app.py:15"
fix_commit: null
---

# Hardcoded API key in sample application

The source file contains a credential-like API key. The captured value is
redacted and must not be copied into the wiki or sent to a hosted model.

## Remediation

Remove the value from source control, rotate it if it were real, and load
secrets through a managed secret store or local environment configuration that
is excluded from Git.
