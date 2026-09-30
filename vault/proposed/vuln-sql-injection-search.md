---
type: vulnerability
title: "SQL injection in search endpoint"
tags:
  - vulnerability
  - cwe-89-sql-injection
  - owasp-a03-injection
  - input-validation
created: 2026-09-30
updated: 2026-09-30
sources:
  - "[[raw/sources/source-2026-09-30-manual-code-review]]"
severity: high
cwe: "CWE-89"
owasp: "A03:2021-Injection"
component: "sample-app/app.py"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "manual:CWE-89:sample-app/app.py:27"
    note: "First recorded from the manual code-review capture."
finding_id: "manual:CWE-89:sample-app/app.py:27"
fix_commit: null
---

# SQL injection in search endpoint

The `/search` endpoint concatenates the untrusted `q` parameter into a
database query. An attacker can alter the query structure and read or modify
data available to the process.

## Remediation

Use parameterized queries, validate the input at the application boundary, and
add a regression test for injection payloads.
