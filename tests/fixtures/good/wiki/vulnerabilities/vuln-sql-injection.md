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
  - "[[raw/sources/source-2026-09-30-scan]]"
severity: high
cwe: "CWE-89"
owasp: "A03:2021-Injection"
component: "sample-app/search.py"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "demo:sql-injection:search"
    note: "First recorded."
finding_id: "demo:sql-injection:search"
fix_commit: null
---

# SQL injection in search endpoint

The search endpoint concatenates untrusted input into a database query. Use
parameterized queries and validate the input at the boundary.
